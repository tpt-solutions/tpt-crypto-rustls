// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Signature verification for certificate chains and handshake signatures:
//! ECDSA (P-256, P-384), Ed25519, and RSA (PKCS#1 v1.5 and PSS).
//!
//! Only verification is implemented. The RSA path uses the `rsa` crate's
//! verification-only API on tpt-crypto's digests. The `rsa` crate's
//! RUSTSEC-2023-0071 (Marvin) affects private-key operations, which this
//! crate never performs.

use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::signature::hazmat::PrehashVerifier;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};
use rustls::SignatureScheme;
use tpt_crypto_curve::weierstrass::{P256, P384};
use tpt_crypto_hash::sha2::{sha256, sha384, sha512};
use tpt_crypto_sig::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
use tpt_crypto_sig::ed25519::{Signature as EdSignature, VerifyingKey as EdVerifyingKey};

/// Every algorithm this provider can verify, with the signature schemes that
/// map to them.
pub(crate) static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ED25519,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384],
        ),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
    ],
};

/// Group orders and their half-orders, big-endian.
const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];
const P256_HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];
const P384_ORDER: [u8; 48] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
    0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73,
];
const P384_HALF_ORDER: [u8; 48] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE3, 0xB1, 0xA6, 0xC0, 0xFA, 0x1B, 0x96, 0xEF,
    0xAC, 0x0D, 0x06, 0xD9, 0x24, 0x58, 0x53, 0xBD, 0x76, 0x76, 0x0C, 0xB5, 0x66, 0x62, 0x94, 0xB9,
];

/// Big-endian `order - s`, for `0 <= s < order`.
fn negate_mod_order(order: &[u8], s: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; s.len()];
    let mut borrow = 0i16;
    for i in (0..s.len()).rev() {
        let d = order[i] as i16 - s[i] as i16 - borrow;
        if d < 0 {
            out[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[i] = d as u8;
            borrow = 0;
        }
    }
    out
}

/// ECDSA verification. tpt-crypto rejects high-S signatures as non-canonical,
/// but X.509 and TLS verifiers must accept both `s` and `n - s`, which are
/// equally valid. OpenSSL emits high-S signatures about half the time. So `s`
/// is normalised to low-S here, and out-of-range values are left for tpt-crypto
/// to reject.
fn verify_ecdsa<C: tpt_crypto_sig::ecdsa::EcdsaCurve>(
    public_key: &[u8],
    digest: &[u8],
    signature: &[u8],
    order: &[u8],
    half: &[u8],
) -> Result<(), InvalidSignature> {
    let key = EcdsaVerifyingKey::<C>::from_sec1(public_key).map_err(|_| InvalidSignature)?;
    let mut fixed = EcdsaSignature::<C>::from_der(signature)
        .map_err(|_| InvalidSignature)?
        .to_fixed();
    let n = fixed.len() / 2;
    let s = fixed[n..].to_vec();
    if s.as_slice() < order && s.as_slice() > half {
        fixed[n..].copy_from_slice(&negate_mod_order(order, &s));
    }
    let sig = EcdsaSignature::<C>::from_fixed(&fixed).map_err(|_| InvalidSignature)?;
    key.verify_prehash(digest, &sig)
        .map_err(|_| InvalidSignature)
}

macro_rules! ecdsa_verifier {
    ($name:ident, $public_alg:expr, $sig_alg:expr, $curve:ty, $hash:path, $order:ident, $half:ident) => {
        #[derive(Debug)]
        struct $name;

        impl SignatureVerificationAlgorithm for $name {
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                $public_alg
            }

            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                $sig_alg
            }

            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                let digest = $hash(message);
                verify_ecdsa::<$curve>(public_key, &digest, signature, &$order, &$half)
            }
        }
    };
}

ecdsa_verifier!(
    EcdsaP256Sha256,
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA256,
    P256,
    sha256,
    P256_ORDER,
    P256_HALF_ORDER
);
ecdsa_verifier!(
    EcdsaP256Sha384,
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA384,
    P256,
    sha384,
    P256_ORDER,
    P256_HALF_ORDER
);
ecdsa_verifier!(
    EcdsaP384Sha256,
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA256,
    P384,
    sha256,
    P384_ORDER,
    P384_HALF_ORDER
);
ecdsa_verifier!(
    EcdsaP384Sha384,
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA384,
    P384,
    sha384,
    P384_ORDER,
    P384_HALF_ORDER
);

const ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP256Sha256;
const ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaP256Sha384;
const ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP384Sha256;
const ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaP384Sha384;

#[derive(Debug)]
struct Ed25519Verifier;

impl SignatureVerificationAlgorithm for Ed25519Verifier {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let pk: [u8; 32] = public_key.try_into().map_err(|_| InvalidSignature)?;
        let sig: [u8; 64] = signature.try_into().map_err(|_| InvalidSignature)?;
        let key = EdVerifyingKey::from_bytes(&pk).map_err(|_| InvalidSignature)?;
        key.verify(message, &EdSignature::from_bytes(sig))
            .map_err(|_| InvalidSignature)
    }
}

const ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519Verifier;

/// RSA verifier. `$scheme` is `rsa::pkcs1v15` or `rsa::pss`; `$digest` is the
/// `sha2` type that supplies the DigestInfo OID / PSS parameters. The digest
/// of the message is computed by tpt-crypto and passed to `verify_prehash`.
macro_rules! rsa_verifier {
    ($name:ident, $sig_alg:expr, $hash:path, $digest:ty, $scheme:ident) => {
        #[derive(Debug)]
        struct $name;

        impl SignatureVerificationAlgorithm for $name {
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::RSA_ENCRYPTION
            }

            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                $sig_alg
            }

            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                let key =
                    rsa::RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| InvalidSignature)?;
                let digest = $hash(message);
                let sig =
                    rsa::$scheme::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
                rsa::$scheme::VerifyingKey::<$digest>::new(key)
                    .verify_prehash(&digest, &sig)
                    .map_err(|_| InvalidSignature)
            }
        }
    };
}

rsa_verifier!(
    RsaPkcs1Sha256,
    alg_id::RSA_PKCS1_SHA256,
    sha256,
    sha2::Sha256,
    pkcs1v15
);
rsa_verifier!(
    RsaPkcs1Sha384,
    alg_id::RSA_PKCS1_SHA384,
    sha384,
    sha2::Sha384,
    pkcs1v15
);
rsa_verifier!(
    RsaPkcs1Sha512,
    alg_id::RSA_PKCS1_SHA512,
    sha512,
    sha2::Sha512,
    pkcs1v15
);
rsa_verifier!(
    RsaPssSha256,
    alg_id::RSA_PSS_SHA256,
    sha256,
    sha2::Sha256,
    pss
);
rsa_verifier!(
    RsaPssSha384,
    alg_id::RSA_PSS_SHA384,
    sha384,
    sha2::Sha384,
    pss
);
rsa_verifier!(
    RsaPssSha512,
    alg_id::RSA_PSS_SHA512,
    sha512,
    sha2::Sha512,
    pss
);

const RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Sha256;
const RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Sha384;
const RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Sha512;
const RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPssSha256;
const RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &RsaPssSha384;
const RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &RsaPssSha512;

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = include_bytes!("../tests/fixtures/sig_msg.bin");
    const RSA_PUB: &[u8] = include_bytes!("../tests/fixtures/rsa_pub_pkcs1.der");
    const PKCS1_SHA256: &[u8] = include_bytes!("../tests/fixtures/sig_pkcs1_sha256.bin");
    const PSS_SHA256: &[u8] = include_bytes!("../tests/fixtures/sig_pss_sha256.bin");

    fn verifier(scheme: SignatureScheme) -> &'static dyn SignatureVerificationAlgorithm {
        ALGORITHMS
            .mapping
            .iter()
            .find(|(s, _)| *s == scheme)
            .map(|(_, algs)| algs[0])
            .expect("scheme mapped")
    }

    #[test]
    fn rsa_pkcs1_sha256_verifies_and_rejects_tampering() {
        let v = verifier(SignatureScheme::RSA_PKCS1_SHA256);
        assert!(v.verify_signature(RSA_PUB, MSG, PKCS1_SHA256).is_ok());
        let mut tampered = MSG.to_vec();
        tampered[0] ^= 1;
        assert!(v
            .verify_signature(RSA_PUB, &tampered, PKCS1_SHA256)
            .is_err());
    }

    #[test]
    fn rsa_pss_sha256_verifies_and_rejects_tampering() {
        let v = verifier(SignatureScheme::RSA_PSS_SHA256);
        assert!(v.verify_signature(RSA_PUB, MSG, PSS_SHA256).is_ok());
        let mut tampered = MSG.to_vec();
        tampered[0] ^= 1;
        assert!(v.verify_signature(RSA_PUB, &tampered, PSS_SHA256).is_err());
    }

    #[test]
    fn high_s_is_normalised_to_low_s() {
        // n - 1 is the largest valid s and must map to 1 under negation.
        let mut n_minus_1 = P256_ORDER;
        n_minus_1[31] -= 1;
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(negate_mod_order(&P256_ORDER, &n_minus_1), one.to_vec());
        assert_eq!(negate_mod_order(&P256_ORDER, &one), n_minus_1.to_vec());
    }
}
