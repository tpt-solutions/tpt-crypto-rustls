// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! A rustls [`CryptoProvider`] built on [tpt-crypto].
//!
//! The provider covers the client side of TLS 1.3 and TLS 1.2:
//!
//! - Cipher suites: `TLS13_AES_128_GCM_SHA256`, `TLS13_AES_256_GCM_SHA384`,
//!   `TLS13_CHACHA20_POLY1305_SHA256`; TLS 1.2 `ECDHE_ECDSA` and `ECDHE_RSA`
//!   with AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
//! - Key exchange: X25519, secp256r1, secp384r1.
//! - Server signature verification: ECDSA P-256 / P-384, Ed25519, RSA
//!   PKCS#1 v1.5 and RSA-PSS (SHA-256, SHA-384, SHA-512).
//!
//! It does not sign, so it cannot act as a TLS server or present client
//! certificates. [`provider`] returns a provider whose `KeyProvider` rejects
//! private keys.
//!
//! **Not audited.** tpt-crypto itself is not audited (see its README).
//!
//! [tpt-crypto]: https://github.com/tpt-solutions/tpt-crypto

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod aead;
mod hash;
mod hmac;
mod kx;
mod random;
mod verify;

use std::sync::Arc;

pub use kx::{SecP256R1, SecP384R1, X25519};

use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    CipherSuiteCommon, CryptoProvider, KeyExchangeAlgorithm, KeyProvider, SupportedKxGroup,
};
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::{
    CipherSuite, Error, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite,
};

/// Signature schemes accepted for ECDHE_ECDSA server certificates.
const TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ED25519,
];

/// Signature schemes accepted for ECDHE_RSA server certificates.
const TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];

/// `TLS13_AES_128_GCM_SHA256`.
pub const TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA256),
        aead_alg: &aead::Aes128GcmAlg,
        quic: None,
    });

/// `TLS13_AES_256_GCM_SHA384`.
pub const TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: hash::SHA384,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA384),
        aead_alg: &aead::Aes256GcmAlg,
        quic: None,
    });

/// `TLS13_CHACHA20_POLY1305_SHA256`.
pub const TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(hmac::SHA256),
        aead_alg: &aead::ChaCha20Alg,
        quic: None,
    });

macro_rules! tls12_suite {
    ($name:ident, $suite:ident, $kx_sigs:expr, $hash:expr, $prf:expr, $aead:expr) => {
        /// TLS 1.2 cipher suite, see the constant name.
        pub const $name: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::$suite,
                hash_provider: $hash,
                confidentiality_limit: u64::MAX,
            },
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: $kx_sigs,
            prf_provider: &PrfUsingHmac($prf),
            aead_alg: $aead,
        });
    };
}

tls12_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS12_ECDSA_SCHEMES,
    hash::SHA256,
    hmac::SHA256,
    &aead::Aes128GcmAlg
);
tls12_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS12_ECDSA_SCHEMES,
    hash::SHA384,
    hmac::SHA384,
    &aead::Aes256GcmAlg
);
tls12_suite!(
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS12_ECDSA_SCHEMES,
    hash::SHA256,
    hmac::SHA256,
    &aead::ChaCha20Alg
);
tls12_suite!(
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS12_RSA_SCHEMES,
    hash::SHA256,
    hmac::SHA256,
    &aead::Aes128GcmAlg
);
tls12_suite!(
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS12_RSA_SCHEMES,
    hash::SHA384,
    hmac::SHA384,
    &aead::Aes256GcmAlg
);
tls12_suite!(
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS12_RSA_SCHEMES,
    hash::SHA256,
    hmac::SHA256,
    &aead::ChaCha20Alg
);

/// Every cipher suite, TLS 1.3 first, in preference order.
pub const ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// Every key-exchange group, in preference order.
pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519, &SecP256R1, &SecP384R1];

/// Key provider for a client-only build: it cannot load private keys.
#[derive(Debug)]
struct ClientOnlyKeys;

impl KeyProvider for ClientOnlyKeys {
    fn load_private_key(
        &self,
        _key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General(
            "tpt-crypto-rustls is client-only and cannot load private keys".into(),
        ))
    }
}

/// Returns the rustls crypto provider for TLS clients.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &random::OsRandom,
        key_provider: &ClientOnlyKeys,
    }
}
