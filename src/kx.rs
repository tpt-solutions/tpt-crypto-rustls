// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Ephemeral key exchange: X25519, secp256r1 (P-256), and secp384r1 (P-384),
//! backed by tpt-crypto.
//!
//! Scalars are drawn from the OS RNG. For the Weierstrass curves, rustls
//! accepts any scalar length and tpt-crypto's point multiplication takes raw
//! big-endian bytes. A scalar that is not reduced modulo the group order gives
//! the same shared x-coordinate, because the peer's point has order `n`.

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};
use tpt_crypto_curve::montgomery25519::X25519 as TptX25519;
use tpt_crypto_curve::weierstrass::{ProjectivePoint, WeierstrassParams, P256, P384};

use crate::random::fill_os;

/// X25519.
#[derive(Debug)]
/// X25519 key exchange group.
pub struct X25519;

/// secp256r1 (P-256).
#[derive(Debug)]
/// secp256r1 (P-256) key exchange group.
pub struct SecP256R1;

/// secp384r1 (P-384).
#[derive(Debug)]
/// secp384r1 (P-384) key exchange group.
pub struct SecP384R1;

impl SupportedKxGroup for X25519 {
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut secret = [0u8; 32];
        fill_os(&mut secret)?;
        let public = TptX25519::diffie_hellman(&secret, &TptX25519::BASE);
        Ok(Box::new(X25519Kx { secret, public }))
    }
}

struct X25519Kx {
    secret: [u8; 32],
    public: [u8; 32],
}

impl ActiveKeyExchange for X25519Kx {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = TptX25519::diffie_hellman(&self.secret, &peer);
        // RFC 7748 §6.1: an all-zero output means the peer sent a low-order point.
        if shared.iter().all(|&b| b == 0) {
            return Err(Error::from(PeerMisbehaved::InvalidKeyShare));
        }
        Ok(SharedSecret::from(&shared[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// Generic ECDH over a tpt-crypto Weierstrass curve.
struct WeierstrassKx<C: WeierstrassParams> {
    secret: Vec<u8>,
    public: Vec<u8>,
    group: NamedGroup,
    _curve: core::marker::PhantomData<fn() -> C>,
}

fn start_weierstrass<C: WeierstrassParams>(
    group: NamedGroup,
    scalar_len: usize,
) -> Result<Box<dyn ActiveKeyExchange>, Error> {
    let mut secret = vec![0u8; scalar_len];
    fill_os(&mut secret)?;
    let point = ProjectivePoint::<C>::generator().mul(&secret);
    let mut public = vec![0u8; 1 + 2 * scalar_len];
    point
        .to_sec1_uncompressed(&mut public)
        .ok_or_else(|| Error::General("ECDH public point is the identity".into()))?;
    Ok(Box::new(WeierstrassKx::<C> {
        secret,
        public,
        group,
        _curve: core::marker::PhantomData,
    }))
}

impl<C: WeierstrassParams + 'static> ActiveKeyExchange for WeierstrassKx<C> {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let their = ProjectivePoint::<C>::from_sec1(peer)
            .ok_or_else(|| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = their.mul(&self.secret);
        let mut encoded = vec![0u8; self.public.len()];
        shared
            .to_sec1_uncompressed(&mut encoded)
            .ok_or_else(|| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        // The shared secret is the affine x-coordinate (SEC1 bytes 1..1+n).
        let n = (self.public.len() - 1) / 2;
        Ok(SharedSecret::from(&encoded[1..1 + n]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

impl SupportedKxGroup for SecP256R1 {
    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        start_weierstrass::<P256>(NamedGroup::secp256r1, 32)
    }
}

impl SupportedKxGroup for SecP384R1 {
    fn name(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        start_weierstrass::<P384>(NamedGroup::secp384r1, 48)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7748 §6.1 test vector.
    #[test]
    fn x25519_matches_rfc7748() {
        let alice_priv = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_pub = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assert_eq!(
            TptX25519::diffie_hellman(&alice_priv, &TptX25519::BASE),
            alice_pub
        );
        assert_eq!(TptX25519::diffie_hellman(&alice_priv, &bob_pub), shared);
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
        }
        out
    }
}
