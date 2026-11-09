// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! HMAC-SHA-256 and HMAC-SHA-384 as rustls `Hmac` providers, backed by tpt-crypto.

use rustls::crypto::hmac::{Hmac, Key, Tag};
use tpt_crypto_hash::mac::Hmac as TptHmac;
use tpt_crypto_hash::sha2::{Sha256, Sha384};
use tpt_crypto_hash::Hasher;

/// HMAC-SHA-256.
pub const SHA256: &dyn Hmac = &HmacSha256;
/// HMAC-SHA-384.
pub const SHA384: &dyn Hmac = &HmacSha384;

#[derive(Debug)]
struct HmacSha256;

#[derive(Debug)]
struct HmacSha384;

/// Keyed HMAC. The key is retained because tpt-crypto's HMAC is rebuilt per
/// call, and rustls may use one key for several `sign_concat` calls.
struct KeyedHmac<H> {
    key: Vec<u8>,
    _marker: core::marker::PhantomData<H>,
}

macro_rules! impl_keyed {
    ($hash:ty, $block:expr, $out:expr) => {
        impl Key for KeyedHmac<$hash> {
            fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
                let mut mac = TptHmac::<$hash, $block, $out>::new(&self.key);
                mac.update(first);
                for part in middle {
                    mac.update(part);
                }
                mac.update(last);
                Tag::new(&mac.finalize())
            }

            fn tag_len(&self) -> usize {
                $out
            }
        }
    };
}

impl_keyed!(Sha256, 64, 32);
impl_keyed!(Sha384, 128, 48);

impl Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(KeyedHmac::<Sha256> {
            key: key.to_vec(),
            _marker: core::marker::PhantomData,
        })
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

impl Hmac for HmacSha384 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(KeyedHmac::<Sha384> {
            key: key.to_vec(),
            _marker: core::marker::PhantomData,
        })
    }

    fn hash_output_len(&self) -> usize {
        48
    }
}
