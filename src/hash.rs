// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! SHA-256 and SHA-384 as rustls `Hash` providers, backed by tpt-crypto.

use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use tpt_crypto_hash::sha2::{Sha256, Sha384};
use tpt_crypto_hash::Hasher;

/// SHA-256.
pub const SHA256: &dyn Hash = &Sha256Provider;
/// SHA-384.
pub const SHA384: &dyn Hash = &Sha384Provider;

#[derive(Debug)]
struct Sha256Provider;

#[derive(Debug)]
struct Sha384Provider;

impl Hash for Sha256Provider {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha256Context(Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&tpt_crypto_hash::sha2::sha256(data))
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
}

impl Hash for Sha384Provider {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha384Context(Sha384::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&tpt_crypto_hash::sha2::sha384(data))
    }

    fn output_len(&self) -> usize {
        48
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }
}

#[derive(Clone)]
struct Sha256Context(Sha256);

#[derive(Clone)]
struct Sha384Context(Sha384);

impl Context for Sha256Context {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(self.clone())
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl Context for Sha384Context {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(self.clone())
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}
