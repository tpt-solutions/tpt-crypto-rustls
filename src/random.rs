// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! Randomness from the operating system (`getrandom`), exposed to rustls as
//! its `SecureRandom` and used for ephemeral key generation.

use rustls::crypto::{GetRandomFailed, SecureRandom};
use rustls::Error;

/// Fills `buf` with OS randomness, mapping failure to a rustls error.
pub(crate) fn fill_os(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(|_| Error::FailedToGetRandomBytes)
}

/// rustls `SecureRandom` backed by the operating system.
#[derive(Debug)]
pub(crate) struct OsRandom;

impl SecureRandom for OsRandom {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::fill(bytes).map_err(|_| GetRandomFailed)
    }
}
