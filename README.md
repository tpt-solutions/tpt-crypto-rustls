# tpt-crypto-rustls

A [rustls](https://github.com/rustls/rustls) `CryptoProvider` built on
[tpt-crypto](https://github.com/tpt-solutions/tpt-crypto). Pure Rust, with no
`ring`, `aws-lc-rs`, or C code. Licensed `MIT OR Apache-2.0`.

> **NOT AUDITED.** tpt-crypto has not been independently security-audited or
> formally verified end-to-end (its README says "reference material only"). This
> provider inherits that status. Do not use it to protect real traffic until an
> audit is complete.

## Coverage

Client side only. The provider cannot sign, so it cannot act as a TLS server or
present client certificates.

| Area | Provided |
| --- | --- |
| TLS 1.3 suites | `TLS13_AES_128_GCM_SHA256`, `TLS13_AES_256_GCM_SHA384`, `TLS13_CHACHA20_POLY1305_SHA256` |
| TLS 1.2 suites | `ECDHE_ECDSA` and `ECDHE_RSA` with AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| Key exchange | X25519, secp256r1 (P-256), secp384r1 (P-384) |
| Server signatures | ECDSA P-256 / P-384, Ed25519, RSA PKCS#1 v1.5 and RSA-PSS (SHA-256/384/512) |
| Randomness | OS (`getrandom`) |

Not provided: TLS 1.0/1.1, DHE, RSA key exchange, client authentication,
QUIC, and any server-side signing.

## Dependencies

- tpt-crypto crates (path dependency, `../tpt-crypto`): AEAD, hashes, HMAC, curves, signatures.
- `rsa` (`MIT OR Apache-2.0`): RSA verification only. Its RUSTSEC-2023-0071
  (Marvin) advisory concerns private-key operations, which this crate never
  performs.
- `sha2` (`MIT OR Apache-2.0`): types that supply the RSA DigestInfo OIDs.
- `getrandom`, `rustls` (`Apache-2.0 OR ISC OR MIT`).
- Dev-only: `rustls-rustcrypto`, as the server in handshake tests.

## Known deviations from tpt-crypto

- tpt-crypto's ECDSA verifier rejects high-S signatures as non-canonical.
  X.509 and TLS verification must accept both `s` and `n - s`, and OpenSSL
  emits high-S about half the time. This crate normalises `s` to low-S before
  calling tpt-crypto. Out-of-range `s` is still rejected.

## Testing

- `cargo test` runs the handshake matrix against a rustls server: every TLS 1.3
  suite and every TLS 1.2 suite, each key-exchange group, and four server key
  types (ECDSA P-256 and P-384, RSA-2048, Ed25519). It also checks that an
  untrusted chain is rejected.
- Unit tests check RSA PKCS#1 and PSS verification against OpenSSL output, the
  low-S normalisation, and X25519 against RFC 7748 §6.1.
- `tests/fixtures/` holds test-only certificates and leaf keys. They are not
  secrets and must never be used outside tests. The test CA private keys are not
  kept in the repository, so the fixtures cannot be re-issued from it.
