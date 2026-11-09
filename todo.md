# tpt-crypto-rustls — Checklist

Owner: TPT Solutions · License: `MIT OR Apache-2.0`
Master plan: [tpt-kernel/todo.md](../tpt-kernel/todo.md)

Scope: a rustls 0.23 `CryptoProvider` built on `tpt-crypto`. It serves the TLS client
path used by `tpt-mcpbox`: TLS 1.3 and 1.2, webpki server verification, and no client
authentication.

Status: builds, and the handshake matrix passes (36 TLS 1.3 and 6 TLS 1.2 combinations).
Not audited.

---

## Repo and publishing

- [x] Create the GitHub remote and push (done: `origin` is `github.com/tpt-solutions/tpt-crypto-rustls`, `master` at `c9d3d62`)
- [x] Switch the `tpt-crypto` path dependency to a git dependency (pinned to `tpt-crypto` `8b73d9b`, which is on its `origin/master`)
- [x] Commit the initial tree (done: `c9d3d62 Initial rustls CryptoProvider on tpt-crypto`)

## Dependencies

- [ ] Remove the `rsa` crate when `tpt-crypto` gains RSA verification (see `tpt-crypto/todo.md`)
- [ ] Remove the dev-only `rustls-rustcrypto` server-side dependency in favour of a rustls test server, so the dev graph no longer carries its advisories
- [ ] Revisit RUSTSEC-2023-0071 (`rsa`) before 2027-02-10, the review date recorded in `tpt-mcpbox/deny.toml`

## Correctness

- [ ] Raise upstream that `tpt-crypto`'s `verify_prehash` rejects high-S ECDSA signatures. The adapter currently normalises `s` to low-S; remove that workaround once upstream accepts them
- [x] Assert the negotiated RSA signature scheme in the handshake tests (both TLS versions pin `RSA_PSS_SHA512` for RSA leaves, via a recording verifier wrapper)

## Assurance

- [ ] External audit before the crate carries real traffic
- [ ] Constant-time review of the adapter paths (the underlying primitives are `tpt-crypto`'s responsibility)

## Documentation

- [ ] Keep the test CA private keys out of the repo; the fixtures cannot be re-issued without them

## Overlap with `tpt-crypto`

- [ ] `tpt-crypto/examples/src/rustls_provider.rs` already implements a TLS 1.3 provider on the same primitives (X25519 and Ed25519 only, no RSA, no TLS 1.2). Decide whether to consolidate onto this crate, and retire the example, or keep both with clear scopes.
