// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! End-to-end TLS handshakes: this crate's provider on the client, the
//! `rustls-rustcrypto` provider on the server (dev-dependency only).
//!
//! The matrix covers every TLS 1.3 and TLS 1.2 suite the provider offers,
//! each key-exchange group, and the four server key types (ECDSA P-256,
//! ECDSA P-384, RSA-2048, Ed25519). For RSA leaves the test also checks which
//! RSA signature scheme the server actually used.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, DigitallySignedStruct, Error, NamedGroup,
    RootCertStore, ServerConfig, ServerConnection, SignatureScheme, StreamOwned,
    SupportedCipherSuite, SupportedProtocolVersion,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture present")
}

fn certs(name: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(&read(name))
        .collect::<Result<_, _>>()
        .expect("valid PEM certificate")
}

fn key(name: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(&read(name)).expect("valid PEM private key")
}

/// Trust anchors: both test CAs, so either chain verifies.
fn roots() -> RootCertStore {
    let mut store = RootCertStore::empty();
    for ca in certs("ca_p256.pem").into_iter().chain(certs("ca_rsa.pem")) {
        store.add(ca).expect("CA certificate accepted");
    }
    store
}

#[derive(Clone, Copy, Debug)]
enum Leaf {
    EcdsaP256,
    EcdsaP384,
    Rsa,
    Ed25519,
}

impl Leaf {
    fn files(self) -> (&'static str, &'static str) {
        match self {
            Leaf::EcdsaP256 => ("leaf_p256.pem", "leaf_p256.key"),
            Leaf::EcdsaP384 => ("leaf_p384.pem", "leaf_p384.key"),
            Leaf::Rsa => ("leaf_rsa.pem", "leaf_rsa.key"),
            Leaf::Ed25519 => ("leaf_ed25519.pem", "leaf_ed25519.key"),
        }
    }
}

/// Signature schemes the client observed being verified, in order.
type SigLog = Arc<Mutex<Vec<SignatureScheme>>>;

/// Delegates all checks to the webpki verifier, and records the scheme of
/// every handshake signature it is asked to verify.
#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    seen: SigLog,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.seen.lock().unwrap().push(dss.scheme);
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.seen.lock().unwrap().push(dss.scheme);
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Server provider: rustls-rustcrypto, restricted to one suite.
fn server_config(
    suite: SupportedCipherSuite,
    versions: &[&'static SupportedProtocolVersion],
    leaf: Leaf,
) -> Arc<ServerConfig> {
    let mut provider: CryptoProvider = rustls_rustcrypto::provider();
    provider.cipher_suites = vec![suite];
    let (cert, key_file) = leaf.files();
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .expect("server versions")
        .with_no_client_auth()
        .with_single_cert(certs(cert), key(key_file))
        .expect("server certificate");
    Arc::new(config)
}

/// Client provider under test, restricted to one suite and one group. Server
/// signatures are verified by webpki using this provider's algorithms, and
/// the schemes used are recorded in the returned log.
fn client_config(
    suite: SupportedCipherSuite,
    group: &'static dyn rustls::crypto::SupportedKxGroup,
    versions: &[&'static SupportedProtocolVersion],
) -> (Arc<ClientConfig>, SigLog) {
    let mut provider = tpt_crypto_rustls::provider();
    provider.cipher_suites = vec![suite];
    provider.kx_groups = vec![group];
    let provider = Arc::new(provider);
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots()), provider.clone())
        .build()
        .expect("webpki verifier");
    let seen: SigLog = Arc::default();
    let verifier = Arc::new(RecordingVerifier {
        inner,
        seen: seen.clone(),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("client versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    (Arc::new(config), seen)
}

/// Runs one handshake and a short echo, then checks the negotiated suite and
/// group, and if given, the single signature scheme the client verified.
/// Returns an error string on any mismatch.
fn handshake(
    server: Arc<ServerConfig>,
    client: (Arc<ClientConfig>, SigLog),
    expect_suite: CipherSuite,
    expect_group: Option<NamedGroup>,
    expect_sig: Option<SignatureScheme>,
) -> Result<(), String> {
    let (client, seen) = client;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;

    let server_thread = thread::spawn(move || -> Result<(), String> {
        let (tcp, _) = listener.accept().map_err(|e| e.to_string())?;
        let conn = ServerConnection::new(server).map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, tcp);
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf)
            .map_err(|e| format!("server read: {e}"))?;
        if &buf != b"ping" {
            return Err(format!("server got {buf:?}"));
        }
        tls.write_all(b"pong")
            .map_err(|e| format!("server write: {e}"))?;
        tls.flush().map_err(|e| format!("server flush: {e}"))?;
        // Drain the close_notify so the client sees a clean end of stream.
        let _ = tls.conn.send_close_notify();
        let _ = tls.conn.complete_io(&mut tls.sock);
        Ok(())
    });

    let tcp = TcpStream::connect(addr).map_err(|e| e.to_string())?;
    let name = ServerName::try_from("localhost").map_err(|e| e.to_string())?;
    let conn = ClientConnection::new(client, name).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, tcp);
    tls.write_all(b"ping")
        .map_err(|e| format!("client write: {e}"))?;
    tls.flush().map_err(|e| format!("client flush: {e}"))?;
    let mut buf = [0u8; 4];
    tls.read_exact(&mut buf)
        .map_err(|e| format!("client read: {e}"))?;
    if &buf != b"pong" {
        return Err(format!("client got {buf:?}"));
    }

    let suite = tls
        .conn
        .negotiated_cipher_suite()
        .ok_or("no suite negotiated")?
        .suite();
    if suite != expect_suite {
        return Err(format!("negotiated {suite:?}, expected {expect_suite:?}"));
    }
    let group = tls.conn.negotiated_key_exchange_group().map(|g| g.name());
    if group != expect_group {
        return Err(format!(
            "negotiated group {group:?}, expected {expect_group:?}"
        ));
    }
    if let Some(expect) = expect_sig {
        let schemes = seen.lock().unwrap().clone();
        if schemes != [expect] {
            return Err(format!(
                "verified signatures {schemes:?}, expected [{expect:?}]"
            ));
        }
    }

    server_thread
        .join()
        .map_err(|_| "server thread panicked".to_string())?
}

/// The signature scheme the server must use for a given leaf, where the test
/// pins it. Only RSA is pinned: the client offers all six RSA schemes, and the
/// rustls-rustcrypto RSA key picks RSA-PSS SHA-512 from them in both versions.
/// The ECDSA and Ed25519 schemes follow from the key type and are not checked.
fn rsa_scheme(leaf: Leaf) -> Option<SignatureScheme> {
    matches!(leaf, Leaf::Rsa).then_some(SignatureScheme::RSA_PSS_SHA512)
}

const TLS13: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];
const TLS12: &[&SupportedProtocolVersion] = &[&rustls::version::TLS12];

#[test]
fn tls13_all_suites_groups_and_key_types() {
    let suites = [
        (
            tpt_crypto_rustls::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
        ),
        (
            tpt_crypto_rustls::TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ),
        (
            tpt_crypto_rustls::TLS13_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        ),
    ];
    let groups: [(&'static dyn rustls::crypto::SupportedKxGroup, NamedGroup); 3] = [
        (&tpt_crypto_rustls::X25519, NamedGroup::X25519),
        (&tpt_crypto_rustls::SecP256R1, NamedGroup::secp256r1),
        (&tpt_crypto_rustls::SecP384R1, NamedGroup::secp384r1),
    ];
    let leaves = [Leaf::EcdsaP256, Leaf::EcdsaP384, Leaf::Rsa, Leaf::Ed25519];

    let mut failures = Vec::new();
    for leaf in leaves {
        for (suite, suite_name) in suites {
            // The server offers only the suite under test.
            let server_suite = match suite_name {
                CipherSuite::TLS13_AES_128_GCM_SHA256 => {
                    rustls_rustcrypto::TLS13_AES_128_GCM_SHA256
                }
                CipherSuite::TLS13_AES_256_GCM_SHA384 => {
                    rustls_rustcrypto::TLS13_AES_256_GCM_SHA384
                }
                _ => rustls_rustcrypto::TLS13_CHACHA20_POLY1305_SHA256,
            };
            for (group, group_name) in groups {
                let expect_sig = rsa_scheme(leaf);
                let server = server_config(server_suite, TLS13, leaf);
                let client = client_config(suite, group, TLS13);
                if let Err(e) = handshake(server, client, suite_name, Some(group_name), expect_sig)
                {
                    failures.push(format!("{leaf:?} / {suite_name:?} / {group_name:?}: {e}"));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "TLS 1.3 failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn tls12_all_suites_and_groups() {
    // (ours, rustls-rustcrypto's equivalent, suite name, leaf for the key type)
    type Case = (
        SupportedCipherSuite,
        SupportedCipherSuite,
        CipherSuite,
        &'static [Leaf],
    );
    let cases: [Case; 6] = [
        (
            tpt_crypto_rustls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rustls_rustcrypto::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            &[Leaf::EcdsaP256, Leaf::EcdsaP384, Leaf::Ed25519],
        ),
        (
            tpt_crypto_rustls::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            rustls_rustcrypto::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            &[Leaf::EcdsaP256, Leaf::EcdsaP384],
        ),
        (
            tpt_crypto_rustls::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            rustls_rustcrypto::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            &[Leaf::EcdsaP256],
        ),
        (
            tpt_crypto_rustls::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            rustls_rustcrypto::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            &[Leaf::Rsa],
        ),
        (
            tpt_crypto_rustls::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rustls_rustcrypto::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            &[Leaf::Rsa],
        ),
        (
            tpt_crypto_rustls::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            rustls_rustcrypto::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            &[Leaf::Rsa],
        ),
    ];
    let groups: [(&'static dyn rustls::crypto::SupportedKxGroup, NamedGroup); 3] = [
        (&tpt_crypto_rustls::X25519, NamedGroup::X25519),
        (&tpt_crypto_rustls::SecP256R1, NamedGroup::secp256r1),
        (&tpt_crypto_rustls::SecP384R1, NamedGroup::secp384r1),
    ];

    let mut failures = Vec::new();
    for (ours, theirs, suite_name, leaves) in cases {
        for &leaf in leaves {
            for (group, group_name) in groups {
                let expect_sig = rsa_scheme(leaf);
                let server = server_config(theirs, TLS12, leaf);
                let client = client_config(ours, group, TLS12);
                if let Err(e) = handshake(server, client, suite_name, Some(group_name), expect_sig)
                {
                    failures.push(format!("{leaf:?} / {suite_name:?} / {group_name:?}: {e}"));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "TLS 1.2 failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn untrusted_server_certificate_is_rejected() {
    // Trust only the P-256 CA; the RSA leaf chains to the RSA CA, so it must fail.
    let mut store = RootCertStore::empty();
    for ca in certs("ca_p256.pem") {
        store.add(ca).expect("CA certificate accepted");
    }
    let mut provider = tpt_crypto_rustls::provider();
    provider.cipher_suites = vec![tpt_crypto_rustls::TLS13_AES_128_GCM_SHA256];
    let client = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(TLS13)
            .expect("versions")
            .with_root_certificates(store)
            .with_no_client_auth(),
    );
    let server = server_config(
        rustls_rustcrypto::TLS13_AES_128_GCM_SHA256,
        TLS13,
        Leaf::Rsa,
    );
    let err = handshake(
        server,
        (client, SigLog::default()),
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        Some(NamedGroup::X25519),
        None,
    )
    .expect_err("handshake must fail");
    assert!(
        err.contains("client") || err.contains("certificate") || err.contains("Certificate"),
        "unexpected error: {err}"
    );
}
