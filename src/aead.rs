// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) TPT Solutions

//! TLS record protection (AES-GCM and ChaCha20-Poly1305) over tpt-crypto's
//! detached-tag AEAD API.
//!
//! Nonce and AAD construction follows RFC 8446 (TLS 1.3), RFC 5288 (TLS 1.2
//! AES-GCM), and RFC 7905 (TLS 1.2 ChaCha20-Poly1305), matching rustls's own
//! providers.

use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, BorrowedPayload, InboundOpaqueMessage,
    InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter, MessageEncrypter,
    Nonce as RustlsNonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};
use tpt_crypto_aead::{Aead, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, Nonce, Tag};

const TAG_LEN: usize = 16;
/// Explicit nonce carried on the wire by TLS 1.2 AES-GCM records.
const GCM_EXPLICIT_LEN: usize = 8;

fn nonce(bytes: [u8; 12]) -> Nonce<12> {
    Nonce::new(bytes)
}

/// Decrypts a record whose tag is the trailing 16 bytes. The tag is verified
/// before any plaintext is exposed; on success the payload is truncated to
/// the plaintext length.
fn open_tail<A: Aead<12, TAG_LEN>>(
    aead: &A,
    nonce_bytes: [u8; 12],
    aad: &[u8],
    payload: &mut BorrowedPayload<'_>,
) -> Result<(), Error> {
    let len = payload.len();
    if len < TAG_LEN {
        return Err(Error::DecryptError);
    }
    let body_len = len - TAG_LEN;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&payload[body_len..]);
    aead.decrypt_in_place_detached(
        &nonce(nonce_bytes),
        aad,
        &mut payload[..body_len],
        &Tag(tag),
    )
    .map_err(|_| Error::DecryptError)?;
    payload.truncate(body_len);
    Ok(())
}

/// TLS 1.3 record encrypter: nonce = IV XOR sequence number; the inner content
/// type is appended before encryption; AAD is built from the record length.
struct Tls13Encrypter<A> {
    aead: A,
    iv: Iv,
}

impl<A: Aead<12, TAG_LEN> + Send + Sync> MessageEncrypter for Tls13Encrypter<A> {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());

        let nonce_bytes = RustlsNonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(total_len);
        let tag = self.aead.encrypt_in_place_detached(
            &nonce(nonce_bytes),
            &aad,
            AsMut::<[u8]>::as_mut(&mut payload),
        );
        payload.extend_from_slice(&tag.0);

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

/// TLS 1.3 record decrypter.
struct Tls13Decrypter<A> {
    aead: A,
    iv: Iv,
}

impl<A: Aead<12, TAG_LEN> + Send + Sync> MessageDecrypter for Tls13Decrypter<A> {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let nonce_bytes = RustlsNonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(m.payload.len());
        open_tail(&self.aead, nonce_bytes, &aad, &mut m.payload)?;
        m.into_tls13_unpadded_message()
    }
}

/// TLS 1.2 AES-GCM record encrypter (RFC 5288). The record carries an 8-byte
/// explicit nonce ahead of the ciphertext.
struct Tls12GcmEncrypter<A> {
    aead: A,
    /// 4-byte implicit salt followed by the 8-byte explicit nonce base.
    iv: Iv,
}

impl<A: Aead<12, TAG_LEN> + Send + Sync> MessageEncrypter for Tls12GcmEncrypter<A> {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce_bytes = RustlsNonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());
        payload.extend_from_slice(&nonce_bytes[4..]);
        payload.extend_from_chunks(&m.payload);

        let tag = self.aead.encrypt_in_place_detached(
            &nonce(nonce_bytes),
            &aad,
            &mut AsMut::<[u8]>::as_mut(&mut payload)[GCM_EXPLICIT_LEN..],
        );
        payload.extend_from_slice(&tag.0);

        Ok(OutboundOpaqueMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_LEN + TAG_LEN
    }
}

/// TLS 1.2 AES-GCM record decrypter.
struct Tls12GcmDecrypter<A> {
    aead: A,
    /// 4-byte implicit salt.
    salt: [u8; 4],
}

impl<A: Aead<12, TAG_LEN> + Send + Sync> MessageDecrypter for Tls12GcmDecrypter<A> {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let len = m.payload.len();
        if len < GCM_EXPLICIT_LEN + TAG_LEN {
            return Err(Error::DecryptError);
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.salt);
        nonce_bytes[4..].copy_from_slice(&m.payload[..GCM_EXPLICIT_LEN]);

        let aad = make_tls12_aad(seq, m.typ, m.version, len - GCM_EXPLICIT_LEN - TAG_LEN);
        let body_end = len - TAG_LEN;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&m.payload[body_end..]);

        self.aead
            .decrypt_in_place_detached(
                &nonce(nonce_bytes),
                &aad,
                &mut m.payload[GCM_EXPLICIT_LEN..body_end],
                &Tag(tag),
            )
            .map_err(|_| Error::DecryptError)?;

        Ok(m.into_plain_message_range(GCM_EXPLICIT_LEN..body_end))
    }
}

/// TLS 1.2 ChaCha20-Poly1305 record encrypter (RFC 7905): no explicit nonce.
struct Tls12ChaChaEncrypter {
    aead: ChaCha20Poly1305,
    iv: Iv,
}

impl MessageEncrypter for Tls12ChaChaEncrypter {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&m.payload);

        let nonce_bytes = RustlsNonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());
        let tag = self.aead.encrypt_in_place_detached(
            &nonce(nonce_bytes),
            &aad,
            AsMut::<[u8]>::as_mut(&mut payload),
        );
        payload.extend_from_slice(&tag.0);

        Ok(OutboundOpaqueMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

/// TLS 1.2 ChaCha20-Poly1305 record decrypter.
struct Tls12ChaChaDecrypter {
    aead: ChaCha20Poly1305,
    iv: Iv,
}

impl MessageDecrypter for Tls12ChaChaDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let nonce_bytes = RustlsNonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(
            seq,
            m.typ,
            m.version,
            m.payload.len().saturating_sub(TAG_LEN),
        );
        open_tail(&self.aead, nonce_bytes, &aad, &mut m.payload)?;
        Ok(m.into_plain_message())
    }
}

/// 12-byte TLS 1.2 AES-GCM IV: 4-byte salt followed by the explicit base.
fn gcm_iv(write_iv: &[u8], explicit: &[u8]) -> Iv {
    let mut iv = [0u8; 12];
    iv[..4].copy_from_slice(write_iv);
    iv[4..].copy_from_slice(explicit);
    Iv::new(iv)
}

/// Copies a key of fixed length `N` out of rustls's key buffer.
///
/// rustls derives key lengths from `key_len` / `key_block_shape`, which the
/// algorithm types below report consistently, so the length always matches.
fn key_array<const N: usize>(key: &AeadKey) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(key.as_ref());
    out
}

fn salt_array(iv: &[u8]) -> [u8; 4] {
    let mut salt = [0u8; 4];
    salt.copy_from_slice(iv);
    salt
}

/// AES-128-GCM.
#[derive(Debug)]
pub(crate) struct Aes128GcmAlg;

/// AES-256-GCM.
#[derive(Debug)]
pub(crate) struct Aes256GcmAlg;

/// ChaCha20-Poly1305.
#[derive(Debug)]
pub(crate) struct ChaCha20Alg;

impl Tls13AeadAlgorithm for Aes128GcmAlg {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Encrypter {
            aead: Aes128Gcm::new(&key_array::<16>(&key)).expect("16-byte key"),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Decrypter {
            aead: Aes128Gcm::new(&key_array::<16>(&key)).expect("16-byte key"),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
}

impl Tls13AeadAlgorithm for Aes256GcmAlg {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Encrypter {
            aead: Aes256Gcm::new(&key_array::<32>(&key)).expect("32-byte key"),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Decrypter {
            aead: Aes256Gcm::new(&key_array::<32>(&key)).expect("32-byte key"),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }
}

impl Tls13AeadAlgorithm for ChaCha20Alg {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Encrypter {
            aead: ChaCha20Poly1305::new(&key_array::<32>(&key)),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Decrypter {
            aead: ChaCha20Poly1305::new(&key_array::<32>(&key)),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

impl Tls12AeadAlgorithm for Aes128GcmAlg {
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12GcmEncrypter {
            aead: Aes128Gcm::new(&key_array::<16>(&key)).expect("16-byte key"),
            iv: gcm_iv(write_iv, explicit),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12GcmDecrypter {
            aead: Aes128Gcm::new(&key_array::<16>(&key)).expect("16-byte key"),
            salt: salt_array(iv),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 16,
            fixed_iv_len: 4,
            explicit_nonce_len: GCM_EXPLICIT_LEN,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm {
            key,
            iv: gcm_iv(write_iv, explicit),
        })
    }
}

impl Tls12AeadAlgorithm for Aes256GcmAlg {
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12GcmEncrypter {
            aead: Aes256Gcm::new(&key_array::<32>(&key)).expect("32-byte key"),
            iv: gcm_iv(write_iv, explicit),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12GcmDecrypter {
            aead: Aes256Gcm::new(&key_array::<32>(&key)).expect("32-byte key"),
            salt: salt_array(iv),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 4,
            explicit_nonce_len: GCM_EXPLICIT_LEN,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm {
            key,
            iv: gcm_iv(write_iv, explicit),
        })
    }
}

impl Tls12AeadAlgorithm for ChaCha20Alg {
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        _explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12ChaChaEncrypter {
            aead: ChaCha20Poly1305::new(&key_array::<32>(&key)),
            iv: Iv::copy(write_iv),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12ChaChaDecrypter {
            aead: ChaCha20Poly1305::new(&key_array::<32>(&key)),
            iv: Iv::copy(iv),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::copy(iv),
        })
    }
}
