// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! EDHOC key derivation functions.

use super::EdhocError;
use super::types::VecExt;
use crate::{Context, KEY_LEN, OscoreError};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF-Extract with SHA-256 (matches python/src/lichen/crypto/edhoc.py:_hkdf_extract exactly).
pub(crate) fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<Sha256>::extract(salt_opt, ikm);
    Zeroizing::new(prk.into())
}

/// EDHOC-KDF (RFC 9528 Section 4.1.2).
///
/// EDHOC-KDF(PRK, TH, label, context, length) = HKDF-Expand(PRK, info, length)
/// where info = (length, TH, label, context) as a CBOR sequence.
pub(crate) fn edhoc_kdf(
    prk: &[u8; 32],
    th: &[u8; 32],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<heapless::Vec<u8, 128>, EdhocError> {
    let mut info = heapless::Vec::<u8, 128>::new();

    if length <= 23 {
        info.push_err(length as u8)?;
    } else if length <= 0xff {
        info.push_err(0x18)?;
        info.push_err(length as u8)?;
    } else if length <= 0xffff {
        info.push_err(0x19)?;
        info.push_err((length >> 8) as u8)?;
        info.push_err((length & 0xff) as u8)?;
    } else {
        return Err(EdhocError::BufferTooSmall);
    }

    // TH as bstr(32)
    info.push_err(0x58)?;
    info.push_err(32)?;
    info.extend_err(th)?;

    // label as tstr
    let label_bytes = label.as_bytes();
    if label_bytes.len() > 255 {
        return Err(EdhocError::BufferTooSmall);
    }
    if label_bytes.len() <= 23 {
        info.push_err(0x60 | label_bytes.len() as u8)?;
    } else {
        info.push_err(0x78)?;
        info.push_err(label_bytes.len() as u8)?;
    }
    info.extend_err(label_bytes)?;

    // context as bstr
    if context.is_empty() {
        info.push_err(0x40)?;
    } else if context.len() <= 23 {
        info.push_err(0x40 | context.len() as u8)?;
        info.extend_err(context)?;
    } else if context.len() <= 255 {
        info.push_err(0x58)?;
        info.push_err(context.len() as u8)?;
        info.extend_err(context)?;
    } else {
        return Err(EdhocError::BufferTooSmall);
    }

    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| EdhocError::KeyDerivation)?;
    let mut okm = heapless::Vec::<u8, 128>::new();
    okm.resize(length, 0)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    hk.expand(&info, &mut okm)
        .map_err(|_| EdhocError::KeyDerivation)?;

    let mut result = heapless::Vec::new();
    result
        .extend_from_slice(okm.as_slice())
        .map_err(|_| EdhocError::BufferTooSmall)?;
    Ok(result)
}

pub(crate) fn export_context(
    prk: &[u8; 32],
    th: &[u8; 32],
    sender_id: &[u8],
    recipient_id: &[u8],
) -> Result<Context, OscoreError> {
    let prk_out_vec = edhoc_kdf(prk, th, "7", th, 32).map_err(|_| OscoreError::KeyDerivation)?;
    let mut prk_out = Zeroizing::new([0u8; 32]);
    prk_out.copy_from_slice(&prk_out_vec[0..32]);
    let prk_exporter_vec =
        edhoc_kdf(&prk_out, th, "10", b"", 32).map_err(|_| OscoreError::KeyDerivation)?;
    let mut prk_exporter = Zeroizing::new([0u8; 32]);
    prk_exporter.copy_from_slice(&prk_exporter_vec);
    let master_secret_vec =
        edhoc_kdf(&prk_exporter, th, "0", b"", KEY_LEN).map_err(|_| OscoreError::KeyDerivation)?;
    let mut master_secret = Zeroizing::new([0u8; KEY_LEN]);
    master_secret.copy_from_slice(&master_secret_vec);
    let master_salt_vec =
        edhoc_kdf(&prk_exporter, th, "1", b"", 8).map_err(|_| OscoreError::KeyDerivation)?;
    let mut master_salt = Zeroizing::new([0u8; 8]);
    master_salt.copy_from_slice(&master_salt_vec);
    Context::new_fresh(
        &master_secret,
        Some(&master_salt[..]),
        None,
        sender_id,
        recipient_id,
    )
}
