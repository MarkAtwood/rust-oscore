// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! EDHOC key derivation functions.

use super::EdhocError;
use super::types::{SecretVec, VecExt};
use crate::{Context, KEY_LEN, OscoreError};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

// EDHOC-KDF info labels (RFC 9528 Section 4.1.2, Figure 6).
// The table is kept complete to mirror python/src/lichen/crypto/edhoc.py;
// labels only exercised by transcript patterns outside Suite 0 SIGN_SIGN
// carry expect(dead_code) so the lint self-reverts if they gain a caller.
pub const LABEL_KEYSTREAM_2: u32 = 0;
#[expect(dead_code)]
pub const LABEL_SALT_3E2M: u32 = 1;
pub const LABEL_MAC_2: u32 = 2;
pub const LABEL_K_3: u32 = 3;
pub const LABEL_IV_3: u32 = 4;
#[expect(dead_code)]
pub const LABEL_SALT_4E3M: u32 = 5;
pub const LABEL_MAC_3: u32 = 6;
pub const LABEL_PRK_OUT: u32 = 7;
#[expect(dead_code)]
pub const LABEL_K_4: u32 = 8;
#[expect(dead_code)]
pub const LABEL_IV_4: u32 = 9;
pub const LABEL_PRK_EXPORTER: u32 = 10;
// OSCORE export labels (used with PRK_exporter)
pub const LABEL_OSCORE_SECRET: u32 = 0;
pub const LABEL_OSCORE_SALT: u32 = 1;

/// HKDF-Extract with SHA-256 (matches python/src/lichen/crypto/edhoc.py:_hkdf_extract exactly).
pub(crate) fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<Sha256>::extract(salt_opt, ikm);
    Zeroizing::new(prk.into())
}

/// EDHOC-KDF (RFC 9528 Section 4.1.2).
///
/// EDHOC-KDF(PRK, info_label, context, length) = HKDF-Expand(PRK, info, length)
/// where info = (info_label: int, context: bstr, length: uint) as a CBOR sequence.
///
/// Labels are defined in RFC 9528 Figure 6 (e.g., 0=KEYSTREAM_2, 2=MAC_2, etc.).
/// TH should be passed as context by the caller where appropriate (e.g., for KEYSTREAM_2).
///
/// The derived key material is returned in a [`SecretVec`] which wipes itself
/// on drop, covering both success and error unwinding at every call site.
pub(crate) fn edhoc_kdf(
    prk: &[u8; 32],
    label: u32,
    context: &[u8],
    length: usize,
) -> Result<SecretVec<128>, EdhocError> {
    let mut info = heapless::Vec::<u8, 128>::new();

    // Encode label as CBOR unsigned integer
    if label <= 23 {
        info.push_err(label as u8)?;
    } else if label <= 0xff {
        info.push_err(0x18)?;
        info.push_err(label as u8)?;
    } else {
        // Labels > 255 not used in EDHOC
        return Err(EdhocError::BufferTooSmall);
    }

    // Encode context as CBOR bstr
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

    // Encode length as CBOR unsigned integer
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

    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| EdhocError::KeyDerivation)?;
    let mut okm = heapless::Vec::<u8, 128>::new();
    okm.resize(length, 0)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    hk.expand(&info, &mut okm)
        .map_err(|_| EdhocError::KeyDerivation)?;
    Ok(SecretVec(okm))
}

pub(crate) fn export_context(
    prk: &[u8; 32],
    th: &[u8; 32],
    sender_id: &[u8],
    recipient_id: &[u8],
) -> Result<Context, OscoreError> {
    // PRK_out = EDHOC-KDF(PRK_4e3m, 7, TH_4, hash_length) (RFC 9528 Section 4.2.1)
    // SECURITY: heapless::Vec does not implement ZeroizeOnDrop, so every
    // edhoc_kdf result is a SecretVec which wipes its buffer on drop.
    let prk_out_vec =
        edhoc_kdf(prk, LABEL_PRK_OUT, th, 32).map_err(|_| OscoreError::KeyDerivation)?;
    let mut prk_out = Zeroizing::new([0u8; 32]);
    prk_out.copy_from_slice(&prk_out_vec[0..32]);
    // PRK_exporter = EDHOC-KDF(PRK_out, 10, h'', hash_length) (RFC 9528 Section 4.2.1)
    let prk_exporter_vec =
        edhoc_kdf(&prk_out, LABEL_PRK_EXPORTER, &[], 32).map_err(|_| OscoreError::KeyDerivation)?;
    let mut prk_exporter = Zeroizing::new([0u8; 32]);
    prk_exporter.copy_from_slice(&prk_exporter_vec);
    // OSCORE export (RFC 9528 Section 7.2.1)
    let master_secret_vec = edhoc_kdf(&prk_exporter, LABEL_OSCORE_SECRET, &[], KEY_LEN)
        .map_err(|_| OscoreError::KeyDerivation)?;
    let mut master_secret = Zeroizing::new([0u8; KEY_LEN]);
    master_secret.copy_from_slice(&master_secret_vec);
    let master_salt_vec = edhoc_kdf(&prk_exporter, LABEL_OSCORE_SALT, &[], 8)
        .map_err(|_| OscoreError::KeyDerivation)?;
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
