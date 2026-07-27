// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! Cryptographic primitives for OSCORE.

use aes::Aes128;
use ccm::{
    consts::{U13, U8},
    Ccm,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::error::OscoreError;
use crate::types::{
    ContextId, ALG_AEAD, KEY_LEN, NONCE_ID_END, NONCE_ID_LEN, NONCE_LEN, PIV_MAX_LEN,
};

/// AES-CCM-16-64-128: 128-bit key, 13-byte nonce, 8-byte tag.
pub(crate) type AesCcm = Ccm<Aes128, U8, U13>;

/// Derive sender/recipient key using HKDF-SHA256 (returns 16-byte AES key).
pub(crate) fn derive_context_id(
    master_secret: &[u8; KEY_LEN],
    master_salt: &[u8],
    id_context: Option<&[u8]>,
    sender_id: &[u8],
) -> ContextId {
    let mut hash = Sha256::new();
    hash.update(b"LICHEN OSCORE sender context\0");
    for part in [master_secret.as_slice(), master_salt] {
        hash.update([part.len() as u8]);
        hash.update(part);
    }
    hash.update([u8::from(id_context.is_some())]);
    if let Some(id_context) = id_context {
        hash.update([id_context.len() as u8]);
        hash.update(id_context);
    }
    hash.update([sender_id.len() as u8]);
    hash.update(sender_id);
    ContextId::new(hash.finalize().into())
}

/// Derive sender/recipient key using HKDF-SHA256 (returns 16-byte AES key).
pub(crate) fn derive_key(
    master_secret: &[u8],
    master_salt: &[u8],
    id: &[u8],
    id_context: Option<&[u8]>,
) -> Result<[u8; KEY_LEN], OscoreError> {
    // Build CBOR info structure per RFC 8613 Section 3.2.1
    let mut info = [0u8; 64];
    let info_len = build_info_cbor(id, id_context, "Key", KEY_LEN, &mut info)?;

    let hk = Hkdf::<Sha256>::new(Some(master_salt), master_secret);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info[..info_len], &mut okm)
        .map_err(|_| OscoreError::KeyDerivation)?;

    Ok(okm)
}

/// Derive Common IV using HKDF-SHA256 (returns 13-byte nonce).
pub(crate) fn derive_iv(
    master_secret: &[u8],
    master_salt: &[u8],
    id_context: Option<&[u8]>,
) -> Result<[u8; NONCE_LEN], OscoreError> {
    // Build CBOR info structure per RFC 8613 Section 3.2.1
    // Common IV uses empty ID per RFC 8613 Section 3.2.1
    let mut info = [0u8; 64];
    let info_len = build_info_cbor(&[], id_context, "IV", NONCE_LEN, &mut info)?;

    let hk = Hkdf::<Sha256>::new(Some(master_salt), master_secret);
    let mut okm = [0u8; NONCE_LEN];
    hk.expand(&info[..info_len], &mut okm)
        .map_err(|_| OscoreError::KeyDerivation)?;

    Ok(okm)
}

/// Build OSCORE HKDF info CBOR structure per RFC 8613 Section 3.2.1.
///
/// CDDL schema (RFC 8613):
/// ```cddl
/// info = [
///     id: bstr,
///     id_context: bstr / nil,
///     alg_aead: int,
///     type: tstr,
///     L: uint
/// ]
/// ```
///
/// - `id`: Sender ID or Recipient ID (depends on key type being derived)
/// - `id_context`: ID Context if present, otherwise CBOR null (0xf6)
/// - `alg_aead`: AEAD algorithm identifier (10 = AES-CCM-16-64-128)
/// - `type`: "Key" or "IV" indicating which material is being derived
/// - `L`: Output length in bytes (16 for Key, 13 for IV)
pub(crate) fn build_info_cbor(
    id: &[u8],
    id_context: Option<&[u8]>,
    type_str: &str,
    out_len: usize,
    buf: &mut [u8],
) -> Result<usize, OscoreError> {
    let mut off = 0;

    // Array of 5 elements
    buf[off] = 0x85;
    off += 1;

    // id: bstr
    if id.len() <= 23 {
        buf[off] = 0x40 | (id.len() as u8);
        off += 1;
    } else {
        buf[off] = 0x58;
        buf[off + 1] = id.len() as u8;
        off += 2;
    }
    buf[off..off + id.len()].copy_from_slice(id);
    off += id.len();

    // id_context: bstr or null
    if let Some(id_context) = id_context {
        if id_context.len() <= 23 {
            buf[off] = 0x40 | (id_context.len() as u8);
            off += 1;
        } else {
            buf[off] = 0x58;
            buf[off + 1] = id_context.len() as u8;
            off += 2;
        }
        buf[off..off + id_context.len()].copy_from_slice(id_context);
        off += id_context.len();
    } else {
        buf[off] = 0xf6; // null
        off += 1;
    }

    // alg_aead: int (10)
    buf[off] = ALG_AEAD;
    off += 1;

    // type: tstr
    let type_bytes = type_str.as_bytes();
    if type_bytes.len() <= 23 {
        buf[off] = 0x60 | (type_bytes.len() as u8);
        off += 1;
    } else {
        buf[off] = 0x78;
        buf[off + 1] = type_bytes.len() as u8;
        off += 2;
    }
    buf[off..off + type_bytes.len()].copy_from_slice(type_bytes);
    off += type_bytes.len();

    // L: uint
    if out_len <= 23 {
        buf[off] = out_len as u8;
        off += 1;
    } else if out_len <= 255 {
        buf[off] = 0x18;
        buf[off + 1] = out_len as u8;
        off += 2;
    } else {
        return Err(OscoreError::InvalidParam);
    }

    Ok(off)
}

/// Build OSCORE AAD (Additional Authenticated Data) per RFC 8613 Section 5.4.
///
/// The AAD for OSCORE is a CBOR Enc_structure (RFC 9052 Section 5.3):
/// ```cddl
/// Enc_structure = [
///     "Encrypt0",     // context string
///     h'',            // protected header (empty for OSCORE)
///     external_aad    // bstr wrapping aad_array
/// ]
///
/// aad_array = [
///     oscore_version,  // uint = 1
///     [alg_aead],      // 1-element array with algorithm
///     request_kid,     // bstr
///     request_piv,     // bstr
///     options          // bstr (Class I options, empty)
/// ]
/// ```
///
/// Both requests and responses use the SAME AAD, built from the original
/// request's KID and PIV. This ties the response cryptographically to its request.
pub(crate) fn build_aad_cbor(
    request_kid: &[u8],
    request_piv: &[u8],
    buf: &mut [u8],
) -> Result<usize, OscoreError> {
    // Build the inner aad_array first
    let mut inner = [0u8; 64];
    let mut ioff = 0;

    // aad_array: 5-element array (0x85 = 0x80 | 5)
    inner[ioff] = 0x85;
    ioff += 1;

    // oscore_version: uint = 1
    inner[ioff] = 0x01;
    ioff += 1;

    // algorithms: 1-element array containing alg_aead
    // 0x81 = array of 1 item, then ALG_AEAD = 10
    inner[ioff] = 0x81;
    ioff += 1;
    inner[ioff] = ALG_AEAD;
    ioff += 1;

    // request_kid: bstr
    if request_kid.len() > 23 {
        return Err(OscoreError::InvalidParam);
    }
    inner[ioff] = 0x40 | (request_kid.len() as u8);
    ioff += 1;
    if !request_kid.is_empty() {
        inner[ioff..ioff + request_kid.len()].copy_from_slice(request_kid);
        ioff += request_kid.len();
    }

    // request_piv: bstr
    if request_piv.len() > 23 {
        return Err(OscoreError::InvalidParam);
    }
    inner[ioff] = 0x40 | (request_piv.len() as u8);
    ioff += 1;
    if !request_piv.is_empty() {
        inner[ioff..ioff + request_piv.len()].copy_from_slice(request_piv);
        ioff += request_piv.len();
    }

    // options: empty bstr (Class I options not used)
    inner[ioff] = 0x40;
    ioff += 1;

    // Now build Enc_structure: ["Encrypt0", h'', external_aad]
    let mut off = 0;

    // 3-element array (0x83 = 0x80 | 3)
    if off >= buf.len() {
        return Err(OscoreError::InvalidParam);
    }
    buf[off] = 0x83;
    off += 1;

    // "Encrypt0" as tstr (8 chars): 0x68 = 0x60 | 8
    if off + 9 > buf.len() {
        return Err(OscoreError::InvalidParam);
    }
    buf[off] = 0x68;
    off += 1;
    buf[off..off + 8].copy_from_slice(b"Encrypt0");
    off += 8;

    // empty bstr (protected header): 0x40
    if off >= buf.len() {
        return Err(OscoreError::InvalidParam);
    }
    buf[off] = 0x40;
    off += 1;

    // external_aad: bstr wrapping the inner CBOR
    if ioff <= 23 {
        if off >= buf.len() {
            return Err(OscoreError::InvalidParam);
        }
        buf[off] = 0x40 | (ioff as u8);
        off += 1;
    } else {
        if off + 1 >= buf.len() {
            return Err(OscoreError::InvalidParam);
        }
        buf[off] = 0x58;
        buf[off + 1] = ioff as u8;
        off += 2;
    }

    if off + ioff > buf.len() {
        return Err(OscoreError::InvalidParam);
    }
    buf[off..off + ioff].copy_from_slice(&inner[..ioff]);
    off += ioff;

    Ok(off)
}

/// Compute nonce from Partial IV and Common IV per RFC 8613 Section 5.2.
///
/// Nonce layout (NONCE_LEN = 13 bytes):
/// ```text
/// +--------+------------------+------------------+
/// | 1 byte |     7 bytes      |     5 bytes      |
/// +--------+------------------+------------------+
/// |   S    | left-padded ID   | left-padded PIV  |
/// +--------+------------------+------------------+
///   [0]      [1..NONCE_ID_END)  [NONCE_PIV_START..NONCE_LEN)
/// ```
///
/// S = sender_id_len (RFC 8613 Section 5.2)
/// The entire nonce is XOR'd with Common IV before use.
pub(crate) fn compute_nonce(
    sender_id: &[u8],
    piv: &[u8],
    common_iv: &[u8; NONCE_LEN],
) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];

    // Byte 0: S is the sender ID length. The PIV length is not mixed into S.
    nonce[0] = sender_id.len() as u8;

    // Bytes 1..NONCE_ID_END: left-padded sender ID (right-aligned, max NONCE_ID_LEN bytes)
    if sender_id.len() <= NONCE_ID_LEN {
        let start = NONCE_ID_END - sender_id.len();
        nonce[start..NONCE_ID_END].copy_from_slice(sender_id);
    }

    // Bytes NONCE_PIV_START..NONCE_LEN: left-padded PIV (right-aligned, max PIV_MAX_LEN bytes)
    if !piv.is_empty() && piv.len() <= PIV_MAX_LEN {
        let piv_end = NONCE_LEN;
        nonce[piv_end - piv.len()..piv_end].copy_from_slice(piv);
    }

    // XOR entire nonce with Common IV
    for (i, &b) in common_iv.iter().enumerate() {
        nonce[i] ^= b;
    }

    nonce
}
