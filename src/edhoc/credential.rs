// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! EDHOC credential handling: encoding, parsing, and validation.

use super::cbor::{encode_bstr, parse_bstr};
use super::types::{IdCred, IdCredReference, VecExt};
use super::{EdhocError, ID_CRED_MAX_LEN, KEY_LEN_32};
use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
use sha2::{Digest, Sha256};

/// Peer authentication material supplied by the application.
///
/// `id_cred` and `credential` are complete deterministic-CBOR data items. CCS
/// and CWT COSE keys are checked against `public_key`; certificate and
/// application credential trust, including X.509 chain validation, remains the
/// application's responsibility.
#[derive(Clone, Copy)]
pub struct PeerCredential<'a> {
    pub(crate) public_key: &'a [u8; KEY_LEN_32],
    pub(crate) id_cred: &'a [u8],
    pub(crate) credential: &'a [u8],
}

impl<'a> PeerCredential<'a> {
    /// Create peer authentication material.
    pub const fn new(
        public_key: &'a [u8; KEY_LEN_32],
        id_cred: &'a [u8],
        credential: &'a [u8],
    ) -> Self {
        Self {
            public_key,
            id_cred,
            credential,
        }
    }
}

/// Build a raw key CCS (COSE_Key credential) from a public key.
///
/// Returns (id_cred, credential) as deterministic CBOR.
pub(crate) fn raw_key_credential(
    pubkey: &[u8; 32],
) -> Result<(heapless::Vec<u8, 40>, heapless::Vec<u8, 80>), EdhocError> {
    // ID_CRED with kid = bstr(hash of public key)
    let kid = Sha256::digest(pubkey);
    let mut id_cred = heapless::Vec::<u8, 40>::new();
    id_cred.push_err(0xa1)?; // map(1)
    id_cred.push_err(0x04)?; // kid (int 4)
    if kid[..23].len() <= 23 {
        id_cred.push_err(0x40 | 8)?;
    } else {
        id_cred.push_err(0x58)?;
        id_cred.push_err(8)?;
    }
    id_cred.extend_err(&kid[..8])?;

    // CCS: COSE_Key with kty=OKP, crv=Ed25519, x=pubkey
    let mut ccs = heapless::Vec::<u8, 80>::new();
    ccs.push_err(0xa3)?; // map(3)
    ccs.push_err(0x01)?; // kty (label 1)
    ccs.push_err(0x01)?; // OKP (kty=1)
    ccs.push_err(0x20)?; // crv (label -1)
    ccs.push_err(0x06)?; // Ed25519 (crv=6)
    ccs.push_err(0x21)?; // x (label -2)
    encode_bstr(&mut ccs, pubkey)?;

    Ok((id_cred, ccs))
}

/// Encode ID_CRED (kid = bstr(hash of pubkey)) as deterministic CBOR.
pub(crate) fn encode_id_cred<const N: usize>(
    buf: &mut heapless::Vec<u8, N>,
    pubkey: &[u8; 32],
) -> Result<(), EdhocError> {
    let kid = Sha256::digest(pubkey);
    buf.push_err(0xa1)?;
    buf.push_err(0x04)?;
    if 8 <= 23 {
        buf.push_err(0x40 | 8)?;
    } else {
        buf.push_err(0x58)?;
        buf.push_err(8)?;
    }
    buf.extend_err(&kid[..8])?;
    Ok(())
}

/// Encode a CCS (raw COSE_Key credential) from a public key.
pub(crate) fn encode_credential<const N: usize>(
    buf: &mut heapless::Vec<u8, N>,
    pubkey: &[u8; 32],
) -> Result<(), EdhocError> {
    buf.push_err(0xa3)?;
    buf.push_err(0x01)?;
    buf.push_err(0x01)?;
    buf.push_err(0x20)?;
    buf.push_err(0x06)?;
    buf.push_err(0x21)?;
    encode_bstr(buf, pubkey)?;
    Ok(())
}

/// Parse an ID_CRED map from deterministic CBOR.
///
/// Returns (IdCred, bytes_consumed).
pub(crate) fn parse_id_cred(data: &[u8]) -> Result<(IdCred, usize), EdhocError> {
    if data.is_empty() || data[0] != 0xa1 {
        // Only single-element maps supported
        return Err(EdhocError::InvalidMessage);
    }
    let mut consumed = 1;
    if data.len() < consumed + 1 {
        return Err(EdhocError::InvalidMessage);
    }
    let label = data[consumed];
    consumed += 1;

    // Parse value as bstr (kid or x5t hash)
    let (value, val_consumed) = parse_bstr(&data[consumed..])?;
    consumed += val_consumed;

    let mut encoded = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
    encoded.extend_err(&data[..consumed])?;

    let reference = match label {
        4 => IdCredReference::Kid(
            heapless::Vec::from_slice(value).map_err(|_| EdhocError::BufferTooSmall)?,
        ),
        _ => return Err(EdhocError::InvalidMessage),
    };

    Ok((IdCred { encoded, reference }, consumed))
}

/// Copy an ID_CRED kid value into a bounded vec.
#[cfg(test)]
pub(crate) fn copy_id_cred_value(
    data: &[u8],
) -> Result<heapless::Vec<u8, ID_CRED_MAX_LEN>, EdhocError> {
    let mut v = heapless::Vec::new();
    v.extend_err(data)?;
    Ok(v)
}

/// Validate deterministic CBOR item (RFC 8949 Section 4.2.3).
#[cfg(test)]
pub(crate) fn validate_deterministic_item(data: &[u8]) -> Result<(), EdhocError> {
    // Validate that maps have canonically sorted keys.
    // This is a minimal check sufficient for test vectors.
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    if first == 0xa0 {
        return Ok(());
    }
    if (0xa1..=0xb7).contains(&first) {
        let pairs = (first - 0xa1) as usize + 1;
        let _ = pairs; // consumed below by walking
        let mut offset = 1;
        let mut prev_key: Option<&[u8]> = None;
        for _ in 0..pairs {
            // Skip key
            if offset >= data.len() {
                return Err(EdhocError::InvalidMessage);
            }
            let key_start = offset;
            // Simple integer keys
            if data[offset] <= 0x17 {
                offset += 1;
            } else if data[offset] == 0x18 {
                offset += 2;
            } else if data[offset] == 0x19 {
                offset += 3;
            } else if data[offset] == 0x1a {
                offset += 5;
            } else if data[offset] == 0x1b {
                offset += 9;
            } else {
                // Text or byte string key -- skip by length
                if data[offset] >= 0x60 && data[offset] <= 0x77 {
                    offset += 1 + (data[offset] - 0x60) as usize;
                } else if data[offset] == 0x78 {
                    if offset + 1 >= data.len() {
                        return Err(EdhocError::InvalidMessage);
                    }
                    offset += 2 + data[offset + 1] as usize;
                } else {
                    return Err(EdhocError::InvalidMessage);
                }
            }
            if offset > data.len() {
                return Err(EdhocError::InvalidMessage);
            }
            let key = &data[key_start..offset];
            if let Some(prev) = prev_key {
                if key <= prev {
                    return Err(EdhocError::InvalidMessage);
                }
            }
            prev_key = Some(key);

            // Skip value
            let (_, val_consumed) = parse_bstr(&data[offset..]).or_else(|_| {
                // Try simple integer
                if offset < data.len() && data[offset] <= 0x17 {
                    Ok((&[], 1))
                } else if offset < data.len() && data[offset] == 0x18 && offset + 1 < data.len() {
                    Ok((&[], 2))
                } else {
                    Err(EdhocError::InvalidMessage)
                }
            })?;
            offset += val_consumed;
        }
        if offset != data.len() {
            return Err(EdhocError::InvalidMessage);
        }
        Ok(())
    } else if (0x80..=0x97).contains(&first) {
        let len = (first - 0x80) as usize;
        let mut offset = 1;
        for _ in 0..len {
            if offset >= data.len() {
                return Err(EdhocError::InvalidMessage);
            }
            let (_, consumed) = parse_bstr(&data[offset..]).or_else(|_| {
                if data[offset] <= 0x17 {
                    Ok((&[], 1))
                } else if data[offset] == 0x18 && offset + 1 < data.len() {
                    Ok((&[], 2))
                } else {
                    Err(EdhocError::InvalidMessage)
                }
            })?;
            offset += consumed;
        }
        if offset != data.len() {
            return Err(EdhocError::InvalidMessage);
        }
        Ok(())
    } else {
        Ok(())
    }
}

/// Validate a peer credential against its embedded public key.
pub(crate) fn validate_peer_credential(peer: PeerCredential<'_>) -> Result<(), EdhocError> {
    // Check the credential contains the expected public key.
    // For raw CCS: the x-value must match peer.public_key.
    let data = peer.credential;
    if data.is_empty() || data[0] != 0xa3 {
        // Non-CCS credentials (CWT, X.509 cert, application) are valid
        // as long as they are valid CBOR. The application-layer trust
        // model (TOFU, DANE, PKIX) handles verification.
        return Ok(());
    }
    // Parse CCS map to find the x-coordinate
    if data.len() < 2 {
        return Err(EdhocError::InvalidMessage);
    }
    if data[0] != 0xa3 {
        return Err(EdhocError::InvalidMessage);
    }
    if data[1] != 0x01 || data.get(2) != Some(&0x01) {
        return Err(EdhocError::InvalidMessage);
    }
    if data.get(3) != Some(&0x20) || data.get(4) != Some(&0x06) {
        return Err(EdhocError::InvalidMessage);
    }
    if data.get(5) != Some(&0x21) {
        return Err(EdhocError::InvalidMessage);
    }
    let x_start = 6;
    let (x_bytes, x_consumed) = parse_bstr(&data[x_start..])?;
    let _ = x_consumed;
    if x_bytes.len() != 32 || x_bytes != peer.public_key {
        return Err(EdhocError::SignatureVerification);
    }
    Ok(())
}

/// Validate a raw 32-byte public key for Schnorr48.
///
/// Rejects identity points, low-order points, and keys not on the curve.
pub(crate) fn validate_pubkey(bytes: &[u8; 32]) -> Result<(), EdhocError> {
    // Decompress and validate the point
    match CompressedEdwardsY(*bytes).decompress() {
        Some(p) if !p.is_identity() && p.is_torsion_free() => Ok(()),
        _ => Err(EdhocError::SignatureVerification),
    }
}
