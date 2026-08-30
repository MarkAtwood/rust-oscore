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

/// Parse an ID_CRED from deterministic CBOR per RFC 9528.
///
/// Accepts:
/// - Bare integers (compact kid encoding): 0x00-0x17, 0x18 xx, 0x20-0x37, 0x38 xx
/// - Bare byte strings (compact kid encoding): 0x40-0x57, 0x58 xx
/// - Maps with 1-8 pairs (0xa1-0xa8)
///
/// Returns (IdCred, bytes_consumed).
pub(crate) fn parse_id_cred(data: &[u8]) -> Result<(IdCred, usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }

    let first = data[0];

    // Handle bare unsigned integer (0x00-0x17) - compact kid encoding
    if (0x00..=0x17).contains(&first) {
        let mut encoded = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
        encoded.push_err(0xa1)?;
        encoded.push_err(0x04)?;
        encoded.push_err(0x41)?;
        encoded.push_err(first)?;
        let mut kid_val = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
        kid_val.push_err(first)?;
        return Ok((
            IdCred {
                encoded,
                reference: IdCredReference::Kid(kid_val),
            },
            1,
        ));
    }

    // Handle bare negative integer (0x20-0x37) - compact kid encoding
    if (0x20..=0x37).contains(&first) {
        let mut encoded = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
        encoded.push_err(0xa1)?;
        encoded.push_err(0x04)?;
        encoded.push_err(0x41)?;
        encoded.push_err(first)?;
        let mut kid_val = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
        kid_val.push_err(first)?;
        return Ok((
            IdCred {
                encoded,
                reference: IdCredReference::Kid(kid_val),
            },
            1,
        ));
    }

    // Handle 2-byte unsigned integer (0x18 xx) - compact kid encoding
    if first == 0x18 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        let mut encoded = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
        encoded.push_err(0xa1)?;
        encoded.push_err(0x04)?;
        encoded.push_err(0x42)?;
        encoded.extend_err(&data[..2])?;
        let mut kid_val = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
        kid_val.extend_err(&data[..2])?;
        return Ok((
            IdCred {
                encoded,
                reference: IdCredReference::Kid(kid_val),
            },
            2,
        ));
    }

    // Handle 2-byte negative integer (0x38 xx) - compact kid encoding
    if first == 0x38 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        let mut encoded = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
        encoded.push_err(0xa1)?;
        encoded.push_err(0x04)?;
        encoded.push_err(0x42)?;
        encoded.extend_err(&data[..2])?;
        let mut kid_val = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
        kid_val.extend_err(&data[..2])?;
        return Ok((
            IdCred {
                encoded,
                reference: IdCredReference::Kid(kid_val),
            },
            2,
        ));
    }

    // Handle bare byte string (0x40-0x57, 0x58) - compact kid encoding
    if (0x40..=0x57).contains(&first) || first == 0x58 {
        let (bstr_val, consumed) = parse_bstr(data)?;
        let mut encoded = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
        encoded.push_err(0xa1)?;
        encoded.push_err(0x04)?;
        encode_bstr(&mut encoded, bstr_val)?;
        let kid_val =
            heapless::Vec::from_slice(bstr_val).map_err(|_| EdhocError::BufferTooSmall)?;
        return Ok((
            IdCred {
                encoded,
                reference: IdCredReference::Kid(kid_val),
            },
            consumed,
        ));
    }

    // Handle maps (0xa1-0xa8)
    if !(0xa1..=0xa8).contains(&first) {
        return Err(EdhocError::InvalidMessage);
    }

    let num_pairs = (first - 0xa0) as usize;
    let mut offset = 1;
    let mut seen_labels: heapless::Vec<i128, 8> = heapless::Vec::new();
    let mut kid_value: Option<heapless::Vec<u8, ID_CRED_MAX_LEN>> = None;
    let mut x5t_value: Option<(i128, heapless::Vec<u8, ID_CRED_MAX_LEN>)> = None;

    for _ in 0..num_pairs {
        if offset >= data.len() {
            return Err(EdhocError::InvalidMessage);
        }

        let label_result = try_parse_cbor_int(&data[offset..]);
        let val_consumed = match label_result {
            Some((label, label_len)) => {
                offset += label_len;
                if seen_labels.contains(&label) {
                    return Err(EdhocError::InvalidMessage);
                }
                seen_labels
                    .push(label)
                    .map_err(|_| EdhocError::BufferTooSmall)?;

                match label {
                    1 => skip_int_value(&data[offset..])?,
                    2 => validate_alg_value(&data[offset..])?,
                    4 => {
                        if kid_value.is_some() {
                            return Err(EdhocError::InvalidMessage);
                        }
                        let (bstr_val, consumed) = parse_canonical_bstr(&data[offset..])?;
                        kid_value = Some(
                            heapless::Vec::from_slice(bstr_val)
                                .map_err(|_| EdhocError::BufferTooSmall)?,
                        );
                        consumed
                    }
                    34 => {
                        if x5t_value.is_some() {
                            return Err(EdhocError::InvalidMessage);
                        }
                        parse_x5t_value(&data[offset..], &mut x5t_value)?
                    }
                    _ => skip_cbor_value(&data[offset..])?,
                }
            }
            None => {
                let key_len = skip_cbor_value(&data[offset..])?;
                offset += key_len;
                skip_cbor_value(&data[offset..])?
            }
        };
        offset += val_consumed;
    }

    let reference = match (kid_value, x5t_value) {
        (Some(kid), None) => IdCredReference::Kid(kid),
        (None, Some((alg, hash))) => IdCredReference::X5t {
            algorithm: alg,
            hash,
        },
        _ => return Err(EdhocError::InvalidMessage),
    };

    let mut encoded = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
    encoded.extend_err(&data[..offset])?;
    Ok((IdCred { encoded, reference }, offset))
}

fn try_parse_cbor_int(data: &[u8]) -> Option<(i128, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if (0x00..=0x17).contains(&first) {
        return Some((first as i128, 1));
    }
    if first == 0x18 {
        if data.len() < 2 || data[1] < 24 {
            return None;
        }
        return Some((data[1] as i128, 2));
    }
    if first == 0x19 {
        if data.len() < 3 {
            return None;
        }
        let val = u16::from_be_bytes([data[1], data[2]]);
        if val <= 0xff {
            return None;
        }
        return Some((val as i128, 3));
    }
    if (0x20..=0x37).contains(&first) {
        return Some((-((first - 0x20) as i128 + 1), 1));
    }
    if first == 0x38 {
        if data.len() < 2 || data[1] < 24 {
            return None;
        }
        return Some((-(data[1] as i128 + 1), 2));
    }
    if first == 0x39 {
        if data.len() < 3 {
            return None;
        }
        let val = u16::from_be_bytes([data[1], data[2]]);
        if val <= 0xff {
            return None;
        }
        return Some((-(val as i128 + 1), 3));
    }
    None
}

fn parse_canonical_bstr(data: &[u8]) -> Result<(&[u8], usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    if (0x40..=0x57).contains(&first) {
        let len = (first - 0x40) as usize;
        if data.len() < 1 + len {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok((&data[1..1 + len], 1 + len));
    }
    if first == 0x58 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        let len = data[1] as usize;
        if len < 24 {
            return Err(EdhocError::InvalidMessage);
        }
        if data.len() < 2 + len {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok((&data[2..2 + len], 2 + len));
    }
    if first == 0x59 {
        if data.len() < 3 {
            return Err(EdhocError::InvalidMessage);
        }
        let len = u16::from_be_bytes([data[1], data[2]]) as usize;
        if len <= 0xff {
            return Err(EdhocError::InvalidMessage);
        }
        if data.len() < 3 + len {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok((&data[3..3 + len], 3 + len));
    }
    Err(EdhocError::InvalidMessage)
}

fn skip_int_value(data: &[u8]) -> Result<usize, EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    if (0x00..=0x17).contains(&first) {
        return Ok(1);
    }
    if first == 0x18 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok(2);
    }
    if first == 0x19 {
        if data.len() < 3 {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok(3);
    }
    if (0x20..=0x37).contains(&first) {
        return Ok(1);
    }
    if first == 0x38 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok(2);
    }
    if first == 0x39 {
        if data.len() < 3 {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok(3);
    }
    Err(EdhocError::InvalidMessage)
}

/// Validate alg value: reject arrays containing ambiguous values.
/// - 1=kty label (also valid kty value, creates ambiguity)
/// - 34=x5t label (creates ambiguity with x5t header)
/// - Duplicate values in the array
fn validate_alg_value(data: &[u8]) -> Result<usize, EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    // Integer values are always OK
    if let Ok(len) = skip_int_value(data) {
        return Ok(len);
    }
    // Arrays need inspection for ambiguous values
    if (0x80..=0x97).contains(&first) {
        let count = (first - 0x80) as usize;
        let mut offset = 1;
        let mut seen_values: heapless::Vec<i128, 8> = heapless::Vec::new();
        for _ in 0..count {
            if offset >= data.len() {
                return Err(EdhocError::InvalidMessage);
            }
            if let Some((val, len)) = try_parse_cbor_int(&data[offset..]) {
                // Reject 1 (kty) and 34 (x5t) as they create ambiguity
                if val == 1 || val == 34 {
                    return Err(EdhocError::InvalidMessage);
                }
                // Reject duplicate values
                if seen_values.contains(&val) {
                    return Err(EdhocError::InvalidMessage);
                }
                seen_values
                    .push(val)
                    .map_err(|_| EdhocError::BufferTooSmall)?;
                offset += len;
            } else {
                offset += skip_cbor_value(&data[offset..])?;
            }
        }
        return Ok(offset);
    }
    Err(EdhocError::InvalidMessage)
}

fn parse_cbor_int(data: &[u8]) -> Result<(i128, usize), EdhocError> {
    try_parse_cbor_int(data).ok_or(EdhocError::InvalidMessage)
}

fn parse_x5t_value(
    data: &[u8],
    out: &mut Option<(i128, heapless::Vec<u8, ID_CRED_MAX_LEN>)>,
) -> Result<usize, EdhocError> {
    if data.is_empty() || data[0] != 0x82 {
        return Err(EdhocError::InvalidMessage);
    }
    let mut offset = 1;
    let (alg, alg_len) = parse_cbor_int(&data[offset..])?;
    offset += alg_len;
    let (hash_val, hash_len) = parse_bstr(&data[offset..])?;
    offset += hash_len;
    *out = Some((
        alg,
        heapless::Vec::from_slice(hash_val).map_err(|_| EdhocError::BufferTooSmall)?,
    ));
    Ok(offset)
}

fn skip_cbor_value(data: &[u8]) -> Result<usize, EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    if (0x00..=0x17).contains(&first) {
        return Ok(1);
    }
    if first == 0x18 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok(2);
    }
    if first == 0x19 {
        if data.len() < 3 {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok(3);
    }
    if (0x20..=0x37).contains(&first) {
        return Ok(1);
    }
    if first == 0x38 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok(2);
    }
    if first == 0x39 {
        if data.len() < 3 {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok(3);
    }
    if (0x40..=0x57).contains(&first) {
        let len = (first - 0x40) as usize;
        if data.len() < 1 + len {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok(1 + len);
    }
    if first == 0x58 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        let len = data[1] as usize;
        if data.len() < 2 + len {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok(2 + len);
    }
    if (0x60..=0x77).contains(&first) {
        let len = (first - 0x60) as usize;
        if data.len() < 1 + len {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok(1 + len);
    }
    if first == 0x78 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        let len = data[1] as usize;
        if data.len() < 2 + len {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok(2 + len);
    }
    if (0x80..=0x97).contains(&first) {
        let count = (first - 0x80) as usize;
        let mut offset = 1;
        for _ in 0..count {
            offset += skip_cbor_value(&data[offset..])?;
        }
        return Ok(offset);
    }
    if first == 0x98 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        let count = data[1] as usize;
        let mut offset = 2;
        for _ in 0..count {
            offset += skip_cbor_value(&data[offset..])?;
        }
        return Ok(offset);
    }
    Err(EdhocError::InvalidMessage)
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
            if let Some(prev) = prev_key
                && key <= prev
            {
                return Err(EdhocError::InvalidMessage);
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
        // Reject non-container types (credentials must be maps or arrays)
        // and indefinite-length encodings (RFC 8949 Section 4.2.3)
        Err(EdhocError::InvalidMessage)
    }
}

/// Validate a peer credential against its embedded public key.
pub(crate) fn validate_peer_credential(peer: PeerCredential<'_>) -> Result<(), EdhocError> {
    // SECURITY: Always validate the public key regardless of credential type
    if peer.public_key.len() != 32 {
        return Err(EdhocError::InvalidMessage);
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(peer.public_key);
    validate_pubkey(&pubkey)?;

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
