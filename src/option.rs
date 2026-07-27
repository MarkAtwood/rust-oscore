// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! OSCORE option parsing and validation.

use crate::error::OscoreError;
use crate::seqnum::OscoreSeqNum;
use crate::types::{
    RequestIdentifiers, ID_CONTEXT_CAPACITY, ID_MAX_LEN, NONCE_ID_LEN, PIV_MAX_LEN,
};

/// Parsed OSCORE option.
#[derive(Debug)]
pub(crate) struct OscoreOption {
    pub(crate) piv: [u8; PIV_MAX_LEN],
    pub(crate) piv_len: u8,
    pub(crate) kid_context: [u8; ID_CONTEXT_CAPACITY],
    pub(crate) kid_context_len: u8,
    pub(crate) kid_context_present: bool,
    pub(crate) kid: [u8; ID_MAX_LEN],
    pub(crate) kid_len: u8,
    pub(crate) kid_present: bool,
}

/// Validate an encoded OSCORE option without requiring an OSCORE context.
pub fn validate_option(data: &[u8]) -> Result<(), OscoreError> {
    parse_option(data).map(|_| ())
}

/// Parse the KID and Partial IV required to protect a response.
pub fn request_identifiers(data: &[u8]) -> Result<RequestIdentifiers, OscoreError> {
    let option = parse_option(data)?;
    if !option.kid_present || option.piv_len == 0 {
        return Err(OscoreError::InvalidParam);
    }
    Ok(RequestIdentifiers {
        kid: option.kid,
        kid_len: option.kid_len,
        piv: option.piv,
        piv_len: option.piv_len,
    })
}

pub(crate) fn parse_option(data: &[u8]) -> Result<OscoreOption, OscoreError> {
    let mut opt = OscoreOption {
        piv: [0; PIV_MAX_LEN],
        piv_len: 0,
        kid_context: [0; ID_CONTEXT_CAPACITY],
        kid_context_len: 0,
        kid_context_present: false,
        kid: [0; ID_MAX_LEN],
        kid_len: 0,
        kid_present: false,
    };

    if data.is_empty() {
        return Ok(opt);
    }
    if data == [0] {
        return Err(OscoreError::InvalidParam);
    }

    let mut pos = 0;
    let flags = data[pos];
    pos += 1;

    if flags & 0xe0 != 0 {
        return Err(OscoreError::InvalidParam);
    }

    let h_flag = flags & 0x10 != 0;
    let k_flag = flags & 0x08 != 0;
    let n = (flags & 0x07) as usize;

    // PIV
    if n > 0 {
        if n > PIV_MAX_LEN || pos + n > data.len() {
            return Err(OscoreError::InvalidParam);
        }
        opt.piv[..n].copy_from_slice(&data[pos..pos + n]);
        if OscoreSeqNum::from_piv(&opt.piv[..n]).is_none() {
            return Err(OscoreError::InvalidParam);
        }
        opt.piv_len = n as u8;
        pos += n;
    }

    // KID Context
    if h_flag {
        if pos >= data.len() {
            return Err(OscoreError::InvalidParam);
        }
        let s = data[pos] as usize;
        pos += 1;
        if s > opt.kid_context.len() || pos + s > data.len() {
            return Err(OscoreError::InvalidParam);
        }
        opt.kid_context[..s].copy_from_slice(&data[pos..pos + s]);
        opt.kid_context_len = s as u8;
        opt.kid_context_present = true;
        pos += s;
    }

    // KID
    if k_flag {
        opt.kid_present = true;
        let remaining = data.len() - pos;
        if remaining > NONCE_ID_LEN {
            return Err(OscoreError::InvalidParam);
        }
        opt.kid[..remaining].copy_from_slice(&data[pos..]);
        opt.kid_len = remaining as u8;
    } else if pos != data.len() {
        return Err(OscoreError::InvalidParam);
    }

    Ok(opt)
}

/// Split an inner CoAP body into encoded options and payload.
pub(crate) fn parse_inner_body(data: &[u8]) -> Result<(&[u8], &[u8]), OscoreError> {
    let mut pos = 0usize;
    let mut option_number = 0u16;

    while pos < data.len() {
        let option_start = pos;
        let header = data[pos];
        pos = pos.checked_add(1).ok_or(OscoreError::InvalidParam)?;

        if header == 0xff {
            if pos == data.len() {
                return Err(OscoreError::InvalidParam);
            }
            return Ok((&data[..option_start], &data[pos..]));
        }

        let mut decode_nibble = |nibble: u8| -> Result<usize, OscoreError> {
            match nibble {
                0..=12 => Ok(nibble as usize),
                13 => {
                    let value = *data.get(pos).ok_or(OscoreError::InvalidParam)? as usize;
                    pos = pos.checked_add(1).ok_or(OscoreError::InvalidParam)?;
                    13usize.checked_add(value).ok_or(OscoreError::InvalidParam)
                }
                14 => {
                    let end = pos.checked_add(2).ok_or(OscoreError::InvalidParam)?;
                    let bytes = data.get(pos..end).ok_or(OscoreError::InvalidParam)?;
                    pos = end;
                    let value = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
                    269usize.checked_add(value).ok_or(OscoreError::InvalidParam)
                }
                15 => Err(OscoreError::InvalidParam),
                _ => unreachable!(),
            }
        };

        let delta = decode_nibble(header >> 4)?;
        let length = decode_nibble(header & 0x0f)?;
        let delta = u16::try_from(delta).map_err(|_| OscoreError::InvalidParam)?;
        option_number = option_number
            .checked_add(delta)
            .ok_or(OscoreError::InvalidParam)?;

        let end = pos.checked_add(length).ok_or(OscoreError::InvalidParam)?;
        if end > data.len() {
            return Err(OscoreError::InvalidParam);
        }
        pos = end;
    }

    Ok((data, &[]))
}

/// Parse CoAP options to find the payload marker position.
///
/// CoAP options use delta-length encoding (RFC 7252 Section 3.1):
/// - First byte: upper nibble = delta (0-12 direct, 13=+1 byte, 14=+2 bytes, 15=reserved)
/// - First byte: lower nibble = length (same encoding)
/// - 0xFF (delta=15, length=15) is the payload marker
///
/// Returns the byte index of the payload marker (0xFF) if present, or None if no payload.
/// This correctly handles 0xFF appearing inside option VALUES (not as a delta-length byte).
pub(crate) fn find_payload_marker(options_and_payload: &[u8]) -> Result<Option<usize>, OscoreError> {
    let mut pos = 0;
    let mut cumulative_number: u16 = 0;

    while pos < options_and_payload.len() {
        let first = options_and_payload[pos];

        // 0xFF as a delta-length byte means payload marker
        if first == 0xFF {
            return Ok(Some(pos));
        }

        let delta_nibble = (first >> 4) & 0x0F;
        let len_nibble = first & 0x0F;

        if delta_nibble == 15 {
            return Err(OscoreError::InvalidParam);
        }
        if len_nibble == 15 {
            return Err(OscoreError::InvalidParam);
        }

        // Skip past first byte
        pos += 1;

        // Parse extended delta bytes
        let delta: u16 = match delta_nibble {
            0..=12 => delta_nibble as u16,
            13 => {
                if pos >= options_and_payload.len() {
                    return Err(OscoreError::InvalidParam);
                }
                let d = options_and_payload[pos] as u16 + 13;
                pos += 1;
                d
            }
            14 => {
                if pos + 1 >= options_and_payload.len() {
                    return Err(OscoreError::InvalidParam);
                }
                let d = ((options_and_payload[pos] as u16) << 8
                    | options_and_payload[pos + 1] as u16)
                    + 269;
                pos += 2;
                d
            }
            _ => unreachable!(),
        };

        cumulative_number = cumulative_number
            .checked_add(delta)
            .ok_or(OscoreError::InvalidParam)?;

        // Determine option length
        let opt_len = match len_nibble {
            0..=12 => len_nibble as usize,
            13 => {
                if pos >= options_and_payload.len() {
                    return Err(OscoreError::InvalidParam);
                }
                let ext = options_and_payload[pos] as usize + 13;
                pos += 1;
                ext
            }
            14 => {
                if pos + 1 >= options_and_payload.len() {
                    return Err(OscoreError::InvalidParam);
                }
                let ext = ((options_and_payload[pos] as usize) << 8)
                    | (options_and_payload[pos + 1] as usize);
                pos += 2;
                ext + 269
            }
            _ => unreachable!(),
        };

        // Validate option value is fully present
        if pos.checked_add(opt_len).ok_or(OscoreError::InvalidParam)? > options_and_payload.len() {
            return Err(OscoreError::InvalidParam);
        }
        pos += opt_len;
    }

    // No payload marker found
    Ok(None)
}
