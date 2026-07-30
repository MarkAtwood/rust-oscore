// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! EDHOC transcript hash computation.

use super::EdhocError;
use super::cbor::{append_cbor_bstr, encode_bstr, encode_identifier};
use super::types::{ConnectionId, VecExt};
use sha2::{Digest, Sha256};

/// Compute transcript hash: H(input).
pub(crate) fn compute_th(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// TH_2 = H(CBOR(G_Y) || encode_connection_id(C_R) || CBOR(H(message_1))).
pub(crate) fn transcript_2(
    g_y: &[u8],
    c_r: &ConnectionId,
    msg1: &[u8],
) -> Result<[u8; 32], EdhocError> {
    let h_msg1 = compute_th(msg1);
    let mut buf = heapless::Vec::<u8, 256>::new();
    encode_bstr(&mut buf, g_y)?;
    encode_identifier(&mut buf, c_r)?;
    encode_bstr(&mut buf, &h_msg1)?;
    Ok(compute_th(&buf))
}

/// TH_3 = H(CBOR(TH_2) || input || CBOR(cred)).
pub(crate) fn transcript_3(
    th_2: &[u8; 32],
    input: &[u8],
    cred: &[u8],
) -> Result<[u8; 32], EdhocError> {
    let mut buf = heapless::Vec::<u8, 1024>::new();
    encode_bstr(&mut buf, th_2)?;
    buf.extend_from_slice(input)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    encode_bstr(&mut buf, cred)?;
    Ok(compute_th(&buf))
}

pub(crate) fn transcript_4(
    th_3: &[u8; 32],
    plaintext_3: &[u8],
    cred_r: &[u8],
) -> Result<[u8; 32], EdhocError> {
    let mut buf = heapless::Vec::<u8, 1024>::new();
    encode_bstr(&mut buf, th_3)?;
    buf.extend_from_slice(plaintext_3)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    encode_bstr(&mut buf, cred_r)?;
    Ok(compute_th(&buf))
}

pub(crate) fn build_context_2(
    c_r: &ConnectionId,
    id_cred: &[u8],
    cred: &[u8],
) -> Result<heapless::Vec<u8, 128>, EdhocError> {
    let mut ctx = heapless::Vec::<u8, 128>::new();
    encode_identifier(&mut ctx, c_r)?;
    append_cbor_bstr(&mut ctx, id_cred)?;
    append_cbor_bstr(&mut ctx, cred)?;
    Ok(ctx)
}

pub(crate) fn build_context_3(
    id_cred: &[u8],
    _th: &[u8; 32],
    cred: &[u8],
) -> Result<heapless::Vec<u8, 128>, EdhocError> {
    let mut ctx = heapless::Vec::<u8, 128>::new();
    append_cbor_bstr(&mut ctx, id_cred)?;
    append_cbor_bstr(&mut ctx, cred)?;
    Ok(ctx)
}

pub(crate) fn build_signature_structure(
    id_cred: &[u8],
    th: &[u8; 32],
    cred: &[u8],
    mac: &[u8],
) -> Result<heapless::Vec<u8, 160>, EdhocError> {
    let mut m = heapless::Vec::<u8, 160>::new();
    m.push_err(0x85)?;
    m.extend_err(b"\x6bSignature1")?;
    append_cbor_bstr(&mut m, id_cred)?;
    append_cbor_bstr(&mut m, th)?;
    append_cbor_bstr(&mut m, cred)?;
    append_cbor_bstr(&mut m, mac)?;
    Ok(m)
}
