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

/// TH_2 = H(CBOR(G_Y) || CBOR(H(message_1))) (RFC 9528 Section 5.3.2).
pub(crate) fn transcript_2(g_y: &[u8], msg1: &[u8]) -> Result<[u8; 32], EdhocError> {
    let h_msg1 = compute_th(msg1);
    let mut buf = heapless::Vec::<u8, 256>::new();
    encode_bstr(&mut buf, g_y)?;
    encode_bstr(&mut buf, &h_msg1)?;
    Ok(compute_th(&buf))
}

/// TH_3 = H(CBOR(TH_2) || CBOR(PLAINTEXT_2) || CRED_R).
pub(crate) fn transcript_3(
    th_2: &[u8; 32],
    input: &[u8],
    cred: &[u8],
) -> Result<[u8; 32], EdhocError> {
    let mut buf = heapless::Vec::<u8, 1024>::new();
    encode_bstr(&mut buf, th_2)?;
    encode_bstr(&mut buf, input)?;
    buf.extend_from_slice(cred)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    Ok(compute_th(&buf))
}

/// TH_4 = H(CBOR(TH_3) || CBOR(PLAINTEXT_3) || CRED_I).
pub(crate) fn transcript_4(
    th_3: &[u8; 32],
    plaintext_3: &[u8],
    cred_i: &[u8],
) -> Result<[u8; 32], EdhocError> {
    let mut buf = heapless::Vec::<u8, 1024>::new();
    encode_bstr(&mut buf, th_3)?;
    encode_bstr(&mut buf, plaintext_3)?;
    buf.extend_from_slice(cred_i)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    Ok(compute_th(&buf))
}

pub(crate) fn build_context_2(
    c_r: &ConnectionId,
    id_cred: &[u8],
    th: &[u8; 32],
    cred: &[u8],
) -> Result<heapless::Vec<u8, 128>, EdhocError> {
    let mut ctx = heapless::Vec::<u8, 128>::new();
    encode_identifier(&mut ctx, c_r)?;
    ctx.extend_from_slice(id_cred)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    encode_bstr(&mut ctx, th)?;
    ctx.extend_from_slice(cred)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    Ok(ctx)
}

pub(crate) fn build_context_3(
    id_cred: &[u8],
    th: &[u8; 32],
    cred: &[u8],
) -> Result<heapless::Vec<u8, 128>, EdhocError> {
    let mut ctx = heapless::Vec::<u8, 128>::new();
    ctx.extend_from_slice(id_cred)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    encode_bstr(&mut ctx, th)?;
    ctx.extend_from_slice(cred)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    Ok(ctx)
}

pub(crate) fn build_signature_structure(
    id_cred: &[u8],
    th: &[u8; 32],
    cred: &[u8],
    mac: &[u8],
) -> Result<heapless::Vec<u8, 160>, EdhocError> {
    let mut m = heapless::Vec::<u8, 160>::new();
    m.push_err(0x84)?;
    m.extend_err(b"\x6aSignature1")?;
    append_cbor_bstr(&mut m, id_cred)?;
    let mut external_aad = heapless::Vec::<u8, 128>::new();
    encode_bstr(&mut external_aad, th)?;
    external_aad
        .extend_from_slice(cred)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    append_cbor_bstr(&mut m, &external_aad)?;
    append_cbor_bstr(&mut m, mac)?;
    Ok(m)
}
