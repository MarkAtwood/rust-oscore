// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! OSCORE message unprotection (decryption).

use ccm::aead::{AeadInPlace, KeyInit};

use crate::error::BufferTooSmall;

use crate::context::Context;
use crate::crypto::{build_aad_cbor, compute_nonce, AesCcm};
use crate::error::OscoreError;
use crate::option::{find_payload_marker, parse_option};
use crate::seqnum::OscoreSeqNum;
use crate::types::TAG_LEN;

/// Authenticated response awaiting atomic replay-state acceptance.
///
/// Plaintext is intentionally inaccessible until [`PendingResponse::commit`]. Dropping this
/// value leaves the context unchanged, so transport acknowledgement failure remains retryable.
pub struct PendingResponse<'a> {
    context: &'a mut Context,
    request_seq: OscoreSeqNum,
    response_seq: Option<OscoreSeqNum>,
    code: u8,
    options: heapless::Vec<u8, 128>,
    payload: heapless::Vec<u8, 128>,
}

impl PendingResponse<'_> {
    /// Accept the request Partial IV exactly once and release the authenticated plaintext.
    pub fn commit(
        self,
    ) -> Result<(u8, heapless::Vec<u8, 128>, heapless::Vec<u8, 128>), OscoreError> {
        if !matches!(self.code >> 5, 2..=5) {
            return Err(OscoreError::InvalidParam);
        }
        if let Some(seq) = self.response_seq {
            self.context.update_replay_window(seq);
        }
        self.context.mark_received_response(self.request_seq);
        Ok((self.code, self.options, self.payload))
    }
}

impl Context {
    /// Unprotect (decrypt) an OSCORE-protected request.
    ///
    /// Returns (code, class_e_options, payload).
    pub fn unprotect_request(
        &mut self,
        oscore_option: &[u8],
        ciphertext: &[u8],
    ) -> Result<(u8, heapless::Vec<u8, 128>, heapless::Vec<u8, 128>), OscoreError> {
        if ciphertext.len() < TAG_LEN + 1 {
            return Err(OscoreError::InvalidParam);
        }

        // Parse OSCORE option
        let opt = parse_option(oscore_option)?;

        if opt.piv_len == 0 || !opt.kid_present {
            return Err(OscoreError::InvalidParam);
        }
        if &opt.kid[..opt.kid_len as usize] != self.recipient_id() {
            return Err(OscoreError::NoContext);
        }
        if opt.kid_context_present
            && (!self.id_context_present
                || opt.kid_context[..opt.kid_context_len as usize]
                    != self.id_context[..self.id_context_len as usize])
        {
            return Err(OscoreError::NoContext);
        }

        // SECURITY: Check replay BEFORE decryption, but update window AFTER.
        // This prevents attackers from poisoning the replay window with forged packets.
        let seq = OscoreSeqNum::from_piv(&opt.piv[..opt.piv_len as usize])
            .ok_or(OscoreError::InvalidParam)?;
        if self.is_replay(seq) {
            return Err(OscoreError::Replay);
        }

        // Compute nonce
        let nonce = compute_nonce(
            self.recipient_id(),
            &opt.piv[..opt.piv_len as usize],
            &self.common_iv,
        );

        // Build AAD per RFC 8613 Section 5.4 using sender's KID and PIV from request
        let mut aad_buf = [0u8; 64];
        let aad_len = build_aad_cbor(
            &opt.kid[..opt.kid_len as usize],
            &opt.piv[..opt.piv_len as usize],
            &mut aad_buf,
        )?;

        // Decrypt in place using detached API (works with plain slices, no Buffer trait needed)
        // Split ciphertext into encrypted data and tag
        let tag_start = ciphertext.len() - TAG_LEN;
        let tag = ccm::aead::Tag::<AesCcm>::from_slice(&ciphertext[tag_start..]);
        let cipher =
            AesCcm::new_from_slice(&self.recipient_key).map_err(|_| OscoreError::KeyDerivation)?;
        const PT_CAP: usize = 256;
        let mut plaintext = heapless::Vec::<u8, PT_CAP>::new();
        plaintext
            .extend_from_slice(&ciphertext[..tag_start])
            .map_err(|_| BufferTooSmall::new(tag_start, PT_CAP))?;
        cipher
            .decrypt_in_place_detached((&nonce).into(), &aad_buf[..aad_len], &mut plaintext, tag)
            .map_err(|_| OscoreError::DecryptFailed)?;

        // Parse plaintext: code || options || 0xFF || payload
        // 0xFF is the CoAP payload marker (RFC 7252 Section 3).
        if plaintext.is_empty() {
            return Err(OscoreError::InvalidParam);
        }

        let code = plaintext[0];
        let rest = &plaintext[1..];

        // Find payload marker using proper CoAP option parsing.
        // SECURITY: Cannot just search for 0xFF - it may appear in option values.
        // Must parse options with delta-length encoding to find the true marker.
        let (options_slice, payload_slice) = match find_payload_marker(rest)? {
            Some(pos) => (&rest[..pos], &rest[pos + 1..]),
            None => (rest, &[][..]),
        };

        const OUT_CAP: usize = 128;
        let mut options = heapless::Vec::<u8, OUT_CAP>::new();
        options
            .extend_from_slice(options_slice)
            .map_err(|_| BufferTooSmall::new(options_slice.len(), OUT_CAP))?;

        let mut payload = heapless::Vec::<u8, OUT_CAP>::new();
        payload
            .extend_from_slice(payload_slice)
            .map_err(|_| BufferTooSmall::new(payload_slice.len(), OUT_CAP))?;

        // Commit only after every authenticated output fits its public bound.
        self.update_replay_window(seq);

        Ok((code, options, payload))
    }

    /// Authenticate and parse an OSCORE-protected response without accepting its request PIV.
    ///
    /// Unlike `unprotect_request`, responses:
    /// - May omit PIV (use `request_piv` parameter for nonce if so)
    /// - Do not use the incoming request replay window
    /// - Use different AAD structure per RFC 8613 Section 5.4 (includes request_kid/request_piv)
    ///
    /// The returned capability does not expose plaintext. Call [`PendingResponse::commit`] only
    /// after any required transport acknowledgement succeeds. Dropping it changes no replay or
    /// response one-shot state.
    ///
    /// # Parameters
    /// - `oscore_option`: The OSCORE option from the response
    /// - `ciphertext`: The encrypted payload
    /// - `request_piv`: The PIV from the original request, used if response omits PIV
    pub fn begin_unprotect_response(
        &mut self,
        oscore_option: &[u8],
        ciphertext: &[u8],
        request_piv: &[u8],
    ) -> Result<PendingResponse<'_>, OscoreError> {
        if ciphertext.len() < TAG_LEN + 1 {
            return Err(OscoreError::InvalidParam);
        }

        // Parse OSCORE option
        let opt = parse_option(oscore_option)?;
        if opt.kid_context_present
            && (!self.id_context_present
                || opt.kid_context[..opt.kid_context_len as usize]
                    != self.id_context[..self.id_context_len as usize])
        {
            return Err(OscoreError::NoContext);
        }
        if opt.kid_present && &opt.kid[..opt.kid_len as usize] != self.recipient_id() {
            return Err(OscoreError::NoContext);
        }

        let request_seq = OscoreSeqNum::from_piv(request_piv).ok_or(OscoreError::InvalidParam)?;
        if self.is_received_response_reuse(request_seq) {
            return Err(OscoreError::Replay);
        }

        let piv = if opt.piv_len > 0 {
            &opt.piv[..opt.piv_len as usize]
        } else {
            request_piv
        };

        let response_seq = if opt.piv_len > 0 {
            let seq = OscoreSeqNum::from_piv(piv).ok_or(OscoreError::InvalidParam)?;
            if self.is_replay(seq) {
                return Err(OscoreError::Replay);
            }
            Some(seq)
        } else {
            None
        };

        let nonce_id = if opt.piv_len > 0 {
            self.recipient_id()
        } else {
            self.sender_id()
        };
        let nonce = compute_nonce(nonce_id, piv, &self.common_iv);

        let mut aad_buf = [0u8; 64];
        let aad_len = build_aad_cbor(self.sender_id(), request_piv, &mut aad_buf)?;

        let tag_start = ciphertext.len() - TAG_LEN;
        let tag = ccm::aead::Tag::<AesCcm>::from_slice(&ciphertext[tag_start..]);
        let cipher =
            AesCcm::new_from_slice(&self.recipient_key).map_err(|_| OscoreError::KeyDerivation)?;
        const PT_CAP: usize = 256;
        let mut plaintext = heapless::Vec::<u8, PT_CAP>::new();
        plaintext
            .extend_from_slice(&ciphertext[..tag_start])
            .map_err(|_| BufferTooSmall::new(tag_start, PT_CAP))?;
        cipher
            .decrypt_in_place_detached((&nonce).into(), &aad_buf[..aad_len], &mut plaintext, tag)
            .map_err(|_| OscoreError::DecryptFailed)?;

        if plaintext.is_empty() {
            return Err(OscoreError::InvalidParam);
        }

        let code = plaintext[0];
        if !matches!(code >> 5, 2..=5) {
            return Err(OscoreError::InvalidParam);
        }
        let rest = &plaintext[1..];

        // Find payload marker using proper CoAP option parsing.
        // SECURITY: Cannot just search for 0xFF - it may appear in option values.
        // Must parse options with delta-length encoding to find the true marker.
        let (options_slice, payload_slice) = match find_payload_marker(rest)? {
            Some(pos) => (&rest[..pos], &rest[pos + 1..]),
            None => (rest, &[][..]),
        };

        const OUT_CAP: usize = 128;
        let mut options = heapless::Vec::<u8, OUT_CAP>::new();
        options
            .extend_from_slice(options_slice)
            .map_err(|_| BufferTooSmall::new(options_slice.len(), OUT_CAP))?;

        let mut payload = heapless::Vec::<u8, OUT_CAP>::new();
        payload
            .extend_from_slice(payload_slice)
            .map_err(|_| BufferTooSmall::new(payload_slice.len(), OUT_CAP))?;

        Ok(PendingResponse {
            context: self,
            request_seq,
            response_seq,
            code,
            options,
            payload,
        })
    }

    /// Unprotect and immediately accept an ordinary OSCORE response.
    pub fn unprotect_response(
        &mut self,
        oscore_option: &[u8],
        ciphertext: &[u8],
        request_piv: &[u8],
    ) -> Result<(u8, heapless::Vec<u8, 128>, heapless::Vec<u8, 128>), OscoreError> {
        self.begin_unprotect_response(oscore_option, ciphertext, request_piv)?
            .commit()
    }
}
