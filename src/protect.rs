// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! OSCORE message protection (encryption).

use ccm::aead::{AeadInPlace, KeyInit};

use crate::error::BufferTooSmall;

use crate::context::Context;
use crate::crypto::{build_aad_cbor, compute_nonce, AesCcm};
use crate::error::{OscoreError, ReservationError};
use crate::option::parse_inner_body;
use crate::seqnum::OscoreSeqNum;
use crate::types::{
    SenderSequenceState, SenderStateStore, NONCE_ID_LEN, OSCORE_OPTION_MAX_LEN, PIV_MAX_LEN,
    TAG_LEN,
};

#[cfg(test)]
pub(crate) enum Construction {
    Fresh,
    Ephemeral,
    Stored(SenderSequenceState),
}

/// Exclusive, one-use capability for sender-sequence encryption.
pub struct ReservedSender<'a> {
    pub(crate) context: &'a mut Context,
    pub(crate) sequence: OscoreSeqNum,
}

impl ReservedSender<'_> {
    /// Protect a request using this durably reserved sender sequence.
    pub fn protect_request(
        self,
        code: u8,
        class_e_options: &[u8],
        payload: &[u8],
    ) -> Result<
        (
            heapless::Vec<u8, 280>,
            heapless::Vec<u8, OSCORE_OPTION_MAX_LEN>,
        ),
        OscoreError,
    > {
        self.context
            .protect_request_reserved(self.sequence, code, class_e_options, payload)
    }

    /// Protect a response with a fresh, durably reserved sender PIV.
    pub fn protect_response_with_piv(
        self,
        code: u8,
        class_e_options: &[u8],
        payload: &[u8],
        request_kid: &[u8],
        request_piv: &[u8],
    ) -> Result<
        (
            heapless::Vec<u8, 280>,
            heapless::Vec<u8, OSCORE_OPTION_MAX_LEN>,
        ),
        OscoreError,
    > {
        self.context.protect_response_with_reserved_piv(
            self.sequence,
            code,
            class_e_options,
            payload,
            request_kid,
            request_piv,
        )
    }
}

impl Context {
    /// Atomically reserve the next sender sequence in durable storage.
    ///
    /// Storage advances before this returns, so a crash can only skip the reserved
    /// sequence. A competing context restored from the same state receives
    /// [`ReservationError::Conflict`] and cannot encrypt with that sequence.
    pub fn reserve_sender<S: SenderStateStore>(
        &mut self,
        store: &mut S,
    ) -> Result<ReservedSender<'_>, ReservationError<S::Error>> {
        if !self.active {
            return Err(ReservationError::Conflict);
        }
        if self.sender_seq_exhausted {
            return Err(ReservationError::SequenceExhausted);
        }

        let sequence = self.sender_seq;
        let expected = self.sender_sequence_state();
        let next = match sequence.increment() {
            Some(next) => SenderSequenceState {
                next_sequence: next.get(),
                exhausted: false,
            },
            None => SenderSequenceState {
                next_sequence: OscoreSeqNum::MAX,
                exhausted: true,
            },
        };

        if !store
            .compare_exchange(&self.context_id, Some(expected), next)
            .map_err(ReservationError::Storage)?
        {
            return Err(ReservationError::Conflict);
        }

        self.sender_seq = OscoreSeqNum::new(next.next_sequence).expect("validated sequence");
        self.sender_seq_exhausted = next.exhausted;
        Ok(ReservedSender {
            context: self,
            sequence,
        })
    }

    /// Check that request protection can fit all bounded outputs before reserving a PIV.
    pub fn preflight_protect_request(
        &self,
        class_e_options: &[u8],
        payload: &[u8],
    ) -> Result<(), OscoreError> {
        if !self.active {
            return Err(OscoreError::InvalidParam);
        }
        const RECEIVER_OUTPUT_CAP: usize = 128;
        if class_e_options.len() > RECEIVER_OUTPUT_CAP {
            return Err(BufferTooSmall::new(class_e_options.len(), RECEIVER_OUTPUT_CAP).into());
        }
        if payload.len() > RECEIVER_OUTPUT_CAP {
            return Err(BufferTooSmall::new(payload.len(), RECEIVER_OUTPUT_CAP).into());
        }

        let required = 1usize
            .checked_add(class_e_options.len())
            .and_then(|n| n.checked_add(usize::from(!payload.is_empty())))
            .and_then(|n| n.checked_add(payload.len()))
            .and_then(|n| n.checked_add(TAG_LEN))
            .ok_or(OscoreError::InvalidParam)?;
        if required > 280 {
            return Err(BufferTooSmall::new(required, 280).into());
        }

        let option_required = 1
            + PIV_MAX_LEN
            + usize::from(self.id_context_present) * (1 + self.id_context_len as usize)
            + self.sender_id_len as usize;
        if option_required > OSCORE_OPTION_MAX_LEN {
            return Err(BufferTooSmall::new(option_required, OSCORE_OPTION_MAX_LEN).into());
        }
        Ok(())
    }

    /// Exact OSCORE option length for the next request sender reservation.
    pub fn next_request_option_len(&self) -> Result<usize, OscoreError> {
        if !self.active || self.sender_seq_exhausted {
            return Err(OscoreError::SeqExhausted);
        }
        let mut piv = [0u8; PIV_MAX_LEN];
        let piv_len = self.sender_seq.encode_piv(&mut piv);
        Ok(1 + piv_len
            + usize::from(self.id_context_present) * (1 + self.id_context_len as usize)
            + self.sender_id_len as usize)
    }

    /// Check that response protection can fit all bounded outputs before reserving a PIV.
    pub fn preflight_protect_response(
        &self,
        class_e_options: &[u8],
        payload: &[u8],
        request_kid: &[u8],
        request_piv: &[u8],
    ) -> Result<(), OscoreError> {
        if !self.active
            || request_kid.len() > NONCE_ID_LEN
            || request_kid != self.recipient_id()
            || OscoreSeqNum::from_piv(request_piv).is_none()
        {
            return Err(OscoreError::InvalidParam);
        }
        const RECEIVER_OUTPUT_CAP: usize = 128;
        if class_e_options.len() > RECEIVER_OUTPUT_CAP {
            return Err(BufferTooSmall::new(class_e_options.len(), RECEIVER_OUTPUT_CAP).into());
        }
        if payload.len() > RECEIVER_OUTPUT_CAP {
            return Err(BufferTooSmall::new(payload.len(), RECEIVER_OUTPUT_CAP).into());
        }
        let (parsed_options, parsed_payload) = parse_inner_body(class_e_options)?;
        if parsed_options != class_e_options || !parsed_payload.is_empty() {
            return Err(OscoreError::InvalidParam);
        }
        let required = 1usize
            .checked_add(class_e_options.len())
            .and_then(|n| n.checked_add(usize::from(!payload.is_empty())))
            .and_then(|n| n.checked_add(payload.len()))
            .and_then(|n| n.checked_add(TAG_LEN))
            .ok_or(OscoreError::InvalidParam)?;
        if required > 280 {
            return Err(BufferTooSmall::new(required, 280).into());
        }
        Ok(())
    }

    /// Protect (encrypt) a CoAP request.
    ///
    /// Returns (ciphertext, OSCORE option value).
    ///
    /// # Errors
    ///
    /// Returns `SeqExhausted` when the sender sequence number reaches the 40-bit maximum.
    /// The security context must be renegotiated before this happens to prevent
    /// nonce reuse (RFC 8613 Section 7.2.1).
    pub(crate) fn protect_request_reserved(
        &mut self,
        seq: OscoreSeqNum,
        code: u8,
        class_e_options: &[u8],
        payload: &[u8],
    ) -> Result<
        (
            heapless::Vec<u8, 280>,
            heapless::Vec<u8, OSCORE_OPTION_MAX_LEN>,
        ),
        OscoreError,
    > {
        // Use pre-reserved sequence number (NVM persistence handled by caller
        // or ReservedSender). SECURITY: SeqExhausted already checked by caller.

        // Encode PIV
        let mut piv = [0u8; PIV_MAX_LEN];
        let piv_len = seq.encode_piv(&mut piv);

        // Compute nonce
        let nonce = compute_nonce(self.sender_id(), &piv[..piv_len], &self.common_iv);

        // Build plaintext directly in ct_out: code || options || 0xFF || payload
        // 0xFF is the CoAP payload marker (RFC 7252 Section 3): it separates
        // the options from the payload and is only present when payload is non-empty.
        // ponytail: empty AAD for now, proper AAD structure in RFC 8613 Section 5.4
        let cipher =
            AesCcm::new_from_slice(&self.sender_key).map_err(|_| OscoreError::KeyDerivation)?;
        const CT_CAP: usize = 280;
        let mut ct_out = heapless::Vec::<u8, CT_CAP>::new();
        // Calculate required size for error reporting
        let ct_required = 1
            + class_e_options.len()
            + if payload.is_empty() {
                0
            } else {
                1 + payload.len()
            }
            + TAG_LEN;
        let ct_err = || BufferTooSmall::new(ct_required, CT_CAP);
        ct_out.push(code).map_err(|_| ct_err())?;
        ct_out
            .extend_from_slice(class_e_options)
            .map_err(|_| ct_err())?;
        if !payload.is_empty() {
            ct_out.push(0xFF).map_err(|_| ct_err())?;
            ct_out.extend_from_slice(payload).map_err(|_| ct_err())?;
        }

        // Build AAD per RFC 8613 Section 5.4 using sender_id as request_kid
        let mut aad_buf = [0u8; 64];
        let aad_len = build_aad_cbor(self.sender_id(), &piv[..piv_len], &mut aad_buf)?;

        // Encrypt in place using detached API (works with plain slices, no Buffer trait needed)
        let tag = cipher
            .encrypt_in_place_detached((&nonce).into(), &aad_buf[..aad_len], &mut ct_out)
            .map_err(|_| OscoreError::EncryptFailed)?;
        ct_out.extend_from_slice(&tag).map_err(|_| ct_err())?;

        // Build OSCORE option
        const OPT_CAP: usize = OSCORE_OPTION_MAX_LEN;
        let mut opt = heapless::Vec::<u8, OPT_CAP>::new();
        let has_context = self.id_context_present;
        let flags = 0x08 | u8::from(has_context) << 4 | (piv_len as u8 & 0x07);
        let context_len = usize::from(has_context) * (1 + self.id_context_len as usize);
        let opt_required = 1 + piv_len + context_len + self.sender_id_len as usize;
        let opt_err = || BufferTooSmall::new(opt_required, OPT_CAP);
        opt.push(flags).map_err(|_| opt_err())?;
        opt.extend_from_slice(&piv[..piv_len])
            .map_err(|_| opt_err())?;
        if has_context {
            opt.push(self.id_context_len).map_err(|_| opt_err())?;
            opt.extend_from_slice(&self.id_context[..self.id_context_len as usize])
                .map_err(|_| opt_err())?;
        }
        opt.extend_from_slice(self.sender_id())
            .map_err(|_| opt_err())?;

        Ok((ct_out, opt))
    }

    /// Protect (encrypt) an OSCORE response.
    ///
    /// Unlike `protect_request`, responses:
    /// - Use the ORIGINAL request's KID and PIV for the AAD (ties response to request)
    /// - Omits PIV from the OSCORE option
    /// - Reuses the request nonce
    ///
    /// Per RFC 8613 Section 5.2, when a response includes a PIV, the nonce uses
    /// the responder's Sender ID and PIV. When omitting PIV, the response reuses
    /// the exact nonce from the original request.
    ///
    /// Returns (ciphertext, oscore_option_value).
    ///
    /// # Parameters
    /// - `code`: Response code (e.g., 0x45 for 2.05 Content)
    /// - `class_e_options`: Class E CoAP options to encrypt
    /// - `payload`: Response payload to encrypt
    /// - `request_kid`: The KID from the original request (requester's sender_id)
    /// - `request_piv`: The PIV from the original request
    pub fn protect_response(
        &mut self,
        code: u8,
        class_e_options: &[u8],
        payload: &[u8],
        request_kid: &[u8],
        request_piv: &[u8],
        include_piv: bool,
    ) -> Result<
        (
            heapless::Vec<u8, 280>,
            heapless::Vec<u8, OSCORE_OPTION_MAX_LEN>,
        ),
        OscoreError,
    > {
        if request_kid.len() > NONCE_ID_LEN
            || OscoreSeqNum::from_piv(request_piv).is_none()
            || request_kid != self.recipient_id()
        {
            return Err(OscoreError::InvalidParam);
        }
        if !self.active {
            return Err(OscoreError::InvalidParam);
        }
        if !include_piv && !self.allow_no_piv_response {
            return Err(OscoreError::InvalidParam);
        }

        // Determine PIV for nonce: own sequence if including, else request's PIV
        let (nonce_piv, piv_len, piv_for_option, resp_seq): (
            [u8; PIV_MAX_LEN],
            usize,
            Option<usize>,
            Option<OscoreSeqNum>,
        ) = if include_piv {
            // Generate own PIV.
            // SECURITY: Returns SeqExhausted if at u32::MAX to prevent nonce reuse.
            let seq = self
                .sender_seq
                .fetch_increment()
                .ok_or(OscoreError::SeqExhausted)?;
            let mut piv = [0u8; PIV_MAX_LEN];
            let len = seq.encode_piv(&mut piv);
            (piv, len, Some(len), None)
        } else {
            let seq = OscoreSeqNum::from_piv(request_piv).ok_or(OscoreError::InvalidParam)?;
            if self.is_response_reuse(seq) {
                return Err(OscoreError::Replay);
            }
            // Reuse the request nonce (no new sequence generated).
            let mut piv = [0u8; PIV_MAX_LEN];
            piv[..request_piv.len()].copy_from_slice(request_piv);
            (piv, request_piv.len(), None, Some(seq))
        };

        let nonce_id = if include_piv {
            self.sender_id()
        } else {
            request_kid
        };
        let nonce = compute_nonce(nonce_id, &nonce_piv[..piv_len], &self.common_iv);

        // Build plaintext: code || options || 0xFF || payload
        const CT_CAP: usize = 280;
        let mut ct_out = heapless::Vec::<u8, CT_CAP>::new();
        let ct_required = 1
            + class_e_options.len()
            + if payload.is_empty() {
                0
            } else {
                1 + payload.len()
            }
            + TAG_LEN;
        let ct_err = || BufferTooSmall::new(ct_required, CT_CAP);
        ct_out.push(code).map_err(|_| ct_err())?;
        ct_out
            .extend_from_slice(class_e_options)
            .map_err(|_| ct_err())?;
        if !payload.is_empty() {
            ct_out.push(0xFF).map_err(|_| ct_err())?;
            ct_out.extend_from_slice(payload).map_err(|_| ct_err())?;
        }

        // Build AAD using ORIGINAL request's KID and PIV
        let mut aad_buf = [0u8; 64];
        let aad_len = build_aad_cbor(request_kid, request_piv, &mut aad_buf)?;

        // Encrypt
        let cipher =
            AesCcm::new_from_slice(&self.sender_key).map_err(|_| OscoreError::KeyDerivation)?;
        let tag = cipher
            .encrypt_in_place_detached((&nonce).into(), &aad_buf[..aad_len], &mut ct_out)
            .map_err(|_| OscoreError::EncryptFailed)?;
        ct_out.extend_from_slice(&tag).map_err(|_| ct_err())?;

        // Build OSCORE option
        const OPT_CAP: usize = OSCORE_OPTION_MAX_LEN;
        let mut opt = heapless::Vec::<u8, OPT_CAP>::new();

        if let Some(len) = piv_for_option {
            // Include PIV in option
            let flags = len as u8 & 0x07;
            opt.push(flags)
                .map_err(|_| BufferTooSmall::new(1 + len, OPT_CAP))?;
            opt.extend_from_slice(&nonce_piv[..len])
                .map_err(|_| BufferTooSmall::new(1 + len, OPT_CAP))?;
        }

        if let Some(seq) = resp_seq {
            self.mark_response_used(seq);
        }

        Ok((ct_out, opt))
    }

    pub(crate) fn protect_response_with_reserved_piv(
        &mut self,
        seq: OscoreSeqNum,
        code: u8,
        class_e_options: &[u8],
        payload: &[u8],
        request_kid: &[u8],
        request_piv: &[u8],
    ) -> Result<
        (
            heapless::Vec<u8, 280>,
            heapless::Vec<u8, OSCORE_OPTION_MAX_LEN>,
        ),
        OscoreError,
    > {
        if request_kid.len() > NONCE_ID_LEN
            || OscoreSeqNum::from_piv(request_piv).is_none()
            || request_kid != self.recipient_id()
        {
            return Err(OscoreError::InvalidParam);
        }

        let mut piv = [0u8; PIV_MAX_LEN];
        let piv_len = seq.encode_piv(&mut piv);
        self.protect_response_with_piv_inner(
            code,
            class_e_options,
            payload,
            request_kid,
            request_piv,
            &piv[..piv_len],
        )
    }

    fn protect_response_with_piv_inner(
        &mut self,
        code: u8,
        class_e_options: &[u8],
        payload: &[u8],
        request_kid: &[u8],
        request_piv: &[u8],
        response_piv: &[u8],
    ) -> Result<
        (
            heapless::Vec<u8, 280>,
            heapless::Vec<u8, OSCORE_OPTION_MAX_LEN>,
        ),
        OscoreError,
    > {
        let nonce = compute_nonce(self.sender_id(), response_piv, &self.common_iv);
        let mut ct_out = heapless::Vec::<u8, 280>::new();
        let required =
            1 + class_e_options.len() + usize::from(!payload.is_empty()) + payload.len() + TAG_LEN;
        ct_out
            .push(code)
            .map_err(|_| BufferTooSmall::new(required, 280))?;
        ct_out
            .extend_from_slice(class_e_options)
            .map_err(|_| BufferTooSmall::new(required, 280))?;
        if !payload.is_empty() {
            ct_out
                .push(0xff)
                .map_err(|_| BufferTooSmall::new(required, 280))?;
            ct_out
                .extend_from_slice(payload)
                .map_err(|_| BufferTooSmall::new(required, 280))?;
        }
        let mut aad_buf = [0u8; 64];
        let aad_len = build_aad_cbor(request_kid, request_piv, &mut aad_buf)?;
        let cipher =
            AesCcm::new_from_slice(&self.sender_key).map_err(|_| OscoreError::KeyDerivation)?;
        let tag = cipher
            .encrypt_in_place_detached((&nonce).into(), &aad_buf[..aad_len], &mut ct_out)
            .map_err(|_| OscoreError::EncryptFailed)?;
        ct_out
            .extend_from_slice(&tag)
            .map_err(|_| BufferTooSmall::new(required, 280))?;

        let mut option = heapless::Vec::<u8, OSCORE_OPTION_MAX_LEN>::new();
        option
            .push(response_piv.len() as u8 & 0x07)
            .map_err(|_| BufferTooSmall::new(1 + response_piv.len(), OSCORE_OPTION_MAX_LEN))?;
        option
            .extend_from_slice(response_piv)
            .map_err(|_| BufferTooSmall::new(1 + response_piv.len(), OSCORE_OPTION_MAX_LEN))?;
        Ok((ct_out, option))
    }
}
