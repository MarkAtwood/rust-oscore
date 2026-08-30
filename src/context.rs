// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! OSCORE security context.

use zeroize::Zeroize;

use crate::crypto::{derive_context_id, derive_iv, derive_key};
use crate::error::{ContextStoreError, OscoreError};
use crate::seqnum::OscoreSeqNum;
use crate::types::{
    ContextId, SenderSequenceState, SenderStateStore, ID_CONTEXT_CAPACITY, ID_MAX_LEN, KEY_LEN,
    NONCE_ID_LEN, NONCE_LEN, SALT_MAX_LEN, WINDOW_SIZE,
};

#[cfg(test)]
use crate::protect::Construction;

/// OSCORE security context.
///
/// Contains cryptographic material and state for one peer.
///
/// # Thread Safety
///
/// Single-threaded use on embedded targets. Replay window and sender_seq are
/// **not thread-safe**. Concurrent `protect`/`unprotect` races on seq/replay.
///
/// For multi-threaded, wrap in Mutex.
///
/// # Key Lifecycle
///
/// All key material zeroized on drop via `Zeroize`.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Context {
    // Common context
    pub(crate) master_secret: [u8; KEY_LEN],
    pub(crate) master_salt: [u8; SALT_MAX_LEN],
    pub(crate) master_salt_len: u8,
    pub(crate) common_iv: [u8; NONCE_LEN],
    pub(crate) id_context: [u8; ID_CONTEXT_CAPACITY],
    pub(crate) id_context_len: u8,
    pub(crate) id_context_present: bool,

    // Sender context
    pub(crate) sender_id: [u8; ID_MAX_LEN],
    pub(crate) sender_id_len: u8,
    pub(crate) sender_key: [u8; KEY_LEN],
    pub(crate) sender_seq: OscoreSeqNum,
    pub(crate) sender_seq_exhausted: bool,
    pub(crate) restored: bool,
    pub(crate) active: bool,

    // Recipient context
    pub(crate) recipient_id: [u8; ID_MAX_LEN],
    pub(crate) recipient_id_len: u8,
    pub(crate) recipient_key: [u8; KEY_LEN],
    pub(crate) recipient_seq: OscoreSeqNum,
    pub(crate) replay_window: u32,

    // Requests for which a response without a fresh PIV has already been protected.
    pub(crate) response_seq: OscoreSeqNum,
    pub(crate) response_window: u32,
    pub(crate) response_window_initialized: bool,
    pub(crate) received_response_seq: OscoreSeqNum,
    pub(crate) received_response_window: u32,
    pub(crate) received_response_window_initialized: bool,
    pub(crate) allow_no_piv_response: bool,
    pub(crate) context_id: ContextId,
}

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Context")
            .field("master_secret", &"[REDACTED]")
            .field("master_salt", &"[REDACTED]")
            .field("common_iv", &"[REDACTED]")
            .field("id_context_len", &self.id_context_len)
            .field("id_context_present", &self.id_context_present)
            .field("sender_id_len", &self.sender_id_len)
            .field("sender_key", &"[REDACTED]")
            .field("sender_seq", &self.sender_seq)
            .field("sender_seq_exhausted", &self.sender_seq_exhausted)
            .field("restored", &self.restored)
            .field("recipient_id_len", &self.recipient_id_len)
            .field("recipient_key", &"[REDACTED]")
            .field("recipient_seq", &self.recipient_seq)
            .field("replay_window", &self.replay_window)
            .field("response_seq", &self.response_seq)
            .field("response_window", &self.response_window)
            .finish()
    }
}

impl Context {
    /// Atomically activate a newly established context in its authoritative store.
    ///
    /// This consumes an EDHOC-exported context and registers its initial sender state
    /// with a single `None -> initial` compare-and-swap. Existing state is never used.
    pub fn register_fresh<S: SenderStateStore>(
        mut self,
        store: &mut S,
    ) -> Result<Self, ContextStoreError<S::Error>> {
        if self.restored || self.active {
            return Err(ContextStoreError::Oscore(OscoreError::InvalidParam));
        }
        if !store
            .compare_exchange(&self.context_id, None, self.sender_sequence_state())
            .map_err(ContextStoreError::Storage)?
        {
            return Err(ContextStoreError::Conflict);
        }
        self.active = true;
        self.allow_no_piv_response = true;
        Ok(self)
    }

    /// Activate a context using sender state already present in its authoritative store.
    pub fn restore_existing<S: SenderStateStore>(
        mut self,
        store: &mut S,
    ) -> Result<Self, ContextStoreError<S::Error>> {
        let state = store
            .load(&self.context_id)
            .map_err(ContextStoreError::Storage)?
            .ok_or(ContextStoreError::Missing)?;
        self.set_sender_state(state)
            .map_err(ContextStoreError::Oscore)?;
        self.restored = true;
        self.active = true;
        self.allow_no_piv_response = false;
        Ok(self)
    }

    /// Create new OSCORE context from master material, optional ID context, and peer IDs (RFC 8613).
    ///
    /// Derives keys/IV via HKDF-SHA256, computes stable ContextId, sets defaults (seq=0,
    /// inactive, not restored). Use `register_fresh`/`restore_existing` to activate with store.
    /// Fixes undefined variables, incomplete struct init, key derivation, ContextId, and
    /// EDHOC compatibility from the oscore-recovery merge. Satisfies zeroize, constant-time,
    /// and RFC 8613.
    ///
    /// # Errors
    ///
    /// `InvalidParam` for: ID lengths > NONCE_ID_LEN, identical sender/recipient IDs,
    /// oversized salt or id_context.
    pub fn new(
        master_secret: &[u8; KEY_LEN],
        master_salt: Option<&[u8]>,
        id_context: Option<&[u8]>,
        sender_id: &[u8],
        recipient_id: &[u8],
    ) -> Result<Self, OscoreError> {
        if sender_id.len() > NONCE_ID_LEN || recipient_id.len() > NONCE_ID_LEN {
            return Err(OscoreError::InvalidParam);
        }
        if sender_id.is_empty() && recipient_id.is_empty() {
            return Err(OscoreError::InvalidParam);
        }

        if sender_id == recipient_id {
            return Err(OscoreError::InvalidParam);
        }

        let salt = master_salt.unwrap_or(&[]);
        if salt.len() > SALT_MAX_LEN {
            return Err(OscoreError::InvalidParam);
        }
        if let Some(ic) = id_context {
            if ic.len() > ID_CONTEXT_CAPACITY {
                return Err(OscoreError::InvalidParam);
            }
        }

        let id_context_value = id_context.unwrap_or(&[]);
        let context_id = derive_context_id(master_secret, salt, id_context, sender_id);
        let sender_seq = OscoreSeqNum::default();
        let restored = false;
        let active = false;
        let allow_no_piv_response = false;

        let mut ctx = Self {
            master_secret: *master_secret,
            master_salt: [0u8; SALT_MAX_LEN],
            master_salt_len: salt.len() as u8,
            common_iv: [0u8; NONCE_LEN],
            id_context: [0u8; ID_CONTEXT_CAPACITY],
            id_context_len: id_context_value.len() as u8,
            id_context_present: id_context.is_some(),
            sender_id: [0u8; ID_MAX_LEN],
            sender_id_len: sender_id.len() as u8,
            sender_key: [0u8; KEY_LEN],
            sender_seq,
            sender_seq_exhausted: false,
            restored,
            active,
            recipient_id: [0u8; ID_MAX_LEN],
            recipient_id_len: recipient_id.len() as u8,
            recipient_key: [0u8; KEY_LEN],
            recipient_seq: OscoreSeqNum::default(),
            replay_window: 0,
            response_seq: OscoreSeqNum::default(),
            response_window: 0,
            response_window_initialized: false,
            received_response_seq: OscoreSeqNum::default(),
            received_response_window: 0,
            received_response_window_initialized: false,
            allow_no_piv_response,
            context_id,
        };

        ctx.master_salt[..salt.len()].copy_from_slice(salt);
        ctx.id_context[..id_context_value.len()].copy_from_slice(id_context_value);
        ctx.sender_id[..sender_id.len()].copy_from_slice(sender_id);
        ctx.recipient_id[..recipient_id.len()].copy_from_slice(recipient_id);

        // Derive keys and IV (post-validation, pre-use; satisfies zeroize/CT/RFC 8613)
        ctx.sender_key = derive_key(master_secret, salt, sender_id, id_context)?;
        ctx.recipient_key = derive_key(master_secret, salt, recipient_id, id_context)?;
        ctx.common_iv = derive_iv(master_secret, salt, id_context)?;

        Ok(ctx)
    }

    /// Fresh context for EDHOC export (starts inactive; register with store).
    pub fn new_fresh(
        master_secret: &[u8; KEY_LEN],
        master_salt: Option<&[u8]>,
        id_context: Option<&[u8]>,
        sender_id: &[u8],
        recipient_id: &[u8],
    ) -> Result<Self, OscoreError> {
        let mut ctx = Self::new(
            master_secret,
            master_salt,
            id_context,
            sender_id,
            recipient_id,
        )?;
        ctx.restored = false;
        ctx.active = false;
        ctx.allow_no_piv_response = true;
        Ok(ctx)
    }

    /// Test-only active context (bypasses store for unit tests).
    #[cfg(test)]
    pub fn new_ephemeral(
        master_secret: &[u8; KEY_LEN],
        master_salt: Option<&[u8]>,
        sender_id: &[u8],
        recipient_id: &[u8],
    ) -> Result<Self, OscoreError> {
        let mut ctx = Self::new(master_secret, master_salt, None, sender_id, recipient_id)?;
        ctx.restored = false;
        ctx.active = true;
        ctx.allow_no_piv_response = true;
        Ok(ctx)
    }

    /// Restore context from known sender state (tests/recovery).
    #[cfg(test)]
    pub fn restore(
        master_secret: &[u8; KEY_LEN],
        master_salt: Option<&[u8]>,
        sender_id: &[u8],
        recipient_id: &[u8],
        next_sequence: u64,
        exhausted: bool,
    ) -> Result<Self, OscoreError> {
        let mut ctx = Self::new(master_secret, master_salt, None, sender_id, recipient_id)?;
        let state = SenderSequenceState {
            next_sequence,
            exhausted,
        };
        ctx.set_sender_state(state)?;
        ctx.restored = true;
        ctx.active = true;
        ctx.allow_no_piv_response = false;
        Ok(ctx)
    }

    #[cfg(test)]
    pub(crate) fn from_sender_state(
        master_secret: &[u8; KEY_LEN],
        master_salt: Option<&[u8]>,
        id_context: Option<&[u8]>,
        sender_id: &[u8],
        recipient_id: &[u8],
        construction: Construction,
    ) -> Result<Self, OscoreError> {
        let mut ctx = Self::new(
            master_secret,
            master_salt,
            id_context,
            sender_id,
            recipient_id,
        )?;
        match construction {
            Construction::Fresh => {
                ctx.restored = false;
                ctx.active = false;
                ctx.allow_no_piv_response = true;
            }
            Construction::Ephemeral => {
                ctx.restored = false;
                ctx.active = true;
                ctx.allow_no_piv_response = true;
            }
            Construction::Stored(state) => {
                ctx.set_sender_state(state)?;
                ctx.restored = true;
                ctx.active = true;
                ctx.allow_no_piv_response = false;
            }
        }
        Ok(ctx)
    }

    pub(crate) fn set_sender_state(&mut self, state: SenderSequenceState) -> Result<(), OscoreError> {
        let sequence = OscoreSeqNum::new(state.next_sequence).ok_or(OscoreError::InvalidParam)?;
        if state.exhausted && state.next_sequence != OscoreSeqNum::MAX {
            return Err(OscoreError::InvalidParam);
        }
        self.sender_seq = sequence;
        self.sender_seq_exhausted = state.exhausted;
        Ok(())
    }

    /// Return the durable-store identifier for this directional context.
    pub fn context_id(&self) -> ContextId {
        self.context_id
    }

    /// Get the next sender sequence number, or `None` if it is exhausted.
    pub fn sender_seq(&self) -> Option<OscoreSeqNum> {
        (!self.sender_seq_exhausted).then_some(self.sender_seq)
    }

    /// Return the sender reservation that must be durable before transmission.
    pub fn sender_sequence_state(&self) -> SenderSequenceState {
        SenderSequenceState {
            next_sequence: self.sender_seq.get(),
            exhausted: self.sender_seq_exhausted,
        }
    }

    /// Return whether this context was reconstructed from persisted state.
    pub fn is_restored(&self) -> bool {
        self.restored
    }

    /// Get sender ID.
    pub fn sender_id(&self) -> &[u8] {
        &self.sender_id[..self.sender_id_len as usize]
    }

    /// Get recipient ID.
    pub fn recipient_id(&self) -> &[u8] {
        &self.recipient_id[..self.recipient_id_len as usize]
    }

    /// Return the master secret (for provisioning key derivation).
    ///
    /// # Security
    /// This should only be used for deriving domain-separated keys (e.g., provisioning).
    pub fn master_secret(&self) -> &[u8; KEY_LEN] {
        &self.master_secret
    }

    // Replay window methods

    pub(crate) fn is_response_reuse(&self, seq: OscoreSeqNum) -> bool {
        if !self.response_window_initialized || seq.get() > self.response_seq.get() {
            return false;
        }

        let diff = self.response_seq.get() - seq.get();
        diff >= u64::from(WINDOW_SIZE) || self.response_window & (1 << diff as u32) != 0
    }

    pub(crate) fn mark_response_used(&mut self, seq: OscoreSeqNum) {
        if !self.response_window_initialized {
            self.response_seq = seq;
            self.response_window = 1;
            self.response_window_initialized = true;
        } else if seq.get() > self.response_seq.get() {
            let shift = seq.get() - self.response_seq.get();
            self.response_window = if shift >= u64::from(WINDOW_SIZE) {
                1
            } else {
                (self.response_window << shift as u32) | 1
            };
            self.response_seq = seq;
        } else {
            let diff = self.response_seq.get() - seq.get();
            self.response_window |= 1 << diff as u32;
        }
    }

    pub(crate) fn is_received_response_reuse(&self, seq: OscoreSeqNum) -> bool {
        if !self.received_response_window_initialized
            || seq.get() > self.received_response_seq.get()
        {
            return false;
        }

        let diff = self.received_response_seq.get() - seq.get();
        diff >= u64::from(WINDOW_SIZE) || self.received_response_window & (1 << diff as u32) != 0
    }

    pub(crate) fn mark_received_response(&mut self, seq: OscoreSeqNum) {
        if !self.received_response_window_initialized {
            self.received_response_seq = seq;
            self.received_response_window = 1;
            self.received_response_window_initialized = true;
        } else if seq.get() > self.received_response_seq.get() {
            let shift = seq.get() - self.received_response_seq.get();
            self.received_response_window = if shift >= u64::from(WINDOW_SIZE) {
                1
            } else {
                (self.received_response_window << shift as u32) | 1
            };
            self.received_response_seq = seq;
        } else {
            let diff = self.received_response_seq.get() - seq.get();
            self.received_response_window |= 1 << diff as u32;
        }
    }

    /// Check if sequence number would be rejected as a replay.
    /// Does NOT update the replay window - call update_replay_window after successful decryption.
    pub(crate) fn is_replay(&self, seq: OscoreSeqNum) -> bool {
        let seq_val = seq.get();
        let recipient_seq_val = self.recipient_seq.get();

        if seq_val > recipient_seq_val {
            // New highest - always valid
            false
        } else {
            // Check if within window
            let diff = recipient_seq_val - seq_val;
            if diff >= u64::from(WINDOW_SIZE) {
                return true; // Too old
            }

            let mask = 1u32 << diff as u32;
            self.replay_window & mask != 0 // Already seen
        }
    }

    /// Update replay window after successful decryption.
    /// SECURITY: Must only be called AFTER decryption succeeds to prevent replay-window poisoning.
    pub(crate) fn update_replay_window(&mut self, seq: OscoreSeqNum) {
        let seq_val = seq.get();
        let recipient_seq_val = self.recipient_seq.get();

        if seq_val > recipient_seq_val {
            // New highest - shift window
            let shift = seq_val - recipient_seq_val;
            if shift >= u64::from(WINDOW_SIZE) {
                self.replay_window = 0;
            } else {
                self.replay_window <<= shift as u32;
            }
            self.replay_window |= 1;
            self.recipient_seq = seq;
        } else {
            // Mark as seen within window
            let diff = recipient_seq_val - seq_val;
            if diff < u64::from(WINDOW_SIZE) {
                let mask = 1u32 << diff as u32;
                self.replay_window |= mask;
            }
        }
    }
}
