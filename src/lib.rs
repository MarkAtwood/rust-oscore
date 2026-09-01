// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! Pure-Rust `no_std` OSCORE (RFC 8613) implementation.
//!
//! Provides end-to-end security for CoAP using AES-CCM-16-64-128 and HKDF-SHA256.
//!
//! # ponytail: pure-Rust OSCORE
//!
//! Using `ccm` + `hkdf` crates directly until a battle-tested no_std OSCORE crate
//! exists. `liboscore` requires C FFI which complicates embedded cross-compilation.
//! Switch to `liboscore` or `coapcore` when they mature for embedded targets.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod error;
pub mod seqnum;

pub use error::BufferTooSmall;

#[cfg(any(feature = "edhoc", feature = "edhoc-schnorr48"))]
pub mod edhoc;

pub use seqnum::OscoreSeqNum;

#[cfg(any(feature = "edhoc", feature = "edhoc-schnorr48"))]
pub use edhoc::{
    ConnectionId, EdhocError, EdhocInitiator, EdhocResponder, IdCred, IdCredReference,
    PeerCredential, PendingMessage2, PendingMessage3,
};

use aes::Aes128;
use ccm::{
    Ccm,
    aead::{AeadInPlace, KeyInit},
    consts::{U8, U13},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// AES-CCM-16-64-128: 128-bit key, 13-byte nonce, 8-byte tag.
type AesCcm = Ccm<Aes128, U8, U13>;

/// Key length (16 bytes for AES-128).
pub const KEY_LEN: usize = 16;

/// Nonce length (13 bytes for CCM L=2).
pub const NONCE_LEN: usize = 13;

/// Authentication tag length (8 bytes).
pub const TAG_LEN: usize = 8;

/// Embedded storage capacity for sender/recipient IDs.
pub const ID_MAX_LEN: usize = 8;

/// Maximum master salt length (LICHEN-specific; matches EDHOC-derived OSCORE Master Salt
/// of 8 bytes and internal buffer. RFC 8613/HKDF-SHA256 allow arbitrary length but
/// we fix for no_std/Zeroize/embedded constraints. See bead project-LICHEN-l3af).
pub const SALT_MAX_LEN: usize = 8;

/// Maximum Partial IV length.
pub const PIV_MAX_LEN: usize = 5;

/// Maximum ID Context length (LICHEN-specific; fits OSCORE option after PIV+KID,
/// matches EDHOC CID capacity and LoRa MTU constraints. Test rejects >8 bytes).
pub const ID_CONTEXT_CAPACITY: usize = 8;

/// Maximum encoded OSCORE option value within this implementation's capacities.
pub const OSCORE_OPTION_MAX_LEN: usize = 1 + PIV_MAX_LEN + 1 + ID_CONTEXT_CAPACITY + NONCE_ID_LEN;

// Nonce layout constants (RFC 8613 Section 5.2):
// +--------+------------------+------------------+
// | 1 byte |     7 bytes      |     5 bytes      |
// +--------+------------------+------------------+
// |   S    | left-padded ID   | left-padded PIV  |
// +--------+------------------+------------------+
//   [0]        [1..8)             [8..13)

/// Nonce field: ID region ends at byte 8 (bytes 1-7 = 7 bytes for ID).
const NONCE_ID_END: usize = 8;

/// Nonce field: PIV region starts at byte 8 (bytes 8-12 = 5 bytes for PIV).
const NONCE_PIV_START: usize = 8;

/// Nonce field: Maximum ID length (7 bytes, fits in bytes 1-7).
const NONCE_ID_LEN: usize = NONCE_ID_END - 1; // = 7

// Compile-time assertions: nonce layout must be consistent
const _: () = assert!(
    NONCE_ID_END == NONCE_PIV_START,
    "ID and PIV fields must be adjacent"
);
const _: () = assert!(
    NONCE_PIV_START + PIV_MAX_LEN == NONCE_LEN,
    "PIV field must fit exactly"
);
const _: () = assert!(
    1 + NONCE_ID_LEN + PIV_MAX_LEN == NONCE_LEN,
    "nonce fields must sum to NONCE_LEN"
);

/// COSE Algorithm ID for AES-CCM-16-64-128.
pub const ALG_AEAD: u8 = 10;

/// OSCORE CoAP option number.
pub const COAP_OPTION_OSCORE: u16 = 9;

/// Replay window size in bits.
pub const WINDOW_SIZE: u32 = 32;

/// OSCORE error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OscoreError {
    /// Invalid parameter provided.
    InvalidParam,
    /// Security context not found.
    NoContext,
    /// Replay attack detected.
    Replay,
    /// Encryption failed.
    EncryptFailed,
    /// Decryption/authentication failed.
    DecryptFailed,
    /// Output buffer too small.
    BufferTooSmall(BufferTooSmall),
    /// Key derivation failed.
    KeyDerivation,
    /// Sender sequence exhausted, key rotation required.
    SeqExhausted,
    /// Entropy source (RNG) failure.
    EntropyFailure,
}

impl From<BufferTooSmall> for OscoreError {
    fn from(e: BufferTooSmall) -> Self {
        Self::BufferTooSmall(e)
    }
}

impl core::fmt::Display for OscoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidParam => write!(f, "invalid parameter"),
            Self::NoContext => write!(f, "security context not found"),
            Self::Replay => write!(f, "replay attack detected"),
            Self::EncryptFailed => write!(f, "encryption failed"),
            Self::DecryptFailed => write!(f, "decryption failed"),
            Self::BufferTooSmall(e) => write!(f, "OSCORE {}", e),
            Self::KeyDerivation => write!(f, "key derivation failed"),
            Self::SeqExhausted => write!(f, "sender sequence exhausted, key rotation required"),
            Self::EntropyFailure => write!(f, "entropy source failure"),
        }
    }
}

impl core::error::Error for OscoreError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

/// Sender sequence state that must be persisted before transmitting a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderSequenceState {
    /// Next sender sequence that may be used.
    pub next_sequence: u64,
    /// Whether the terminal sequence has already been consumed.
    pub exhausted: bool,
}

/// Recipient-side replay state that should be persisted after each successful unprotect.
///
/// Without persistence, a reboot allows replay of every message the peer ever sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientReplayState {
    /// Highest accepted incoming request sequence.
    pub recipient_seq: u64,
    /// Sliding window of accepted sequences (bit 0 = recipient_seq).
    pub replay_window: u32,
    /// Server role: highest request PIV for which a no-PIV response was sent.
    pub response_seq: u64,
    pub response_window: u32,
    pub response_window_initialized: bool,
    /// Client role: highest accepted peer response (by request seq).
    pub received_response_seq: u64,
    pub received_response_window: u32,
    pub received_response_window_initialized: bool,
    /// Client role: highest accepted peer response (by explicit PIV).
    pub received_response_piv_seq: u64,
    pub received_response_piv_window: u32,
    pub received_response_piv_window_initialized: bool,
}

/// Stable identifier for one directional OSCORE sender context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroize)]
pub struct ContextId([u8; 32]);

impl ContextId {
    /// Return the identifier bytes for use as a durable-store key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Durable storage for OSCORE context state (sender sequence + recipient replay windows).
///
/// Sender state uses atomic compare-exchange (must be persisted BEFORE transmit).
/// Recipient state is best-effort (persisted AFTER successful unprotect).
pub trait ContextStateStore {
    /// Storage-specific failure.
    type Error;

    /// Load sender state for exactly `context_id`.
    fn load_sender(
        &mut self,
        context_id: &ContextId,
    ) -> Result<Option<SenderSequenceState>, Self::Error>;

    /// Atomically replace sender `expected` with `next` for exactly `context_id`.
    fn compare_exchange_sender(
        &mut self,
        context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error>;

    /// Load recipient replay state for `context_id`. Returns `None` on fresh context.
    fn load_recipient(
        &mut self,
        context_id: &ContextId,
    ) -> Result<Option<RecipientReplayState>, Self::Error>;

    /// Persist recipient replay state after a successful unprotect.
    fn save_recipient(
        &mut self,
        context_id: &ContextId,
        state: &RecipientReplayState,
    ) -> Result<(), Self::Error>;
}

/// Failure to construct a context against its authoritative sender-state store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextStoreError<E> {
    /// OSCORE material or sender state was invalid.
    Oscore(OscoreError),
    /// Durable storage failed.
    Storage(E),
    /// No durable sender state exists for this context.
    Missing,
    /// The store changed incompatibly during registration.
    Conflict,
}

/// Failure to reserve a sender sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationError<E> {
    /// The context has consumed every sender sequence.
    SequenceExhausted,
    /// Another context owner advanced the durable state first.
    Conflict,
    /// Durable storage failed.
    Storage(E),
}

/// Exclusive, one-use capability for sender-sequence encryption.
pub struct ReservedSender<'a> {
    context: &'a mut Context,
    sequence: OscoreSeqNum,
}

/// Authenticated response awaiting atomic replay-state acceptance.
///
/// Plaintext is intentionally inaccessible until [`PendingResponse::commit`]. Dropping this
/// value leaves the context unchanged, so transport acknowledgement failure remains retryable.
pub struct PendingResponse<'a> {
    context: &'a mut Context,
    request_seq: OscoreSeqNum,
    response_seq: Option<OscoreSeqNum>,
    mark_request_used: bool,
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
            self.context.mark_received_response_piv(seq);
        }
        if self.mark_request_used {
            self.context.mark_received_response(self.request_seq);
        }
        Ok((self.code, self.options, self.payload))
    }
}

#[allow(dead_code)] // variants gated by features
enum Construction {
    #[cfg(any(feature = "edhoc", feature = "edhoc-schnorr48", test))]
    Fresh,
    #[cfg(test)]
    Ephemeral,
    Stored(SenderSequenceState),
}

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
    master_secret: [u8; KEY_LEN],
    master_salt: [u8; SALT_MAX_LEN],
    master_salt_len: u8,
    common_iv: [u8; NONCE_LEN],
    id_context: [u8; ID_CONTEXT_CAPACITY],
    id_context_len: u8,
    id_context_present: bool,

    // Sender context
    sender_id: [u8; ID_MAX_LEN],
    sender_id_len: u8,
    sender_key: [u8; KEY_LEN],
    sender_seq: OscoreSeqNum,
    sender_seq_exhausted: bool,
    restored: bool,
    active: bool,

    // Recipient context
    recipient_id: [u8; ID_MAX_LEN],
    recipient_id_len: u8,
    recipient_key: [u8; KEY_LEN],
    recipient_seq: OscoreSeqNum,
    replay_window: u32,

    // Requests for which a response without a fresh PIV has already been protected.
    response_seq: OscoreSeqNum,
    response_window: u32,
    response_window_initialized: bool,
    received_response_seq: OscoreSeqNum,
    received_response_window: u32,
    received_response_window_initialized: bool,
    received_response_piv_seq: OscoreSeqNum,
    received_response_piv_window: u32,
    received_response_piv_window_initialized: bool,
    allow_no_piv_response: bool,
    context_id: ContextId,
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
    pub fn register_fresh<S: ContextStateStore>(
        mut self,
        store: &mut S,
    ) -> Result<Self, ContextStoreError<S::Error>> {
        if self.restored || self.active {
            return Err(ContextStoreError::Oscore(OscoreError::InvalidParam));
        }
        if !store
            .compare_exchange_sender(&self.context_id, None, self.sender_sequence_state())
            .map_err(ContextStoreError::Storage)?
        {
            return Err(ContextStoreError::Conflict);
        }
        self.active = true;
        self.allow_no_piv_response = true;
        Ok(self)
    }

    /// Activate a context using state already present in its authoritative store.
    pub fn restore_existing<S: ContextStateStore>(
        mut self,
        store: &mut S,
    ) -> Result<Self, ContextStoreError<S::Error>> {
        let state = store
            .load_sender(&self.context_id)
            .map_err(ContextStoreError::Storage)?
            .ok_or(ContextStoreError::Missing)?;
        self.set_sender_state(state)
            .map_err(ContextStoreError::Oscore)?;
        if let Some(rs) = store
            .load_recipient(&self.context_id)
            .map_err(ContextStoreError::Storage)?
        {
            self.set_recipient_replay_state(rs);
        }
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
        if let Some(ic) = id_context
            && ic.len() > ID_CONTEXT_CAPACITY
        {
            return Err(OscoreError::InvalidParam);
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
            received_response_piv_seq: OscoreSeqNum::default(),
            received_response_piv_window: 0,
            received_response_piv_window_initialized: false,
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

    /// Restore context for vector testing (allows no-PIV responses).
    /// Only available with the `test-vectors` feature.
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn restore_for_vectors(
        master_secret: &[u8; KEY_LEN],
        master_salt: Option<&[u8]>,
        sender_id: &[u8],
        recipient_id: &[u8],
        next_sequence: u64,
    ) -> Result<Self, OscoreError> {
        let mut ctx = Self::new(master_secret, master_salt, None, sender_id, recipient_id)?;
        let state = SenderSequenceState {
            next_sequence,
            exhausted: false,
        };
        ctx.set_sender_state(state)?;
        ctx.restored = true;
        ctx.active = true;
        // Allow no-PIV responses for vector conformance testing.
        ctx.allow_no_piv_response = true;
        Ok(ctx)
    }

    #[cfg(test)]
    fn from_sender_state(
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

    fn set_sender_state(&mut self, state: SenderSequenceState) -> Result<(), OscoreError> {
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

    /// Snapshot of all recipient-side replay windows for persistence.
    pub fn recipient_replay_state(&self) -> RecipientReplayState {
        RecipientReplayState {
            recipient_seq: self.recipient_seq.get(),
            replay_window: self.replay_window,
            response_seq: self.response_seq.get(),
            response_window: self.response_window,
            response_window_initialized: self.response_window_initialized,
            received_response_seq: self.received_response_seq.get(),
            received_response_window: self.received_response_window,
            received_response_window_initialized: self.received_response_window_initialized,
            received_response_piv_seq: self.received_response_piv_seq.get(),
            received_response_piv_window: self.received_response_piv_window,
            received_response_piv_window_initialized: self.received_response_piv_window_initialized,
        }
    }

    /// Restore recipient-side replay windows from persisted state.
    fn set_recipient_replay_state(&mut self, s: RecipientReplayState) {
        self.recipient_seq = OscoreSeqNum::new(s.recipient_seq).unwrap_or_default();
        self.replay_window = s.replay_window;
        self.response_seq = OscoreSeqNum::new(s.response_seq).unwrap_or_default();
        self.response_window = s.response_window;
        self.response_window_initialized = s.response_window_initialized;
        self.received_response_seq = OscoreSeqNum::new(s.received_response_seq).unwrap_or_default();
        self.received_response_window = s.received_response_window;
        self.received_response_window_initialized = s.received_response_window_initialized;
        self.received_response_piv_seq = OscoreSeqNum::new(s.received_response_piv_seq).unwrap_or_default();
        self.received_response_piv_window = s.received_response_piv_window;
        self.received_response_piv_window_initialized = s.received_response_piv_window_initialized;
    }

    /// Atomically reserve the next sender sequence in durable storage.
    ///
    /// Storage advances before this returns, so a crash can only skip the reserved
    /// sequence. A competing context restored from the same state receives
    /// [`ReservationError::Conflict`] and cannot encrypt with that sequence.
    pub fn reserve_sender<S: ContextStateStore>(
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
            .compare_exchange_sender(&self.context_id, Some(expected), next)
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

    /// Return the EDHOC/OSCORE master salt used to derive this context.
    ///
    /// # Security
    /// Expose this only to provisioning and conformance code that already has
    /// authority to handle the corresponding master secret.
    pub fn master_salt(&self) -> &[u8] {
        &self.master_salt[..self.master_salt_len as usize]
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
    fn protect_request_reserved(
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
            Some(pos) => {
                let payload = &rest[pos + 1..];
                // RFC 7252 Section 3: Payload marker with empty payload is malformed.
                if payload.is_empty() {
                    return Err(OscoreError::InvalidParam);
                }
                (&rest[..pos], payload)
            }
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

    fn protect_response_with_reserved_piv(
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
        self.begin_unprotect_response_mode(oscore_option, ciphertext, request_piv, false)
    }

    /// Authenticate an Observe notification bound to an original OSCORE request.
    ///
    /// RFC 8613 responses reuse the original request KID and PIV in their AAD. RFC 7641
    /// permits many notifications for one request, so this API deliberately does not consume
    /// the request PIV. Every notification MUST instead carry a fresh responder PIV; that PIV
    /// is checked in a dedicated replay window and is accepted only by
    /// [`PendingResponse::commit`]. Dropping the pending response (for example, when transport
    /// delivery or acknowledgement fails) leaves both replay windows unchanged.
    ///
    /// The caller remains responsible for binding the CoAP token to the stored request KID/PIV
    /// and for removing that association on cancellation or RST. An exact retransmission that
    /// was already committed is rejected as a replay; transports should recognize and ACK their
    /// cached ciphertext without decrypting it again.
    pub fn begin_unprotect_observe_response(
        &mut self,
        oscore_option: &[u8],
        ciphertext: &[u8],
        request_piv: &[u8],
    ) -> Result<PendingResponse<'_>, OscoreError> {
        self.begin_unprotect_response_mode(oscore_option, ciphertext, request_piv, true)
    }

    fn begin_unprotect_response_mode(
        &mut self,
        oscore_option: &[u8],
        ciphertext: &[u8],
        request_piv: &[u8],
        observe: bool,
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
        if !observe && self.is_received_response_reuse(request_seq) {
            return Err(OscoreError::Replay);
        }

        // A response without a PIV derives its nonce from the request. That construction is
        // safe only once and therefore cannot represent a stream of Observe notifications.
        if observe && opt.piv_len == 0 {
            return Err(OscoreError::InvalidParam);
        }

        let piv = if opt.piv_len > 0 {
            &opt.piv[..opt.piv_len as usize]
        } else {
            request_piv
        };

        let response_seq = if opt.piv_len > 0 {
            let seq = OscoreSeqNum::from_piv(piv).ok_or(OscoreError::InvalidParam)?;
            // Explicit response PIVs have their own receive window. Do not mix it with the
            // request receive window or with the responder's no-PIV nonce-reuse window.
            if self.is_received_response_piv_reuse(seq) {
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
            Some(pos) => {
                let payload = &rest[pos + 1..];
                // RFC 7252 Section 3: Payload marker with empty payload is malformed.
                if payload.is_empty() {
                    return Err(OscoreError::InvalidParam);
                }
                (&rest[..pos], payload)
            }
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
            mark_request_used: !observe,
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

    /// Unprotect and immediately accept an OSCORE Observe notification.
    ///
    /// Use [`Context::begin_unprotect_observe_response`] when transport acknowledgement must
    /// succeed before the responder PIV is committed.
    pub fn unprotect_observe_response(
        &mut self,
        oscore_option: &[u8],
        ciphertext: &[u8],
        request_piv: &[u8],
    ) -> Result<(u8, heapless::Vec<u8, 128>, heapless::Vec<u8, 128>), OscoreError> {
        self.begin_unprotect_observe_response(oscore_option, ciphertext, request_piv)?
            .commit()
    }

    fn is_response_reuse(&self, seq: OscoreSeqNum) -> bool {
        if !self.response_window_initialized || seq.get() > self.response_seq.get() {
            return false;
        }

        let diff = self.response_seq.get() - seq.get();
        diff >= u64::from(WINDOW_SIZE) || self.response_window & (1 << diff as u32) != 0
    }

    fn mark_response_used(&mut self, seq: OscoreSeqNum) {
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

    fn is_received_response_reuse(&self, seq: OscoreSeqNum) -> bool {
        if !self.received_response_window_initialized
            || seq.get() > self.received_response_seq.get()
        {
            return false;
        }

        let diff = self.received_response_seq.get() - seq.get();
        diff >= u64::from(WINDOW_SIZE) || self.received_response_window & (1 << diff as u32) != 0
    }

    fn mark_received_response(&mut self, seq: OscoreSeqNum) {
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

    fn is_received_response_piv_reuse(&self, seq: OscoreSeqNum) -> bool {
        if !self.received_response_piv_window_initialized
            || seq.get() > self.received_response_piv_seq.get()
        {
            return false;
        }

        let diff = self.received_response_piv_seq.get() - seq.get();
        diff >= u64::from(WINDOW_SIZE)
            || self.received_response_piv_window & (1 << diff as u32) != 0
    }

    fn mark_received_response_piv(&mut self, seq: OscoreSeqNum) {
        if !self.received_response_piv_window_initialized {
            self.received_response_piv_seq = seq;
            self.received_response_piv_window = 1;
            self.received_response_piv_window_initialized = true;
        } else if seq.get() > self.received_response_piv_seq.get() {
            let shift = seq.get() - self.received_response_piv_seq.get();
            self.received_response_piv_window = if shift >= u64::from(WINDOW_SIZE) {
                1
            } else {
                (self.received_response_piv_window << shift as u32) | 1
            };
            self.received_response_piv_seq = seq;
        } else {
            let diff = self.received_response_piv_seq.get() - seq.get();
            self.received_response_piv_window |= 1 << diff as u32;
        }
    }

    /// Check if sequence number would be rejected as a replay.
    /// Does NOT update the replay window - call update_replay_window after successful decryption.
    fn is_replay(&self, seq: OscoreSeqNum) -> bool {
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
    fn update_replay_window(&mut self, seq: OscoreSeqNum) {
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

/// Parsed OSCORE option.
#[derive(Debug)]
struct OscoreOption {
    piv: [u8; PIV_MAX_LEN],
    piv_len: u8,
    kid_context: [u8; ID_CONTEXT_CAPACITY],
    kid_context_len: u8,
    kid_context_present: bool,
    kid: [u8; ID_MAX_LEN],
    kid_len: u8,
    kid_present: bool,
}

/// Request identifiers needed to bind an OSCORE response to its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestIdentifiers {
    kid: [u8; ID_MAX_LEN],
    kid_len: u8,
    piv: [u8; PIV_MAX_LEN],
    piv_len: u8,
}

impl RequestIdentifiers {
    /// Request sender identifier.
    pub fn kid(&self) -> &[u8] {
        &self.kid[..self.kid_len as usize]
    }

    /// Canonical request Partial IV.
    pub fn piv(&self) -> &[u8] {
        &self.piv[..self.piv_len as usize]
    }
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

fn parse_option(data: &[u8]) -> Result<OscoreOption, OscoreError> {
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
fn parse_inner_body(data: &[u8]) -> Result<(&[u8], &[u8]), OscoreError> {
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

/// Derive sender/recipient key using HKDF-SHA256 (returns 16-byte AES key).
fn derive_context_id(
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
    ContextId(hash.finalize().into())
}

/// Derive sender/recipient key using HKDF-SHA256 (returns 16-byte AES key).
fn derive_key(
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
fn derive_iv(
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
fn build_info_cbor(
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
fn build_aad_cbor(
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

/// Parse CoAP options to find the payload marker position.
///
/// CoAP options use delta-length encoding (RFC 7252 Section 3.1):
/// - First byte: upper nibble = delta (0-12 direct, 13=+1 byte, 14=+2 bytes, 15=reserved)
/// - First byte: lower nibble = length (same encoding)
/// - 0xFF (delta=15, length=15) is the payload marker
///
/// Returns the byte index of the payload marker (0xFF) if present, or None if no payload.
/// This correctly handles 0xFF appearing inside option VALUES (not as a delta-length byte).
fn find_payload_marker(options_and_payload: &[u8]) -> Result<Option<usize>, OscoreError> {
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
fn compute_nonce(sender_id: &[u8], piv: &[u8], common_iv: &[u8; NONCE_LEN]) -> [u8; NONCE_LEN] {
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use hex_literal::hex;
    use serde_json::Value;

    fn vector(name: &str) -> Value {
        let vectors: Value =
            serde_json::from_str(include_str!("../test/vectors/oscore.json")).unwrap();
        vectors["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap()
            .clone()
    }

    fn json_hex(value: &Value) -> std::vec::Vec<u8> {
        let text = value.as_str().unwrap();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8613_key_iv_and_nonce_vectors() {
        for name in [
            "rfc8613_c1_key_derivation_client_with_salt",
            "rfc8613_c1_key_derivation_server_with_salt",
            "rfc8613_c2_key_derivation_client_no_salt",
            "rfc8613_c2_key_derivation_server_no_salt",
            "rfc8613_c3_key_derivation_client_with_id_context",
            "rfc8613_c3_key_derivation_server_with_id_context",
        ] {
            let v = vector(name);
            let secret: [u8; KEY_LEN] = json_hex(&v["master_secret"]).try_into().unwrap();
            let salt = v["master_salt"]
                .as_str()
                .map(|_| json_hex(&v["master_salt"]));
            let sender_id = json_hex(&v["sender_id"]);
            let recipient_id = json_hex(&v["recipient_id"]);
            let id_context = if v["id_context"].is_string() {
                json_hex(&v["id_context"])
            } else {
                std::vec::Vec::new()
            };
            let salt = salt.as_deref().unwrap_or(&[]);
            let id_context_opt: Option<&[u8]> = if id_context.is_empty() {
                None
            } else {
                Some(id_context.as_slice())
            };

            assert_eq!(
                derive_key(&secret, salt, &sender_id, id_context_opt)
                    .unwrap()
                    .as_slice(),
                json_hex(&v["expected"]["sender_key"])
            );
            assert_eq!(
                derive_key(&secret, salt, &recipient_id, id_context_opt)
                    .unwrap()
                    .as_slice(),
                json_hex(&v["expected"]["recipient_key"])
            );
            assert_eq!(
                derive_iv(&secret, salt, id_context_opt).unwrap().as_slice(),
                json_hex(&v["expected"]["common_iv"])
            );
        }

        for name in [
            "rfc8613_c4_request_protection",
            "rfc8613_c5_request_protection_no_salt",
            "rfc8613_c6_request_protection_with_id_context",
            "rfc8613_c7_response_protection",
            "rfc8613_c8_response_with_partial_iv",
        ] {
            let v = vector(name);
            let expected = json_hex(&v["expected"]["nonce"]);
            let sender_id = if v["type"] == "response_protection" && v["include_piv"] == false {
                json_hex(&v["request_kid"])
            } else {
                json_hex(&v["sender_id"])
            };
            let piv = if v["type"] == "request_protection" {
                OscoreSeqNum::new(v["sender_seq"].as_u64().unwrap())
            } else if v["include_piv"] == false {
                OscoreSeqNum::from_piv(&json_hex(&v["request_piv"]))
            } else {
                OscoreSeqNum::new(v["sender_seq"].as_u64().unwrap())
            };
            let secret: [u8; KEY_LEN] = json_hex(&v["master_secret"]).try_into().unwrap();
            let salt = v["master_salt"]
                .as_str()
                .map(|_| json_hex(&v["master_salt"]));
            let id_context = if v["id_context"].is_string() {
                json_hex(&v["id_context"])
            } else {
                std::vec::Vec::new()
            };
            let id_context2_opt: Option<&[u8]> = if id_context.is_empty() {
                None
            } else {
                Some(id_context.as_slice())
            };
            let derived_iv =
                derive_iv(&secret, salt.as_deref().unwrap_or(&[]), id_context2_opt).unwrap();
            let mut piv_bytes = [0u8; PIV_MAX_LEN];
            let piv_len = piv.unwrap().encode_piv(&mut piv_bytes);

            assert_eq!(
                compute_nonce(&sender_id, &piv_bytes[..piv_len], &derived_iv),
                expected.as_slice()
            );
        }
    }

    struct TestStore {
        context_id: ContextId,
        state: SenderSequenceState,
        recipient: Option<RecipientReplayState>,
    }

    impl TestStore {
        fn for_context(context: &Context) -> Self {
            Self {
                context_id: context.context_id(),
                state: context.sender_sequence_state(),
                recipient: None,
            }
        }
    }

    impl ContextStateStore for TestStore {
        type Error = core::convert::Infallible;

        fn load_sender(
            &mut self,
            context_id: &ContextId,
        ) -> Result<Option<SenderSequenceState>, Self::Error> {
            Ok((*context_id == self.context_id).then_some(self.state))
        }

        fn compare_exchange_sender(
            &mut self,
            context_id: &ContextId,
            expected: Option<SenderSequenceState>,
            next: SenderSequenceState,
        ) -> Result<bool, Self::Error> {
            if *context_id != self.context_id || expected != Some(self.state) {
                return Ok(false);
            }
            self.state = next;
            Ok(true)
        }

        fn load_recipient(
            &mut self,
            context_id: &ContextId,
        ) -> Result<Option<RecipientReplayState>, Self::Error> {
            Ok(if *context_id == self.context_id { self.recipient } else { None })
        }

        fn save_recipient(
            &mut self,
            context_id: &ContextId,
            state: &RecipientReplayState,
        ) -> Result<(), Self::Error> {
            if *context_id == self.context_id {
                self.recipient = Some(*state);
            }
            Ok(())
        }
    }

    trait TestProtect {
        fn protect_request(
            &mut self,
            code: u8,
            options: &[u8],
            payload: &[u8],
        ) -> Result<
            (
                heapless::Vec<u8, 280>,
                heapless::Vec<u8, OSCORE_OPTION_MAX_LEN>,
            ),
            OscoreError,
        >;

        fn protect_response_with_piv(
            &mut self,
            code: u8,
            options: &[u8],
            payload: &[u8],
            request_kid: &[u8],
            request_piv: &[u8],
        ) -> Result<
            (
                heapless::Vec<u8, 280>,
                heapless::Vec<u8, OSCORE_OPTION_MAX_LEN>,
            ),
            OscoreError,
        >;
    }

    impl TestProtect for Context {
        fn protect_request(
            &mut self,
            code: u8,
            options: &[u8],
            payload: &[u8],
        ) -> Result<
            (
                heapless::Vec<u8, 280>,
                heapless::Vec<u8, OSCORE_OPTION_MAX_LEN>,
            ),
            OscoreError,
        > {
            let mut store = TestStore::for_context(self);
            self.reserve_sender(&mut store)
                .map_err(|_| OscoreError::SeqExhausted)?
                .protect_request(code, options, payload)
        }

        fn protect_response_with_piv(
            &mut self,
            code: u8,
            options: &[u8],
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
            let mut store = TestStore::for_context(self);
            self.reserve_sender(&mut store)
                .map_err(|_| OscoreError::SeqExhausted)?
                .protect_response_with_piv(code, options, payload, request_kid, request_piv)
        }
    }

    #[test]
    fn test_piv_encode_decode() {
        let mut piv = [0u8; PIV_MAX_LEN];

        let seq = OscoreSeqNum::new(0).unwrap();
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 1);
        assert_eq!(piv[0], 0);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]).unwrap().get(), 0);

        let seq = OscoreSeqNum::new(1).unwrap();
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 1);
        assert_eq!(piv[0], 1);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]).unwrap().get(), 1);

        let seq = OscoreSeqNum::new(256).unwrap();
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 2);
        assert_eq!(&piv[..2], &[0x01, 0x00]);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]).unwrap().get(), 256);

        let seq = OscoreSeqNum::new(0x123456).unwrap();
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 3);
        assert_eq!(&piv[..3], &[0x12, 0x34, 0x56]);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]).unwrap().get(), 0x123456);
    }

    #[test]
    fn test_context_creation() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let sender_id = &[0x00];
        let recipient_id = &[0x01];

        let ctx = Context::new_ephemeral(&master_secret, None, sender_id, recipient_id).unwrap();

        assert_eq!(ctx.sender_id(), &[0x00]);
        assert_eq!(ctx.recipient_id(), &[0x01]);
        assert_eq!(ctx.sender_seq().unwrap().get(), 0);
        assert_eq!(
            Context::new_ephemeral(&master_secret, None, sender_id, sender_id).unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn present_empty_id_context_has_distinct_literal_derivation_and_option() {
        let master_secret = hex!("000102030405060708090a0b0c0d0e0f");
        let absent = Context::new_fresh(&master_secret, None, None, &[0], &[1]).unwrap();
        let mut present = Context::new_fresh(&master_secret, None, Some(&[]), &[0], &[1]).unwrap();

        assert_eq!(absent.sender_key, hex!("624bcd37ebc31fd9fa757b0fe7974b97"));
        assert_eq!(present.sender_key, hex!("e74a10155402072b63b54ab7bfd9ea73"));
        assert_eq!(
            absent.context_id().as_bytes(),
            &hex!("d5880fe273b739c21dbf005764bee790f7c4d99573db246c93f8a2f4e1ad6447")
        );
        assert_eq!(
            present.context_id().as_bytes(),
            &hex!("bd32b23ac2dd7c5a60a2349929dc5bc953d335a90d575e39b8fdf6589174d65b")
        );

        present.active = true;
        let mut store = TestStore::for_context(&present);
        let (_, option) = present
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(0x01, &[], &[])
            .unwrap();
        assert_eq!(option.as_slice(), &hex!("19000000"));
        let parsed = parse_option(&option).unwrap();
        assert!(parsed.kid_context_present);
        assert_eq!(parsed.kid_context_len, 0);
    }

    #[test]
    fn id_context_over_implementation_capacity_is_rejected() {
        assert_eq!(
            Context::new_fresh(&[0; KEY_LEN], None, Some(&[0; 9]), &[0], &[1]).unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn rfc8613_c7_c8_response_protection_literals() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let master_salt = hex!("9e7ca92223786340");
        let payload = b"Hello World!";

        let mut c7 = Context::new_ephemeral(&master_secret, Some(&master_salt), &[1], &[]).unwrap();
        let (ciphertext, option) = c7
            .protect_response(0x45, &[], payload, &[], &[0x14], false)
            .unwrap();
        assert_eq!(option.as_slice(), b"");
        assert_eq!(
            ciphertext.as_slice(),
            &hex!("dbaad1e9a7e7b2a813d3c31524378303cdafae119106")
        );

        let mut c8 =
            Context::restore(&master_secret, Some(&master_salt), &[1], &[], 0, false).unwrap();
        let (ciphertext, option) = c8
            .protect_response_with_piv(0x45, &[], payload, &[], &[0x14])
            .unwrap();
        assert_eq!(option.as_slice(), &hex!("0100"));
        assert_eq!(
            ciphertext.as_slice(),
            &hex!("4d4c13669384b67354b2b6175ff4b8658c666a6cf88e")
        );
    }

    #[test]
    fn restored_context_continues_at_reserved_sequence() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut ctx = Context::restore(&master_secret, None, &[0], &[1], 0x0102, false).unwrap();

        let mut store = TestStore::for_context(&ctx);
        let (_, option) = ctx
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(0x01, &[], b"restored")
            .unwrap();

        assert_eq!(option.as_slice(), b"\x0a\x01\x02\x00");
        assert_eq!(ctx.sender_seq().unwrap().get(), 0x0103);
        assert!(ctx.is_restored());
        assert_eq!(
            ctx.sender_sequence_state(),
            SenderSequenceState {
                next_sequence: 0x0103,
                exhausted: false
            }
        );
    }

    #[test]
    fn restored_contexts_race_and_exactly_one_can_encrypt() {
        let secret = [0x42; KEY_LEN];
        let mut first = Context::restore(&secret, None, &[0], &[1], 9, false).unwrap();
        let mut second = Context::restore(&secret, None, &[0], &[1], 9, false).unwrap();
        let mut store = TestStore::for_context(&first);

        let (_, option) = first
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(0x01, &[], b"winner")
            .unwrap();

        assert_eq!(option.as_slice(), b"\x09\x09\x00");
        assert!(matches!(
            second.reserve_sender(&mut store),
            Err(ReservationError::Conflict)
        ));
        assert_eq!(second.sender_sequence_state().next_sequence, 9);
        assert_eq!(store.state.next_sequence, 10);
    }

    #[test]
    fn sender_store_rejects_a_context_using_b_record() {
        let secret = [0x43; KEY_LEN];
        let mut context_a = Context::new_ephemeral(&secret, None, &[0], &[1]).unwrap();
        let context_b = Context::new_ephemeral(&secret, None, &[2], &[1]).unwrap();
        let mut store = TestStore::for_context(&context_b);

        assert!(matches!(
            context_a.reserve_sender(&mut store),
            Err(ReservationError::Conflict)
        ));
        assert_eq!(store.state.next_sequence, 0);
    }

    #[test]
    fn context_id_is_stable_directional_context_bound_and_recipient_independent() {
        let secret = [0x46; KEY_LEN];
        let first = Context::new_fresh(&secret, Some(&[7]), Some(&[8]), &[0], &[1]).unwrap();
        let same = Context::new_fresh(&secret, Some(&[7]), Some(&[8]), &[0], &[1]).unwrap();
        let other_recipient =
            Context::new_fresh(&secret, Some(&[7]), Some(&[8]), &[0], &[2]).unwrap();
        let reverse = Context::new_fresh(&secret, Some(&[7]), Some(&[8]), &[1], &[0]).unwrap();
        let other_context =
            Context::new_fresh(&secret, Some(&[7]), Some(&[9]), &[0], &[1]).unwrap();

        assert_eq!(first.context_id(), same.context_id());
        assert_eq!(first.context_id(), other_recipient.context_id());
        assert_ne!(first.context_id(), reverse.context_id());
        assert_ne!(first.context_id(), other_context.context_id());
    }

    #[test]
    fn same_sender_material_with_different_recipients_shares_sequence_record() {
        let secret = [0x4b; KEY_LEN];
        let mut first = Context::new_ephemeral(&secret, Some(&[7]), &[0], &[1]).unwrap();
        let mut other_recipient = Context::new_ephemeral(&secret, Some(&[7]), &[0], &[2]).unwrap();
        let mut store = TestStore::for_context(&first);

        assert_eq!(first.context_id(), other_recipient.context_id());
        first.reserve_sender(&mut store).unwrap();
        assert!(matches!(
            other_recipient.reserve_sender(&mut store),
            Err(ReservationError::Conflict)
        ));
    }

    #[test]
    fn fresh_context_activates_only_after_atomic_registration() {
        struct EmptyStore(Option<(ContextId, SenderSequenceState)>);

        impl ContextStateStore for EmptyStore {
            type Error = core::convert::Infallible;

            fn load_sender(
                &mut self,
                context_id: &ContextId,
            ) -> Result<Option<SenderSequenceState>, Self::Error> {
                Ok(self
                    .0
                    .filter(|(stored_id, _)| stored_id == context_id)
                    .map(|(_, state)| state))
            }

            fn compare_exchange_sender(
                &mut self,
                context_id: &ContextId,
                expected: Option<SenderSequenceState>,
                next: SenderSequenceState,
            ) -> Result<bool, Self::Error> {
                if self.load_sender(context_id)? != expected {
                    return Ok(false);
                }
                self.0 = Some((*context_id, next));
                Ok(true)
            }

            fn load_recipient(&mut self, _: &ContextId) -> Result<Option<RecipientReplayState>, Self::Error> { Ok(None) }
            fn save_recipient(&mut self, _: &ContextId, _: &RecipientReplayState) -> Result<(), Self::Error> { Ok(()) }
        }

        let secret = [0x4c; KEY_LEN];
        let mut context = Context::new_fresh(&secret, None, None, &[1], &[0]).unwrap();
        assert_eq!(
            context
                .protect_response(0x45, &[], b"response", &[0], &[3], true)
                .unwrap_err(),
            OscoreError::InvalidParam
        );

        let mut store = EmptyStore(None);
        let mut context = context.register_fresh(&mut store).unwrap();
        assert!(
            context
                .protect_response(0x45, &[], b"response", &[0], &[3], true)
                .is_ok()
        );
    }

    #[test]
    fn supplied_material_restores_authoritative_state_and_disables_no_piv() {
        let secret = [0x44; KEY_LEN];
        let template = Context::new_ephemeral(&secret, None, &[1], &[0]).unwrap();
        let mut store = TestStore {
            context_id: template.context_id(),
            state: SenderSequenceState {
                next_sequence: 7,
                exhausted: false,
            },
            recipient: None,
        };
        let mut context = Context::new(&secret, None, None, &[1], &[0])
            .unwrap()
            .restore_existing(&mut store)
            .unwrap();

        assert_eq!(context.sender_sequence_state(), store.state);
        assert!(
            context
                .protect_response(0x45, &[], b"response", &[0], &[3], true)
                .is_ok()
        );
        assert_eq!(
            context
                .protect_response(0x45, &[], b"response", &[0], &[3], false)
                .unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn supplied_material_requires_existing_durable_state() {
        struct EmptyStore;

        impl ContextStateStore for EmptyStore {
            type Error = core::convert::Infallible;

            fn load_sender(&mut self, _: &ContextId) -> Result<Option<SenderSequenceState>, Self::Error> { Ok(None) }
            fn compare_exchange_sender(&mut self, _: &ContextId, _: Option<SenderSequenceState>, _: SenderSequenceState) -> Result<bool, Self::Error> { panic!("load_existing must not write") }
            fn load_recipient(&mut self, _: &ContextId) -> Result<Option<RecipientReplayState>, Self::Error> { Ok(None) }
            fn save_recipient(&mut self, _: &ContextId, _: &RecipientReplayState) -> Result<(), Self::Error> { Ok(()) }
        }

        assert!(matches!(
            Context::new(&[0x44; KEY_LEN], None, None, &[1], &[0])
                .unwrap()
                .restore_existing(&mut EmptyStore),
            Err(ContextStoreError::Missing)
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn independent_store_handles_race_one_durable_record() {
        use std::sync::{Arc, Barrier, Mutex};
        use std::thread;

        #[derive(Clone)]
        struct SharedStore {
            record: Arc<Mutex<(ContextId, SenderSequenceState)>>,
            barrier: Arc<Barrier>,
        }

        impl ContextStateStore for SharedStore {
            type Error = core::convert::Infallible;

            fn load_sender(&mut self, context_id: &ContextId) -> Result<Option<SenderSequenceState>, Self::Error> {
                let record = self.record.lock().unwrap();
                Ok((*context_id == record.0).then_some(record.1))
            }

            fn compare_exchange_sender(&mut self, context_id: &ContextId, expected: Option<SenderSequenceState>, next: SenderSequenceState) -> Result<bool, Self::Error> {
                self.barrier.wait();
                let mut record = self.record.lock().unwrap();
                if *context_id != record.0 || expected != Some(record.1) {
                    return Ok(false);
                }
                record.1 = next;
                Ok(true)
            }

            fn load_recipient(&mut self, _: &ContextId) -> Result<Option<RecipientReplayState>, Self::Error> { Ok(None) }
            fn save_recipient(&mut self, _: &ContextId, _: &RecipientReplayState) -> Result<(), Self::Error> { Ok(()) }
        }

        let secret = [0x45; KEY_LEN];
        let template = Context::new_ephemeral(&secret, None, &[0], &[1]).unwrap();
        let record = Arc::new(Mutex::new((
            template.context_id(),
            template.sender_sequence_state(),
        )));
        let barrier = Arc::new(Barrier::new(2));
        let mut first_store = SharedStore {
            record: Arc::clone(&record),
            barrier: Arc::clone(&barrier),
        };
        let mut second_store = first_store.clone();
        let mut first = Context::new(&secret, None, None, &[0], &[1])
            .unwrap()
            .restore_existing(&mut first_store)
            .unwrap();
        let mut second = Context::new(&secret, None, None, &[0], &[1])
            .unwrap()
            .restore_existing(&mut second_store)
            .unwrap();

        let first = thread::spawn(move || first.reserve_sender(&mut first_store).is_ok());
        let second = thread::spawn(move || second.reserve_sender(&mut second_store).is_ok());

        assert_ne!(first.join().unwrap(), second.join().unwrap());
        assert_eq!(record.lock().unwrap().1.next_sequence, 1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn fresh_context_registration_race_has_one_winner() {
        use std::sync::{Arc, Barrier, Mutex};
        use std::thread;

        #[derive(Clone)]
        struct SharedEmptyStore {
            record: Arc<Mutex<Option<(ContextId, SenderSequenceState)>>>,
            barrier: Arc<Barrier>,
        }

        impl ContextStateStore for SharedEmptyStore {
            type Error = core::convert::Infallible;

            fn load_sender(&mut self, context_id: &ContextId) -> Result<Option<SenderSequenceState>, Self::Error> {
                Ok(self.record.lock().unwrap()
                    .filter(|(stored_id, _)| stored_id == context_id)
                    .map(|(_, state)| state))
            }

            fn compare_exchange_sender(&mut self, context_id: &ContextId, expected: Option<SenderSequenceState>, next: SenderSequenceState) -> Result<bool, Self::Error> {
                self.barrier.wait();
                let mut record = self.record.lock().unwrap();
                let current = record.filter(|(stored_id, _)| stored_id == context_id).map(|(_, state)| state);
                if current != expected {
                    return Ok(false);
                }
                *record = Some((*context_id, next));
                Ok(true)
            }

            fn load_recipient(&mut self, _: &ContextId) -> Result<Option<RecipientReplayState>, Self::Error> { Ok(None) }
            fn save_recipient(&mut self, _: &ContextId, _: &RecipientReplayState) -> Result<(), Self::Error> { Ok(()) }
        }

        let secret = [0x47; KEY_LEN];
        let first = Context::new_fresh(&secret, None, None, &[0], &[1]).unwrap();
        let second = Context::new_fresh(&secret, None, None, &[0], &[1]).unwrap();
        let record = Arc::new(Mutex::new(None));
        let barrier = Arc::new(Barrier::new(2));
        let mut first_store = SharedEmptyStore {
            record: Arc::clone(&record),
            barrier: Arc::clone(&barrier),
        };
        let mut second_store = first_store.clone();

        let first = thread::spawn(move || first.register_fresh(&mut first_store).is_ok());
        let second = thread::spawn(move || second.register_fresh(&mut second_store).is_ok());

        assert_ne!(first.join().unwrap(), second.join().unwrap());
        assert_eq!(record.lock().unwrap().unwrap().1.next_sequence, 0);
    }

    #[test]
    fn oscore_option_has_literal_implementation_capacity() {
        let secret = [0x48; KEY_LEN];
        let mut context = Context::from_sender_state(
            &secret,
            None,
            Some(&hex!("1011121314151617")),
            &hex!("00010203040506"),
            &[0x20],
            Construction::Ephemeral,
        )
        .unwrap();
        context.sender_seq = OscoreSeqNum::new(OscoreSeqNum::MAX).unwrap();
        let mut store = TestStore::for_context(&context);

        let (_, option) = context
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(0x01, &[], &[])
            .unwrap();

        assert_eq!(option.len(), OSCORE_OPTION_MAX_LEN);
        assert_eq!(
            option.as_slice(),
            &hex!("1dffffffffff08101112131415161700010203040506")
        );
    }

    #[test]
    fn oversized_request_does_not_poison_valid_same_sequence_retry() {
        let secret = [0x49; KEY_LEN];
        let mut oversized_sender = Context::new_ephemeral(&secret, None, &[0], &[1]).unwrap();
        let mut valid_sender = Context::new_ephemeral(&secret, None, &[0], &[1]).unwrap();
        let mut recipient = Context::new_ephemeral(&secret, None, &[1], &[0]).unwrap();
        let oversized = oversized_sender
            .protect_request(0x02, &[], &[0x55; 129])
            .unwrap();
        let valid = valid_sender.protect_request(0x02, &[], b"valid").unwrap();

        assert!(matches!(
            recipient.unprotect_request(&oversized.1, &oversized.0),
            Err(OscoreError::BufferTooSmall(_))
        ));
        assert_eq!(
            recipient.unprotect_request(&valid.1, &valid.0).unwrap().2,
            b"valid"
        );
    }

    #[test]
    fn oversized_explicit_piv_response_does_not_poison_valid_retry() {
        let secret = [0x4a; KEY_LEN];
        let mut client = Context::new_ephemeral(&secret, None, &[0], &[1]).unwrap();
        let mut oversized_server = Context::new_ephemeral(&secret, None, &[1], &[0]).unwrap();
        let mut valid_server = Context::new_ephemeral(&secret, None, &[1], &[0]).unwrap();
        let (_, request_option) = client.protect_request(0x01, &[], &[]).unwrap();
        let request_piv = &request_option[1..2];
        let oversized = oversized_server
            .protect_response_with_piv(0x45, &[], &[0x55; 129], &[0], request_piv)
            .unwrap();
        let valid = valid_server
            .protect_response_with_piv(0x45, &[], b"valid", &[0], request_piv)
            .unwrap();

        assert!(matches!(
            client.unprotect_response(&oversized.1, &oversized.0, request_piv),
            Err(OscoreError::BufferTooSmall(_))
        ));
        assert_eq!(
            client
                .unprotect_response(&valid.1, &valid.0, request_piv)
                .unwrap()
                .2,
            b"valid"
        );
    }

    #[test]
    fn crash_after_reservation_skips_sequence_after_restore() {
        let secret = [0x24; KEY_LEN];
        let mut crashed = Context::restore(&secret, None, &[0], &[1], 3, false).unwrap();
        let mut store = TestStore::for_context(&crashed);

        {
            let _unused = crashed.reserve_sender(&mut store).unwrap();
        }

        let mut restarted = Context::restore(
            &secret,
            None,
            &[0],
            &[1],
            store.state.next_sequence,
            store.state.exhausted,
        )
        .unwrap();
        let (_, option) = restarted
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(0x01, &[], b"after crash")
            .unwrap();

        assert_eq!(option.as_slice(), b"\x09\x04\x00");
        assert_eq!(store.state.next_sequence, 5);
    }

    #[test]
    fn restored_context_rejects_response_without_piv() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut ctx = Context::restore(&master_secret, None, &[1], &[0], 7, false).unwrap();

        assert!(
            ctx.protect_response(0x45, &[], b"response", &[0], &[3], true)
                .is_ok()
        );
        assert_eq!(
            ctx.protect_response(0x45, &[], b"response", &[0], &[3], false)
                .unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn restore_rejects_invalid_sender_state() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");

        assert_eq!(
            Context::restore(
                &master_secret,
                None,
                &[0],
                &[1],
                OscoreSeqNum::MAX + 1,
                false
            )
            .unwrap_err(),
            OscoreError::InvalidParam
        );
        assert_eq!(
            Context::restore(&master_secret, None, &[0], &[1], 7, true).unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn rfc8613_nonce_formula_literal() {
        assert_eq!(
            compute_nonce(&[0xaa, 0xbb], &[0x01, 0x02, 0x03], &[0; NONCE_LEN]),
            hex!("020000000000aabb0000010203")
        );
    }

    #[test]
    fn oscore_option_literals() {
        let empty = parse_option(b"").unwrap();
        assert_eq!(empty.piv_len, 0);
        assert_eq!(empty.kid_len, 0);
        assert!(!empty.kid_present);
        assert!(!empty.kid_context_present);

        let populated = parse_option(b"\x09\x01\xaa").unwrap();
        assert_eq!(&populated.piv[..populated.piv_len as usize], b"\x01");
        assert_eq!(&populated.kid[..populated.kid_len as usize], b"\xaa");
        assert!(populated.kid_present);

        let with_context = parse_option(b"\x19\x01\x02\xbb\xcc\xaa").unwrap();
        assert_eq!(
            &with_context.kid_context[..with_context.kid_context_len as usize],
            b"\xbb\xcc"
        );
        assert!(with_context.kid_context_present);
        assert!(with_context.kid_present);

        for malformed in [
            &b"\x00"[..],
            &b"\x20"[..],
            &b"\x40"[..],
            &b"\x80"[..],
            &b"\x00\xaa"[..],
            &b"\x01\xaa\xbb"[..],
            &b"\x10\x00\xaa"[..],
        ] {
            assert_eq!(
                parse_option(malformed).unwrap_err(),
                OscoreError::InvalidParam
            );
        }
    }

    #[test]
    fn response_without_piv_uses_literal_request_nonce() {
        let master_secret = [0; KEY_LEN];
        let mut responder =
            Context::new_ephemeral(&master_secret, None, b"\xbb\xcc", b"\xaa").unwrap();
        responder.sender_key = [0x11; KEY_LEN];
        responder.common_iv = [0; NONCE_LEN];

        let (ciphertext, option) = responder
            .protect_response(0x45, &[], &[], b"\xaa", b"\x05", false)
            .unwrap();

        assert_eq!(ciphertext.as_slice(), &hex!("26f4d77f5a397d9c0a"));
        assert!(option.is_empty());
    }

    fn seq(n: u64) -> OscoreSeqNum {
        OscoreSeqNum::new(n).unwrap()
    }

    #[test]
    fn test_replay_window() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut ctx = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();

        // First packet accepted (is_replay returns false for valid packets)
        assert!(!ctx.is_replay(seq(0)));
        ctx.update_replay_window(seq(0));
        // Replay rejected (is_replay returns true for replays)
        assert!(ctx.is_replay(seq(0)));
        // New packet accepted
        assert!(!ctx.is_replay(seq(1)));
        ctx.update_replay_window(seq(1));
        // Earlier replay rejected
        assert!(ctx.is_replay(seq(0)));
        // Jump ahead - accepted
        assert!(!ctx.is_replay(seq(100)));
        ctx.update_replay_window(seq(100));
        // Now 50 is too old (outside window)
        assert!(ctx.is_replay(seq(50)));
    }

    #[test]
    fn five_byte_replay_ordering_and_duplicates() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let mut recipient = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
        sender.sender_seq = seq(0x1_0000_0000);

        let first = sender.protect_request(0x01, &[], b"first").unwrap();
        let second = sender.protect_request(0x01, &[], b"second").unwrap();
        assert_eq!(&first.1[1..6], b"\x01\x00\x00\x00\x00");

        recipient.unprotect_request(&second.1, &second.0).unwrap();
        recipient.unprotect_request(&first.1, &first.0).unwrap();
        assert_eq!(
            recipient.unprotect_request(&first.1, &first.0).unwrap_err(),
            OscoreError::Replay
        );
    }

    #[test]
    fn test_protect_unprotect_roundtrip() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender_ctx =
            Context::new_ephemeral(&master_secret, None, &[0x00], &[0x01]).unwrap();
        let mut recipient_ctx =
            Context::new_ephemeral(&master_secret, None, &[0x01], &[0x00]).unwrap();

        let code = 0x01; // GET
        let payload = b"hello";

        let (ciphertext, oscore_opt) = sender_ctx.protect_request(code, &[], payload).unwrap();

        let (dec_code, _options, dec_payload) = recipient_ctx
            .unprotect_request(&oscore_opt, &ciphertext)
            .unwrap();

        assert_eq!(dec_code, code);
        assert_eq!(dec_payload.as_slice(), payload);
    }

    #[test]
    fn empty_request_kid_still_requires_k_flag() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender = Context::new_ephemeral(&master_secret, None, b"", b"\x01").unwrap();
        let mut recipient = Context::new_ephemeral(&master_secret, None, b"\x01", b"").unwrap();
        let (ciphertext, option) = sender.protect_request(0x01, &[], b"request").unwrap();

        assert_eq!(option.as_slice(), b"\x09\x00");
        assert_eq!(
            recipient
                .unprotect_request(b"\x09\x00\x02", &ciphertext)
                .unwrap_err(),
            OscoreError::NoContext
        );
        assert_eq!(
            recipient
                .unprotect_request(b"\x01\x00", &ciphertext)
                .unwrap_err(),
            OscoreError::InvalidParam
        );
        recipient.unprotect_request(&option, &ciphertext).unwrap();
    }

    #[test]
    fn unprotect_request_compares_literal_id_context() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender = Context::new_ephemeral(&master_secret, None, b"\x00", b"\x01").unwrap();
        let (ciphertext, _) = sender.protect_request(0x01, &[], b"request").unwrap();
        let mut matching = Context::new_ephemeral(&master_secret, None, b"\x01", b"\x00").unwrap();
        matching.id_context[0] = 0xaa;
        matching.id_context_len = 1;
        matching.id_context_present = true;

        matching
            .unprotect_request(b"\x19\x00\x01\xaa\x00", &ciphertext)
            .unwrap();

        let mut tampered = Context::new_ephemeral(&master_secret, None, b"\x01", b"\x00").unwrap();
        tampered.id_context[0] = 0xaa;
        tampered.id_context_len = 1;
        tampered.id_context_present = true;
        assert_eq!(
            tampered
                .unprotect_request(b"\x19\x00\x01\xbb\x00", &ciphertext)
                .unwrap_err(),
            OscoreError::NoContext
        );
    }

    #[test]
    fn terminal_sender_sequence_is_used_once_then_exhausted() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut ctx = Context::new_ephemeral(&master_secret, None, &[0x00], &[0x01]).unwrap();

        ctx.sender_seq = OscoreSeqNum::new(OscoreSeqNum::MAX).unwrap();

        let (_, option) = ctx.protect_request(0x01, &[], b"last").unwrap();
        assert_eq!(option.as_slice(), b"\x0d\xff\xff\xff\xff\xff\x00");
        assert_eq!(ctx.sender_seq(), None);
        assert_eq!(
            ctx.protect_request(0x01, &[], b"again").unwrap_err(),
            OscoreError::SeqExhausted
        );
        assert_eq!(
            ctx.protect_response_with_piv(0x45, &[], b"again", &[1], &[0])
                .unwrap_err(),
            OscoreError::SeqExhausted
        );
        assert_eq!(ctx.sender_seq(), None);
    }

    #[test]
    fn rfc7252_inner_body_literal() {
        let body = b"\xbb.well-known\x04core\xff</sensors>";
        let (options, payload) = parse_inner_body(body).unwrap();
        assert_eq!(options, b"\xbb.well-known\x04core");
        assert_eq!(payload, b"</sensors>");
    }

    #[test]
    fn inner_body_preserves_ff_in_values_and_extensions() {
        let value = [0x13, 0xaa, 0xff, 0xbb];
        assert_eq!(parse_inner_body(&value).unwrap(), (&value[..], &[][..]));

        let extension = [0xd1, 0xff, 0xff];
        assert_eq!(
            parse_inner_body(&extension).unwrap(),
            (&extension[..], &[][..])
        );

        let mut length_extension = [0u8; 270];
        length_extension[0] = 0x0d;
        length_extension[1] = 0xff;
        length_extension[100] = 0xff;
        assert_eq!(
            parse_inner_body(&length_extension).unwrap(),
            (&length_extension[..], &[][..])
        );
    }

    #[test]
    fn public_roundtrip_preserves_embedded_ff_option_value() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let mut recipient = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
        let options = [0x13, 0xaa, 0xff, 0xbb];

        let (ciphertext, oscore_option) =
            sender.protect_request(0x02, &options, b"payload").unwrap();
        let (code, decoded_options, payload) = recipient
            .unprotect_request(&oscore_option, &ciphertext)
            .unwrap();

        assert_eq!(code, 0x02);
        assert_eq!(decoded_options.as_slice(), &options);
        assert_eq!(payload.as_slice(), b"payload");
    }

    #[test]
    fn public_unprotect_rejects_malformed_inner_options() {
        let malformed: &[&[u8]] = &[
            &[0xf0],                   // Reserved delta nibble.
            &[0x0f],                   // Reserved length nibble.
            &[0xd0],                   // Truncated one-byte delta extension.
            &[0xe0, 0x00],             // Truncated two-byte delta extension.
            &[0x0d],                   // Truncated one-byte length extension.
            &[0x0e, 0x00],             // Truncated two-byte length extension.
            &[0x02, 0xaa],             // Truncated option value.
            &[0xff],                   // Payload marker with an empty payload.
            &[0xe0, 0xfe, 0xf2, 0x10], // Cumulative option number overflow.
        ];
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");

        for options in malformed {
            let mut sender = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
            let mut recipient = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
            let (ciphertext, oscore_option) = sender.protect_request(0x02, options, &[]).unwrap();

            assert_eq!(
                recipient
                    .unprotect_request(&oscore_option, &ciphertext)
                    .unwrap_err(),
                OscoreError::InvalidParam,
                "accepted malformed options: {options:02x?}"
            );
        }
    }

    #[test]
    fn test_unprotect_response_with_piv() {
        // Simulate Alice -> Bob request, Bob -> Alice response
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice_ctx = Context::new_ephemeral(&master_secret, None, &[0x00], &[0x01]).unwrap();
        let mut bob_ctx = Context::new_ephemeral(&master_secret, None, &[0x01], &[0x00]).unwrap();

        // Alice sends request, save request_kid and request_piv
        let (_ciphertext, request_opt) = alice_ctx.protect_request(0x01, &[], b"request").unwrap();
        let request_piv_len = (request_opt[0] & 0x07) as usize;
        let request_piv = &request_opt[1..1 + request_piv_len];
        // Request KID is Alice's sender_id
        let request_kid = alice_ctx.sender_id();

        // Bob sends response using protect_response (with proper AAD)
        let response_code = 0x45; // 2.05 Content
        let (response_ciphertext, response_opt) = bob_ctx
            .protect_response(
                response_code,
                &[],
                b"response",
                request_kid,
                request_piv,
                true,
            )
            .unwrap();

        let mut forged = response_ciphertext.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert_eq!(
            alice_ctx
                .unprotect_response(&response_opt, &forged, request_piv)
                .unwrap_err(),
            OscoreError::DecryptFailed
        );

        // Alice decrypts response using unprotect_response.
        let (dec_code, _options, dec_payload) = alice_ctx
            .unprotect_response(&response_opt, &response_ciphertext, request_piv)
            .unwrap();

        assert_eq!(dec_code, response_code);
        assert_eq!(dec_payload.as_slice(), b"response");
        assert_eq!(
            alice_ctx
                .unprotect_response(&response_opt, &response_ciphertext, request_piv)
                .unwrap_err(),
            OscoreError::Replay
        );
    }

    #[test]
    fn ordinary_response_rejects_duplicate_request_piv() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let mut bob = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
        let (_, request_option) = alice.protect_request(0x01, &[], b"request").unwrap();
        let request_piv = &request_option[1..2];
        let response = bob
            .protect_response_with_piv(0x45, &[], b"response", &[0], request_piv)
            .unwrap();

        alice
            .unprotect_response(&response.1, &response.0, request_piv)
            .unwrap();
        assert_eq!(
            alice
                .unprotect_response(&response.1, &response.0, request_piv)
                .unwrap_err(),
            OscoreError::Replay
        );
    }

    #[test]
    fn observe_accepts_multiple_fresh_responder_pivs_for_one_request() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let mut bob = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
        let (_, request_option) = alice.protect_request(0x01, &[], b"observe").unwrap();
        let request_piv = &request_option[1..2];
        let first = bob
            .protect_response_with_piv(0x45, &[], b"first", &[0], request_piv)
            .unwrap();
        let second = bob
            .protect_response_with_piv(0x45, &[], b"second", &[0], request_piv)
            .unwrap();

        assert_eq!(
            alice
                .unprotect_observe_response(&first.1, &first.0, request_piv)
                .unwrap()
                .2,
            b"first"
        );
        assert_eq!(
            alice
                .unprotect_observe_response(&second.1, &second.0, request_piv)
                .unwrap()
                .2,
            b"second"
        );

        // A normal response remains one-shot even when each response has a fresh PIV.
        let mut ordinary = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        ordinary
            .unprotect_response(&first.1, &first.0, request_piv)
            .unwrap();
        assert_eq!(
            ordinary
                .unprotect_response(&second.1, &second.0, request_piv)
                .unwrap_err(),
            OscoreError::Replay
        );
    }

    #[test]
    fn observe_replay_window_accepts_out_of_order_once_and_rejects_old() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let mut request_sender = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let (_, request_option) = request_sender
            .protect_request(0x01, &[], b"observe")
            .unwrap();
        let request_piv = &request_option[1..2];

        let make_response = |sequence: u64, payload: &'static [u8]| {
            let mut responder = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
            responder.sender_seq = seq(sequence);
            responder
                .protect_response_with_piv(0x45, &[], payload, &[0], request_piv)
                .unwrap()
        };
        let ten = make_response(10, b"ten");
        let twelve = make_response(12, b"twelve");
        let eleven = make_response(11, b"eleven");
        let forty_four = make_response(44, b"forty-four");

        for response in [&ten, &twelve, &eleven] {
            alice
                .unprotect_observe_response(&response.1, &response.0, request_piv)
                .unwrap();
        }
        assert!(matches!(
            alice.begin_unprotect_observe_response(&eleven.1, &eleven.0, request_piv),
            Err(OscoreError::Replay)
        ));
        alice
            .unprotect_observe_response(&forty_four.1, &forty_four.0, request_piv)
            .unwrap();
        assert!(matches!(
            alice.begin_unprotect_observe_response(&twelve.1, &twelve.0, request_piv),
            Err(OscoreError::Replay)
        ));
    }

    #[test]
    fn observe_failure_and_dropped_pending_do_not_advance_replay_state() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let mut bob = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
        let (_, request_option) = alice.protect_request(0x01, &[], b"observe").unwrap();
        let request_piv = &request_option[1..2];
        let response = bob
            .protect_response_with_piv(0x45, &[], b"notification", &[0], request_piv)
            .unwrap();

        let mut corrupt = response.0.clone();
        corrupt[0] ^= 1;
        assert!(matches!(
            alice.begin_unprotect_observe_response(&response.1, &corrupt, request_piv),
            Err(OscoreError::DecryptFailed)
        ));
        let mut wrong_kid = response.1.clone();
        wrong_kid[0] |= 0x08;
        wrong_kid.push(2).unwrap();
        assert!(matches!(
            alice.begin_unprotect_observe_response(&wrong_kid, &response.0, request_piv),
            Err(OscoreError::NoContext)
        ));

        drop(
            alice
                .begin_unprotect_observe_response(&response.1, &response.0, request_piv)
                .unwrap(),
        );
        alice
            .unprotect_observe_response(&response.1, &response.0, request_piv)
            .unwrap();
        // Once committed, an exact encrypted retransmission is recognized as replay. The CoAP
        // transport handles such a retransmission from its cached bytes without decrypting it.
        assert!(matches!(
            alice.begin_unprotect_observe_response(&response.1, &response.0, request_piv),
            Err(OscoreError::Replay)
        ));
    }

    #[test]
    fn observe_requires_explicit_piv_and_accepts_terminal_40_bit_piv_once() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let mut bob = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
        let (_, request_option) = alice.protect_request(0x01, &[], b"observe").unwrap();
        let request_piv = &request_option[1..2];

        let no_piv = bob
            .protect_response(0x45, &[], b"one-shot", &[0], request_piv, false)
            .unwrap();
        assert!(matches!(
            alice.begin_unprotect_observe_response(&no_piv.1, &no_piv.0, request_piv),
            Err(OscoreError::InvalidParam)
        ));

        bob.sender_seq = seq(OscoreSeqNum::MAX);
        let terminal = bob
            .protect_response_with_piv(0x45, &[], b"terminal", &[0], request_piv)
            .unwrap();
        assert_eq!(terminal.1.as_slice(), b"\x05\xff\xff\xff\xff\xff");
        alice
            .unprotect_observe_response(&terminal.1, &terminal.0, request_piv)
            .unwrap();
        assert!(matches!(
            alice.begin_unprotect_observe_response(&terminal.1, &terminal.0, request_piv),
            Err(OscoreError::Replay)
        ));
        assert_eq!(
            bob.protect_response_with_piv(0x45, &[], b"exhausted", &[0], request_piv)
                .unwrap_err(),
            OscoreError::SeqExhausted
        );
    }

    #[test]
    fn dropped_pending_response_preserves_committed_window_across_large_jump() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let mut bob = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
        let prior_piv = [0];
        let current_piv = [64];
        let prior = bob
            .protect_response_with_piv(0x45, &[], b"prior", &[0], &prior_piv)
            .unwrap();
        let current = bob
            .protect_response_with_piv(0x45, &[], b"current", &[0], &current_piv)
            .unwrap();

        alice
            .unprotect_response(&prior.1, &prior.0, &prior_piv)
            .unwrap();
        drop(
            alice
                .begin_unprotect_response(&current.1, &current.0, &current_piv)
                .unwrap(),
        );

        assert_eq!(
            alice
                .unprotect_response(&prior.1, &prior.0, &prior_piv)
                .unwrap_err(),
            OscoreError::Replay
        );
        let (_, _, payload) = alice
            .begin_unprotect_response(&current.1, &current.0, &current_piv)
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(payload.as_slice(), b"current");
        assert_eq!(
            alice
                .unprotect_response(&current.1, &current.0, &current_piv)
                .unwrap_err(),
            OscoreError::Replay
        );
    }

    #[test]
    fn invalid_response_code_does_not_consume_request_piv() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let mut bob = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
        let (_, request_option) = alice.protect_request(0x01, &[], b"request").unwrap();
        let request_piv = &request_option[1..2];

        for code in [0x01, 0xc1] {
            let invalid = bob
                .protect_response_with_piv(code, &[], b"invalid", &[0], request_piv)
                .unwrap();
            assert!(matches!(
                alice.begin_unprotect_response(&invalid.1, &invalid.0, request_piv),
                Err(OscoreError::InvalidParam)
            ));
        }

        let valid = bob
            .protect_response_with_piv(0x45, &[], b"valid", &[0], request_piv)
            .unwrap();
        assert_eq!(
            alice
                .unprotect_response(&valid.1, &valid.0, request_piv)
                .unwrap()
                .2,
            b"valid"
        );
    }

    #[test]
    fn delayed_explicit_piv_ordinary_response_ignores_peer_replay_window() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let mut bob = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
        let (_, request_option) = alice.protect_request(0x01, &[], b"request").unwrap();
        let request_piv = &request_option[1..2];
        bob.sender_seq = seq(0x1_0000_0000);

        let delayed = bob
            .protect_response_with_piv(0x45, &[], b"delayed", &[0], request_piv)
            .unwrap();
        assert_eq!(delayed.1.as_slice(), b"\x05\x01\x00\x00\x00\x00");
        alice.recipient_seq = seq(0x1_0000_0020);
        alice.replay_window = u32::MAX;

        alice
            .unprotect_response(&delayed.1, &delayed.0, request_piv)
            .unwrap();
        assert_eq!(
            alice
                .unprotect_response(&delayed.1, &delayed.0, request_piv)
                .unwrap_err(),
            OscoreError::Replay
        );
    }

    #[test]
    fn response_kid_mismatch_does_not_consume_request() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let mut bob = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
        let (_, request_option) = alice.protect_request(0x01, &[], b"request").unwrap();
        let request_piv = &request_option[1..2];
        let response = bob
            .protect_response_with_piv(0x45, &[], b"response", &[0], request_piv)
            .unwrap();

        assert_eq!(
            alice
                .unprotect_response(b"\x09\x00\x02", &response.0, request_piv)
                .unwrap_err(),
            OscoreError::NoContext
        );
        alice
            .unprotect_response(&response.1, &response.0, request_piv)
            .unwrap();
    }

    #[test]
    fn response_id_context_is_checked_before_decryption() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new_ephemeral(&master_secret, None, b"\x00", b"\x01").unwrap();
        let mut bob = Context::new_ephemeral(&master_secret, None, b"\x01", b"\x00").unwrap();
        let (_, request_option) = alice.protect_request(0x01, &[], b"request").unwrap();
        let request_piv = &request_option[1..2];
        let (ciphertext, _) = bob
            .protect_response_with_piv(0x45, &[], b"response", b"\x00", request_piv)
            .unwrap();
        alice.id_context[0] = 0xaa;
        alice.id_context_len = 1;
        alice.id_context_present = true;

        assert_eq!(
            alice
                .unprotect_response(b"\x11\x00\x01\xbb", &ciphertext, request_piv)
                .unwrap_err(),
            OscoreError::NoContext
        );
    }

    #[test]
    fn response_without_piv_requires_requester_identity() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut responder = Context::new_ephemeral(&master_secret, None, b"\x01", b"\x00").unwrap();

        assert_eq!(
            responder
                .protect_response(0x45, &[], b"response", b"\x02", b"\x00", false)
                .unwrap_err(),
            OscoreError::InvalidParam
        );
        responder
            .protect_response(0x45, &[], b"response", b"\x00", b"\x00", false)
            .unwrap();
    }

    #[test]
    fn request_identifiers_accept_present_empty_kid() {
        let identifiers = request_identifiers(b"\x09\x01").unwrap();

        assert_eq!(identifiers.kid(), b"");
        assert_eq!(identifiers.piv(), b"\x01");
    }

    #[test]
    fn response_with_piv_requires_requester_identity() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut responder = Context::new_ephemeral(&master_secret, None, b"\x01", b"\x00").unwrap();

        assert_eq!(
            responder
                .protect_response_with_piv(0x45, &[], b"response", b"\x02", b"\x00")
                .unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn response_without_piv_is_one_shot_per_request() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut responder = Context::new_ephemeral(&master_secret, None, b"\x01", b"\x00").unwrap();

        responder
            .protect_response(0x45, &[], b"first", b"\x00", b"\x07", false)
            .unwrap();
        assert_eq!(
            responder
                .protect_response(0x45, &[], b"second", b"\x00", b"\x07", false)
                .unwrap_err(),
            OscoreError::Replay
        );

        responder
            .protect_response(0x45, &[], b"later", b"\x00", b"\x28", false)
            .unwrap();
        assert_eq!(
            responder
                .protect_response(0x45, &[], b"stale", b"\x00", b"\x07", false)
                .unwrap_err(),
            OscoreError::Replay
        );
    }

    #[test]
    fn public_unprotect_rejects_nonminimal_piv() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender = Context::new_ephemeral(&master_secret, None, &[0], &[1]).unwrap();
        let mut recipient = Context::new_ephemeral(&master_secret, None, &[1], &[0]).unwrap();
        let (ciphertext, _) = sender.protect_request(0x01, &[], b"request").unwrap();

        assert_eq!(
            recipient
                .unprotect_request(b"\x0a\x00\x00\x00", &ciphertext)
                .unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn test_unprotect_response_without_piv_uses_request_piv() {
        // Test that when response has no PIV in OSCORE option, request_piv is used for nonce
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice_ctx = Context::new_ephemeral(&master_secret, None, &[0x00], &[0x01]).unwrap();
        let mut bob_ctx = Context::new_ephemeral(&master_secret, None, &[0x01], &[0x00]).unwrap();

        // Alice sends request, save request_kid and request_piv
        let (_ciphertext, request_opt) = alice_ctx.protect_request(0x01, &[], b"request").unwrap();
        let request_piv_len = (request_opt[0] & 0x07) as usize;
        let request_piv = request_opt[1..1 + request_piv_len].to_vec();
        let request_kid = alice_ctx.sender_id();

        // Bob sends response without PIV in OSCORE option (include_piv: false)
        let response_code = 0x45u8;
        let payload = b"response";
        let (response_ciphertext, response_opt) = bob_ctx
            .protect_response(
                response_code,
                &[],
                payload,
                request_kid,
                &request_piv,
                false,
            )
            .unwrap();

        // No PIV, KID, or KID Context encodes as an empty option value.
        assert!(response_opt.is_empty());

        // Alice decrypts using unprotect_response with request_piv
        let (dec_code, _options, dec_payload) = alice_ctx
            .unprotect_response(&response_opt, &response_ciphertext, &request_piv)
            .unwrap();

        assert_eq!(dec_code, response_code);
        assert_eq!(dec_payload.as_slice(), payload);
        assert_eq!(
            alice_ctx
                .unprotect_response(&response_opt, &response_ciphertext, &request_piv)
                .unwrap_err(),
            OscoreError::Replay
        );
    }

    #[test]
    fn test_find_payload_marker_skips_0xff_in_option_value() {
        // Test that find_payload_marker correctly parses options and doesn't
        // mistake 0xFF in option values for the payload marker.
        //
        // CoAP option encoding (RFC 7252 Section 3.1):
        //   byte 0: delta (upper nibble) | length (lower nibble)
        //   bytes 1..1+len: option value
        //
        // Example: An option with delta=1, length=1, value=0xFF
        // Wire format: [0x11, 0xFF] followed by [0xFF] payload marker

        // Option: delta=1, length=1, value=0xFF, then payload marker, then payload "hi"
        let data = [0x11, 0xFF, 0xFF, b'h', b'i'];

        // The payload marker should be at index 2, NOT index 1
        let marker_pos = find_payload_marker(&data).unwrap();
        assert_eq!(marker_pos, Some(2));

        // Verify the slices would be correct
        let options_slice = &data[..2]; // [0x11, 0xFF]
        let payload_slice = &data[3..]; // "hi"
        assert_eq!(options_slice, &[0x11, 0xFF]);
        assert_eq!(payload_slice, b"hi");
    }

    #[test]
    fn test_find_payload_marker_no_marker() {
        // Options only, no payload marker
        let data = [0x11, 0x42]; // delta=1, length=1, value=0x42
        let marker_pos = find_payload_marker(&data).unwrap();
        assert_eq!(marker_pos, None);
    }

    #[test]
    fn test_find_payload_marker_immediate_marker() {
        // Payload marker at start (no options)
        let data = [0xFF, b'p', b'a', b'y'];
        let marker_pos = find_payload_marker(&data).unwrap();
        assert_eq!(marker_pos, Some(0));
    }

    #[test]
    fn test_find_payload_marker_extended_length() {
        // Option with extended length (13 + ext byte)
        // delta=0, length=13 (0x0D), extended_len=0 => actual len=13
        // Format: [0x0D, 0x00, <13 value bytes>, 0xFF, payload...]
        let data: [u8; 23] = [
            0x0D, 0x00, // delta=0, length=13, ext=0 (actual 13)
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, // 13 value bytes
            0xFF, // payload marker
            b'p', b'a', b'y', b'l', b'o', b'a', b'd', // "payload"
        ];

        let marker_pos = find_payload_marker(&data).unwrap();
        assert_eq!(marker_pos, Some(15)); // 2 header bytes + 13 value bytes
    }

    #[test]
    fn test_roundtrip_with_0xff_in_class_e_options() {
        // End-to-end test: protect a request with 0xFF in options, verify decryption
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender_ctx =
            Context::new_ephemeral(&master_secret, None, &[0x00], &[0x01]).unwrap();
        let mut recipient_ctx =
            Context::new_ephemeral(&master_secret, None, &[0x01], &[0x00]).unwrap();

        let code = 0x01; // GET
        // Class E options with 0xFF embedded in a value:
        // Option delta=1, length=2, value=[0xFF, 0x42]
        let class_e_options = [0x12, 0xFF, 0x42];
        let payload = b"test payload";

        let (ciphertext, oscore_opt) = sender_ctx
            .protect_request(code, &class_e_options, payload)
            .unwrap();

        let (dec_code, dec_options, dec_payload) = recipient_ctx
            .unprotect_request(&oscore_opt, &ciphertext)
            .unwrap();

        assert_eq!(dec_code, code);
        assert_eq!(dec_options.as_slice(), &class_e_options);
        assert_eq!(dec_payload.as_slice(), payload);
    }
}
