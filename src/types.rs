// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! Core types and constants for OSCORE.

use zeroize::Zeroize;

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
pub const NONCE_ID_END: usize = 8;

/// Nonce field: PIV region starts at byte 8 (bytes 8-12 = 5 bytes for PIV).
pub const NONCE_PIV_START: usize = 8;

/// Nonce field: Maximum ID length (7 bytes, fits in bytes 1-7).
pub const NONCE_ID_LEN: usize = NONCE_ID_END - 1; // = 7

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

/// Sender sequence state that must be persisted before transmitting a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderSequenceState {
    /// Next sender sequence that may be used.
    pub next_sequence: u64,
    /// Whether the terminal sequence has already been consumed.
    pub exhausted: bool,
}

/// Stable identifier for one directional OSCORE sender context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroize)]
pub struct ContextId([u8; 32]);

impl ContextId {
    /// Create a new ContextId from raw bytes.
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the identifier bytes for use as a durable-store key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Atomic durable storage for an OSCORE sender sequence.
///
/// Implementations MUST update `expected` to `next` atomically and return
/// `Ok(false)` without changing storage when the current value differs.
pub trait SenderStateStore {
    /// Storage-specific failure.
    type Error;

    /// Load state for exactly `context_id`.
    fn load(&mut self, context_id: &ContextId) -> Result<Option<SenderSequenceState>, Self::Error>;

    /// Atomically replace `expected` with `next` for exactly `context_id`.
    fn compare_exchange(
        &mut self,
        context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error>;
}

/// Request identifiers needed to bind an OSCORE response to its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestIdentifiers {
    pub(crate) kid: [u8; ID_MAX_LEN],
    pub(crate) kid_len: u8,
    pub(crate) piv: [u8; PIV_MAX_LEN],
    pub(crate) piv_len: u8,
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
