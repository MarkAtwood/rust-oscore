// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! Error types for OSCORE operations.

/// Buffer size insufficient for the requested operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall {
    /// Bytes required.
    pub needed: usize,
    /// Bytes available.
    pub available: usize,
}

impl BufferTooSmall {
    /// Create a new BufferTooSmall error.
    pub fn new(needed: usize, available: usize) -> Self {
        Self { needed, available }
    }
}

impl core::fmt::Display for BufferTooSmall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "buffer too small: needed {} bytes, available {}",
            self.needed, self.available
        )
    }
}

impl core::error::Error for BufferTooSmall {}

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
