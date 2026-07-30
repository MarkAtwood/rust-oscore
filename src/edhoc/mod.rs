// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! EDHOC (RFC 9528) Suite 0 implementation for establishing OSCORE contexts.
//!
//! Suite 0: X25519 + Ed25519/Schnorr48 + AES-CCM-16-64-128 + SHA-256
//!
//! # Signature Schemes
//!
//! - **`edhoc` feature (default)**: Ed25519 signatures (64B), RFC 9528 compliant
//! - **`edhoc-schnorr48` feature**: Schnorr48 signatures (48B), LICHEN variant
//!
//! # ponytail: minimal Suite 0
//!
//! Rolled minimal implementation because:
//! - lakers only supports Suite 2 (P-256), not Suite 0 (X25519/Ed25519)
//! - Suite 0 matches LICHEN link-layer requirements
//! - Python simulator uses Suite 0, so interop requires Suite 0
//!
//! Uses existing crates: x25519-dalek, ed25519-dalek or schnorr48, aes/ccm, hkdf/sha2.
//! Their zeroize features wipe owned secret keys, hash state, and expanded AES schedules on drop.
//! HMAC 0.13 key setup and HKDF 0.13 expansion also use private call-local arrays which their
//! APIs do not expose for wiping. Replacing those vetted primitives locally would violate the
//! project's crypto policy; remediation requires upstream support. Rust likewise cannot
//! guarantee removal of compiler-created register or stack copies.

mod cbor;
mod credential;
mod initiator;
mod kdf;
mod responder;
pub(crate) mod sign;
mod transcript;
mod types;

#[cfg(test)]
mod tests;

// Re-export public types and functions
pub use credential::PeerCredential;
pub use initiator::{EdhocInitiator, PendingMessage2};
pub use responder::{EdhocResponder, PendingMessage3};
pub use types::{ConnectionId, IdCred, IdCredReference};

/// X25519 key length.
pub const KEY_LEN_32: usize = 32;

/// Signature length (64B for Ed25519, 48B for Schnorr48).
pub use sign::SIG_LEN;

/// Suite 0 identifier.
pub const SUITE_0: u8 = 0;

/// Connection identifier capacity supported by this implementation's OSCORE nonce layout.
pub const CONNECTION_ID_CAPACITY: usize = 7;

/// Maximum encoded ID_CRED length accepted by this implementation.
pub const ID_CRED_MAX_LEN: usize = 64;

/// Maximum number of COSE header parameters accepted in an ID_CRED map.
pub const ID_CRED_MAX_PARAMETERS: usize = 8;

/// EDHOC error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EdhocError {
    /// Protocol state error.
    InvalidState,
    /// Invalid message format.
    InvalidMessage,
    /// Unsupported cipher suite.
    UnsupportedSuite,
    /// Signature verification failed.
    SignatureVerification,
    /// AEAD decryption failed.
    DecryptFailed,
    /// Buffer too small.
    BufferTooSmall,
    /// Key derivation function failed.
    KeyDerivation,
}

impl core::fmt::Display for EdhocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidState => write!(f, "invalid protocol state"),
            Self::InvalidMessage => write!(f, "invalid message format"),
            Self::UnsupportedSuite => write!(f, "unsupported cipher suite"),
            Self::SignatureVerification => write!(f, "signature verification failed"),
            Self::DecryptFailed => write!(f, "AEAD decryption failed"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::KeyDerivation => write!(f, "key derivation failed"),
        }
    }
}

impl core::error::Error for EdhocError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lifecycle {
    Created,
    Message1Created,
    AwaitingMessage3,
    PendingMessage2,
    PendingMessage3,
    Complete,
    Failed,
    Zeroized,
}
