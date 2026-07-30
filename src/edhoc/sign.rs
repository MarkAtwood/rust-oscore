// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! Signature abstraction for EDHOC.
//!
//! Provides a unified interface over Ed25519 (RFC 9528 standard) and
//! Schnorr48 (LICHEN variant) based on feature flags.

#[cfg(feature = "edhoc-schnorr48")]
use zeroize::{Zeroize, ZeroizeOnDrop};
#[cfg(not(feature = "edhoc-schnorr48"))]
use zeroize::Zeroize;

/// Signature length in bytes.
#[cfg(feature = "edhoc-schnorr48")]
pub const SIG_LEN: usize = 48;

#[cfg(not(feature = "edhoc-schnorr48"))]
pub const SIG_LEN: usize = 64;

/// Signing private key (zeroized on drop).
#[cfg(feature = "edhoc-schnorr48")]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey {
    inner: schnorr48::PrivateKey,
}

#[cfg(not(feature = "edhoc-schnorr48"))]
pub struct SigningKey {
    inner: ed25519_dalek::SigningKey,
}

#[cfg(not(feature = "edhoc-schnorr48"))]
impl Clone for SigningKey {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

#[cfg(not(feature = "edhoc-schnorr48"))]
impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        // ed25519_dalek::SigningKey implements ZeroizeOnDrop internally
        // We can't easily zeroize it, but it will be wiped on drop
    }
}

#[cfg(not(feature = "edhoc-schnorr48"))]
impl Drop for SigningKey {
    fn drop(&mut self) {
        // ed25519_dalek::SigningKey already implements ZeroizeOnDrop
    }
}

/// Verification public key.
#[derive(Clone, Copy)]
pub struct VerifyingKey {
    #[cfg(feature = "edhoc-schnorr48")]
    inner: schnorr48::PublicKey,
    #[cfg(not(feature = "edhoc-schnorr48"))]
    inner: ed25519_dalek::VerifyingKey,
}

impl SigningKey {
    /// Derive signing key from 32-byte seed.
    #[cfg(feature = "edhoc-schnorr48")]
    pub fn from_seed(seed: &[u8; 32]) -> (Self, VerifyingKey) {
        let schnorr_seed = schnorr48::Seed::new(*seed);
        let (privkey, pubkey) = schnorr48::derive_keypair(&schnorr_seed);
        (
            Self { inner: privkey },
            VerifyingKey { inner: pubkey },
        )
    }

    #[cfg(not(feature = "edhoc-schnorr48"))]
    pub fn from_seed(seed: &[u8; 32]) -> (Self, VerifyingKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        (
            Self { inner: signing_key },
            VerifyingKey { inner: verifying_key },
        )
    }

    /// Get raw key bytes (for testing zeroization).
    #[cfg(feature = "edhoc-schnorr48")]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }

    #[cfg(not(feature = "edhoc-schnorr48"))]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }

    /// Sign a message.
    #[cfg(feature = "edhoc-schnorr48")]
    pub fn sign(&self, pubkey: &VerifyingKey, message: &[u8]) -> [u8; SIG_LEN] {
        schnorr48::sign(&self.inner, &pubkey.inner, message)
    }

    #[cfg(not(feature = "edhoc-schnorr48"))]
    pub fn sign(&self, _pubkey: &VerifyingKey, message: &[u8]) -> [u8; SIG_LEN] {
        use ed25519_dalek::Signer;
        self.inner.sign(message).to_bytes()
    }
}

impl VerifyingKey {
    /// Create from 32-byte public key bytes.
    #[cfg(feature = "edhoc-schnorr48")]
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        // Validate point is on curve using curve25519-dalek
        use curve25519_dalek::edwards::CompressedEdwardsY;
        let compressed = CompressedEdwardsY::from_slice(bytes).ok()?;
        let _point = compressed.decompress()?;
        Some(Self {
            inner: schnorr48::PublicKey::new(*bytes),
        })
    }

    #[cfg(not(feature = "edhoc-schnorr48"))]
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .ok()
            .map(|inner| Self { inner })
    }

    /// Verify a signature.
    #[cfg(feature = "edhoc-schnorr48")]
    pub fn verify(&self, message: &[u8], signature: &[u8; SIG_LEN]) -> bool {
        schnorr48::verify(&self.inner, message, signature)
    }

    #[cfg(not(feature = "edhoc-schnorr48"))]
    pub fn verify(&self, message: &[u8], signature: &[u8; SIG_LEN]) -> bool {
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.inner.verify_strict(message, &sig).is_ok()
    }

    /// Get raw 32-byte public key.
    #[cfg(feature = "edhoc-schnorr48")]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }

    #[cfg(not(feature = "edhoc-schnorr48"))]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }
}
