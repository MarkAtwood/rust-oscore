// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! Core EDHOC types: connection identifiers, credential references, and buffer helpers.

use super::{CONNECTION_ID_CAPACITY, EdhocError, ID_CRED_MAX_LEN};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An EDHOC connection identifier in its raw byte-string form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionId(pub(crate) heapless::Vec<u8, CONNECTION_ID_CAPACITY>);

impl ConnectionId {
    /// Create a bounded connection identifier.
    pub fn new(value: &[u8]) -> Result<Self, EdhocError> {
        let mut id = heapless::Vec::new();
        id.extend_from_slice(value)
            .map_err(|_| EdhocError::BufferTooSmall)?;
        Ok(Self(id))
    }

    /// Return the raw identifier bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<u8> for ConnectionId {
    fn from(value: u8) -> Self {
        let mut id = heapless::Vec::new();
        id.push(value).expect("one byte fits in a connection ID");
        Self(id)
    }
}

/// Credential reference carried by ID_CRED.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdCredReference {
    /// COSE `kid` header parameter.
    Kid(heapless::Vec<u8, ID_CRED_MAX_LEN>),
    /// COSE `x5t` header parameter: hash algorithm and certificate thumbprint.
    X5t {
        algorithm: i128,
        hash: heapless::Vec<u8, ID_CRED_MAX_LEN>,
    },
}

/// Parsed deterministic-CBOR ID_CRED with its exact canonical map encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdCred {
    pub(crate) encoded: heapless::Vec<u8, ID_CRED_MAX_LEN>,
    pub(crate) reference: IdCredReference,
}

impl IdCred {
    /// Return the canonical map encoding used by EDHOC transcript calculations.
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Return the credential reference selected by the peer.
    pub fn reference(&self) -> &IdCredReference {
        &self.reference
    }
}

/// Helper trait for heapless::Vec push/extend with error mapping.
pub(crate) trait VecExt<T, const N: usize> {
    fn push_err(&mut self, item: T) -> Result<(), EdhocError>;
    fn extend_err(&mut self, slice: &[T]) -> Result<(), EdhocError>
    where
        T: Clone;
}

impl<T, const N: usize> VecExt<T, N> for heapless::Vec<T, N> {
    fn push_err(&mut self, item: T) -> Result<(), EdhocError> {
        self.push(item).map_err(|_| EdhocError::BufferTooSmall)
    }

    fn extend_err(&mut self, slice: &[T]) -> Result<(), EdhocError>
    where
        T: Clone,
    {
        self.extend_from_slice(slice)
            .map_err(|_| EdhocError::BufferTooSmall)
    }
}

/// A stack-backed byte buffer which wipes its initialized contents on drop.
pub(crate) struct SecretVec<const N: usize>(pub(crate) heapless::Vec<u8, N>);

impl<const N: usize> SecretVec<N> {
    pub(crate) fn new() -> Self {
        Self(heapless::Vec::new())
    }
}

impl<const N: usize> core::ops::Deref for SecretVec<N> {
    type Target = heapless::Vec<u8, N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> core::ops::DerefMut for SecretVec<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> Drop for SecretVec<N> {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

impl<const N: usize> Zeroize for SecretVec<N> {
    fn zeroize(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

// The Drop impl above wipes the initialized buffer, matching the marker contract.
impl<const N: usize> ZeroizeOnDrop for SecretVec<N> {}
