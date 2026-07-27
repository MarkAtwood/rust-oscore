//! OSCORE sender sequence number newtype.
//!
//! Wraps a 40-bit sequence number with OSCORE-specific semantics:
//! - Monotonically increasing (never wraps for security)
//! - Used for nonce derivation and replay protection
//!
//! The newtype provides type safety to prevent mixing OSCORE sequence
//! numbers with other integer values or link-layer sequence numbers.

use zeroize::Zeroize;

/// OSCORE sender sequence number (40-bit, monotonic).
///
/// This is the Partial IV (PIV) included in OSCORE-protected messages.
/// Unlike link-layer sequence numbers, OSCORE sequences must never wrap
/// for the same security context - doing so would compromise security.
///
/// # Security
///
/// When `sender_seq` approaches [`OscoreSeqNum::MAX`], the context must be
/// renegotiated to prevent nonce reuse. The `is_near_exhaustion`
/// method checks for this condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Zeroize)]
#[repr(transparent)]
pub struct OscoreSeqNum(u64);

/// Threshold for sequence number exhaustion warning.
const EXHAUSTION_THRESHOLD: u64 = OscoreSeqNum::MAX - 1000;

impl OscoreSeqNum {
    /// Maximum OSCORE Partial IV value (RFC 8613 Section 5.2).
    pub const MAX: u64 = (1 << 40) - 1;

    /// Create a new OSCORE sequence number, or `None` if it exceeds 40 bits.
    #[inline]
    pub const fn new(value: u64) -> Option<Self> {
        if value <= Self::MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Get the raw value.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Increment by one, returning the new value.
    ///
    /// Returns `None` if the sequence number is at `Self::MAX` (would overflow).
    /// SECURITY: Callers must handle `None` by renegotiating the security context
    /// to prevent nonce reuse, which would compromise AES-CCM confidentiality.
    #[inline]
    #[must_use = "returns a new value; does not modify self"]
    pub const fn increment(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(v) if v <= Self::MAX => Some(Self(v)),
            _ => None,
        }
    }

    /// Increment in place, returning the old value.
    ///
    /// Useful for the sender path where you want to use the current
    /// sequence number and advance to the next.
    ///
    /// Returns `None` if the sequence number is at `Self::MAX` (would overflow).
    /// SECURITY: Callers must handle `None` by renegotiating the security context
    /// to prevent nonce reuse, which would compromise AES-CCM confidentiality.
    #[inline]
    pub fn fetch_increment(&mut self) -> Option<Self> {
        let old = *self;
        *self = self.increment()?;
        Some(old)
    }

    /// Check if the sequence number is near exhaustion.
    ///
    /// Returns true when fewer than 1000 sequence numbers remain before
    /// overflow. The application should renegotiate the security context
    /// when this returns true.
    #[inline]
    pub const fn is_near_exhaustion(self) -> bool {
        self.0 >= EXHAUSTION_THRESHOLD
    }

    /// Encode as variable-length big-endian PIV (1-5 bytes).
    ///
    /// OSCORE uses the minimum number of bytes needed to represent the value.
    pub fn encode_piv(self, piv: &mut [u8; 5]) -> usize {
        let seq = self.0;
        if seq == 0 {
            piv[0] = 0;
            return 1;
        }

        let mut len = 0;
        let mut tmp = seq;
        while tmp > 0 {
            len += 1;
            tmp >>= 8;
        }

        let mut s = seq;
        for i in 0..len {
            piv[len - 1 - i] = (s & 0xFF) as u8;
            s >>= 8;
        }

        len
    }

    /// Decode from a 1-5 byte big-endian PIV.
    pub fn from_piv(piv: &[u8]) -> Option<Self> {
        if piv.is_empty() || piv.len() > 5 || (piv.len() > 1 && piv[0] == 0) {
            return None;
        }
        Self::new(
            piv.iter()
                .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte)),
        )
    }
}

impl core::fmt::Display for OscoreSeqNum {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for OscoreSeqNum {
    #[inline]
    fn from(value: u32) -> Self {
        Self(u64::from(value))
    }
}

impl TryFrom<u64> for OscoreSeqNum {
    type Error = ();

    #[inline]
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(())
    }
}

impl From<OscoreSeqNum> for u64 {
    #[inline]
    fn from(value: OscoreSeqNum) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_operations() {
        let seq = OscoreSeqNum::new(0).unwrap();
        assert_eq!(seq.get(), 0);
        assert_eq!(seq.increment().unwrap().get(), 1);
    }

    #[test]
    fn fetch_increment() {
        let mut seq = OscoreSeqNum::new(0).unwrap();
        let old = seq.fetch_increment().expect("should not overflow from 0");
        assert_eq!(old.get(), 0);
        assert_eq!(seq.get(), 1);
    }

    #[test]
    fn increment_at_max_returns_none() {
        let seq = OscoreSeqNum::new(OscoreSeqNum::MAX).unwrap();
        assert!(seq.increment().is_none());

        let mut seq_mut = OscoreSeqNum::new(OscoreSeqNum::MAX).unwrap();
        assert!(seq_mut.fetch_increment().is_none());
        // Value unchanged after failed increment
        assert_eq!(seq_mut.get(), OscoreSeqNum::MAX);
    }

    #[test]
    fn increment_near_max_succeeds() {
        let seq = OscoreSeqNum::new((u32::MAX - 1) as u64).unwrap();
        let next = seq.increment().expect("should succeed at MAX-1");
        assert_eq!(next.get(), u32::MAX as u64);
    }

    #[test]
    fn exhaustion_detection() {
        let low = OscoreSeqNum::new(1000).unwrap();
        assert!(!low.is_near_exhaustion());

        let high = OscoreSeqNum::new(EXHAUSTION_THRESHOLD).unwrap();
        assert!(high.is_near_exhaustion());

        let max = OscoreSeqNum::new(OscoreSeqNum::MAX).unwrap();
        assert!(max.is_near_exhaustion());
    }

    #[test]
    fn literal_piv_boundaries_roundtrip_minimally() {
        for (value, encoded) in [
            (0xff, &b"\xff"[..]),
            (0x100, &b"\x01\x00"[..]),
            (0xffff_ffff, &b"\xff\xff\xff\xff"[..]),
            (0x1_0000_0000, &b"\x01\x00\x00\x00\x00"[..]),
            (0xff_ffff_ffff, &b"\xff\xff\xff\xff\xff"[..]),
        ] {
            let seq = OscoreSeqNum::new(value).unwrap();
            let mut piv = [0u8; 5];
            let len = seq.encode_piv(&mut piv);
            assert_eq!(&piv[..len], encoded);
            assert_eq!(OscoreSeqNum::from_piv(encoded), Some(seq));
        }
    }

    #[test]
    fn rejects_out_of_range_overlong_and_nonminimal_pivs() {
        assert_eq!(OscoreSeqNum::new(0x0100_0000_0000), None);
        assert_eq!(OscoreSeqNum::from_piv(b"\x01\x00\x00\x00\x00\x00"), None);
        assert_eq!(OscoreSeqNum::from_piv(b"\x00\x01"), None);
        assert_eq!(OscoreSeqNum::from_piv(b"\x00\x00"), None);
        assert_eq!(OscoreSeqNum::from_piv(b"\x00"), OscoreSeqNum::new(0));
    }

    #[test]
    fn conversion_traits() {
        let seq: OscoreSeqNum = 42u32.into();
        assert_eq!(seq.get(), 42);

        let raw: u64 = seq.into();
        assert_eq!(raw, 42);
    }
}
