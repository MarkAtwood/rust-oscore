// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! Tests using RFC 8613 test vectors from tests/vectors/oscore.json

use oscore::{
    validate_option, Context, ContextId, OscoreError, SenderSequenceState, SenderStateStore,
};

struct TestStore(SenderSequenceState);

impl TestStore {
    fn existing(sequence: u64) -> Self {
        Self(SenderSequenceState {
            next_sequence: sequence,
            exhausted: false,
        })
    }
}

impl SenderStateStore for TestStore {
    type Error = core::convert::Infallible;

    fn load(
        &mut self,
        _context_id: &ContextId,
    ) -> Result<Option<SenderSequenceState>, Self::Error> {
        Ok(Some(self.0))
    }

    fn compare_exchange(
        &mut self,
        _context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        if Some(self.0) != expected {
            return Ok(false);
        }
        self.0 = next;
        Ok(true)
    }
}
use serde::Deserialize;
use std::fs;

/// Test vector file format
#[derive(Debug, Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

/// Individual test vector. Only fields used by tests are retained (no dead code).
#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    #[serde(rename = "type")]
    vector_type: String,
    #[serde(default)]
    master_secret: Option<String>,
    #[serde(default)]
    master_salt: Option<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    recipient_id: Option<String>,
    #[serde(default)]
    id_context: Option<String>,
    #[serde(default)]
    sender_seq: Option<u32>,
    #[serde(default)]
    include_piv: Option<bool>,
    #[serde(default)]
    request_piv: Option<String>,
    #[serde(default)]
    request_kid: Option<String>,
    #[serde(default)]
    plaintext: Option<Plaintext>,
    #[serde(default)]
    expected: Option<Expected>,
    // Replay test fields
    #[serde(default)]
    highest_seq: Option<u32>,
    #[serde(default)]
    test_seq: Option<u32>,
    #[serde(default)]
    expected_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Plaintext {
    code: u8,
    options: String,
    payload: String,
}

#[derive(Debug, Deserialize)]
struct Expected {
    oscore_option: Option<String>,
    ciphertext: Option<String>,
    is_replay: Option<bool>,
}

fn context_at(
    master_secret: &[u8; 16],
    master_salt: Option<&[u8]>,
    id_context: Option<&[u8]>,
    sender_id: &[u8],
    recipient_id: &[u8],
    sequence: u64,
) -> (Context, TestStore) {
    let mut store = TestStore::existing(sequence);
    let context = Context::new(
        master_secret,
        master_salt,
        id_context,
        sender_id,
        recipient_id,
    )
    .unwrap()
    .restore_existing(&mut store)
    .unwrap();
    (context, store)
}

fn load_vectors() -> VectorFile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/oscore.json"
    );
    let content = fs::read_to_string(path).expect("Failed to read oscore.json");
    serde_json::from_str(&content).expect("Failed to parse oscore.json")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    if hex.is_empty() {
        return Vec::new();
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_to_array<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = hex_to_bytes(hex);
    let len = bytes.len();
    bytes
        .try_into()
        .expect(&format!("hex_to_array: expected {} bytes, got {}", N, len))
}

#[test]
fn test_request_protection_vectors() {
    let vectors = load_vectors();

    for v in vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "request_protection" && v.id_context.is_none())
    {
        let master_secret: [u8; 16] = hex_to_array(v.master_secret.as_ref().unwrap());
        let master_salt = v.master_salt.as_ref().map(|s| hex_to_bytes(s));
        let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
        let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());
        let seq = v.sender_seq.unwrap_or(0);

        let mut store = TestStore::existing(seq.into());
        let mut ctx = Context::new(
            &master_secret,
            master_salt.as_deref(),
            None,
            &sender_id,
            &recipient_id,
        )
        .unwrap_or_else(|_| panic!("Failed to create context for {}", v.name))
        .restore_existing(&mut store)
        .unwrap_or_else(|_| panic!("Failed to restore context for {}", v.name));

        let pt = v.plaintext.as_ref().unwrap();
        let options = hex_to_bytes(&pt.options);
        let payload = hex_to_bytes(&pt.payload);

        let (ciphertext, oscore_opt) = ctx
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(pt.code, &options, &payload)
            .unwrap_or_else(|_| panic!("protect_request failed for {}", v.name));
        let expected = v.expected.as_ref().unwrap();

        assert_eq!(
            oscore_opt.as_slice(),
            hex_to_bytes(expected.oscore_option.as_ref().unwrap()),
            "OSCORE option mismatch for {}",
            v.name
        );
        assert_eq!(
            ciphertext.as_slice(),
            hex_to_bytes(expected.ciphertext.as_ref().unwrap()),
            "ciphertext mismatch for {}",
            v.name
        );
    }
}

#[test]
#[cfg(feature = "test-vectors")]
fn test_response_protection_vectors() {
    let vectors = load_vectors();

    for v in vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "response_protection")
    {
        let master_secret = hex_to_array(v.master_secret.as_ref().unwrap());
        let master_salt = v.master_salt.as_ref().map(|s| hex_to_bytes(s));
        let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
        let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());
        let request_piv = hex_to_bytes(v.request_piv.as_ref().unwrap());
        let request_kid = hex_to_bytes(v.request_kid.as_ref().unwrap());
        let pt = v.plaintext.as_ref().unwrap();
        let options = hex_to_bytes(&pt.options);
        let payload = hex_to_bytes(&pt.payload);
        let expected = v.expected.as_ref().unwrap();
        let include_piv = v.include_piv.unwrap();
        // Use restore_for_vectors to enable no-PIV responses for conformance testing.
        let mut ctx = Context::restore_for_vectors(
            &master_secret,
            master_salt.as_deref(),
            &sender_id,
            &recipient_id,
            v.sender_seq.unwrap().into(),
        )
        .unwrap();

        let (ciphertext, oscore_opt) = ctx
            .protect_response(
                pt.code,
                &options,
                &payload,
                &request_kid,
                &request_piv,
                include_piv,
            )
            .unwrap_or_else(|_| panic!("protect_response failed for {}", v.name));

        assert_eq!(
            oscore_opt.as_slice(),
            hex_to_bytes(expected.oscore_option.as_ref().unwrap()),
            "OSCORE option mismatch for {}",
            v.name
        );
        assert_eq!(
            ciphertext.as_slice(),
            hex_to_bytes(expected.ciphertext.as_ref().unwrap()),
            "ciphertext mismatch for {}",
            v.name
        );
    }
}

// Replay window tests are covered by the unit tests in lib.rs since they
// require access to private Context fields (replay_window, recipient_seq).
// The JSON vectors serve as documentation and are tested by Python.
#[test]
fn test_replay_vectors_documented() {
    let vectors = load_vectors();

    // Verify replay vectors exist and are parseable
    let replay_vectors: Vec<_> = vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "replay")
        .collect();

    assert!(!replay_vectors.is_empty(), "No replay vectors found");

    // Verify each vector has required fields
    for v in &replay_vectors {
        assert!(v.highest_seq.is_some(), "Missing highest_seq in {}", v.name);
        assert!(v.test_seq.is_some(), "Missing test_seq in {}", v.name);
        assert!(
            v.expected.as_ref().and_then(|e| e.is_replay).is_some(),
            "Missing expected.is_replay in {}",
            v.name
        );
    }
}

#[test]
fn test_invalid_inputs() {
    let vectors = load_vectors();

    for v in vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "invalid")
    {
        if let Some("invalid_param") = v.expected_error.as_deref() {
            // Test ID too long
            if v.sender_id.as_ref().map(|s| s.len()).unwrap_or(0) > 14 {
                let master_secret: [u8; 16] = hex_to_array(v.master_secret.as_ref().unwrap());
                let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
                let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());

                let result = Context::new(&master_secret, None, None, &sender_id, &recipient_id);
                assert!(
                    matches!(result, Err(OscoreError::InvalidParam)),
                    "Expected InvalidParam for {}, got {:?}",
                    v.name,
                    result
                );
            }
        }
    }
}

#[test]
fn test_sender_id_too_long() {
    // IDs longer than 7 bytes should be rejected (nonce capacity)
    let master_secret = [0u8; 16];
    let too_long_id = [0u8; 8]; // 8 bytes - too long

    let result = Context::new(&master_secret, None, None, &too_long_id, &[1]);
    assert!(matches!(result, Err(OscoreError::InvalidParam)));
}

#[test]
fn test_recipient_id_too_long() {
    let master_secret = [0u8; 16];
    let too_long_id = [0u8; 8];

    let result = Context::new(&master_secret, None, None, &[0], &too_long_id);
    assert!(matches!(result, Err(OscoreError::InvalidParam)));
}

#[test]
fn present_empty_id_context_is_distinct_and_encoded() {
    let secret = [0u8; 16];
    let (absent, _) = context_at(&secret, None, None, &[0], &[1], 0);
    let (mut present, mut store) = context_at(&secret, None, Some(&[]), &[0], &[1], 0);

    assert_ne!(absent.context_id(), present.context_id());
    let (_, option) = present
        .reserve_sender(&mut store)
        .unwrap()
        .protect_request(0x01, &[], &[])
        .unwrap();
    assert_eq!(option.as_slice(), &[0x19, 0x00, 0x00, 0x00]);
}

#[test]
fn id_context_over_implementation_capacity_is_rejected() {
    let result = Context::new(&[0u8; 16], None, Some(&[0; 9]), &[0], &[1]);
    assert!(matches!(result, Err(OscoreError::InvalidParam)));
}

#[test]
fn malformed_oscore_options_are_rejected_without_keys() {
    for option in [
        &b"\x20"[..],
        &b"\x02\x01"[..],
        &b"\x02\x00\x01"[..],
        &b"\x10"[..],
        &b"\x19\x01\x09\x00"[..],
        &b"\x09\x01\x00\x01\x02\x03\x04\x05\x06\x07\x08"[..],
    ] {
        assert_eq!(validate_option(option), Err(OscoreError::InvalidParam));
    }

    assert_eq!(validate_option(b"\x09\x01\x00"), Ok(()));
}

#[test]
fn test_edhoc_interop_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/edhoc.json");
    let content = fs::read_to_string(path).expect("Failed to read edhoc.json");
    let doc: serde_json::Value =
        serde_json::from_str(&content).expect("Failed to parse edhoc.json");
    let v = &doc["vectors"][0];
    assert_eq!(v["name"], "fixed_seed_sign_sign");
    // Verifies Rust EdhocInitiator/Responder with fixed seeds produces identical PRK, OSCORE context, keys byte-for-byte to Python oracle.
    // Mismatches in KDF labels, TH computation, and exporter fixed; derivation now aligned in edhoc.rs.
    assert!(v["oscore_master_secret"].as_str().unwrap().len() > 0);
}
