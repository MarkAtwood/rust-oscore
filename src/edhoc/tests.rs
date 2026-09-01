// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! EDHOC unit tests.

use super::cbor::{encode_identifier, parse_identifier, parse_suites_i};
use super::credential::{
    PeerCredential, copy_id_cred_value, encode_credential, encode_id_cred, parse_id_cred,
    raw_key_credential, validate_deterministic_item, validate_peer_credential,
};
use super::initiator::EdhocInitiator;
use super::kdf::{
    LABEL_KEYSTREAM_2, LABEL_OSCORE_SALT, LABEL_OSCORE_SECRET, LABEL_PRK_EXPORTER, LABEL_PRK_OUT,
    edhoc_kdf,
};
use super::responder::EdhocResponder;
use super::sign::SIG_LEN;
use super::transcript::{build_context_2, build_signature_structure};
use super::types::{ConnectionId, IdCredReference, SecretVec};
use super::{EdhocError, KEY_LEN_32, Lifecycle};
use crate::{ContextId, ContextStateStore, OscoreError, RecipientReplayState, SenderSequenceState};
use aes::Aes128;
use core::num::NonZeroU32;
use hex_literal::hex;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[test]
fn crypto_schedules_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<Aes128>();
    assert_zeroize_on_drop::<Sha256>();
    // edhoc_kdf output buffers (keystreams, MACs, K_3/IV_3, PRK chains) and
    // pending Message 2/3 plaintext are SecretVec: marker asserts the Drop
    // path wipes, and the explicit check below observes the wipe itself.
    assert_zeroize_on_drop::<SecretVec<128>>();

    let mut derived = SecretVec::<128>::new();
    derived
        .extend_from_slice(&[0xAA; 32])
        .expect("buffer capacity");
    derived.zeroize();
    assert!(derived.iter().all(|&b| b == 0));
}

struct TestStore {
    context_id: ContextId,
    state: Option<SenderSequenceState>,
}

impl TestStore {
    fn empty_for(context: &crate::Context) -> Self {
        Self {
            context_id: context.context_id(),
            state: None,
        }
    }
}

impl ContextStateStore for TestStore {
    type Error = core::convert::Infallible;

    fn load_sender(&mut self, context_id: &ContextId) -> Result<Option<SenderSequenceState>, Self::Error> {
        Ok((*context_id == self.context_id).then_some(self.state).flatten())
    }

    fn compare_exchange_sender(&mut self, context_id: &ContextId, expected: Option<SenderSequenceState>, next: SenderSequenceState) -> Result<bool, Self::Error> {
        if *context_id != self.context_id || expected != self.state {
            return Ok(false);
        }
        self.state = Some(next);
        Ok(true)
    }

    fn load_recipient(&mut self, _: &ContextId) -> Result<Option<RecipientReplayState>, Self::Error> { Ok(None) }
    fn save_recipient(&mut self, _: &ContextId, _: &RecipientReplayState) -> Result<(), Self::Error> { Ok(()) }
}

struct TestRng(u64);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

struct FixedRng([u8; 32]);

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        panic!("fixed RNG only supports try_fill_bytes")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("fixed RNG only supports try_fill_bytes")
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(&self.0[..dest.len()]);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}

struct FailingRng;

impl RngCore for FailingRng {
    fn next_u32(&mut self) -> u32 {
        panic!("constructor must use try_fill_bytes")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("constructor must use try_fill_bytes")
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        panic!("constructor must use try_fill_bytes")
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Err(rand_core::Error::from(
            NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
        ))
    }
}

impl CryptoRng for FailingRng {}

fn initiator(seed: [u8; 32], c_i: u8) -> EdhocInitiator {
    EdhocInitiator::new(seed, c_i, &mut TestRng(1))
}

fn responder(seed: [u8; 32], c_r: u8) -> EdhocResponder {
    EdhocResponder::new_with_rng(seed, c_r, &mut TestRng(2)).unwrap()
}

#[test]
fn embedded_constructors_accept_injected_rng() {
    fn construct<R: RngCore + CryptoRng>(rng: &mut R) {
        let _ = EdhocInitiator::new_with_rng([1; 32], 0, rng).unwrap();
        let _ = EdhocResponder::new_with_rng([2; 32], 1, rng).unwrap();
    }

    construct(&mut TestRng(3));
}

#[cfg(feature = "std")]
#[test]
fn std_convenience_constructors_remain_available() {
    let _ = EdhocInitiator::new_std([1; 32], 0).unwrap();
    let _ = EdhocResponder::new_std([2; 32], 1).unwrap();
}

#[test]
fn constructors_propagate_entropy_failure() {
    assert!(matches!(
        EdhocInitiator::new_with_rng([1; 32], 0, &mut FailingRng),
        Err(OscoreError::EntropyFailure)
    ));
    assert!(matches!(
        EdhocResponder::new_with_rng([2; 32], 1, &mut FailingRng),
        Err(OscoreError::EntropyFailure)
    ));
}

#[test]
fn test_initiator_creation() {
    let seed = [0x01u8; 32];
    let mut rng = rand_core::OsRng;
    let initiator = EdhocInitiator::new(seed, 0x00, &mut rng);
    assert_eq!(initiator.c_i, ConnectionId::from(0x00));
}

#[test]
fn test_responder_creation() {
    let seed = [0x01u8; 32];
    let mut rng = rand_core::OsRng;
    let responder = EdhocResponder::new(seed, 0x01, &mut rng);
    assert_eq!(responder.c_r, ConnectionId::from(0x01));
}

#[test]
fn test_message_1_creation() {
    let seed = [0x01u8; 32];
    let mut rng = rand_core::OsRng;
    let mut initiator = EdhocInitiator::new(seed, 0x05, &mut rng);
    let msg1 = initiator.create_message_1().unwrap();

    // Check basic structure: METHOD, SUITE, G_X, C_I
    assert_eq!(msg1[0], 0); // METHOD = SIGN/SIGN
    assert_eq!(msg1[1], 0); // Suite 0
    assert_eq!(msg1[2], 0x58); // bstr marker
    assert_eq!(msg1[3], 32); // G_X length
    // msg1[4..36] is G_X; C_I = 0x05 coincides with the one-byte CBOR
    // integer 5, so RFC 9528 Section 3.3.2 requires the int form (0x05,
    // not bstr 0x4105).
    assert_eq!(msg1[36], 0x05);
    assert_eq!(msg1.len(), 37);
}

#[test]
fn identifiers_use_rfc9528_canonical_encoding() {
    // RFC 9528 Section 3.3.2: a byte string that coincides with a one-byte
    // CBOR integer encoding (0x00-0x17 -> uint 0..23, 0x20-0x37 -> negative
    // -24..-1) is represented by that integer; other byte strings (including
    // empty, 0x18, 0x38, 0xef) stay bstr. The 0x21 and 0x38 rows are the
    // RFC's own examples.
    for (raw, encoded) in [
        (&[0x0d][..], &[0x0d][..]),
        (&[0x15][..], &[0x15][..]),
        (&[0x18][..], &[0x41, 0x18][..]),
        (&[0x21][..], &[0x21][..]),
        (&[0x38][..], &[0x41, 0x38][..]),
        (&[0xef][..], &[0x41, 0xef][..]),
        (&[][..], &[0x40][..]),
        (&[0xaa, 0xbb][..], &[0x42, 0xaa, 0xbb][..]),
    ] {
        let id = ConnectionId::new(raw).unwrap();
        let mut output = heapless::Vec::<u8, 8>::new();
        encode_identifier(&mut output, &id).unwrap();
        assert_eq!(output.as_slice(), encoded);
    }
    // Decode roundtrip. parse_identifier resolves negative integers via the
    // two's-complement convention (0x21 -> h'fe'), so only the uint and bstr
    // forms roundtrip byte-exactly; the negative-int wire form is tracked
    // separately.
    for (raw, encoded) in [
        (&[0x0d][..], &[0x0d][..]),
        (&[0x15][..], &[0x15][..]),
        (&[0x18][..], &[0x41, 0x18][..]),
        (&[0x38][..], &[0x41, 0x38][..]),
        (&[0xef][..], &[0x41, 0xef][..]),
        (&[][..], &[0x40][..]),
        (&[0xaa, 0xbb][..], &[0x42, 0xaa, 0xbb][..]),
    ] {
        let (parsed, consumed) = parse_identifier(encoded).unwrap();
        assert_eq!(parsed.as_bytes(), raw);
        assert_eq!(consumed, encoded.len());
    }
    assert_eq!(
        parse_identifier(&[0x41, 0x0d]),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(
        parse_identifier(&[0x18, 0x0d]),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(ConnectionId::new(&[0; 8]), Err(EdhocError::BufferTooSmall));
}

#[test]
fn id_cred_accepts_compact_kid_and_rfc9529_x5t() {
    for (wire, canonical) in [
        (&[0x2d][..], &[0xa1, 0x04, 0x41, 0x2d][..]),
        (&[0x42, 0xaa, 0xbb][..], &[0xa1, 0x04, 0x42, 0xaa, 0xbb][..]),
        (
            &hex!("a11822822e4879f2a41b510c1f9b")[..],
            &hex!("a11822822e4879f2a41b510c1f9b")[..],
        ),
    ] {
        let (parsed, consumed) = parse_id_cred(wire).unwrap();
        assert_eq!(parsed.as_bytes(), canonical);
        assert_eq!(consumed, wire.len());
    }

    assert_eq!(
        parse_id_cred(&hex!("a11822812e")),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(
        parse_id_cred(&[0xa1, 0x04, 0x2d]),
        Err(EdhocError::InvalidMessage)
    );
}

#[test]
fn id_cred_preserves_multi_parameter_maps_and_identifies_references() {
    let kid = hex!("a301270281040442aabb");
    let (parsed, consumed) = parse_id_cred(&kid).unwrap();
    assert_eq!(consumed, kid.len());
    assert_eq!(parsed.as_bytes(), kid);
    assert_eq!(
        parsed.reference(),
        &IdCredReference::Kid(copy_id_cred_value(&[0xaa, 0xbb]).unwrap())
    );

    let text_parameter = hex!("a20441aa63666f6f01");
    let (parsed, consumed) = parse_id_cred(&text_parameter).unwrap();
    assert_eq!(consumed, text_parameter.len());
    assert_eq!(parsed.as_bytes(), text_parameter);

    let x5t = hex!("a201271822822e481122334455667788");
    let (parsed, consumed) = parse_id_cred(&x5t).unwrap();
    assert_eq!(consumed, x5t.len());
    assert_eq!(parsed.as_bytes(), x5t);
    assert_eq!(
        parsed.reference(),
        &IdCredReference::X5t {
            algorithm: -15,
            hash: copy_id_cred_value(&hex!("1122334455667788")).unwrap(),
        }
    );
}

#[test]
fn id_cred_rejects_duplicate_noncanonical_and_ambiguous_headers() {
    for malformed in [
        &hex!("a20441aa0441bb")[..],
        &hex!("a2180441aa0127")[..],
        &hex!("a2045801aa0127")[..],
        &hex!("a301270281010441aa")[..],
        &hex!("a2028118220441aa")[..],
        &hex!("a2028204040441aa")[..],
        &hex!("a20441aa1822822e481122334455667788")[..],
        &hex!("a10127")[..],
        &hex!("a20441aa01")[..],
        &hex!("a20441aa")[..],
        &hex!("a90441aa")[..],
    ] {
        assert_eq!(
            parse_id_cred(malformed),
            Err(EdhocError::InvalidMessage),
            "accepted malformed ID_CRED {malformed:02x?}"
        );
    }
}

#[test]
fn id_cred_accepts_sorted_and_unsorted_literal_maps() {
    let sorted = hex!("a301270281040442aabb");
    let unsorted = hex!("a30442aabb0281040127");
    let (sorted_id, sorted_len) = parse_id_cred(&sorted).unwrap();
    let (unsorted_id, unsorted_len) = parse_id_cred(&unsorted).unwrap();

    assert_eq!(sorted_len, sorted.len());
    assert_eq!(unsorted_len, unsorted.len());
    assert_eq!(sorted_id.reference(), unsorted_id.reference());
    assert_eq!(sorted_id.as_bytes(), sorted);
    assert_eq!(unsorted_id.as_bytes(), unsorted);

    assert_eq!(
        parse_id_cred(&hex!("a30441aa01270441bb")),
        Err(EdhocError::InvalidMessage)
    );
}

#[test]
fn general_map_keys_use_bytewise_lexicographic_order() {
    assert!(validate_deterministic_item(&hex!("a21818006000")).is_ok());
    assert_eq!(
        validate_deterministic_item(&hex!("a26000181800")),
        Err(EdhocError::InvalidMessage)
    );
}

#[test]
fn id_cred_rejects_encoded_capacity_overflow() {
    let mut oversized = heapless::Vec::<u8, 65>::new();
    oversized
        .extend_from_slice(&[0xa1, 0x04, 0x58, 61])
        .unwrap();
    oversized.resize(65, 0).unwrap();
    assert_eq!(parse_id_cred(&oversized), Err(EdhocError::BufferTooSmall));
}

#[test]
fn pending_messages_expose_id_cred_before_retryable_credential_selection() {
    let mut initiator = initiator([0x11; 32], 0);
    let mut responder = responder([0x22; 32], 1);
    let initiator_key = *initiator.pubkey.as_bytes();
    let responder_key = *responder.pubkey.as_bytes();
    let (_, wrong_pubkey) = super::sign::SigningKey::from_seed(&[0x33; 32]);
    let wrong_key = *wrong_pubkey.as_bytes();
    let (wrong_id, wrong_credential) = raw_key_credential(&wrong_key).unwrap();
    let (responder_id, responder_credential) = raw_key_credential(&responder_key).unwrap();
    let (initiator_id, initiator_credential) = raw_key_credential(&initiator_key).unwrap();

    assert_eq!(
        responder.process_message_3(&[0], &initiator_key),
        Err(EdhocError::InvalidState)
    );
    assert_eq!(responder.state.lifecycle, Lifecycle::Created);

    let message_1 = initiator.create_message_1().unwrap();
    let message_2 = responder.process_message_1(&message_1).unwrap();
    let pending_2 = initiator.begin_process_message_2(&message_2).unwrap();
    assert_eq!(pending_2.id_cred().as_bytes(), responder_id.as_slice());
    assert_eq!(
        initiator.finish_process_message_2(
            &pending_2,
            PeerCredential::new(&wrong_key, &wrong_id, &wrong_credential),
        ),
        Err(EdhocError::SignatureVerification)
    );
    assert_eq!(initiator.state.lifecycle, Lifecycle::PendingMessage2);
    let message_3 = initiator
        .finish_process_message_2(
            &pending_2,
            PeerCredential::new(&responder_key, &responder_id, &responder_credential),
        )
        .unwrap();

    let pending_3 = responder.begin_process_message_3(&message_3).unwrap();
    assert_eq!(pending_3.id_cred().as_bytes(), initiator_id.as_slice());
    // SECURITY: Wrong credential poisons state - no retry allowed.
    // Application must inspect pending_3.id_cred() and pass correct credential.
    assert_eq!(
        responder.finish_process_message_3(
            &pending_3,
            PeerCredential::new(&wrong_key, &wrong_id, &wrong_credential),
        ),
        Err(EdhocError::SignatureVerification)
    );
    assert_eq!(responder.state.lifecycle, Lifecycle::Failed);
    // Verify poisoned state rejects further operations
    assert_eq!(
        responder.finish_process_message_3(
            &pending_3,
            PeerCredential::new(&initiator_key, &initiator_id, &initiator_credential),
        ),
        Err(EdhocError::InvalidState)
    );
}

#[test]
fn credentials_accept_bounded_deterministic_cbor_forms() {
    let (_, test_pubkey) = super::sign::SigningKey::from_seed(&[7; 32]);
    let public_key = *test_pubkey.as_bytes();
    let (id_cred, ccs) = raw_key_credential(&public_key).unwrap();
    let mut multi_claim_ccs = heapless::Vec::<u8, 96>::new();
    multi_claim_ccs
        .extend_from_slice(&[0xa2, 0x01, 0x63])
        .unwrap();
    multi_claim_ccs.extend_from_slice(b"iss").unwrap();
    multi_claim_ccs.push(0x08).unwrap();
    multi_claim_ccs.extend_from_slice(&ccs[2..]).unwrap();
    validate_peer_credential(PeerCredential::new(&public_key, &id_cred, &multi_claim_ccs)).unwrap();

    let mut cwt = heapless::Vec::<u8, 100>::new();
    cwt.extend_from_slice(&[0xd8, 0x3d]).unwrap();
    cwt.extend_from_slice(&multi_claim_ccs).unwrap();
    validate_peer_credential(PeerCredential::new(&public_key, &id_cred, &cwt)).unwrap();

    let x5t = hex!("a11822822e4879f2a41b510c1f9b");
    for credential in [
        &hex!("820141aa")[..],
        &hex!("a201f564726f6c65646e6f6465")[..],
        &hex!("4401020304")[..],
    ] {
        validate_peer_credential(PeerCredential::new(&public_key, &x5t, credential)).unwrap();
    }
}

#[test]
fn malformed_or_unbound_credentials_are_rejected() {
    for malformed in [
        &hex!("a202000100")[..],
        &hex!("a201000100")[..],
        &hex!("9f01ff")[..],
        &hex!("1800")[..],
        &hex!("61ff")[..],
        &hex!("0102")[..],
        &hex!("fa3f800000")[..],
    ] {
        assert_eq!(
            validate_deterministic_item(malformed),
            Err(EdhocError::InvalidMessage),
            "accepted malformed credential {malformed:02x?}"
        );
    }

    let too_deep = [0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0x00];
    assert_eq!(
        validate_deterministic_item(&too_deep),
        Err(EdhocError::InvalidMessage)
    );
    let mut too_many = heapless::Vec::<u8, 66>::new();
    too_many.extend_from_slice(&[0x98, 0x40]).unwrap();
    too_many.resize(66, 0).unwrap();
    assert_eq!(
        validate_deterministic_item(&too_many),
        Err(EdhocError::InvalidMessage)
    );

    let (_, test_pubkey) = super::sign::SigningKey::from_seed(&[7; 32]);
    let public_key = *test_pubkey.as_bytes();
    let (id_cred, mut credential) = raw_key_credential(&public_key).unwrap();
    *credential.last_mut().unwrap() ^= 1;
    assert_eq!(
        validate_peer_credential(PeerCredential::new(&public_key, &id_cred, &credential,)),
        Err(EdhocError::SignatureVerification)
    );
}

#[test]
fn weak_ed25519_keys_are_rejected_and_responder_is_poisoned() {
    let weak_key = [0; 32];
    let id_cred = hex!("a11822822e4879f2a41b510c1f9b");
    assert_eq!(
        validate_peer_credential(PeerCredential::new(&weak_key, &id_cred, &[0x40])),
        Err(EdhocError::SignatureVerification)
    );

    let mut initiator = initiator([0x11; 32], 0);
    let mut responder = responder([0x22; 32], 1);
    let responder_key = *responder.pubkey.as_bytes();
    let message_1 = initiator.create_message_1().unwrap();
    let message_2 = responder.process_message_1(&message_1).unwrap();
    let message_3 = initiator
        .process_message_2(&message_2, &responder_key)
        .unwrap();
    let pending = responder.begin_process_message_3(&message_3).unwrap();
    let (_, weak_credential) = raw_key_credential(&weak_key).unwrap();
    assert_eq!(
        responder.finish_process_message_3(
            &pending,
            PeerCredential::new(&weak_key, pending.id_cred().as_bytes(), &weak_credential),
        ),
        Err(EdhocError::SignatureVerification)
    );
    assert_eq!(responder.state.lifecycle, Lifecycle::Failed);
    assert_eq!(responder.privkey.as_bytes().clone(), [0; 32]);
}

#[test]
fn equal_connection_ids_are_rejected_and_poisoned() {
    let mut equal_responder = responder([0x22; 32], 0);
    let mut equal_initiator = initiator([0x11; 32], 0);
    let message_1 = equal_initiator.create_message_1().unwrap();
    assert_eq!(
        equal_responder.process_message_1(&message_1),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(equal_responder.state.lifecycle, Lifecycle::Failed);
    assert!(equal_responder.eph_secret.is_none());

    let mut initiator = initiator([0x33; 32], 1);
    let mut responder = responder([0x44; 32], 0);
    let responder_key = *responder.pubkey.as_bytes();
    let message_1 = initiator.create_message_1().unwrap();
    let message_2 = responder.process_message_1(&message_1).unwrap();
    initiator.c_i = ConnectionId::from(0);
    assert_eq!(
        initiator.process_message_2(&message_2, &responder_key),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(initiator.state.lifecycle, Lifecycle::Failed);
    assert!(initiator.eph_secret.is_none());
}

#[test]
fn rejects_unconfigured_ead_trailing_items_and_parses_suite_error() {
    let mut first_initiator = initiator([0x11; 32], 0);
    let mut message_1 = first_initiator.create_message_1().unwrap();
    message_1.push(0).unwrap();
    let mut first_responder = responder([0x22; 32], 1);
    assert_eq!(
        first_responder.process_message_1(&message_1),
        Err(EdhocError::InvalidMessage)
    );
    assert!(first_responder.eph_secret.is_some());

    assert_eq!(
        first_initiator.process_message_2(&[2, 0], &[0; 32]),
        Err(EdhocError::UnsupportedSuite)
    );
    assert_eq!(first_initiator.state.lifecycle, Lifecycle::Failed);
    assert!(first_initiator.eph_secret.is_none());

    let mut malformed_error_initiator = initiator([0x12; 32], 0);
    malformed_error_initiator.create_message_1().unwrap();
    assert_eq!(
        malformed_error_initiator.process_message_2(&[2, 0, 0], &[0; 32]),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(malformed_error_initiator.state.lifecycle, Lifecycle::Failed);
    assert!(malformed_error_initiator.eph_secret.is_none());

    let mut initiator = initiator([0x33; 32], 0);
    let mut responder = responder([0x44; 32], 1);
    let message_1 = initiator.create_message_1().unwrap();
    let mut message_2 = responder.process_message_1(&message_1).unwrap();
    message_2.push(0).unwrap();
    assert_eq!(
        initiator.process_message_2(&message_2, responder.pubkey.as_bytes()),
        Err(EdhocError::InvalidMessage)
    );
    assert!(initiator.eph_secret.is_some());
}

#[test]
fn rfc9528_suites_i_literals() {
    assert_eq!(parse_suites_i(&[0x00, 0xff]), Ok((0, 1)));
    // RFC 9528 Section 3.3.2: FIRST element of array is the selected suite
    assert_eq!(parse_suites_i(&[0x82, 0x02, 0x00, 0xff]), Ok((2, 3)));
    assert_eq!(parse_suites_i(&[0x82, 0x00, 0x00]), Ok((0, 3)));

    // Single-element arrays are accepted (first element is selected suite)
    assert_eq!(parse_suites_i(&[0x81, 0x00]), Ok((0, 2)));
    assert_eq!(
        parse_suites_i(&[0x9f, 0x00, 0xff]),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(
        parse_suites_i(&[0x82, 0x18]),
        Err(EdhocError::InvalidMessage)
    );
    // Non-minimal integer encoding (0x18 0x00 for value 0) is accepted
    assert_eq!(parse_suites_i(&[0x18, 0x00]), Ok((0, 2)));
    assert_eq!(parse_suites_i(&[0x1c]), Err(EdhocError::InvalidMessage));
    assert_eq!(
        parse_suites_i(&[0x82, 0x40, 0x00]),
        Err(EdhocError::InvalidMessage)
    );
}

#[test]
fn suites_i_parses_every_signed_integer_width() {
    let suites = [
        0x8b, 0x17, 0x18, 0x18, 0x19, 0x01, 0x00, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x1b, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x38, 0x18, 0x39, 0x01, 0x00, 0x3a, 0x00, 0x01,
        0x00, 0x00, 0x3b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    ];
    // First element is 0x17 = 23 (the selected suite per RFC 9528)
    assert_eq!(parse_suites_i(&suites), Ok((23, suites.len() - 1)));
}

#[test]
fn responder_applies_suite_selection_rules() {
    let seed = [0x01; 32];
    let mut message = [0u8; 40];
    message[0] = 0;
    message[1..4].copy_from_slice(&[0x82, 0x02, 0x00]);
    message[4..6].copy_from_slice(&[0x58, 32]);
    message[6..38].copy_from_slice(&hex!(
        "31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04"
    ));
    message[38] = 0;

    // SUITES_I = [2, 0]: first element is 2, responder only supports 0 -> UnsupportedSuite
    let result = responder(seed, 1).process_message_1(&message[..39]);
    assert_eq!(result, Err(EdhocError::UnsupportedSuite));

    // Change to [0, 0]: first element is 0, responder supports 0 -> OK
    message[2] = 0;
    let result = responder(seed, 1).process_message_1(&message[..39]);
    assert!(result.is_ok(), "valid suite selection failed: {result:?}");
}

#[test]
fn export_requires_completed_exchange() {
    use zeroize::Zeroize;
    assert!(matches!(
        initiator([0x11; 32], 0).export_oscore(),
        Err(OscoreError::NoContext)
    ));
    assert!(matches!(
        responder([0x22; 32], 1).export_oscore(),
        Err(OscoreError::NoContext)
    ));

    let mut initiator = initiator([0x33; 32], 2);
    initiator.zeroize();
    assert_eq!(initiator.state.lifecycle, Lifecycle::Zeroized);
    assert_eq!(initiator.create_message_1(), Err(EdhocError::InvalidState));
    assert!(matches!(
        initiator.export_oscore(),
        Err(OscoreError::NoContext)
    ));
}

#[test]
fn pre_dh_parse_failures_are_retryable() {
    let mut initiator = initiator([0x11; 32], 0);
    let mut responder = responder([0x22; 32], 1);
    let responder_pubkey = *responder.pubkey.as_bytes();
    let msg1 = initiator.create_message_1().unwrap();

    assert_eq!(
        initiator.process_message_2(&[0], &responder_pubkey),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(initiator.state.lifecycle, Lifecycle::Message1Created);
    assert!(initiator.eph_secret.is_some());

    assert_eq!(
        responder.process_message_1(&[0]),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(responder.state.lifecycle, Lifecycle::Created);
    assert!(responder.eph_secret.is_some());

    let msg2 = responder.process_message_1(&msg1).unwrap();
    assert!(
        initiator
            .process_message_2(&msg2, &responder_pubkey)
            .is_ok()
    );
}

#[test]
fn initiator_post_dh_failure_wipes_and_poison_state() {
    let mut initiator = initiator([0x11; 32], 0);
    let (_, peer_pubkey) = super::sign::SigningKey::from_seed(&[0x22; 32]);
    let peer_key = *peer_pubkey.as_bytes();
    initiator.create_message_1().unwrap();
    // message_2 = bstr(G_Y||CIPHERTEXT_2)
    // Use all-zeros G_Y to trigger DH failure (shared secret is identity point).
    // CIPHERTEXT_2 is ID_CRED_R + SIG_LEN bytes so the strict length gate
    // accepts the message and the all-zero shared secret is what gets rejected.
    let mut msg2 = heapless::Vec::<u8, 128>::new();
    msg2.extend_from_slice(&[0x58, (KEY_LEN_32 + 1 + SIG_LEN) as u8])
        .unwrap(); // bstr header
    msg2.extend_from_slice(&[0; KEY_LEN_32]).unwrap(); // G_Y = all zeros (triggers DH failure)
    msg2.extend_from_slice(&[0; 1 + SIG_LEN]).unwrap(); // CIPHERTEXT_2

    assert_eq!(
        initiator.process_message_2(&msg2, &peer_key),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(initiator.state.lifecycle, Lifecycle::Failed);
    assert!(initiator.eph_secret.is_none());
    assert_eq!(initiator.privkey.as_bytes().clone(), [0; KEY_LEN_32]);
    assert_eq!(initiator.state.prk_2e, [0; KEY_LEN_32]);
    assert_eq!(initiator.state.prk_3e2m, [0; KEY_LEN_32]);
    assert_eq!(initiator.state.prk_4e3m, [0; KEY_LEN_32]);
    assert_eq!(initiator.state.th_2, [0; KEY_LEN_32]);
    assert_eq!(initiator.state.th_3, [0; KEY_LEN_32]);
    assert_eq!(initiator.state.th_4, [0; KEY_LEN_32]);
    assert_eq!(initiator.create_message_1(), Err(EdhocError::InvalidState));
    assert_eq!(
        initiator.process_message_2(&msg2, &[0; KEY_LEN_32]),
        Err(EdhocError::InvalidState)
    );
}

#[test]
fn rejects_all_zero_x25519_shared_secret() {
    let mut initiator = initiator([0x11; 32], 0);
    initiator.create_message_1().unwrap();
    // message_2 = bstr(G_Y||CIPHERTEXT_2)
    // CIPHERTEXT_2 is ID_CRED_R + SIG_LEN bytes so the strict length gate
    // accepts the message and the all-zero G_Y is what gets rejected.
    let mut message_2 = heapless::Vec::<u8, 128>::new();
    message_2
        .extend_from_slice(&[0x58, (KEY_LEN_32 + 1 + SIG_LEN) as u8])
        .unwrap(); // bstr header
    message_2.extend_from_slice(&[0; 32]).unwrap(); // G_Y = all zeros (triggers DH failure)
    message_2.extend_from_slice(&[0; 1 + SIG_LEN]).unwrap(); // CIPHERTEXT_2
    assert_eq!(
        initiator.process_message_2(&message_2, &[1; 32]),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(initiator.state.lifecycle, Lifecycle::Failed);

    let mut responder = responder([0x22; 32], 1);
    let mut message_1 = heapless::Vec::<u8, 40>::new();
    message_1.extend_from_slice(&[0, 0, 0x58, 32]).unwrap();
    message_1.extend_from_slice(&[0; 32]).unwrap();
    message_1.push(0).unwrap();
    assert_eq!(
        responder.process_message_1(&message_1),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(responder.state.lifecycle, Lifecycle::Failed);
}

#[test]
fn responder_post_dh_failure_wipes_and_poison_state() {
    let mut initiator = initiator([0x11; 32], 0);
    let mut responder = responder([0x22; 32], 1);
    let msg1 = initiator.create_message_1().unwrap();
    responder.process_message_1(&msg1).unwrap();

    assert_eq!(
        responder.process_message_3(&[0], initiator.pubkey.as_bytes()),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(responder.state.lifecycle, Lifecycle::Failed);
    assert!(responder.eph_secret.is_none());
    assert_eq!(responder.privkey.as_bytes().clone(), [0; KEY_LEN_32]);
    assert_eq!(responder.state.prk_2e, [0; KEY_LEN_32]);
    assert_eq!(responder.state.prk_3e2m, [0; KEY_LEN_32]);
    assert_eq!(responder.state.prk_4e3m, [0; KEY_LEN_32]);
    assert_eq!(responder.state.th_2, [0; KEY_LEN_32]);
    assert_eq!(responder.state.th_3, [0; KEY_LEN_32]);
    assert_eq!(responder.state.th_4, [0; KEY_LEN_32]);
    assert_eq!(
        responder.process_message_1(&msg1),
        Err(EdhocError::InvalidState)
    );
    assert_eq!(
        responder.process_message_3(&[0], initiator.pubkey.as_bytes()),
        Err(EdhocError::InvalidState)
    );
}

/// Integration test: full EDHOC handshake with key verification.
#[test]
fn test_full_handshake() {
    // Create initiator and responder with different seeds
    let initiator_seed = [0x11u8; 32];
    let responder_seed = [0x22u8; 32];
    let mut rng = rand_core::OsRng;
    let mut initiator = EdhocInitiator::new(initiator_seed, 0x00, &mut rng);
    let mut responder = EdhocResponder::new(responder_seed, 0x01, &mut rng);

    // Get public keys for verification
    let initiator_pubkey = *initiator.pubkey.as_bytes();
    let responder_pubkey = *responder.pubkey.as_bytes();

    // Step 1: Initiator creates Message 1
    let msg1 = initiator
        .create_message_1()
        .expect("create_message_1 failed");

    // Step 2: Responder processes Message 1, creates Message 2
    let msg2 = responder
        .process_message_1(&msg1)
        .expect("process_message_1 failed");

    // Step 3: Initiator processes Message 2, creates Message 3
    let msg3 = initiator
        .process_message_2(&msg2, &responder_pubkey)
        .expect("process_message_2 failed");

    // Step 4: Responder processes Message 3
    responder
        .process_message_3(&msg3, &initiator_pubkey)
        .expect("process_message_3 failed");

    assert_eq!(
        initiator.process_message_2(&msg2, &responder_pubkey),
        Err(EdhocError::InvalidState)
    );
    assert_eq!(
        responder.process_message_1(&msg1),
        Err(EdhocError::InvalidState)
    );
    assert_eq!(
        responder.process_message_3(&msg3, &initiator_pubkey),
        Err(EdhocError::InvalidState)
    );
    assert_eq!(initiator.create_message_1(), Err(EdhocError::InvalidState));

    // Step 5: Both export OSCORE contexts
    let initiator_ctx = initiator
        .export_oscore()
        .expect("initiator export_oscore failed");
    let responder_ctx = responder
        .export_oscore()
        .expect("responder export_oscore failed");
    let mut initiator_store = TestStore::empty_for(&initiator_ctx);
    let mut responder_store = TestStore::empty_for(&responder_ctx);
    let mut initiator_ctx = initiator_ctx
        .register_fresh(&mut initiator_store)
        .expect("initiator register_fresh failed");
    let mut responder_ctx = responder_ctx
        .register_fresh(&mut responder_store)
        .expect("responder register_fresh failed");

    // Step 6: Verify contexts can communicate via functional roundtrip test.
    // This is more robust than comparing raw keys - it proves the derived
    // key material is correct by demonstrating successful encrypt/decrypt.

    // 6a: Initiator sends request to Responder
    let test_code: u8 = 0x01; // GET
    let test_options: &[u8] = &[0xB1, 0x61]; // Uri-Path "a"
    let test_payload: &[u8] = b"hello from initiator";

    let (ciphertext, oscore_opt) = initiator_ctx
        .reserve_sender(&mut initiator_store)
        .expect("initiator reserve failed")
        .protect_request(test_code, test_options, test_payload)
        .expect("initiator protect_request failed");

    let (recv_code, recv_options, recv_payload) = responder_ctx
        .unprotect_request(&oscore_opt, &ciphertext)
        .expect("responder unprotect_request failed");

    assert_eq!(recv_code, test_code, "request code mismatch");
    assert_eq!(&recv_options[..], test_options, "request options mismatch");
    assert_eq!(&recv_payload[..], test_payload, "request payload mismatch");

    // 6b: Responder sends response back to Initiator
    // Extract PIV from the request's OSCORE option for response AAD
    let request_piv_len = (oscore_opt[0] & 0x07) as usize;
    let request_piv = &oscore_opt[1..1 + request_piv_len];
    let request_kid = &oscore_opt[1 + request_piv_len..];

    let resp_code: u8 = 0x45; // 2.05 Content
    let resp_options: &[u8] = &[];
    let resp_payload: &[u8] = b"hello from responder";

    let (resp_ciphertext, resp_oscore_opt) = responder_ctx
        .protect_response(
            resp_code,
            resp_options,
            resp_payload,
            request_kid,
            request_piv,
            false,
        )
        .expect("responder protect_response failed");

    let (recv_resp_code, recv_resp_options, recv_resp_payload) = initiator_ctx
        .unprotect_response(&resp_oscore_opt, &resp_ciphertext, request_piv)
        .expect("initiator unprotect_response failed");

    assert_eq!(recv_resp_code, resp_code, "response code mismatch");
    assert_eq!(
        &recv_resp_options[..],
        resp_options,
        "response options mismatch"
    );
    assert_eq!(
        &recv_resp_payload[..],
        resp_payload,
        "response payload mismatch"
    );
}

#[test]
fn test_parse_suites_i_single_int() {
    // Single int 0
    assert_eq!(parse_suites_i(&[0x00]).unwrap(), (0, 1));
    // Single int 2
    assert_eq!(parse_suites_i(&[0x02]).unwrap(), (2, 1));
    // Single int 23 (max direct encoding)
    assert_eq!(parse_suites_i(&[0x17]).unwrap(), (23, 1));
    // Single int 24 (1-byte follow)
    assert_eq!(parse_suites_i(&[0x18, 0x18]).unwrap(), (24, 2));
}

#[test]
fn test_parse_suites_i_array() {
    // Array [0] - single element
    assert_eq!(parse_suites_i(&[0x81, 0x00]).unwrap(), (0, 2));
    // Array [0, 2] - prefer Suite 0, also supports Suite 2
    assert_eq!(parse_suites_i(&[0x82, 0x00, 0x02]).unwrap(), (0, 3));
    // Array [0, 2, 3] - three suites
    assert_eq!(parse_suites_i(&[0x83, 0x00, 0x02, 0x03]).unwrap(), (0, 4));
    // Array [2, 0] - prefer Suite 2
    assert_eq!(parse_suites_i(&[0x82, 0x02, 0x00]).unwrap(), (2, 3));
}

#[test]
fn test_parse_suites_i_errors() {
    // Empty input
    assert!(parse_suites_i(&[]).is_err());
    // Empty array
    assert!(parse_suites_i(&[0x80]).is_err());
    // Truncated 1-byte int
    assert!(parse_suites_i(&[0x18]).is_err());
}

/// Test responder accepts Message 1 with array-format SUITES_I (RFC 9528 Section 3.3.2).
#[test]
fn test_responder_accepts_suites_i_array() {
    let responder_seed = [0x22u8; 32];
    let mut rng = rand_core::OsRng;
    let mut responder = EdhocResponder::new(responder_seed, 0x01, &mut rng);

    // Build a Message 1 with SUITES_I as array [0, 2]
    // Format: METHOD (0 = SIGN_SIGN) | SUITES_I (array) | G_X (bstr 32) | C_I
    let mut msg1 = heapless::Vec::<u8, 64>::new();
    msg1.push(0x00).unwrap(); // METHOD = 0 (SIGN_SIGN)
    msg1.push(0x82).unwrap(); // CBOR array of 2
    msg1.push(0x00).unwrap(); // Suite 0 (selected)
    msg1.push(0x02).unwrap(); // Suite 2 (also supported)
    msg1.push(0x58).unwrap(); // bstr header
    msg1.push(32).unwrap(); // length 32
    // G_X: 32 bytes of ephemeral public key (dummy)
    let g_x = [0xAAu8; 32];
    msg1.extend_from_slice(&g_x).unwrap();
    msg1.push(0x05).unwrap(); // C_I = 5

    // Responder should accept this Message 1
    let result = responder.process_message_1(&msg1);
    assert!(
        result.is_ok(),
        "Responder should accept array-format SUITES_I: {:?}",
        result.err()
    );
}

/// Test responder rejects unsupported suite even when sent as array.
#[test]
fn test_responder_rejects_unsupported_suite_in_array() {
    let responder_seed = [0x22u8; 32];
    let mut rng = rand_core::OsRng;
    let mut responder = EdhocResponder::new(responder_seed, 0x01, &mut rng);

    // Build a Message 1 with SUITES_I as array [2, 0] - Suite 2 selected
    let mut msg1 = heapless::Vec::<u8, 64>::new();
    msg1.push(0x00).unwrap(); // METHOD = 0 (SIGN_SIGN)
    msg1.push(0x82).unwrap(); // CBOR array of 2
    msg1.push(0x02).unwrap(); // Suite 2 (selected - NOT supported)
    msg1.push(0x00).unwrap(); // Suite 0 (also supported)
    msg1.push(0x58).unwrap(); // bstr header
    msg1.push(32).unwrap(); // length 32
    let g_x = [0xAAu8; 32];
    msg1.extend_from_slice(&g_x).unwrap();
    msg1.push(0x05).unwrap(); // C_I = 5

    let result = responder.process_message_1(&msg1);
    assert!(matches!(result, Err(EdhocError::UnsupportedSuite)));
}

/// Test that export_oscore returns NoContext if called before handshake completes.
#[test]
fn test_export_before_handshake_returns_error() {
    use crate::OscoreError;

    // Initiator: export_oscore before process_message_2
    let initiator_seed = [0x11u8; 32];
    let mut rng = rand_core::OsRng;
    let mut initiator = EdhocInitiator::new(initiator_seed, 0x00, &mut rng);
    let _msg1 = initiator.create_message_1().unwrap();
    // Handshake incomplete - should fail
    assert!(
        matches!(initiator.export_oscore(), Err(OscoreError::NoContext)),
        "Initiator export_oscore should fail before process_message_2"
    );

    // Responder: export_oscore before process_message_3
    let responder_seed = [0x22u8; 32];
    let mut rng = rand_core::OsRng;
    let mut responder = EdhocResponder::new(responder_seed, 0x01, &mut rng);
    // Even after process_message_1, handshake is incomplete
    let _msg2 = responder.process_message_1(&_msg1).unwrap();
    assert!(
        matches!(responder.export_oscore(), Err(OscoreError::NoContext)),
        "Responder export_oscore should fail before process_message_3"
    );
}

use serde_json::Value;

fn edhoc_vector(name: &str) -> Value {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/vectors/edhoc.json")).unwrap();
    vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"].as_str().unwrap() == name)
        .cloned()
        .unwrap()
}

#[test]
fn test_prk_oscore_interop_vectors() {
    // Validate test/vectors/edhoc.json self-consistency (Python reference oracle).
    let v = edhoc_vector("fixed_seed_sign_sign");
    assert_eq!(v["prk_3e2m"], v["prk_2e"]);
    assert_eq!(v["prk_4e3m"], v["prk_2e"]);
    assert_eq!(v["th_2"], v["responder_th_2"]);
    assert_eq!(v["th_3"], v["responder_th_3"]);
    assert_eq!(v["th_4"], v["responder_th_4"]);
    assert_eq!(v["oscore_sender_id"].as_str().unwrap(), "01");
    assert_eq!(v["oscore_recipient_id"].as_str().unwrap(), "00");

    // All crypto fields present (non-empty hex)
    for field in &[
        "prk_2e",
        "th_2",
        "th_3",
        "th_4",
        "oscore_master_secret",
        "oscore_master_salt",
    ] {
        assert!(
            !v[field].as_str().unwrap().is_empty(),
            "missing field {field}"
        );
    }

    // Functional: deterministic full handshake roundtrip
    let initiator_seed = [0x11u8; 32];
    let responder_seed = [0x22u8; 32];
    let mut initiator =
        EdhocInitiator::new_with_rng(initiator_seed, 0x00, &mut TestRng(1)).unwrap();
    let mut responder =
        EdhocResponder::new_with_rng(responder_seed, 0x01, &mut TestRng(2)).unwrap();
    let initiator_pubkey = *initiator.pubkey.as_bytes();
    let responder_pubkey = *responder.pubkey.as_bytes();

    let msg1 = initiator.create_message_1().unwrap();
    let msg2 = responder.process_message_1(&msg1).unwrap();
    let msg3 = initiator
        .process_message_2(&msg2, &responder_pubkey)
        .unwrap();
    responder
        .process_message_3(&msg3, &initiator_pubkey)
        .unwrap();

    let initiator_ctx = initiator.export_oscore().unwrap();
    let responder_ctx = responder.export_oscore().unwrap();
    let mut initiator_store = TestStore::empty_for(&initiator_ctx);
    let mut responder_store = TestStore::empty_for(&responder_ctx);
    let mut initiator_ctx = initiator_ctx
        .register_fresh(&mut initiator_store)
        .expect("initiator register_fresh failed");
    let mut responder_ctx = responder_ctx
        .register_fresh(&mut responder_store)
        .expect("responder register_fresh failed");
    let test_payload = b"interop roundtrip";

    let (ciphertext, oscore_opt) = initiator_ctx
        .reserve_sender(&mut initiator_store)
        .unwrap()
        .protect_request(0x01, &[], test_payload)
        .unwrap();
    let (recv_code, _recv_opts, recv_payload) = responder_ctx
        .unprotect_request(&oscore_opt, &ciphertext)
        .unwrap();
    assert_eq!(recv_code, 0x01);
    assert_eq!(&recv_payload[..], test_payload);
}

#[test]
fn rfc9529_export_chain_matches_exact_literals() {
    // RFC 9529 Sections 2.5 and 2.6, Method 0 / Suite 0 trace. These literals
    // are an independent standards oracle, not generated by this crate.
    let prk_4e3m = hex!("d584ac2e5dad5a77d14b53ebe72ef1d5daa8860d399373bf2c240afa7ba804da");
    let th_4 = hex!("0eb868f263cf3555dccd396dd8dec29d3750d599be42d5a41a5a37c896f294ac");
    let prk_out = edhoc_kdf(&prk_4e3m, LABEL_PRK_OUT, &th_4, 32).unwrap();
    assert_eq!(
        prk_out.as_slice(),
        &hex!("b744cb7d8a87cc0447c3350e165b250dab12ec453325abb922b30307e5c368f0")
    );
    let prk_exporter = edhoc_kdf(
        prk_out.as_slice().try_into().unwrap(),
        LABEL_PRK_EXPORTER,
        &[],
        32,
    )
    .unwrap();
    assert_eq!(
        prk_exporter.as_slice(),
        &hex!("2aaec8fc4ab3bc3295def6b551051a2fa561424db301fa84f642f5578a6df51a")
    );
    let exporter: &[u8; 32] = prk_exporter.as_slice().try_into().unwrap();
    assert_eq!(
        edhoc_kdf(exporter, LABEL_OSCORE_SECRET, &[], 16)
            .unwrap()
            .as_slice(),
        &hex!("1e1c6beac3a8a1cac435de7e2f9ae7ff")
    );
    assert_eq!(
        edhoc_kdf(exporter, LABEL_OSCORE_SALT, &[], 8)
            .unwrap()
            .as_slice(),
        &hex!("ce7ab844c0106d73")
    );
}

#[test]
fn deterministic_python_vector_matches_every_derived_stage() {
    fn decode(value: &str) -> heapless::Vec<u8, 512> {
        let mut output = heapless::Vec::new();
        for pair in value.as_bytes().chunks_exact(2) {
            output
                .push(u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .unwrap();
        }
        output
    }

    let vector = edhoc_vector("fixed_seed_sign_sign");
    let seed_i = core::array::from_fn(|index| index as u8);
    let seed_r = core::array::from_fn(|index| (index + 32) as u8);
    let mut initiator = EdhocInitiator::new_with_rng(seed_i, 0, &mut FixedRng([0x42; 32])).unwrap();
    let mut responder = EdhocResponder::new_with_rng(seed_r, 1, &mut FixedRng([0x42; 32])).unwrap();
    let initiator_pubkey = *initiator.pubkey.as_bytes();
    let responder_pubkey = *responder.pubkey.as_bytes();

    let msg1 = initiator.create_message_1().unwrap();
    assert_eq!(msg1.as_slice(), decode(vector["msg1"].as_str().unwrap()));
    let msg2 = responder.process_message_1(&msg1).unwrap();
    let mut id_cred_r = heapless::Vec::<u8, 40>::new();
    encode_id_cred(&mut id_cred_r, &responder_pubkey).unwrap();
    let mut credential_r = heapless::Vec::<u8, 80>::new();
    encode_credential(&mut credential_r, &responder_pubkey).unwrap();
    // Transcript-derived literals below track the Python reference oracle
    // (lichen.crypto.edhoc, same seeds/RNG/CIDs); regenerated after the
    // RFC 9528 Section 3.3.2 C_I transport-encoding fix changed msg1 and
    // every downstream hash.
    let context_2 = build_context_2(
        &ConnectionId::new(&[1]).unwrap(),
        &id_cred_r,
        &responder.state.th_2,
        &credential_r,
    )
    .unwrap();
    assert_eq!(
        context_2.as_slice(),
        decode(
            "01a1044824f6ed6acbfe1009582035879fa20a3966a349d2a2a18be12058c46bcfaf2fd00ab89d389e91ba44490ea30101200621582029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
        )
    );
    let mac_2 = edhoc_kdf(&responder.state.prk_3e2m, 2, &context_2, 32).unwrap();
    assert_eq!(
        mac_2.as_slice(),
        decode("e27e07a76d86ae93bff34c7b51a4d1361f6deaa1b6c1e490b6c420f925d88ad2")
    );
    let m_2 = build_signature_structure(&id_cred_r, &responder.state.th_2, &credential_r, &mac_2)
        .unwrap();
    assert_eq!(
        m_2.as_slice(),
        decode(
            "846a5369676e6174757265314ba1044824f6ed6acbfe1009584a582035879fa20a3966a349d2a2a18be12058c46bcfaf2fd00ab89d389e91ba44490ea30101200621582029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd75820e27e07a76d86ae93bff34c7b51a4d1361f6deaa1b6c1e490b6c420f925d88ad2"
        )
    );
    assert_eq!(
        responder.privkey.sign(&responder.pubkey, &m_2).as_slice(),
        decode(
            "9b6a8e8a5778737c8f4ea4e2452f536c442a4962e487308fa51900425f89f6228ccc4dac3d19cd5967e68547a1f83f0f"
        )
    );
    let expected_msg2 = decode(vector["msg2"].as_str().unwrap());
    let (actual_wire, _) = super::cbor::parse_bstr(&msg2).unwrap();
    let (expected_wire, _) = super::cbor::parse_bstr(&expected_msg2).unwrap();
    let keystream = edhoc_kdf(
        &responder.state.prk_2e,
        LABEL_KEYSTREAM_2,
        &responder.state.th_2,
        actual_wire.len() - KEY_LEN_32,
    )
    .unwrap();
    let actual_plaintext: heapless::Vec<u8, 128> = actual_wire[KEY_LEN_32..]
        .iter()
        .zip(keystream.iter())
        .map(|(byte, key)| byte ^ key)
        .collect();
    let expected_plaintext: heapless::Vec<u8, 128> = expected_wire[KEY_LEN_32..]
        .iter()
        .zip(keystream.iter())
        .map(|(byte, key)| byte ^ key)
        .collect();
    assert_eq!(actual_plaintext, expected_plaintext, "plaintext_2");
    assert_eq!(msg2.as_slice(), decode(vector["msg2"].as_str().unwrap()));
    let msg3 = initiator
        .process_message_2(&msg2, &responder_pubkey)
        .unwrap();
    assert_eq!(msg3.as_slice(), decode(vector["msg3"].as_str().unwrap()));
    responder
        .process_message_3(&msg3, &initiator_pubkey)
        .unwrap();

    for (actual, field) in [
        (&initiator.state.prk_2e, "prk_2e"),
        (&initiator.state.prk_3e2m, "prk_3e2m"),
        (&initiator.state.prk_4e3m, "prk_4e3m"),
        (&initiator.state.th_2, "th_2"),
        (&initiator.state.th_3, "th_3"),
        (&initiator.state.th_4, "th_4"),
        (&responder.state.th_2, "responder_th_2"),
        (&responder.state.th_3, "responder_th_3"),
        (&responder.state.th_4, "responder_th_4"),
    ] {
        assert_eq!(
            actual.as_slice(),
            decode(vector[field].as_str().unwrap()),
            "{field}"
        );
    }

    let initiator_ctx = initiator.export_oscore().unwrap();
    let responder_ctx = responder.export_oscore().unwrap();
    let secret = decode(vector["oscore_master_secret"].as_str().unwrap());
    let salt = decode(vector["oscore_master_salt"].as_str().unwrap());
    assert_eq!(initiator_ctx.master_secret().as_slice(), secret);
    assert_eq!(responder_ctx.master_secret().as_slice(), secret);
    assert_eq!(initiator_ctx.master_salt(), salt);
    assert_eq!(responder_ctx.master_salt(), salt);
    assert_eq!(initiator_ctx.sender_id(), &[1]);
    assert_eq!(initiator_ctx.recipient_id(), &[0]);
    assert_eq!(responder_ctx.sender_id(), &[0]);
    assert_eq!(responder_ctx.recipient_id(), &[1]);
}
