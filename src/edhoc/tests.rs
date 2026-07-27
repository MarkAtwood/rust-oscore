// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! EDHOC unit tests.

use super::cbor::{encode_identifier, parse_identifier, parse_suites_i};
use super::credential::{
    copy_id_cred_value, parse_id_cred, raw_key_credential, validate_deterministic_item,
    validate_peer_credential, PeerCredential,
};
use super::initiator::EdhocInitiator;
use super::kdf::edhoc_kdf;
use super::responder::EdhocResponder;
use super::transcript::{transcript_3, transcript_4};
use super::types::{ConnectionId, IdCredReference};
use super::{EdhocError, Lifecycle, KEY_LEN_32};
use crate::{ContextId, OscoreError, SenderSequenceState, SenderStateStore};
use aes::Aes128;
use core::num::NonZeroU32;
use ed25519_dalek::SigningKey;
use hex_literal::hex;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

#[test]
fn crypto_schedules_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<Aes128>();
    assert_zeroize_on_drop::<Sha256>();
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

impl SenderStateStore for TestStore {
    type Error = core::convert::Infallible;

    fn load(
        &mut self,
        context_id: &ContextId,
    ) -> Result<Option<SenderSequenceState>, Self::Error> {
        Ok((*context_id == self.context_id)
            .then_some(self.state)
            .flatten())
    }

    fn compare_exchange(
        &mut self,
        context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        if *context_id != self.context_id || expected != self.state {
            return Ok(false);
        }
        self.state = Some(next);
        Ok(true)
    }
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
        Err(OscoreError::KeyDerivation)
    ));
    assert!(matches!(
        EdhocResponder::new_with_rng([2; 32], 1, &mut FailingRng),
        Err(OscoreError::KeyDerivation)
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
                             // msg1[4..36] is G_X
    assert_eq!(msg1[36], 0x41); // bstr(1)
    assert_eq!(msg1[37], 5); // C_I
}

#[test]
fn rfc9529_signature_trace_vectors() {
    // Use RFC 9529 Annex E hardcoded oracle values for transcript
    // and edhoc_kdf helper function tests. Full-flow handshake is
    // tested separately in test_full_handshake.

    let th_2 = hex!("c1d8c6ee4eeb1672d7fcbb44f8d811419739b79b852fce03f527eacdaf6633c4");

    let prk_2e = hex!("e998b69d67c5856ceb6812f20590d0cd55ab25e24bf53348f35915883e94b694");
    let keystream_2 = hex!(
        "c8419a8f1cae45674cf4c7ba021a110538c7fa2639ae70f316e8c3c34a0faf5dbf68cf835ec76f8f532fda302c647b303f02397f72710d072bd962118e35c6fe6d3f0a46a4160fba02a12eeec59e54135c3d"
    );
    assert_eq!(
        edhoc_kdf(&prk_2e, &th_2, "KEYSTREAM_2", &[], 82)
            .unwrap()
            .as_slice(),
        keystream_2
    );

    let plaintext_2 = hex!(
        "4118a11822822e4879f2a41b510c1f9b5840c3b5bd44d1e44a085c03d3aede4e1e6c11c572a1968cc3629b505f98c681608d3d1de793d1c40eb5dd5d89acf1966aea07022b48cdc99870ebc40374e8fa6e09"
    );
    let credential_r = hex!(
        "58f13081ee3081a1a003020102020462319ec4300506032b6570301d311b301906035504030c124544484f4320526f6f742045643235353139301e170d3232303331363038323433365a170d3239313233313233303030305a30223120301e06035504030c174544484f4320526573706f6e6465722045643235353139302a300506032b6570032100a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359300506032b6570034100b723bc01eab0928e8b2b6c98de19cc3823d46e7d6987b032478fecfaf14537a1af14cc8be829c6b73044101837eb4abc949565d86dce51cfae52ab82c152cb02"
    );
    let th_3 = hex!("093c4bed6f1f679d7ef8c6dada0f631b75cf19d8a6eea88b2a5ac1a9fb9e5986");
    assert_eq!(
        transcript_3(&th_2, &plaintext_2, &credential_r).unwrap(),
        th_3
    );

    let plaintext_3 = hex!(
        "a11822822e48c24ab2fd7643c79f584096e1cd5fceadfac1b5af819443f70924f5719955957fd02655beb4775e1a73186a0d1d3ea683f08f8d03dcecb9cf154e1c6f555a1e12ca118ce42bdba6878907"
    );
    let th_4 = transcript_4(&th_3, &plaintext_3, &credential_r).unwrap();
    assert_eq!(
        th_4,
        hex!("fc7811c2b14cf00ac220cc7ad98e1900f950809fce87fc862c784704b80c0796")
    );

    // KDF test vectors from independent Python oracle
    // (lichen.crypto.edhoc + cbor2 + cryptography.hazmat HKDFExpand).
    let prk_out_vec = edhoc_kdf(&prk_2e, &th_4, "PRK_out", &[], 32).unwrap();
    assert_eq!(
        prk_out_vec.as_slice(),
        &hex!("4b71e171b0bdc32b80d1c8cf0e76d13d983d278c1617470a02e80544ae605643")
    );
    let prk_out: &[u8; 32] = prk_out_vec[..32].try_into().expect("PRK_out is 32 bytes");
    let prk_exporter_vec = edhoc_kdf(prk_out, &th_4, "10", &[], 32).unwrap();
    assert_eq!(
        prk_exporter_vec.as_slice(),
        &hex!("27dd11fd563d4553b8b1651cbe7df628e925e9fa1b5adb00439395311bb8064f")
    );
    let prk_exporter: &[u8; 32] = prk_exporter_vec[..32]
        .try_into()
        .expect("prk_exporter is 32 bytes");
    assert_eq!(
        edhoc_kdf(prk_exporter, &th_4, "0", &[], 16)
            .unwrap()
            .as_slice(),
        &hex!("0b53a88bc7d8688bfbc8dc8aee8aafac")
    );
    assert_eq!(
        edhoc_kdf(prk_exporter, &th_4, "1", &[], 8)
            .unwrap()
            .as_slice(),
        &hex!("d94446754f3e3f07")
    );
}

#[test]
fn identifiers_use_rfc9528_canonical_encoding() {
    for (raw, encoded) in [
        (&[0x0d][..], &[0x0d][..]),
        (&[0x15][..], &[0x15][..]),
        (&[0x18][..], &[0x41, 0x18][..]),
        (&[0x21][..], &[0x41, 0x21][..]),
        (&[0x38][..], &[0x41, 0x38][..]),
        (&[0xef][..], &[0x30][..]),
        (&[][..], &[0x40][..]),
        (&[0xaa, 0xbb][..], &[0x42, 0xaa, 0xbb][..]),
    ] {
        let id = ConnectionId::new(raw).unwrap();
        let mut output = heapless::Vec::<u8, 8>::new();
        encode_identifier(&mut output, &id).unwrap();
        assert_eq!(output.as_slice(), encoded);
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
    let initiator_key = initiator.pubkey.to_bytes();
    let responder_key = responder.pubkey.to_bytes();
    let wrong_key = SigningKey::from_bytes(&[0x33; 32])
        .verifying_key()
        .to_bytes();
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
    assert_eq!(
        responder.finish_process_message_3(
            &pending_3,
            PeerCredential::new(&wrong_key, &wrong_id, &wrong_credential),
        ),
        Err(EdhocError::SignatureVerification)
    );
    assert_eq!(responder.state.lifecycle, Lifecycle::PendingMessage3);
    responder
        .finish_process_message_3(
            &pending_3,
            PeerCredential::new(&initiator_key, &initiator_id, &initiator_credential),
        )
        .unwrap();
    assert_eq!(responder.state.lifecycle, Lifecycle::Complete);
}

#[test]
fn credentials_accept_bounded_deterministic_cbor_forms() {
    let public_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    let (id_cred, ccs) = raw_key_credential(&public_key).unwrap();
    let mut multi_claim_ccs = heapless::Vec::<u8, 96>::new();
    multi_claim_ccs
        .extend_from_slice(&[0xa2, 0x01, 0x63])
        .unwrap();
    multi_claim_ccs.extend_from_slice(b"iss").unwrap();
    multi_claim_ccs.push(0x08).unwrap();
    multi_claim_ccs.extend_from_slice(&ccs[2..]).unwrap();
    validate_peer_credential(PeerCredential::new(&public_key, &id_cred, &multi_claim_ccs))
        .unwrap();

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

    let public_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
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
    let responder_key = responder.pubkey.to_bytes();
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
    assert_eq!(responder.signing_key.to_bytes(), [0; 32]);
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
    let responder_key = responder.pubkey.to_bytes();
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
        initiator.process_message_2(&message_2, &responder.pubkey.to_bytes()),
        Err(EdhocError::InvalidMessage)
    );
    assert!(initiator.eph_secret.is_some());
}

#[test]
fn rfc9528_suites_i_literals() {
    assert_eq!(parse_suites_i(&[0x00, 0xff]), Ok((0, 1)));
    assert_eq!(parse_suites_i(&[0x82, 0x02, 0x00, 0xff]), Ok((0, 3)));
    assert_eq!(parse_suites_i(&[0x82, 0x00, 0x00]), Ok((0, 3)));

    assert_eq!(
        parse_suites_i(&[0x81, 0x00]),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(
        parse_suites_i(&[0x9f, 0x00, 0xff]),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(
        parse_suites_i(&[0x82, 0x18]),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(
        parse_suites_i(&[0x18, 0x00]),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(parse_suites_i(&[0x1c]), Err(EdhocError::InvalidMessage));
    assert_eq!(
        parse_suites_i(&[0x82, 0x40, 0x00]),
        Err(EdhocError::InvalidMessage)
    );
}

#[test]
fn suites_i_parses_every_signed_integer_width() {
    let suites = [
        0x8b, 0x17, 0x18, 0x18, 0x19, 0x01, 0x00, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x1b, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x38, 0x18, 0x39, 0x01, 0x00, 0x3a,
        0x00, 0x01, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff,
    ];
    assert_eq!(parse_suites_i(&suites), Ok((0, suites.len() - 1)));
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

    let result = responder(seed, 1).process_message_1(&message[..39]);
    assert!(result.is_ok(), "valid suite selection failed: {result:?}");

    message[2] = 0;
    assert_eq!(
        responder(seed, 1).process_message_1(&message[..39]),
        Err(EdhocError::UnsupportedSuite)
    );
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
    let responder_pubkey = responder.pubkey.to_bytes();
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
    assert!(initiator
        .process_message_2(&msg2, &responder_pubkey)
        .is_ok());
}

#[test]
fn initiator_post_dh_failure_wipes_and_poison_state() {
    let mut initiator = initiator([0x11; 32], 0);
    let peer_key = SigningKey::from_bytes(&[0x22; 32])
        .verifying_key()
        .to_bytes();
    initiator.create_message_1().unwrap();
    let mut msg2 = heapless::Vec::<u8, 40>::new();
    msg2.extend_from_slice(&[0x58, 33]).unwrap();
    msg2.extend_from_slice(&[7; KEY_LEN_32]).unwrap();
    msg2.push(0).unwrap();

    assert_eq!(
        initiator.process_message_2(&msg2, &peer_key),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(initiator.state.lifecycle, Lifecycle::Failed);
    assert!(initiator.eph_secret.is_none());
    assert_eq!(initiator.signing_key.to_bytes(), [0; KEY_LEN_32]);
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
    let mut message_2 = heapless::Vec::<u8, 40>::new();
    message_2.extend_from_slice(&[0x58, 33]).unwrap();
    message_2.extend_from_slice(&[0; 33]).unwrap();
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
        responder.process_message_3(&[0], &initiator.pubkey.to_bytes()),
        Err(EdhocError::InvalidMessage)
    );
    assert_eq!(responder.state.lifecycle, Lifecycle::Failed);
    assert!(responder.eph_secret.is_none());
    assert_eq!(responder.signing_key.to_bytes(), [0; KEY_LEN_32]);
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
        responder.process_message_3(&[0], &initiator.pubkey.to_bytes()),
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
    let initiator_pubkey = initiator.pubkey.to_bytes();
    let responder_pubkey = responder.pubkey.to_bytes();

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
    let mut initiator_ctx = initiator
        .export_oscore()
        .expect("initiator export_oscore failed");
    let mut responder_ctx = responder
        .export_oscore()
        .expect("responder export_oscore failed");
    let mut initiator_store = TestStore::empty_for(&initiator_ctx);
    let _responder_store = TestStore::empty_for(&responder_ctx);

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
        serde_json::from_str(include_str!("../../../../test/vectors/edhoc.json")).unwrap();
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
    assert_eq!(v["oscore_sender_id"].as_str().unwrap(), "00");
    assert_eq!(v["oscore_recipient_id"].as_str().unwrap(), "01");

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
    let initiator_pubkey = initiator.pubkey.to_bytes();
    let responder_pubkey = responder.pubkey.to_bytes();

    let msg1 = initiator.create_message_1().unwrap();
    let msg2 = responder.process_message_1(&msg1).unwrap();
    let msg3 = initiator
        .process_message_2(&msg2, &responder_pubkey)
        .unwrap();
    responder
        .process_message_3(&msg3, &initiator_pubkey)
        .unwrap();

    let mut initiator_ctx = initiator.export_oscore().unwrap();
    let mut responder_ctx = responder.export_oscore().unwrap();
    let mut initiator_store = TestStore::empty_for(&initiator_ctx);
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
