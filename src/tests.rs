// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! Tests for OSCORE implementation.

extern crate std;

use hex_literal::hex;
use serde_json::Value;

use crate::context::Context;
use crate::crypto::{compute_nonce, derive_iv, derive_key};
use crate::error::{ContextStoreError, OscoreError, ReservationError};
use crate::option::{find_payload_marker, parse_inner_body, parse_option, request_identifiers};
use crate::protect::Construction;
use crate::seqnum::OscoreSeqNum;
use crate::types::{
    ContextId, SenderSequenceState, SenderStateStore, KEY_LEN, NONCE_LEN, OSCORE_OPTION_MAX_LEN,
    PIV_MAX_LEN,
};

fn vector(name: &str) -> Value {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../test/vectors/oscore.json")).unwrap();
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
}

impl TestStore {
    fn for_context(context: &Context) -> Self {
        Self {
            context_id: context.context_id(),
            state: context.sender_sequence_state(),
        }
    }
}

impl SenderStateStore for TestStore {
    type Error = core::convert::Infallible;

    fn load(
        &mut self,
        context_id: &ContextId,
    ) -> Result<Option<SenderSequenceState>, Self::Error> {
        Ok((*context_id == self.context_id).then_some(self.state))
    }

    fn compare_exchange(
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

    impl SenderStateStore for EmptyStore {
        type Error = core::convert::Infallible;

        fn load(
            &mut self,
            context_id: &ContextId,
        ) -> Result<Option<SenderSequenceState>, Self::Error> {
            Ok(self
                .0
                .filter(|(stored_id, _)| stored_id == context_id)
                .map(|(_, state)| state))
        }

        fn compare_exchange(
            &mut self,
            context_id: &ContextId,
            expected: Option<SenderSequenceState>,
            next: SenderSequenceState,
        ) -> Result<bool, Self::Error> {
            if self.load(context_id)? != expected {
                return Ok(false);
            }
            self.0 = Some((*context_id, next));
            Ok(true)
        }
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
    assert!(context
        .protect_response(0x45, &[], b"response", &[0], &[3], true)
        .is_ok());
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
    };
    let mut context = Context::new(&secret, None, None, &[1], &[0])
        .unwrap()
        .restore_existing(&mut store)
        .unwrap();

    assert_eq!(context.sender_sequence_state(), store.state);
    assert!(context
        .protect_response(0x45, &[], b"response", &[0], &[3], true)
        .is_ok());
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

    impl SenderStateStore for EmptyStore {
        type Error = core::convert::Infallible;

        fn load(
            &mut self,
            _context_id: &ContextId,
        ) -> Result<Option<SenderSequenceState>, Self::Error> {
            Ok(None)
        }

        fn compare_exchange(
            &mut self,
            _context_id: &ContextId,
            _expected: Option<SenderSequenceState>,
            _next: SenderSequenceState,
        ) -> Result<bool, Self::Error> {
            panic!("load_existing must not write")
        }
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

    impl SenderStateStore for SharedStore {
        type Error = core::convert::Infallible;

        fn load(
            &mut self,
            context_id: &ContextId,
        ) -> Result<Option<SenderSequenceState>, Self::Error> {
            let record = self.record.lock().unwrap();
            Ok((*context_id == record.0).then_some(record.1))
        }

        fn compare_exchange(
            &mut self,
            context_id: &ContextId,
            expected: Option<SenderSequenceState>,
            next: SenderSequenceState,
        ) -> Result<bool, Self::Error> {
            self.barrier.wait();
            let mut record = self.record.lock().unwrap();
            if *context_id != record.0 || expected != Some(record.1) {
                return Ok(false);
            }
            record.1 = next;
            Ok(true)
        }
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

    impl SenderStateStore for SharedEmptyStore {
        type Error = core::convert::Infallible;

        fn load(
            &mut self,
            context_id: &ContextId,
        ) -> Result<Option<SenderSequenceState>, Self::Error> {
            Ok(self
                .record
                .lock()
                .unwrap()
                .filter(|(stored_id, _)| stored_id == context_id)
                .map(|(_, state)| state))
        }

        fn compare_exchange(
            &mut self,
            context_id: &ContextId,
            expected: Option<SenderSequenceState>,
            next: SenderSequenceState,
        ) -> Result<bool, Self::Error> {
            self.barrier.wait();
            let mut record = self.record.lock().unwrap();
            let current = record
                .filter(|(stored_id, _)| stored_id == context_id)
                .map(|(_, state)| state);
            if current != expected {
                return Ok(false);
            }
            *record = Some((*context_id, next));
            Ok(true)
        }
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

    assert!(ctx
        .protect_response(0x45, &[], b"response", &[0], &[3], true)
        .is_ok());
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
