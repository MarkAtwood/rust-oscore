// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! Group OSCORE (RFC 9203) support for LICHEN.
//!
//! Provides shared group contexts for multicast confessions and per-recipient
//! pairwise E2E contexts for dead-drop store-and-forward.
//!
//! # Security
//!
//! Group keys provide confidentiality within the group but do NOT provide sender
//! authentication (any group member can encrypt as any other). For authenticated
//! group communication, pair with link-layer Ed25519 signatures or per-message signing.
//!
//! # Sequence Space
//!
//! All members of a group share a common sender ID derived from the group name,
//! producing a shared [`ContextId`] and durable sequence counter. Without a
//! Group Manager (RFC 9203 Section 3.2) or deterministic partitioning, competing
//! members will race on the sequence store. For point-to-point use (dead-drop,
//! confessions to a known gateway), the gateway's sequence counter is the
//! authoritative store. For true multicast, a Group Manager is required.

use crate::{
    Context, ContextStoreError, OscoreError, SenderStateStore, ID_CONTEXT_CAPACITY, KEY_LEN,
};
use heapless::Vec;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const GROUP_NAME_MAX_LEN: usize = 16;

pub const GROUP_MAX_MEMBERS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
#[non_exhaustive]
pub enum GroupTrust {
    Unknown = 0,
    Provisioned = 1,
    Established = 2,
    Verified = 3,
}

impl GroupTrust {
    pub fn escalate(&mut self, target: GroupTrust) -> Result<(), OscoreError> {
        if target > *self {
            *self = target;
            Ok(())
        } else {
            Err(OscoreError::InvalidParam)
        }
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct GroupContext {
    group_name: [u8; GROUP_NAME_MAX_LEN],
    group_name_len: u8,
    master_secret: [u8; KEY_LEN],
    member_index: u8,
    trust: GroupTrust,
    member_ctx: Option<Context>,
}

impl core::fmt::Debug for GroupContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GroupContext")
            .field("group_name_len", &self.group_name_len)
            .field("member_index", &self.member_index)
            .field("trust", &self.trust)
            .field("member_ctx", &"[REDACTED]")
            .finish()
    }
}

impl GroupContext {
    pub fn new(
        group_name: &[u8],
        master_secret: &[u8; KEY_LEN],
        member_index: u8,
    ) -> Result<Self, OscoreError> {
        if group_name.len() > GROUP_NAME_MAX_LEN {
            return Err(OscoreError::InvalidParam);
        }
        if member_index as usize >= GROUP_MAX_MEMBERS {
            return Err(OscoreError::InvalidParam);
        }

        let common_sender = derive_common_sender_id(group_name);
        let member_recipient = member_recipient_id(member_index);
        let id_context = derive_group_id_context(group_name);
        let member_ctx = Context::new(
            master_secret,
            None,
            Some(&id_context),
            &common_sender,
            &member_recipient,
        )?;

        let mut gn = [0u8; GROUP_NAME_MAX_LEN];
        gn[..group_name.len()].copy_from_slice(group_name);

        Ok(Self {
            group_name: gn,
            group_name_len: group_name.len() as u8,
            master_secret: *master_secret,
            member_index,
            trust: GroupTrust::Unknown,
            member_ctx: Some(member_ctx),
        })
    }

    pub fn member_context(&self) -> Option<&Context> {
        self.member_ctx.as_ref()
    }

    pub fn take_member_context(&mut self) -> Option<Context> {
        self.member_ctx.take()
    }

    pub fn trust(&self) -> GroupTrust {
        self.trust
    }

    pub fn escalate_trust(&mut self, target: GroupTrust) -> Result<(), OscoreError> {
        self.trust.escalate(target)
    }

    pub fn register_fresh<S: SenderStateStore>(
        &mut self,
        store: &mut S,
    ) -> Result<&Context, ContextStoreError<S::Error>> {
        let ctx = self.member_ctx.take().ok_or(ContextStoreError::Conflict)?;
        let active_ctx = ctx.register_fresh(store)?;
        self.member_ctx = Some(active_ctx);
        Ok(self.member_ctx.as_ref().expect("just set"))
    }

    pub fn restore_existing<S: SenderStateStore>(
        &mut self,
        store: &mut S,
    ) -> Result<&Context, ContextStoreError<S::Error>> {
        let ctx = self.member_ctx.take().ok_or(ContextStoreError::Conflict)?;
        let active_ctx = ctx.restore_existing(store)?;
        self.member_ctx = Some(active_ctx);
        Ok(self.member_ctx.as_ref().expect("just set"))
    }

    pub fn group_name(&self) -> &[u8] {
        &self.group_name[..self.group_name_len as usize]
    }

    pub fn member_index(&self) -> u8 {
        self.member_index
    }

    pub fn group_receive_context(&self, member_index: u8) -> Result<Context, OscoreError> {
        if member_index as usize >= GROUP_MAX_MEMBERS {
            return Err(OscoreError::InvalidParam);
        }
        let common_sender = derive_common_sender_id(self.group_name());
        let member_recipient = member_recipient_id(member_index);
        let id_context = derive_group_id_context(self.group_name());
        Context::new(
            &self.master_secret,
            None,
            Some(&id_context),
            &member_recipient,
            &common_sender,
        )
    }

    pub fn dead_drop_context(
        peer_pubkey: &[u8; 32],
        peer_iid: &[u8; 8],
        sender_id: &[u8],
        recipient_id: &[u8],
    ) -> Result<Context, OscoreError> {
        Context::from_peer_key(peer_pubkey, peer_iid, sender_id, recipient_id)
    }

    pub fn common_sender_id(group_name: &[u8]) -> [u8; 4] {
        let mut hash = Sha256::new();
        hash.update(b"LICHEN-group-sender\0");
        hash.update(group_name);
        let digest = hash.finalize();
        let mut id = [0u8; 4];
        id.copy_from_slice(&digest[..4]);
        id
    }
}

fn derive_common_sender_id(group_name: &[u8]) -> Vec<u8, { crate::ID_MAX_LEN }> {
    let mut hash = Sha256::new();
    hash.update(b"LICHEN-group-sender\0");
    hash.update(group_name);
    let digest = hash.finalize();
    let mut sender = Vec::new();
    sender
        .extend_from_slice(&digest[..4])
        .expect("4 bytes fit in 8-byte ID");
    sender
}

fn derive_group_id_context(group_name: &[u8]) -> [u8; ID_CONTEXT_CAPACITY] {
    let mut hash = Sha256::new();
    hash.update(b"LICHEN-group-idctx\0");
    hash.update(group_name);
    let digest = hash.finalize();
    let mut ctx = [0u8; ID_CONTEXT_CAPACITY];
    ctx.copy_from_slice(&digest[..ID_CONTEXT_CAPACITY]);
    ctx
}

fn member_recipient_id(member_index: u8) -> Vec<u8, { crate::ID_MAX_LEN }> {
    let mut recipient = Vec::new();
    recipient.push(member_index).expect("single byte fits");
    recipient
}

#[cfg(test)]
mod tests {
    use super::*;

    static MASTER_SECRET: [u8; KEY_LEN] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];

    static PEER_PUBKEY: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    #[test]
    fn group_context_creation() {
        let gc = GroupContext::new(b"confessions", &MASTER_SECRET, 0).unwrap();
        assert_eq!(gc.group_name(), b"confessions");
        assert_eq!(gc.member_index(), 0);
        assert_eq!(gc.trust(), GroupTrust::Unknown);
        assert!(gc.member_context().is_some());
    }

    #[test]
    fn group_context_trust_escalation() {
        let mut gc = GroupContext::new(b"group-a", &MASTER_SECRET, 0).unwrap();
        assert_eq!(gc.trust(), GroupTrust::Unknown);

        gc.escalate_trust(GroupTrust::Provisioned).unwrap();
        assert_eq!(gc.trust(), GroupTrust::Provisioned);

        gc.escalate_trust(GroupTrust::Verified).unwrap();
        assert_eq!(gc.trust(), GroupTrust::Verified);

        assert_eq!(
            gc.escalate_trust(GroupTrust::Provisioned).unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn group_members_share_sender_context_id() {
        let gc0 = GroupContext::new(b"shared-sender", &MASTER_SECRET, 0).unwrap();
        let gc1 = GroupContext::new(b"shared-sender", &MASTER_SECRET, 1).unwrap();

        let ctx0 = gc0.member_context().unwrap();
        let ctx1 = gc1.member_context().unwrap();

        assert_eq!(ctx0.sender_id(), ctx1.sender_id());
        assert_eq!(ctx0.context_id(), ctx1.context_id());
    }

    #[test]
    fn group_members_have_distinct_recipient_ids() {
        let gc0 = GroupContext::new(b"distinct-recip", &MASTER_SECRET, 0).unwrap();
        let gc1 = GroupContext::new(b"distinct-recip", &MASTER_SECRET, 1).unwrap();

        let ctx0 = gc0.member_context().unwrap();
        let ctx1 = gc1.member_context().unwrap();

        assert_eq!(ctx0.recipient_id(), &[0u8]);
        assert_eq!(ctx1.recipient_id(), &[1u8]);
    }

    #[test]
    fn group_receive_context_can_decrypt_peer_message() {
        let gc_sender = GroupContext::new(b"crypt-recv", &MASTER_SECRET, 0).unwrap();
        let gc_receiver = GroupContext::new(b"crypt-recv", &MASTER_SECRET, 1).unwrap();
        let recv_ctx = gc_receiver.group_receive_context(0).unwrap();

        assert_eq!(
            gc_sender.member_context().unwrap().sender_id(),
            recv_ctx.recipient_id()
        );
        assert_eq!(
            gc_sender.member_context().unwrap().sender_key,
            recv_ctx.recipient_key
        );
    }

    #[test]
    fn group_receive_context_matches_sender_keys() {
        let gc0 = GroupContext::new(b"key-match", &MASTER_SECRET, 0).unwrap();
        let gc1 = GroupContext::new(b"key-match", &MASTER_SECRET, 1).unwrap();

        let send_ctx = gc0.member_context().unwrap();
        let recv_ctx = gc1.group_receive_context(0).unwrap();

        assert_eq!(send_ctx.sender_key, recv_ctx.recipient_key);
        assert_eq!(send_ctx.sender_id(), recv_ctx.recipient_id());
    }

    #[test]
    fn dead_drop_context_creation() {
        let peer_iid = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let ctx =
            GroupContext::dead_drop_context(&PEER_PUBKEY, &peer_iid, &[0x10], &[0x20]).unwrap();

        assert_eq!(ctx.sender_id(), &[0x10]);
        assert_eq!(ctx.recipient_id(), &[0x20]);
    }

    #[test]
    fn dead_drop_different_pubkeys_produce_different_secrets() {
        let peer_iid = [0u8; 8];
        let pubkey_a = PEER_PUBKEY;
        let mut pubkey_b = PEER_PUBKEY;
        pubkey_b[0] ^= 1;

        let ms_a = Context::derive_master_secret_from_peer_key(&pubkey_a, &peer_iid).unwrap();
        let ms_b = Context::derive_master_secret_from_peer_key(&pubkey_b, &peer_iid).unwrap();

        assert_ne!(ms_a, ms_b);
    }

    #[test]
    fn common_sender_id_is_deterministic() {
        let id1 = GroupContext::common_sender_id(b"group-x");
        let id2 = GroupContext::common_sender_id(b"group-x");
        assert_eq!(id1, id2);
    }

    #[test]
    fn common_sender_id_different_for_different_groups() {
        let id1 = GroupContext::common_sender_id(b"group-a");
        let id2 = GroupContext::common_sender_id(b"group-b");
        assert_ne!(id1, id2);
    }

    #[test]
    fn group_name_too_long() {
        let long_name = [b'A'; GROUP_NAME_MAX_LEN + 1];
        assert_eq!(
            GroupContext::new(&long_name, &MASTER_SECRET, 0).unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn member_index_out_of_bounds() {
        assert_eq!(
            GroupContext::new(b"test", &MASTER_SECRET, GROUP_MAX_MEMBERS as u8).unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn group_receive_context_rejects_invalid_index() {
        let gc = GroupContext::new(b"inv-idx", &MASTER_SECRET, 0).unwrap();
        assert_eq!(
            gc.group_receive_context(GROUP_MAX_MEMBERS as u8)
                .unwrap_err(),
            OscoreError::InvalidParam
        );
    }
}
