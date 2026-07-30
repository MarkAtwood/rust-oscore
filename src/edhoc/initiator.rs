// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! EDHOC Initiator (client role) implementation.

use super::cbor::{encode_bstr, parse_bstr, parse_identifier, parse_suites_r};
use super::credential::{
    PeerCredential, encode_credential, encode_id_cred, raw_key_credential,
    validate_peer_credential, validate_pubkey,
};
use super::kdf::{edhoc_kdf, export_context, hkdf_extract};
use super::transcript::{
    build_context_2, build_context_3, build_signature_structure, transcript_2, transcript_3,
    transcript_4,
};
use super::types::{ConnectionId, IdCred, SecretVec, VecExt};
use super::{EdhocError, KEY_LEN_32, Lifecycle, SIG_LEN, SUITE_0};
use crate::{Context, KEY_LEN, NONCE_LEN, OscoreError};
use aes::Aes128;
use ccm::{
    Ccm,
    aead::{AeadInPlace, KeyInit},
    consts::{U8, U13},
};
use rand_core::{CryptoRng, RngCore};
use schnorr48::{PrivateKey, PublicKey as SchnorrPubKey};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// AES-CCM for Suite 0.
type AesCcm = Ccm<Aes128, U8, U13>;

/// EDHOC Initiator (client role).
///
/// Implements EDHOC method 0 (SIGN_SIGN) with Suite 0 (LICHEN variant: Schnorr48).
// SECURITY: PrivateKey and StaticSecret must be zeroized on drop.
// PrivateKey and StaticSecret implement ZeroizeOnDrop themselves.
pub struct EdhocInitiator {
    /// Our Schnorr48 private key (implements ZeroizeOnDrop).
    pub(crate) privkey: PrivateKey,
    /// Our Schnorr48 public key.
    pub(crate) pubkey: SchnorrPubKey,
    /// Our connection identifier.
    pub(crate) c_i: ConnectionId,
    /// Ephemeral X25519 secret (implements ZeroizeOnDrop).
    pub(crate) eph_secret: Option<StaticSecret>,
    /// Ephemeral X25519 public key.
    eph_public: PublicKey,
    /// Protocol state.
    pub(crate) state: InitiatorState,
}

/// Initiator protocol state.
///
/// PRK derivation chain per python/src/lichen/crypto/edhoc.py:
/// PRK_2e = HKDF-Extract(salt=TH_2, IKM=G_XY)
/// PRK_3e2m = PRK_2e for Suite 0 SIGN_SIGN (needed for MAC_2)
/// PRK_4e3m = PRK_3e2m (needed for MAC_3 and OSCORE export)
/// All must be zeroized on drop.
pub(crate) struct InitiatorState {
    pub(crate) msg1: heapless::Vec<u8, 64>,
    g_y: [u8; 32],
    pub(crate) c_r: ConnectionId,
    pub(crate) prk_2e: [u8; 32],
    pub(crate) prk_3e2m: [u8; 32],
    pub(crate) prk_4e3m: [u8; 32],
    pub(crate) th_2: [u8; 32],
    pub(crate) th_3: [u8; 32],
    pub(crate) th_4: [u8; 32],
    /// True when handshake completed (process_message_2 succeeded).
    pub(crate) completed: bool,
    pub(crate) lifecycle: Lifecycle,
}

impl Default for InitiatorState {
    fn default() -> Self {
        Self {
            msg1: heapless::Vec::new(),
            g_y: [0; 32],
            c_r: ConnectionId::new(&[]).expect("empty connection ID fits"),
            prk_2e: [0; 32],
            prk_3e2m: [0; 32],
            prk_4e3m: [0; 32],
            th_2: [0; 32],
            th_3: [0; 32],
            th_4: [0; 32],
            completed: false,
            lifecycle: Lifecycle::Created,
        }
    }
}

impl Zeroize for InitiatorState {
    fn zeroize(&mut self) {
        self.g_y.zeroize();
        self.prk_2e.zeroize();
        self.prk_3e2m.zeroize();
        self.prk_4e3m.zeroize();
        self.th_2.zeroize();
        self.th_3.zeroize();
        self.th_4.zeroize();
        self.msg1.zeroize();
    }
}

impl core::fmt::Debug for InitiatorState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InitiatorState")
            .field("msg1", &self.msg1)
            .field("g_y", &"[REDACTED]")
            .field("c_r", &self.c_r)
            .field("prk_2e", &"[REDACTED]")
            .field("prk_3e2m", &"[REDACTED]")
            .field("prk_4e3m", &"[REDACTED]")
            .field("th_2", &"[REDACTED]")
            .field("th_3", &"[REDACTED]")
            .field("th_4", &"[REDACTED]")
            .field("completed", &self.completed)
            .field("lifecycle", &self.lifecycle)
            .finish()
    }
}

impl ZeroizeOnDrop for InitiatorState {}

impl core::fmt::Debug for EdhocInitiator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EdhocInitiator")
            .field("privkey", &"[REDACTED]")
            .field("pubkey", &"[REDACTED]")
            .field("c_i", &self.c_i)
            .field("eph_secret", &"[REDACTED]")
            .field("eph_public", &self.eph_public)
            .field("state", &self.state)
            .finish()
    }
}

impl ZeroizeOnDrop for EdhocInitiator {}

impl Zeroize for EdhocInitiator {
    fn zeroize(&mut self) {
        self.privkey = PrivateKey::new([0; KEY_LEN_32]);
        self.pubkey = SchnorrPubKey::new([0; KEY_LEN_32]);
        self.eph_secret.zeroize();
        self.state.zeroize();
        self.state.lifecycle = Lifecycle::Zeroized;
    }
}

impl EdhocInitiator {
    /// Create a new EDHOC initiator using OsRng.
    #[cfg(feature = "std")]
    pub fn new_std(seed: [u8; 32], c_i: u8) -> Result<Self, OscoreError> {
        Ok(Self::new(seed, c_i, &mut rand_core::OsRng))
    }

    /// Create a new EDHOC initiator using caller-provided entropy.
    pub fn new_with_rng<R: RngCore + CryptoRng, C: Into<ConnectionId>>(
        seed: [u8; 32],
        c_i: C,
        rng: &mut R,
    ) -> Result<Self, OscoreError> {
        let schnorr_seed = schnorr48::Seed::new(seed);
        let (privkey, pubkey) = schnorr48::derive_keypair(&schnorr_seed);

        let mut eph_seed = Zeroizing::new([0u8; KEY_LEN_32]);
        rng.try_fill_bytes(&mut eph_seed[..])
            .map_err(|_| OscoreError::KeyDerivation)?;
        let eph_secret = StaticSecret::from(*eph_seed);
        eph_seed.zeroize();
        let eph_public = PublicKey::from(&eph_secret);

        Ok(Self {
            privkey,
            pubkey,
            c_i: c_i.into(),
            eph_secret: Some(eph_secret),
            eph_public,
            state: InitiatorState::default(),
        })
    }

    /// Create a new EDHOC initiator.
    ///
    /// # Arguments
    /// * `seed` - Schnorr48 seed (32 bytes)
    /// * `c_i` - Connection identifier (1 byte)
    /// * `rng` - RNG implementing RngCore + CryptoRng for ephemeral key
    pub fn new<R: RngCore + CryptoRng>(seed: [u8; 32], c_i: u8, rng: &mut R) -> Self {
        let schnorr_seed = schnorr48::Seed::new(seed);
        let (privkey, pubkey) = schnorr48::derive_keypair(&schnorr_seed);

        let eph_secret = StaticSecret::random_from_rng(rng);
        let eph_public = PublicKey::from(&eph_secret);

        Self {
            privkey,
            pubkey,
            c_i: ConnectionId::new(&[c_i]).expect("1-byte connection ID fits"),
            eph_secret: Some(eph_secret),
            eph_public,
            state: InitiatorState::default(),
        }
    }

    /// Create EDHOC Message 1.
    ///
    /// message_1 = (METHOD, SUITES_I, G_X, C_I, ? EAD_1)
    pub fn create_message_1(&mut self) -> Result<heapless::Vec<u8, 64>, EdhocError> {
        let mut msg1 = heapless::Vec::<u8, 64>::new();
        msg1.push_err(0)?; // METHOD = 0 (signature/signature)
        msg1.push_err(SUITE_0)?;
        encode_bstr(&mut msg1, self.eph_public.as_bytes())?;
        encode_bstr(&mut msg1, self.c_i.as_bytes())?;

        self.state.msg1 = msg1.clone();
        self.state.lifecycle = Lifecycle::Message1Created;
        Ok(msg1)
    }

    /// Process EDHOC Message 2 and create Message 3.
    ///
    /// # Arguments
    /// * `msg2` - Message 2 from responder
    /// * `peer_pubkey` - Responder's Ed25519 public key
    ///
    /// Returns Message 3 to send back.
    pub fn process_message_2(
        &mut self,
        msg2: &[u8],
        peer_pubkey: &[u8; 32],
    ) -> Result<heapless::Vec<u8, 128>, EdhocError> {
        let (id_cred, credential) = raw_key_credential(peer_pubkey)?;
        self.process_message_2_with_credential(
            msg2,
            PeerCredential::new(peer_pubkey, &id_cred, &credential),
        )
    }

    /// Process Message 2 using application-validated peer authentication material.
    pub fn process_message_2_with_credential(
        &mut self,
        msg2: &[u8],
        peer: PeerCredential<'_>,
    ) -> Result<heapless::Vec<u8, 128>, EdhocError> {
        let pending = self.begin_process_message_2(msg2)?;
        self.finish_process_message_2(&pending, peer)
    }

    /// Decrypt and parse Message 2 so the application can select a credential.
    pub fn begin_process_message_2(&mut self, msg2: &[u8]) -> Result<PendingMessage2, EdhocError> {
        if self.state.lifecycle != Lifecycle::Message1Created || self.eph_secret.is_none() {
            return Err(EdhocError::InvalidState);
        }

        if msg2.first() == Some(&2) {
            let error = match parse_suites_r(&msg2[1..]) {
                Ok(consumed) if consumed + 1 == msg2.len() => EdhocError::UnsupportedSuite,
                _ => EdhocError::InvalidMessage,
            };
            self.poison();
            return Err(error);
        }

        let (g_y_ct2, consumed) = parse_bstr(msg2)?;
        let (c_r_from_wire, c_r_consumed) = parse_identifier(&msg2[consumed..])?;
        if consumed + c_r_consumed != msg2.len() || g_y_ct2.len() < KEY_LEN_32 + 1 {
            return Err(EdhocError::InvalidMessage);
        }
        let mut g_y = [0u8; KEY_LEN_32];
        g_y.copy_from_slice(&g_y_ct2[..KEY_LEN_32]);
        let ciphertext_2 = &g_y_ct2[KEY_LEN_32..];

        // Compute shared secret G_XY (ephemeral key consumed - single use only)
        let eph_secret = self.eph_secret.take().ok_or(EdhocError::InvalidState)?;
        let peer_eph_public = PublicKey::from(g_y);
        let g_xy = eph_secret.diffie_hellman(&peer_eph_public);
        drop(eph_secret);
        self.state.g_y = g_y;
        // SECURITY: eph_secret is intentionally NOT stored back - single-use semantics
        // prevent cryptographic weakness from ephemeral key reuse (RFC 9528 freshness).

        let result = (|| {
            if g_xy.as_bytes() == &[0; KEY_LEN_32] {
                return Err(EdhocError::InvalidMessage);
            }
            self.state.th_2 = transcript_2(&self.state.g_y, &c_r_from_wire, &self.state.msg1)?;

            // PRK_2e = HKDF-Extract(salt=TH_2, IKM=G_XY)
            let prk_2e_z = hkdf_extract(&self.state.th_2, g_xy.as_bytes());
            self.state.prk_2e.copy_from_slice(&*prk_2e_z);
            drop(prk_2e_z);
            drop(g_xy);

            // Decrypt CIPHERTEXT_2 with KEYSTREAM_2
            let keystream_2 = edhoc_kdf(
                &self.state.prk_2e,
                &self.state.th_2,
                "KEYSTREAM_2",
                &[],
                ciphertext_2.len(),
            )?;
            let mut plaintext_2 = SecretVec::<128>::new();
            for (i, &b) in ciphertext_2.iter().enumerate() {
                plaintext_2.push_err(b ^ keystream_2[i])?;
            }

            // PRK_3e2m = PRK_2e for Suite 0 SIGN_SIGN (needed for MAC_2)
            self.state.prk_3e2m = self.state.prk_2e;

            let pt2 = plaintext_2.as_slice();
            let (c_r, c_r_len) = parse_identifier(pt2)?;
            if c_r == self.c_i {
                return Err(EdhocError::InvalidMessage);
            }
            let (id_cred_r, id_len) = super::credential::parse_id_cred(&pt2[c_r_len..])?;
            let sig_offset = c_r_len + id_len;
            let (signature_bytes, sig_len) = parse_bstr(&pt2[sig_offset..])?;
            if signature_bytes.len() != SIG_LEN || sig_offset + sig_len != pt2.len() {
                return Err(EdhocError::InvalidMessage);
            }

            let mut plaintext = heapless::Vec::new();
            plaintext.extend_err(pt2)?;
            self.state.lifecycle = Lifecycle::PendingMessage2;
            Ok(PendingMessage2 {
                id_cred: id_cred_r,
                plaintext,
                c_r,
                signature_offset: sig_offset,
                transcript_binding: self.state.th_2,
            })
        })();

        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Verify a pending Message 2 and create Message 3 with the selected credential.
    pub fn finish_process_message_2(
        &mut self,
        pending: &PendingMessage2,
        peer: PeerCredential<'_>,
    ) -> Result<heapless::Vec<u8, 128>, EdhocError> {
        if self.state.lifecycle != Lifecycle::PendingMessage2
            || pending.transcript_binding != self.state.th_2
        {
            return Err(EdhocError::InvalidState);
        }
        if peer.id_cred != pending.id_cred.as_bytes() {
            return Err(EdhocError::SignatureVerification);
        }

        let result = (|| {
            validate_peer_credential(peer)?;
            let signature_bytes = parse_bstr(&pending.plaintext[pending.signature_offset..])?.0;
            let context_2 =
                build_context_2(&pending.c_r, pending.id_cred.as_bytes(), peer.credential)?;
            let mac_2 = edhoc_kdf(
                &self.state.prk_3e2m,
                &self.state.th_2,
                "MAC_2",
                &context_2,
                32,
            )?;
            let m_2 = build_signature_structure(
                pending.id_cred.as_bytes(),
                &self.state.th_2,
                peer.credential,
                &mac_2,
            )?;
            validate_pubkey(peer.public_key)?;
            let peer_pubkey = SchnorrPubKey::new(*peer.public_key);
            let signature_2: [u8; SIG_LEN] = signature_bytes
                .try_into()
                .map_err(|_| EdhocError::InvalidMessage)?;
            if !schnorr48::verify(&peer_pubkey, &m_2, &signature_2) {
                return Err(EdhocError::SignatureVerification);
            }

            self.state.c_r = pending.c_r.clone();
            self.state.th_3 = transcript_3(&self.state.th_2, &pending.plaintext, peer.credential)?;

            // PRK_4e3m = PRK_3e2m for SIGN_SIGN (needed for MAC_3 and OSCORE export)
            self.state.prk_4e3m = self.state.prk_3e2m;

            let mut credential_i = heapless::Vec::<u8, 80>::new();
            encode_credential(&mut credential_i, self.pubkey.as_bytes())?;
            let mut id_cred_i = heapless::Vec::<u8, 40>::new();
            encode_id_cred(&mut id_cred_i, self.pubkey.as_bytes())?;
            let context_3 = build_context_3(&id_cred_i, &self.state.th_3, &credential_i)?;
            let mac_3 = edhoc_kdf(
                &self.state.prk_4e3m,
                &self.state.th_3,
                "MAC_3",
                &context_3,
                32,
            )?;
            let m_3 =
                build_signature_structure(&id_cred_i, &self.state.th_3, &credential_i, &mac_3)?;
            let signature_3 = schnorr48::sign(&self.privkey, &self.pubkey, &m_3);
            let mut ciphertext_3 = SecretVec::<128>::new();
            encode_bstr(&mut ciphertext_3, self.pubkey.as_bytes())?;
            encode_bstr(&mut ciphertext_3, &signature_3)?;

            // K_3 and IV_3 for AEAD
            let k_3 = edhoc_kdf(&self.state.prk_3e2m, &self.state.th_3, "K_3", &[], KEY_LEN)?;
            let iv_3 = edhoc_kdf(
                &self.state.prk_3e2m,
                &self.state.th_3,
                "IV_3",
                &[],
                NONCE_LEN,
            )?;

            let mut a_3 = heapless::Vec::<u8, 64>::new();
            a_3.push_err(0x83)?;
            a_3.push_err(0x68)?;
            a_3.extend_err(b"Encrypt0")?;
            a_3.push_err(0x40)?;
            a_3.push_err(0x58)?;
            a_3.push_err(32)?;
            a_3.extend_err(&self.state.th_3)?;

            let data_3 = ciphertext_3.0.clone();

            let cipher = AesCcm::new_from_slice(&k_3).map_err(|_| EdhocError::InvalidState)?;
            let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
            nonce.copy_from_slice(&iv_3);
            let tag = cipher
                .encrypt_in_place_detached((&*nonce).into(), &a_3, &mut ciphertext_3)
                .map_err(|_| EdhocError::InvalidState)?;
            ciphertext_3.extend_err(&tag)?;

            self.state.th_4 = transcript_4(&self.state.th_3, &data_3, peer.credential)?;

            self.state.completed = true;
            self.state.lifecycle = Lifecycle::Complete;
            let mut msg3 = heapless::Vec::new();
            encode_bstr(&mut msg3, &ciphertext_3.0)?;
            Ok(msg3)
        })();

        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Export OSCORE security context.
    ///
    /// # Errors
    /// Returns `OscoreError::NoContext` if called before handshake completes
    /// (i.e., before `process_message_2` succeeds).
    pub fn export_oscore(&self) -> Result<Context, OscoreError> {
        if !self.state.completed || self.state.prk_4e3m.iter().fold(0u8, |acc, &b| acc | b) == 0 {
            return Err(OscoreError::NoContext);
        }
        // Use dedicated exporter for full master_secret/salt derivation + new_fresh.
        // IDs: local c_i as sender_id for initiator context.
        export_context(
            &self.state.prk_4e3m,
            &self.state.th_4,
            self.c_i.as_bytes(),
            self.state.c_r.as_bytes(),
        )
    }

    pub(crate) fn poison(&mut self) {
        self.privkey = PrivateKey::new([0; KEY_LEN_32]);
        self.pubkey = SchnorrPubKey::new([0; KEY_LEN_32]);
        self.eph_secret.zeroize();
        self.state.zeroize();
        self.state.lifecycle = Lifecycle::Failed;
    }
}

/// In-progress Message 2 decryption, before credential verification.
pub struct PendingMessage2 {
    /// Parsed ID_CRED from the responder.
    id_cred: IdCred,
    /// Decrypted plaintext of Message 2 (without keystream).
    pub(crate) plaintext: heapless::Vec<u8, 128>,
    /// Connection identifier from the responder.
    pub(crate) c_r: ConnectionId,
    /// Byte offset where the signature begins.
    pub(crate) signature_offset: usize,
    /// Transcript binding at time of parsing.
    pub(crate) transcript_binding: [u8; 32],
}

impl PendingMessage2 {
    /// Return the credential reference offered by the peer.
    pub fn id_cred(&self) -> &IdCred {
        &self.id_cred
    }
}
