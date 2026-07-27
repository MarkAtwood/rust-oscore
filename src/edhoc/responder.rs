// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Mark Atwood

//! EDHOC Responder (server role) implementation.

use super::cbor::{encode_bstr, encode_identifier, parse_bstr, parse_suites_i};
use super::credential::{
    encode_credential, encode_id_cred, parse_id_cred, raw_key_credential, strong_verifying_key,
    validate_peer_credential, PeerCredential,
};
use super::kdf::{edhoc_kdf, export_context, hkdf_extract};
use super::transcript::{
    build_context_2, build_context_3, build_signature_structure, transcript_2, transcript_3,
    transcript_4,
};
use super::types::{ConnectionId, IdCred, SecretVec, VecExt};
use super::{EdhocError, Lifecycle, KEY_LEN_32, SIG_LEN, SUITE_0};
use crate::{Context, OscoreError, KEY_LEN, NONCE_LEN, TAG_LEN};
use aes::Aes128;
use ccm::{
    aead::{AeadInPlace, KeyInit},
    consts::{U13, U8},
    Ccm,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// AES-CCM for Suite 0.
type AesCcm = Ccm<Aes128, U8, U13>;

/// EDHOC Responder (server role).
// SECURITY: SigningKey and StaticSecret must be zeroized on drop.
// SigningKey and StaticSecret implement ZeroizeOnDrop themselves.
pub struct EdhocResponder {
    /// Our Ed25519 signing key (implements ZeroizeOnDrop).
    pub(crate) signing_key: SigningKey,
    /// Our Ed25519 public key.
    pub(crate) pubkey: VerifyingKey,
    /// Our connection identifier.
    pub(crate) c_r: ConnectionId,
    /// Ephemeral X25519 secret (implements ZeroizeOnDrop).
    pub(crate) eph_secret: Option<StaticSecret>,
    /// Ephemeral X25519 public key.
    eph_public: PublicKey,
    /// Protocol state.
    pub(crate) state: ResponderState,
}

/// Responder protocol state.
///
/// PRK derivation chain per python/src/lichen/crypto/edhoc.py:
/// PRK_2e = HKDF-Extract(salt=TH_2, IKM=G_XY)
/// PRK_3e2m = PRK_2e for Suite 0 SIGN_SIGN (needed for MAC_2)
/// PRK_4e3m = PRK_3e2m (needed for MAC_3 and OSCORE export)
/// All must be zeroized on drop.
pub(crate) struct ResponderState {
    msg1: heapless::Vec<u8, 64>,
    g_x: [u8; 32],
    pub(crate) c_i: ConnectionId,
    pub(crate) prk_2e: [u8; 32],
    pub(crate) prk_3e2m: [u8; 32],
    pub(crate) prk_4e3m: [u8; 32],
    pub(crate) th_2: [u8; 32],
    pub(crate) th_3: [u8; 32],
    pub(crate) th_4: [u8; 32],
    /// True when handshake completed (process_message_3 succeeded).
    pub(crate) completed: bool,
    pub(crate) lifecycle: Lifecycle,
}

impl Default for ResponderState {
    fn default() -> Self {
        Self {
            msg1: heapless::Vec::new(),
            g_x: [0; 32],
            c_i: ConnectionId::new(&[]).expect("empty connection ID fits"),
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

impl Zeroize for ResponderState {
    fn zeroize(&mut self) {
        self.g_x.zeroize();
        self.prk_2e.zeroize();
        self.prk_3e2m.zeroize();
        self.prk_4e3m.zeroize();
        self.th_2.zeroize();
        self.th_3.zeroize();
        self.th_4.zeroize();
        self.msg1.zeroize();
    }
}

impl core::fmt::Debug for ResponderState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResponderState")
            .field("msg1", &self.msg1)
            .field("g_x", &"[REDACTED]")
            .field("c_i", &self.c_i)
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

impl ZeroizeOnDrop for ResponderState {}

impl core::fmt::Debug for EdhocResponder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EdhocResponder")
            .field("signing_key", &"[REDACTED]")
            .field("pubkey", &self.pubkey)
            .field("c_r", &self.c_r)
            .field("eph_secret", &"[REDACTED]")
            .field("eph_public", &self.eph_public)
            .field("state", &self.state)
            .finish()
    }
}

impl Zeroize for EdhocResponder {
    fn zeroize(&mut self) {
        self.signing_key = SigningKey::from_bytes(&[0; KEY_LEN_32]);
        self.eph_secret.zeroize();
        self.state.zeroize();
        self.state.lifecycle = Lifecycle::Zeroized;
    }
}

impl EdhocResponder {
    /// Create a new EDHOC responder using OsRng.
    #[cfg(feature = "std")]
    pub fn new_std(seed: [u8; 32], c_r: u8) -> Result<Self, OscoreError> {
        Self::new_with_rng(seed, c_r, &mut rand_core::OsRng)
    }

    /// Create a new EDHOC responder.
    ///
    /// # Arguments
    /// * `seed` - Ed25519 seed (32 bytes)
    /// * `c_r` - Connection identifier (1 byte)
    /// * `rng` - RNG implementing RngCore + CryptoRng for ephemeral key
    pub fn new<R: RngCore + CryptoRng>(seed: [u8; 32], c_r: u8, rng: &mut R) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key();

        let eph_secret = StaticSecret::random_from_rng(rng);
        let eph_public = PublicKey::from(&eph_secret);

        Self {
            signing_key,
            pubkey,
            c_r: ConnectionId::new(&[c_r]).expect("1-byte connection ID fits"),
            eph_secret: Some(eph_secret),
            eph_public,
            state: ResponderState::default(),
        }
    }

    /// Create a new EDHOC responder using caller-provided entropy.
    pub fn new_with_rng<R: RngCore + CryptoRng>(
        seed: [u8; 32],
        c_r: u8,
        rng: &mut R,
    ) -> Result<Self, OscoreError> {
        let mut eph_seed = [0u8; KEY_LEN_32];
        rng.try_fill_bytes(&mut eph_seed[..])
            .map_err(|_| OscoreError::KeyDerivation)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key();
        let eph_secret = StaticSecret::from(eph_seed);
        let eph_public = PublicKey::from(&eph_secret);

        Ok(Self {
            signing_key,
            pubkey,
            c_r: ConnectionId::new(&[c_r]).expect("1-byte connection ID fits"),
            eph_secret: Some(eph_secret),
            eph_public,
            state: ResponderState::default(),
        })
    }

    pub(crate) fn poison(&mut self) {
        self.signing_key = SigningKey::from_bytes(&[0; KEY_LEN_32]);
        self.eph_secret.zeroize();
        self.state.zeroize();
        self.state.lifecycle = Lifecycle::Failed;
    }

    /// Process EDHOC Message 1 and create Message 2.
    pub fn process_message_1(&mut self, msg1: &[u8]) -> Result<heapless::Vec<u8, 160>, EdhocError> {
        if self.state.lifecycle != Lifecycle::Created || self.eph_secret.is_none() {
            return Err(EdhocError::InvalidState);
        }

        let mut stored_msg1 = heapless::Vec::<u8, 64>::new();
        stored_msg1.extend_err(msg1)?;

        // Parse message_1 = (METHOD, SUITES_I, G_X, C_I, ? EAD_1).
        if msg1.len() < 37 {
            return Err(EdhocError::InvalidMessage);
        }

        // METHOD = 0 means SIGN_SIGN (both parties use signature authentication)
        if msg1[0] != 0 {
            return Err(EdhocError::InvalidMessage);
        }

        // Parse SUITES_I per RFC 9528 Section 3.3.2:
        // - Single int: the selected suite
        // - Array of ints: [selected_suite, ...other_supported_suites]
        let (selected_suite, suites_i_end) = parse_suites_i(&msg1[1..])?;

        if selected_suite != SUITE_0 {
            return Err(EdhocError::UnsupportedSuite);
        }

        // Parse G_X (32-byte bstr) - starts after METHOD_CORR + SUITES_I
        let g_x_start = 1 + suites_i_end;
        if msg1.len() < g_x_start + 2 + 32 + 1 {
            return Err(EdhocError::InvalidMessage);
        }
        if msg1[g_x_start] != 0x58 || msg1[g_x_start + 1] != 32 {
            return Err(EdhocError::InvalidMessage);
        }
        let g_x = {
            let mut gx = [0u8; 32];
            gx.copy_from_slice(&msg1[g_x_start + 2..g_x_start + 2 + 32]);
            gx
        };
        self.state.g_x = g_x;

        // Parse C_I
        let rest = &msg1[g_x_start + 2 + 32..];
        let c_i = if !rest.is_empty() {
            if rest[0] <= 23 {
                rest[0]
            } else if rest[0] == 0x41 && rest.len() > 1 {
                rest[1]
            } else {
                return Err(EdhocError::InvalidMessage);
            }
        } else {
            return Err(EdhocError::InvalidMessage);
        };
        if self.c_r.as_bytes() == [c_i] {
            self.poison();
            return Err(EdhocError::InvalidMessage);
        }

        // Compute shared secret (ephemeral key consumed - single use only)
        let eph_secret = self.eph_secret.take().ok_or(EdhocError::InvalidState)?;
        let peer_eph_public = PublicKey::from(g_x);
        let g_xy = eph_secret.diffie_hellman(&peer_eph_public);
        drop(eph_secret);
        self.state.msg1 = stored_msg1;
        self.state.g_x = g_x;
        self.state.c_i = c_i.into();
        // SECURITY: eph_secret is intentionally NOT stored back - single-use semantics
        // prevent cryptographic weakness from ephemeral key reuse if this function
        // is called multiple times (e.g., due to retransmission handling bugs).

        let result = (|| {
            if g_xy.as_bytes() == &[0; KEY_LEN_32] {
                return Err(EdhocError::InvalidMessage);
            }
            self.state.th_2 = transcript_2(self.eph_public.as_bytes(), &self.c_r, msg1)?;

            // PRK_2e = HKDF-Extract(salt=TH_2, IKM=G_XY)
            let prk_2e_z = hkdf_extract(&self.state.th_2, g_xy.as_bytes());
            self.state.prk_2e.copy_from_slice(&*prk_2e_z);
            drop(prk_2e_z);
            drop(g_xy);

            // PRK_3e2m = PRK_2e for Suite 0 SIGN_SIGN (needed for MAC_2)
            self.state.prk_3e2m = self.state.prk_2e;

            let mut id_cred_r = heapless::Vec::<u8, 40>::new();
            encode_id_cred(&mut id_cred_r, self.pubkey.as_bytes())?;
            let mut credential_r = heapless::Vec::<u8, 80>::new();
            encode_credential(&mut credential_r, self.pubkey.as_bytes())?;
            let context_2 = build_context_2(&self.c_r, &id_cred_r, &credential_r)?;
            let mac_2 = edhoc_kdf(
                &self.state.prk_3e2m,
                &self.state.th_2,
                "MAC_2",
                &context_2,
                32,
            )?;
            let m_2 =
                build_signature_structure(&id_cred_r, &self.state.th_2, &credential_r, &mac_2)?;
            let signature_2 = self.signing_key.sign(&m_2);

            let mut plaintext_2 = SecretVec::<128>::new();
            encode_identifier(&mut plaintext_2, &self.c_r)?;
            encode_bstr(&mut plaintext_2, self.pubkey.as_bytes())?;
            encode_bstr(&mut plaintext_2, &signature_2.to_bytes())?;

            // Encrypt with KEYSTREAM_2
            let keystream_2 = edhoc_kdf(
                &self.state.prk_2e,
                &self.state.th_2,
                "KEYSTREAM_2",
                &[],
                plaintext_2.len(),
            )?;
            let mut ciphertext_2 = heapless::Vec::<u8, 128>::new();
            for (i, &b) in plaintext_2.iter().enumerate() {
                ciphertext_2.push_err(b ^ keystream_2[i])?;
            }

            self.state.th_3 = transcript_3(&self.state.th_2, &plaintext_2, &credential_r)?;

            let mut msg2 = heapless::Vec::<u8, 160>::new();
            let mut g_y_ciphertext = heapless::Vec::<u8, 144>::new();
            g_y_ciphertext.extend_err(self.eph_public.as_bytes())?;
            g_y_ciphertext.extend_err(&ciphertext_2)?;
            encode_bstr(&mut msg2, &g_y_ciphertext)?;
            encode_identifier(&mut msg2, &self.c_r)?;

            self.state.lifecycle = Lifecycle::AwaitingMessage3;
            Ok(msg2)
        })();

        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Process EDHOC Message 3.
    pub fn process_message_3(
        &mut self,
        msg3: &[u8],
        peer_pubkey: &[u8; 32],
    ) -> Result<(), EdhocError> {
        let (id_cred, credential) = raw_key_credential(peer_pubkey)?;
        self.process_message_3_with_credential(
            msg3,
            PeerCredential::new(peer_pubkey, &id_cred, &credential),
        )
    }

    /// Process Message 3 using application-validated peer authentication material.
    pub fn process_message_3_with_credential(
        &mut self,
        msg3: &[u8],
        peer: PeerCredential<'_>,
    ) -> Result<(), EdhocError> {
        let pending = self.begin_process_message_3(msg3)?;
        self.finish_process_message_3(&pending, peer)
    }

    /// Authenticate-decrypt and parse Message 3 before credential selection.
    pub fn begin_process_message_3(&mut self, msg3: &[u8]) -> Result<PendingMessage3, EdhocError> {
        if self.state.lifecycle != Lifecycle::AwaitingMessage3 {
            return Err(EdhocError::InvalidState);
        }

        let result = (|| {
            let (ciphertext_3, consumed) = parse_bstr(msg3)?;
            if consumed != msg3.len() {
                return Err(EdhocError::InvalidMessage);
            }

            // K_3 and IV_3 for AEAD decryption
            let k_3 = edhoc_kdf(&self.state.prk_3e2m, &self.state.th_3, "K_3", &[], KEY_LEN)?;
            let iv_3 = edhoc_kdf(
                &self.state.prk_3e2m,
                &self.state.th_3,
                "IV_3",
                &[],
                NONCE_LEN,
            )?;

            // A_3 (AAD)
            let mut a_3 = heapless::Vec::<u8, 64>::new();
            a_3.push_err(0x83)?;
            a_3.push_err(0x68)?;
            a_3.extend_err(b"Encrypt0")?;
            a_3.push_err(0x40)?;
            a_3.push_err(0x58)?;
            a_3.push_err(32)?;
            a_3.extend_err(&self.state.th_3)?;

            // Decrypt CIPHERTEXT_3
            if ciphertext_3.len() < TAG_LEN {
                return Err(EdhocError::InvalidMessage);
            }
            let tag_start = ciphertext_3.len() - TAG_LEN;
            let tag = ccm::aead::Tag::<AesCcm>::from_slice(&ciphertext_3[tag_start..]);
            let cipher = AesCcm::new_from_slice(&k_3).map_err(|_| EdhocError::InvalidState)?;
            let mut plaintext_3 = SecretVec::<128>::new();
            plaintext_3.extend_err(&ciphertext_3[..tag_start])?;
            let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
            nonce.copy_from_slice(&iv_3);
            cipher
                .decrypt_in_place_detached((&*nonce).into(), &a_3, &mut plaintext_3, tag)
                .map_err(|_| EdhocError::DecryptFailed)?;

            let (id_cred_i, id_len) = parse_id_cred(&plaintext_3)?;
            let (sig_bytes, sig_len) = parse_bstr(&plaintext_3[id_len..])?;
            if sig_bytes.len() != SIG_LEN || id_len + sig_len != plaintext_3.len() {
                return Err(EdhocError::InvalidMessage);
            }

            let mut plaintext = heapless::Vec::new();
            plaintext.extend_err(&plaintext_3)?;
            self.state.lifecycle = Lifecycle::PendingMessage3;
            Ok(PendingMessage3 {
                id_cred: id_cred_i,
                plaintext,
                signature_offset: id_len,
                transcript_binding: self.state.th_3,
            })
        })();

        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Verify a pending Message 3 with the selected peer credential.
    pub fn finish_process_message_3(
        &mut self,
        pending: &PendingMessage3,
        peer: PeerCredential<'_>,
    ) -> Result<(), EdhocError> {
        if self.state.lifecycle != Lifecycle::PendingMessage3
            || pending.transcript_binding != self.state.th_3
        {
            return Err(EdhocError::InvalidState);
        }
        if peer.id_cred != pending.id_cred.as_bytes() {
            return Err(EdhocError::SignatureVerification);
        }

        let result = (|| {
            validate_peer_credential(peer)?;
            let sig_bytes = parse_bstr(&pending.plaintext[pending.signature_offset..])?.0;
            let signature = Signature::from_bytes(
                sig_bytes
                    .try_into()
                    .map_err(|_| EdhocError::InvalidMessage)?,
            );
            let peer_verifying_key = strong_verifying_key(peer.public_key)?;

            // PRK_4e3m = PRK_3e2m for SIGN_SIGN (needed for MAC_3 and OSCORE export)
            self.state.prk_4e3m = self.state.prk_3e2m;
            let context_3 = build_context_3(
                pending.id_cred.as_bytes(),
                &self.state.th_3,
                peer.credential,
            )?;
            let mac_3 = edhoc_kdf(
                &self.state.prk_4e3m,
                &self.state.th_3,
                "MAC_3",
                &context_3,
                32,
            )?;
            let m_3 = build_signature_structure(
                pending.id_cred.as_bytes(),
                &self.state.th_3,
                peer.credential,
                &mac_3,
            )?;

            peer_verifying_key
                .verify_strict(&m_3, &signature)
                .map_err(|_| EdhocError::SignatureVerification)?;

            let mut credential_r = heapless::Vec::<u8, 80>::new();
            encode_credential(&mut credential_r, self.pubkey.as_bytes())?;
            self.state.th_4 = transcript_4(&self.state.th_3, &pending.plaintext, &credential_r)?;
            self.state.completed = true;
            self.state.lifecycle = Lifecycle::Complete;

            Ok(())
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
    /// (i.e., before `process_message_3` succeeds).
    pub fn export_oscore(&self) -> Result<Context, OscoreError> {
        if !self.state.completed || self.state.prk_4e3m.iter().fold(0u8, |acc, &b| acc | b) == 0 {
            return Err(OscoreError::NoContext);
        }
        // Use dedicated exporter for full master_secret/salt derivation + new_fresh.
        // IDs: local c_r as sender_id for responder context.
        export_context(
            &self.state.prk_4e3m,
            &self.state.th_4,
            self.c_r.as_bytes(),
            self.state.c_i.as_bytes(),
        )
    }
}

/// In-progress Message 3 decryption, before credential verification.
pub struct PendingMessage3 {
    /// Parsed ID_CRED from the initiator.
    id_cred: IdCred,
    /// Decrypted plaintext of Message 3.
    pub(crate) plaintext: heapless::Vec<u8, 128>,
    /// Byte offset where the signature begins.
    signature_offset: usize,
    /// Transcript binding at time of parsing.
    pub(crate) transcript_binding: [u8; 32],
}

impl PendingMessage3 {
    /// Return the credential reference offered by the peer.
    pub fn id_cred(&self) -> &IdCred {
        &self.id_cred
    }
}
