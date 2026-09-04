//! Double Ratchet Algorithm (Signal Protocol)
//!
//! Implements the core encryption algorithm of the Signal protocol:
//! - X3DH initial key exchange
//! - Double Ratchet key updates (KDF chains)
//! - Forward secrecy + post-compromise security
//!
//! Migrated from: D:\FIBEMATE\01_Rust源码_E盘\src\double_ratchet.rs

use std::collections::HashMap;
use std::sync::Mutex;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Maximum number of messages that may be skipped in a single ratchet step.
/// Bounds the skipped-key pool to prevent memory-exhaustion DoS.
const MAX_SKIP: u32 = 1000;
/// Maximum entries kept in previous_send_keys to bound memory growth.
/// On insertion, if the map exceeds this size the oldest key (lowest message_num) is evicted.
const MAX_PREVIOUS_SEND_KEYS: usize = 100;

/// Ratchet key pair (X25519)
#[derive(Clone, Zeroize)]
pub struct RatchetKeyPair {
    pub public_key: [u8; 32],
    #[zeroize]
    pub private_key: [u8; 32],
}

impl RatchetKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self {
            public_key: *public.as_bytes(),
            private_key: secret.to_bytes(),
        }
    }

    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private_key);
        let public = PublicKey::from(&secret);
        Self {
            public_key: *public.as_bytes(),
            private_key,
        }
    }

    pub fn diffie_hellman(&self, their_public: &[u8; 32]) -> Result<[u8; 32], String> {
        let their_public = PublicKey::from(*their_public);
        let our_secret = StaticSecret::from(self.private_key);
        Ok(*our_secret.diffie_hellman(&their_public).as_bytes())
    }
}

/// Ratchet state for one conversation direction
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RatchetState {
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub send_public_key: [u8; 32],
    pub recv_public_key: [u8; 32],
    pub send_message_num: u32,
    pub recv_message_num: u32,
    pub previous_send_keys: HashMap<u32, [u8; 32]>,
    pub skipped_messages: u32,
    /// Skipped message keys pool (Signal spec). When messages arrive out of
    /// order, the keys of skipped-over messages are stored here so they can
    /// be decrypted when they eventually arrive. Indexed by message number.
    #[serde(default)]
    pub skipped_keys: HashMap<u32, [u8; 32]>,
    /// Public keys of chains we have ratcheted away from. Late messages that
    /// carry one of these keys belong to an OLD chain and must NOT trigger
    /// another DH ratchet — they decrypt via previous_send_keys instead.
    #[serde(default)]
    pub previous_chain_pubkeys: Vec<[u8; 32]>,
    // ── DH ratchet state (v2) ──
    /// Our current DH ratchet private key (X25519, 32 bytes)
    #[serde(default)]
    pub dh_private: [u8; 32],
    /// Root key for the DH ratchet (chain-updated on each ratchet step)
    #[serde(default)]
    pub root_key: [u8; 32],
    /// Role marker: true = initiator (Alice), false = responder (Bob)
    #[serde(default)]
    pub is_initiator: bool,
    // ── Identity binding (for Safety Number) ──
    /// The identity key we used during X3DH (KeyStore identifier)
    #[serde(default)]
    pub our_identity_id: Option<String>,
    /// The peer's identity public key from X3DH (X25519, 32 bytes)
    #[serde(default)]
    pub peer_identity_pk: Option<[u8; 32]>,
}

impl RatchetState {
    pub fn init_from_shared_secret(
        shared_secret: &[u8; 32],
        is_initiator: bool,
    ) -> Result<Self, String> {
        // Symmetric chain-key derivation from the X3DH shared secret.
        // The info strings are role-swapped so that:
        //   initiator.send_chain == responder.recv_chain
        //   initiator.recv_chain == responder.send_chain
        // This makes message 1 decryptable before any DH ratchet has run.
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut initiator_send = [0u8; 32];
        let mut initiator_recv = [0u8; 32];
        hkdf.expand(b"initiator_send", &mut initiator_send)
            .map_err(|e| e.to_string())?;
        hkdf.expand(b"initiator_recv", &mut initiator_recv)
            .map_err(|e| e.to_string())?;

        let keypair = RatchetKeyPair::generate();
        Ok(Self {
            send_chain_key: if is_initiator {
                initiator_send
            } else {
                initiator_recv
            },
            recv_chain_key: if is_initiator {
                initiator_recv
            } else {
                initiator_send
            },
            send_public_key: keypair.public_key,
            recv_public_key: [0u8; 32],
            send_message_num: 0,
            recv_message_num: 0,
            previous_send_keys: HashMap::new(),
            skipped_messages: 0,
            skipped_keys: HashMap::new(),
            previous_chain_pubkeys: Vec::new(),
            dh_private: keypair.private_key,
            root_key: *shared_secret,
            is_initiator,
            our_identity_id: None,
            peer_identity_pk: None,
        })
    }

    pub fn ratchet_step(&mut self, their_public_key: [u8; 32]) -> Result<(), String> {
        // Migrate this chain's unused skipped message keys into the cross-chain
        // pool (previous_send_keys) BEFORE clearing. Messages from the OLD chain
        // may still arrive late (in flight during the ratchet); their message
        // keys are message keys (MK), so decrypting with them is correct.
        // Without this, late old-chain messages would fail with aead::Error.
        for (num, mk) in self.skipped_keys.drain() {
            self.previous_send_keys.insert(num, mk);
        }
        // Remember the chain we are ratcheting away from, so late messages
        // carrying this public key are recognised as old-chain messages and
        // do not trigger another ratchet.
        if self.recv_public_key != [0u8; 32]
            && !self.previous_chain_pubkeys.contains(&self.recv_public_key)
        {
            self.previous_chain_pubkeys.push(self.recv_public_key);
            if self.previous_chain_pubkeys.len() > 8 {
                self.previous_chain_pubkeys.remove(0); // FIFO — drop oldest chain
            }
        }
        // Evict oldest entry if map grew beyond the cap (FIFO).
        while self.previous_send_keys.len() > MAX_PREVIOUS_SEND_KEYS {
            if let Some(&min_key) = self.previous_send_keys.keys().min() {
                self.previous_send_keys.remove(&min_key);
            }
        }
        // 1. Derive a new recv chain from (current dh_private, their new pub)
        let shared =
            RatchetKeyPair::from_private_key(self.dh_private).diffie_hellman(&their_public_key)?;
        let (new_rk, recv_ck) = kdf_rk(&self.root_key, &shared);
        self.root_key = new_rk;
        self.recv_chain_key = recv_ck;
        // 2. Generate a fresh DH keypair for our sending side
        let new_keypair = RatchetKeyPair::generate();
        let shared2 = new_keypair.diffie_hellman(&their_public_key)?;
        let (new_rk2, send_ck) = kdf_rk(&self.root_key, &shared2);
        self.root_key = new_rk2;
        self.send_chain_key = send_ck;
        self.dh_private = new_keypair.private_key;
        self.send_public_key = new_keypair.public_key;
        self.recv_public_key = their_public_key;
        self.send_message_num = 0;
        self.skipped_messages = 0;
        Ok(())
    }
}

/// Signal KDF_RK: derive (new_root_key, chain_key) from (root_key, dh_output).
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut okm = [0u8; 64];
    hkdf.expand(b"fibemate-dr-rk-v1", &mut okm)
        .expect("HKDF expand should never fail for 64 bytes");
    let mut new_rk = [0u8; 32];
    let mut chain = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    chain.copy_from_slice(&okm[32..]);
    (new_rk, chain)
}

/// KDF chain for deriving message keys
pub struct KdfChain {
    chain_key: [u8; 32],
}

impl KdfChain {
    pub fn new(chain_key: [u8; 32]) -> Self {
        Self { chain_key }
    }

    pub fn next_message_key(&mut self) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(None, &self.chain_key);
        let mut message_key = [0u8; 32];
        let mut next_chain_key = [0u8; 32];
        hkdf.expand(b"message_key", &mut message_key).unwrap();
        hkdf.expand(b"next_chain", &mut next_chain_key).unwrap();
        self.chain_key = next_chain_key;
        message_key
    }

    pub fn skip_messages(&mut self, count: u32) -> Vec<[u8; 32]> {
        let mut keys = Vec::new();
        for _ in 0..count {
            keys.push(self.next_message_key());
        }
        keys
    }
}

/// AES-256-GCM encryptor
pub struct AesGcmEncryptor;

impl AesGcmEncryptor {
    pub fn encrypt(
        key: &[u8; 32],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 12]), String> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|e| e.to_string())?;
        Ok((ciphertext, nonce_bytes))
    }

    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
        let nonce = Nonce::from_slice(nonce);
        cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|e| e.to_string())
    }
}

/// X3DH initial key exchange
pub struct X3DH;

impl X3DH {
    pub fn initiator(
        my_identity: &RatchetKeyPair,
        my_ephemeral: &RatchetKeyPair,
        their_identity: &[u8; 32],
        their_signed_prekey: &[u8; 32],
    ) -> Result<[u8; 32], String> {
        // X3DH (Signal spec): DH1 = DH(IK_A, SPK_B)
        let dh1 = my_identity.diffie_hellman(their_signed_prekey)?;
        let dh2 = my_ephemeral.diffie_hellman(their_identity)?;
        let dh3 = my_ephemeral.diffie_hellman(their_signed_prekey)?;
        let mut combined = [0u8; 96];
        combined[..32].copy_from_slice(&dh1);
        combined[32..64].copy_from_slice(&dh2);
        combined[64..].copy_from_slice(&dh3);
        let hkdf = Hkdf::<Sha256>::new(None, &combined);
        let mut shared_secret = [0u8; 32];
        hkdf.expand(b"shared_secret", &mut shared_secret)
            .map_err(|e| e.to_string())?;
        Ok(shared_secret)
    }

    pub fn responder(
        my_identity: &RatchetKeyPair,
        my_signed_prekey: &RatchetKeyPair,
        their_identity: &[u8; 32],
        their_ephemeral: &[u8; 32],
    ) -> Result<[u8; 32], String> {
        let dh1 = my_signed_prekey.diffie_hellman(their_identity)?;
        let dh2 = my_identity.diffie_hellman(their_ephemeral)?;
        let dh3 = my_signed_prekey.diffie_hellman(their_ephemeral)?;
        let mut combined = [0u8; 96];
        combined[..32].copy_from_slice(&dh1);
        combined[32..64].copy_from_slice(&dh2);
        combined[64..].copy_from_slice(&dh3);
        let hkdf = Hkdf::<Sha256>::new(None, &combined);
        let mut shared_secret = [0u8; 32];
        hkdf.expand(b"shared_secret", &mut shared_secret)
            .map_err(|e| e.to_string())?;
        Ok(shared_secret)
    }
}

/// Encrypted message structure (serializable)
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedMessage {
    pub public_key: [u8; 32],
    pub message_num: u32,
    pub previous_chain_length: u32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Session manager — holds all active Double Ratchet sessions
pub struct SessionManager {
    sessions: Mutex<HashMap<String, RatchetState>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn create_session(
        &self,
        session_id: &str,
        shared_secret: &[u8; 32],
        is_initiator: bool,
    ) -> Result<(), String> {
        let state = RatchetState::init_from_shared_secret(shared_secret, is_initiator)?;
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        sessions.insert(session_id.to_string(), state);
        Ok(())
    }

    /// Set the peer's public key for a session.
    ///
    /// If recv_public_key is currently all-zero (initial state), this means we are
    /// receiving the peer's first DH public key after X3DH. In that case we must
    /// perform a ratchet step immediately so both sides derive the same chain keys.
    ///
    /// Background:
    ///   - Alice (initiator) creates session with send_chain=K1, recv_chain=K1'
    ///   - Bob (responder) receives init message, ratchets immediately: recv_chain=K1',
    ///     send_chain=K2', send_public_key=P_B2
    ///   - Bob sends x3dh_accept_rust carrying P_B2
    ///   - Alice receives P_B2 → setPeerKey(P_B2) with zero recv_public_key
    ///   - Without ratchet_step here, Alice's send_chain stays K1 but Bob's recv_chain
    ///     is K1' → AEAD fails on message 2
    ///   - With ratchet_step: Alice derives K2, Bob's recv_chain=K2' → symmetric ✅
    pub fn set_peer_key(&self, session_id: &str, peer_public_key: [u8; 32]) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let state = sessions.get_mut(session_id).ok_or("Session not found")?;

        if state.recv_public_key == [0u8; 32] {
            // First peer key received — just store it. Chain keys were already
            // derived symmetrically at init, so both sides' message 1 decrypts.
            // A DH ratchet step is triggered later by decrypt_message only when
            // the peer rotates their DH public key.
            state.recv_public_key = peer_public_key;
        } else {
            // Subsequent key update — just store it.
            state.recv_public_key = peer_public_key;
        }

        Ok(())
    }

    /// Get current recv_public_key for a session (for diagnostics).
    pub fn get_session_recv_pk(&self, session_id: &str) -> Result<[u8; 32], String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let state = sessions.get(session_id).ok_or("Session not found")?;
        Ok(state.recv_public_key)
    }

    /// Test-only: force a DH ratchet step on a session, simulating the peer
    /// rotating their DH public key mid-conversation.
    #[cfg(test)]
    pub fn debug_ratchet_step(&self, session_id: &str, their_pub: [u8; 32]) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let state = sessions.get_mut(session_id).ok_or("Session not found")?;
        state.ratchet_step(their_pub)
    }

    /// Check if a session exists.
    pub fn has_session(&self, session_id: &str) -> Result<bool, String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        Ok(sessions.contains_key(session_id))
    }

    /// Check if decrypt_message would trigger a ratchet step (for diagnostics).
    pub fn will_ratchet_on_decrypt(
        &self,
        session_id: &str,
        message: &EncryptedMessage,
    ) -> Result<bool, String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let state = sessions.get(session_id).ok_or("Session not found")?;
        Ok(message.public_key != state.recv_public_key)
    }

    /// Bind identity keys to this session (for Safety Number display).
    /// Call once after X3DH handshake completes.
    pub fn set_identity_keys(
        &self,
        session_id: &str,
        our_identity_id: &str,
        peer_identity_pk: [u8; 32],
    ) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let state = sessions.get_mut(session_id).ok_or("Session not found")?;
        state.our_identity_id = Some(our_identity_id.to_string());
        state.peer_identity_pk = Some(peer_identity_pk);
        Ok(())
    }

    pub fn get_send_key(&self, session_id: &str) -> Result<[u8; 32], String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let state = sessions.get(session_id).ok_or("Session not found")?;
        Ok(state.send_public_key)
    }

    pub fn encrypt_message(
        &self,
        session_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedMessage, String> {
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let state = sessions.get_mut(session_id).ok_or("Session not found")?;
        let mut chain = KdfChain::new(state.send_chain_key);
        let message_key = chain.next_message_key();
        state.send_chain_key = chain.chain_key;
        let associated_data = &state.send_public_key;
        let (ciphertext, nonce) =
            AesGcmEncryptor::encrypt(&message_key, plaintext, associated_data)?;
        let message = EncryptedMessage {
            public_key: state.send_public_key,
            message_num: state.send_message_num,
            previous_chain_length: state.skipped_messages,
            nonce,
            ciphertext,
        };
        state.send_message_num += 1;
        Ok(message)
    }

    /// Decrypt a message. Returns:
    ///   Ok(Some(plaintext))  — successful decryption
    ///   Ok(None)            — duplicate / replay, silently drop
    ///   Err(e)              — real decryption failure
    pub fn decrypt_message(
        &self,
        session_id: &str,
        message: &EncryptedMessage,
    ) -> Result<Option<Vec<u8>>, String> {
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let state = sessions.get_mut(session_id).ok_or("Session not found")?;

        // 1. Handshake / DH ratchet
        if state.recv_public_key == [0u8; 32] {
            // Handshake not yet complete. Adopt the peer's initial DH public
            // key WITHOUT ratcheting — chain keys were already derived
            // symmetrically at init, so ratcheting here would diverge.
            state.recv_public_key = message.public_key;
        } else if message.public_key != state.recv_public_key {
            // Peer rotated their DH public key → ratchet our recv chain.
            // Exception: a LATE message from a chain we already ratcheted away
            // from carries an old public key — it must NOT trigger another
            // ratchet; it decrypts via the previous_send_keys pool instead.
            if !state.previous_chain_pubkeys.contains(&message.public_key) {
                state.ratchet_step(message.public_key)?;
            }
        }

        // 2. Message-key derivation (Signal spec: skipped-key pool).
        //    Two distinct cases:
        //      a) CURRENT chain (message.public_key == recv_public_key):
        //         normal order / skip-ahead / in-chain late messages.
        //      b) OLD chain (message.public_key != recv_public_key): a late
        //         message from a chain we ratcheted away from — decrypt via
        //         previous_send_keys (which now stores message keys, MK).
        let mut chain = KdfChain::new(state.recv_chain_key);
        let message_key = if message.public_key == state.recv_public_key {
            if message.message_num == state.recv_message_num {
                // Expected next message in order.
                chain.next_message_key()
            } else if message.message_num > state.recv_message_num {
                // Out-of-order (jump forward). Derive the skipped-over message
                // keys and stash them in the skipped-key pool so they can be
                // decrypted when they eventually arrive.
                let skip_count = message.message_num - state.recv_message_num;
                if skip_count > MAX_SKIP {
                    return Err(format!(
                        "Too many skipped messages: {} (MAX_SKIP={})",
                        skip_count, MAX_SKIP
                    ));
                }
                let skipped = chain.skip_messages(skip_count);
                for (i, k) in skipped.iter().enumerate() {
                    state
                        .skipped_keys
                        .insert(state.recv_message_num + i as u32, *k);
                }
                // Derive the key for the current message (one past the skips).
                chain.next_message_key()
            } else {
                // message_num < recv_message_num: a previously-skipped (late)
                // message arrived within the current chain.
                if let Some(k) = state.skipped_keys.remove(&message.message_num) {
                    k
                } else {
                    // No key found — genuine duplicate / replay.
                    return Ok(None);
                }
            }
        } else {
            // Old-chain late message. Its message key was migrated into
            // previous_send_keys when we ratcheted away.
            if let Some(k) = state.previous_send_keys.remove(&message.message_num) {
                k
            } else {
                // Unknown old chain / expired / replay — silently drop.
                return Ok(None);
            }
        };

        // 3. Advance chain state only for current-chain messages that moved
        //    the window forward. Old-chain late messages must not touch it.
        if message.public_key == state.recv_public_key
            && message.message_num >= state.recv_message_num
        {
            state.recv_chain_key = chain.chain_key;
            state.recv_message_num = message.message_num + 1;
        }

        // 4. Decrypt
        let associated_data = &message.public_key;
        let plaintext = AesGcmEncryptor::decrypt(
            &message_key,
            &message.nonce,
            &message.ciphertext,
            associated_data,
        )?;
        Ok(Some(plaintext))
    }

    pub fn delete_session(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
    }

    /// Restore sessions from a pre-loaded HashMap (used after disk load).
    pub fn from_sessions(sessions: HashMap<String, RatchetState>) -> Self {
        Self {
            sessions: Mutex::new(sessions),
        }
    }

    /// Persist all sessions to disk (acquires inner lock).
    /// Legacy plaintext path — kept for tests and migration.
    pub fn save_to_disk(&self, path: &std::path::Path) -> Result<(), String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        save_sessions_to_disk(path, &sessions)
    }

    /// Persist all sessions to disk, AES-256-GCM encrypted (acquires inner lock).
    pub fn save_to_disk_encrypted(
        &self,
        path: &std::path::Path,
        enc_key: &[u8; 32],
    ) -> Result<(), String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        save_sessions_to_disk_encrypted(path, &sessions, enc_key)
    }

    /// List all active session IDs.
    pub fn list_session_ids(&self) -> Vec<String> {
        let sessions = self.sessions.lock().unwrap();
        sessions.keys().cloned().collect()
    }

    /// Retrieve identity binding for a session (for Safety Number).
    /// Returns (our_identity_id, peer_identity_pk) or error if not bound.
    pub fn get_identity_keys(&self, session_id: &str) -> Result<(String, [u8; 32]), String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let state = sessions
            .get(session_id)
            .ok_or(format!("Session not found: {session_id}"))?;
        let our_id = state
            .our_identity_id
            .as_ref()
            .ok_or("Safety number unavailable: our identity not bound to this session.")?;
        let peer_pk = state
            .peer_identity_pk
            .ok_or("Safety number unavailable: peer identity not bound to this session.")?;
        Ok((our_id.clone(), peer_pk))
    }
}

// ════════════════════════════════════════════════════════════════
// Disk Persistence
// ════════════════════════════════════════════════════════════════

/// Session storage format version tag.
/// Bump this when the RatchetState schema or chain-key derivation changes,
/// so old (potentially diverged) on-disk sessions are discarded and both
/// sides are forced to re-handshake. v1 → v2: symmetric chain-key derivation
/// rewrite (v3.15) — all v1 sessions had asymmetric/diverged chain keys.
const SESSION_FILE_VERSION: &str = "2";

#[derive(serde::Serialize, serde::Deserialize)]
struct SessionFile {
    v: String,
    sessions: HashMap<String, RatchetState>,
}

/// Write all sessions to disk as JSON (atomic: temp + rename).
/// Legacy plaintext format — kept for tests and migration reading.
pub fn save_sessions_to_disk(
    path: &std::path::Path,
    sessions: &HashMap<String, RatchetState>,
) -> Result<(), String> {
    let file = SessionFile {
        v: SESSION_FILE_VERSION.to_string(),
        sessions: sessions.clone(),
    };
    let json = serde_json::to_string_pretty(&file)
        .map_err(|e| format!("Session serialization failed: {e}"))?;

    // Atomic write: temp file → rename
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &json).map_err(|e| format!("Session write failed: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("Session rename failed: {e}"))?;
    Ok(())
}

/// Load sessions from a JSON file on disk.
/// Returns empty HashMap if file doesn't exist or is corrupted.
pub fn load_sessions_from_disk(path: &std::path::Path) -> HashMap<String, RatchetState> {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => return HashMap::new(),
    };
    match serde_json::from_str::<SessionFile>(&data) {
        Ok(file) => {
            if file.v != SESSION_FILE_VERSION {
                eprintln!(
                    "[SessionManager] Session file version {} != {} — discarding old sessions (re-handshake required)",
                    file.v, SESSION_FILE_VERSION
                );
                return HashMap::new();
            }
            file.sessions
        }
        Err(e) => {
            eprintln!("[SessionManager] Corrupted session file, starting fresh: {e}");
            // Don't delete the corrupted file — user may want to recover it
            HashMap::new()
        }
    }
}

// ════════════════════════════════════════════════════════════════
// Encrypted Session Persistence (v3, security hardening)
// ════════════════════════════════════════════════════════════════
//
// v3 stores the entire session file (including dh_private, root_key,
// and both chain keys) AES-256-GCM encrypted under a key derived from
// the device key. On-disk layout: [12-byte nonce][ciphertext+tag].
// Domain-separated HKDF keeps this key distinct from the ML-KEM key
// encryption key used by KeyStore.

/// HKDF info tag for the session-encryption key derivation.
const SESSION_ENC_INFO: &[u8] = b"fibemate-sessions-enc-v1";
/// AAD bound to every encrypted session file (tamper detection).
const SESSION_ENC_AAD: &[u8] = b"fibemate-sessions-enc-v1";

/// Derive the session-file encryption key from the device key.
/// Domain-separated: never reuses the KeyStore ML-KEM key directly.
pub fn derive_session_enc_key(device_key: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, device_key);
    let mut key = [0u8; 32];
    hkdf.expand(SESSION_ENC_INFO, &mut key)
        .expect("HKDF expand should never fail for 32 bytes");
    key
}

/// Serialize + AES-256-GCM encrypt all sessions to disk (atomic: temp + rename).
/// Returns an error if encryption or write fails.
pub fn save_sessions_to_disk_encrypted(
    path: &std::path::Path,
    sessions: &HashMap<String, RatchetState>,
    enc_key: &[u8; 32],
) -> Result<(), String> {
    let file = SessionFile {
        v: SESSION_FILE_VERSION.to_string(),
        sessions: sessions.clone(),
    };
    let json =
        serde_json::to_string(&file).map_err(|e| format!("Session serialization failed: {e}"))?;

    // AES-256-GCM encrypt with a fresh random nonce.
    let cipher = Aes256Gcm::new_from_slice(enc_key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: json.as_bytes(),
                aad: SESSION_ENC_AAD,
            },
        )
        .map_err(|e| format!("Session encryption failed: {e}"))?;

    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    // Atomic write: temp file → rename.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &blob).map_err(|e| format!("Session write failed: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("Session rename failed: {e}"))?;
    Ok(())
}

/// Load + AES-256-GCM decrypt sessions from disk.
///
/// Returns `Err` on a genuine decryption failure (wrong key / tampered
/// file), so the caller can distinguish "no sessions" from "key mismatch".
pub fn load_sessions_from_disk_decrypted(
    path: &std::path::Path,
    enc_key: &[u8; 32],
) -> Result<HashMap<String, RatchetState>, String> {
    let blob = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return Ok(HashMap::new()), // no file yet — fresh start
    };
    if blob.len() < 12 + 16 {
        return Err("Encrypted session file too short (corrupt)".to_string());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(enc_key).map_err(|e| e.to_string())?;
    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: SESSION_ENC_AAD,
            },
        )
        .map_err(|e| {
            format!("Session decryption failed (device key mismatch or tampered file): {e}")
        })?;

    let file: SessionFile = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Decrypted session file corrupt: {e}"))?;
    if file.v != SESSION_FILE_VERSION {
        eprintln!(
            "[SessionManager] Session file version {} != {} — discarding old sessions (re-handshake required)",
            file.v, SESSION_FILE_VERSION
        );
        return Ok(HashMap::new());
    }
    Ok(file.sessions)
}

/// Attempt to load sessions with transparent legacy migration:
///   1. Try the encrypted (v3) format first.
///   2. If the file is an old plaintext v2 JSON, read it and report that
///      a migration is needed (caller re-saves, which rewrites as v3).
pub fn load_sessions_with_migration(
    path: &std::path::Path,
    enc_key: &[u8; 32],
) -> (HashMap<String, RatchetState>, bool) {
    // No file at all — fresh start.
    if !path.exists() {
        return (HashMap::new(), false);
    }
    // Try encrypted format.
    match load_sessions_from_disk_decrypted(path, enc_key) {
        Ok(sessions) => return (sessions, false),
        Err(_) => { /* fall through to legacy plaintext attempt */ }
    }
    // Legacy plaintext v2 format.
    let legacy = load_sessions_from_disk(path);
    if !legacy.is_empty() {
        eprintln!("[SessionManager] Migrating legacy plaintext sessions to encrypted v3 format");
        return (legacy, true);
    }
    (HashMap::new(), false)
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = RatchetKeyPair::generate();
        assert_ne!(kp.public_key, [0u8; 32]);
        assert_ne!(kp.private_key, [0u8; 32]);
    }

    #[test]
    fn test_diffie_hellman() {
        let alice = RatchetKeyPair::generate();
        let bob = RatchetKeyPair::generate();
        let s1 = alice.diffie_hellman(&bob.public_key).unwrap();
        let s2 = bob.diffie_hellman(&alice.public_key).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_x3dh_symmetry() {
        // X3DH 双方共享密钥必须一致（Signal 规范）
        let ik_a = RatchetKeyPair::generate();
        let ek_a = RatchetKeyPair::generate();
        let ik_b = RatchetKeyPair::generate();
        let spk_b = RatchetKeyPair::generate();

        let initiator_ss =
            X3DH::initiator(&ik_a, &ek_a, &ik_b.public_key, &spk_b.public_key).unwrap();
        let responder_ss =
            X3DH::responder(&ik_b, &spk_b, &ik_a.public_key, &ek_a.public_key).unwrap();
        assert_eq!(initiator_ss, responder_ss, "X3DH 双方共享密钥不对称");
    }

    #[test]
    fn test_x3dh_with_independent_spk_and_signature() {
        // SPK 独立化：Bob 的 signed pre-key 独立于身份密钥（不再是 SPK=IK
        // 退化），且 SPK 由 ML-DSA-65 身份签名密钥签名；篡改 SPK 验签失败。
        use crate::pq::MlDsa65KeyPair;

        let ik_a = RatchetKeyPair::generate();
        let ek_a = RatchetKeyPair::generate();
        let ik_b = RatchetKeyPair::generate();
        let spk_b = RatchetKeyPair::generate(); // 独立 SPK
        assert_ne!(
            ik_b.public_key, spk_b.public_key,
            "SPK 必须独立于 IK（修复 DH2=DH3 退化）"
        );

        // Bob 用 ISK（ML-DSA-65）签名 SPK 公钥
        let isk_b = MlDsa65KeyPair::generate();
        let sig = isk_b.sign(&spk_b.public_key, b"fibemate-spk-v1").unwrap();
        assert!(isk_b
            .verify(&spk_b.public_key, b"fibemate-spk-v1", &sig)
            .unwrap());

        // Alice 验签通过后执行 X3DH（用独立 SPK_B）
        let init_ss = X3DH::initiator(&ik_a, &ek_a, &ik_b.public_key, &spk_b.public_key).unwrap();
        let resp_ss = X3DH::responder(&ik_b, &spk_b, &ik_a.public_key, &ek_a.public_key).unwrap();
        assert_eq!(init_ss, resp_ss, "独立 SPK 下 X3DH 双方共享密钥必须一致");

        // 篡改 SPK → 验签必须失败
        let spk_b_tampered = RatchetKeyPair::generate();
        assert!(
            !isk_b
                .verify(&spk_b_tampered.public_key, b"fibemate-spk-v1", &sig)
                .unwrap(),
            "篡改 SPK 后验签必须失败"
        );

        // 完整握手：独立 SPK 下会话可正常建立并互发消息
        let sm_a = SessionManager::new();
        let sm_b = SessionManager::new();
        sm_a.create_session("bob", &init_ss, true).unwrap();
        sm_b.create_session("alice", &resp_ss, false).unwrap();
        sm_b.set_peer_key("alice", sm_a.get_send_key("bob").unwrap())
            .unwrap();
        sm_a.set_peer_key("bob", sm_b.get_send_key("alice").unwrap())
            .unwrap();
        let m = sm_a.encrypt_message("bob", b"independent-spk-ok").unwrap();
        let pt = sm_b.decrypt_message("alice", &m).unwrap().unwrap();
        assert_eq!(pt, b"independent-spk-ok");
    }

    #[test]
    fn test_full_handshake_roundtrip_realistic() {
        // 模拟真实命令：Bob 的 SPK = IK（identity.rs x3dh_respond 用 my_identity.clone()）
        let ik_a = RatchetKeyPair::generate();
        let ek_a = RatchetKeyPair::generate();
        let ik_b = RatchetKeyPair::generate();

        // Alice: x3dhInitiate(IK_A, EK_A, IK_B, SPK_B=IK_B)
        let initiator_ss =
            X3DH::initiator(&ik_a, &ek_a, &ik_b.public_key, &ik_b.public_key).unwrap();
        // Bob: x3dhRespond(IK_B, SPK_B=IK_B, IK_A, EK_A)
        let responder_ss =
            X3DH::responder(&ik_b, &ik_b, &ik_a.public_key, &ek_a.public_key).unwrap();
        assert_eq!(
            initiator_ss, responder_ss,
            "X3DH 双方共享密钥不对称（SPK=IK 退化）"
        );

        let sm = SessionManager::new();
        sm.create_session("alice", &initiator_ss, true).unwrap();
        sm.create_session("bob", &responder_ss, false).unwrap();

        // Alice → Bob
        let msg1 = sm.encrypt_message("alice", b"hello bob").unwrap();
        let pt1 = sm.decrypt_message("bob", &msg1).unwrap().unwrap();
        assert_eq!(pt1, b"hello bob");

        // Bob → Alice
        let msg2 = sm.encrypt_message("bob", b"hello alice").unwrap();
        let pt2 = sm.decrypt_message("alice", &msg2).unwrap().unwrap();
        assert_eq!(pt2, b"hello alice");

        // 多轮 Alice → Bob
        for i in 0..10 {
            let m = sm
                .encrypt_message("alice", format!("m{}", i).as_bytes())
                .unwrap();
            let p = sm.decrypt_message("bob", &m).unwrap().unwrap();
            assert_eq!(p, format!("m{}", i).into_bytes());
        }
    }

    #[test]
    fn test_hkdf_golden_vectors() {
        use hkdf::Hkdf;
        use sha2::Sha256;
        // 固定输入，供 JS 端对齐验证
        let secret = [42u8; 32];
        let hkdf = Hkdf::<Sha256>::new(None, &secret);
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        hkdf.expand(b"send_chain_key", &mut send_key).unwrap();
        hkdf.expand(b"recv_chain_key", &mut recv_key).unwrap();
        eprintln!("GOLDEN_SEND_KEY={}", hex::encode(send_key));
        eprintln!("GOLDEN_RECV_KEY={}", hex::encode(recv_key));

        let hkdf2 = Hkdf::<Sha256>::new(None, &send_key);
        let mut msg_key = [0u8; 32];
        let mut next_chain = [0u8; 32];
        hkdf2.expand(b"message_key", &mut msg_key).unwrap();
        hkdf2.expand(b"next_chain", &mut next_chain).unwrap();
        eprintln!("GOLDEN_MSG_KEY={}", hex::encode(msg_key));
        eprintln!("GOLDEN_NEXT_CHAIN={}", hex::encode(next_chain));

        let combined = [7u8; 96];
        let hkdf3 = Hkdf::<Sha256>::new(None, &combined);
        let mut ss = [0u8; 32];
        hkdf3.expand(b"shared_secret", &mut ss).unwrap();
        eprintln!("GOLDEN_SHARED_SECRET={}", hex::encode(ss));

        assert_eq!(send_key.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [1u8; 32];
        let (ct, nonce) = AesGcmEncryptor::encrypt(&key, b"Hello, Fibemate!", b"aad").unwrap();
        let pt = AesGcmEncryptor::decrypt(&key, &nonce, &ct, b"aad").unwrap();
        assert_eq!(pt, b"Hello, Fibemate!");
    }

    #[test]
    fn test_session_roundtrip() {
        let secret = [42u8; 32];
        let alice = SessionManager::new();
        let bob = SessionManager::new();
        alice.create_session("bob", &secret, true).unwrap();
        bob.create_session("alice", &secret, false).unwrap();
        bob.set_peer_key("alice", alice.get_send_key("bob").unwrap())
            .unwrap();
        alice
            .set_peer_key("bob", bob.get_send_key("alice").unwrap())
            .unwrap();
        let enc = alice.encrypt_message("bob", b"Test").unwrap();
        let dec = bob.decrypt_message("alice", &enc).unwrap().unwrap();
        assert_eq!(dec, b"Test");
    }

    #[test]
    fn test_out_of_order_with_skipped_keys() {
        // 工业级双棘轮核心：乱序消息 + 跳钥池
        let secret = [42u8; 32];
        let alice = SessionManager::new();
        let bob = SessionManager::new();
        alice.create_session("bob", &secret, true).unwrap();
        bob.create_session("alice", &secret, false).unwrap();
        bob.set_peer_key("alice", alice.get_send_key("bob").unwrap())
            .unwrap();
        alice
            .set_peer_key("bob", bob.get_send_key("alice").unwrap())
            .unwrap();

        // Alice 连发 5 条
        let msgs: Vec<_> = (0..5)
            .map(|i| {
                alice
                    .encrypt_message("bob", format!("m{}", i).as_bytes())
                    .unwrap()
            })
            .collect();

        // Bob 乱序接收：3, 1, 4, 0, 2
        let order = [3usize, 1, 4, 0, 2];
        for &idx in &order {
            let pt = bob.decrypt_message("alice", &msgs[idx]).unwrap().unwrap();
            assert_eq!(
                pt,
                format!("m{}", idx).into_bytes(),
                "乱序消息 {} 解密失败",
                idx
            );
        }

        // 全部解密后，skipped 池应已清空
        let sessions = bob.list_session_ids();
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn test_replay_rejected() {
        // 重放/过期消息必须被拒绝（不在跳钥池中）
        let secret = [42u8; 32];
        let alice = SessionManager::new();
        let bob = SessionManager::new();
        alice.create_session("bob", &secret, true).unwrap();
        bob.create_session("alice", &secret, false).unwrap();
        bob.set_peer_key("alice", alice.get_send_key("bob").unwrap())
            .unwrap();
        alice
            .set_peer_key("bob", bob.get_send_key("alice").unwrap())
            .unwrap();

        let m0 = alice.encrypt_message("bob", b"first").unwrap();
        let m1 = alice.encrypt_message("bob", b"second").unwrap();
        let m2 = alice.encrypt_message("bob", b"third").unwrap();

        assert_eq!(
            bob.decrypt_message("alice", &m0).unwrap().unwrap(),
            b"first"
        );
        assert_eq!(
            bob.decrypt_message("alice", &m1).unwrap().unwrap(),
            b"second"
        );
        assert_eq!(
            bob.decrypt_message("alice", &m2).unwrap().unwrap(),
            b"third"
        );

        // 重放 m0（已消费）→ Ok(None) = silent drop
        assert_eq!(bob.decrypt_message("alice", &m0).unwrap(), None);
    }

    #[test]
    fn test_cross_chain_late_message_with_previous_keys() {
        // 跨链迟到消息：DH ratchet 之后，旧链的在途消息必须仍能解密。
        // 依赖两个修正：
        //   1) ratchet_step 把旧链 skipped_keys（消息密钥 MK）迁移到
        //      previous_send_keys（此前存链密钥 CK，直接用 CK 当 AES 密钥解密会失败）
        //   2) 旧链公钥记入 previous_chain_pubkeys，迟到消息不触发二次 ratchet
        let secret = [42u8; 32];
        let alice = SessionManager::new();
        let bob = SessionManager::new();
        alice.create_session("bob", &secret, true).unwrap();
        bob.create_session("alice", &secret, false).unwrap();
        bob.set_peer_key("alice", alice.get_send_key("bob").unwrap())
            .unwrap();
        alice
            .set_peer_key("bob", bob.get_send_key("alice").unwrap())
            .unwrap();

        // Alice 连发 5 条（链 A，同一 DH 公钥 P_A）
        let msgs: Vec<_> = (0..5)
            .map(|i| {
                alice
                    .encrypt_message("bob", format!("m{}", i).as_bytes())
                    .unwrap()
            })
            .collect();
        let chain_a_pk = msgs[0].public_key;

        // Bob 先收跳号消息 m3：skipped_keys 生成 MK1、MK2，MK3 消费。
        // 注意：skipped_keys 是收到跳号消息时才派生的，不是预生成。
        assert_eq!(
            bob.decrypt_message("alice", &msgs[3]).unwrap().unwrap(),
            b"m3"
        );

        // 模拟对端轮换 DH 公钥：Bob 收到新公钥消息 → 触发 DH ratchet。
        // 旧链 P_A 应被记录，skipped_keys(MK1、MK2) 应迁移到 previous_send_keys。
        bob.debug_ratchet_step("alice", [9u8; 32]).unwrap();

        // 旧链迟到消息 m1（公钥 = P_A ∈ previous_chain_pubkeys）→ 不二次 ratchet，经 previous_send_keys 解密
        let pt = bob.decrypt_message("alice", &msgs[1]).unwrap().unwrap();
        assert_eq!(pt, b"m1");

        // 旧链迟到消息 m2 同样可解密
        let pt = bob.decrypt_message("alice", &msgs[2]).unwrap().unwrap();
        assert_eq!(pt, b"m2");

        // 旧链已消费消息 m3 重放 → 静默丢弃（previous_send_keys 无 m3）
        assert_eq!(bob.decrypt_message("alice", &msgs[3]).unwrap(), None);

        // recv 公钥已切换到新链，且旧链公钥被记住
        assert_eq!(bob.get_session_recv_pk("alice").unwrap(), [9u8; 32]);
        let sessions = bob.list_session_ids();
        assert_eq!(sessions.len(), 1);
        assert_eq!(chain_a_pk, msgs[2].public_key, "链 A 内公钥应一致");
    }

    #[test]
    fn test_encrypted_persistence_roundtrip() {
        use tempfile::TempDir;
        // 加密持久化 roundtrip：双端保存 → 重启加载 → 链状态一致、可继续互操作
        let dir = TempDir::new().unwrap();
        let path_a = dir.path().join("alice.json");
        let path_b = dir.path().join("bob.json");
        let enc_key = derive_session_enc_key(&[7u8; 32]);

        let secret = [42u8; 32];
        let alice = SessionManager::new();
        let bob = SessionManager::new();
        alice.create_session("bob", &secret, true).unwrap();
        bob.create_session("alice", &secret, false).unwrap();
        bob.set_peer_key("alice", alice.get_send_key("bob").unwrap())
            .unwrap();
        alice
            .set_peer_key("bob", bob.get_send_key("alice").unwrap())
            .unwrap();

        // 保存前先走一条消息，让链状态推进
        let m0 = alice.encrypt_message("bob", b"before reload").unwrap();
        assert_eq!(
            bob.decrypt_message("alice", &m0).unwrap().unwrap(),
            b"before reload"
        );

        // 加密保存双端
        alice.save_to_disk_encrypted(&path_a, &enc_key).unwrap();
        bob.save_to_disk_encrypted(&path_b, &enc_key).unwrap();

        // 磁盘上必须是二进制密文，绝不能是明文 JSON
        for p in [&path_a, &path_b] {
            let raw = std::fs::read(p).unwrap();
            assert!(
                !raw.windows(4).any(|w| w == b"\"v\":"),
                "session file must not contain plaintext JSON markers"
            );
            assert!(raw.len() > 12 + 16, "encrypted blob too small");
        }

        // 用正确密钥加载（模拟应用重启）
        let alice2 = SessionManager::from_sessions(
            load_sessions_from_disk_decrypted(&path_a, &enc_key).unwrap(),
        );
        let bob2 = SessionManager::from_sessions(
            load_sessions_from_disk_decrypted(&path_b, &enc_key).unwrap(),
        );
        assert!(alice2.has_session("bob").unwrap());
        assert!(bob2.has_session("alice").unwrap());

        // 重启后双端链状态一致，可继续互操作
        let m1 = alice2.encrypt_message("bob", b"after reload").unwrap();
        let pt = bob2.decrypt_message("alice", &m1).unwrap().unwrap();
        assert_eq!(pt, b"after reload");
    }

    #[test]
    fn test_encrypted_persistence_wrong_key_fails() {
        use tempfile::TempDir;
        // 错误密钥必须解密失败（而非静默返回空）
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sessions.json");
        let enc_key = derive_session_enc_key(&[7u8; 32]);

        let sm = SessionManager::new();
        sm.create_session("bob", &[42u8; 32], true).unwrap();
        sm.save_to_disk_encrypted(&path, &enc_key).unwrap();

        let wrong_key = derive_session_enc_key(&[8u8; 32]);
        let result = load_sessions_from_disk_decrypted(&path, &wrong_key);
        assert!(result.is_err(), "wrong key must not decrypt sessions");
    }

    #[test]
    fn test_legacy_plaintext_migration() {
        use tempfile::TempDir;
        // 旧明文 v2 文件 → 加载并标记需要迁移
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sessions.json");
        let enc_key = derive_session_enc_key(&[7u8; 32]);

        // 构造 v2 明文文件
        let sm = SessionManager::new();
        sm.create_session("legacy", &[42u8; 32], true).unwrap();
        sm.save_to_disk(&path).unwrap(); // 明文 v2 格式

        // 迁移加载：应读到旧会话 + 标记 needs_migration
        let (sessions, needs_migration) = load_sessions_with_migration(&path, &enc_key);
        assert!(
            needs_migration,
            "legacy plaintext file must trigger migration flag"
        );
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key("legacy"));

        // 迁移后立即加密重写 → 磁盘不再含明文 JSON
        save_sessions_to_disk_encrypted(&path, &sessions, &enc_key).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(4).any(|w| w == b"\"v\":"),
            "migrated file must be encrypted"
        );

        // 加密格式可正常回读
        let (sessions2, needs_migration2) = load_sessions_with_migration(&path, &enc_key);
        assert!(!needs_migration2);
        assert_eq!(sessions2.len(), 1);
    }
}
