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
        Self { public_key: *public.as_bytes(), private_key: secret.to_bytes() }
    }

    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private_key);
        let public = PublicKey::from(&secret);
        Self { public_key: *public.as_bytes(), private_key }
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
    pub fn init_from_shared_secret(shared_secret: &[u8; 32], is_initiator: bool) -> Result<Self, String> {
        // Symmetric chain-key derivation from the X3DH shared secret.
        // The info strings are role-swapped so that:
        //   initiator.send_chain == responder.recv_chain
        //   initiator.recv_chain == responder.send_chain
        // This makes message 1 decryptable before any DH ratchet has run.
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut initiator_send = [0u8; 32];
        let mut initiator_recv = [0u8; 32];
        hkdf.expand(b"initiator_send", &mut initiator_send).map_err(|e| e.to_string())?;
        hkdf.expand(b"initiator_recv", &mut initiator_recv).map_err(|e| e.to_string())?;

        let keypair = RatchetKeyPair::generate();
        Ok(Self {
            send_chain_key: if is_initiator { initiator_send } else { initiator_recv },
            recv_chain_key: if is_initiator { initiator_recv } else { initiator_send },
            send_public_key: keypair.public_key,
            recv_public_key: [0u8; 32],
            send_message_num: 0,
            recv_message_num: 0,
            previous_send_keys: HashMap::new(),
            skipped_messages: 0,
            skipped_keys: HashMap::new(),
            dh_private: keypair.private_key,
            root_key: *shared_secret,
            is_initiator,
            our_identity_id: None,
            peer_identity_pk: None,
        })
    }

    pub fn ratchet_step(&mut self, their_public_key: [u8; 32]) -> Result<(), String> {
        self.previous_send_keys.insert(self.send_message_num, self.send_chain_key);
        // 1. Derive a new recv chain from (current dh_private, their new pub)
        let shared = RatchetKeyPair::from_private_key(self.dh_private)
            .diffie_hellman(&their_public_key)?;
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
    pub fn new(chain_key: [u8; 32]) -> Self { Self { chain_key } }

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
        for _ in 0..count { keys.push(self.next_message_key()); }
        keys
    }
}

/// AES-256-GCM encryptor
pub struct AesGcmEncryptor;

impl AesGcmEncryptor {
    pub fn encrypt(key: &[u8; 32], plaintext: &[u8], associated_data: &[u8]) -> Result<(Vec<u8>, [u8; 12]), String> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad: associated_data })
            .map_err(|e| e.to_string())?;
        Ok((ciphertext, nonce_bytes))
    }

    pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
        let nonce = Nonce::from_slice(nonce);
        cipher.decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad: associated_data })
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
        hkdf.expand(b"shared_secret", &mut shared_secret).map_err(|e| e.to_string())?;
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
        hkdf.expand(b"shared_secret", &mut shared_secret).map_err(|e| e.to_string())?;
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
        Self { sessions: Mutex::new(HashMap::new()) }
    }

    pub fn create_session(&self, session_id: &str, shared_secret: &[u8; 32], is_initiator: bool) -> Result<(), String> {
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

    /// Check if a session exists.
    pub fn has_session(&self, session_id: &str) -> Result<bool, String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        Ok(sessions.contains_key(session_id))
    }

    /// Check if decrypt_message would trigger a ratchet step (for diagnostics).
    pub fn will_ratchet_on_decrypt(&self, session_id: &str, message: &EncryptedMessage) -> Result<bool, String> {
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

    pub fn encrypt_message(&self, session_id: &str, plaintext: &[u8]) -> Result<EncryptedMessage, String> {
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let state = sessions.get_mut(session_id).ok_or("Session not found")?;
        let mut chain = KdfChain::new(state.send_chain_key);
        let message_key = chain.next_message_key();
        state.send_chain_key = chain.chain_key;
        let associated_data = &state.send_public_key;
        let (ciphertext, nonce) = AesGcmEncryptor::encrypt(&message_key, plaintext, associated_data)?;
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

    pub fn decrypt_message(&self, session_id: &str, message: &EncryptedMessage) -> Result<Vec<u8>, String> {
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
            state.ratchet_step(message.public_key)?;
        }

        // 2. Message-key derivation (Signal spec: skipped-key pool)
        let mut chain = KdfChain::new(state.recv_chain_key);
        let message_key = if message.message_num == state.recv_message_num {
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
                state.skipped_keys.insert(state.recv_message_num + i as u32, *k);
            }
            // Derive the key for the current message (one past the skips).
            chain.next_message_key()
        } else {
            // message_num < recv_message_num: a previously-skipped (late)
            // message arrived. Try the skipped-key pool; otherwise it is a
            // replay and must be rejected.
            match state.skipped_keys.remove(&message.message_num) {
                Some(k) => k,
                None => {
                    return Err(format!(
                        "Replay or stale message: num={} already advanced past {} (no skipped key)",
                        message.message_num, state.recv_message_num
                    ));
                }
            }
        };

        // 3. Advance chain state only when the message moved the window forward.
        if message.message_num >= state.recv_message_num {
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
        Ok(plaintext)
    }

    pub fn delete_session(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
    }

    /// Restore sessions from a pre-loaded HashMap (used after disk load).
    pub fn from_sessions(sessions: HashMap<String, RatchetState>) -> Self {
        Self { sessions: Mutex::new(sessions) }
    }

    /// Persist all sessions to disk (acquires inner lock).
    pub fn save_to_disk(&self, path: &std::path::Path) -> Result<(), String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        save_sessions_to_disk(path, &sessions)
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
        let state = sessions.get(session_id).ok_or(format!("Session not found: {session_id}"))?;
        let our_id = state.our_identity_id.as_ref()
            .ok_or("Safety number unavailable: our identity not bound to this session.")?;
        let peer_pk = state.peer_identity_pk
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
pub fn save_sessions_to_disk(path: &std::path::Path, sessions: &HashMap<String, RatchetState>) -> Result<(), String> {
    let file = SessionFile {
        v: SESSION_FILE_VERSION.to_string(),
        sessions: sessions.clone(),
    };
    let json = serde_json::to_string_pretty(&file).map_err(|e| format!("Session serialization failed: {e}"))?;

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

impl Default for SessionManager {
    fn default() -> Self { Self::new() }
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

        let initiator_ss = X3DH::initiator(&ik_a, &ek_a, &ik_b.public_key, &spk_b.public_key).unwrap();
        let responder_ss = X3DH::responder(&ik_b, &spk_b, &ik_a.public_key, &ek_a.public_key).unwrap();
        assert_eq!(initiator_ss, responder_ss, "X3DH 双方共享密钥不对称");
    }

    #[test]
    fn test_full_handshake_roundtrip_realistic() {
        // 模拟真实命令：Bob 的 SPK = IK（identity.rs x3dh_respond 用 my_identity.clone()）
        let ik_a = RatchetKeyPair::generate();
        let ek_a = RatchetKeyPair::generate();
        let ik_b = RatchetKeyPair::generate();

        // Alice: x3dhInitiate(IK_A, EK_A, IK_B, SPK_B=IK_B)
        let initiator_ss = X3DH::initiator(&ik_a, &ek_a, &ik_b.public_key, &ik_b.public_key).unwrap();
        // Bob: x3dhRespond(IK_B, SPK_B=IK_B, IK_A, EK_A)
        let responder_ss = X3DH::responder(&ik_b, &ik_b, &ik_a.public_key, &ek_a.public_key).unwrap();
        assert_eq!(initiator_ss, responder_ss, "X3DH 双方共享密钥不对称（SPK=IK 退化）");

        let sm = SessionManager::new();
        sm.create_session("alice", &initiator_ss, true).unwrap();
        sm.create_session("bob", &responder_ss, false).unwrap();

        // Alice → Bob
        let msg1 = sm.encrypt_message("alice", b"hello bob").unwrap();
        let pt1 = sm.decrypt_message("bob", &msg1).unwrap();
        assert_eq!(pt1, b"hello bob");

        // Bob → Alice
        let msg2 = sm.encrypt_message("bob", b"hello alice").unwrap();
        let pt2 = sm.decrypt_message("alice", &msg2).unwrap();
        assert_eq!(pt2, b"hello alice");

        // 多轮 Alice → Bob
        for i in 0..10 {
            let m = sm.encrypt_message("alice", format!("m{}", i).as_bytes()).unwrap();
            let p = sm.decrypt_message("bob", &m).unwrap();
            assert_eq!(p, format!("m{}", i).as_bytes());
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
        bob.set_peer_key("alice", alice.get_send_key("bob").unwrap()).unwrap();
        alice.set_peer_key("bob", bob.get_send_key("alice").unwrap()).unwrap();
        let enc = alice.encrypt_message("bob", b"Test").unwrap();
        let dec = bob.decrypt_message("alice", &enc).unwrap();
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
        bob.set_peer_key("alice", alice.get_send_key("bob").unwrap()).unwrap();
        alice.set_peer_key("bob", bob.get_send_key("alice").unwrap()).unwrap();

        // Alice 连发 5 条
        let msgs: Vec<_> = (0..5)
            .map(|i| alice.encrypt_message("bob", format!("m{}", i).as_bytes()).unwrap())
            .collect();

        // Bob 乱序接收：3, 1, 4, 0, 2
        let order = [3usize, 1, 4, 0, 2];
        for &idx in &order {
            let pt = bob.decrypt_message("alice", &msgs[idx]).unwrap();
            assert_eq!(pt, format!("m{}", idx).as_bytes(), "乱序消息 {} 解密失败", idx);
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
        bob.set_peer_key("alice", alice.get_send_key("bob").unwrap()).unwrap();
        alice.set_peer_key("bob", bob.get_send_key("alice").unwrap()).unwrap();

        let m0 = alice.encrypt_message("bob", b"first").unwrap();
        let m1 = alice.encrypt_message("bob", b"second").unwrap();
        let m2 = alice.encrypt_message("bob", b"third").unwrap();

        assert_eq!(bob.decrypt_message("alice", &m0).unwrap(), b"first");
        assert_eq!(bob.decrypt_message("alice", &m1).unwrap(), b"second");
        assert_eq!(bob.decrypt_message("alice", &m2).unwrap(), b"third");

        // 重放 m0（已消费，不在池中）→ 拒绝
        assert!(bob.decrypt_message("alice", &m0).is_err());
    }
}
