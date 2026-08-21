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
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        hkdf.expand(b"send_chain_key", &mut send_key).map_err(|e| e.to_string())?;
        hkdf.expand(b"recv_chain_key", &mut recv_key).map_err(|e| e.to_string())?;
        let keypair = RatchetKeyPair::generate();
        Ok(Self {
            send_chain_key: if is_initiator { send_key } else { recv_key },
            recv_chain_key: if is_initiator { recv_key } else { send_key },
            send_public_key: keypair.public_key,
            recv_public_key: [0u8; 32],
            send_message_num: 0,
            recv_message_num: 0,
            previous_send_keys: HashMap::new(),
            skipped_messages: 0,
            our_identity_id: None,
            peer_identity_pk: None,
        })
    }

    pub fn ratchet_step(&mut self, their_public_key: [u8; 32]) -> Result<(), String> {
        self.previous_send_keys.insert(self.send_message_num, self.send_chain_key);
        let new_keypair = RatchetKeyPair::generate();
        let shared = new_keypair.diffie_hellman(&their_public_key)?;
        let hkdf = Hkdf::<Sha256>::new(None, &shared);
        hkdf.expand(b"chain_key", &mut self.send_chain_key).map_err(|e| e.to_string())?;
        hkdf.expand(b"next_chain", &mut self.recv_chain_key).map_err(|e| e.to_string())?;
        self.send_public_key = new_keypair.public_key;
        self.recv_public_key = their_public_key;
        self.send_message_num = 0;
        self.skipped_messages = 0;
        Ok(())
    }
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
        let dh1 = my_identity.diffie_hellman(their_identity)?;
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

    pub fn set_peer_key(&self, session_id: &str, peer_public_key: [u8; 32]) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let state = sessions.get_mut(session_id).ok_or("Session not found")?;
        state.recv_public_key = peer_public_key;
        Ok(())
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
        if message.public_key != state.recv_public_key {
            state.ratchet_step(message.public_key)?;
        }
        let mut chain = KdfChain::new(state.recv_chain_key);
        if message.message_num > state.recv_message_num {
            let skip_count = message.message_num - state.recv_message_num;
            let _ = chain.skip_messages(skip_count);
            state.skipped_messages += skip_count;
        }
        let message_key = chain.next_message_key();
        state.recv_chain_key = chain.chain_key;
        let associated_data = &message.public_key;
        let plaintext = AesGcmEncryptor::decrypt(&message_key, &message.nonce, &message.ciphertext, associated_data)?;
        state.recv_message_num = message.message_num + 1;
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
const SESSION_FILE_VERSION: &str = "1";

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
        Ok(file) => file.sessions,
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
}
