//! FIBEMATE Tauri Commands — Module root
//!
//! Crypto state shared across all commands.
//! Secret keys, shared secrets, and session state live here —
//! the frontend NEVER touches key material.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::double_ratchet::SessionManager;
use crate::key_store::KeyStore;

pub mod audit_cmd;
pub mod identity;
pub mod kem;
pub mod ratchet;
pub mod safety_number;
pub mod sm2_cmd;

#[cfg(test)]
mod ipc_tests;

/// Global cryptographic state managed by Tauri.
///
/// All secret material stays in Rust memory (or encrypted on disk via KeyStore).
/// The frontend only receives opaque identifiers (key_id, ss_id, session_id).
pub struct CryptoState {
    /// Encrypted key storage (device-key AES-256-GCM)
    pub key_store: Mutex<KeyStore>,
    /// Pending shared secrets, indexed by ss_id
    /// (consumed by dr_init, then removed)
    pub shared_secrets: Mutex<HashMap<String, [u8; 32]>>,
    /// Active Double Ratchet sessions
    pub sessions: Mutex<SessionManager>,
    /// Path to sessions.json for persistence
    pub sessions_path: PathBuf,
    /// Domain-separated key for encrypting sessions.json at rest
    /// (derived from the device key via HKDF — never exposed to JS).
    session_enc_key: [u8; 32],
}

impl CryptoState {
    /// Initialize with an app data directory for encrypted key storage.
    /// Loads persisted DR sessions from disk if available.
    pub fn new(app_data: PathBuf) -> Result<Self, String> {
        crate::audit::init(&app_data);
        let key_store = KeyStore::new(&app_data)?;
        let sessions_path = app_data.join("sessions.json");

        // Derive the session-file encryption key from the device key
        // (domain-separated from the ML-KEM key-encryption key).
        let session_enc_key = crate::double_ratchet::derive_session_enc_key(key_store.device_key());

        // Restore persisted sessions from disk, transparently migrating
        // legacy plaintext v2 files to the encrypted v3 format.
        let (sessions, migrated) = {
            let (loaded, needs_migration) = crate::double_ratchet::load_sessions_with_migration(
                &sessions_path,
                &session_enc_key,
            );
            if loaded.is_empty() {
                println!("[CryptoState] No persisted sessions found — starting fresh.");
            } else {
                println!(
                    "[CryptoState] Restored {} persisted session(s) from disk.",
                    loaded.len()
                );
            }
            (SessionManager::from_sessions(loaded), needs_migration)
        };

        let state = Self {
            key_store: Mutex::new(key_store),
            shared_secrets: Mutex::new(HashMap::new()),
            sessions: Mutex::new(sessions),
            sessions_path,
            session_enc_key,
        };

        // If a legacy plaintext file was migrated, immediately rewrite it
        // encrypted so no plaintext copy remains on disk.
        if migrated {
            state.save_sessions_to_disk()?;
        }

        Ok(state)
    }

    /// Persist the current session state to disk, encrypted at rest.
    /// Call this after any session-mutating operation.
    pub fn save_sessions_to_disk(&self) -> Result<(), String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        sessions.save_to_disk_encrypted(&self.sessions_path, &self.session_enc_key)
    }
}
