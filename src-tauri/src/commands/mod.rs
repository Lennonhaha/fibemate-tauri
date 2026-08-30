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

pub mod identity;
pub mod kem;
pub mod ratchet;
pub mod safety_number;
pub mod sm2_cmd;

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
}

impl CryptoState {
    /// Initialize with an app data directory for encrypted key storage.
    /// Loads persisted DR sessions from disk if available.
    pub fn new(app_data: PathBuf) -> Result<Self, String> {
        let key_store = KeyStore::new(&app_data)?;
        let sessions_path = app_data.join("sessions.json");

        // Restore persisted sessions from disk
        let sessions = {
            let loaded = crate::double_ratchet::load_sessions_from_disk(&sessions_path);
            if loaded.is_empty() {
                println!("[CryptoState] No persisted sessions found — starting fresh.");
                SessionManager::new()
            } else {
                println!(
                    "[CryptoState] Restored {} persisted session(s) from disk.",
                    loaded.len()
                );
                SessionManager::from_sessions(loaded)
            }
        };

        Ok(Self {
            key_store: Mutex::new(key_store),
            shared_secrets: Mutex::new(HashMap::new()),
            sessions: Mutex::new(sessions),
            sessions_path,
        })
    }

    /// Persist the current session state to disk.
    /// Call this after any session-mutating operation.
    pub fn save_sessions_to_disk(&self) -> Result<(), String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        sessions.save_to_disk(&self.sessions_path)
    }
}
