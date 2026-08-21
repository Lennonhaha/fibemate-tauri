//! Double Ratchet Session Commands
//!
//! Frontend calls these via `invoke()` — session state and
//! message keys live entirely in Rust memory.

use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

use crate::commands::CryptoState;
use crate::double_ratchet::EncryptedMessage;

// ── Response types ──────────────────────────────────────────────

#[derive(Serialize, Clone)]
pub struct DrInitResponse {
    /// Opaque session identifier for all subsequent operations
    pub session_id: String,
    /// Our X25519 public key for this session (hex, 64 chars)
    /// Must be sent to the peer so they can call dr_set_peer
    pub our_public_key: String,
}

#[derive(Serialize, Clone)]
pub struct DrEncryptResponse {
    /// The encrypted message as JSON (EncryptedMessage)
    pub message_json: String,
    /// Message number (monotonically increasing)
    pub message_num: u32,
}

/// Used by Tauri command handlers in binary context.
#[allow(dead_code)]
#[derive(Deserialize)]
pub struct DrDecryptRequest {
    /// The EncryptedMessage serialized as JSON
    pub message_json: String,
}

#[derive(Serialize, Clone)]
pub struct DrDecryptResponse {
    /// Decrypted plaintext as hex string
    pub plaintext_hex: String,
}

// ── Commands ────────────────────────────────────────────────────

/// Initialize a Double Ratchet session from a stored shared secret.
///
/// Consumes the shared secret (identified by ss_id) — it is removed
/// from storage after session creation (single-use).
///
/// Optionally binds identity keys for Safety Number display.
#[tauri::command]
pub fn dr_init(
    state: State<CryptoState>,
    ss_id: String,
    peer_name: String,
    is_initiator: bool,
    // Our identity key Store ID (optional — enables Safety Number)
    our_identity_id: Option<String>,
    // Peer's identity public key hex (optional — enables Safety Number)
    peer_identity_pk_hex: Option<String>,
) -> Result<DrInitResponse, String> {
    // Parse peer identity key if provided
    let peer_identity_pk: Option<[u8; 32]> = match peer_identity_pk_hex {
        Some(ref hex_str) if !hex_str.is_empty() => {
            let bytes = hex::decode(hex_str)
                .map_err(|e| format!("Invalid peer identity pk hex: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!("Peer identity pk must be 32 bytes, got {}", bytes.len()));
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes);
            Some(pk)
        }
        _ => None,
    };

    // Consume the shared secret (single-use, removed from storage)
    let (session_id, our_pk) = {
        let mut secrets = state.shared_secrets.lock().map_err(|e| e.to_string())?;
        let ss = secrets.remove(&ss_id).ok_or(format!("Shared secret not found: {ss_id}"))?;
        drop(secrets);

        let session_id = format!("{}_{peer_name}", Uuid::new_v4().to_string().split('-').next().unwrap_or("session"));

        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        sessions.create_session(&session_id, &ss, is_initiator)?;

        // Bind identity keys if provided
        if let (Some(ref our_id), Some(pk)) = (&our_identity_id, peer_identity_pk) {
            sessions.set_identity_keys(&session_id, our_id, pk)?;
        }

        let our_pk = sessions.get_send_key(&session_id)?;
        (session_id, our_pk)
    }; // both locks dropped

    // Persist to disk
    state.save_sessions_to_disk()?;

    Ok(DrInitResponse {
        session_id,
        our_public_key: hex::encode(our_pk),
    })
}

/// Set the peer's public key for a session.
///
/// Must be called before decrypting the first message.
#[tauri::command]
pub fn dr_set_peer(
    state: State<CryptoState>,
    session_id: String,
    peer_public_key_hex: String,
) -> Result<(), String> {
    let pk_bytes = hex::decode(&peer_public_key_hex)
        .map_err(|e| format!("Invalid hex: {e}"))?;
    if pk_bytes.len() != 32 {
        return Err(format!("Invalid public key length: expected 32, got {}", pk_bytes.len()));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_bytes);

    {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        sessions.set_peer_key(&session_id, pk)?;
    }
    state.save_sessions_to_disk()?;
    Ok(())
}

/// Encrypt a plaintext message in a Double Ratchet session.
///
/// Returns the EncryptedMessage as JSON ready for wire transmission.
/// The plaintext is expected as a hex-encoded byte string.
#[tauri::command]
pub fn dr_encrypt(
    state: State<CryptoState>,
    session_id: String,
    plaintext_hex: String,
) -> Result<DrEncryptResponse, String> {
    let plaintext = hex::decode(&plaintext_hex)
        .map_err(|e| format!("Invalid hex plaintext: {e}"))?;

    let (encrypted, msg_num) = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        let encrypted = sessions.encrypt_message(&session_id, &plaintext)?;
        let msg_num = encrypted.message_num;
        (encrypted, msg_num)
    };

    let message_json = serde_json::to_string(&encrypted)
        .map_err(|e| format!("Serialization failed: {e}"))?;

    state.save_sessions_to_disk()?;

    Ok(DrEncryptResponse { message_json, message_num: msg_num })
}

/// Decrypt a message in a Double Ratchet session.
///
/// Expects the EncryptedMessage as JSON.
/// Returns the plaintext as a hex-encoded byte string.
#[tauri::command]
pub fn dr_decrypt(
    state: State<CryptoState>,
    session_id: String,
    message_json: String,
) -> Result<DrDecryptResponse, String> {
    let encrypted: EncryptedMessage = serde_json::from_str(&message_json)
        .map_err(|e| format!("Invalid message JSON: {e}"))?;

    let plaintext = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        sessions.decrypt_message(&session_id, &encrypted)?
    };

    state.save_sessions_to_disk()?;

    Ok(DrDecryptResponse { plaintext_hex: hex::encode(&plaintext) })
}

/// Get this session's current sending public key.
#[tauri::command]
pub fn dr_get_send_key(
    state: State<CryptoState>,
    session_id: String,
) -> Result<String, String> {
    let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
    let pk = sessions.get_send_key(&session_id)?;
    Ok(hex::encode(pk))
}

/// List all active session IDs.
#[tauri::command]
pub fn dr_list_sessions(
    state: State<CryptoState>,
) -> Result<Vec<String>, String> {
    let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
    Ok(sessions.list_session_ids())
}

/// Delete a session and wipe its key material.
#[tauri::command]
pub fn dr_delete_session(
    state: State<CryptoState>,
    session_id: String,
) -> Result<(), String> {
    {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        sessions.delete_session(&session_id);
    }
    state.save_sessions_to_disk()?;
    Ok(())
}
