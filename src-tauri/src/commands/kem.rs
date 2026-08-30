//! ML-KEM-768 Post-Quantum Key Encapsulation Commands
//!
//! Frontend calls these via `invoke()`.
//! ML-KEM secret keys live encrypted on disk (AES-256-GCM device key) — never in JS.
//! Shared secrets NEVER leave Rust — stored internally and consumed by dr_init via ss_id.
//! Frontend receives only opaque identifiers (key_id, ss_id).

use serde::Serialize;
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::commands::CryptoState;
use crate::pq::{
    MlKem768Encapsulation, MlKem768PublicKey, MLKEM768_CT_SIZE, MLKEM768_PK_SIZE, MLKEM768_SK_SIZE,
};

// ── Response types ──────────────────────────────────────────────

#[derive(Serialize, Clone)]
pub struct KemKeygenResponse {
    /// Opaque identifier — frontend uses this to reference the keypair
    pub key_id: String,
    /// ML-KEM-768 public key (hex, 1184 bytes → 2368 hex chars)
    pub public_key: String,
    /// Human-readable fingerprint (SHA3-256, first 8 bytes)
    pub fingerprint: String,
}

#[derive(Serialize, Clone)]
pub struct KemEncapsulateResponse {
    /// Opaque identifier for the resulting shared secret.
    /// Pass to dr_init() — the shared secret itself NEVER reaches JS.
    pub ss_id: String,
    /// ML-KEM-768 ciphertext (hex, 1088 bytes → 2176 hex chars)
    /// Send this to the peer so they can decapsulate with their key.
    pub ciphertext: String,
}

#[derive(Serialize, Clone)]
pub struct KemDecapsulateResponse {
    /// Opaque identifier for the resulting shared secret.
    /// Pass to dr_init() — the shared secret itself NEVER reaches JS.
    pub ss_id: String,
}

// ── Commands ────────────────────────────────────────────────────

/// Generate a new ML-KEM-768 keypair.
///
/// The secret key is encrypted and stored to disk via KeyStore (AES-256-GCM).
/// Never exposed to frontend — only returns an opaque key_id.
#[tauri::command]
pub fn kem_keygen(state: State<CryptoState>) -> Result<KemKeygenResponse, String> {
    use crate::pq::MlKem768KeyPair;

    let kp = MlKem768KeyPair::generate();
    let key_id = Uuid::new_v4().to_string();
    let public_key_hex = hex::encode(&kp.public_key);
    let fingerprint = crate::pq::fingerprint(&kp.public_key);

    // Store secret key encrypted to disk
    {
        let mut store = state.key_store.lock().map_err(|e| e.to_string())?;
        store.store_secret_key(&key_id, &kp.public_key, &kp.secret_key, &fingerprint)?;
    }

    Ok(KemKeygenResponse {
        key_id,
        public_key: public_key_hex,
        fingerprint,
    })
}

/// Encapsulate a shared secret to a peer's public key.
///
/// ML-KEM encapsulate only needs the recipient's public key.
/// Returns the ciphertext (send to peer) and the shared_secret (for JS Double Ratchet init).
/// The shared secret is also stored internally under ss_id for Rust Double Ratchet.
#[tauri::command]
pub fn kem_encapsulate(
    state: State<CryptoState>,
    peer_public_key_hex: String,
) -> Result<KemEncapsulateResponse, String> {
    // Decode peer's public key
    let peer_pk_bytes = hex::decode(&peer_public_key_hex)
        .map_err(|e| format!("Invalid hex in peer public key: {e}"))?;
    if peer_pk_bytes.len() != MLKEM768_PK_SIZE {
        return Err(format!(
            "Invalid peer public key length: expected {}, got {}",
            MLKEM768_PK_SIZE,
            peer_pk_bytes.len()
        ));
    }
    let mut pk_arr = [0u8; MLKEM768_PK_SIZE];
    pk_arr.copy_from_slice(&peer_pk_bytes);
    let peer_pk = MlKem768PublicKey::from_bytes(&pk_arr)
        .map_err(|e| format!("Invalid ML-KEM public key: {e}"))?;

    // Encapsulate
    let enc = MlKem768Encapsulation::encapsulate(&peer_pk);
    let ss_id = Uuid::new_v4().to_string();
    let ciphertext_hex = hex::encode(enc.ciphertext);

    // Store shared secret internally for Rust Double Ratchet (consumed by dr_init)
    // 🔒 NEVER returned to frontend — ss_id is the only handle JS sees
    let mut secrets = state.shared_secrets.lock().map_err(|e| e.to_string())?;
    secrets.insert(ss_id.clone(), enc.shared_secret);

    Ok(KemEncapsulateResponse {
        ss_id,
        ciphertext: ciphertext_hex,
    })
}

/// Decapsulate a shared secret from a peer's ciphertext.
///
/// Loads our secret key from encrypted KeyStore, decapsulates, then zeroizes SK bytes.
/// Returns ss_id and shared_secret — caller uses ss_id for dr_init.
#[tauri::command]
pub fn kem_decapsulate(
    state: State<CryptoState>,
    key_id: String,
    ciphertext_hex: String,
) -> Result<KemDecapsulateResponse, String> {
    // Decode ciphertext
    let ct_bytes =
        hex::decode(&ciphertext_hex).map_err(|e| format!("Invalid hex in ciphertext: {e}"))?;
    if ct_bytes.len() != MLKEM768_CT_SIZE {
        return Err(format!(
            "Invalid ciphertext length: expected {}, got {}",
            MLKEM768_CT_SIZE,
            ct_bytes.len()
        ));
    }
    let mut ct_arr = [0u8; MLKEM768_CT_SIZE];
    ct_arr.copy_from_slice(&ct_bytes);

    // Load secret key from encrypted KeyStore
    let mut sk_bytes = {
        let store = state.key_store.lock().map_err(|e| e.to_string())?;
        store.load_secret_key(&key_id)?
    };

    if sk_bytes.len() != MLKEM768_SK_SIZE {
        sk_bytes.zeroize();
        return Err(format!(
            "Invalid secret key length: expected {}, got {}",
            MLKEM768_SK_SIZE,
            sk_bytes.len()
        ));
    }

    let mut sk_arr = [0u8; MLKEM768_SK_SIZE];
    sk_arr.copy_from_slice(&sk_bytes);
    sk_bytes.zeroize(); // 🔒 SK bytes erased from memory

    // Decapsulate
    let ss = crate::pq::mlkem768_decapsulate_bytes(&sk_arr, &ct_arr);
    let ss_id = Uuid::new_v4().to_string();

    // Store shared secret internally for Rust Double Ratchet (consumed by dr_init)
    // 🔒 NEVER returned to frontend — ss_id is the only handle JS sees
    let mut secrets = state.shared_secrets.lock().map_err(|e| e.to_string())?;
    secrets.insert(ss_id.clone(), ss);

    Ok(KemDecapsulateResponse { ss_id })
}

/// List stored key IDs (public metadata only — secret keys encrypted on disk).
#[tauri::command]
pub fn kem_list_keys(state: State<CryptoState>) -> Result<Vec<KemKeygenResponse>, String> {
    let store = state.key_store.lock().map_err(|e| e.to_string())?;
    Ok(store
        .list_keys()
        .into_iter()
        .map(|(key_id, meta)| KemKeygenResponse {
            key_id,
            public_key: hex::encode(&meta.public_key),
            fingerprint: meta.fingerprint.clone(),
        })
        .collect())
}
