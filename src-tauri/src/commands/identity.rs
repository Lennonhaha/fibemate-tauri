//! Identity Key & X3DH Handshake Commands
//!
//! X25519 identity key generation + X3DH key exchange.
//! Identity secret keys are stored encrypted in KeyStore (never exposed).
//! X3DH shared secrets flow directly into the shared_secrets HashMap
//! (consumed by dr_init via ss_id — never exposed to JS).

use serde::Serialize;
use tauri::State;
use uuid::Uuid;

use crate::commands::CryptoState;
use crate::double_ratchet::{RatchetKeyPair, X3DH};

// ── Response types ──────────────────────────────────────────────

#[derive(Serialize, Clone)]
pub struct IkGenerateResponse {
    /// Opaque handle — frontend uses this to reference the identity key
    pub identity_id: String,
    /// X25519 public key (hex, 64 chars)
    pub public_key_hex: String,
    /// Human-readable fingerprint (SHA3-256, first 8 bytes)
    pub fingerprint: String,
}

#[derive(Serialize, Clone)]
pub struct IkGetPublicResponse {
    pub identity_id: String,
    pub public_key_hex: String,
    pub fingerprint: String,
}

#[derive(Serialize, Clone)]
pub struct X3dhInitiateResponse {
    /// Opaque handle for the resulting X3DH shared secret (pass to dr_init)
    pub ss_id: String,
    /// Our identity public key (hex) — for peer verification
    pub our_identity_pk_hex: String,
    /// Our ephemeral public key (hex) — send to peer
    pub our_ephemeral_pk_hex: String,
}

#[derive(Serialize, Clone)]
pub struct X3dhRespondResponse {
    /// Opaque handle for the resulting X3DH shared secret (pass to dr_init)
    pub ss_id: String,
    /// Our identity public key (hex) — for peer verification
    pub our_identity_pk_hex: String,
    /// Our signed pre-key public key (hex) — send to peer for their confirmation
    pub our_signed_prekey_pk_hex: String,
}

#[derive(Serialize, Clone)]
pub struct IkListResponse {
    pub identities: Vec<IkGetPublicResponse>,
}

// ── Internal helpers ────────────────────────────────────────────

/// Prefix for identity key storage in KeyStore
const IK_PREFIX: &str = "ik_";

/// Internal: encode a KeyStore key for an identity key.
#[doc(hidden)]
pub fn ik_key_id(identity_id: &str) -> String {
    format!("{IK_PREFIX}{identity_id}")
}

/// Load an identity keypair from KeyStore (secret key decrypts from disk each use).
fn load_identity_keypair(state: &CryptoState, identity_id: &str) -> Result<RatchetKeyPair, String> {
    let store = state.key_store.lock().map_err(|e| e.to_string())?;
    let sk_bytes = store.load_secret_key(&ik_key_id(identity_id))?;
    if sk_bytes.len() != 32 {
        return Err(format!("Identity key corrupt: expected 32 bytes, got {}", sk_bytes.len()));
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&sk_bytes);
    Ok(RatchetKeyPair::from_private_key(private_key))
}

/// Store an X3DH shared secret and return its opaque ss_id.
fn stash_shared_secret(state: &CryptoState, ss_bytes: [u8; 32]) -> Result<String, String> {
    let ss_id = Uuid::new_v4().to_string();
    let mut secrets = state.shared_secrets.lock().map_err(|e| e.to_string())?;
    secrets.insert(ss_id.clone(), ss_bytes);
    Ok(ss_id)
}

// ── Commands ────────────────────────────────────────────────────

/// Generate a new X25519 identity keypair (or return existing one).
///
/// Identity keys are persistent — generated once per installation.
/// The secret key is stored encrypted in KeyStore (never exposed to JS).
#[tauri::command]
pub fn ik_generate(
    state: State<CryptoState>,
    identity_id: Option<String>,
) -> Result<IkGenerateResponse, String> {
    let id = identity_id.unwrap_or_else(|| Uuid::new_v4().to_string());

    // Check if already exists
    {
        let store = state.key_store.lock().map_err(|e| e.to_string())?;
        if store.has_key(&ik_key_id(&id)) {
            let meta = store.get_meta(&ik_key_id(&id))
                .ok_or("Identity metadata missing")?;
            return Ok(IkGenerateResponse {
                identity_id: id,
                public_key_hex: hex::encode(&meta.public_key),
                fingerprint: meta.fingerprint.clone(),
            });
        }
    }

    // Generate new X25519 keypair
    let kp = RatchetKeyPair::generate();
    let public_key_hex = hex::encode(kp.public_key);
    let fingerprint = crate::pq::fingerprint(&kp.public_key);

    // Store encrypted to disk
    {
        let mut store = state.key_store.lock().map_err(|e| e.to_string())?;
        store.store_secret_key(
            &ik_key_id(&id),
            &kp.public_key,
            &kp.private_key,
            &fingerprint,
        )?;
    }

    Ok(IkGenerateResponse {
        identity_id: id,
        public_key_hex,
        fingerprint,
    })
}

/// Get the public key for an existing identity (without decrypting the secret key).
#[tauri::command]
pub fn ik_get_public(
    state: State<CryptoState>,
    identity_id: String,
) -> Result<IkGetPublicResponse, String> {
    let store = state.key_store.lock().map_err(|e| e.to_string())?;
    let meta = store.get_meta(&ik_key_id(&identity_id))
        .ok_or(format!("Identity not found: {identity_id}"))?;
    Ok(IkGetPublicResponse {
        identity_id,
        public_key_hex: hex::encode(&meta.public_key),
        fingerprint: meta.fingerprint.clone(),
    })
}

/// List all identity keys stored in KeyStore (public metadata only).
#[tauri::command]
pub fn ik_list(state: State<CryptoState>) -> Result<IkListResponse, String> {
    let store = state.key_store.lock().map_err(|e| e.to_string())?;
    let all_meta = store.list_keys();
    let identities = all_meta
        .into_iter()
        .filter_map(|(key_id, meta)| {
            key_id.strip_prefix(IK_PREFIX).map(|stripped| {
                IkGetPublicResponse {
                    identity_id: stripped.to_string(),
                    public_key_hex: hex::encode(&meta.public_key),
                    fingerprint: meta.fingerprint.clone(),
                }
            })
        })
        .collect();
    Ok(IkListResponse { identities })
}

/// Initiate X3DH key exchange (Alice side).
///
/// Performs 3-DH computation:
///   DH1 = DH(our_identity, their_identity)
///   DH2 = DH(our_ephemeral, their_identity)
///   DH3 = DH(our_ephemeral, their_signed_prekey)
///   → HKDF to 32-byte shared secret
///
/// Returns ss_id for dr_init() and our_ephemeral_pk_hex to send to peer.
#[tauri::command]
pub fn x3dh_initiate(
    state: State<CryptoState>,
    my_identity_id: String,
    peer_identity_pk_hex: String,
    peer_signed_prekey_pk_hex: String,
) -> Result<X3dhInitiateResponse, String> {
    // Load our identity key
    let my_identity = load_identity_keypair(&state, &my_identity_id)?;

    // Parse peer's keys
    let their_identity = hex_to_bytes_32(&peer_identity_pk_hex, "peer identity key")?;
    let their_signed_prekey = hex_to_bytes_32(&peer_signed_prekey_pk_hex, "peer signed pre-key")?;

    // Generate ephemeral key
    let my_ephemeral = RatchetKeyPair::generate();
    let our_ephemeral_pk_hex = hex::encode(my_ephemeral.public_key);

    // X3DH initiator computation
    let shared_secret = X3DH::initiator(
        &my_identity, &my_ephemeral, &their_identity, &their_signed_prekey,
    )?;

    let ss_id = stash_shared_secret(&state, shared_secret)?;

    Ok(X3dhInitiateResponse {
        ss_id,
        our_identity_pk_hex: hex::encode(my_identity.public_key),
        our_ephemeral_pk_hex,
    })
}

/// Respond to X3DH key exchange (Bob side).
///
/// Performs 3-DH computation:
///   DH1 = DH(our_signed_prekey, their_identity)
///   DH2 = DH(our_identity, their_ephemeral)
///   DH3 = DH(our_signed_prekey, their_ephemeral)
///   → HKDF to 32-byte shared secret
///
/// Returns ss_id for dr_init() and our_signed_prekey_pk_hex to confirm to peer.
#[tauri::command]
pub fn x3dh_respond(
    state: State<CryptoState>,
    my_identity_id: String,
    peer_identity_pk_hex: String,
    peer_ephemeral_pk_hex: String,
) -> Result<X3dhRespondResponse, String> {
    // Load our identity key
    let my_identity = load_identity_keypair(&state, &my_identity_id)?;

    // Parse peer's keys
    let their_identity = hex_to_bytes_32(&peer_identity_pk_hex, "peer identity key")?;
    let their_ephemeral = hex_to_bytes_32(&peer_ephemeral_pk_hex, "peer ephemeral key")?;

    // Signed pre-key = identity key (spk = ik)
    // 对齐前端 getMyPreKeyBundle() 的 "Reuse identity key as pre-key" 设计。
    // 若这里临时生成新 spk，则与前端上传的 bundle（signedPreKey=identityKey）不一致，
    // 导致 X3DH 双方 dh1 不对称、shared secret 永远不一致（Bug 2）。
    // TODO: 将来升级为独立持久化 signed pre-key（需同步前端 bundle 上传逻辑）。
    let my_signed_prekey = my_identity.clone();

    // X3DH responder computation
    let shared_secret = X3DH::responder(
        &my_identity, &my_signed_prekey, &their_identity, &their_ephemeral,
    )?;

    let ss_id = stash_shared_secret(&state, shared_secret)?;

    Ok(X3dhRespondResponse {
        ss_id,
        our_identity_pk_hex: hex::encode(my_identity.public_key),
        our_signed_prekey_pk_hex: hex::encode(my_signed_prekey.public_key),
    })
}

// ── Utility ─────────────────────────────────────────────────────

fn hex_to_bytes_32(hex: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex).map_err(|e| format!("Invalid hex for {label}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("Invalid {label} length: expected 32, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
