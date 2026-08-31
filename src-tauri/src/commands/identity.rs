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
use crate::pq::MlDsa65KeyPair;

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

/// Full pre-key bundle response (identity + signing key + signed pre-key).
/// This is what the frontend uploads to the server / shares with peers.
#[derive(Serialize, Clone)]
pub struct SpkGetPublicResponse {
    pub identity_id: String,
    /// X25519 identity public key (hex) — IK
    pub identity_pk_hex: String,
    /// ML-DSA-65 identity signing public key (hex) — verifies the SPK signature
    pub signing_pk_hex: String,
    /// Independent X25519 signed pre-key public key (hex) — SPK
    pub signed_prekey_hex: String,
    /// ML-DSA-65 signature over the SPK public key (hex)
    pub signed_prekey_sig_hex: String,
    /// Opaque SPK version identifier (changes on rotation)
    pub signed_prekey_id: String,
}

#[derive(Serialize, Clone)]
pub struct IkListResponse {
    pub identities: Vec<IkGetPublicResponse>,
}

// ── Internal helpers ────────────────────────────────────────────

/// Prefix for identity key storage in KeyStore
const IK_PREFIX: &str = "ik_";
/// Prefix for the ML-DSA-65 identity signing key (signs the SPK)
const IK_SIGN_PREFIX: &str = "iksign_";
/// Prefix for the independent signed pre-key (X25519)
const IK_SPK_PREFIX: &str = "ikspk_";
/// Domain-separation context for the ML-DSA-65 SPK signature.
const SPK_SIGN_CONTEXT: &[u8] = b"fibemate-spk-v1";

/// Internal: encode a KeyStore key for an identity key.
#[doc(hidden)]
pub fn ik_key_id(identity_id: &str) -> String {
    format!("{IK_PREFIX}{identity_id}")
}

/// Internal: encode a KeyStore key for the ML-DSA-65 identity signing key.
fn ik_sign_key_id(identity_id: &str) -> String {
    format!("{IK_SIGN_PREFIX}{identity_id}")
}

/// Internal: encode a KeyStore key for the independent signed pre-key.
fn ik_spk_key_id(identity_id: &str) -> String {
    format!("{IK_SPK_PREFIX}{identity_id}")
}

/// Load an identity keypair from KeyStore (secret key decrypts from disk each use).
fn load_identity_keypair(state: &CryptoState, identity_id: &str) -> Result<RatchetKeyPair, String> {
    let store = state.key_store.lock().map_err(|e| e.to_string())?;
    let sk_bytes = store.load_secret_key(&ik_key_id(identity_id))?;
    if sk_bytes.len() != 32 {
        return Err(format!(
            "Identity key corrupt: expected 32 bytes, got {}",
            sk_bytes.len()
        ));
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&sk_bytes);
    Ok(RatchetKeyPair::from_private_key(private_key))
}

/// Load (or lazily generate + persist) the ML-DSA-65 identity signing key.
/// Lazy init keeps pre-existing identities (created before SPK support)
/// working — the ISK appears on first bundle request.
fn load_or_create_isk(state: &CryptoState, identity_id: &str) -> Result<MlDsa65KeyPair, String> {
    let result = {
        let store = state.key_store.lock().map_err(|e| e.to_string())?;
        store.load_secret_key(&ik_sign_key_id(identity_id))
    };
    let sk_bytes = match result {
        Ok(bytes) => bytes,
        Err(_) => {
            let kp = MlDsa65KeyPair::generate();
            let mut store = state.key_store.lock().map_err(|e| e.to_string())?;
            store.store_secret_key(
                &ik_sign_key_id(identity_id),
                &kp.public_key,
                &kp.secret_key,
                &crate::pq::fingerprint(&kp.public_key),
            )?;
            return Ok(kp);
        }
    };
    if sk_bytes.len() != crate::pq::MLDSA65_SK_SIZE {
        return Err(format!(
            "Identity signing key corrupt: expected {} bytes, got {}",
            crate::pq::MLDSA65_SK_SIZE,
            sk_bytes.len()
        ));
    }
    let mut secret_key = [0u8; crate::pq::MLDSA65_SK_SIZE];
    secret_key.copy_from_slice(&sk_bytes);
    // rustpq 0.3 cannot derive the public key from the secret key, so it is
    // read back from the KeyStore metadata (stored alongside on creation).
    let public_key = {
        let store = state.key_store.lock().map_err(|e| e.to_string())?;
        let meta = store
            .get_meta(&ik_sign_key_id(identity_id))
            .ok_or("Identity signing key metadata missing")?;
        let mut pk = [0u8; crate::pq::MLDSA65_PK_SIZE];
        if meta.public_key.len() != crate::pq::MLDSA65_PK_SIZE {
            return Err(format!(
                "Identity signing key metadata corrupt: expected {} bytes, got {}",
                crate::pq::MLDSA65_PK_SIZE,
                meta.public_key.len()
            ));
        }
        pk.copy_from_slice(&meta.public_key);
        pk
    };
    Ok(MlDsa65KeyPair {
        public_key,
        secret_key,
    })
}

/// Load (or lazily generate + persist) the independent X25519 signed pre-key.
/// Being separate from the identity key means X3DH DH2 != DH3 (no degenerate
/// duplicate) and the SPK can be rotated without rotating the identity.
fn load_or_create_spk(state: &CryptoState, identity_id: &str) -> Result<RatchetKeyPair, String> {
    let result = {
        let store = state.key_store.lock().map_err(|e| e.to_string())?;
        store.load_secret_key(&ik_spk_key_id(identity_id))
    };
    let sk_bytes = match result {
        Ok(bytes) => bytes,
        Err(_) => {
            let kp = RatchetKeyPair::generate();
            let mut store = state.key_store.lock().map_err(|e| e.to_string())?;
            store.store_secret_key(
                &ik_spk_key_id(identity_id),
                &kp.public_key,
                &kp.private_key,
                &crate::pq::fingerprint(&kp.public_key),
            )?;
            return Ok(kp);
        }
    };
    if sk_bytes.len() != 32 {
        return Err(format!(
            "SPK corrupt: expected 32 bytes, got {}",
            sk_bytes.len()
        ));
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&sk_bytes);
    Ok(RatchetKeyPair::from_private_key(private_key))
}

/// Sign the SPK public key with the ML-DSA-65 identity signing key.
/// Deterministic inputs → signature is stable for a given (ISK, SPK) pair,
/// so it does not need to be persisted separately.
fn sign_spk(
    isk: &MlDsa65KeyPair,
    spk_pub: &[u8; 32],
) -> Result<[u8; crate::pq::MLDSA65_SIG_SIZE], String> {
    isk.sign(spk_pub, SPK_SIGN_CONTEXT)
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
            let meta = store
                .get_meta(&ik_key_id(&id))
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
    let meta = store
        .get_meta(&ik_key_id(&identity_id))
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
            key_id
                .strip_prefix(IK_PREFIX)
                .map(|stripped| IkGetPublicResponse {
                    identity_id: stripped.to_string(),
                    public_key_hex: hex::encode(&meta.public_key),
                    fingerprint: meta.fingerprint.clone(),
                })
        })
        .collect();
    Ok(IkListResponse { identities })
}

/// Build the full pre-key bundle for an identity:
/// IK (X25519) + ISK (ML-DSA-65 signing key) + independent SPK (X25519)
/// with an ML-DSA-65 signature binding the SPK to the identity.
///
/// The SPK is generated lazily on first call and persisted; the signature is
/// deterministic (same ISK + SPK => same signature) so it is computed on the
/// fly. This replaces the old "SPK = IK" degenerate design: X3DH now gets
/// three distinct DH inputs (DH2 != DH3) and a fresh SPK can be rotated
/// without touching the long-term identity key.
#[tauri::command]
pub fn spk_get_public(
    state: State<CryptoState>,
    identity_id: String,
) -> Result<SpkGetPublicResponse, String> {
    // IK public key (from metadata - no secret decryption needed).
    let identity_pk_hex = {
        let store = state.key_store.lock().map_err(|e| e.to_string())?;
        let meta = store
            .get_meta(&ik_key_id(&identity_id))
            .ok_or(format!("Identity not found: {identity_id}"))?;
        hex::encode(&meta.public_key)
    };

    // ISK (ML-DSA-65) - lazily created on first use.
    let isk = load_or_create_isk(&state, &identity_id)?;
    let signing_pk_hex = hex::encode(isk.public_key);

    // Independent SPK (X25519) - lazily created on first use.
    let spk = load_or_create_spk(&state, &identity_id)?;
    let signed_prekey_hex = hex::encode(spk.public_key);

    // ML-DSA-65 signature over the SPK public key.
    let sig = sign_spk(&isk, &spk.public_key)?;
    let signed_prekey_sig_hex = hex::encode(sig);

    // SPK version identifier - derived from the SPK so it changes on rotation.
    let signed_prekey_id = hex::encode(&spk.public_key[..8]);

    Ok(SpkGetPublicResponse {
        identity_id,
        identity_pk_hex,
        signing_pk_hex,
        signed_prekey_hex,
        signed_prekey_sig_hex,
        signed_prekey_id,
    })
}

/// Key-store controlled self-destruct (defense-in-depth, manual-only).
///
/// Triggers:
///   1. Memory: all DR sessions (Zeroize-derived → drop wipes) and pending
///      shared secrets are destroyed.
///   2. Disk: every encrypted key blob in keys/, device.key, sessions.json
///      and key_meta.json is overwritten 3x with random bytes, then removed.
///
/// Constraints (hard):
///   - Requires the exact confirmation phrase "DESTROY ALL KEYS".
///   - Only destroys FIBEMATE's own data under app_data — never touches
///     other user files.
///   - No automatic / scheduled / remote-triggered path exists.
#[tauri::command]
pub fn keystore_selfdestruct(state: State<CryptoState>, confirm: String) -> Result<String, String> {
    if confirm != "DESTROY ALL KEYS" {
        return Err("确认短语不正确 — 操作已取消。".to_string());
    }
    crate::audit::audit("keystore_selfdestruct", "begin");

    // 1. Memory: destroy all ratchet sessions (RatchetState: derive(Zeroize))
    {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        for sid in sessions.list_session_ids() {
            sessions.delete_session(&sid);
        }
    }
    // 2. Memory: clear pending X3DH shared secrets
    {
        let mut secrets = state.shared_secrets.lock().map_err(|e| e.to_string())?;
        secrets.clear();
    }
    // 3. Disk: overwrite-then-delete every encrypted key blob
    {
        let mut store = state.key_store.lock().map_err(|e| e.to_string())?;
        let ids: Vec<String> = store.list_keys().into_iter().map(|(id, _)| id).collect();
        for id in ids {
            let path = store.keys_dir().join(format!("{id}.enc"));
            for _ in 0..3 {
                let junk: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
                let _ = std::fs::write(&path, &junk);
            }
            let _ = std::fs::remove_file(&path);
            let _ = store.delete_secret_key(&id);
        }
    }
    // 4. Disk: overwrite-then-delete device key, session file, metadata
    if let Some(app_data) = state.sessions_path.parent() {
        for f in ["device.key", "sessions.json", "key_meta.json"] {
            let p = app_data.join(f);
            if p.exists() {
                for _ in 0..3 {
                    let junk: Vec<u8> = (0..512).map(|_| rand::random::<u8>()).collect();
                    let _ = std::fs::write(&p, &junk);
                }
                let _ = std::fs::remove_file(&p);
            }
        }
    }

    crate::audit::audit("keystore_selfdestruct", "complete");
    Ok("密钥库已销毁。重新启动后应用将处于全新状态。".to_string())
}

/// Rotate the independent signed pre-key: generates a fresh X25519 SPK and
/// re-signs it. Old sessions already established are unaffected; new X3DH
/// handshakes use the new SPK. Callers should re-upload their bundle.
#[tauri::command]
pub fn spk_rotate(
    state: State<CryptoState>,
    identity_id: String,
) -> Result<SpkGetPublicResponse, String> {
    let new_spk = RatchetKeyPair::generate();
    let mut store = state.key_store.lock().map_err(|e| e.to_string())?;
    store.store_secret_key(
        &ik_spk_key_id(&identity_id),
        &new_spk.public_key,
        &new_spk.private_key,
        &crate::pq::fingerprint(&new_spk.public_key),
    )?;
    drop(store);

    // Rebuild the full bundle with the rotated SPK.
    spk_get_public(state, identity_id)
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
    // Optional SPK authenticity check: the peer's ML-DSA-65 signing public
    // key + the signature over their SPK. When provided, the handshake is
    // rejected if the signature does not verify (prevents SPK substitution).
    peer_signing_pk_hex: Option<String>,
    peer_spk_sig_hex: Option<String>,
) -> Result<X3dhInitiateResponse, String> {
    // Load our identity key
    let my_identity = load_identity_keypair(&state, &my_identity_id)?;

    // Parse peer's keys
    let their_identity = hex_to_bytes_32(&peer_identity_pk_hex, "peer identity key")?;
    let their_signed_prekey = hex_to_bytes_32(&peer_signed_prekey_pk_hex, "peer signed pre-key")?;

    // Verify the SPK signature when the peer provided its signing key.
    if let (Some(signing_pk_hex), Some(sig_hex)) = (peer_signing_pk_hex, peer_spk_sig_hex) {
        let signing_pk = hex::decode(&signing_pk_hex)
            .map_err(|e| format!("Invalid peer signing pk hex: {e}"))?;
        let sig_bytes =
            hex::decode(&sig_hex).map_err(|e| format!("Invalid peer spk signature hex: {e}"))?;
        if signing_pk.len() != crate::pq::MLDSA65_PK_SIZE {
            return Err(format!(
                "Invalid peer signing pk length: expected {}, got {}",
                crate::pq::MLDSA65_PK_SIZE,
                signing_pk.len()
            ));
        }
        if sig_bytes.len() != crate::pq::MLDSA65_SIG_SIZE {
            return Err(format!(
                "Invalid peer spk signature length: expected {}, got {}",
                crate::pq::MLDSA65_SIG_SIZE,
                sig_bytes.len()
            ));
        }
        let mut pk_arr = [0u8; crate::pq::MLDSA65_PK_SIZE];
        pk_arr.copy_from_slice(&signing_pk);
        let mut sig_arr = [0u8; crate::pq::MLDSA65_SIG_SIZE];
        sig_arr.copy_from_slice(&sig_bytes);
        // Verify: signature is over the SPK public key, context "fibemate-spk-v1".
        let peer_isk = MlDsa65KeyPair {
            public_key: pk_arr,
            secret_key: [0u8; crate::pq::MLDSA65_SK_SIZE],
        };
        if !peer_isk.verify(&their_signed_prekey, SPK_SIGN_CONTEXT, &sig_arr)? {
            return Err(
                "SPK signature verification failed — peer bundle may be tampered with".to_string(),
            );
        }
    }

    // Generate ephemeral key
    let my_ephemeral = RatchetKeyPair::generate();
    let our_ephemeral_pk_hex = hex::encode(my_ephemeral.public_key);

    // X3DH initiator computation
    let shared_secret = X3DH::initiator(
        &my_identity,
        &my_ephemeral,
        &their_identity,
        &their_signed_prekey,
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

    // Independent signed pre-key (persisted, lazily created on first use).
    // Distinct from the identity key: X3DH gets three distinct DH inputs
    // (DH2 != DH3) and the SPK can be rotated without rotating the identity.
    // The frontend uploads this SPK via spk_get_public() so both sides agree.
    let my_signed_prekey = load_or_create_spk(&state, &my_identity_id)?;

    // X3DH responder computation
    let shared_secret = X3DH::responder(
        &my_identity,
        &my_signed_prekey,
        &their_identity,
        &their_ephemeral,
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
        return Err(format!(
            "Invalid {label} length: expected 32, got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
