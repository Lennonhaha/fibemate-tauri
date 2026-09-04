//! Hybrid Key Exchange Commands (X25519 + ML-KEM-768)
//!
//! Frontend calls these via `invoke()`. Secret keys live encrypted on disk
//! (AES-256-GCM device key) — never in JS. Shared secrets NEVER leave Rust:
//! stored internally under ss_id and consumed by the Double Ratchet layer.
//! Frontend receives only opaque identifiers (key_id, ss_id).
//!
//! Protocol roles:
//!   - `hybrid_keygen`  : responder-side persistent keypair (X25519 + ML-KEM)
//!   - `hybrid_begin`   : initiator, ephemeral X25519, no persistent state
//!   - `hybrid_accept`  : responder, loads persisted keys, derives same secret
//!
//! Wire format (matches `pq::hybrid`):
//!   - bundle: 0x01 ‖ x25519_pk(32)                   [classic]
//!             0x02 ‖ x25519_pk(32) ‖ mlkem_pk(1184)  [hybrid]
//!   - enc:    0x01 ‖ x25519_epk(32)                  [classic]
//!             0x02 ‖ x25519_epk(32) ‖ mlkem_ct(1088) [hybrid]

use serde::Serialize;
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::commands::CryptoState;
use crate::pq::hybrid::{
    combine_secrets, HybridEncapsulation, HybridKeyPair, HybridMode, HybridPublicBundle,
};
use crate::pq::{MLKEM768_PK_SIZE, MLKEM768_SK_SIZE};

// ── Response types ──────────────────────────────────────────────

#[derive(Serialize, Clone, Debug)]
pub struct HybridKeygenResponse {
    /// Opaque identifier — frontend references the hybrid keypair with this
    pub key_id: String,
    /// Hybrid mode actually used ("classic" | "hybrid")
    pub mode: String,
    /// Serialized public bundle (hex) — send to peer
    pub bundle: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct HybridBeginResponse {
    /// Serialized encapsulation payload (hex) — send to peer
    pub enc: String,
    /// Opaque identifier for the combined shared secret.
    /// Pass to dr_init() — the secret itself NEVER reaches JS.
    pub ss_id: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct HybridAcceptResponse {
    /// Opaque identifier for the combined shared secret.
    pub ss_id: String,
}

// ── Helpers ─────────────────────────────────────────────────────

fn parse_mode(mode: &str) -> Result<HybridMode, String> {
    match mode {
        "classic" => Ok(HybridMode::Classic),
        "hybrid" => Ok(HybridMode::Hybrid),
        other => Err(format!(
            "Invalid hybrid mode '{other}' — expected 'classic' or 'hybrid'"
        )),
    }
}

fn mode_str(mode: HybridMode) -> String {
    match mode {
        HybridMode::Classic => "classic".to_string(),
        HybridMode::Hybrid => "hybrid".to_string(),
    }
}

/// Store a 32-byte X25519 secret under `<key_id>-x`.
fn store_x25519_half(
    state: &State<'_, CryptoState>,
    key_id: &str,
    pk: &[u8; 32],
    sk: &[u8; 32],
) -> Result<(), String> {
    let x_id = format!("{key_id}-x");
    let fingerprint = crate::pq::fingerprint(pk);
    let mut store = state.key_store.lock().map_err(|e| e.to_string())?;
    store.store_secret_key(&x_id, pk, sk, &fingerprint)
}

/// Store the ML-KEM half (sk 2400 B) under `<key_id>-m`.
fn store_mlkem_half(
    state: &State<'_, CryptoState>,
    key_id: &str,
    pk: &[u8; MLKEM768_PK_SIZE],
    sk: &[u8; MLKEM768_SK_SIZE],
) -> Result<(), String> {
    let m_id = format!("{key_id}-m");
    let fingerprint = crate::pq::fingerprint(pk);
    let mut store = state.key_store.lock().map_err(|e| e.to_string())?;
    store.store_secret_key(&m_id, pk, sk, &fingerprint)
}

fn insert_ss(state: &State<'_, CryptoState>, secret: [u8; 64]) -> Result<String, String> {
    let ss_id = Uuid::new_v4().to_string();
    let mut secrets = state.shared_secrets.lock().map_err(|e| e.to_string())?;
    // Hybrid secrets are 64 bytes; the DR layer consumes 32-byte root keys,
    // so the first half is stored — matching how kem/identity secrets enter
    // the same map (32-byte shared secrets keyed by ss_id).
    let mut root = [0u8; 32];
    root.copy_from_slice(&secret[..32]);
    secrets.insert(ss_id.clone(), root);
    Ok(ss_id)
}

// ── Commands ────────────────────────────────────────────────────

/// Generate a hybrid keypair (X25519 [+ ML-KEM-768]) — responder side.
///
/// Both halves are stored encrypted under sibling ids (`<id>-x`, `<id>-m`)
/// so the existing per-key KeyStore layout is preserved. Returns the public
/// bundle the initiator needs for `hybrid_begin`.
#[tauri::command]
pub fn hybrid_keygen(
    state: State<CryptoState>,
    mode: String,
) -> Result<HybridKeygenResponse, String> {
    let hm = parse_mode(&mode)?;
    let kp = match hm {
        HybridMode::Classic => HybridKeyPair::generate_classic(),
        HybridMode::Hybrid => HybridKeyPair::generate(),
    };

    let key_id = Uuid::new_v4().to_string();
    store_x25519_half(&state, &key_id, &kp.x25519_public, &kp.x25519_secret)?;
    if hm == HybridMode::Hybrid {
        store_mlkem_half(&state, &key_id, &kp.mlkem_public, &kp.mlkem_secret)?;
    }

    let bundle = kp.public_bundle(hm);
    Ok(HybridKeygenResponse {
        key_id,
        mode: mode_str(hm),
        bundle: hex::encode(bundle.to_bytes()),
    })
}

/// Initiator: combine X25519 ECDH with ML-KEM encapsulation toward a peer
/// bundle using an ephemeral key (no persistent state on this side).
///
/// Returns the encapsulation payload the responder needs plus an ss_id for
/// the combined 64-byte secret.
#[tauri::command]
pub fn hybrid_begin(
    state: State<CryptoState>,
    peer_bundle_hex: String,
) -> Result<HybridBeginResponse, String> {
    let bundle_bytes =
        hex::decode(&peer_bundle_hex).map_err(|e| format!("Invalid hex in peer bundle: {e}"))?;
    let bundle =
        HybridPublicBundle::from_bytes(&bundle_bytes).map_err(|e| format!("Bad bundle: {e}"))?;

    // Initiator only needs an ephemeral X25519 keypair; ML-KEM goes one-way
    // (encapsulate to the peer's public key).
    let eph = HybridKeyPair::generate_classic();
    let our_x25519_pk = eph.x25519_public;
    let our_sk = x25519_dalek::StaticSecret::from(eph.x25519_secret);

    match bundle {
        HybridPublicBundle::Classic { x25519 } => {
            let their_pk = x25519_dalek::PublicKey::from(x25519);
            let ecdh = our_sk.diffie_hellman(&their_pk);
            let mut secret = [0u8; 64];
            secret[..32].copy_from_slice(ecdh.as_bytes());
            let ss_id = insert_ss(&state, secret)?;
            let enc = HybridEncapsulation {
                mode: HybridMode::Classic,
                x25519_public: our_x25519_pk,
                mlkem_ciphertext: None,
            };
            Ok(HybridBeginResponse {
                enc: hex::encode(enc.to_bytes()),
                ss_id,
            })
        }
        HybridPublicBundle::Hybrid { x25519, mlkem } => {
            let their_x25519_pk = x25519_dalek::PublicKey::from(x25519);
            let ecdh = our_sk.diffie_hellman(&their_x25519_pk);
            let their_mlkem_pk = crate::pq::MlKem768PublicKey::from_bytes(&mlkem)
                .map_err(|e| format!("Invalid ML-KEM PK: {e}"))?;
            let enc_obj = crate::pq::MlKem768Encapsulation::encapsulate(&their_mlkem_pk);
            let combined = combine_secrets(ecdh.as_bytes(), &enc_obj.shared_secret)
                .map_err(|e| format!("Combine failed: {e}"))?;
            let ss_id = insert_ss(&state, combined)?;
            let enc = HybridEncapsulation {
                mode: HybridMode::Hybrid,
                x25519_public: our_x25519_pk,
                mlkem_ciphertext: Some(enc_obj.ciphertext),
            };
            Ok(HybridBeginResponse {
                enc: hex::encode(enc.to_bytes()),
                ss_id,
            })
        }
    }
}

/// Responder: derive the same combined secret from an initiator payload.
///
/// Loads our X25519 secret (and ML-KEM secret in hybrid mode) from the
/// encrypted KeyStore, performs ECDH + decapsulation, then stores the
/// combined 64-byte secret under a fresh ss_id.
#[tauri::command]
pub fn hybrid_accept(
    state: State<CryptoState>,
    key_id: String,
    enc_hex: String,
) -> Result<HybridAcceptResponse, String> {
    let enc_bytes =
        hex::decode(&enc_hex).map_err(|e| format!("Invalid hex in enc payload: {e}"))?;
    let enc =
        HybridEncapsulation::from_bytes(&enc_bytes).map_err(|e| format!("Bad enc payload: {e}"))?;

    // Load X25519 secret half.
    let x_id = format!("{key_id}-x");
    let mut x_sk_bytes = {
        let store = state.key_store.lock().map_err(|e| e.to_string())?;
        store.load_secret_key(&x_id)?
    };
    if x_sk_bytes.len() != 32 {
        x_sk_bytes.zeroize();
        return Err(format!(
            "Invalid X25519 secret key length: expected 32, got {}",
            x_sk_bytes.len()
        ));
    }
    let x_sk =
        x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(x_sk_bytes.as_slice()).unwrap());
    x_sk_bytes.zeroize();

    let secret = match (enc.mode, enc.mlkem_ciphertext) {
        (HybridMode::Classic, None) => {
            let their_pk = x25519_dalek::PublicKey::from(enc.x25519_public);
            let ecdh = x_sk.diffie_hellman(&their_pk);
            let mut secret = [0u8; 64];
            secret[..32].copy_from_slice(ecdh.as_bytes());
            secret
        }
        (HybridMode::Hybrid, Some(ct)) => {
            // ML-KEM half
            let m_id = format!("{key_id}-m");
            let mut m_sk_bytes = {
                let store = state.key_store.lock().map_err(|e| e.to_string())?;
                store.load_secret_key(&m_id)?
            };
            if m_sk_bytes.len() != MLKEM768_SK_SIZE {
                m_sk_bytes.zeroize();
                return Err(format!(
                    "Invalid ML-KEM secret key length: expected {MLKEM768_SK_SIZE}, got {}",
                    m_sk_bytes.len()
                ));
            }
            let m_sk = <[u8; MLKEM768_SK_SIZE]>::try_from(m_sk_bytes.as_slice()).unwrap();
            m_sk_bytes.zeroize();
            let mlkem_ss = crate::pq::mlkem768_decapsulate_bytes(&m_sk, &ct);

            // X25519 half
            let their_pk = x25519_dalek::PublicKey::from(enc.x25519_public);
            let ecdh = x_sk.diffie_hellman(&their_pk);
            combine_secrets(ecdh.as_bytes(), &mlkem_ss)
                .map_err(|e| format!("Combine failed: {e}"))?
        }
        (HybridMode::Classic, Some(_)) => {
            return Err("Protocol error: classic mode with ML-KEM ciphertext".into());
        }
        (HybridMode::Hybrid, None) => {
            return Err("Protocol error: hybrid mode without ML-KEM ciphertext".into());
        }
    };

    let ss_id = insert_ss(&state, secret)?;
    Ok(HybridAcceptResponse { ss_id })
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq::MLKEM768_CT_SIZE;
    use tauri::Manager;

    type MockApp = tauri::App<tauri::test::MockRuntime>;

    macro_rules! st {
        ($app:expr) => {
            $app.state::<crate::commands::CryptoState>()
        };
    }

    fn build_app() -> (tempfile::TempDir, MockApp) {
        let dir = tempfile::TempDir::new().unwrap();
        let state = CryptoState::new(dir.path().to_path_buf()).unwrap();
        let app = tauri::test::mock_builder()
            .manage(state)
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        (dir, app)
    }

    #[test]
    fn test_keygen_classic_bundle_roundtrip() {
        let (_dir, app) = build_app();
        let resp = hybrid_keygen(st!(app), "classic".to_string()).unwrap();
        assert_eq!(resp.mode, "classic");
        let bytes = hex::decode(&resp.bundle).unwrap();
        assert_eq!(bytes.len(), 33); // 0x01 + 32-byte X25519 pk
        let bundle = HybridPublicBundle::from_bytes(&bytes).unwrap();
        assert_eq!(bundle.mode(), HybridMode::Classic);
    }

    #[test]
    fn test_keygen_hybrid_bundle_roundtrip() {
        let (_dir, app) = build_app();
        let resp = hybrid_keygen(st!(app), "hybrid".to_string()).unwrap();
        assert_eq!(resp.mode, "hybrid");
        let bytes = hex::decode(&resp.bundle).unwrap();
        assert_eq!(bytes.len(), 1 + 32 + MLKEM768_PK_SIZE);
        let bundle = HybridPublicBundle::from_bytes(&bytes).unwrap();
        assert_eq!(bundle.mode(), HybridMode::Hybrid);
    }

    #[test]
    fn test_invalid_mode_rejected() {
        let (_dir, app) = build_app();
        let err = hybrid_keygen(st!(app), "quantum".to_string()).unwrap_err();
        assert!(err.contains("Invalid hybrid mode"));
    }

    #[test]
    fn test_hybrid_begin_accept_roundtrip() {
        let (_dir_a, app_b) = build_app(); // responder side holds keypair
        let (_dir_b, app_a) = build_app(); // initiator side

        // Bob generates a hybrid keypair, publishes bundle.
        let bob = hybrid_keygen(st!(app_b), "hybrid".to_string()).unwrap();

        // Alice begins toward Bob's bundle.
        let alice = hybrid_begin(st!(app_a), bob.bundle.clone()).unwrap();
        let enc_bytes = hex::decode(&alice.enc).unwrap();
        assert_eq!(enc_bytes.len(), 1 + 32 + MLKEM768_CT_SIZE);
        let enc = HybridEncapsulation::from_bytes(&enc_bytes).unwrap();
        assert_eq!(enc.mode, HybridMode::Hybrid);
        assert!(enc.mlkem_ciphertext.is_some());

        // Bob accepts Alice's encapsulation with his stored key_id.
        let bob_resp = hybrid_accept(st!(app_b), bob.key_id.clone(), alice.enc.clone()).unwrap();

        // Both sides must have derived the same combined secret.
        let alice_ss = {
            let st_a = app_a.state::<CryptoState>();
            let sa = st_a.shared_secrets.lock().unwrap();
            *sa.get(&alice.ss_id).expect("alice ss_id present")
        };
        let bob_ss = {
            let st_b = app_b.state::<CryptoState>();
            let sb = st_b.shared_secrets.lock().unwrap();
            *sb.get(&bob_resp.ss_id).expect("bob ss_id present")
        };
        assert_eq!(alice_ss, bob_ss);
    }

    #[test]
    fn test_classic_begin_accept_roundtrip() {
        let (_dir_a, app_b) = build_app();
        let (_dir_b, app_a) = build_app();

        let bob = hybrid_keygen(st!(app_b), "classic".to_string()).unwrap();
        let alice = hybrid_begin(st!(app_a), bob.bundle.clone()).unwrap();
        let enc_bytes = hex::decode(&alice.enc).unwrap();
        assert_eq!(enc_bytes.len(), 33); // 0x01 + 32
        let bob_resp = hybrid_accept(st!(app_b), bob.key_id.clone(), alice.enc.clone()).unwrap();

        let alice_ss = {
            let st_a = app_a.state::<CryptoState>();
            let sa = st_a.shared_secrets.lock().unwrap();
            *sa.get(&alice.ss_id).unwrap()
        };
        let bob_ss = {
            let st_b = app_b.state::<CryptoState>();
            let sb = st_b.shared_secrets.lock().unwrap();
            *sb.get(&bob_resp.ss_id).unwrap()
        };
        assert_eq!(alice_ss, bob_ss);
    }

    #[test]
    fn test_hybrid_accept_missing_key_fails() {
        let (_dir, app) = build_app();
        // Well-formed classic enc payload (0x01 + 32 zero bytes), but no
        // keypair was ever generated — accept must fail at loading <id>-x.
        let enc_hex = "01".to_string() + &"00".repeat(32);
        let err = hybrid_accept(st!(app), "ghost-key".to_string(), enc_hex).unwrap_err();
        assert!(err.contains("Key not found"), "got: {err}");
    }

    #[test]
    fn test_hybrid_accept_malformed_enc_fails() {
        let (_dir, app) = build_app();
        // Truncated classic enc (0x01 + only 1 byte) fails at parse.
        let err = hybrid_accept(st!(app), "k".to_string(), "01aa".to_string()).unwrap_err();
        assert!(err.contains("expected 33 bytes"), "got: {err}");
    }
}
