//! Command-layer tests for the session / key-administration surface.
//!
//! Covers the `#[tauri::command]` wrappers that `ipc_tests.rs` does not
//! exercise: session administration (`dr_list_sessions`, `dr_session_exists`,
//! `dr_get_send_key`, `dr_revoke_session`, `dr_delete_session`), key listing
//! (`kem_list_keys`, `ik_list`), signed-pre-key rotation (`spk_rotate`), the
//! userId → identity mapping (`get_identity_for_user`) and the destructive
//! `keystore_selfdestruct` confirmation gate.
//!
//! Only public command functions are called; no business logic is modified and
//! no secret material is asserted on (opaque handles / public hex only).

use tauri::Manager;

use crate::commands::{identity, kem, ratchet, CryptoState};

// ── Test helpers ────────────────────────────────────────────────

type MockApp = tauri::App<tauri::test::MockRuntime>;

/// Build a mock Tauri app with an isolated `CryptoState` (temp dir).
fn build_app() -> (tempfile::TempDir, MockApp) {
    let dir = tempfile::TempDir::new().unwrap();
    let state = CryptoState::new(dir.path().to_path_buf()).unwrap();
    let app = tauri::test::mock_builder()
        .manage(state)
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    (dir, app)
}

/// Re-fetch a fresh `State<CryptoState>` handle (`State` is not `Copy`).
fn st(app: &MockApp) -> tauri::State<'_, CryptoState> {
    app.state::<CryptoState>()
}

/// Stash a shared secret under `ss_id` and initialize a DR session from it,
/// returning the session id (== `ss_id`).
fn seed_session(app: &MockApp, ss_id: &str) -> String {
    {
        let state = app.state::<CryptoState>();
        let mut secrets = state.shared_secrets.lock().unwrap();
        secrets.insert(ss_id.to_string(), [42u8; 32]);
    }
    ratchet::dr_init(st(app), ss_id.to_string(), "peer".into(), true, None, None)
        .unwrap()
        .session_id
}

/// Path of the app-data directory that `keystore_selfdestruct` targets.
fn app_data_dir(app: &MockApp) -> std::path::PathBuf {
    app.state::<CryptoState>()
        .sessions_path
        .parent()
        .unwrap()
        .to_path_buf()
}

// ── Session administration ──────────────────────────────────────

#[test]
fn dr_list_sessions_tracks_created_sessions() {
    let (_dir, app) = build_app();
    assert!(ratchet::dr_list_sessions(st(&app)).unwrap().is_empty());

    let sid = seed_session(&app, "ss-list");
    let listed = ratchet::dr_list_sessions(st(&app)).unwrap();
    assert_eq!(listed, vec![sid], "the created session must be listed");
}

#[test]
fn dr_session_exists_reflects_state() {
    let (_dir, app) = build_app();
    assert!(!ratchet::dr_session_exists(st(&app), "ss-x".into()).unwrap());

    let sid = seed_session(&app, "ss-x");
    assert!(ratchet::dr_session_exists(st(&app), sid).unwrap());
}

#[test]
fn dr_get_send_key_matches_dr_init_public_key() {
    let (_dir, app) = build_app();
    {
        let state = app.state::<CryptoState>();
        let mut secrets = state.shared_secrets.lock().unwrap();
        secrets.insert("ss-key".into(), [7u8; 32]);
    }
    let init =
        ratchet::dr_init(st(&app), "ss-key".into(), "peer".into(), true, None, None).unwrap();

    let send_key = ratchet::dr_get_send_key(st(&app), init.session_id).unwrap();
    assert_eq!(send_key, init.our_public_key);
    assert_eq!(send_key.len(), 64, "X25519 public key = 32 bytes hex");
}

#[test]
fn dr_get_send_key_unknown_session_rejected() {
    let (_dir, app) = build_app();
    assert!(ratchet::dr_get_send_key(st(&app), "no-such-session".into()).is_err());
}

#[test]
fn dr_revoke_session_removes_session_and_key() {
    let (_dir, app) = build_app();
    let sid = seed_session(&app, "ss-revoke");
    assert!(ratchet::dr_session_exists(st(&app), sid.clone()).unwrap());

    assert!(ratchet::dr_revoke_session(st(&app), sid.clone()).is_ok());

    assert!(!ratchet::dr_session_exists(st(&app), sid.clone()).unwrap());
    assert!(!ratchet::dr_list_sessions(st(&app)).unwrap().contains(&sid));
    assert!(
        ratchet::dr_get_send_key(st(&app), sid).is_err(),
        "revoked session must no longer expose a send key"
    );
}

#[test]
fn dr_revoke_unknown_session_does_not_disturb_state() {
    let (_dir, app) = build_app();
    let sid = seed_session(&app, "ss-keep");

    assert!(ratchet::dr_revoke_session(st(&app), "ghost-session".into()).is_ok());
    assert_eq!(
        ratchet::dr_list_sessions(st(&app)).unwrap(),
        vec![sid],
        "revoking an unknown id must be a no-op"
    );
}

#[test]
fn dr_delete_session_removes_session() {
    let (_dir, app) = build_app();
    let sid = seed_session(&app, "ss-delete");

    assert!(ratchet::dr_delete_session(st(&app), sid.clone()).is_ok());

    assert!(!ratchet::dr_session_exists(st(&app), sid.clone()).unwrap());
    assert!(ratchet::dr_list_sessions(st(&app)).unwrap().is_empty());
}

// ── Key listing ─────────────────────────────────────────────────

#[test]
fn kem_list_keys_tracks_generated_keys() {
    let (_dir, app) = build_app();
    assert!(kem::kem_list_keys(st(&app)).unwrap().is_empty());

    let k = kem::kem_keygen(st(&app)).unwrap();
    let listed = kem::kem_list_keys(st(&app)).unwrap();

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].key_id, k.key_id);
    assert_eq!(listed[0].public_key, k.public_key);
    assert_eq!(listed[0].fingerprint, k.fingerprint);
}

#[test]
fn ik_list_tracks_identities_only() {
    let (_dir, app) = build_app();
    assert!(identity::ik_list(st(&app)).unwrap().identities.is_empty());

    let a = identity::ik_generate(st(&app), Some("id-a".into())).unwrap();
    let b = identity::ik_generate(st(&app), Some("id-b".into())).unwrap();
    // A KEM key must not leak into the identity listing.
    let _kem = kem::kem_keygen(st(&app)).unwrap();

    let ids: Vec<String> = identity::ik_list(st(&app))
        .unwrap()
        .identities
        .into_iter()
        .map(|i| i.identity_id)
        .collect();
    assert_eq!(ids.len(), 2, "only identity keys are listed");
    assert!(ids.contains(&a.identity_id) && ids.contains(&b.identity_id));
}

// ── SPK rotation ────────────────────────────────────────────────

#[test]
fn spk_rotate_replaces_signed_prekey() {
    let (_dir, app) = build_app();
    let id = identity::ik_generate(st(&app), Some("alice".into()))
        .unwrap()
        .identity_id;

    let before = identity::spk_get_public(st(&app), id.clone()).unwrap();
    let rotated = identity::spk_rotate(st(&app), id.clone()).unwrap();

    assert_ne!(
        before.signed_prekey_hex, rotated.signed_prekey_hex,
        "rotation must mint a fresh SPK"
    );
    assert_ne!(before.signed_prekey_id, rotated.signed_prekey_id);
    assert_eq!(
        before.identity_pk_hex, rotated.identity_pk_hex,
        "the identity key itself must not rotate"
    );

    // The rotated bundle is what subsequent reads return.
    let after = identity::spk_get_public(st(&app), id).unwrap();
    assert_eq!(after.signed_prekey_hex, rotated.signed_prekey_hex);
    assert_eq!(after.signed_prekey_id, rotated.signed_prekey_id);
}

#[test]
fn spk_get_public_unknown_identity_rejected() {
    let (_dir, app) = build_app();
    assert!(identity::spk_get_public(st(&app), "no-such-id".into()).is_err());
}

// ── userId → identity mapping ───────────────────────────────────

#[test]
fn get_identity_for_user_is_stable_and_persisted() {
    let (_dir, app) = build_app();

    let first = identity::get_identity_for_user(st(&app), "user-1".into()).unwrap();
    let again = identity::get_identity_for_user(st(&app), "user-1".into()).unwrap();
    assert_eq!(first, again, "same userId must map to the same identity");

    let other = identity::get_identity_for_user(st(&app), "user-2".into()).unwrap();
    assert_ne!(first, other, "different users get distinct identities");

    // The mapping is persisted to disk next to sessions.json.
    let map_path = app_data_dir(&app).join("identity_map.json");
    let raw = std::fs::read_to_string(&map_path).expect("identity_map.json must exist");
    assert!(raw.contains("user-1") && raw.contains("user-2"));

    // A mapped identity really exists in the KeyStore.
    assert!(identity::ik_get_public(st(&app), first).is_ok());
}

// ── keystore_selfdestruct ───────────────────────────────────────

#[test]
fn keystore_selfdestruct_requires_exact_confirmation_phrase() {
    let (_dir, app) = build_app();
    let _id = identity::ik_generate(st(&app), Some("keep".into())).unwrap();

    for wrong in ["", "destroy all keys", "DESTROY ALL KEYS ", "DESTROY"] {
        let err = identity::keystore_selfdestruct(st(&app), wrong.into()).unwrap_err();
        assert!(
            err.contains("确认"),
            "unexpected error for {wrong:?}: {err}"
        );
    }

    // Nothing may be destroyed by a failed confirmation.
    assert_eq!(identity::ik_list(st(&app)).unwrap().identities.len(), 1);
}

#[test]
fn keystore_selfdestruct_wipes_sessions_keys_and_files() {
    let (_dir, app) = build_app();
    let id = identity::ik_generate(st(&app), Some("doomed".into()))
        .unwrap()
        .identity_id;
    let _sid = seed_session(&app, "ss-doomed");

    let app_data = app_data_dir(&app);
    for f in ["device.key", "sessions.json", "key_meta.json"] {
        assert!(
            app_data.join(f).exists(),
            "{f} should exist before destruction"
        );
    }

    let msg = identity::keystore_selfdestruct(st(&app), "DESTROY ALL KEYS".into()).unwrap();
    assert!(!msg.is_empty());

    // In-memory state is gone.
    assert!(ratchet::dr_list_sessions(st(&app)).unwrap().is_empty());
    assert!(kem::kem_list_keys(st(&app)).unwrap().is_empty());
    assert!(identity::ik_get_public(st(&app), id).is_err());

    // On-disk material is gone.
    for f in ["device.key", "sessions.json", "key_meta.json"] {
        assert!(
            !app_data.join(f).exists(),
            "{f} must be removed by self-destruct"
        );
    }
}
