//! Persistence / crash-recovery tests (P1) — FIBEMATE
//!
//! Proves the on-disk layers survive corruption, tampering, partial writes,
//! and process restarts. Covers three tiers:
//!
//!   * **KeyStore** — device.key, keys/*.enc, key_meta.json
//!   * **SessionManager** — sessions.json (plaintext v2 + encrypted v3)
//!   * **CryptoState** — end-to-end restart through the real `new()` path
//!
//! Design notes:
//!
//!   * We exercise the **public** API and the **known on-disk layout**, injecting
//!     corruption by writing bad bytes directly to the file — this is what a
//!     crash (torn write), a disk error, or an attacker would actually produce.
//!   * AES-256-GCM provides *confidentiality + integrity*: flipping a single
//!     ciphertext byte must fail decryption, not silently return garbage.
//!   * AAD (`fibemate-sessions-enc-v1`) binds the session blob to its format, so
//!     even a valid-GCM ciphertext written under a different context is rejected.

use std::fs;

use crate::commands::CryptoState;
use crate::double_ratchet::{
    derive_session_enc_key, load_sessions_from_disk, load_sessions_from_disk_decrypted,
    load_sessions_with_migration, SessionManager,
};
use crate::key_store::KeyStore;

// ── Constants (mirror of the on-disk layout) ───────────────────

const NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

/// Smallest valid encrypted blob: nonce (12) + tag (16).
const MIN_BLOB_LEN: usize = NONCE_LEN + GCM_TAG_LEN;

// ════════════════════════════════════════════════════════════════
// KeyStore — device.key corruption
// ════════════════════════════════════════════════════════════════

#[test]
fn device_key_wrong_length_returns_error() {
    // A torn write (crash mid-write) leaves a device.key of the wrong length.
    // `KeyStore::new` must surface this as an error, never silently
    // fabricate or reuse a truncated key.
    let dir = tempfile::TempDir::new().unwrap();
    let device_key = dir.path().join("device.key");
    fs::write(&device_key, b"torn-write-partial").unwrap();

    let result = KeyStore::new(dir.path());
    assert!(result.is_err(), "truncated device.key must fail init");
    let err = result.err().unwrap();
    assert!(
        err.contains("corrupt"),
        "error should flag corruption, got: {err}"
    );
}

#[test]
fn device_key_empty_file_returns_error() {
    // Zero-length device.key (empty file left by an aborted first run).
    let dir = tempfile::TempDir::new().unwrap();
    let device_key = dir.path().join("device.key");
    fs::write(&device_key, b"").unwrap();

    let result = KeyStore::new(dir.path());
    assert!(result.is_err(), "empty device.key must fail init");
}

// ════════════════════════════════════════════════════════════════
// KeyStore — key_meta.json corruption (graceful degradation)
// ════════════════════════════════════════════════════════════════

#[test]
fn key_meta_invalid_json_degrades_gracefully() {
    // `save_meta` uses a non-atomic `fs::write`; a crash mid-write leaves
    // half a JSON document. On reload the store must NOT panic — it degrades
    // to an empty metadata map (`serde_json::from_str(...).unwrap_or_default()`).
    let dir = tempfile::TempDir::new().unwrap();
    let meta = dir.path().join("key_meta.json");
    fs::write(&meta, r#"{"unterminated":"#).unwrap(); // torn JSON

    let store = KeyStore::new(dir.path()).expect("corrupt meta must not panic");
    assert!(
        store.list_keys().is_empty(),
        "corrupt metadata should degrade to empty map"
    );
}

#[test]
fn key_meta_truncated_json_degrades_gracefully() {
    // A longer torn write: valid prefix, cut off before completion.
    let dir = tempfile::TempDir::new().unwrap();
    let meta = dir.path().join("key_meta.json");
    fs::write(&meta, r#"{"some-key":{"key_id":"some-key","#).unwrap();

    let store = KeyStore::new(dir.path()).expect("torn meta must not panic");
    assert!(store.list_keys().is_empty());
}

// ════════════════════════════════════════════════════════════════
// KeyStore — keys/*.enc corruption (AES-GCM integrity)
// ════════════════════════════════════════════════════════════════

#[test]
fn encrypted_key_tamper_detected() {
    // Flip one ciphertext byte; AES-256-GCM must reject the file.
    let dir = tempfile::TempDir::new().unwrap();
    let mut store = KeyStore::new(dir.path()).unwrap();
    store
        .store_secret_key("crash-key-001", &[0xAA; 1184], &[0xBB; 2400], "fp")
        .unwrap();

    let key_path = dir.path().join("keys").join("crash-key-001.enc");
    let mut blob = fs::read(&key_path).unwrap();
    assert!(blob.len() > MIN_BLOB_LEN, "blob too small to tamper");
    // Flip a byte inside the ciphertext (past the 12-byte nonce).
    let idx = NONCE_LEN + 5;
    blob[idx] ^= 0xFF;
    fs::write(&key_path, &blob).unwrap();

    let result = store.load_secret_key("crash-key-001");
    assert!(result.is_err(), "tampered ciphertext must fail decryption");
}

#[test]
fn encrypted_key_truncation_detected() {
    // Truncate below nonce+tag; loader must reject as "too short".
    let dir = tempfile::TempDir::new().unwrap();
    let mut store = KeyStore::new(dir.path()).unwrap();
    store
        .store_secret_key("trunc-key", &[0xAA; 1184], &[0xBB; 2400], "fp")
        .unwrap();

    let key_path = dir.path().join("keys").join("trunc-key.enc");
    let blob = fs::read(&key_path).unwrap();
    fs::write(&key_path, &blob[..NONCE_LEN + 4]).unwrap(); // 16 bytes total

    let result = store.load_secret_key("trunc-key");
    assert!(result.is_err(), "truncated key file must fail");
    let err = result.unwrap_err();
    assert!(
        err.contains("corrupt") || err.contains("short"),
        "got: {err}"
    );
}

// ════════════════════════════════════════════════════════════════
// SessionManager — encrypted session file (v3) integrity
// ════════════════════════════════════════════════════════════════

/// Build a SessionManager with one live session, keyed by `enc_key`.
fn make_live_session() -> (SessionManager, [u8; 32]) {
    let sm = SessionManager::new();
    sm.create_session("bob", &[42u8; 32], true).unwrap();
    let enc_key = derive_session_enc_key(&[7u8; 32]);
    (sm, enc_key)
}

#[test]
fn encrypted_session_tamper_detected() {
    // Flip a ciphertext byte — AAD-bound AES-256-GCM must return Err,
    // distinguishing "tampered" from "no sessions".
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("sessions.json");
    let (sm, enc_key) = make_live_session();
    sm.save_to_disk_encrypted(&path, &enc_key).unwrap();

    let mut blob = fs::read(&path).unwrap();
    let idx = NONCE_LEN + 7;
    blob[idx] ^= 0x01;
    fs::write(&path, &blob).unwrap();

    let result = load_sessions_from_disk_decrypted(&path, &enc_key);
    assert!(
        result.is_err(),
        "tampered session blob must fail decryption (AAD)"
    );
}

#[test]
fn encrypted_session_nonce_tamper_detected() {
    // Flipping a nonce byte also invalidates the GCM tag.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("sessions.json");
    let (sm, enc_key) = make_live_session();
    sm.save_to_disk_encrypted(&path, &enc_key).unwrap();

    let mut blob = fs::read(&path).unwrap();
    blob[0] ^= 0x80;
    fs::write(&path, &blob).unwrap();

    assert!(load_sessions_from_disk_decrypted(&path, &enc_key).is_err());
}

#[test]
fn encrypted_session_truncation_detected() {
    // Below nonce+tag → explicit "too short" error, not silent empty.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("sessions.json");
    let (sm, enc_key) = make_live_session();
    sm.save_to_disk_encrypted(&path, &enc_key).unwrap();

    let blob = fs::read(&path).unwrap();
    fs::write(&path, &blob[..NONCE_LEN + 2]).unwrap();

    let result = load_sessions_from_disk_decrypted(&path, &enc_key);
    assert!(result.is_err(), "truncated session blob must fail");
}

#[test]
fn encrypted_session_wrong_key_fails() {
    // A device key from a different machine/user must never decrypt.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("sessions.json");
    let (sm, enc_key) = make_live_session();
    sm.save_to_disk_encrypted(&path, &enc_key).unwrap();

    let other_key = derive_session_enc_key(&[0xDE; 32]);
    assert!(
        load_sessions_from_disk_decrypted(&path, &other_key).is_err(),
        "wrong device key must not decrypt session blob"
    );
}

// ════════════════════════════════════════════════════════════════
// SessionManager — atomic write / stale tmp recovery
// ════════════════════════════════════════════════════════════════

#[test]
fn atomic_save_consumes_stale_tmp() {
    // A crash can leave a stale `sessions.tmp` behind. The next save must
    // overwrite it and `rename` it into place, so no stale bytes survive.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("sessions.json");
    let tmp = dir.path().join("sessions.tmp");

    // Simulate a leftover tmp from a previous crash.
    fs::write(&tmp, b"stale-tmp-garbage").unwrap();

    let (sm, enc_key) = make_live_session();
    sm.save_to_disk_encrypted(&path, &enc_key).unwrap();

    assert!(path.exists(), "sessions.json must be written");
    assert!(
        !tmp.exists(),
        "atomic rename must consume the stale .tmp file"
    );

    // The surviving file is valid and decrypts to the one session.
    let sessions = load_sessions_from_disk_decrypted(&path, &enc_key).unwrap();
    assert_eq!(sessions.len(), 1);
    assert!(sessions.contains_key("bob"));
}

#[test]
fn stale_tmp_alone_does_not_break_load() {
    // If only a .tmp exists (crash before rename), the loader must treat
    // the real path as absent and return a clean empty map.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("sessions.json");
    let tmp = dir.path().join("sessions.tmp");
    fs::write(&tmp, b"orphaned-tmp").unwrap();

    let enc_key = derive_session_enc_key(&[7u8; 32]);
    let sessions = load_sessions_from_disk_decrypted(&path, &enc_key).unwrap();
    assert!(sessions.is_empty(), "orphaned tmp must not yield sessions");
}

// ════════════════════════════════════════════════════════════════
// SessionManager — version mismatch & corrupt plaintext (v2)
// ════════════════════════════════════════════════════════════════

#[test]
fn session_version_mismatch_discards() {
    // A file tagged with an unrecognized version must be discarded (forces a
    // re-handshake) rather than loaded with potentially-diverged chain keys.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("sessions.json");

    // Write a valid plaintext v2 file, then bump its version tag.
    let (sm, _enc_key) = make_live_session();
    sm.save_to_disk(&path).unwrap();

    let content = fs::read_to_string(&path).unwrap();
    let mut val: serde_json::Value = serde_json::from_str(&content).unwrap();
    val["v"] = serde_json::Value::String("999999".to_string());
    fs::write(&path, serde_json::to_string(&val).unwrap()).unwrap();

    let sessions = load_sessions_from_disk(&path);
    assert!(
        sessions.is_empty(),
        "unrecognized version must discard all sessions"
    );
}

#[test]
fn corrupt_plaintext_session_start_fresh() {
    // Torn plaintext JSON must be swallowed (logged, not panic), leaving a
    // clean slate — while preserving the corrupt file for manual recovery.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("sessions.json");
    fs::write(&path, b"{\"v\":\"2\",\"sessions\":{").unwrap();

    let sessions = load_sessions_from_disk(&path);
    assert!(sessions.is_empty(), "corrupt plaintext must yield empty");
    assert!(path.exists(), "corrupt file must be preserved for recovery");
}

#[test]
fn missing_session_file_yields_empty() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("sessions.json");
    let enc_key = derive_session_enc_key(&[7u8; 32]);

    let (sessions, needs_migration) = load_sessions_with_migration(&path, &enc_key);
    assert!(sessions.is_empty());
    assert!(!needs_migration, "no file means no migration");
}

// ════════════════════════════════════════════════════════════════
// CryptoState — end-to-end restart (real `new()` path)
// ════════════════════════════════════════════════════════════════

#[test]
fn cryptostate_recovers_sessions_after_restart() {
    // Full integration: create a session, persist, drop the state, then
    // re-initialize via `CryptoState::new` and confirm the session survives.
    let dir = tempfile::TempDir::new().unwrap();
    let app_data = dir.path().to_path_buf();

    {
        let state = CryptoState::new(app_data.clone()).unwrap();
        state
            .sessions
            .lock()
            .unwrap()
            .create_session("bob", &[42u8; 32], true)
            .unwrap();
        state.save_sessions_to_disk().unwrap();
    }

    // "Restart" the app.
    let state2 = CryptoState::new(app_data).unwrap();
    let has = state2.sessions.lock().unwrap().has_session("bob").unwrap();
    assert!(
        has,
        "session must survive a restart through CryptoState::new"
    );
}

#[test]
fn cryptostate_survives_corrupt_session_file_on_startup() {
    // A corrupt sessions.json at startup must NOT crash the app. `new()`
    // degrades to a clean state and stays usable (can create a new session).
    let dir = tempfile::TempDir::new().unwrap();
    let app_data = dir.path().to_path_buf();

    // Pre-seed a corrupt session file.
    let sessions_path = app_data.join("sessions.json");
    fs::write(&sessions_path, vec![0xFFu8; 64]).unwrap(); // 64 random bytes

    let state = CryptoState::new(app_data).expect("corrupt session file must not crash startup");

    // The store is usable: we can create and persist a fresh session.
    state
        .sessions
        .lock()
        .unwrap()
        .create_session("fresh", &[9u8; 32], true)
        .unwrap();
    state.save_sessions_to_disk().unwrap();
    assert!(state.sessions.lock().unwrap().has_session("fresh").unwrap());
}
