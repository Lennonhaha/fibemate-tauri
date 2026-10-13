//! Command-layer tests for the SM2 command surface (`sm2_cmd.rs`).
//!
//! These exercise the `#[tauri::command]` boundary only: argument handling,
//! hex wire formats, round-trips and error paths. No business logic is
//! changed, and no private-key material is asserted on — only opaque handles
//! and hex outputs, mirroring the style of `ipc_tests.rs`.
//!
//! Rationale: `sm2_cmd.rs` (12 commands) previously had no test coverage of
//! its own — the SM2 primitives in `sm2.rs` are unit-tested, but the command
//! wrappers (key store plumbing, hex parsing, range checks, `_full` variants)
//! were not. These tests cover that seam.

use tauri::Manager;

use crate::commands::{sm2_cmd, CryptoState};

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

/// A 32-byte digest in hex — the shape `sm2_sign` expects.
fn digest_hex() -> String {
    "ab".repeat(32)
}

/// Flip one hex digit of a 64-char signature component, keeping it valid hex.
fn tamper_hex(hex_str: &str) -> String {
    let mut chars: Vec<char> = hex_str.chars().collect();
    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
    chars.into_iter().collect()
}

// ── sm2_generate / sm2_get_public ───────────────────────────────

#[test]
fn sm2_generate_returns_uncompressed_public_key() {
    let (_dir, app) = build_app();
    let k = sm2_cmd::sm2_generate(st(&app)).unwrap();

    assert!(!k.key_id.is_empty(), "key_id must be an opaque handle");
    assert_eq!(
        k.public_key_hex.len(),
        130,
        "04||x||y uncompressed = 130 hex chars"
    );
    assert!(k.public_key_hex.starts_with("04"));
}

#[test]
fn sm2_get_public_matches_generate() {
    let (_dir, app) = build_app();
    let generated = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let fetched = sm2_cmd::sm2_get_public(st(&app), generated.key_id.clone()).unwrap();

    assert_eq!(fetched.key_id, generated.key_id);
    assert_eq!(fetched.public_key_hex, generated.public_key_hex);
}

#[test]
fn sm2_get_public_unknown_key_rejected() {
    let (_dir, app) = build_app();
    assert!(sm2_cmd::sm2_get_public(st(&app), "no-such-key".into()).is_err());
}

// ── sm2_sign / sm2_verify ───────────────────────────────────────

#[test]
fn sm2_sign_verify_roundtrip() {
    let (_dir, app) = build_app();
    let k = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let hash = digest_hex();

    let sig = sm2_cmd::sm2_sign(st(&app), k.key_id.clone(), hash.clone()).unwrap();
    assert_eq!(sig.r.len(), 64);
    assert_eq!(sig.s.len(), 64);

    let res = sm2_cmd::sm2_verify(k.public_key_hex.clone(), hash, sig.r, sig.s).unwrap();
    assert!(res.valid, "a freshly produced signature must verify");
}

#[test]
fn sm2_verify_tampered_signature_is_false() {
    let (_dir, app) = build_app();
    let k = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let hash = digest_hex();
    let sig = sm2_cmd::sm2_sign(st(&app), k.key_id.clone(), hash.clone()).unwrap();

    let bad = sm2_cmd::sm2_verify(
        k.public_key_hex.clone(),
        hash.clone(),
        tamper_hex(&sig.r),
        sig.s.clone(),
    )
    .unwrap();
    assert!(!bad.valid, "tampered r must not verify");

    let bad_s = sm2_cmd::sm2_verify(k.public_key_hex, hash, sig.r, tamper_hex(&sig.s)).unwrap();
    assert!(!bad_s.valid, "tampered s must not verify");
}

#[test]
fn sm2_verify_wrong_key_is_false() {
    let (_dir, app) = build_app();
    let a = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let b = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let hash = digest_hex();

    let sig = sm2_cmd::sm2_sign(st(&app), a.key_id.clone(), hash.clone()).unwrap();
    let res = sm2_cmd::sm2_verify(b.public_key_hex, hash, sig.r, sig.s).unwrap();
    assert!(
        !res.valid,
        "signature must not verify under an unrelated key"
    );
}

#[test]
fn sm2_sign_rejects_unknown_key() {
    let (_dir, app) = build_app();
    assert!(sm2_cmd::sm2_sign(st(&app), "no-such-key".into(), digest_hex()).is_err());
}

// ── sm2_import ──────────────────────────────────────────────────

#[test]
fn sm2_import_roundtrips_and_signs() {
    let (_dir, app) = build_app();
    // d = 1 is the smallest valid scalar (public key = G).
    let imported = sm2_cmd::sm2_import(st(&app), "01".into()).unwrap();
    assert_eq!(imported.public_key_hex.len(), 130);

    let hash = digest_hex();
    let sig = sm2_cmd::sm2_sign(st(&app), imported.key_id.clone(), hash.clone()).unwrap();
    assert!(
        sm2_cmd::sm2_verify(imported.public_key_hex.clone(), hash, sig.r, sig.s)
            .unwrap()
            .valid
    );

    // Re-deriving the public key from the stored scalar must agree.
    let derived = sm2_cmd::sm2_get_public(st(&app), imported.key_id).unwrap();
    assert_eq!(derived.public_key_hex, imported.public_key_hex);
}

#[test]
fn sm2_import_rejects_out_of_range_and_bad_hex() {
    let (_dir, app) = build_app();

    // d = 0 is outside [1, n-1].
    let zero = sm2_cmd::sm2_import(st(&app), "00".into())
        .err()
        .expect("d = 0 must be rejected");
    assert!(zero.contains("out of range"), "unexpected error: {zero}");

    // 33 bytes of 0xff exceeds n (a 256-bit value).
    let too_big = sm2_cmd::sm2_import(st(&app), "ff".repeat(33))
        .err()
        .expect("d > n must be rejected");
    assert!(
        too_big.contains("out of range"),
        "unexpected error: {too_big}"
    );

    // Non-hex input must be rejected before any key is stored.
    let bad = sm2_cmd::sm2_import(st(&app), "zz-not-hex".into())
        .err()
        .expect("non-hex input must be rejected");
    assert!(bad.contains("Invalid private key hex"), "unexpected: {bad}");
}

// ── sm2_ecdh ────────────────────────────────────────────────────

#[test]
fn sm2_ecdh_both_sides_derive_the_same_secret() {
    let (_dir_a, app_a) = build_app();
    let (_dir_b, app_b) = build_app();

    let a = sm2_cmd::sm2_generate(st(&app_a)).unwrap();
    let b = sm2_cmd::sm2_generate(st(&app_b)).unwrap();

    let ss_a = sm2_cmd::sm2_ecdh(st(&app_a), a.key_id.clone(), b.public_key_hex.clone()).unwrap();
    let ss_b = sm2_cmd::sm2_ecdh(st(&app_b), b.key_id.clone(), a.public_key_hex.clone()).unwrap();

    assert_ne!(ss_a.ss_id, ss_b.ss_id, "each side mints its own handle");

    let secrets_a = app_a.state::<CryptoState>();
    let secrets_a = secrets_a.shared_secrets.lock().unwrap();
    let secrets_b = app_b.state::<CryptoState>();
    let secrets_b = secrets_b.shared_secrets.lock().unwrap();

    let ka = format!("sm2:{}", ss_a.ss_id);
    let kb = format!("sm2:{}", ss_b.ss_id);
    assert_eq!(
        secrets_a.get(&ka),
        secrets_b.get(&kb),
        "ECDH must agree on both sides"
    );
    assert!(secrets_a.contains_key(&ka), "secret stored under ss handle");
}

#[test]
fn sm2_ecdh_rejects_bad_peer_key() {
    let (_dir, app) = build_app();
    let k = sm2_cmd::sm2_generate(st(&app)).unwrap();

    // Wrong length / non-hex peer public keys must fail, not panic.
    assert!(sm2_cmd::sm2_ecdh(st(&app), k.key_id.clone(), "04ab".into()).is_err());
    assert!(sm2_cmd::sm2_ecdh(st(&app), k.key_id, "zz".repeat(65)).is_err());
}

// ── sm2_encrypt / sm2_decrypt (simplified C1C2) ─────────────────

#[test]
fn sm2_encrypt_decrypt_roundtrip() {
    let (_dir, app) = build_app();
    let k = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let message = "fibemate sm2".to_string();

    let ct = sm2_cmd::sm2_encrypt(k.public_key_hex.clone(), message.clone()).unwrap();
    let pt = sm2_cmd::sm2_decrypt(st(&app), k.key_id.clone(), ct.c1, ct.c2).unwrap();
    assert_eq!(pt.plaintext, message);
}

#[test]
fn sm2_decrypt_simplified_mode_never_recovers_another_keys_message() {
    let (_dir, app) = build_app();
    let a = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let b = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let message = "secret payload".to_string();

    let ct = sm2_cmd::sm2_encrypt(a.public_key_hex.clone(), message.clone()).unwrap();
    let recovered = sm2_cmd::sm2_decrypt(st(&app), b.key_id, ct.c1, ct.c2);

    // The simplified C1C2 mode carries no integrity tag (unlike `_full`), so a
    // wrong key yields either a UTF-8 error or a different plaintext — but the
    // original message must never come back.
    assert!(
        !matches!(&recovered, Ok(pt) if pt.plaintext == message),
        "wrong key must not recover the message"
    );
}

// ── sm2_encrypt_full / sm2_decrypt_full (GB/T 32918.4) ──────────

#[test]
fn sm2_encrypt_full_decrypt_full_roundtrip() {
    let (_dir, app) = build_app();
    let k = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let message = "国密 SM2 标准模式".to_string();

    let ct = sm2_cmd::sm2_encrypt_full(k.public_key_hex.clone(), message.clone()).unwrap();
    let pt = sm2_cmd::sm2_decrypt_full(st(&app), k.key_id.clone(), ct.ciphertext).unwrap();
    assert_eq!(pt.plaintext, message);
}

#[test]
fn sm2_decrypt_full_rejects_tampered_ciphertext() {
    let (_dir, app) = build_app();
    let k = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let ct = sm2_cmd::sm2_encrypt_full(k.public_key_hex, "integrity".into()).unwrap();

    // Flip a hex digit inside C2 (the last character) — C3 must fail.
    let mut chars: Vec<char> = ct.ciphertext.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '0' { '1' } else { '0' };
    let tampered: String = chars.into_iter().collect();

    let err = sm2_cmd::sm2_decrypt_full(st(&app), k.key_id, tampered)
        .err()
        .expect("tampered ciphertext must be rejected");
    assert!(err.contains("C3"), "expected integrity failure, got: {err}");
}

#[test]
fn sm2_decrypt_full_rejects_malformed_ciphertext() {
    let (_dir, app) = build_app();
    let k = sm2_cmd::sm2_generate(st(&app)).unwrap();

    assert!(sm2_cmd::sm2_decrypt_full(st(&app), k.key_id.clone(), "ab".into()).is_err());
    assert!(sm2_cmd::sm2_decrypt_full(st(&app), k.key_id, "zz".repeat(100)).is_err());
}

// ── sm2_sign_full / sm2_verify_full (ZA-bound) ──────────────────

#[test]
fn sm2_sign_full_verify_full_roundtrip() {
    let (_dir, app) = build_app();
    let k = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let message = "ZA-bound message".to_string();

    let sig = sm2_cmd::sm2_sign_full(st(&app), k.key_id.clone(), message.clone(), None).unwrap();
    let res = sm2_cmd::sm2_verify_full(
        k.public_key_hex.clone(),
        message.clone(),
        sig.r.clone(),
        sig.s.clone(),
        None,
    )
    .unwrap();
    assert!(res.valid, "default (frontend) user id must round-trip");

    // The same default id, passed explicitly, must also verify.
    let res_explicit = sm2_cmd::sm2_verify_full(
        k.public_key_hex.clone(),
        message.clone(),
        sig.r.clone(),
        sig.s.clone(),
        Some("1234567812345678".into()),
    )
    .unwrap();
    assert!(res_explicit.valid, "explicit default user id must match");
}

#[test]
fn sm2_verify_full_rejects_wrong_user_id() {
    let (_dir, app) = build_app();
    let k = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let message = "bound to one ZA".to_string();

    let sig = sm2_cmd::sm2_sign_full(st(&app), k.key_id, message.clone(), None).unwrap();
    let res = sm2_cmd::sm2_verify_full(
        k.public_key_hex,
        message,
        sig.r,
        sig.s,
        Some("someone.else".into()),
    )
    .unwrap();
    assert!(!res.valid, "ZA binding must be enforced across user ids");
}

#[test]
fn sm2_sign_full_custom_user_id_roundtrip() {
    let (_dir, app) = build_app();
    let k = sm2_cmd::sm2_generate(st(&app)).unwrap();
    let message = "custom uid".to_string();
    let uid = "alice@fibemate.net".to_string();

    let sig =
        sm2_cmd::sm2_sign_full(st(&app), k.key_id, message.clone(), Some(uid.clone())).unwrap();
    let res = sm2_cmd::sm2_verify_full(k.public_key_hex, message, sig.r, sig.s, Some(uid)).unwrap();
    assert!(res.valid, "custom user id must round-trip");
}
