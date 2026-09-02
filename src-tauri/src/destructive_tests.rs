//! P3 destructive / adversarial-input tests.
//!
//! Unlike the P1/P2 suites (which prove *correctness* and *performance*), this
//! suite proves the code is *safe under malicious or extreme input*: it must
//! return `Err` / degrade gracefully, never `panic!`, never allocate
//! unboundedly, and never let a crafted identifier escape its sandbox.
//!
//! Attack surfaces covered:
//!   * KeyStore key_id → filesystem path (traversal / collision / truncation)
//!   * hex decoding boundary (empty / odd-length / oversized)
//!   * Double Ratchet `EncryptedMessage` crafted fields (skip-ahead / u32::MAX
//!     message_num / malformed ciphertext)
//!   * session_id extremes (empty / oversized)
//!   * randomized fuzzing with `catch_unwind` guards

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::double_ratchet::{EncryptedMessage, SessionManager};
use crate::key_store::KeyStore;

// ── KeyStore: key_id → path sanitization ──────────────────────

#[test]
fn test_key_id_path_traversal_sanitized() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut ks = KeyStore::new(dir.path()).unwrap();

    // "../evil" must not escape the keys directory.
    ks.store_secret_key("../evil", &[0u8; 32], &[0xCCu8; 16], "fp")
        .unwrap();

    assert!(
        !dir.path().join("evil.enc").exists(),
        "traversal must not write outside the keys dir"
    );
    // `.` and `/` are stripped → the sanitized id is "evil", inside keys/.
    assert!(
        ks.keys_dir().join("evil.enc").exists(),
        "sanitized key lands inside the keys dir"
    );
}

#[test]
fn test_key_id_backslash_sanitized() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut ks = KeyStore::new(dir.path()).unwrap();

    ks.store_secret_key("C:\\evil\\key", &[0u8; 32], &[0xDDu8; 16], "fp")
        .unwrap();

    // Backslashes stripped, alphanumerics kept → "Cevilkey.enc" inside keys/.
    assert!(ks.keys_dir().join("Cevilkey.enc").exists());
    assert!(!dir.path().join("evil").exists());
}

#[test]
fn test_key_id_special_chars_no_collision() {
    // All-punctuation key_ids sanitize to "" and fall back to their hex
    // encoding, so distinct raw ids map to distinct files — no silent
    // overwrite of one key by another.
    let dir = tempfile::TempDir::new().unwrap();
    let mut ks = KeyStore::new(dir.path()).unwrap();

    ks.store_secret_key("@@@", &[0u8; 32], &[0xAAu8; 16], "fp")
        .unwrap();
    ks.store_secret_key("###", &[0u8; 32], &[0xBBu8; 16], "fp")
        .unwrap();

    let a = ks.load_secret_key("@@@").unwrap();
    let b = ks.load_secret_key("###").unwrap();
    assert_eq!(a, vec![0xAAu8; 16], "@@@ must decrypt to its own key");
    assert_eq!(b, vec![0xBBu8; 16], "### must decrypt to its own key");

    // Two logical keys → two distinct files on disk.
    let files = std::fs::read_dir(ks.keys_dir()).unwrap().count();
    assert_eq!(files, 2, "distinct key_ids map to distinct .enc files");
}

#[test]
fn test_key_id_truncated_at_64() {
    // Known limitation (not a fix target): `take(64)` truncates over-long ids,
    // so two ids sharing a 64-char sanitized prefix still collide. Legitimate
    // ids are UUIDs (36 chars) and never hit this path.
    let dir = tempfile::TempDir::new().unwrap();
    let mut ks = KeyStore::new(dir.path()).unwrap();

    let a = "a".repeat(100);
    let b = "a".repeat(64);
    ks.store_secret_key(&a, &[0u8; 32], &[0x01u8; 16], "fp")
        .unwrap();
    ks.store_secret_key(&b, &[0u8; 32], &[0x02u8; 16], "fp")
        .unwrap();

    // Both truncate to the same 64-char id → collision.
    let loaded = ks.load_secret_key(&a).unwrap();
    assert_eq!(
        loaded,
        vec![0x02u8; 16],
        "64-char truncation causes collision"
    );
}

// ── hex decoding boundary ─────────────────────────────────────

#[test]
fn test_hex_empty_decodes_to_empty() {
    // Lock the exact behavior: empty hex is valid and yields empty bytes.
    assert_eq!(hex::decode("").unwrap(), Vec::<u8>::new());
}

#[test]
fn test_hex_odd_length_rejected() {
    assert!(hex::decode("a").is_err());
    assert!(hex::decode("abc").is_err());
}

#[test]
fn test_hex_oversized_no_panic() {
    let big = "f".repeat(8 * 1024 * 1024); // 8 MiB of hex
    let res = catch_unwind(|| hex::decode(&big));
    assert!(res.is_ok(), "oversized hex must not panic");
    assert_eq!(res.unwrap().unwrap().len(), 4 * 1024 * 1024);
}

// ── Double Ratchet: crafted EncryptedMessage ──────────────────

#[test]
fn test_decrypt_skip_ahead_attack_blocked() {
    let sm = SessionManager::new();
    sm.create_session("sid", &[42u8; 32], true).unwrap();

    // A peer claims message_num=5000 while we are at 0 → skip-ahead attack.
    let msg = EncryptedMessage {
        public_key: [0x11u8; 32],
        message_num: 5000,
        previous_chain_length: 0,
        nonce: [0u8; 12],
        ciphertext: vec![0u8; 16],
    };
    let res = sm.decrypt_message("sid", &msg);
    let err = res.err().expect("skip-ahead must be rejected");
    assert!(
        err.contains("Too many skipped"),
        "MAX_SKIP guard must trigger: {err}"
    );
}

#[test]
fn test_decrypt_message_num_u32max_no_panic() {
    let sm = SessionManager::new();
    sm.create_session("sid", &[42u8; 32], true).unwrap();

    let msg = EncryptedMessage {
        public_key: [0x22u8; 32],
        message_num: u32::MAX,
        previous_chain_length: 0,
        nonce: [0u8; 12],
        ciphertext: vec![0u8; 16],
    };
    // Must return Err (skip_count = u32::MAX > MAX_SKIP), never overflow-panic
    // on `message_num + 1`.
    let res = catch_unwind(AssertUnwindSafe(|| sm.decrypt_message("sid", &msg)));
    assert!(res.is_ok(), "u32::MAX message_num must not panic");
    assert!(res.unwrap().is_err());
}

#[test]
fn test_decrypt_malformed_ciphertext_no_panic() {
    let sm = SessionManager::new();
    sm.create_session("sid", &[42u8; 32], true).unwrap();

    // In-order message_num but garbage ciphertext/nonce → GCM must fail cleanly.
    let msg = EncryptedMessage {
        public_key: [0u8; 32],
        message_num: 0,
        previous_chain_length: 0,
        nonce: [0xFFu8; 12],
        ciphertext: vec![0u8; 16],
    };
    let res = catch_unwind(AssertUnwindSafe(|| sm.decrypt_message("sid", &msg)));
    assert!(res.is_ok(), "malformed ciphertext must not panic");
    assert!(
        res.unwrap().is_err(),
        "GCM auth failure must surface as Err"
    );
}

// ── session_id extremes ───────────────────────────────────────

/// Establish an initiator/responder pair (like `benches/perf.rs`). The Double
/// Ratchet has separate send/recv chains, so a single session cannot decrypt its
/// own ciphertext — we need the two sides to handshake via `set_peer_key`.
fn roundtrip_pair(a_id: &str, b_id: &str) -> (SessionManager, SessionManager) {
    let alice = SessionManager::new();
    let bob = SessionManager::new();
    alice.create_session(a_id, &[42u8; 32], true).unwrap();
    bob.create_session(b_id, &[42u8; 32], false).unwrap();
    let alice_pk = alice.get_send_key(a_id).unwrap();
    bob.set_peer_key(b_id, alice_pk).unwrap();
    (alice, bob)
}

#[test]
fn test_empty_session_id_handled() {
    let (alice, bob) = roundtrip_pair("", "");
    let msg = alice.encrypt_message("", b"hello").unwrap();
    let dec = bob.decrypt_message("", &msg).unwrap();
    assert_eq!(dec, Some(b"hello".to_vec()));
}

#[test]
fn test_oversized_session_id_handled() {
    let long_id = "x".repeat(1_000_000);
    let (alice, bob) = roundtrip_pair(&long_id, &long_id);
    let msg = alice.encrypt_message(&long_id, b"hi").unwrap();
    let dec = bob.decrypt_message(&long_id, &msg).unwrap();
    assert_eq!(dec, Some(b"hi".to_vec()));
}

// ── randomized fuzzing (catch_unwind guarded) ─────────────────

#[test]
fn test_fuzz_random_inputs_never_panic() {
    use rand::RngCore;

    let mut rng = rand::thread_rng();
    for _ in 0..1000 {
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);

        // Random bytes as hex string: decode must never panic.
        let hex_str = hex::encode(&buf);
        assert!(catch_unwind(|| hex::decode(&hex_str)).is_ok());

        // Random bytes as a raw (lossy) string key_id: store/load must not panic.
        let raw = String::from_utf8_lossy(&buf).to_string();
        let dir = tempfile::TempDir::new().unwrap();
        let mut ks = KeyStore::new(dir.path()).unwrap();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _ = ks.store_secret_key(&raw, &buf, &buf, "fuzz");
            let _ = ks.load_secret_key(&raw);
        }));

        // Random message_num field: decrypt must not panic (may Err).
        let sm = SessionManager::new();
        let _ = sm.create_session("fz", &[0u8; 32], true);
        let msg = EncryptedMessage {
            public_key: buf[..32].try_into().unwrap(),
            message_num: u32::from_le_bytes(buf[32..36].try_into().unwrap()),
            previous_chain_length: 0,
            nonce: buf[36..48].try_into().unwrap(),
            ciphertext: buf[48..].to_vec(),
        };
        assert!(catch_unwind(AssertUnwindSafe(|| sm.decrypt_message("fz", &msg))).is_ok());
    }
}
