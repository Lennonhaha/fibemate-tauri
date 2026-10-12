//! Double Ratchet state-machine tests (P4) - FIBEMATE
//!
//! Fills the gaps left by the read-only audit of `double_ratchet.rs`
//! (2026-10-12). Unlike the P1/P2/P3 suites (correctness, performance,
//! adversarial input), this module pins the *state machine* itself:
//!
//!   * T13  an AEAD failure must roll the whole state back (the 2026-10-06
//!          fix) - both on the current chain and on a ratchet-triggering
//!          new chain.
//!   * T10  `MAX_SKIP` boundary: `== MAX_SKIP` is admitted, `> MAX_SKIP`
//!          is rejected; the two paths are told apart by their error text.
//!   * T14  `previous_chain_pubkeys` FIFO cap (8) evicts the oldest chain.
//!   * T15  `previous_send_keys` FIFO cap (100) evicts the lowest number.
//!   * T16  `ratchet_step` migrates the skipped-key pool into the
//!          cross-chain pool.
//!   * T17  send side: `encrypt_message` advances chain and counters, and
//!          never touches the receive side.
//!   * T19  unknown session -> `Err` on every public operation.
//!   * T20  `delete_session` removes the state and blocks further use.
//!   * T30/T31  command layer smoke (mock app): unknown session, and the
//!          init -> encrypt -> revoke path.
//!
//! State assertions use `SessionManager::debug_state_snapshot`, which is
//! `#[cfg(test)]`-gated (same pattern as `debug_ratchet_step`), so the
//! tests assert *facts* rather than behaviour proxies.

use crate::double_ratchet::{EncryptedMessage, SessionManager, MAX_SKIP};

/// Establish an initiator/responder pair with peer keys exchanged.
/// Same construction as `concurrency_tests::establish_pair`.
fn establish_pair() -> (SessionManager, SessionManager) {
    let alice = SessionManager::new();
    let bob = SessionManager::new();
    alice.create_session("bob", &[42u8; 32], true).unwrap();
    bob.create_session("alice", &[42u8; 32], false).unwrap();
    alice
        .set_peer_key("bob", bob.get_send_key("alice").unwrap())
        .unwrap();
    bob.set_peer_key("alice", alice.get_send_key("bob").unwrap())
        .unwrap();
    (alice, bob)
}

/// Flip one ciphertext byte so GCM authentication fails.
fn tamper(m: &EncryptedMessage) -> EncryptedMessage {
    let mut t = m.clone();
    if let Some(b) = t.ciphertext.first_mut() {
        *b ^= 0xFF;
    }
    t
}

/// Well-formed envelope with a chosen DH public key and message number, but
/// garbage ciphertext (no genuine key material). The nonce is drawn straight
/// from the RNG so that no cryptographic constant appears in the source.
fn crafted(public_key: [u8; 32], message_num: u32) -> EncryptedMessage {
    EncryptedMessage {
        public_key,
        message_num,
        previous_chain_length: 0,
        nonce: rand::random(),
        ciphertext: vec![0u8; 16],
    }
}

// ---------------------------------------------------------------------------
// T13 - AEAD failure rolls the state back
// ---------------------------------------------------------------------------

#[test]
fn dr_t13a_aead_failure_rolls_back_current_chain_state() {
    let (alice, bob) = establish_pair();
    let m0 = alice.encrypt_message("bob", b"first").unwrap();
    let m1 = alice.encrypt_message("bob", b"second").unwrap();

    let before = bob.debug_state_snapshot("alice").unwrap();

    let err = bob.decrypt_message("alice", &tamper(&m0)).unwrap_err();
    assert!(
        err.contains("AEAD decrypt failed"),
        "tampered ciphertext must fail at AEAD, got: {err}"
    );

    // The failed message must leave no trace: without the rollback the
    // receive window would advance and m0's retransmission would look like a
    // replay and be dropped forever.
    let after = bob.debug_state_snapshot("alice").unwrap();
    assert_eq!(after, before, "a failed AEAD must not mutate any state");

    // Both genuine messages still decrypt.
    assert_eq!(
        bob.decrypt_message("alice", &m0).unwrap().unwrap(),
        b"first"
    );
    assert_eq!(
        bob.decrypt_message("alice", &m1).unwrap().unwrap(),
        b"second"
    );
}

#[test]
fn dr_t13b_aead_failure_on_new_chain_does_not_commit_ratchet() {
    let (alice, bob) = establish_pair();
    let m0 = alice.encrypt_message("bob", b"m0").unwrap();
    assert_eq!(bob.decrypt_message("alice", &m0).unwrap().unwrap(), b"m0");
    let chain_a_pk = m0.public_key;

    let before = bob.debug_state_snapshot("alice").unwrap();
    assert_eq!(before.recv_public_key, chain_a_pk);
    assert_eq!(before.previous_chain_pubkeys_len, 0);

    // An unknown DH public key normally triggers `ratchet_step` (the same
    // shape that `test_cross_chain_late_message_with_previous_keys` forces
    // with [9u8; 32]). Here the AEAD fails, so the ratchet must not commit.
    let err = bob
        .decrypt_message("alice", &crafted([9u8; 32], before.recv_message_num))
        .unwrap_err();
    assert!(err.contains("AEAD decrypt failed"), "got: {err}");

    let after = bob.debug_state_snapshot("alice").unwrap();
    assert_eq!(after, before, "a failed AEAD must not commit the ratchet");
    assert_eq!(after.recv_public_key, chain_a_pk);
    assert_eq!(after.previous_chain_pubkeys_len, 0);

    // The old chain is still live: had the ratchet committed, recv_public_key
    // would be [9u8; 32] and this message would be misfiled as old-chain.
    let m1 = alice.encrypt_message("bob", b"m1").unwrap();
    assert_eq!(bob.decrypt_message("alice", &m1).unwrap().unwrap(), b"m1");
}

// ---------------------------------------------------------------------------
// T10 - MAX_SKIP boundary
// ---------------------------------------------------------------------------

#[test]
fn dr_t10a_skip_ahead_at_max_skip_is_admitted() {
    let sm = SessionManager::new();
    sm.create_session("sid", &[42u8; 32], true).unwrap();

    // The guard is `skip_count > MAX_SKIP`, so exactly MAX_SKIP is the
    // largest jump that must be admitted. The envelope is crafted, so the
    // message still fails later at AEAD - what matters is *which* error.
    let err = sm
        .decrypt_message("sid", &crafted([0x11u8; 32], MAX_SKIP))
        .unwrap_err();
    assert!(
        !err.contains("Too many skipped"),
        "MAX_SKIP must be inclusive (== MAX_SKIP admitted), got: {err}"
    );
    assert!(err.contains("AEAD decrypt failed"), "got: {err}");

    // The skip really happened (MAX_SKIP keys derived) and was rolled back.
    let snap = sm.debug_state_snapshot("sid").unwrap();
    assert_eq!(
        snap.skipped_keys_len, 0,
        "failed AEAD must roll back the skipped-key pool"
    );
    assert_eq!(snap.recv_message_num, 0, "window must not advance");
}

#[test]
fn dr_t10b_skip_ahead_over_max_skip_is_rejected() {
    let sm = SessionManager::new();
    sm.create_session("sid", &[42u8; 32], true).unwrap();

    let err = sm
        .decrypt_message("sid", &crafted([0x11u8; 32], MAX_SKIP + 1))
        .unwrap_err();
    assert!(
        err.contains("Too many skipped"),
        "MAX_SKIP + 1 must be rejected, got: {err}"
    );
    assert!(err.contains(&format!("MAX_SKIP={MAX_SKIP}")), "got: {err}");

    let snap = sm.debug_state_snapshot("sid").unwrap();
    assert_eq!(
        snap.skipped_keys_len, 0,
        "a rejected jump must store nothing"
    );
}

// ---------------------------------------------------------------------------
// T14/T15/T16 - FIFO caps and skipped-key migration
// ---------------------------------------------------------------------------

#[test]
fn dr_t14_previous_chain_pubkeys_fifo_cap_eight() {
    let sm = SessionManager::new();
    sm.create_session("sid", &[42u8; 32], false).unwrap();

    // Entry i is recorded when ratcheting *away* from it, so after 9 steps
    // the list holds P1..=P8 (cap 8) and the 10th step evicts P1 (FIFO).
    for i in 1..=9u8 {
        sm.debug_ratchet_step("sid", [i; 32]).unwrap();
    }
    let snap = sm.debug_state_snapshot("sid").unwrap();
    assert_eq!(snap.previous_chain_pubkeys_len, 8, "cap is 8");
    assert_eq!(
        snap.previous_chain_pubkeys,
        (1..=8u8).map(|i| [i; 32]).collect::<Vec<_>>()
    );
    assert_eq!(snap.recv_public_key, [9u8; 32]);

    sm.debug_ratchet_step("sid", [10u8; 32]).unwrap();
    let snap = sm.debug_state_snapshot("sid").unwrap();
    assert_eq!(
        snap.previous_chain_pubkeys_len, 8,
        "cap still 8 after overflow"
    );
    assert_eq!(
        snap.previous_chain_pubkeys,
        (2..=9u8).map(|i| [i; 32]).collect::<Vec<_>>(),
        "P1 must be evicted first (FIFO)"
    );
    assert_eq!(snap.recv_public_key, [10u8; 32]);
}

#[test]
fn dr_t15_previous_send_keys_fifo_cap_hundred() {
    let (alice, bob) = establish_pair();

    // Alice sends 102 messages on chain A (numbers 0..=101).
    let msgs: Vec<_> = (0..102)
        .map(|i| {
            alice
                .encrypt_message("bob", format!("m{i}").as_bytes())
                .unwrap()
        })
        .collect();
    let chain_a_pk = msgs[0].public_key;

    // Bob takes the farthest message first: 101 keys (0..=100) are stashed.
    assert_eq!(
        bob.decrypt_message("alice", &msgs[101]).unwrap().unwrap(),
        b"m101"
    );
    assert_eq!(
        bob.debug_state_snapshot("alice").unwrap().skipped_keys_len,
        101
    );

    // Ratchet away: the pool drains into previous_send_keys (101 entries),
    // then the cap (100) evicts the lowest message number (0).
    bob.debug_ratchet_step("alice", [9u8; 32]).unwrap();
    let snap = bob.debug_state_snapshot("alice").unwrap();
    assert_eq!(
        snap.skipped_keys_len, 0,
        "pool drained into the cross-chain map"
    );
    assert_eq!(snap.previous_send_keys_len, 100, "cap is 100");
    assert_eq!(snap.previous_chain_pubkeys, vec![chain_a_pk]);

    // The evicted number is unrecoverable; a surviving number still decrypts.
    assert_eq!(bob.decrypt_message("alice", &msgs[0]).unwrap(), None);
    assert_eq!(
        bob.decrypt_message("alice", &msgs[1]).unwrap().unwrap(),
        b"m1"
    );
}

#[test]
fn dr_t16_ratchet_migrates_skipped_keys_into_previous_send_keys() {
    let (alice, bob) = establish_pair();
    let msgs: Vec<_> = (0..5)
        .map(|i| {
            alice
                .encrypt_message("bob", format!("m{i}").as_bytes())
                .unwrap()
        })
        .collect();
    let chain_a_pk = msgs[0].public_key;

    // Receive m3 first: the keys for m1/m2 are skipped, not yet derived.
    assert_eq!(
        bob.decrypt_message("alice", &msgs[3]).unwrap().unwrap(),
        b"m3"
    );
    assert_eq!(
        bob.debug_state_snapshot("alice").unwrap().skipped_keys_len,
        3
    );

    bob.debug_ratchet_step("alice", [9u8; 32]).unwrap();
    let snap = bob.debug_state_snapshot("alice").unwrap();
    assert_eq!(snap.skipped_keys_len, 0, "skipped keys migrated out");
    assert_eq!(
        snap.previous_send_keys_len, 3,
        "migrated into the cross-chain pool"
    );
    assert_eq!(snap.previous_chain_pubkeys, vec![chain_a_pk]);

    // Late old-chain messages decrypt from the migrated pool; the consumed
    // one is silently dropped as a replay.
    assert_eq!(
        bob.decrypt_message("alice", &msgs[1]).unwrap().unwrap(),
        b"m1"
    );
    assert_eq!(
        bob.decrypt_message("alice", &msgs[2]).unwrap().unwrap(),
        b"m2"
    );
    assert_eq!(bob.decrypt_message("alice", &msgs[3]).unwrap(), None);
}

// ---------------------------------------------------------------------------
// T17 - send-side state transitions
// ---------------------------------------------------------------------------

#[test]
fn dr_t17_encrypt_advances_send_chain_and_message_numbers() {
    let (alice, bob) = establish_pair();
    let before = alice.debug_state_snapshot("bob").unwrap();

    let msgs: Vec<_> = (0..3)
        .map(|i| {
            alice
                .encrypt_message("bob", format!("m{i}").as_bytes())
                .unwrap()
        })
        .collect();

    assert_eq!(
        msgs.iter().map(|m| m.message_num).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(msgs.iter().all(|m| m.previous_chain_length == 0));
    assert!(
        msgs.windows(2).all(|w| w[0].public_key == w[1].public_key),
        "one DH public key per sending chain"
    );
    assert!(
        msgs.windows(2).all(|w| w[0].nonce != w[1].nonce),
        "fresh nonce per message"
    );

    let after = alice.debug_state_snapshot("bob").unwrap();
    assert_eq!(after.send_message_num, before.send_message_num + 3);
    assert_ne!(
        after.send_chain_key, before.send_chain_key,
        "send chain advances"
    );
    assert_eq!(
        after.recv_chain_key, before.recv_chain_key,
        "encrypting must not touch the receive chain"
    );
    assert_eq!(after.recv_message_num, before.recv_message_num);
    assert_eq!(
        after.root_key, before.root_key,
        "no ratchet without an inbound key"
    );

    for (i, m) in msgs.iter().enumerate() {
        assert_eq!(
            bob.decrypt_message("alice", m).unwrap().unwrap(),
            format!("m{i}").into_bytes()
        );
    }
}

// ---------------------------------------------------------------------------
// T19/T20 - session lookup and deletion
// ---------------------------------------------------------------------------

#[test]
fn dr_t19_unknown_session_operations_return_err() {
    let sm = SessionManager::new();
    let msg = crafted([0u8; 32], 0);

    assert!(sm.get_send_key("nope").is_err());
    assert!(sm.get_session_recv_pk("nope").is_err());
    assert!(sm.encrypt_message("nope", b"x").is_err());
    assert!(sm.decrypt_message("nope", &msg).is_err());
    assert!(sm.will_ratchet_on_decrypt("nope", &msg).is_err());
    assert!(sm.set_peer_key("nope", [1u8; 32]).is_err());
    assert!(sm.set_identity_keys("nope", "me", [0u8; 32]).is_err());
    assert!(sm.get_identity_keys("nope").is_err());

    // Documented-total lookups do not error.
    assert!(!sm.has_session("nope").unwrap());
    assert!(sm.list_session_ids().is_empty());
    assert!(sm.debug_state_snapshot("nope").is_none());
}

#[test]
fn dr_t20_delete_session_removes_state_and_blocks_use() {
    let (alice, bob) = establish_pair();
    let m0 = alice.encrypt_message("bob", b"before").unwrap();
    assert_eq!(
        bob.decrypt_message("alice", &m0).unwrap().unwrap(),
        b"before"
    );
    assert!(bob.has_session("alice").unwrap());

    bob.delete_session("alice");
    assert!(!bob.has_session("alice").unwrap());
    assert!(bob.list_session_ids().is_empty());
    assert!(bob.debug_state_snapshot("alice").is_none());
    assert!(bob.encrypt_message("alice", b"x").is_err());
    assert!(bob.decrypt_message("alice", &m0).is_err());

    // Deleting an absent session is a no-op, not a panic.
    bob.delete_session("alice");
    assert!(!bob.has_session("alice").unwrap());
}

// ---------------------------------------------------------------------------
// T30/T31 - command layer smoke (mock app, same scaffold as concurrency_tests)
// ---------------------------------------------------------------------------

use crate::commands::{ratchet, CryptoState};
use tauri::Manager;

type MockApp = tauri::App<tauri::test::MockRuntime>;

/// `State` is not `Copy`; re-fetch inline at each call site.
macro_rules! st {
    ($app:expr) => {
        $app.state::<crate::commands::CryptoState>()
    };
}

/// Extract the error without requiring `T: Debug` on the response types
/// (`commands::ratchet` response structs only derive `Serialize`).
fn err_of<T>(r: Result<T, String>) -> String {
    match r {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    }
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
fn dr_t30_command_layer_unknown_session_errors() {
    let (_dir, app) = build_app();

    let err = err_of(ratchet::dr_encrypt(
        st!(app),
        "nope".into(),
        hex::encode(b"hi"),
    ));
    assert!(err.contains("Session not found"), "got: {err}");

    let json = serde_json::to_string(&crafted([0u8; 32], 0)).unwrap();
    let err = err_of(ratchet::dr_decrypt(st!(app), "nope".into(), json));
    assert!(err.contains("Session not found"), "got: {err}");

    assert!(!ratchet::dr_session_exists(st!(app), "nope".into()).unwrap());
    assert!(ratchet::dr_get_send_key(st!(app), "nope".into()).is_err());
    assert!(ratchet::dr_list_sessions(st!(app)).unwrap().is_empty());
}

#[test]
fn dr_t31_command_layer_init_encrypt_revoke() {
    let (_dir, app) = build_app();
    st!(app)
        .shared_secrets
        .lock()
        .unwrap()
        .insert("ss-dr".to_string(), [42u8; 32]);

    let init = ratchet::dr_init(st!(app), "ss-dr".into(), "bob".into(), true, None, None).unwrap();
    assert_eq!(init.session_id, "ss-dr");
    assert_eq!(init.our_public_key.len(), 64, "hex-encoded X25519 key");

    let enc = ratchet::dr_encrypt(st!(app), "ss-dr".into(), hex::encode(b"ping")).unwrap();
    assert_eq!(enc.message_num, 0);
    assert!(enc.message_json.contains("public_key"));

    assert!(ratchet::dr_session_exists(st!(app), "ss-dr".into()).unwrap());
    assert_eq!(
        ratchet::dr_get_send_key(st!(app), "ss-dr".into()).unwrap(),
        init.our_public_key
    );

    ratchet::dr_revoke_session(st!(app), "ss-dr".into()).unwrap();
    assert!(!ratchet::dr_session_exists(st!(app), "ss-dr".into()).unwrap());
    assert!(ratchet::dr_encrypt(st!(app), "ss-dr".into(), hex::encode(b"x")).is_err());
}
