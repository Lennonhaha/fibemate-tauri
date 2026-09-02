//! Concurrency / race-condition tests (P2) — FIBEMATE
//!
//! Proves the Double Ratchet and crypto state stay correct under thread
//! contention. Unlike the IPC tests (which focus on argument parsing and the
//! serialization boundary), this module targets the *shared mutable state*:
//!
//!   * concurrent `encrypt_message` on one session — message numbers unique,
//!     and every ciphertext must decrypt back to the right plaintext.
//!   * concurrent `decrypt_message` with out-of-order arrival — the skipped-key
//!     pool must survive interleaving from multiple threads.
//!   * `shared_secrets` single-consumption — an X3DH secret must never be
//!     consumed twice, or two sessions would share key material.
//!   * concurrent create/delete — no lost or ghost sessions.
//!
//! Thread-safety model: `SessionManager` guards `HashMap<String, RatchetState>`
//! behind a `Mutex`; `CryptoState` guards its three fields independently. All
//! operations below lock a whole map per call, so correctness reduces to
//! "every individual call is atomic" — which these tests verify end to end.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tauri::Manager;

use crate::commands::{ratchet, CryptoState};
use crate::double_ratchet::SessionManager;

// ── Mock-app helper (for dr_init idempotency) ──────────────────

type MockApp = tauri::App<tauri::test::MockRuntime>;

/// `State` is not `Copy`; re-fetch inline at each call site.
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

/// Establish a bidirectional DR session between two `SessionManager`s,
/// returning the pair with peer keys already exchanged.
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

// ════════════════════════════════════════════════════════════════
// Concurrent encryption — all ciphertexts must decrypt
// ════════════════════════════════════════════════════════════════

#[test]
fn concurrent_encrypt_messages_all_decryptable() {
    // 200 threads encrypt on the same session. Message numbers must be a
    // unique 0..N (guarded by the session lock) and every ciphertext must
    // round-trip, even when the receiver reads them in *reverse* order.
    let (alice, bob) = establish_pair();
    let alice = Arc::new(alice);

    const N: usize = 200;
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let alice = Arc::clone(&alice);
        handles.push(std::thread::spawn(move || {
            alice
                .encrypt_message("bob", format!("m{i}").as_bytes())
                .unwrap()
        }));
    }
    let mut msgs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Worst-case out-of-order: highest message number first.
    msgs.reverse();

    let mut got: Vec<String> = Vec::with_capacity(N);
    for m in &msgs {
        let pt = bob.decrypt_message("alice", m).unwrap().unwrap();
        got.push(String::from_utf8(pt).unwrap());
    }
    got.sort();
    let mut expected: Vec<String> = (0..N).map(|i| format!("m{i}")).collect();
    expected.sort();
    assert_eq!(got, expected, "every concurrent ciphertext must decrypt");
}

// ════════════════════════════════════════════════════════════════
// Concurrent decryption — out-of-order arrival across threads
// ════════════════════════════════════════════════════════════════

#[test]
fn concurrent_decrypt_out_of_order() {
    // Alice encrypts in order; Bob decrypts from N threads, each handling a
    // *different* out-of-order message number (a full permutation). The
    // skipped-key pool must interleave safely under lock contention.
    let (alice, bob) = establish_pair();
    let bob = Arc::new(bob);

    const N: usize = 128;
    let msgs: Vec<_> = (0..N)
        .map(|i| {
            alice
                .encrypt_message("bob", format!("m{i}").as_bytes())
                .unwrap()
        })
        .collect();

    // 37 is coprime with 128, so (i*37) % N visits every index exactly once.
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let bob = Arc::clone(&bob);
        let msg = msgs[(i * 37) % N].clone();
        handles.push(std::thread::spawn(move || {
            let pt = bob.decrypt_message("alice", &msg).unwrap().unwrap();
            String::from_utf8(pt).unwrap()
        }));
    }

    let mut got: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    got.sort();
    let mut expected: Vec<String> = (0..N).map(|i| format!("m{i}")).collect();
    expected.sort();
    assert_eq!(
        got, expected,
        "out-of-order concurrent decrypt must be lossless"
    );
}

// ════════════════════════════════════════════════════════════════
// Shared-secret single consumption (X3DH security invariant)
// ════════════════════════════════════════════════════════════════

#[test]
fn shared_secret_consumed_exactly_once() {
    // An X3DH shared secret MUST be consumed exactly once. If two threads
    // both removed it, two sessions would be seeded from the same secret —
    // a catastrophic key-reuse. `HashMap::remove` under `Mutex` is atomic.
    let dir = tempfile::TempDir::new().unwrap();
    let state = Arc::new(CryptoState::new(dir.path().to_path_buf()).unwrap());
    state
        .shared_secrets
        .lock()
        .unwrap()
        .insert("ss-race".to_string(), [42u8; 32]);

    const N: usize = 64;
    let consumed = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let state = Arc::clone(&state);
        let consumed = Arc::clone(&consumed);
        handles.push(std::thread::spawn(move || {
            let mut secrets = state.shared_secrets.lock().unwrap();
            if secrets.remove("ss-race").is_some() {
                consumed.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        consumed.load(Ordering::SeqCst),
        1,
        "shared secret must be consumed exactly once under contention"
    );
}

// ════════════════════════════════════════════════════════════════
// dr_init idempotency — actual behavior under repeated delivery
// ════════════════════════════════════════════════════════════════

#[test]
fn dr_init_repeated_delivery_single_session() {
    // `dr_init` must be idempotent under repeated delivery of the same
    // initMessage (WS reconnect / history replay). Since the 2026-09-02 fix,
    // the `has_session` existence check runs BEFORE the secret is consumed,
    // atomically in the same critical section:
    //   * 1st delivery: consumes secret, creates session
    //   * 2nd delivery: session exists → reuse (same send key, no duplicate)
    let (_dir, app) = build_app();
    st!(app)
        .shared_secrets
        .lock()
        .unwrap()
        .insert("ss-idem".to_string(), [42u8; 32]);

    let r1 = ratchet::dr_init(st!(app), "ss-idem".into(), "bob".into(), true, None, None)
        .expect("first dr_init must succeed");
    assert_eq!(r1.session_id, "ss-idem");

    // Second delivery: idempotent reuse — Ok, not "Shared secret not found".
    let r2 = ratchet::dr_init(st!(app), "ss-idem".into(), "bob".into(), true, None, None)
        .expect("repeated dr_init must reuse the existing session (idempotent)");
    assert_eq!(r2.session_id, "ss-idem");
    // Same ratchet send key — reuse must NOT create a new DH key pair
    // (a fresh key would make the peer's ratchet diverge).
    assert_eq!(
        r1.our_public_key, r2.our_public_key,
        "idempotent reuse must return the same send key"
    );

    // The secret was consumed exactly once and is gone.
    assert!(
        !st!(app)
            .shared_secrets
            .lock()
            .unwrap()
            .contains_key("ss-idem"),
        "shared secret must not be re-inserted by the reuse path"
    );

    // Exactly one session survives.
    let ids = st!(app).sessions.lock().unwrap().list_session_ids();
    assert_eq!(ids, vec!["ss-idem".to_string()]);
}

// ════════════════════════════════════════════════════════════════
// Concurrent create/delete — no lost or ghost sessions
// ════════════════════════════════════════════════════════════════

#[test]
fn concurrent_session_create_delete_no_loss() {
    let sm = Arc::new(SessionManager::new());

    const N: usize = 64;
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let sm = Arc::clone(&sm);
        handles.push(std::thread::spawn(move || {
            sm.create_session(&format!("s{i}"), &[i as u8; 32], true)
                .unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        sm.list_session_ids().len(),
        N,
        "all sessions must be created"
    );

    // Delete the even-numbered half concurrently.
    let mut handles = Vec::new();
    for i in (0..N).step_by(2) {
        let sm = Arc::clone(&sm);
        handles.push(std::thread::spawn(move || {
            sm.delete_session(&format!("s{i}"));
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let ids = sm.list_session_ids();
    assert_eq!(ids.len(), N / 2, "deleted sessions must not linger");
    for id in &ids {
        let n: usize = id.trim_start_matches('s').parse().unwrap();
        assert!(n % 2 == 1, "only odd sessions should remain, got {id}");
    }
}
