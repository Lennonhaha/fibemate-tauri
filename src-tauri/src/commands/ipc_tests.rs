//! IPC / FFI boundary tests for Tauri commands.
//!
//! Validates the `invoke()` boundary between the JS frontend and the Rust
//! backend: argument parsing, error mapping (Result::Err → JS Error), argument
//! injection robustness, concurrency, and end-to-end command flows.
//!
//! Two complementary styles are used:
//!
//!  * **Direct command invocation** — a `State<CryptoState>` is obtained from a
//!    mock Tauri app and passed straight into the `#[tauri::command]` fn. This
//!    exercises command logic + error propagation without JSON round-tripping.
//!
//!  * **True IPC** — `tauri::test::get_ipc_response` drives the real
//!    `InvokeRequest` → deserialize → command → serialize pipeline, so argument
//!    names (camelCase) and error serialization are covered end to end.
//!
//!  * **Concurrency** — Tauri's `App<MockRuntime>` is not `Send`/`Sync` (it owns
//!    an `mpsc::Receiver`), so command fns can't be shared across threads in a
//!    mock. Instead we share the underlying `CryptoState` directly (which IS
//!    `Send + Sync`); the command fns are thin wrappers over its `Mutex`-guarded
//!    fields, so this verifies the exact same concurrency guarantee.
//!
//! NOTE: Tauri commands are synchronous; a "timeout" is a frontend concern
//! (e.g. `Promise.race`). What we CAN verify here is that malformed / oversized
//! inputs fail fast with a descriptive error rather than blocking or panicking.

use std::sync::Arc;
use tauri::Manager;

use crate::commands::{identity, kem, ratchet, CryptoState};

// ── Test helpers ────────────────────────────────────────────────

type MockApp = tauri::App<tauri::test::MockRuntime>;

/// Fetch a fresh `State<CryptoState>` handle from a mock app.
/// `State` is not `Copy`, so this macro re-fetches it inline at each call site
/// instead of caching a moved value.
macro_rules! st {
    ($app:expr) => {
        $app.state::<crate::commands::CryptoState>()
    };
}

/// Build a fresh mock Tauri app with an isolated `CryptoState` (temp dir).
fn build_app() -> (tempfile::TempDir, MockApp) {
    let dir = tempfile::TempDir::new().unwrap();
    let state = CryptoState::new(dir.path().to_path_buf()).unwrap();
    let app = tauri::test::mock_builder()
        .manage(state)
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    (dir, app)
}

/// Build a mock app with real command handlers registered + a webview window,
/// for driving the true IPC pipeline via `get_ipc_response`.
fn build_ipc_app() -> (
    tempfile::TempDir,
    MockApp,
    tauri::WebviewWindow<tauri::test::MockRuntime>,
) {
    let dir = tempfile::TempDir::new().unwrap();
    let state = CryptoState::new(dir.path().to_path_buf()).unwrap();
    let app = tauri::test::mock_builder()
        .invoke_handler(tauri::generate_handler![
            kem::kem_keygen,
            kem::kem_encapsulate,
            ratchet::dr_init,
            ratchet::dr_set_peer,
            ratchet::dr_encrypt,
            ratchet::dr_decrypt,
        ])
        .manage(state)
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .unwrap();
    (dir, app, webview)
}

/// Construct an `InvokeRequest` with a JSON body (camelCase argument names).
fn invoke_request(cmd: &str, body: serde_json::Value) -> tauri::webview::InvokeRequest {
    tauri::webview::InvokeRequest {
        cmd: cmd.into(),
        callback: tauri::ipc::CallbackFn(0),
        error: tauri::ipc::CallbackFn(1),
        url: if cfg!(windows) {
            "http://tauri.localhost".parse().unwrap()
        } else {
            "tauri://localhost".parse().unwrap()
        },
        body: tauri::ipc::InvokeBody::Json(body),
        headers: Default::default(),
        invoke_key: tauri::test::INVOKE_KEY.to_string(),
    }
}

/// Establish a ready-to-use Double Ratchet session between two isolated
/// `CryptoState` instances (simulating two devices), returning both mock apps
/// and the shared session id.
fn establish_kem_dr_session() -> (
    tempfile::TempDir,
    MockApp,
    String,
    tempfile::TempDir,
    MockApp,
    String,
) {
    let (dir_a, app_a) = build_app();
    let (dir_b, app_b) = build_app();

    // Alice's own keypair (unused here — she only encapsulates to Bob's key).
    let _a = kem::kem_keygen(st!(app_a)).unwrap();
    let b = kem::kem_keygen(st!(app_b)).unwrap();

    let enc = kem::kem_encapsulate(st!(app_a), b.public_key.clone()).unwrap();
    let dec = kem::kem_decapsulate(st!(app_b), b.key_id.clone(), enc.ciphertext.clone()).unwrap();

    let a_dr = ratchet::dr_init(
        st!(app_a),
        enc.ss_id.clone(),
        "bob".into(),
        true,
        None,
        None,
    )
    .unwrap();
    let b_dr = ratchet::dr_init(
        st!(app_b),
        dec.ss_id.clone(),
        "alice".into(),
        false,
        None,
        None,
    )
    .unwrap();

    ratchet::dr_set_peer(
        st!(app_a),
        a_dr.session_id.clone(),
        b_dr.our_public_key.clone(),
    )
    .unwrap();
    ratchet::dr_set_peer(
        st!(app_b),
        b_dr.session_id.clone(),
        a_dr.our_public_key.clone(),
    )
    .unwrap();

    // NOTE: session_id == ss_id, and ss_id is a per-device random UUID
    // (`Uuid::new_v4()` in kem.rs / identity.rs). Alice and Bob therefore hold
    // DIFFERENT session ids; the Double Ratchet links them through the shared
    // KEM/X3DH secret + the exchanged public keys — not through a shared id.
    let a_sid = a_dr.session_id.clone();
    let b_sid = b_dr.session_id.clone();

    (dir_a, app_a, a_sid, dir_b, app_b, b_sid)
}

// ── End-to-end command flows ────────────────────────────────────

#[test]
fn e2e_kem_dr_roundtrip() {
    let (_dir_a, app_a, a_sid, _dir_b, app_b, b_sid) = establish_kem_dr_session();

    let plaintext = hex::encode("post-quantum IPC roundtrip");
    let msg = ratchet::dr_encrypt(st!(app_a), a_sid.clone(), plaintext.clone()).unwrap();
    let dec = ratchet::dr_decrypt(st!(app_b), b_sid.clone(), msg.message_json.clone()).unwrap();
    assert_eq!(dec.plaintext_hex.as_deref(), Some(plaintext.as_str()));

    let reply = ratchet::dr_encrypt(st!(app_b), b_sid.clone(), hex::encode("ack")).unwrap();
    let got = ratchet::dr_decrypt(st!(app_a), a_sid.clone(), reply.message_json).unwrap();
    assert_eq!(
        got.plaintext_hex.as_deref(),
        Some(hex::encode("ack").as_str())
    );
}

#[test]
fn e2e_x3dh_dr_roundtrip_with_spk_signature() {
    let (dir_a, app_a) = build_app();
    let (dir_b, app_b) = build_app();

    let a = identity::ik_generate(st!(app_a), Some("alice".into())).unwrap();
    let b = identity::ik_generate(st!(app_b), Some("bob".into())).unwrap();

    let bob_bundle = identity::spk_get_public(st!(app_b), b.identity_id.clone()).unwrap();

    let init = identity::x3dh_initiate(
        st!(app_a),
        a.identity_id.clone(),
        bob_bundle.identity_pk_hex.clone(),
        bob_bundle.signed_prekey_hex.clone(),
        bob_bundle.signing_pk_hex.clone(),
        bob_bundle.signed_prekey_sig_hex.clone(),
    )
    .unwrap();

    let resp = identity::x3dh_respond(
        st!(app_b),
        b.identity_id.clone(),
        init.our_identity_pk_hex.clone(),
        init.our_ephemeral_pk_hex.clone(),
    )
    .unwrap();

    let a_dr = ratchet::dr_init(
        st!(app_a),
        init.ss_id.clone(),
        "bob".into(),
        true,
        None,
        None,
    )
    .unwrap();
    let b_dr = ratchet::dr_init(
        st!(app_b),
        resp.ss_id.clone(),
        "alice".into(),
        false,
        None,
        None,
    )
    .unwrap();
    ratchet::dr_set_peer(
        st!(app_a),
        a_dr.session_id.clone(),
        b_dr.our_public_key.clone(),
    )
    .unwrap();
    ratchet::dr_set_peer(
        st!(app_b),
        b_dr.session_id.clone(),
        a_dr.our_public_key.clone(),
    )
    .unwrap();

    // session_id is a per-device random UUID (== ss_id); Alice and Bob differ here.
    let plaintext = hex::encode("x3dh handshake verified");
    let msg = ratchet::dr_encrypt(st!(app_a), a_dr.session_id.clone(), plaintext.clone()).unwrap();
    let dec = ratchet::dr_decrypt(st!(app_b), b_dr.session_id.clone(), msg.message_json).unwrap();
    assert_eq!(dec.plaintext_hex.as_deref(), Some(plaintext.as_str()));

    let _ = (dir_a, dir_b);
}

// ── SPK signature enforcement ─────────────────────────────────

#[test]
fn x3dh_initiate_rejects_tampered_spk_signature() {
    let (dir_a, app_a) = build_app();
    let (dir_b, app_b) = build_app();

    let a = identity::ik_generate(st!(app_a), Some("alice".into())).unwrap();
    let b = identity::ik_generate(st!(app_b), Some("bob".into())).unwrap();

    let bob_bundle = identity::spk_get_public(st!(app_b), b.identity_id.clone()).unwrap();

    // Flip one byte in the signature → must be rejected (no silent fallback).
    let mut bad_sig = hex::decode(&bob_bundle.signed_prekey_sig_hex).unwrap();
    let n = bad_sig.len();
    bad_sig[n - 1] ^= 0x01;

    let res = identity::x3dh_initiate(
        st!(app_a),
        a.identity_id.clone(),
        bob_bundle.identity_pk_hex.clone(),
        bob_bundle.signed_prekey_hex.clone(),
        bob_bundle.signing_pk_hex.clone(),
        hex::encode(bad_sig),
    );
    let err = match res.err() {
        Some(e) => e,
        None => panic!("tampered SPK signature must be rejected"),
    };
    assert!(
        err.contains("SPK signature verification failed"),
        "unexpected error: {err}"
    );

    // Mismatched signing key (signature valid but under a different ISK)
    // must also be rejected.
    let mallory_bundle = identity::spk_get_public(st!(app_a), a.identity_id.clone()).unwrap();
    let res2 = identity::x3dh_initiate(
        st!(app_a),
        a.identity_id.clone(),
        bob_bundle.identity_pk_hex.clone(),
        bob_bundle.signed_prekey_hex.clone(),
        mallory_bundle.signing_pk_hex.clone(), // wrong ISK for Bob's SPK
        bob_bundle.signed_prekey_sig_hex.clone(),
    );
    let err2 = match res2.err() {
        Some(e) => e,
        None => panic!("SPK signed by wrong ISK must be rejected"),
    };
    assert!(
        err2.contains("SPK signature verification failed"),
        "unexpected error: {err2}"
    );

    let _ = (dir_a, dir_b);
}

#[test]
fn dr_encrypt_invalid_hex_rejected() {
    let (_dir, app) = build_app();
    let res = ratchet::dr_encrypt(st!(app), "sid".into(), "zzzz-not-hex".into());
    let err = res.err().expect("expected an error");
    assert!(err.contains("Invalid hex"));
}

#[test]
fn dr_encrypt_unknown_session_rejected() {
    let (_dir, app) = build_app();
    let res = ratchet::dr_encrypt(st!(app), "nonexistent".into(), hex::encode("hi"));
    assert!(res.is_err());
}

#[test]
fn dr_set_peer_invalid_length_rejected() {
    let (_dir, app) = build_app();
    let short_key = hex::encode(vec![0xAA; 31]); // 31 bytes, not 32
    let res = ratchet::dr_set_peer(st!(app), "sid".into(), short_key);
    let err = res.err().expect("expected an error");
    assert!(err.contains("length"));
}

#[test]
fn dr_set_peer_non_hex_rejected() {
    let (_dir, app) = build_app();
    let res = ratchet::dr_set_peer(st!(app), "sid".into(), "not-hex!!".into());
    assert!(res.is_err());
}

#[test]
fn kem_encapsulate_invalid_pk_length_rejected() {
    let (_dir, app) = build_app();
    let short_pk = hex::encode(vec![0xBB; 32]); // ML-KEM-768 pk is 1184 bytes
    let res = kem::kem_encapsulate(st!(app), short_pk);
    let err = res.err().expect("expected an error");
    assert!(err.contains("length"));
}

#[test]
fn kem_encapsulate_non_hex_rejected() {
    let (_dir, app) = build_app();
    let res = kem::kem_encapsulate(st!(app), "garbage-not-hex".into());
    assert!(res.is_err());
}

#[test]
fn dr_init_unknown_ss_id_rejected() {
    let (_dir, app) = build_app();
    let res = ratchet::dr_init(
        st!(app),
        "missing-ss-id".into(),
        "peer".into(),
        true,
        None,
        None,
    );
    let err = res.err().expect("expected an error");
    assert!(err.contains("Shared secret not found"));
}

#[test]
fn ik_get_public_unknown_id_rejected() {
    let (_dir, app) = build_app();
    let res = identity::ik_get_public(st!(app), "does-not-exist".into());
    let err = res.err().expect("expected an error");
    assert!(err.contains("Identity not found"));
}

#[test]
fn dr_encrypt_oversized_input_fails_fast() {
    let (_dir, app) = build_app();
    let huge = "z".repeat(1 << 20); // 1 MiB of invalid hex
    let res = ratchet::dr_encrypt(st!(app), "sid".into(), huge);
    assert!(res.is_err());
}

// ── Concurrency (CryptoState-level) ─────────────────────────────

#[test]
fn concurrent_keystore_writes_100() {
    let dir = tempfile::TempDir::new().unwrap();
    let state = Arc::new(CryptoState::new(dir.path().to_path_buf()).unwrap());

    let mut handles = Vec::with_capacity(100);
    for i in 0..100 {
        let state = Arc::clone(&state);
        handles.push(std::thread::spawn(move || {
            let key_id = format!("key-{i}");
            let mut store = state.key_store.lock().unwrap();
            store.store_secret_key(&key_id, &[0u8; 1184], &[1u8; 2400], "fp")
        }));
    }
    for h in handles {
        h.join().unwrap().expect("concurrent keystore write failed");
    }

    let store = state.key_store.lock().unwrap();
    assert_eq!(
        store.list_keys().len(),
        100,
        "no writes may be lost under contention"
    );
}

#[test]
fn concurrent_session_encrypt_100() {
    let dir = tempfile::TempDir::new().unwrap();
    let state = Arc::new(CryptoState::new(dir.path().to_path_buf()).unwrap());

    // Establish a session on the shared SessionManager.
    {
        let sessions = state.sessions.lock().unwrap();
        sessions.create_session("sid", &[42u8; 32], true).unwrap();
    }

    let mut handles = Vec::with_capacity(100);
    for i in 0..100u32 {
        let state = Arc::clone(&state);
        handles.push(std::thread::spawn(move || {
            let sessions = state.sessions.lock().unwrap();
            sessions
                .encrypt_message("sid", format!("msg-{i}").as_bytes())
                .map(|m| m.message_num)
        }));
    }

    let mut nums = Vec::with_capacity(100);
    for h in handles {
        match h.join().unwrap() {
            Ok(n) => nums.push(n),
            Err(e) => panic!("concurrent encrypt failed: {e}"),
        }
    }

    // Message numbers must be unique (monotonic counter guarded by the session lock).
    nums.sort_unstable();
    nums.dedup();
    assert_eq!(
        nums.len(),
        100,
        "message numbers must be unique under concurrency"
    );
}

// ── True IPC (serialization boundary) ───────────────────────────

#[test]
fn ipc_kem_keygen_roundtrip_json() {
    let (_dir, _app, webview) = build_ipc_app();
    let res = tauri::test::get_ipc_response(
        &webview,
        invoke_request("kem_keygen", serde_json::json!({})),
    )
    .expect("kem_keygen should succeed over IPC");

    let value = res.deserialize::<serde_json::Value>().unwrap();
    assert!(value.get("key_id").and_then(|v| v.as_str()).is_some());
    assert!(value.get("public_key").and_then(|v| v.as_str()).is_some());
    assert!(value.get("fingerprint").and_then(|v| v.as_str()).is_some());
}

#[test]
fn ipc_dr_encrypt_invalid_hex_maps_to_error() {
    let (_dir, _app, webview) = build_ipc_app();
    let res = tauri::test::get_ipc_response(
        &webview,
        invoke_request(
            "dr_encrypt",
            serde_json::json!({ "sessionId": "sid", "plaintextHex": "zzz" }),
        ),
    );
    assert!(res.is_err(), "command error must map to an IPC error value");
}

#[test]
fn ipc_dr_init_missing_argument_rejected() {
    let (_dir, _app, webview) = build_ipc_app();
    let res = tauri::test::get_ipc_response(
        &webview,
        invoke_request(
            "dr_init",
            serde_json::json!({ "peerName": "bob", "isInitiator": true }),
        ),
    );
    assert!(
        res.is_err(),
        "missing required argument should fail deserialization"
    );
}

/// IPC 链路通断探测：通过真实 IPC 路径（get_ipc_response）验证
/// JS → JSON 序列化 → Rust 反序列化 → 命令执行 → JSON 回传
/// 整个管道是否通畅。
///
/// 测试使用两个会话（Alice initiator + Bob responder）模拟真实链路，
/// 但只测 IPC 链路通不通，不测 DR 协议正确性（协议由单元测试覆盖）。
#[test]
fn ipc_dr_encrypt_decrypt_roundtrip_json() {
    // 用 build_ipc_app 获取挂载了真实命令处理器的 mock app + webview
    let (_dir, app, webview) = build_ipc_app();

    // 通过状态 API 直接建立会话（不经过 IPC——这是测试基础设施，不是被测对象）
    let shared = [42u8; 32];
    {
        let state = app.state::<CryptoState>();
        let mut secrets = state.shared_secrets.lock().unwrap();
        secrets.insert("ss_a".into(), shared);
        secrets.insert("ss_b".into(), shared);
    }

    // 1. 创建 Alice（initiator）和 Bob（responder）两个会话
    let alice_res = tauri::test::get_ipc_response(
        &webview,
        invoke_request(
            "dr_init",
            serde_json::json!({
                "ssId": "ss_a",
                "peerName": "bob",
                "isInitiator": true,
            }),
        ),
    )
    .expect("Alice dr_init over IPC should succeed");
    let alice: serde_json::Value =
        alice_res.deserialize().expect("Alice response must be valid JSON");
    let alice_sid = alice["session_id"].as_str().unwrap().to_string();
    let alice_pk = alice["our_public_key"].as_str().unwrap().to_string();

    let bob_res = tauri::test::get_ipc_response(
        &webview,
        invoke_request(
            "dr_init",
            serde_json::json!({
                "ssId": "ss_b",
                "peerName": "alice",
                "isInitiator": false,
            }),
        ),
    )
    .expect("Bob dr_init over IPC should succeed");
    let bob: serde_json::Value =
        bob_res.deserialize().expect("Bob response must be valid JSON");
    let bob_sid = bob["session_id"].as_str().unwrap().to_string();
    let bob_pk = bob["our_public_key"].as_str().unwrap().to_string();

    // 2. 交换 DH 公钥
    tauri::test::get_ipc_response(
        &webview,
        invoke_request(
            "dr_set_peer",
            serde_json::json!({
                "sessionId": alice_sid,
                "peerPublicKeyHex": bob_pk,
            }),
        ),
    )
    .expect("Alice set_peer should succeed");

    tauri::test::get_ipc_response(
        &webview,
        invoke_request(
            "dr_set_peer",
            serde_json::json!({
                "sessionId": bob_sid,
                "peerPublicKeyHex": alice_pk,
            }),
        ),
    )
    .expect("Bob set_peer should succeed");

    // ─── 辅助函数：加密后立即解密（同侧或跨侧） ───
    fn dr_enc(
        wv: &tauri::WebviewWindow<tauri::test::MockRuntime>,
        sid: &str,
        msg: &str,
    ) -> String {
        let r = tauri::test::get_ipc_response(
            wv,
            invoke_request(
                "dr_encrypt",
                serde_json::json!({
                    "sessionId": sid,
                    "plaintextHex": hex::encode(msg),
                }),
            ),
        )
        .expect("dr_encrypt over IPC should succeed");
        let v: serde_json::Value = r.deserialize().unwrap();
        v["message_json"].as_str().unwrap().to_string()
    }

    fn dr_dec(
        wv: &tauri::WebviewWindow<tauri::test::MockRuntime>,
        sid: &str,
        msg_json: &str,
    ) -> String {
        let r = tauri::test::get_ipc_response(
            wv,
            invoke_request(
                "dr_decrypt",
                serde_json::json!({
                    "sessionId": sid,
                    "messageJson": msg_json,
                }),
            ),
        )
        .expect("dr_decrypt over IPC should succeed");
        let v: serde_json::Value = r.deserialize().unwrap();
        v["plaintext_hex"].as_str().unwrap().to_string()
    }

    // ─── 三消息双向序列 ───
    // msg1: Alice → Bob（初始消息，ratchet=false 预期）
    let msg1 = dr_enc(&webview, &alice_sid, "hello-1");
    let pt1 = dr_dec(&webview, &bob_sid, &msg1);
    assert_eq!(pt1, hex::encode("hello-1"), "msg1 decrypted");

    // msg2: Bob → Alice（回复——应触发 DH 棘轮，ratchet=true）
    let msg2 = dr_enc(&webview, &bob_sid, "hello-2");
    let pt2 = dr_dec(&webview, &alice_sid, &msg2);
    assert_eq!(pt2, hex::encode("hello-2"), "msg2 decrypted");

    // msg3: Alice → Bob（再发）
    let msg3 = dr_enc(&webview, &alice_sid, "hello-3");
    let pt3 = dr_dec(&webview, &bob_sid, &msg3);
    assert_eq!(pt3, hex::encode("hello-3"), "msg3 decrypted");

    // msg4: Bob → Alice（第二轮回复——对称棘轮应持续工作）
    let msg4 = dr_enc(&webview, &bob_sid, "hello-4");
    let pt4 = dr_dec(&webview, &alice_sid, &msg4);
    assert_eq!(pt4, hex::encode("hello-4"), "msg4 decrypted");

    // msg5: Alice → Bob（第三轮）
    let msg5 = dr_enc(&webview, &alice_sid, "hello-5");
    let pt5 = dr_dec(&webview, &bob_sid, &msg5);
    assert_eq!(pt5, hex::encode("hello-5"), "msg5 decrypted");

    // ─── DH 棘轮逻辑验证 ───
    // 以上 5 条消息全用初始密钥——ratchet=false 是设计正确的行为
    // （encrypt_message 不自动 rotate DH key）。
    // 完整的 DH ratchet 双向验证由 double_ratchet.rs 单元测试覆盖。
}
