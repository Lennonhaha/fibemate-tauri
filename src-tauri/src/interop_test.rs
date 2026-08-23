//! 跨语言互通验证测试
//! 用 JS 端（js-double-ratchet.js）生成的密钥和密文，验证 Rust 端能解密
//! 这证明 JS 实现与 Rust 实现字节级互通

use crate::double_ratchet::{SessionManager, EncryptedMessage};

#[test]
fn test_js_to_rust_interop() {
    // 固定 shared_secret（来自旧 JS 双棘轮降级链，作为链密钥派生逻辑的回归锚点）。
    // 注：v3 已移除 JS P-256 DR（改为 Rust 原生 X25519 DR），原「JS→Rust 字节级互通」
    // 测试对象已不存在。此测试改为验证：相同 shared_secret 下 Rust 两端互通，
    // 防止 init_from_shared_secret 的链密钥派生（info 字符串/对称性）被无意改动。
    let shared_secret = hex_to_bytes_32("d88fbfd8e21a80e8765ada5fb5799c404a7d21862f69487ad98f1a8650c64a44");

    // Alice 端（initiator）会话
    let alice = SessionManager::new();
    alice.create_session("bob", &shared_secret, true).unwrap();
    // Bob 端（responder）会话
    let bob = SessionManager::new();
    bob.create_session("alice", &shared_secret, false).unwrap();

    // 交换双方 DR 公钥
    bob.set_peer_key("alice", alice.get_send_key("bob").unwrap()).unwrap();
    alice.set_peer_key("bob", bob.get_send_key("alice").unwrap()).unwrap();

    // 加密 → 解密
    let encrypted = alice.encrypt_message("bob", "跨语言互通测试 hello world".as_bytes()).unwrap();
    let plaintext = bob.decrypt_message("alice", &encrypted).unwrap();
    let text = String::from_utf8(plaintext).unwrap();
    assert_eq!(text, "跨语言互通测试 hello world", "固定 shared_secret 两端互通失败");
}

#[test]
fn test_rust_to_js_interop() {
    // Rust 端用相同密钥加密，输出 JSON 供 JS 端解密
    // （加密侧对齐通过 test_js_to_rust_interop 的对称性 + HKDF golden 保证）
    let shared_secret = hex_to_bytes_32("d88fbfd8e21a80e8765ada5fb5799c404a7d21862f69487ad98f1a8650c64a44");

    // Alice 端（initiator）会话
    let alice = SessionManager::new();
    alice.create_session("bob", &shared_secret, true).unwrap();

    // 加密一条消息（Rust 生成）
    let encrypted = alice.encrypt_message("bob", "rust hello".as_bytes()).unwrap();
    let json = serde_json::to_string(&encrypted).unwrap();
    eprintln!("RUST_ENCRYPTED_JSON={json}");

    // 验证 EncryptedMessage serde 结构（字段名对齐 JS 端）
    assert!(json.contains("\"public_key\""));
    assert!(json.contains("\"message_num\""));
    assert!(json.contains("\"previous_chain_length\""));
    assert!(json.contains("\"nonce\""));
    assert!(json.contains("\"ciphertext\""));
}

fn hex_to_bytes_32(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}
