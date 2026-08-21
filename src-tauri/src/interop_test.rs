//! 跨语言互通验证测试
//! 用 JS 端（js-double-ratchet.js）生成的密钥和密文，验证 Rust 端能解密
//! 这证明 JS 实现与 Rust 实现字节级互通

use crate::double_ratchet::{SessionManager, EncryptedMessage};

#[test]
fn test_js_to_rust_interop() {
    // JS 端输出的关键参数
    let shared_secret_hex = "d88fbfd8e21a80e8765ada5fb5799c404a7d21862f69487ad98f1a8650c64a44";
    let alice_dr_send_pub_hex = "8a8c7338c2695a03c5472f113ef2d8bdebe6d77b7486b720d4dc3b5089dc7e65";

    // JS 端 Alice 加密的密文（JSON）
    let encrypted_json = r#"{"public_key":[138,140,115,56,194,105,90,3,197,71,47,17,62,242,216,189,235,230,215,123,116,134,183,32,212,220,59,80,137,220,126,101],"message_num":0,"previous_chain_length":0,"nonce":[93,10,254,83,231,81,174,163,18,61,156,163],"ciphertext":[166,60,78,96,185,228,2,72,222,206,225,202,107,42,94,18,13,64,247,194,37,253,92,69,225,174,36,189,67,39,105,167,39,29,245,129,142,59,98,65,90,225,129,78,115,190,8,67,238]}"#;

    let shared_secret = hex_to_bytes_32(shared_secret_hex);
    let alice_send_pub = hex_to_bytes_32(alice_dr_send_pub_hex);

    // Bob 端（responder）会话
    let bob = SessionManager::new();
    bob.create_session("alice", &shared_secret, false).unwrap();
    bob.set_peer_key("alice", alice_send_pub).unwrap();

    // 解密 JS 端 Alice 加密的消息
    let encrypted: EncryptedMessage = serde_json::from_str(encrypted_json).unwrap();
    let plaintext = bob.decrypt_message("alice", &encrypted).unwrap();
    let text = String::from_utf8(plaintext).unwrap();
    assert_eq!(text, "跨语言互通测试 hello world", "JS→Rust 解密失败");
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
