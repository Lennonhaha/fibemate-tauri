use tauri::Manager;

mod pq;
mod double_ratchet;
mod key_store;
pub mod sm2;
pub mod sm3;
mod commands;

use commands::CryptoState;

// ================================================
// Platform Utility Commands
// ================================================

/// Get WebSocket server URL (configurable via env FIBEMATE_WS_URL)
#[tauri::command]
fn get_ws_url() -> String {
    std::env::var("FIBEMATE_WS_URL")
        .unwrap_or_else(|_| "ws://8.156.77.68/ws".to_string())
}

/// Get user data directory for key storage
#[tauri::command]
fn get_user_data_path(app: tauri::AppHandle) -> String {
    app.path()
        .app_data_dir()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

/// Get application version
#[tauri::command]
fn get_version(app: tauri::AppHandle) -> String {
    app.package_info().version.to_string()
}

/// Get platform identifier
#[tauri::command]
fn get_platform() -> String {
    std::env::consts::OS.to_string()
}

/// Get system locale
#[tauri::command]
fn get_locale() -> String {
    std::env::var("LANG")
        .or_else(|_| std::env::var("LC_ALL"))
        .unwrap_or_else(|_| "en-US".to_string())
}

// ================================================
// App Entry Point
// ================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            // Platform utilities
            get_ws_url,
            get_user_data_path,
            get_version,
            get_platform,
            get_locale,
            // Post-Quantum KEM
            commands::kem::kem_keygen,
            commands::kem::kem_encapsulate,
            commands::kem::kem_decapsulate,
            commands::kem::kem_list_keys,
            // Identity Keys (X25519)
            commands::identity::ik_generate,
            commands::identity::ik_get_public,
            commands::identity::ik_list,
            // X3DH Key Exchange
            commands::identity::x3dh_initiate,
            commands::identity::x3dh_respond,
            // Double Ratchet sessions
            commands::ratchet::dr_init,
            commands::ratchet::dr_set_peer,
            commands::ratchet::dr_encrypt,
            commands::ratchet::dr_decrypt,
            commands::ratchet::dr_get_send_key,
            commands::ratchet::dr_delete_session,
            commands::ratchet::dr_list_sessions,
            // Safety Number
            commands::safety_number::dr_safety_number,
            // SM2 Elliptic Curve Cryptography (GB/T 32918)
            commands::sm2_cmd::sm2_generate,
            commands::sm2_cmd::sm2_get_public,
            commands::sm2_cmd::sm2_import,
            commands::sm2_cmd::sm2_sign,
            commands::sm2_cmd::sm2_verify,
            commands::sm2_cmd::sm2_ecdh,
            commands::sm2_cmd::sm2_encrypt,
            commands::sm2_cmd::sm2_decrypt,
            commands::sm2_cmd::sm2_encrypt_full,
            commands::sm2_cmd::sm2_decrypt_full,
            commands::sm2_cmd::sm2_sign_full,
            commands::sm2_cmd::sm2_verify_full,
        ])
        .setup(|app| {
            // Initialize encrypted key store with the app data directory
            let app_data = app.path().app_data_dir()
                .map_err(|e| format!("App data dir not available: {e}"))?;
            let crypto_state = CryptoState::new(app_data)
                .map_err(|e| format!("Failed to initialize crypto state: {e}"))?;
            app.manage(crypto_state);

            let version = app.package_info().version.to_string();
            println!("[FIBEMATE] Tauri backend v{version} started.");
            println!("[FIBEMATE] PQ crypto: ML-KEM-768 + X25519 + SM2 + Double Ratchet ready.");
            println!("[FIBEMATE] Key store: encrypted on disk (AES-256-GCM device key).");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running FIBEMATE tauri application");
}
