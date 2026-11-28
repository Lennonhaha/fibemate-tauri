use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tauri::Manager;

// Per-account device identities, stored OUTSIDE the WebView2 profile.
//
// Why: the id used to live only in localStorage, which dies with the WebView2
// user-data directory. A reinstall (or a profile reset) silently minted a new
// id, the server created a new device row, and every stale row kept isRead
// false until it was pruned. Keeping the mapping in the app data dir - the
// same place the encrypted key store lives - makes the install id survive
// reinstalls.

const FILE_NAME: &str = "device_identities.json";

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    accounts: BTreeMap<String, String>,
}

fn store_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("app data dir unavailable: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir.join(FILE_NAME))
}

fn normalize_account(account: &str) -> String {
    account.trim().to_lowercase()
}

fn is_uuid_like(id: &str) -> bool {
    let b = id.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, c) in b.iter().enumerate() {
        let ok = match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        };
        if !ok {
            return false;
        }
    }
    true
}

fn read_store(path: &Path) -> StoreFile {
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str::<StoreFile>(&text).unwrap_or_default(),
        Err(_) => StoreFile::default(),
    }
}

fn write_store(path: &Path, store: &StoreFile) -> Result<(), String> {
    let body = serde_json::to_string_pretty(store).map_err(|e| format!("serialize: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, body.as_bytes()).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", tmp.display()))?;
    Ok(())
}

#[tauri::command]
pub fn device_identity_get(app: tauri::AppHandle, account: String) -> Result<Option<String>, String> {
    let account = normalize_account(&account);
    if account.is_empty() {
        return Ok(None);
    }
    let path = store_path(&app)?;
    let store = read_store(&path);
    Ok(store.accounts.get(&account).cloned())
}

#[tauri::command]
pub fn device_identity_all(app: tauri::AppHandle) -> Result<BTreeMap<String, String>, String> {
    let path = store_path(&app)?;
    Ok(read_store(&path).accounts)
}

#[tauri::command]
pub fn device_identity_remember(
    app: tauri::AppHandle,
    account: String,
    device_id: String,
) -> Result<(), String> {
    let account = normalize_account(&account);
    if account.is_empty() {
        return Err("account is required".into());
    }
    let id = device_id.trim().to_lowercase();
    if !is_uuid_like(&id) {
        return Err("device id is not a UUID".into());
    }
    let path = store_path(&app)?;
    let mut store = read_store(&path);
    if store.accounts.get(&account) == Some(&id) {
        return Ok(());
    }
    store.version = 1;
    store.accounts.insert(account, id);
    write_store(&path, &store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_shape_is_checked() {
        assert!(is_uuid_like("495cb9f8-e06b-414d-9fe9-6e803c386318"));
        assert!(!is_uuid_like("495cb9f8e06b414d9fe96e803c386318"));
        assert!(!is_uuid_like("zzzzzzzz-e06b-414d-9fe9-6e803c386318"));
        assert!(!is_uuid_like(""));
    }

    #[test]
    fn account_names_are_case_insensitive() {
        assert_eq!(normalize_account("  009 "), "009");
        assert_eq!(normalize_account("Alice"), "alice");
    }

    #[test]
    fn store_round_trips() {
        let dir = std::env::temp_dir().join(format!("fk-device-id-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE_NAME);
        let mut store = StoreFile { version: 1, accounts: BTreeMap::new() };
        store
            .accounts
            .insert("009".to_string(), "495cb9f8-e06b-414d-9fe9-6e803c386318".to_string());
        write_store(&path, &store).unwrap();
        let back = read_store(&path);
        assert_eq!(back.accounts.get("009").unwrap(), "495cb9f8-e06b-414d-9fe9-6e803c386318");
        let _ = fs::remove_dir_all(&dir);
    }
}
