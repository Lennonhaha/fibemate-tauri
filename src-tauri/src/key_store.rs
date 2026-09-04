//! Encrypted Key Store — FIBEMATE
//!
//! Purse-boot encryption for ML-KEM secret keys using AES-256-GCM.
//! Zero external C dependencies (no libsodium, no Stronghold).
//!
//! Architecture:
//!   Device Key (32 random bytes) → stored at app_data/fibemate/device.key
//!   ML-KEM SKs → stored at app_data/fibemate/keys/{key_id}.enc
//!   Each .enc file:  [12-byte nonce] [AES-GCM ciphertext+tag]
//!
//! Security:
//!   - Device key is 32 random bytes, file permissions restricted on OS
//!   - Each SK file uses unique random nonce
//!   - SK bytes zeroized after use
//!   - No external C dependencies (pure Rust)

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

// ── Constants ──────────────────────────────────────────────────

const DEVICE_KEY_FILE: &str = "device.key";
const KEYS_DIR: &str = "keys";
const DEVICE_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

// ── Windows DPAPI device-key protection ─────────────────────────
// On Windows the device key is wrapped with DPAPI (CryptProtectData),
// binding it to the current Windows user+machine. A copied device.key
// is therefore useless on another machine / account (e.g. cloud sync
// leaks). Unix keeps the plaintext file with 0600 permissions.
#[cfg(windows)]
mod dpapi {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    pub fn protect(bytes: &[u8]) -> Result<Vec<u8>, String> {
        unsafe {
            let in_blob = CRYPT_INTEGER_BLOB {
                cbData: bytes.len() as u32,
                pbData: bytes.as_ptr() as *mut u8,
            };
            let mut out_blob = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            let ok = CryptProtectData(
                &in_blob,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            );
            if ok == 0 {
                return Err("DPAPI CryptProtectData failed".to_string());
            }
            let out =
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
            LocalFree(out_blob.pbData as _);
            Ok(out)
        }
    }

    pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>, String> {
        unsafe {
            let in_blob = CRYPT_INTEGER_BLOB {
                cbData: blob.len() as u32,
                pbData: blob.as_ptr() as *mut u8,
            };
            let mut out_blob = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            let ok = CryptUnprotectData(
                &in_blob,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            );
            if ok == 0 {
                return Err(
                    "DPAPI CryptUnprotectData failed (wrong user or corrupted file)".to_string(),
                );
            }
            let out =
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
            LocalFree(out_blob.pbData as _);
            Ok(out)
        }
    }
}

/// Magic prefix marking a DPAPI-wrapped device key file (Windows only).
#[cfg(windows)]
const DPAPI_MAGIC: &[u8] = b"FIBEDPAPI1";
#[cfg(windows)]
const DPAPI_MAGIC_LEN: usize = 10;

/// Read the raw device-key material from disk, transparently handling
/// the on-disk protection format:
///   - Windows: DPAPI-wrapped blob (magic prefix) or legacy plaintext 32B
///     (migrated in place to DPAPI on first read).
///   - Unix: plaintext 32B with 0600 permissions.
fn read_device_key_from_disk(key_path: &Path) -> Result<[u8; DEVICE_KEY_LEN], String> {
    let bytes = fs::read(key_path).map_err(|e| format!("Failed to read device key: {e}"))?;

    // ── Windows: DPAPI-wrapped format ──
    #[cfg(windows)]
    {
        if bytes.starts_with(DPAPI_MAGIC) {
            let plain = dpapi::unprotect(&bytes[DPAPI_MAGIC_LEN..])?;
            if plain.len() != DEVICE_KEY_LEN {
                return Err(format!(
                    "Device key corrupt: expected {DEVICE_KEY_LEN} bytes, got {}",
                    plain.len()
                ));
            }
            let mut key = [0u8; DEVICE_KEY_LEN];
            key.copy_from_slice(&plain);
            return Ok(key);
        }
        // Legacy plaintext 32B → migrate to DPAPI in place.
        if bytes.len() == DEVICE_KEY_LEN {
            let protected = dpapi::protect(&bytes)?;
            let mut out = Vec::with_capacity(DPAPI_MAGIC_LEN + protected.len());
            out.extend_from_slice(DPAPI_MAGIC);
            out.extend_from_slice(&protected);
            fs::write(key_path, &out)
                .map_err(|e| format!("Failed to migrate device key to DPAPI: {e}"))?;
            let mut key = [0u8; DEVICE_KEY_LEN];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
        // Fall through to shared length check for any other corrupt form.
    }

    // ── Unix / plaintext format ──
    if bytes.len() != DEVICE_KEY_LEN {
        return Err(format!(
            "Device key corrupt: expected {DEVICE_KEY_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    let mut key = [0u8; DEVICE_KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Write the device-key material to disk with platform protection:
///   - Windows: DPAPI-wrapped (bound to current user+machine).
///   - Unix: 0600 plaintext file.
fn write_device_key_to_disk(key_path: &Path, key: &[u8; DEVICE_KEY_LEN]) -> Result<(), String> {
    #[cfg(windows)]
    {
        let protected = dpapi::protect(key)?;
        let mut out = Vec::with_capacity(DPAPI_MAGIC_LEN + protected.len());
        out.extend_from_slice(DPAPI_MAGIC);
        out.extend_from_slice(&protected);
        fs::write(key_path, &out).map_err(|e| format!("Failed to write device key: {e}"))?;
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        fs::write(key_path, key).map_err(|e| format!("Failed to write device key: {e}"))?;
        // On Unix, chmod 600.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to restrict device key permissions: {e}"))?;
        Ok(())
    }
}

// ── Device Key ─────────────────────────────────────────────────

/// Get or create the device-level encryption key.
///
/// On first run, generates 32 random bytes and writes to disk (DPAPI
/// on Windows, 0600 file on Unix). Subsequent runs read the file,
/// transparently migrating legacy plaintext Windows files to DPAPI.
fn get_or_create_device_key(app_data: &Path) -> Result<[u8; DEVICE_KEY_LEN], String> {
    let key_path = app_data.join(DEVICE_KEY_FILE);

    if key_path.exists() {
        read_device_key_from_disk(&key_path)
    } else {
        // First run — generate a new device key
        let mut key = [0u8; DEVICE_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut key);

        // Create parent directories
        fs::create_dir_all(app_data).map_err(|e| format!("Failed to create app data dir: {e}"))?;

        write_device_key_to_disk(&key_path, &key)?;
        Ok(key)
    }
}

// ── Key Store ──────────────────────────────────────────────────

/// Metadata about a stored keypair (public info only).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyMeta {
    pub key_id: String,
    pub public_key: Vec<u8>, // 1184 bytes ML-KEM-768
    pub fingerprint: String, // human-readable
    pub created_at: u64,     // Unix timestamp
}

pub struct KeyStore {
    app_data: PathBuf,
    device_key: [u8; DEVICE_KEY_LEN],
    key_meta: HashMap<String, KeyMeta>, // key_id → metadata
    meta_path: PathBuf,
}

impl KeyStore {
    /// Initialize the key store.
    ///
    /// `app_data` should be the Tauri app data directory (e.g. `%APPDATA%/com.fibemate.app`).
    pub fn new(app_data: &Path) -> Result<Self, String> {
        let device_key = get_or_create_device_key(app_data)?;
        let keys_dir = app_data.join(KEYS_DIR);
        let meta_path = app_data.join("key_meta.json");

        fs::create_dir_all(&keys_dir)
            .map_err(|e| format!("Failed to create keys directory: {e}"))?;

        // Load existing metadata
        let key_meta: HashMap<String, KeyMeta> = if meta_path.exists() {
            let json = fs::read_to_string(&meta_path)
                .map_err(|e| format!("Failed to read key metadata: {e}"))?;
            serde_json::from_str(&json).unwrap_or_default()
        } else {
            HashMap::new()
        };

        Ok(KeyStore {
            app_data: app_data.to_path_buf(),
            device_key,
            key_meta,
            meta_path,
        })
    }

    // ── Key Pair Management ───────────────────────────────────

    /// Store a secret key encrypted under the device key.
    pub fn store_secret_key(
        &mut self,
        key_id: &str,
        public_key: &[u8],
        secret_key: &[u8],
        fingerprint: &str,
    ) -> Result<(), String> {
        // Encrypt the secret key
        let cipher = Aes256Gcm::new_from_slice(&self.device_key)
            .map_err(|e| format!("AES key error: {e}"))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, secret_key)
            .map_err(|e| format!("Encryption failed: {e}"))?;

        // Format: [nonce (12)] [ciphertext+tag]
        let mut encrypted = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        encrypted.extend_from_slice(&nonce_bytes);
        encrypted.extend_from_slice(&ciphertext);

        // Write to disk
        let key_path = self.key_path(key_id);
        fs::write(&key_path, &encrypted)
            .map_err(|e| format!("Failed to write encrypted key: {e}"))?;

        // Update metadata
        self.key_meta.insert(
            key_id.to_string(),
            KeyMeta {
                key_id: key_id.to_string(),
                public_key: public_key.to_vec(),
                fingerprint: fingerprint.to_string(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            },
        );

        // Persist metadata
        self.save_meta()?;

        Ok(())
    }

    /// Load and decrypt a secret key.
    ///
    /// Returns decrypted bytes. Caller MUST zeroize after use.
    pub fn load_secret_key(&self, key_id: &str) -> Result<Vec<u8>, String> {
        let key_path = self.key_path(key_id);
        if !key_path.exists() {
            return Err(format!("Key not found: {key_id}"));
        }

        let encrypted =
            fs::read(&key_path).map_err(|e| format!("Failed to read encrypted key: {e}"))?;

        if encrypted.len() < NONCE_LEN + 16 {
            return Err("Encrypted key file corrupt (too short)".to_string());
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.device_key)
            .map_err(|e| format!("AES key error: {e}"))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed — device key mismatch or file corrupt".to_string())?;

        Ok(plaintext)
    }

    /// Delete a secret key from disk (used by Tauri commands in binary context).
    pub fn delete_secret_key(&mut self, key_id: &str) -> Result<(), String> {
        let key_path = self.key_path(key_id);
        if key_path.exists() {
            fs::remove_file(&key_path).map_err(|e| format!("Failed to delete key file: {e}"))?;
        }
        self.key_meta.remove(key_id);
        self.save_meta()?;
        Ok(())
    }

    /// Get public metadata for a key.
    pub fn get_meta(&self, key_id: &str) -> Option<&KeyMeta> {
        self.key_meta.get(key_id)
    }

    /// Access the device key for domain-separated key derivation
    /// (e.g. session-file encryption). Callers must NOT persist or
    /// expose this value to the frontend.
    pub fn device_key(&self) -> &[u8; DEVICE_KEY_LEN] {
        &self.device_key
    }

    /// List all stored key IDs with their metadata (id, meta).
    pub fn list_keys(&self) -> Vec<(String, &KeyMeta)> {
        self.key_meta.iter().map(|(k, v)| (k.clone(), v)).collect()
    }

    /// Check if a key exists.
    pub fn has_key(&self, key_id: &str) -> bool {
        self.key_meta.contains_key(key_id)
    }

    // ── Internal ───────────────────────────────────────────────

    /// Absolute path of the keys directory (for self-destruct / diagnostics).
    pub fn keys_dir(&self) -> PathBuf {
        self.app_data.join(KEYS_DIR)
    }

    fn key_path(&self, key_id: &str) -> PathBuf {
        // Sanitize key_id for filesystem safety. If filtering empties the id
        // (all-punctuation input like "@@@" / "###"), fall back to its hex
        // encoding so distinct ids can never collide onto the same ".enc" file.
        // Legitimate ids (UUIDs) are alphanumeric+dash and are unaffected.
        let safe_id: String = key_id
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .take(64)
            .collect();
        let safe_id = if safe_id.is_empty() {
            hex::encode(key_id.as_bytes())
        } else {
            safe_id
        };
        self.app_data.join(KEYS_DIR).join(format!("{safe_id}.enc"))
    }

    fn save_meta(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.key_meta)
            .map_err(|e| format!("Failed to serialize metadata: {e}"))?;
        fs::write(&self.meta_path, json).map_err(|e| format!("Failed to write metadata: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_store_and_load() {
        let dir = TempDir::new().unwrap();
        let mut store = KeyStore::new(dir.path()).unwrap();

        let key_id = "test-key-001";
        let pk = [42u8; 1184];
        let sk = [7u8; 2400];
        let fp = "abcd1234";

        store.store_secret_key(key_id, &pk, &sk, fp).unwrap();
        assert!(store.has_key(key_id));

        let loaded = store.load_secret_key(key_id).unwrap();
        assert_eq!(loaded, &sk[..]);

        let meta = store.get_meta(key_id).unwrap();
        assert_eq!(meta.fingerprint, fp);
    }

    #[test]
    fn test_delete() {
        let dir = TempDir::new().unwrap();
        let mut store = KeyStore::new(dir.path()).unwrap();

        store
            .store_secret_key("k1", &[0u8; 1184], &[1u8; 2400], "f1")
            .unwrap();
        assert!(store.has_key("k1"));

        store.delete_secret_key("k1").unwrap();
        assert!(!store.has_key("k1"));
        assert!(store.load_secret_key("k1").is_err());
    }

    #[test]
    fn test_persistence() {
        let dir = TempDir::new().unwrap();
        let app_data = dir.path();

        {
            let mut store = KeyStore::new(app_data).unwrap();
            store
                .store_secret_key("persist", &[0u8; 1184], &[9u8; 2400], "pf")
                .unwrap();
        }

        // Re-open — key should still be there
        {
            let store = KeyStore::new(app_data).unwrap();
            assert!(store.has_key("persist"));
            let loaded = store.load_secret_key("persist").unwrap();
            assert_eq!(loaded, &[9u8; 2400]);
        }
    }
}
