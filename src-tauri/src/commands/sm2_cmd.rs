//! SM2 Elliptic Curve Cryptography Commands (GB/T 32918)
//!
//! Exposes SM2 key generation, signing, verification, ECDH, encryption,
//! and decryption to the Tauri frontend via seven commands.
//!
//! Private keys live exclusively in the Rust KeyStore (AES-256-GCM encrypted).
//! The frontend only receives opaque key_id / ss_id handles and hex-encoded
//! public data.

use num_bigint::BigUint;
use num_traits::Num;
use serde::Serialize;
use tauri::State;

use crate::commands::CryptoState;
use crate::sm2;

// ── Response types ─────────────────────────────────────────────

#[derive(Serialize, Clone)]
pub struct Sm2GenerateResponse {
    pub key_id: String,
    pub public_key_hex: String,
}

#[derive(Serialize, Clone)]
pub struct Sm2GetPublicResponse {
    pub key_id: String,
    pub public_key_hex: String,
}

#[derive(Serialize, Clone)]
pub struct Sm2SignResponse {
    pub r: String,
    pub s: String,
}

#[derive(Serialize, Clone)]
pub struct Sm2VerifyResponse {
    pub valid: bool,
}

#[derive(Serialize, Clone)]
pub struct Sm2EcdhResponse {
    pub ss_id: String,
}

#[derive(Serialize, Clone)]
pub struct Sm2EncryptResponse {
    pub c1: String,
    pub c2: String,
}

#[derive(Serialize, Clone)]
pub struct Sm2DecryptResponse {
    pub plaintext: String,
}

// ── Helpers ────────────────────────────────────────────────────

fn store_sm2_key(
    state: &CryptoState,
    key_id: &str,
    public_key_hex: &str,
    d: &BigUint,
) -> Result<(), String> {
    let hex = format!("{:x}", d);
    let mut ks = state.key_store.lock().map_err(|e| e.to_string())?;
    ks.store_secret_key(
        &format!("sm2:{}", key_id),
        public_key_hex.as_bytes(),
        hex.as_bytes(),
        &format!("SM2-{}", &key_id[..8.min(key_id.len())]),
    )
}

fn load_sm2_key(state: &CryptoState, key_id: &str) -> Result<BigUint, String> {
    let ks = state.key_store.lock().map_err(|e| e.to_string())?;
    let data = ks.load_secret_key(&format!("sm2:{}", key_id))?;
    let hex = String::from_utf8(data).map_err(|e| format!("Key data not valid UTF-8: {}", e))?;
    BigUint::from_str_radix(&hex, 16).map_err(|e| format!("Invalid private key hex: {}", e))
}

fn new_key_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn new_ss_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ── Commands ───────────────────────────────────────────────────

/// Generate a new SM2 key pair.
///
/// Private key is immediately stored in the encrypted KeyStore and is
/// **never** returned. The frontend receives only an opaque key_id and
/// the uncompressed public key hex.
#[tauri::command]
pub fn sm2_generate(state: State<CryptoState>) -> Result<Sm2GenerateResponse, String> {
    let keypair = sm2::generate_key_pair();
    let public_key_hex = sm2::pk_to_hex(&keypair.public_key);
    let key_id = new_key_id();

    store_sm2_key(&state, &key_id, &public_key_hex, &keypair.private_key)?;

    Ok(Sm2GenerateResponse {
        key_id,
        public_key_hex,
    })
}

/// Derive and return the public key for an existing SM2 key_id.
#[tauri::command]
pub fn sm2_get_public(
    state: State<CryptoState>,
    key_id: String,
) -> Result<Sm2GetPublicResponse, String> {
    let d = load_sm2_key(&state, &key_id)?;
    let pk = sm2::public_key_from_private(&d);
    let public_key_hex = sm2::pk_to_hex(&pk);

    Ok(Sm2GetPublicResponse {
        key_id,
        public_key_hex,
    })
}

/// Import an existing SM2 private key (migration from legacy JS storage).
///
/// Validates the private key is in `[1, n-1]`, derives the public key,
/// stores the private key in the encrypted KeyStore, and returns the same
/// `key_id` + `public_key_hex` shape as `sm2_generate`.
///
/// This is the migration entry point: the frontend reads the legacy
/// `p2p_gm_keypair` (plaintext hex) once, calls this command, and then
/// deletes the plaintext copy.
#[tauri::command]
pub fn sm2_import(
    state: State<CryptoState>,
    private_key_hex: String,
) -> Result<Sm2GenerateResponse, String> {
    let d = BigUint::from_str_radix(&private_key_hex, 16)
        .map_err(|_| "Invalid private key hex".to_string())?;

    // Range check: d ∈ [1, n-1]
    if d == BigUint::from(0u32) || d >= *sm2::SM2_N {
        return Err("Private key out of range [1, n-1]".to_string());
    }

    let pk = sm2::public_key_from_private(&d);
    let public_key_hex = sm2::pk_to_hex(&pk);
    let key_id = new_key_id();

    store_sm2_key(&state, &key_id, &public_key_hex, &d)?;

    Ok(Sm2GenerateResponse {
        key_id,
        public_key_hex,
    })
}

/// Sign a message hash with an SM2 private key.
///
/// `msg_hash` must be a 64-character hex string (32-byte digest, e.g. SHA-256).
#[tauri::command]
pub fn sm2_sign(
    state: State<CryptoState>,
    key_id: String,
    msg_hash: String,
) -> Result<Sm2SignResponse, String> {
    let d = load_sm2_key(&state, &key_id)?;
    let h = BigUint::from_str_radix(&msg_hash, 16)
        .map_err(|e| format!("Invalid msg_hash hex: {}", e))?;
    let sig = sm2::sign(&d, &h);

    Ok(Sm2SignResponse { r: sig.r, s: sig.s })
}

/// Verify an SM2 signature against a message hash.
///
/// `public_key_hex` must be uncompressed (`04||x||y`, 130 hex chars).
#[tauri::command]
pub fn sm2_verify(
    public_key_hex: String,
    msg_hash: String,
    r: String,
    s: String,
) -> Result<Sm2VerifyResponse, String> {
    let h = BigUint::from_str_radix(&msg_hash, 16)
        .map_err(|e| format!("Invalid msg_hash hex: {}", e))?;
    let valid = sm2::verify(&public_key_hex, &h, &r, &s)?;

    Ok(Sm2VerifyResponse { valid })
}

/// Compute an SM2 ECDH shared secret with a peer's public key.
///
/// The 32-byte secret is stored in `shared_secrets` under the opaque `ss_id`.
/// Only the `ss_id` handle is returned — the raw secret never reaches JS.
#[tauri::command]
pub fn sm2_ecdh(
    state: State<CryptoState>,
    key_id: String,
    peer_public_key_hex: String,
) -> Result<Sm2EcdhResponse, String> {
    let d = load_sm2_key(&state, &key_id)?;
    let shared = sm2::compute_shared_secret(&d, &peer_public_key_hex)?;

    // Truncate to 32 bytes for Double Ratchet (first half of 64-byte result)
    let mut secret32 = [0u8; 32];
    secret32.copy_from_slice(&shared[..32]);

    let ss_id = new_ss_id();
    let mut secrets = state.shared_secrets.lock().map_err(|e| e.to_string())?;
    secrets.insert(format!("sm2:{}", ss_id), secret32);

    Ok(Sm2EcdhResponse { ss_id })
}

/// Encrypt plaintext for a recipient identified by their SM2 public key.
#[tauri::command]
pub fn sm2_encrypt(
    public_key_hex: String,
    plaintext: String,
) -> Result<Sm2EncryptResponse, String> {
    let ct = sm2::encrypt(&public_key_hex, plaintext.as_bytes())?;

    Ok(Sm2EncryptResponse {
        c1: ct.c1,
        c2: ct.c2,
    })
}

/// Decrypt an SM2 ciphertext using the private key identified by `key_id`.
#[tauri::command]
pub fn sm2_decrypt(
    state: State<CryptoState>,
    key_id: String,
    c1: String,
    c2: String,
) -> Result<Sm2DecryptResponse, String> {
    let d = load_sm2_key(&state, &key_id)?;
    let plaintext_bytes = sm2::decrypt(&d, &c1, &c2)?;
    let plaintext = String::from_utf8(plaintext_bytes)
        .map_err(|e| format!("Decrypted data is not valid UTF-8: {}", e))?;

    Ok(Sm2DecryptResponse { plaintext })
}

// ── Standard SM2 (GB/T 32918.4 — KDF + C3 integrity) ──────────

#[derive(Serialize, Clone)]
pub struct Sm2EncryptFullResponse {
    /// Full wire-format ciphertext: C1 || C3 || C2 (hex).
    pub ciphertext: String,
}

/// Encrypt plaintext for a recipient's SM2 public key (standard mode).
///
/// Uses the same GB/T 32918.4 construction as the frontend `SM2Browser`:
/// C1||C3||C2 with SM3 KDF and SM3 integrity tag. This is the wire format
/// that must be used for interop with the JS GM messaging path.
#[tauri::command]
pub fn sm2_encrypt_full(
    public_key_hex: String,
    plaintext: String,
) -> Result<Sm2EncryptFullResponse, String> {
    let ct = sm2::encrypt_standard(&public_key_hex, plaintext.as_bytes())?;
    Ok(Sm2EncryptFullResponse {
        ciphertext: ct.to_hex(),
    })
}

/// Decrypt a standard SM2 ciphertext using the private key identified by `key_id`.
///
/// `ciphertext` is the C1||C3||C2 wire format. The C3 integrity tag is
/// verified before the plaintext is returned.
#[tauri::command]
pub fn sm2_decrypt_full(
    state: State<CryptoState>,
    key_id: String,
    ciphertext: String,
) -> Result<Sm2DecryptResponse, String> {
    let d = load_sm2_key(&state, &key_id)?;
    let parsed = sm2::Sm2StandardCipher::from_hex(&ciphertext)?;
    let plaintext_bytes = sm2::decrypt_standard(&d, &parsed)?;
    let plaintext = String::from_utf8(plaintext_bytes)
        .map_err(|e| format!("Decrypted data is not valid UTF-8: {}", e))?;

    Ok(Sm2DecryptResponse { plaintext })
}

// ── Standard SM2 signature with ZA (frontend-aligned) ────────

/// Sign a raw message with ZA digest derivation (GB/T 32918.2 §5.5).
///
/// Matches the frontend `SM2Browser.sign` default (`hash=true`) which derives
/// `e = SM3(ZA || M)`. `user_id` defaults to the frontend's fixed
/// `"1234567812345678"`. Returns `r` and `s` as 64-char hex each (concatenated
/// they form the same 128-char format the frontend uses).
#[tauri::command]
pub fn sm2_sign_full(
    state: State<CryptoState>,
    key_id: String,
    message: String,
    user_id: Option<String>,
) -> Result<Sm2SignResponse, String> {
    let d = load_sm2_key(&state, &key_id)?;
    let pk = sm2::public_key_from_private(&d);
    let pk_hex = sm2::pk_to_hex(&pk);
    let uid = user_id.unwrap_or_else(|| "1234567812345678".to_string());

    let sig = sm2::sign_with_za(&d, &pk_hex, &uid, message.as_bytes())?;
    Ok(Sm2SignResponse { r: sig.r, s: sig.s })
}

/// Verify a ZA-derived SM2 signature against a raw message.
#[tauri::command]
pub fn sm2_verify_full(
    public_key_hex: String,
    message: String,
    r: String,
    s: String,
    user_id: Option<String>,
) -> Result<Sm2VerifyResponse, String> {
    let uid = user_id.unwrap_or_else(|| "1234567812345678".to_string());
    let valid = sm2::verify_with_za(&public_key_hex, &uid, message.as_bytes(), &r, &s)?;
    Ok(Sm2VerifyResponse { valid })
}
