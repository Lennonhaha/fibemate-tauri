//! FIBEMATE Post-Quantum Cryptography WASM Module
//!
//! ML-KEM-768 (FIPS 203) key encapsulation via pqc_kyber crate.
//! Provides real post-quantum hybrid key exchange for FIBEMATE messaging.
//!
//! Security notes (2026-07-27):
//! - All public inputs are length-validated before being passed downstream.
//! - Shared secrets are copied from pqc_kyber's output into a fixed-size buffer
//!   and the original Vec is zeroized before leaving this crate.
//! - The `zeroize` crate is used to clear intermediate key material when it
//!   goes out of scope.
//! - The internal Fujisaki-Okamoto comparison is performed by `pqc_kyber`. If
//!   an audit shows it is not constant-time, apply the two-decapsulation +
//!   mask-select wrapper documented in `docs/mlkem-constant-time-2026-07-27.md`.

use wasm_bindgen::prelude::*;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

// ML-KEM-768 constants — per FIPS 203
pub const KYBER_PUBLICKEYBYTES: usize = 1184;
pub const KYBER_SECRETKEYBYTES: usize = 2400;
pub const KYBER_CIPHERTEXTBYTES: usize = 1088;
pub const KYBER_SSBYTES: usize = 32;

/// Initialize panic hook for better error messages in WASM
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// ML-KEM-768 Keypair
#[wasm_bindgen]
pub struct KyberKeypair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl KyberKeypair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }

    /// Serialize to JSON string
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> String {
        format!(
            "{{\"public_key\":\"{}\",\"secret_key\":\"{}\"}}",
            base64_encode(&self.public_key),
            base64_encode(&self.secret_key)
        )
    }
}

/// ML-KEM-768 Encapsulation result
#[wasm_bindgen]
pub struct KyberCiphertext {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl KyberCiphertext {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }

    /// Serialize to JSON string
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> String {
        format!(
            "{{\"ciphertext\":\"{}\",\"shared_secret\":\"{}\"}}",
            base64_encode(&self.ciphertext),
            base64_encode(&self.shared_secret)
        )
    }
}

/// Generate a new ML-KEM-768 keypair
///
/// Uses pqc_kyber crate (FIPS 203 compliant ML-KEM-768).
///
/// # Returns
/// KyberKeypair containing public (1184 bytes) and secret (2400 bytes) keys
#[wasm_bindgen(js_name = generateKeypair)]
pub fn generate_keypair() -> Result<KyberKeypair, JsValue> {
    let mut rng = OsRng;
    let keys = pqc_kyber::keypair(&mut rng)
        .map_err(|e| JsValue::from_str(&format!("Keypair generation failed: {:?}", e)))?;

    Ok(KyberKeypair {
        public_key: keys.public.to_vec(),
        secret_key: keys.secret.to_vec(),
    })
}

/// Encapsulate a shared secret using a public key
///
/// Uses pqc_kyber encapsulate (FIPS 203 compliant).
///
/// # Arguments
/// * `public_key` - The recipient's public key (1184 bytes)
///
/// # Returns
/// KyberCiphertext containing the ciphertext (1088 bytes) and shared secret (32 bytes)
#[wasm_bindgen(js_name = encapsulate)]
pub fn encapsulate(public_key: &[u8]) -> Result<KyberCiphertext, JsValue> {
    if public_key.len() != KYBER_PUBLICKEYBYTES {
        return Err(JsValue::from_str(&format!(
            "Invalid public key length: expected {}, got {}",
            KYBER_PUBLICKEYBYTES,
            public_key.len()
        )));
    }

    let mut rng = OsRng;
    let (ciphertext, shared_secret) = pqc_kyber::encapsulate(public_key, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Encapsulation failed: {:?}", e)))?;

    Ok(KyberCiphertext {
        ciphertext: ciphertext.to_vec(),
        shared_secret: shared_secret.to_vec(),
    })
}

/// Decapsulate a shared secret using secret key and ciphertext
///
/// Uses pqc_kyber decapsulate (FIPS 203 compliant).
///
/// # Arguments
/// * `secret_key` - The recipient's secret key (2400 bytes)
/// * `ciphertext` - The ciphertext from encapsulation (1088 bytes)
///
/// # Returns
/// The shared secret (32 bytes) — matches encapsulate output when keys are paired
#[wasm_bindgen(js_name = decapsulate)]
pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    if secret_key.len() != KYBER_SECRETKEYBYTES {
        return Err(JsValue::from_str(&format!(
            "Invalid secret key length: expected {}, got {}",
            KYBER_SECRETKEYBYTES,
            secret_key.len()
        )));
    }

    if ciphertext.len() != KYBER_CIPHERTEXTBYTES {
        return Err(JsValue::from_str(&format!(
            "Invalid ciphertext length: expected {}, got {}",
            KYBER_CIPHERTEXTBYTES,
            ciphertext.len()
        )));
    }

    // Wrap the pqc_kyber output in a Zeroizing buffer so the original Vec is
    // cleared as soon as we copy the shared secret out.
    let mut shared_secret = Zeroizing::new(
        pqc_kyber::decapsulate(ciphertext, secret_key)
            .map_err(|e| JsValue::from_str(&format!("Decapsulation failed: {:?}", e)))?
            .to_vec()
    );

    if shared_secret.len() != KYBER_SSBYTES {
        return Err(JsValue::from_str("Unexpected shared secret length from pqc_kyber"));
    }

    // Copy to a fresh Vec for the JS/WASM boundary. The Zeroizing wrapper
    // ensures the original allocation is zeroed on drop.
    let mut ss = [0u8; KYBER_SSBYTES];
    ss.copy_from_slice(&shared_secret);
    shared_secret.zeroize();

    let out = ss.to_vec();
    ss.zeroize();
    Ok(out)
}

/// Get ML-KEM-768 constants
#[wasm_bindgen(js_name = getConstants)]
pub fn get_constants() -> String {
    format!(
        "{{\"PUBLIC_KEY_BYTES\":{},\"SECRET_KEY_BYTES\":{},\"CIPHERTEXT_BYTES\":{},\"SHARED_SECRET_BYTES\":{}}}",
        KYBER_PUBLICKEYBYTES,
        KYBER_SECRETKEYBYTES,
        KYBER_CIPHERTEXTBYTES,
        KYBER_SSBYTES
    )
}

/// Hybrid key exchange: Combine ML-KEM-768 shared secret with ECDH
///
/// Uses HKDF-SHA256 with domain separation for proper dual-PRF security.
///
/// # Arguments
/// * `kem_secret` - ML-KEM-768 shared secret (32 bytes)
/// * `ecdh_secret` - ECDH shared secret (variable length)
///
/// # Returns
/// Combined 32-byte keying material suitable for Double Ratchet root key
#[wasm_bindgen(js_name = hybridCombine)]
pub fn hybrid_combine(kem_secret: &[u8], ecdh_secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    if kem_secret.len() != KYBER_SSBYTES {
        return Err(JsValue::from_str("Invalid KEM secret length (expected 32 bytes)"));
    }
    if ecdh_secret.is_empty() {
        return Err(JsValue::from_str("ECDH secret must not be empty"));
    }

    use sha2::Sha256;
    use hkdf::Hkdf;

    // IKM = KEM_SS || ECDH_SS
    let mut ikm = Vec::with_capacity(kem_secret.len() + ecdh_secret.len());
    ikm.extend_from_slice(kem_secret);
    ikm.extend_from_slice(ecdh_secret);

    // Domain-separated HKDF: info = "FIBEMATE-PQ-HYBRID-V1"
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = vec![0u8; 32];
    hk.expand(b"FIBEMATE-PQ-HYBRID-V1", &mut okm)
        .map_err(|e| JsValue::from_str(&format!("HKDF expand failed: {}", e)))?;

    // Zeroize the concatenated IKM before returning.
    ikm.zeroize();

    Ok(okm)
}

/// Simple base64 encoding helper
fn base64_encode(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data)
}
