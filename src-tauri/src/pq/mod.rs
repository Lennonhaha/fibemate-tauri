//! Post-Quantum Cryptography Module
//!
//! Re-exports ML-KEM-768 and ML-DSA-65 from rustpq,
//! plus helpers for the FIBEMATE hybrid key exchange.
//!
//! Note: Most PQ types are currently unused at the command layer (future integration).
#![allow(dead_code)]
//!
//! Migrated from: D:\FIBEMATE\01_Rust源码_E盘\src\pq\mod.rs
//! Target: Tauri v2 desktop backend

use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod hybrid;

// ── Size constants ──────────────────────────────────────────────

/// ML-KEM-768 public key size (FIPS 203)
pub const MLKEM768_PK_SIZE: usize = 1184;
/// ML-KEM-768 secret key size
pub const MLKEM768_SK_SIZE: usize = 2400;
/// ML-KEM-768 ciphertext size
pub const MLKEM768_CT_SIZE: usize = 1088;
/// ML-KEM-768 shared secret size (always 32 bytes)
pub const MLKEM768_SS_SIZE: usize = 32;

/// ML-DSA-65 public key size (FIPS 204)
pub const MLDSA65_PK_SIZE: usize = 1952;
/// ML-DSA-65 secret key size
pub const MLDSA65_SK_SIZE: usize = 4032;
/// ML-DSA-65 signature size
pub const MLDSA65_SIG_SIZE: usize = 3293;

// ── Re-export rustpq types ──────────────────────────────────────

pub use rustpq::ml_kem::mlkem768::{
    Ciphertext as MlKem768Ciphertext, PublicKey as MlKem768PublicKey,
    SecretKey as MlKem768SecretKey,
};

pub use rustpq::ml_dsa::mldsa65;

// ── High-level wrappers ─────────────────────────────────────────

/// Generate ML-KEM-768 keypair
pub fn mlkem768_generate() -> (MlKem768PublicKey, MlKem768SecretKey) {
    rustpq::ml_kem::mlkem768::generate(&mut OsRng)
}

/// Encapsulate to a public key (returns ciphertext + shared secret)
pub fn mlkem768_encapsulate(
    pk: &MlKem768PublicKey,
) -> (MlKem768Ciphertext, [u8; MLKEM768_SS_SIZE]) {
    let (ct, ss) = rustpq::ml_kem::mlkem768::encapsulate(pk, &mut OsRng);
    let ss_bytes = *ss.as_bytes();
    (ct, ss_bytes)
}

/// Decapsulate ciphertext to shared secret
pub fn mlkem768_decapsulate(
    sk: &MlKem768SecretKey,
    ct: &MlKem768Ciphertext,
) -> [u8; MLKEM768_SS_SIZE] {
    let ss = rustpq::ml_kem::mlkem768::decapsulate(sk, ct);
    *ss.as_bytes()
}

/// Byte-level decapsulate — for use with KeyStore loaded raw keys.
/// Takes raw byte arrays and returns the shared secret.
pub fn mlkem768_decapsulate_bytes(
    sk: &[u8; MLKEM768_SK_SIZE],
    ct: &[u8; MLKEM768_CT_SIZE],
) -> [u8; MLKEM768_SS_SIZE] {
    let sk_typed = MlKem768SecretKey::from_bytes(sk)
        .map_err(|e| panic!("Invalid ML-KEM secret key: {e}"))
        .unwrap();
    let ct_typed = MlKem768Ciphertext::from_bytes(ct)
        .map_err(|e| panic!("Invalid ML-KEM ciphertext: {e}"))
        .unwrap();
    mlkem768_decapsulate(&sk_typed, &ct_typed)
}

/// ML-KEM-768 keypair with secure memory handling
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem768KeyPair {
    pub public_key: [u8; MLKEM768_PK_SIZE],
    #[zeroize]
    pub secret_key: [u8; MLKEM768_SK_SIZE],
}

impl MlKem768KeyPair {
    pub fn generate() -> Self {
        let (pk, sk) = mlkem768_generate();
        let mut public_key = [0u8; MLKEM768_PK_SIZE];
        let mut secret_key = [0u8; MLKEM768_SK_SIZE];
        public_key.copy_from_slice(pk.as_bytes());
        secret_key.copy_from_slice(sk.as_bytes());
        Self {
            public_key,
            secret_key,
        }
    }

    pub fn from_bytes(pk: &[u8; MLKEM768_PK_SIZE], sk: &[u8; MLKEM768_SK_SIZE]) -> Self {
        Self {
            public_key: *pk,
            secret_key: *sk,
        }
    }
}

/// ML-KEM-768 encapsulation result
#[derive(Clone)]
pub struct MlKem768Encapsulation {
    pub ciphertext: [u8; MLKEM768_CT_SIZE],
    pub shared_secret: [u8; MLKEM768_SS_SIZE],
}

impl MlKem768Encapsulation {
    pub fn encapsulate(pk: &MlKem768PublicKey) -> Self {
        let (ct, ss) = mlkem768_encapsulate(pk);
        let mut ct_bytes = [0u8; MLKEM768_CT_SIZE];
        ct_bytes.copy_from_slice(ct.as_bytes());
        Self {
            ciphertext: ct_bytes,
            shared_secret: ss,
        }
    }

    pub fn from_bytes(ct: &[u8; MLKEM768_CT_SIZE], ss: &[u8; MLKEM768_SS_SIZE]) -> Self {
        Self {
            ciphertext: *ct,
            shared_secret: *ss,
        }
    }
}

/// ML-DSA-65 signing keypair
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65KeyPair {
    pub public_key: [u8; MLDSA65_PK_SIZE],
    #[zeroize]
    pub secret_key: [u8; MLDSA65_SK_SIZE],
}

impl MlDsa65KeyPair {
    pub fn generate() -> Self {
        let (pk, sk) = mldsa65::generate(&mut OsRng);
        let mut public_key = [0u8; MLDSA65_PK_SIZE];
        let mut secret_key = [0u8; MLDSA65_SK_SIZE];
        public_key.copy_from_slice(pk.as_bytes());
        secret_key.copy_from_slice(sk.as_bytes());
        Self {
            public_key,
            secret_key,
        }
    }

    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<[u8; MLDSA65_SIG_SIZE], String> {
        let sk = mldsa65::SecretKey::from_bytes(&self.secret_key)
            .map_err(|e| format!("Invalid SK: {e}"))?;
        let sig = mldsa65::sign(&sk, message, context, &mut OsRng)
            .map_err(|e| format!("Sign failed: {e}"))?;
        let mut out = [0u8; MLDSA65_SIG_SIZE];
        out.copy_from_slice(sig.as_bytes());
        Ok(out)
    }

    pub fn verify(
        &self,
        message: &[u8],
        context: &[u8],
        sig: &[u8; MLDSA65_SIG_SIZE],
    ) -> Result<bool, String> {
        let pk = mldsa65::PublicKey::from_bytes(&self.public_key)
            .map_err(|e| format!("Invalid PK: {e}"))?;
        let sig =
            mldsa65::Signature::from_bytes(sig).map_err(|_| "Invalid sig format".to_string())?;
        Ok(mldsa65::verify(&pk, message, context, &sig).is_ok())
    }
}

/// SHA3-256 fingerprint → "XX XX XX XX XX XX XX XX"
pub fn fingerprint(data: &[u8]) -> String {
    let hash = Sha3_256::digest(data);
    hash[..8]
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Validate ML-KEM-768 public key
pub fn is_valid_mlkem768_pk(pk: &[u8]) -> bool {
    pk.len() == MLKEM768_PK_SIZE && MlKem768PublicKey::from_bytes(pk).is_ok()
}

/// Validate ML-KEM-768 ciphertext
pub fn is_valid_mlkem768_ct(ct: &[u8]) -> bool {
    ct.len() == MLKEM768_CT_SIZE && MlKem768Ciphertext::from_bytes(ct).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem768_roundtrip() {
        let (pk, sk) = mlkem768_generate();
        let (ct, ss1) = mlkem768_encapsulate(&pk);
        let ss2 = mlkem768_decapsulate(&sk, &ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_mldsa65_sign_verify() {
        let kp = MlDsa65KeyPair::generate();
        let sig = kp.sign(b"hello", b"context").unwrap();
        assert!(kp.verify(b"hello", b"context", &sig).unwrap());
        assert!(!kp.verify(b"wrong", b"context", &sig).unwrap());
    }

    #[test]
    fn test_fingerprint() {
        let fp = fingerprint(b"test");
        assert_eq!(fp.len(), 23);
    }
}
