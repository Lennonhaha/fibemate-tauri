//! Hybrid Key Exchange: Classical ECDH + Post-Quantum ML-KEM
//!
//! Combines X25519 (classical) + ML-KEM-768 (post-quantum) via HKDF-SHA3-512.
//!
//! Note: Not yet wired into the command layer (future hybrid DR integration).
#![allow(dead_code)]
#![allow(clippy::large_enum_variant)]
//! Output: 64-byte quantum-resistant combined secret for X3DH / Double Ratchet.
//!
//! Migrated from: D:\FIBEMATE\01_Rust源码_E盘\src\pq\hybrid.rs

use hkdf::Hkdf;
use sha3::Sha3_512;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::pq::{
    MlKem768KeyPair, MlKem768Encapsulation,
    MlKem768PublicKey, MlKem768SecretKey, MlKem768Ciphertext,
    MLKEM768_PK_SIZE, MLKEM768_SK_SIZE, MLKEM768_CT_SIZE, MLKEM768_SS_SIZE,
};

// ── Hybrid Mode ─────────────────────────────────────────────────

/// Hybrid key exchange mode
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HybridMode {
    /// Classic X25519 only (backward compatible)
    #[default]
    Classic,
    /// Hybrid X25519 + ML-KEM-768 (post-quantum safe)
    Hybrid,
}

impl Zeroize for HybridMode {
    fn zeroize(&mut self) {}
}
impl ZeroizeOnDrop for HybridMode {}

// ── Hybrid KeyPair ───────────────────────────────────────────────

/// Hybrid keypair: X25519 (classical) + ML-KEM-768 (post-quantum)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKeyPair {
    pub x25519_public: [u8; 32],
    #[zeroize]
    pub x25519_secret: [u8; 32],
    pub mlkem_public: [u8; MLKEM768_PK_SIZE],
    #[zeroize]
    pub mlkem_secret: [u8; MLKEM768_SK_SIZE],
}

impl HybridKeyPair {
    pub fn generate() -> Self {
        let x25519_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let x25519_pk = x25519_dalek::PublicKey::from(&x25519_sk);
        let mut x25519_public = [0u8; 32];
        let mut x25519_secret = [0u8; 32];
        x25519_public.copy_from_slice(x25519_pk.as_bytes());
        x25519_secret.copy_from_slice(x25519_sk.as_bytes());
        let mlkem = MlKem768KeyPair::generate();
        Self { x25519_public, x25519_secret, mlkem_public: mlkem.public_key, mlkem_secret: mlkem.secret_key }
    }

    pub fn generate_classic() -> Self {
        let x25519_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let x25519_pk = x25519_dalek::PublicKey::from(&x25519_sk);
        let mut x25519_public = [0u8; 32];
        let mut x25519_secret = [0u8; 32];
        x25519_public.copy_from_slice(x25519_pk.as_bytes());
        x25519_secret.copy_from_slice(x25519_sk.as_bytes());
        Self { x25519_public, x25519_secret, mlkem_public: [0u8; MLKEM768_PK_SIZE], mlkem_secret: [0u8; MLKEM768_SK_SIZE] }
    }

    pub fn public_bundle(&self, mode: HybridMode) -> HybridPublicBundle {
        match mode {
            HybridMode::Classic => HybridPublicBundle::Classic { x25519: self.x25519_public },
            HybridMode::Hybrid => HybridPublicBundle::Hybrid { x25519: self.x25519_public, mlkem: self.mlkem_public },
        }
    }

    pub fn exchange_initiator(&self, their_bundle: &HybridPublicBundle) -> Result<HybridSharedSecret, String> {
        match their_bundle {
            HybridPublicBundle::Classic { x25519 } => {
                let their_pk = x25519_dalek::PublicKey::from(*x25519);
                let our_sk = x25519_dalek::StaticSecret::from(self.x25519_secret);
                let shared = our_sk.diffie_hellman(&their_pk);
                let mut secret = [0u8; 64];
                secret[..32].copy_from_slice(shared.as_bytes());
                Ok(HybridSharedSecret { mode: HybridMode::Classic, secret })
            }
            HybridPublicBundle::Hybrid { x25519, mlkem } => {
                let their_mlkem_pk = MlKem768PublicKey::from_bytes(mlkem)
                    .map_err(|e| format!("Invalid ML-KEM PK: {e}"))?;
                let their_x25519_pk = x25519_dalek::PublicKey::from(*x25519);
                let our_x25519_sk = x25519_dalek::StaticSecret::from(self.x25519_secret);
                let ecdh_ss = our_x25519_sk.diffie_hellman(&their_x25519_pk);
                let enc = MlKem768Encapsulation::encapsulate(&their_mlkem_pk);
                let combined = combine_secrets(ecdh_ss.as_bytes(), &enc.shared_secret)?;
                Ok(HybridSharedSecret { mode: HybridMode::Hybrid, secret: combined })
            }
        }
    }

    pub fn exchange_responder(
        &self,
        their_x25519: &[u8; 32],
        mlkem_ct: Option<&[u8; MLKEM768_CT_SIZE]>,
    ) -> Result<HybridSharedSecret, String> {
        if let Some(ct_bytes) = mlkem_ct {
            let their_x25519_pk = x25519_dalek::PublicKey::from(*their_x25519);
            let our_x25519_sk = x25519_dalek::StaticSecret::from(self.x25519_secret);
            let ecdh_ss = our_x25519_sk.diffie_hellman(&their_x25519_pk);
            let sk = MlKem768SecretKey::from_bytes(&self.mlkem_secret)
                .map_err(|e| format!("Invalid ML-KEM SK: {e}"))?;
            let ct = MlKem768Ciphertext::from_bytes(ct_bytes)
                .map_err(|e| format!("Invalid ML-KEM CT: {e}"))?;
            let mlkem_ss = crate::pq::mlkem768_decapsulate(&sk, &ct);
            let combined = combine_secrets(ecdh_ss.as_bytes(), &mlkem_ss)?;
            Ok(HybridSharedSecret { mode: HybridMode::Hybrid, secret: combined })
        } else {
            let their_pk = x25519_dalek::PublicKey::from(*their_x25519);
            let our_sk = x25519_dalek::StaticSecret::from(self.x25519_secret);
            let shared = our_sk.diffie_hellman(&their_pk);
            let mut secret = [0u8; 64];
            secret[..32].copy_from_slice(shared.as_bytes());
            Ok(HybridSharedSecret { mode: HybridMode::Classic, secret })
        }
    }
}

// ── Public Bundle ────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum HybridPublicBundle {
    Classic { x25519: [u8; 32] },
    Hybrid { x25519: [u8; 32], mlkem: [u8; MLKEM768_PK_SIZE] },
}

impl HybridPublicBundle {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Classic { x25519 } => { let mut b = vec![0x01]; b.extend_from_slice(x25519); b }
            Self::Hybrid { x25519, mlkem } => { let mut b = vec![0x02]; b.extend_from_slice(x25519); b.extend_from_slice(mlkem); b }
        }
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        let version = b.first().copied().ok_or("empty bytes")?;
        match version {
            0x01 => {
                if b.len() != 33 { return Err(format!("Classic bundle: expected 33, got {}", b.len())); }
                let mut x25519 = [0u8; 32]; x25519.copy_from_slice(&b[1..33]);
                Ok(Self::Classic { x25519 })
            }
            0x02 => {
                if b.len() != 33 + MLKEM768_PK_SIZE { return Err(format!("Hybrid bundle: expected {}", 33 + MLKEM768_PK_SIZE)); }
                let mut x25519 = [0u8; 32]; let mut mlkem = [0u8; MLKEM768_PK_SIZE];
                x25519.copy_from_slice(&b[1..33]); mlkem.copy_from_slice(&b[33..]);
                Ok(Self::Hybrid { x25519, mlkem })
            }
            v => Err(format!("Unknown bundle version: {v}")),
        }
    }

    pub fn mode(&self) -> HybridMode {
        match self { Self::Classic { .. } => HybridMode::Classic, Self::Hybrid { .. } => HybridMode::Hybrid }
    }
}

// ── Shared Secret ────────────────────────────────────────────────

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    pub mode: HybridMode,
    pub secret: [u8; 64],
}

impl HybridSharedSecret {
    pub fn as_bytes_32(&self) -> [u8; 32] { self.secret[..32].try_into().unwrap() }
    pub fn as_bytes_64(&self) -> [u8; 64] { self.secret }

    pub fn derive_ratchet_keys(&self) -> Result<([u8; 32], [u8; 32]), String> {
        let hk = Hkdf::<Sha256>::new(None, &self.secret);
        let mut send = [0u8; 32]; let mut recv = [0u8; 32];
        hk.expand(b"send_chain_key", &mut send).map_err(|e| format!("HKDF: {e}"))?;
        hk.expand(b"recv_chain_key", &mut recv).map_err(|e| format!("HKDF: {e}"))?;
        Ok((send, recv))
    }
}

// ── Internal ─────────────────────────────────────────────────────

pub(crate) fn combine_secrets(ecdh: &[u8; 32], mlkem: &[u8; MLKEM768_SS_SIZE]) -> Result<[u8; 64], String> {
    let mut concat = Vec::with_capacity(64);
    concat.extend_from_slice(ecdh); concat.extend_from_slice(mlkem);
    let hk = Hkdf::<Sha3_512>::new(Some(b"fibemate-hybrid-v1"), &concat);
    let mut okm = [0u8; 64];
    hk.expand(b"shared-secret", &mut okm).map_err(|e| format!("HKDF-SHA3-512: {e}"))?;
    Ok(okm)
}

// ── Encapsulation (initiator → responder) ───────────────────────

#[derive(Clone)]
pub struct HybridEncapsulation {
    pub mode: HybridMode,
    pub x25519_public: [u8; 32],
    pub mlkem_ciphertext: Option<[u8; MLKEM768_CT_SIZE]>,
}

impl HybridEncapsulation {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.mlkem_ciphertext {
            None => { let mut b = vec![0x01]; b.extend_from_slice(&self.x25519_public); b }
            Some(ct) => { let mut b = vec![0x02]; b.extend_from_slice(&self.x25519_public); b.extend_from_slice(&ct); b }
        }
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        let version = b.first().copied().ok_or("empty bytes")?;
        match version {
            0x01 => {
                if b.len() != 33 { return Err("Classic encapsulation: expected 33 bytes".into()); }
                let mut x25519 = [0u8; 32]; x25519.copy_from_slice(&b[1..33]);
                Ok(Self { mode: HybridMode::Classic, x25519_public: x25519, mlkem_ciphertext: None })
            }
            0x02 => {
                if b.len() != 33 + MLKEM768_CT_SIZE { return Err(format!("Hybrid encapsulation: expected {}", 33 + MLKEM768_CT_SIZE)); }
                let mut x25519 = [0u8; 32]; let mut ct = [0u8; MLKEM768_CT_SIZE];
                x25519.copy_from_slice(&b[1..33]); ct.copy_from_slice(&b[33..]);
                Ok(Self { mode: HybridMode::Hybrid, x25519_public: x25519, mlkem_ciphertext: Some(ct) })
            }
            v => Err(format!("Unknown encapsulation version: {v}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classic_roundtrip() {
        let alice = HybridKeyPair::generate_classic();
        let bob = HybridKeyPair::generate_classic();
        let bob_bundle = bob.public_bundle(HybridMode::Classic);
        let alice_ss = alice.exchange_initiator(&bob_bundle).unwrap();
        let bob_ss = bob.exchange_responder(&alice.x25519_public, None).unwrap();
        assert_eq!(alice_ss.secret[..32], bob_ss.secret[..32]);
    }

    #[test]
    fn test_hybrid_roundtrip() {
        let alice = HybridKeyPair::generate();
        let bob = HybridKeyPair::generate();
        let bob_mlkem_pk = MlKem768PublicKey::from_bytes(&bob.mlkem_public).unwrap();
        let enc = MlKem768Encapsulation::encapsulate(&bob_mlkem_pk);
        let their_x25519_pk = x25519_dalek::PublicKey::from(bob.x25519_public);
        let our_x25519_sk = x25519_dalek::StaticSecret::from(alice.x25519_secret);
        let ecdh_ss = our_x25519_sk.diffie_hellman(&their_x25519_pk);
        let alice_combined = combine_secrets(ecdh_ss.as_bytes(), &enc.shared_secret).unwrap();
        let alice_ss = HybridSharedSecret { mode: HybridMode::Hybrid, secret: alice_combined };
        let bob_ss = bob.exchange_responder(&alice.x25519_public, Some(&enc.ciphertext)).unwrap();
        assert_eq!(alice_ss.secret, bob_ss.secret);
    }
}
