//! Safety Number Fingerprint
//!
//! Implements the end-to-end identity verification display.
//! Derived from both parties' X25519 identity public keys via SHA-256,
//! rendered as 25 numeric digits in 5 groups of 5 — designed for
//! easy audio/visual comparison (inspired by Signal/ZRTP).

use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::State;

use crate::commands::CryptoState;
use crate::commands::identity;

/// Generate a deterministic 25-digit Safety Number from two identity keys.
///
/// Algorithm:
/// 1. Sort keys (lexicographic) → same result on both sides
/// 2. SHA-256(our_ik || peer_ik)
/// 3. First 12 hash bytes → u128 number → mod 10^25
/// 4. Format as 5 groups of 5 digits
pub fn generate_safety_number(our_ik: &[u8; 32], peer_ik: &[u8; 32]) -> String {
    // 1. Sort for determinism (both parties compute the same value)
    let (a, b) = if our_ik <= peer_ik {
        (our_ik, peer_ik)
    } else {
        (peer_ik, our_ik)
    };

    // 2. SHA-256
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    let hash = hasher.finalize();

    // 3. First 12 hash bytes → u128 → mod 10^25 → 25-digit zero-padded string
    let mut acc: u128 = 0;
    for &b in hash.iter().take(12) {
        acc = acc.wrapping_mul(256).wrapping_add(b as u128);
    }
    let modulus = 10u128.pow(25); // 10^25
    let num = acc % modulus;
    let digits = format!("{:025}", num);

    // 4. Group: "XXXXX XXXXX XXXXX XXXXX XXXXX"
    let mut result = String::with_capacity(29);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && i % 5 == 0 {
            result.push(' ');
        }
        result.push(ch);
    }
    result
}

// ── Tauri Command ───────────────────────────────────────────────

#[derive(Serialize, Clone)]
pub struct SafetyNumberResponse {
    /// "XXXXX XXXXX XXXXX XXXXX XXXXX"
    pub safety_number: String,
    /// Our identity public key fingerprint (for debug)
    pub our_fingerprint: String,
    /// Peer identity public key fingerprint (for debug)
    pub peer_fingerprint: String,
}

/// Compute the Safety Number for a session.
///
/// Requires the session to have identity keys bound (via dr_init's
/// our_identity_id + peer_identity_pk_hex params).
#[tauri::command]
pub fn dr_safety_number(
    state: State<CryptoState>,
    session_id: String,
) -> Result<SafetyNumberResponse, String> {
    // Get identity bindings
    let (our_identity_id, peer_identity_pk) = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        sessions.get_identity_keys(&session_id)?
    };

    // Load our identity public key from KeyStore (only loads meta, not secret)
    let store = state.key_store.lock().map_err(|e| e.to_string())?;
    let ik_id = identity::ik_key_id(&our_identity_id);
    let meta = store.get_meta(&ik_id)
        .ok_or(format!("Identity key not found in KeyStore: {our_identity_id}"))?;

    // Convert public key Vec<u8> → [u8; 32]
    let our_public_key: [u8; 32] = {
        let pk = &meta.public_key;
        if pk.len() != 32 {
            return Err(format!("Identity key corrupt: expected 32 bytes, got {}", pk.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pk);
        arr
    };

    // Compute safety number
    let safety_number = generate_safety_number(&our_public_key, &peer_identity_pk);

    Ok(SafetyNumberResponse {
        safety_number,
        our_fingerprint: meta.fingerprint.clone(),
        peer_fingerprint: crate::pq::fingerprint(&peer_identity_pk),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_number_symmetric() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let sn_a = generate_safety_number(&alice, &bob);
        let sn_b = generate_safety_number(&bob, &alice);
        assert_eq!(sn_a, sn_b);
    }

    #[test]
    fn test_safety_number_format() {
        let ik1 = [0x42u8; 32];
        let ik2 = [0x99u8; 32];
        let sn = generate_safety_number(&ik1, &ik2);
        // Should be 29 chars: 25 digits + 4 spaces
        assert_eq!(sn.len(), 29);
        // Every 6th character should be a space
        for (i, ch) in sn.chars().enumerate() {
            if (i + 1) % 6 == 0 {
                assert_eq!(ch, ' ', "Expected space at position {i}");
            } else {
                assert!(ch.is_ascii_digit(), "Expected digit at position {i}, got '{ch}'");
            }
        }
    }

    #[test]
    fn test_deterministic() {
        let ik1 = [0xAAu8; 32];
        let ik2 = [0xBBu8; 32];
        let sn1 = generate_safety_number(&ik1, &ik2);
        let sn2 = generate_safety_number(&ik1, &ik2);
        assert_eq!(sn1, sn2);
    }
}
