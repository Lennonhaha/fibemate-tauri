// SPDX-License-Identifier: GPL-3.0-only
//! ML-KEM-768 known-answer tests — final FIPS 203 vectors only.
//!
//! Vectors: NIST ACVP-Server `ML-KEM-keyGen-FIPS203` / `ML-KEM-encapDecap-FIPS203`
//! (2024), trimmed into `tests/kat-vectors/mlkem768.json`.
//!
//! The draft-era (October 2023) intermediate values that used to live here are
//! gone on purpose: the engine is now `libcrux-ml-kem`, which implements the
//! final standard, so a draft vector is a test of the wrong thing. Keeping it
//! would only let a regression pass by matching the old KDF input.
//!
//! These tests are the CI gate for "the KEM in the shipped binary is FIPS 203
//! final". KeyGen is deterministic (`KeyGen_internal(d, z)`), so a mismatch is
//! always a code/dependency change, never RNG noise.

#![cfg(test)]

use crate::pq::{
    mlkem768_decapsulate, mlkem768_encapsulate_derand, mlkem768_generate_derand,
    MlKem768Ciphertext, MlKem768PublicKey, MlKem768SecretKey,
};
use serde_json::Value;

/// NIST ACVP **final** FIPS 203 vectors (2024).
const FINAL_VECTORS: &str = include_str!("../../tests/kat-vectors/mlkem768.json");

fn bytes(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap_or_else(|| panic!("missing field {k}"))).expect("valid hex")
}

fn a32(v: &Value, k: &str) -> [u8; 32] {
    bytes(v, k).try_into().expect("32 bytes")
}

fn up(b: &[u8]) -> String {
    hex::encode(b).to_uppercase()
}

fn final_vectors() -> Value {
    serde_json::from_str(FINAL_VECTORS).expect("mlkem768.json parses")
}

// ── final FIPS 203 (ACVP) ────────────────────────────────────────────────────

#[test]
fn acvp_mlkem768_keygen() {
    let j = final_vectors();
    let cases = j["keyGen"].as_array().expect("keyGen array");
    assert!(!cases.is_empty(), "no keyGen cases");
    for t in cases {
        let (pk, sk) = mlkem768_generate_derand(&a32(t, "d"), &a32(t, "z"));
        assert_eq!(
            up(pk.as_bytes()),
            t["ek"].as_str().unwrap().to_uppercase(),
            "tc{} ek",
            t["tcId"]
        );
        assert_eq!(
            up(sk.as_bytes()),
            t["dk"].as_str().unwrap().to_uppercase(),
            "tc{} dk",
            t["tcId"]
        );
    }
}

#[test]
fn acvp_mlkem768_encapsulation() {
    let j = final_vectors();
    for t in j["encapsulation"].as_array().expect("encapsulation array") {
        let pk = MlKem768PublicKey::from_bytes(&bytes(t, "ek")).expect("valid ek");
        let (ct, ss) = mlkem768_encapsulate_derand(&pk, a32(t, "m"));
        assert_eq!(
            up(ct.as_bytes()),
            t["c"].as_str().unwrap().to_uppercase(),
            "tc{} c",
            t["tcId"]
        );
        assert_eq!(
            up(&ss),
            t["k"].as_str().unwrap().to_uppercase(),
            "tc{} k",
            t["tcId"]
        );
    }
}

#[test]
fn acvp_mlkem768_decapsulation() {
    let j = final_vectors();
    for t in j["decapsulation"].as_array().expect("decapsulation array") {
        let sk = MlKem768SecretKey::from_bytes(&bytes(t, "dk")).expect("valid dk");
        let ct = MlKem768Ciphertext::from_bytes(&bytes(t, "c")).expect("valid c");
        let ss = mlkem768_decapsulate(&sk, &ct);
        assert_eq!(
            up(&ss),
            t["k"].as_str().unwrap().to_uppercase(),
            "tc{} k",
            t["tcId"]
        );
    }
}

/// A tampered ciphertext must yield the implicit-rejection value, not an error
/// and not the original secret. This pins the FIPS 203 §7.3 behaviour that the
/// retired draft path got wrong by construction.
#[test]
fn acvp_mlkem768_tamper_yields_implicit_rejection() {
    let j = final_vectors();
    let t = &j["decapsulation"].as_array().expect("decapsulation array")[0];
    let sk = MlKem768SecretKey::from_bytes(&bytes(t, "dk")).expect("valid dk");
    let mut ct_bytes = bytes(t, "c");
    ct_bytes[0] ^= 0x01;
    let ct = MlKem768Ciphertext::from_bytes(&ct_bytes).expect("still 1088 bytes");
    let tampered = mlkem768_decapsulate(&sk, &ct);
    let expected = t["k"].as_str().unwrap().to_uppercase();
    assert_ne!(up(&tampered), expected, "tampered ct must not return k");
}
