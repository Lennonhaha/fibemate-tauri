// SPDX-License-Identifier: GPL-3.0-only
//! ML-DSA-65 known-answer tests against the **final** FIPS 204 ACVP vectors.
//!
//! The vectors come from NIST ACVP-Server
//! (`gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204`, 2024) and are
//! trimmed into `src-tauri/tests/kat-vectors/mldsa65.json`.
//!
//! These tests used to be `#[ignore]`d because `rustpq 0.3` emitted 3293-byte
//! signatures where the standard specifies 3309 (the commitment `c~` must be
//! `lambda/4 = 48` bytes). The backend is now `libcrux-ml-dsa 0.0.11`, which
//! takes the seed and the signing randomness from the caller, so the
//! deterministic vectors can actually run: keygen uses the vector's `seed`,
//! sigGen uses `rnd = 0`.
//!
//! There is deliberately **one** vector set here. The October 2023 draft
//! intermediates that used to be checked as a second "truth" are gone: the
//! question they answered ("is this crate pre-final?") is settled, and keeping
//! them around invites the next reader to treat the draft as a fallback.

#![cfg(test)]

use crate::pq::{
    mldsa65_generate_deterministic, mldsa65_sign_bytes, mldsa65_verify_bytes, MLDSA65_PK_SIZE,
    MLDSA65_SIG_SIZE, MLDSA65_SK_SIZE,
};
use serde_json::Value;

/// NIST ACVP **final** FIPS 204 vectors (2024).
const FINAL_VECTORS: &str = include_str!("../../tests/kat-vectors/mldsa65.json");

fn bytes(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap_or_else(|| panic!("missing field {k}"))).expect("valid hex")
}

fn a32(v: &Value, k: &str) -> [u8; 32] {
    bytes(v, k).try_into().expect("32 bytes")
}

fn arr<const N: usize>(v: &Value, k: &str, what: &str) -> [u8; N] {
    let b = bytes(v, k);
    assert_eq!(b.len(), N, "tc{} {what} length", v["tcId"]);
    b.try_into().expect("length checked")
}

fn up(b: &[u8]) -> String {
    hex::encode(b).to_uppercase()
}

fn final_vectors() -> Value {
    serde_json::from_str(FINAL_VECTORS).expect("mldsa65.json parses")
}

#[test]
fn acvp_mldsa65_keygen() {
    let j = final_vectors();
    let cases = j["keyGen"].as_array().expect("keyGen array");
    assert!(!cases.is_empty(), "no keyGen cases");
    for t in cases {
        let kp = mldsa65_generate_deterministic(a32(t, "seed"));
        assert_eq!(
            up(&kp.public_key),
            t["pk"].as_str().unwrap().to_uppercase(),
            "tc{} pk",
            t["tcId"]
        );
        assert_eq!(
            up(&kp.secret_key),
            t["sk"].as_str().unwrap().to_uppercase(),
            "tc{} sk",
            t["tcId"]
        );
    }
}

#[test]
fn acvp_mldsa65_siggen() {
    let j = final_vectors();
    let cases = j["sigGen"].as_array().expect("sigGen array");
    assert!(!cases.is_empty(), "no sigGen cases");
    for t in cases {
        let sk: [u8; MLDSA65_SK_SIZE] = arr(t, "sk", "sk");
        // FIPS 204 ACVP deterministic mode: rnd = 0.
        let sig = mldsa65_sign_bytes(&sk, &bytes(t, "message"), &bytes(t, "context"), [0u8; 32])
            .unwrap_or_else(|e| panic!("tc{} sign failed: {e}", t["tcId"]));
        assert_eq!(
            sig.len(),
            MLDSA65_SIG_SIZE,
            "tc{} signature length",
            t["tcId"]
        );
        assert_eq!(
            up(&sig),
            t["signature"].as_str().unwrap().to_uppercase(),
            "tc{} signature",
            t["tcId"]
        );
    }
}

#[test]
fn acvp_mldsa65_sigver() {
    let j = final_vectors();
    for t in j["sigVer"].as_array().expect("sigVer array") {
        let pk: [u8; MLDSA65_PK_SIZE] = arr(t, "pk", "pk");
        let sig: [u8; MLDSA65_SIG_SIZE] = arr(t, "signature", "signature");
        let got = mldsa65_verify_bytes(&pk, &bytes(t, "message"), &bytes(t, "context"), &sig);
        assert_eq!(
            got,
            t["testPassed"].as_bool().unwrap(),
            "tc{} testPassed",
            t["tcId"]
        );
    }
}

/// A single flipped bit must be rejected, and a mutated message with a valid
/// signature must be rejected too. This pins the negative path independently of
/// whatever `sigVer` cases NIST happened to include.
#[test]
fn mldsa65_rejects_tampering() {
    let j = final_vectors();
    // Sign and verify with the *same* keypair: the sigGen vectors ship only
    // `sk`, so borrowing a `pk` from a different tcId would test nothing but
    // my own bookkeeping.
    let kp = mldsa65_generate_deterministic(a32(&j["keyGen"][0], "seed"));
    let message = bytes(&j["sigGen"][0], "message");
    let context = bytes(&j["sigGen"][0], "context");

    let sig = mldsa65_sign_bytes(&kp.secret_key, &message, &context, [0u8; 32]).expect("sign");
    assert!(mldsa65_verify_bytes(
        &kp.public_key,
        &message,
        &context,
        &sig
    ));

    let mut bad_sig = sig;
    bad_sig[0] ^= 1;
    assert!(
        !mldsa65_verify_bytes(&kp.public_key, &message, &context, &bad_sig),
        "flipped signature bit accepted"
    );

    let mut bad_msg = message.clone();
    bad_msg.push(0);
    assert!(
        !mldsa65_verify_bytes(&kp.public_key, &bad_msg, &context, &sig),
        "extended message accepted"
    );
}
