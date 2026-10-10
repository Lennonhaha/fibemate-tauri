// SPDX-License-Identifier: GPL-3.0-only
//! X25519 known-answer tests against RFC 7748 (§5.2 vectors + §6.1 DH example).
//!
//! These guard the classical half of the hybrid handshake: if `x25519-dalek`
//! is ever swapped or misconfigured, these tests go red before a release.

#![cfg(test)]

use x25519_dalek::{PublicKey, StaticSecret};

fn sk(hex_str: &str) -> StaticSecret {
    let b = hex::decode(hex_str).expect("valid hex");
    let arr: [u8; 32] = b.as_slice().try_into().expect("32 bytes");
    StaticSecret::from(arr)
}

/// RFC 7748 §6.1 — Alice/Bob key agreement: public keys and the shared secret.
#[test]
fn rfc7748_section_6_1() {
    let alice_sk = sk("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pk = PublicKey::from(&alice_sk);
    assert_eq!(
        hex::encode(alice_pk.as_bytes()),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        "Alice public key"
    );

    let bob_sk = sk("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_pk = PublicKey::from(&bob_sk);
    assert_eq!(
        hex::encode(bob_pk.as_bytes()),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "Bob public key"
    );

    let shared_a = alice_sk.diffie_hellman(&bob_pk);
    let shared_b = bob_sk.diffie_hellman(&alice_pk);
    assert_eq!(shared_a.as_bytes(), shared_b.as_bytes(), "DH symmetry");
    assert_eq!(
        hex::encode(shared_a.as_bytes()),
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        "shared secret (RFC 7748 §6.1)"
    );
}

/// RFC 7748 §5.2 — X25519(scalar, u) test vectors.
#[test]
fn rfc7748_section_5_2() {
    let cases = [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ];
    for (i, (k, u, out)) in cases.iter().enumerate() {
        let s = sk(k);
        let u_bytes: [u8; 32] = hex::decode(u).unwrap().as_slice().try_into().unwrap();
        let got = s.diffie_hellman(&PublicKey::from(u_bytes));
        assert_eq!(hex::encode(got.as_bytes()), *out, "RFC 7748 §5.2 case {}", i + 1);
    }
}
