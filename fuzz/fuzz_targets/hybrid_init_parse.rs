#![no_main]

use libfuzzer_sys::fuzz_target;

use fibemate_lib::pq::hybrid::{HybridEncapsulation, HybridPublicBundle};

// Untrusted wire payloads of the hybrid key exchange
// (`src-tauri/src/pq/hybrid.rs`).
//
// Both parsers are pure, take attacker-controlled bytes straight off the wire,
// and need no application state — so they are fuzzed directly, with **no**
// production code path modified.
//
//   enc    0x01 || x25519_epk(32)                    [classic]
//          0x02 || x25519_epk(32) || mlkem_ct(1088)  [hybrid]
//   bundle 0x01 || x25519_pk(32)                     [classic]
//          0x02 || x25519_pk(32)  || mlkem_pk(1184)  [hybrid]
fuzz_target!(|data: &[u8]| {
    // Initiator -> responder payload.
    if let Ok(enc) = HybridEncapsulation::from_bytes(data) {
        // An accepted input must re-serialise byte-for-byte.
        assert_eq!(enc.to_bytes(), data, "enc round-trip mismatch");
    }

    // Responder public bundle.
    if let Ok(bundle) = HybridPublicBundle::from_bytes(data) {
        assert_eq!(bundle.to_bytes(), data, "bundle round-trip mismatch");
    }
});
