#![no_main]

use libfuzzer_sys::fuzz_target;

use fibemate_lib::sm2::Sm2StandardCipher;

// Untrusted SM2 application-layer envelope, exactly as it arrives from the
// frontend and is handed to the Rust backend: C1 || C3 || C2, hex-encoded
// (`src-tauri/src/sm2.rs`).
//
// The wire value is a hex *string*, so decode the fuzzer bytes to UTF-8 first —
// invalid UTF-8 is rejected upstream by the transport, mirroring the real call
// path. `from_hex` is pure and `State`-free, so this needs no production change.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(cipher) = Sm2StandardCipher::from_hex(s) {
            // An accepted input must re-serialise byte-for-byte.
            assert_eq!(cipher.to_hex(), s, "envelope round-trip mismatch");
        }
    }
});
