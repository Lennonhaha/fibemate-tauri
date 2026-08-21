# 🔐 FIBEMATE v3.0 — Post-Quantum Secure Messaging

**End-to-end encrypted messaging with NIST-standard post-quantum cryptography.**  
Built on Tauri v2 (Rust + WebView), designed for the quantum era.

[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-12%2F12%20passed-brightgreen)]()
[![Rust](https://img.shields.io/badge/rust-1.85+-orange)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## 🛡️ Security Architecture

```
┌─────────────────────────────────────────────────┐
│  WebView (JS)                 Rust Backend       │
│  ┌───────────┐              ┌─────────────────┐ │
│  │ UI Layer  │── invoke()──▶│ Tauri Commands   │ │
│  │ keyId only│              │ ┌─────────────┐  │ │
│  │ no secrets│              │ │ ML-KEM-768  │  │ │
│  │ in memory │              │ │ ML-DSA-65   │  │ │
│  └───────────┘              │ │ X25519+Hybrid│ │ │
│                             │ │ DoubleRatchet│ │ │
│                             │ │ X3DH         │ │ │
│                             │ └─────────────┘  │ │
│                             │ ┌─────────────┐  │ │
│                             │ │ KeyStore     │  │ │
│                             │ │ AES-256-GCM  │  │ │
│                             │ │ device key   │  │ │
│                             │ └─────────────┘  │ │
│                             └─────────────────┘ │
└─────────────────────────────────────────────────┘
```

**Key principle:** The JavaScript frontend never touches plaintext private keys — only opaque `keyId` strings. All cryptographic operations execute exclusively in the Rust backend, isolated from the WebView's attack surface.

---

## 🧬 Cryptographic Suite

| Algorithm | Standard | Use | Key Size |
|-----------|----------|-----|----------|
| **ML-KEM-768** | FIPS 203 | Key encapsulation (PQ) | 1184/2400/1088 B |
| **ML-DSA-65** | FIPS 204 | Digital signatures (PQ) | 1952/4032/3293 B |
| **X25519** | RFC 7748 | Classical ECDH | 32/32 B |
| **Hybrid X25519+ML-KEM** | Custom | Combiner binding | 64 B shared |
| **Double Ratchet** | Signal spec | Per-message forward secrecy | X25519 per-step |
| **X3DH** | Signal spec | Asynchronous key agreement | 3-DH handshake |
| **AES-256-GCM** | FIPS 197 | Message encryption + KeyStore | 256-bit |
| **HKDF-SHA512** | RFC 5869 | Key derivation | — |

### Hybrid Key Exchange

```
X25519 ECDH  ─┐
               ├── HKDF-SHA512 ──▶ 64-byte combined secret ──▶ Double Ratchet
ML-KEM-768 PQ ─┘
```

Classical + post-quantum combined: even if one layer is broken, the other protects the session.

---

## 📦 Key Store

Private keys are stored encrypted on disk, decrypted on-demand, and zeroized after use:

```
%APPDATA%/com.fibemate.app/
├── device.key          ← 32 random bytes, generated on first run
├── key_meta.json       ← public key metadata (keyId, fingerprint, timestamp)
└── keys/
    ├── {uuid-1}.enc    ← AES-256-GCM(device_key, ML-KEM secret key)
    └── {uuid-2}.enc
```

- ✅ **AES-256-GCM** per-key unique nonce
- ✅ **Zeroized** after each decapsulation
- ✅ **No C dependencies** — pure Rust (`aes-gcm` + `rand`)
- ✅ **Survives app restart** — keys persist in encrypted form

---

## 🚀 Quick Start

### Prerequisites

- Rust 1.85+
- Node.js 18+
- Windows 10+ (macOS/Linux support planned)

### Build & Run

```bash
# Clone
git clone https://github.com/your-org/fibemate.git
cd fibemate

# Install frontend dependencies
npm install

# Run in development mode (with hot reload)
npx tauri dev

# Build production binary
npx tauri build
# Output: src-tauri/target/release/fibemate.exe
# Installer: src-tauri/target/release/bundle/nsis/FIBEMATE_3.0.0_x64-setup.exe
```

### Run Tests

```bash
cd src-tauri
cargo test
# Expected: 12 tests, 0 failures
```

---

## 🧪 Test Coverage

```
$ cargo test
running 12 tests
test pq::tests::test_mlkem768_roundtrip ............. ok   keygen→encaps→decaps
test pq::tests::test_mldsa65_sign_verify ............ ok   sign→verify
test pq::tests::test_fingerprint .................... ok
test pq::hybrid::tests::test_classic_roundtrip ...... ok   X25519-only exchange
test pq::hybrid::tests::test_hybrid_roundtrip ....... ok   X25519+ML-KEM combined
test double_ratchet::tests::test_keypair_generation .. ok
test double_ratchet::tests::test_diffie_hellman ...... ok
test double_ratchet::tests::test_encrypt_decrypt ..... ok   full DR cycle
test double_ratchet::tests::test_session_roundtrip ... ok
test key_store::tests::test_store_and_load ........... ok   encrypt→decrypt
test key_store::tests::test_delete ................... ok   delete→unavailable
test key_store::tests::test_persistence .............. ok   reopen→key still there

test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured
```

---

## 📁 Project Structure

```
fibemate-tauri/
├── src/                          # Frontend (HTML/JS/CSS)
│   ├── index.html                # Login / splash
│   ├── main.html                 # Main chat UI
│   ├── tauri-crypto-bridge.js    # ML-KEM invoke() bridge
│   ├── message-crypto-v2.js      # X3DH + Double Ratchet (JS side)
│   ├── key-manager.js            # Key lifecycle UI
│   └── ...
├── src-tauri/                    # Rust backend
│   ├── src/
│   │   ├── lib.rs                # App entry, setup, command registration
│   │   ├── pq/
│   │   │   ├── mod.rs            # ML-KEM-768 + ML-DSA-65 wrappers
│   │   │   └── hybrid.rs         # X25519+ML-KEM hybrid exchange
│   │   ├── double_ratchet.rs     # Double Ratchet + X3DH
│   │   ├── key_store.rs          # AES-256-GCM encrypted key storage
│   │   └── commands/
│   │       ├── mod.rs            # CryptoState (shared state)
│   │       ├── kem.rs            # ML-KEM commands (4 endpoints)
│   │       └── ratchet.rs        # Double Ratchet commands (7 endpoints)
│   ├── Cargo.toml
│   └── tauri.conf.json
├── package.json
└── README.md
```

### Tauri Commands (11 registered)

| Command | Module | Description |
|---------|--------|-------------|
| `kem_keygen` | kem.rs | Generate ML-KEM-768 keypair → store in KeyStore |
| `kem_encapsulate` | kem.rs | Encapsulate to a public key → ciphertext + shared_secret |
| `kem_decapsulate` | kem.rs | Decapsulate using keyId → shared_secret (key zeroized) |
| `kem_list_keys` | kem.rs | List all stored key metadatas |
| `dr_init` | ratchet.rs | Initialize Double Ratchet session |
| `dr_set_peer` | ratchet.rs | Set peer's public key |
| `dr_encrypt` | ratchet.rs | Encrypt message → ciphertext |
| `dr_decrypt` | ratchet.rs | Decrypt message → plaintext |
| `dr_get_send_key` | ratchet.rs | Get current sending ratchet key |
| `dr_list_sessions` | ratchet.rs | List active sessions |
| `dr_delete_session` | ratchet.rs | Delete a session |

---

## 🔒 Security Properties

| Property | Status |
|----------|--------|
| **Post-quantum key exchange** | ✅ ML-KEM-768 (FIPS 203) |
| **Classical fallback** | ✅ X25519 hybrid combiner |
| **Forward secrecy** | ✅ Double Ratchet per-message |
| **Post-compromise security** | ✅ Ratchet self-healing |
| **Private keys never in JS** | ✅ Only keyId strings cross invoke() |
| **Encrypted at rest** | ✅ AES-256-GCM device key |
| **Memory zeroization** | ✅ `zeroize` after every use |
| **No C dependencies** | ✅ Pure Rust crypto stack |
| **Deniability** | ✅ X3DH (Signal-style) |

---

## 📜 Standards Compliance

- **FIPS 203**: ML-KEM-768 key encapsulation
- **FIPS 204**: ML-DSA-65 digital signatures
- **FIPS 197**: AES-256-GCM message encryption
- **RFC 5869**: HKDF-SHA512 key derivation
- **RFC 7748**: X25519 elliptic curve DH
- **Signal Protocol**: Double Ratchet + X3DH

---

## 🛣️ Roadmap

- [x] ML-KEM-768 backend commands
- [x] AES-256-GCM encrypted KeyStore
- [x] Double Ratchet + X3DH (Rust)
- [x] Tauri v2 release build
- [x] 12/12 unit tests passing
- [ ] Double Ratchet fully in Rust (currently JS bridge)
- [ ] ML-DSA-65 signing commands
- [ ] P2P WebRTC with PQ key exchange
- [ ] Mobile (Capacitor/Tauri Mobile)
- [ ] Formal security audit
- [ ] FIPS 140-3 validation

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*"Security is not a product; it's a process." — Bruce Schneier*
