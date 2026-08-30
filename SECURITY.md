# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 3.0.x   | :white_check_mark: |
| < 3.0   | :x:                |

## Reporting a Vulnerability

FIBEMATE Tauri is a **research prototype** of post-quantum secure messaging. It has **not undergone formal security audit**.

If you discover a security vulnerability:

1. **Do NOT open a public issue.**
2. Email: **security@fibemate.com** (PGP key available on request)
3. Include: description, reproduction steps, impact assessment
4. Response time: within 72 hours

## Disclosure Timeline

- **Day 0**: Vulnerability reported
- **Day 1-3**: Acknowledgment + initial assessment
- **Day 3-30**: Fix development + testing
- **Day 30**: Public disclosure (if fix available)

## Scope

**In scope:**
- Cryptographic implementation flaws (ML-KEM-768, ML-DSA-65, X25519, Double Ratchet)
- Key storage / memory handling bugs
- Tauri IPC boundary violations (JS accessing plaintext keys)
- Side-channel vulnerabilities

**Out of scope:**
- Social engineering
- Physical device access
- Network-level attacks (use TLS separately)
- Issues in dependencies (report upstream)

## Security Properties

| Property | Status |
|----------|--------|
| PQ key exchange | ML-KEM-768 (FIPS 203) |
| Classical hybrid | X25519 + ML-KEM combiner |
| Forward secrecy | Double Ratchet per-message |
| Private keys in JS | Never — only opaque keyId |
| Encryption at rest | AES-256-GCM |
| Memory zeroization | `zeroize` crate after use |

## Known Limitations

- **No formal security audit** — research prototype only
- **Double Ratchet has JS bridge** — not fully Rust-native yet
- **No FIPS 140-3 validation** — uses pure Rust implementations
- **Windows-only** — macOS/Linux not tested
- **No P2P transport** — WebRTC planned but not implemented

Do not use this software for real-world encrypted communications.
