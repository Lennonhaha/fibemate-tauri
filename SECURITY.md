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
2. Email: **security@fibemate.net** (PGP key available on request)
3. Include: description, reproduction steps, impact assessment
4. Response time: within 72 hours

## Disclosure Timeline

- **Day 0**: Vulnerability reported
- **Day 1-3**: Acknowledgment + initial assessment
- **Day 3-30**: Fix development + testing
- **Day 30**: Public disclosure (if fix available)

## Bug Bounty

FIBEMATE Tauri is a single-maintainer research prototype without funding. We **do not** operate a paid bounty program. We recognize good-faith security research as follows:

| Severity | Reward |
|----------|--------|
| Critical (private key recovery, plaintext disclosure, KEM/DR break) | Public acknowledgment + named in `Acknowledgments` |
| High (authentication bypass, key confusion, downgrade) | Public acknowledgment + named in `Acknowledgments` |
| Medium (timing leak, non-catastrophic protocol flaw) | Named in `Acknowledgments` |
| Low (documentation error, hardening suggestion) | Noted in release notes where applicable |

**Eligibility**:
- Report via `security@fibemate.net` (not a public issue)
- Provide a reproducible proof-of-concept or clear impact assessment
- Do not exfiltrate data, disrupt services, or access data beyond what is needed to demonstrate the issue
- First reporter of a distinct issue receives the acknowledgment

**Non-eligibility**: issues in third-party dependencies (report upstream), social engineering, physical access, or denial-of-service without a cryptographic component.

This is a **recognition-only** program and may evolve into a paid program if the project later receives grant or sponsorship funding.

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
- **Hybrid PQ Double Ratchet** — X25519 + ML-KEM-768 key exchange, Rust-native core (wasm/JS bridge removed in v3)
- **No FIPS 140-3 validation** — uses pure Rust implementations
- **Windows-only** — macOS/Linux not tested
- **No P2P transport** — WebRTC planned but not implemented

Do not use this software for real-world encrypted communications.
