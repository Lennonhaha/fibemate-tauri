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

## Code Review Status

This repository is maintained by a **single maintainer**, and **no merged change is approved by a second person**. The OpenSSF Scorecard `Code-Review` check therefore reports **0/30 approved changesets** (Scorecard alert `#258` in this repository).

This is a structural limitation of an unsponsored research project, not an absence of checks. Every change to `main` must pass the automated gates below before it can be merged; they are required status checks in branch protection, and the protection is enforced for administrators as well:

| Gate | What it enforces |
|------|------------------|
| `dco` | every commit carries a `Signed-off-by` trailer (DCO 1.1) |
| `Build & Test` (macOS / Ubuntu / Windows) | `cargo fmt --check`, `cargo clippy --all-targets --all-features`, `cargo test --all-features`, and documented test/command counts (`scripts/check_readme_claims.py`) |
| `cargo-deny (advisories)` | no dependency with a known vulnerability and an available fix (workspace scope) |
| `interop` | cross-implementation interoperability vectors |
| `Perf regression gate (criterion)` | performance and memory regressions |
| `Analyze` (CodeQL) | code scanning for JavaScript/TypeScript, Rust and Actions |

We do **not** claim independent human review of any change, and this section is written down so that the gap is explicit rather than implied. Independent external review is tracked on the roadmap (see `README.md` › Roadmap, "Invite an external security review"); this section will be updated once a second reviewer is in place.

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

### Known Dependency Advisories (Tolerated)

Re-reviewed before every release. The `deny.toml` scope filter keeps these out of the CI
signal; that is not the same as reporting them as safe. Reachability analysis:
`docs/security/RUSTSEC-assessment-20261111.md`.

- **`glib` 0.18.5 — RUSTSEC-2024-0429 (unsound, GHSA-wrw7-89jp-8q8g)**: the affected `glib::VariantStrIter` iterators are never called here — `glib::` and `VariantStrIter` both appear zero times in `src-tauri/src`. The crate arrives only through the GTK 3 stack. Tolerated: not in release artifact, Windows-only build. `tauri` 2.x pins `gtk ^0.18`, and the first patched `glib` (0.20) needs gtk4, i.e. `tauri` 3.x.
- **`proc-macro-error` 1.0.4 — RUSTSEC-2024-0370 (unmaintained)**: a compile-time proc-macro reached through `glib-macros` 0.18 and `gtk3-macros` 0.18; nothing from it is linked into the artifact. Tolerated: not in release artifact, Windows-only build. No patched version exists — the fix is the same gtk-rs upgrade.

本清单每次 release 前复审；scope 过滤不等于免报。

## 商用密码合规 / Commercial Cryptography Compliance

SM2 / SM3 / SM4 are implemented per public Chinese national standards
(GB/T 32918 / 32905 / 32907). This repository ships **no** keys, credentials,
or production config, and claims **no** commercial-cryptography product
certification. Operators who deploy it as a commercial cryptography
product/service, or who are critical-information-infrastructure operators,
are responsible for their own certification, security assessment, and
import/export compliance. See the README section
“商用密码合规声明 / Commercial Cryptography Compliance” for details.
