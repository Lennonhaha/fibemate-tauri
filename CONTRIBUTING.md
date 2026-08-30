# Contributing to FIBEMATE Tauri

Thank you for your interest in contributing! This is a research project exploring post-quantum cryptography in desktop applications.

## Getting Started

### Prerequisites

- Rust 1.85+ (2024 edition)
- Node.js 18+
- Windows 10+ (macOS/Linux support planned)

### Development Setup

```bash
git clone https://github.com/Lennonhaha/fibemate-tauri.git
cd fibemate-tauri
npm install
npx tauri dev
```

### Running Tests

```bash
cd src-tauri
cargo test
# Expected: 12 tests, 0 failures
```

## How to Contribute

### Bug Reports

1. Check existing issues first
2. Open a new issue with:
   - OS version, Rust version, Node version
   - Minimal reproduction steps
   - Expected vs actual behavior

### Feature Requests

We welcome contributions in these areas (see Roadmap in README):

- Double Ratchet full Rust implementation (remove JS bridge)
- ML-DSA-65 signing commands
- P2P WebRTC transport with PQ key exchange
- macOS/Linux support
- Mobile (Tauri Mobile / Capacitor)

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Run tests: `cd src-tauri && cargo test`
4. Ensure `cargo clippy` passes with no warnings
5. Commit with conventional commits: `feat:`, `fix:`, `docs:`, `test:`
6. Open a PR with a clear description

### Code Style

**Rust:**
- Follow `rustfmt` defaults
- `clippy` must pass
- Use `zeroize` for any struct containing key material
- No `unsafe` without justification in comments

**JavaScript:**
- ES modules (`import`/`export`)
- No minification in source
- JSDoc comments for public functions

## Architecture Notes

- **JS frontend** never touches plaintext private keys — only opaque `keyId` strings
- **Rust backend** performs all cryptographic operations
- **Tauri IPC** (`invoke()`) is the only bridge between JS and Rust
- **KeyStore** uses AES-256-GCM with a device key stored on disk

## License

By contributing, you agree that your contributions will be licensed under the GPLv3 license.
