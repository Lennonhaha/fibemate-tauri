# 🔐 FIBEMATE — Post-Quantum Secure Messaging (Tauri Desktop)

**End-to-end encrypted messaging with NIST-standard post-quantum cryptography.**
Built on Tauri v2 (Rust backend + WebView frontend), designed for the quantum era.

[![Rust](https://img.shields.io/badge/rust-1.85+-orange)]()
[![Tests](https://img.shields.io/badge/tests-131%2F131%20passed-brightgreen)]()
[![PQ](https://img.shields.io/badge/PQC-ML--KEM--768%20%7C%20ML--DSA--65-blue)]()
[![License](https://img.shields.io/badge/license-GPLv3-blue)]()
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Lennonhaha/fibemate-tauri/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Lennonhaha/fibemate-tauri)

> ⚠️ **Honest scope note:** the X3DH handshake DH layer is **classical X25519** today.
> Post-quantum primitives (ML-KEM-768 / ML-DSA-65) are wired in as an **independent KEM
> path** (`kem_*` commands) and as the **SPK signature layer** (ML-DSA-65, FIPS 204).
> A single mixed PQ+classical handshake (hybrid X3DH) exists at the library layer only
> and is **not yet connected** to any command. This is a teaching/reference implementation —
> see [docs/protocol-spec.md](https://github.com/Lennonhaha/fibemate/blob/main/docs/protocol-spec.md).

---

## 🛡️ Security Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  WebView (JS)                    Rust Backend                │
│  ┌─────────────┐  invoke()      ┌─────────────────────────┐ │
│  │  UI layer   │ ─────────────▶ │ 45 Tauri commands        │ │
│  │ keyId only  │                │ ┌─────────────────────┐ │ │
│  │ ss_id only  │                │ │ X3DH (3-DH, X25519) │ │ │
│  │ session_id  │                │ │ Double Ratchet      │ │ │
│  │ no secrets  │                │ │  (fully in Rust)    │ │ │
│  └─────────────┘                │ ├─────────────────────┤ │ │
│                                 │ │ ML-KEM-768 (FIPS203)│ │ │
│                                 │ │ ML-DSA-65 (FIPS204)│ │ │
│                                 │ │ SM2 / SM3 (GM)     │ │ │
│                                 │ ├─────────────────────┤ │ │
│                                 │ │ KeyStore            │ │ │
│                                 │ │  AES-256-GCM        │ │ │
│                                 │ │  + DPAPI device key │ │ │
│                                 │ └─────────────────────┘ │ │
│                                 └─────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

**Key principle:** the JavaScript frontend never touches private keys, shared
secrets, or ratchet state — only opaque handles (`keyId`, `ss_id`,
`session_id`) and public keys cross the IPC boundary. All cryptographic
operations execute exclusively in the Rust backend.

> ⚠️ **Exception — ZK module is experimental and default-off.** The `src/zk/*`
> module (PBKDF2 key derivation + P-256 Schnorr/Bulletproofs proofs) currently
> runs in the **JS/WebView layer** and is **not** wired to the Rust backend, so it
> is an exception to the "all crypto in Rust" principle above. It is gated behind
> the `FIBEMATE_EXPERIMENT_ZK` env flag and ships **disabled by default**; when
> the flag is unset no `src/zk/*` code is loaded or executed. This is a known
> technical-debt item tracked for a later P2 evaluation of moving it into Rust.

---

## 🧬 Cryptographic Suite

| Algorithm | Standard | Use | Notes |
|-----------|----------|-----|-------|
| **ML-KEM-768** | FIPS 203 | PQ key encapsulation (`kem_*`) | rustpq 0.3, NIST Cat 3 |
| **ML-DSA-65** | FIPS 204 | SPK signing / verification | rustpq 0.3; context `fibemate-spk-v1` |
| **X25519** | RFC 7748 | IK / SPK / ephemeral DH | x25519-dalek 2 |
| **X3DH** | Signal spec | Asynchronous key agreement | 3 distinct DH inputs (IK×SPK, EK×IK, EK×SPK) |
| **Double Ratchet** | Signal spec | Per-message forward secrecy | fully in Rust, skip pool 1000 |
| **AES-256-GCM** | FIPS 197 | Message AEAD + KeyStore | aes-gcm 0.10 |
| **HKDF-SHA256** | RFC 5869 | All key derivation | hkdf 0.12 |
| **SM2 / SM3** | GB/T 32918 / 32905 | GM crypto interop line | 12 commands incl. C1‖C3‖C2 wire format |

### Message security (Double Ratchet)

- Per-message X25519 ratchet step → forward secrecy + post-compromise self-healing
- Skip pool `MAX_SKIP = 1000` tolerates out-of-order / lost messages
- Previous-send-key pool (100) detects replays → silently returns `Ok(None)`
- Wire format: `pubkey(32) ‖ msg_num(u32) ‖ prev_chain_len(u32) ‖ nonce(12) ‖ AEAD ct`

### Handshake (X3DH with independent SPK)

```
Alice                                          Bob
  │ 1. GET bundle: IK_B ‖ ISK_B ‖ SPK_B ‖ sig
  │ 2. verify ML-DSA-65 sig over SPK_B          │
  │ 3. DH1=DH(IK_A,SPK_B) DH2=DH(EK_A,IK_B)    │
  │    DH3=DH(EK_A,SPK_B) → HKDF → SS           │
  │ 4. x3dh_initiate ─────────────────────────▶ │
  │                                             │ 5. x3dh_respond
  │ ◀────────────────── SPK_B confirm ───────── │
  │ 6. Double Ratchet begins (implicit confirm) │
```

The signed pre-key is **independent** from the identity key (fixes the legacy
"SPK = IK" degenerate design where DH2 = DH3) and can be rotated without
touching the long-term identity.

---

## 📦 Key Store (encrypted at rest)

```
%APPDATA%/com.fibemate.app/
├── device.key          ← 32 random bytes, DPAPI-wrapped on Windows
├── key_meta.json       ← public metadata (keyId, fingerprint)
├── sessions.json       ← DR sessions, AES-256-GCM (domain-separated key)
├── audit.log           ← append-only security audit trail
└── keys/
    ├── ik_{id}.enc         ← X25519 identity key (AES-256-GCM)
    ├── iksign_{id}.enc     ← ML-DSA-65 signing key
    └── ikspk_{id}.enc      ← X25519 signed pre-key
```

- ✅ **DPAPI** wraps the device key on Windows (bound to user + machine)
- ✅ Domain separation (`fibemate-*-v1` HKDF contexts + AEAD AAD)
- ✅ `zeroize` on every key after use
- ✅ Survives app restart — keys persist encrypted
- ✅ `keystore_selfdestruct` (phrase `DESTROY ALL KEYS`): 3× random
  overwrite then delete — manual-only, no remote/auto trigger

---

## 🚀 Quick Start

### Prerequisites

- Rust 1.85+
- Node.js 18+
- Windows 10+ (macOS/Linux support planned)

### Build & Run

```bash
git clone https://github.com/Lennonhaha/fibemate-tauri.git
cd fibemate-tauri

npm install
npx tauri dev          # development (hot reload)
npx tauri build        # production binary
```

### Run Tests

```bash
cd src-tauri
cargo test --release --lib
# Expected: 131 tests, 0 failures
```

```
test result: ok. 131 passed; 0 failed; 0 ignored; 0 measured
```

Coverage highlights (all real, verified 2026-09-02):
- X3DH with independent SPK + ML-DSA-65 signature verification
- Double Ratchet encrypt/decrypt roundtrip + encrypted persistence roundtrip
- Persistence with wrong device key → rejected
- Legacy plaintext session migration
- ML-KEM-768 / ML-DSA-65 roundtrips (rustpq)
- SM2/SM3 full suite (sign/verify/encrypt/decrypt, ZA digest, C1‖C3‖C2 wire format)

---

## 📁 Project Structure

```
fibemate-tauri/
├── src/                          # Frontend (HTML/JS/CSS) — no key material
├── src-tauri/                    # Rust backend
│   ├── src/
│   │   ├── lib.rs                # App entry + 45 command registrations
│   │   ├── double_ratchet.rs     # Double Ratchet + X3DH + session encryption
│   │   ├── key_store.rs          # AES-256-GCM + DPAPI encrypted storage
│   │   ├── audit.rs              # Structured audit log
│   │   ├── interop_test.rs       # Rust ⇄ frontend interop tests
│   │   ├── sm2.rs / sm3.rs       # GM crypto (GB/T 32918 / 32905)
│   │   ├── pq/
│   │   │   ├── mod.rs            # ML-KEM-768 + ML-DSA-65 wrappers
│   │   │   └── hybrid.rs         # Hybrid combiner (library-only, NOT wired)
│   │   └── commands/
│   │       ├── identity.rs       # IK / SPK / X3DH / self-destruct
│   │       ├── ratchet.rs        # DR session commands
│   │       ├── kem.rs            # ML-KEM commands
│   │       ├── sm2_cmd.rs        # SM2 commands
│   │       ├── safety_number.rs  # Safety number / fingerprint
│   │       └── mod.rs            # CryptoState
│   └── Cargo.toml
└── package.json
```

### Tauri Commands (45 registered, grouped by layer)

| Layer | Commands |
|-------|----------|
| Platform (5) | `get_ws_url` `get_user_data_path` `get_version` `get_platform` `get_locale` |
| PQ KEM (4) | `kem_keygen` `kem_encapsulate` `kem_decapsulate` `kem_list_keys` |
| Identity (3) | `ik_generate` `ik_get_public` `ik_list` |
| Signed pre-key (2) | `spk_get_public` `spk_rotate` |
| KeyStore (1) | `keystore_selfdestruct` |
| X3DH (2) | `x3dh_initiate` `x3dh_respond` |
| DR sessions (9) | `dr_init` `dr_set_peer` `dr_encrypt` `dr_decrypt` `dr_get_send_key` `dr_session_exists` `dr_list_sessions` `dr_delete_session` `dr_revoke_session` |
| Safety number (1) | `dr_safety_number` |
| SM2 (12) | `sm2_generate` `sm2_get_public` `sm2_import` `sm2_sign` `sm2_verify` `sm2_ecdh` `sm2_encrypt` `sm2_decrypt` `sm2_encrypt_full` `sm2_decrypt_full` `sm2_sign_full` `sm2_verify_full` |

---

## 🔒 Security Properties

| Property | Status |
|----------|--------|
| PQ key encapsulation | ✅ ML-KEM-768 (FIPS 203), `kem_*` command path |
| PQ signatures | ✅ ML-DSA-65 (FIPS 204) — SPK binding |
| Forward secrecy | ✅ Double Ratchet, per-message ratchet step |
| Post-compromise security | ✅ ratchet self-healing |
| Private keys never in JS | ✅ opaque handles only |
| Encrypted at rest | ✅ AES-256-GCM + DPAPI device key |
| Memory zeroization | ✅ `zeroize` after every use |
| Audit trail | ✅ append-only `audit.log` (opaque IDs only) |
| Key-store self-destruct | ✅ manual, 3× overwrite |
| Deniability | ✅ X3DH (Signal-style, authenticated not anonymous) |

**Known limitations (honest):**
- X3DH DH layer is classical X25519; ML-KEM is a separate session path — there is
  no single hybrid PQ handshake yet (`pq/hybrid.rs` is library-only)
- Handshake is authenticated (IK is transmitted), not anonymous — see
  [docs/x3dh-anonymity-review.md](https://github.com/Lennonhaha/fibemate/blob/main/docs/x3dh-anonymity-review.md)

---

## 📜 Standards

- **FIPS 203**: ML-KEM-768
- **FIPS 204**: ML-DSA-65
- **FIPS 197**: AES-256-GCM
- **RFC 5869**: HKDF-SHA256
- **RFC 7748**: X25519
- **Signal Protocol**: Double Ratchet + X3DH
- **GB/T 32918 / 32905 / 32907**: SM2 / SM3 / SM4 (GM interop)

---

## 🛣️ Roadmap

- [x] ML-KEM-768 backend commands
- [x] ML-DSA-65 SPK signing + verification
- [x] Double Ratchet fully in Rust
- [x] X3DH with independent SPK (DH2 ≠ DH3)
- [x] AES-256-GCM + DPAPI encrypted KeyStore
- [x] 131/131 lib tests passing
- [ ] Hybrid PQ handshake (wire `pq/hybrid.rs` into X3DH) — P2
- [ ] Session-level PQ ratchet (ML-KEM inside ratchet, PQXDH Level 3) — P2
- [ ] P2P WebRTC with PQ key exchange
- [ ] Mobile (Tauri Mobile)
- [ ] Formal security audit
- [ ] FIPS 140-3 validation

---

## ⚖️ 商用密码合规声明 / Commercial Cryptography Compliance

> 以下为工程口径的合规说明，**不构成法律意见**；发布/商用前请自行或由律师核定。

### 🇨🇳 中国境内
- 本项目使用的 **SM2 / SM3 / SM4** 均依据公开国家标准实现（GB/T 32918、GB/T 32905、GB/T 32907）——算法本身为公开标准，不含国家秘密。
- 依据《中华人民共和国密码法》与《商用密码管理条例》（2023 年修订）：
  - **本仓库**是开源参考实现，不销售密码产品/服务，不自行声明为“商用密码产品”；
  - **若使用者**将其作为商用密码产品/服务对外提供，或属于关键信息基础设施运营者，则需自行满足商用密码**检测认证 / 应用安全性评估**等法定义务；
  - 商用密码的**进出口**可能需依规办理许可；跨境提供亦受相关法规约束。
- 面向中国境内公众提供**即时通信服务**另有实名与许可要求（《互联网用户账号信息管理规定》《电信条例》等）。**本项目为工程演示平台，非运营服务，不承担即时通信服务提供者义务；若使用者将其部署为公开服务，须自行完成实名认证、ICP 备案及内容审核。**

### 🔑 密钥与凭据
- 本仓库**不包含**任何私钥、口令、令牌或生产配置；密钥在本地生成并存放于**仓库之外**（桌面端为应用数据目录 + 操作系统凭据保护）。
- 请勿向仓库提交 `.env`、`*.pem`、`*.key`、`*.jks` 等；`.gitignore` 已默认忽略。
- CI 与仓库中不使用生产凭据。

### 🌐 出口与许可
- 密码软件在部分司法辖区（例如 EU 双重用途条例、美国 EAR）可能属于受控物项；分发/出口前请自行判定适用分类与申报义务。**本仓库不含加密硬件，为纯软件实现；出口管制分类责任在部署方。**

### 📄 许可证
- 本项目以 **GPL-3.0-only** 发布：分发衍生作品须以相同许可开源并提供源码。**使用者若将其集成至闭源产品，须自行评估 GPL 传染性，或寻求商业许可。**
- GPLv3 **不要求**“网络服务即开源”（区别于 AGPL）——若未来需要网络级 copyleft，需单独评估。

---

## 📄 License

GNU General Public License v3.0 (GPLv3) — see [LICENSE](LICENSE) for details.

---

*"Security is not a product; it's a process." — Bruce Schneier*
