# Security boundary: IPC and key flow

This document records where key material lives in the desktop app and what crosses the
WebView ↔ Rust boundary. It describes the current design. It is not a threat model, and it is not
an audit.

Measured on 2026-11-20 against `src-tauri/src` on `main`. Line numbers are anchors for review, not
a contract; re-derive them before quoting.

## 1. Three zones

| Zone | Holds | Assumed |
|---|---|---|
| WebView (renderer, `src/`) | the UI, its JS state, and any key the JS layer creates | untrusted for key custody |
| Rust core (`src-tauri/src`) | device key, encrypted key files, decrypted secret keys during an operation, Double Ratchet state, pending shared secrets | trusted, to the extent a process on the user's machine can be |
| Disk (`$APPDATA/com.fibemate.app`) | `device.key`, `keys/*.enc`, `sessions.json`, `key_meta.json` | confidential at rest, readable by the same OS user |

The boundary is the IPC payload, not the process boundary. Both zones run as the same OS user, and
the WebView can call every registered command. What this boundary buys is **the absence of raw key
bytes in IPC payloads** — not resistance to a compromised renderer. Section 5 states the difference
plainly.

## 2. What crosses IPC

45 commands are registered in `src-tauri/src/lib.rs:80-139`. The frontend references 42 of them,
counting both direct `invoke('name')` calls and the `invoke()('name')` wrapper in
`src/tauri-ratchet-bridge.js`. Three are registered and never referenced: `kem_list_keys`,
`ik_generate`, `audit_approval`.

| Group | Commands | Input from JS | Output to JS | Raw key bytes in payload |
|---|---|---|---|---|
| Platform | `get_ws_url`, `get_user_data_path`, `get_version`, `get_platform`, `get_locale` | nothing | strings | no |
| ML-KEM-768 | `kem_keygen`, `kem_encapsulate`, `kem_decapsulate`, `kem_list_keys` | peer public key hex, key id, ciphertext hex | `key_id`, `public_key` hex, `fingerprint`, `ss_id`, ciphertext hex | **no** — `ss_id` is the only handle |
| Hybrid X25519+ML-KEM | `hybrid_keygen`, `hybrid_begin`, `hybrid_accept` | public bundle, ids | public bundle, `ss_id` | **no** |
| Identity | `ik_generate`, `ik_get_public`, `ik_list`, `spk_get_public`, `spk_rotate` | ids | public keys only | no |
| X3DH | `x3dh_initiate`, `x3dh_respond` | peer bundle | `ss_id`-style handles | no |
| Double Ratchet | `dr_init`, `dr_set_peer`, `dr_encrypt`, `dr_decrypt`, `dr_get_send_key`, `dr_list_sessions`, `dr_session_exists`, `dr_revoke_session`, `dr_delete_session` | session id, plaintext hex, message JSON | message JSON, plaintext hex, **sending public key** | no session or root keys; plaintext of messages necessarily crosses |
| Safety number | `dr_safety_number` | session id | digits | no |
| SM2 | `sm2_generate`, `sm2_get_public`, `sm2_import`, `sm2_sign`, `sm2_verify`, `sm2_ecdh`, `sm2_encrypt*`, `sm2_decrypt*`, `sm2_sign_full`, `sm2_verify_full` | ids, hashes, ciphertexts, **and one plaintext private key in `sm2_import`** | ids, public key, signature parts, ciphertext | only `sm2_import` takes a secret in; nothing returns one |
| Audit / flags / destructive | `audit_approval`, `get_experiments`, `keystore_selfdestruct` | opaque ids, a confirmation phrase | status | no (audit rejects secret-shaped values by contract, `src/audit.rs:27`) |

Two details worth stating because they are easy to get wrong:

- `kem_encapsulate` does **not** return the shared secret. The doc comment above it still says
  "Returns ... the shared_secret (for JS Double Ratchet init)" (`src-tauri/src/commands/kem.rs:78`)
  while the code stores it under `ss_id` and returns only `{ss_id, ciphertext}`
  (`kem.rs:107-113`). The comment was stale; it is corrected in the same change that adds this file.
- `dr_get_send_key` sounds like a key export. It returns the session's current **sending public
  key** (`src-tauri/src/commands/ratchet.rs:268-272`), which is what the peer needs to derive the
  next chain — not a private key.

## 3. Key flow, per key type

| Key | Generated | Stored | What JS ever sees | Notes |
|---|---|---|---|---|
| ML-KEM-768 keypair | Rust, `kem.rs:54-57` | secret key encrypted at `keys/{key_id}.enc` (`kem.rs:65`) | `key_id`, public key, fingerprint | secret key bytes are zeroized right after being copied for decapsulation (`kem.rs:140-156`) |
| ML-KEM shared secret | Rust, encapsulate/decapsulate | `CryptoState.shared_secrets` map, keyed by `ss_id` (`commands/mod.rs:37-39`) | `ss_id` only | consumed and removed by `dr_init` |
| X25519 identity + signed pre-key | Rust, `commands/identity.rs` | same encrypted store | public keys | SPK carries an ML-DSA-65 signature |
| Hybrid secret | Rust, `commands/hybrid_cmd.rs` | 64-byte secret; first 32 bytes become the root key under `ss_id` (`hybrid_cmd.rs:103-111`) | `ss_id` | the 64-byte secret never leaves Rust |
| Double Ratchet state | Rust, `double_ratchet.rs` | `sessions.json`, encrypted with a key derived from the device key via HKDF, domain-separated from the key-encryption key (`commands/mod.rs:44-46,57-59`) | session ids, ciphertext, plaintext, sending public key | legacy plaintext v2 files are migrated to the encrypted v3 format on load (`mod.rs:61-77`) |
| SM2 private key | Rust, or **imported from JS once** | encrypted store | `key_id`, public key | `sm2_import` range-checks `d ∈ [1, n-1]` and is the only inbound secret (`sm2_cmd.rs:139-161`); it exists for the `p2p_gm_keypair` localStorage migration |

## 4. At rest

- `device.key`: 32 random bytes, `DEVICE_KEY_LEN` (`key_store.rs:29-32`). On Windows it is wrapped
  with DPAPI, so the file is bound to the current user + machine and a copied file is useless
  elsewhere (`key_store.rs:34-39`). On Unix it stays a plaintext file with `0600`.
- `keys/{key_id}.enc`: `[12-byte nonce][AES-256-GCM ciphertext+tag]`, one random nonce per file
  (`key_store.rs:6-14`).
- `sessions.json`: encrypted with the HKDF-derived session key; a plaintext v2 file left by an older
  build is rewritten encrypted immediately after load.
- `keystore_selfdestruct`: requires the exact phrase `DESTROY ALL KEYS`, zeroizes sessions and
  pending secrets, overwrites every key blob three times with random bytes, then removes
  `device.key` and the metadata (`commands/identity.rs:360-400`). There is no scheduled, automatic,
  or remote trigger.

## 5. What this boundary does not protect

1. **A compromised renderer is equivalent to key access.** It cannot read raw keys from an IPC
   response, but it can call `kem_decapsulate`, `dr_decrypt` and `sm2_sign` on any id it can name.
   The IPC shape prevents accidental leakage in logs, screenshots and crash dumps; it does not stop
   deliberate abuse from inside the WebView.
2. **DevTools are enabled in the shipped configuration** (`src-tauri/tauri.conf.json:22`,
   `"devtools": true`). A local user can open the console and invoke commands directly. If the
   release build should not allow that, it is a build-profile change, not a code change.
3. **The renderer can read the encrypted store and the clipboard.** `capabilities/default.json`
   grants `fs:allow-read`/`allow-write`/`allow-exists` over `$APPDATA/**`, plus
   `clipboard-manager:allow-read-text`. It cannot decrypt the blobs without going through the
   commands, but it can copy them, and it can read whatever the user copies.
4. **Every registered command is callable, including the destructive one.** 42 of the 45 are wired
   into the frontend, `keystore_selfdestruct` among them; only `kem_list_keys`, `ik_generate` and
   `audit_approval` are unreferenced. This is not a reduced surface: the WebView can reach all 45.
5. **A second, older crypto generation still exists in the renderer.** `src/key-manager.js:156-162`
   creates WebCrypto keypairs and encrypts the private JWKs with a password;
   `src/modules/gm/*.js` still carries an SM2 path; `p2p_gm_keypair` was historically a plaintext
   private key in `localStorage` and is removed only after the migration call
   (`src/modules/gm/encrypt-with-gm.js:53-60`). Keys created by those paths are not covered by Rust
   custody.
6. **No memory locking.** There is no `mlock`/`VirtualLock`, and not every intermediate buffer is
   zeroized. Secret material lives in the Rust heap while in use, so swap, hibernation and core
   dumps are outside the boundary.
7. **No per-command authorization.** There is no user-presence check and no per-window scoping of
   custom commands. Tauri capabilities govern plugin APIs; the CSP governs what can be loaded, not
   who may invoke.
8. **Out of scope entirely:** screen capture, OS-level attackers, the network protocol, the server,
   and timing/side channels. The last one has its own measurement record in the main repository:
   `docs/research/falcon-sidechannel-threat-model.md`.

## 6. Invariants worth keeping

| Invariant | Anchor | How to check |
|---|---|---|
| No IPC response type carries a secret key or shared secret | `kem.rs:40-45,110-113`; `hybrid_cmd.rs:47-54`; `sm2_cmd.rs:197-200` | read the response structs; they contain ids, public keys and ciphertext only |
| Loaded secret keys are zeroized after use | `kem.rs:140-156` | code review; `zeroize` is a direct dependency |
| DPAPI wrapping is Windows-only and compiled out elsewhere | `key_store.rs:39` | `#[cfg(windows)]` |
| Self-destruct cannot fire without the exact phrase | `identity.rs:375-378` | `destructive_tests.rs` |
| Inline script and frames are blocked in the renderer | `tauri.conf.json:31-33` | CSP has `script-src 'self'`, `frame-src 'none'`, `freezePrototype: true` |

## 7. Re-verifying the counts in this document

```bash
grep -rn "#\[tauri::command\]" src-tauri/src | grep -v _tests | wc -l   # 45 registered
grep -rhoE "invoke(\(\))?\('[a-z0-9_]+'" src | sort -u | wc -l  # 42 referenced by the frontend
grep -n '"devtools"' src-tauri/tauri.conf.json                # true
grep -n "fs:allow-read\|clipboard-manager:allow-read-text" src-tauri/capabilities/default.json
```

If any of those numbers change, this document is stale — update it in the same PR that changes the
boundary, rather than afterwards.
