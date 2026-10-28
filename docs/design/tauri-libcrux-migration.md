# Replace `rustpq` with `libcrux-ml-kem` for ML-KEM in the Tauri backend

Status: **design only** — no production code changed. Drafted 2026-10-28.
Tracking issue: `Lennonhaha/fibemate-tauri#76`. Sandbox evidence from `tmp/libcrux-sandbox` (report posted on the issue).

---

## 1. Why

`rustpq 0.3` implements a **pre-final (October 2023 draft)** FIPS 203 for ML-KEM. Its KeyGen does not match final FIPS 203, which is why `src-tauri/src/pq/mlkem_kat.rs::acvp_mlkem768_keygen` is `#[ignore]`d today — the crate passes a draft-era vector and fails the final ACVP one. Everything else in the pipeline (encapsulation, decapsulation, hybrid handshake) is green, so the defect is invisible in normal operation and only appears when someone compares against final vectors or interoperates with a final implementation.

`libcrux-ml-kem 0.0.10` was tested in a sandbox and satisfies the exact requirement rustpq fails:

| Test | Result |
|---|---|
| `generate_key_pair([u8; 64])` is `KeyGen_internal(d ‖ z)` | **PASS** — `ind_cca.rs:17` seed = 32 + 32; `randomness[0..32] = d`, `[32..] = z` |
| pk / sk / ct / ss byte-identical to `@noble/post-quantum@0.7.1` on a fixed `d`, `z`, `m` | **PASS** — all four |
| roundtrip, `validate_public_key`, `validate_private_key(sk, ct)`, tamper rejection, `pk` embedded in `sk` | **PASS** |
| normal dependency graph | 16 crates, **no `cc` / `clang-sys` / `bindgen`** |
| `cargo audit` | 0 vulnerabilities, 1 build-time `unmaintained` (`proc-macro-error2` via `hax-lib-macros`) |
| aarch64 | **UNVERIFIED** here (no rustup/target); `no_std` + `mlkem768` build passes, SIMD is opt-in |
| `cargo deny` bans/licenses/sources | ok (advisories check cannot run offline) |

So the swap is a substitution, not a redesign: same key sizes, same NIST algorithm, only the crate and the keygen entry point change.

## 2. Scope

In scope

- `src-tauri/Cargo.toml`: ML-KEM dependency only.
- `src-tauri/src/pq/mod.rs`: re-exports, wrappers, keypair struct.
- `src-tauri/src/pq/mlkem_kat.rs`: un-ignore the final ACVP keygen test, adapt it to the new keygen API.
- CI: run the KAT test (now meaningful) and add an arm64 job.
- `deny.toml` / advisory refresh if the repo already has supply-chain config.

Out of scope

- ML-DSA-65 stays on `rustpq` (`mldsa65`). It has its own final-ACVP coverage and no equivalent defect was established; replacing two algorithms in one change would blur the rollback boundary.
- No changes to `src-tauri/src/pq/hybrid.rs`, the command layer, storage formats or wire formats.
- No change to JS/frontend (`pq-integration.js` already reports availability from the Rust bridge after #79).

## 3. Dependency changes

```toml
# before
rustpq = { version = "0.3", features = ["mlkem768", "mldsa65"] }

# after
rustpq = { version = "0.3", features = ["mldsa65"] }
libcrux-ml-kem = { version = "=0.0.10", default-features = false, features = ["mlkem768", "std"] }
```

Notes

- Pin with `=0.0.10`: pre-1.0 crate, no API stability promise. Bump deliberately, re-running the KAT.
- Keep the `kyber` feature **off**; it provides the Kyber variant, which is not what we ship.
- Leave `simd128` / `simd256` off. The dispatcher then resolves to the portable path, which is the one verified here. Enabling SIMD later requires a separate aarch64/AVX2 verification step.
- `default-features = false` drops the crate's `rand` integration on purpose: randomness is supplied by the application (§4.1), so the KEM crate must not own an RNG choice.
- Expected normal graph is 16 crates; `bindgen`/`clang-sys`/`crabgrind` appear in `Cargo.lock` only under `libcrux-secrets`' `cfg(valgrind_ct_test)` target dependency and are never built.

## 4. `pq/mod.rs` changes

### 4.1 API mapping

| Today (rustpq 0.3) | After (libcrux 0.0.10) |
|---|---|
| `mlkem768::generate(&mut OsRng) -> (PublicKey, SecretKey)` | `let mut seed = [0u8; 64]; OsRng.fill_bytes(&mut seed); generate_key_pair(seed) -> MlKemKeyPair` |
| `mlkem768::generate_deterministic(&d, &z)` | `let mut seed = [0u8; 64]; seed[..32].copy_from_slice(&d); seed[32..].copy_from_slice(&z); generate_key_pair(seed)` |
| `mlkem768::encapsulate(pk, &mut OsRng) -> (Ciphertext, SharedSecret)` | `let mut m = [0u8; 32]; OsRng.fill_bytes(&mut m); encapsulate(pk, m) -> (MlKemCiphertext, MlKemSharedSecret)` |
| `mlkem768::decapsulate(sk, ct)` | `decapsulate(sk, ct)` — same semantics, implicit rejection is internal in both |
| `PublicKey::from_bytes`, `SecretKey::from_bytes` | `validate_public_key` / `validate_private_key(sk, ct)` + `MlKemPublicKey::as_slice()` conversions |

The one behavioural difference to be explicit about: **`encapsulate` takes the 32-byte message randomness from the caller.** The wrapper must fill it from `OsRng` on every call (never reuse, never derive it from a counter). This is a net improvement — the RNG choice becomes ours and is testable — but it is the kind of change that silently becomes a catastrophe if a deterministic seed leaks into production code, so the wrapper keeps the randomness argument private to `mlkem768_encapsulate`.

### 4.2 Type surface

- Keep the public names (`MlKem768PublicKey`, `MlKem768SecretKey`, `MlKem768Ciphertext`, `MlKem768KeyPair`, `MLKEM768_*` constants) by aliasing the libcrux types, so `hybrid.rs` and the command layer compile untouched.
- `MlKem768KeyPair` currently stores `[u8; 2400]`; keep that shape (zeroize derive stays). libcrux's `private_key()`/`public_key()` return slices — copy into the arrays at the boundary.
- `mlkem768_decapsulate_bytes` currently **panics** on malformed key/ciphertext (`panic!("Invalid ML-KEM secret key: {e}")`). While touching the file, return `Result<[u8; 32], String>` and let the command layer map it to a `tauri` error. A panic in a decrypt path is a denial-of-service surface; it should not survive the rewrite.

### 4.3 Validation semantics

`is_valid_mlkem768_pk` / `is_valid_mlkem768_ct` should delegate to `validate_public_key` / (length + range checks for ciphertexts). libcrux's public-key check is the FIPS 203 modulus check; the old helper only compared lengths. This tightens behaviour, so audit call sites: a stored key that previously "passed" by length but fails the modulus check will now be rejected — which is the correct outcome but must be surfaced as a user-visible error, not a silent drop.

## 5. KAT changes (`mlkem_kat.rs`)

- Remove the `#[ignore]` from `acvp_mlkem768_keygen` and switch its body to `generate_key_pair(d‖z)`.
- Keep `acvp_mlkem768_encapsulation` and `acvp_mlkem768_decapsulation` as-is (they pass today and must keep passing).
- **Delete** `draft2023_mlkem768_keygen` and its vector blob: after this change the crate has no reason to pin pre-final behaviour, and keeping the draft test invites someone to "fix" the final test by reverting.
- Update the module doc comment: rustpq is now ML-DSA only.

Expected result: 3/3 final-ACVP tests pass, one draft-era test removed.

## 6. CI and supply chain

1. `cargo test --lib pq::mlkem_kat` must be a required check on PRs (today the meaningful half is skipped, so this is a new gate).
2. Add an arm64 job (`macos-14` is arm64; or `ubuntu-24.04-arm` if available) running the KAT — this closes the only UNVERIFIED item in the sandbox report.
3. Refresh the advisory DB in CI (the sandbox result used a 2026-06-25 cache because fetching is blocked locally). Expect `RUSTSEC-2026-0173` (unmaintained `proc-macro-error2`, build-time via `hax-lib-macros`); record it as an accepted build-time warning with a review date rather than suppressing the whole advisory check.
4. If `cargo deny` is adopted: allow-list MIT/Apache-2.0/BSD/ISC/Unicode-3.0/Zlib/MPL-2.0/CC0-1.0, `multiple-versions = "warn"`, `sources` unknown-registry/git = deny. That configuration produced `bans ok, licenses ok, sources ok` in the sandbox.

## 7. Blast radius on existing keys — **measured: none**

rustpq 0.3 is a pre-final implementation, so the obvious worry was that every keypair it produced is not a valid ML-KEM-768 keypair (the mobile situation in `fibemate-mobile#94`). **Measurement says otherwise.**

A minimal sandbox crate against `rustpq 0.3` with fixed `d = 00..1f`, `z = 20..3f`:

```
pk == noble pk (same d, z)                      : false   <- derivation differs (draft G without k)
sk == noble sk                                  : false
sk embedded pk == pk                            : true
H(pk) at sk[2336..2368]                         : true
rustpq roundtrip                                : true
noble decaps(rustpq ct, rustpq sk) == rustpq ss : true
noble encaps(rustpq pk) -> noble decaps         : true, matches
```

Interpretation: rustpq's *derivation* from `(d, z)` differs from final FIPS 203 — which is exactly why the ACVP keyGen vector fails — but the resulting keypair is a **structurally valid** ML-KEM-768 keypair in the NTT domain. A correct FIPS implementation can encapsulate to it and decapsulate its ciphertexts, and vice versa. Determinism matters for a KAT; validity does not depend on it.

Consequences:

- **No re-key, no dual engine, no migration window for the desktop app.** Existing identities, stored ciphertexts and published public keys stay valid across the swap.
- The only difference is that new keys will not equal what rustpq *would* have produced for the same seed — unobservable, because seeds are random.
- Rollback stays simple (§8).

This is the opposite of the mobile finding, and the difference is instructive: mobile's legacy module encodes time-domain polynomials, a structural defect; rustpq has a differing derivation but correct encoding. "Fails the final KAT" and "produces invalid keys" are different claims, and only measurement separates them.

## 8. Rollback

- The change is one dependency line plus one module's wrappers; reverting the commit restores rustpq. No stored-format change is introduced by the swap itself.
- If §7 finds incompatible key material, rollback stops being simple and the dual-engine design becomes mandatory — which is precisely why §7 gates the work.

## 9. Risks

| Risk | Mitigation |
|---|---|
| Pre-1.0 crate churn (`0.0.x`) | Exact pin, KAT gate, deliberate bump PRs |
| Caller-supplied encapsulation randomness misused | Randomness stays private to the wrapper; test that two calls differ |
| `validate_public_key` rejects previously accepted stored keys | Audit call sites; surface typed errors; document user-visible recovery |
| aarch64/windows differences | arm64 CI job + existing windows runner |
| Build-time unmaintained macro crate | Track `RUSTSEC-2026-0173`; it is build-time only and does not ship |
| Hybrid handshake regressions | Existing `cargo test --lib hybrid` (9 tests incl. `test_hybrid_begin_accept_roundtrip`) stays green |

## 10. Acceptance criteria

- `cargo test --lib pq::mlkem_kat` passes **with no `#[ignore]`d final tests**.
- `cargo test --lib hybrid` still 9/9; `scripts/test-pq-availability.cjs` still 15/15.
- `cargo tree -e normal` shows 16 crates for the KEM subtree and no `cc`/`bindgen`.
- arm64 KAT job green.
- `Cargo.lock` diff contains no new C-toolchain crates in the normal graph.
- §7 measurement recorded on the issue with PASS/FAIL and verbatim output (done: keys interoperate across implementations, no re-key needed).
