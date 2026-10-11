# Fuzzing

Coverage-guided fuzzing for FIBEMATE Tauri's attacker-facing parse paths.
Runs on `cargo-fuzz` (libFuzzer) under a nightly toolchain.

## Targets

Both targets exercise **pure, `State`-free `pub` functions** on
attacker-controlled input — no production code path is modified to fuzz them.

| Target | Entry point | Input |
|---|---|---|
| `hybrid_init_parse` | `fibemate_lib::pq::hybrid::{HybridEncapsulation, HybridPublicBundle}::from_bytes` | Raw hybrid key-exchange wire bytes (`src-tauri/src/pq/hybrid.rs`) |
| `envelope_parse` | `fibemate_lib::sm2::Sm2StandardCipher::from_hex` | SM2 application-layer envelope `C1\|\|C3\|\|C2` as an ASCII hex string (`src-tauri/src/sm2.rs`) |

Each target also asserts that an **accepted** input re-serialises byte-for-byte
(`to_bytes` / `to_hex` round-trip); a mismatch aborts, so it is caught as a bug
rather than silently accepted.

## Running locally

Requires a nightly toolchain and `cargo-fuzz`:

```bash
cargo install cargo-fuzz --locked
node fuzz/scripts/gen-corpus.mjs     # initial setup only (seeds are committed)
cd fuzz
cargo +nightly fuzz run hybrid_init_parse
cargo +nightly fuzz run envelope_parse
```

> The fuzzed lib depends on `tauri`; on Linux install the webview/GTK stack
> first (`libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev
> librsvg2-dev`) — see `.github/workflows/fuzz.yml`.

## Corpus

- **Seeds** — `fuzz/corpus/<target>/` holds minimal-but-valid wire payloads.
  They are **committed to git** and created once via
  `node fuzz/scripts/gen-corpus.mjs` (initial setup only — not run in CI).
- **Growth** — CI restores the accumulated corpus from the Actions cache
  (key `fuzz-corpus-<target>-<run_id>`, prefix restore) and saves it back with
  `if: always()`, so inputs discovered by earlier runs are replayed later
  instead of the corpus restarting from the seeds every time.
- **Crashes** — a fixed crash's reproducer is committed into
  `fuzz/corpus/<target>/` so it is replayed forever after (see Triage).

> TODO (not yet implemented): prune `fuzz/corpus/<target>/` once cache growth
> approaches the 10 GB Actions cache limit, keeping the most recent N files per
> target.

## Triage

When libFuzzer reports a crash:

1. **Reproduce** — `cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>`
2. **Classify** — panic / timeout / OOM / UB (UB only shows under ASan/UBSan)
3. **Locate** — map the stack frame back to the source line
4. **Fix** — open a PR; no fix merges without the reproducer
5. **Regression** — copy the crash input into `fuzz/corpus/<target>/` so it is
   replayed by CI forever after
6. **Verify** — confirm the target survives the old reproducer and CI is green

## CI

`.github/workflows/fuzz.yml`:

- **PR** (`paths: src-tauri/**, fuzz/**`): 300 s per target — catches regressions.
- **Nightly** (`schedule`, 06:00 UTC): 3600 s per target — finds new bugs.
- **Manual** (`workflow_dispatch`): long run on demand.

Crash inputs are uploaded as build artifacts when a run fails.

## Coverage

```bash
cd fuzz
cargo +nightly fuzz coverage hybrid_init_parse
cargo +nightly fuzz coverage envelope_parse
```
