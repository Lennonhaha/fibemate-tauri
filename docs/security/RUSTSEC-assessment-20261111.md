# RUSTSEC advisory assessment — 2026-11-11

Status: record only. No code, dependency or CI change accompanies this document.

This file answers one question for a reader who opens the repository and sees two
cargo-deny warnings in the dependency tree: *what are they, can they hurt us, and why
has nothing been done*. It also records three places where `SECURITY.md` no longer
matches the tree, because a stale security document is worse than a missing one.

## 1. Scope and method

| | |
|---|---|
| Repository | `Lennonhaha/fibemate-tauri` |
| Commit | `fdf571a` (main) |
| Package | `fibemate-tauri` 3.3.7 / `tauri` 2.12.3 |
| Lockfile | `src-tauri/Cargo.lock`, 570 packages |
| Gate | `.github/workflows/deny.yml` → `cargo-deny-action`, `check advisories --all-features` |
| Config | `deny.toml` (`[advisories] version = 2`) |
| Last green run | `42638310971` (schedule, 2026-11-09T14:48:36Z, head `fdf571a`) |

Checked: the advisory text at rustsec.org, the dependency graph as recorded in
`Cargo.lock`, the call sites in `src-tauri/src`, and what the release workflow actually
builds.

Not checked: `cargo tree` and `cargo deny` were not executed locally — no Rust toolchain
is installed on the recording machine. The graph below is derived from `Cargo.lock`
(which pins the exact versions the CI gate resolved) and from the advisory metadata. Any
conclusion that depends on target-gating is cross-checked against CI behaviour rather
than inferred.

## 2. Why the gate is green while the tree still carries two warnings

`deny.toml` sets `unmaintained = "workspace"` and `unsound = "workspace"`: advisories of
those two classes fail the check only when they hit a *direct* dependency of this
workspace. Vulnerabilities (`vulnerability` class) always fail — cargo-deny v2 removed
the ability to downgrade them.

Both advisories below are transitive and belong to the GTK subtree, so they are filtered
by that scope rather than ignored by name. `unused-ignored-advisory = "deny"` keeps any
future named ignore honest.

This is a scope decision, not a suppression: if either package ever becomes a direct
dependency, or if a `vulnerability`-class advisory lands on it, the same gate fails.

## 3. RUSTSEC-2024-0429 — `glib` 0.18.5, unsound

| Field | Value |
|---|---|
| Class | `unsound` (not a CVE; UB, not a known exploit) |
| Reported / issued | 2024-03-30 / 2024-12-23 (last modified 2025-10-28) |
| Affected | `glib` >= 0.15.0, patched >= 0.20.0 |
| In our lockfile | 0.18.5 |
| Alias | GHSA-wrw7-89jp-8q8g |
| Affected APIs | `glib::VariantStrIter::{next, next_back, nth, nth_back, last}` |

What the advisory says: `VariantStrIter::impl_get` passes an immutable reference to a
`*mut c_char` into C code that writes through it as an out-argument. With current
compiler optimisations those writes can be dropped, after which
`CStr::from_ptr` receives a pointer that violates its safety contract. The result is
undefined behaviour — memory unsoundness, not a demonstrated read/write primitive.

Reachability in this repository:

- `glib::` appears **0 times** in `src-tauri/src`; the application does not call glib.
- `VariantStrIter` appears **0 times** in the source tree.
- `glib` arrives only through the GTK 3 stack: `gtk` 0.18.2 → `glib` 0.18.5, with
  `atk`, `cairo-rs`, `gdk`, `gdk-pixbuf`, `gdkx11`, `gio`, `javascriptcore-rs`,
  `libappindicator`, `pango`, `soup3` and `webkit2gtk` 2.0.2 as sibling dependents.
- `gtk` 0.18.2 is pulled by `libappindicator` 0.9.0, `muda` 0.20.0, `tao` 0.37.1,
  `tauri` 2.12.3, `tauri-runtime` 2.12.2, `tauri-runtime-wry` 2.12.2, `webkit2gtk` 2.0.2
  and `wry` 0.57.0 — all of it the windowing stack, none of it our code.

Exposure: the shipped artifact is Windows-only — `src-tauri/tauri.conf.json` sets
`"targets": "nsis"`, `release.yml` states the same in a comment and builds only
`windows-latest` for the bundle, and `SECURITY.md` says "Windows-only — macOS/Linux not
tested". The GTK/glib subtree is not compiled into that artifact.

Why it cannot be fixed from here: `tauri` 2.x requires `gtk ^0.18`, and `glib` 0.20 —
the first patched release — is incompatible with it. Moving to `glib` 0.20 means moving
to gtk4, which means `tauri` 3.x (still alpha at the time of writing) or a
`[patch.crates-io]` override that would fork the windowing stack. Neither is a change
this repository should make to silence a warning that cannot reach its binary.

## 4. RUSTSEC-2024-0370 — `proc-macro-error` 1.0.4, unmaintained

| Field | Value |
|---|---|
| Class | `unmaintained` (no patched version exists) |
| Reported / issued | 2024-09-01 / 2024-09-05 (last modified 2026-06-07) |
| In our lockfile | 1.0.4 |
| Paths | `glib-macros` 0.18.5 → `proc-macro-error`; `gtk3-macros` 0.18.2 → `proc-macro-error` |

What the advisory says: the maintainer is unreachable, no commits for two years, no
releases for four, and the crate pulls `syn` 1.x into build trees that may otherwise use
`syn` 2.x. There is no vulnerability and no patched version; the concern is maintenance
and dependency duplication. Suggested alternatives: `manyhow`,
`proc-macro2-diagnostics`.

Reachability: it is a **proc-macro** crate — it runs at compile time and produces code;
it is not linked into the shipped binary. Both entry points are macros used by the
gtk-rs bindings while compiling the GTK subtree, i.e. the same Linux-only branch as
above. A Windows NSIS build never compiles it.

Why it cannot be fixed from here: the same `gtk ^0.18` pin. `glib-macros` 0.18 depends on
`proc-macro-error` 1.0, and the maintained fork (`proc-macro-error2`) is not a drop-in
substitution that upstream gtk-rs 0.18 accepts.

## 5. Documentation drift found while recording this

`SECURITY.md` carries a "Known Dependency Vulnerabilities (Open)" list with three
entries. Measured against the tree at `fdf571a`, two of them are no longer true, and the
advisory that *is* still true is the only one that is not listed by its RUSTSEC id.

1. **`pqc_kyber` 0.7.1 (KyberSlash, High) — listed as open, package absent.**
   `pqc_kyber` appears **0 times** in `src-tauri/Cargo.lock` and **0 times** in `src`.
   The WASM/JS bridge it belonged to was retired in v3, and PR #84 removed the remaining
   time-domain ML-KEM artifacts. The entry should move to a "resolved" section with the
   commit that removed it. Leaving a High-severity item open in a public security
   document overstates the risk and, worse, teaches readers that the list is not
   maintained.
2. **`serde_with` 3.20.0 → 3.23.0 — listed as open, fix already applied.**
   The lockfile pins `serde_with` 3.23.0, which is past the 3.21.0 fix for
   GHSA-7gcf-g7xr-8hxj. Same treatment: move to resolved.
3. **`RUSTSEC-2024-0370` (`proc-macro-error`) — absent from `SECURITY.md`.**
   The two GTK advisories are filtered by the `deny.toml` scope, so they never surface as
   CI noise; that is precisely why they belong in the security document, where a reader
   looks for them. Only `glib` is mentioned today.

No edit to `SECURITY.md` is made here: this document is the record, the correction is a
separate decision (and a separate commit) for the repository owner.

## 6. When to re-open this assessment

Re-evaluate — do not re-read this file — if any of the following becomes true:

- `tauri` 3.x reaches stable with gtk4 support, or `glib` >= 0.20 becomes reachable while
  `gtk` stays at 0.18 (the latter is not expected).
- `cargo-deny` reports a `vulnerability`-class advisory on `glib`, `proc-macro-error`,
  `gtk`, `webkit2gtk` or `syn` 1.x. The gate already fails in that case; the point here
  is that the documented reasoning must be revisited, not just the CI status.
- The release target changes from Windows-only to include Linux or macOS bundles. The
  entire reachability argument above collapses at that moment.
- 2027-02-11 (three months), whichever comes first.

## 7. Reproduce

```bash
# the gate itself (needs a Rust toolchain)
cargo deny check advisories --all-features --manifest-path src-tauri/Cargo.toml

# the graph claims
cargo tree -i glib --manifest-path src-tauri/Cargo.toml
cargo tree -i proc-macro-error --manifest-path src-tauri/Cargo.toml

# the call-site claims (expected: no output)
grep -rn "glib::" src-tauri/src
grep -rn "VariantStrIter" src-tauri/src

# the packaging claim
grep -n '"targets"' src-tauri/tauri.conf.json   # "nsis"
```

Recorded 2026-11-11. Advisory text read from `https://rustsec.org/advisories/RUSTSEC-2024-0429`
and `https://rustsec.org/advisories/RUSTSEC-2024-0370`.
