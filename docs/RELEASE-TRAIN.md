# Release train

This document describes the workflow-level release discipline added on
2026-11-25. It is a **publication** process, not an auto-updater.

## Lanes

| Lane | Trigger | Tag | GitHub Release | Version gate |
|---|---|---|---|---|
| nightly | daily, 03:00 UTC; manual dispatch | `nightly-YYYYMMDD-<sha>` | prerelease | skipped (`skip_version_gate=true`) |
| stable | Monday 04:00 UTC on even ISO weeks; manual dispatch | `v<package.version>` | **draft first** | required (5 files, 6 places) |

Nightly does not bump `package.json` during the freeze. Its tag is the version
identifier; the installer still carries the package version. Read the tag and the
commit SHA, not the version field, to tell nightly builds apart.

Stable requires a real version bump and a matching tag. If the tag or release
already exists, the prepare job skips rather than rebuilds it.

## Freeze switch

`RELEASE_TRAIN_FROZEN` is a repository variable. When it is `true`, the first
step of every release job exits 1:

```text
::error::RELEASE_TRAIN_FROZEN=true; release blocked
```

Set it with:

```bash
gh variable set RELEASE_TRAIN_FROZEN --repo Lennonhaha/fibemate-tauri --body true
gh variable get RELEASE_TRAIN_FROZEN --repo Lennonhaha/fibemate-tauri
```

This blocks `release.yml` (including tag pushes), `release-train.yml`, and
`release-promote.yml`. It does **not** reach an installed client: there is no
remote-config polling in the app. It is a publishing kill switch, not a client
kill switch.

## Stable promotion

`release-train.yml` creates the stable release as a draft. A draft is not public
and has no "latest" designation. Promotion is a separate manual action:

```bash
gh workflow run release-promote.yml \
  --repo Lennonhaha/fibemate-tauri \
  --ref main \
  -f tag=v3.3.14 \
  -f confirm=PROMOTE
```

The promote workflow refuses to run when the freeze switch is on, requires the
literal confirmation, and checks that the release is still a draft before
publishing. The optional `stable-release` environment can be given required
reviewers in repository settings; without that setting the workflow is still a
manual, typed gate.

## Manual nightly and stable dispatch

```bash
# resolve only; no build
gh workflow run release-train.yml \
  --repo Lennonhaha/fibemate-tauri \
  --ref main \
  -f channel=nightly \
  -f dry_run=true

# real stable draft (version tag must be unused)
gh workflow run release-train.yml \
  --repo Lennonhaha/fibemate-tauri \
  --ref main \
  -f channel=stable \
  -f confirm=RELEASE
```

`release.yml` keeps its original `push: tags: v*` path. The dispatch/reusable
inputs are additive: `tag`, `target`, `channel`, `prerelease`, `draft`, and
`skip_version_gate`. A normal `v*` tag push still uses `--verify-tag`.

## Boundary: what is not implemented

The client has no updater plugin, no telemetry, and no remote rollout config.
Therefore this release train **does not** implement:

- 5% → 50% → 100% automatic rollout;
- a client-side kill switch or automatic rollback;
- an update manifest that installed clients consume.

Those require client code plus an external service and are outside the frozen
period. Do not add a fake manifest or claim that publishing a draft is a
percentage rollout. The only rollout-shaped guarantee here is
**draft → manual promote → public**, plus the workflow freeze switch.

## Known unverified item

`release.yml`'s `workflow_call` build path has **not** been exercised end to end.
The 2026-11-25 verification covered only the workflow syntax (actionlint), the
`release-train.prepare` resolution with `dry_run=true`, and the freeze-guard
negative tests. The reusable call skipped the actual build.

The first real stable/nightly run after unfreeze must confirm:

- `tag`, `target`, `channel`, `prerelease`, `draft`, and `skip_version_gate`
  arrive at the reusable workflow as intended;
- artifact upload/download names and the `publish` paths still match the
  standalone tag-push path;
- the created tag and release point at the intended commit.

Until then, do not describe the reusable call path as verified.

## Test the switch without publishing

1. Set `RELEASE_TRAIN_FROZEN=false`.
2. Dispatch `release-train.yml` with `channel=nightly`, `dry_run=true`: the
   prepare job should resolve a tag and skip the Release call.
3. Set `RELEASE_TRAIN_FROZEN=true`.
4. Repeat the dispatch: the first step must fail with the freeze error.
5. Leave it `true` until the freeze is explicitly lifted.

No client code, version, tag, or installer is changed by this process.

> 2026-11-25 note: five freeze/dry-run negative tests have already been run.
> Do not re-run any release workflow while the freeze is active; it only adds
> red runs and does not increase confidence.
