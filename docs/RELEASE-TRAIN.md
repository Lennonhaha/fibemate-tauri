# Release train

This document describes the workflow-level release discipline added on
2026-11-25. It is a **publication** process, not an auto-updater.

## Lanes

| Lane | Trigger | Tag | GitHub Release | Version gate |
|---|---|---|---|---|
| nightly | daily, 03:00 UTC; manual dispatch | `nightly-YYYYMMDD-<sha>` | prerelease | skipped (`skip_version_gate=true`) |
| stable | Monday 04:00 UTC on even ISO weeks; manual dispatch | `v<package.version>` | **draft first** | required (5 files, 6 places) |

All cron expressions in this repository are standard five-field UTC. GitHub does
not accept a timezone in `cron`; a missing or extra field is a hard parse error,
so a wrong timezone cannot be expressed here. Scheduled runs are nevertheless
queued late by the platform - see "Scheduled lane timing" below before treating
a late run as a bug.

Nightly does not bump `package.json` during the freeze. Its tag is the version
identifier; the installer still carries the package version. Read the tag and the
commit SHA, not the version field, to tell nightly builds apart.

Stable requires a real version bump and a matching tag. If the tag or release
already exists, the prepare job skips rather than rebuilds it.

## Freeze switch

`RELEASE_TRAIN_FROZEN` is a repository variable. When it is `true`, the train
stops **publishing**: the nightly lane is skipped (a nightly tag is a
prerelease publication) and `release-promote.yml` is skipped. A stable candidate
may still be built as a **draft**: the freeze switch blocks publish/promote, not
draft builds, and a draft may exist while the train is frozen without being
released.

A frozen publish job ends as **skipped** (grey), not failed:

```text
Release train (nightly)   skipped
Promote release           skipped
```

The switch deliberately does not use `exit 1` any more - a daily schedule that
goes red every night is indistinguishable from a real release failure, and an
intentional freeze must not look like an incident.

Status semantics for operators and for the nightly digest:

- `skipped` + `RELEASE_TRAIN_FROZEN=true` -> expected, no action;
- `skipped` + variable `false` -> the trigger itself resolved to skip (odd ISO
  week, existing tag, or `dry_run=true`); read the prepare job before acting;
- `failure` -> a real failure; the freeze cannot produce one.

The digest maps the first case to `expected:frozen` and keeps it out of the
action list.

Set it with:

```bash
gh variable set RELEASE_TRAIN_FROZEN --repo Lennonhaha/fibemate-tauri --body true
gh variable get RELEASE_TRAIN_FROZEN --repo Lennonhaha/fibemate-tauri
```

This blocks `release.yml` for published channels (nightly and tag pushes), the
nightly lane of `release-train.yml`, and `release-promote.yml`. A stable draft
build is still allowed. It does **not** reach an installed client: there is no
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
literal confirmation, checks that the release is still a draft, and refuses a
draft whose `targetCommitish` is not the current `main` head (#118). The last
check exists because a draft is a snapshot: it keeps verifying against the commit
it was built from while `main` moves on, so promoting a stale draft publishes code
that does not contain the reviewed tree. The gate prints `STALE_DRAFT` with both
commits and tells you to rebuild; re-run `release-train.yml` on the current `main`
instead of promoting the old artifact set. The optional `stable-release`
environment can be given required reviewers in repository settings; without that
setting the workflow is still a manual, typed gate.

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
4. Repeat the dispatch: the run must end as `skipped`, with no job started and
   no error.
5. Leave it `true` until the freeze is explicitly lifted.

No client code, version, tag, or installer is changed by this process.

## Scheduled lane timing (measured 2026-11-25)

GitHub scheduled workflows are best-effort and this repository's are queued
about 9-11 hours late. Measured with `gh run list --event schedule`:

| Workflow | Declared (UTC) | Observed (UTC) | Delay |
|---|---|---|---|
| Fuzz | 06:00 daily | 16:39, 16:50, 17:06 | ~10.6-11.1 h |
| deny | 06:00 Monday | 16:57 Monday | ~10.9 h |
| CodeQL | 06:00 Wednesday | 15:00, 16:42 Wednesday | ~9.0-10.7 h |
| OpenSSF Scorecard | 00:00 Monday | 06:05 Monday | ~6.1 h |
| Release train (nightly) | 03:00 daily | 11:51 | ~8.9 h |

The delay is uniform across workflows with different expressions, so the
schedule syntax is not the cause - the runner queue is. Do not "fix" the cron
and do not treat a late run as a bug.

Consequences:

- the nightly tag is stamped with the UTC date at resolve time, i.e. the day the
  run actually starts, not the day it was scheduled for;
- a wall-clock guarantee ("released at 03:00 UTC") is not available from the
  platform. It would need an external trigger calling `workflow_dispatch`, which
  needs a credential that the current OIDC-only setup avoids.

> 2026-11-25 note: five freeze/dry-run negative tests have already been run.
> Do not re-run any release workflow while the freeze is active; since the
> switch now skips instead of failing, a re-run only adds a skipped run and
> does not increase confidence.
>
> 2026-11-26 note: the `exit 1` gate was replaced by a job-level `if`, because
> the daily schedule kept producing red runs that looked like incidents. The
> freeze still blocks every release job; it is now visible as `skipped`.
