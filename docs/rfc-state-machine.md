# RFC: client state, schema migration, and privacy-friendly crash reporting

- Status: Draft
- Date: 2026-11-25
- Scope: `fibemate-tauri` client
- This document is design only. It does not change client code.

## Why this RFC exists

The v3.3.9 through v3.3.14 releases were six patches for what turned out to be
three missing layers, not six unrelated bugs:

1. per-conversation state isolation and a single source of truth for what is
   currently rendered;
2. request correlation and generation fencing for asynchronous work;
3. versioned storage with an explicit migration path.

The client also has no privacy-reviewed crash path; `console.error` is the only
diagnostic channel. This RFC defines the smallest design that closes those
gaps without rewriting the application into a new architecture.

## Current evidence

This is not a hypothetical problem. The present code already contains partial
guards:

- `src/modules/chat.js` uses `STATE.currentPeerId`,
  `STATE.currentConversationId`, `STATE._msgAbort`, and
  `list.dataset.conversationId` to reject stale work.
- `openChat` clears the message list synchronously before awaiting
  `ensureConversation`; `loadMessages` checks the abort token and the current
  conversation before replacing the DOM.
- `sendMessage` captures `peer` and `conversationId`, but reads mutable global
  state again after awaits.
- `src/modules/websocket.js` writes decrypted plaintext to
  `fibemate_pt_<messageId>` and failure markers to `fibemate_df_<messageId>`;
  rendering still depends on the active conversation.
- Storage is spread across `localStorage` keys and three IndexedDB databases:
  `fibemate_secure_keys` (v1), `fibemate_vault` (v1), and `fibemate_p2p` (v1).
  Rust session files use `SESSION_FILE_VERSION = "2"`.
- `src/key-storage-migration.js` is a one-off localStorage-to-IndexedDB key
  migration, not a schema framework.

These guards are useful, but they are local patches. They do not define which
state transitions are legal, which stale results must be discarded, or what
happens when stored data has an unknown version. The same class of bug can
reappear in any new async path.

## Design principles

1. **One active render target.** At most one conversation can own the visible
   message list at a time. Every render carries an explicit token.
2. **Generation fencing.** Every asynchronous operation is bound to the state
   generation that started it. A result from an older generation is discarded,
   not merged and not queued for later.
3. **Fail closed on ambiguity.** Unknown storage versions, failed migrations,
   and missing conversation identities must produce a read-only or explicit
   error state. Never "try anyway" and never silently reset user data.
4. **Cache first, render second.** Incoming messages and offline batches may
   update per-conversation caches without touching the DOM. Rendering requires a
   matching active token.
5. **Privacy by default.** Crash reporting is off until the user opts in. It
   never carries message content, keys, tokens, peer identifiers, file names,
   or free-form error text.
6. **Design only in the freeze.** This RFC does not authorize client code,
   version, build, tag, or production changes.

## 1. Client state machine

### 1.1 States

| State | Meaning | Writes to message DOM? |
|---|---|---|
| `BOOT` | Process started, storage not yet inspected | No |
| `UNAUTHENTICATED` | No usable token | No |
| `AUTHENTICATED_IDLE` | Token present, no conversation selected | No |
| `CONVERSATION_LOADING` | A conversation is selected and a load is in flight | Placeholder only |
| `CONVERSATION_READY` | Active conversation matches the current token | Yes |
| `SEND_INFLIGHT` | A send is in progress for a captured token | Only its own bubble |
| `DEGRADED_STALE` | Load failed, last verified snapshot shown with a stale banner | Snapshot only |
| `READONLY_SAFE_MODE` | Storage version/migration is unsafe | No writes, explicit banner |
| `FATAL` | Unrecoverable startup error | No |

### 1.2 Tokens

Introduce two monotonic values, both in memory and both starting at zero on app
launch:

- `appEpoch`: increments on every successful login/logout/account switch.
- `conversationGeneration`: increments on every `openChat`, even when the same
  peer is clicked again.

The active render token is the tuple:

```text
RenderToken = { appEpoch, conversationId, conversationGeneration }
```

A token is valid only if all three fields match the current state. The
conversation id alone is not sufficient, because a user can leave and return to
the same conversation while an old request is still in flight.

Each asynchronous operation captures a token at call time:

- load history;
- find-or-create conversation;
- session setup and handshake;
- encrypt and send;
- read-receipt upload;
- offline replay and reconnect;
- websocket message handling that touches the active DOM.

### 1.3 Transition rules

```text
BOOT
  -> UNAUTHENTICATED            (no token)
  -> READONLY_SAFE_MODE         (unsafe storage version)
  -> AUTHENTICATED_IDLE         (token ok)

AUTHENTICATED_IDLE
  -> CONVERSATION_LOADING       (openChat; bump generation synchronously)
  -> READONLY_SAFE_MODE         (storage failure)

CONVERSATION_LOADING
  -> CONVERSATION_READY         (load result token matches)
  -> DEGRADED_STALE             (load failed for current token)
  -> AUTHENTICATED_IDLE         (user left; token invalid)

CONVERSATION_READY
  -> CONVERSATION_LOADING       (switch or reload; bump generation)
  -> SEND_INFLIGHT              (send starts with captured token)
  -> AUTHENTICATED_IDLE         (user leaves)

SEND_INFLIGHT
  -> CONVERSATION_READY         (send settled for same token)
  -> CONVERSATION_READY         (send settled for stale token: remove its bubble)
```

Rules:

- `openChat` increments `conversationGeneration` **before** the first await and
  clears the visible list synchronously. No old message may remain visible
  under the new peer name.
- A stale result is dropped. It is not rendered into a hidden buffer and it is
  not replayed when the user returns.
- A result whose token matches may commit. A result whose token does not match
  may only update a cache keyed by its own conversation id.
- If a load fails for the current token, enter `DEGRADED_STALE` and show the
  last verified snapshot with an explicit "showing last content" notice. If no
  snapshot exists, show an explicit failure state, not an empty conversation.
- `READONLY_SAFE_MODE` disables message sends, writes, migrations, and key
  changes. It still allows the user to export diagnostics and sign out.

### 1.4 Send path

`sendMessage` captures once, before any await:

```text
SendContext = {
  appEpoch,
  peerId,
  conversationId,
  conversationGeneration,
  clientMessageId,
  draftText
}
```

- Every await checks `isCurrent(SendContext)` before continuing.
- The optimistic bubble is keyed by `clientMessageId`; a failure removes only
  that bubble and restores `draftText` if the input has not changed.
- The server request carries an idempotency key derived from
  `clientMessageId` so a retry cannot create a duplicate message.
- A stale send may finish on the wire, but it must never append into the new
  conversation's DOM. If it succeeded, it belongs to its captured conversation
  cache only.

### 1.5 Websocket and offline replay

- Incoming ciphertext is decrypted into a per-message cache first.
- DOM rendering requires a valid `RenderToken`.
- If the message is for another conversation, update that conversation's cache
  and unread state, but do not call the active renderer.
- Offline replay processes messages in server order, with a batch token. A
  reconnect that changes the active token must drop the remainder of the old
  batch from the DOM path and leave already-decrypted entries in the cache.
- `lastSeen` advances only after a successful decrypt and cache write.

### 1.6 Invariants

- **I1:** at most one active render token exists.
- **I2:** `conversationGeneration` never decreases and never wraps in a session.
- **I3:** a result with an older token never mutates the active DOM.
- **I4:** cached plaintext is keyed by message id and is never used as proof
  that a message belongs to the active conversation.
- **I5:** the visible list and the title always describe the same conversation.
- **I6:** a send cannot cross to a different peer after a switch.
- **I7:** every failure path ends in an explicit state, never a blank panel.

### 1.7 Test obligations

- A delayed `find-or-create` for A resolves after switching to B; B's title and
  A's messages must never coexist.
- Two `loadMessages` calls overlap; only the newest token may replace the DOM.
- A send is in flight when the user switches; the bubble and the request stay
  with the captured peer, and the new conversation is untouched.
- A websocket message arrives for A while B is active; it enters A's cache and
  does not render in B.
- A failed load with a prior snapshot enters `DEGRADED_STALE`, not a blank list.
- Storage failure enters `READONLY_SAFE_MODE` and blocks writes.

These can be deterministic unit tests with fake timers and deferred promises;
they do not require a live server.

## 2. Schema and migration framework

### 2.1 Current storage map

| Domain | Location | Current version | Secret? |
|---|---|---|---|
| Auth token / identity | `localStorage` (`fk_token`, `fk_uid`, `fk_uname`, ...) | none | Yes |
| Contacts and read receipts | `localStorage` (`fk_contacts`, `fk_read_receipts`) | none | Personal data |
| Settings and theme | `localStorage` (`fk_setting_*`, `fk_theme`) | none | Low |
| Vault metadata | `localStorage` (`fk_vault`) | none | Personal data |
| Vault blobs | IndexedDB `fibemate_vault` | 1 | Yes |
| Encrypted device keys | IndexedDB `fibemate_secure_keys` | 1 | Yes |
| P2P/GM state | IndexedDB `fibemate_p2p` | 1 | Yes |
| Rust ratchet sessions | app data directory | `SESSION_FILE_VERSION="2"` | Yes |
| Message caches | `localStorage` (`fibemate_pt_*`, `fibemate_df_*`) | none | Plaintext / markers |

The absence of a version is the problem. A reader cannot tell "this is the
current format" from "this is an old format that happens to parse".

### 2.2 Manifest

Add one non-secret manifest key, for example `fk_schema`, containing:

```json
{
  "schemaVersion": 2,
  "minReadable": 1,
  "createdBy": "3.3.x",
  "stores": {
    "localStorage": 1,
    "secureKeys": 1,
    "vault": 1,
    "p2p": 1,
    "rustSessions": "2"
  }
}
```

The manifest is a pointer, not a copy of user data. It must never contain
tokens, keys, message content, or peer identifiers.

### 2.3 Migration state machine

```text
UNINITIALIZED
  -> PROBE
PROBE
  -> READY                    (manifest current, all stores readable)
  -> MIGRATION_NEEDED         (older manifest/store)
  -> READONLY_SAFE_MODE       (future version or unreadable manifest)
MIGRATION_NEEDED
  -> BACKUP
BACKUP
  -> MIGRATING
MIGRATING
  -> VERIFYING
VERIFYING
  -> READY                    (all checks pass; commit manifest last)
  -> READONLY_SAFE_MODE       (any check fails; keep old data)
```

Rules:

- **Forward only.** A newer schema is never downgraded by an older client.
  Unknown future versions enter `READONLY_SAFE_MODE`; they do not reset data.
- **No destructive default.** Never call `localStorage.clear()` or delete an
  IndexedDB database as a recovery action. A corrupt entry is quarantined, not
  silently replaced.
- **Commit last.** The manifest version is written only after every migrated
  store passes verification. A crash mid-migration leaves the old manifest in
  place and the migration is retried.
- **Idempotent steps.** Each `n -> n+1` step can run twice without changing the
  result. A migration journal records `started`, `completed`, and `failed`.
- **Preserve unknown keys.** Unknown localStorage keys and unknown IndexedDB
  records are copied through untouched. They may belong to a newer build or to
  another feature.
- **Secrets stay encrypted.** Migration backups of key stores must not create a
  plaintext copy. Prefer new records written alongside old records and a
  pointer swap after verification.
- **One account at a time.** Account-scoped keys include the account identity;
  migration must not merge two accounts' data.
- **Rust sessions remain fail-closed.** A `SESSION_FILE_VERSION` mismatch is a
  re-handshake, not a best-effort parse. If a future Rust migration is added, it
  must use the same journal/verify/commit discipline.

### 2.4 Migration registry

Each store declares:

- `from` and `to` versions;
- a pure transform function (no network, no UI);
- a verifier (counts, required keys, checksum where meaningful);
- a rollback rule (keep old records; pointer remains old on failure).

The app ships all migrations it can still read, not only the latest one. A
user who skipped three releases must be able to move forward in order.

### 2.5 Test matrix

- current manifest: no migration, no writes;
- `1 -> 2` with representative fixtures;
- interrupted migration at every step, then resume;
- future manifest: `READONLY_SAFE_MODE`, zero writes;
- corrupt manifest: safe mode, no reset;
- unknown localStorage key preserved;
- two accounts on one install do not merge;
- migration failure leaves the old data readable;
- Rust session version mismatch forces re-handshake;
- no migration path writes plaintext secrets.

## 3. Privacy-friendly crash reporting

### 3.1 Defaults

Crash reporting is **opt-in**. Before consent, a crash may be written to a
local, bounded buffer for the current launch only, and must not be uploaded.
Telemetry and crash reporting are separate consents; this RFC does not add
product analytics.

### 3.2 Allowed fields

```text
eventId            random UUID, not derived from device or account
schemaVersion      crash event schema version
appVersion         package version
buildSha           commit SHA embedded at build time
osFamily           windows / macos / linux
arch               x86_64 / aarch64
errorCode          stable code, not free text
stackHash          hash of the normalized stack
frames             module + function + line bucket, no absolute paths
breadcrumbs        event type + count only
consentVersion     which consent text the user accepted
```

Never collect: message text, plaintext, ciphertext, keys, tokens, passwords,
peer ids, usernames, file names, full URLs, IP addresses, free-form
`error.message`, or arbitrary object dumps.

### 3.3 State machine

```text
DISABLED
  -> CONSENTED                 (explicit user action)
CONSENTED
  -> COLLECTING                (crash occurs)
COLLECTING
  -> REDACTING
REDACTING
  -> QUEUED                    (allowlist passes)
  -> DROPPED                   (unexpected field or canary found)
QUEUED
  -> UPLOADING                 (online, consent still valid)
UPLOADING
  -> UPLOADED
  -> QUEUED                    (retry with backoff)
```

Rules:

- The crash handler must never throw. Any failure in collection, redaction, or
  upload is swallowed locally.
- Queue cap: 20 events, 7 days, oldest dropped first.
- Crash-loop guard: at most 3 uploads per launch and no upload during boot
  before consent is loaded.
- A user can inspect, export, and delete queued events.
- Turning consent off clears the queue and stops collection immediately.
- Upload is best-effort; offline events remain local and expire.
- The server endpoint and retention policy are out of scope for this RFC; the
  client must work with no endpoint configured.

### 3.4 Redaction

The redactor is allowlist-first: build a new object from the allowed fields; do
not attempt to scrub an arbitrary error object. In addition:

- normalize stack frames to module-relative names;
- replace line numbers with coarse buckets if needed;
- hash the stack and keep the hash only;
- truncate every string to a fixed maximum;
- reject any event containing a canary token planted by tests.

### 3.5 Test obligations

- Plant fake tokens, message text, peer ids, and file paths in an error object;
  none may appear in the serialized event.
- Disable consent mid-queue; queue is cleared and no upload occurs.
- Crash during collection; the handler still returns and the app continues.
- Offline queue expiry; no unbounded growth.
- Future event schema; old client drops the event rather than guessing.

## 4. Implementation order after unfreeze

This RFC deliberately does not start a rewrite. The order is:

1. **Generation fencing** in the existing chat/websocket modules. It is pure
   JavaScript, reversible, and directly addresses the observed cross-conversation
   bugs.
2. **Schema manifest and migration journal** for the existing stores. Start with
   read-only probing and a no-op migration; add transforms one store at a time.
3. **Crash reporting skeleton** with consent off, local queue, and redaction
   tests. No upload endpoint is required for the first PR.

Each step is a separate PR with its own tests and a feature flag where
practical. None of them changes the wire protocol, the installer, or the
production server.

## 5. Non-goals

- A single global store rewrite or a UI thin-shell rewrite.
- Automatic updater, telemetry, percentage rollout, or remote kill switch.
- Changes to the Double Ratchet or hybrid PQ protocol.
- A server-side crash ingestion service.
- Any release, tag, installer, or production deployment during the freeze.

## 6. Open questions

1. Should `appEpoch` reset on process restart, or persist per install? This
   design resets it; persisted epochs would need a separate monotonic source.
2. Which storage domains are allowed to migrate automatically versus requiring
   an explicit user prompt?
3. Is there an approved crash endpoint and retention policy, or should the
   first implementation remain local-only?
4. What consent text and jurisdiction-specific wording are required?
5. Should message caches have a size cap and TTL independent of schema
   migration? They are plaintext and deserve their own retention policy.
