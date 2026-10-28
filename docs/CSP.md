# Production CSP: what the config says, and what Tauri does to it

`src-tauri/tauri.conf.json` carries the CSP as a single string. It cannot carry
comments, so the two settings that have to agree are documented here instead.

## The trap

The policy contains `style-src 'self' 'unsafe-inline'`, which reads as "inline
styles are allowed". In a production build they were not.

Tauri rewrites the policy at build time (`tauri/src/manager/mod.rs`,
`replace_csp_nonce`): it appends the hashes of the assets it injects, and a
nonce, to `style-src`. Under CSP3, **a nonce or hash in the source list makes
`'unsafe-inline'` be ignored**. So every `style="..."` attribute the app ships
was blocked, silently — no error, no visual clue beyond missing styling, and in
four cases a panel that should have started hidden appeared on first paint.

Measured on a debug production build (`tauri build --debug --no-bundle`, WebView2
`Edg/148`, page `http://tauri.localhost/main.html`), one load:

| violation | before | after |
|---|---|---|
| `style-src-attr` | 58 | 0 |
| `style-src-elem` | 7 | 0 |
| `connect-src` (`ipc.localhost`) | 1 | 0 |
| `connect-src` (`localhost:8080/8081/status`) | 4 | 4 |
| `script-src` | 0 | 0 |

## The two settings

```json
"csp": "... connect-src 'self' ipc: http://ipc.localhost ...",
"dangerousDisableAssetCspModification": ["style-src"]
```

- `connect-src ipc: http://ipc.localhost` — Tauri's IPC endpoint. Tauri's own
  documentation uses this value; without it the IPC fetch is refused (the
  `invoke` path has a fallback, so this shows up as console noise rather than a
  broken app, which is exactly why it went unnoticed).
- `dangerousDisableAssetCspModification: ["style-src"]` — stop Tauri from adding
  a nonce to `style-src`, so `'unsafe-inline'` keeps its meaning. The name is
  accurate: it disables a protection. It is scoped to `style-src` only, which is
  what keeps `script-src` nonce-protected. Allowing inline styles is a much
  smaller concession than allowing inline scripts.

If the app is ever refactored to ship no inline `style` attributes, the opt-out
can be dropped and the nonce restored. Until then, removing either half of the
pair silently breaks styling again.

## Guards

`scripts/check-csp-config.cjs` asserts the coupling (run in CI):

- `style-src` still has `'unsafe-inline'`
- Tauri is told not to rewrite `style-src`
- Tauri still rewrites `script-src` (opt-out is not `true`, not a list with
  `script-src`)
- `script-src` has neither `'unsafe-inline'` nor `'unsafe-eval'`
- `connect-src` allows `ipc:` and `http://ipc.localhost`
- `object-src`/`frame-src` are `'none'`, `base-uri` is `'self'`, `default-src`
  is `'self'`

`--self-test` runs eight mutations of the config and requires every one to turn
the gate red.

## Not covered

`modules/quantum/quantum-adapter.js` polls `http://localhost:8080/status` and
`http://localhost:8081/status`, which the policy does not allow. Whether those
endpoints are expected on a user machine is still undetermined (issue #53), so
they are deliberately left blocked: a refused poll is the correct default for an
endpoint that may not be ours.

## Verifying by hand

`tauri dev` cannot verify any of this: the policy is applied to responses on the
embedded asset protocol, and the dev server bypasses it. Use a production build
and watch `securitypolicyviolation` events from the page:

```js
document.addEventListener('securitypolicyviolation', (e) =>
  console.log(e.effectiveDirective, e.blockedURI, e.sample));
```

Register it before the page's own scripts run, or the first paint is already
past.
