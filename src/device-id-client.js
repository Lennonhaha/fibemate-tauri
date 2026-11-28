// SPDX-License-Identifier: GPL-3.0-only
/**
 * Per-account device identity for the desktop client.
 *
 * The server binds a UUID to exactly one account and rejects an id owned by
 * someone else. The id must survive reloads/logout, and two accounts on the
 * same machine must not share one. Hence the key is per lower-cased username,
 * with a mirror in fk_device_id for the main page's legacy device-registration
 * code.
 *
 * Browser: window.FIBEMATE_DEVICE_ID
 * Node:    module.exports (used by scripts/verify-device-id.cjs)
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.FIBEMATE_DEVICE_ID = api;
})(typeof window !== 'undefined' ? window : null, function () {
  'use strict';

  const DEVICE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const PREFIX = 'fk_device_id:';

  function storageOf(storage) {
    if (storage) return storage;
    return typeof localStorage !== 'undefined' ? localStorage : null;
  }

  function keyFor(username) {
    return PREFIX + String(username || '').trim().toLowerCase();
  }

  function normalizeUsername(username) {
    return String(username || '').trim().toLowerCase();
  }

  function isValid(id) {
    return typeof id === 'string' && DEVICE_ID_RE.test(id.trim().toLowerCase());
  }

  function generate() {
    const c = typeof crypto !== 'undefined' ? crypto : null;
    if (c && typeof c.randomUUID === 'function') return c.randomUUID().toLowerCase();
    if (c && typeof c.getRandomValues === 'function') {
      const b = new Uint8Array(16);
      c.getRandomValues(b);
      b[6] = (b[6] & 0x0f) | 0x40;
      b[8] = (b[8] & 0x3f) | 0x80;
      const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
      return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    }
    throw new Error('secure RNG unavailable');
  }

  /** Read a valid id, adopting a valid legacy fk_device_id once. */
  function read(username, storage) {
    const s = storageOf(storage);
    if (!s) return '';
    const key = keyFor(username);
    const own = s.getItem(key);
    if (isValid(own)) return own.trim().toLowerCase();
    const legacy = s.getItem('fk_device_id');
    const owner = s.getItem('fk_device_id_owner');
    // Adopt the main page's id only when it is unowned (legacy) or belongs to
    // this account. Otherwise two accounts on one machine share one id and the
    // second login would (correctly) be rejected as E_DEVICE_OWNED.
    if (isValid(legacy) && (!owner || owner === normalizeUsername(username))) {
      const value = legacy.trim().toLowerCase();
      s.setItem(key, value);
      s.setItem('fk_device_id_owner', normalizeUsername(username));
      return value;
    }
    return '';
  }

  /** Store only valid ids; returns the normalised value or ''. */
  function remember(username, id, storage) {
    const s = storageOf(storage);
    if (!s || !isValid(id)) return '';
    const value = id.trim().toLowerCase();
    s.setItem(keyFor(username), value);
    s.setItem('fk_device_id', value);
    s.setItem('fk_device_id_owner', normalizeUsername(username));
    return value;
  }

  function getOrCreate(username, storage) {
    const s = storageOf(storage);
    const existing = read(username, s);
    if (existing) return existing;
    return remember(username, generate(), s);
  }

  function reset(username, storage) {
    return remember(username, generate(), storage);
  }

  // ---------------------------------------------------------------------
  // Durable copy (fixes fibemate-tauri#127)
  //
  // localStorage lives inside the WebView2 profile and dies with it, so a
  // reinstall used to mint a brand new device id and the server grew one more
  // device row per install. The Rust side keeps the same mapping in the app
  // data dir (device_identities.json), next to the encrypted key store, which
  // survives uninstall/reinstall. Order of truth: localStorage -> Rust -> new.
  // ---------------------------------------------------------------------

  function invokeFn() {
    const t = typeof window !== 'undefined' ? window : null;
    if (!t) return null;
    if (t.__TAURI__ && t.__TAURI__.core && typeof t.__TAURI__.core.invoke === 'function') {
      return t.__TAURI__.core.invoke.bind(t.__TAURI__.core);
    }
    if (t.__TAURI_INTERNALS__ && typeof t.__TAURI_INTERNALS__.invoke === 'function') {
      return t.__TAURI_INTERNALS__.invoke.bind(t.__TAURI_INTERNALS__);
    }
    return null;
  }

  /** Persist the id on disk. Best effort: a failure only costs a new row later. */
  function persist(username, id, storage) {
    const remember = rememberSafely(username, id, storage);
    const invoke = invokeFn();
    if (!invoke || !remember) return Promise.resolve(false);
    return invoke('device_identity_remember', { account: normalizeUsername(username), deviceId: remember })
      .then(() => true)
      .catch((e) => {
        if (typeof console !== 'undefined') console.warn('[device-id] could not persist identity:', e && e.message ? e.message : e);
        return false;
      });
  }

  function rememberSafely(username, id, storage) {
    // remember() is the local mirror only; keep this name distinct so the
    // durable write stays explicit at every call site.
    return remember(username, id, storage);
  }

  /**
   * Restore ids that the WebView2 profile lost. Runs on load, and is safe to
   * call again. Returns the number of accounts recovered.
   */
  function hydrate(storage) {
    const s = storageOf(storage);
    const invoke = invokeFn();
    if (!s || !invoke) return Promise.resolve(0);
    return invoke('device_identity_all')
      .then((map) => {
        if (!map || typeof map !== 'object') return 0;
        let restored = 0;
        Object.keys(map).forEach((account) => {
          const id = map[account];
          if (!isValid(id)) return;
          const had = read(account, s);
          if (had) return;
          remember(account, id, s);
          restored += 1;
        });
        return restored;
      })
      .catch((e) => {
        if (typeof console !== 'undefined') console.warn('[device-id] hydrate failed:', e && e.message ? e.message : e);
        return 0;
      });
  }

  function getOrCreatePersistent(username, storage) {
    const s = storageOf(storage);
    const existing = read(username, s);
    if (existing) {
      persist(username, existing, s);
      return existing;
    }
    const fresh = remember(username, generate(), s);
    if (fresh && typeof console !== 'undefined') {
      console.info('[device-id] minted a new id for', normalizeUsername(username), '(no stored or persisted id)');
    }
    persist(username, fresh, s);
    return fresh;
  }

  return {
    DEVICE_ID_RE,
    keyFor,
    isValid,
    generate,
    read,
    remember,
    getOrCreate,
    reset,
    persist,
    hydrate,
    getOrCreatePersistent,
  };
});

// Recover the ids the WebView2 profile may have dropped, as early as possible.
(function autoHydrate() {
  if (typeof window === 'undefined' || typeof document === 'undefined') return;
  if (!window.FIBEMATE_DEVICE_ID) return;
  const run = () => {
    window.FIBEMATE_DEVICE_ID.hydrate().then((n) => {
      if (n > 0 && typeof console !== 'undefined') console.info('[device-id] restored', n, 'device id(s) from disk');
    });
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run, { once: true });
  } else {
    run();
  }
})();
