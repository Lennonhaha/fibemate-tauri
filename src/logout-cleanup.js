// SPDX-License-Identifier: GPL-3.0-only
/**
 * Logout purge for the desktop client.
 *
 * Logging out used to remove seven `fk_*` keys and nothing else, so the refresh
 * token, the contact list, the notification list, the file-vault metadata and
 * the conversation caches all survived into the next account on the same
 * machine. This module owns the exact list of what logout must remove and what
 * it must keep, and is unit-tested without a browser.
 *
 * Kept on purpose:
 *   - `fk_device_id`, `fk_device_id:*`, `fk_device_id_owner` — the per-account
 *     device identity must survive logout, otherwise every logout registers a
 *     new device and the device table grows without bound.
 *   - `fk_setting_*`, `fk_theme`, `fk_api_base` / `fk_api_url` /
 *     `fibemate_api_base`, `fk_encryption_mode` — device preferences, not
 *     account data.
 *   - `fibemate_secure_keys` (IndexedDB) — private keys encrypted with the
 *     account password by design. Another account cannot read them, and they
 *     are the only local copy, so deleting them would destroy history.
 *   - `p2p_gm_keypair` / `fibemate_gm_key_id` — device-level GM identity, not a
 *     per-account cache.
 *
 * Browser: window.FIBEMATE_LOGOUT
 * Node:    module.exports (used by scripts/test-logout-cleanup.cjs)
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.FIBEMATE_LOGOUT = api;
})(typeof window !== 'undefined' ? window : null, function () {
  'use strict';

  // Credentials, identity and account-scoped business caches.
  const SESSION_KEYS = [
    'fk_token',
    'fk_refresh_token',
    'fk_uid',
    'fk_uname',
    'fk_user_level',
    'fk_displayName',
    'fk_public_key',
    'fk_privkey_jwk',
    'fk_pubkey_hex',
    'fk_zk_secrets',
    'fk_key_version',
    'fk_contacts',
    'fk_contactGroups',
    'fk_callHistory',
    'fk_call_history',
    'fk_notifications',
    'fk_vault',
    'fibemate_token',
    'fibemate_contacts'
  ];

  // Per-account caches written with a dynamic suffix:
  //   fibemate_df_<id>              decrypted message cache
  //   fibemate_pt_<id>              plaintext cache
  //   fibemate_rust_identity_id_<u> Rust keystore identity mapping
  const SESSION_PREFIXES = [
    'fibemate_df_',
    'fibemate_pt_',
    'fibemate_rust_identity_id_'
  ];

  const IDB_NAMES = ['fibemate_vault'];

  function isSessionKey(key) {
    if (SESSION_KEYS.indexOf(key) !== -1) return true;
    return SESSION_PREFIXES.some((p) => key.indexOf(p) === 0);
  }

  /**
   * Remove account-scoped keys from a Storage-like object.
   * Returns the removed keys, sorted, so callers can log or assert on them.
   */
  function purgeLocal(storage) {
    if (!storage || typeof storage.key !== 'function') return [];
    const doomed = [];
    for (let i = 0; i < storage.length; i += 1) {
      const key = storage.key(i);
      if (key && isSessionKey(key)) doomed.push(key);
    }
    // Collect first: removing while iterating shifts the index.
    doomed.forEach((k) => storage.removeItem(k));
    return doomed.sort();
  }

  /**
   * Delete the file-vault database (metadata alone would leave orphaned blobs).
   * Never rejects and never blocks logout for more than `timeoutMs`.
   */
  function purgeIndexedDB(idb, timeoutMs) {
    const wait = typeof timeoutMs === 'number' ? timeoutMs : 1500;
    if (!idb || typeof idb.deleteDatabase !== 'function') return Promise.resolve([]);
    const deleted = [];
    const tasks = IDB_NAMES.map((name) => new Promise((resolve) => {
      let settled = false;
      const finish = (ok) => {
        if (settled) return;
        settled = true;
        if (ok) deleted.push(name);
        resolve();
      };
      try {
        const req = idb.deleteDatabase(name);
        req.onsuccess = () => finish(true);
        req.onerror = () => finish(false);
        req.onblocked = () => finish(false);
      } catch (_) {
        finish(false);
      }
      setTimeout(() => finish(false), wait);
    }));
    return Promise.all(tasks).then(() => deleted.sort());
  }

  return { SESSION_KEYS, SESSION_PREFIXES, IDB_NAMES, isSessionKey, purgeLocal, purgeIndexedDB };
});
