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

  return { DEVICE_ID_RE, keyFor, isValid, generate, read, remember, getOrCreate, reset };
});
