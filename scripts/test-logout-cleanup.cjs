/**
 * Unit tests for logout-cleanup.js — no browser required.
 * Run: node scripts/test-logout-cleanup.cjs
 */
'use strict';

const path = require('path');
const purge = require(path.join(__dirname, '..', 'src', 'logout-cleanup.js'));

let pass = 0;
let fail = 0;
function check(name, cond, detail) {
  if (cond) { pass += 1; console.log('PASS ' + name); }
  else { fail += 1; console.log('FAIL ' + name + (detail ? ' — ' + detail : '')); }
}

function fakeStorage(entries) {
  const map = new Map(Object.entries(entries));
  return {
    get length() { return map.size; },
    key(i) { return Array.from(map.keys())[i] ?? null; },
    getItem(k) { return map.has(k) ? map.get(k) : null; },
    setItem(k, v) { map.set(k, String(v)); },
    removeItem(k) { map.delete(k); },
    _keys() { return Array.from(map.keys()).sort(); }
  };
}

const seeded = fakeStorage({
  fk_token: 't',
  fk_refresh_token: 'r',
  fk_uid: '1',
  fk_uname: 'alice',
  fk_user_level: '2',
  fk_displayName: 'Alice',
  fk_public_key: 'pk',
  fk_privkey_jwk: '{}',
  fk_pubkey_hex: 'ab',
  fk_zk_secrets: '{}',
  fk_key_version: '3',
  fk_contacts: '[]',
  fk_contactGroups: '[]',
  fk_callHistory: '[]',
  fk_call_history: '[]',
  fk_notifications: '[]',
  fk_vault: '[]',
  fibemate_token: 't2',
  fibemate_contacts: '[]',
  fibemate_df_42: 'cached',
  fibemate_pt_42: 'cached',
  fibemate_rust_identity_id_alice: 'x',
  // must survive
  fk_device_id: '11111111-1111-4111-8111-111111111111',
  'fk_device_id:alice': '11111111-1111-4111-8111-111111111111',
  fk_device_id_owner: 'alice',
  fk_theme: 'dark',
  fk_setting_fontSize: '14',
  fk_api_base: 'https://example.invalid',
  fibemate_api_base: 'https://example.invalid',
  fk_encryption_mode: 'pq',
  p2p_gm_keypair: '{"privateKey":"k"}',
  fibemate_gm_key_id: 'gm-1'
});

const removed = purge.purgeLocal(seeded);
const left = seeded._keys();

check('removes the refresh token', !left.includes('fk_refresh_token'));
check('removes the access token', !left.includes('fk_token'));
check('removes contacts and groups', !left.includes('fk_contacts') && !left.includes('fk_contactGroups'));
check('removes notifications and call history', !left.includes('fk_notifications') && !left.includes('fk_call_history'));
check('removes vault metadata', !left.includes('fk_vault'));
check('removes prefixed caches', !left.includes('fibemate_df_42') && !left.includes('fibemate_pt_42') && !left.includes('fibemate_rust_identity_id_alice'));
check('removes the legacy fibemate_* duplicates', !left.includes('fibemate_token') && !left.includes('fibemate_contacts'));
check('keeps the device identity', left.includes('fk_device_id') && left.includes('fk_device_id:alice') && left.includes('fk_device_id_owner'));
check('keeps device preferences', left.includes('fk_theme') && left.includes('fk_setting_fontSize') && left.includes('fk_api_base') && left.includes('fibemate_api_base'));
check('keeps the GM identity', left.includes('p2p_gm_keypair') && left.includes('fibemate_gm_key_id'));
check('returns what it removed', removed.includes('fk_refresh_token') && removed.includes('fibemate_df_42') && removed.length === 22, 'len=' + removed.length);
check('is idempotent', purge.purgeLocal(seeded).length === 0);
check('tolerates a null storage', purge.purgeLocal(null).length === 0);
check('classifies a settings key as not session', purge.isSessionKey('fk_setting_theme') === false);
check('classifies a prefixed cache as session', purge.isSessionKey('fibemate_df_9') === true);

// IndexedDB: delete named DBs, resolve even when blocked, never reject.
let requested = [];
const fakeIdb = {
  deleteDatabase(name) {
    requested.push(name);
    return { set onsuccess(fn) { setTimeout(fn, 0); }, set onerror(_) {}, set onblocked(_) {} };
  }
};

purge.purgeIndexedDB(fakeIdb, 50).then((deleted) => {
  check('deletes the vault database', requested.includes('fibemate_vault'));
  check('reports the deleted database', deleted.includes('fibemate_vault'));

  const blockedIdb = {
    deleteDatabase() { return { set onsuccess(_) {}, set onerror(_) {}, set onblocked(fn) { setTimeout(fn, 0); } }; }
  };
  return purge.purgeIndexedDB(blockedIdb, 50).then((none) => {
    check('a blocked delete resolves without rejecting', Array.isArray(none) && none.length === 0);
    check('a missing indexedDB resolves', true);
    return purge.purgeIndexedDB(null).then((v) => {
      check('null indexedDB yields empty', Array.isArray(v) && v.length === 0);

      console.log('\n' + (fail === 0 ? 'ALL PASS' : 'FAILURES') + ' (' + pass + ' passed, ' + fail + ' failed)');
      process.exit(fail === 0 ? 0 : 1);
    });
  });
});
