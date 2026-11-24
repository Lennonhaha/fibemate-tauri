#!/usr/bin/env node
/* 3.3.14 regression: inactive real-time messages must advance the ratchet and
 * cache plaintext, otherwise switching back to that peer renders every incoming
 * message as “旧会话，无法解密”. */

const fs = require('fs');
const vm = require('vm');
const path = require('path');

const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'modules', 'websocket.js'), 'utf8');
const names = ['_lastSeenKey', '_lastSeen', '_noteLastSeen'];
const blocks = names.map((name) => {
  const re = new RegExp(`function ${name}\\([^)]*\\) \\{[\\s\\S]*?\\n\\}`);
  const m = source.match(re);
  if (!m) throw new Error(`missing ${name}`);
  return m[0];
});
const cacheMatch = source.match(/async function _cacheInactiveRealTimeMessage[\s\S]*?\n\}/);
if (!cacheMatch) throw new Error('missing _cacheInactiveRealTimeMessage');

const localStorage = {
  _data: new Map(),
  getItem(k) { return this._data.has(k) ? this._data.get(k) : null; },
  setItem(k, v) { this._data.set(k, String(v)); }
};
const calls = [];
const Crypto = {
  async decrypt(peer, wire) {
    calls.push({ peer, wire });
    if (wire && wire.fail) throw new Error('boom');
    if (wire && wire.null) return null;
    return 'plain-' + (wire && wire.body || 'none');
  }
};
const sandbox = {
  localStorage,
  console: { log() {}, warn() {}, error() {} },
  Number, JSON, String, Date, setTimeout, clearTimeout
};
vm.createContext(sandbox);
vm.runInContext(blocks.join('\n') + '\n' + cacheMatch[0], sandbox);

(async () => {
  let passed = 0;
  let failed = 0;
  const check = (name, ok) => {
    if (ok) { console.log('PASS', name); passed++; }
    else { console.log('FAIL', name); failed++; }
  };

  calls.length = 0;
  await sandbox._cacheInactiveRealTimeMessage({
    from: 'peer-a', messageId: 'm1', createdAt: 1000,
    envelope: JSON.stringify({ body: 'hello' })
  }, Crypto);
  check('S1 caches plaintext for inactive peer', localStorage.getItem('fibemate_pt_m1') === 'plain-hello');
  check('S1 advances last-seen baseline', localStorage.getItem('fibemate_lastseen_peer-a') === '1000');

  calls.length = 0;
  await sandbox._cacheInactiveRealTimeMessage({
    from: 'peer-b', messageId: 'm2', createdAt: 2000,
    envelope: JSON.stringify({ initMessage: { type: 'x3dh_init' }, message: { body: 'after-init' } })
  }, Crypto);
  check('S2 decrypts payload, not initMessage', calls.length === 1 && calls[0].wire.body === 'after-init');

  calls.length = 0;
  await sandbox._cacheInactiveRealTimeMessage({
    from: 'peer-c', messageId: 'm3', messageType: 'voice',
    envelope: JSON.stringify({ body: 'voice' })
  }, Crypto);
  check('S3 skips voice while chat is inactive', calls.length === 0 && localStorage.getItem('fibemate_pt_m3') === null);

  calls.length = 0;
  await sandbox._cacheInactiveRealTimeMessage({
    from: 'peer-d', messageId: 'm4', createdAt: 3000,
    envelope: JSON.stringify({ fail: true })
  }, Crypto);
  check('S4 decrypt failure is not cached', localStorage.getItem('fibemate_pt_m4') === null);

  calls.length = 0;
  await sandbox._cacheInactiveRealTimeMessage({
    from: 'peer-e', messageId: 'm5', createdAt: 4000,
    envelope: JSON.stringify({ null: true })
  }, Crypto);
  check('S5 duplicate/null is not cached', localStorage.getItem('fibemate_pt_m5') === null);

  console.log(`\n${passed}/${passed + failed} PASS`);
  process.exit(failed === 0 ? 0 : 1);
})().catch((err) => {
  console.error('FATAL', err && err.stack || err);
  process.exit(2);
});
