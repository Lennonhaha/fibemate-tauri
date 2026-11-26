'use strict';
// SECURITY-BOUNDARY.md §9.2 negative tests. These are expected to FAIL against
// the current adapter; each failure names the invariant that is not enforced.
const path = require('path');

const ADAPTER = path.join(__dirname, '..', 'src', 'tauri-message-crypto-adapter.js');
const DR = 'double-ratchet-x25519';

const store = new Map();
global.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
  clear: () => store.clear(),
};

function makeBridge() {
  const calls = [];
  return {
    calls,
    init() { calls.push('init'); },
    getIdentityForUser: async (u) => { calls.push('getIdentityForUser'); return 'id-' + u; },
    getIdentityPublic: async () => ({ publicKeyHex: '11'.repeat(32) }),
    x3dhInitiate: async () => { calls.push('x3dhInitiate'); return { ssId: 'ss1', ourIdentityPkHex: 'aa'.repeat(32), ourEphemeralPkHex: 'bb'.repeat(32) }; },
    x3dhRespond: async () => { calls.push('x3dhRespond'); return { ssId: 'ss2', ourIdentityPkHex: 'cc'.repeat(32), ourSignedPrekeyPkHex: 'dd'.repeat(32) }; },
    initSession: async (id) => { calls.push('initSession'); return { sessionId: 'sess-' + id, ourPublicKeyHex: 'ee'.repeat(32) }; },
    setPeerKey: async () => { calls.push('setPeerKey'); },
    sessionExists: async () => { calls.push('sessionExists'); return true; },
    getSendKey: async () => 'ff'.repeat(32),
    decrypt: async () => { calls.push('decrypt'); return 'plaintext'; },
    initiateHybridPQSession: async () => { calls.push('initiateHybridPQSession'); return { sessionId: 'hs1', enc: '11', ourPublicKeyHex: '22' }; },
    acceptHybridSession: async () => { calls.push('acceptHybridSession'); return { sessionId: 'hs2', ourPublicKeyHex: '33' }; },
  };
}

function loadAdapter(bridge) {
  delete require.cache[require.resolve(ADAPTER)];
  global.window = { RatchetBridge: bridge };
  global.window._DRAdapterInstalled = false;
  return require(ADAPTER);
}

async function fresh(bridge, seed) {
  store.clear();
  store.set('fk_uid', 'u1');
  if (seed) for (const [k, v] of Object.entries(seed)) store.set(k, JSON.stringify(v));
  const adapter = loadAdapter(bridge);
  await adapter.init();
  return adapter;
}

const assert = (c, m) => { if (!c) throw new Error(m || 'assertion failed'); };
async function assertRejects(fn, re, label) {
  try { await fn(); } catch (e) {
    const msg = (e && e.message) ? e.message : String(e);
    assert(re.test(msg), label + ': wrong error: ' + msg);
    return msg;
  }
  throw new Error(label + ': expected a rejection, call succeeded');
}

let failures = 0;
async function check(name, fn) {
  try { await fn(); console.log('PASS ' + name); }
  catch (e) { failures++; console.log('FAIL ' + name + ' - ' + e.message); }
}

const seenKey = 'fibemate_hybrid_seen_u1';
const sessionsKey = 'fibemate_rust_sessions_u1';

(async () => {
  await check('9.2-1a v3 envelope with a foreign protocol is rejected', async () => {
    const a = await fresh(makeBridge());
    await assertRejects(() => a.decrypt('p', { version: 3, protocol: 'double-ratchet-p256', messageJson: '{}' }), /protocol/i, '9.2-1a');
  });

  await check('9.2-1b v3 envelope with no protocol string is rejected', async () => {
    const a = await fresh(makeBridge());
    await assertRejects(() => a.decrypt('p', { version: 3, messageJson: '{}' }), /protocol/i, '9.2-1b');
  });

  await check('9.2-1c exact v3 envelope is still accepted', async () => {
    const bridge = makeBridge();
    const a = await fresh(bridge, { [sessionsKey]: { p: { sessionId: 's1', identityId: 'id-u1', version: 3 } } });
    const out = await a.decrypt('p', { version: 3, protocol: DR, messageJson: '{}' });
    assert(out === 'plaintext', 'expected plaintext, got ' + out);
    assert(bridge.calls.includes('decrypt'), 'bridge.decrypt was not called');
  });

  await check('9.2-1d v3 init with a foreign protocol is rejected', async () => {
    const a = await fresh(makeBridge());
    await assertRejects(() => a.receiveSession('p', {
      type: 'x3dh_init_rust', version: 3, protocol: 'double-ratchet-p256',
      identityKey: 'aa', ephemeralKey: 'bb', drPublicKey: 'cc',
    }), /protocol/i, '9.2-1d');
  });

  await check('9.2-5 v1/v2 envelopes stay rejected', async () => {
    const a = await fresh(makeBridge());
    await assertRejects(() => a.decrypt('p', { version: 2, envelope: {} }), /Unsupported protocol version/i, '9.2-5a');
    await assertRejects(() => a.decrypt('p', { ciphertext: 'x', nonce: 'y' }), /Unsupported protocol version/i, '9.2-5b');
  });

  await check('9.2-2a a peer that never advertised hybrid can still go classical', async () => {
    const bridge = makeBridge();
    const a = await fresh(bridge);
    const out = await a.initiateSession('p', {
      identityKey: 'aa'.repeat(32), signedPreKey: 'bb'.repeat(32),
      identitySigningKey: 'cc'.repeat(32), signedPreKeySignature: 'dd'.repeat(64),
    });
    assert(out && out.initialMessage, 'no init produced');
    assert(bridge.calls.includes('x3dhInitiate'), 'classical path did not run');
  });

  await check('9.2-2b a peer already seen with hybrid cannot fall back to classical', async () => {
    const bridge = makeBridge();
    const a = await fresh(bridge, { [seenKey]: { p: true } });
    await assertRejects(() => a.initiateSession('p', {
      identityKey: 'aa'.repeat(32), signedPreKey: 'bb'.repeat(32),
      identitySigningKey: 'cc'.repeat(32), signedPreKeySignature: 'dd'.repeat(64),
    }), /downgrade|hybrid/i, '9.2-2b');
    assert(!bridge.calls.includes('x3dhInitiate'), 'classical handshake ran despite a known hybrid peer');
  });

  await check('9.2-2c a bundle without hybrid for a known hybrid peer is rejected, not downgraded', async () => {
    const bridge = makeBridge();
    const a = await fresh(bridge, { [seenKey]: { p: true } });
    await assertRejects(() => a.initiateHybridSession('p', {
      identityKey: 'aa'.repeat(32), signedPreKey: 'bb'.repeat(32),
      identitySigningKey: 'cc'.repeat(32), signedPreKeySignature: 'dd'.repeat(64),
    }), /downgrade|hybrid/i, '9.2-2c');
    assert(!bridge.calls.includes('x3dhInitiate'), 'fell back to classical X3DH');
  });

  await check('9.2-2d a stored hybrid session is not rebuilt as classical', async () => {
    const bridge = makeBridge();
    const a = await fresh(bridge, { [sessionsKey]: { p: { sessionId: 's1', identityId: 'id-u1', version: 3, hybrid: true } } });
    await assertRejects(() => a.receiveSession('p', {
      type: 'x3dh_init_rust', version: 3, protocol: DR,
      identityKey: 'aa'.repeat(32), ephemeralKey: 'bb'.repeat(32), drPublicKey: 'cc'.repeat(32),
    }), /downgrade|hybrid/i, '9.2-2d');
    assert(!bridge.calls.includes('x3dhRespond'), 'rebuilt the hybrid session as classical');
  });

  await check('9.2-3 an unknown hybrid bundle version byte fails closed', async () => {
    const bridge = makeBridge();
    const a = await fresh(bridge);
    await assertRejects(() => a.initiateHybridSession('p', { _hybridBundleHex: '03' + 'aa'.repeat(10), identityKey: 'aa'.repeat(32) }), /bundle version|unknown/i, '9.2-3');
    assert(!bridge.calls.includes('initiateHybridPQSession'), 'passed an unknown bundle byte to Rust');
  });

  console.log(failures === 0 ? 'ALL PASS (10 checks)' : 'FAILED ' + failures + '/10');
  process.exit(failures === 0 ? 0 : 1);
})();
