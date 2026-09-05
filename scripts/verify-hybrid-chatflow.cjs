/**
 * Verify the hybrid PQ chat-flow integration chain end-to-end with mocks.
 *
 *   §1 main.js upload body carries hybridKeyId/hybridBundleHex/hybridMode
 *   §2 server update-keys stores + get-keys returns hybrid fields
 *   §3 chat.js/voice-message.js bundle passes hybrid fields & picks PQ path
 *   §4 adapter.receiveSession routes hybrid_init_rust -> receiveHybridSession
 *      (order: hybrid_init BEFORE generic version===3 fallthrough)
 *   §5 behavioral: Bob receiving hybrid_init_rust invokes rust hybrid_accept
 *      + dr_init + set_peer_key and answers hybrid_accept_rust
 *
 * Run: node verify-hybrid-chatflow.cjs
 */
'use strict';

const path = require('path');
const fs = require('fs');

const localStorageMock = (() => {
  const store = {};
  return {
    getItem: (k) => (k in store ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: (k) => { delete store[k]; }
  };
})();

let pass = 0, fail = 0;
const ok = (name, cond, extra) => {
  if (cond) { pass++; console.log('  PASS ' + name); }
  else { fail++; console.log('  FAIL ' + name + (extra ? ' — ' + extra : '')); }
};

// ── §1: main.js upload body ────────────────────────────────────
console.log('== §1 main.js upload body carries hybrid advertisement ==');
const mainSrc = fs.readFileSync(path.resolve(__dirname, '../src/main.js'), 'utf8');
const uploadBlock = mainSrc.slice(mainSrc.indexOf('auth/update-keys'));
ok('body includes hybridKeyId', /hybridKeyId:\s*bundle\._hybridKeyId \|\| null/.test(uploadBlock));
ok('body includes hybridBundleHex', /hybridBundleHex:\s*bundle\._hybridBundleHex \|\| null/.test(uploadBlock));
ok('body includes hybridMode', /hybridMode:\s*bundle\._hybridMode \|\| null/.test(uploadBlock));

// ── §2: server fields ──────────────────────────────────────────
console.log('== §2 server update-keys / get-keys hybrid fields ==');
const srvSrc = fs.readFileSync(path.resolve(__dirname, '../../fibemate/src/index.js'), 'utf8');
const upBlock = srvSrc.slice(srvSrc.indexOf("app.post('/api/auth/update-keys'"));
const keysBlock = srvSrc.slice(srvSrc.indexOf("app.get('/api/users/:userId/keys'"));
ok('update-keys destructures 3 hybrid fields',
  /hybridKeyId,\s*hybridBundleHex,\s*hybridMode/.test(upBlock));
ok('update-keys stores hybridKeyId', /if \(hybridKeyId\) updates\.hybridKeyId = hybridKeyId/.test(upBlock));
ok('update-keys stores hybridBundleHex', /if \(hybridBundleHex\) updates\.hybridBundleHex = hybridBundleHex/.test(upBlock));
ok('update-keys stores hybridMode', /if \(hybridMode\) updates\.hybridMode = hybridMode/.test(upBlock));
ok('get-keys returns hybridKeyId', /hybridKeyId:\s*user\.hybridKeyId \|\| null/.test(keysBlock));
ok('get-keys returns hybridBundleHex', /hybridBundleHex:\s*user\.hybridBundleHex \|\| null/.test(keysBlock));
ok('get-keys returns hybridMode', /hybridMode:\s*user\.hybridMode \|\| null/.test(keysBlock));

// ── §3: chat.js + voice-message.js ─────────────────────────────
console.log('== §3 chat.js + voice-message.js hybrid selection ==');
const chatSrc = fs.readFileSync(path.resolve(__dirname, '../src/modules/chat.js'), 'utf8');
const voiceSrc = fs.readFileSync(path.resolve(__dirname, '../src/modules/voice-message.js'), 'utf8');
ok('chat.js maps _hybridKeyId', /_hybridKeyId:\s*keysResp\.hybridKeyId \|\| null/.test(chatSrc));
ok('chat.js maps _hybridBundleHex', /_hybridBundleHex:\s*keysResp\.hybridBundleHex \|\| null/.test(chatSrc));
ok('chat.js PQ when _hybridBundleHex', /if \(bundle\._hybridBundleHex\)/.test(chatSrc));
ok('chat.js calls initiateHybridSession', /Crypto\.initiateHybridSession\(STATE\.currentPeerId, bundle\)/.test(chatSrc));
ok('voice.js maps _hybridBundleHex', /_hybridBundleHex:\s*keysResp\.hybridBundleHex \|\| null/.test(voiceSrc));
ok('voice.js PQ when _hybridBundleHex', /if \(bundle\._hybridBundleHex\)/.test(voiceSrc));

// ── §4: adapter dispatch (the core fix) — full-file scoped check ──
console.log('== §4 adapter.receiveSession routes hybrid_init_rust ==');
const adapterSrc = fs.readFileSync(path.resolve(__dirname, '../src/tauri-message-crypto-adapter.js'), 'utf8');
const recvStart = adapterSrc.indexOf('async receiveSession(peerId, initMessage)');
const recvEnd = adapterSrc.indexOf('async _receiveAcceptRust(peerId, initMessage)');
const recvBody = adapterSrc.slice(recvStart, recvEnd);
ok('hybrid_init_rust handled in receiveSession',
  recvBody.includes("initMessage.type === 'hybrid_init_rust'"));
ok('hybrid_init check placed BEFORE generic version===3 fallthrough',
  recvBody.indexOf("initMessage.type === 'hybrid_init_rust'") < recvBody.indexOf('initMessage.version === 3'));
ok('hybrid_init dispatched to receiveHybridSession',
  /if \(initMessage\.type === 'hybrid_init_rust'\) \{\s*return this\.receiveHybridSession\(peerId, initMessage\);/.test(recvBody));
ok('accept types still routed first',
  recvBody.includes("initMessage.type === 'x3dh_accept_rust' || initMessage.type === 'hybrid_accept_rust'"));

// ── §5: behavioral — Bob side receive of hybrid_init_rust ──────
console.log('== §5 behavioral: receiveSession(hybrid_init_rust) reaches hybrid accept ==');
const invokeCalls = [];
let sawHybridAccept = false, sawDrInit = false;

const bridgeMock = {
  init() {},
  async getIdentityPublic(id) {
    return { publicKeyHex: 'a1'.repeat(32) };
  },
  async generateIdentity() {
    return { identityId: 'id_bob' };
  },
  async hybridKeygen(mode) {
    return {
      keyId: 'k_bob_1',
      mode: 'hybrid',
      bundle: '02' + 'b2'.repeat(32) + 'b3'.repeat(1184)
    };
  },
  async acceptHybridSession(peerId, keyId, encHex) {
    sawHybridAccept = true;
    invokeCalls.push('hybrid_accept');
    if (keyId !== 'k_bob_1') throw new Error('unexpected keyId ' + keyId);
    if (!/^02[0-9a-f]{2240}$/.test(encHex)) throw new Error('bad encHex len ' + encHex.length);
    // Mirrors real ratchet-bridge: hybridAccept -> dr_init(ssId, responder)
    sawDrInit = true;
    invokeCalls.push('dr_init');
    return { sessionId: 'sess_bob', ourPublicKeyHex: 'c4'.repeat(32) };
  },
  async initSession(ssId, peerId, isInitiator) {
    sawDrInit = true;
    invokeCalls.push('dr_init');
    return { sessionId: 'sess_dr_' + ssId, ourPublicKeyHex: 'c5'.repeat(32) };
  },
  async setPeerKey(sessionId, peerPkHex) {
    invokeCalls.push('set_peer_key');
    if (peerPkHex !== 'e1'.repeat(32)) throw new Error('unexpected peer pk');
    return { ok: true };
  }
};

global.window = { RatchetBridge: bridgeMock };
global.localStorage = localStorageMock;
const Adapter = require(path.resolve(__dirname, '../src/tauri-message-crypto-adapter.js'));

(async () => {
  try {
    await Adapter.init();
    const pre = await Adapter.ensureHybridPreKey('hybrid');
    ok('ensureHybridPreKey caches key', pre.keyId === 'k_bob_1' && !!pre.bundleHex);

    const hybridInit = {
      type: 'hybrid_init_rust',
      version: 3,
      protocol: 'fibemate-dr-v3',
      hybridEnc: '02' + 'd1'.repeat(32) + 'd2'.repeat(1088),
      drPublicKey: 'e1'.repeat(32),
      hybridBundleId: 'k_bob_1'
    };
    const result = await Adapter.receiveSession('alice', hybridInit);
    ok('session established', result && result.sessionEstablished === true);
    ok('flags hybridSession', result && result.hybridSession === true);
    ok('responseMessage hybrid_accept_rust', result.responseMessage && result.responseMessage.type === 'hybrid_accept_rust');
    ok('rust hybrid_accept invoked', sawHybridAccept);
    ok('rust dr_init invoked', sawDrInit);
    ok('rust set_peer_key with alice drPublicKey', invokeCalls.includes('set_peer_key'));

    console.log('');
    console.log('RESULT: ' + pass + ' passed, ' + fail + ' failed');
    process.exit(fail === 0 ? 0 : 1);
  } catch (e) {
    console.error('Fatal:', e);
    process.exit(1);
  }
})();
