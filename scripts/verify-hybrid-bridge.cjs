/**
 * Verify tauri-ratchet-bridge.js hybrid methods against a mock invoke that
 * mimics the REAL Rust hybrid_cmd responses (field names copied from
 * hybrid_cmd.rs: HybridKeygenResponse{key_id,mode,bundle},
 * HybridBeginResponse{enc,ss_id}, HybridAcceptResponse{ss_id}).
 *
 * Run: node verify-hybrid-bridge.cjs
 * Loads the actual src file (module.exports path) with a window mock that
 * provides __TAURI__.core.invoke + localStorage.
 */
'use strict';

const path = require('path');
const fs = require('fs');

// ── Minimal environment for the bridge IIFE ────────────────────
const localStorageMock = (() => {
  let store = {};
  return {
    getItem: (k) => (k in store ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: (k) => { delete store[k]; }
  };
})();

// ── Mock invoke: dispatches by command name like Tauri would ────
// keypair registry shared between begin and accept so the crypto math
// is coherent (like two apps in the Rust tests sharing key_store… but we
// only emulate the *shape*; real crypto is exercised by Rust ipc tests).
const registry = { bundles: {}, encs: {} };
let ssCounter = 0;

function makeInvoke(calls) {
  return async function invoke(cmd, args) {
    calls.push({ cmd, args: args || {} });
    switch (cmd) {
      case 'hybrid_keygen': {
        const mode = (args && args.mode) || 'hybrid';
        const keyId = 'k_' + (++ssCounter);
        const xpk = '11'.repeat(32);
        const mpk = mode === 'hybrid' ? '22'.repeat(1184) : '';
        const bundle = mode === 'hybrid' ? '02' + xpk + mpk : '01' + xpk;
        registry.bundles[keyId] = { mode, bundle };
        return { key_id: keyId, mode, bundle };
      }
      case 'hybrid_begin': {
        const peerBundleHex = args.peerBundleHex;
        if (!peerBundleHex) throw new Error('missing peerBundleHex');
        const isHybrid = peerBundleHex.startsWith('02');
        const enc = isHybrid ? '02' + '33'.repeat(32) + '44'.repeat(1088) : '01' + '33'.repeat(32);
        const ssId = 'ss_' + (++ssCounter);
        registry.encs[ssId] = { enc, isHybrid };
        return { enc, ss_id: ssId };
      }
      case 'hybrid_accept': {
        const keyId = args.keyId;
        const encHex = args.encHex;
        if (!registry.bundles[keyId]) throw new Error('Key not found: ' + keyId + '-x');
        if (!encHex) throw new Error('missing encHex');
        return { ss_id: 'ss_acc_' + (++ssCounter) };
      }
      case 'dr_init': {
        const ssId = args.ssId;
        if (!ssId) throw new Error('Shared secret not found: undefined');
        const isInitiator = !!args.isInitiator;
        // 32-byte pk hex = 64 chars exactly
        const tag = ssId.replace(/[^a-z0-9]/g, '').slice(0, 30).padEnd(30, '0');
        const pk = ((isInitiator ? 'aa' : 'bb') + tag + '00'.repeat(16)).slice(0, 64);
        return { session_id: 'sess_' + tag + '_' + (++ssCounter), our_public_key: pk };
      }
      default:
        throw new Error('unexpected cmd ' + cmd);
    }
  };
}

// ── Load bridge with window mock ───────────────────────────────
const calls = [];
const invoke = makeInvoke(calls);
const windowMock = { __TAURI__: { core: { invoke } } };
global.window = windowMock;
global.localStorage = localStorageMock;

const bridgePath = path.resolve(__dirname, 'D:/FIBEMATE/fibemate-tauri/src/tauri-ratchet-bridge.js');
const RatchetBridge = require(bridgePath);

(async () => {
  let pass = 0, fail = 0;
  const ok = (name, cond, extra) => {
    if (cond) { pass++; console.log('  PASS ' + name); }
    else { fail++; console.log('  FAIL ' + name + (extra ? ' — ' + extra : '')); }
  };

  console.log('== hybridKeygen ==');
  const kg = await RatchetBridge.hybridKeygen('hybrid');
  ok('returns keyId', typeof kg.keyId === 'string' && kg.keyId.length > 0);
  ok('mode echoed', kg.mode === 'hybrid');
  ok('bundle is hex starting 02', /^02[0-9a-f]+$/.test(kg.bundle));
  ok('invoke cmd name correct', calls.some(c => c.cmd === 'hybrid_keygen' && c.args.mode === 'hybrid'));

  console.log('== hybridBegin ==');
  const beg = await RatchetBridge.hybridBegin(kg.bundle);
  ok('returns enc', typeof beg.enc === 'string' && beg.enc.length > 0);
  ok('returns ssId', typeof beg.ssId === 'string' && beg.ssId.length > 0);
  const begCall = calls.find(c => c.cmd === 'hybrid_begin');
  ok('invoke hybrid_begin with peerBundleHex', begCall && begCall.args.peerBundleHex === kg.bundle);

  console.log('== hybridAccept ==');
  const acc = await RatchetBridge.hybridAccept(kg.keyId, beg.enc);
  ok('returns ssId', typeof acc.ssId === 'string' && acc.ssId.length > 0);
  const accCall = calls.find(c => c.cmd === 'hybrid_accept');
  ok('invoke hybrid_accept with keyId+encHex', accCall && accCall.args.keyId === kg.keyId && accCall.args.encHex === beg.enc);

  console.log('== classic mode ==');
  const kgc = await RatchetBridge.hybridKeygen('classic');
  ok('classic bundle starts 01', /^01[0-9a-f]{64}$/.test(kgc.bundle));

  console.log('== full flows (initiator + responder) ==');
  // responder prepares
  const prep = await RatchetBridge.prepareHybridSession('bob', 'hybrid');
  ok('prepare gives keyId+bundle', prep.keyId && prep.bundle && prep.mode === 'hybrid');
  // initiator runs against responder's bundle
  const init = await RatchetBridge.initiateHybridPQSession('alice-session', prep.bundle);
  ok('initiate gives sessionId', typeof init.sessionId === 'string' && init.sessionId.length > 0);
  ok('initMessage.type hybrid_init', init.initMessage && init.initMessage.type === 'hybrid_init');
  ok('initMessage carries enc', init.initMessage && init.initMessage.enc === init.enc);
  // responder accepts with the enc from initiate
  const acc2 = await RatchetBridge.acceptHybridSession('bob-session', prep.keyId, init.enc);
  ok('accept gives sessionId', typeof acc2.sessionId === 'string' && acc2.sessionId.length > 0);
  ok('accept ourPublicKeyHex', typeof acc2.ourPublicKeyHex === 'string' && acc2.ourPublicKeyHex.length === 64);

  console.log('== legacy alias hybridX3dhInitiate still works ==');
  // Needs full X3DH path — we mock minimal: it should throw only when no signing keys.
  let threw = false;
  try {
    await RatchetBridge.hybridX3dhInitiate('id', {});
  } catch (e) {
    threw = /signingPkHex/.test(e.message);
  }
  ok('deprecated alias guards missing signing key', threw);

  console.log('');
  console.log('RESULT: ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('Fatal:', e); process.exit(1); });
