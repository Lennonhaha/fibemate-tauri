/**
 * Phase 2.3 协议测试 — 握手协商 + 能力广播 + 加密字段
 */
const fs = require('fs');
const path = require('path');

// === Mock 环境 (同 Phase 2.2) ===
global.window = {};
(() => {
  const src = fs.readFileSync(path.join(__dirname, 'modules', 'gm', 'sm3_implementation.js'), 'utf-8')
    .replace(/if \(typeof window !== 'undefined'\) \{\s*window\.SM3 = SM3;\s*\}/, '')
    .replace(/if \(typeof module !== 'undefined' && module\.exports\) \{\s*module\.exports = SM3;\s*\}/, '');
  eval(`(function(){ const Module={}; ${src}; global.window.SM3 = SM3; })()`);
})();
eval(fs.readFileSync(path.resolve(__dirname, '..', '..', '文件', 'sm2-browser.bundle.js'), 'utf-8'));
eval(fs.readFileSync(path.join(__dirname, 'modules', 'gm', 'message-gm.js'), 'utf-8'));

global.crypto = { getRandomValues: (arr) => { for (let i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 256); return arr; }, randomUUID: () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16); }), subtle: { encrypt: () => { throw new Error('not implemented'); }, decrypt: () => { throw new Error('not implemented'); }, generateKey: () => { throw new Error('not implemented'); }, importKey: () => { throw new Error('not implemented'); }, exportKey: () => { throw new Error('not implemented'); } } };
global.localStorage = { _store: {}, getItem: (k) => global.localStorage._store[k] || null, setItem: (k, v) => { global.localStorage._store[k] = v; }, removeItem: (k) => { delete global.localStorage._store[k]; } };
global.indexedDB = { open: () => { const db = { transaction: () => { const done = { then: (fn) => fn() }; return { objectStore: () => ({ put: (msg) => { let r = { onsuccess: null, get onerror() { return null; } }; setTimeout(() => { if (r.onsuccess) r.onsuccess(); }, 0); return r; }, get: () => ({ onsuccess: null }), index: () => ({ openCursor: () => ({ onsuccess: null }) }) }), get done() { return done; } }; } }; const r = { result: db, onerror: null, onsuccess: null, onupgradeneeded: null }; return r; } };
global.RTCPeerConnection = class { constructor() { this.onicecandidate = null; this.onicegatheringstatechange = null; this.iceGatheringState = 'complete'; } createDataChannel(name) { const dc = new MockDataChannel(name); this._dc = dc; return dc; } createOffer() { return Promise.resolve({ sdp: 'mock' }); } setLocalDescription() { return Promise.resolve(); } addTrack() {} };
global.TextDecoder = TextDecoder;
global.TextEncoder = TextEncoder;

// Mock DataChannel (双向握手)
class MockDataChannel {
  constructor(name) { this._name = name; this.readyState = 'connecting'; this._peer = null; }
  pair(other) { this._peer = other; other._peer = this; }
  send(data) {
    if (this._peer && this._peer.onmessage) {
      // 模拟异步
      setTimeout(() => this._peer.onmessage({ data }), 1);
    }
  }
  open() { this.readyState = 'open'; if (this.onopen) this.onopen(); }
}

// intercept RTCPeerConnection.createDataChannel to wire bidirectional
const origRTCPC = global.RTCPeerConnection;
global.RTCPeerConnection = class extends origRTCPC {
  constructor(cfg) { super(cfg); this._cfg = cfg; }
};

// Load p2p-core
eval(fs.readFileSync(path.join(__dirname, 'p2p-core.js'), 'utf-8'));

async function test() {
  console.log('=== Phase 2.3 Protocol Test ===\n');

  // --- Test 1: Protocol constants ---
  console.log('1. Protocol constants...');
  const net = new window.P2PNetwork();
  if (net.encryptionMode !== 'aes-gcm') { console.error('   FAIL: default mode'); process.exit(1); }
  if (!net.peerCapabilities || !(net.peerCapabilities instanceof Map)) { console.error('   FAIL: peerCapabilities'); process.exit(1); }
  console.log('   PASS');

  // --- Test 2: Handshake format ---
  console.log('2. Handshake message format...');
  net.gmKeypair = window.MessageGM.generateKeypair();
  const handshake = {
    type: 'handshake',
    protocol: 2,
    encryptions: ['aes-gcm', 'sm2-sm4-sm3'],
    gmPublicKey: net.getGMPublicKey()
  };
  if (handshake.type !== 'handshake') { console.error('   FAIL: type'); process.exit(1); }
  if (!handshake.gmPublicKey || handshake.gmPublicKey.length < 64) { console.error('   FAIL: gmPublicKey'); process.exit(1); }
  console.log(`   PASS (pub: ${handshake.gmPublicKey.slice(0,32)}...)`);

  // --- Test 3: handleHandshake → peerCapabilities ---
  console.log('3. handleHandshake...');
  const peerId = 'test-peer-1';
  net.handleHandshake(peerId, handshake);
  const caps = net.peerCapabilities.get(peerId);
  if (!caps) { console.error('   FAIL: no capabilities stored'); process.exit(1); }
  if (caps.protocolVersion !== 2) { console.error('   FAIL: protocolVersion'); process.exit(1); }
  if (!caps.encryptions.includes('sm2-sm4-sm3')) { console.error('   FAIL: encryptions'); process.exit(1); }
  // Verify GM key auto-stored
  const storedKey = net.getGMPeerPublicKey(peerId);
  if (storedKey !== handshake.gmPublicKey) { console.error('   FAIL: gmPublicKey not stored'); process.exit(1); }
  console.log('   PASS');

  // --- Test 4: peerSupportsEncryption ---
  console.log('4. peerSupportsEncryption...');
  if (!net.peerSupportsEncryption(peerId, 'sm2-sm4-sm3')) { console.error('   FAIL: should support GM'); process.exit(1); }
  if (!net.peerSupportsEncryption(peerId, 'aes-gcm')) { console.error('   FAIL: should support AES'); process.exit(1); }
  if (net.peerSupportsEncryption(peerId, 'chacha20')) { console.error('   FAIL: should not support chacha20'); process.exit(1); }
  // Unknown peer → only AES
  if (net.peerSupportsEncryption('ghost', 'sm2-sm4-sm3')) { console.error('   FAIL: ghost should not support GM'); process.exit(1); }
  if (!net.peerSupportsEncryption('ghost', 'aes-gcm')) { console.error('   FAIL: ghost should support AES'); process.exit(1); }
  console.log('   PASS');

  // --- Test 5: negotiateEncryption ---
  console.log('5. negotiateEncryption...');
  if (net.negotiateEncryption(peerId, 'sm2-sm4-sm3') !== 'sm2-sm4-sm3') { console.error('   FAIL: should negotiate GM'); process.exit(1); }
  if (net.negotiateEncryption(peerId, 'aes-gcm') !== 'aes-gcm') { console.error('   FAIL: should negotiate AES'); process.exit(1); }
  // Unknown peer → AES fallback
  if (net.negotiateEncryption('ghost', 'sm2-sm4-sm3') !== 'aes-gcm') { console.error('   FAIL: ghost should fallback to AES'); process.exit(1); }
  console.log('   PASS');

  // --- Test 6: Message envelope with protocol + encryption ---
  console.log('6. Message envelope...');
  const alice = window.MessageGM.generateKeypair();
  const bob = window.MessageGM.generateKeypair();
  const aliceNet = new window.P2PNetwork();
  aliceNet.gmKeypair = alice;
  aliceNet.setGMPeerPublicKey('bob', bob.publicKey);
  aliceNet.encryptionMode = 'sm2-sm4-sm3';
  const envelope = await aliceNet.encryptMessage('bob', 'Test GM message');
  if (envelope.encryption !== 'sm2-sm4-sm3') { console.error('   FAIL: encryption tag'); process.exit(1); }
  const bobNet = new window.P2PNetwork();
  bobNet.gmKeypair = bob;
  bobNet.setGMPeerPublicKey('alice', alice.publicKey);
  const decrypted = await bobNet.decryptMessage('alice', envelope);
  if (decrypted !== 'Test GM message') { console.error('   FAIL: decrypt'); process.exit(1); }
  console.log('   PASS');

  // --- Test 7: handleChatMessage with encryption field ---
  console.log('7. handleChatMessage encryption field...');
  console.log('7. handleChatMessage encryption field...');
  // Override store to skip IDB dependency
  bobNet.store.saveMessage = async () => {};
  bobNet.store.updateMessageStatus = async () => {};
  bobNet.handleHandshake('alice', { type:'handshake', protocol:2, encryptions:['aes-gcm','sm2-sm4-sm3'], gmPublicKey: alice.publicKey });
  let notif = null;
  bobNet.onMessage(h => { if (h.type === 'new_message') notif = h; });
  await bobNet.handleChatMessage('alice', {
    type: 'chat',
    protocol: 2,
    id: 'msg-1',
    from: 'alice',
    encrypted: envelope,
    timestamp: Date.now()
  });
  if (!notif) { console.error('   FAIL: no notification'); process.exit(1); }
  if (notif.encryption !== 'sm2-sm4-sm3') { console.error(`   FAIL: encryption field = ${notif.encryption}`); process.exit(1); }
  if (notif.content !== 'Test GM message') { console.error('   FAIL: content mismatch'); process.exit(1); }
  console.log('   PASS');

  // --- Test 8: setEncryptionMode validation ---
  console.log('8. setEncryptionMode validation...');
  aliceNet.setEncryptionMode('aes-gcm');
  if (aliceNet.encryptionMode !== 'aes-gcm') { console.error('   FAIL: mode not set'); process.exit(1); }
  aliceNet.setEncryptionMode('sm2-sm4-sm3');
  if (aliceNet.encryptionMode !== 'sm2-sm4-sm3') { console.error('   FAIL: GM mode not set'); process.exit(1); }
  let threw = false;
  try { aliceNet.setEncryptionMode('bad-mode'); } catch (e) { threw = true; }
  if (!threw) { console.error('   FAIL: should reject invalid mode'); process.exit(1); }
  console.log('   PASS');

  console.log('\n=== ALL TESTS PASSED (8/8) ===');
  console.log('Phase 2.3 Protocol: handshake / capabilities / negotiation / envelope — verified');
  process.exit(0);
}

test().catch(e => { console.error('TEST FAILED:', e.message); process.exit(1); });
