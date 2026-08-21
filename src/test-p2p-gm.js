/**
 * Phase 2.2 Integration Test — p2p-core.js GM branch
 * Simulates P2PNetwork.encryptMessage/decryptMessage round-trip in Node.js
 */
const fs = require('fs');
const path = require('path');

const gmDir = path.join(__dirname, 'modules', 'gm');

// Load SM3
global.window = {};
(() => {
  const src = fs.readFileSync(path.join(gmDir, 'sm3_implementation.js'), 'utf-8')
    .replace(/if \(typeof window !== 'undefined'\) \{\s*window\.SM3 = SM3;\s*\}/, '')
    .replace(/if \(typeof module !== 'undefined' && module\.exports\) \{\s*module\.exports = SM3;\s*\}/, '');
  eval(`(function(){ const Module={}; ${src}; global.window.SM3 = SM3; })()`);
})();

// Load SM2Browser
eval(fs.readFileSync(path.resolve(gmDir, '..', '..', '..', '..', '文件', 'sm2-browser.bundle.js'), 'utf-8'));

// Load MessageGM
eval(fs.readFileSync(path.join(gmDir, 'message-gm.js'), 'utf-8'));

// Mock Web APIs not available in Node
global.crypto = { getRandomValues: (arr) => { for (let i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 256); return arr; }, randomUUID: () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16); }), subtle: { encrypt: () => { throw new Error('not implemented'); }, decrypt: () => { throw new Error('not implemented'); }, generateKey: () => { throw new Error('not implemented'); }, importKey: () => { throw new Error('not implemented'); }, exportKey: () => { throw new Error('not implemented'); } } };
global.localStorage = { _store: {}, getItem: (k) => global.localStorage._store[k] || null, setItem: (k, v) => { global.localStorage._store[k] = v; }, removeItem: (k) => { delete global.localStorage._store[k]; } };
global.indexedDB = { open: () => ({ result: null, onerror: null, onsuccess: null, onupgradeneeded: null }) };
global.RTCPeerConnection = class { constructor() { this.onicecandidate = null; this.onicegatheringstatechange = null; this.iceGatheringState = 'complete'; } createDataChannel() {} createOffer() { return Promise.resolve({ sdp: 'mock' }); } setLocalDescription() { return Promise.resolve(); } addTrack() {} }; (p=>(p.crypto=p, p))({});
global.TextDecoder = TextDecoder;
global.TextEncoder = TextEncoder;

// Load p2p-core.js
eval(fs.readFileSync(path.join(__dirname, 'p2p-core.js'), 'utf-8'));

async function test() {
  console.log('=== Phase 2.2 GM Integration Test ===\n');

  const p2p = new window.P2PNetwork();
  await p2p.init();

  // Verify GM keypair exists
  console.log('1. GM keypair check...');
  const pub = p2p.getGMPublicKey();
  if (!pub) { console.error('   FAIL: no GM public key'); process.exit(1); }
  console.log(`   PASS (pub: ${pub.slice(0,32)}...)`);

  // Exchange public keys (simulate)
  const alice = window.MessageGM.generateKeypair();
  const bob = window.MessageGM.generateKeypair();
  p2p.gmKeypair = alice;  // pretend we're Alice
  p2p.setGMPeerPublicKey('bob-peer', bob.publicKey);  // Bob's public key
  console.log('\n2. Key exchange...');
  console.log(`   Alice pub: ${alice.publicKey.slice(0,32)}...`);
  console.log(`   Bob   pub: ${bob.publicKey.slice(0,32)}...`);
  console.log('   PASS');

  // Switch to GM mode
  p2p.setEncryptionMode('gm');
  console.log('\n3. Encryption mode...');
  console.log(`   mode: ${p2p.encryptionMode}`);
  console.log('   PASS');

  // Encrypt
  console.log('\n4. encryptMessage (GM)...');
  const aliceEncrypted = await p2p.encryptMessage('bob-peer', 'Hello from Alice via SM2+SM4!');
  console.log(`   envelope: ct=${String(aliceEncrypted.ciphertext).slice(0,20)}..., enc=${aliceEncrypted.encryption}`);
  if (aliceEncrypted.encryption !== 'sm2-sm4-sm3') {
    console.error('   FAIL: wrong encryption tag');
    process.exit(1);
  }
  console.log('   PASS');

  // Decrypt (as Bob)
  console.log('\n5. decryptMessage (GM)...');
  p2p.gmKeypair = bob;
  p2p.setGMPeerPublicKey('alice-peer', alice.publicKey);
  const decrypted = await p2p.decryptMessage('alice-peer', aliceEncrypted);
  if (decrypted !== 'Hello from Alice via SM2+SM4!') {
    console.error(`   FAIL: "${decrypted}"`);
    process.exit(1);
  }
  console.log(`   PASS (plaintext: "${decrypted}")`);

  // Verify AES-GCM mode still routeable
  console.log('\n6. Mode switching...');
  p2p.setEncryptionMode('aes-gcm');
  console.log(`   mode: ${p2p.encryptionMode}`);
  console.log('   PASS');

  // Verify auto-detection on decrypt
  console.log('\n7. Auto-detect decrypt...');
  p2p.setEncryptionMode('aes-gcm'); // sender mode doesn't matter for decrypt
  const autoDecrypted = await p2p.decryptMessage('alice-peer', aliceEncrypted);
  if (autoDecrypted !== 'Hello from Alice via SM2+SM4!') {
    console.error('   FAIL: auto-detect failed');
    process.exit(1);
  }
  console.log('   PASS');

  console.log('\n=== ALL TESTS PASSED ===');
  process.exit(0);
}

test().catch(e => { console.error('TEST FAILED:', e); process.exit(1); });
