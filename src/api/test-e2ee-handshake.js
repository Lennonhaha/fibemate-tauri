/**
 * FIBEMATE E2EE Handshake End-to-End Test (Node.js Simulation)
 * 
 * ⚠️  IMPORTANT: This test uses Node.js crypto module for simulation.
 *     It does NOT use the real browser WebCrypto API (message-crypto-v2.js).
 *     Results may differ from production behavior.
 * 
 * For real browser testing, use: test-e2ee-playwright.js
 * 
 * Validates the complete X3DH → Double Ratchet → encrypt → decrypt flow
 * between two simulated clients (Alice and Bob) through the mock server.
 * 
 * Usage: node test-e2ee-handshake.js
 * 
 * Prerequisites: mock-server.js running on http://localhost:3002
 * 
 * Test Flow:
 *   1. Alice & Bob generate identity keys
 *   2. Bob uploads pre-key bundle to server
 *   3. Alice fetches Bob's bundle from server
 *   4. Alice initiates X3DH session (4-DH)
 *   5. Alice sends X3DH init message to server
 *   6. Bob receives X3DH init from server
 *   7. Bob establishes session (4-DH, should derive same root key)
 *   8. Alice encrypts message → sends opaque envelope via server
 *   9. Bob decrypts → verify plaintext matches
 *  10. Bob encrypts reply → sends to server
 *  11. Alice decrypts reply → verify
 *  12. Test out-of-order messages (ratchet handles skipped keys)
 */

const http = require('http');

const MOCK_SERVER = 'http://localhost:3002';
const TEST_TOKEN = 'Bearer test-e2ee-token-001';

// ============================================================
// Minimal HTTP client for mock server interaction
// ============================================================
async function apiRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, MOCK_SERVER);
    const options = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': TEST_TOKEN
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode >= 400) {
            reject(new Error(`HTTP ${res.statusCode}: ${JSON.stringify(parsed)}`));
          } else {
            resolve(parsed);
          }
        } catch (e) {
          reject(new Error(`Parse error: ${data}`));
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ============================================================
// Crypto primitives (SIMULATION — uses Node.js crypto)
// NOT the real browser WebCrypto API used in production
// Known differences from message-crypto-v2.js:
//   - Node crypto.generateKeyPairSync vs browser subtle.generateKey
//   - No subtle.exportKey limitations (can export private keys)
//   - HKDF implementation may differ from WebCrypto subtle.deriveBits
// ============================================================
const crypto = require('crypto');

async function generateDH() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
  return { publicKey, privateKey };
}

async function dh(privateKeyDer, publicKeyDer) {
  const privKey = crypto.createPrivateKey({
    key: privateKeyDer, format: 'der', type: 'pkcs8'
  });
  const pubKey = crypto.createPublicKey({
    key: publicKeyDer, format: 'der', type: 'spki'
  });
  const shared = crypto.diffieHellman({
    privateKey: privKey, publicKey: pubKey
  });
  return shared;
}

async function hkdf(ikm, salt, info) {
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  const infoBytes = Buffer.concat([
    Buffer.from(info, 'utf-8'),
    Buffer.from([0x01])
  ]);
  const okm = crypto.createHmac('sha256', prk).update(infoBytes).digest();
  return okm;
}

function aesGcmEncrypt(key, iv, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([encrypted, tag]);
}

function aesGcmDecrypt(key, iv, ciphertext) {
  const tagOffset = ciphertext.length - 16;
  const ct = ciphertext.slice(0, tagOffset);
  const tag = ciphertext.slice(tagOffset);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// ============================================================
// Simplified Double Ratchet State (for testing only)
// ============================================================
class RatchetState {
  constructor() {
    this.rootKey = null;
    this.sendingChainKey = null;
    this.receivingChainKey = null;
    this.selfDH = null;
    this.peerDHPublic = null;
    this.sendMessageNumber = 0;
    this.recvMessageNumber = 0;
    this.previousSelfDH = null;  // for previous sending chain
    this.previousMessageNumber = 0;
    this.skippedKeys = new Map();
  }
}

async function ratchetInitInitiator(rootKey, peerDHPublicDer) {
  const state = new RatchetState();
  state.rootKey = rootKey;
  state.peerDHPublic = peerDHPublicDer;
  // Perform DH ratchet step: generate new self DH, compute DH with peer
  state.selfDH = await generateDH();
  const dhOut = await dh(state.selfDH.privateKey, peerDHPublicDer);
  const [newRoot, chainKey] = await kdfRK(rootKey, dhOut);
  state.rootKey = newRoot;
  state.sendingChainKey = chainKey;
  return state;
}

async function ratchetInitReceiver(rootKey, selfDH) {
  const state = new RatchetState();
  state.rootKey = rootKey;
  state.selfDH = selfDH;
  return state;
}

async function kdfRK(rk, dhOutput) {
  // KDF_RK(rk, dh_output) → (new_root_key, chain_key)
  const info = Buffer.from('FIBEMateRatchetStep');
  const derived = crypto.createHmac('sha256', rk).update(dhOutput).digest();
  const newRoot = derived.slice(0, 16);
  const chainKey = derived.slice(16, 32);
  // Extend to 32 bytes each via HKDF for proper key material
  const rootKeyFull = await hkdf(newRoot, Buffer.alloc(32), 'FIBEMateRootKey');
  const chainKeyFull = await hkdf(chainKey, Buffer.alloc(32), 'FIBEMateChainKey');
  return [rootKeyFull, chainKeyFull];
}

async function kdfCK(chainKey) {
  // KDF_CK(ck) → (new_chain_key, message_key)
  const mk = crypto.createHmac('sha256', chainKey).update(Buffer.from([0x01])).digest();
  const newCK = crypto.createHmac('sha256', chainKey).update(Buffer.from([0x02])).digest();
  return [newCK, mk];
}

async function ratchetEncrypt(state, plaintext) {
  // Advance chain key
  const [newCK, messageKey] = await kdfCK(state.sendingChainKey);
  state.sendingChainKey = newCK;

  const iv = crypto.randomBytes(12);
  const ct = aesGcmEncrypt(messageKey, iv, Buffer.from(plaintext, 'utf-8'));

  const selfDHPublic = state.selfDH.publicKey;
  const header = {
    dh: Array.from(selfDHPublic),
    pn: state.previousMessageNumber,
    n: state.sendMessageNumber
  };

  state.sendMessageNumber++;
  return { header, ciphertext: Array.from(ct), iv: Array.from(iv) };
}

async function ratchetDecrypt(state, header, ciphertext, iv) {
  // Try skipped keys first
  const skipKey = `${header.n}:${header.pn || 0}`;
  if (state.skippedKeys.has(skipKey)) {
    const mk = state.skippedKeys.get(skipKey);
    state.skippedKeys.delete(skipKey);
    return aesGcmDecrypt(mk, Buffer.from(iv), Buffer.from(ciphertext)).toString('utf-8');
  }

  // If header contains new DH public key → DH ratchet step
  const headerDHBuf = Buffer.from(header.dh);
  if (!state.peerDHPublic || !headerDHBuf.equals(state.peerDHPublic)) {
    // Skip any messages in the current receiving chain
    if (state.receivingChainKey) {
      while (state.recvMessageNumber < header.pn) {
        const [newCK, mk] = await kdfCK(state.receivingChainKey);
        state.receivingChainKey = newCK;
        state.skippedKeys.set(`${state.recvMessageNumber}:${header.pn}`, mk);
        state.recvMessageNumber++;
      }
    }

    // DH ratchet step
    state.peerDHPublic = headerDHBuf;
    const dhOut1 = await dh(state.selfDH.privateKey, state.peerDHPublic);
    const [rk1, receivingChain] = await kdfRK(state.rootKey, dhOut1);
    state.rootKey = rk1;
    state.receivingChainKey = receivingChain;
    state.previousMessageNumber = state.sendMessageNumber;
    state.sendMessageNumber = 0;
    state.recvMessageNumber = 0;

    // New self DH
    state.selfDH = await generateDH();
    const dhOut2 = await dh(state.selfDH.privateKey, state.peerDHPublic);
    const [rk2, sendingChain] = await kdfRK(state.rootKey, dhOut2);
    state.rootKey = rk2;
    state.sendingChainKey = sendingChain;
  }

  // Skip messages in receiving chain
  while (state.recvMessageNumber < header.n) {
    const [newCK, mk] = await kdfCK(state.receivingChainKey);
    state.receivingChainKey = newCK;
    state.skippedKeys.set(`${state.recvMessageNumber}:${header.n}`, mk);
    state.recvMessageNumber++;
  }

  // Derive message key
  const [newCK, messageKey] = await kdfCK(state.receivingChainKey);
  state.receivingChainKey = newCK;
  state.recvMessageNumber++;

  return aesGcmDecrypt(messageKey, Buffer.from(iv), Buffer.from(ciphertext)).toString('utf-8');
}

// ============================================================
// X3DH Simulation
// ============================================================
async function x3dhAlice(aliceIK, aliceEK, bobIKPublic, bobSPKPublic, bobOPKPublic = null) {
  const dh1 = await dh(aliceIK.privateKey, bobSPKPublic);
  const dh2 = await dh(aliceEK.privateKey, bobIKPublic);
  const dh3 = await dh(aliceEK.privateKey, bobSPKPublic);
  let dh4 = Buffer.alloc(0);
  if (bobOPKPublic) {
    dh4 = await dh(aliceEK.privateKey, bobOPKPublic);
  }

  const ikm = Buffer.concat([dh1, dh2, dh3, dh4].filter(b => b.length > 0));
  const rootKey = await hkdf(ikm, Buffer.alloc(32), 'FIBEMateX3DH');
  return rootKey;
}

async function x3dhBob(bobIK, bobSPK, bobOPK, aliceIKPublic, aliceEKPublic) {
  const dh1 = await dh(bobSPK.privateKey, aliceIKPublic);
  const dh2 = await dh(bobIK.privateKey, aliceEKPublic);
  const dh3 = await dh(bobSPK.privateKey, aliceEKPublic);
  let dh4 = Buffer.alloc(0);
  if (bobOPK) {
    dh4 = await dh(bobOPK.privateKey, aliceEKPublic);
  }

  const ikm = Buffer.concat([dh1, dh2, dh3, dh4].filter(b => b.length > 0));
  const rootKey = await hkdf(ikm, Buffer.alloc(32), 'FIBEMateX3DH');
  return rootKey;
}



// ============================================================
// ECDSA Signing Helpers (P1-1: SPK Signature)
// ============================================================
function ecdsaGenerateSigningKey() {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
}

function ecdsaSign(signingPrivateKeyDer, data) {
  const key = crypto.createPrivateKey({ key: signingPrivateKeyDer, format: 'der', type: 'pkcs8' });
  return crypto.sign('sha256', data, key);
}

function ecdsaVerify(signingPublicKeyDer, signature, data) {
  const key = crypto.createPublicKey({ key: signingPublicKeyDer, format: 'der', type: 'spki' });
  return crypto.verify('sha256', data, key, signature);
}

// ============================================================
// Safety Number Fingerprint (P1-3)
// ============================================================
function computeSafetyNumber(userId1, key1Der, userId2, key2Der) {
  const ids = [userId1, userId2].sort();
  const keys = ids[0] === userId1 ? [key1Der, key2Der] : [key2Der, key1Der];
  const data = Buffer.concat([
    Buffer.from(ids[0]), keys[0],
    Buffer.from(ids[1]), keys[1]
  ]);
  const hash = crypto.createHash('sha512').update(data).digest();
  const digits = [];
  for (let i = 0; i < 30; i++) {
    digits.push(Math.floor(hash[i] / 2.56).toString().padStart(2, '0'));
  }
  const full = digits.join('');
  const blocks = [];
  for (let i = 0; i < 60; i += 5) {
    blocks.push(full.slice(i, i + 5));
  }
  return blocks.join(' ');
}

// ============================================================
// Test Runner
// ============================================================
async function runTests() {
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║  FIBEMATE E2EE Handshake End-to-End Test         ║');
  console.log('╚══════════════════════════════════════════════════╝\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, testName) {
    if (condition) {
      console.log(`  ✅ ${testName}`);
      passed++;
    } else {
      console.log(`  ❌ ${testName}`);
      failed++;
    }
  }

  // ---- Step 1: Generate Identity Keys ----
  console.log('\n📦 Step 1: Generate identity keys (Alice & Bob)');
  const aliceIK = await generateDH();
  const bobIK = await generateDH();
  // P1-1: Generate ECDSA signing keys (separate from ECDH identity keys)
  const aliceSigningKey = ecdsaGenerateSigningKey();
  const bobSigningKey = ecdsaGenerateSigningKey();
  assert(aliceIK.privateKey.length > 0, 'Alice identity key generated');
  assert(bobIK.privateKey.length > 0, 'Bob identity key generated');
  assert(aliceSigningKey.privateKey.length > 0, 'Alice ECDSA signing key generated');
  assert(bobSigningKey.privateKey.length > 0, 'Bob ECDSA signing key generated');

  // ---- Step 2: Bob generates pre-keys and uploads to server ----
  console.log('\n📦 Step 2: Bob uploads pre-key bundle to server');
  const bobSPK = await generateDH();
  const bobOPK1 = await generateDH();
  const bobOPK2 = await generateDH();

  // P1-1: Sign the SPK with Bob's identity signing key
  const bobSpkSignature = ecdsaSign(bobSigningKey.privateKey, bobSPK.publicKey);

  const bobBundlePayload = {
    identityKey: Array.from(bobIK.publicKey),
    identitySigningKey: Array.from(bobSigningKey.publicKey),       // P1-1: ECDSA public key
    signedPreKey: Array.from(bobSPK.publicKey),
    signedPreKeyId: Date.now(),
    signedPreKeySignature: Array.from(bobSpkSignature),            // P1-1: ECDSA signature
    oneTimePreKeys: [
      { keyId: Date.now() + 1, publicKey: Array.from(bobOPK1.publicKey) },
      { keyId: Date.now() + 2, publicKey: Array.from(bobOPK2.publicKey) }
    ]
  };

  try {
    const uploadResult = await apiRequest('POST', `/pre-keys/bob`, bobBundlePayload);
    assert(uploadResult.userId === 'bob', 'Bob pre-key bundle uploaded');
    assert(uploadResult.oneTimePreKeyCount === 2, 'Bob has 2 OPKs');
  } catch (e) {
    assert(false, `Bob upload failed: ${e.message}`);
    console.log('    ⚠️  Is mock-server.js running? (node mock-server.js)');
    process.exit(1);
  }

  // ---- Step 3: Alice fetches Bob's bundle ----
  console.log('\n📦 Step 3: Alice fetches Bob\'s pre-key bundle');
  const bobBundle = await apiRequest('GET', `/pre-keys/bob`);
  assert(bobBundle.identityKey && bobBundle.identityKey.length > 0, 'Alice got Bob\'s identity key');
  assert(bobBundle.signedPreKey && bobBundle.signedPreKey.length > 0, 'Alice got Bob\'s signed pre-key');
  assert(bobBundle.oneTimePreKey && bobBundle.oneTimePreKey.length > 0, 'Alice got Bob\'s one-time pre-key (4-DH enabled)');

  // Verify OPK was consumed
  const bobStatus = await apiRequest('GET', `/pre-keys/bob/status`);
  assert(bobStatus.oneTimePreKeysAvailable === 1, 'OPK consumed (1 remaining)');

  // ---- Step 4: X3DH Key Agreement ----
  console.log('\n📦 Step 4: X3DH 4-DH key agreement');
  const aliceEK = await generateDH();

  // Alice computes X3DH
  const aliceRootKey = await x3dhAlice(
    aliceIK, aliceEK,
    Buffer.from(bobBundle.identityKey),
    Buffer.from(bobBundle.signedPreKey),
    bobBundle.oneTimePreKey ? Buffer.from(bobBundle.oneTimePreKey) : null
  );

  // Bob computes X3DH (finding the right OPK by keyId)
  const bobRootKey = await x3dhBob(
    bobIK, bobSPK, bobOPK1,
    aliceIK.publicKey,
    aliceEK.publicKey
  );

  assert(aliceRootKey.equals(bobRootKey), 'Alice & Bob derived identical root key (X3DH 4-DH ✓)');
  console.log(`    Root key (Alice): ${aliceRootKey.toString('hex').slice(0, 32)}...`);
  console.log(`    Root key (Bob):   ${bobRootKey.toString('hex').slice(0, 32)}...`);

  // ---- Step 5: Initialize Double Ratchet ----
  console.log('\n📦 Step 5: Initialize Double Ratchet sessions');
  const aliceState = await ratchetInitInitiator(aliceRootKey, Buffer.from(bobBundle.signedPreKey));
  const bobState = await ratchetInitReceiver(bobRootKey, bobSPK);
  assert(aliceState.sendingChainKey !== null, 'Alice has sending chain');
  assert(bobState.rootKey !== null, 'Bob has root key');

  // ---- Step 6: Alice → Bob encrypted message ----
  console.log('\n📦 Step 6: Alice encrypts message → Bob decrypts');
  const msg1 = '你好 Bob！这是 Alice 发送的第一条端到端加密消息 🎉';
  const encrypted1 = await ratchetEncrypt(aliceState, msg1);
  console.log(`    Ciphertext length: ${encrypted1.ciphertext.length} bytes`);

  let decrypted1;
  try {
    decrypted1 = await ratchetDecrypt(bobState, encrypted1.header, encrypted1.ciphertext, encrypted1.iv);
    assert(decrypted1 === msg1, 'Bob decrypted Alice\'s message correctly (含中文+emoji ✓)');
  } catch (e) {
    assert(false, `Bob decrypt failed: ${e.message}`);
  }

  // ---- Step 7: Bob → Alice reply ----
  console.log('\n📦 Step 7: Bob encrypts reply → Alice decrypts');
  const msg2 = '收到！Alice，前向保密验证通过 🔐';
  const encrypted2 = await ratchetEncrypt(bobState, msg2);

  let decrypted2;
  try {
    decrypted2 = await ratchetDecrypt(aliceState, encrypted2.header, encrypted2.ciphertext, encrypted2.iv);
    assert(decrypted2 === msg2, 'Alice decrypted Bob\'s reply correctly ✓');
  } catch (e) {
    assert(false, `Alice decrypt failed: ${e.message}`);
  }

  // ---- Step 8: Multiple messages (ratchet advances) ----
  console.log('\n📦 Step 8: Multiple messages — ratchet advances');
  const messages = [
    '消息3: Double Ratchet 推进中',
    '消息4: 每条消息独立密钥',
    '消息5: 前向保密保证'
  ];

  for (const msg of messages) {
    const enc = await ratchetEncrypt(aliceState, msg);
    const dec = await ratchetDecrypt(bobState, enc.header, enc.ciphertext, enc.iv);
    assert(dec === msg, `Ratchet message: "${msg.slice(0, 15)}..."`);
  }

  // ---- Step 9: 3-DH fallback (no OPK) ----
  console.log('\n📦 Step 9: 3-DH fallback (no one-time pre-key)');
  const aliceEK2 = await generateDH();
  const aliceRootKey3DH = await x3dhAlice(aliceIK, aliceEK2, bobIK.publicKey, bobSPK.publicKey, null);
  const bobRootKey3DH = await x3dhBob(bobIK, bobSPK, null, aliceIK.publicKey, aliceEK2.publicKey);
  assert(aliceRootKey3DH.equals(bobRootKey3DH), '3-DH fallback: root keys match ✓');

  // ---- Step 10: Opaque envelope verification ----
  console.log('\n📦 Step 10: Opaque envelope — server cannot read content');
  const msgFinal = '这条消息对服务器完全不可见 👻';
  const encFinal = await ratchetEncrypt(aliceState, msgFinal);
  const envelope = {
    version: 2,
    protocol: 'double-ratchet',
    envelope: {
      h: encFinal.header,
      c: encFinal.ciphertext,
      iv: encFinal.iv
    }
  };
  // Verify envelope doesn't contain plaintext
  const envelopeStr = JSON.stringify(envelope);
  assert(!envelopeStr.includes(msgFinal), 'Plaintext NOT in envelope (server can\'t read ✓)');
  assert(envelopeStr.includes('double-ratchet'), 'Protocol identifier visible (for routing ✓)');
  assert(envelope.version === 2, 'Envelope version is 2 ✓');


  // ---- Step 11: P1-1 ECDSA SPK Signature Verification ----
  console.log('\n📦 Step 11: P1-1 ECDSA signed pre-key verification (MITM protection)');
  // Re-fetch bundle to get signature fields
  const bobBundleWithSig = await apiRequest('GET', '/pre-keys/bob');
  assert(!!bobBundleWithSig.identitySigningKey, 'Bundle includes identity signing key');
  assert(!!bobBundleWithSig.signedPreKeySignature, 'Bundle includes SPK signature');

  // Verify signature
  const spkSigValid = ecdsaVerify(
    Buffer.from(bobBundleWithSig.identitySigningKey),
    Buffer.from(bobBundleWithSig.signedPreKeySignature),
    Buffer.from(bobBundleWithSig.signedPreKey)
  );
  assert(spkSigValid, 'SPK signature verified ✓ (MITM protection active)');

  // Test tampered signature detection
  const tamperedSPK = Buffer.from(bobBundleWithSig.signedPreKey);
  tamperedSPK[0] ^= 0xFF;  // flip first byte
  const tamperedValid = ecdsaVerify(
    Buffer.from(bobBundleWithSig.identitySigningKey),
    Buffer.from(bobBundleWithSig.signedPreKeySignature),
    tamperedSPK
  );
  assert(!tamperedValid, 'Tampered SPK rejected ✓ (MITM detected)');

  // ---- Step 12: P1-2 OPK Auto-Replenishment Warning ----
  console.log('\n📦 Step 12: P1-2 OPK auto-replenishment warning');
  // Bob started with 2 OPKs, 1 was consumed → 1 remaining
  // Threshold is 5, so should be low
  const bobStatusAfter = await apiRequest('GET', '/pre-keys/bob/status');
  assert(bobStatusAfter.hasSigningKey === true, 'Status shows signing key present');
  assert(bobStatusAfter.hasSPKSignature === true, 'Status shows SPK signature present');
  assert(bobStatusAfter.lowOPKs === true, 'OPK low warning triggered ✓');
  assert(bobStatusAfter.current < bobStatusAfter.threshold, 'OPK count (' + bobStatusAfter.current + ') < threshold (' + bobStatusAfter.threshold + ')');

  // Upload more OPKs to replenish
  const newOPKs = [];
  for (let i = 0; i < 10; i++) {
    const opk = await generateDH();
    newOPKs.push({ keyId: Date.now() + 100 + i, publicKey: Array.from(opk.publicKey) });
  }
  const replenishResult = await apiRequest('POST', '/pre-keys/bob', {
    identityKey: Array.from(bobIK.publicKey),
    identitySigningKey: Array.from(bobSigningKey.publicKey),
    signedPreKey: Array.from(bobSPK.publicKey),
    signedPreKeyId: bobBundlePayload.signedPreKeyId,
    signedPreKeySignature: Array.from(bobSpkSignature),
    oneTimePreKeys: newOPKs
  });
  assert(replenishResult.lowOPKs === false, 'OPK replenished — low warning cleared ✓');
  assert(replenishResult.oneTimePreKeyCount >= 10, 'OPKs now: ' + replenishResult.oneTimePreKeyCount);

  // ---- Step 13: P1-3 Safety Number Fingerprint ----
  console.log('\n📦 Step 13: P1-3 Safety number fingerprint (X3DH identity key)');
  const aliceSafetyNum = computeSafetyNumber('alice', aliceIK.publicKey, 'bob', bobIK.publicKey);
  const bobSafetyNum = computeSafetyNumber('bob', bobIK.publicKey, 'alice', aliceIK.publicKey);
  assert(aliceSafetyNum === bobSafetyNum, 'Both sides compute identical safety number ✓');
  assert(aliceSafetyNum.split(' ').length === 12, 'Safety number has 12 groups of 5 digits');
  console.log('    Safety number: ' + aliceSafetyNum);

  // Verify different keys produce different safety numbers
  const evilIK = await generateDH();
  const evilSafetyNum = computeSafetyNumber('alice', evilIK.publicKey, 'bob', bobIK.publicKey);
  assert(evilSafetyNum !== aliceSafetyNum, 'Different keys → different safety number (MITM detected) ✓');

  // ---- Summary ----
  console.log('\n╔══════════════════════════════════════════════════╗');
  console.log(`║  Results: ${passed} passed, ${failed} failed                        ║`);
  if (failed === 0) {
    console.log('║  🎉 ALL TESTS PASSED — E2EE handshake verified!  ║');
  } else {
    console.log('║  ⚠️  Some tests failed — see above for details   ║');
  }
  console.log('╚══════════════════════════════════════════════════╝\n');

  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
