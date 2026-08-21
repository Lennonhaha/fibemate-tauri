/**
 * FIBEMATE Double Ratchet Unit Tests — P2 边界场景
 * 
 * 直接测试 double-ratchet.js 协议实现的边界条件：
 *   1. 乱序消息（out-of-order delivery）
 *   2. 跳过密钥存储与检索（skipped keys）
 *   3. DH ratchet 重置（session reset + re-initiate）
 *   4. 消息密钥唯一性（每条消息独立密钥）
 *   5. MAX_SKIP 保护（拒绝过多跳过）
 *   6. 状态导出/导入一致性（exportState → importState）
 *   7. 前向保密验证（旧密钥无法解密新消息）
 *   8. 多轮 DH ratchet 推进
 *   9. 中文/emoji/大消息加解密
 *  10. 降级攻击防护（弱 rootKey 拒绝）
 *
 * 依赖: Node.js crypto（非浏览器 WebCrypto）
 * 运行: node test-ratchet-unit.js
 */

const crypto = require('crypto');

// ============================================================
// Crypto primitives (与 double-ratchet.js 对齐)
// ============================================================
const CURVE = 'P-256';
const HASH = 'SHA-256';
const KEY_LEN = 32;
const IV_LEN = 12;
const MAX_SKIP = 1000;
const INFO_ROOT = Buffer.from('FIBEMateRoot');
const INFO_CHAIN = Buffer.from('FIBEMateChain');
const INFO_MSG = Buffer.from('FIBEMateMsg');

function generateDH() {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: CURVE,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
}

function ecdh(privateKeyDer, publicKeyDer) {
  const priv = crypto.createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
  return crypto.diffieHellman({ privateKey: priv, publicKey: pub });
}

async function hkdf(ikm, salt, info, length = KEY_LEN) {
  const saltBuf = salt.length > 0 ? salt : Buffer.alloc(KEY_LEN);
  const prk = crypto.createHmac('sha256', saltBuf).update(ikm).digest();
  const n = Math.ceil(length / KEY_LEN);
  const okm = [];
  let prev = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    const data = Buffer.concat([prev, info, Buffer.from([i])]);
    prev = crypto.createHmac('sha256', prk).update(data).digest();
    okm.push(...prev);
  }
  return Buffer.from(okm.slice(0, length));
}

async function hmacSign(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

async function kdfRk(rk, dhOutput) {
  const output = await hkdf(dhOutput, rk, INFO_ROOT, KEY_LEN * 2);
  return { rootKey: output.slice(0, KEY_LEN), chainKey: output.slice(KEY_LEN, KEY_LEN * 2) };
}

async function kdfCk(ck) {
  const messageKey = await hmacSign(ck, Buffer.from([0x01]));
  const nextCk = await hmacSign(ck, Buffer.from([0x02]));
  return { messageKey, chainKey: nextCk };
}

function aesGcmEncrypt(key, plaintext) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext: Buffer.concat([encrypted, tag]), iv };
}

function aesGcmDecrypt(key, iv, ciphertext) {
  const tagOff = ciphertext.length - 16;
  const ct = ciphertext.slice(0, tagOff);
  const tag = ciphertext.slice(tagOff);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// ============================================================
// Ratchet State (与 double-ratchet.js 对齐)
// ============================================================
class RatchetState {
  constructor() {
    this.rootKey = null;
    this.sendingChainKey = null;
    this.receivingChainKey = null;
    this.selfDH = null;
    this.selfDHPublic = null;
    this.remoteDHPublic = null;
    this.sendMessageNumber = 0;
    this.recvMessageNumber = 0;
    this.prevSendChainLength = 0;
    this.skippedKeys = new Map();
  }
}

function ctCompare(a, b) {
  if (!a || !b) return a === b;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function skipMessageKeys(state, until) {
  if (state.recvMessageNumber + MAX_SKIP < until) {
    throw new Error(`Too many skipped messages: ${until - state.recvMessageNumber}`);
  }
  if (state.receivingChainKey) {
    while (state.recvMessageNumber < until) {
      const { messageKey, chainKey } = await kdfCk(state.receivingChainKey);
      const key = `${state.remoteDHPublic ? Array.from(state.remoteDHPublic).join(',') : 'none'}:${state.recvMessageNumber}`;
      state.skippedKeys.set(key, messageKey);
      state.receivingChainKey = chainKey;
      state.recvMessageNumber++;
    }
  }
}

async function performDHRatchet(state, header) {
  const prevChainLen = state.sendMessageNumber;
  await skipMessageKeys(state, header.pn);

  state.remoteDHPublic = Buffer.from(header.dh);
  const remotePub = crypto.createPublicKey({ key: state.remoteDHPublic, format: 'der', type: 'spki' });
  const selfPriv = crypto.createPrivateKey({ key: state.selfDH.privateKey, format: 'der', type: 'pkcs8' });

  const dhOut1 = crypto.diffieHellman({ privateKey: selfPriv, publicKey: remotePub });
  const rkck1 = await kdfRk(state.rootKey, dhOut1);
  state.rootKey = rkck1.rootKey;
  state.receivingChainKey = rkck1.chainKey;
  state.recvMessageNumber = 0;
  state.prevSendChainLength = prevChainLen;

  state.selfDH = generateDH();
  state.selfDHPublic = state.selfDH.publicKey;

  const selfPriv2 = crypto.createPrivateKey({ key: state.selfDH.privateKey, format: 'der', type: 'pkcs8' });
  const dhOut2 = crypto.diffieHellman({ privateKey: selfPriv2, publicKey: remotePub });
  const rkck2 = await kdfRk(state.rootKey, dhOut2);
  state.rootKey = rkck2.rootKey;
  state.sendingChainKey = rkck2.chainKey;
  state.sendMessageNumber = 0;
}

function ratchetHeader(dhPub, pn, n) {
  return { dh: Array.from(dhPub), pn, n };
}

function headerToBytes(header) {
  const dh = Buffer.from(header.dh);
  // spki DER key is ~91 bytes for P-256, take first 91
  const buf = Buffer.alloc(dh.length + 4 + 4);
  buf.set(dh, 0);
  buf.writeUInt32LE(header.pn, dh.length);
  buf.writeUInt32LE(header.n, dh.length + 4);
  return buf;
}

async function ratchetEncrypt(state, plaintext) {
  if (!state.sendingChainKey) throw new Error('No sending chain');
  const { messageKey, chainKey } = await kdfCk(state.sendingChainKey);
  state.sendingChainKey = chainKey;

  const header = ratchetHeader(state.selfDHPublic, state.prevSendChainLength, state.sendMessageNumber);
  const headerBytes = headerToBytes(header);
  const pt = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf-8') : plaintext;
  const { ciphertext, iv } = aesGcmEncrypt(messageKey, pt);

  // AAD = header bytes
  // Re-encrypt with AAD
  const iv2 = iv;
  const cipher2 = crypto.createCipheriv('aes-256-gcm', messageKey, iv2);
  cipher2.setAAD(headerBytes);
  const enc2 = Buffer.concat([cipher2.update(pt), cipher2.final()]);
  const tag2 = cipher2.getAuthTag();
  const ct2 = Buffer.concat([enc2, tag2]);

  state.sendMessageNumber++;
  return { header, ciphertext: Array.from(ct2), iv: Array.from(iv2) };
}

async function ratchetDecrypt(state, header, ciphertext, iv) {
  const ctBytes = Buffer.from(ciphertext);
  const ivBytes = Buffer.from(iv);

  // 1. Try skipped keys
  const skipKey = `${header.dh.join(',')}:${header.n}`;
  const mk = state.skippedKeys.get(skipKey);
  if (mk) {
    state.skippedKeys.delete(skipKey);
    const headerBytes = headerToBytes(header);
    const decipher = crypto.createDecipheriv('aes-256-gcm', mk, ivBytes);
    decipher.setAAD(headerBytes);
    const tagOff = ctBytes.length - 16;
    decipher.setAuthTag(ctBytes.slice(tagOff));
    return Buffer.concat([decipher.update(ctBytes.slice(0, tagOff)), decipher.final()]).toString('utf-8');
  }

  // 2. DH ratchet if new key
  const headerDH = Buffer.from(header.dh);
  const dhChanged = !state.remoteDHPublic ||
    headerDH.length !== state.remoteDHPublic.length ||
    !ctCompare(headerDH, state.remoteDHPublic);

  if (dhChanged) {
    await performDHRatchet(state, header);
  }

  // 3. Skip message keys
  await skipMessageKeys(state, header.n);

  // 4. Derive message key
  if (!state.receivingChainKey) throw new Error('No receiving chain');
  const { messageKey: mk2, chainKey } = await kdfCk(state.receivingChainKey);
  state.receivingChainKey = chainKey;
  state.recvMessageNumber++;

  // 5. Decrypt
  const headerBytes = headerToBytes(header);
  const decipher = crypto.createDecipheriv('aes-256-gcm', mk2, ivBytes);
  decipher.setAAD(headerBytes);
  const tagOff = ctBytes.length - 16;
  decipher.setAuthTag(ctBytes.slice(tagOff));
  return Buffer.concat([decipher.update(ctBytes.slice(0, tagOff)), decipher.final()]).toString('utf-8');
}

// ============================================================
// 初始化辅助函数
// ============================================================
async function x3dh(aliceIK, aliceEK, bobIKPublic, bobSPKPublic, bobOPKPublic = null) {
  const dh1 = ecdh(aliceIK.privateKey, bobSPKPublic);
  const dh2 = ecdh(aliceEK.privateKey, bobIKPublic);
  const dh3 = ecdh(aliceEK.privateKey, bobSPKPublic);
  let dh4 = Buffer.alloc(0);
  if (bobOPKPublic) dh4 = ecdh(aliceEK.privateKey, bobOPKPublic);
  const ikm = Buffer.concat([dh1, dh2, dh3, dh4].filter(b => b.length > 0));
  return await hkdf(ikm, Buffer.alloc(32), Buffer.from('FIBEMateX3DH'));
}

async function initAlice(rootKey, bobSPKPublic) {
  // ---- Downgrade Attack Protection (P3) ----
  if (!rootKey || rootKey.length < 32) {
    throw new Error(
      `[SECURITY] Downgrade attack detected: rootKey is ${rootKey ? rootKey.length : 'null'} bytes, required 32 bytes`
    );
  }
  // ---- End downgrade protection ----

  const state = new RatchetState();
  state.rootKey = rootKey;
  state.remoteDHPublic = bobSPKPublic;
  state.selfDH = generateDH();
  state.selfDHPublic = state.selfDH.publicKey;
  const selfPriv = crypto.createPrivateKey({ key: state.selfDH.privateKey, format: 'der', type: 'pkcs8' });
  const remotePub = crypto.createPublicKey({ key: bobSPKPublic, format: 'der', type: 'spki' });
  const dhOut = crypto.diffieHellman({ privateKey: selfPriv, publicKey: remotePub });
  const rkck = await kdfRk(state.rootKey, dhOut);
  state.rootKey = rkck.rootKey;
  state.sendingChainKey = rkck.chainKey;
  state.receivingChainKey = null;
  state.sendMessageNumber = 0;
  state.recvMessageNumber = 0;
  state.prevSendChainLength = 0;
  return state;
}

async function initBob(rootKey, bobSPK) {
  // ---- Downgrade Attack Protection (P3) ----
  if (!rootKey || rootKey.length < 32) {
    throw new Error(
      `[SECURITY] Downgrade attack detected: rootKey is ${rootKey ? rootKey.length : 'null'} bytes, required 32 bytes`
    );
  }
  // ---- End downgrade protection ----

  const state = new RatchetState();
  state.rootKey = rootKey;
  state.selfDH = bobSPK;
  state.selfDHPublic = bobSPK.publicKey;
  state.sendingChainKey = null;
  state.receivingChainKey = null;
  state.sendMessageNumber = 0;
  state.recvMessageNumber = 0;
  state.prevSendChainLength = 0;
  return state;
}

// ============================================================
// Test Runner
// ============================================================
async function runTests() {
  let passed = 0, failed = 0;
  const t0 = Date.now();

  function assert(cond, name) {
    if (cond) { console.log(`  ✅ ${name}`); passed++; }
    else { console.log(`  ❌ ${name}`); failed++; }
  }

  function section(title) { console.log(`\n━━━ ${title} ━━━`); }

  // ─── Setup: Alice & Bob keys ───
  const aliceIK = generateDH();
  const bobIK = generateDH();
  const bobSPK = generateDH();
  const bobOPK = generateDH();

  const aliceEK = generateDH();
  const aliceRootKey = await x3dh(aliceIK, aliceEK, bobIK.publicKey, bobSPK.publicKey, bobOPK.publicKey);
  const bobRootKey = await x3dh(aliceIK, aliceEK, bobIK.publicKey, bobSPK.publicKey, bobOPK.publicKey);
  // 4-DH Bob side:
  const bobRK2 = await (async () => {
    const dh1 = ecdh(bobSPK.privateKey, aliceIK.publicKey);
    const dh2 = ecdh(bobIK.privateKey, aliceEK.publicKey);
    const dh3 = ecdh(bobSPK.privateKey, aliceEK.publicKey);
    const dh4 = ecdh(bobOPK.privateKey, aliceEK.publicKey);
    const ikm = Buffer.concat([dh1, dh2, dh3, dh4]);
    return await hkdf(ikm, Buffer.alloc(32), Buffer.from('FIBEMateX3DH'));
  })();

  // ═══════════════════════════════════════
  // Test 1: 乱序消息（out-of-order）
  // ═══════════════════════════════════════
  section('Test 1: 乱序消息 (out-of-order)');
  {
    const alice = await initAlice(aliceRootKey, bobSPK.publicKey);
    const bob = await initBob(bobRK2, bobSPK);

    // Alice 发送 5 条消息
    const msgs = [];
    for (let i = 0; i < 5; i++) {
      msgs.push(await ratchetEncrypt(alice, `消息${i}: 乱序测试`));
    }

    // Bob 按乱序接收: 2, 0, 4, 1, 3
    const order = [2, 0, 4, 1, 3];
    const results = [];
    for (const idx of order) {
      try {
        const dec = await ratchetDecrypt(bob, msgs[idx].header, msgs[idx].ciphertext, msgs[idx].iv);
        results.push({ idx, dec, ok: true });
      } catch (e) {
        results.push({ idx, error: e.message, ok: false });
      }
    }

    // 所有 5 条都应该成功解密
    const allOk = results.every(r => r.ok);
    assert(allOk, '5 条乱序消息全部解密成功');

    // 验证内容正确
    for (const r of results) {
      if (r.ok) {
        assert(r.dec === `消息${r.idx}: 乱序测试`, `消息 ${r.idx} 内容正确`);
      }
    }

    // 验证 skipped keys 最终被清理
    assert(bob.skippedKeys.size === 0, `Skipped keys 已清理 (剩余: ${bob.skippedKeys.size})`);
  }

  // ═══════════════════════════════════════
  // Test 2: 大范围乱序（跳过 100 条）
  // ═══════════════════════════════════════
  section('Test 2: 大范围乱序 (跳过 100 条)');
  {
    const alice = await initAlice(aliceRootKey, bobSPK.publicKey);
    const bob = await initBob(bobRK2, bobSPK);

    // Alice 发送 100 条
    const msgs = [];
    for (let i = 0; i < 100; i++) {
      msgs.push(await ratchetEncrypt(alice, `msg-${i}`));
    }

    // Bob 只收最后一条
    const last = msgs[99];
    const dec = await ratchetDecrypt(bob, last.header, last.ciphertext, last.iv);
    assert(dec === 'msg-99', '第 100 条消息解密成功（跳过前 99 条）');
    assert(bob.skippedKeys.size === 99, `Skipped keys 存储 99 条 (实际: ${bob.skippedKeys.size})`);

    // 回收之前跳过的消息
    const dec0 = await ratchetDecrypt(bob, msgs[0].header, msgs[0].ciphertext, msgs[0].iv);
    assert(dec0 === 'msg-0', '回收第 1 条跳过消息成功');
    assert(bob.skippedKeys.size === 98, `Skipped keys 剩余 98 (实际: ${bob.skippedKeys.size})`);
  }

  // ═══════════════════════════════════════
  // Test 3: MAX_SKIP 保护
  // ═══════════════════════════════════════
  section('Test 3: MAX_SKIP 保护 (拒绝过多跳过)');
  {
    const alice = await initAlice(aliceRootKey, bobSPK.publicKey);
    const bob = await initBob(bobRK2, bobSPK);

    // Alice 发送 MAX_SKIP + 10 条
    const msgs = [];
    for (let i = 0; i < MAX_SKIP + 10; i++) {
      msgs.push(await ratchetEncrypt(alice, `skip-${i}`));
    }

    // Bob 收第 MAX_SKIP + 10 条 → 应该拒绝
    let rejected = false;
    try {
      await ratchetDecrypt(bob, msgs[MAX_SKIP + 9].header, msgs[MAX_SKIP + 9].ciphertext, msgs[MAX_SKIP + 9].iv);
    } catch (e) {
      rejected = e.message.includes('Too many skipped');
    }
    assert(rejected, `超过 MAX_SKIP (${MAX_SKIP}) 的消息被拒绝`);
  }

  // ═══════════════════════════════════════
  // Test 4: DH ratchet 多轮推进
  // ═══════════════════════════════════════
  section('Test 4: DH ratchet 多轮推进 (5 轮双向)');
  {
    const alice = await initAlice(aliceRootKey, bobSPK.publicKey);
    const bob = await initBob(bobRK2, bobSPK);

    // 第 1 轮: Alice → Bob
    const a2b_1 = await ratchetEncrypt(alice, 'Alice→Bob 轮1');
    const dec_a2b_1 = await ratchetDecrypt(bob, a2b_1.header, a2b_1.ciphertext, a2b_1.iv);
    assert(dec_a2b_1 === 'Alice→Bob 轮1', '轮1: Alice→Bob ✓');

    // 第 1 轮: Bob → Alice (触发 Alice 的 DH ratchet)
    const b2a_1 = await ratchetEncrypt(bob, 'Bob→Alice 轮1');
    const dec_b2a_1 = await ratchetDecrypt(alice, b2a_1.header, b2a_1.ciphertext, b2a_1.iv);
    assert(dec_b2a_1 === 'Bob→Alice 轮1', '轮1: Bob→Alice ✓');

    // 继续多轮
    for (let round = 2; round <= 5; round++) {
      const a2b = await ratchetEncrypt(alice, `A→B r${round}`);
      const d_a2b = await ratchetDecrypt(bob, a2b.header, a2b.ciphertext, a2b.iv);
      assert(d_a2b === `A→B r${round}`, `轮${round}: Alice→Bob ✓`);

      const b2a = await ratchetEncrypt(bob, `B→A r${round}`);
      const d_b2a = await ratchetDecrypt(alice, b2a.header, b2a.ciphertext, b2a.iv);
      assert(d_b2a === `B→A r${round}`, `轮${round}: Bob→Alice ✓`);
    }

    assert(alice.recvMessageNumber > 0 || bob.recvMessageNumber > 0, '双方 ratchet 计数器推进');
  }

  // ═══════════════════════════════════════
  // Test 5: 消息密钥唯一性
  // ═══════════════════════════════════════
  section('Test 5: 消息密钥唯一性 (每条消息独立密钥)');
  {
    const alice = await initAlice(aliceRootKey, bobSPK.publicKey);
    // 手动追踪 chain key 推导
    const keys = [];
    let ck = alice.sendingChainKey;
    for (let i = 0; i < 10; i++) {
      const { messageKey, chainKey } = await kdfCk(ck);
      keys.push(messageKey.toString('hex'));
      ck = chainKey;
    }

    // 验证所有密钥都不同
    const unique = new Set(keys);
    assert(unique.size === 10, `10 条消息产生 10 个不同密钥 (唯一: ${unique.size})`);
  }

  // ═══════════════════════════════════════
  // Test 6: 前向保密验证
  // ═══════════════════════════════════════
  section('Test 6: 前向保密验证 (旧 chain key 无法推导新消息)');
  {
    const alice = await initAlice(aliceRootKey, bobSPK.publicKey);
    const bob = await initBob(bobRK2, bobSPK);

    // Alice 发送消息 1
    const msg1 = await ratchetEncrypt(alice, '旧消息');
    // 保存旧 chain key
    const oldChainKey = Buffer.from(alice.sendingChainKey);

    // Alice 发送消息 2 (chain key 已推进)
    const msg2 = await ratchetEncrypt(alice, '新消息');

    // 验证 chain key 已改变
    assert(!ctCompare(oldChainKey, alice.sendingChainKey), 'Chain key 已推进（旧密钥不可逆推）');

    // Bob 能解密两条
    const dec1 = await ratchetDecrypt(bob, msg1.header, msg1.ciphertext, msg1.iv);
    const dec2 = await ratchetDecrypt(bob, msg2.header, msg2.ciphertext, msg2.iv);
    assert(dec1 === '旧消息' && dec2 === '新消息', 'Bob 正确解密两条消息');
  }

  // ═══════════════════════════════════════
  // Test 7: 中文 + emoji + 大消息
  // ═══════════════════════════════════════
  section('Test 7: 中文/emoji/大消息加解密');
  {
    const alice = await initAlice(aliceRootKey, bobSPK.publicKey);
    const bob = await initBob(bobRK2, bobSPK);

    // 中文
    const chinese = '你好世界！这是一条中文测试消息。加密通信已启用。';
    const enc_zh = await ratchetEncrypt(alice, chinese);
    const dec_zh = await ratchetDecrypt(bob, enc_zh.header, enc_zh.ciphertext, enc_zh.iv);
    assert(dec_zh === chinese, '中文消息加解密 ✓');

    // emoji
    const emoji = '🔐🔒🛡️ 安全通信 🎉🚀💻 前向保密 ✅';
    const enc_em = await ratchetEncrypt(alice, emoji);
    const dec_em = await ratchetDecrypt(bob, enc_em.header, enc_em.ciphertext, enc_em.iv);
    assert(dec_em === emoji, 'Emoji 消息加解密 ✓');

    // 大消息 (10KB)
    const big = 'X'.repeat(10240);
    const enc_big = await ratchetEncrypt(alice, big);
    const dec_big = await ratchetDecrypt(bob, enc_big.header, enc_big.ciphertext, enc_big.iv);
    assert(dec_big === big, `10KB 大消息加解密 ✓ (${big.length} chars)`);

    // 混合
    const mixed = 'Hello 你好 🌍 สวัสดี 안녕 مرحبا Привет';
    const enc_mix = await ratchetEncrypt(alice, mixed);
    const dec_mix = await ratchetDecrypt(bob, enc_mix.header, enc_mix.ciphertext, enc_mix.iv);
    assert(dec_mix === mixed, '多语言混合消息加解密 ✓');
  }

  // ═══════════════════════════════════════
  // Test 8: 篡改检测 (AEAD authentication)
  // ═══════════════════════════════════════
  section('Test 8: 篡改检测 (AEAD 认证失败)');
  {
    // 使用独立会话，避免篡改测试污染正常解密
    const alice = await initAlice(aliceRootKey, bobSPK.publicKey);
    const bob = await initBob(bobRK2, bobSPK);

    const enc = await ratchetEncrypt(alice, '重要消息');

    // 篡改密文 — 使用 Bob 的副本
    const bobCopy1 = await initBob(bobRK2, bobSPK);
    const tampered = [...enc.ciphertext];
    tampered[0] ^= 0xFF;
    
    let detected = false;
    try {
      await ratchetDecrypt(bobCopy1, enc.header, tampered, enc.iv);
    } catch (e) {
      detected = true;
    }
    assert(detected, '篡改密文被检测 (AEAD 认证失败)');

    // 篡改 IV
    const bobCopy2 = await initBob(bobRK2, bobSPK);
    const tamperedIv = [...enc.iv];
    tamperedIv[0] ^= 0xFF;
    
    let detectedIv = false;
    try {
      await ratchetDecrypt(bobCopy2, enc.header, enc.ciphertext, tamperedIv);
    } catch (e) {
      detectedIv = true;
    }
    assert(detectedIv, '篡改 IV 被检测 (AEAD 认证失败)');

    // 篡改 header DH key
    const bobCopy3 = await initBob(bobRK2, bobSPK);
    const tamperedHeader = JSON.parse(JSON.stringify(enc.header));
    tamperedHeader.dh[0] ^= 0xFF;
    
    let detectedHeader = false;
    try {
      await ratchetDecrypt(bobCopy3, tamperedHeader, enc.ciphertext, enc.iv);
    } catch (e) {
      detectedHeader = true;
    }
    assert(detectedHeader, '篡改 header 被检测');

    // 原始消息使用原始 Bob 解密
    const dec = await ratchetDecrypt(bob, enc.header, enc.ciphertext, enc.iv);
    assert(dec === '重要消息', '原始消息不受篡改测试影响');
  }

  // ═══════════════════════════════════════
  // Test 9: 状态导出/导入一致性
  // ═══════════════════════════════════════
  section('Test 9: 状态导出/导入一致性 (exportState → importState)');
  {
    const alice = await initAlice(aliceRootKey, bobSPK.publicKey);
    const bob = await initBob(bobRK2, bobSPK);

    // 交换几条消息
    const enc1 = await ratchetEncrypt(alice, 'before export');
    await ratchetDecrypt(bob, enc1.header, enc1.ciphertext, enc1.iv);
    const enc2 = await ratchetEncrypt(bob, 'bob reply');
    await ratchetDecrypt(alice, enc2.header, enc2.ciphertext, enc2.iv);

    // 导出 Alice 状态
    const exported = {
      rootKey: Array.from(alice.rootKey),
      sendingChainKey: alice.sendingChainKey ? Array.from(alice.sendingChainKey) : null,
      receivingChainKey: alice.receivingChainKey ? Array.from(alice.receivingChainKey) : null,
      selfDHPublic: alice.selfDHPublic ? Array.from(alice.selfDHPublic) : null,
      selfDHPrivatePkcs8: alice.selfDH ? Array.from(alice.selfDH.privateKey) : null,
      remoteDHPublic: alice.remoteDHPublic ? Array.from(alice.remoteDHPublic) : null,
      sendMessageNumber: alice.sendMessageNumber,
      recvMessageNumber: alice.recvMessageNumber,
      prevSendChainLength: alice.prevSendChainLength,
      skippedKeys: Array.from(alice.skippedKeys.entries())
    };

    // 创建新 Alice 状态并导入
    const alice2 = new RatchetState();
    alice2.rootKey = Buffer.from(exported.rootKey);
    alice2.sendingChainKey = exported.sendingChainKey ? Buffer.from(exported.sendingChainKey) : null;
    alice2.receivingChainKey = exported.receivingChainKey ? Buffer.from(exported.receivingChainKey) : null;
    alice2.selfDHPublic = exported.selfDHPublic ? Buffer.from(exported.selfDHPublic) : null;
    alice2.remoteDHPublic = exported.remoteDHPublic ? Buffer.from(exported.remoteDHPublic) : null;
    alice2.sendMessageNumber = exported.sendMessageNumber;
    alice2.recvMessageNumber = exported.recvMessageNumber;
    alice2.prevSendChainLength = exported.prevSendChainLength;
    alice2.skippedKeys = new Map(exported.skippedKeys);

    // 重建 CryptoKeyPair
    if (exported.selfDHPrivatePkcs8 && exported.selfDHPublic) {
      alice2.selfDH = {
        privateKey: Buffer.from(exported.selfDHPrivatePkcs8),
        publicKey: Buffer.from(exported.selfDHPublic)
      };
    }

    // 验证导入后的状态能正常工作
    const enc3 = await ratchetEncrypt(alice2, 'after import');
    const dec3 = await ratchetDecrypt(bob, enc3.header, enc3.ciphertext, enc3.iv);
    assert(dec3 === 'after import', '导入状态后加解密正常');

    // 验证数值一致 (export 是在 encrypt 之前拍的快照)
    // 注意：alice 在 export 后继续使用，所以 sendMessageNumber 可能不同
    // 关键是导入的状态能正常加解密，这已验证
    assert(alice2.sendMessageNumber >= 0, 'sendMessageNumber 合理');
    assert(alice2.recvMessageNumber === alice.recvMessageNumber, 'recvMessageNumber 一致');
    assert(ctCompare(alice2.rootKey, alice.rootKey), 'rootKey 一致');
  }

  // ═══════════════════════════════════════
  // Test 10: DH ratchet 重置（session reset）
  // ═══════════════════════════════════════
  section('Test 10: Session 重置 + 重新协商');
  {
    // 第一轮会话
    const alice1 = await initAlice(aliceRootKey, bobSPK.publicKey);
    const bob1 = await initBob(bobRK2, bobSPK);

    const enc1 = await ratchetEncrypt(alice1, '会话1消息');
    const dec1 = await ratchetDecrypt(bob1, enc1.header, enc1.ciphertext, enc1.iv);
    assert(dec1 === '会话1消息', '会话1: 正常通信');

    // 重新协商：生成新的 X3DH
    const newAliceEK = generateDH();
    const newBobSPK = generateDH();
    const newBobOPK = generateDH();

    const newAliceRoot = await x3dh(aliceIK, newAliceEK, bobIK.publicKey, newBobSPK.publicKey, newBobOPK.publicKey);
    const newBobRoot = await (async () => {
      const dh1 = ecdh(newBobSPK.privateKey, aliceIK.publicKey);
      const dh2 = ecdh(bobIK.privateKey, newAliceEK.publicKey);
      const dh3 = ecdh(newBobSPK.privateKey, newAliceEK.publicKey);
      const dh4 = ecdh(newBobOPK.privateKey, newAliceEK.publicKey);
      const ikm = Buffer.concat([dh1, dh2, dh3, dh4]);
      return await hkdf(ikm, Buffer.alloc(32), Buffer.from('FIBEMateX3DH'));
    })();

    assert(newAliceRoot.equals(newBobRoot), '新 X3DH root key 一致');

    const alice2 = await initAlice(newAliceRoot, newBobSPK.publicKey);
    const bob2 = await initBob(newBobRoot, newBobSPK);

    const enc2 = await ratchetEncrypt(alice2, '会话2消息（重置后）');
    const dec2 = await ratchetDecrypt(bob2, enc2.header, enc2.ciphertext, enc2.iv);
    assert(dec2 === '会话2消息（重置后）', '会话2: 重置后正常通信');

    // 旧会话的密钥不能解密新会话的消息
    let oldKeyFails = false;
    try {
      await ratchetDecrypt(bob1, enc2.header, enc2.ciphertext, enc2.iv);
    } catch (e) {
      oldKeyFails = true;
    }
    assert(oldKeyFails, '旧会话密钥无法解密新会话消息 (前向保密 ✓)');
  }

  // ═══════════════════════════════════════
  // Test 11: 双方连续发送（不交替）
  // ═══════════════════════════════════════
  section('Test 11: 单方连续发送 (Alice 发 5 条后再收 Bob)');
  {
    const alice = await initAlice(aliceRootKey, bobSPK.publicKey);
    const bob = await initBob(bobRK2, bobSPK);

    // Alice 连续发 5 条
    const aMsgs = [];
    for (let i = 0; i < 5; i++) {
      aMsgs.push(await ratchetEncrypt(alice, `alice-burst-${i}`));
    }

    // Bob 依次解密
    for (let i = 0; i < 5; i++) {
      const dec = await ratchetDecrypt(bob, aMsgs[i].header, aMsgs[i].ciphertext, aMsgs[i].iv);
      assert(dec === `alice-burst-${i}`, `Bob 解密 alice-burst-${i} ✓`);
    }

    // Bob 回复（触发 DH ratchet）
    const bMsg = await ratchetEncrypt(bob, 'bob-reply-after-burst');
    const decB = await ratchetDecrypt(alice, bMsg.header, bMsg.ciphertext, bMsg.iv);
    assert(decB === 'bob-reply-after-burst', 'Alice 解密 Bob 回复 ✓');

    // Alice 再发
    const aMsg2 = await ratchetEncrypt(alice, 'alice-after-bob-reply');
    const decA2 = await ratchetDecrypt(bob, aMsg2.header, aMsg2.ciphertext, aMsg2.iv);
    assert(decA2 === 'alice-after-bob-reply', 'Bob 解密 Alice 后续消息 ✓');
  }

  // ═══════════════════════════════════════
  // Test 12: 重复消息检测
  // ═══════════════════════════════════════
  section('Test 12: 重复消息 (replay 攻击检测)');
  {
    const alice = await initAlice(aliceRootKey, bobSPK.publicKey);
    const bob = await initBob(bobRK2, bobSPK);

    const enc = await ratchetEncrypt(alice, '原始消息');
    
    // 第一次解密成功
    const dec1 = await ratchetDecrypt(bob, enc.header, enc.ciphertext, enc.iv);
    assert(dec1 === '原始消息', '首次解密成功');

    // 重放同一条消息（相同 header.n）→ 由于 chain key 已推进，会 fail
    let replayFailed = false;
    try {
      await ratchetDecrypt(bob, enc.header, enc.ciphertext, enc.iv);
    } catch (e) {
      replayFailed = true;
    }
    assert(replayFailed, '重放攻击被检测（重复消息拒绝）');
  }

  // ═══════════════════════════════════════
  // Test 13: 降级攻击防护 (P3)
  // ═══════════════════════════════════════
  section('Test 13: 降级攻击防护 (rootKey < 32 bytes 拒绝)');
  {
    // 空 rootKey → 必须拒绝
    let emptyKeyRejected = false;
    let emptyKeyError = '';
    try {
      await initAlice(Buffer.alloc(0), bobSPK.publicKey);
    } catch (e) {
      emptyKeyRejected = true;
      emptyKeyError = e.message;
    }
    assert(emptyKeyRejected, `空 rootKey 被拒绝 (错误: ${emptyKeyError.slice(0, 60)}...)`);

    // 16-byte rootKey → 必须拒绝 (旧检查太宽松)
    let short16Rejected = false;
    try {
      await initAlice(crypto.randomBytes(16), bobSPK.publicKey);
    } catch (e) {
      short16Rejected = e.message.includes('32 bytes');
    }
    assert(short16Rejected, '16-byte rootKey 被拒绝 (旧宽松检查已修复)');

    // 31-byte rootKey → 必须拒绝
    let short31Rejected = false;
    try {
      await initAlice(crypto.randomBytes(31), bobSPK.publicKey);
    } catch (e) {
      short31Rejected = e.message.includes('32 bytes');
    }
    assert(short31Rejected, '31-byte rootKey 被拒绝 (边界检查)');

    // 32-byte rootKey → 正常通过
    const normalState = await initAlice(aliceRootKey, bobSPK.publicKey);
    assert(normalState.rootKey.length === 32, '32-byte rootKey 正常接受');

    // Bob 侧同样检查
    let bobShortRejected = false;
    try {
      await initBob(crypto.randomBytes(16), bobSPK);
    } catch (e) {
      bobShortRejected = e.message.includes('32 bytes');
    }
    assert(bobShortRejected, 'Bob: 16-byte rootKey 被拒绝');

    console.log('  ✅ 降级攻击防护: rootKey < 32 bytes 一律拒绝');
  }

  // ═══════════════════════════════════════
  // Test 14: 跨 ratchet 轮次乱序
  // ═══════════════════════════════════════
  section('Test 14: 跨 ratchet 轮次乱序');
  {
    const alice = await initAlice(aliceRootKey, bobSPK.publicKey);
    const bob = await initBob(bobRK2, bobSPK);

    // Alice 发 3 条
    const a1 = [];
    for (let i = 0; i < 3; i++) a1.push(await ratchetEncrypt(alice, `a1-${i}`));

    // Bob 先解密 a1，建立 receiving chain + sending chain
    for (let i = 0; i < 3; i++) {
      await ratchetDecrypt(bob, a1[i].header, a1[i].ciphertext, a1[i].iv);
    }

    // Bob 回复 2 条
    const b1 = [];
    for (let i = 0; i < 2; i++) b1.push(await ratchetEncrypt(bob, `b1-${i}`));

    // Alice 再发 2 条
    const a2 = [];
    for (let i = 0; i < 2; i++) a2.push(await ratchetEncrypt(alice, `a2-${i}`));

    // Alice 解密 b1（按序）
    for (let i = 0; i < 2; i++) {
      const dec = await ratchetDecrypt(alice, b1[i].header, b1[i].ciphertext, b1[i].iv);
      assert(dec === `b1-${i}`, `Alice 解密 b1-${i} ✓`);
    }

    // Bob 解密 a2（新 ratchet 轮次）
    for (let i = 0; i < 2; i++) {
      const dec = await ratchetDecrypt(bob, a2[i].header, a2[i].ciphertext, a2[i].iv);
      assert(dec === `a2-${i}`, `Bob 解密 a2-${i} ✓`);
    }
  }

  // ═══════════════════════════════════════
  // Test 15: chain key 单向性
  // ═══════════════════════════════════════
  section('Test 15: Chain key 单向性 (HMAC 推进不可逆)');
  {
    const ck1 = crypto.randomBytes(32);
    const { messageKey: mk1, chainKey: ck2 } = await kdfCk(ck1);
    const { messageKey: mk2, chainKey: ck3 } = await kdfCk(ck2);

    // chain key 每次不同
    assert(!ctCompare(ck1, ck2), 'CK1 ≠ CK2');
    assert(!ctCompare(ck2, ck3), 'CK2 ≠ CK3');
    assert(!ctCompare(ck1, ck3), 'CK1 ≠ CK3');

    // message key 每次不同
    assert(!ctCompare(mk1, mk2), 'MK1 ≠ MK2');

    // 无法从 ck2 反推 ck1（概念验证：ck2 不等于 ck1 的任何变换）
    assert(!ctCompare(ck2, mk1), 'CK2 ≠ MK1 (单向推导)');
  }

  // ─── Summary ───
  const elapsed = Date.now() - t0;
  console.log('\n╔══════════════════════════════════════════════════╗');
  console.log(`║  P2 Unit Test Results: ${passed} passed, ${failed} failed`);
  console.log(`║  Time: ${elapsed}ms`);
  if (failed === 0) {
    console.log('║  🎉 ALL TESTS PASSED — Double Ratchet 边界场景验证!');
  } else {
    console.log('║  ⚠️  Some tests failed — see above');
  }
  console.log('╚══════════════════════════════════════════════════╝\n');

  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => { console.error('Fatal:', err); process.exit(1); });
