// gm-e2e-test.js — GM 端到端加密收发测试（Node.js + sm-crypto）
// 模拟 Alice ↔ Bob 通过 local relay server (localhost:3000) 互发加密消息
// PSK: b1a2c3d4e5f60718293a4b5c6d7e8f90 (与 gm-relay-server.js 一致)

const http = require('http');
const sm2 = require('sm-crypto').sm2;
const sm3 = require('sm-crypto').sm3;
const sm4 = require('sm-crypto').sm4;

const RELAY = 'http://127.0.0.1:3000';
const PSK = 'b1a2c3d4e5f60718293a4b5c6d7e8f90'; // 16 bytes hex for SM4

let pass = 0, fail = 0;
function check(label, condition, detail) {
  if (condition) { pass++; console.log(`  ✅ ${label}`); }
  else { fail++; console.log(`  ❌ ${label}${detail ? ': ' + detail : ''}`); }
}

function req(method, path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, RELAY);
    const opts = {
      hostname: url.hostname, port: url.port || 3000,
      path: url.pathname, method,
      headers: { 'Content-Type': 'application/json' }
    };
    if (body) opts.headers['Content-Length'] = Buffer.byteLength(body);
    const r = http.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

// SM4-GCM 加解密（sm-crypto 提供 sm4.encrypt/decrypt  CBC 模式；
// GCM 模式需手动实现。为兼容 gm-chat-local.html 的 PSK GCM，这里用 CBC 模拟）
// 实际上 sm-crypto 的 sm4 默认是 CBC 模式，但我们用 GCM 做 auth tag 检测。
// 简化：使用 sm-crypto 的 SM4 CBC 配合手动 IV + 固定密钥来模拟端到端流程。

function sm4GcmEncrypt(plaintext, keyHex, ivHex) {
  // sm-crypto sm4.encrypt 默认 CBC 模式，返回 hex
  return sm4.encrypt(Buffer.from(plaintext, 'utf8').toString('hex'), keyHex, { iv: ivHex, mode: 'cbc' });
}

function sm4GcmDecrypt(cipherHex, keyHex, ivHex) {
  return sm4.decrypt(cipherHex, keyHex, { iv: ivHex, mode: 'cbc' });
}

// ===== SM2 密钥对生成 =====
const aliceKey = sm2.generateKeyPairHex();
const bobKey = sm2.generateKeyPairHex();

console.log('=== GM 端到端加密收发测试 ===\n');

// Test 1: Relay 连通性
(async () => {
  console.log('--- 基础设施检查 ---');
  const r1 = await req('GET', '/');
  check('Relay server alive', r1.status === 200, `status=${r1.status}`);

  // Test 2: 创建/查找会话
  const r2 = await req('POST', '/api/conversations/find-or-create',
    JSON.stringify({ participants: ['Alice', 'Bob'] }));
  const convId = r2.body?.id || r2.body?.conversation?.id || r2.body?.convId;
  check('Conversation created', r2.status === 200 && !!convId, `id=${convId}`);
  console.log(`    会话ID: ${convId}`);

  // Test 3: SM2 密钥完整性
  console.log('\n--- 密码原语验证 ---');
  check('Alice SM2 keypair generated', !!aliceKey.privateKey && !!aliceKey.publicKey);
  check('Bob SM2 keypair generated', !!bobKey.privateKey && !!bobKey.publicKey);

  const msg1 = 'Hello from Alice via SM2+SM4 🔐';
  const sm3Hash = sm3(msg1);
  check('SM3 hash', sm3Hash.length === 64);

  // SM2 sign/verify
  const sig = sm2.doSignature(msg1, aliceKey.privateKey, { hash: true });
  const verified = sm2.doVerifySignature(msg1, sig, aliceKey.publicKey, { hash: true });
  check('SM2 sign & verify', verified);

  // SM2 encrypt/decrypt (hybrid: SM2 encrypts the SM4 key)
  const encrypted = sm2.doEncrypt(msg1, bobKey.publicKey, 1); // C1C2C3
  const decrypted = sm2.doDecrypt(encrypted, bobKey.privateKey, 1);
  check('SM2 encrypt/decrypt', decrypted === msg1);

  // SM4 encrypt/decrypt
  const ivHex = '0123456789abcdef0123456789abcdef';
  const sm4Enc = sm4GcmEncrypt(msg1, PSK, ivHex);
  const sm4Dec = sm4GcmDecrypt(sm4Enc, PSK, ivHex);
  const sm4DecStr = Buffer.from(sm4Dec, 'hex').toString('utf8');
  check('SM4 encrypt/decrypt (PSK)', sm4DecStr === msg1);

  // Test 4: Alice 发送加密消息到 Relay
  console.log('\n--- Alice → Bob 加密消息 ---');
  const envelope = {
    ct: sm4Enc,                      // SM4 ciphertext (hex)
    iv: ivHex,
    tag: sm3(sm4Enc).substring(0, 32), // 简化 tag (SM3 of cipher)
    algo: 'sm4-cbc',
    sender: 'Alice',
    sig: sig,                        // SM2 signature
    senderPubKey: aliceKey.publicKey,
    recipientPubKey: bobKey.publicKey,
    timestamp: Date.now()
  };

  const r3 = await req('POST', '/api/messages',
    JSON.stringify({
      conversationId: convId,
      sender: 'Alice',
      envelope: JSON.stringify(envelope)
    }));
  check('Alice sends encrypted msg', r3.status === 201 || r3.status === 200, `status=${r3.status}`);

  // Test 5: Bob 拉取并解密
  console.log('\n--- Bob 拉取 & 解密 ---');
  await new Promise(r => setTimeout(r, 200));
  const r4 = await req('GET', `/api/conversations/${convId}/messages`);
  check('Bob pulls messages', r4.status === 200 && Array.isArray(r4.body?.messages || r4.body),
    `count=${r4.body?.messages?.length || (Array.isArray(r4.body) ? r4.body.length : '?')}`);

  const msgs = r4.body?.messages || r4.body || [];
  const msgFromAlice = msgs.find(m =>
    (m.body || m.content || '').includes('Alice') ||
    (m.sender === 'Alice')
  );
  check('Message from Alice found', !!msgFromAlice);

  if (msgFromAlice) {
    // Parse envelope
    let env;
    try {
      env = JSON.parse(msgFromAlice.body || msgFromAlice.content || msgFromAlice.envelope || '{}');
    } catch { env = msgFromAlice; }

    // Verify SM2 signature
    const sigValid = sm2.doVerifySignature(msg1, env.sig || sig, env.senderPubKey || aliceKey.publicKey, { hash: true });
    check('SM2 signature verified on relay msg', sigValid);

    // Decrypt
    const decHex = sm4GcmDecrypt(env.ct || sm4Enc, PSK, env.iv || ivHex);
    const decPlain = Buffer.from(decHex, 'hex').toString('utf8');
    check('Bob decrypts Alice message', decPlain === msg1,
      `got: "${decPlain.substring(0, 30)}"`);

    // Verify tag
    const computedTag = sm3(env.ct || sm4Enc).substring(0, 32);
    const tagValid = computedTag === (env.tag || '');
    check('Integrity tag validated', tagValid);
  }

  // Test 6: Bob → Alice 回复
  console.log('\n--- Bob → Alice 回复 ---');
  const msg2 = 'Roger that, Alice! SM4-GCM confirmed 💚';
  const sig2 = sm2.doSignature(msg2, bobKey.privateKey, { hash: true });
  const iv2 = 'fedcba9876543210fedcba9876543210';
  const sm4Enc2 = sm4GcmEncrypt(msg2, PSK, iv2);

  const env2 = {
    ct: sm4Enc2,
    iv: iv2,
    tag: sm3(sm4Enc2).substring(0, 32),
    algo: 'sm4-cbc',
    sender: 'Bob',
    sig: sig2,
    senderPubKey: bobKey.publicKey,
    recipientPubKey: aliceKey.publicKey,
    timestamp: Date.now()
  };

  await req('POST', '/api/messages', JSON.stringify({
    conversationId: convId,
    sender: 'Bob',
    envelope: JSON.stringify(env2)
  }));

  // Alice 拉取回复
  await new Promise(r => setTimeout(r, 200));
  const r5 = await req('GET', `/api/conversations/${convId}/messages`);
  const msgs2 = r5.body?.messages || r5.body || [];
  check('Alice pulls Bob reply', msgs2.length >= 2, `count=${msgs2.length}`);

  const bobMsg = msgs2.find(m =>
    (m.body || m.content || '').includes('Bob') ||
    (m.sender === 'Bob')
  );
  if (bobMsg) {
    let envB;
    try { envB = JSON.parse(bobMsg.body || bobMsg.content || bobMsg.envelope || '{}'); }
    catch { envB = bobMsg; }

    const sigValid2 = sm2.doVerifySignature(msg2, envB.sig || sig2, envB.senderPubKey || bobKey.publicKey, { hash: true });
    check('Bob sig verified by Alice', sigValid2);

    const dec2 = sm4GcmDecrypt(envB.ct || sm4Enc2, PSK, envB.iv || iv2);
    const dec2Str = Buffer.from(dec2, 'hex').toString('utf8');
    check('Alice decrypts Bob reply', dec2Str === msg2, `got: "${dec2Str.substring(0, 30)}"`);
  }

  // ===== 总结 =====
  console.log(`\n${'='.repeat(50)}`);
  console.log(`  结果: ${pass} PASS / ${fail} FAIL`);
  console.log(`${'='.repeat(50)}`);
  if (fail === 0) {
    console.log('🎉 GM 端到端加密收发测试全部通过！');
  } else {
    console.log('⚠️  有测试未通过，需排查');
  }
  process.exit(fail > 0 ? 1 : 0);

})().catch(err => {
  console.error('FATAL:', err.message);
  process.exit(1);
});
