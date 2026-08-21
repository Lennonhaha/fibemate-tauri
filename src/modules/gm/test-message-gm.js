/**
 * Self-test: MessageGM module
 * Node.js test — loads all dependencies as browser scripts would
 */
const fs = require('fs');
const path = require('path');

// Load SM3 (exports class SM3 to module)
const SM3Path = path.join(__dirname, 'sm3_implementation.js');
global.window = {};

// Load SM3 via eval-wrapper to avoid double-declaration
(() => {
  const src = fs.readFileSync(SM3Path, 'utf-8')
    .replace(/if \(typeof window !== 'undefined'\) \{\s*window\.SM3 = SM3;\s*\}/, '')
    .replace(/if \(typeof module !== 'undefined' && module\.exports\) \{\s*module\.exports = SM3;\s*\}/, '');
  eval(`(function(){const Module={}; ${src}; global.window.SM3 = SM3;})()`);
})();

// Load SM2Browser bundle (exports to window)
const bundlePath = path.resolve(__dirname, '..', '..', '..', '..', '文件', 'sm2-browser.bundle.js');
eval(fs.readFileSync(bundlePath, 'utf-8'));

// Load MessageGM
eval(fs.readFileSync(path.join(__dirname, 'message-gm.js'), 'utf-8'));
const GM = global.window.MessageGM;

if (!GM) {
  console.error('FAIL: MessageGM not loaded');
  process.exit(1);
}

console.log('=== MessageGM Self-Test ===\n');

// Test 1: Keypair generation
console.log('1. generateKeypair...');
const alice = GM.generateKeypair();
const bob = GM.generateKeypair();
console.log(`   Alice pub: ${alice.publicKey.slice(0, 32)}...`);
console.log(`   Bob   pub: ${bob.publicKey.slice(0, 32)}...`);
console.log('   PASS\n');

// Test 2: Encrypt & Decrypt
console.log('2. encryptMessage / decryptMessage...');
const msg = '你好，世界！FIBEMATE-GM-v1';
const envelope = GM.encryptMessage(msg, bob.publicKey, alice.privateKey);
console.log(`   envelope: ct=${envelope.ciphertext.slice(0, 20)}..., alg=${envelope.algorithm}`);

const result = GM.decryptMessage(envelope, bob.privateKey, alice.publicKey);
if (!result.verified) {
  console.error(`   FAIL: verification failed: ${result.error}`);
  process.exit(1);
}
if (result.plaintext !== msg) {
  console.error(`   FAIL: "${result.plaintext}" !== "${msg}"`);
  process.exit(1);
}
console.log('   PASS\n');

// Test 3: Tamper
console.log('3. Tamper detection...');
const tampered = { ...envelope, ciphertext: '00deadbeef' + envelope.ciphertext.slice(10) };
const tResult = GM.decryptMessage(tampered, bob.privateKey, alice.publicKey);
if (tResult.verified) {
  console.error('   FAIL: not detected');
  process.exit(1);
}
console.log(`   PASS (${tResult.error})\n`);

// Test 4: Wrong key
console.log('4. Wrong key...');
const mallory = GM.generateKeypair();
const wResult = GM.decryptMessage(envelope, mallory.privateKey, alice.publicKey);
if (wResult.verified) {
  console.error('   FAIL: not detected');
  process.exit(1);
}
console.log(`   PASS (${wResult.error})\n`);

// Test 5: Selftest
console.log('5. selftest...');
const st = GM.selftest();
if (!st.ok) {
  console.error(`   FAIL: ${st.err}`);
  process.exit(1);
}
console.log(`   PASS (pub: ${st.publicKey})\n`);

console.log('=== ALL PASSED ===');
process.exit(0);
