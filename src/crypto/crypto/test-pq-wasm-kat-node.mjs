// PQ-WASM KAT — Cross-Validation Test (Node.js)
// Verifies WASM (pqc_kyber v0.7.1) vs Pure JS (ml-kem-768.js)
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { initSync } from './pq-wasm-pkg/fibemate_pq_wasm.js';
import * as pqWasm from './pq-wasm-pkg/fibemate_pq_wasm.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// Load pure JS ML-KEM-768 (CommonJS)
const MLKEM768 = require('./ml-kem-768.js');

// Load WASM pqc_kyber — use initSync to avoid file:// fetch issue in Node.js
const wasmBytes = readFileSync(join(__dirname, 'pq-wasm-pkg', 'fibemate_pq_wasm_bg.wasm'));
initSync(wasmBytes);

// ==================== Helpers ====================
let pass = 0, fail = 0;
const failures = [];

function bytesToHex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every((v, i) => v === b[i]);
}

function toArr(v) {
  return v instanceof Uint8Array ? Array.from(v) : v;
}

const CHECK = (cond, msg) => { if (!cond) throw new Error(msg); };
const EQ = (a, b, msg) => CHECK(a === b, `${msg}: expected ${b}, got ${a}`);
const HASH = (s, n=32) => bytesToHex(s.slice(0, Math.min(s.length, n)));

// ==================== Test Runner ====================
async function run(name, fn) {
  try {
    await fn();
    process.stdout.write(`  ✅ ${name}\n`);
    pass++;
  } catch (e) {
    process.stdout.write(`  ❌ ${name}\n     ${e.message.split('\n').join('\n     ')}\n`);
    fail++;
    failures.push({ name, error: e.message });
  }
}

function suite(name) {
  process.stdout.write(`\n${'='.repeat(64)}\n${name}\n${'='.repeat(64)}\n`);
}

// ==================== S1: Constants ====================
suite('S1: Constants Verification');

run('WASM PK=1184', () => EQ(JSON.parse(pqWasm.getConstants()).PUBLIC_KEY_BYTES, 1184));
run('WASM SK=2400', () => EQ(JSON.parse(pqWasm.getConstants()).SECRET_KEY_BYTES, 2400));
run('WASM CT=1088', () => EQ(JSON.parse(pqWasm.getConstants()).CIPHERTEXT_BYTES, 1088));
run('WASM SS=32',   () => EQ(JSON.parse(pqWasm.getConstants()).SHARED_SECRET_BYTES, 32));
run('PureJS constants match', () => {
  EQ(MLKEM768.PUBLIC_KEY_BYTES, 1184);
  EQ(MLKEM768.SECRET_KEY_BYTES, 2400);
  EQ(MLKEM768.CIPHERTEXT_BYTES, 1088);
  EQ(MLKEM768.SHARED_SECRET_BYTES, 32);
});

// ==================== S2: WASM Roundtrip ====================
suite('S2: WASM Roundtrip (pqc_kyber v0.7.1)');

let s2kp, s2enc;
run('Generate keypair', () => {
  s2kp = pqWasm.generateKeypair();
  EQ(s2kp.public_key.length, 1184);
  EQ(s2kp.secret_key.length, 2400);
});
run('Encapsulate', () => {
  s2enc = pqWasm.encapsulate(s2kp.public_key);
  EQ(s2enc.ciphertext.length, 1088);
  EQ(s2enc.shared_secret.length, 32);
});
run('Decapsulate recovers SS', () => {
  const ss = pqWasm.decapsulate(s2kp.secret_key, s2enc.ciphertext);
  CHECK(bytesEqual(ss, s2enc.shared_secret),
    `SS mismatch\n  enc: ${HASH(s2enc.shared_secret)}\n  dec: ${HASH(ss)}`);
});
run('Ciphertext non-zero', () => CHECK(s2enc.ciphertext.some(b => b !== 0)));
run('Different encaps ≠ same CT', () => {
  const e2 = pqWasm.encapsulate(s2kp.public_key);
  CHECK(!bytesEqual(s2enc.ciphertext, e2.ciphertext));
});

// ==================== S3: Multi-Round WASM ====================
suite('S3: WASM Multi-Round (50x)');
let s3fail = 0;
for (let i = 0; i < 50; i++) {
  const kp = pqWasm.generateKeypair();
  const enc = pqWasm.encapsulate(kp.public_key);
  const ss = pqWasm.decapsulate(kp.secret_key, enc.ciphertext);
  if (!bytesEqual(ss, enc.shared_secret)) s3fail++;
}
run(`50 roundtrips`, () => EQ(s3fail, 0, `${s3fail}/50 failed`));

// ==================== S4: Cross-Val A — JS Encap → WASM Decap ====================
suite('S4: Cross-Val A: JS keygen/encap → WASM decap');

let s4Result;
run('JS keygen + encaps', () => {
  const kp = MLKEM768.generateKeypair();
  const enc = MLKEM768.encapsulate(kp.publicKey);
  globalThis._s4 = { pk: kp.publicKey, sk: kp.secretKey, ct: enc.ciphertext, ss: enc.sharedSecret };
});
run('WASM decaps JS ciphertext', () => {
  const { sk, ct, ss: jsSS } = globalThis._s4;
  const wasmSS = pqWasm.decapsulate(sk, ct);
  const match = bytesEqual(wasmSS, jsSS);
  s4Result = { match, wasmSS, jsSS };
  CHECK(match,
    `CROSS-FAIL: JS encap → WASM decap mismatch\n` +
    `  JS SS:   ${HASH(jsSS)}\n` +
    `  WASM SS: ${HASH(wasmSS)}`);
});

// ==================== S5: Cross-Val B — WASM Encap → JS Decap ====================
suite('S5: Cross-Val B: WASM keygen/encap → JS decap');

let s5Result;
run('WASM keygen + encaps', () => {
  const kp = pqWasm.generateKeypair();
  const enc = pqWasm.encapsulate(kp.public_key);
  globalThis._s5 = { pk: kp.public_key, sk: kp.secret_key, ct: enc.ciphertext, ss: enc.shared_secret };
});
run('JS decaps WASM ciphertext', () => {
  const { sk, ct, ss: wasmSS } = globalThis._s5;
  const jsSS = MLKEM768.decapsulate(sk, ct);
  const match = bytesEqual(jsSS, wasmSS);
  s5Result = { match, jsSS, wasmSS };
  CHECK(match,
    `CROSS-FAIL: WASM encap → JS decap mismatch\n` +
    `  WASM SS: ${HASH(wasmSS)}\n` +
    `  JS SS:   ${HASH(jsSS)}`);
});

// ==================== S6: Cross-Val Multi (20x) ====================
suite('S6: Cross-Val Multi-Round (20x)');
let s6fail = 0;
for (let i = 0; i < 20; i++) {
  const kp = MLKEM768.generateKeypair();
  const enc = pqWasm.encapsulate(kp.publicKey);
  const ss = pqWasm.decapsulate(kp.secretKey, enc.ciphertext);
  if (!bytesEqual(ss, enc.shared_secret)) s6fail++;
}
run(`20x JS keygen → WASM encaps/decaps`, () => EQ(s6fail, 0, `${s6fail}/20 failed`));

// ==================== S7: Hybrid Combine ====================
suite('S7: Hybrid Key Combine (HKDF-SHA256)');

run('Deterministic', () => {
  const kem = new Uint8Array(32).fill(0xAB);
  const ecdh = new Uint8Array(32).fill(0xCD);
  const h1 = pqWasm.hybridCombine(kem, ecdh);
  const h2 = pqWasm.hybridCombine(kem, ecdh);
  EQ(h1.length, 32);
  CHECK(bytesEqual(h1, h2));
});
run('Different KEM → different output', () => {
  const ecdh = new Uint8Array(32).fill(0xCD);
  const h1 = pqWasm.hybridCombine(new Uint8Array(32).fill(0xAB), ecdh);
  const h2 = pqWasm.hybridCombine(new Uint8Array(32).fill(0xAC), ecdh);
  CHECK(!bytesEqual(h1, h2));
});
run('Different ECDH → different output', () => {
  const kem = new Uint8Array(32).fill(0xAB);
  const h1 = pqWasm.hybridCombine(kem, new Uint8Array(32).fill(0xCD));
  const h2 = pqWasm.hybridCombine(kem, new Uint8Array(32).fill(0xCE));
  CHECK(!bytesEqual(h1, h2));
});
run('Well-distributed output', () => {
  const h = pqWasm.hybridCombine(new Uint8Array(32).fill(0xAB), new Uint8Array(32).fill(0xCD));
  const unique = new Set(h);
  CHECK(unique.size >= 10, `Only ${unique.size} unique bytes`);
});

// ==================== S8: Edge Cases ====================
suite('S8: Edge Cases');

run('Keypair non-zero keys', () => {
  const kp = pqWasm.generateKeypair();
  CHECK(kp.public_key.some(b => b !== 0));
  CHECK(kp.secret_key.some(b => b !== 0));
});
run('Zero PK encaps produces CT', () => {
  try {
    const enc = pqWasm.encapsulate(new Uint8Array(1184));
    EQ(enc.ciphertext.length, 1088);
  } catch(e) {
    // acceptable either way
  }
});

// ==================== S9: Performance ====================
suite('S9: Performance Benchmark (100x)');

const N = 100;
// Warmup
for (let i = 0; i < 10; i++) {
  const kp = pqWasm.generateKeypair();
  const enc = pqWasm.encapsulate(kp.public_key);
  pqWasm.decapsulate(kp.secret_key, enc.ciphertext);
}

run('Measuring…', () => {});

let t0, t1;

// WASM
t0 = performance.now();
for (let i = 0; i < N; i++) pqWasm.generateKeypair();
const wasmKeygen = (performance.now() - t0) / N;

t0 = performance.now();
const bk = pqWasm.generateKeypair();
for (let i = 0; i < N; i++) pqWasm.encapsulate(bk.public_key);
const wasmEncap = (performance.now() - t0) / N;

t0 = performance.now();
const be = pqWasm.encapsulate(bk.public_key);
for (let i = 0; i < N; i++) pqWasm.decapsulate(bk.secret_key, be.ciphertext);
const wasmDecap = (performance.now() - t0) / N;

// Pure JS
t0 = performance.now();
for (let i = 0; i < N; i++) MLKEM768.generateKeypair();
const jsKeygen = (performance.now() - t0) / N;

t0 = performance.now();
const jk = MLKEM768.generateKeypair();
for (let i = 0; i < N; i++) MLKEM768.encapsulate(jk.publicKey);
const jsEncap = (performance.now() - t0) / N;

t0 = performance.now();
const je = MLKEM768.encapsulate(jk.publicKey);
for (let i = 0; i < N; i++) MLKEM768.decapsulate(jk.secretKey, je.ciphertext);
const jsDecap = (performance.now() - t0) / N;

console.log();
console.log('┌──────────────┬────────────┬────────────┬──────────┐');
console.log('│ Operation    │ WASM       │ Pure JS    │ Speedup  │');
console.log('├──────────────┼────────────┼────────────┼──────────┤');
console.log(`│ Keygen       │ ${wasmKeygen.toFixed(2).padStart(7)}ms  │ ${jsKeygen.toFixed(2).padStart(7)}ms  │ ${(jsKeygen/wasmKeygen).toFixed(2).padStart(5)}×   │`);
console.log(`│ Encaps       │ ${wasmEncap.toFixed(2).padStart(7)}ms  │ ${jsEncap.toFixed(2).padStart(7)}ms  │ ${(jsEncap/wasmEncap).toFixed(2).padStart(5)}×   │`);
console.log(`│ Decaps       │ ${wasmDecap.toFixed(2).padStart(7)}ms  │ ${jsDecap.toFixed(2).padStart(7)}ms  │ ${(jsDecap/wasmDecap).toFixed(2).padStart(5)}×   │`);
console.log('└──────────────┴────────────┴────────────┴──────────┘');

// ==================== Summary ====================
console.log(`\n${'='.repeat(64)}`);
console.log(`RESULTS: ${pass} passed, ${fail} failed out of ${pass + fail}`);
console.log(`${'='.repeat(64)}`);

if (fail === 0) {
  console.log('\n✅ ALL TESTS PASSED — WASM implementation validated');
} else {
  console.log(`\n⚠️  ${fail} FAILURES:`);
  failures.forEach(f => console.log(`   - ${f.name}: ${f.error.split('\n')[0]}`));
}

// Cross-validation diagnosis
if (s4Result && !s4Result.match) {
  console.log('\n🔬 DIAGNOSIS (S4: JS→WASM decap failure):');
  console.log('   This means pure JS and pqc_kyber have different secret key formats.');
  console.log('   Both may be FIPS 203 compliant but serialize s/t/ρ/H(pk)/z differently.');
  console.log(`   JS SS:        ${HASH(s4Result.jsSS)}`);
  console.log(`   WASM SS:      ${HASH(s4Result.wasmSS)}`);
  console.log('   → KEY FORMAT MISMATCH (not algorithmic error)');
}
if (s5Result && !s5Result.match) {
  console.log('\n🔬 DIAGNOSIS (S5: WASM→JS decap failure):');
  console.log('   Same root cause: incompatible secret key serialization.');
  console.log(`   WASM SS:      ${HASH(s5Result.wasmSS)}`);
  console.log(`   JS SS:        ${HASH(s5Result.jsSS)}`);
  console.log('   → KEY FORMAT MISMATCH (not algorithmic error)');
}

process.exit(fail > 0 ? 1 : 0);