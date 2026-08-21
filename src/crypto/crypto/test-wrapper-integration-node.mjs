/**
 * ml-kem-768-wrapper Integration Test (Node.js)
 * Verifies WASM-first strategy with pure JS fallback
 */
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============================================================
// Simulate browser environment for WASM loading
// ============================================================
globalThis.window = globalThis;

// ============================================================
// Stage 1: Load pure JS ML-KEM-768 (simulating <script> tag)
// ============================================================
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const PureJS = require('./ml-kem-768.js');

// Set on window (as index.html does via <script>)
globalThis.window.MLKEM768 = PureJS;

console.log('Stage 1: Pure JS loaded on window.MLKEM768');
console.log('  PureJS.generateKeypair:', typeof PureJS.generateKeypair);
console.log('  PureJS.encapsulate:', typeof PureJS.encapsulate);
console.log('  PureJS.decapsulate:', typeof PureJS.decapsulate);

// ============================================================
// Stage 2: Override fetch to serve WASM from disk
// ============================================================
const wasmPath = join(__dirname, 'pq-wasm-pkg', 'fibemate_pq_wasm_bg.wasm');
const wasmBytes = readFileSync(wasmPath);

globalThis.fetch = async (url) => {
  if (typeof url === 'string' && url.includes('fibemate_pq_wasm_bg.wasm')) {
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () => wasmBytes.buffer.slice(0),
    };
  }
  throw new Error(`Unexpected fetch: ${url}`);
};

// Also mock import() for wasm module
// Node.js's dynamic import() with relative paths works from the caller's context,
// but since this wrapper uses import('./pq-wasm-pkg/...') and we're in the 
// crypto/ directory, it should resolve correctly.
// Let's create a simple redirect:
const wasmModulePath = join(__dirname, 'pq-wasm-pkg', 'fibemate_pq_wasm.js');
// Dynamic import of a file:// URL works in Node.js
globalThis.__WASM_MODULE_URL__ = new URL(wasmModulePath, import.meta.url).href;

// ============================================================
// Stage 3: Load the unified wrapper
// ============================================================
console.log('\nStage 3: Loading unified wrapper...');
await import('./ml-kem-768-wrapper.js');

// Wait for auto-init
await new Promise(r => setTimeout(r, 500));

const mlkem = globalThis.window.MLKEM768;
console.log(`  initialized: ${mlkem.initialized}`);
console.log(`  engine: ${mlkem.getStatus().engine}`);

// ============================================================
// Stage 4: Run functional tests
// ============================================================
console.log('\n=== Stage 4: Functional Tests ===');

let pass = 0, fail = 0;
function check(name, condition, detail = '') {
  if (condition) {
    console.log(`  ✅ ${name}${detail ? ': ' + detail : ''}`);
    pass++;
  } else {
    console.log(`  ❌ ${name}${detail ? ': ' + detail : ''}`);
    fail++;
  }
}

// 4a: API surface
const api = mlkem;
check('init() returns Promise', api.init() instanceof Promise);
check('keygen() exists', typeof api.keygen === 'function');
check('encaps() exists', typeof api.encaps === 'function');
check('decaps() exists', typeof api.decaps === 'function');
check('getStatus() returns object', typeof api.getStatus() === 'object');

// 4b: Key generation
const kp = api.keygen();
check('publicKey is Uint8Array', kp.publicKey instanceof Uint8Array, `len=${kp.publicKey.length}`);
check('publicKey = 1184 bytes', kp.publicKey.length === 1184);
check('secretKey is Uint8Array', kp.secretKey instanceof Uint8Array, `len=${kp.secretKey.length}`);
check('secretKey = 2400 bytes', kp.secretKey.length === 2400);

// 4c: Encapsulation
const enc = api.encaps(kp.publicKey);
check('ciphertext is Uint8Array', enc.ciphertext instanceof Uint8Array, `len=${enc.ciphertext.length}`);
check('ciphertext = 1088 bytes', enc.ciphertext.length === 1088);
check('sharedSecret is Uint8Array', enc.sharedSecret instanceof Uint8Array, `len=${enc.sharedSecret.length}`);
check('sharedSecret = 32 bytes', enc.sharedSecret.length === 32);

// 4d: Decapsulation
const dec = api.decaps(kp.secretKey, enc.ciphertext);
check('decaps result is Uint8Array', dec instanceof Uint8Array, `len=${dec.length}`);
check('decaps result = 32 bytes', dec.length === 32);

// 4e: Roundtrip
const match = Buffer.from(enc.sharedSecret).equals(Buffer.from(dec));
check('Encap/Decap roundtrip', match, match ? 'SS matches' : 'SS MISMATCH');

// 4f: Multiple roundtrips
console.log('\n  --- Multi-round (20×) ---');
let roundtripOk = 0;
for (let i = 0; i < 20; i++) {
  const kp2 = api.keygen();
  const enc2 = api.encaps(kp2.publicKey);
  const dec2 = api.decaps(kp2.secretKey, enc2.ciphertext);
  if (Buffer.from(enc2.sharedSecret).equals(Buffer.from(dec2))) {
    roundtripOk++;
  }
}
check(`20× roundtrip`, roundtripOk === 20, `${roundtripOk}/20`);

// 4g: Performance benchmark
console.log('\n  --- Performance (100×) ---');
const warmup = 5;
for (let i = 0; i < warmup; i++) { api.keygen(); api.encaps(kp.publicKey); api.decaps(kp.secretKey, enc.ciphertext); }

const trials = 100;
let kgTime = 0, encTime = 0, decTime = 0;
for (let i = 0; i < trials; i++) {
  const t0 = performance.now();
  const kp3 = api.keygen();
  kgTime += performance.now() - t0;
  
  const t1 = performance.now();
  const enc3 = api.encaps(kp3.publicKey);
  encTime += performance.now() - t1;
  
  const t2 = performance.now();
  api.decaps(kp3.secretKey, enc3.ciphertext);
  decTime += performance.now() - t2;
}

const engine = api.getStatus().engine;
console.log(`  Engine: ${engine.toUpperCase()}`);
console.log(`  Keygen: ${(kgTime / trials).toFixed(2)}ms`);
console.log(`  Encaps: ${(encTime / trials).toFixed(2)}ms`);
console.log(`  Decaps: ${(decTime / trials).toFixed(2)}ms`);

// ============================================================
// Summary
// ============================================================
console.log(`\n========================================`);
console.log(`RESULTS: ${pass} passed, ${fail} failed out of ${pass + fail}`);
console.log(`Engine: ${api.getStatus().engine}`);
console.log(`========================================`);

if (fail > 0) process.exit(1);
