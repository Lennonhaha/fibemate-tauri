// Fallback test: WASM disabled → pure JS should work
globalThis.window = globalThis;

import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Load pure JS
window.MLKEM768 = require('./ml-kem-768.js');

// Break WASM: no fetch
delete globalThis.fetch;

// Load wrapper (should fall back to JS)
await import('./ml-kem-768-wrapper.js');
await new Promise(r => setTimeout(r, 500));

const m = window.MLKEM768;
console.log('Engine:', m.getStatus().engine);
console.log('Initialized:', m.initialized);

const kp = m.keygen();
const enc = m.encaps(kp.publicKey);
const dec = m.decaps(kp.secretKey, enc.ciphertext);
const ok = Buffer.from(enc.sharedSecret).equals(Buffer.from(dec));
console.log('Roundtrip:', ok ? 'PASS' : 'FAIL');
console.log('PK:', kp.publicKey.length, 'SK:', kp.secretKey.length);

if (!ok || m.getStatus().engine !== 'js') process.exit(1);
