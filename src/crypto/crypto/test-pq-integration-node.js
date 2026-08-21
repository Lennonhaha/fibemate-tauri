/**
 * PQXDH Integration Test - Node.js version
 * Tests the WASM-compatible wrapper interface
 */

const fs = require('fs');
const path = require('path');

// Read and evaluate the ML-KEM implementation
const mlKemCode = fs.readFileSync(path.join(__dirname, 'ml-kem-768.js'), 'utf8');
eval(mlKemCode);

// Read and evaluate the wrapper
const wrapperCode = fs.readFileSync(path.join(__dirname, 'ml-kem-768-wrapper.js'), 'utf8');
eval(wrapperCode);

function eq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

console.log('=== PQXDH Integration Test (Node.js) ===\n');

// Test 1: Wrapper initialization
console.log('Test 1: Wrapper init');
if (global.MLKEM768 && global.MLKEM768.initialized) {
  console.log('  MLKEM768 wrapper initialized: OK');
} else {
  console.log('  MLKEM768 not initialized, calling init...');
  global.MLKEM768.init().then(() => {
    console.log('  MLKEM768 initialized after init(): OK');
  }).catch(err => {
    console.log('  ERROR: ' + err.message);
  });
}

// Test 2: Keygen (WASM format)
console.log('\nTest 2: Keygen (WASM format)');
try {
  const kp = global.MLKEM768.keygen();
  console.log('  public_key: ' + kp.public_key.length + ' bytes (exp 1184) ' + (kp.public_key.length === 1184 ? 'OK' : 'FAIL'));
  console.log('  secret_key: ' + kp.secret_key.length + ' bytes (exp 2400) ' + (kp.secret_key.length === 2400 ? 'OK' : 'FAIL'));
} catch (e) {
  console.log('  ERROR: ' + e.message);
}

// Test 3: Encaps/Decaps (WASM format)
console.log('\nTest 3: Encaps/Decaps (WASM format)');
try {
  const kp = global.MLKEM768.keygen();
  const enc = global.MLKEM768.encaps(kp.public_key);
  console.log('  ciphertext: ' + enc.ciphertext.length + ' bytes (exp 1088) ' + (enc.ciphertext.length === 1088 ? 'OK' : 'FAIL'));
  console.log('  shared_secret: ' + enc.shared_secret.length + ' bytes (exp 32) ' + (enc.shared_secret.length === 32 ? 'OK' : 'FAIL'));
  
  const ss2 = global.MLKEM768.decaps(kp.secret_key, enc.ciphertext);
  const match = eq(enc.shared_secret, ss2);
  console.log('  match: ' + (match ? 'OK' : 'FAIL'));
} catch (e) {
  console.log('  ERROR: ' + e.message);
  console.error(e);
}

// Test 4: Multiple iterations
console.log('\nTest 4: 3 Iterations');
let pass = 0;
for (let i = 0; i < 3; i++) {
  try {
    const kp = global.MLKEM768.keygen();
    const enc = global.MLKEM768.encaps(kp.public_key);
    const ss2 = global.MLKEM768.decaps(kp.secret_key, enc.ciphertext);
    if (eq(enc.shared_secret, ss2)) pass++;
  } catch (e) {
    console.log('  iter ' + i + ': ERROR - ' + e.message);
  }
}
console.log('  passed: ' + pass + '/3 ' + (pass === 3 ? 'OK' : 'FAIL'));

console.log('\n=== Done ===');
