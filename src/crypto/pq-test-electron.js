/**
 * PQ-WASM Electron Test
 * Run this in Electron DevTools console to test ML-KEM-768
 */

async function runPQTests() {
  console.log('========================================');
  console.log('PQ-WASM Test Suite');
  console.log('========================================\n');
  
  const results = {
    passed: 0,
    failed: 0,
    tests: []
  };
  
  function test(name, fn) {
    return new Promise(async (resolve) => {
      try {
        await fn();
        results.passed++;
        results.tests.push({ name, status: 'PASS' });
        console.log(`✓ ${name}`);
        resolve();
      } catch (err) {
        results.failed++;
        results.tests.push({ name, status: 'FAIL', error: err.message });
        console.error(`✗ ${name}: ${err.message}`);
        resolve();
      }
    });
  }
  
  // Test 1: WASM Module Available
  await test('ML-KEM-768 module exists', () => {
    if (!window.MLKEM768) throw new Error('window.MLKEM768 not found');
  });
  
  // Test 2: Module Initialized
  await test('ML-KEM-768 initialized', () => {
    if (!window.MLKEM768.initialized) throw new Error('Not initialized');
  });
  
  // Test 3: Key Generation
  await test('Generate keypair', async () => {
    const kp = await window.MLKEM768.keygen();
    if (!kp.public_key || kp.public_key.length !== 1184) {
      throw new Error(`Invalid public key: ${kp.public_key?.length} bytes`);
    }
    if (!kp.secret_key || kp.secret_key.length !== 2400) {
      throw new Error(`Invalid secret key: ${kp.secret_key?.length} bytes`);
    }
    window._testKeypair = kp; // Store for later tests
  });
  
  // Test 4: Encapsulation
  await test('Encapsulate', async () => {
    const kp = window._testKeypair;
    const enc = await window.MLKEM768.encaps(kp.public_key);
    if (!enc.ciphertext || enc.ciphertext.length !== 1088) {
      throw new Error(`Invalid ciphertext: ${enc.ciphertext?.length} bytes`);
    }
    if (!enc.shared_secret || enc.shared_secret.length !== 32) {
      throw new Error(`Invalid shared secret: ${enc.shared_secret?.length} bytes`);
    }
    window._testEncapsulation = enc;
  });
  
  // Test 5: Decapsulation
  await test('Decapsulate', async () => {
    const kp = window._testKeypair;
    const enc = window._testEncapsulation;
    const dec = await window.MLKEM768.decaps(kp.secret_key, enc.ciphertext);
    if (!dec || dec.length !== 32) {
      throw new Error(`Invalid decaps result: ${dec?.length} bytes`);
    }
    window._testDecapsulation = dec;
  });
  
  // Test 6: Shared Secret Match
  await test('Shared secrets match', () => {
    const enc = window._testEncapsulation;
    const dec = window._testDecapsulation;
    const match = enc.shared_secret.every((b, i) => b === dec[i]);
    if (!match) throw new Error('Shared secrets do not match!');
  });
  
  // Test 7: PQIntegration Available
  await test('PQIntegration exists', () => {
    if (!window.PQIntegration) throw new Error('PQIntegration not found');
  });
  
  // Test 8: PQ Status
  await test('PQIntegration status', () => {
    const status = window.PQIntegration.getStatus();
    console.log('  Status:', JSON.stringify(status, null, 2));
    if (!status.wasmLoaded) throw new Error('WASM not loaded');
  });
  
  // Test 9: Hybrid Key Generation
  await test('Generate hybrid keys', async () => {
    const keys = await window.PQIntegration.generateHybridKeys();
    if (!keys.kemPublicKey || keys.kemPublicKey.length !== 1184) {
      throw new Error(`Invalid hybrid keys: ${keys.kemPublicKey?.length} bytes`);
    }
  });
  
  // Summary
  console.log('\n========================================');
  console.log(`Results: ${results.passed} passed, ${results.failed} failed`);
  console.log('========================================');
  
  if (results.failed === 0) {
    console.log('✓ ALL TESTS PASSED');
  } else {
    console.error(`✗ ${results.failed} test(s) failed`);
  }
  
  return results;
}

// Auto-run if in browser
if (typeof window !== 'undefined') {
  window.runPQTests = runPQTests;
  console.log('PQ-WASM test suite loaded. Run runPQTests() to execute.');
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { runPQTests };
}
