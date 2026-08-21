// Node.js test for ML-KEM-768
// Run with: node test-ml-kem-node.js

const fs = require('fs');
const path = require('path');

// Read and eval the ML-KEM implementation
const mlkemCode = fs.readFileSync(path.join(__dirname, 'ml-kem-768.js'), 'utf8');
eval(mlkemCode);

console.log('ML-KEM-768 Node.js Test');
console.log('========================');

let passCount = 0;
let failCount = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`✓ ${name}`);
        passCount++;
    } catch (e) {
        console.log(`✗ ${name}: ${e.message}`);
        failCount++;
    }
}

function assertEqual(actual, expected, msg) {
    if (actual !== expected) {
        throw new Error(`${msg}: expected ${expected}, got ${actual}`);
    }
}

// Test 1: Constants
test('Constants', () => {
    assertEqual(MLKEM768.PUBLIC_KEY_BYTES, 1184, 'PUBLIC_KEY_BYTES');
    assertEqual(MLKEM768.SECRET_KEY_BYTES, 2400, 'SECRET_KEY_BYTES');
    assertEqual(MLKEM768.CIPHERTEXT_BYTES, 1088, 'CIPHERTEXT_BYTES');
    assertEqual(MLKEM768.SHARED_SECRET_BYTES, 32, 'SHARED_SECRET_BYTES');
});

// Test 2: Keygen
test('Keypair generation', () => {
    const kp = MLKEM768.generateKeypair();
    assertEqual(kp.publicKey.length, 1184, 'publicKey length');
    assertEqual(kp.secretKey.length, 2400, 'secretKey length');
});

// Test 3: Single roundtrip
test('Single encaps/decaps', () => {
    const kp = MLKEM768.generateKeypair();
    const enc = MLKEM768.encapsulate(kp.publicKey);
    assertEqual(enc.ciphertext.length, 1088, 'ciphertext length');
    assertEqual(enc.sharedSecret.length, 32, 'sharedSecret length');
    
    const ss2 = MLKEM768.decapsulate(kp.secretKey, enc.ciphertext);
    assertEqual(ss2.length, 32, 'decapsulated secret length');
    
    const match = enc.sharedSecret.every((b, i) => b === ss2[i]);
    if (!match) {
        throw new Error(`Shared secret mismatch!\nExpected: ${Buffer.from(enc.sharedSecret).toString('hex').slice(0,16)}...\nGot:      ${Buffer.from(ss2).toString('hex').slice(0,16)}...`);
    }
});

// Test 4: Multiple roundtrips
let multiPass = 0;
const multiTotal = 50;
for (let i = 0; i < multiTotal; i++) {
    try {
        const kp = MLKEM768.generateKeypair();
        const enc = MLKEM768.encapsulate(kp.publicKey);
        const ss2 = MLKEM768.decapsulate(kp.secretKey, enc.ciphertext);
        if (enc.sharedSecret.every((b, j) => b === ss2[j])) multiPass++;
    } catch (e) {
        // silent fail
    }
}
test(`50 roundtrips (${multiPass}/50 pass)`, () => {
    if (multiPass < 50) {
        throw new Error(`Only ${multiPass}/50 passed`);
    }
});

// Test 5: Same keypair, multiple encaps
const kp = MLKEM768.generateKeypair();
let sameKpPass = 0;
const sameKpTotal = 20;
for (let i = 0; i < sameKpTotal; i++) {
    try {
        const enc = MLKEM768.encapsulate(kp.publicKey);
        const ss2 = MLKEM768.decapsulate(kp.secretKey, enc.ciphertext);
        if (enc.sharedSecret.every((b, j) => b === ss2[j])) sameKpPass++;
    } catch (e) {
        // silent fail
    }
}
test(`Same keypair 20x (${sameKpPass}/20 pass)`, () => {
    if (sameKpPass < 20) {
        throw new Error(`Only ${sameKpPass}/20 passed`);
    }
});

console.log('\n========================');
console.log(`Results: ${passCount} passed, ${failCount} failed`);
console.log(`Multi-round: ${multiPass}/${multiTotal}`);
console.log(`Same KP: ${sameKpPass}/${sameKpTotal}`);

if (failCount === 0 && multiPass === multiTotal && sameKpPass === sameKpTotal) {
    console.log('\n✓ ALL TESTS PASSED');
    process.exit(0);
} else {
    console.log('\n✗ SOME TESTS FAILED');
    process.exit(1);
}