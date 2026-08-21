// Node.js test for ML-KEM-768 fix v2
const fs = require('fs');
const crypto = require('crypto');

// Read the ml-kem-768.js file
const code = fs.readFileSync('./ml-kem-768.js', 'utf8');

// Create a minimal browser environment
global.crypto = {
    getRandomValues: (arr) => crypto.randomFillSync(arr),
    subtle: crypto.webcrypto.subtle
};

// Load the module
eval(code);

function bufToHex(buf) {
    return Array.from(buf).map(b => b.toString(16).padStart(2,'0')).join('');
}

console.log('=== ML-KEM-768 Fix Verification v2 ===\n');

// Test 1: Basic
console.log('--- Test 1: Basic Round Trip ---');
try {
    const kp = MLKEM768.generateKeypair();
    const enc = MLKEM768.encapsulate(kp.publicKey);
    const dec = MLKEM768.decapsulate(kp.secretKey, enc.ciphertext);
    
    const match = bufToHex(enc.sharedSecret) === bufToHex(dec);
    console.log(`Shared secret (enc): ${bufToHex(enc.sharedSecret)}`);
    console.log(`Shared secret (dec): ${bufToHex(dec)}`);
    console.log(`Result: ${match ? 'MATCH ✓' : 'MISMATCH ✗'}`);
} catch(e) {
    console.error('Error:', e.message);
}

// Test 2: 20 rounds
console.log('\n--- Test 2: 20 Rounds ---');
let passCount = 0;
for(let i=0; i<20; i++) {
    try {
        const kp = MLKEM768.generateKeypair();
        const enc = MLKEM768.encapsulate(kp.publicKey);
        const dec = MLKEM768.decapsulate(kp.secretKey, enc.ciphertext);
        if(bufToHex(enc.sharedSecret) === bufToHex(dec)) passCount++;
    } catch(e) {
        console.error(`Round ${i+1} error:`, e.message);
    }
}
console.log(`Passed: ${passCount}/20`);

// Test 3: Same keypair
console.log('\n--- Test 3: Same Keypair, 10x ---');
try {
    const kp = MLKEM768.generateKeypair();
    let sameKpPass = 0;
    for(let i=0; i<10; i++) {
        const enc = MLKEM768.encapsulate(kp.publicKey);
        const dec = MLKEM768.decapsulate(kp.secretKey, enc.ciphertext);
        if(bufToHex(enc.sharedSecret) === bufToHex(dec)) sameKpPass++;
    }
    console.log(`Passed: ${sameKpPass}/10`);
} catch(e) {
    console.error('Error:', e.message);
}

console.log('\n=== Done ===');
