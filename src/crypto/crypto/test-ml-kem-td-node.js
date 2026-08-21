/**
 * ML-KEM-768 Time-Domain Node.js Test
 * Run with: node test-ml-kem-td-node.js
 */

const crypto = require('crypto');

// Polyfill crypto.getRandomValues for Node.js
global.crypto = {
    getRandomValues: (arr) => {
        const buf = crypto.randomBytes(arr.length);
        for (let i = 0; i < arr.length; i++) arr[i] = buf[i];
        return arr;
    },
    subtle: crypto.subtle
};

// Load the implementation
const MLKEM = require('./ml-kem-768-td.js');

function bufEq(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

function bufHex(buf) {
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function runTests() {
    console.log('=== ML-KEM-768 Time-Domain Tests ===\n');
    
    // Test 1: KeyGen
    console.log('Test 1: Key Generation');
    const kp = MLKEM.generateKeypair();
    console.log(`  Public key: ${kp.publicKey.length} bytes (exp ${MLKEM.PUBLIC_KEY_BYTES}) ${kp.publicKey.length === MLKEM.PUBLIC_KEY_BYTES ? '✓' : '✗'}`);
    console.log(`  Secret key: ${kp.secretKey.length} bytes (exp ${MLKEM.SECRET_KEY_BYTES}) ${kp.secretKey.length === MLKEM.SECRET_KEY_BYTES ? '✓' : '✗'}`);
    
    // Test 2: Encaps/Decaps
    console.log('\nTest 2: Encapsulate/Decapsulate');
    const enc = MLKEM.encapsulate(kp.publicKey);
    console.log(`  Ciphertext: ${enc.ciphertext.length} bytes (exp ${MLKEM.CIPHERTEXT_BYTES}) ${enc.ciphertext.length === MLKEM.CIPHERTEXT_BYTES ? '✓' : '✗'}`);
    console.log(`  Shared secret: ${enc.sharedSecret.length} bytes (exp ${MLKEM.SHARED_SECRET_BYTES}) ${enc.sharedSecret.length === MLKEM.SHARED_SECRET_BYTES ? '✓' : '✗'}`);
    
    const ss2 = MLKEM.decapsulate(kp.secretKey, enc.ciphertext);
    const match = bufEq(enc.sharedSecret, ss2);
    console.log(`  Decaps match: ${match ? '✓ PASS' : '✗ FAIL'}`);
    if (!match) {
        console.log(`    Expected: ${bufHex(enc.sharedSecret)}`);
        console.log(`    Got:      ${bufHex(ss2)}`);
    }
    
    // Test 3: Multiple iterations
    console.log('\nTest 3: 20 Iterations');
    let pass = 0;
    const times = [];
    for (let i = 0; i < 20; i++) {
        const t0 = Date.now();
        const kp2 = MLKEM.generateKeypair();
        const enc2 = MLKEM.encapsulate(kp2.publicKey);
        const ss3 = MLKEM.decapsulate(kp2.secretKey, enc2.ciphertext);
        const t1 = Date.now();
        times.push(t1 - t0);
        if (bufEq(enc2.sharedSecret, ss3)) pass++;
    }
    console.log(`  Passed: ${pass}/20 ${pass === 20 ? '✓' : '✗'}`);
    const avg = times.reduce((a,b) => a+b, 0) / times.length;
    console.log(`  Avg time: ${avg.toFixed(1)}ms`);
    
    // Test 4: Wrong ciphertext
    console.log('\nTest 4: Wrong ciphertext (implicit rejection)');
    const kp3 = MLKEM.generateKeypair();
    const enc3 = MLKEM.encapsulate(kp3.publicKey);
    const wrongCt = Buffer.from(enc3.ciphertext);
    wrongCt[0] ^= 0xFF;
    const ssWrong = MLKEM.decapsulate(kp3.secretKey, wrongCt);
    const diff = !bufEq(enc3.sharedSecret, ssWrong);
    console.log(`  Different ss on wrong ct: ${diff ? '✓ PASS' : '✗ FAIL'}`);
    
    // Test 5: Hybrid
    console.log('\nTest 5: Hybrid Key Exchange');
    try {
        const alice = new MLKEM.HybridKeyExchange();
        const bob = new MLKEM.HybridKeyExchange();
        const alicePub = await alice.initialize();
        const bobPub = await bob.initialize();
        
        const aliceEnc = await alice.encapsulateToPeer(bobPub.kemPublicKey, bobPub.ecdhPublicKey);
        const bobSs = await bob.decapsulateFromPeer(aliceEnc.ciphertext, alicePub.ecdhPublicKey);
        
        const hybridMatch = bufEq(aliceEnc.sharedSecret, bobSs);
        console.log(`  Shared secrets match: ${hybridMatch ? '✓ PASS' : '✗ FAIL'}`);
    } catch(e) {
        console.log(`  ERROR: ${e.message}`);
    }
    
    console.log('\n=== Tests Complete ===');
}

runTests().catch(console.error);
