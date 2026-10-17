/**
 * ML-KEM-768 KAT Verifier
 * Compares time-domain implementation against NIST intermediate values
 */

const fs = require('fs');
const path = require('path');
const { parseKatFile, convertToInternalFormat } = require('./kat-parser');
const { modAdd, modMul } = require('./ntt-forward');

// NOTE: verification below works off the parsed NIST KAT files (./kat-parser)
// plus the NTT helpers (./ntt-forward); ml-kem-768.js is not loaded here.

/**
 * Compare two polynomials with tolerance
 */
function comparePolynomials(a, b, name, tolerance = 0) {
    if (!a || !b) {
        console.log(`  ${name}: MISSING`);
        return false;
    }
    
    if (a.length !== b.length) {
        console.log(`  ${name}: LENGTH MISMATCH ${a.length} vs ${b.length}`);
        return false;
    }
    
    let mismatches = 0;
    for (let i = 0; i < a.length; i++) {
        const diff = Math.abs(((a[i] % 3329) + 3329) % 3329 - ((b[i] % 3329) + 3329) % 3329);
        if (diff > tolerance) {
            if (mismatches < 3) {
                console.log(`  ${name}[${i}]: ${a[i]} vs ${b[i]} (diff=${diff})`);
            }
            mismatches++;
        }
    }
    
    if (mismatches === 0) {
        console.log(`  ${name}: ✅ MATCH`);
        return true;
    } else {
        console.log(`  ${name}: ❌ ${mismatches}/${a.length} mismatches`);
        return false;
    }
}

/**
 * Compare two k-vectors of polynomials
 */
function compareVectorOfPolynomials(a, b, name) {
    if (!a || !b) {
        console.log(`${name}: MISSING`);
        return false;
    }
    
    if (a.length !== b.length) {
        console.log(`${name}: LENGTH MISMATCH ${a.length} vs ${b.length}`);
        return false;
    }
    
    let allMatch = true;
    for (let i = 0; i < a.length; i++) {
        const match = comparePolynomials(a[i], b[i], `${name}[${i}]`);
        allMatch = allMatch && match;
    }
    
    return allMatch;
}

/**
 * Verify a single KAT test case
 */
function verifyKatTestCase(kat, testIndex) {
    console.log(`\n=== Test Case ${testIndex} ===`);
    console.log(`Type: ${kat.type || 'unknown'}`);
    
    let results = {
        seeds: false,
        aMatrix: false,
        sVector: false,
        eVector: false,
        sHat: false,
        eHat: false,
        tHat: false,
        ek: false,
        dk: false
    };
    
    // Check seeds
    if (kat.d && kat.z) {
        console.log(`d: ${Buffer.from(kat.d).toString('hex').substring(0, 32)}...`);
        console.log(`z: ${Buffer.from(kat.z).toString('hex').substring(0, 32)}...`);
        results.seeds = true;
    }
    
    // For now, we can't fully verify without implementing deterministic keygen
    // Let's verify what we can from the parsed data
    
    // Verify internal consistency: tHat = aHat * sHat + eHat
    if (kat.aHat && kat.sHat && kat.eHat && kat.tHat) {
        console.log('\nVerifying tHat = aHat * sHat + eHat...');
        
        const k = kat.tHat.length;
        let tHatComputed = [];
        
        for (let i = 0; i < k; i++) {
            // tHat[i] = sum_j (aHat[i][j] * sHat[j]) + eHat[i]
            // In NTT domain: pointwise multiplication then add
            let sum = new Array(256).fill(0);
            
            for (let j = 0; j < k; j++) {
                for (let l = 0; l < 256; l++) {
                    sum[l] = modAdd(sum[l], modMul(kat.aHat[i][j][l], kat.sHat[j][l]));
                }
            }
            
            // Add eHat
            for (let l = 0; l < 256; l++) {
                sum[l] = modAdd(sum[l], kat.eHat[i][l]);
            }
            
            tHatComputed.push(sum);
        }
        
        results.tHat = compareVectorOfPolynomials(tHatComputed, kat.tHat, 'tHat_computed');
    }
    
    // Summary
    console.log('\n--- Results ---');
    Object.entries(results).forEach(([key, value]) => {
        console.log(`${key}: ${value ? '✅' : '❌'}`);
    });
    
    return results;
}

/**
 * Main verification
 */
function main() {
    const katDir = path.join(__dirname, '..', 'intermediate-2023', 'PQC Intermediate Values');
    
    // Parse Key Generation KAT
    const keyGenPath = path.join(katDir, 'Key Generation -- ML-KEM-768.txt');
    console.log(`Parsing ${keyGenPath}...`);
    
    if (!fs.existsSync(keyGenPath)) {
        console.error('KAT file not found!');
        process.exit(1);
    }
    
    const testCases = parseKatFile(keyGenPath);
    console.log(`Parsed ${testCases.length} test cases`);
    
    // Verify first test case
    if (testCases.length > 0) {
        const kat = convertToInternalFormat(testCases[0]);
        verifyKatTestCase(kat, 0);
    }
}

// Run if called directly
if (require.main === module) {
    main();
}

module.exports = { verifyKatTestCase, comparePolynomials };
