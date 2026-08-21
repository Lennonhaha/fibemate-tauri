/**
 * ML-KEM-768 KAT Verifier
 * Compares time-domain implementation against NIST intermediate values
 */

const fs = require('fs');
const path = require('path');
const { parseKatFile, convertToInternalFormat } = require('./kat-parser');
const { nttForward, modAdd, modMul } = require('./ntt-forward');

// Load the ML-KEM implementation
const mlKemPath = path.join(__dirname, '..', '..', 'crypto', 'crypto', 'ml-kem-768.js');
const mlKemCode = fs.readFileSync(mlKemPath, 'utf8');

// We need to extract functions without the crypto dependency
// Create a modified version for deterministic testing
const modifiedCode = mlKemCode
    .replace('const d = crypto.getRandomValues(new Uint8Array(32));', '// d provided externally')
    .replace('const z = crypto.getRandomValues(new Uint8Array(32));', '// z provided externally');

// For now, let's implement a deterministic keygen that accepts seeds
function deterministicKeygen(d, z) {
    // We'll implement this based on the ML-KEM spec
    // This is a simplified version for KAT verification
    
    // Import required functions from ml-kem-768.js
    // For now, we'll use a subprocess or direct inclusion
    
    // Placeholder: return structure matching expected format
    return {
        rho: null,      // to be filled
        sigma: null,    // to be filled
        s: [],          // time domain
        e: [],          // time domain
        t: [],          // time domain
        pk: null,       // encoded public key
        sk: null        // encoded secret key
    };
}

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
 * Compare two k×k matrices of polynomials
 */
function compareMatrixOfPolynomials(a, b, name) {
    if (!a || !b) {
        console.log(`${name}: MISSING`);
        return false;
    }
    
    if (a.length !== b.length) {
        console.log(`${name}: ROW MISMATCH ${a.length} vs ${b.length}`);
        return false;
    }
    
    let allMatch = true;
    for (let i = 0; i < a.length; i++) {
        if (a[i].length !== b[i].length) {
            console.log(`${name}[${i}]: COL MISMATCH ${a[i].length} vs ${b[i].length}`);
            allMatch = false;
            continue;
        }
        for (let j = 0; j < a[i].length; j++) {
            const match = comparePolynomials(a[i][j], b[i][j], `${name}[${i}][${j}]`);
            allMatch = allMatch && match;
        }
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
