/**
 * KAT File Parser for NIST PQC Intermediate Values
 * Parses the text format from NIST Round 3 submission
 */

const fs = require('fs');
const path = require('path');

/**
 * Parse a single KAT test case from text content
 * Format:
 *   Key Generation -- ML-KEM-768
 *   z: <hex>
 *   d: <hex>
 *   rho: <hex>
 *   sigma: <hex>
 *   aHat: [[[...]]]
 *   s: [[...]]
 *   e: [[...]]
 *   sHat: [[...]]
 *   eHat: [[...]]
 *   tHat: [[...]]
 *   ek: <hex>
 *   dk: <hex>
 */
function parseKatFile(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    
    const testCases = [];
    let current = null;
    let inMatrix = false;
    let matrixBuffer = '';
    let currentMatrixName = '';
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        
        if (line.startsWith('Key Generation') || line.startsWith('Encapsulation') || line.startsWith('Decapsulation')) {
            if (current) testCases.push(current);
            current = { type: line };
            inMatrix = false;
            continue;
        }
        
        if (!current) continue;
        
        // Check for hex values
        if (line.startsWith('z:') || line.startsWith('d:') || line.startsWith('rho:') || 
            line.startsWith('sigma:') || line.startsWith('ek:') || line.startsWith('dk:') ||
            line.startsWith('m:') || line.startsWith('K:') || line.startsWith('c:')) {
            const colonIdx = line.indexOf(':');
            const key = line.substring(0, colonIdx).trim();
            const value = line.substring(colonIdx + 1).trim();
            current[key] = hexToBytes(value);
            inMatrix = false;
            continue;
        }
        
        // Check for matrix start
        if (line.startsWith('aHat:') || line.startsWith('s:') || line.startsWith('e:') ||
            line.startsWith('sHat:') || line.startsWith('eHat:') || line.startsWith('tHat:') ||
            line.startsWith('r:') || line.startsWith('e1:') || line.startsWith('e2:') ||
            line.startsWith('u:') || line.startsWith('v:') || line.startsWith('AT:') ||
            line.startsWith('u\':') || line.startsWith('v\':')) {
            if (inMatrix && matrixBuffer) {
                current[currentMatrixName] = parseMatrix(matrixBuffer);
            }
            const colonIdx = line.indexOf(':');
            currentMatrixName = line.substring(0, colonIdx).trim();
            matrixBuffer = line.substring(colonIdx + 1).trim();
            inMatrix = true;
            continue;
        }
        
        // Continue matrix
        if (inMatrix && line.length > 0) {
            matrixBuffer += line;
        }
        
        // End of matrix on empty line or new section
        if (inMatrix && line.length === 0) {
            current[currentMatrixName] = parseMatrix(matrixBuffer);
            inMatrix = false;
            matrixBuffer = '';
        }
    }
    
    // Don't forget the last one
    if (inMatrix && matrixBuffer && current) {
        current[currentMatrixName] = parseMatrix(matrixBuffer);
    }
    if (current) testCases.push(current);
    
    return testCases;
}

function hexToBytes(hex) {
    hex = hex.replace(/\s/g, '');
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function parseMatrix(buffer) {
    // Remove whitespace
    buffer = buffer.replace(/\s/g, '');
    
    // Parse nested arrays
    try {
        // Replace JavaScript array syntax
        // The format is like: [[[503, 2488, ...], [...]], [[...], [...]]]
        return eval(buffer);
    } catch (e) {
        console.error('Failed to parse matrix:', e.message);
        console.error('Buffer preview:', buffer.substring(0, 200));
        return null;
    }
}

/**
 * Convert parsed matrix to our internal format
 * aHat: k×k array of polynomials (each polynomial is array of 256 coefficients in bit-reversed order)
 * s, e: k array of polynomials (each polynomial is array of 256 coefficients in normal order)
 * sHat, eHat: k array of polynomials (NTT domain, bit-reversed)
 * tHat: k array of polynomials (NTT domain, bit-reversed)
 */
function convertToInternalFormat(testCase) {
    const result = {};
    
    // Copy simple fields
    ['z', 'd', 'rho', 'sigma', 'ek', 'dk', 'm', 'K', 'c'].forEach(key => {
        if (testCase[key]) result[key] = testCase[key];
    });
    
    // Convert matrices
    if (testCase.aHat) {
        result.A = testCase.aHat;  // k×k matrix of polynomials
    }
    if (testCase.s) {
        result.s = testCase.s;  // k vector of polynomials
    }
    if (testCase.e) {
        result.e = testCase.e;  // k vector of polynomials
    }
    if (testCase.sHat) {
        result.sHat = testCase.sHat;  // k vector of NTT polynomials
    }
    if (testCase.eHat) {
        result.eHat = testCase.eHat;  // k vector of NTT polynomials
    }
    if (testCase.tHat) {
        result.tHat = testCase.tHat;  // k vector of NTT polynomials
    }
    if (testCase.r) {
        result.r = testCase.r;
    }
    if (testCase.e1) {
        result.e1 = testCase.e1;
    }
    if (testCase.e2) {
        result.e2 = testCase.e2;
    }
    if (testCase.u) {
        result.u = testCase.u;
    }
    if (testCase.v) {
        result.v = testCase.v;
    }
    
    return result;
}

module.exports = { parseKatFile, hexToBytes, convertToInternalFormat };
