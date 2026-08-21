/**
 * Constant-Time Utility Functions
 * 
 * Purpose: Prevent timing attacks by ensuring comparison operations
 * take constant time regardless of input values.
 * 
 * Usage: Replace all === and !== comparisons on sensitive data
 * (keys, MACs, hashes, identifiers) with constantTimeEqual()
 */

'use strict';

/**
 * Constant-time byte array comparison
 * Returns true if a === b, false otherwise
 * Takes same time regardless of where mismatch occurs
 * 
 * @param {Uint8Array|ArrayBuffer|String} a - First value
 * @param {Uint8Array|ArrayBuffer|String} b - Second value
 * @returns {boolean} - true if a === b
 */
function constantTimeEqual(a, b) {
    // Handle string inputs by converting to bytes
    let aBytes, bBytes;
    
    if (typeof a === 'string') {
        const enc = new TextEncoder();
        aBytes = enc.encode(a);
        a = aBytes.buffer;
    }
    
    if (typeof b === 'string') {
        const enc = new TextEncoder();
        bBytes = enc.encode(b);
        b = bBytes.buffer;
    }
    
    // Convert to Uint8Array if needed
    if (a instanceof ArrayBuffer) {
        a = new Uint8Array(a);
    }
    if (b instanceof ArrayBuffer) {
        b = new Uint8Array(b);
    }
    
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
        throw new TypeError('Inputs must be Uint8Array, ArrayBuffer, or string');
    }
    
    // Length mismatch - still compare all bytes but result is always false
    if (a.length !== b.length) {
        // Compare all bytes anyway to maintain constant time
        let diff = 0;
        const len = Math.max(a.length, b.length);
        for (let i = 0; i < len; i++) {
            const ai = i < a.length ? a[i] : 0;
            const bi = i < b.length ? b[i] : 0;
            diff |= ai ^ bi;
        }
        return false; // Length mismatch always returns false
    }
    
    // Compare all bytes
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    
    return result === 0;
}

/**
 * Constant-time buffer comparison (Node.js compatible)
 * @param {Buffer} a - First buffer
 * @param {Buffer} b - Second buffer
 * @returns {boolean} - true if a === b
 */
function constantTimeEqualBuffers(a, b) {
    // Handle Node.js Buffer
    if (typeof Buffer !== 'undefined' && (a instanceof Buffer || b instanceof Buffer)) {
        const aLen = a instanceof Buffer ? a.length : a.byteLength;
        const bLen = b instanceof Buffer ? b.length : b.byteLength;
        
        if (aLen !== bLen) {
            // Constant time comparison even on length mismatch
            let diff = 0;
            const len = Math.max(aLen, bLen);
            for (let i = 0; i < len; i++) {
                const ai = i < aLen ? (a instanceof Buffer ? a[i] : a[i]) : 0;
                const bi = i < bLen ? (b instanceof Buffer ? b[i] : b[i]) : 0;
                diff |= ai ^ bi;
            }
            return false;
        }
        
        let result = 0;
        for (let i = 0; i < aLen; i++) {
            result |= a[i] ^ b[i];
        }
        return result === 0;
    }
    
    // Fall back to Uint8Array comparison
    return constantTimeEqual(
        a instanceof Uint8Array ? a : new Uint8Array(a),
        b instanceof Uint8Array ? b : new Uint8Array(b)
    );
}

/**
 * Constant-time hexadecimal string comparison
 * @param {String} a - First hex string (without 0x prefix)
 * @param {String} b - Second hex string (without 0x prefix)
 * @returns {boolean} - true if a === b
 */
function constantTimeEqualHex(a, b) {
    // Normalize: remove 0x prefix if present
    const normalize = (h) => {
        if (h.startsWith('0x') || h.startsWith('0X')) {
            return h.slice(2);
        }
        return h;
    };
    
    const aNorm = normalize(a);
    const bNorm = normalize(b);
    
    // Convert hex to bytes
    const hexToBytes = (hex) => {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    };
    
    try {
        return constantTimeEqual(hexToBytes(aNorm), hexToBytes(bNorm));
    } catch (e) {
        // Invalid hex - treat as not equal
        return false;
    }
}

/**
 * Constant-time boolean comparison
 * Always returns true or false in constant time
 * @param {boolean} a 
 * @param {boolean} b
 * @returns {boolean}
 */
function constantTimeEqualBool(a, b) {
    // Convert booleans to 0/1
    const aVal = a ? 1 : 0;
    const bVal = b ? 1 : 0;
    return (aVal ^ bVal) === 0;
}

/**
 * Constant-time greater-than comparison
 * @param {number} a
 * @param {number} b
 * @returns {boolean} - true if a > b
 */
function constantTimeGreaterThan(a, b) {
    // Use constant-time technique: compute (a - b) and check sign via bit operations
    // This avoids branches that could leak timing information
    const diff = a - b;
    // Check if diff is positive: (diff >> 31) gives 0 if positive, 1 if negative
    // But we need to be careful about integer overflow
    // For safe integer comparison, use this trick:
    const mask = (diff >> 31) & 1;
    // If diff is positive: mask = 0, result = true
    // If diff is negative: mask = 1, result = false
    return mask === 0 && diff !== 0;
}

/**
 * Constant-time less-than comparison
 * @param {number} a
 * @param {number} b
 * @returns {boolean} - true if a < b
 */
function constantTimeLessThan(a, b) {
    return constantTimeGreaterThan(b, a);
}

/**
 * Constant-time greater-than-or-equal comparison
 * @param {number} a
 * @param {number} b
 * @returns {boolean} - true if a >= b
 */
function constantTimeGreaterOrEqual(a, b) {
    return !constantTimeLessThan(a, b);
}

/**
 * Constant-time less-than-or-equal comparison
 * @param {number} a
 * @param {number} b
 * @returns {boolean} - true if a <= b
 */
function constantTimeLessOrEqual(a, b) {
    return !constantTimeGreaterThan(a, b);
}

// Export for Node.js / module environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        constantTimeEqual,
        constantTimeEqualBuffers,
        constantTimeEqualHex,
        constantTimeEqualBool,
        constantTimeGreaterThan,
        constantTimeLessThan,
        constantTimeGreaterOrEqual,
        constantTimeLessOrEqual
    };
}

// Export for browser global
if (typeof window !== 'undefined') {
    window.constantTimeEqual = constantTimeEqual;
    window.constantTimeEqualBuffers = constantTimeEqualBuffers;
    window.constantTimeEqualHex = constantTimeEqualHex;
    window.constantTimeEqualBool = constantTimeEqualBool;
    window.constantTimeGreaterThan = constantTimeGreaterThan;
    window.constantTimeLessThan = constantTimeLessThan;
    window.constantTimeGreaterOrEqual = constantTimeGreaterOrEqual;
    window.constantTimeLessOrEqual = constantTimeLessOrEqual;
}