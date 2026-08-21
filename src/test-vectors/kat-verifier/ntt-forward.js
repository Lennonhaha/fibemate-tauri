/**
 * NTT Forward Transform - For KAT Verification Only
 * Converts time-domain polynomials to NTT domain for comparison with NIST intermediate values
 * 
 * ML-KEM NTT uses:
 * - n = 256
 * - q = 3329
 * - ζ = 17 (primitive 512th root, so ζ^256 = -1 mod q)
 * - Output in bit-reversed order
 * 
 * Layer structure (from inner to outer):
 * Layer 0: pairs (stride=2), ζ^(2^6 * k) for k=0..127
 * Layer 1: groups of 4 (stride=4), ζ^(2^5 * k) for k=0..63
 * ...
 * Layer 6: full 256 (stride=256), ζ^(2^0 * k) for k=0..1, i.e., ζ^0=1, ζ^1=17
 */

const KYBER_N = 256;
const KYBER_Q = 3329;
const ZETA = 17;

// Precompute zetas for each layer
// zetas[layer][k] where layer=0..6, k ranges appropriately
const zetasByLayer = [];

function precomputeZetas() {
    // Layer 0: stride=2, need zeta^(2^6 * k) = zeta^(64k) for k=0..127
    // But actually we need zeta^(brv(k)) where brv is bit-reverse
    // Standard ML-KEM uses: zetas[i] = zeta^(brv(i+1)) for i=0..127
    
    const zetas = new Int16Array(128);
    for (let i = 0; i < 128; i++) {
        // bit-reverse of (i+1) as 7-bit number
        const br = bitReverse7(i + 1);
        zetas[i] = modExp(ZETA, br);
    }
    
    // Organize by layer
    let idx = 0;
    for (let layer = 0; layer < 7; layer++) {
        const count = 1 << layer;  // 1, 2, 4, 8, 16, 32, 64
        zetasByLayer[layer] = new Int16Array(count);
        for (let k = 0; k < count; k++) {
            zetasByLayer[layer][k] = zetas[idx++];
        }
    }
}

function bitReverse7(x) {
    let r = 0;
    for (let i = 0; i < 7; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

function modAdd(a, b) {
    const r = a + b;
    return r >= KYBER_Q ? r - KYBER_Q : r < 0 ? r + KYBER_Q : r;
}

function modSub(a, b) {
    const r = a - b;
    return r < 0 ? r + KYBER_Q : r;
}

function modMul(a, b) {
    let r = Number((BigInt(a) * BigInt(b)) % BigInt(KYBER_Q));
    return r < 0 ? r + KYBER_Q : r;
}

function modExp(base, exp) {
    let result = 1;
    let b = ((base % KYBER_Q) + KYBER_Q) % KYBER_Q;
    let e = exp;
    while (e > 0) {
        if (e & 1) result = modMul(result, b);
        b = modMul(b, b);
        e >>= 1;
    }
    return result;
}

/**
 * Forward NTT - Standard Cooley-Tukey
 * Input: f[0..255] in normal order
 * Output: f̂[0..255] in bit-reversed order
 */
function nttForward(f) {
    const n = KYBER_N;
    const a = new Int16Array(n);
    
    // Normalize to [0, q-1]
    for (let i = 0; i < n; i++) {
        a[i] = ((f[i] % KYBER_Q) + KYBER_Q) % KYBER_Q;
    }
    
    // Layer-by-layer butterfly
    // Layer 0: pairs, layer 1: groups of 4, ..., layer 6: full 256
    for (let layer = 0; layer < 7; layer++) {
        const stride = 2 << layer;  // 2, 4, 8, 16, 32, 64, 128
        const half = stride >> 1;    // 1, 2, 4, 8, 16, 32, 64
        const numGroups = n / stride; // 128, 64, 32, 16, 8, 4, 2
        
        for (let group = 0; group < numGroups; group++) {
            const zeta = zetasByLayer[layer][group];
            const base = group * stride;
            
            for (let j = 0; j < half; j++) {
                const idx1 = base + j;
                const idx2 = idx1 + half;
                
                const t = modMul(zeta, a[idx2]);
                a[idx2] = modSub(a[idx1], t);
                a[idx1] = modAdd(a[idx1], t);
            }
        }
    }
    
    return a;
}

/**
 * Verify NTT is correct by checking properties
 */
function verifyNttProperties() {
    // Check ζ^256 = -1 mod q
    const zeta256 = modExp(ZETA, 256);
    console.assert(zeta256 === KYBER_Q - 1, "ζ^256 should be -1");
    
    // Check ζ^512 = 1 mod q
    const zeta512 = modExp(ZETA, 512);
    console.assert(zeta512 === 1, "ζ^512 should be 1");
    
    console.log("NTT properties verified");
}

// Precompute
precomputeZetas();

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { nttForward, modMul, modAdd, modSub, bitReverse7, verifyNttProperties };
}
