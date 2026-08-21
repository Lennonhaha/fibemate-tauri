/**
 * ML-KEM-768 — Pure Time-Domain Implementation (No NTT)
 * 
 * All polynomial operations in Z_Q[x]/(x^256+1) use direct negacyclic convolution.
 * Complexity: O(n^2) per multiplication = 65536 modular multiplications.
 * With k=3, each keygen/encaps/decaps needs ~10-20 polyMul calls.
 * Total: ~1-2 million modular multiplications → ~10-50ms in modern JS.
 */

const KYBER_N = 256;
const KYBER_Q = 3329;
const KYBER_ETA1 = 2;
const KYBER_ETA2 = 2;
const KYBER_DU = 10;
const KYBER_DV = 4;
const KYBER_K = 3;
const KYBER_PUBLICKEYBYTES = 1184;
const KYBER_SECRETKEYBYTES = 2400;
const KYBER_CIPHERTEXTBYTES = 1088;
const KYBER_SSBYTES = 32;

// ============================================================================
// SHA-3 / SHAKE - Pure JavaScript Keccak
// ============================================================================

const KeccakF1600Constants = {
    RhoOffsets: [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
    ],
    PiOffsets: [
        0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4
    ],
    RoundConstants: [
        0x0000000000000001n,0x0000000000008082n,0x800000000000808an,
        0x8000000080008000n,0x000000000000808bn,0x0000000080000001n,
        0x8000000080008081n,0x8000000000008009n,0x000000000000008an,
        0x0000000000000088n,0x0000000080008009n,0x000000008000000an,
        0x000000008000808bn,0x800000000000008bn,0x8000000000008089n,
        0x8000000000008003n,0x8000000000008002n,0x8000000000000080n,
        0x000000000000800an,0x800000008000000an,0x8000000080008081n,
        0x8000000000008080n,0x0000000080000001n,0x8000000080008008n
    ]
};

function ROL64(a, n) {
    return n === 0 ? a : ((a << BigInt(n)) | (a >> BigInt(64 - n))) & 0xFFFFFFFFFFFFFFFFn;
}

function KeccakF1600Ref(state) {
    const C = new BigInt64Array(5);
    const D = new BigInt64Array(5);
    const B = new BigInt64Array(25);
    for (let round = 0; round < 24; round++) {
        for (let x = 0; x < 5; x++)
            C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
        for (let x = 0; x < 5; x++)
            D[x] = C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1);
        for (let i = 0; i < 25; i++)
            state[i] ^= D[i % 5];
        for (let i = 0; i < 25; i++)
            B[KeccakF1600Constants.PiOffsets[i]] = ROL64(state[i], KeccakF1600Constants.RhoOffsets[i]);
        for (let x = 0; x < 5; x++)
            for (let y = 0; y < 5; y++)
                state[x+5*y] = B[x+5*y] ^ ((~B[(x+1)%5+5*y] & 0xFFFFFFFFFFFFFFFFn) & B[(x+2)%5+5*y]);
        state[0] ^= KeccakF1600Constants.RoundConstants[round];
    }
}

function load64(b, i) {
    let r = 0n;
    for (let j = 0; j < 8; j++) r |= BigInt(b[i+j]) << BigInt(8*j);
    return r;
}
function store64(b, i, v) {
    for (let j = 0; j < 8; j++) { b[i+j] = Number(v & 0xFFn); v >>= 8n; }
}

class XofShake {
    constructor(rate, suffix) {
        this.state = new BigInt64Array(25);
        this.rate = rate;
        this.suffix = suffix;
        this.byteBuf = new Uint8Array(200);
        this.pos = 0;
        this.finalized = false;
    }
    absorb(data) {
        if (this.finalized) throw new Error('already finalized');
        for (let i = 0; i < data.length; i++) {
            this.byteBuf[this.pos++] ^= data[i];
            if (this.pos === this.rate) {
                this._bytesToLanes(); KeccakF1600Ref(this.state); this._lanesToBytes(); this.pos = 0;
            }
        }
    }
    finalize() {
        if (this.finalized) return;
        this.byteBuf[this.pos] ^= this.suffix;
        this.byteBuf[this.rate - 1] ^= 0x80;
        this._bytesToLanes(); KeccakF1600Ref(this.state); this._lanesToBytes(); this.pos = 0;
        this.finalized = true;
    }
    squeeze(n) {
        if (!this.finalized) this.finalize();
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++) {
            out[i] = this.byteBuf[this.pos++];
            if (this.pos === this.rate) {
                this._bytesToLanes(); KeccakF1600Ref(this.state); this._lanesToBytes(); this.pos = 0;
            }
        }
        return out;
    }
    _bytesToLanes() { for (let i = 0; i < 25; i++) this.state[i] = load64(this.byteBuf, i * 8); }
    _lanesToBytes() { for (let i = 0; i < 25; i++) store64(this.byteBuf, i * 8, this.state[i]); }
}

function shake128(data, n) { const s = new XofShake(168, 0x1f); s.absorb(data); return s.squeeze(n); }
function shake256(data, n) { const s = new XofShake(136, 0x1f); s.absorb(data); return s.squeeze(n); }
function sha3_256(data) { const s = new XofShake(136, 0x06); s.absorb(data); return s.squeeze(32); }
function sha3_512(data) { const s = new XofShake(72, 0x06); s.absorb(data); return s.squeeze(64); }

// ============================================================================
// Modular arithmetic
// ============================================================================
function modAdd(a, b) { const r = a + b; return r >= KYBER_Q ? r - KYBER_Q : r < 0 ? r + KYBER_Q : r; }
function modSub(a, b) { const r = a - b; return r < 0 ? r + KYBER_Q : r; }
function modMul(a, b) { let r = Number((BigInt(a) * BigInt(b)) % BigInt(KYBER_Q)); return r < 0 ? r + KYBER_Q : r; }

// ============================================================================
// Polynomial multiplication — Negacyclic convolution in time domain
// Z_Q[x]/(x^256+1): (f*g)[k] = sum_{i+j=k} f[i]*g[j] - sum_{i+j=k+256} f[i]*g[j]
// ============================================================================
function polyMul(f, g) {
    const r = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) {
        if (f[i] === 0) continue;
        for (let j = 0; j < KYBER_N; j++) {
            if (g[j] === 0) continue;
            const k = i + j;
            const prod = modMul(f[i], g[j]);
            if (k < KYBER_N) {
                r[k] = modAdd(r[k], prod);
            } else {
                r[k - KYBER_N] = modSub(r[k - KYBER_N], prod);
            }
        }
    }
    return r;
}

// ============================================================================
// Matrix/Vector operations — ALL in time domain
// ============================================================================

// Matrix-vector multiply: A (k×k matrix of polynomials) · s (k vector)
// Each A[i][j] and s[j] are polynomials in time domain
// Result: k vector of polynomials
function matVecMul(A, s, k) {
    const r = [];
    for (let i = 0; i < k; i++) {
        let sum = new Int16Array(KYBER_N);
        for (let j = 0; j < k; j++) {
            const prod = polyMul(A[i][j], s[j]);
            for (let l = 0; l < KYBER_N; l++) sum[l] = modAdd(sum[l], prod[l]);
        }
        r[i] = sum;
    }
    return r;
}

// Vector dot product: a^T · b (both k vectors of polynomials)
// Result: single polynomial
function vecDot(a, b, k) {
    let r = new Int16Array(KYBER_N);
    for (let i = 0; i < k; i++) {
        const prod = polyMul(a[i], b[i]);
        for (let j = 0; j < KYBER_N; j++) r[j] = modAdd(r[j], prod[j]);
    }
    return r;
}

// Vector add: a + b (k vectors)
function vecAdd(a, b, k) {
    const r = [];
    for (let i = 0; i < k; i++) {
        r[i] = new Int16Array(KYBER_N);
        for (let j = 0; j < KYBER_N; j++) r[i][j] = modAdd(a[i][j], b[i][j]);
    }
    return r;
}

// ============================================================================
// Serialization, CBD, Sampling
// ============================================================================

function byteEncode(f, d) {
    const out = new Uint8Array(256 * d / 8);
    for (let i = 0; i < 256; i++) {
        let t = ((f[i] % KYBER_Q) + KYBER_Q) % KYBER_Q;
        for (let j = 0; j < d; j++) {
            const bi = i * d + j;
            out[bi >> 3] |= ((t >> j) & 1) << (bi & 7);
        }
    }
    return out;
}

function byteDecode(data, d) {
    const f = new Int16Array(256);
    for (let i = 0; i < 256; i++) {
        let t = 0;
        for (let j = 0; j < d; j++) {
            const bi = i * d + j;
            t |= ((data[bi >> 3] >> (bi & 7)) & 1) << j;
        }
        f[i] = t;
    }
    return f;
}

function compress(f, d) {
    const g = new Int16Array(256);
    for (let i = 0; i < 256; i++) {
        let x = ((f[i] % KYBER_Q) + KYBER_Q) % KYBER_Q;
        g[i] = Number((BigInt(x) * BigInt(1 << d) + BigInt(KYBER_Q >> 1)) / BigInt(KYBER_Q)) & ((1 << d) - 1);
    }
    return g;
}

function decompress(g, d) {
    const f = new Int16Array(256);
    for (let i = 0; i < 256; i++) {
        f[i] = Number((BigInt(g[i]) * BigInt(KYBER_Q) + BigInt(1 << (d - 1))) >> BigInt(d));
    }
    return f;
}

// CBD with eta=2: each byte produces 2 coefficients
function cbd2(buf) {
    const r = new Int16Array(256);
    for (let i = 0; i < 128; i++) {
        const b = buf[i];
        r[2*i] = (b & 1) + ((b >> 1) & 1) - ((b >> 2) & 1) - ((b >> 3) & 1);
        r[2*i+1] = ((b >> 4) & 1) + ((b >> 5) & 1) - ((b >> 6) & 1) - ((b >> 7) & 1);
    }
    return r;
}

// Sample polynomial uniformly from seed+nonce
// Returns polynomial in TIME DOMAIN (not NTT domain)
function samplePoly(seed, nonce) {
    const stream = shake128(new Uint8Array([...seed, nonce]), 504);
    const a = new Int16Array(256);
    let j = 0, idx = 0;
    while (j < 256 && idx < 503) {
        const d1 = stream[idx] | ((stream[idx+1] & 0x0F) << 8);
        const d2 = (stream[idx+1] >> 4) | (stream[idx+2] << 4);
        idx += 3;
        if (d1 < KYBER_Q) a[j++] = d1;
        if (j < 256 && d2 < KYBER_Q) a[j++] = d2;
    }
    return a;
}

// ============================================================================
// KeyGen, Encaps, Decaps — Pure Time Domain
// ============================================================================

function generateKeypair() {
    const d = crypto.getRandomValues(new Uint8Array(32));
    const z = crypto.getRandomValues(new Uint8Array(32));
    const seed = sha3_512(d);
    const rho = seed.slice(0, 32);
    const sigma = seed.slice(32, 64);

    // A is k×k matrix of polynomials in TIME DOMAIN
    const A = [];
    for (let i = 0; i < KYBER_K; i++) {
        A[i] = [];
        for (let j = 0; j < KYBER_K; j++) {
            A[i][j] = samplePoly(rho, (i << 8) | j);
        }
    }

    // s and e in time domain
    const s = [], e = [];
    for (let i = 0; i < KYBER_K; i++) {
        s[i] = cbd2(shake256(new Uint8Array([...sigma, i]), 128));
        e[i] = cbd2(shake256(new Uint8Array([...sigma, i + KYBER_K]), 128));
    }

    // t = A·s + e (all in time domain)
    const As = matVecMul(A, s, KYBER_K);
    const t = vecAdd(As, e, KYBER_K);

    // Encode public key
    const pk = new Uint8Array(KYBER_PUBLICKEYBYTES);
    let off = 0;
    for (let i = 0; i < KYBER_K; i++) {
        pk.set(byteEncode(t[i], 12), off);
        off += 384;
    }
    pk.set(rho, off);

    // Encode secret key
    const sk = new Uint8Array(KYBER_SECRETKEYBYTES);
    off = 0;
    for (let i = 0; i < KYBER_K; i++) {
        sk.set(byteEncode(s[i], 12), off);
        off += 384;
    }
    sk.set(pk, off); off += KYBER_PUBLICKEYBYTES;
    sk.set(sha3_256(pk), off); off += 32;
    sk.set(z, off);

    return { publicKey: pk, secretKey: sk };
}

function encapsulate(publicKey) {
    const m = crypto.getRandomValues(new Uint8Array(32));

    // Decode t from public key
    const t = [];
    let off = 0;
    for (let i = 0; i < KYBER_K; i++) {
        t[i] = byteDecode(publicKey.slice(off, off + 384), 12);
        off += 384;
    }
    const rho = publicKey.slice(off, off + 32);

    const h = sha3_256(publicKey);
    const K_bar = sha3_256(new Uint8Array([...m, ...h]));

    // A^T is k×k matrix in time domain
    const AT = [];
    for (let i = 0; i < KYBER_K; i++) {
        AT[i] = [];
        for (let j = 0; j < KYBER_K; j++) {
            AT[i][j] = samplePoly(rho, (j << 8) | i);
        }
    }

    // r, e1, e2 in time domain
    const r = [], e1 = [];
    for (let i = 0; i < KYBER_K; i++) {
        r[i] = cbd2(shake256(new Uint8Array([...m, i]), 128));
        e1[i] = cbd2(shake256(new Uint8Array([...m, i + KYBER_K]), 128));
    }
    const e2 = cbd2(shake256(new Uint8Array([...m, 2 * KYBER_K]), 128));

    // u = A^T · r + e1
    const ATr = matVecMul(AT, r, KYBER_K);
    const u = vecAdd(ATr, e1, KYBER_K);

    // v = t^T · r + e2 + m
    const tTr = vecDot(t, r, KYBER_K);
    const mPoly = new Int16Array(256);
    for (let i = 0; i < 256; i++) {
        mPoly[i] = ((m[i >> 3] >> (i & 7)) & 1) * Math.floor(KYBER_Q / 2);
    }
    const v = new Int16Array(256);
    for (let i = 0; i < 256; i++) {
        v[i] = modAdd(modAdd(tTr[i], e2[i]), mPoly[i]);
    }

    // Encode ciphertext
    const ct = new Uint8Array(KYBER_CIPHERTEXTBYTES);
    off = 0;
    for (let i = 0; i < KYBER_K; i++) {
        ct.set(byteEncode(compress(u[i], KYBER_DU), KYBER_DU), off);
        off += 320;
    }
    ct.set(byteEncode(compress(v, KYBER_DV), KYBER_DV), off);

    const ss = sha3_256(new Uint8Array([...K_bar, ...sha3_256(ct)]));
    return { ciphertext: ct, sharedSecret: ss };
}

function decapsulate(secretKey, ciphertext) {
    const n = KYBER_K;

    // Decode s from secret key
    const s = [];
    let off = 0;
    for (let i = 0; i < n; i++) {
        s[i] = byteDecode(secretKey.slice(off, off + 384), 12);
        off += 384;
    }
    const pk = secretKey.slice(off, off + KYBER_PUBLICKEYBYTES); off += KYBER_PUBLICKEYBYTES;
    const h = secretKey.slice(off, off + 32); off += 32;
    const z = secretKey.slice(off, off + 32);

    // Decode u and v from ciphertext
    const u = [];
    off = 0;
    for (let i = 0; i < n; i++) {
        u[i] = decompress(byteDecode(ciphertext.slice(off, off + 320), KYBER_DU), KYBER_DU);
        off += 320;
    }
    const v = decompress(byteDecode(ciphertext.slice(off, off + 128), KYBER_DV), KYBER_DV);

    // m' = Decode(v - s^T · u)
    const sTu = vecDot(s, u, n);
    const mp = new Int16Array(256);
    for (let i = 0; i < 256; i++) {
        mp[i] = ((modSub(v[i], sTu[i]) % KYBER_Q) + KYBER_Q) % KYBER_Q;
    }

    // Decode m' to bytes
    const mPrime = new Uint8Array(32);
    const mpc = compress(mp, 1);
    for (let i = 0; i < 256; i++) {
        mPrime[i >> 3] |= mpc[i] << (i & 7);
    }

    const K_bar_prime = sha3_256(new Uint8Array([...mPrime, ...h]));
    const rho = pk.slice(n * 384, n * 384 + 32);

    // Re-encrypt with mPrime to verify
    const AT = [];
    for (let i = 0; i < n; i++) {
        AT[i] = [];
        for (let j = 0; j < n; j++) {
            AT[i][j] = samplePoly(rho, (j << 8) | i);
        }
    }

    const r = [], e1 = [];
    for (let i = 0; i < n; i++) {
        r[i] = cbd2(shake256(new Uint8Array([...mPrime, i]), 128));
        e1[i] = cbd2(shake256(new Uint8Array([...mPrime, i + n]), 128));
    }
    const e2 = cbd2(shake256(new Uint8Array([...mPrime, 2 * n]), 128));

    const ATr = matVecMul(AT, r, n);
    const u2 = vecAdd(ATr, e1, n);

    const t = [];
    let tOff = 0;
    for (let i = 0; i < n; i++) {
        t[i] = byteDecode(pk.slice(tOff, tOff + 384), 12);
        tOff += 384;
    }
    const tTr = vecDot(t, r, n);
    const mPoly2 = new Int16Array(256);
    for (let i = 0; i < 256; i++) {
        mPoly2[i] = ((mPrime[i >> 3] >> (i & 7)) & 1) * Math.floor(KYBER_Q / 2);
    }
    const v2 = new Int16Array(256);
    for (let i = 0; i < 256; i++) {
        v2[i] = modAdd(modAdd(tTr[i], e2[i]), mPoly2[i]);
    }

    const ct2 = new Uint8Array(KYBER_CIPHERTEXTBYTES);
    off = 0;
    for (let i = 0; i < n; i++) {
        ct2.set(byteEncode(compress(u2[i], KYBER_DU), KYBER_DU), off);
        off += 320;
    }
    ct2.set(byteEncode(compress(v2, KYBER_DV), KYBER_DV), off);

    // Constant-time comparison
    let fail = 0;
    for (let i = 0; i < KYBER_CIPHERTEXTBYTES; i++) {
        fail |= ciphertext[i] ^ ct2[i];
    }

    return fail ? sha3_256(new Uint8Array([...z, ...sha3_256(ciphertext)])) 
                : sha3_256(new Uint8Array([...K_bar_prime, ...sha3_256(ciphertext)]));
}

// ============================================================================
// Hybrid Key Exchange (ECDH P-256 + ML-KEM-768)
// ============================================================================
class HybridKeyExchange {
    constructor() {
        this.kemKeypair = null;
        this.ecdhKeypair = null;
    }
    async initialize() {
        this.kemKeypair = generateKeypair();
        this.ecdhKeypair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
        );
        return {
            kemPublicKey: this.kemKeypair.publicKey,
            ecdhPublicKey: await crypto.subtle.exportKey('raw', this.ecdhKeypair.publicKey)
        };
    }
    async encapsulateToPeer(pk, ecdhPk) {
        const k = encapsulate(pk);
        const e = await crypto.subtle.importKey('raw', ecdhPk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
        const d = await crypto.subtle.deriveBits({ name: 'ECDH', public: e }, this.ecdhKeypair.privateKey, 256);
        const c = new Uint8Array(64);
        c.set(k.sharedSecret, 0);
        c.set(new Uint8Array(d), 32);
        return { ciphertext: k.ciphertext, sharedSecret: sha3_256(c) };
    }
    async decapsulateFromPeer(ct, ecdhPk) {
        const ks = decapsulate(this.kemKeypair.secretKey, ct);
        const e = await crypto.subtle.importKey('raw', ecdhPk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
        const d = await crypto.subtle.deriveBits({ name: 'ECDH', public: e }, this.ecdhKeypair.privateKey, 256);
        const c = new Uint8Array(64);
        c.set(ks, 0);
        c.set(new Uint8Array(d), 32);
        return sha3_256(c);
    }
}

// ============================================================================
// Exports
// ============================================================================
const MLKEM768 = {
    generateKeypair,
    encapsulate,
    decapsulate,
    HybridKeyExchange,
    PUBLIC_KEY_BYTES: KYBER_PUBLICKEYBYTES,
    SECRET_KEY_BYTES: KYBER_SECRETKEYBYTES,
    CIPHERTEXT_BYTES: KYBER_CIPHERTEXTBYTES,
    SHARED_SECRET_BYTES: KYBER_SSBYTES
};

if (typeof window !== 'undefined') window.MLKEM768 = MLKEM768;
if (typeof module !== 'undefined' && module.exports) module.exports = MLKEM768;
