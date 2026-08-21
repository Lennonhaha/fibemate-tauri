/**
 * FIBEMATE SM4 Block Cipher Browser Edition
 * ==========================================
 * SM4-ECB + SM4-GCM (GB/T 32907-2016)
 *
 * SM4 is a 128-bit block cipher with 32 rounds, using Feistel-like structure
 * with an 8-bit S-box and linear transformation L.
 *
 * GCM mode (Galois/Counter Mode) provides authenticated encryption:
 *   encrypt(plaintext, key, iv) → { ciphertext, authTag }
 *   decrypt(ciphertext, key, iv, authTag) → plaintext | null
 *
 * API:
 *   SM4GCM.encrypt(plaintext: string, key: hex, opts?: { iv?: hex }) → { ciphertext: hex, iv: hex, authTag: hex }
 *   SM4GCM.decrypt(ciphertext: hex, key: hex, iv: hex, authTag: hex) → string | null
 */
(function () {
  'use strict';

  // ================================================================
  //  SM4 S-box (GB/T 32907-2016, Appendix A)
  // ================================================================
  const SBOX = new Uint8Array([
    0xD6,0x90,0xE9,0xFE,0xCC,0xE1,0x3D,0xB7,0x16,0xB6,0x14,0xC2,0x28,0xFB,0x2C,0x05,
    0x2B,0x67,0x9A,0x76,0x2A,0xBE,0x04,0xC3,0xAA,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9C,0x42,0x50,0xF4,0x91,0xEF,0x98,0x7A,0x33,0x54,0x0B,0x43,0xED,0xCF,0xAC,0x62,
    0xE4,0xB3,0x1C,0xA9,0xC9,0x08,0xE8,0x95,0x80,0xDF,0x94,0xFA,0x75,0x8F,0x3F,0xA6,
    0x47,0x07,0xA7,0xFC,0xF3,0x73,0x17,0xBA,0x83,0x59,0x3C,0x19,0xE6,0x85,0x4F,0xA8,
    0x68,0x6B,0x81,0xB2,0x71,0x64,0xDA,0x8B,0xF8,0xEB,0x0F,0x4B,0x70,0x56,0x9D,0x35,
    0x1E,0x24,0x0E,0x5E,0x63,0x58,0xD1,0xA2,0x25,0x22,0x7C,0x3B,0x01,0x21,0x78,0x87,
    0xD4,0x00,0x46,0x57,0x9F,0xD3,0x27,0x52,0x4C,0x36,0x02,0xE7,0xA0,0xC4,0xC8,0x9E,
    0xEA,0xBF,0x8A,0xD2,0x40,0xC7,0x38,0xB5,0xA3,0xF7,0xF2,0xCE,0xF9,0x61,0x15,0xA1,
    0xE0,0xAE,0x5D,0xA4,0x9B,0x34,0x1A,0x55,0xAD,0x93,0x32,0x30,0xF5,0x8C,0xB1,0xE3,
    0x1D,0xF6,0xE2,0x2E,0x82,0x66,0xCA,0x60,0xC0,0x29,0x23,0xAB,0x0D,0x53,0x4E,0x6F,
    0xD5,0xDB,0x37,0x45,0xDE,0xFD,0x8E,0x2F,0x03,0xFF,0x6A,0x72,0x6D,0x6C,0x5B,0x51,
    0x8D,0x1B,0xAF,0x92,0xBB,0xDD,0xBC,0x7F,0x11,0xD9,0x5C,0x41,0x1F,0x10,0x5A,0xD8,
    0x0A,0xC1,0x31,0x88,0xA5,0xCD,0x7B,0xBD,0x2D,0x74,0xD0,0x12,0xB8,0xE5,0xB4,0xB0,
    0x89,0x69,0x97,0x4A,0x0C,0x96,0x77,0x7E,0x65,0xB9,0xF1,0x09,0xC5,0x6E,0xC6,0x84,
    0x18,0xF0,0x7D,0xEC,0x3A,0xDC,0x4D,0x20,0x79,0xEE,0x5F,0x3E,0xD7,0xCB,0x39,0x48,
  ]);

  // ================================================================
  //  System Parameters FK (GB/T 32907 §7.2)
  // ================================================================
  const FK = new Uint32Array([
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC,
  ]);

  // ================================================================
  //  Constant Parameters CK (GB/T 32907 §7.2)
  // ================================================================
  const CK = new Uint32Array(32);
  (function initCK() {
    for (let i = 0; i < 32; i++) {
      let c = 0;
      for (let j = 0; j < 4; j++) {
        c = (c << 8) | ((4 * i + j) * 7) & 0xFF;
      }
      CK[i] = c;
    }
  })();

  // ================================================================
  //  Utility
  // ================================================================
  function rotl(x, n) { return (x << n) | (x >>> (32 - n)); }

  function TAU(a) {
    // Non-linear substitution τ (4×S-box lookups)
    const aa = new Uint8Array(4);
    aa[0] = (a >>> 24) & 0xFF;
    aa[1] = (a >>> 16) & 0xFF;
    aa[2] = (a >>> 8) & 0xFF;
    aa[3] = a & 0xFF;
    return (SBOX[aa[0]] << 24) |
           (SBOX[aa[1]] << 16) |
           (SBOX[aa[2]] << 8) |
           SBOX[aa[3]];
  }

  // L' : linear transformation for key schedule (§7.2.2)
  function L_PRIME(b) {
    return b ^ rotl(b, 13) ^ rotl(b, 23);
  }

  // L : linear transformation for encryption (§7.3)
  function L(b) {
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24);
  }

  // T: round function for key schedule
  function T_PRIME(z) { return L_PRIME(TAU(z)); }

  // T: round function for encryption
  function T(z) { return L(TAU(z)); }

  // Hex utilities
  function hexToBytes(hex) {
    if (hex instanceof Uint8Array) return hex;
    const len = hex.length / 2;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++)
      bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function getRandomBytes(n) {
    const buf = new Uint8Array(n);
    crypto.getRandomValues(buf);
    return buf;
  }

  function paddingWrite(plaintext) {
    const pt = typeof plaintext === 'string'
      ? new TextEncoder().encode(plaintext)
      : plaintext;
    const padLen = 16 - (pt.length % 16);
    const padded = new Uint8Array(pt.length + padLen);
    padded.set(pt);
    padded.fill(padLen, pt.length);
    return padded;
  }

  function paddingStrip(block) {
    const padLen = block[block.length - 1];
    if (padLen < 1 || padLen > 16) return null;
    for (let i = 1; i <= padLen; i++)
      if (block[block.length - i] !== padLen) return null;
    return block.slice(0, block.length - padLen);
  }

  // ================================================================
  //  Key Schedule (rK: 32 round keys)
  // ================================================================
  function keySchedule(keyBytes) {
    const MK = new Uint32Array(4);
    for (let i = 0; i < 4; i++) {
      MK[i] = (keyBytes[4 * i] << 24) |
              (keyBytes[4 * i + 1] << 16) |
              (keyBytes[4 * i + 2] << 8) |
              keyBytes[4 * i + 3];
    }

    const K = new Uint32Array(36);
    K[0] = MK[0] ^ FK[0];
    K[1] = MK[1] ^ FK[1];
    K[2] = MK[2] ^ FK[2];
    K[3] = MK[3] ^ FK[3];

    const rK = new Uint32Array(32);
    for (let i = 0; i < 32; i++) {
      rK[i] = K[i + 4] = K[i] ^ T_PRIME(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
    }
    return rK;
  }

  // ================================================================
  //  SM4 Block Encrypt (one 128-bit block)
  // ================================================================
  function sm4EncryptBlock(rK, block) {
    let X0 = (block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3];
    let X1 = (block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7];
    let X2 = (block[8] << 24) | (block[9] << 16) | (block[10] << 8) | block[11];
    let X3 = (block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15];

    for (let i = 0; i < 32; i += 4) {
      X0 ^= T(X1 ^ X2 ^ X3 ^ rK[i]);
      X1 ^= T(X2 ^ X3 ^ X0 ^ rK[i + 1]);
      X2 ^= T(X3 ^ X0 ^ X1 ^ rK[i + 2]);
      X3 ^= T(X0 ^ X1 ^ X2 ^ rK[i + 3]);
    }

    const out = new Uint8Array(16);
    out[0] = X3 >>> 24; out[1] = (X3 >>> 16) & 0xFF; out[2] = (X3 >>> 8) & 0xFF; out[3] = X3 & 0xFF;
    out[4] = X2 >>> 24; out[5] = (X2 >>> 16) & 0xFF; out[6] = (X2 >>> 8) & 0xFF; out[7] = X2 & 0xFF;
    out[8] = X1 >>> 24; out[9] = (X1 >>> 16) & 0xFF; out[10] = (X1 >>> 8) & 0xFF; out[11] = X1 & 0xFF;
    out[12] = X0 >>> 24; out[13] = (X0 >>> 16) & 0xFF; out[14] = (X0 >>> 8) & 0xFF; out[15] = X0 & 0xFF;
    return out;
  }

  // ================================================================
  //  SM4-CTR (used internally by GCM)
  // ================================================================
  function sm4CTR(rK, counter, buf, out, offset, length) {
    const ctr = new Uint8Array(16);
    ctr.set(counter);
    const stream = new Uint8Array(16);

    for (let i = 0; i < length; i += 16) {
      // Increment counter (big-endian on last 4 bytes)
      const ek = sm4EncryptBlock(rK, ctr);
      const remaining = Math.min(16, length - i);
      for (let j = 0; j < remaining; j++)
        out[offset + i + j] = buf[offset + i + j] ^ ek[j];
      // Increment counter
      for (let j = 15; j >= 12; j--) {
        ctr[j] = (ctr[j] + 1) & 0xFF;
        if (ctr[j] !== 0) break;
      }
    }
  }

  // ================================================================
  //  GF(2^128) Multiplication (for GCM authentication)
  // ================================================================
  function gfMul(x, y) {
    let R = new Uint8Array(16);
    const Z = new Uint8Array(16);
    let V = new Uint8Array(y);

    for (let i = 0; i < 128; i++) {
      const bit = (x[i >> 3] >> (7 - (i & 7))) & 1;
      if (bit) {
        for (let j = 0; j < 16; j++) Z[j] ^= V[j];
      }
      // V = (V >> 1) ⊕ (R if LSB was set)
      const lsb = V[15] & 1;
      let carry = 0;
      for (let j = 15; j >= 0; j--) {
        const nextCarry = (V[j] & 1) << 7;
        V[j] = ((V[j] >>> 1) | carry) & 0xFF;
        carry = nextCarry;
      }
      if (lsb) {
        V[0] ^= 0xE1;
      }
    }
    return Z;
  }

  function ghash(H, A, C) {
    let Y = new Uint8Array(16);

    // Process A (additional authenticated data)
    for (let i = 0; i < A.length; i += 16) {
      const len = Math.min(16, A.length - i);
      const block = new Uint8Array(16);
      block.set(A.subarray(i, i + len));
      for (let j = 0; j < 16; j++) Y[j] ^= block[j];
      Y = gfMul(Y, H);
    }

    // Process C (ciphertext)
    for (let i = 0; i < C.length; i += 16) {
      const len = Math.min(16, C.length - i);
      const block = new Uint8Array(16);
      block.set(C.subarray(i, i + len));
      for (let j = 0; j < 16; j++) Y[j] ^= block[j];
      Y = gfMul(Y, H);
    }

    // Process lengths (A_len || C_len) × 8, 64-bit big-endian each
    const lenBlock = new Uint8Array(16);
    const aBits = A.length * 8;
    const cBits = C.length * 8;
    lenBlock[4] = (aBits >>> 56) & 0xFF;
    lenBlock[5] = (aBits >>> 48) & 0xFF;
    lenBlock[6] = (aBits >>> 40) & 0xFF;
    lenBlock[7] = (aBits >>> 32) & 0xFF;
    lenBlock[8] = (aBits >>> 24) & 0xFF;
    lenBlock[9] = (aBits >>> 16) & 0xFF;
    lenBlock[10] = (aBits >>> 8) & 0xFF;
    lenBlock[11] = aBits & 0xFF;
    lenBlock[12] = (cBits >>> 56) & 0xFF;
    lenBlock[13] = (cBits >>> 48) & 0xFF;
    lenBlock[14] = (cBits >>> 40) & 0xFF;
    lenBlock[15] = (cBits >>> 32) & 0xFF;
    for (let j = 0; j < 16; j++) Y[j] ^= lenBlock[j];
    Y = gfMul(Y, H);

    return Y;
  }

  // ================================================================
  //  Public API
  // ================================================================
  const SM4GCM = {
    /**
     * Encrypt with SM4-GCM
     * @param {string|Uint8Array} plaintext
     * @param {string|Uint8Array} key - 16 bytes (hex or Uint8Array)
     * @param {object} opts - { iv?: hex, aad?: string }
     * @returns {{ ciphertext: hex, iv: hex, authTag: hex }}
     */
    encrypt(plaintext, key, opts) {
      const keyBytes = hexToBytes(key);
      if (keyBytes.length !== 16) throw new Error('SM4 key must be 16 bytes');

      const iv = opts && opts.iv
        ? hexToBytes(opts.iv)
        : getRandomBytes(12);
      if (iv.length !== 12) throw new Error('GCM IV must be 12 bytes');

      const aad = (opts && opts.aad)
        ? (typeof opts.aad === 'string' ? new TextEncoder().encode(opts.aad) : opts.aad)
        : new Uint8Array(0);

      const pt = typeof plaintext === 'string'
        ? new TextEncoder().encode(plaintext)
        : plaintext;

      const rK = keySchedule(keyBytes);

      // H = E_K(0^128)
      const zeroBlock = new Uint8Array(16);
      const H = sm4EncryptBlock(rK, zeroBlock);

      // J0 = IV || 0^31 || 1
      const J0 = new Uint8Array(16);
      J0.set(iv);
      J0[15] = 1;

      // Encrypt with CTR starting from J0 (counter = J0 + 1)
      const counter = new Uint8Array(16);
      counter.set(J0);
      // J0 + 1
      for (let i = 15; i >= 12; i--) {
        counter[i] = (counter[i] + 1) & 0xFF;
        if (counter[i] !== 0) break;
      }

      const ct = new Uint8Array(pt.length);
      sm4CTR(rK, counter, pt, ct, 0, pt.length);

      // Compute authentication tag
      const tag = ghash(H, aad, ct);
      // XOR tag with E_K(J0)
      const eJ0 = sm4EncryptBlock(rK, J0);
      for (let i = 0; i < 16; i++) tag[i] ^= eJ0[i];

      return {
        ciphertext: bytesToHex(ct),
        iv: bytesToHex(iv),
        authTag: bytesToHex(tag),
      };
    },

    /**
     * Decrypt with SM4-GCM
     * @returns {string|null} plaintext or null if auth fails
     */
    decrypt(cipherHex, key, ivHex, authTagHex, aadParam) {
      const keyBytes = hexToBytes(key);
      const ct = hexToBytes(cipherHex);
      const iv = hexToBytes(ivHex);
      const expectedTag = hexToBytes(authTagHex);
      const aad = aadParam
        ? (typeof aadParam === 'string' ? new TextEncoder().encode(aadParam) : hexToBytes(aadParam))
        : new Uint8Array(0);

      const rK = keySchedule(keyBytes);

      // H = E_K(0^128)
      const zeroBlock = new Uint8Array(16);
      const H = sm4EncryptBlock(rK, zeroBlock);

      // J0
      const J0 = new Uint8Array(16);
      J0.set(iv);
      J0[15] = 1;

      // Verify authentication tag
      const tag = ghash(H, aad, ct);
      const eJ0 = sm4EncryptBlock(rK, J0);
      for (let i = 0; i < 16; i++) tag[i] ^= eJ0[i];
      for (let i = 0; i < 16; i++) {
        if (tag[i] !== expectedTag[i]) return null; // auth failed
      }

      // Decrypt with CTR
      const counter = new Uint8Array(16);
      counter.set(J0);
      for (let i = 15; i >= 12; i--) {
        counter[i] = (counter[i] + 1) & 0xFF;
        if (counter[i] !== 0) break;
      }

      const pt = new Uint8Array(ct.length);
      sm4CTR(rK, counter, ct, pt, 0, ct.length);

      return new TextDecoder().decode(pt);
    },

    /**
     * SM4-ECB encrypt (one block, unsigned, for internal use)
     */
    encryptBlock(keyBytes, block) {
      const rK = keySchedule(keyBytes);
      return sm4EncryptBlock(rK, block);
    },

    /** Self-test with test vectors from GB/T 32907-2016 Appendix A */
    selftest() {
      try {
        // A.1: Encrypt test vector
        const keyHex = '0123456789abcdeffedcba9876543210';
        const ptHex = '0123456789abcdeffedcba9876543210';
        const expectedCtHex = '681edf34d206965e86b3e94f536e4246';

        const rK = keySchedule(hexToBytes(keyHex));
        const ct = sm4EncryptBlock(rK, hexToBytes(ptHex));
        const ctHexActual = bytesToHex(ct);
        if (ctHexActual !== expectedCtHex)
          return { ok: false, err: `SM4 ECB encrypt: expected ${expectedCtHex}, got ${ctHexActual}` };

        // A.2: 1,000,000 iterations (too slow for selftest, skip)

        // GCM roundtrip
        const sm4key = bytesToHex(getRandomBytes(16));
        const pt = 'FIBEMATE SM4-GCM Self-Test: Hello World! 你好世界';
        const encRes = SM4GCM.encrypt(pt, sm4key);
        const dec = SM4GCM.decrypt(encRes.ciphertext, sm4key, encRes.iv, encRes.authTag);
        if (dec !== pt)
          return { ok: false, err: `GCM roundtrip: expected "${pt}", got "${dec}"` };

        // Tamper detection
        const badTag = 'aa' + encRes.authTag.substring(2);
        const tamper = SM4GCM.decrypt(encRes.ciphertext, sm4key, encRes.iv, badTag);
        if (tamper !== null)
          return { ok: false, err: 'GCM tamper detection failed' };

        return { ok: true };
      } catch (e) {
        return { ok: false, err: e.message };
      }
    }
  };

  window.SM4GCM = SM4GCM;
})();
