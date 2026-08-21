/**
 * FIBEMATE SM3 Hash Browser Edition
 * ==================================
 * GB/T 32905-2016 合规实现
 * 来源: message-crypto-v2.js SM3 Class (已验证)
 * 新增: HMAC-SM3 + SM2 KDF
 *
 * API:
 *   SM3Hash.digest(input: Uint8Array) → Uint8Array(32)
 *   SM3Hash.digestHex(input: Uint8Array | string) → hex
 *   SM3Hash.hmac(key: string, data: string | Uint8Array) → hex
 *   SM3Hash.kdf(z: Uint8Array, keyLen: number) → Uint8Array  (GB/T 32918.4 §5.4.3)
 */
(function () {
  'use strict';

  // ========== SM3 Hash Core ==========
  class SM3 {
    constructor() {
      this.digestSize = 256;
      this.IV = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
      ];
    }

    static leftRotate(x, n) {
      return ((x << n) | (x >>> (32 - n))) >>> 0;
    }

    static FF0(x, y, z) { return (x ^ y ^ z) >>> 0; }
    static FF1(x, y, z) { return ((x & y) | (x & z) | (y & z)) >>> 0; }
    static GG0(x, y, z) { return (x ^ y ^ z) >>> 0; }
    static GG1(x, y, z) { return ((x & y) | ((~x) & z)) >>> 0; }

    static P0(x) {
      return (x ^ SM3.leftRotate(x, 9) ^ SM3.leftRotate(x, 17)) >>> 0;
    }

    static P1(x) {
      return (x ^ SM3.leftRotate(x, 15) ^ SM3.leftRotate(x, 23)) >>> 0;
    }

    messageExpand(B) {
      const W = new Array(68);
      const W1 = new Array(64);

      for (let i = 0; i < 16; i++) {
        W[i] = ((B[i * 4] << 24) | (B[i * 4 + 1] << 16) | (B[i * 4 + 2] << 8) | B[i * 4 + 3]) >>> 0;
      }

      for (let i = 16; i < 68; i++) {
        const t = W[i - 16] ^ W[i - 9] ^ SM3.leftRotate(W[i - 3], 15);
        W[i] = (SM3.P1(t) ^ SM3.leftRotate(W[i - 13], 7) ^ W[i - 6]) >>> 0;
      }

      for (let i = 0; i < 64; i++) {
        W1[i] = (W[i] ^ W[i + 4]) >>> 0;
      }

      return { W, W1 };
    }

    compress(V, B) {
      const { W, W1 } = this.messageExpand(B);

      let A = V[0], BB = V[1], C = V[2], D = V[3],
          E = V[4], F = V[5], G = V[6], H = V[7];

      const T0 = 0x79cc4519;
      const T1 = 0x7a879d8a;

      for (let j = 0; j < 64; j++) {
        const T = (j < 16) ? T0 : T1;
        const FF = (j < 16) ? SM3.FF0 : SM3.FF1;
        const GG = (j < 16) ? SM3.GG0 : SM3.GG1;

        const SS1 = SM3.leftRotate((SM3.leftRotate(A, 12) + E + SM3.leftRotate(T, j % 32)) & 0xFFFFFFFF, 7);
        const SS2 = (SS1 ^ SM3.leftRotate(A, 12)) >>> 0;
        const TT1 = (FF(A, BB, C) + D + SS2 + W1[j]) >>> 0;
        const TT2 = (GG(E, F, G) + H + SS1 + W[j]) >>> 0;

        D = C;
        C = SM3.leftRotate(BB, 9);
        BB = A;
        A = TT1;
        H = G;
        G = SM3.leftRotate(F, 19);
        F = E;
        E = (TT2 ^ SM3.leftRotate(TT2, 9) ^ SM3.leftRotate(TT2, 17)) >>> 0;
      }

      return [
        (V[0] ^ A) >>> 0, (V[1] ^ BB) >>> 0, (V[2] ^ C) >>> 0, (V[3] ^ D) >>> 0,
        (V[4] ^ E) >>> 0, (V[5] ^ F) >>> 0, (V[6] ^ G) >>> 0, (V[7] ^ H) >>> 0
      ];
    }

    pad(message) {
      const len = message.length;
      const bitLen = len * 8;
      const padLen = (len % 64 < 56) ? (56 - len % 64) : (120 - len % 64);
      const padded = new Uint8Array(len + padLen + 8);
      padded.set(message);
      padded[len] = 0x80;
      const view = new DataView(padded.buffer);
      view.setBigUint64(padded.length - 8, BigInt(bitLen), false);
      return padded;
    }

    hash(message) {
      const padded = this.pad(message);
      let V = [...this.IV];
      for (let i = 0; i < padded.length; i += 64) {
        const block = padded.slice(i, i + 64);
        V = this.compress(V, block);
      }
      const result = new Uint8Array(32);
      const view = new DataView(result.buffer);
      for (let i = 0; i < 8; i++) {
        view.setUint32(i * 4, V[i], false);
      }
      return result;
    }
  }

  const sm3Instance = new SM3();

  // ========== Hex utilities ==========
  function hexToBytes(hex) {
    if (typeof hex !== 'string') return hex; // already Uint8Array
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2)
      bytes[i >> 1] = parseInt(hex.substring(i, i + 2), 16);
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function toBytes(input) {
    if (input instanceof Uint8Array) return input;
    if (typeof input === 'string') {
      // If looks like hex, decode; otherwise encode as UTF-8
      if (/^[0-9a-fA-F]+$/.test(input) && input.length % 2 === 0) {
        return hexToBytes(input);
      }
      return new TextEncoder().encode(input);
    }
    return new Uint8Array(input);
  }

  // ========== Public API ==========
  const SM3Hash = {
    /**
     * digest(input) → Uint8Array(32)
     */
    digest(input) {
      return sm3Instance.hash(toBytes(input));
    },

    /**
     * digestHex(input) → hex string (64 chars)
     */
    digestHex(input) {
      return bytesToHex(sm3Instance.hash(toBytes(input)));
    },

    /**
     * HMAC-SM3 (RFC 2104)
     * hmac(key: hex | string, data: string | Uint8Array) → hex
     */
    hmac(key, data) {
      const BLOCK_SIZE = 64;
      let k = typeof key === 'string' ? hexToBytes(key) : key;
      if (k.length > BLOCK_SIZE) {
        k = sm3Instance.hash(k);
      }
      // Pad key to block size
      const paddedKey = new Uint8Array(BLOCK_SIZE);
      paddedKey.set(k);

      // ipad
      const ipad = new Uint8Array(BLOCK_SIZE);
      for (let i = 0; i < BLOCK_SIZE; i++) ipad[i] = paddedKey[i] ^ 0x36;

      // opad
      const opad = new Uint8Array(BLOCK_SIZE);
      for (let i = 0; i < BLOCK_SIZE; i++) opad[i] = paddedKey[i] ^ 0x5C;

      const dataBytes = toBytes(data);
      const innerInput = new Uint8Array(BLOCK_SIZE + dataBytes.length);
      innerInput.set(ipad);
      innerInput.set(dataBytes, BLOCK_SIZE);
      const innerHash = sm3Instance.hash(innerInput);

      const outerInput = new Uint8Array(BLOCK_SIZE + 32);
      outerInput.set(opad);
      outerInput.set(innerHash, BLOCK_SIZE);
      return bytesToHex(sm3Instance.hash(outerInput));
    },

    /**
     * SM2 KDF (GB/T 32918.4 §5.4.3)
     * kdf(z: Uint8Array, keyLen: number) → Uint8Array(keyLen)
     *
     * K = H(Z || ct) where ct is a 32-bit counter (big-endian)
     * Loops until enough key material is generated.
     * Z = ECDH shared point (x || y, 64 bytes)
     */
    kdf(z, keyLen) {
      const zBytes = z instanceof Uint8Array ? z : hexToBytes(z);
      let result = new Uint8Array(0);
      let ct = 1;
      const ctBytes = new Uint8Array(4);

      while (result.length < keyLen) {
        const dv = new DataView(ctBytes.buffer);
        dv.setUint32(0, ct, false); // big-endian

        const input = new Uint8Array(zBytes.length + 4);
        input.set(zBytes);
        input.set(ctBytes, zBytes.length);

        const hash = sm3Instance.hash(input);
        const combined = new Uint8Array(result.length + hash.length);
        combined.set(result);
        combined.set(hash, result.length);
        result = combined;
        ct++;
      }

      return result.slice(0, keyLen);
    },

    /**
     * Convenience: SM2 ECDH → session key
     * Given shared secret from SM2EC.computeSharedSecret(), derive a symmetric key
     */
    deriveSessionKey(sharedSecret, keyLen) {
      const salt = 'FIBEMATE-SM2-KDF-v1';
      const saltedZ = new Uint8Array(sharedSecret.length + salt.length);
      saltedZ.set(sharedSecret);
      saltedZ.set(new TextEncoder().encode(salt), sharedSecret.length);
      return SM3Hash.kdf(saltedZ, keyLen);
    },

    /** Self-test */
    selftest() {
      try {
        // Test vector from GB/T 32905-2016 Appendix A.1
        const testInput = new TextEncoder().encode('abc');
        const hash = SM3Hash.digestHex(testInput);
        const expected = '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0';
        if (hash !== expected) return { ok: false, err: `digest mismatch: ${hash}` };

        // HMAC test
        const hmacResult = SM3Hash.hmac('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'Hi There');
        if (hmacResult.length !== 64) return { ok: false, err: 'hmac length error' };

        return { ok: true };
      } catch (e) {
        return { ok: false, err: e.message };
      }
    }
  };

  window.SM3Hash = SM3Hash;
})();
