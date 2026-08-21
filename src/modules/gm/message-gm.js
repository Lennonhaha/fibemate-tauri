/**
 * MessageGM - 国密消息加密模块
 * SM2 密钥协商 + SM4-CTR 加密 + SM3-HMAC 认证
 *
 * 依赖:
 *   - window.SM2Browser  (sm2-browser.bundle.js)
 *   - window.SM3          (sm3_implementation.js)
 *
 * API:
 *   MessageGM.generateKeypair() → { publicKey, privateKey }
 *   MessageGM.encryptMessage(plaintext, recipientPubKey, senderPrivKey) → { ciphertext, iv, signature, algorithm }
 *   MessageGM.decryptMessage(envelope, myPrivKey, senderPubKey) → { plaintext, verified }
 */

const MessageGM = (() => {
  'use strict';

  // ============================================================
  // SM4 - GB/T 32907-2016  (compact implementation)
  // ============================================================
  const SM4_SBOX = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
  ];

  const SM4_CK = [
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279
  ];

  const SM4_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

  function sm4_sbox(x) {
    return SM4_SBOX[x & 0xff];
  }

  function sm4_tau(a) {
    return (sm4_sbox(a >>> 24) << 24) |
           (sm4_sbox((a >>> 16) & 0xff) << 16) |
           (sm4_sbox((a >>> 8) & 0xff) << 8) |
           (sm4_sbox(a & 0xff));
  }

  function sm4_rotl(x, n) {
    return ((x << n) | (x >>> (32 - n))) >>> 0;
  }

  function sm4_l(b) {
    return (b ^ sm4_rotl(b, 2) ^ sm4_rotl(b, 10) ^ sm4_rotl(b, 18) ^ sm4_rotl(b, 24)) >>> 0;
  }

  function sm4_lprime(b) {
    return (b ^ sm4_rotl(b, 13) ^ sm4_rotl(b, 23)) >>> 0;
  }

  function sm4_t(x) {
    return sm4_l(sm4_tau(x));
  }

  function sm4_tprime(x) {
    return sm4_lprime(sm4_tau(x));
  }

  function sm4_keySchedule(mk) {
    const rk = new Uint32Array(32);
    const K = new Uint32Array(36);
    for (let i = 0; i < 4; i++) {
      K[i] = (mk[i * 4] << 24) | (mk[i * 4 + 1] << 16) | (mk[i * 4 + 2] << 8) | mk[i * 4 + 3];
      K[i] ^= SM4_FK[i];
    }
    for (let i = 0; i < 32; i++) {
      K[i + 4] = K[i] ^ sm4_tprime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ SM4_CK[i]);
      rk[i] = K[i + 4];
    }
    return rk;
  }

  function sm4_block_encrypt(X, rk) {
    const x = new Uint32Array(36);
    for (let i = 0; i < 4; i++) {
      x[i] = (X[i * 4] << 24) | (X[i * 4 + 1] << 16) | (X[i * 4 + 2] << 8) | X[i * 4 + 3];
    }
    for (let i = 0; i < 32; i++) {
      x[i + 4] = x[i] ^ sm4_t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]);
    }
    const out = new Uint8Array(16);
    for (let i = 0; i < 4; i++) {
      const v = x[35 - i];
      out[i * 4] = (v >>> 24) & 0xff;
      out[i * 4 + 1] = (v >>> 16) & 0xff;
      out[i * 4 + 2] = (v >>> 8) & 0xff;
      out[i * 4 + 3] = v & 0xff;
    }
    return out;
  }

  function sm4_ctr_encrypt(key, iv, plaintext) {
    const rk = sm4_keySchedule(key);
    const blockCount = Math.ceil(plaintext.length / 16);
    const output = new Uint8Array(plaintext.length);
    const counter = new Uint8Array(iv);

    for (let b = 0; b < blockCount; b++) {
      // Increment counter (big-endian)
      for (let i = 15; i >= 0; i--) {
        counter[i]++;
        if (counter[i] !== 0) break;
      }
      const keystream = sm4_block_encrypt(counter, rk);
      const chunkStart = b * 16;
      const chunkSize = Math.min(16, plaintext.length - chunkStart);
      for (let i = 0; i < chunkSize; i++) {
        output[chunkStart + i] = plaintext[chunkStart + i] ^ keystream[i];
      }
    }
    return output;
  }

  // ============================================================
  // SM3-HMAC  (uses window.SM3 from sm3_implementation.js)
  // ============================================================
  function sm3_hash(data) {
    if (typeof window.SM3 !== 'undefined') {
      const sm3 = new window.SM3();
      return sm3.hashSync(data);
    }
    throw new Error('SM3 implementation not loaded. Include sm3_implementation.js');
  }

  function sm3_hmac(key, data) {
    const blockSize = 64;
    const k = new Uint8Array(blockSize);
    if (key.length > blockSize) {
      const h = sm3_hash(key);
      k.set(h, 0);
    } else {
      k.set(key, 0);
    }

    const ipad = new Uint8Array(blockSize);
    const opad = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
      ipad[i] = k[i] ^ 0x36;
      opad[i] = k[i] ^ 0x5c;
    }

    const inner = new Uint8Array(blockSize + data.length);
    inner.set(ipad);
    inner.set(data, blockSize);

    const innerHash = sm3_hash(inner);
    const outer = new Uint8Array(blockSize + innerHash.length);
    outer.set(opad);
    outer.set(innerHash, blockSize);

    return sm3_hash(outer);
  }

  // ============================================================
  // Key derivation - SM3 KDF (GB/T 32918.4-2016 §5.4.3)
  // ============================================================
  function sm3_kdf(z, klen) {
    const ct = 1;
    const hashSize = 32; // SM3 outputs 256 bits
    const n = Math.ceil(klen / hashSize);
    const result = new Uint8Array(klen);

    for (let i = 1; i <= n; i++) {
      const input = new Uint8Array(z.length + 4);
      input.set(z);
      input[z.length] = (i >>> 24) & 0xff;
      input[z.length + 1] = (i >>> 16) & 0xff;
      input[z.length + 2] = (i >>> 8) & 0xff;
      input[z.length + 3] = i & 0xff;

      const hash = sm3_hash(input);
      const offset = (i - 1) * hashSize;
      const copyLen = Math.min(hashSize, klen - offset);
      for (let j = 0; j < copyLen; j++) {
        result[offset + j] = hash[j];
      }
    }
    return result;
  }

  // ============================================================
  // Utility
  // ============================================================
  function hexToBytes(hex) {
    hex = hex.replace(/\s/g, '');
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i >> 1] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function randomBytes(len) {
    const buf = new Uint8Array(len);
    crypto.getRandomValues(buf);
    return buf;
  }

  function concatBytes(a, b) {
    const c = new Uint8Array(a.length + b.length);
    c.set(a);
    c.set(b, a.length);
    return c;
  }

  function utf8Encode(str) {
    return new TextEncoder().encode(str);
  }

  function utf8Decode(bytes) {
    return new TextDecoder().decode(bytes);
  }

  // ============================================================
  // Public API
  // ============================================================

  /**
   * Generate SM2 keypair
   * @returns {{ publicKey: string, privateKey: string }}
   */
  function generateKeypair() {
    const kp = SM2Browser.generateKeypair();
    return {
      publicKey: kp.publicKey,   // '04' + 64 bytes (x||y)
      privateKey: kp.privateKey  // 64 hex chars (32 bytes)
    };
  }

  // ============================================================
  // Backend-aware key handling (Tauri migration)
  // ============================================================
  //
  // `key` may be either:
  //   - a legacy 64-char hex private key string (pure-JS / node tests)
  //   - { keyId } opaque handle (Tauri - private key lives in Rust KeyStore)
  //
  // Signing and unwrap (the two operations that use *our* private key)
  // are routed to the Rust backend when window.SM2 is available.

  function _hasBackend() {
    return typeof window !== 'undefined' && window.SM2
      && typeof window.SM2.signFull === 'function';
  }

  function _isKeyRef(key) {
    return key !== null && typeof key === 'object' && typeof key.keyId === 'string';
  }

  /**
   * Sign a raw message string with our SM2 private key.
   * Returns 128-char hex (r||s), matching the frontend SM2Browser.sign format.
   */
  async function _signWithKey(key, message) {
    if (_isKeyRef(key) && _hasBackend()) {
      const res = await window.SM2.signFull(key.keyId, message);
      return res.r + res.s;
    }
    // legacy pure-JS path
    return SM2Browser.sign(key, message);
  }

  /**
   * Unwrap an SM2-encapsulated SM4 key with our SM2 private key.
   * Returns the 32-char hex string (sm4Key hex) the frontend produces.
   */
  async function _unwrapWithKey(key, wrappedKey) {
    if (_isKeyRef(key) && _hasBackend()) {
      const res = await window.SM2.decryptFull(key.keyId, wrappedKey);
      return res.plaintext;  // 32-char hex (sm4Key hex)
    }
    // legacy pure-JS path
    return SM2Browser.decrypt(key, wrappedKey, 1);
  }

  /**
   * Encrypt message for recipient (encrypt-then-sign)
   *
   * Flow:
   *   1. Derive SM4 session key via SM2 ECDH (ephemeral × recipient_pk)
   *   2. Encrypt plaintext with SM4-CTR
   *   3. Compute SM3-HMAC over (IV || ciphertext)
   *   4. Sign the envelope with sender's SM2 private key
   *
   * @param {string} plaintext - UTF-8 message
   * @param {string} recipientPubKey - Recipient's SM2 public key (hex, 130 chars)
   * @param {string} senderPrivKey - Sender's SM2 private key (hex, 64 chars)
   * @returns {{ ciphertext: string, iv: string, ephemeralPK: string, hmac: string, signature: string, algorithm: string }}
   */
  /**
   * Encrypt message for recipient (encrypt-then-sign)
   *
   * Flow:
   *   1. Derive SM4 session key via SM2 ECDH (ephemeral × recipient_pk)
   *   2. Encrypt plaintext with SM4-CTR
   *   3. Compute SM3-HMAC over (IV || ciphertext)
   *   4. Sign the envelope with sender's SM2 private key
   *
   * @param {string} plaintext - UTF-8 message
   * @param {string} recipientPubKey - Recipient's SM2 public key (hex, 130 chars)
   * @param {string|{keyId}} senderKey - sender's private key (hex) or { keyId } handle
   * @returns {Promise<{ ciphertext, iv, ephemeralPK, wrappedKey, hmac, signature, algorithm }>}
   */
  async function encryptMessage(plaintext, recipientPubKey, senderKey) {
    // 1. Generate ephemeral keypair for ECDH
    const ephemeral = SM2Browser.generateKeypair();

    // 2. Compute shared secret: S = ephemeral_priv × recipient_pub
    //    Use SM2 encryption as key encapsulation:
    //    - Encrypt a known plaintext to derive shared secret
    //    - SM2 encrypt includes: C1 (e*G), SM3(x2||y2) based key derivation
    //    Instead, we compute directly: encrypt dummy, extract the random key
    //
    //    Simpler approach: use SM2 encrypt to wrap our random SM4 key.
    //    Step A: Generate random SM4 key + IV
    const sm4Key = randomBytes(16);
    const iv = randomBytes(16);

    // 3. Encrypt plaintext with SM4-CTR
    const dataBytes = utf8Encode(plaintext);
    const ciphertextBytes = sm4_ctr_encrypt(sm4Key, iv, dataBytes);

    // 4. Wrap SM4 key with recipient's SM2 public key
    //    (SM2 encrypt can handle 16-byte key)
    const wrappedKey = SM2Browser.encrypt(recipientPubKey, bytesToHex(sm4Key), 1);

    // 5. Compute HMAC for integrity: SM3-HMAC(SM4-key, IV || ciphertext)
    const authInput = concatBytes(iv, ciphertextBytes);
    const hmac = sm3_hmac(sm4Key, authInput);

    // 6. Sign the envelope with sender's key
    //    Signature covers: ephemeralPK || wrappedKey || hmac
    const sigInput = ephemeral.publicKey + wrappedKey + bytesToHex(hmac);
    const signature = await _signWithKey(senderKey, sigInput);

    return {
      ciphertext: bytesToHex(ciphertextBytes),
      iv: bytesToHex(iv),
      ephemeralPK: ephemeral.publicKey,  // sent for sender ECDH (future use)
      wrappedKey: wrappedKey,
      hmac: bytesToHex(hmac),
      signature: signature,
      algorithm: 'sm2-sm4-sm3'
    };
  }

  /**
   * Decrypt message (verify-then-decrypt)
   *
   * @param {Object} envelope - Output of encryptMessage
   * @param {string|{keyId}} myKey - recipient's private key (hex) or { keyId } handle
   * @param {string} senderPubKey - Sender's SM2 public key
   * @returns {Promise<{ plaintext: string, verified: boolean }>}
   */
  async function decryptMessage(envelope, myKey, senderPubKey) {
    // 1. Verify signature
    const { ciphertext, iv, ephemeralPK, wrappedKey, hmac, signature } = envelope;
    const sigInput = ephemeralPK + wrappedKey + hmac;
    const verified = SM2Browser.verify(senderPubKey, signature, sigInput);
    if (!verified) {
      return { plaintext: '', verified: false, error: 'Signature verification failed' };
    }

    // 2. Unwrap SM4 key
    const sm4KeyHex = await _unwrapWithKey(myKey, wrappedKey);
    if (!sm4KeyHex) {
      return { plaintext: '', verified: false, error: 'Key unwrap failed' };
    }
    const sm4Key = hexToBytes(sm4KeyHex);

    // 3. Verify HMAC
    const ivBytes = hexToBytes(iv);
    const ciphertextBytes = hexToBytes(ciphertext);
    const authInput = concatBytes(ivBytes, ciphertextBytes);
    const expectedHmac = sm3_hmac(sm4Key, authInput);
    const receivedHmac = hexToBytes(hmac);
    
    let hmacOk = true;
    if (expectedHmac.length !== receivedHmac.length) {
      hmacOk = false;
    } else {
      for (let i = 0; i < expectedHmac.length; i++) {
        if (expectedHmac[i] !== receivedHmac[i]) {
          hmacOk = false;
          break;
        }
      }
    }

    if (!hmacOk) {
      return { plaintext: '', verified: false, error: 'HMAC verification failed' };
    }

    // 4. Decrypt with SM4-CTR
    const plaintextBytes = sm4_ctr_encrypt(sm4Key, ivBytes, ciphertextBytes);
    const plaintext = utf8Decode(plaintextBytes);

    return { plaintext, verified: true };
  }

  /**
   * Self-test: generate keypair, encrypt, decrypt, verify
   * @returns {Promise<{ ok: boolean, err?: string }>}
   */
  async function selftest() {
    try {
      const kp = generateKeypair();
      const msg = `FIBEMATE-GM-${Date.now()}`;
      
      const envelope = await encryptMessage(msg, kp.publicKey, kp.privateKey);
      const result = await decryptMessage(envelope, kp.privateKey, kp.publicKey);
      
      if (!result.verified) return { ok: false, err: 'signature/hmac verify' };
      if (result.plaintext !== msg) return { ok: false, err: 'encrypt/decrypt mismatch' };
      
      return { ok: true, publicKey: kp.publicKey.slice(0, 20) + '...' };
    } catch (e) {
      return { ok: false, err: e.message };
    }
  }

  // ============================================================
  // Export
  // ============================================================
  return {
    generateKeypair,
    encryptMessage,
    decryptMessage,
    selftest
  };
})();

// Register globally
if (typeof window !== 'undefined') {
  window.MessageGM = MessageGM;
}
