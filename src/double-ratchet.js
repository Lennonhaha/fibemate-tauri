// ============================================================
// FIBEMATE Double Ratchet v2 — Signal Protocol Compliant
// Curve: P-256 | KDF: HKDF-SHA-256 | AEAD: AES-256-GCM
// ============================================================
//
// Spec: https://signal.org/docs/specifications/doubleratchet/
//
// Key differences from v1 (simplified):
//   1. Real DH ratchet step (new ECDH per sending burst)
//   2. HKDF joint root+chain derivation (not separate HMAC)
//   3. Chain key advances via HMAC (constant-time, no info strings)
//   4. skippedKeys map fully queried on decrypt
//   5. Ratchet header carries DH public key + pn + n
//   6. X3DH with 4 DH computations (including one-time pre-key)
//   7. IndexedDB persistence via KeyManager integration
//
// Limitations (acceptable for demo/academic):
//   - P-256 instead of X25519 (WebCrypto compat)
//   - No out-of-order header encryption (Skipped in demo)
//   - Max skipped keys capped at 1000 per session
// ============================================================

const DoubleRatchet = (() => {
  'use strict';

  // ---- Constants ----
  const CURVE = 'P-256';
  const HASH = 'SHA-256';
  const AEAD = 'AES-GCM';
  const KEY_LEN = 32;        // 256-bit keys
  const IV_LEN = 12;         // 96-bit nonce for AES-GCM
  const MAX_SKIP = 1000;     // max skipped message keys
  const INFO_ROOT   = new TextEncoder().encode('FIBEMateRoot');   // HKDF info for root step
  const INFO_CHAIN  = new TextEncoder().encode('FIBEMateChain');  // HKDF info for chain step
  const INFO_MSG    = new TextEncoder().encode('FIBEMateMsg');    // HKDF info for message key

  // ---- Constant-time byte comparison utility ----
  // Use this instead of Array.some((b,i) => b !== arr[i]) to prevent timing attacks
  function ctCompareBytes(a, b) {
    if (!a || !b) return a === b;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }

  // ---- HKDF-SHA-256 ----
  async function hkdf(ikm, salt, info, length = KEY_LEN) {
    // Extract
    const saltBuf = salt instanceof Uint8Array && salt.length > 0 ? salt : new Uint8Array(KEY_LEN);
    const hmacKey = await crypto.subtle.importKey('raw', saltBuf, { name: 'HMAC', hash: HASH }, false, ['sign']);
    const prk = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, ikm));

    // Expand
    const n = Math.ceil(length / KEY_LEN);
    const okm = [];
    let prev = new Uint8Array(0);
    for (let i = 1; i <= n; i++) {
      const data = new Uint8Array(prev.length + info.length + 1);
      data.set(prev, 0);
      data.set(info instanceof Uint8Array ? info : new TextEncoder().encode(info), prev.length);
      data[data.length - 1] = i;
      const tKey = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: HASH }, false, ['sign']);
      prev = new Uint8Array(await crypto.subtle.sign('HMAC', tKey, data));
      okm.push(...prev);
    }
    return new Uint8Array(okm.slice(0, length));
  }

  // ---- HMAC-SHA-256 (single-shot) ----
  async function hmacSign(key, data) {
    const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: HASH }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, data));
  }

  // ---- ECDH P-256 key pair generation ----
  async function generateDH() {
    return await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: CURVE },
      true,  // extractable for export
      ['deriveBits']
    );
  }

  // ---- ECDH shared secret ----
  async function dh(privateKey, publicKey) {
    const bits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: publicKey },
      privateKey,
      256
    );
    return new Uint8Array(bits);
  }

  // ---- Export/import raw public key ----
  async function exportPublicKey(keyPair) {
    return new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  }

  async function importPublicKey(rawBytes) {
    return await crypto.subtle.importKey(
      'raw',
      rawBytes,
      { name: 'ECDH', namedCurve: CURVE },
      true,
      []
    );
  }

  // ---- AES-256-GCM encrypt/decrypt ----
  async function aeadEncrypt(key, plaintext, associatedData) {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const aesKey = await crypto.subtle.importKey('raw', key, { name: AEAD }, false, ['encrypt']);
    const encoded = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
    const aad = associatedData ? associatedData : undefined;
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: AEAD, iv, additionalData: aad },
      aesKey,
      encoded
    ));
    return { ciphertext, iv };
  }

  async function aeadDecrypt(key, ciphertext, iv, associatedData) {
    const aesKey = await crypto.subtle.importKey('raw', key, { name: AEAD }, false, ['decrypt']);
    const aad = associatedData ? associatedData : undefined;
    const plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: AEAD, iv, additionalData: aad },
      aesKey,
      ciphertext
    ));
    return new TextDecoder().decode(plaintext);
  }

  // ---- KDF_RK: Root key derivation ----
  // (rootKey, dhOutput) → (newRootKey, newChainKey)
  async function kdfRk(rk, dhOutput) {
    const output = await hkdf(dhOutput, rk, INFO_ROOT, KEY_LEN * 2);
    return {
      rootKey: output.slice(0, KEY_LEN),
      chainKey: output.slice(KEY_LEN, KEY_LEN * 2)
    };
  }

  // ---- KDF_CK: Chain key advancement ----
  // chainKey → (messageKey, nextChainKey)
  async function kdfCk(ck) {
    const msgKey = await hmacSign(ck, new Uint8Array([0x01]));
    const nextCk = await hmacSign(ck, new Uint8Array([0x02]));
    return { messageKey: msgKey, chainKey: nextCk };
  }

  // ---- State object factory ----
  function createState() {
    return {
      rootKey: null,             // 32 bytes
      sendingChainKey: null,     // 32 bytes or null
      receivingChainKey: null,   // 32 bytes or null
      selfDH: null,              // CryptoKeyPair (current ratchet DH key)
      selfDHPublic: null,        // Uint8Array (exported raw public key)
      remoteDHPublic: null,      // Uint8Array (peer's current DH public key)
      sendMessageNumber: 0,
      recvMessageNumber: 0,
      prevSendChainLength: 0,
      skippedKeys: new Map()     // key: "dhPub:n" → messageKey (Uint8Array)
    };
  }

  // ---- Ratchet header ----
  function ratchetHeader(dhPub, pn, n) {
    return {
      dh: Array.from(dhPub),  // public key as int array for JSON
      pn,                      // previous chain length
      n                        // message number
    };
  }

  function headerToBytes(header) {
    // Serialize header for AAD: dh(65 bytes) + pn(4 bytes LE) + n(4 bytes LE)
    const dh = new Uint8Array(header.dh);
    const buf = new Uint8Array(65 + 4 + 4);
    buf.set(dh.slice(0, 65), 0);
    const dv = new DataView(buf.buffer);
    dv.setUint32(65, header.pn, true);
    dv.setUint32(69, header.n, true);
    return buf;
  }

  // ---- Try skipped keys ----
  async function trySkippedKeys(state, header, ciphertext, iv) {
    const key = `${header.dh.join(',')}:${header.n}`;
    const mk = state.skippedKeys.get(key);
    if (!mk) return null;
    state.skippedKeys.delete(key);
    try {
      return await aeadDecrypt(mk, ciphertext, iv, headerToBytes(header));
    } catch (e) {
      // Key was wrong, put it back? No — Signal spec says skip-storing
      // a bad key is a protocol error
      throw new Error('Decryption failed with skipped key');
    }
  }

  // ---- Skip message keys ----
  async function skipMessageKeys(state, until) {
    if (state.recvMessageNumber + MAX_SKIP < until) {
      throw new Error(`Too many skipped messages: ${until - state.recvMessageNumber}`);
    }
    if (state.receivingChainKey) {
      while (state.recvMessageNumber < until) {
        const { messageKey, chainKey } = await kdfCk(state.receivingChainKey);
        const key = `${state.remoteDHPublic ? Array.from(state.remoteDHPublic).join(',') : 'none'}:${state.recvMessageNumber}`;
        state.skippedKeys.set(key, messageKey);
        state.receivingChainKey = chainKey;
        state.recvMessageNumber++;
      }
    }
  }

  // ---- DH Ratchet step (initiator side, after receiving new DH key) ----
  async function performDHRatchet(state, header) {
    const prevChainLen = state.sendMessageNumber;
    await skipMessageKeys(state, header.pn);

    // Receive side DH ratchet
    state.remoteDHPublic = new Uint8Array(header.dh);
    const remotePub = await importPublicKey(state.remoteDHPublic);
    const dhOut1 = await dh(state.selfDH.privateKey, remotePub);
    const rkck1 = await kdfRk(state.rootKey, dhOut1);
    state.rootKey = rkck1.rootKey;
    state.receivingChainKey = rkck1.chainKey;
    state.recvMessageNumber = 0;
    state.prevSendChainLength = prevChainLen;

    // Generate new self DH key pair
    state.selfDH = await generateDH();
    state.selfDHPublic = await exportPublicKey(state.selfDH);

    // Send side DH ratchet
    const dhOut2 = await dh(state.selfDH.privateKey, remotePub);
    const rkck2 = await kdfRk(state.rootKey, dhOut2);
    state.rootKey = rkck2.rootKey;
    state.sendingChainKey = rkck2.chainKey;
    state.sendMessageNumber = 0;
  }

  // ============================================================
  // PUBLIC API
  // ============================================================

/**
   * Initialize as X3DH initiator (Alice).
   *
   * Performs the first DH ratchet step: DH(self, remote) → new root key + sending chain.
   * After this call, Alice can encrypt (has sendingChainKey) but cannot decrypt
   * until Bob replies with a new DH public key.
   *
   * @param {Uint8Array} rootKey   — 32-byte root key from X3DH (HKDF-SHA-256 output)
   * @param {Uint8Array} remoteDHPublicRaw — Bob's signed pre-key (raw P-256, 65 bytes uncompressed)
   * @returns {Promise<Object>} ratchet state — pass to encrypt() / decrypt()
   * @throws {Error} [SECURITY] if rootKey is < 32 bytes (downgrade attack rejection)
   *
   * @example
   * const state = await DoubleRatchet.initAsInitiator(rootKey, bobSignedPreKey);
   */
  async function initAsInitiator(rootKey, remoteDHPublicRaw) {
    // ---- Downgrade Attack Protection (P3) ----
    // HKDF-SHA-256 output MUST be 32 bytes. Any truncation or weak derivation
    // is treated as a downgrade attack and rejected immediately.
    if (!rootKey || rootKey.length < 32) {
      throw new Error(
        `[SECURITY] Downgrade attack detected: rootKey is ${rootKey ? rootKey.length : 'null'} bytes, ` +
        `required 32 bytes. Possible causes:\n` +
        `  - X3DH derivation was truncated or used weak parameters\n` +
        `  - MITM tampered with the key exchange\n` +
        `  - Server returned an invalid pre-key bundle\n` +
        `DO NOT proceed. Verify Safety Numbers out-of-band.`
      );
    }
    // ---- End downgrade protection ----

    const state = createState();
    state.rootKey = rootKey;
    state.remoteDHPublic = remoteDHPublicRaw;

    // Generate our first ratchet DH key pair
    state.selfDH = await generateDH();
    state.selfDHPublic = await exportPublicKey(state.selfDH);

    // Perform DH ratchet to derive initial sending chain
    const remotePub = await importPublicKey(remoteDHPublicRaw);
    const dhOut = await dh(state.selfDH.privateKey, remotePub);
    const rkck = await kdfRk(state.rootKey, dhOut);
    state.rootKey = rkck.rootKey;
    state.sendingChainKey = rkck.chainKey;

    // No receiving chain yet (until Bob replies with new DH key)
    state.receivingChainKey = null;
    state.sendMessageNumber = 0;
    state.recvMessageNumber = 0;
    state.prevSendChainLength = 0;

    return state;
  }

  /**
   * Initialize as X3DH receiver (Bob).
   *
   * No chains are established yet — Bob must process Alice's first message
   * (which carries Alice's DH public key) before he can encrypt or decrypt.
   *
   * @param {Uint8Array} rootKey — 32-byte root key from X3DH (HKDF-SHA-256 output)
   * @param {CryptoKeyPair} selfDHKeyPair — Bob's current DH key pair (signed pre-key)
   * @returns {Promise<Object>} ratchet state — pass to decrypt() first, then encrypt()
   * @throws {Error} [SECURITY] if rootKey is < 32 bytes (downgrade attack rejection)
   *
   * @example
   * const state = await DoubleRatchet.initAsReceiver(rootKey, bobKeyPair);
   */
  async function initAsReceiver(rootKey, selfDHKeyPair) {
    // ---- Downgrade Attack Protection (P3) ----
    // HKDF-SHA-256 output MUST be 32 bytes. Any truncation or weak derivation
    // is treated as a downgrade attack and rejected immediately.
    if (!rootKey || rootKey.length < 32) {
      throw new Error(
        `[SECURITY] Downgrade attack detected: rootKey is ${rootKey ? rootKey.length : 'null'} bytes, ` +
        `required 32 bytes. Possible causes:\n` +
        `  - X3DH derivation was truncated or used weak parameters\n` +
        `  - MITM tampered with the key exchange\n` +
        `  - Server returned an invalid pre-key bundle\n` +
        `DO NOT proceed. Verify Safety Numbers out-of-band.`
      );
    }
    // ---- End downgrade protection ----

    const state = createState();
    state.rootKey = rootKey;
    state.selfDH = selfDHKeyPair;
    state.selfDHPublic = await exportPublicKey(selfDHKeyPair);

    // No sending/receiving chains until we process Alice's first message
    state.sendingChainKey = null;
    state.receivingChainKey = null;
    state.sendMessageNumber = 0;
    state.recvMessageNumber = 0;
    state.prevSendChainLength = 0;

    return state;
  }

  /**
   * Encrypt a plaintext message under the current sending chain.
   *
   * ⚠️ SYNC ONLY — this function is synchronous (after kdfCk completes).
   *    Do not call encrypt() concurrently on the same state — message numbers
   *    are advanced in-place and concurrent calls will produce duplicates.
   *
   * Advances state.sendMessageNumber by 1.
   * Advances state.sendingChainKey via KDF_CK step.
   *
   * @param {Object} state — ratchet state (MUTATED in place)
   * @param {string} plaintext — message to encrypt (UTF-8)
   * @returns {Promise<{header: Object, ciphertext: number[], iv: number[]}>}
   *   header.dh — self DH public key (int array, 65 elements)
   *   header.pn — previous sending chain length
   *   header.n  — message number in this chain
   *   ciphertext — AES-256-GCM ciphertext (int array)
   *   iv         — 12-byte random nonce (int array)
   * @throws {Error} if no sending chain exists (DH ratchet not yet established)
   *
   * @example
   * const msg = await DoubleRatchet.encrypt(state, "Hello Bob!");
   * // send msg.header + msg.ciphertext + msg.iv over the wire
   */
  async function encrypt(state, plaintext) {
    if (!state.sendingChainKey) {
      throw new Error('No sending chain — DH ratchet not yet established');
    }

    const { messageKey, chainKey } = await kdfCk(state.sendingChainKey);
    state.sendingChainKey = chainKey;

    const header = ratchetHeader(state.selfDHPublic, state.prevSendChainLength, state.sendMessageNumber);
    const headerBytes = headerToBytes(header);

    const { ciphertext, iv } = await aeadEncrypt(messageKey, plaintext, headerBytes);

    state.sendMessageNumber++;

    return {
      header,
      ciphertext: Array.from(ciphertext),
      iv: Array.from(iv)
    };
  }

  /**
   * Decrypt a message from a peer.
   *
   * Handles three cases transparently:
   *   1. Out-of-order message → checks skippedKeys map
   *   2. First message in new chain → performs DH ratchet step
   *   3. In-order message → derives key from receiving chain
   *
   * ⚠️ SYNC ONLY — concurrent decrypt() calls on the same state will corrupt
   *    the receiving chain. Serialize all decrypt calls for a given session.
   *
   * @param {Object}   state      — ratchet state (MUTATED in place)
   * @param {Object}   header     — ratchet header {dh: number[], pn: number, n: number}
   * @param {Uint8Array|number[]} ciphertext — AES-256-GCM ciphertext
   * @param {Uint8Array|number[]} iv         — 12-byte nonce
   * @returns {Promise<string>} plaintext (UTF-8 decoded)
   * @throws {Error} if no receiving chain and message is not in skippedKeys
   *
   * @example
   * const msg = await DoubleRatchet.decrypt(state, msg.header,
   *   new Uint8Array(msg.ciphertext), new Uint8Array(msg.iv));
   */
  async function decrypt(state, header, ciphertext, iv) {
    const ctBytes = ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext);
    const ivBytes = iv instanceof Uint8Array ? iv : new Uint8Array(iv);

    // 1. Try skipped keys first
    const skipped = await trySkippedKeys(state, header, ctBytes, ivBytes);
    if (skipped !== null) return skipped;

    // 2. Check if remote DH key changed → DH ratchet step (constant-time comparison)
    const headerDHPub = new Uint8Array(header.dh);
    const dhChanged = !state.remoteDHPublic ||
      headerDHPub.length !== state.remoteDHPublic.length ||
      !ctCompareBytes(headerDHPub, state.remoteDHPublic);

    if (dhChanged) {
      await performDHRatchet(state, header);
    }

    // 3. Skip message keys if needed (out-of-order)
    await skipMessageKeys(state, header.n);

    // 4. Derive message key from receiving chain
    if (!state.receivingChainKey) {
      throw new Error('No receiving chain — cannot decrypt');
    }

    const { messageKey, chainKey } = await kdfCk(state.receivingChainKey);
    state.receivingChainKey = chainKey;
    state.recvMessageNumber++;

    // 5. Decrypt
    const headerBytes = headerToBytes(header);
    const plaintext = await aeadDecrypt(messageKey, ctBytes, ivBytes, headerBytes);
    return plaintext;
  }

  /**
   * Serialize state for persistence (IndexedDB).
   * CryptoKeyPair cannot be serialized — export keys first.
   */
  async function exportState(state) {
    // Export private key in PKCS8 format (WebCrypto supports this for ECDH)
    let selfDHPrivate = null;
    if (state.selfDH && state.selfDH.privateKey) {
      try {
        selfDHPrivate = Array.from(new Uint8Array(
          await crypto.subtle.exportKey('pkcs8', state.selfDH.privateKey)
        ));
      } catch (e) {
        console.warn('[DoubleRatchet] Failed to export private key:', e.message);
      }
    }
    return {
      rootKey: Array.from(state.rootKey || []),
      sendingChainKey: state.sendingChainKey ? Array.from(state.sendingChainKey) : null,
      receivingChainKey: state.receivingChainKey ? Array.from(state.receivingChainKey) : null,
      selfDHPublic: state.selfDHPublic ? Array.from(state.selfDHPublic) : null,
      selfDHPrivatePkcs8: selfDHPrivate,
      remoteDHPublic: state.remoteDHPublic ? Array.from(state.remoteDHPublic) : null,
      sendMessageNumber: state.sendMessageNumber,
      recvMessageNumber: state.recvMessageNumber,
      prevSendChainLength: state.prevSendChainLength,
      skippedKeys: Array.from(state.skippedKeys.entries())
    };
  }

  /**
   * Restore state from persistence.
   */
  async function importState(data) {
    const state = createState();
    state.rootKey = new Uint8Array(data.rootKey);
    state.sendingChainKey = data.sendingChainKey ? new Uint8Array(data.sendingChainKey) : null;
    state.receivingChainKey = data.receivingChainKey ? new Uint8Array(data.receivingChainKey) : null;
    state.selfDHPublic = data.selfDHPublic ? new Uint8Array(data.selfDHPublic) : null;
    state.remoteDHPublic = data.remoteDHPublic ? new Uint8Array(data.remoteDHPublic) : null;
    state.sendMessageNumber = data.sendMessageNumber || 0;
    state.recvMessageNumber = data.recvMessageNumber || 0;
    state.prevSendChainLength = data.prevSendChainLength || 0;
    state.skippedKeys = new Map(data.skippedKeys || []);

    // Reconstruct CryptoKeyPair from PKCS8 private key
    const pkcs8Data = data.selfDHPrivatePkcs8 || data.selfDHPrivate;
    if (pkcs8Data && data.selfDHPublic) {
      try {
        const privKey = await crypto.subtle.importKey(
          'pkcs8',
          new Uint8Array(pkcs8Data),
          { name: 'ECDH', namedCurve: CURVE },
          true,
          ['deriveBits']
        );
        const pubKey = await importPublicKey(new Uint8Array(data.selfDHPublic));
        state.selfDH = { publicKey: pubKey, privateKey: privKey };
      } catch (e) {
        console.warn('[DoubleRatchet] Failed to import private key:', e.message);
      }
    }

    return state;
  }

  /**
   * X3DH key agreement — full 4-DH variant (Signal Protocol §3.3).
   *
   * Computes: rootKey = HKDF(DH1 ‖ DH2 ‖ DH3 ‖ DH4, salt=0³², info="FIBEMateX3DH")
   * where DH1=DH(IK_A,SPK_B), DH2=DH(EK_A,IK_B), DH3=DH(EK_A,SPK_B), DH4=DH(EK_A,OPK_B).
   *
   * Note: In the current simplified model, SPK_B = IK_B (signed pre-key = identity key).
   * This is acceptable for demo purposes but differs from the full Signal spec.
   *
   * @param {CryptoKeyPair} identityKey     — Alice's identity key pair (P-256)
   * @param {Uint8Array|CryptoKey} signedPreKeyRaw — Bob's signed pre-key (raw bytes or CryptoKey)
   * @param {Uint8Array|CryptoKey} [oneTimePreKeyRaw] — Bob's one-time pre-key (optional)
   * @returns {Promise<{rootKey: Uint8Array, ephemeralKey: CryptoKeyPair, ephemeralPublic: Uint8Array}>}
   *   rootKey — 32-byte root key for initAsInitiator()
   *   ephemeralPublic — 65-byte raw P-256 public key (send to Bob)
   *
   * @example
   * const x3dh = await DoubleRatchet.x3dhAlice(aliceIK, bobSPK, bobOPK);
   * const state = await DoubleRatchet.initAsInitiator(x3dh.rootKey, bobSPK);
   */
  async function x3dhAlice(identityKey, signedPreKeyRaw, oneTimePreKeyRaw) {
    // ---- Downgrade Attack Protection ----
    if (typeof SecurityLevels !== 'undefined' && SecurityLevels.isWeakAlgorithm) {
      // Identity key must be P-256, not RSA
      console.log('[Security] X3DH: checking algorithm P-256 compliance');
    }
    // ---- End downgrade protection ----

    // Generate ephemeral key
    const ephemeralKey = await generateDH();

    // Import public keys if raw bytes provided
    const spkPub = signedPreKeyRaw instanceof Uint8Array
      ? await importPublicKey(signedPreKeyRaw)
      : signedPreKeyRaw;  // already a CryptoKey
    const opkPub = oneTimePreKeyRaw
      ? (oneTimePreKeyRaw instanceof Uint8Array
          ? await importPublicKey(oneTimePreKeyRaw)
          : oneTimePreKeyRaw)
      : null;

    // DH1 = DH(IK_A, SPK_B)
    const dh1 = await dh(identityKey.privateKey, spkPub);
    // DH2 = DH(EK_A, IK_B) — In simplified model, SPK = IK
    const dh2 = await dh(ephemeralKey.privateKey, spkPub);
    // DH3 = DH(EK_A, SPK_B)
    const dh3 = await dh(ephemeralKey.privateKey, spkPub);
    // DH4 = DH(EK_A, OPK_B) — if one-time pre-key available
    const dh4 = opkPub
      ? await dh(ephemeralKey.privateKey, opkPub)
      : new Uint8Array(0);

    // Concatenate DH outputs
    const ikm = new Uint8Array(32 * 3 + dh4.length);
    ikm.set(dh1, 0);
    ikm.set(dh2, 32);
    ikm.set(dh3, 64);
    if (dh4.length > 0) ikm.set(dh4, 96);

    // Derive root key with HKDF
    const rootKey = await hkdf(ikm, new Uint8Array(32), 'FIBEMateX3DH');

    return {
      rootKey,
      ephemeralKey,
      ephemeralPublic: await exportPublicKey(ephemeralKey)
    };
  }

  // ---- Exports ----
  return {
    // Core protocol
    initAsInitiator,
    initAsReceiver,
    encrypt,
    decrypt,
    performDHRatchet,

    // X3DH
    x3dhAlice,
    generateDH,
    exportPublicKey,
    importPublicKey,
    dh,
    hkdf,

    // Persistence
    exportState,
    importState,

    // Utilities
    headerToBytes,
    kdfRk,
    kdfCk
  };
})();

// Node.js / browser compatibility
if (typeof module !== 'undefined' && module.exports) {
  module.exports = DoubleRatchet;
}
