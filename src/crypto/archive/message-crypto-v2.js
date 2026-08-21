// ============================================================
// FIBEMATE Message Crypto v2 — 完整前向保密
// 修复 v1 的 3 个断裂点：
//   #1 密钥交换从简化ECDH升级为完整X3DH (4-DH)
//   #2 加密消息不再明文发给后端，后端只转发opaque blob
//   #3 解密失败时明确告警，不静默降级
//
// 协议栈: X3DH → Double Ratchet → AES-256-GCM
// Curve: P-256 | KDF: HKDF-SHA-256 | AEAD: AES-256-GCM
// ============================================================

const MessageCryptoV2 = (() => {
  'use strict';

  // ---- Constants ----
  const DB_NAME = 'fibemate_crypto_v2';
  const STORE_SESSIONS = 'sessions';
  const STORE_IDENTITY = 'identity';
  const STORE_PREKEYS = 'prekeys';
  const MAX_SKIP = 1000;
  const PREKEY_BUNDLE_COUNT = 100;  // 服务端预存 signed pre-key 数量

  let db = null;

  // ============================================================
  // IndexedDB Persistence
  // ============================================================
  async function initDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => { db = request.result; resolve(db); };
      request.onupgradeneeded = (e) => {
        const database = e.target.result;
        if (!database.objectStoreNames.contains(STORE_SESSIONS))
          database.createObjectStore(STORE_SESSIONS, { keyPath: 'peerId' });
        if (!database.objectStoreNames.contains(STORE_IDENTITY))
          database.createObjectStore(STORE_IDENTITY, { keyPath: 'key' });
        if (!database.objectStoreNames.contains(STORE_PREKEYS))
          database.createObjectStore(STORE_PREKEYS, { keyPath: 'keyId' });
      };
    });
  }

  function tx(storeName, mode) {
    if (!db) throw new Error('[MessageCryptoV2] DB not initialized');
    return db.transaction(storeName, mode).objectStore(storeName);
  }

  function promisify(request) {
    return new Promise((resolve, reject) => {
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
    });
  }

  async function loadSession(peerId) {
    const result = await promisify(tx(STORE_SESSIONS, 'readonly').get(peerId));
    if (!result?.state) return null;
    try {
      return await DoubleRatchet.importState(result.state);
    } catch (e) {
      console.warn(`[MessageCryptoV2] Failed to import session for ${peerId}:`, e.message);
      return null;
    }
  }

  async function saveSession(peerId, state) {
    const exported = DoubleRatchet.exportState(state);
    await promisify(tx(STORE_SESSIONS, 'readwrite').put({ peerId, state: exported }));
  }

  async function deleteSession(peerId) {
    await promisify(tx(STORE_SESSIONS, 'readwise').delete(peerId));
  }

  // ---- Session Cache ----
  const sessionCache = new Map();

  async function getSession(peerId) {
    if (sessionCache.has(peerId)) return sessionCache.get(peerId);
    const state = await loadSession(peerId);
    if (state) sessionCache.set(peerId, state);
    return state;
  }

  async function updateSession(peerId, state) {
    sessionCache.set(peerId, state);
    await saveSession(peerId, state);
  }

  // ============================================================
  // Identity Key Management (长期密钥对，持久化)
  // ============================================================
  let _identityKeyPair = null;
  let _identitySigningKeyPair = null; // ECDSA P-256 for signing pre-keys

  async function getOrCreateIdentityKey() {
    if (_identityKeyPair) return _identityKeyPair;

    try {
      const result = await promisify(tx(STORE_IDENTITY, 'readonly').get('my_identity'));
      if (result?.pkcs8 && result?.rawPublic) {
        const privKey = await crypto.subtle.importKey(
          'pkcs8', new Uint8Array(result.pkcs8),
          { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
        );
        const pubKey = await DoubleRatchet.importPublicKey(new Uint8Array(result.rawPublic));
        _identityKeyPair = { publicKey: pubKey, privateKey: privKey };
        console.log('[MessageCryptoV2] Loaded identity key from storage');
        return _identityKeyPair;
      }
    } catch (e) {
      console.warn('[MessageCryptoV2] No identity key found, generating new one');
    }

    // Generate new identity key pair
    _identityKeyPair = await DoubleRatchet.generateDH();
    const rawPublic = await DoubleRatchet.exportPublicKey(_identityKeyPair);
    const pkcs8 = Array.from(new Uint8Array(
      await crypto.subtle.exportKey('pkcs8', _identityKeyPair.privateKey)
    ));
    await promisify(tx(STORE_IDENTITY, 'readwrite').put({
      key: 'my_identity', pkcs8, rawPublic: Array.from(rawPublic)
    }));
    console.log('[MessageCryptoV2] Generated new identity key');
    return _identityKeyPair;
  }



  // ============================================================
  // Identity Signing Key (ECDSA P-256, separate from ECDH key)
  // X3DH spec: identity key signs the signed pre-key to prevent MITM
  // ECDH keys can't sign in WebCrypto, so we need a dedicated signing key
  // ============================================================
  async function getOrCreateIdentitySigningKey() {
    if (_identitySigningKeyPair) return _identitySigningKeyPair;

    try {
      const result = await promisify(tx(STORE_IDENTITY, 'readonly').get('my_signing_key'));
      if (result?.pkcs8 && result?.rawPublic) {
        const privKey = await crypto.subtle.importKey(
          'pkcs8', new Uint8Array(result.pkcs8),
          { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']
        );
        const pubKey = await crypto.subtle.importKey(
          'spki', new Uint8Array(result.rawPublic),
          { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']
        );
        _identitySigningKeyPair = { publicKey: pubKey, privateKey: privKey };
        console.log('[MessageCryptoV2] Loaded identity signing key from storage');
        return _identitySigningKeyPair;
      }
    } catch (e) {
      console.warn('[MessageCryptoV2] No signing key found, generating new one');
    }

    // Generate new ECDSA P-256 signing key pair
    _identitySigningKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const rawPublic = Array.from(new Uint8Array(
      await crypto.subtle.exportKey('spki', _identitySigningKeyPair.publicKey)
    ));
    const pkcs8 = Array.from(new Uint8Array(
      await crypto.subtle.exportKey('pkcs8', _identitySigningKeyPair.privateKey)
    ));
    await promisify(tx(STORE_IDENTITY, 'readwrite').put({
      key: 'my_signing_key', pkcs8, rawPublic
    }));
    console.log('[MessageCryptoV2] Generated new identity signing key');
    return _identitySigningKeyPair;
  }

  /**
   * Sign a pre-key using the identity signing key
   * @param {Uint8Array} spkPublicBytes - The signed pre-key public key bytes to sign
   * @returns {Promise<Uint8Array>} - DER-encoded ECDSA signature
   */
  async function signPreKey(spkPublicBytes) {
    const signingKey = await getOrCreateIdentitySigningKey();
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      signingKey.privateKey,
      spkPublicBytes
    );
    return new Uint8Array(signature);
  }

  /**
   * Verify a pre-key signature (static method, used by Alice when fetching Bob's bundle)
   * @param {Uint8Array|number[]} signingPublicBytes - Identity signing public key (SPKI or raw)
   * @param {Uint8Array} spkPublicBytes - The signed pre-key public key bytes
   * @param {Uint8Array|number[]} signature - DER-encoded ECDSA signature
   * @returns {Promise<boolean>}
   */
  async function verifyPreKeySignature(signingPublicBytes, spkPublicBytes, signature) {
    try {
      // Import signing public key (SPKI format)
      const signingPubKey = await crypto.subtle.importKey(
        'spki',
        signingPublicBytes instanceof Uint8Array ? signingPublicBytes : new Uint8Array(signingPublicBytes),
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
      );
      const sigBytes = signature instanceof Uint8Array ? signature : new Uint8Array(signature);
      return await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        signingPubKey,
        sigBytes,
        spkPublicBytes
      );
    } catch (e) {
      console.error('[MessageCryptoV2] Pre-key signature verification failed:', e.message);
      return false;
    }
  }

  // ============================================================
  // One-Time Pre-Key (OPK) Management — P1-2 自动补充机制
  // ============================================================
  const OPK_BATCH_SIZE = 25;           // 每次补充 25 个 OPK
  const OPK_LOW_THRESHOLD = 10;        // 低于此值触发补充
  const OPK_TARGET_COUNT = 100;        // 目标保持 100 个 OPK
  let _opkReplenishTimer = null;       // 定时器引用
  let _opkUploadCallback = null;       // 外部上传回调 (privacyAPI.uploadPreKeyBundle)

  /**
   * 设置 OPK 上传回调（由上层初始化时注入）
   * @param {Function} callback - async (bundle) => uploadResult
   */
  function setOPKUploadCallback(callback) {
    _opkUploadCallback = callback;
  }

  /**
   * 生成一批 one-time pre-keys（一次性预密钥）
   * 这些密钥用于 X3DH 4-DH，每次会话消耗一个
   * @param {number} count - 生成数量
   * @returns {Promise<Array>} - [{ keyId, publicKey, privateKeyPkcs8 }]
   */
  async function generateOneTimePreKeys(count = OPK_BATCH_SIZE) {
    const opks = [];

    for (let i = 0; i < count; i++) {
      const opk = await DoubleRatchet.generateDH();
      const opkPublic = await DoubleRatchet.exportPublicKey(opk);
      const keyId = Date.now() + i;

      const privateKeyPkcs8 = Array.from(new Uint8Array(
        await crypto.subtle.exportKey('pkcs8', opk.privateKey)
      ));

      // 本地持久化
      await promisify(tx(STORE_PREKEYS, 'readwrite').put({
        keyId,
        privateKeyPkcs8,
        publicKey: Array.from(opkPublic),
        createdAt: Date.now(),
        type: 'opk'  // 标记为 one-time pre-key
      }));

      opks.push({
        keyId,
        publicKey: Array.from(opkPublic)
      });
    }

    console.log(`[MessageCryptoV2] Generated ${count} one-time pre-keys`);
    return opks;
  }

  /**
   * 获取本地剩余的 OPK 数量
   */
  async function getLocalOPKCount() {
    return new Promise((resolve, reject) => {
      const request = tx(STORE_PREKEYS, 'readonly').openCursor();
      let count = 0;
      request.onsuccess = (e) => {
        const cursor = e.target.result;
        if (cursor) {
          if (cursor.value.type === 'opk') count++;
          cursor.continue();
        } else {
          resolve(count);
        }
      };
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * 检查并补充 OPK（核心自动补充逻辑）
   * 触发条件：
   *   1. 启动时检查
   *   2. 每次收到 X3DH init 后检查
   *   3. 定时轮询（每 6 小时）
   * @param {boolean} force - 强制补充，忽略阈值
   * @returns {Promise<object>} - { replenished: boolean, uploaded: number, remaining: number }
   */
  async function checkAndReplenishOPKs(force = false) {
    const currentCount = await getLocalOPKCount();

    if (!force && currentCount >= OPK_LOW_THRESHOLD) {
      console.log(`[MessageCryptoV2] OPK check: ${currentCount} available (threshold: ${OPK_LOW_THRESHOLD})`);
      return { replenished: false, uploaded: 0, remaining: currentCount };
    }

    const needCount = OPK_TARGET_COUNT - currentCount;
    if (needCount <= 0) {
      return { replenished: false, uploaded: 0, remaining: currentCount };
    }

    console.log(`[MessageCryptoV2] OPK low: ${currentCount}/${OPK_TARGET_COUNT}, generating ${needCount}...`);

    // 生成新的 OPKs
    const newOPKs = await generateOneTimePreKeys(needCount);

    // 上传到服务器（需要回调）
    if (_opkUploadCallback) {
      try {
        // 获取当前 bundle 的其他部分
        const identityKey = await getOrCreateIdentityKey();
        const identityPublic = await DoubleRatchet.exportPublicKey(identityKey);
        const signingKey = await getOrCreateIdentitySigningKey();
        const signingPublic = new Uint8Array(
          await crypto.subtle.exportKey('spki', signingKey.publicKey)
        );

        // 获取或生成 signed pre-key
        const spk = await DoubleRatchet.generateDH();
        const spkPublic = await DoubleRatchet.exportPublicKey(spk);
        const spkId = Date.now();
        const spkSignature = await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          signingKey.privateKey,
          spkPublic
        );

        // 持久化 SPK 私钥
        await promisify(tx(STORE_PREKEYS, 'readwrite').put({
          keyId: spkId,
          privateKeyPkcs8: Array.from(new Uint8Array(
            await crypto.subtle.exportKey('pkcs8', spk.privateKey)
          )),
          publicKey: Array.from(spkPublic),
          createdAt: Date.now(),
          type: 'spk'
        }));

        const bundle = {
          identityKey: Array.from(identityPublic),
          identitySigningKey: Array.from(signingPublic),
          signedPreKey: Array.from(spkPublic),
          signedPreKeyId: spkId,
          signedPreKeySignature: Array.from(new Uint8Array(spkSignature)),
          oneTimePreKeys: newOPKs
        };

        const result = await _opkUploadCallback(bundle);
        console.log(`[MessageCryptoV2] OPK replenished: +${newOPKs.length}, server reports ${result.oneTimePreKeyCount || '?'} total`);

        return { replenished: true, uploaded: newOPKs.length, remaining: currentCount + newOPKs.length };
      } catch (err) {
        console.error('[MessageCryptoV2] OPK upload failed:', err.message);
        // 上传失败但本地已生成，下次会重试
        return { replenished: false, uploaded: 0, remaining: currentCount, error: err.message };
      }
    } else {
      console.warn('[MessageCryptoV2] No OPK upload callback set — cannot replenish');
      return { replenished: false, uploaded: 0, remaining: currentCount, error: 'No upload callback' };
    }
  }

  /**
   * 启动 OPK 自动补充定时器
   * 每 6 小时检查一次，同时监听页面可见性变化
   */
  function startOPKAutoReplenish() {
    // 立即检查一次
    checkAndReplenishOPKs();

    // 定时检查（6小时）
    if (_opkReplenishTimer) clearInterval(_opkReplenishTimer);
    _opkReplenishTimer = setInterval(() => {
      checkAndReplenishOPKs();
    }, 6 * 60 * 60 * 1000);

    // 页面重新可见时检查（用户可能长时间离开）
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
          console.log('[MessageCryptoV2] Page visible, checking OPK levels...');
          checkAndReplenishOPKs();
        }
      });
    }

    console.log('[MessageCryptoV2] OPK auto-replenish started (interval: 6h)');
  }

  /**
   * 停止 OPK 自动补充
   */
  function stopOPKAutoReplenish() {
    if (_opkReplenishTimer) {
      clearInterval(_opkReplenishTimer);
      _opkReplenishTimer = null;
    }
  }

  // ============================================================
  // Signed Pre-Key Bundle Management
  // ============================================================
  /**
   * 生成一批 signed pre-key 并上传到服务器
   * Signal 协议要求客户端定期刷新 pre-key bundle
   */
  async function generateAndUploadPreKeys(count = PREKEY_BUNDLE_COUNT) {
    const identityKey = await getOrCreateIdentityKey();
    const signingKey = await getOrCreateIdentitySigningKey();
    const signingPublic = new Uint8Array(
      await crypto.subtle.exportKey('spki', signingKey.publicKey)
    );
    const bundles = [];

    for (let i = 0; i < count; i++) {
      const spk = await DoubleRatchet.generateDH();
      const spkPublic = await DoubleRatchet.exportPublicKey(spk);

      // Sign the SPK with identity signing key (ECDSA P-256)
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        signingKey.privateKey,
        spkPublic
      );

      bundles.push({
        keyId: Date.now() + i,
        publicKey: Array.from(spkPublic),
        signature: Array.from(new Uint8Array(signature))
      });

      // 本地缓存
      await promisify(tx(STORE_PREKEYS, 'readwrite').put({
        keyId: Date.now() + i,
        privateKeyPkcs8: Array.from(new Uint8Array(
          await crypto.subtle.exportKey('pkcs8', spk.privateKey)
        )),
        publicKey: Array.from(spkPublic),
        createdAt: Date.now()
      }));
    }

    console.log(`[MessageCryptoV2] Generated ${count} signed pre-keys (ECDSA signed)`);
    return bundles;
  }

  // ============================================================
  // X3DH Key Exchange — 完整 4-DH 变体
  // ============================================================

  /**
   * 步骤 1: Alice 发起密钥交换
   * 从 Bob 的 pre-key bundle 中获取公钥，计算 X3DH shared secret
   *
   * @param {string} peerId - Bob's user ID
   * @param {object} bobBundle - Bob's pre-key bundle from server:
   *   { identityKey: number[], signedPreKey: number[], signedPreKeyId: number,
   *     oneTimePreKey?: number[] }
   * @returns {Promise<object>} - { initialMessage, bundleForBob }
   */
  async function initiateSession(peerId, bobBundle) {
    const identityKey = await getOrCreateIdentityKey();
    const identityPublic = await DoubleRatchet.exportPublicKey(identityKey);

    // 生成 ephemeral key (EK_A)
    const ephemeralKey = await DoubleRatchet.generateDH();
    const ephemeralPublic = await DoubleRatchet.exportPublicKey(ephemeralKey);

    // Import Bob's keys
    const bobIkPub = await DoubleRatchet.importPublicKey(new Uint8Array(bobBundle.identityKey));
    const bobSpkPub = await DoubleRatchet.importPublicKey(new Uint8Array(bobBundle.signedPreKey));

    // === SPK Signature Verification (MITM protection) ===
    if (bobBundle.identitySigningKey && bobBundle.signedPreKeySignature) {
      const sigValid = await verifyPreKeySignature(
        bobBundle.identitySigningKey,
        new Uint8Array(bobBundle.signedPreKey),
        bobBundle.signedPreKeySignature
      );
      if (!sigValid) {
        throw new Error(
          '[SECURITY ALERT] Signed pre-key signature verification FAILED!\n' +
          'Possible MITM attack — the signed pre-key may have been replaced.\n' +
          'DO NOT proceed with this session. Verify Safety Numbers out-of-band.'
        );
      }
      console.log('[MessageCryptoV2] SPK signature verified ✓ (MITM protection active)');
    } else {
      console.warn('[MessageCryptoV2] No SPK signature in bundle — MITM protection disabled');
    }

    // === X3DH 4-DH Computation ===

    // DH1 = DH(IK_A, SPK_B) — Alice's identity with Bob's signed pre-key
    const dh1 = await DoubleRatchet.dh(identityKey.privateKey, bobSpkPub);

    // DH2 = DH(EK_A, IK_B) — Alice's ephemeral with Bob's identity
    const dh2 = await DoubleRatchet.dh(ephemeralKey.privateKey, bobIkPub);

    // DH3 = DH(EK_A, SPK_B) — Alice's ephemeral with Bob's signed pre-key
    const dh3 = await DoubleRatchet.dh(ephemeralKey.privateKey, bobSpkPub);

    // DH4 = DH(EK_A, OPK_B) — Alice's ephemeral with Bob's one-time pre-key (optional)
    let dh4;
    if (bobBundle.oneTimePreKey) {
      const bobOpkPub = await DoubleRatchet.importPublicKey(new Uint8Array(bobBundle.oneTimePreKey));
      dh4 = await DoubleRatchet.dh(ephemeralKey.privateKey, bobOpkPub);
    } else {
      dh4 = new Uint8Array(0);
    }

    // Concatenate all DH outputs
    const ikm = new Uint8Array(32 * 3 + dh4.length);
    ikm.set(dh1, 0);
    ikm.set(dh2, 32);
    ikm.set(dh3, 64);
    if (dh4.length > 0) ikm.set(dh4, 96);

    // Derive root key via HKDF
    const rootKey = await DoubleRatchet.hkdf(ikm, new Uint8Array(32), 'FIBEMateX3DH');

    // Initialize Double Ratchet as initiator
    const state = await DoubleRatchet.initAsInitiator(rootKey, new Uint8Array(bobBundle.signedPreKey));

    // Save session immediately (forward secrecy starts now)
    await updateSession(peerId, state);

    // Store pending info for completion confirmation
    sessionCache.set(`_x3dh_${peerId}`, {
      ephemeralKey,
      bobSignedPreKeyId: bobBundle.signedPreKeyId,
      timestamp: Date.now()
    });

    console.log(`[MessageCryptoV2] X3DH initiated with ${peerId} (4-DH${dh4.length > 0 ? '' : '-noOPK'})`);

    return {
      // This is what gets sent to the server (and forwarded to Bob)
      initialMessage: {
        type: 'x3dh_init',
        identityKey: Array.from(identityPublic),
        ephemeralKey: Array.from(ephemeralPublic),
        signedPreKeyId: bobBundle.signedPreKeyId,
        oneTimePreKeyId: bobBundle.oneTimePreKeyId || null
      },
      // Local state is already saved
      sessionEstablished: true
    };
  }

  /**
   * 步骤 2: Bob 收到 Alice 的 X3DH 初始化消息，建立会话
   *
   * @param {string} peerId - Alice's user ID
   * @param {object} aliceInit - Alice's initial message:
   *   { identityKey: number[], ephemeralKey: number[],
   *     signedPreKeyId: number, oneTimePreKeyId?: number }
   * @returns {Promise<object>} - { responseMessage, sessionEstablished, sessionReady }
   */
  async function receiveSession(peerId, aliceInit) {
    const identityKey = await getOrCreateIdentityKey();
    const identityPublic = await DoubleRatchet.exportPublicKey(identityKey);

    // Find the used signed pre-key
    const usedSpk = await promisify(tx(STORE_PREKEYS, 'readonly').get(aliceInit.signedPreKeyId));
    if (!usedSpk) {
      throw new Error(`[MessageCryptoV2] Signed pre-key ${aliceInit.signedPreKeyId} not found`);
    }

    // Import used signed pre-key private key
    const spkPrivKey = await crypto.subtle.importKey(
      'pkcs8', new Uint8Array(usedSpk.privateKeyPkcs8),
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
    );

    // Import Alice's keys
    const aliceIkPub = await DoubleRatchet.importPublicKey(new Uint8Array(aliceInit.identityKey));
    const aliceEkPub = await DoubleRatchet.importPublicKey(new Uint8Array(aliceInit.ephemeralKey));

    // === X3DH 4-DH Computation (Bob side) ===

    // DH1 = DH(SPK_B, IK_A) — same as Alice's DH1
    const dh1 = await DoubleRatchet.dh(spkPrivKey, aliceIkPub);

    // DH2 = DH(IK_B, EK_A) — same as Alice's dh2
    const dh2 = await DoubleRatchet.dh(identityKey.privateKey, aliceEkPub);

    // DH3 = DH(SPK_B, EK_A) — same as Alice's dh3
    const dh3 = await DoubleRatchet.dh(spkPrivKey, aliceEkPub);

    // DH4 = DH(OPK_B, EK_A) if one-time pre-key was used
    let dh4;
    if (aliceInit.oneTimePreKeyId) {
      // Find and use the one-time pre-key
      const opkRecord = await promisify(tx(STORE_PREKEYS, 'readonly').get(aliceInit.oneTimePreKeyId));
      if (opkRecord) {
        const opkPrivKey = await crypto.subtle.importKey(
          'pkcs8', new Uint8Array(opkRecord.privateKeyPkcs8),
          { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
        );
        dh4 = await DoubleRatchet.dh(opkPrivKey, aliceEkPub);
        // Delete one-time pre-key after use (Signal spec: single-use)
        await promisify(tx(STORE_PREKEYS, 'readwise').delete(aliceInit.oneTimePreKeyId));
      }
    }
    if (!dh4) dh4 = new Uint8Array(0);

    // Concatenate (same order as Alice)
    const ikm = new Uint8Array(32 * 3 + dh4.length);
    ikm.set(dh1, 0);
    ikm.set(dh2, 32);
    ikm.set(dh3, 64);
    if (dh4.length > 0) ikm.set(dh4, 96);

    // Derive root key (MUST match Alice's computation)
    const rootKey = await DoubleRatchet.hkdf(ikm, new Uint8Array(32), 'FIBEMateX3DH');

    // Initialize Double Ratchet as receiver
    // Use the signed pre-key as initial self DH key
    const selfDH = { publicKey: await DoubleRatchet.importPublicKey(new Uint8Array(usedSpk.publicKey)), privateKey: spkPrivKey };
    const state = await DoubleRatchet.initAsReceiver(rootKey, selfDH);

    // Save session
    await updateSession(peerId, state);

    // Delete used signed pre-key (prevent reuse → forward secrecy)
    await promisify(tx(STORE_PREKEYS, 'readwise').delete(aliceInit.signedPreKeyId));

    console.log(`[MessageCryptoV2] X3DH received from ${peerId}, session established (receiver)`);

    return {
      responseMessage: {
        type: 'x3dh_accept',
        identityKey: Array.from(identityPublic),
        // Include Bob's public keys for Alice to verify and complete handshake
        publicKey: Array.from(identityPublic),
        ephemeralPublic: Array.from(usedSpk.publicKey),
        accepted: true,
        hybrid: false  // Standard X3DH (no ML-KEM yet)
      },
      sessionEstablished: true,
      sessionReady: true  // 兼容旧代码
    };
  }

  /**
   * 步骤 3 (可选): Alice 收到 Bob 的确认
   * 在当前实现中，session 在步骤 1 就已建立，
   * 此步骤仅用于确认对方已准备好接收消息
   */
  async function confirmSession(peerId, bobResponse) {
    const pending = sessionCache.get(`_x3dh_${peerId}`);
    if (!pending) {
      console.warn(`[MessageCryptoV2] No pending X3DH for ${peerId}, may already be confirmed`);
      return { confirmed: true };
    }

    sessionCache.delete(`_x3dh_${peerId}`);
    console.log(`[MessageCryptoV2] Session with ${peerId} confirmed by Bob`);
    return { confirmed: true };
  }

  // ============================================================
  // Encrypt / Decrypt — 核心接口
  // ============================================================

  /**
   * 加密消息（端到端）
   *
   * 前向保密保证：
   *   - 每条消息使用独立的 message key（由 chain key HMAC 推导）
   *   - chain key 单向推进，无法逆向推导之前的 key
   *   - DH ratchet 步骤后旧链密钥永久销毁（内存中覆盖）
   *
   * @param {string} peerId - 对方用户ID
   * @param {string} plaintext - 明文消息
   * @returns {Promise<object>} - Opaque encrypted envelope (server cannot read)
   */
  async function encrypt(peerId, plaintext) {
    const state = await getSession(peerId);
    if (!state) {
      throw new Error(
        `[MessageCryptoV2] No secure session with "${peerId}". ` +
        `前向保密会话未建立 — 需要先完成X3DH密钥交换。` +
        `请调用 initiateSession() 或等待对方发起。`
      );
    }

    const plaintextBytes = typeof plaintext === 'string'
      ? new TextEncoder().encode(plaintext)
      : plaintext;

    const result = await DoubleRatchet.encrypt(state, plaintextBytes);

    // 立即持久化状态（ratchet 已推进，必须保存）
    await updateSession(peerId, state);

    // 返回 opaque envelope — 后端只看到这个，无法解密
    return {
      version: 2,
      protocol: 'double-ratchet',
      // Opaque blob: 后端无法解读内部结构
      envelope: {
        h: result.header,       // ratchet header (contains DH pub key + pn + n)
        c: result.ciphertext,   // AES-256-GCM ciphertext
        iv: result.iv           // 96-bit nonce
      }
      // 注意：不暴露 rootKey, chainKey, messageKey 或任何中间密钥材料
    };
  }

  /**
   * 解密消息（端到端）
   *
   * @param {string} peerId - 对方用户ID
   * @param {object} envelope - encrypt() 返回的 opaque envelope
   * @returns {Promise<string>} - 明文消息
   * @throws {Error} 解密失败时抛出具体错误（不静默降级）
   */
  async function decrypt(peerId, envelope) {
    if (!envelope || envelope.version !== 2) {
      throw new Error(
        `[MessageCryptoV2] 无效的加密信封 (version=${envelope?.version ?? 'null'}). ` +
        `可能原因：消息来自不兼容的客户端版本，或传输中被篡改。`
      );
    }

    const state = await getSession(peerId);
    if (!state) {
      throw new Error(
        `[MessageCryptoV2] 无法解密来自 "${peerId}" 的消息：没有安全会话。 ` +
        `需要先与该用户建立X3DH会话。`
      );
    }

    const { h: header, c: ciphertext, iv } = envelope.envelope;

    try {
      const plaintextBytes = await DoubleRatchet.decrypt(
        state,
        header,
        ciphertext,
        iv
      );

      // 解密成功 → 持久化推进后的状态
      await updateSession(peerId, state);

      return new TextDecoder().decode(plaintextBytes);
    } catch (decryptError) {
      // === 断裂点 #3 修复：不静默降级 ===
      // 可能的原因：
      //   a) 消息被重放（replay attack）→ skipped keys 已消耗
      //   b) 对方的 DH ratchet 不同步
      //   c) 消息在传输中被篡改（AEAD authentication failure）
      //   d) 会话状态损坏
      console.error(`[MessageCryptoV2] DECRYPT FAILED for ${peerId}:`, decryptError.message);

      // 尝试恢复：重建会话
      if (decryptError.message.includes('skipped') || decryptError.message.includes('chain')) {
        console.warn(`[MessageCryptoV2] Attempting session reset for ${peerId}`);
        // 不自动删除 — 让上层决定是否重新协商
      }

      throw new Error(
        `[SECURITY ALERT] 解密失败: ${decryptError.message}\n` +
        `联系人: ${peerId}\n` +
        `建议操作：\n` +
        `  1. 检查 Safety Numbers 是否匹配（可能中间人攻击）\n` +
        `  2. 如果持续失败，需重新协商会话（重置加密）\n` +
        `  3. 不要忽略此警告 — 安全可能已受损`
      );
    }
  }

  // ============================================================
  // Session Management
  // ============================================================

  async function hasSession(peerId) {
    const state = await getSession(peerId);
    return state !== null;
  }

  async function resetSession(peerId) {
    sessionCache.delete(peerId);
    await deleteSession(peerId);
    console.log(`[MessageCryptoV2] Session reset for ${peerId} — forward secrecy re-established on next exchange`);
  }

  /**
   * 获取安全状态摘要（供 UI 显示）
   */
  async function getSecurityStatus(peerId) {
    const state = await getSession(peerId);
    if (!state) {
      return { secured: false, protocol: null, forwardSecrecy: false };
    }

    return {
      secured: true,
      protocol: 'Double Ratchet (Signal Protocol)',
      curve: 'P-256 / NIST P-256',
      kdf: 'HKDF-SHA-256',
      aead: 'AES-256-GCM',
      forwardSecrecy: true,         // ✅ 前向保密已激活
      futureSecrecy: true,          // ✅ 后向保密（新 DH ratchet 后旧密钥不可推导）
      messagesSent: state.sendMessageNumber,
      messagesReceived: state.recvMessageNumber,
      hasReceivingChain: state.receivingChainKey !== null,
      skippedKeysCount: state.skippedKeys.size,
      sessionAge: Date.now() - (state._createdAt || Date.now())
    };
  }

  // ============================================================
  // Pre-Key Bundle API (for server interaction)
  // ============================================================

  /**
   * 获取自己的 pre-key bundle（上传到服务器供他人发起会话）
   */
  async function getMyPreKeyBundle() {
    const identityKey = await getOrCreateIdentityKey();
    const identityPublic = await DoubleRatchet.exportPublicKey(identityKey);
    const signingKey = await getOrCreateIdentitySigningKey();
    const signingPublic = new Uint8Array(
      await crypto.subtle.exportKey('spki', signingKey.publicKey)
    );

    // Get or generate a fresh signed pre-key
    const spk = await DoubleRatchet.generateDH();
    const spkPublic = await DoubleRatchet.exportPublicKey(spk);
    const spkId = Date.now();

    // Sign the SPK with identity signing key
    const spkSignature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      signingKey.privateKey,
      spkPublic
    );

    // Persist the private key
    await promisify(tx(STORE_PREKEYS, 'readwrite').put({
      keyId: spkId,
      privateKeyPkcs8: Array.from(new Uint8Array(
        await crypto.subtle.exportKey('pkcs8', spk.privateKey)
      )),
      publicKey: Array.from(spkPublic),
      createdAt: Date.now()
    }));

    return {
      identityKey: Array.from(identityPublic),
      identitySigningKey: Array.from(signingPublic),   // SPKI-encoded ECDSA public key
      signedPreKey: Array.from(spkPublic),
      signedPreKeyId: spkId,
      signedPreKeySignature: Array.from(new Uint8Array(spkSignature))  // DER-encoded ECDSA sig
    };
  }

  // ============================================================
  // Safety Number Fingerprint (P1-3: unified with X3DH identity key)
  // Generates a Signal-style 60-digit fingerprint from two identity keys
  // ============================================================
  async function getSafetyNumberFingerprint(localUserId, remoteUserId, remoteIdentityKeyBytes) {
    const identityKey = await getOrCreateIdentityKey();
    const localPublic = await DoubleRatchet.exportPublicKey(identityKey);

    // Sort user IDs for deterministic ordering (both sides compute same number)
    const ids = [localUserId, remoteUserId].sort();
    const keys = ids[0] === localUserId
      ? [localPublic, new Uint8Array(remoteIdentityKeyBytes)]
      : [new Uint8Array(remoteIdentityKeyBytes), localPublic];

    // Concatenate: id1 + key1 + id2 + key2
    const id1Bytes = new TextEncoder().encode(ids[0]);
    const id2Bytes = new TextEncoder().encode(ids[1]);
    const data = new Uint8Array(id1Bytes.length + keys[0].length + id2Bytes.length + keys[1].length);
    let offset = 0;
    data.set(id1Bytes, offset); offset += id1Bytes.length;
    data.set(keys[0], offset); offset += keys[0].length;
    data.set(id2Bytes, offset); offset += id2Bytes.length;
    data.set(keys[1], offset);

    // SHA-512 hash, then format as 12 groups of 5 digits
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-512', data));
    // Take first 30 bytes, each maps to 2 decimal digits → 60 digits → 12 groups of 5
    const digits = [];
    for (let i = 0; i < 30; i++) {
      const d = hash[i];
      digits.push(Math.floor(d / 25.6).toString().padStart(2, '0'));  // 0-99
    }
    const fullNumber = digits.join('');
    // Group into 12 blocks of 5 digits
    const blocks = [];
    for (let i = 0; i < 60; i += 5) {
      blocks.push(fullNumber.slice(i, i + 5));
    }
    return blocks.join(' ');
  }

  // ============================================================
  // Public API
  // ============================================================
  return {
    // Version
    version: 2,

    // Initialization
    init: initDB,

    // Identity & Pre-keys
    getMyPreKeyBundle,
    generateAndUploadPreKeys,

    // OPK Auto-Replenishment (P1-2)
    setOPKUploadCallback,
    checkAndReplenishOPKs,
    startOPKAutoReplenish,
    stopOPKAutoReplenish,
    getLocalOPKCount,
    generateOneTimePreKeys,

    // X3DH Key Exchange (完整 4-DH)
    initiateSession,     // Alice initiates
    receiveSession,      // Bob receives
    confirmSession,      // Optional confirmation

    // Core Encryption (端到端)
    encrypt,
    decrypt,
    hasSession,

    // Session Management
    resetSession,
    getSecurityStatus,
    deleteSession,

    // Safety Numbers (P1-3: X3DH identity key fingerprint)
    getSafetyNumberFingerprint,

    // Signing (P1: ECDSA signed pre-key)
    getIdentitySigningKey: getOrCreateIdentitySigningKey,
    signPreKey,
    verifyPreKeySignature,

    // Post-Quantum Integration (ML-KEM-768 hybrid)
    /**
     * Generate hybrid pre-key bundle with ML-KEM-768
     * Includes both classical ECDH and post-quantum KEM public keys
     */
    async getHybridPreKeyBundle() {
      const bundle = await getMyPreKeyBundle();
      
      // Check if ML-KEM-768 is available (WASM or JS)
      const mlkem = (typeof window !== 'undefined' && window.MLKEM768) ? window.MLKEM768 : null;
      
      if (mlkem && mlkem.keygen) {
        try {
          // Generate ML-KEM-768 keypair
          const kemKeypair = await mlkem.keygen();
          
          // Add KEM public key to bundle
          bundle.kemPublicKey = Array.from(kemKeypair.publicKey);
          bundle.kemKeyId = Date.now();
          bundle.hybrid = true;
          
          // Store KEM secret key locally
          await promisify(tx(STORE_PREKEYS, 'readwrite').put({
            keyId: 'kem_' + bundle.kemKeyId,
            kemSecretKey: Array.from(kemKeypair.secretKey),
            kemPublicKey: Array.from(kemKeypair.publicKey),
            createdAt: Date.now(),
            type: 'kem'
          }));
          
          console.log('[MessageCryptoV2] Hybrid pre-key bundle generated (ML-KEM-768 + ECDH)');
        } catch (err) {
          console.warn('[MessageCryptoV2] ML-KEM-768 keygen failed, using classical only:', err);
          bundle.hybrid = false;
        }
      } else {
        console.log('[MessageCryptoV2] ML-KEM-768 not available, using classical X3DH only');
        bundle.hybrid = false;
      }
      
      return bundle;
    },

    /**
     * Perform hybrid X3DH key agreement with ML-KEM-768 encapsulation
     * Combines classical ECDH shared secret with post-quantum KEM shared secret
     * 
     * @param {string} peerId - Target user ID
     * @param {object} bobBundle - Bob's pre-key bundle with optional kemPublicKey
     * @returns {Promise<object>} - { initialMessage, sessionEstablished, hybrid, kemCiphertext? }
     */
    async initiateHybridSession(peerId, bobBundle) {
      const mlkem = (typeof window !== 'undefined' && window.MLKEM768) ? window.MLKEM768 : null;
      const usePQ = mlkem && mlkem.initialized && bobBundle.kemPublicKey && bobBundle.hybrid;
      
      // Step 1: Standard ECDH X3DH (always performed)
      const identityKey = await getOrCreateIdentityKey();
      const identityPublic = await DoubleRatchet.exportPublicKey(identityKey);
      
      // Generate ephemeral key (EK_A)
      const ephemeralKey = await DoubleRatchet.generateDH();
      const ephemeralPublic = await DoubleRatchet.exportPublicKey(ephemeralKey);
      
      // Import Bob's keys
      const bobIkPub = await DoubleRatchet.importPublicKey(new Uint8Array(bobBundle.identityKey));
      const bobSpkPub = await DoubleRatchet.importPublicKey(new Uint8Array(bobBundle.signedPreKey));
      
      // SPK Signature Verification
      if (bobBundle.identitySigningKey && bobBundle.signedPreKeySignature) {
        const sigValid = await verifyPreKeySignature(
          bobBundle.identitySigningKey,
          new Uint8Array(bobBundle.signedPreKey),
          bobBundle.signedPreKeySignature
        );
        if (!sigValid) {
          throw new Error(
            '[SECURITY ALERT] Signed pre-key signature verification FAILED!\n' +
            'Possible MITM attack — the signed pre-key may have been replaced.\n' +
            'DO NOT proceed with this session. Verify Safety Numbers out-of-band.'
          );
        }
        console.log('[MessageCryptoV2] SPK signature verified ✓ (MITM protection active)');
      }
      
      // X3DH 4-DH Computation
      const dh1 = await DoubleRatchet.dh(identityKey.privateKey, bobSpkPub);
      const dh2 = await DoubleRatchet.dh(ephemeralKey.privateKey, bobIkPub);
      const dh3 = await DoubleRatchet.dh(ephemeralKey.privateKey, bobSpkPub);
      
      let dh4 = new Uint8Array(0);
      if (bobBundle.oneTimePreKey) {
        const bobOpkPub = await DoubleRatchet.importPublicKey(new Uint8Array(bobBundle.oneTimePreKey));
        dh4 = await DoubleRatchet.dh(ephemeralKey.privateKey, bobOpkPub);
      }
      
      // Concatenate DH outputs
      const ecdhIkm = new Uint8Array(32 * 3 + dh4.length);
      ecdhIkm.set(dh1, 0);
      ecdhIkm.set(dh2, 32);
      ecdhIkm.set(dh3, 64);
      if (dh4.length > 0) ecdhIkm.set(dh4, 96);
      
      // Step 2: Post-Quantum Key Exchange (ML-KEM-768)
      let kemCiphertext = null;
      let kemSharedSecret = null;
      
      if (usePQ) {
        try {
          console.log('[MessageCryptoV2] Performing ML-KEM-768 encapsulation...');
          const kemPublicKey = new Uint8Array(bobBundle.kemPublicKey);
          
          // Use WASM encapsulate function
          const encResult = mlkem.encaps(kemPublicKey);
          
          // Handle both async and sync returns
          const kemResult = encResult instanceof Promise ? await encResult : encResult;
          
          kemCiphertext = kemResult.ciphertext;
          kemSharedSecret = kemResult.shared_secret;
          
          console.log('[MessageCryptoV2] ML-KEM-768 encapsulation complete ✓');
        } catch (err) {
          console.warn('[MessageCryptoV2] ML-KEM-768 encapsulation failed:', err.message);
          // Continue with classical only
        }
      }
      
      // Step 3: Combine secrets (hybrid or classical)
      let rootKey;
      if (kemSharedSecret) {
        // Hybrid: ECDH || KEM -> HKDF
        const combinedIkm = new Uint8Array(ecdhIkm.length + kemSharedSecret.length);
        combinedIkm.set(ecdhIkm, 0);
        combinedIkm.set(kemSharedSecret, ecdhIkm.length);
        rootKey = await DoubleRatchet.hkdf(combinedIkm, new Uint8Array(32), 'FIBEMateHybridX3DH');
        console.log('[MessageCryptoV2] Hybrid root key derived (ECDH + ML-KEM-768)');
      } else {
        // Classical only
        rootKey = await DoubleRatchet.hkdf(ecdhIkm, new Uint8Array(32), 'FIBEMateX3DH');
      }
      
      // Initialize Double Ratchet
      const state = await DoubleRatchet.initAsInitiator(rootKey, new Uint8Array(bobBundle.signedPreKey));
      await updateSession(peerId, state);
      
      // Store pending info
      sessionCache.set(`_x3dh_${peerId}`, {
        ephemeralKey,
        bobSignedPreKeyId: bobBundle.signedPreKeyId,
        timestamp: Date.now(),
        hybrid: !!kemSharedSecret
      });
      
      // Build initial message
      const initialMessage = {
        type: 'x3dh_init',
        identityKey: Array.from(identityPublic),
        ephemeralKey: Array.from(ephemeralPublic),
        signedPreKeyId: bobBundle.signedPreKeyId,
        oneTimePreKeyId: bobBundle.oneTimePreKeyId || null,
        hybrid: !!kemSharedSecret
      };
      
      if (kemCiphertext) {
        initialMessage.kemCiphertext = Array.from(kemCiphertext);
        initialMessage.kemKeyId = bobBundle.kemKeyId;  // Bob needs this to find the secret key
      }
      
      console.log(`[MessageCryptoV2] X3DH initiated with ${peerId} (${kemSharedSecret ? 'hybrid' : 'classical'})`);
      
      return {
        initialMessage,
        sessionEstablished: true,
        hybrid: !!kemSharedSecret,
        kemCiphertext: kemCiphertext ? Array.from(kemCiphertext) : null
      };
    },
    
    /**
     * Receive hybrid X3DH initialization (Bob side)
     * @param {string} peerId - Alice's user ID
     * @param {object} aliceInit - Alice's init message
     * @returns {Promise<object>} - { responseMessage, sessionEstablished, sessionReady, hybrid }
     */
    async receiveHybridSession(peerId, aliceInit) {
      const identityKey = await getOrCreateIdentityKey();
      const identityPublic = await DoubleRatchet.exportPublicKey(identityKey);
      
      // Find used signed pre-key
      const usedSpk = await promisify(tx(STORE_PREKEYS, 'readonly').get(aliceInit.signedPreKeyId));
      if (!usedSpk) {
        throw new Error(`[MessageCryptoV2] Signed pre-key ${aliceInit.signedPreKeyId} not found`);
      }
      
      const spkPrivKey = await crypto.subtle.importKey(
        'pkcs8', new Uint8Array(usedSpk.privateKeyPkcs8),
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
      );
      
      // Import Alice's keys
      const aliceIkPub = await DoubleRatchet.importPublicKey(new Uint8Array(aliceInit.identityKey));
      const aliceEkPub = await DoubleRatchet.importPublicKey(new Uint8Array(aliceInit.ephemeralKey));
      
      // ECDH computations
      const dh1 = await DoubleRatchet.dh(spkPrivKey, aliceIkPub);
      const dh2 = await DoubleRatchet.dh(identityKey.privateKey, aliceEkPub);
      const dh3 = await DoubleRatchet.dh(spkPrivKey, aliceEkPub);
      
      // DH4 with OPK
      let dh4 = new Uint8Array(0);
      if (aliceInit.oneTimePreKeyId) {
        const opkRecord = await promisify(tx(STORE_PREKEYS, 'readonly').get(aliceInit.oneTimePreKeyId));
        if (opkRecord) {
          const opkPrivKey = await crypto.subtle.importKey(
            'pkcs8', new Uint8Array(opkRecord.privateKeyPkcs8),
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
          );
          dh4 = await DoubleRatchet.dh(opkPrivKey, aliceEkPub);
          await promisify(tx(STORE_PREKEYS, 'readwrite').delete(aliceInit.oneTimePreKeyId));
        }
      }
      
      // Build ECDH IKM
      const ecdhIkm = new Uint8Array(32 * 3 + dh4.length);
      ecdhIkm.set(dh1, 0);
      ecdhIkm.set(dh2, 32);
      ecdhIkm.set(dh3, 64);
      if (dh4.length > 0) ecdhIkm.set(dh4, 96);
      
      // Post-Quantum Decapsulation
      let kemSharedSecret = null;
      if (aliceInit.hybrid && aliceInit.kemCiphertext) {
        const mlkem = (typeof window !== 'undefined' && window.MLKEM768) ? window.MLKEM768 : null;
        if (mlkem && mlkem.initialized) {
          try {
            // Find KEM secret key
            const kemRecord = await promisify(tx(STORE_PREKEYS, 'readonly').get('kem_' + aliceInit.kemKeyId));
            if (kemRecord && kemRecord.kemSecretKey) {
              console.log('[MessageCryptoV2] Performing ML-KEM-768 decapsulation...');
              const secretKey = new Uint8Array(kemRecord.kemSecretKey);
              const ciphertext = new Uint8Array(aliceInit.kemCiphertext);
              
              const decResult = mlkem.decaps(secretKey, ciphertext);
              // decaps may return sharedSecret directly or a Promise
              kemSharedSecret = decResult instanceof Promise ? await decResult : decResult;
              // If result is an object (wrapper format), extract sharedSecret
              if (kemSharedSecret && typeof kemSharedSecret === 'object' && kemSharedSecret.sharedSecret) {
                kemSharedSecret = kemSharedSecret.sharedSecret;
              }
              
              console.log('[MessageCryptoV2] ML-KEM-768 decapsulation complete ✓');
            }
          } catch (err) {
            console.warn('[MessageCryptoV2] ML-KEM-768 decapsulation failed:', err.message);
          }
        }
      }
      
      // Derive root key
      let rootKey;
      if (kemSharedSecret) {
        const combinedIkm = new Uint8Array(ecdhIkm.length + kemSharedSecret.length);
        combinedIkm.set(ecdhIkm, 0);
        combinedIkm.set(kemSharedSecret, ecdhIkm.length);
        rootKey = await DoubleRatchet.hkdf(combinedIkm, new Uint8Array(32), 'FIBEMateHybridX3DH');
      } else {
        rootKey = await DoubleRatchet.hkdf(ecdhIkm, new Uint8Array(32), 'FIBEMateX3DH');
      }
      
      // Initialize Double Ratchet
      const selfDH = { 
        publicKey: await DoubleRatchet.importPublicKey(new Uint8Array(usedSpk.publicKey)), 
        privateKey: spkPrivKey 
      };
      const state = await DoubleRatchet.initAsReceiver(rootKey, selfDH);
      await updateSession(peerId, state);
      
      // Delete used SPK
      await promisify(tx(STORE_PREKEYS, 'readwrite').delete(aliceInit.signedPreKeyId));
      
      console.log(`[MessageCryptoV2] X3DH received from ${peerId} (${kemSharedSecret ? 'hybrid' : 'classical'})`);
      
      return {
        responseMessage: {
          type: 'x3dh_accept',
          identityKey: Array.from(identityPublic),
          publicKey: Array.from(identityPublic),      // For Alice to verify
          ephemeralPublic: Array.from(usedSpk.publicKey),  // Bob's SPK for confirmation
          accepted: true,
          hybrid: !!kemSharedSecret
        },
        sessionEstablished: true,
        sessionReady: true,  // 兼容旧代码
        hybrid: !!kemSharedSecret
      };
    },
    
    /**
     * Legacy hybrid X3DH (deprecated, use initiateHybridSession)
     */
    async hybridX3DHInitiate(peerBundle) {
      console.warn('[MessageCryptoV2] hybridX3DHInitiate is deprecated, use initiateHybridSession');
      return this.initiateHybridSession('legacy', peerBundle);
    },

    // Internal access (for testing/debugging)
    _getIdentityKey: getOrCreateIdentityKey,
    _getSession: getSession,
  };
})();

// Global export
if (typeof window !== 'undefined') {
  window.MessageCryptoV2 = MessageCryptoV2;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = MessageCryptoV2;
}
