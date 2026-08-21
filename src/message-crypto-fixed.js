// ============================================================
// FIBEMATE Message Crypto - Double Ratchet Session Manager (Fixed)
// 管理多个peer的加密会话，提供简单API供main.js调用
// 修复：使用完整的X3DH密钥交换
// ============================================================

const MessageCrypto = (() => {
  'use strict';

  const DB_NAME = 'fibemate_crypto';
  const STORE_NAME = 'sessions';
  let db = null;

  // ---- IndexedDB初始化 ----
  async function initDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        db = request.result;
        resolve(db);
      };
      request.onupgradeneeded = (e) => {
        const database = e.target.result;
        if (!database.objectStoreNames.contains(STORE_NAME)) {
          database.createObjectStore(STORE_NAME, { keyPath: 'peerId' });
        }
      };
    });
  }

  // ---- 加载会话状态 ----
  async function loadSession(peerId) {
    if (!db) await initDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const request = store.get(peerId);
      request.onerror = () => reject(request.error);
      request.onsuccess = async () => {
        if (request.result && request.result.state) {
          try {
            const state = await DoubleRatchet.importState(request.result.state);
            console.log(`[MessageCrypto] Loaded session for ${peerId}`);
            resolve(state);
          } catch (e) {
            console.warn(`[MessageCrypto] Failed to import session:`, e.message);
            resolve(null);
          }
        } else {
          resolve(null);
        }
      };
    });
  }

  // ---- 保存会话状态 ----
  async function saveSession(peerId, state) {
    if (!db) await initDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const exported = DoubleRatchet.exportState(state);
      const request = store.put({ peerId, state: exported });
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        console.log(`[MessageCrypto] Saved session for ${peerId}`);
        resolve();
      };
    });
  }

  // ---- 删除会话 ----
  async function deleteSession(peerId) {
    if (!db) await initDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const request = store.delete(peerId);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        console.log(`[MessageCrypto] Deleted session for ${peerId}`);
        resolve();
      };
    });
  }

  // ---- 会话缓存（内存） ----
  const sessionCache = new Map();

  // ---- 获取或加载会话 ----
  async function getSession(peerId) {
    if (sessionCache.has(peerId)) {
      return sessionCache.get(peerId);
    }
    const state = await loadSession(peerId);
    if (state) {
      sessionCache.set(peerId, state);
    }
    return state;
  }

  // ---- 更新会话缓存并持久化 ----
  async function updateSession(peerId, state) {
    sessionCache.set(peerId, state);
    await saveSession(peerId, state);
  }

  // ---- 检查会话是否存在 ----
  async function hasSession(peerId) {
    const state = await getSession(peerId);
    return state !== null;
  }

  // ============================================================
  // 核心加密接口
  // ============================================================

  /**
   * 加密消息
   * @param {string} peerId - 对方用户ID
   * @param {string} plaintext - 明文消息
   * @returns {Promise<{ciphertext: number[], header: object}>} - 密文和ratchet header
   */
  async function encrypt(peerId, plaintext) {
    let state = await getSession(peerId);
    
    if (!state) {
      throw new Error(`[MessageCrypto] No session with ${peerId} — need key exchange first`);
    }

    // 调用Double Ratchet加密
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(plaintext);
    
    const result = await DoubleRatchet.encrypt(state, plaintextBytes);
    
    // 更新并持久化状态
    await updateSession(peerId, state);
    
    // 返回可序列化的格式（包含iv用于解密）
    return {
      ciphertext: Array.from(result.ciphertext),
      iv: Array.from(result.iv),
      header: {
        dh: Array.from(result.header.dh),
        pn: result.header.pn,
        n: result.header.n
      }
    };
  }

  /**
   * 解密消息
   * @param {string} peerId - 对方用户ID
   * @param {number[]} ciphertext - 密文字节数组
   * @param {object} header - Ratchet header
   * @returns {Promise<string>} - 明文消息
   */
  async function decrypt(peerId, ciphertext, iv, header) {
    let state = await getSession(peerId);
    
    if (!state) {
      throw new Error(`[MessageCrypto] No session with ${peerId} — need key exchange first`);
    }

    // 重建header对象
    const ratchetHeader = {
      dh: new Uint8Array(header.dh),
      pn: header.pn,
      n: header.n
    };

    // 调用Double Ratchet解密（需要iv参数）
    const plaintextBytes = await DoubleRatchet.decrypt(
      state,
      ratchetHeader,
      new Uint8Array(ciphertext),
      new Uint8Array(iv)
    );
    
    // 更新并持久化状态
    await updateSession(peerId, state);
    
    // 返回明文字符串
    const decoder = new TextDecoder();
    return decoder.decode(plaintextBytes);
  }

  // ============================================================
  // 密钥交换（Key Exchange）- 修复版：完整X3DH
  // ============================================================

  /**
   * 发起密钥交换（Alice角色 - 主动方）
   * 生成identity key和ephemeral key，发送public keys给对方
   * @param {string} peerId - 对方用户ID
   * @returns {Promise<{identityPublic: number[], ephemeralPublic: number[]}>}
   */
  async function initiateKeyExchange(peerId) {
    // 生成identity密钥对（长期密钥）
    const identityKey = await DoubleRatchet.generateDH();
    const identityPublic = await DoubleRatchet.exportPublicKey(identityKey);
    
    // 生成ephemeral密钥对（临时密钥）
    const ephemeralKey = await DoubleRatchet.generateDH();
    const ephemeralPublic = await DoubleRatchet.exportPublicKey(ephemeralKey);
    
    // 存储待完成的状态（等待Bob的响应）
    const pendingState = {
      identityKey,
      ephemeralKey,
      role: 'initiator',
      timestamp: Date.now()
    };
    
    sessionCache.set(`_pending_${peerId}`, pendingState);
    
    console.log(`[MessageCrypto] Initiated key exchange with ${peerId}`);
    
    return {
      identityPublic: Array.from(identityPublic),
      ephemeralPublic: Array.from(ephemeralPublic)
    };
  }

  /**
   * 响应密钥交换（Bob角色 - 被动方）
   * 接收Alice的identity key和ephemeral key，计算X3DH shared secret
   * @param {string} peerId - 对方用户ID
   * @param {number[]} aliceIdentityPublic - Alice的身份公钥
   * @param {number[]} aliceEphemeralPublic - Alice的临时公钥
   * @returns {Promise<{identityPublic: number[], signedPreKeyPublic: number[]}>}
   */
  async function respondKeyExchange(peerId, aliceIdentityPublic, aliceEphemeralPublic) {
    // 生成自己的identity密钥对（长期密钥）
    const identityKey = await DoubleRatchet.generateDH();
    const identityPublic = await DoubleRatchet.exportPublicKey(identityKey);
    
    // 生成signed pre-key（中期密钥）
    const signedPreKey = await DoubleRatchet.generateDH();
    const signedPreKeyPublic = await DoubleRatchet.exportPublicKey(signedPreKey);
    
    // 导入Alice的公钥
    const aliceIdPub = await DoubleRatchet.importPublicKey(new Uint8Array(aliceIdentityPublic));
    const aliceEpPub = await DoubleRatchet.importPublicKey(new Uint8Array(aliceEphemeralPublic));
    
    // X3DH: 计算3个DH值
    // DH1 = DH(SPK_B, IK_A)
    const dh1 = await DoubleRatchet.dh(signedPreKey.privateKey, aliceIdPub);
    // DH2 = DH(IK_B, EK_A)
    const dh2 = await DoubleRatchet.dh(identityKey.privateKey, aliceEpPub);
    // DH3 = DH(SPK_B, EK_A)
    const dh3 = await DoubleRatchet.dh(signedPreKey.privateKey, aliceEpPub);
    
    // 合并DH输出
    const ikm = new Uint8Array(32 * 3);
    ikm.set(dh1, 0);
    ikm.set(dh2, 32);
    ikm.set(dh3, 64);
    
    // 派生root key
    const rootKey = await DoubleRatchet.hkdf(
      ikm,
      new Uint8Array(32),
      'FIBEMateX3DH'
    );
    
    // 初始化Double Ratchet作为接收方
    const state = await DoubleRatchet.initAsReceiver(rootKey, signedPreKey);
    
    // 保存会话
    await updateSession(peerId, state);
    
    console.log(`[MessageCrypto] Established session with ${peerId} (as receiver)`);
    
    return {
      identityPublic: Array.from(identityPublic),
      signedPreKeyPublic: Array.from(signedPreKeyPublic)
    };
  }

  /**
   * 完成密钥交换（Alice收到Bob的响应后）
   * @param {string} peerId - 对方用户ID
   * @param {number[]} bobIdentityPublic - Bob的身份公钥
   * @param {number[]} bobSignedPreKeyPublic - Bob的signed pre-key公钥
   */
  async function completeKeyExchange(peerId, bobIdentityPublic, bobSignedPreKeyPublic) {
    const pending = sessionCache.get(`_pending_${peerId}`);
    if (!pending) {
      throw new Error(`[MessageCrypto] No pending key exchange with ${peerId}`);
    }
    
    const { identityKey, ephemeralKey } = pending;
    
    // 导入Bob的公钥
    const bobIdPub = await DoubleRatchet.importPublicKey(new Uint8Array(bobIdentityPublic));
    const bobSpkPub = await DoubleRatchet.importPublicKey(new Uint8Array(bobSignedPreKeyPublic));
    
    // X3DH: 计算3个DH值（Alice侧）
    // DH1 = DH(IK_A, SPK_B)
    const dh1 = await DoubleRatchet.dh(identityKey.privateKey, bobSpkPub);
    // DH2 = DH(EK_A, IK_B)
    const dh2 = await DoubleRatchet.dh(ephemeralKey.privateKey, bobIdPub);
    // DH3 = DH(EK_A, SPK_B)
    const dh3 = await DoubleRatchet.dh(ephemeralKey.privateKey, bobSpkPub);
    
    // 合并DH输出
    const ikm = new Uint8Array(32 * 3);
    ikm.set(dh1, 0);
    ikm.set(dh2, 32);
    ikm.set(dh3, 64);
    
    // 派生root key（必须与Bob的计算结果一致）
    const rootKey = await DoubleRatchet.hkdf(
      ikm,
      new Uint8Array(32),
      'FIBEMateX3DH'
    );
    
    // 初始化Double Ratchet作为发起方
    const state = await DoubleRatchet.initAsInitiator(
      rootKey,
      new Uint8Array(bobSignedPreKeyPublic)  // remote DH public
    );
    
    // 保存会话
    await updateSession(peerId, state);
    
    // 清理pending状态
    sessionCache.delete(`_pending_${peerId}`);
    
    console.log(`[MessageCrypto] Established session with ${peerId} (as initiator)`);
  }

  // ============================================================
  // 导出API
  // ============================================================
  
  return {
    // 核心加密接口
    encrypt,
    decrypt,
    hasSession,
    
    // 密钥交换
    initiateKeyExchange,
    respondKeyExchange,
    completeKeyExchange,
    
    // 会话管理
    deleteSession,
    
    // 初始化
    initDB
  };
})();

// 全局导出
if (typeof window !== 'undefined') {
  window.MessageCrypto = MessageCrypto;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = MessageCrypto;
}
