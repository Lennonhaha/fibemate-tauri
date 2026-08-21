// ============================================================
// FIBEMATE Message Crypto - Double Ratchet Session Manager
// 管理多个peer的加密会话，提供简单API供main.js调用
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
        console.log('[MessageCrypto] Saved session for ' + peerId);
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
  // 密钥交换（Key Exchange）
  // ============================================================

  /**
   * 发起密钥交换（Alice角色 - 主动方）
   * 生成ephemeral key并发送public key给对方
   * @param {string} peerId - 对方用户ID
   * @returns {Promise<{publicKey: number[], ephemeralPublic: number[]}>}
   */
  async function initiateKeyExchange(peerId) {
    // 生成ephemeral密钥对
    const ephemeralKey = await DoubleRatchet.generateDH();
    const ephemeralPublic = await DoubleRatchet.exportPublicKey(ephemeralKey);
    
    // 存储待完成的状态（等待Bob的响应）
    const pendingState = {
      ephemeralKey,
      role: 'initiator',
      timestamp: Date.now()
    };
    
    sessionCache.set(`_pending_${peerId}`, pendingState);
    
    console.log(`[MessageCrypto] Initiated key exchange with ${peerId}`);
    
    return {
      publicKey: Array.from(ephemeralPublic),
      ephemeralPublic: Array.from(ephemeralPublic)  // 两个字段相同（简化）
    };
  }

  /**
   * 响应密钥交换（Bob角色 - 被动方）
   * 接收Alice的public key，生成自己的密钥对，建立会话
   * @param {string} peerId - 对方用户ID
   * @param {number[]} alicePublic - Alice的公钥
   * @param {number[]} aliceEphemeral - Alice的临时公钥（与alicePublic相同）
   * @returns {Promise<{publicKey: number[], ephemeralPublic: number[]}>}
   */
  async function respondKeyExchange(peerId, alicePublic, aliceEphemeral) {
    // 生成自己的密钥对
    const selfKey = await DoubleRatchet.generateDH();
    const selfPublic = await DoubleRatchet.exportPublicKey(selfKey);
    
    // 导入Alice的公钥
    const alicePubKey = await DoubleRatchet.importPublicKey(new Uint8Array(alicePublic));
    
    // 计算shared secret (ECDH)
    const sharedSecret = await DoubleRatchet.dh(selfKey.privateKey, alicePubKey);
    
    // 派生root key
    const rootKey = await DoubleRatchet.hkdf(
      sharedSecret,
      new Uint8Array(32),
      'FIBEMateECDH'
    );
    
    // 初始化Double Ratchet作为接收方
    const state = await DoubleRatchet.initAsReceiver(rootKey, selfKey);
    
    // 保存会话
    await updateSession(peerId, state);
    
    console.log(`[MessageCrypto] Established session with ${peerId} (as receiver)`);
    
    return {
      publicKey: Array.from(selfPublic),
      ephemeralPublic: Array.from(selfPublic)  // 发送自己的公钥
    };
  }

  /**
   * 完成密钥交换（Alice收到Bob的响应后）
   * @param {string} peerId - 对方用户ID
   * @param {number[]} bobPublic - Bob的公钥
   * @param {number[]} bobEphemeral - Bob的ephemeral公钥（与bobPublic相同）
   */
  async function completeKeyExchange(peerId, bobPublic, bobEphemeral) {
    const pending = sessionCache.get(`_pending_${peerId}`);
    if (!pending) {
      throw new Error(`[MessageCrypto] No pending key exchange with ${peerId}`);
    }
    
    const { ephemeralKey } = pending;
    
    // 导入Bob的公钥
    const bobPubKey = await DoubleRatchet.importPublicKey(new Uint8Array(bobPublic));
    
    // 计算shared secret (ECDH)
    const sharedSecret = await DoubleRatchet.dh(ephemeralKey.privateKey, bobPubKey);
    
    // 派生root key（必须与Bob的计算结果一致）
    const rootKey = await DoubleRatchet.hkdf(
      sharedSecret,
      new Uint8Array(32),
      'FIBEMateECDH'
    );
    
    // 初始化Double Ratchet作为发起方
    const state = await DoubleRatchet.initAsInitiator(
      rootKey,
      new Uint8Array(bobPublic)  // remote DH public
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
    init: initDB
  };
})();

// 自动初始化
if (typeof window !== 'undefined') {
  MessageCrypto.init().catch(e => console.error('[MessageCrypto] Init failed:', e));
}
