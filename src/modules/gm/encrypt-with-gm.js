/**
 * EncryptWithGM — 国密加密桥接模块
 * 
 * 将 MessageGM (SM2+SM4+SM3) 挂接到 chat.js 的消息发送/接收管线中。
 * 
 * API (chat.js 调用):
 *   window.encryptWithGM.encrypt(peerId, plaintext) → env object { encryption, ... }
 *   window.encryptWithGM.decrypt(senderUserId, envelope) → plaintext string
 *   window.encryptWithGM.init() → Promise<void>
 *   window.encryptWithGM.isReady() → boolean
 *   window.encryptWithGM.uploadPublicKey() → Promise<void>
 * 
 * 密钥交换:
 *   - SM2 公钥通过服务端 pre-key bundle 协议传输（扩展字段 gmPublicKey）
 *   - 与 P2P 模块共用 localStorage 中的 GM 密钥对
 */

const EncryptWithGM = (() => {
  'use strict';

  let gmKeypair = null;
  let initialized = false;

  // Tauri 后端迁移：私钥以 keyId 句柄引用，不再明文存 localStorage
  let gmKeyId = null;   // 后端 KeyStore 的 key_id
  let gmPublicKey = null;

  const KEY_ID_STORAGE = 'fibemate_gm_key_id';

  function _hasBackend() {
    return typeof window !== 'undefined' && window.SM2
      && typeof window.SM2.importKey === 'function';
  }

  // ============================================================
  // 初始化
  // ============================================================

  async function init() {
    if (initialized) return;

    try {
      // ── Tauri 后端路径：私钥收进 Rust KeyStore ──
      if (_hasBackend()) {
        const storedId = localStorage.getItem(KEY_ID_STORAGE);
        if (storedId) {
          gmKeyId = storedId;
          const pk = await window.SM2.getPublicKey(storedId);
          gmPublicKey = pk.publicKeyHex;
          console.log('[GM Bridge] GM key loaded from Rust KeyStore:', storedId);
        } else {
          // 迁移旧明文私钥（若存在）
          const legacy = localStorage.getItem('p2p_gm_keypair');
          if (legacy) {
            const legacyKp = JSON.parse(legacy);
            const imported = await window.SM2.importKey(legacyKp.privateKey);
            gmKeyId = imported.keyId;
            gmPublicKey = imported.publicKeyHex;
            localStorage.setItem(KEY_ID_STORAGE, gmKeyId);
            localStorage.removeItem('p2p_gm_keypair');  // 删除明文私钥
            console.log('[GM Bridge] Legacy GM key migrated to Rust KeyStore:', gmKeyId);
          } else {
            // 全新生成，私钥直接进 KeyStore
            const generated = await window.SM2.generateKeyPair();
            gmKeyId = generated.keyId;
            gmPublicKey = generated.publicKeyHex;
            localStorage.setItem(KEY_ID_STORAGE, gmKeyId);
            console.log('[GM Bridge] GM key generated in Rust KeyStore:', gmKeyId);
          }
        }

        // 自我诊断（用 keyId 后端化路径验证全链路）
        const testResult = await window.MessageGM.selftest();
        if (!testResult.ok) {
          console.error('[GM Bridge] MessageGM selftest failed:', testResult.err);
          return;
        }
        console.log('[GM Bridge] MessageGM selftest passed');

        await uploadPublicKey();
        initialized = true;
        console.log('[GM Bridge] Initialized (backend), pubkey:', gmPublicKey.slice(0, 20) + '...');
        return;
      }

      // ── 纯 JS 回退路径（node 测试 / 非 Tauri） ──
      const stored = localStorage.getItem('p2p_gm_keypair');
      if (stored) {
        gmKeypair = JSON.parse(stored);
        console.log('[GM Bridge] Keypair loaded from localStorage');
      } else if (typeof window.MessageGM !== 'undefined') {
        gmKeypair = window.MessageGM.generateKeypair();
        localStorage.setItem('p2p_gm_keypair', JSON.stringify(gmKeypair));
        console.log('[GM Bridge] Keypair generated');
      } else {
        console.error('[GM Bridge] MessageGM not available — SM2 module not loaded');
        return;
      }

      // 自我诊断
      const testResult = await window.MessageGM.selftest();
      if (!testResult.ok) {
        console.error('[GM Bridge] MessageGM selftest failed:', testResult.err);
        return;
      }
      console.log('[GM Bridge] MessageGM selftest passed');

      // 上传公钥到服务器
      await uploadPublicKey();

      initialized = true;
      console.log('[GM Bridge] Initialized, pubkey:', gmKeypair.publicKey.slice(0, 20) + '...');
    } catch (e) {
      console.error('[GM Bridge] Init failed:', e.message);
    }
  }

  function isReady() {
    return initialized && (gmKeyId !== null || gmKeypair !== null);
  }

  function getPublicKey() {
    return gmPublicKey || gmKeypair?.publicKey || null;
  }

  // ============================================================
  // 密钥交换 — 通过服务端 API
  // ============================================================

  /**
   * 上传本端 SM2 公钥到服务器
   * 内嵌到 pre-key bundle 的 gmPublicKey 字段
   */
  async function uploadPublicKey() {
    const pubKey = getPublicKey();
    if (!pubKey) return;

    const token = localStorage.getItem('fk_token');
    const userId = localStorage.getItem('fk_uid');
    if (!token || !userId) {
      console.warn('[GM Bridge] Not logged in, skip key upload');
      return;
    }

    try {
      // 先获取现有 bundle，追加/更新 gmPublicKey
      let bundle = { gmPublicKey: pubKey };
      
      try {
        const existingRes = await fetch(`/api/pre-keys/${userId}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (existingRes.ok) {
          bundle = { ...(await existingRes.json()), gmPublicKey: pubKey };
        }
      } catch { /* 没有现有 bundle，就用仅含 gmPublicKey 的新 bundle */ }

      const res = await fetch(`/api/pre-keys/${userId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(bundle)
      });

      if (res.ok) {
        console.log('[GM Bridge] SM2 public key uploaded');
      } else {
        console.warn('[GM Bridge] Key upload returned:', res.status);
      }
    } catch (e) {
      console.warn('[GM Bridge] Key upload failed:', e.message);
    }
  }

  /**
   * 获取对端 SM2 公钥
   * 先查 localStorage 缓存，再查服务器
   */
  async function getPeerPublicKey(peerId) {
    // 1. localStorage 缓存
    const cached = localStorage.getItem(`p2p_gm_peer_${peerId}`);
    if (cached) {
      return cached;
    }

    // 2. 从服务器预密钥 bundle 获取
    const token = localStorage.getItem('fk_token');
    if (!token) return null;

    try {
      const res = await fetch(`/api/pre-keys/${peerId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!res.ok) return null;

      const bundle = await res.json();
      if (bundle.gmPublicKey) {
        // 缓存到 localStorage
        localStorage.setItem(`p2p_gm_peer_${peerId}`, bundle.gmPublicKey);
        return bundle.gmPublicKey;
      }
    } catch (e) {
      console.warn('[GM Bridge] Fetch peer key failed:', e.message);
    }

    return null;
  }

  /**
   * 手动设置对端公钥 (由 P2P 握手等途径)
   */
  function setPeerPublicKey(peerId, publicKey) {
    localStorage.setItem(`p2p_gm_peer_${peerId}`, publicKey);
  }

  // ============================================================
  // 加密 / 解密
  // ============================================================

  /**
   * 加密消息（chat.js 调用）
   * 
   * @param {string} peerId - 对端用户 ID
   * @param {string} plaintext - 明文消息
   * @returns {object} envelope — { ciphertext, iv, ephemeralPK, wrappedKey, hmac, signature, encryption }
   */
  async function encrypt(peerId, plaintext) {
    const keyRef = gmKeyId ? { keyId: gmKeyId } : gmKeypair?.privateKey;
    if (!keyRef) {
      throw new Error('GM keypair not initialized. Call init() first.');
    }

    // 确保已上传公钥
    await uploadPublicKey();

    // 获取对端公钥
    const recipientPubKey = await getPeerPublicKey(peerId);
    if (!recipientPubKey) {
      throw new Error(
        `No SM2 public key for peer ${peerId}. ` +
        'The peer must upload their GM key first (they need to open FIBEMATE and enable GM mode).'
      );
    }

    // 调用 MessageGM 加密
    const envelope = await window.MessageGM.encryptMessage(
      plaintext,
      recipientPubKey,
      keyRef
    );

    return {
      ...envelope,
      encryption: 'sm2-sm4-sm3',
      version: 2
    };
  }

  /**
   * 解密消息（chat.js 调用）
   * 
   * @param {string} senderUserId - 发送者用户 ID
   * @param {object} envelope - 加密信封
   * @returns {string} 明文
   */
  async function decrypt(senderUserId, envelope) {
    const keyRef = gmKeyId ? { keyId: gmKeyId } : gmKeypair?.privateKey;
    if (!keyRef) {
      throw new Error('GM keypair not initialized');
    }

    // 获取发送者身份公钥（MessageGM 签名验证需要永久身份密钥，非临时密钥）
    // envelope 中不包含身份公钥，统一从服务端/缓存获取
    const senderPubKey = await getPeerPublicKey(senderUserId);
    if (!senderPubKey) {
      throw new Error(`No SM2 public key for sender ${senderUserId}`);
    }

    const result = await window.MessageGM.decryptMessage(
      envelope,
      keyRef,
      senderPubKey
    );

    if (!result.verified) {
      throw new Error(
        `GM decryption verification failed: ${result.error || 'signature or HMAC mismatch'}`
      );
    }

    return result.plaintext;
  }

  // ============================================================
  // 诊断
  // ============================================================

  function diagnostics() {
    const status = {
      initialized,
      backendMode: gmKeyId !== null,
      hasKeypair: gmKeyId !== null || gmKeypair !== null,
      keyId: gmKeyId ? gmKeyId.slice(0, 16) + '...' : null,
      publicKey: getPublicKey() ? getPublicKey().slice(0, 20) + '...' : null,
      messageGMLoaded: typeof window.MessageGM !== 'undefined',
      selftestResult: null
    };

    return status;
  }

  // ============================================================
  // 导出
  // ============================================================
  return {
    init,
    isReady,
    getPublicKey,
    uploadPublicKey,
    getPeerPublicKey,
    setPeerPublicKey,
    encrypt,
    decrypt,
    diagnostics
  };
})();

// 注册全局
if (typeof window !== 'undefined') {
  window.encryptWithGM = EncryptWithGM;

  // 自动初始化（等 DOM ready 后）
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      EncryptWithGM.init().then(() => {
        console.log('[GM Bridge] Auto-init complete');
      });
    });
  } else {
    EncryptWithGM.init().then(() => {
      console.log('[GM Bridge] Auto-init complete');
    });
  }
}
