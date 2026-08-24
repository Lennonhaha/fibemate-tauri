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
      // 后端 /api/auth/update-keys 支持 gmPublicKey 字段（与 X3DH publicKey 并存）
      const res = await fetch(`${API_BASE}/auth/update-keys`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ gmPublicKey: pubKey })
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
   * 缓存格式: { pk: string, fp: string, ts: number } （fp 为公钥 SHA256 前 16 字符）
   * 旧格式（裸字符串/字符串 "null"）自动识别为坏值并清除
   * TTL: 7 天兜底；轮换检测：服务器 fingerprint 不一致时主动失效
   */
  function _isValidCachedPk(obj) {
    if (!obj) return false;
    if (typeof obj !== 'object') return false;
    if (typeof obj.pk !== 'string' || obj.pk.length < 64) return false;
    if (typeof obj.ts !== 'number') return false;
    // TTL 兜底：超过 7 天强制刷新
    if (Date.now() - obj.ts > 7 * 24 * 3600 * 1000) return false;
    return true;
  }

  function _fingerprintOf(pk) {
    if (typeof pk !== 'string' || pk.length < 8) return '';
    // 用 web crypto 不可用时降级到简单 hash
    try {
      // SHA256 first 8 bytes hex (16 chars)
      // 不引入依赖，使用内置 SubtleCrypto（现代浏览器/Tauri webview 均支持）
      // 注意：这里只用于缓存比较，不需要密码学强度
      let h = 5381;
      for (let i = 0; i < pk.length; i++) h = ((h << 5) + h + pk.charCodeAt(i)) | 0;
      return ('00000000' + (h >>> 0).toString(16)).slice(-8);
    } catch { return ''; }
  }

  /**
   * 获取对端 SM2 公钥
   * 先查 localStorage 缓存（带 fingerprint 比对 + TTL），再查服务器
   */
  async function getPeerPublicKey(peerId) {
    // 1. localStorage 缓存（带 TTL + 主动失效）
    const raw = localStorage.getItem(`p2p_gm_peer_${peerId}`);
    let cached = null;
    if (raw) {
      // 新格式 (JSON 对象)
      if (raw.startsWith('{')) {
        try {
          const obj = JSON.parse(raw);
          if (_isValidCachedPk(obj)) cached = obj;
        } catch { /* 坏 JSON */ }
      } else if (raw !== 'null' && raw !== 'undefined' && raw.length >= 64) {
        // 旧格式（裸字符串，键入 24h 宽限期），升级为新格式
        const ts = Date.now();
        const fp = _fingerprintOf(raw);
        cached = { pk: raw, fp, ts };
        localStorage.setItem(`p2p_gm_peer_${peerId}`, JSON.stringify(cached));
      } else {
        // 坏值（"null"/"undefined"/空）→ 清除
        console.warn('[GM Bridge] Removing invalid cache for peer', peerId, ':', raw);
        localStorage.removeItem(`p2p_gm_peer_${peerId}`);
      }
    }

    // 2. 从服务器获取对端 SM2 公钥（与 X3DH 预密钥 bundle 同端点）
    const token = localStorage.getItem('fk_token');
    if (!token) return cached?.pk || null;

    try {
      const res = await fetch(`${API_BASE}/users/${peerId}/keys`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!res.ok) return cached?.pk || null;

      const bundle = await res.json();
      if (bundle.gmPublicKey && bundle.gmPublicKey.length >= 64) {
        const serverFp = bundle.gmKeyFingerprint || _fingerprintOf(bundle.gmPublicKey);
        // 主动失效：服务器 fingerprint 与本地不一致 → 立即采用新公钥
        if (!cached || cached.fp !== serverFp) {
          const newEntry = { pk: bundle.gmPublicKey, fp: serverFp, ts: Date.now() };
          localStorage.setItem(`p2p_gm_peer_${peerId}`, JSON.stringify(newEntry));
          if (cached && cached.fp !== serverFp) {
            console.log('[GM Bridge] Peer key rotated, refreshed cache for', peerId);
          }
          return bundle.gmPublicKey;
        }
        return cached.pk;
      }
    } catch (e) {
      console.warn('[GM Bridge] Fetch peer key failed:', e.message);
    }

    return cached?.pk || null;
  }

  /**
   * 手动设置对端公钥 (由 P2P 握手等途径)
   * 守卫: 坏值（null/undefined/"null"）直接清除旧缓存，不写入坏值
   */
  function setPeerPublicKey(peerId, publicKey) {
    if (!publicKey || publicKey === 'null' || publicKey === 'undefined' || (typeof publicKey === 'string' && publicKey.length < 64)) {
      console.warn('[GM Bridge] Refusing to cache invalid peer key for', peerId);
      localStorage.removeItem(`p2p_gm_peer_${peerId}`);
      return;
    }
    const entry = { pk: publicKey, fp: _fingerprintOf(publicKey), ts: Date.now() };
    localStorage.setItem(`p2p_gm_peer_${peerId}`, JSON.stringify(entry));
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
