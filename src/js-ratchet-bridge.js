/**
 * JS Ratchet Bridge — 纯 JS Double Ratchet 降级实现
 * ─────────────────────────────────────────────────────────
 * 与 tauri-ratchet-bridge.js 接口完全一致，但用纯 JS 实现（tweetnacl + WebCrypto）。
 *
 * 用途：非 Tauri 环境（手机 Capacitor WebView / 浏览器）下，
 * 替代 Rust 后端的 X25519 / X3DH / Double Ratchet。
 *
 * 🔒 密钥材料存 localStorage（identity 私钥），会话密钥存内存。
 * ⚠️ 安全级别低于 Rust 后端（Rust 用 AES-256-GCM 加密私钥落盘 + 零化），
 *    但协议字节级一致，能与 Rust 端互通。
 *
 * 与 Rust 端（src-tauri/src/double_ratchet.rs）协议对齐：
 *   - X25519 (tweetnacl scalarMult)
 *   - X3DH: DH1||DH2||DH3 (96B) → HKDF-SHA256(None) "shared_secret"
 *   - DR init: HKDF(None, ss) "send_chain_key"/"recv_chain_key"
 *   - ratchet_step: HKDF(None, dh) "chain_key"/"next_chain"
 *   - message key: HKDF(None, chain) "message_key"/"next_chain"
 *   - AEAD: AES-256-GCM, AAD = 发送方 X25519 公钥 (32B)
 *
 * ⚠️ 关键约定（与 Rust commands/identity.rs 一致）：
 *   - signed pre-key = identity key（复用身份密钥，见 getMyPreKeyBundle）
 *   - X3DH initiator DH1 = DH(IK_A, SPK_B)（Signal 规范，修复后）
 */

(function () {
  'use strict';

  // ── 依赖 ─────────────────────────────────────────────────────
  const DR = (typeof window !== 'undefined' && window.JSDoubleRatchetLib) ? window.JSDoubleRatchetLib : null;
  const nacl = (typeof window !== 'undefined' && window.nacl) ? window.nacl : null;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  // ── Hex ↔ Bytes ─────────────────────────────────────────────
  function hexToBytes(hex) {
    if (typeof hex !== 'string') return hex;
    const len = hex.length / 2;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return bytes;
  }
  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ── 身份密钥持久化（localStorage）────────────────────────────
  // 身份私钥存 localStorage（hex），公钥用于上传 bundle
  const IDENTITY_STORAGE = 'fibemate_js_identities'; // identityId → { secretKeyHex, publicKeyHex, fingerprint }

  function _loadIdentities() {
    try {
      const raw = localStorage.getItem(IDENTITY_STORAGE);
      return raw ? JSON.parse(raw) : {};
    } catch (e) { return {}; }
  }
  function _saveIdentities(map) {
    try {
      localStorage.setItem(IDENTITY_STORAGE, JSON.stringify(map));
    } catch (e) {
      console.warn('[JS RatchetBridge] 身份密钥持久化失败:', e.message);
    }
  }

  // SHA3-256 不可用于 WebCrypto，改用 SHA-256 做指纹（与 Rust pq::fingerprint 有差异，
  // 但指纹仅用于显示，不影响协议互通；安全号码走 dr_safety_number 的 SHA-256）
  async function _fingerprint(publicKeyHex) {
    const digest = await crypto.subtle.digest('SHA-256', hexToBytes(publicKeyHex));
    return bytesToHex(new Uint8Array(digest)).slice(0, 16).toUpperCase();
  }

  // ── Bridge object ───────────────────────────────────────────
  const RatchetBridge = {
    initialized: false,
    _identityId: null,
    _sessions: new Map(),  // sessionId → { peerName, state: JSDoubleRatchet 内部状态引用 }

    // ════════════════════════════════════════════════════════════
    // Initialization
    // ════════════════════════════════════════════════════════════

    init() {
      if (this.initialized) return;
      if (!DR) throw new Error('[JS RatchetBridge] JSDoubleRatchetLib 未加载（需先加载 js-double-ratchet.js）');
      if (!nacl) throw new Error('[JS RatchetBridge] tweetnacl 未加载（需先加载 nacl-fast.js）');
      this.initialized = true;
      console.log('[JS RatchetBridge] ✅ Initialized — 纯 JS X25519 Double Ratchet backend');
    },

    getStatus() {
      return {
        initialized: this.initialized,
        identityId: this._identityId,
        activeSessions: this._sessions.size,
        engine: 'js-double-ratchet',
        curve: 'X25519',
        protocol: 'X3DH + Double Ratchet (Signal Protocol)'
      };
    },

    // ════════════════════════════════════════════════════════════
    // Identity Key Management
    // ════════════════════════════════════════════════════════════

    async generateIdentity(identityId) {
      if (!this.initialized) this.init();
      const identities = _loadIdentities();
      const id = identityId || (crypto.randomUUID ? crypto.randomUUID() : 'id_' + Date.now() + '_' + Math.random().toString(36).slice(2));

      // 已存在则返回
      if (identities[id]) {
        this._identityId = id;
        return {
          identityId: id,
          publicKeyHex: identities[id].publicKeyHex,
          fingerprint: identities[id].fingerprint
        };
      }

      // 生成新 X25519 密钥对
      const kp = nacl.box.keyPair();
      const publicKeyHex = bytesToHex(new Uint8Array(kp.publicKey));
      const fingerprint = await _fingerprint(publicKeyHex);
      identities[id] = {
        secretKeyHex: bytesToHex(new Uint8Array(kp.secretKey)),
        publicKeyHex,
        fingerprint
      };
      _saveIdentities(identities);
      this._identityId = id;
      console.log('[JS RatchetBridge] Identity:', id, 'fingerprint:', fingerprint);
      return { identityId: id, publicKeyHex, fingerprint };
    },

    async getIdentityPublic(identityId) {
      if (!this.initialized) this.init();
      const identities = _loadIdentities();
      const id = identities[identityId];
      if (!id) throw new Error(`Identity not found: ${identityId}`);
      return { identityId, publicKeyHex: id.publicKeyHex, fingerprint: id.fingerprint };
    },

    async listIdentities() {
      if (!this.initialized) this.init();
      const identities = _loadIdentities();
      return Object.entries(identities).map(([identityId, v]) => ({
        identityId, publicKeyHex: v.publicKeyHex, fingerprint: v.fingerprint
      }));
    },

    // ── 内部：取身份私钥 ──────────────────────────────────────
    _getIdentitySecretKey(identityId) {
      const identities = _loadIdentities();
      const id = identities[identityId];
      if (!id) throw new Error(`Identity not found: ${identityId}`);
      return hexToBytes(id.secretKeyHex);
    },

    // ════════════════════════════════════════════════════════════
    // X3DH Key Exchange
    // ════════════════════════════════════════════════════════════

    async x3dhInitiate(myIdentityId, peerIdentityPkHex, peerSignedPrekeyPkHex) {
      if (!this.initialized) this.init();
      const myIkPriv = this._getIdentitySecretKey(myIdentityId);
      const myEk = nacl.box.keyPair();
      const theirIkPub = hexToBytes(peerIdentityPkHex);
      const theirSpkPub = hexToBytes(peerSignedPrekeyPkHex);

      const combined = DR.x3dhInitiator(
        myIkPriv,
        new Uint8Array(myEk.secretKey),
        theirIkPub,
        theirSpkPub
      );
      const sharedSecret = await DR.hkdfExpand(combined, 'shared_secret', 32);

      // 生成 ssId（会话共享密钥暂存，供 dr_init 消费）
      const ssId = 'ss_' + (crypto.randomUUID ? crypto.randomUUID() : Date.now() + '_' + Math.random().toString(36).slice(2));
      this._sharedSecrets = this._sharedSecrets || new Map();
      this._sharedSecrets.set(ssId, sharedSecret);

      return {
        ssId,
        ourIdentityPkHex: bytesToHex(new Uint8Array(nacl.box.keyPair.fromSecretKey(myIkPriv).publicKey)),
        ourEphemeralPkHex: bytesToHex(new Uint8Array(myEk.publicKey))
      };
    },

    async x3dhRespond(myIdentityId, peerIdentityPkHex, peerEphemeralPkHex) {
      if (!this.initialized) this.init();
      const myIkPriv = this._getIdentitySecretKey(myIdentityId);
      // signed pre-key = identity key（对齐 Rust x3dh_respond 的 spk=ik 约定）
      const mySpkPriv = myIkPriv;
      const mySpkPub = nacl.box.keyPair.fromSecretKey(myIkPriv).publicKey;
      const theirIkPub = hexToBytes(peerIdentityPkHex);
      const theirEkPub = hexToBytes(peerEphemeralPkHex);

      const combined = DR.x3dhResponder(
        myIkPriv,
        mySpkPriv,
        theirIkPub,
        theirEkPub
      );
      const sharedSecret = await DR.hkdfExpand(combined, 'shared_secret', 32);

      const ssId = 'ss_' + (crypto.randomUUID ? crypto.randomUUID() : Date.now() + '_' + Math.random().toString(36).slice(2));
      this._sharedSecrets = this._sharedSecrets || new Map();
      this._sharedSecrets.set(ssId, sharedSecret);

      return {
        ssId,
        ourIdentityPkHex: bytesToHex(new Uint8Array(mySpkPub)),
        ourSignedPrekeyPkHex: bytesToHex(new Uint8Array(mySpkPub))
      };
    },

    // ════════════════════════════════════════════════════════════
    // Double Ratchet Session Management
    // ════════════════════════════════════════════════════════════

    async initSession(ssId, peerName, isInitiator, identity) {
      if (!this.initialized) this.init();
      const sharedSecret = this._sharedSecrets && this._sharedSecrets.get(ssId);
      if (!sharedSecret) throw new Error(`Shared secret not found for ss_id: ${ssId}（可能已被消费）`);

      // 消费 shared secret（单次）
      if (this._sharedSecrets) this._sharedSecrets.delete(ssId);

      // 用 JSDoubleRatchet 创建会话
      const engine = new DR.JSDoubleRatchet();
      const sessionId = 'js_' + (crypto.randomUUID ? crypto.randomUUID() : Date.now() + '_' + Math.random().toString(36).slice(2));
      await engine.createSession(sessionId, sharedSecret, isInitiator);
      const state = engine.getState(sessionId);
      const ourPublicKeyHex = bytesToHex(state.send_public_key);

      this._sessions.set(sessionId, {
        peerName,
        engine,
        isInitiator,
        ourIdentityId: identity?.ourIdentityId,
        peerIdentityPkHex: identity?.peerIdentityPkHex
      });

      console.log(`[JS RatchetBridge] DR session created: ${sessionId} with ${peerName}`);
      return { sessionId, ourPublicKeyHex };
    },

    async setPeerKey(sessionId, peerPublicKeyHex) {
      if (!this.initialized) this.init();
      const s = this._sessions.get(sessionId);
      if (!s) throw new Error(`Session not found: ${sessionId}`);
      await s.engine.setPeerKey(sessionId, hexToBytes(peerPublicKeyHex));
    },

    async encrypt(sessionId, plaintext) {
      if (!this.initialized) this.init();
      const s = this._sessions.get(sessionId);
      if (!s) throw new Error(`Session not found: ${sessionId}`);
      const msg = await s.engine.encrypt(sessionId, encoder.encode(plaintext));
      return {
        messageJson: JSON.stringify(msg),
        messageNum: msg.message_num
      };
    },

    async decrypt(sessionId, messageJson) {
      if (!this.initialized) this.init();
      const s = this._sessions.get(sessionId);
      if (!s) throw new Error(`Session not found: ${sessionId}`);
      const msg = typeof messageJson === 'string' ? JSON.parse(messageJson) : messageJson;
      const plaintext = await s.engine.decrypt(sessionId, msg);
      return decoder.decode(plaintext);
    },

    async getSendKey(sessionId) {
      if (!this.initialized) this.init();
      const s = this._sessions.get(sessionId);
      if (!s) throw new Error(`Session not found: ${sessionId}`);
      const state = s.engine.getState(sessionId);
      return bytesToHex(state.send_public_key);
    },

    async deleteSession(sessionId) {
      if (!this.initialized) this.init();
      this._sessions.delete(sessionId);
      console.log(`[JS RatchetBridge] Session deleted: ${sessionId}`);
    },

    async getSafetyNumber(sessionId) {
      if (!this.initialized) this.init();
      const s = this._sessions.get(sessionId);
      if (!s) throw new Error(`Session not found: ${sessionId}`);
      // 安全号码 = SHA-256(our_identity_pk || peer_identity_pk) 前 30 字节 → 分组显示
      const ourPk = s.ourIdentityId ? this._getIdentityPublicHex(s.ourIdentityId) : null;
      const peerPk = s.peerIdentityPkHex || null;
      let safetyNumber = '00000 00000 00000 00000 00000';
      if (ourPk && peerPk) {
        const combined = hexToBytes(ourPk + peerPk);
        const digest = await crypto.subtle.digest('SHA-256', combined);
        const hex = bytesToHex(new Uint8Array(digest)).slice(0, 30);
        safetyNumber = hex.match(/.{1,6}/g).join(' ').toUpperCase();
      }
      return {
        safetyNumber,
        ourFingerprint: ourPk ? (await _fingerprint(ourPk)) : null,
        peerFingerprint: peerPk ? (await _fingerprint(peerPk)) : null
      };
    },

    _getIdentityPublicHex(identityId) {
      const identities = _loadIdentities();
      return identities[identityId]?.publicKeyHex || null;
    },

    // ════════════════════════════════════════════════════════════
    // ML-KEM-768 Hybrid X3DH（降级：回退经典 X3DH）
    // ════════════════════════════════════════════════════════════

    async hybridX3dhInitiate(myIdentityId, peerBundle) {
      console.warn('[JS RatchetBridge] hybridX3dhInitiate — 降级为经典 X3DH');
      return this.x3dhInitiate(myIdentityId, peerBundle.identityPkHex, peerBundle.signedPrekeyPkHex);
    },

    // ════════════════════════════════════════════════════════════
    // Full Flow Helper
    // ════════════════════════════════════════════════════════════

    async setupSessionAsInitiator(peerName, peerBundle) {
      if (!this._identityId) {
        const id = await this.generateIdentity();
        this._identityId = id.identityId;
      }
      const x3dh = await this.x3dhInitiate(
        this._identityId,
        peerBundle.identityPkHex,
        peerBundle.signedPrekeyPkHex
      );
      const dr = await this.initSession(x3dh.ssId, peerName, true);
      return {
        sessionId: dr.sessionId,
        ourPublicKeyHex: dr.ourPublicKeyHex,
        initMessage: {
          type: 'x3dh_init',
          identityPkHex: x3dh.ourIdentityPkHex,
          ephemeralPkHex: x3dh.ourEphemeralPkHex
        }
      };
    },

    async setupSessionAsResponder(peerName, initMessage) {
      if (!this._identityId) {
        const id = await this.generateIdentity();
        this._identityId = id.identityId;
      }
      const x3dh = await this.x3dhRespond(
        this._identityId,
        initMessage.identityPkHex,
        initMessage.ephemeralPkHex
      );
      const dr = await this.initSession(x3dh.ssId, peerName, false);
      return {
        sessionId: dr.sessionId,
        ourPublicKeyHex: dr.ourPublicKeyHex,
        acceptMessage: {
          type: 'x3dh_accept',
          identityPkHex: x3dh.ourIdentityPkHex,
          signedPrekeyPkHex: x3dh.ourSignedPrekeyPkHex
        }
      };
    }
  };

  // ── Global export ─────────────────────────────────────────────
  if (typeof window !== 'undefined') {
    // 仅在非 Tauri（无 __TAURI__）或 RatchetBridge 未注册时，注册 JS 版
    if (!window.RatchetBridge) {
      window.RatchetBridge = RatchetBridge;
      window.FIBEMATE_DR = RatchetBridge;
      console.log('[JS RatchetBridge] ✅ Registered — window.RatchetBridge (纯 JS X25519 降级)');
    } else {
      console.log('[JS RatchetBridge] Rust RatchetBridge 已存在，跳过 JS 降级注册');
    }
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = RatchetBridge;
  }
})();
