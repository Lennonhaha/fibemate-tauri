/**
 * Tauri MessageCrypto Adapter — Drop-in MessageCryptoV2 replacement
 * ──────────────────────────────────────────────────────────────────
 * Same public API as MessageCryptoV2.js, backed by Rust Double Ratchet.
 *
 * Protocol versions:
 *   v1 — Legacy ECDH (MessageCrypto.js)
 *   v2 — JS Double Ratchet P-256 (MessageCryptoV2.js)
 *   v3 — Rust Double Ratchet X25519 (this adapter → RatchetBridge)
 *
 * 🔒 v3 (X25519 Rust DR): encrypt/decrypt via Tauri invoke() — zero key material in JS.
 * 🚫 v1/v2 (P-256 JS DR): hard-rejected — no JS fallback loaded.
 *
 * ⚠️ This file REPLACES MessageCryptoV2.js. Main-v3.js needs NO changes:
 *    `window.MessageCryptoV2` is set to this adapter.
 *    double-ratchet.js + message-crypto-v2.js are no longer loaded in main.html.
 */

(function () {
  'use strict';

  // Internal state
  let _initialized = false;
  let _identityBundles = {};               // identityId → { identityId, publicKeyHex, fingerprint }
  let _sessionMap = new Map();             // peerId → { sessionId, identityId, version }
  let _opkUploadCallback = null;

  // Session persistence key
  // Per-user session storage key to isolate same-machine multi-account sessions.
  const STORAGE_KEY = () => 'fibemate_rust_sessions_' + (localStorage.getItem('fk_uid') || 'default');
  const DR_PROTOCOL = 'double-ratchet-x25519';
  const DR_VERSION = 3;

  // Track logged-in user to detect account switches
  let _currentUserId = localStorage.getItem('fk_uid') || 'default';

  // ── Persistence ──────────────────────────────────────────────

  function _saveSessionMap() {
    try {
      const data = {};
      for (const [peerId, info] of _sessionMap) {
        data[peerId] = info;
      }
      localStorage.setItem(STORAGE_KEY(), JSON.stringify(data));
    } catch (e) {
      console.warn('[DR Adapter] Failed to persist session map:', e.message);
    }
  }

  function _loadSessionMap() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY());
      if (raw) {
        const data = JSON.parse(raw);
        for (const [peerId, info] of Object.entries(data)) {
          _sessionMap.set(peerId, info);
        }
        console.log(`[DR Adapter] Loaded ${_sessionMap.size} Rust DR sessions`);
      }
    } catch (e) {
      console.warn('[DR Adapter] Failed to load session map:', e.message);
    }
  }

  // ── Helpers ──────────────────────────────────────────────────

  function _getRatchetBridge() {
    return window.RatchetBridge || window.FIBEMATE_DR;
  }

  /**
   * Detect protocol version from envelope.
   * v3: { version: 3, protocol: 'double-ratchet-x25519', messageJson: "..." }
   * v2: { version: 2, protocol: 'double-ratchet', envelope: { h, c, iv } }
   * v1: { ciphertext: "...", nonce: "...", ephemeralPublicKey: "..." }
   */
  function _detectVersion(envelope) {
    if (!envelope || typeof envelope !== 'object') return 0;
    if (envelope.version === 3 && envelope.messageJson) return 3;
    if (envelope.version === 2 && envelope.envelope) return 2;
    if (envelope.ciphertext && envelope.nonce) return 1;
    return 0;
  }

  // ── Adapter Public API ───────────────────────────────────────

  const Adapter = {
    version: DR_VERSION,
    protocol: DR_PROTOCOL,

    // ════════════════════════════════════════════════════════════
    // Init
    // ════════════════════════════════════════════════════════════

    async init() {
      if (_initialized) return;
      const bridge = _getRatchetBridge();
      if (!bridge) {
        throw new Error('[DR Adapter] Rust DR backend not available — Tauri required');
      }
      bridge.init();
      _loadSessionMap();
      _initialized = true;
      console.log(`[DR Adapter] ✅ Ready (curve=X25519, sessions=${_sessionMap.size})`);
    },

    /** Get current status for debugging. */
    getStatus() {
      return {
        adapter: 'tauri-rust-dr',
        version: DR_VERSION,
        curve: 'X25519',
        protocol: DR_PROTOCOL,
        initialized: _initialized,
        identityBundles: Object.keys(_identityBundles).length,
        rustSessions: _sessionMap.size,
        engine: 'rust-double-ratchet'
      };
    },

    // ════════════════════════════════════════════════════════════
    // Identity & Pre-Key Bundle (for server upload)
    // ════════════════════════════════════════════════════════════

    async getMyPreKeyBundle() {
      if (!_initialized) await this.init();
      const bridge = _getRatchetBridge();
      if (!bridge) {
        throw new Error('[DR Adapter] Rust DR backend not available');
      }

      // Detect account switch — clear session/identity state for the new user
      const currentUserId = localStorage.getItem('fk_uid') || 'default';
      if (currentUserId !== _currentUserId) {
        _sessionMap.clear();
        _identityBundles = {};
        _currentUserId = currentUserId;
      }

      // Per-user identity isolation: 同机双账号时各用独立 identity
      const identityKey = 'fibemate_rust_identity_id_' + currentUserId;

      // Ensure we have an identity
      let identityId = localStorage.getItem(identityKey);
      let identity;
      if (identityId) {
        try {
          identity = await bridge.getIdentityPublic(identityId);
        } catch (e) {
          console.warn('[DR Adapter] Identity not found, generating new...');
          identityId = null;
        }
      }
      if (!identityId) {
        identity = await bridge.generateIdentity();
        identityId = identity.identityId;
        localStorage.setItem(identityKey, identityId);
      }
      _identityBundles[identityId] = identity;

      // Build full pre-key bundle via Rust spk_get_public:
      //   identityKey            - X25519 identity key (IK)
      //   identitySigningKey     - ML-DSA-65 identity signing key (ISK)
      //   signedPreKey           - independent X25519 signed pre-key (SPK)
      //   signedPreKeySignature  - ML-DSA-65 signature over the SPK
      const spkBundle = await bridge.getSpkPublic(identityId);
      return {
        identityKey: identity.publicKeyHex,             // X25519 32-byte hex (64 chars)
        identitySigningKey: spkBundle.signing_pk_hex,      // ML-DSA-65 ISK (hex)
        signedPreKey: spkBundle.signed_prekey_hex,         // independent X25519 SPK (hex)
        signedPreKeyId: spkBundle.signed_prekey_id,
        signedPreKeySignature: spkBundle.signed_prekey_sig_hex,
        oneTimePreKeys: [],
        // Rust-specific metadata
        _rustIdentityId: identityId,
        _rustProtocol: DR_PROTOCOL,
        _rustVersion: DR_VERSION,
        // Also include PQ key if available
        _pqAvailable: false
      };
    },

    /** Generate and upload pre-keys (compat stub). */
    async generateAndUploadPreKeys() {
      return await this.getMyPreKeyBundle();
    },

    // ════════════════════════════════════════════════════════════
    // OPK management stubs (Rust generates keys on demand)
    // ════════════════════════════════════════════════════════════

    setOPKUploadCallback(cb) {
      _opkUploadCallback = cb;
    },

    async checkAndReplenishOPKs() {
      return { replenished: false, uploaded: 0, remaining: '∞ (Rust generates on demand)' };
    },

    startOPKAutoReplenish() {
      console.log('[DR Adapter] OPK auto-replenish: not needed (Rust KeyStore persistence)');
    },

    stopOPKAutoReplenish() {
      // no-op
    },

    getLocalOPKCount() {
      return Infinity; // Rust generates keys on demand, no pre-key pool needed
    },

    async generateOneTimePreKeys(count) {
      // Rust doesn't need pre-key pools — return empty
      return [];
    },

    // ════════════════════════════════════════════════════════════
    // X3DH Key Exchange
    // ════════════════════════════════════════════════════════════

    /**
     * Initiate X3DH session (Alice side).
     *
     * @param {string} peerId — peer's user ID
     * @param {object} bundle — peer's pre-key bundle from server
     * @returns {Promise<{initialMessage, sessionEstablished}>}
     */
    async initiateSession(peerId, bundle) {
      if (!_initialized) await this.init();
      const bridge = _getRatchetBridge();
      if (!bridge) {
        throw new Error('[DR Adapter] Rust DR backend not available — Tauri required');
      }

      const currentUserId = localStorage.getItem('fk_uid') || 'default';

      if (currentUserId !== _currentUserId) {
        _sessionMap.clear();
        _identityBundles = {};
        _currentUserId = currentUserId;
      }
      const identityKey = 'fibemate_rust_identity_id_' + currentUserId;
      let myId = localStorage.getItem(identityKey);
      if (!myId) throw new Error('No identity generated — call getMyPreKeyBundle() first');

      // Extract peer's identity key from bundle
      let peerIdentityPkHex;
      if (typeof bundle.identityKey === 'string') {
        // Hex string (X25519, 64 chars)
        peerIdentityPkHex = bundle.identityKey;
      } else if (Array.isArray(bundle.identityKey)) {
        // byte array (P-256 from legacy bundle)
        peerIdentityPkHex = Array.from(bundle.identityKey)
          .map(b => b.toString(16).padStart(2, '0')).join('');
      } else {
        throw new Error('Invalid peer identity key format');
      }

      // Get peer signed pre-key
      let peerSpkHex;
      if (typeof bundle.signedPreKey === 'string') {
        peerSpkHex = bundle.signedPreKey;
      } else if (Array.isArray(bundle.signedPreKey)) {
        peerSpkHex = Array.from(bundle.signedPreKey)
          .map(b => b.toString(16).padStart(2, '0')).join('');
      } else {
        // Fallback: use identity key as pre-key
        peerSpkHex = peerIdentityPkHex;
      }

      console.log(`[DR Adapter] X3DH initiate with ${peerId} (X25519)`);

      // X3DH handshake
      const peerSigningPkHex = (typeof bundle.identitySigningKey === 'string')
        ? bundle.identitySigningKey : null;
      const peerSpkSigHex = (typeof bundle.signedPreKeySignature === 'string')
        ? bundle.signedPreKeySignature : null;

      // X3DH handshake (Rust verifies the SPK signature when provided)
      const x3dh = await bridge.x3dhInitiate(myId, peerIdentityPkHex, peerSpkHex, peerSigningPkHex, peerSpkSigHex);

      // Init DR session
      const dr = await bridge.initSession(x3dh.ssId, peerId, true);

      // Store mapping
      _sessionMap.set(peerId, {
        sessionId: dr.sessionId,
        identityId: myId,
        version: DR_VERSION,
        createdAt: Date.now()
      });
      _saveSessionMap();

      // The peer must also call setPeerKey with our DR public key.
      // For now, we include our DR pk in the init message.
      return {
        initialMessage: {
          type: 'x3dh_init_rust',
          version: DR_VERSION,
          protocol: DR_PROTOCOL,
          identityKey: x3dh.ourIdentityPkHex,         // X25519 identity (hex)
          ephemeralKey: x3dh.ourEphemeralPkHex,        // X25519 ephemeral (hex)
          drPublicKey: dr.ourPublicKeyHex,              // DR ratchet public key (hex)
          signedPreKeyId: bundle.signedPreKeyId || 0
        },
        sessionEstablished: true,
        rustSession: true
      };
    },

    /**
     * Receive X3DH session (Bob side).
     *
     * @param {string} peerId — initiator's user ID
     * @param {object} initMessage — Alice's initial message
     * @returns {Promise<{responseMessage, sessionEstablished, sessionReady}>}
     */
    async receiveSession(peerId, initMessage) {
      if (!_initialized) await this.init();

      // Bob receives Alice's x3dh_accept_rust — set peer DR key on existing session
      // MUST be checked BEFORE version check, since x3dh_accept_rust carries version:3
      if (initMessage.type === 'x3dh_accept_rust') {
        return this._receiveAcceptRust(peerId, initMessage);
      }

      // Detect protocol version
      if (initMessage.type === 'x3dh_init_rust' || initMessage.version === 3) {
        return this._receiveRustSession(peerId, initMessage);
      }

      // Legacy init — hard reject (P-256 JS DR removed)
      throw new Error(`[DR Adapter] Legacy X3DH init from ${peerId} (version ${initMessage.version || '?'}). Please ask your contact to update to FIBEMATE v3.`);
    },

    /** Handle Bob's x3dh_accept_rust on Alice's side — sets peer DR key on existing session. */
    async _receiveAcceptRust(peerId, initMessage) {
      const bridge = _getRatchetBridge();
      if (!bridge) throw new Error('Rust DR backend not available');

      const sessionInfo = _sessionMap.get(peerId);
      if (!sessionInfo) {
        // No existing session — create one (fallback)
        const currentUserId = localStorage.getItem('fk_uid') || 'default';

      if (currentUserId !== _currentUserId) {
        _sessionMap.clear();
        _identityBundles = {};
        _currentUserId = currentUserId;
      }
        const identityKey = 'fibemate_rust_identity_id_' + currentUserId;
        let myId = localStorage.getItem(identityKey);
        if (!myId) throw new Error('No identity — call getMyPreKeyBundle() first');
        const syntheticSsId = 'confirm_' + peerId;
        const dr = await bridge.initSession(syntheticSsId, peerId, false);
        if (initMessage.drPublicKey) {
          await bridge.setPeerKey(dr.sessionId, initMessage.drPublicKey);
        }
        _sessionMap.set(peerId, { sessionId: dr.sessionId, identityId: myId, version: DR_VERSION, createdAt: Date.now() });
        _saveSessionMap();
        console.log('[DR Adapter] Created session from x3dh_accept_rust for ' + peerId);
        return { confirmed: true, sessionEstablished: true, sessionReady: true, rustSession: true };
      }

      // Existing session — set peer DR key
      if (initMessage.drPublicKey) {
        await bridge.setPeerKey(sessionInfo.sessionId, initMessage.drPublicKey);
      }
      console.log('[DR Adapter] Session confirmed (x3dh_accept_rust) for ' + peerId);
      return { confirmed: true, sessionEstablished: true, sessionReady: true, rustSession: true };
    },

    async _receiveRustSession(peerId, initMessage) {
      const bridge = _getRatchetBridge();
      if (!bridge) throw new Error('Rust DR backend not available');

      const peerDrPublicKeyHex = initMessage.drPublicKey;

      // ── 幂等保护（修复版：旧会话无 initEphemeralKey 也复用）──
      // 同一条 initMessage 会被 3 个路径重复调用（websocket 全局块 / 当前窗口块 /
      // 历史消息加载块）。若每次调用都重新 x3dhRespond + initSession，会重新随机生成
      // DH 公钥，导致 Alice 用旧的 peer DH 公钥解密 Bob 新消息时触发 ratchet 发散 →
      // AEAD 失败。
      // 幂等键：initMessage.ephemeralKey（每次 initiateSession 随机生成）。
      //   - 相同 ephemeralKey → 同一条 initMessage 重复到达 → 复用旧 session
      //   - 不同 ephemeralKey → Alice 重新发起握手 → 重建新 session
      // ⚠️ 2026-08-24 修复：旧会话映射（v3.15 格式，只有 peerEphemeralKey）无 initEphemeralKey
      //    → sameHandshake 恒 false → 重复 init 重建 → DR 发散 → aead::Error
      //    → 改为：Rust 侧 session 真实存在即复用，不要求 initEphemeralKey 字段
      const existing = _sessionMap.get(peerId);
      let existingValid = false;
      if (existing && existing.sessionId) {
        try {
          existingValid = await bridge.sessionExists(existing.sessionId);
        } catch {
          existingValid = false;
        }
      }
      const sameHandshake = existing && existing.initEphemeralKey && initMessage.ephemeralKey
        && existing.initEphemeralKey === initMessage.ephemeralKey;
      // 只要 Rust 侧 session 还在就复用（不要求 initEphemeralKey 匹配）
      if (existing && existing.sessionId && existingValid) {
        if (peerDrPublicKeyHex) {
          try {
            await bridge.setPeerKey(existing.sessionId, peerDrPublicKeyHex);
          } catch (e) {
            console.warn('[DR Adapter] setPeerKey (idempotent) failed:', e && e.message);
          }
        }
        const ourSendKey = await bridge.getSendKey(existing.sessionId);
        console.log(`[DR Adapter] Reusing existing session ${existing.sessionId} for ${peerId}`);
        return {
          responseMessage: {
            type: 'x3dh_accept_rust',
            version: DR_VERSION,
            protocol: DR_PROTOCOL,
            identityKey: initMessage.identityKey,
            signedPrekeyPk: ourSendKey,
            drPublicKey: ourSendKey,
            sessionId: existing.sessionId,
            accepted: true
          },
          sessionEstablished: true,
          sessionReady: true,
          rustSession: true
        };
      }

      const currentUserId = localStorage.getItem('fk_uid') || 'default';

      if (currentUserId !== _currentUserId) {
        _sessionMap.clear();
        _identityBundles = {};
        _currentUserId = currentUserId;
      }
      const identityKey = 'fibemate_rust_identity_id_' + currentUserId;
      let myId = localStorage.getItem(identityKey);
      if (!myId) throw new Error('No identity generated — call getMyPreKeyBundle() first');

      // Parse initiator's keys (hex strings)
      const peerIdentityPkHex = initMessage.identityKey;
      const peerEphemeralPkHex = initMessage.ephemeralKey;

      console.log(`[DR Adapter] X3DH respond to ${peerId} (X25519)`);

      // X3DH responder
      const x3dh = await bridge.x3dhRespond(myId, peerIdentityPkHex, peerEphemeralPkHex);

      // Init DR session
      const dr = await bridge.initSession(x3dh.ssId, peerId, false);

      // Set peer DR key
      await bridge.setPeerKey(dr.sessionId, peerDrPublicKeyHex || peerEphemeralPkHex);

      // Store mapping
      _sessionMap.set(peerId, {
        sessionId: dr.sessionId,
        identityId: myId,
        version: DR_VERSION,
        createdAt: Date.now(),
        initEphemeralKey: initMessage.ephemeralKey
      });
      _saveSessionMap();

      return {
        responseMessage: {
          type: 'x3dh_accept_rust',
          version: DR_VERSION,
          protocol: DR_PROTOCOL,
          identityKey: x3dh.ourIdentityPkHex,
          signedPrekeyPk: x3dh.ourSignedPrekeyPkHex,
          drPublicKey: dr.ourPublicKeyHex,
          sessionId: dr.sessionId,
          accepted: true
        },
        sessionEstablished: true,
        sessionReady: true,
        rustSession: true
      };
    },

    /** Confirm Alice's side after Bob's accept (sets peer DR key). */
    async confirmSession(peerId, bobResponse) {
      const sessionInfo = _sessionMap.get(peerId);
      if (!sessionInfo || sessionInfo.version !== DR_VERSION) {
        return { confirmed: false };
      }

      const bridge = _getRatchetBridge();
      // Support both wrapped {responseMessage: x3dh_accept_rust} and raw x3dh_accept_rust
      const accept = (bobResponse && bobResponse.responseMessage) ? bobResponse.responseMessage : bobResponse;
      if (accept && accept.drPublicKey) {
        // CRITICAL: session is device-local. Our session lives under OUR sessionId;
        // Bob's sessionId (accept.sessionId) points to a session on Bob's device,
        // which does NOT exist here. We must set the peer's DR key on OUR session.
        const ourSessionId = sessionInfo.sessionId;
        console.error(`[DR-CONFIRM] ourSessionId=${ourSessionId} drPublicKey=${accept.drPublicKey.slice(0,8)}`);
        await bridge.setPeerKey(ourSessionId, accept.drPublicKey);
      }
      console.log(`[DR Adapter] Session confirmed with ${peerId}`);
      return { confirmed: true };
    },

    // ════════════════════════════════════════════════════════════
    // Encrypt / Decrypt — Core Interface
    // ════════════════════════════════════════════════════════════

    /**
     * Encrypt a message.
     *
     * @param {string} peerId
     * @param {string} plaintext
     * @returns {Promise<{version, protocol, messageJson}>}
     */
    async encrypt(peerId, plaintext) {
      if (!_initialized) await this.init();
      const sessionInfo = _sessionMap.get(peerId);
      const bridge = _getRatchetBridge();

      if (sessionInfo && sessionInfo.version >= DR_VERSION && bridge) {
        // Use Rust DR
        try {
          const result = await bridge.encrypt(sessionInfo.sessionId, plaintext);
          return {
            version: DR_VERSION,
            protocol: DR_PROTOCOL,
            messageJson: result.messageJson,
            messageNum: result.messageNum
          };
        } catch (e) {
          console.error(`[DR Adapter] Rust encrypt failed for ${peerId}:`, e.message);
          throw new Error(`Encrypt failed: ${e.message}`);
        }
      }

      throw new Error(`No crypto session for ${peerId} — call initiateSession first`);
    },

    /**
     * Decrypt a message. Auto-detects protocol version and dispatches.
     *
     * @param {string} peerId
     * @param {object} envelope — from encrypt() output
     * @returns {Promise<string|null>} plaintext (null = duplicate, silently drop)
     */
    async decrypt(peerId, envelope) {
      if (!_initialized) await this.init();
      const version = _detectVersion(envelope);

      if (version === DR_VERSION) {
        // Rust DR v3
        const result = await this._decryptRust(peerId, envelope);
        // null = duplicate / replay → silently drop this message
        if (result === null) return null;
        return result;
      }

      // v1/v2 — hard reject (P-256 JS DR removed in v3)
      throw new Error(`Unsupported protocol version ${version}. Please ask your contact to update to FIBEMATE v3 (X25519 Rust DR).`);
    },

    async _decryptRust(peerId, envelope) {
      const bridge = _getRatchetBridge();
      if (!bridge) throw new Error('Rust DR backend not available');

      let sessionInfo = _sessionMap.get(peerId);
      if (sessionInfo && sessionInfo.version >= DR_VERSION) {
        try {
          return await bridge.decrypt(sessionInfo.sessionId, envelope.messageJson);
        } catch (e) {
          const errMsg = (e && e.message) ? e.message : (typeof e === 'string' ? e : JSON.stringify(e));
          // MESSAGE_DROP = duplicate / replay → silently drop, don't show error to user
          if (errMsg === 'MESSAGE_DROP') {
            console.debug(`[DR Adapter] Silent-drop duplicate message for ${peerId}`);
            return null;
          }
          // 解密失败 → 自动重试一次（可能对方也刚做了 session 恢复）
          console.warn(`[DR Adapter] Decrypt failed (first attempt) for ${peerId}:`, errMsg);
          try {
            const retryResult = await bridge.decrypt(sessionInfo.sessionId, envelope.messageJson);
            if (retryResult === null) {
              console.debug(`[DR Adapter] Silent-drop on retry for ${peerId}`);
              return null;
            }
            console.log(`[DR Adapter] Decrypt succeeded on retry for ${peerId}`);
            return retryResult;
          } catch (retryErr) {
            const retryMsg = (retryErr && retryErr.message) ? retryErr.message : (typeof retryErr === 'string' ? retryErr : JSON.stringify(retryErr));
            if (retryMsg === 'MESSAGE_DROP') {
              console.debug(`[DR Adapter] Silent-drop on retry for ${peerId}`);
              return null;
            }
            console.error(`[DR Adapter] Decrypt failed on retry for ${peerId}:`, retryMsg);
            throw new Error('Decrypt failed: ' + errMsg);
          }
        }
      }

      throw new Error(`No Rust DR session established with ${peerId}`);
    },

    // ════════════════════════════════════════════════════════════
    // Session Management
    // ════════════════════════════════════════════════════════════

    /** Check if a session exists (and is actually usable in the Rust store). */
    async hasSession(peerId) {
      const sessionInfo = _sessionMap.get(peerId);
      if (!sessionInfo || !sessionInfo.sessionId) return false;
      // Validate against the real Rust session store — the JS mapping may be
      // stale (e.g. on-disk sessions discarded after a format-version bump).
      try {
        const bridge = _getRatchetBridge();
        if (bridge && bridge.sessionExists) {
          const ok = await bridge.sessionExists(sessionInfo.sessionId);
          if (!ok) {
            console.warn(`[DR Adapter] Stale session mapping for ${peerId} — clearing`);
            _sessionMap.delete(peerId);
            _saveSessionMap();
            return false;
          }
        }
      } catch (e) {
        console.warn('[DR Adapter] hasSession validation failed:', e && e.message);
      }
      return true;
    },

    async deleteSession(peerId) {
      const sessionInfo = _sessionMap.get(peerId);
      if (!sessionInfo) return;
      const bridge = _getRatchetBridge();
      if (bridge) await bridge.deleteSession(sessionInfo.sessionId);
      _sessionMap.delete(peerId);
      _saveSessionMap();
    },

    async getSessionStatus(peerId) {
      const sessionInfo = _sessionMap.get(peerId);
      if (sessionInfo && sessionInfo.version >= DR_VERSION) {
        return {
          secured: true,
          protocol: DR_PROTOCOL,
          curve: 'X25519',
          kdf: 'HKDF-SHA-256',
          aead: 'AES-256-GCM',
          forwardSecrecy: true,
          futureSecrecy: true,
          sessionAge: Date.now() - (sessionInfo.createdAt || Date.now()),
          backend: 'rust-native'
        };
      }
      return { secured: false, protocol: null, forwardSecrecy: false };
    },

    // ════════════════════════════════════════════════════════════
    // Safety Number Fingerprint
    // ════════════════════════════════════════════════════════════

    /** Alias: main-v3.js uses getSecurityStatus. */
    async getSecurityStatus(peerId) {
      return this.getSessionStatus(peerId);
    },

    // ════════════════════════════════════════════════════════════
    // Safety Number Fingerprint (Rust SHA-256 via dr_safety_number)
    // ════════════════════════════════════════════════════════════

    /**
     * Get the Safety Number for a peer.
     *
     * Delegates to Rust `dr_safety_number` — no JS key material.
     *
     * @param {string} peerId
     * @returns {Promise<{fingerprint, ourFingerprint, peerFingerprint}>}
     */
    async getSafetyNumberFingerprint(peerId) {
      const sessionInfo = _sessionMap.get(peerId);
      if (!sessionInfo) throw new Error(`No session for ${peerId}`);
      const bridge = _getRatchetBridge();
      if (!bridge) throw new Error('Rust DR backend not available');
      const sn = await bridge.getSafetyNumber(sessionInfo.sessionId);
      console.log(`[DR Adapter] Safety Number: ${sn.safetyNumber}`);
      return {
        fingerprint: sn.safetyNumber,
        ourFingerprint: sn.ourFingerprint,
        peerFingerprint: sn.peerFingerprint,
        backend: 'rust-x25519-sha256'
      };
    },



    // ════════════════════════════════════════════════════════════
    // Hybrid PQ support (delegated to JS PQ layer for now)
    // ════════════════════════════════════════════════════════════

    async initiateHybridSession(peerId, bundle) {
      // TODO: After dr_init supports two ss_ids, combine X3DH + ML-KEM
      console.log('[DR Adapter] initiateHybridSession: falling back to classical X3DH (hybrid not yet in Rust)');
      return this.initiateSession(peerId, bundle);
    },

    async receiveHybridSession(peerId, aliceInit) {
      // TODO: After dr_init supports two ss_ids, combine X3DH + ML-KEM
      return this.receiveSession(peerId, aliceInit);
    },

  };

  // Install as window.MessageCryptoV2 (pure Rust X25519 v3 backend)
  if (typeof window !== 'undefined' && !window._DRAdapterInstalled) {
    window.MessageCryptoV2 = Adapter;
    window._DRAdapterInstalled = true;
    console.log('[DR Adapter] ✅ Installed as window.MessageCryptoV2 (Rust X25519 backend — no JS fallback)');
  }

  // Also export as standalone
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = Adapter;
  }

})();
