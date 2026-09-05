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
      // Hybrid PQ pre-key (responder bundle) — cached across calls.
      let hybrid = null;
      try {
        hybrid = await this.ensureHybridPreKey('hybrid');
      } catch (hErr) {
        console.warn('[DR Adapter] Hybrid pre-key unavailable:', hErr && hErr.message ? hErr.message : hErr);
      }

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
        // Hybrid PQ advertisement — lazily create/cache our ML-KEM-768
        // responder keypair so the stored bundle always matches our keyId.
        // Peers that support it will run a real PQ handshake; others
        // seamlessly fall back to classical X3DH (fields are additive).
        _pqAvailable: !!hybrid,
        _hybridKeyId: hybrid ? hybrid.keyId : null,
        _hybridBundleHex: hybrid ? hybrid.bundleHex : null,
        _hybridMode: hybrid ? hybrid.mode : null
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

      // X3DH handshake — SPK signature is MANDATORY (prevents SPK substitution).
      // Rust rejects the handshake if the signature is absent or does not verify.
      const peerSigningPkHex = (typeof bundle.identitySigningKey === 'string')
        ? bundle.identitySigningKey : null;
      const peerSpkSigHex = (typeof bundle.signedPreKeySignature === 'string')
        ? bundle.signedPreKeySignature : null;
      if (!peerSigningPkHex || !peerSpkSigHex) {
        throw new Error(`[DR Adapter] Peer bundle for ${peerId} is missing identitySigningKey/signedPreKeySignature — SPK verification cannot be skipped`);
      }

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

      // Bob/Alice receives an accept (x3dh or hybrid) — set peer DR key on
      // the existing session.  MUST be checked BEFORE version check, since
      // both accept types carry version:3.
      if (initMessage.type === 'x3dh_accept_rust' || initMessage.type === 'hybrid_accept_rust') {
        return this._receiveAcceptRust(peerId, initMessage);
      }

      // Hybrid PQ init (Alice → Bob) — X25519 ECDH + ML-KEM-768 encaps.
      // MUST be routed before the generic version-3 path: hybrid_init_rust
      // carries hybridEnc + drPublicKey (no X3DH fields), so treating it as
      // a classical x3dh init would break the handshake.
      if (initMessage.type === 'hybrid_init_rust') {
        return this.receiveHybridSession(peerId, initMessage);
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
    // Hybrid PQ support — ML-KEM-768 + X25519 (Rust hybrid_cmd layer)
    // ════════════════════════════════════════════════════════════
    //
    // Bob advertises a hybrid bundle (hybrid_keygen output) inside the
    // pre-key bundle (_hybridKeyId/_hybridBundleHex, cached in localStorage
    // so the bundle on the server always matches Bob's local keyId).
    // Alice detects it and runs a real PQ handshake:
    //   Alice: hybrid_begin(bob_bundle) -> ss_id -> dr_init(initiator)
    //   Bob:   hybrid_accept(key_id, alice_enc) -> ss_id -> dr_init(responder)
    // The 64-byte combined secret (HKDF-SHA3-512 of ECDH | ML-KEM) is split
    // at 32 bytes into shared_secrets — identical to an X3DH ss.  No change
    // to dr_init; the DR layer is unaware it is seeded from a PQ mix.
    // Sessions that only have classical bundles keep the X3DH path.

    // localStorage cache key for the responder's hybrid keypair.
    _hybridStorageKey() {
      return 'fibemate_rust_hybrid_' + (localStorage.getItem('fk_uid') || 'default');
    },

    /**
     * Lazily create (and cache) our hybrid responder keypair, then return
     * the parts that must ride along in the pre-key bundle.
     *
     * @param {'classic'|'hybrid'} [mode='hybrid']
     * @returns {Promise<{keyId, bundleHex, mode}>}
     */
    async ensureHybridPreKey(mode) {
      if (!_initialized) await this.init();
      const bridge = _getRatchetBridge();
      const cacheKey = this._hybridStorageKey();
      let cached = null;
      try { cached = JSON.parse(localStorage.getItem(cacheKey)); } catch (e) { cached = null; }
      if (cached && cached.keyId && cached.bundleHex) {
        return cached;
      }
      const kg = await bridge.hybridKeygen(mode || 'hybrid');
      const entry = { keyId: kg.keyId, bundleHex: kg.bundle, mode: kg.mode, createdAt: Date.now() };
      try { localStorage.setItem(cacheKey, JSON.stringify(entry)); } catch (e) { /* ignore */ }
      console.log('[DR Adapter] Hybrid pre-key ready (' + entry.mode + ') key_id=' + entry.keyId);
      return entry;
    },

    /**
     * Initiate a hybrid (ML-KEM-768 + X25519) session toward a peer whose
     * bundle carries a hybrid bundle.  Falls back to classical X3DH when the
     * peer has not advertised a hybrid bundle.
     *
     * @param {string} peerId
     * @param {object} bundle — pre-key bundle (may carry _hybridKeyId/_hybridBundleHex)
     * @returns {Promise<{initialMessage, sessionEstablished, hybridSession}>}
     */
    async initiateHybridSession(peerId, bundle) {
      if (!_initialized) await this.init();
      const bridge = _getRatchetBridge();
      if (!bridge) {
        throw new Error('[DR Adapter] Rust DR backend not available — Tauri required');
      }

      const peerHybridHex = bundle && (bundle._hybridBundleHex || bundle.hybridBundleHex);
      if (!peerHybridHex) {
        console.log('[DR Adapter] Peer has no hybrid bundle — falling back to classical X3DH');
        return this.initiateSession(peerId, bundle);
      }

      const currentUserId = localStorage.getItem('fk_uid') || 'default';
      if (currentUserId !== _currentUserId) {
        _sessionMap.clear();
        _identityBundles = {};
        _currentUserId = currentUserId;
      }
      const identityKey = 'fibemate_rust_identity_id_' + currentUserId;
      const myId = localStorage.getItem(identityKey);
      if (!myId) throw new Error('No identity generated — call getMyPreKeyBundle() first');

      console.log('[DR Adapter] Hybrid PQ session initiate with ' + peerId + ' (X25519 + ML-KEM-768)');
      const pq = await bridge.initiateHybridPQSession(peerId, peerHybridHex);

      _sessionMap.set(peerId, {
        sessionId: pq.sessionId,
        identityId: myId,
        version: DR_VERSION,
        hybrid: true,
        pqMode: 'x25519+mlkem768',
        createdAt: Date.now()
      });
      _saveSessionMap();

      return {
        initialMessage: {
          type: 'hybrid_init_rust',
          version: DR_VERSION,
          protocol: DR_PROTOCOL,
          hybridEnc: pq.enc,
          drPublicKey: pq.ourPublicKeyHex,
          hybridBundleId: bundle._hybridKeyId || null
        },
        sessionEstablished: true,
        rustSession: true,
        hybridSession: true
      };
    },

    /**
     * Receive a hybrid session (Bob side).  Handles Alice's hybrid_init_rust
     * using our cached hybrid keypair.  Falls back to classical X3DH for any
     * other message shape.
     *
     * @param {string} peerId — initiator's user ID
     * @param {object} aliceInit — Alice's hybrid_init_rust (or legacy init)
     */
    async receiveHybridSession(peerId, aliceInit) {
      if (!_initialized) await this.init();
      if (!aliceInit || aliceInit.type !== 'hybrid_init_rust') {
        return this.receiveSession(peerId, aliceInit);
      }

      const bridge = _getRatchetBridge();
      if (!bridge) throw new Error('[DR Adapter] Rust DR backend not available');

      const cacheKey = this._hybridStorageKey();
      let cached = null;
      try { cached = JSON.parse(localStorage.getItem(cacheKey)); } catch (e) { cached = null; }
      if (!cached || !cached.keyId) {
        throw new Error('[DR Adapter] No hybrid pre-key cached — call ensureHybridPreKey() before accepting PQ sessions');
      }

      console.log('[DR Adapter] Hybrid PQ session accept from ' + peerId + ' (key_id=' + cached.keyId + ')');
      const dr = await bridge.acceptHybridSession(peerId, cached.keyId, aliceInit.hybridEnc);

      if (aliceInit.drPublicKey) {
        await bridge.setPeerKey(dr.sessionId, aliceInit.drPublicKey);
      }

      const currentUserId = localStorage.getItem('fk_uid') || 'default';
      const identityKey = 'fibemate_rust_identity_id_' + currentUserId;
      const myId = localStorage.getItem(identityKey) || null;
      _sessionMap.set(peerId, {
        sessionId: dr.sessionId,
        identityId: myId,
        version: DR_VERSION,
        hybrid: true,
        pqMode: 'x25519+mlkem768',
        createdAt: Date.now()
      });
      _saveSessionMap();

      return {
        responseMessage: {
          type: 'hybrid_accept_rust',
          version: DR_VERSION,
          protocol: DR_PROTOCOL,
          drPublicKey: dr.ourPublicKeyHex
        },
        sessionEstablished: true,
        sessionReady: true,
        rustSession: true,
        hybridSession: true
      };
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
