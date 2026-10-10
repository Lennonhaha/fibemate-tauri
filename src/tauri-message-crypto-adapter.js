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
  let _hybridUploadCallback = null;        // main.js registers the hybrid pre-key publisher
  let _hybridKeyPromise = null;            // single-flight guard for ensureHybridPreKey()
  let _publishingBundle = false;           // re-entrancy guard while a bundle upload is in flight

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

      // Per-user identity isolation via Rust-persisted map
      //
      // The localStorage identity reference was fragile — WebView2 profile
      // resets or binary recompiles would orphan the identity on disk and
      // generate a new one. Now Rust maintains a userId → identity_id map
      // in identity_map.json, so the same identity is reused across restarts.
      const identityId = await bridge.getIdentityForUser(currentUserId);

      // Load identity public metadata (no secret key exposure)
      const identity = await bridge.getIdentityPublic(identityId);
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

    /**
     * Register the publisher used to push a changed hybrid pre-key to the
     * server. Called by main.js once the API client is ready.
     */
    setHybridUploadCallback(cb) {
      _hybridUploadCallback = cb;
    },

    /** Record that the given hybrid keyId is now published on the server. */
    markHybridUploaded(keyId) {
      try {
        if (keyId) localStorage.setItem(this._hybridUploadedKey(), keyId);
        localStorage.removeItem(this._hybridPendingKey());
      } catch (e) { /* ignore */ }
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
      const myId = await bridge.getIdentityForUser(currentUserId);

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

      // Init DR session (bind identity keys so dr_safety_number works)
      const dr = await bridge.initSession(x3dh.ssId, peerId, true, { ourIdentityId: myId, peerIdentityPkHex });

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

      // 2026-10-09 修复#3：过滤伪自环（历史 initMessage 路径会生成 peerId === 自己 的假 session）
      {
        const _myUid = localStorage.getItem('fk_uid');
        if (_myUid && peerId === _myUid) {
          console.warn('[DR Adapter] Ignoring self-initiate (peerId === myUid): ' + peerId);
          return null;
        }
      }

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
        const myId = await bridge.getIdentityForUser(currentUserId);
        const syntheticSsId = 'confirm_' + peerId;
        // 合成路径：有对端 identity 就绑，无则降级为 null（不阻断握手）
        const dr = await bridge.initSession(syntheticSsId, peerId, false, { ourIdentityId: myId, peerIdentityPkHex: initMessage.identityKey || null });
        if (initMessage.drPublicKey) {
          await bridge.setPeerKey(dr.sessionId, initMessage.drPublicKey);
        }
        _sessionMap.set(peerId, { sessionId: dr.sessionId, identityId: myId, version: DR_VERSION, createdAt: Date.now() });
        _saveSessionMap();
        console.log('[DR Adapter] Created session from x3dh_accept_rust for ' + encodeURIComponent(JSON.stringify(peerId)));
        return { confirmed: true, sessionEstablished: true, sessionReady: true, rustSession: true };
      }

      // Existing session — set peer DR key
      if (initMessage.drPublicKey) {
        await bridge.setPeerKey(sessionInfo.sessionId, initMessage.drPublicKey);
      }
      console.log('[DR Adapter] Session confirmed (x3dh_accept_rust) for ' + encodeURIComponent(JSON.stringify(peerId)));
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
      // ⚠️ 2026-10-09 修复：仅当已有 session 也是 classical 时才复用。
      //    若已有是 hybrid 而收到 classical init → 重建，采用对端协议（否则双向失配）。
      if (existing && existing.sessionId && existingValid && existing.hybrid !== true) {
        if (peerDrPublicKeyHex && !existing.peerKeyInitialized) {
          try {
            await bridge.setPeerKey(existing.sessionId, peerDrPublicKeyHex);
            existing.peerKeyInitialized = true;
            _saveSessionMap();
          } catch (e) {
            console.warn('[DR Adapter] setPeerKey (idempotent) failed:', e && e.message);
          }
        }
        const ourSendKey = await bridge.getSendKey(existing.sessionId);
        console.log(`[DR Adapter] Reusing existing session ${encodeURIComponent(JSON.stringify(existing.sessionId))} for ${encodeURIComponent(JSON.stringify(peerId))}`);
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
      const myId = await bridge.getIdentityForUser(currentUserId);

      if (existing && existing.sessionId && existing.hybrid === true) {
        console.log('[DR Adapter] Protocol mismatch: stored=hybrid, init=classical -> rebuilding classical (adopt peer protocol)');
      }
      // Parse initiator's keys (hex strings)
      const peerIdentityPkHex = initMessage.identityKey;
      const peerEphemeralPkHex = initMessage.ephemeralKey;

      console.log(`[DR Adapter] X3DH respond to ${encodeURIComponent(JSON.stringify(peerId))} (X25519)`);

      // X3DH responder
      const x3dh = await bridge.x3dhRespond(myId, peerIdentityPkHex, peerEphemeralPkHex);

      // Init DR session (bind identity keys so dr_safety_number works)
      const dr = await bridge.initSession(x3dh.ssId, peerId, false, { ourIdentityId: myId, peerIdentityPkHex });

      // Set peer DR key
      await bridge.setPeerKey(dr.sessionId, peerDrPublicKeyHex || peerEphemeralPkHex);

      // Store mapping
      _sessionMap.set(peerId, {
        sessionId: dr.sessionId,
        identityId: myId,
        version: DR_VERSION,
        createdAt: Date.now(),
        initEphemeralKey: initMessage.ephemeralKey,
        peerKeyInitialized: true
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
            console.debug(`[DR Adapter] Silent-drop duplicate message for ${encodeURIComponent(JSON.stringify(peerId))}`);
            return null;
          }
          // 解密失败 → 自动重试一次（可能对方也刚做了 session 恢复）
          console.warn(`[DR Adapter] Decrypt failed (first attempt) for ${encodeURIComponent(JSON.stringify(peerId))}: ${encodeURIComponent(JSON.stringify(errMsg))}`);
          try {
            const retryResult = await bridge.decrypt(sessionInfo.sessionId, envelope.messageJson);
            if (retryResult === null) {
              console.debug(`[DR Adapter] Silent-drop on retry for ${encodeURIComponent(JSON.stringify(peerId))}`);
              return null;
            }
            console.log(`[DR Adapter] Decrypt succeeded on retry for ${encodeURIComponent(JSON.stringify(peerId))}`);
            return retryResult;
          } catch (retryErr) {
            const retryMsg = (retryErr && retryErr.message) ? retryErr.message : (typeof retryErr === 'string' ? retryErr : JSON.stringify(retryErr));
            if (retryMsg === 'MESSAGE_DROP') {
              console.debug(`[DR Adapter] Silent-drop on retry for ${encodeURIComponent(JSON.stringify(peerId))}`);
              return null;
            }
            console.error(`[DR Adapter] Decrypt failed on retry for ${encodeURIComponent(JSON.stringify(peerId))}: ${encodeURIComponent(JSON.stringify(retryMsg))}`);
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
        const isHybrid = !!sessionInfo.hybrid;
        return {
          secured: true,
          protocol: DR_PROTOCOL,
          curve: isHybrid ? 'X25519 + ML-KEM-768' : 'X25519',
          pq: isHybrid ? 'ml-kem-768' : null,
          pqMode: isHybrid ? (sessionInfo.pqMode || 'x25519+mlkem768') : null,
          hybrid: isHybrid,
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

    // Per-user markers: which hybrid keyId the server already has (uploaded),
    // and one waiting to be published (pending) because no uploader existed yet.
    _hybridUploadedKey() {
      return 'fibemate_rust_hybrid_uploaded_' + (localStorage.getItem('fk_uid') || 'default');
    },
    _hybridPendingKey() {
      return 'fibemate_rust_hybrid_pending_' + (localStorage.getItem('fk_uid') || 'default');
    },

    /**
     * Lazily create (and cache) our hybrid responder keypair, then return
     * the parts that must ride along in the pre-key bundle.
     *
     * Single-flight: concurrent callers share one generation. Two parallel
     * calls used to mint two different keypairs, and the later localStorage
     * write could then disagree with the bundle built by the earlier caller —
     * the same "server holds a stale hybrid key" fork as the 2026-10-09 outage.
     *
     * @param {'classic'|'hybrid'} [mode='hybrid']
     * @returns {Promise<{keyId, bundleHex, mode}>}
     */
    async ensureHybridPreKey(mode) {
      if (!_initialized) await this.init();
      if (_hybridKeyPromise) return _hybridKeyPromise;
      _hybridKeyPromise = (async () => {
        const bridge = _getRatchetBridge();
        const cacheKey = this._hybridStorageKey();
        let cached = null;
        try { cached = JSON.parse(localStorage.getItem(cacheKey)); } catch (e) { cached = null; }
        if (cached && cached.keyId && cached.bundleHex) {
          await this._maybeUploadHybridKey(cached);
          return cached;
        }
        const kg = await bridge.hybridKeygen(mode || 'hybrid');
        const entry = { keyId: kg.keyId, bundleHex: kg.bundle, mode: kg.mode, createdAt: Date.now() };
        try { localStorage.setItem(cacheKey, JSON.stringify(entry)); } catch (e) { /* ignore */ }
        console.log('[DR Adapter] Hybrid pre-key ready (' + entry.mode + ') key_id=' + entry.keyId);
        await this._maybeUploadHybridKey(entry);
        return entry;
      })();
      try {
        return await _hybridKeyPromise;
      } finally {
        _hybridKeyPromise = null;
      }
    },

    /**
     * Publish our hybrid pre-key whenever the cached keyId has not been
     * uploaded yet. Idempotent (skips when already published), never throws,
     * and records a pending marker when no uploader is registered yet so the
     * next bundle upload can flush it.
     */
    async _maybeUploadHybridKey(entry) {
      if (!entry || !entry.keyId) return;
      if (_publishingBundle) return; // re-entrancy: an upload is already running
      const uploadedKey = this._hybridUploadedKey();
      const pendingKey = this._hybridPendingKey();
      let uploaded = null;
      try { uploaded = localStorage.getItem(uploadedKey); } catch (e) { uploaded = null; }
      if (uploaded === entry.keyId) return;
      if (typeof _hybridUploadCallback !== 'function') {
        try { localStorage.setItem(pendingKey, entry.keyId); } catch (e) { /* ignore */ }
        return;
      }
      try {
        _publishingBundle = true;
        await _hybridUploadCallback(entry);
        try {
          localStorage.setItem(uploadedKey, entry.keyId);
          localStorage.removeItem(pendingKey);
        } catch (e) { /* ignore */ }
        console.log('[DR Adapter] Hybrid pre-key published (key_id=' + entry.keyId + ')');
      } catch (e) {
        try { localStorage.setItem(pendingKey, entry.keyId); } catch (e2) { /* ignore */ }
        console.warn('[DR Adapter] Hybrid pre-key upload deferred:', e && e.message ? e.message : e);
      } finally {
        _publishingBundle = false;
      }
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
      const myId = await bridge.getIdentityForUser(currentUserId);

      console.log('[DR Adapter] Hybrid PQ session initiate with ' + peerId + ' (X25519 + ML-KEM-768)');

      // 安全码：hybrid 路径也要把身份键绑到 DR 会话（否则 dr_safety_number 报 our identity not bound）。
      // 本端 identity pk 随 hybrid_init 发给对端；对端 identity pk 取 peer bundle 的 identityKey。
      let ourIdentityPkHex = null;
      try {
        const idPub = await bridge.getIdentityPublic(myId);
        ourIdentityPkHex = (idPub && idPub.publicKeyHex) || null;
      } catch (e) { /* degrade: 无 identity 公钥时仅记录不阻断 */ }
      const peerIdentityPkHexHybrid = (typeof bundle.identityKey === 'string')
        ? bundle.identityKey
        : (Array.isArray(bundle.identityKey)
          ? Array.from(bundle.identityKey).map(b => b.toString(16).padStart(2, '0')).join('')
          : null);
      const pq = await bridge.initiateHybridPQSession(peerId, peerHybridHex, { ourIdentityId: myId, peerIdentityPkHex: peerIdentityPkHexHybrid });

      _sessionMap.set(peerId, {
        sessionId: pq.sessionId,
        identityId: myId,
        version: DR_VERSION,
        hybrid: true,
        pqMode: 'x25519+mlkem768',
        // 2026-10-09 修复#2：记录本次握手指纹（本端 init 的 hybridEnc+drPublicKey）
        hybridFingerprint: this._handshakeFingerprint(pq.enc, pq.ourPublicKeyHex),
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
          hybridBundleId: bundle._hybridKeyId || null,
          // 安全码（方案 A）：本端 X25519 身份公钥 hex，供对端绑定 peer identity
          identityKey: ourIdentityPkHex
        },
        sessionEstablished: true,
        rustSession: true,
        hybridSession: true
      };
    },

    /**
     * 2026-10-09 修复#2：握手指纹。
     * 取对端 init 的 hybridEnc + drPublicKey（每次握手唯一）做确定性摘要，
     * 用于区分「同一次握手的重复到达」与「对端重新发起的新握手 / 分叉自救」。
     * 同步、无依赖（FNV-1a 双通道 64-bit），非安全用途。
     */
    _handshakeFingerprint(hybridEnc, drPublicKey) {
      if (!hybridEnc && !drPublicKey) return null;
      const s = String(hybridEnc || '') + ':' + String(drPublicKey || '');
      let h1 = 0x811c9dc5, h2 = 0x1000193;
      for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
        h2 = Math.imul(h2 ^ (c + i), 0x85ebca6b) >>> 0;
      }
      return h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0');
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
      // 2026-10-09 修复#3：过滤伪自环
      {
        const _myUid = localStorage.getItem('fk_uid');
        if (_myUid && peerId === _myUid) {
          console.warn('[DR Adapter] Ignoring self-initiate (peerId === myUid): ' + peerId);
          return null;
        }
      }
      if (!aliceInit || aliceInit.type !== 'hybrid_init_rust') {
        return this.receiveSession(peerId, aliceInit);
      }

      const bridge = _getRatchetBridge();
      if (!bridge) throw new Error('[DR Adapter] Rust DR backend not available');

      // ═══ [FIX] 幂等：已有有效 session 直接复用，不重建 ═══
      const existing = _sessionMap.get(peerId);
      // 2026-10-09 修复#2：握手指纹 —— 用对端 init 的 hybridEnc+drPublicKey 指纹区分
      //   「同一次握手重复到达」（fp 相同 → 复用）与「对端重新发起 / 分叉自救」（fp 不同 → 重建）。
      //   旧记录无 fingerprint 视为不匹配 → 重建（不再锁死）。
      //   注：ss_id 是本地生成的、两端不同，不能用于比对。
      const incomingFp = this._handshakeFingerprint(aliceInit.hybridEnc, aliceInit.drPublicKey);
      // ⚠️ 2026-10-09 修复：仅当已有 session 也是 hybrid 时才复用。
      //    否则（已有是 classical 而收到 hybrid init 的反向场景）重建，采用对端协议。
      if (existing && existing.sessionId && existing.hybrid === true) {
        let valid = false;
        try { valid = await bridge.sessionExists(existing.sessionId); } catch { valid = false; }
        const sameHandshakeFp = valid && !!incomingFp && existing.hybridFingerprint === incomingFp;
        if (valid && !sameHandshakeFp) {
          console.log('[DR Adapter] Hybrid fingerprint mismatch — rebuilding (old=' + String(existing.hybridFingerprint).slice(0, 12) + ' new=' + String(incomingFp).slice(0, 12) + ') for ' + encodeURIComponent(JSON.stringify(peerId)));
        }
        if (sameHandshakeFp) {
          if (aliceInit.drPublicKey && !existing.peerKeyInitialized) {
            try {
              await bridge.setPeerKey(existing.sessionId, aliceInit.drPublicKey);
              existing.peerKeyInitialized = true;
              _saveSessionMap();
            } catch (e) { /* ignore */ }
          }
          console.log('[DR Adapter] Reusing existing hybrid session for ' + encodeURIComponent(JSON.stringify(peerId)));
          const ourSendKey = await bridge.getSendKey(existing.sessionId);
          return {
            responseMessage: {
              type: 'hybrid_accept_rust',
              version: DR_VERSION,
              protocol: DR_PROTOCOL,
              drPublicKey: ourSendKey
            },
            sessionEstablished: true,
            sessionReady: true,
            rustSession: true,
            hybridSession: true,
            reused: true
          };
        }
      }
      // ═══ [FIX END] ═══

      const cacheKey = this._hybridStorageKey();
      let cached = null;
      try { cached = JSON.parse(localStorage.getItem(cacheKey)); } catch (e) { cached = null; }
      if (!cached || !cached.keyId) {
        throw new Error('[DR Adapter] No hybrid pre-key cached — call ensureHybridPreKey() before accepting PQ sessions');
      }

      if (existing && existing.sessionId) {
        console.log('[DR Adapter] Protocol mismatch: stored=classical, init=hybrid -> rebuilding hybrid (adopt peer protocol)');
      }
      const currentUserId = localStorage.getItem('fk_uid') || 'default';
      const myId = await bridge.getIdentityForUser(currentUserId);

      console.log('[DR Adapter] Hybrid PQ session accept from ' + encodeURIComponent(JSON.stringify(peerId)) + ' (key_id=' + encodeURIComponent(JSON.stringify(cached.keyId)) + ')');
      // 安全码：对端 identity pk 来自 hybrid_init.identityKey（方案 A）；旧版消息无此字段则降级 null
      const peerIdentityPkHexHybrid = aliceInit.identityKey || null;
      if (!peerIdentityPkHexHybrid) console.warn('[DR Adapter] hybrid_init missing identityKey — binding degraded for ' + encodeURIComponent(JSON.stringify(peerId)));
      const dr = await bridge.acceptHybridSession(peerId, cached.keyId, aliceInit.hybridEnc, { ourIdentityId: myId, peerIdentityPkHex: peerIdentityPkHexHybrid });

      if (aliceInit.drPublicKey) {
        await bridge.setPeerKey(dr.sessionId, aliceInit.drPublicKey);
      }
      _sessionMap.set(peerId, {
        sessionId: dr.sessionId,
        identityId: myId,
        version: DR_VERSION,
        hybrid: true,
        pqMode: 'x25519+mlkem768',
        // 2026-10-09 修复#2：记录本次接受的握手指纹，供后续握手比对
        hybridFingerprint: incomingFp,
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
