/**
 * Tauri Ratchet Bridge — FIBEMATE Double Ratchet Frontend
 * ─────────────────────────────────────────────────────────
 * Replaces MessageCryptoV2.js with Rust-backed Double Ratchet.
 *
 * 🔒 All key material lives in Rust memory (X25519, X3DH, Double Ratchet).
 * 🔒 Shared secrets NEVER reach JS — consumed via opaque ss_id handles.
 * 🔒 Identity secret keys stored encrypted on disk (AES-256-GCM device key).
 * 🔒 Session keys live only in Rust memory — zeroize() on delete.
 *
 * Protocol stack:
 *   Identity:  X25519 keypair (persistent, encrypted on disk)
 *   Key Exchange: X3DH (3-DH) in Rust
 *   Ratchet:   Double Ratchet (Signal Protocol) in Rust
 *   AEAD:      AES-256-GCM in Rust
 *
 * Full E2E flow:
 *   ┌──────────────┐                          ┌──────────────┐
 *   │    Alice      │                          │     Bob       │
 *   │ ik_generate() │                          │ ik_generate() │
 *   │ x3dh_initiate │ ──→ {ik, ek} ──────────→│ x3dh_respond │
 *   │ dr_init()     │                          │ dr_init()     │
 *   │ dr_set_peer() │←── exchange X25519 pk → │ dr_set_peer() │
 *   │ dr_encrypt()  │ ──→ message_json ─────→ │ dr_decrypt()  │
 *   └──────────────┘                          └──────────────┘
 */

(function () {
  'use strict';

  // ── Lazy Tauri invoke ───────────────────────────────────────
  let _invoke = null;
  function invoke() {
    if (_invoke) return _invoke;
    if (typeof window !== 'undefined' && window.__TAURI__?.core?.invoke) {
      _invoke = window.__TAURI__.core.invoke;
      return _invoke;
    }
    throw new Error('[RatchetBridge] Not running in Tauri — window.__TAURI__.core.invoke unavailable');
  }

  // ── Hex ↔ Bytes ────────────────────────────────────────────
  function hexToBytes(hex) {
    const len = hex.length / 2;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // ── Text ↔ Hex ─────────────────────────────────────────────
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function textToHex(str) {
    return bytesToHex(encoder.encode(str));
  }

  function hexToText(hex) {
    return decoder.decode(hexToBytes(hex));
  }

  // ── Bridge object ───────────────────────────────────────────
  const RatchetBridge = {
    initialized: false,
    _identityId: null,
    _sessions: new Map(),  // sessionId → { peerName, createdAt }

    // ════════════════════════════════════════════════════════════
    // Initialization
    // ════════════════════════════════════════════════════════════

    /** One-time init — verifies Tauri backend is reachable. */
    init() {
      if (this.initialized) return;
      invoke(); // quick sanity check
      this.initialized = true;
      console.log('[RatchetBridge] ✅ Initialized — Rust DR backend ready');
    },

    /** Get current status for debugging. */
    getStatus() {
      return {
        initialized: this.initialized,
        identityId: this._identityId,
        activeSessions: this._sessions.size,
        engine: 'tauri-rust-double-ratchet',
        curve: 'X25519',
        protocol: 'X3DH + Double Ratchet (Signal Protocol)'
      };
    },

    // ════════════════════════════════════════════════════════════
    // Identity Key Management
    // ════════════════════════════════════════════════════════════

    /**
     * Generate or retrieve an X25519 identity keypair.
     * Call once per installation — key is persisted encrypted on disk.
     *
     * @param {string} [identityId] — optional, generated if omitted
     * @returns {Promise<{identityId, publicKeyHex, fingerprint}>}
     */
    async generateIdentity(identityId) {
      if (!this.initialized) this.init();
      const fn = invoke();
      const result = await fn('ik_generate', { identityId: identityId || null });
      this._identityId = result.identity_id;
      console.log('[RatchetBridge] Identity:', result.identity_id, 'fingerprint:', result.fingerprint);
      return {
        identityId: result.identity_id,
        publicKeyHex: result.public_key_hex,
        fingerprint: result.fingerprint
      };
    },

    /** Get public info for an identity (without decrypting secret key). */
    async getIdentityPublic(identityId) {
      if (!this.initialized) this.init();
      const result = await invoke()('ik_get_public', { identityId });
      return {
        identityId: result.identity_id,
        publicKeyHex: result.public_key_hex,
        fingerprint: result.fingerprint
      };
    },

    /** List all stored identities. */
    async listIdentities() {
      if (!this.initialized) this.init();
      const result = await invoke()('ik_list');
      return result.identities.map(i => ({
        identityId: i.identity_id,
        publicKeyHex: i.public_key_hex,
        fingerprint: i.fingerprint
      }));
    },

    // ════════════════════════════════════════════════════════════
    // X3DH Key Exchange
    // ════════════════════════════════════════════════════════════

    /**
     * Initiate X3DH key exchange (Alice side).
     *
     * Call this after fetching the peer's pre-key bundle from the server.
     * The peer's signed pre-key is ephemeral — generated fresh per bundle.
     *
     * @param {string} myIdentityId — from generateIdentity()
     * @param {string} peerIdentityPkHex — peer's X25519 identity public key (hex)
     * @param {string} peerSignedPrekeyPkHex — peer's X25519 signed pre-key (hex)
     * @returns {Promise<{ssId, ourIdentityPkHex, ourEphemeralPkHex}>}
     *   → send {ourIdentityPkHex, ourEphemeralPkHex} to peer via server
     */
    async x3dhInitiate(myIdentityId, peerIdentityPkHex, peerSignedPrekeyPkHex, peerSigningPkHex = null, peerSpkSigHex = null) {
      if (!this.initialized) this.init();
      const result = await invoke()('x3dh_initiate', {
        myIdentityId,
        peerIdentityPkHex,
        peerSignedPrekeyPkHex,
        peerSigningPkHex,
        peerSpkSigHex
      });
      console.log('[RatchetBridge] X3DH initiate → ss_id:', result.ss_id);
      return {
        ssId: result.ss_id,
        ourIdentityPkHex: result.our_identity_pk_hex,
        ourEphemeralPkHex: result.our_ephemeral_pk_hex
      };
    },

    /**
     * Fetch the full pre-key bundle (IK + ISK + independent SPK + signature).
     * The SPK is lazily generated on first use and persisted; the ML-DSA-65
     * signature binds the SPK to the identity.
     *
     * @param {string} myIdentityId — from generateIdentity()
     * @returns {Promise<{identity_id, identity_pk_hex, signing_pk_hex,
     *                    signed_prekey_hex, signed_prekey_sig_hex, signed_prekey_id}>}
     */
    async getSpkPublic(myIdentityId) {
      if (!this.initialized) this.init();
      return await invoke()('spk_get_public', { identityId: myIdentityId });
    },

    /**
     * Rotate the independent signed pre-key and return the fresh bundle.
     * Old established sessions are unaffected; new handshakes use the new SPK.
     */
    async rotateSpk(myIdentityId) {
      if (!this.initialized) this.init();
      return await invoke()('spk_rotate', { identityId: myIdentityId });
    },

    /**
     * Respond to X3DH key exchange (Bob side).
     *
     * Call this after receiving Alice's {identityPkHex, ephemeralPkHex}.
     *
     * @param {string} myIdentityId — from generateIdentity()
     * @param {string} peerIdentityPkHex — initiator's identity public key (hex)
     * @param {string} peerEphemeralPkHex — initiator's ephemeral public key (hex)
     * @returns {Promise<{ssId, ourIdentityPkHex, ourSignedPrekeyPkHex}>}
     */
    async x3dhRespond(myIdentityId, peerIdentityPkHex, peerEphemeralPkHex) {
      if (!this.initialized) this.init();
      const result = await invoke()('x3dh_respond', {
        myIdentityId,
        peerIdentityPkHex,
        peerEphemeralPkHex
      });
      console.log('[RatchetBridge] X3DH respond → ss_id:', result.ss_id);
      return {
        ssId: result.ss_id,
        ourIdentityPkHex: result.our_identity_pk_hex,
        ourSignedPrekeyPkHex: result.our_signed_prekey_pk_hex
      };
    },

    // ════════════════════════════════════════════════════════════
    // Double Ratchet Session Management
    // ════════════════════════════════════════════════════════════

    /**
     * Initialize a Double Ratchet session from an X3DH shared secret.
     *
     * Consumes the ss_id (shared secret removed from Rust HashMap after use).
     *
     * @param {string} ssId — from x3dhInitiate() or x3dhRespond()
     * @param {string} peerName — human-readable peer identifier
     * @param {boolean} isInitiator — true for Alice, false for Bob
     * @param {object} [identity] — optional identity binding for Safety Number
     * @param {string} [identity.ourIdentityId] — our identity KeyStore ID
     * @param {string} [identity.peerIdentityPkHex] — peer's identity public key (hex)
     * @returns {Promise<{sessionId, ourPublicKeyHex}>}
     */
    async initSession(ssId, peerName, isInitiator, identity) {
      if (!this.initialized) this.init();
      const params = { ssId, peerName, isInitiator };
      if (identity) {
        params.ourIdentityId = identity.ourIdentityId || null;
        params.peerIdentityPkHex = identity.peerIdentityPkHex || null;
      }
      const result = await invoke()('dr_init', params);
      this._sessions.set(result.session_id, {
        peerName,
        createdAt: Date.now(),
        ourIdentityId: identity?.ourIdentityId,
        peerIdentityPkHex: identity?.peerIdentityPkHex
      });
      console.log(`[RatchetBridge] DR session created: ${result.session_id} with ${peerName}`);
      return {
        sessionId: result.session_id,
        ourPublicKeyHex: result.our_public_key
      };
    },

    /**
     * Set the peer's DR public key.
     * Must be called before decrypting messages from them.
     *
     * @param {string} sessionId
     * @param {string} peerPublicKeyHex — from their dr_init() response
     */
    async setPeerKey(sessionId, peerPublicKeyHex) {
      if (!this.initialized) this.init();
      await invoke()('dr_set_peer', { sessionId, peerPublicKeyHex });
    },

    /**
     * Encrypt a plaintext message in a Double Ratchet session.
     *
     * Each call advances the ratchet (forward secrecy).
     *
     * @param {string} sessionId
     * @param {string} plaintext — raw text (auto-encoded to UTF-8)
     * @returns {Promise<{messageJson, messageNum}>}
     *   → send messageJson to peer via server
     */
    async encrypt(sessionId, plaintext) {
      if (!this.initialized) this.init();
      const plaintextHex = textToHex(plaintext);
      const result = await invoke()('dr_encrypt', { sessionId, plaintextHex });
      return {
        messageJson: result.message_json,
        messageNum: result.message_num
      };
    },

    /**
     * Decrypt a message in a Double Ratchet session.
     *
     * Each call advances the ratchet (forward secrecy).
     *
     * @param {string} sessionId
     * @param {string} messageJson — from encrypt() output
     * @returns {Promise<string>} plaintext
     * @throws {Error} on AEAD failure (tampered/corrupt message)
     */
    async decrypt(sessionId, messageJson) {
      if (!this.initialized) this.init();
      const result = await invoke()('dr_decrypt', { sessionId, messageJson });
      // null plaintext_hex means duplicate/replay — signal silent drop to adapter
      if (result.plaintext_hex === null) {
        throw new Error('MESSAGE_DROP');
      }
      return hexToText(result.plaintext_hex);
    },

    /**
     * Get this session's current sending X25519 public key.
     * Send this to the peer so they can setPeerKey().
     */
    async getSendKey(sessionId) {
      if (!this.initialized) this.init();
      return await invoke()('dr_get_send_key', { sessionId });
    },

    /**
     * Delete a session and wipe its key material from memory.
     */
    async deleteSession(sessionId) {
      if (!this.initialized) this.init();
      await invoke()('dr_delete_session', { sessionId });
      this._sessions.delete(sessionId);
      console.log(`[RatchetBridge] Session deleted: ${sessionId}`);
    },

    /**
     * Check whether a Rust DR session actually exists.
     * Used by the adapter to validate JS-side session mappings against the
     * real Rust session store (e.g. after on-disk sessions were discarded).
     */
    async sessionExists(sessionId) {
      if (!this.initialized) this.init();
      return await invoke()('dr_session_exists', { sessionId });
    },

    /**
     * List all active Rust DR session IDs.
     * session_id format: `{uuid8}_{peerName}` (peerName = peerId from adapter).
     *
     * @returns {Promise<string[]>}
     */
    async listSessions() {
      if (!this.initialized) this.init();
      const result = await invoke()('dr_list_sessions');
      return Array.isArray(result) ? result : [];
    },

    /**
     * Get the Safety Number for a session.
     *
     * Requires the session to have been initialized with identity key
     * binding (ourIdentityId + peerIdentityPkHex passed to initSession).
     *
     * @param {string} sessionId
     * @returns {Promise<{safetyNumber, ourFingerprint, peerFingerprint}>}
     *
     * @example
     * const sn = await bridge.getSafetyNumber(sessionId);
     * console.log('Safety Number:', sn.safetyNumber);
     * // → "12345 67890 12345 67890 12345"
     */
    async getSafetyNumber(sessionId) {
      if (!this.initialized) this.init();
      const result = await invoke()('dr_safety_number', { sessionId });
      console.log(`[RatchetBridge] Safety Number for ${sessionId}: ${result.safety_number}`);
      return {
        safetyNumber: result.safety_number,
        ourFingerprint: result.our_fingerprint,
        peerFingerprint: result.peer_fingerprint
      };
    },

    // ════════════════════════════════════════════════════════════
    // ML-KEM-768 Hybrid X3DH (Post-Quantum)
    // ════════════════════════════════════════════════════════════

    /**
     * Perform hybrid X3DH + ML-KEM-768 key exchange (initiator).
     *
     * Combines classical X25519 X3DH with post-quantum ML-KEM-768.
     * Both shared secrets are passed to dr_init for HKDF combination.
     *
     * ⚠️ NOT YET IMPLEMENTED — requires dr_init to accept two ss_ids.
     * Currently you can only use X3DH alone or ML-KEM alone.
     */
    async hybridX3dhInitiate(myIdentityId, peerBundle) {
      console.warn('[RatchetBridge] hybridX3dhInitiate — hybrid combine in Rust not yet exposed via commands');
      // For now: fall back to classical X3DH only
      return this.x3dhInitiate(myIdentityId, peerBundle.identityPkHex, peerBundle.signedPrekeyPkHex);
    },

    // ════════════════════════════════════════════════════════════
    // Full Flow Helper
    // ════════════════════════════════════════════════════════════

    /**
     * Complete E2E session setup (Alice side).
     *
     * Generates identity → fetches peer bundle → X3DH → DR init.
     *
     * @param {string} peerName — peer's human-readable name
     * @param {object} peerBundle — { identityPkHex, signedPrekeyPkHex } from server
     * @returns {Promise<{sessionId, initMessage}>}
     *   initMessage = { identityPkHex, ephemeralPkHex } — send to peer
     */
    async setupSessionAsInitiator(peerName, peerBundle) {
      // Step 1: Ensure we have an identity
      if (!this._identityId) {
        const id = await this.generateIdentity();
        this._identityId = id.identityId;
      }

      // Step 2: X3DH initiate
      const x3dh = await this.x3dhInitiate(
        this._identityId,
        peerBundle.identityPkHex,
        peerBundle.signedPrekeyPkHex
      );

      // Step 3: DR init
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

    /**
     * Complete E2E session setup (Bob side).
     *
     * @param {string} peerName — initiator's human-readable name
     * @param {object} initMessage — { identityPkHex, ephemeralPkHex } from Alice
     * @returns {Promise<{sessionId, acceptMessage}>}
     *   acceptMessage = { identityPkHex, signedPrekeyPkHex } — send to initiator
     */
    async setupSessionAsResponder(peerName, initMessage) {
      // Step 1: Ensure we have an identity
      if (!this._identityId) {
        const id = await this.generateIdentity();
        this._identityId = id.identityId;
      }

      // Step 2: X3DH respond
      const x3dh = await this.x3dhRespond(
        this._identityId,
        initMessage.identityPkHex,
        initMessage.ephemeralPkHex
      );

      // Step 3: DR init
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
    // Check if Tauri is available
    if (window.__TAURI__?.core?.invoke) {
      window.RatchetBridge = RatchetBridge;
      window.FIBEMATE_DR = RatchetBridge;  // short alias
      console.log('[RatchetBridge] ✅ Registered — window.RatchetBridge + window.FIBEMATE_DR');
    } else {
      console.warn('[RatchetBridge] Not in Tauri — RatchetBridge not registered (use MessageCryptoV2 fallback?)');
    }
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = RatchetBridge;
  }

})();
