/**
 * Tauri Crypto Bridge — FIBEMATE Post-Quantum Desktop
 * ───────────────────────────────────────────────────
 * Replaces WASM/pure-JS ML-KEM with Tauri invoke() calls.
 *
 * 🔒 ML-KEM secret keys → encrypted on disk (AES-256-GCM device key).
 * 🔒 Shared secrets → NEVER leave Rust (returned as opaque ss_id).
 * 🔒 Full crypto isolation — frontend sees only opaque identifiers.
 *
 * API:
 *   bridge.keygen()            → { publicKey, secretKey(keyId) }
 *   bridge.encaps(pk)           → { ciphertext, ssId }
 *   bridge.decaps(keyId, ct)    → { ssId }
 *   bridge.getStatus()          → { initialized, engine, ... }
 *
 * Shared secrets consumed by dr_init(ss_id) in Rust — JS never sees them.
 */

(function () {
  'use strict';

  // ── Constants ───────────────────────────────────────────────
  const PK_SIZE  = 1184;   // ML-KEM-768 public key bytes
  const SK_SIZE  = 2400;   // ML-KEM-768 secret key bytes
  const CT_SIZE  = 1088;   // ML-KEM-768 ciphertext bytes
  const SS_SIZE  = 32;     // Shared secret bytes

  // ── Hex ↔ Bytes (no external deps) ──────────────────────────
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

  // ── Lazy Tauri invoke ───────────────────────────────────────
  let _invoke = null;
  function getInvoke() {
    if (_invoke) return _invoke;
    if (typeof window !== 'undefined' && window.__TAURI__?.core?.invoke) {
      _invoke = window.__TAURI__.core.invoke;
      return _invoke;
    }
    throw new Error('[TauriCrypto] window.__TAURI__.core.invoke not found — not running in Tauri?');
  }

  // ── Bridge object ───────────────────────────────────────────
  const TauriCryptoBridge = {
    initialized: false,
    _engine: null,

    // ── init ──────────────────────────────────────────────────
    init() {
      if (this.initialized) return;
      try {
        getInvoke();
        this._engine = 'tauri';
        this.initialized = true;
        console.log('[TauriCrypto] ✅ Initialized — Rust backend ready');
      } catch (e) {
        console.warn('[TauriCrypto] Init failed:', e.message);
        throw e;
      }
    },

    // ── keygen ────────────────────────────────────────────────
    // Returns { publicKey: Uint8Array, secretKey: String(keyId) }
    // secretKey is an opaque keyId — NOT raw key bytes!
    async keygen() {
      if (!this.initialized) await this.init();
      const invoke = getInvoke();

      const result = await invoke('kem_keygen');
      console.log('[TauriCrypto] keygen → key_id:', result.key_id);

      return {
        publicKey: hexToBytes(result.public_key),
        secretKey: result.key_id   // ⚠️ Opaque keyId, not raw bytes!
      };
    },

    // ── encaps ────────────────────────────────────────────────
    // 🔒 Returns { ciphertext, ssId } — shared_secret stays in Rust.
    // ssId is an opaque handle for dr_init().
    async encaps(peerPublicKey) {
      if (!this.initialized) await this.init();
      const invoke = getInvoke();

      const pkHex = bytesToHex(peerPublicKey);
      const result = await invoke('kem_encapsulate', { peerPublicKeyHex: pkHex });
      console.log('[TauriCrypto] encaps → ss_id:', result.ss_id);

      return {
        ciphertext: hexToBytes(result.ciphertext),
        ssId: result.ss_id       // ← opaque handle, pass to dr_init()
      };
    },

    // ── decaps ────────────────────────────────────────────────
    // 🔒 Returns { ssId } — shared_secret stays in Rust.
    // keyId must be a string from keygen() (NOT raw bytes).
    async decaps(keyId, ciphertext) {
      if (!this.initialized) await this.init();
      const invoke = getInvoke();

      if (typeof keyId !== 'string') {
        throw new Error(
          '[TauriCrypto] decaps: expected keyId string (from keygen()), got ' +
          (keyId instanceof Uint8Array ? 'raw bytes — WASM era is over' : typeof keyId)
        );
      }

      const ctHex = bytesToHex(ciphertext);
      const result = await invoke('kem_decapsulate', { keyId, ciphertextHex: ctHex });
      console.log('[TauriCrypto] decaps → ss_id:', result.ss_id);

      return { ssId: result.ss_id };   // ← opaque handle, pass to dr_init()
    },

    // ── hybridCombine ─────────────────────────────────────────
    // ⚠️ DEPRECATED in Tauri mode — hybrid combine now happens in Rust.
    // Kept for non-Tauri (WASM/pure-JS) fallback only.
    async hybridCombine(kemSecret, ecdhSecret) {
      console.warn('[TauriCrypto] hybridCombine in Tauri — use Rust dr_init with both ss_ids');
      const combined = new Uint8Array(kemSecret.length + ecdhSecret.length);
      combined.set(kemSecret, 0);
      combined.set(ecdhSecret, kemSecret.length);
      const hash = await crypto.subtle.digest('SHA-256', combined);
      return new Uint8Array(hash);
    },

    // ── status ────────────────────────────────────────────────
    getStatus() {
      return {
        initialized: this.initialized,
        engine: this._engine || 'pending',
        wasmAvailable: false,
        tauriAvailable: this._engine === 'tauri'
      };
    }
  };

  // ════════════════════════════════════════════════════════════
  // SM2 Elliptic Curve Cryptography (GB/T 32918)
  // ════════════════════════════════════════════════════════════
  //
  // All SM2 private keys live in the Rust KeyStore — the frontend
  // only sees opaque keyId / ssId handles.  Never raw key bytes.
  //
  // API:
  //   SM2.generateKeyPair()              → { keyId, publicKeyHex }
  //   SM2.getPublicKey(keyId)            → { publicKeyHex }
  //   SM2.sign(keyId, msgHash)           → { r, s }
  //   SM2.verify(pubKeyHex, msgHash, r, s) → { valid }
  //   SM2.ecdh(keyId, peerPubKeyHex)     → { ssId }
  //   SM2.encrypt(pubKeyHex, plaintext)  → { c1, c2 }
  //   SM2.decrypt(keyId, c1, c2)         → { plaintext }

  const SM2 = {
    /**
     * Generate a new SM2 key pair.
     * Private key → encrypted in KeyStore (never returned).
     * @returns {{ keyId: string, publicKeyHex: string }}
     */
    async generateKeyPair() {
      const invoke = getInvoke();
      const result = await invoke('sm2_generate');
      console.log('[SM2] generateKeyPair → keyId:', result.key_id);
      return { keyId: result.key_id, publicKeyHex: result.public_key_hex };
    },

    /**
     * Import an existing SM2 private key (legacy JS storage migration).
     * @param {string} privateKeyHex — 64-char hex (32 bytes)
     * @returns {{ keyId: string, publicKeyHex: string }}
     */
    async importKey(privateKeyHex) {
      const invoke = getInvoke();
      const result = await invoke('sm2_import', { privateKeyHex });
      console.log('[SM2] importKey → keyId:', result.key_id);
      return { keyId: result.key_id, publicKeyHex: result.public_key_hex };
    },

    /**
     * Derive the public key for an existing SM2 key_id.
     * @param {string} keyId — opaque handle from generateKeyPair()
     * @returns {{ publicKeyHex: string }}
     */
    async getPublicKey(keyId) {
      const invoke = getInvoke();
      const result = await invoke('sm2_get_public', { keyId });
      return { publicKeyHex: result.public_key_hex };
    },

    /**
     * Sign a message hash with an SM2 private key.
     * @param {string} keyId — opaque handle
     * @param {string} msgHash — 64-char hex (e.g. SHA-256 digest)
     * @returns {{ r: string, s: string }} — hex signature components
     */
    async sign(keyId, msgHash) {
      const invoke = getInvoke();
      const result = await invoke('sm2_sign', { keyId, msgHash });
      console.log('[SM2] sign → r:', result.r.slice(0, 16) + '…');
      return { r: result.r, s: result.s };
    },

    /**
     * Verify an SM2 signature against a message hash.
     * @param {string} publicKeyHex — uncompressed 04||x||y hex (130 chars)
     * @param {string} msgHash — 64-char hex
     * @param {string} r — signature r (hex)
     * @param {string} s — signature s (hex)
     * @returns {{ valid: boolean }}
     */
    async verify(publicKeyHex, msgHash, r, s) {
      const invoke = getInvoke();
      return await invoke('sm2_verify', { publicKeyHex, msgHash, r, s });
    },

    /**
     * Compute SM2 ECDH shared secret with a peer's public key.
     * Shared secret → stored in Rust shared_secrets (never returned).
     * @param {string} keyId — our SM2 key
     * @param {string} peerPublicKeyHex — peer's uncompressed public key
     * @returns {{ ssId: string }} — opaque handle (consume with dr_init)
     */
    async ecdh(keyId, peerPublicKeyHex) {
      const invoke = getInvoke();
      const result = await invoke('sm2_ecdh', { keyId, peerPublicKeyHex });
      console.log('[SM2] ecdh → ssId:', result.ss_id);
      return { ssId: result.ss_id };
    },

    /**
     * Encrypt plaintext for a recipient using their SM2 public key.
     * @param {string} publicKeyHex — uncompressed 04||x||y
     * @param {string} plaintext — UTF-8 plaintext
     * @returns {{ c1: string, c2: string }} — hex ciphertext components
     */
    async encrypt(publicKeyHex, plaintext) {
      const invoke = getInvoke();
      return await invoke('sm2_encrypt', { publicKeyHex, plaintext });
    },

    /**
     * Decrypt an SM2 ciphertext using the private key identified by keyId.
     * @param {string} keyId — opaque handle
     * @param {string} c1 — ciphertext C1 (hex)
     * @param {string} c2 — ciphertext C2 (hex)
     * @returns {{ plaintext: string }} — decrypted UTF-8
     */
    async decrypt(keyId, c1, c2) {
      const invoke = getInvoke();
      return await invoke('sm2_decrypt', { keyId, c1, c2 });
    },

    // ── Standard SM2 (GB/T 32918.4 — KDF + C3 integrity) ──────
    //
    // These mirror the frontend `SM2Browser` byte-for-byte, so the
    // GM messaging path can route key material out of JS entirely.

    /**
     * Encrypt plaintext with standard SM2 (C1||C3||C2 wire format).
     * @param {string} publicKeyHex — uncompressed 04||x||y (130 chars)
     * @param {string} plaintext — UTF-8 plaintext (or hex string for key wrap)
     * @returns {{ ciphertext: string }} — C1||C3||C2 hex
     */
    async encryptFull(publicKeyHex, plaintext) {
      const invoke = getInvoke();
      return await invoke('sm2_encrypt_full', { publicKeyHex, plaintext });
    },

    /**
     * Decrypt a standard SM2 ciphertext (C1||C3||C2) with private key keyId.
     * @param {string} keyId — opaque handle
     * @param {string} ciphertext — C1||C3||C2 hex
     * @returns {{ plaintext: string }} — decrypted UTF-8
     */
    async decryptFull(keyId, ciphertext) {
      const invoke = getInvoke();
      return await invoke('sm2_decrypt_full', { keyId, ciphertext });
    },

    /**
     * Sign a raw message with standard SM2 (ZA digest derivation).
     * Matches frontend `SM2Browser.sign` default (hash=true, userId default).
     * @param {string} keyId — opaque handle
     * @param {string} message — raw message string
     * @returns {{ r: string, s: string }} — 64-char hex each
     */
    async signFull(keyId, message) {
      const invoke = getInvoke();
      return await invoke('sm2_sign_full', { keyId, message });
    },

    /**
     * Verify a standard SM2 signature against a raw message.
     * @param {string} publicKeyHex — uncompressed 04||x||y
     * @param {string} message — raw message string
     * @param {string} r — signature r (hex)
     * @param {string} s — signature s (hex)
     * @returns {{ valid: boolean }}
     */
    async verifyFull(publicKeyHex, message, r, s) {
      const invoke = getInvoke();
      return await invoke('sm2_verify_full', { publicKeyHex, message, r, s });
    }
  };

  // ── Detect & Replace ───────────────────────────────────────
  function detectAndReplace() {
    try {
      getInvoke();
      if (typeof window !== 'undefined') {
        window.MLKEM768 = TauriCryptoBridge;
        window.TauriCryptoBridge = TauriCryptoBridge;
        window.SM2 = SM2;
        console.log('[TauriCrypto] ✅ Tauri detected — ML-KEM + SM2 routed to Rust backend');
      }
    } catch (e) {
      console.log('[TauriCrypto] Not in Tauri — keeping WASM/pure-JS ML-KEM');
    }
  }

  if (typeof window !== 'undefined') {
    window.TauriCryptoBridge = TauriCryptoBridge;
    detectAndReplace();
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = TauriCryptoBridge;
  }

})();
