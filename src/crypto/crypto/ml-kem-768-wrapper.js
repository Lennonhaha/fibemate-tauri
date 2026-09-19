/**
 * ML-KEM-768 Unified Wrapper
 * ───────────────────────────────────────────
 * Implementation: Pure JS time-domain reference implementation
 *                  (NTT-free Kyber, defined in ml-kem-768.js as window.MLKEM768).
 *
 * NOTE: The experimental WASM engine (pqc_kyber v0.7.1, KyberSlash-affected,
 * abandoned upstream) was removed. The production desktop path uses the Rust
 * `rustpq::ml_kem::mlkem768` backend via tauri-crypto-bridge and does NOT
 * depend on this wrapper. This wrapper remains only as a non-Tauri JS fallback
 * for the dev/test pages.
 *
 * API:
 *   MLKEM768.init()           → Promise<void>
 *   MLKEM768.keygen()         → { publicKey, secretKey }
 *   MLKEM768.encaps(pk)       → { ciphertext, sharedSecret }
 *   MLKEM768.decaps(sk, ct)   → sharedSecret
 *   MLKEM768.hybridCombine(kemSecret, ecdhSecret) → combinedKey
 */

// ============================================================
// Capture pure JS implementation (defined by ml-kem-768.js as window.MLKEM768)
// ============================================================
const _PureJS_MLKEM768 = typeof window !== 'undefined' ? window.MLKEM768 : undefined;

// ============================================================
// Unified wrapper object — pure JS only
// ============================================================
const MLKEM768Wrapper = {
  initialized: false,
  _engine: null,       // 'js'
  _wasm: null,         // (unused — WASM engine removed)
  _initPromise: null,

  // ── init ──────────────────────────────────────────────────
  async init() {
    if (this.initialized) return;
    if (this._initPromise) return this._initPromise;

    this._initPromise = (async () => {
      if (!_PureJS_MLKEM768) {
        throw new Error('ML-KEM-768 not available — pure JS implementation (ml-kem-768.js) not loaded');
      }

      this._engine = 'js';
      this.initialized = true;
      console.log('[ML-KEM] Using pure JS implementation');
    })();

    return this._initPromise;
  },

  // ── keygen ────────────────────────────────────────────────
  keygen() {
    if (!this.initialized) throw new Error('ML-KEM-768 not initialized');

    return _PureJS_MLKEM768.generateKeypair();
  },

  // ── encaps ────────────────────────────────────────────────
  encaps(publicKey) {
    if (!this.initialized) throw new Error('ML-KEM-768 not initialized');

    const result = _PureJS_MLKEM768.encapsulate(publicKey);
    return {
      ciphertext: result.ciphertext,
      sharedSecret: result.sharedSecret
    };
  },

  // ── decaps ────────────────────────────────────────────────
  decaps(secretKey, ciphertext) {
    if (!this.initialized) throw new Error('ML-KEM-768 not initialized');

    return _PureJS_MLKEM768.decapsulate(secretKey, ciphertext);
  },

  // ── hybridCombine (WASM only) ─────────────────────────────
  hybridCombine(kemSecret, ecdhSecret) {
    if (!this.initialized) throw new Error('ML-KEM-768 not initialized');

    console.warn('[ML-KEM] hybridCombine is a no-op on the pure-JS path; returning kemSecret as-is');
    return kemSecret;
  },

  // ── status ────────────────────────────────────────────────
  getStatus() {
    return {
      initialized: this.initialized,
      engine: this._engine || 'js',
      wasmAvailable: false,  // WASM engine removed
    };
  }
};

// ============================================================
// Export to global scope
// ============================================================
if (typeof window !== 'undefined') {
  window.MLKEM768 = MLKEM768Wrapper;

  // Also expose the pure JS interface under a different name for debugging
  if (_PureJS_MLKEM768) {
    window.MLKEM768_JS = _PureJS_MLKEM768;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = MLKEM768Wrapper;
}

// ============================================================
// Auto-init on load
// ============================================================
MLKEM768Wrapper.init().catch(err => {
  console.warn('[ML-KEM] Auto-init failed:', err.message);
});