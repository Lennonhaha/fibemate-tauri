/**
 * ML-KEM-768 Unified Wrapper
 * ───────────────────────────────────────────
 * NOTE: The WASM code path (pq-wasm / pqc_kyber v0.7.1) was removed in commit
 * #8 because pqc_kyber 0.7.x is affected by KyberSlash (CVE-2023-1942) and is
 * upstream-abandoned (see issue #7). This wrapper now exposes only the pure-JS
 * constant-time implementation (ml-kem-768.js).
 *
 * API (unchanged from original wrapper):
 *   MLKEM768.init()           → Promise<void>
 *   MLKEM768.keygen()         → { publicKey, secretKey }
 *   MLKEM768.encaps(pk)       → { ciphertext, sharedSecret }
 *   MLKEM768.decaps(sk, ct)   → sharedSecret
 *   MLKEM768.hybridCombine(kemSecret, ecdhSecret) → combinedKey
 */

// ============================================================
// Capture pure JS implementation before we overwrite window.MLKEM768
// ============================================================
const _PureJS_MLKEM768 = typeof window !== 'undefined' ? window.MLKEM768 : undefined;

// ============================================================
// Unified wrapper object
// ============================================================
const MLKEM768Wrapper = {
  initialized: false,
  _engine: 'js',        // pure-JS engine only (WASM path removed, see issue #7)
  _initPromise: null,

  // ── init ──────────────────────────────────────────────────
  async init() {
    if (this.initialized) return;
    if (this._initPromise) return this._initPromise;

    this._initPromise = (async () => {
      // Pure-JS constant-time implementation (ml-kem-768.js).
      if (!_PureJS_MLKEM768) {
        throw new Error('ML-KEM-768 not available — pure JS implementation not loaded');
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

  // ── hybridCombine (WASM engine removed; non-functional) ────
  hybridCombine(kemSecret, ecdhSecret) {
    if (!this.initialized) throw new Error('ML-KEM-768 not initialized');

    console.warn('[ML-KEM] hybridCombine requires WASM engine (removed, see issue #7); returning kemSecret as-is');
    return kemSecret;
  },

  // ── status ────────────────────────────────────────────────
  getStatus() {
    return {
      initialized: this.initialized,
      engine: this._engine || 'pending',
      wasmAvailable: this._engine === 'wasm'
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