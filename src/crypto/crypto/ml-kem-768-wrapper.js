/**
 * ML-KEM-768 Unified Wrapper
 * ───────────────────────────────────────────
 * Primary:  WASM (pqc_kyber v0.7.1) — ~200× faster, FIPS 203 compliant
 * Fallback: Pure JS time-domain — reference implementation
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
// WASM loader — dynamic import + initSync (avoids file:// fetch issue)
// ============================================================
async function _loadWasmEngine() {
  try {
    // Dynamic import of wasm-bindgen glue code
    const wasmModule = await import('./pq-wasm-pkg/fibemate_pq_wasm.js');

    // Fetch WASM binary
    const resp = await fetch('./pq-wasm-pkg/fibemate_pq_wasm_bg.wasm');
    if (!resp.ok) throw new Error(`WASM fetch: HTTP ${resp.status}`);

    const bytes = await resp.arrayBuffer();
    wasmModule.initSync({ module: bytes });

    return wasmModule;
  } catch (e) {
    throw e; // caller handles fallback
  }
}

// ============================================================
// Unified wrapper object
// ============================================================
const MLKEM768Wrapper = {
  initialized: false,
  _engine: null,       // 'wasm' | 'js'
  _wasm: null,         // wasm-bindgen module reference
  _initPromise: null,

  // ── init ──────────────────────────────────────────────────
  async init() {
    if (this.initialized) return;
    if (this._initPromise) return this._initPromise;

    this._initPromise = (async () => {
      // --- Stage 1: try WASM ---
      try {
        this._wasm = await _loadWasmEngine();
        this._engine = 'wasm';
        this.initialized = true;
        console.log('[ML-KEM] ✅ WASM loaded (pqc_kyber v0.7.1, ~200× faster)');
        return;
      } catch (e) {
        console.warn('[ML-KEM] WASM not available:', e.message);
      }

      // --- Stage 2: fall back to pure JS ---
      if (!_PureJS_MLKEM768) {
        throw new Error('ML-KEM-768 not available — neither WASM nor pure JS loaded');
      }

      this._engine = 'js';
      this.initialized = true;
      console.log('[ML-KEM] Using pure JS fallback');
    })();

    return this._initPromise;
  },

  // ── keygen ────────────────────────────────────────────────
  keygen() {
    if (!this.initialized) throw new Error('ML-KEM-768 not initialized');

    if (this._engine === 'wasm') {
      const kp = this._wasm.generateKeypair();
      return {
        publicKey: kp.public_key,
        secretKey: kp.secret_key
      };
    }

    // Pure JS fallback
    return _PureJS_MLKEM768.generateKeypair();
  },

  // ── encaps ────────────────────────────────────────────────
  encaps(publicKey) {
    if (!this.initialized) throw new Error('ML-KEM-768 not initialized');

    if (this._engine === 'wasm') {
      const result = this._wasm.encapsulate(publicKey);
      return {
        ciphertext: result.ciphertext,
        sharedSecret: result.shared_secret
      };
    }

    // Pure JS fallback
    const result = _PureJS_MLKEM768.encapsulate(publicKey);
    return {
      ciphertext: result.ciphertext,
      sharedSecret: result.sharedSecret
    };
  },

  // ── decaps ────────────────────────────────────────────────
  decaps(secretKey, ciphertext) {
    if (!this.initialized) throw new Error('ML-KEM-768 not initialized');

    if (this._engine === 'wasm') {
      return this._wasm.decapsulate(secretKey, ciphertext);
    }

    // Pure JS fallback
    return _PureJS_MLKEM768.decapsulate(secretKey, ciphertext);
  },

  // ── hybridCombine (WASM only) ─────────────────────────────
  hybridCombine(kemSecret, ecdhSecret) {
    if (!this.initialized) throw new Error('ML-KEM-768 not initialized');

    if (this._engine === 'wasm' && this._wasm.hybridCombine) {
      return this._wasm.hybridCombine(kemSecret, ecdhSecret);
    }

    console.warn('[ML-KEM] hybridCombine requires WASM engine; returning kemSecret as-is');
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