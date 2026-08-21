/**
 * FIBEMATE Post-Quantum Integration Module
 * 
 * Integrates ML-KEM-768 with Double Ratchet for hybrid post-quantum security.
 * 
 * Architecture:
 * - X3DH initialization uses Hybrid Key Exchange (ML-KEM + ECDH P-256)
 * - Double Ratchet chain keys derived from hybrid shared secret
 * - Provides both classical and post-quantum security
 * 
 * WASM Integration:
 * - Uses compiled Rust/WASM ML-KEM-768 when available (window.MLKEM768)
 * - Graceful fallback to classical X3DH if WASM not loaded
 * 
 * Security Levels:
 * - Classical: 128-bit (ECDH P-256)
 * - Post-Quantum: 192-bit (ML-KEM-768)
 * - Combined: 128-bit classical + post-quantum
 */

// ============================================================
// ML-KEM-768 Detection & Initialization
// ============================================================

let _mlkemModule = null;
let _initialized = false;

/**
 * Initialize ML-KEM-768 module
 * Supports both WASM (preferred) and JS fallback
 */
async function initMLKEM() {
  if (_initialized) return _mlkemModule;
  
  // Priority 1: WASM module from Rust (fastest)
  if (typeof window !== 'undefined' && window.MLKEM768 && window.MLKEM768.initialized) {
    _mlkemModule = window.MLKEM768;
    _initialized = true;
    console.log('[PQ] ML-KEM-768 WASM ready');
    return _mlkemModule;
  }
  
  // Priority 2: Check if WASM is loading
  if (typeof window !== 'undefined' && window.MLKEM768 && !window.MLKEM768.initialized) {
    console.log('[PQ] ML-KEM-768 WASM loading, waiting...');
    // Wait up to 5 seconds for initialization
    for (let i = 0; i < 50; i++) {
      await new Promise(r => setTimeout(r, 100));
      if (window.MLKEM768.initialized) {
        _mlkemModule = window.MLKEM768;
        _initialized = true;
        console.log('[PQ] ML-KEM-768 WASM ready after wait');
        return _mlkemModule;
      }
    }
    console.warn('[PQ] WASM initialization timeout');
  }
  
  console.warn('[PQ] ML-KEM-768 not available, will use classical X3DH');
  _initialized = true; // Mark as checked
  return null;
}

/**
 * Get ML-KEM-768 module (sync, may return null if not initialized)
 */
function getMLKEM() {
  if (_mlkemModule) return _mlkemModule;
  if (typeof window !== 'undefined' && window.MLKEM768 && window.MLKEM768.initialized) {
    _mlkemModule = window.MLKEM768;
    return _mlkemModule;
  }
  return null;
}

// ============================================================
// Hybrid Key Exchange Helpers
// ============================================================

/**
 * Generate hybrid pre-key bundle (ECDH + ML-KEM)
 * @returns {Promise<object>} - { kemKeypair, kemPublicKey }
 */
async function generateHybridKeys() {
  const mlkem = await initMLKEM();
  if (!mlkem) {
    throw new Error('ML-KEM-768 not available');
  }
  
  try {
    const keypair = mlkem.keygen();
    const kp = keypair instanceof Promise ? await keypair : keypair;
    
    return {
      kemKeypair: {
        publicKey: kp.publicKey,
        secretKey: kp.secretKey
      },
      kemPublicKey: kp.publicKey
    };
  } catch (err) {
    console.error('[PQ] Key generation failed:', err);
    throw err;
  }
}

/**
 * Encapsulate shared secret using ML-KEM-768
 * @param {Uint8Array} publicKey - Recipient's KEM public key
 * @returns {Promise<object>} - { ciphertext, shared_secret }
 */
async function encapsulateSecret(publicKey) {
  const mlkem = getMLKEM();
  if (!mlkem) throw new Error('ML-KEM-768 not available');
  
  try {
    const result = mlkem.encaps(publicKey);
    return result instanceof Promise ? await result : result;
  } catch (err) {
    console.error('[PQ] Encapsulation failed:', err);
    throw err;
  }
}

/**
 * Decapsulate shared secret using ML-KEM-768
 * @param {Uint8Array} secretKey - Recipient's KEM secret key
 * @param {Uint8Array} ciphertext - Encapsulated secret
 * @returns {Promise<Uint8Array>} - Shared secret
 */
async function decapsulateSecret(secretKey, ciphertext) {
  const mlkem = getMLKEM();
  if (!mlkem) throw new Error('ML-KEM-768 not available');
  
  try {
    const result = mlkem.decaps(secretKey, ciphertext);
    return result instanceof Promise ? await result : result;
  } catch (err) {
    console.error('[PQ] Decapsulation failed:', err);
    throw err;
  }
}

// ============================================================
// Integration with MessageCryptoV2
// ============================================================

/**
 * Wrap MessageCryptoV2 with PQ capabilities
 * This patches the existing crypto module to support hybrid X3DH
 */
function patchMessageCryptoV2() {
  if (typeof window === 'undefined' || !window.MessageCryptoV2) {
    console.warn('[PQ] MessageCryptoV2 not found, cannot patch');
    return false;
  }
  
  const crypto = window.MessageCryptoV2;
  
  // Store original functions
  const originalInitiate = crypto.initiateSession;
  const originalReceive = crypto.receiveSession;
  
  // Override with hybrid versions
  crypto.initiateSession = async function(peerId, bobBundle) {
    // If PQ is available and peer supports it, use hybrid
    const mlkem = getMLKEM();
    if (mlkem && bobBundle.kemPublicKey) {
      console.log('[PQ] Using hybrid X3DH (ECDH + ML-KEM-768)');
      return crypto.initiateHybridSession(peerId, bobBundle);
    }
    // Fall back to classical
    return originalInitiate.call(this, peerId, bobBundle);
  };
  
  crypto.receiveSession = async function(peerId, aliceInit) {
    // If PQ is indicated in init message, use hybrid receive
    if (aliceInit.hybrid || aliceInit.kemCiphertext) {
      console.log('[PQ] Using hybrid X3DH receive (ECDH + ML-KEM-768)');
      return crypto.receiveHybridSession(peerId, aliceInit);
    }
    // Fall back to classical
    return originalReceive.call(this, peerId, aliceInit);
  };
  
  console.log('[PQ] MessageCryptoV2 patched with hybrid X3DH support');
  return true;
}

// ============================================================
// Public API
// ============================================================

const PQIntegration = {
  // Initialization
  init: initMLKEM,
  
  // Key generation
  generateHybridKeys,
  
  // Encapsulation/Decapsulation
  encapsulate: encapsulateSecret,
  decapsulate: decapsulateSecret,
  
  // Integration
  patchMessageCryptoV2,
  
  // Status
  isAvailable() {
    return getMLKEM() !== null;
  },
  
  getStatus() {
    const mlkem = getMLKEM();
    return {
      available: mlkem !== null,
      initialized: _initialized,
      algorithm: 'ML-KEM-768 + ECDH P-256 Hybrid',
      classicalSecurity: '128-bit (ECDH P-256)',
      quantumSecurity: mlkem ? '192-bit (ML-KEM-768)' : 'not available',
      combinedSecurity: mlkem ? '128-bit classical + post-quantum' : 'classical only',
      wasmLoaded: typeof window !== 'undefined' && window.MLKEM768 !== undefined
    };
  },
  
  // Constants
  constants: {
    KEM_PUBLIC_KEY_SIZE: 1184,   // ML-KEM-768 public key
    KEM_SECRET_KEY_SIZE: 2400,   // ML-KEM-768 secret key
    KEM_CIPHERTEXT_SIZE: 1088,   // ML-KEM-768 ciphertext
    KEM_SHARED_SECRET_SIZE: 32   // Shared secret output
  }
};

// Auto-initialize on load
if (typeof window !== 'undefined') {
  window.PQIntegration = PQIntegration;
  
  // Try to initialize immediately
  initMLKEM().then(() => {
    if (PQIntegration.isAvailable()) {
      console.log('[PQ] Post-quantum cryptography ready');
      // Patch MessageCryptoV2 if available
      if (window.MessageCryptoV2) {
        patchMessageCryptoV2();
      }
    } else {
      console.log('[PQ] Post-quantum cryptography not available, using classical');
    }
  });
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = PQIntegration;
}
