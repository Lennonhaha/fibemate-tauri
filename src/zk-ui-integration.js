/**
 * ZK UI Integration - Connects ZK authentication with UI flow
 * Features: State management, progress visualization, graceful fallback
 */

class ZKUIIntegration {
  constructor() {
    this.state = {
      isZKMode: false,
      isProcessing: false,
      lastError: null,
      fallbackUsed: false,
      zkEnabled: true // Can be disabled if browser doesn't support required APIs
    };
    
    // Check browser support
    this._checkBrowserSupport();
  }

  /**
   * Check if browser supports required crypto APIs
   */
  _checkBrowserSupport() {
    try {
      if (!window.crypto || !window.crypto.subtle) {
        console.warn('[ZK-UI] Web Crypto API not available, disabling ZK mode');
        this.state.zkEnabled = false;
        this.state.isZKMode = false;
        return;
      }
      
      // Check BigInt support (required for EC operations)
      if (typeof BigInt === 'undefined') {
        console.warn('[ZK-UI] BigInt not available, disabling ZK mode');
        this.state.zkEnabled = false;
        this.state.isZKMode = false;
        return;
      }
      
      console.log('[ZK-UI] Browser support check passed');
    } catch (e) {
      console.error('[ZK-UI] Browser support check failed:', e);
      this.state.zkEnabled = false;
    }
  }

  /**
   * Initialize ZK UI integration
   * Loads user preference from localStorage
   */
  async init() {
    // Load ZK mode preference
    const savedMode = localStorage.getItem('fibemate_zk_mode');
    if (savedMode !== null) {
      this.state.isZKMode = savedMode === 'true' && this.state.zkEnabled;
    }
    
    // Update UI toggle to match saved state
    this._updateUIToggle();
    
    console.log('[ZK-UI] Initialized, ZK mode:', this.state.isZKMode);
  }

  /**
   * Toggle ZK mode on/off
   */
  toggleZKMode(enabled) {
    if (!this.state.zkEnabled && enabled) {
      console.warn('[ZK-UI] Cannot enable ZK mode - browser not supported');
      return false;
    }
    
    this.state.isZKMode = enabled;
    localStorage.setItem('fibemate_zk_mode', enabled ? 'true' : 'false');
    this._updateUIToggle();
    
    console.log('[ZK-UI] ZK mode toggled:', enabled);
    return true;
  }

  /**
   * Update UI toggle switch to match current state
   */
  _updateUIToggle() {
    const toggle = document.querySelector('[data-setting="zkMode"]');
    if (toggle) {
      toggle.checked = this.state.isZKMode;
    }
  }

  /**
   * Perform login with ZK or standard fallback
   * @param {string} username - Username
   * @param {string} password - Password
   * @param {Object} options - Login options
   * @returns {Promise<Object>} Login result
   */
  async login(username, password, options = {}) {
    const { 
      onProgress = () => {},
      onZKStep = () => {},
      forceStandard = false 
    } = options;

    // If ZK mode is off or forced standard, use standard login
    if (!this.state.isZKMode || forceStandard || !this.state.zkEnabled) {
      console.log('[ZK-UI] Using standard login (ZK mode off or forced)');
      return this._standardLogin(username, password);
    }

    // Attempt ZK login
    this.state.isProcessing = true;
    this.state.fallbackUsed = false;
    
    try {
      onProgress('init', 'Initializing ZK authentication...');
      
      // Step 1: Generate ZK proof
      onZKStep(1, 'Generating EC keypair...');
      const startTime = performance.now();
      
      // Use the new EC-based ZK v2
      let proof;
      try {
        proof = await this._generateZKProofV2(username, password);
      } catch (zkError) {
        console.warn('[ZK-UI] ZK v2 failed, trying v1 fallback:', zkError.message);
        onZKStep(1, 'Falling back to ZK v1...');
        proof = await this._generateZKProofV1(username, password);
      }
      
      onZKStep(2, 'Computing Pedersen commitment...');
      onZKStep(3, 'Generating Schnorr proof...');
      
      // Step 2: Send proof to server
      onZKStep(4, 'Verifying with server...');
      const result = await this._verifyZKProofWithServer(proof, username);
      
      const duration = (performance.now() - startTime).toFixed(1);
      console.log(`[ZK-UI] ZK login completed in ${duration}ms`);
      
      this.state.isProcessing = false;
      return {
        success: true,
        token: result.token,
        userId: result.userId,
        displayName: result.displayName || username,
        zkUsed: true,
        duration: `${duration}ms`
      };
      
    } catch (error) {
      console.error('[ZK-UI] ZK login failed:', error);
      this.state.lastError = error.message;
      
      // Graceful fallback to standard login
      if (!options.noFallback) {
        console.log('[ZK-UI] Falling back to standard login');
        this.state.fallbackUsed = true;
        onProgress('fallback', 'ZK failed, using standard login...');
        
        try {
          const result = await this._standardLogin(username, password);
          result.zkUsed = false;
          result.fallbackUsed = true;
          result.zkError = error.message;
          this.state.isProcessing = false;
          return result;
        } catch (standardError) {
          this.state.isProcessing = false;
          throw new Error(`Both ZK and standard login failed: ${standardError.message}`);
        }
      }
      
      this.state.isProcessing = false;
      throw error;
    }
  }

  /**
   * Generate ZK proof using v2 (correct EC implementation)
   */
  async _generateZKProofV2(username, password) {
    if (typeof SchnorrProverV2 === 'undefined') {
      throw new Error('SchnorrProverV2 not loaded');
    }
    
    // Derive deterministic private key from username+password
    const privateKey = await this._derivePrivateKey(username, password);
    
    // Generate public key
    const prover = new SchnorrProverV2();
    await prover.init();
    const publicKey = prover._scalarMult(privateKey, prover.curve.G);
    
    // Generate Schnorr proof
    const proof = await prover.prove(privateKey, publicKey);
    
    return {
      type: 'schnorr_v2',
      username,
      publicKey: {
        x: publicKey.x.toString(16).padStart(64, '0'),
        y: publicKey.y.toString(16).padStart(64, '0')
      },
      proof: {
        R: {
          x: proof.R.x.toString(16).padStart(64, '0'),
          y: proof.R.y.toString(16).padStart(64, '0')
        },
        s: proof.s.toString(16).padStart(64, '0')
      },
      timestamp: Date.now()
    };
  }

  /**
   * Generate ZK proof using v1 (legacy, for fallback)
   */
  async _generateZKProofV1(username, password) {
    if (typeof FIBEMATE_ZK === 'undefined') {
      throw new Error('FIBEMATE_ZK not loaded');
    }
    
    // Use existing ZK auth
    const zkAuth = new ZKAuth();
    await zkAuth.init();
    const proof = await zkAuth.generateLoginProof(username, password);
    
    return {
      type: 'zk_v1',
      ...proof
    };
  }

  /**
   * Derive deterministic private key from credentials
   */
  async _derivePrivateKey(username, password) {
    const data = new TextEncoder().encode(username + ':' + password + ':fibemate-zk-salt');
    const hash = await crypto.subtle.digest('SHA-256', data);
    const hashHex = Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    
    // Convert to BigInt and ensure it's in valid range for P-256
    const scalar = BigInt('0x' + hashHex);
    
    // P-256 curve order
    const n = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    
    return scalar % (n - 1n) + 1n; // Ensure in [1, n-1]
  }

  /**
   * Verify ZK proof with server
   */
  async _verifyZKProofWithServer(proof, username) {
    const apiUrl = localStorage.getItem('fk_api_url') || (typeof API_BASE !== 'undefined' ? API_BASE : 'https://fibemate.net/api');
    
    const res = await fetch(`${apiUrl}/auth/zk-login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        proofType: proof.type,
        publicKey: proof.publicKey,
        proof: proof.proof,
        timestamp: proof.timestamp
      })
    });
    
    const data = await res.json();
    
    if (!data.success) {
      throw new Error(data.message || 'ZK verification failed');
    }
    
    return data;
  }

  /**
   * Standard password login (fallback)
   */
  async _standardLogin(username, password) {
    // Use existing FIBEMATE_ZK.doLogin or direct API call
    if (typeof FIBEMATE_ZK !== 'undefined' && FIBEMATE_ZK.doLogin) {
      return await FIBEMATE_ZK.doLogin(username, password);
    }
    
    // Direct API fallback
    const apiUrl = localStorage.getItem('fk_api_url') || (typeof API_BASE !== 'undefined' ? API_BASE : 'https://fibemate.net/api');
    const res = await fetch(`${apiUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    
    const data = await res.json();
    
    if (!data.success && !data.token) {
      throw new Error(data.message || 'Login failed');
    }
    
    return {
      success: true,
      token: data.token,
      userId: data.userId,
      displayName: data.displayName || username
    };
  }

  /**
   * Get current ZK state
   */
  getState() {
    return { ...this.state };
  }

  /**
   * Check if ZK login was used for last authentication
   */
  wasZKUsed() {
    return this.state.isZKMode && !this.state.fallbackUsed;
  }

  /**
   * Reset state (e.g., on logout)
   */
  reset() {
    this.state.isProcessing = false;
    this.state.lastError = null;
    this.state.fallbackUsed = false;
  }
}

// Global instance
let zkUIIntegration = null;

function getZKUIIntegration() {
  if (!zkUIIntegration) {
    zkUIIntegration = new ZKUIIntegration();
  }
  return zkUIIntegration;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ZKUIIntegration, getZKUIIntegration };
}
if (typeof window !== 'undefined') {
  window.ZKUIIntegration = ZKUIIntegration;
  window.getZKUIIntegration = getZKUIIntegration;
}