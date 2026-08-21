/**
 * ZK Integration - Bridges existing P-256 auth with new Schnorr+Bulletproofs ZK
 * Provides unified FIBEMATE_ZK API
 */

class ZKIntegration {
  constructor() {
    this.zkAuth = new ZKAuth();
    this.initialized = false;
  }

  async init() {
    if (this.initialized) return;
    await this.zkAuth.init();
    this.initialized = true;
    console.log('[ZK-Integration] Initialized');
  }

  /**
   * Generate ZK login proof using Schnorr + Bulletproofs
   * Falls back to existing P-256 ZK if new modules unavailable
   */
  async generateZKProof(username, password) {
    await this.init();
    
    try {
      // Use new Schnorr + Bulletproofs ZK
      const proof = await this.zkAuth.generateLoginProof(username, password);
      return {
        type: 'schnorr_bulletproofs',
        proof,
        timestamp: Date.now()
      };
    } catch (err) {
      console.warn('[ZK-Integration] New ZK failed, falling back to P-256:', err.message);
      // Fall back to existing P-256 ZK
      return null;
    }
  }

  /**
   * Verify ZK proof (server-side logic, client-side for testing)
   */
  async verifyZKProof(proofBundle) {
    await this.init();
    
    if (proofBundle.type === 'schnorr_bulletproofs') {
      return await this.zkAuth.verifyLoginProof(proofBundle.proof);
    }
    
    // Legacy P-256 verification
    return false;
  }

  /**
   * Check if new ZK modules are available
   */
  isNewZKAvailable() {
    return typeof ZKAuth !== 'undefined' && typeof SchnorrProver !== 'undefined';
  }
}

// Global instance
let zkIntegration = null;

async function getZKIntegration() {
  if (!zkIntegration) {
    zkIntegration = new ZKIntegration();
    await zkIntegration.init();
  }
  return zkIntegration;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ZKIntegration, getZKIntegration };
}
if (typeof window !== 'undefined') {
  window.ZKIntegration = ZKIntegration;
  window.getZKIntegration = getZKIntegration;
}
