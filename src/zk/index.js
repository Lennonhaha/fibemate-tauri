/**
 * ZK Module Index - Entry point for all ZK functionality
 */

const FIBEMATE_ZK_V2 = {
  version: '2.1.0',
  modules: {
    SchnorrProver,
    SchnorrProverV2, // Elliptic curve implementation (correct)
    SchnorrVerifier,
    Bulletproofs,
    ZKAuth,
    ZKIntegration
  },

  async init() {
    console.log('[FIBEMATE_ZK_V2] Initializing v' + this.version);
    const zk = new ZKAuth();
    await zk.init();
    return zk;
  },

  async generateLoginProof(username, password) {
    const zk = await this.init();
    return await zk.generateLoginProof(username, password);
  },

  async verifyLoginProof(proofBundle) {
    const zk = await this.init();
    return await zk.verifyLoginProof(proofBundle);
  },

  // New: Use correct EC-based Schnorr
  async generateProofEC(privateKey, publicKey) {
    const prover = new SchnorrProverV2();
    await prover.init();
    return await prover.prove(privateKey, publicKey);
  },

  async verifyProofEC(proof, publicKey) {
    const prover = new SchnorrProverV2();
    await prover.init();
    return await prover.verify(proof, publicKey);
  }
};

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = FIBEMATE_ZK_V2;
}
if (typeof window !== 'undefined') {
  window.FIBEMATE_ZK_V2 = FIBEMATE_ZK_V2;
}
