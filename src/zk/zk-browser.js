/**
 * ZK Browser Compatibility Layer
 * Ensures ZK modules work in browser environments without Node.js crypto
 */

// Polyfill for Node.js crypto in browser
if (typeof window !== 'undefined' && !window.crypto) {
  console.warn('[ZK-Browser] Web Crypto API not available');
}

// Ensure BigInt support
if (typeof BigInt === 'undefined') {
  throw new Error('[ZK-Browser] BigInt not supported in this browser');
}

// Helper to detect environment
const ZKEnv = {
  isNode: typeof process !== 'undefined' && process.versions && process.versions.node,
  isBrowser: typeof window !== 'undefined',
  isElectron: typeof process !== 'undefined' && process.versions && process.versions.electron,
  
  getCrypto() {
    if (this.isNode) {
      return require('crypto');
    }
    return window.crypto || window.msCrypto;
  },
  
  async sha256(data) {
    const crypto = this.getCrypto();
    if (this.isNode) {
      const hash = crypto.createHash('sha256');
      hash.update(data);
      return hash.digest('hex');
    }
    const encoder = new TextEncoder();
    const buf = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },
  
  randomBytes(size) {
    const crypto = this.getCrypto();
    if (this.isNode) {
      return crypto.randomBytes(size);
    }
    const buf = new Uint8Array(size);
    crypto.getRandomValues(buf);
    return buf;
  }
};

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ZKEnv };
}
if (typeof window !== 'undefined') {
  window.ZKEnv = ZKEnv;
}
