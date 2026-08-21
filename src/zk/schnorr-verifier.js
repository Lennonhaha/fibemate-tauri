/**
 * Schnorr Verifier - Server-side verification
 */

class SchnorrVerifier {
  constructor() {
    this.q = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  }

  /**
   * Verify a Schnorr proof
   * @param {Object} proof - {t: commitment (hex), s: response (hex), c: challenge (hex)}
   * @param {Object} publicParams - {g: generator (hex), p: modulus (hex), y: public key (hex)}
   * @returns {boolean}
   */
  async verify(proof, publicParams) {
    try {
      const { t, s, c } = proof;
      const { g, p, y } = publicParams;
      
      // Convert hex to BigInt
      const tBig = BigInt('0x' + t);
      const sBig = BigInt('0x' + s);
      const cBig = BigInt('0x' + c);
      const gBig = BigInt('0x' + g);
      const pBig = BigInt('0x' + p);
      const yBig = BigInt('0x' + y);
      
      // Recompute challenge
      const cPrime = await this._hashChallenge(gBig, yBig, tBig);
      
      // Check c == c'
      if (cBig !== cPrime) {
        console.log('[Schnorr] Challenge mismatch');
        return false;
      }
      
      // Verify g^s == t * y^c mod p
      const lhs = this._modPow(gBig, sBig, pBig);
      const rhs = (tBig * this._modPow(yBig, cBig, pBig)) % pBig;
      
      const valid = lhs === rhs;
      console.log('[Schnorr] Verification:', valid ? 'PASSED' : 'FAILED');
      return valid;
    } catch (err) {
      console.error('[Schnorr] Verification error:', err);
      return false;
    }
  }

  /**
   * Hash function for Fiat-Shamir
   */
  async _hashChallenge(g, y, t) {
    const data = `${g.toString(16)}${y.toString(16)}${t.toString(16)}`;
    
    // Node.js crypto
    if (typeof require !== 'undefined') {
      const crypto = require('crypto');
      const hash = crypto.createHash('sha256').update(data).digest('hex');
      return BigInt('0x' + hash) % this.q;
    }
    
    // Browser crypto
    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    const hashHex = Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    return BigInt('0x' + hashHex) % this.q;
  }

  /**
   * Modular exponentiation
   */
  _modPow(base, exp, mod) {
    let result = BigInt(1);
    let b = base % mod;
    let e = exp;
    
    while (e > 0) {
      if (e & BigInt(1)) {
        result = (result * b) % mod;
      }
      b = (b * b) % mod;
      e >>= BigInt(1);
    }
    
    return result;
  }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SchnorrVerifier;
}
if (typeof window !== 'undefined') {
  window.SchnorrVerifier = SchnorrVerifier;
}
