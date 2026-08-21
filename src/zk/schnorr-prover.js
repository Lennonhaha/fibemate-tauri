/**
 * Schnorr Prover - Zero-Knowledge Proof of Knowledge
 * Proves knowledge of discrete log without revealing it
 */

class SchnorrProver {
  constructor(curve = 'P-256') {
    this.curve = curve;
    this.q = null; // Order of the group
  }

  /**
   * Initialize with curve parameters
   */
  async init() {
    // P-256 curve order
    this.q = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    return this;
  }

  /**
   * Generate a Schnorr proof
   * @param {BigInt} x - Private key (discrete log)
   * @param {Object} params - {g: generator, p: modulus, y: public key = g^x mod p}
   * @returns {Object} - {t: commitment, s: response, c: challenge}
   */
  async prove(x, params) {
    const { g, p, y } = params;
    
    // Generate random nonce r
    const r = this._randomScalar();
    
    // Compute commitment t = g^r mod p
    const t = this._modPow(g, r, p);
    
    // Generate challenge c = H(g, y, t) using Fiat-Shamir
    const c = await this._hashChallenge(g, y, t);
    
    // Compute response s = r + c * x mod q
    const s = (r + c * x) % this.q;
    
    return { t, s, c };
  }

  /**
   * Verify a Schnorr proof
   * @param {Object} proof - {t, s, c}
   * @param {Object} params - {g, p, y}
   * @returns {boolean}
   */
  async verify(proof, params) {
    const { t, s, c } = proof;
    const { g, p, y } = params;
    
    // Recompute challenge
    const cPrime = await this._hashChallenge(g, y, t);
    
    // Check c == c'
    if (c !== cPrime) return false;
    
    // Verify g^s == t * y^c mod p
    const lhs = this._modPow(g, s, p);
    const rhs = (t * this._modPow(y, c, p)) % p;
    
    return lhs === rhs;
  }

  /**
   * Hash function for Fiat-Shamir transform
   */
  async _hashChallenge(g, y, t) {
    const data = `${g.toString(16)}${y.toString(16)}${t.toString(16)}`;
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

  /**
   * Generate random scalar in [1, q-1]
   */
  _randomScalar() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    const hex = Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    return BigInt('0x' + hex) % (this.q - BigInt(1)) + BigInt(1);
  }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SchnorrProver;
}
if (typeof window !== 'undefined') {
  window.SchnorrProver = SchnorrProver;
}
