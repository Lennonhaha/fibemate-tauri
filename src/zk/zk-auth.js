/**
 * ZK Auth - Main Authentication Module
 * Combines Schnorr identity proof with Bulletproofs range proofs
 */

class ZKAuth {
  constructor() {
    this.schnorr = new SchnorrProverV2();
    this.bulletproofs = new Bulletproofs(32);
    this.initialized = false;
  }

  /**
   * Initialize ZK modules
   */
  async init() {
    await this.schnorr.init();
    await this.bulletproofs.init();
    this.initialized = true;
    console.log('[ZK-Auth] Initialized');
  }

  /**
   * Generate ZK login proof (v2: P-256 EC Schnorr)
   * @param {string} username - Username
   * @param {string} password - Password
   * @returns {Object} - ZK proof bundle
   */
  async generateLoginProof(username, password) {
    if (!this.initialized) await this.init();

    // Derive private key from password (scalar in [1, n-1])
    const privateKey = await this._derivePrivateKey(username, password);
    
    // Generate EC public key: P = priv * G (P-256 point)
    const publicKey = await this._derivePublicKey(privateKey);
    
    // Generate Schnorr proof on P-256 (EC-based, not modPow)
    const schnorrProof = await this.schnorr.prove(privateKey, publicKey);

    // Generate range proof for account age (example attribute)
    const accountAge = BigInt(Math.floor(Date.now() / 1000));
    const gamma = this.bulletproofs._randomScalar();
    const commitment = this.bulletproofs.commit(accountAge, gamma);
    const rangeProof = await this.bulletproofs.proveRange(accountAge, gamma);

    return {
      type: 'zk_login',
      username,
      schnorrProof: {
        R: {
          x: schnorrProof.R.x.toString(16),
          y: schnorrProof.R.y.toString(16)
        },
        s: schnorrProof.s.toString(16)
      },
      rangeProof: {
        commitment: commitment.toString(16),
        proof: rangeProof
      },
      publicKey: {
        x: publicKey.x.toString(16),
        y: publicKey.y.toString(16)
      },
      timestamp: Date.now()
    };
  }

  /**
   * Verify ZK login proof (v2: P-256 EC Schnorr)
   * @param {Object} proofBundle - ZK proof bundle
   * @returns {boolean}
   */
  async verifyLoginProof(proofBundle) {
    try {
      const { schnorrProof, publicKey } = proofBundle;

      // Accept publicKey as both {x, y} object or hex string (legacy)
      let pk;
      if (typeof publicKey === 'object' && publicKey.x) {
        pk = {
          x: BigInt('0x' + publicKey.x),
          y: BigInt('0x' + publicKey.y)
        };
      } else {
        // Legacy: single hex string → derive y from curve equation
        const pkStr = typeof publicKey === 'string' ? publicKey : String(publicKey);
        pk = this._recoverPoint(BigInt('0x' + pkStr));
      }

      const verifier = new SchnorrProverV2();
      await verifier.init();

      // Parse R.x / R.y from schnorrProof (or fallback to legacy t for R.x)
      const Rx = BigInt('0x' + (schnorrProof.R?.x || schnorrProof.t));
      const Ry = BigInt('0x' + (schnorrProof.R?.y || '0'));
      const s = BigInt('0x' + schnorrProof.s);

      return await verifier.verify({ R: { x: Rx, y: Ry }, s }, pk);
    } catch (err) {
      console.error('[ZK-Auth] Verification error:', err);
      return false;
    }
  }

  /**
   * Derive private key from credentials
   */
  async _derivePrivateKey(username, password) {
    const data = username + ':' + password;
    const encoder = new TextEncoder();
    
    if (typeof require !== 'undefined') {
      const crypto = require('crypto');
      const hash = crypto.createHash('sha256').update(data).digest('hex');
      return BigInt('0x' + hash) % this.schnorr.curve.n;
    }
    
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    const hashHex = Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    return BigInt('0x' + hashHex) % this.schnorr.curve.n;
  }

  /**
   * Derive EC public key from private key: P = priv * G (P-256 point)
   * @param {BigInt} privateKey
   * @returns {{x: BigInt, y: BigInt}}
   */
  async _derivePublicKey(privateKey) {
    return this.schnorr._scalarMult(privateKey, this.schnorr.curve.G);
  }

  /**
   * Recover P-256 curve point from x-coordinate (for legacy compatibility)
   * y² = x³ + ax + b (mod p) → y = sqrt_mod_p(x³ + ax + b)
   * @param {BigInt} x
   * @returns {{x: BigInt, y: BigInt}}
   */
  _recoverPoint(x) {
    const { p, a, b } = this.schnorr.curve;
    const rhs = ((((x * x) % p) * x) % p + ((a * x) % p) + b) % p;
    const y = this._sqrtModP(rhs, p);
    return { x, y };
  }

  /**
   * Modular square root: y² ≡ a (mod p), p ≡ 3 (mod 4) for P-256
   */
  _sqrtModP(a, p) {
    // P-256: p = 2²⁵⁶ - 2²²⁴ + 2¹⁹² + 2⁹⁶ - 1 ≡ 3 (mod 4)
    // Use: sqrt(a) = a^((p+1)/4) (mod p) when p ≡ 3 (mod 4)
    return this._modPow(a, (p + 1n) / 4n, p);
  }

  _modPow(base, exp, mod) {
    let result = 1n;
    let b = base % mod;
    let e = exp;
    
    while (e > 0n) {
      if (e & 1n) {
        result = (result * b) % mod;
      }
      b = (b * b) % mod;
      e >>= 1n;
    }
    
    return result;
  }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ZKAuth;
}
if (typeof window !== 'undefined') {
  window.ZKAuth = ZKAuth;
}
