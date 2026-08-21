/**
 * Schnorr Prover v2 - Correct Elliptic Curve Implementation
 * Uses P-256 elliptic curve point operations (not modular exponentiation)
 */

class SchnorrProverV2 {
  constructor() {
    this.initialized = false;
  }

  async init() {
    // P-256 curve parameters
    this.curve = {
      name: 'P-256',
      p: BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
      a: BigInt('0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc'),
      b: BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
      n: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'), // order
      G: {
        x: BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
        y: BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
      }
    };
    this.initialized = true;
  }

  /**
   * Generate Schnorr proof on P-256
   * @param {BigInt} privateKey - Private scalar
   * @param {Object} publicKey - Public key point {x, y}
   */
  async prove(privateKey, publicKey) {
    if (!this.initialized) await this.init();

    // Generate random nonce k ∈ [1, n-1]
    const k = this._randomScalar();

    // Compute R = k * G (elliptic curve point multiplication)
    const R = this._scalarMult(k, this.curve.G);

    // Challenge c = H(R.x || publicKey.x)
    const c = await this._hashChallenge(R.x, publicKey.x);

    // Response s = k + c * privateKey mod n
    const s = (k + c * privateKey) % this.curve.n;

    return { R, s };
  }

  /**
   * Verify Schnorr proof
   * @param {Object} proof - {R: {x,y}, s, c}
   * @param {Object} publicKey - {x, y}
   */
  async verify(proof, publicKey) {
    if (!this.initialized) await this.init();

    const { R, s } = proof;

    // Recompute challenge from R and publicKey (standard Schnorr)
    const c = await this._hashChallenge(R.x, publicKey.x);

    // Verify: s * G == R + c * publicKey
    const sG = this._scalarMult(s, this.curve.G);
    const cP = this._scalarMult(c, publicKey);
    const RHS = this._pointAdd(R, cP);

    return this._pointsEqual(sG, RHS);
  }

  // Elliptic curve point addition
  _pointAdd(P, Q) {
    if (!P) return Q;
    if (!Q) return P;

    const { p, a } = this.curve;
    const { x: x1, y: y1 } = P;
    const { x: x2, y: y2 } = Q;

    if (x1 === x2 && y1 === ((p - y2) % p)) {
      return null; // Point at infinity
    }

    let m;
    if (x1 === x2 && y1 === y2) {
      // Tangent (point doubling)
      const num = (3n * x1 * x1 + a) % p;
      const den = this._modInv(2n * y1 % p, p);
      m = (num * den) % p;
    } else {
      const num = ((y2 - y1) % p + p) % p;
      const den = this._modInv(((x2 - x1) % p + p) % p, p);
      m = (num * den) % p;
    }

    const x3 = ((m * m - x1 - x2) % p + p) % p;
    const y3 = ((m * (x1 - x3) - y1) % p + p) % p;

    return {
      x: x3,
      y: y3
    };
  }

  // Scalar multiplication: k * P using double-and-add
  // Reduces k modulo n first to avoid unnecessary iterations
  _scalarMult(k, P) {
    // Reduce scalar modulo curve order
    let scalar = k % this.curve.n;
    if (scalar === 0n) return null; // Point at infinity
    
    let result = null;
    let addend = P;

    while (scalar > 0n) {
      if (scalar & 1n) {
        result = this._pointAdd(result, addend);
      }
      addend = this._pointAdd(addend, addend);
      scalar >>= 1n;
    }

    return result;
  }

  // Modular inverse using extended Euclidean algorithm
  _modInv(a, m) {
    // Ensure a is positive and within range
    a = ((a % m) + m) % m;
    if (a === 0n) throw new Error('Modular inverse of 0');
    
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];

    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }

    // old_r should be 1 (gcd)
    if (old_r !== 1n) throw new Error('No modular inverse exists');
    
    return ((old_s % m) + m) % m;
  }

  // Hash challenge using SHA-256
  async _hashChallenge(Rx, Px) {
    const data = `${Rx.toString(16).padStart(64, '0')}${Px.toString(16).padStart(64, '0')}`;
    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    const hashHex = Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    return BigInt('0x' + hashHex) % this.curve.n;
  }

  // Random scalar in [1, n-1]
  _randomScalar() {
    const nBytes = (this.curve.n.toString(2).length + 7) >> 3;
    const buf = new Uint8Array(nBytes);
    let scalar;
    do {
      crypto.getRandomValues(buf);
      scalar = BigInt('0x' + Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join(''));
    } while (scalar >= this.curve.n || scalar === 0n);
    return scalar;
  }

  _pointsEqual(P, Q) {
    if (!P || !Q) return P === Q;
    return P.x === Q.x && P.y === Q.y;
  }
}

// Export
if (typeof module !== 'undefined') module.exports = SchnorrProverV2;
if (typeof window !== 'undefined') { window.SchnorrProverV2 = SchnorrProverV2; }
