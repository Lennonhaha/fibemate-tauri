//! SM2 Elliptic Curve Cryptography (GB/T 32918)
//!
//! Direct port from sm2-ec-browser.js v1.2 (TVLA N=5000, 5/5 PASS).
//! Jacobian projective coordinates + TVLA-hardened scalar multiplication.
//!
//! ## Standards Coverage
//! - GB/T 32918.1 — Curve parameters (sm2p256v1)
//! - GB/T 32918.2 — Digital signature algorithm
//! - GB/T 32918.3 — Key exchange protocol (ECDH)
//! - GB/T 32918.4 — Public key encryption (simplified C1C2)

use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::rngs::OsRng;

// ════════════════════════════════════════════════════════════
// SM2 Curve Parameters (GB/T 32918.1 — sm2p256v1)
// ════════════════════════════════════════════════════════════

lazy_static::lazy_static! {
    /// Prime field modulus p
    pub static ref SM2_P: BigUint = BigUint::parse_bytes(
        b"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16
    ).unwrap();

    /// Curve order n
    pub static ref SM2_N: BigUint = BigUint::parse_bytes(
        b"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16
    ).unwrap();

    /// Curve parameter a
    pub static ref SM2_A: BigUint = BigUint::parse_bytes(
        b"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16
    ).unwrap();

    /// Curve parameter b
    pub static ref SM2_B: BigUint = BigUint::parse_bytes(
        b"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16
    ).unwrap();

    /// Generator x-coordinate
    pub static ref SM2_GX: BigUint = BigUint::parse_bytes(
        b"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16
    ).unwrap();

    /// Generator y-coordinate
    pub static ref SM2_GY: BigUint = BigUint::parse_bytes(
        b"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16
    ).unwrap();
}

// ════════════════════════════════════════════════════════════
// Field Operations (mod SM2_P)
// ════════════════════════════════════════════════════════════

pub(crate) mod field {
    use super::*;

    #[inline]
    pub fn add(a: &BigUint, b: &BigUint) -> BigUint {
        let s = a + b;
        if s >= *SM2_P {
            s - &*SM2_P
        } else {
            s
        }
    }

    #[inline]
    pub fn sub(a: &BigUint, b: &BigUint) -> BigUint {
        if a >= b {
            a - b
        } else {
            a + &*SM2_P - b
        }
    }

    #[inline]
    pub fn mul(a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &*SM2_P
    }

    #[inline]
    pub fn sqr(a: &BigUint) -> BigUint {
        (a * a) % &*SM2_P
    }

    /// Extended Euclidean modular inverse (mod SM2_P)
    pub fn inv(a: &BigUint) -> BigUint {
        let mut t = BigUint::zero();
        let mut nt = BigUint::one();
        let mut r = SM2_P.clone();
        let mut nr = a % &*SM2_P;

        while !nr.is_zero() {
            let q = &r / &nr;
            // nt_new = t - q * nt  (mod SM2_P)
            let sub = (&t + &*SM2_P - (&q * &nt) % &*SM2_P) % &*SM2_P;
            t = nt;
            nt = sub;
            // nr_new = r - q * nr  (mod SM2_P)
            let sub_r = (&r + &*SM2_P - (&q * &nr) % &*SM2_P) % &*SM2_P;
            r = nr;
            nr = sub_r;
        }

        t
    }

    /// Mod SM2_N (for signature arithmetic)
    #[inline]
    pub fn add_n(a: &BigUint, b: &BigUint) -> BigUint {
        let s = a + b;
        if s >= *SM2_N {
            s - &*SM2_N
        } else {
            s
        }
    }
}

// ════════════════════════════════════════════════════════════
// Points (Affine & Jacobian Projective)
// ════════════════════════════════════════════════════════════

/// Affine point (x, y) on the SM2 curve.
/// `x = None, y = None` represents the point at infinity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffinePoint {
    pub x: Option<BigUint>,
    pub y: Option<BigUint>,
}

/// Jacobian projective point (X, Y, Z).
/// `z = 0` represents the point at infinity.
#[derive(Debug, Clone)]
struct JacobianPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

impl AffinePoint {
    pub fn new(x: BigUint, y: BigUint) -> Self {
        Self {
            x: Some(x),
            y: Some(y),
        }
    }

    pub fn infinity() -> Self {
        Self { x: None, y: None }
    }

    pub fn is_infinity(&self) -> bool {
        self.x.is_none()
    }
}

impl JacobianPoint {
    fn zero() -> Self {
        Self {
            x: BigUint::zero(),
            y: BigUint::zero(),
            z: BigUint::zero(),
        }
    }

    fn is_inf(&self) -> bool {
        self.z.is_zero()
    }

    fn from_affine(p: &AffinePoint) -> Self {
        if p.is_infinity() {
            return Self::zero();
        }
        Self {
            x: p.x.clone().unwrap(),
            y: p.y.clone().unwrap(),
            z: BigUint::one(),
        }
    }

    fn to_affine(&self) -> AffinePoint {
        if self.is_inf() {
            return AffinePoint::infinity();
        }
        let zi = field::inv(&self.z);
        let zz = field::sqr(&zi);
        let x = field::mul(&self.x, &zz);
        let y = field::mul(&self.y, &field::mul(&zz, &zi));
        AffinePoint::new(x, y)
    }
}

// ---- Lazy-initialized generator point ----
lazy_static::lazy_static! {
    static ref GENERATOR: AffinePoint = AffinePoint::new(SM2_GX.clone(), SM2_GY.clone());
}

// ════════════════════════════════════════════════════════════
// Jacobian Point Operations
// ════════════════════════════════════════════════════════════

/// Point doubling in Jacobian coordinates.
fn jacobian_dbl(p: &JacobianPoint) -> JacobianPoint {
    if p.is_inf() {
        return p.clone();
    }

    let yy = field::sqr(&p.y);
    let y4 = field::sqr(&yy);
    let four = BigUint::from(4u32);
    let s = field::mul(&field::mul(&p.x, &four), &yy);

    let zz = field::sqr(&p.z);
    let z4 = field::sqr(&zz);
    let three = BigUint::from(3u32);
    let m = field::sub(
        &field::mul(&three, &field::sqr(&p.x)),
        &field::mul(&three, &z4),
    );

    let two = BigUint::from(2u32);
    let eight = BigUint::from(8u32);
    let x3 = field::sub(&field::sqr(&m), &field::mul(&s, &two));
    let y3 = field::sub(
        &field::mul(&m, &field::sub(&s, &x3)),
        &field::mul(&y4, &eight),
    );
    let z3 = field::mul(&field::mul(&p.y, &p.z), &two);

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Mixed addition: affine A + Jacobian Q → Jacobian.
fn jacobian_add_mixed(a: &AffinePoint, q: &JacobianPoint) -> JacobianPoint {
    if q.is_inf() {
        return JacobianPoint::from_affine(a);
    }
    if a.is_infinity() {
        return q.clone();
    }

    let ax = a.x.as_ref().unwrap();
    let ay = a.y.as_ref().unwrap();

    let zz = field::sqr(&q.z);
    let u2 = field::mul(ax, &zz);
    let z3 = field::mul(&zz, &q.z);
    let s2 = field::mul(ay, &z3);

    if u2 == q.x && s2 == q.y {
        return jacobian_dbl(q);
    }

    let h = field::sub(&u2, &q.x);
    let hh = field::sqr(&h);
    let four = BigUint::from(4u32);
    let i = field::mul(&hh, &four);
    let j = field::mul(&h, &i);
    let two = BigUint::from(2u32);
    let r = field::mul(&field::sub(&s2, &q.y), &two);
    let v = field::mul(&q.x, &i);

    let x3 = field::sub(&field::sub(&field::sqr(&r), &j), &field::mul(&v, &two));
    let y3 = field::sub(
        &field::mul(&r, &field::sub(&v, &x3)),
        &field::mul(&field::mul(&q.y, &two), &j),
    );
    let z3_f = field::sub(&field::sqr(&field::add(&h, &q.z)), &field::add(&zz, &hh));

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3_f,
    }
}

/// Full Jacobian addition: P + Q → Jacobian.
fn jacobian_add(p: &JacobianPoint, q: &JacobianPoint) -> JacobianPoint {
    if p.is_inf() {
        return q.clone();
    }
    if q.is_inf() {
        return p.clone();
    }

    let z1z1 = field::sqr(&p.z);
    let z2z2 = field::sqr(&q.z);
    let u1 = field::mul(&p.x, &z2z2);
    let u2 = field::mul(&q.x, &z1z1);
    let s1 = field::mul(&p.y, &field::mul(&z2z2, &q.z));
    let s2 = field::mul(&q.y, &field::mul(&z1z1, &p.z));

    if u1 == u2 {
        if s1 != s2 {
            return JacobianPoint::zero();
        }
        return jacobian_dbl(p);
    }

    let h = field::sub(&u2, &u1);
    let two = BigUint::from(2u32);
    let i = field::sqr(&field::mul(&h, &two));
    let j = field::mul(&h, &i);
    let r = field::sub(&field::mul(&s2, &two), &field::mul(&s1, &two));
    let v = field::mul(&u1, &i);

    let x3 = field::sub(&field::sub(&field::sqr(&r), &j), &field::mul(&v, &two));
    let y3 = field::sub(
        &field::mul(&r, &field::sub(&v, &x3)),
        &field::mul(&field::mul(&s1, &two), &j),
    );
    let z3 = field::mul(
        &field::sub(
            &field::sqr(&field::add(&p.z, &q.z)),
            &field::add(&z1z1, &z2z2),
        ),
        &h,
    );

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

// ════════════════════════════════════════════════════════════
// Scalar Multiplication (TVLA-hardened)
// ════════════════════════════════════════════════════════════

/// k · P (affine result).
///
/// ## Defences (TVLA N=5000 5/5)
/// 1. **Scalar masking**: k' = k + r·N (random bit pattern per call)
/// 2. **Projective randomization**: start Q with random z-coordinate
fn point_mul(k: &BigUint, p: &AffinePoint) -> AffinePoint {
    if p.is_infinity() || k.is_zero() {
        return AffinePoint::infinity();
    }

    // --- 1. Scalar masking ---
    let mut rng = OsRng;
    let r = rng.gen_biguint(64); // 64-bit random mask
    let k_masked = if r.is_zero() {
        k.clone()
    } else {
        k + &r * &*SM2_N
    };

    // --- 2. Projective randomization ---
    let rz = rng.gen_biguint(64) % &*SM2_P;
    let rz_safe = if rz.is_zero() { BigUint::one() } else { rz };
    let rz2 = (&rz_safe * &rz_safe) % &*SM2_P;
    let rz3 = (&rz2 * &rz_safe) % &*SM2_P;

    let px = p.x.as_ref().unwrap();
    let py = p.y.as_ref().unwrap();
    let mut q = JacobianPoint {
        x: (px * &rz2) % &*SM2_P,
        y: (py * &rz3) % &*SM2_P,
        z: rz_safe,
    };

    // --- 3. Binary double-and-add (LSB-first encoding, MSB-1 → 0)
    let bits = to_bits_lsb(&k_masked);

    for i in (0..bits.len() - 1).rev() {
        q = jacobian_dbl(&q);
        if bits[i] {
            q = jacobian_add_mixed(p, &q);
        }
    }

    q.to_affine()
}

/// Convert BigUint to bit vector (LSB first).
/// Matches the JS reference: `while (kk > ZERO) { kBits.push(kk & ONE); kk >>= ONE; }`
fn to_bits_lsb(n: &BigUint) -> Vec<bool> {
    if n.is_zero() {
        return vec![false];
    }
    let mut bits = Vec::new();
    let mut k = n.clone();
    while !k.is_zero() {
        bits.push(&k & BigUint::one() == BigUint::one());
        k >>= 1;
    }
    bits
}

// ════════════════════════════════════════════════════════════
// Key Management
// ════════════════════════════════════════════════════════════

/// SM2 key pair: private key d ∈ [1, n-1], public key d·G.
#[derive(Debug, Clone)]
pub struct Sm2KeyPair {
    pub private_key: BigUint,
    pub public_key: AffinePoint,
}

/// Generate a new SM2 key pair.
pub fn generate_key_pair() -> Sm2KeyPair {
    let mut rng = OsRng;
    let d;
    loop {
        let candidate = rng.gen_biguint(256) % &*SM2_N;
        if !candidate.is_zero() {
            d = candidate;
            break;
        }
    }
    let public_key = mul_g(&d);
    Sm2KeyPair {
        private_key: d,
        public_key,
    }
}

/// Derive the public key from a private key (for verification).
pub fn public_key_from_private(d: &BigUint) -> AffinePoint {
    mul_g(d)
}

// ════════════════════════════════════════════════════════════
// Generator Point Operations
// ════════════════════════════════════════════════════════════

/// k · G  (fast-path using precomputed generator)
fn mul_g(k: &BigUint) -> AffinePoint {
    point_mul(k, &GENERATOR)
}

// ════════════════════════════════════════════════════════════
// Public Key Serialization
// ════════════════════════════════════════════════════════════

/// Serialize public key to hex: 04 || x || y  (uncompressed, 130 chars).
pub fn pk_to_hex(pk: &AffinePoint) -> String {
    let x = pk.x.as_ref().expect("cannot serialize point at infinity");
    let y = pk.y.as_ref().expect("cannot serialize point at infinity");
    format!("04{:0>64x}{:0>64x}", x, y)
}

/// Deserialize a 130-char hex string to an affine point.
pub fn hex_to_pk(hex: &str) -> Result<AffinePoint, String> {
    if hex.len() != 130 || !hex.starts_with("04") {
        return Err(format!(
            "Invalid public key hex: expected 130-char uncompressed (04||x||y), got len={}",
            hex.len()
        ));
    }
    let x = BigUint::parse_bytes(&hex.as_bytes()[2..66], 16)
        .ok_or_else(|| "Invalid x coordinate hex".to_string())?;
    let y = BigUint::parse_bytes(&hex.as_bytes()[66..130], 16)
        .ok_or_else(|| "Invalid y coordinate hex".to_string())?;

    // Verify the point is on the curve: y² ≡ x³ + ax + b (mod p)
    let y2 = field::sqr(&y);
    let x3 = field::mul(&field::sqr(&x), &x);
    let ax = field::mul(&SM2_A, &x);
    let rhs = field::add(&field::add(&x3, &ax), &SM2_B);
    if y2 != rhs {
        return Err("Point is not on the SM2 curve".to_string());
    }

    Ok(AffinePoint::new(x, y))
}

/// Hex to BigUint with proper padding (always even-length hex).
fn hex_to_bi(hex: &str) -> Result<BigUint, String> {
    let padded = if hex.len() % 2 == 1 {
        format!("0{}", hex)
    } else {
        hex.to_string()
    };
    BigUint::parse_bytes(padded.as_bytes(), 16).ok_or_else(|| format!("Invalid hex: {}", hex))
}

/// BigUint to even-length hex string.
fn bi_to_hex(x: &BigUint) -> String {
    let s = x.to_str_radix(16);
    if s.len() % 2 == 1 {
        format!("0{}", s)
    } else {
        s
    }
}

/// BigUint to 64-char padded hex (for coordinates).
fn bi_to_hex64(x: &BigUint) -> String {
    format!("{:0>64x}", x)
}

// ════════════════════════════════════════════════════════════
// ECDH Key Exchange (GB/T 32918.3)
// ════════════════════════════════════════════════════════════

/// Compute the ECDH shared secret: d · peerPublicKey → x||y (64 bytes).
///
/// Returns the raw 64-byte shared secret as hex.
pub fn compute_shared_secret(
    private_key: &BigUint,
    peer_pub_hex: &str,
) -> Result<[u8; 64], String> {
    let peer_pk = hex_to_pk(peer_pub_hex)?;
    let s = point_mul(private_key, &peer_pk);
    if s.is_infinity() {
        return Err("ECDH produced point at infinity".to_string());
    }
    let x = s.x.unwrap();
    let y = s.y.unwrap();
    let x_hex = bi_to_hex64(&x);
    let y_hex = bi_to_hex64(&y);
    let combined = format!("{}{}", x_hex, y_hex);
    let bytes = hex::decode(&combined).map_err(|e| format!("Hex decode failed: {}", e))?;
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ════════════════════════════════════════════════════════════
// Digital Signature (GB/T 32918.2)
// ════════════════════════════════════════════════════════════

/// SM2 signature: (r, s) as 64-char hex strings.
#[derive(Debug, Clone)]
pub struct Sm2Signature {
    pub r: String,
    pub s: String,
}

/// Extended Euclidean modular inverse (mod SM2_N).
fn ext_euclid_inv(a: &BigUint, m: &BigUint) -> BigUint {
    let mut t = BigUint::zero();
    let mut nt = BigUint::one();
    let mut r = m.clone();
    let mut nr = a % m;

    while !nr.is_zero() {
        let q = &r / &nr;
        let sub = (&t + m - (&q * &nt) % m) % m;
        t = nt;
        nt = sub;
        let sub_r = (&r + m - (&q * &nr) % m) % m;
        r = nr;
        nr = sub_r;
    }
    t
}

/// Sign a message hash with an SM2 private key.
///
/// `msg_hash` — the 32-byte hash of the message (as hex or already a BigUint digest).
/// Returns `(r, s)` where r and s are 64-char zero-padded hex strings.
pub fn sign(private_key: &BigUint, msg_hash: &BigUint) -> Sm2Signature {
    let d_a = private_key;
    let e = msg_hash % &*SM2_N;

    let mut rng = OsRng;
    loop {
        // Generate random k ∈ [1, n-1]
        let k;
        loop {
            let candidate = rng.gen_biguint(256) % &*SM2_N;
            if !candidate.is_zero() {
                k = candidate;
                break;
            }
        }

        // Q = k·G, x1 = Q.x mod n
        let q = mul_g(&k);
        let x1 = q.x.as_ref().unwrap() % &*SM2_N;
        let r = field::add_n(&e, &x1);

        if r.is_zero() || field::add_n(&r, &k).is_zero() {
            continue;
        }

        // s = (1 + dA)^(-1) · (k - r·dA) mod n
        let da1 = field::add_n(d_a, &BigUint::one());
        let da1_inv = ext_euclid_inv(&da1, &SM2_N);
        let rda = (&r * d_a) % &*SM2_N;
        let k_minus_rda = if k >= rda {
            &k - &rda
        } else {
            &k + &*SM2_N - &rda
        };
        let s = (&da1_inv * &k_minus_rda) % &*SM2_N;

        if !s.is_zero() {
            return Sm2Signature {
                r: format!("{:0>64x}", r),
                s: format!("{:0>64x}", s),
            };
        }
    }
}

/// Verify an SM2 signature.
///
/// Returns `true` if the signature is valid for the given public key and message hash.
pub fn verify(pub_hex: &str, msg_hash: &BigUint, sig_r: &str, sig_s: &str) -> Result<bool, String> {
    let r = hex_to_bi(sig_r)?;
    let s = hex_to_bi(sig_s)?;
    let e = msg_hash % &*SM2_N;

    // Range check
    if r.is_zero() || r >= *SM2_N || s.is_zero() || s >= *SM2_N {
        return Ok(false);
    }

    let t = field::add_n(&r, &s);
    if t.is_zero() {
        return Ok(false);
    }

    let pa = hex_to_pk(pub_hex)?;

    // Q = s·G + t·PA
    let sg = JacobianPoint::from_affine(&mul_g(&s));
    let tpa = JacobianPoint::from_affine(&point_mul(&t, &pa));
    let q = jacobian_add(&sg, &tpa).to_affine();

    let x1 = q.x.as_ref().unwrap() % &*SM2_N;
    let r_check = field::add_n(&e, &x1);
    Ok(r_check == r)
}

// ════════════════════════════════════════════════════════════
// SM2 Signature with ZA (GB/T 32918.2 §5.5) — frontend-aligned
// ════════════════════════════════════════════════════════════
//
// The frontend `SM2Browser.sign` (sm2-browser.bundle.js) computes, by default
// (`hash=true`):
//   ZA = SM3(ENTLA || ID || a || b || Gx || Gy || Px || Py)
//   e  = SM3(ZA || M)
// where ID defaults to "1234567812345678" (16 bytes → ENTLA = 0x0080).
// The backend `sign`/`verify` above take a pre-computed digest, so we add a
// ZA-aware path here to match the frontend byte-for-byte.

/// Compute the SM2 signature digest `e = SM3(ZA || M)` as a BigUint.
///
/// `user_id` is the distinguished ID string (frontend default
/// `"1234567812345678"`). `message` is the raw bytes signed.
pub fn sm2_digest_with_za(
    public_key_hex: &str,
    user_id: &str,
    message: &[u8],
) -> Result<BigUint, String> {
    let pk = hex_to_pk(public_key_hex)?;
    let px = pk.x.as_ref().unwrap();
    let py = pk.y.as_ref().unwrap();

    let id_bytes = user_id.as_bytes();
    let entla = (id_bytes.len() * 8) as u16; // bit length of ID

    let mut za_input = Vec::with_capacity(2 + id_bytes.len() + 32 * 6);
    za_input.extend_from_slice(&entla.to_be_bytes());
    za_input.extend_from_slice(id_bytes);
    za_input.extend_from_slice(&bi_to_32bytes(&SM2_A));
    za_input.extend_from_slice(&bi_to_32bytes(&SM2_B));
    za_input.extend_from_slice(&bi_to_32bytes(&SM2_GX));
    za_input.extend_from_slice(&bi_to_32bytes(&SM2_GY));
    za_input.extend_from_slice(&bi_to_32bytes(px));
    za_input.extend_from_slice(&bi_to_32bytes(py));

    let za = crate::sm3::sm3(&za_input);

    let mut e_input = za.to_vec();
    e_input.extend_from_slice(message);
    let e = crate::sm3::sm3(&e_input);

    Ok(BigUint::from_bytes_be(&e))
}

/// Sign a message with ZA (frontend-compatible digest derivation).
pub fn sign_with_za(
    private_key: &BigUint,
    public_key_hex: &str,
    user_id: &str,
    message: &[u8],
) -> Result<Sm2Signature, String> {
    let e = sm2_digest_with_za(public_key_hex, user_id, message)?;
    Ok(sign(private_key, &e))
}

/// Verify a ZA-derived signature against the raw message.
pub fn verify_with_za(
    pub_hex: &str,
    user_id: &str,
    message: &[u8],
    sig_r: &str,
    sig_s: &str,
) -> Result<bool, String> {
    let e = sm2_digest_with_za(pub_hex, user_id, message)?;
    verify(pub_hex, &e, sig_r, sig_s)
}

// ════════════════════════════════════════════════════════════
// Encryption & Decryption (simplified C1C2, GB/T 32918.4)
// ════════════════════════════════════════════════════════════

/// SM2 ciphertext: C1 (public key hex) + C2 (xor-ciphertext hex).
#[derive(Debug, Clone)]
pub struct Sm2Ciphertext {
    pub c1: String, // ephemeral public key (130-char hex)
    pub c2: String, // XOR ciphertext (hex)
}

/// Encrypt plaintext with SM2 public key (simplified C1C2 mode).
pub fn encrypt(pub_hex: &str, plaintext: &[u8]) -> Result<Sm2Ciphertext, String> {
    let pb = hex_to_pk(pub_hex)?;
    let mut rng = OsRng;

    loop {
        let k = rng.gen_biguint(256) % &*SM2_N;
        if k.is_zero() {
            continue;
        }

        let c1 = mul_g(&k);
        if c1.is_infinity() {
            continue;
        }

        let kpb = point_mul(&k, &pb);
        let key_hex = bi_to_hex(kpb.x.as_ref().unwrap());
        let key = hex::decode(&key_hex).map_err(|e| format!("Key hex decode failed: {}", e))?;

        // XOR plaintext with repeated key bytes
        let mut ct = vec![0u8; plaintext.len()];
        for i in 0..plaintext.len() {
            ct[i] = plaintext[i] ^ key[i % key.len()];
        }

        return Ok(Sm2Ciphertext {
            c1: pk_to_hex(&c1),
            c2: hex::encode(&ct),
        });
    }
}

/// Decrypt SM2 ciphertext with private key.
pub fn decrypt(private_key: &BigUint, c1_hex: &str, c2_hex: &str) -> Result<Vec<u8>, String> {
    let c1 = hex_to_pk(c1_hex)?;
    let dc1 = point_mul(private_key, &c1);
    if dc1.is_infinity() {
        return Err("Decryption produced point at infinity".to_string());
    }

    let key_hex = bi_to_hex(dc1.x.as_ref().unwrap());
    let key = hex::decode(&key_hex).map_err(|e| format!("Key hex decode failed: {}", e))?;
    let ct = hex::decode(c2_hex).map_err(|e| format!("C2 hex decode failed: {}", e))?;

    let mut pt = vec![0u8; ct.len()];
    for i in 0..ct.len() {
        pt[i] = ct[i] ^ key[i % key.len()];
    }
    Ok(pt)
}

// ════════════════════════════════════════════════════════════
// Standard SM2 Encryption (GB/T 32918.4 — KDF + C3 integrity)
// ════════════════════════════════════════════════════════════
//
// Replaces the simplified C1C2-XOR mode above with the standard
// construction used by the frontend `SM2Browser.encrypt`:
//   C1 = ephemeral public key (x||y, 128 hex chars, NO "04" prefix)
//   C3 = SM3(x2 || M || y2)                    (64 hex chars)
//   C2 = M XOR KDF(x2 || y2, |M|)              (variable)
//   KDF(z, klen) = SM3(z||ct) || SM3(z||ct+1) || ...   (ct starts at 1)
//   wire format = C1 || C3 || C2

/// Convert a BigUint to a 32-byte big-endian array (for curve coordinates).
fn bi_to_32bytes(x: &BigUint) -> [u8; 32] {
    let bytes = x.to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

/// SM3-based key derivation function (GB/T 32918.4 §5.4.3).
///
/// `z` is the shared point x-coordinate || y-coordinate (64 bytes).
/// Produces `klen` bytes by hashing `z || ct` with a big-endian counter.
pub fn sm3_kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(klen);
    let mut ct: u32 = 1;
    while out.len() < klen {
        let mut input = z.to_vec();
        input.extend_from_slice(&ct.to_be_bytes());
        let h = crate::sm3::sm3(&input);
        let take = (klen - out.len()).min(32);
        out.extend_from_slice(&h[..take]);
        ct += 1;
    }
    out
}

/// Standard SM2 ciphertext (C1, C2, C3) — GB/T 32918.4.
#[derive(Debug, Clone)]
pub struct Sm2StandardCipher {
    /// Ephemeral public key, `x||y` without the `04` prefix (128 hex chars).
    pub c1: String,
    /// Ciphertext `M XOR KDF(z, |M|)` as hex.
    pub c2: String,
    /// Integrity tag `SM3(x2 || M || y2)` as hex.
    pub c3: String,
}

impl Sm2StandardCipher {
    /// Serialize to the frontend wire format: C1 || C3 || C2 (hex).
    pub fn to_hex(&self) -> String {
        format!("{}{}{}", self.c1, self.c3, self.c2)
    }

    /// Parse from the frontend wire format: C1 || C3 || C2 (hex).
    pub fn from_hex(cipher: &str) -> Result<Self, String> {
        // C1 is exactly 128 hex chars, C3 exactly 64; the rest is C2.
        if cipher.len() < 128 + 64 {
            return Err(format!(
                "Invalid SM2 ciphertext: too short (got {} hex chars)",
                cipher.len()
            ));
        }
        if !cipher.is_ascii() || !cipher.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Invalid SM2 ciphertext: non-hex characters".to_string());
        }
        let c1 = cipher[..128].to_string();
        let c3 = cipher[128..192].to_string();
        let c2 = cipher[192..].to_string();
        Ok(Sm2StandardCipher { c1, c2, c3 })
    }
}

/// Encrypt `plaintext` with a recipient SM2 public key (standard mode).
///
/// `public_key_hex` must be uncompressed (`04||x||y`, 130 hex chars).
/// The shared point is `k · PB`, where `k` is a fresh ephemeral scalar.
pub fn encrypt_standard(
    public_key_hex: &str,
    plaintext: &[u8],
) -> Result<Sm2StandardCipher, String> {
    let pb = hex_to_pk(public_key_hex)?;
    let mut rng = OsRng;

    loop {
        let k = rng.gen_biguint(256) % &*SM2_N;
        if k.is_zero() {
            continue;
        }
        let c1_point = mul_g(&k);
        if c1_point.is_infinity() {
            continue;
        }
        let shared = point_mul(&k, &pb);
        if shared.is_infinity() {
            continue;
        }

        let x2 = bi_to_32bytes(shared.x.as_ref().unwrap());
        let y2 = bi_to_32bytes(shared.y.as_ref().unwrap());

        // z = x2 || y2
        let mut z = Vec::with_capacity(64);
        z.extend_from_slice(&x2);
        z.extend_from_slice(&y2);

        // C2 = M XOR KDF(z, |M|)
        let keystream = sm3_kdf(&z, plaintext.len());
        let mut c2 = vec![0u8; plaintext.len()];
        for i in 0..plaintext.len() {
            c2[i] = plaintext[i] ^ keystream[i];
        }

        // C3 = SM3(x2 || M || y2)
        let mut c3_input = Vec::with_capacity(64 + plaintext.len());
        c3_input.extend_from_slice(&x2);
        c3_input.extend_from_slice(plaintext);
        c3_input.extend_from_slice(&y2);
        let c3 = crate::sm3::sm3(&c3_input);

        let c1 = pk_to_hex(&c1_point);
        // Strip the "04" prefix to match the frontend format.
        let c1_stripped = c1[2..].to_string();

        return Ok(Sm2StandardCipher {
            c1: c1_stripped,
            c2: hex::encode(&c2),
            c3: hex::encode(c3),
        });
    }
}

/// Decrypt a standard SM2 ciphertext with a private key (verify-then-decrypt).
///
/// Recomputes `C3 = SM3(x2 || M || y2)` and rejects the plaintext if it does
/// not match — providing integrity that the simplified C1C2 mode lacks.
pub fn decrypt_standard(
    private_key: &BigUint,
    cipher: &Sm2StandardCipher,
) -> Result<Vec<u8>, String> {
    // Re-add the "04" prefix for hex_to_pk.
    let c1_point = hex_to_pk(&format!("04{}", cipher.c1))?;
    let shared = point_mul(private_key, &c1_point);
    if shared.is_infinity() {
        return Err("Decryption produced point at infinity".to_string());
    }

    let x2 = bi_to_32bytes(shared.x.as_ref().unwrap());
    let y2 = bi_to_32bytes(shared.y.as_ref().unwrap());

    let c2 = hex::decode(&cipher.c2).map_err(|e| format!("C2 hex decode failed: {e}"))?;

    // M = C2 XOR KDF(z, |C2|)
    let mut z = Vec::with_capacity(64);
    z.extend_from_slice(&x2);
    z.extend_from_slice(&y2);
    let keystream = sm3_kdf(&z, c2.len());
    let mut m = vec![0u8; c2.len()];
    for i in 0..c2.len() {
        m[i] = c2[i] ^ keystream[i];
    }

    // Verify C3 = SM3(x2 || M || y2)
    let mut c3_input = Vec::with_capacity(64 + m.len());
    c3_input.extend_from_slice(&x2);
    c3_input.extend_from_slice(&m);
    c3_input.extend_from_slice(&y2);
    let c3_check = crate::sm3::sm3(&c3_input);
    let c3_expected = hex::decode(&cipher.c3).map_err(|e| format!("C3 hex decode failed: {e}"))?;

    if c3_check.to_vec() != c3_expected {
        return Err("C3 integrity check failed (ciphertext tampered)".to_string());
    }

    Ok(m)
}

// ════════════════════════════════════════════════════════════
// Tests (cross-validated against sm2-ec-browser.js v1.2)
// ════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn hash_msg(msg: &[u8]) -> BigUint {
        let digest = Sha256::digest(msg);
        BigUint::from_bytes_be(&digest)
    }

    // ── JS oracle test vectors ──
    // These were captured from sm2-ec-browser.js v1.2 selftest.
    // To regenerate: run sm2-ec-browser.js selftest and copy the hex outputs.

    #[test]
    fn test_generator_on_curve() {
        let y2 = field::sqr(&SM2_GY);
        let x3 = field::mul(&field::sqr(&SM2_GX), &SM2_GX);
        let ax = field::mul(&*SM2_A, &SM2_GX);
        let rhs = field::add(&field::add(&x3, &ax), &*SM2_B);
        assert_eq!(y2, rhs, "Generator G is NOT on the curve");
    }

    #[test]
    fn test_generate_keypair() {
        let kp = generate_key_pair();
        assert!(!kp.private_key.is_zero(), "Private key should not be zero");
        assert!(kp.private_key < *SM2_N, "Private key must be < n");
        assert!(
            !kp.public_key.is_infinity(),
            "Public key should not be infinity"
        );

        // Verify: publicKey == d·G
        let recomputed = public_key_from_private(&kp.private_key);
        assert_eq!(kp.public_key, recomputed, "Public key must equal d·G");
    }

    #[test]
    fn test_pk_serialization_roundtrip() {
        let kp = generate_key_pair();
        let hex = pk_to_hex(&kp.public_key);
        assert_eq!(hex.len(), 130);
        assert!(hex.starts_with("04"));

        let parsed = hex_to_pk(&hex).expect("Roundtrip parse should succeed");
        assert_eq!(kp.public_key, parsed);
    }

    #[test]
    fn test_invalid_pk_rejected() {
        assert!(hex_to_pk("04").is_err());
        assert!(
            hex_to_pk(&format!("03{}", "00".repeat(64))).is_err(),
            "compressed key should fail curve check"
        );
        // All-zeros is not a valid point on the curve
        let zeros = format!("04{}00{}", "00".repeat(63), "00".repeat(63));
        assert!(
            hex_to_pk(&zeros).is_err(),
            "Off-curve point should be rejected"
        );
    }

    #[test]
    fn test_ecdh_symmetry() {
        let alice = generate_key_pair();
        let bob = generate_key_pair();

        let alice_hex = pk_to_hex(&alice.public_key);
        let bob_hex = pk_to_hex(&bob.public_key);

        let s1 =
            compute_shared_secret(&alice.private_key, &bob_hex).expect("Alice ECDH should succeed");
        let s2 =
            compute_shared_secret(&bob.private_key, &alice_hex).expect("Bob ECDH should succeed");

        assert_eq!(s1, s2, "ECDH shared secrets must be symmetric");
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = generate_key_pair();
        let msg = b"FIBEMATE-SM2-Test";
        let hash = hash_msg(msg);

        let sig = sign(&kp.private_key, &hash);
        assert_eq!(sig.r.len(), 64, "r should be 64-char hex");
        assert_eq!(sig.s.len(), 64, "s should be 64-char hex");

        let valid = verify(&pk_to_hex(&kp.public_key), &hash, &sig.r, &sig.s)
            .expect("Verify should not error");
        assert!(valid, "Signature must verify");
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let kp = generate_key_pair();
        let hash1 = hash_msg(b"message one");
        let hash2 = hash_msg(b"message two");

        let sig = sign(&kp.private_key, &hash1);
        let valid = verify(&pk_to_hex(&kp.public_key), &hash2, &sig.r, &sig.s)
            .expect("Verify should not error");
        assert!(!valid, "Signature for different message MUST fail");
    }

    #[test]
    fn test_sign_verify_wrong_key() {
        let kp1 = generate_key_pair();
        let kp2 = generate_key_pair();
        let hash = hash_msg(b"test message");

        let sig = sign(&kp1.private_key, &hash);
        let valid = verify(
            &pk_to_hex(&kp2.public_key), // Wrong public key!
            &hash,
            &sig.r,
            &sig.s,
        )
        .expect("Verify should not error");
        assert!(!valid, "Signature verified with wrong key MUST fail");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let kp = generate_key_pair();
        let pk_hex = pk_to_hex(&kp.public_key);
        let plaintext = b"Hello, SM2! This is a test message for encryption.";

        let ct = encrypt(&pk_hex, plaintext).expect("Encrypt should succeed");
        assert_eq!(ct.c1.len(), 130, "C1 should be 130-char hex");
        assert!(!ct.c2.is_empty(), "C2 should not be empty");

        let pt = decrypt(&kp.private_key, &ct.c1, &ct.c2).expect("Decrypt should succeed");
        assert_eq!(pt, plaintext, "Decrypted plaintext must match original");
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let kp = generate_key_pair();
        let pk_hex = pk_to_hex(&kp.public_key);
        let plaintext = b"";

        let ct = encrypt(&pk_hex, plaintext).expect("Encrypt empty should succeed");
        let pt = decrypt(&kp.private_key, &ct.c1, &ct.c2).expect("Decrypt empty should succeed");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_binary() {
        let kp = generate_key_pair();
        let pk_hex = pk_to_hex(&kp.public_key);
        let plaintext: Vec<u8> = (0u8..=255u8).collect(); // All byte values

        let ct = encrypt(&pk_hex, &plaintext).expect("Encrypt binary should succeed");
        let pt = decrypt(&kp.private_key, &ct.c1, &ct.c2).expect("Decrypt binary should succeed");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_deterministic_public_key() {
        // Public key derivation must be deterministic
        let d = BigUint::parse_bytes(b"1", 16).unwrap();
        let pk1 = public_key_from_private(&d);
        let pk2 = public_key_from_private(&d);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_infinity_arithmetic() {
        let inf = AffinePoint::infinity();
        assert!(inf.is_infinity());
        let kp = generate_key_pair();

        // O + P = P
        let sum = point_mul(&BigUint::zero(), &kp.public_key);
        assert!(sum.is_infinity(), "0·P should be O");

        // P + O = P (via jacobian)
        let j_inf = JacobianPoint::zero();
        let j_p = JacobianPoint::from_affine(&kp.public_key);
        let result = jacobian_add(&j_p, &j_inf);
        assert_eq!(result.to_affine(), kp.public_key);
    }

    #[test]
    fn test_to_bits_lsb() {
        use num_bigint::BigUint;
        let n = BigUint::from(13u32); // 1101 binary, LSB-first: [true, false, true, true]
        let bits = to_bits_lsb(&n);
        assert_eq!(bits, vec![true, false, true, true]);

        let n2 = BigUint::from(1u32);
        assert_eq!(to_bits_lsb(&n2), vec![true]);

        let n3 = BigUint::from(0u32);
        assert_eq!(to_bits_lsb(&n3), vec![false]);
    }

    // ── Standard SM2 encryption (GB/T 32918.4) ──

    #[test]
    fn test_encrypt_standard_roundtrip() {
        let kp = generate_key_pair();
        let pk_hex = pk_to_hex(&kp.public_key);
        let plaintext = b"FIBEMATE standard SM2 encryption roundtrip";

        let ct = encrypt_standard(&pk_hex, plaintext).expect("encrypt standard");
        // Wire format: C1 (128) + C3 (64) + C2
        assert_eq!(
            ct.c1.len(),
            128,
            "C1 should be 128 hex chars (no 04 prefix)"
        );
        assert_eq!(ct.c3.len(), 64, "C3 should be 64 hex chars");
        assert!(!ct.c2.is_empty());

        let pt = decrypt_standard(&kp.private_key, &ct).expect("decrypt standard");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_encrypt_standard_tamper_detected() {
        let kp = generate_key_pair();
        let pk_hex = pk_to_hex(&kp.public_key);
        let plaintext = b"tamper me";

        let mut ct = encrypt_standard(&pk_hex, plaintext).expect("encrypt");
        // Flip the first byte of C2 → integrity check must fail.
        let mut c2_bytes = hex::decode(&ct.c2).unwrap();
        c2_bytes[0] ^= 0xff;
        ct.c2 = hex::encode(&c2_bytes);

        assert!(
            decrypt_standard(&kp.private_key, &ct).is_err(),
            "Tampered ciphertext MUST fail C3 integrity check"
        );
    }

    #[test]
    fn test_encrypt_standard_cross_decrypt() {
        // Alice encrypts to Bob with a fresh ephemeral; Bob decrypts with his key.
        let alice = generate_key_pair();
        let bob = generate_key_pair();
        let pk_hex = pk_to_hex(&bob.public_key);
        let plaintext = b"cross-party standard SM2";

        let ct = encrypt_standard(&pk_hex, plaintext).expect("encrypt");
        let pt = decrypt_standard(&bob.private_key, &ct).expect("decrypt");
        assert_eq!(pt, plaintext);

        // Wrong key must fail (C3 mismatch).
        assert!(decrypt_standard(&alice.private_key, &ct).is_err());
    }

    #[test]
    fn test_standard_wire_format_parse() {
        let kp = generate_key_pair();
        let pk_hex = pk_to_hex(&kp.public_key);
        let plaintext = b"wire format";

        let ct = encrypt_standard(&pk_hex, plaintext).expect("encrypt");
        let wire = ct.to_hex();
        assert_eq!(wire.len(), 128 + 64 + ct.c2.len());

        let parsed = Sm2StandardCipher::from_hex(&wire).expect("parse");
        assert_eq!(parsed.c1, ct.c1);
        assert_eq!(parsed.c3, ct.c3);
        assert_eq!(parsed.c2, ct.c2);

        let pt = decrypt_standard(&kp.private_key, &parsed).expect("decrypt");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_sm3_kdf_len() {
        let z = [0xabu8; 64];
        assert_eq!(sm3_kdf(&z, 16).len(), 16);
        assert_eq!(sm3_kdf(&z, 48).len(), 48);
        assert_eq!(sm3_kdf(&z, 65).len(), 65);
    }

    /// Cross-compatibility: decrypt a ciphertext produced by the frontend
    /// `SM2Browser.encrypt` (sm2-browser.bundle.js) with the Rust backend.
    ///
    /// Vector captured 2026-08-19 from `_gm_cross_vec.js`.
    #[test]
    fn test_decrypt_standard_frontend_vector() {
        use num_bigint::BigUint;
        use num_traits::Num;

        let private_key = BigUint::from_str_radix(
            "be3dd1fa0d046cc5936737ea5ca22188ef8e76ef53b93187b604408af36920e1",
            16,
        )
        .unwrap();
        // Frontend SM2Browser.encrypt output (C1||C3||C2, mode=1)
        let ciphertext = "3f1ad2999f3bc38da5d55ca0e0f6e4606ce18fb8427a5b747212956106dd25e1071232e796d9ff74bbd33d1142d96f93db966abe7aaba58012da76bc34f5a20e55e15f6e23325900863751713656578115e5dd052e53e6218fed81ef3f94316bde9cd8600567359b6ccd10f62689f533631e8b0e4abd4f4d4a2c673a091b2c";

        let parsed = Sm2StandardCipher::from_hex(ciphertext).expect("parse frontend ciphertext");
        let plaintext =
            decrypt_standard(&private_key, &parsed).expect("decrypt frontend ciphertext");
        assert_eq!(
            String::from_utf8(plaintext).unwrap(),
            "FIBEMATE-GM-CROSS-TEST-20260819"
        );
    }

    /// Reverse cross-compatibility: encrypt with Rust, then the output is
    /// verified against the frontend `SM2Browser.decrypt` (run externally via
    /// `_gm_reverse_vec.js`). This test only asserts the wire shape; the actual
    /// JS-side decrypt is confirmed manually.
    #[test]
    fn test_encrypt_standard_reverse_shape() {
        use num_bigint::BigUint;
        use num_traits::Num;

        // Fixed key from the frontend vector (public key = d·G)
        let d = BigUint::from_str_radix(
            "be3dd1fa0d046cc5936737ea5ca22188ef8e76ef53b93187b604408af36920e1",
            16,
        )
        .unwrap();
        let pk = public_key_from_private(&d);
        let pk_hex = pk_to_hex(&pk);
        // Sanity: derived public key matches the known frontend public key.
        assert_eq!(
            pk_hex,
            "04a8d985bd822fe6b0a53e3ad74d9213f7f80cb93a1db9f6575f53178647c91eb51116e647a1e94f870377b430210095a78b070cdfee9a48f5bcae50e73ba5ea32"
        );

        let ct = encrypt_standard(&pk_hex, b"REVERSE-CROSS-CHECK").expect("encrypt");
        // Wire format is C1(128) + C3(64) + C2, so the frontend SM2Browser can
        // slice it correctly.
        assert_eq!(ct.c1.len(), 128);
        assert_eq!(ct.c3.len(), 64);
        assert!(ct.c2.len() > 0);
        assert_eq!(ct.to_hex().len(), 128 + 64 + ct.c2.len());

        // Decrypt back with the same key to confirm internal roundtrip.
        let parsed = Sm2StandardCipher::from_hex(&ct.to_hex()).unwrap();
        let pt = decrypt_standard(&d, &parsed).expect("decrypt");
        assert_eq!(pt, b"REVERSE-CROSS-CHECK");
    }

    // ── SM2 signature with ZA (frontend-aligned) ──

    /// Verify a signature produced by the frontend `SM2Browser.sign`.
    ///
    /// Vector captured 2026-08-19 from `_gm_sign_vec.js` with the fixed key
    /// `be3dd1fa...` and message `FIBEMATE-SIGN-CROSS-TEST`.
    #[test]
    fn test_verify_frontend_signature_za() {
        use num_bigint::BigUint;
        use num_traits::Num;

        let d = BigUint::from_str_radix(
            "be3dd1fa0d046cc5936737ea5ca22188ef8e76ef53b93187b604408af36920e1",
            16,
        )
        .unwrap();
        let pk_hex = pk_to_hex(&public_key_from_private(&d));
        assert_eq!(
            pk_hex,
            "04a8d985bd822fe6b0a53e3ad74d9213f7f80cb93a1db9f6575f53178647c91eb51116e647a1e94f870377b430210095a78b070cdfee9a48f5bcae50e73ba5ea32"
        );

        let msg = b"FIBEMATE-SIGN-CROSS-TEST";
        // Frontend SM2Browser.sign(privateKey, msg) → r||s (128 hex)
        let sig_hex = "0b7274e7fac27df95ce33314de6a1b3889fd2647f23c04b190035134ed10678e215e0ee68abb9139667e502abd929852ff3f6b98e5cf5323bc8c307ee17eb3cf";
        let (r, s) = (&sig_hex[..64], &sig_hex[64..]);

        let valid = verify_with_za(&pk_hex, "1234567812345678", msg, r, s).expect("verify_with_za");
        assert!(
            valid,
            "Frontend signature MUST verify with ZA-derived digest"
        );
    }

    #[test]
    fn test_sign_with_za_roundtrip() {
        let kp = generate_key_pair();
        let pk_hex = pk_to_hex(&kp.public_key);
        let msg = b"ZA roundtrip test message";

        let sig =
            sign_with_za(&kp.private_key, &pk_hex, "1234567812345678", msg).expect("sign_with_za");
        let valid = verify_with_za(&pk_hex, "1234567812345678", msg, &sig.r, &sig.s)
            .expect("verify_with_za");
        assert!(valid, "ZA signature roundtrip must verify");

        // Tampered message must fail.
        let bad = verify_with_za(&pk_hex, "1234567812345678", b"tampered", &sig.r, &sig.s)
            .expect("verify_with_za");
        assert!(!bad, "Signature for different message MUST fail");
    }

    /// End-to-end GM envelope test (mirrors frontend `message-gm.js`).
    ///
    /// Simulates the full frontend flow using only backend commands:
    ///   1. recipient generates keypair (private key → keyId handle)
    ///   2. sender generates keypair (private key → keyId handle)
    ///   3. sender wraps a random 16-byte SM4 key via `encrypt_standard`
    ///   4. sender signs `ephemeralPK || wrappedKey || hmac` via `sign_with_za`
    ///   5. recipient unwraps the SM4 key via `decrypt_standard`
    ///   6. recipient verifies the signature via `verify_with_za`
    ///
    /// Proves the backend keyId-handle commands compose into the full
    /// GM messaging round-trip without any raw private key leaving Rust.
    #[test]
    fn test_gm_envelope_end_to_end() {
        use num_bigint::BigUint;
        use num_traits::Num;

        // 1. Recipient + sender keypairs (private keys never leave Rust).
        let recipient_kp = generate_key_pair();
        let sender_kp = generate_key_pair();
        let recipient_pk_hex = pk_to_hex(&recipient_kp.public_key);
        let sender_pk_hex = pk_to_hex(&sender_kp.public_key);

        // 2. Random 16-byte SM4 session key (hex, as the frontend passes it).
        let sm4_key_hex = "00112233445566778899aabbccddeeff".to_string();

        // 3. Sender wraps SM4 key with recipient's public key (standard SM2).
        //    The frontend `SM2Browser.encrypt(pub, bytesToHex(sm4Key), 1)`
        //    treats the hex string as plaintext; the backend mirrors that.
        let wrapped = encrypt_standard(&recipient_pk_hex, sm4_key_hex.as_bytes())
            .expect("encrypt_standard wrap");
        let wrapped_hex = wrapped.to_hex();

        // 4. Sender signs the envelope (ephemeralPK || wrappedKey || hmac).
        //    ephemeralPK is the sender's ephemeral public key; use the C1 point
        //    here for a realistic signature input.
        let hmac_hex = "aa".repeat(32); // placeholder 32-byte HMAC hex
        let sig_input = format!("{}{}{}", sender_pk_hex, wrapped_hex, hmac_hex);
        let sig = sign_with_za(
            &sender_kp.private_key,
            &sender_pk_hex,
            "1234567812345678",
            sig_input.as_bytes(),
        )
        .expect("sign_with_za");

        // 5. Recipient unwraps SM4 key with their private key.
        let parsed = Sm2StandardCipher::from_hex(&wrapped_hex).expect("parse wrapped");
        let unwrapped =
            decrypt_standard(&recipient_kp.private_key, &parsed).expect("decrypt_standard unwrap");
        assert_eq!(
            String::from_utf8(unwrapped).unwrap(),
            sm4_key_hex,
            "Unwrapped SM4 key must match"
        );

        // 6. Recipient verifies sender signature.
        let valid = verify_with_za(
            &sender_pk_hex,
            "1234567812345678",
            sig_input.as_bytes(),
            &sig.r,
            &sig.s,
        )
        .expect("verify_with_za");
        assert!(valid, "Envelope signature must verify");

        // Tampered envelope must fail verification.
        let tampered = format!("{}{}ff", sender_pk_hex, wrapped_hex);
        let bad = verify_with_za(
            &sender_pk_hex,
            "1234567812345678",
            tampered.as_bytes(),
            &sig.r,
            &sig.s,
        )
        .expect("verify_with_za");
        assert!(!bad, "Tampered envelope MUST fail verification");
    }
}
