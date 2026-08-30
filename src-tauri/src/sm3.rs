//! SM3 cryptographic hash function (GB/T 32905-2016)
//!
//! 256-bit output. Rust port of the reference implementation, validated
//! against the official GB/T 32905-2016 Appendix A test vectors.
//!
//! This mirrors the frontend `modules/gm/sm3_implementation.js` byte-for-byte
//! semantics (the JS impl has two dead lines before the correct `P0(TT2)`
//! assignment, which are overridden — the effective computation is standard).

const IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

/// T_j constants: T[0] for 0..=15, T[1] for 16..=63.
const T: [u32; 2] = [0x79cc4519, 0x7a879d8a];

#[inline]
fn ff(x: u32, y: u32, z: u32, j: usize) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

#[inline]
fn gg(x: u32, y: u32, z: u32, j: usize) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | ((!x) & z)
    }
}

#[inline]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

fn compress(v: &mut [u32; 8], block: &[u8]) {
    debug_assert_eq!(block.len(), 64);

    // Message expansion: W[0..68], W'[0..64]
    let mut w = [0u32; 68];
    let mut w1 = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..68 {
        let t = w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15);
        w[i] = p1(t) ^ w[i - 13].rotate_left(7) ^ w[i - 6];
    }
    for i in 0..64 {
        w1[i] = w[i] ^ w[i + 4];
    }

    let mut a = v[0];
    let mut b = v[1];
    let mut c = v[2];
    let mut d = v[3];
    let mut e = v[4];
    let mut f = v[5];
    let mut g = v[6];
    let mut h = v[7];

    for j in 0..64 {
        let tj = if j < 16 { T[0] } else { T[1] };
        let ss1 = (a
            .rotate_left(12)
            .wrapping_add(e)
            .wrapping_add(tj.rotate_left((j % 32) as u32)))
        .rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let tt1 = ff(a, b, c, j)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(w1[j]);
        let tt2 = gg(e, f, g, j)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(w[j]);

        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    v[0] ^= a;
    v[1] ^= b;
    v[2] ^= c;
    v[3] ^= d;
    v[4] ^= e;
    v[5] ^= f;
    v[6] ^= g;
    v[7] ^= h;
}

/// Compute the SM3 digest of `msg`, returning 32 bytes.
pub fn sm3(msg: &[u8]) -> [u8; 32] {
    let bit_len = (msg.len() as u64).wrapping_mul(8);

    // Padding: append 0x80, zero-pad to 56 mod 64, then 64-bit big-endian bit length.
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut v = IV;
    for block in padded.chunks(64) {
        compress(&mut v, block);
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&v[i].to_be_bytes());
    }
    out
}

/// Compute the SM3 digest and return it as a lowercase hex string.
pub fn sm3_hex(msg: &[u8]) -> String {
    sm3(msg).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_sm3_abc() {
        // GB/T 32905-2016 Appendix A, example 1: "abc"
        let digest = sm3(b"abc");
        let expect = hex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
        assert_eq!(digest.to_vec(), expect);
    }

    #[test]
    fn test_sm3_abcd_x16() {
        // GB/T 32905-2016 Appendix A, example 2: "abcd" repeated 16 times (64 bytes)
        let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        let digest = sm3(msg);
        let expect = hex("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
        assert_eq!(digest.to_vec(), expect);
    }

    #[test]
    fn test_sm3_empty() {
        // Self-consistency: empty input must be deterministic and 32 bytes.
        let a = sm3(b"");
        let b = sm3(b"");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn test_sm3_hex_format() {
        assert_eq!(
            sm3_hex(b"abc"),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
    }
}
