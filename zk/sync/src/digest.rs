//! Raito's Blake2s commitments, computed from rust-bitcoin types.
//!
//! Each function mirrors the Cairo code block by block (`utils::blake2s_hasher`), with
//! the same compress and finalize calls, rather than hashing a byte string with a
//! standard Blake2s: the Cairo code is not always standard Blake2s. With exactly six
//! previous timestamps, `ChainState::blake2s_digest` compresses its second block as a
//! non-final block and then finalizes an empty one, which standard Blake2s never does.
//!
//! A Bitcoin hash enters as eight words, each the big-endian reading of four bytes of the
//! hash in internal byte order (`utils::hash::Digest`). A digest leaves as the eight
//! Blake2s state words; as a `u256` it is those words big-endian, word 0 first.

use bitcoin::block::Header;
use bitcoin_zk_args::ChainState;

/// A Blake2s digest as Cairo's `Blake2sDigest`: eight u32 words.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Digest(pub [u32; 8]);

impl Digest {
    /// Cairo's `Into<u256>`: the words big-endian, word 0 most significant.
    pub fn to_u256_be(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, w) in self.0.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    pub fn from_u256_be(be: [u8; 32]) -> Self {
        let mut w = [0u32; 8];
        for (i, c) in be.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        Digest(w)
    }

    /// `(high, low)` 128-bit halves of the u256 value.
    pub fn to_u128_halves(&self) -> (u128, u128) {
        let be = self.to_u256_be();
        let mut hi = [0u8; 16];
        let mut lo = [0u8; 16];
        hi.copy_from_slice(&be[..16]);
        lo.copy_from_slice(&be[16..]);
        (u128::from_be_bytes(hi), u128::from_be_bytes(lo))
    }

    pub fn from_u128_halves(high: u128, low: u128) -> Self {
        let mut be = [0u8; 32];
        be[..16].copy_from_slice(&high.to_be_bytes());
        be[16..].copy_from_slice(&low.to_be_bytes());
        Self::from_u256_be(be)
    }

    /// The u256 value as 64 lowercase hex digits.
    pub fn to_hex(&self) -> String { self.to_u256_be().iter().map(|b| format!("{b:02x}")).collect() }

    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim_start_matches("0x");
        if s.len() != 64 || !s.is_ascii() {
            return None;
        }
        let mut be = [0u8; 32];
        for (i, b) in be.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(Self::from_u256_be(be))
    }
}

const IV: [u32; 8] = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// The Blake2s compression function (RFC 7693), as `core::blake::blake2s_compress`
/// (`last = false`) and `blake2s_finalize` (`last = true`) apply it: `t` is the total
/// byte count including this block.
fn compress(h: &mut [u32; 8], m: &[u32; 16], t: u32, last: bool) {
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t;
    if last {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        let mut g = |a: usize, b: usize, c: usize, d: usize, x: u32, y: u32| {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        };
        g(0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// `utils::blake2s_hasher::Blake2sHasher`, call for call.
pub struct Blake2sHasher {
    h: [u32; 8],
    byte_len: u32,
}

impl Default for Blake2sHasher {
    fn default() -> Self { Self::new() }
}

impl Blake2sHasher {
    pub fn new() -> Self {
        let mut h = IV;
        h[0] ^= 0x0101_0020; // no key, 32-byte output
        Blake2sHasher { h, byte_len: 0 }
    }

    /// `compress_block`: 64 bytes, not final.
    pub fn compress_block(&mut self, data: [u32; 16]) {
        self.byte_len += 64;
        compress(&mut self.h, &data, self.byte_len, false);
    }

    /// `finalize`: up to 16 words, zero-padded, final; an empty `data` still finalizes an
    /// all-zero block.
    pub fn finalize(mut self, data: &[u32]) -> Digest {
        assert!(data.len() <= 16, "Cairo's finalize takes at most 16 words");
        let mut block = [0u32; 16];
        block[..data.len()].copy_from_slice(data);
        compress(&mut self.h, &block, self.byte_len + 4 * data.len() as u32, true);
        Digest(self.h)
    }

    /// `finalize_block`: a full block, final, counting `byte_len` bytes of it.
    pub fn finalize_block(mut self, data: [u32; 16], byte_len: u32) -> Digest {
        compress(&mut self.h, &data, self.byte_len + byte_len, true);
        Digest(self.h)
    }
}

/// `blake2s_hash_pair`: the parent of two MMR nodes.
pub fn hash_pair(left: &Digest, right: &Digest) -> Digest {
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(&left.0);
    block[8..].copy_from_slice(&right.0);
    Blake2sHasher::new().finalize_block(block, 64)
}

/// A Bitcoin hash (internal byte order) as `utils::hash::Digest` words.
pub fn hash_words(internal: [u8; 32]) -> [u32; 8] {
    let mut w = [0u32; 8];
    for (i, c) in internal.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    w
}

/// `u256_to_u32x8` of a big-endian 256-bit number.
fn be_words(be: [u8; 32]) -> [u32; 8] { hash_words(be) }

/// `Header::blake2s_digest(prev_block_hash, merkle_root)`: the block's leaf in the MMR.
/// Everything it hashes is in the header itself.
pub fn header_leaf(header: &Header) -> Digest {
    let p = hash_words(header.prev_blockhash.to_byte_array());
    let m = hash_words(header.merkle_root.to_byte_array());
    let mut hasher = Blake2sHasher::new();
    hasher.compress_block([
        header.version.to_consensus() as u32,
        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
        m[0], m[1], m[2], m[3], m[4], m[5], m[6],
    ]);
    hasher.finalize_block(
        [m[7], header.time.to_u32(), header.bits.to_consensus(), header.nonce, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        16,
    )
}

/// `ChainStateHashTrait::blake2s_digest`.
pub fn chain_state_digest(cs: &ChainState) -> Digest {
    let w = be_words(cs.total_work.to_be_bytes());
    let b = hash_words(cs.best_block_hash.to_byte_array());
    let t = be_words(cs.current_target.to_be_bytes());
    let mut hasher = Blake2sHasher::new();
    hasher.compress_block([
        cs.block_height,
        w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
        b[0], b[1], b[2], b[3], b[4], b[5], b[6],
    ]);
    let head = [b[7], t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], cs.epoch_start_time];
    let ts = &cs.prev_timestamps;
    if ts.len() >= 6 {
        let mut block = [0u32; 16];
        block[..10].copy_from_slice(&head);
        block[10..].copy_from_slice(&ts[..6]);
        hasher.compress_block(block);
        hasher.finalize(&ts[6..])
    } else {
        let mut buffer = head.to_vec();
        buffer.extend_from_slice(ts);
        hasher.finalize(&buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_paths_equal_standard_blake2s() {
        use blake2::{Blake2s256, Digest as _};
        let std_hash = |words: &[u32]| {
            let mut h = Blake2s256::new();
            for w in words {
                h.update(w.to_le_bytes());
            }
            let out = h.finalize();
            let mut d = [0u32; 8];
            for (i, c) in out.chunks_exact(4).enumerate() {
                d[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            }
            Digest(d)
        };
        let words: Vec<u32> = (0..48u32).map(|i| i.wrapping_mul(0x9E37_79B9)).collect();
        // One full block, final.
        let mut b16 = [0u32; 16];
        b16.copy_from_slice(&words[..16]);
        assert_eq!(Blake2sHasher::new().finalize_block(b16, 64), std_hash(&words[..16]));
        // A partial final block after full blocks.
        for tail in 1..=16 {
            let mut h = Blake2sHasher::new();
            h.compress_block(b16);
            let mut b2 = [0u32; 16];
            b2.copy_from_slice(&words[16..32]);
            h.compress_block(b2);
            assert_eq!(h.finalize(&words[32..32 + tail]), std_hash(&words[..32 + tail]), "tail {tail}");
        }
        // The one non-standard path: an empty finalize after full blocks.
        let mut h = Blake2sHasher::new();
        h.compress_block(b16);
        assert_ne!(h.finalize(&[]), std_hash(&words[..16]));
    }
}
