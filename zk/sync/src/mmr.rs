//! Raito's Merkle Mountain Range of block hashes (`utils::mmr`), and inclusion proofs.
//!
//! The accumulator keeps one root per height (`None` for a gap) and always ends in
//! `None`. Adding a leaf carries it up through the occupied heights, each time hashing
//! `hash_pair(older_root, node)`, so a perfect subtree's parent is `hash(left, right)` with
//! the earlier leaves on the left.

use crate::digest::{hash_pair, Blake2sHasher, Digest};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mmr {
    roots: Vec<Option<Digest>>,
}

impl Default for Mmr {
    fn default() -> Self { Mmr { roots: vec![None] } }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MmrError {
    /// Roots must end in `None`, as Cairo's `MMRTrait::add` and `new` leave them.
    MissingTrailingNone,
    LeafCountMismatch { proof: u64, mmr: u64 },
    IndexOutOfRange,
    WrongPathLength { expected: usize, got: usize },
    RootMismatch,
}

impl Mmr {
    pub fn from_roots(roots: Vec<Option<Digest>>) -> Result<Self, MmrError> {
        match roots.last() {
            Some(None) => Ok(Mmr { roots }),
            _ => Err(MmrError::MissingTrailingNone),
        }
    }

    pub fn roots(&self) -> &[Option<Digest>] { &self.roots }

    pub fn leaf_count(&self) -> u64 {
        self.roots.iter().enumerate().filter(|(_, r)| r.is_some()).map(|(h, _)| 1u64 << h).sum()
    }

    /// `MMRTrait::add`.
    pub fn add(&self, leaf: Digest) -> Mmr {
        let mut new_roots = Vec::with_capacity(self.roots.len() + 1);
        let mut first_none_found = false;
        let mut node = leaf;
        for root in &self.roots {
            if !first_none_found {
                match root {
                    Some(root) => {
                        node = hash_pair(root, &node);
                        new_roots.push(None);
                    }
                    None => {
                        first_none_found = true;
                        new_roots.push(Some(node));
                    }
                }
            } else {
                new_roots.push(*root);
            }
        }
        if new_roots.last().is_some_and(|r| r.is_some()) {
            new_roots.push(None);
        }
        Mmr { roots: new_roots }
    }

    /// `MMRTrait::blake2s_digest`, block for block: roots in pairs, a gap as zeros.
    ///
    /// When the number of roots is odd, Cairo hashes zeros in place of the last root
    /// without reading it. That is only a commitment to the whole MMR because the last
    /// root is always `None`; `Mmr` keeps that invariant, and `chain_segment` asserts it
    /// on its input (without the check, a prover could put any subtree in that slot).
    pub fn digest(&self) -> Digest {
        let words = |r: &Option<Digest>| r.unwrap_or_default().0;
        let mut hasher = Blake2sHasher::new();
        let mut pairs = self.roots.chunks_exact(2).peekable();
        let odd = self.roots.len() % 2 == 1;
        while let Some(pair) = pairs.next() {
            let mut block = [0u32; 16];
            block[..8].copy_from_slice(&words(&pair[0]));
            block[8..].copy_from_slice(&words(&pair[1]));
            if pairs.peek().is_none() && !odd {
                return hasher.finalize_block(block, 64);
            }
            hasher.compress_block(block);
        }
        hasher.finalize_block([0; 16], 32)
    }

    /// Check that `leaf` is leaf number `proof.leaf_index` of this accumulator.
    pub fn verify(&self, leaf: &Digest, proof: &InclusionProof) -> Result<(), MmrError> {
        let n = self.leaf_count();
        if proof.leaf_count != n {
            return Err(MmrError::LeafCountMismatch { proof: proof.leaf_count, mmr: n });
        }
        let (height, local) = locate(n, proof.leaf_index).ok_or(MmrError::IndexOutOfRange)?;
        if proof.siblings.len() != height as usize {
            return Err(MmrError::WrongPathLength { expected: height as usize, got: proof.siblings.len() });
        }
        let mut node = *leaf;
        for (j, sibling) in proof.siblings.iter().enumerate() {
            node = if (local >> j) & 1 == 1 { hash_pair(sibling, &node) } else { hash_pair(&node, sibling) };
        }
        match self.roots.get(height as usize) {
            Some(Some(root)) if *root == node => Ok(()),
            _ => Err(MmrError::RootMismatch),
        }
    }
}

/// Which peak holds leaf `index` of an `n`-leaf MMR, and its index inside that peak.
/// Peaks are filled from the highest: the first `2^h_max` leaves form the highest one.
fn locate(n: u64, index: u64) -> Option<(u32, u64)> {
    if index >= n {
        return None;
    }
    let mut offset = 0u64;
    for h in (0..64u32).rev() {
        if n & (1 << h) != 0 {
            if index < offset + (1 << h) {
                return Some((h, index - offset));
            }
            offset += 1 << h;
        }
    }
    None
}

/// Path from a leaf to its peak: siblings bottom-up.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<Digest>,
}

/// All leaves, for whoever serves inclusion proofs (a full node, not the light client).
#[derive(Default, Clone)]
pub struct MmrTree {
    leaves: Vec<Digest>,
}

impl MmrTree {
    pub fn push(&mut self, leaf: Digest) { self.leaves.push(leaf); }

    pub fn len(&self) -> u64 { self.leaves.len() as u64 }

    pub fn is_empty(&self) -> bool { self.leaves.is_empty() }

    pub fn proof(&self, index: u64) -> Option<InclusionProof> {
        let n = self.len();
        let (height, local) = locate(n, index)?;
        let start = (index - local) as usize;
        let mut level: Vec<Digest> = self.leaves[start..start + (1usize << height)].to_vec();
        let mut pos = local as usize;
        let mut siblings = Vec::with_capacity(height as usize);
        for _ in 0..height {
            siblings.push(level[pos ^ 1]);
            level = level.chunks_exact(2).map(|p| hash_pair(&p[0], &p[1])).collect();
            pos >>= 1;
        }
        Some(InclusionProof { leaf_index: index, leaf_count: n, siblings })
    }
}
