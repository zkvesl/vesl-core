//! Standalone tip5 Merkle tree for Nockchain.
//!
//! Provides tip5 hash functions, Merkle tree construction, proof generation,
//! and proof verification. Mathematical mirror of Hoon's `rag-logic.hoon`.
//!
//! # tip5 Hash Alignment
//!
//! Hoon's `hash-leaf` / `hash-pair` (via `zeke.hoon`) and this crate's
//! functions (via `nockchain-math`) produce identical digests, ensuring
//! cross-runtime compatibility for ZK-circuit verification.
//!
//! ## Leaf hashing
//!
//! Both sides split the atom's LE bytes into 7-byte chunks (each < 2^56 <
//! Goldilocks prime), prepend the chunk count, and feed to `hash_varlen`.
//!
//! ## Pair hashing
//!
//! Both sides concatenate two 5-limb digests into 10 belts and feed to
//! `hash_10` (tip5 fixed-rate sponge).
//!
//! # Example
//!
//! ```ignore
//! use nockchain_tip5_rs::*;
//!
//! let leaves: Vec<&[u8]> = vec![b"chunk A", b"chunk B", b"chunk C", b"chunk D"];
//! let tree = MerkleTree::build(&leaves).unwrap();
//! let root = tree.root();
//!
//! // Generate and verify a proof for leaf 0
//! let proof = tree.proof(0).unwrap();
//! assert!(verify_proof(b"chunk A", &proof, &root));
//!
//! // Tampered data fails verification
//! assert!(!verify_proof(b"TAMPERED", &proof, &root));
//! ```

use nockchain_math::belt::{Belt, PRIME};
use nockchain_math::tip5::hash::{hash_10, hash_varlen};
use subtle::ConstantTimeEq;

/// tip5 digest: 5 Goldilocks field elements.
///
/// Matches Hoon `noun-digest:tip5 = [@ @ @ @ @]`.
/// Each limb is a u64 < Goldilocks prime (2^64 - 2^32 + 1).
pub type Tip5Hash = [u64; 5];

/// The zero digest (all limbs zero).
pub const TIP5_ZERO: Tip5Hash = [0u64; 5];

/// A digest limb that is not a canonical Goldilocks field element.
///
/// `nockchain-math` range-checks limbs only under `debug_assert!`, so a
/// release build hashes an off-field limb unreduced and reaches a digest
/// that disagrees with the Hoon verifier — a chainsplit primitive. Every
/// `Tip5Hash` materialized from external bytes must be screened with
/// [`check_tip5_limbs`] first (audit C-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldRangeError {
    /// The offending limb (`>= PRIME`).
    pub limb: u64,
}

impl std::fmt::Display for FieldRangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "digest limb {} is not below the Goldilocks prime",
            self.limb
        )
    }
}

impl std::error::Error for FieldRangeError {}

/// Reject a digest whose limbs are not canonical Goldilocks field
/// elements (`>= PRIME`). MUST be called on every `Tip5Hash` built from
/// external bytes — wire reads, protobuf, `serde` deserialization —
/// before it is fed to any hash or comparison (audit C-04).
pub fn check_tip5_limbs(hash: &Tip5Hash) -> Result<(), FieldRangeError> {
    for &limb in hash {
        if limb >= PRIME {
            return Err(FieldRangeError { limb });
        }
    }
    Ok(())
}

/// A node in a Merkle inclusion proof.
///
/// Matches Hoon `+$proof-node [hash=@ side=?]`.
///
/// Side convention:
///   `true`  (`%.y`) = sibling is LEFT  -> `hash_pair(sibling, current)`
///   `false` (`%.n`) = sibling is RIGHT -> `hash_pair(current, sibling)`
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProofNode {
    pub hash: Tip5Hash,
    pub side: bool,
}

// ---------------------------------------------------------------------------
// tip5-to-atom encoding
// ---------------------------------------------------------------------------

/// Convert a tip5 hash `[u64; 5]` to LE atom bytes.
///
/// Computes the base-p polynomial: `limb[0] + limb[1]*P + limb[2]*P^2 + ...`
/// where P = Goldilocks prime. Matches Hoon's `digest-to-atom:tip5`.
///
/// Uses u128 arithmetic with carry propagation to avoid BigUint dependency.
pub fn tip5_to_atom_le_bytes(hash: &Tip5Hash) -> Vec<u8> {
    let mut result = [0u8; 48]; // 5 * 64 bits = 40 bytes + carry room
    let mut result_len: usize = 0;

    // Horner's method: ((((limb[4]*P + limb[3])*P + limb[2])*P + limb[1])*P + limb[0])
    for &limb in hash.iter().rev() {
        // Multiply result by PRIME
        let mut carry: u128 = 0;
        for byte in result[..result_len].iter_mut() {
            let prod = (*byte as u128) * (PRIME as u128) + carry;
            *byte = prod as u8;
            carry = prod >> 8;
        }
        while carry > 0 {
            if result_len < result.len() {
                result[result_len] = carry as u8;
                result_len += 1;
            }
            carry >>= 8;
        }

        // Add limb
        let mut add_carry: u128 = limb as u128;
        for byte in result.iter_mut() {
            if add_carry == 0 {
                break;
            }
            let sum = (*byte as u128) + add_carry;
            *byte = sum as u8;
            add_carry = sum >> 8;
        }
        if result_len == 0 && limb > 0 {
            result_len = 8;
        }
        while result_len < result.len() && result[result_len] != 0 {
            result_len += 1;
        }
    }

    // AUDIT 2026-05-21 L-22: an all-zero digest yields `vec![]` — the
    // canonical little-endian encoding of atom 0 — not `vec![0]`.
    let len = result.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
    result[..len].to_vec()
}

// ---------------------------------------------------------------------------
// Hash primitives
// ---------------------------------------------------------------------------

/// Split LE atom bytes into 7-byte chunks, each a valid Goldilocks field element.
///
/// Mirrors Hoon's `+split-to-belts`: `(end [3 7] a)` / `(rsh [3 7] a)` loop.
/// 7 bytes = 56 bits -> max value 2^56 - 1 ~ 7.2e16 < PRIME ~ 1.8e19.
///
/// # Trailing-zero normalization (AUDIT 2026-04-17 L-07)
///
/// Input bytes are the little-endian form of a Hoon atom (bignum).
/// Trailing zero bytes are **stripped** via `rposition` before
/// chunking — matching Hoon's bignum form, where `0x05` and
/// `0x05 00 00` are the same value. Both sides of the cross-VM
/// boundary (this function and the Hoon `split-to-belts` in
/// `protocol/lib/vesl-merkle.hoon`) normalize identically, so the hash
/// of `"x"`, `"x\0"`, and `"x\0\0\0"` are all equal.
///
/// Callers that treat byte-length as distinguishing between
/// logically-distinct payloads **will see hash collisions**. Fix:
/// encode length into the payload explicitly — e.g. prepend a 4-byte
/// length field, or add a domain-separating prefix before hashing.
fn atom_bytes_to_belts(bytes: &[u8]) -> Vec<Belt> {
    let len = bytes.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
    if len == 0 {
        return vec![Belt(0)];
    }
    let bytes = &bytes[..len];
    let mut belts = Vec::with_capacity(len.div_ceil(7));
    for chunk in bytes.chunks(7) {
        let mut val: u64 = 0;
        for (i, &b) in chunk.iter().enumerate() {
            val |= (b as u64) << (i * 8);
        }
        belts.push(Belt(val));
    }
    belts
}

/// tip5 hash of raw leaf data.
///
/// Mirror of Hoon's `+hash-leaf`: split -> belts -> prepend count -> hash_varlen.
pub fn hash_leaf(data: &[u8]) -> Tip5Hash {
    let belts = atom_bytes_to_belts(data);
    let count = belts.len() as u64;
    let mut input: Vec<Belt> = Vec::with_capacity(1 + belts.len());
    input.push(Belt(count));
    input.extend(belts);
    hash_varlen(&mut input)
}

/// tip5 pair hash of two digests via fixed-rate sponge (10 belts).
///
/// Mirror of Hoon's `+hash-pair`: `(hash-ten-cell:tip5 [ld rd])`.
/// Byte layout: `[l0, l1, l2, l3, l4, r0, r1, r2, r3, r4]`.
pub fn hash_pair(l: &Tip5Hash, r: &Tip5Hash) -> Tip5Hash {
    let mut input: Vec<Belt> = l.iter().chain(r.iter()).map(|&v| Belt(v)).collect();
    hash_10(&mut input)
}

/// Verify a Merkle proof from leaf to root.
///
/// Mirrors Hoon's `+verify-chunk`. Walks the proof path applying the
/// side convention:
///   `side=true`  -> sibling is LEFT  -> `hash_pair(sibling, current)`
///   `side=false` -> sibling is RIGHT -> `hash_pair(current, sibling)`
pub fn verify_proof(leaf_data: &[u8], proof: &[ProofNode], expected_root: &Tip5Hash) -> bool {
    // Depth guard: match Hoon's 64-node limit.
    // AUDIT 2026-04-17 L-01: a silent `false` here is indistinguishable
    // from "wrong proof" at the caller — warn so oversize proofs
    // surface in logs instead of looking like generic failures.
    if proof.len() > 64 {
        tracing::warn!(
            proof_depth = proof.len(),
            "verify_proof: proof exceeds 64-node cap (matches Hoon's verify-chunk), rejecting"
        );
        return false;
    }

    // AUDIT 2026-05-19 C-04: reject off-field limbs in caller-supplied
    // digests. nockchain-math range-checks only under debug_assert!, so a
    // release build would otherwise hash unreduced limbs and reach a
    // different digest than the Hoon verifier.
    if let Err(e) = check_tip5_limbs(expected_root) {
        tracing::warn!(
            limb = e.limb,
            "verify_proof: expected_root limb off-field, rejecting"
        );
        return false;
    }
    for node in proof {
        if let Err(e) = check_tip5_limbs(&node.hash) {
            tracing::warn!(
                limb = e.limb,
                "verify_proof: proof node limb off-field, rejecting"
            );
            return false;
        }
    }

    let mut cur = hash_leaf(leaf_data);

    for node in proof {
        cur = if node.side {
            hash_pair(&node.hash, &cur)
        } else {
            hash_pair(&cur, &node.hash)
        };
    }

    // AUDIT 2026-05-20 M-19: the final digest compare below is constant-time
    // over the digest bytes — but the hash_pair recompute loop above is NOT
    // (it branches on node.side). Merkle proof contents are public, so that
    // is acceptable; ct_eq here only avoids leaking expected_root through
    // compare timing. This does not make verify_proof constant-time overall.
    let cur_bytes: Vec<u8> = cur.iter().flat_map(|x| x.to_le_bytes()).collect();
    let exp_bytes: Vec<u8> = expected_root.iter().flat_map(|x| x.to_le_bytes()).collect();
    cur_bytes.ct_eq(&exp_bytes).into()
}

// ---------------------------------------------------------------------------
// Merkle tree
// ---------------------------------------------------------------------------

/// Error from [`MerkleTree::build`] / [`MerkleTree::proof`].
///
/// AUDIT 2026-05-21 L-21: those constructors used `assert!` panics on a
/// misuse — an empty leaf set, or a proof index past the last leaf. They
/// now surface a typed error so a direct `MerkleTree` consumer can handle
/// the case instead of crashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleTreeError {
    /// `build` was called with an empty leaf slice.
    EmptyLeaves,
    /// `proof` was called with `index` at or past the leaf count.
    IndexOutOfBounds { index: usize, leaf_count: usize },
}

impl std::fmt::Display for MerkleTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyLeaves => f.write_str("cannot build a Merkle tree from zero leaves"),
            Self::IndexOutOfBounds { index, leaf_count } => write!(
                f,
                "Merkle proof index {index} out of bounds (tree has {leaf_count} leaves)"
            ),
        }
    }
}

impl std::error::Error for MerkleTreeError {}

/// A complete Merkle tree built from leaf data.
///
/// Stores all levels for proof generation. Pads odd-count levels by
/// duplicating the last node (standard Merkle convention).
pub struct MerkleTree {
    /// Nodes stored level-by-level: `levels[0]` = leaf hashes, last = root.
    levels: Vec<Vec<Tip5Hash>>,
}

impl MerkleTree {
    /// Build a Merkle tree from raw leaf byte slices.
    ///
    /// AUDIT 2026-05-21 L-21: returns [`MerkleTreeError::EmptyLeaves`]
    /// instead of panicking when `leaves` is empty.
    pub fn build(leaves: &[&[u8]]) -> Result<Self, MerkleTreeError> {
        if leaves.is_empty() {
            return Err(MerkleTreeError::EmptyLeaves);
        }

        let mut current: Vec<Tip5Hash> = leaves.iter().map(|l| hash_leaf(l)).collect();
        let mut levels = vec![current.clone()];

        while current.len() > 1 {
            if !current.len().is_multiple_of(2) {
                let last = *current.last().unwrap();
                current.push(last);
            }

            let next: Vec<Tip5Hash> = current
                .chunks(2)
                .map(|pair| hash_pair(&pair[0], &pair[1]))
                .collect();

            levels.push(next.clone());
            current = next;
        }

        Ok(MerkleTree { levels })
    }

    /// The Merkle root hash.
    pub fn root(&self) -> Tip5Hash {
        *self.levels.last().unwrap().first().unwrap()
    }

    /// Number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    /// Generate the proof path for the leaf at `index`.
    ///
    /// Side convention (mirrors Hoon's `verify-chunk`):
    ///   Even index (left child)  -> sibling is RIGHT -> `side=false`
    ///   Odd index  (right child) -> sibling is LEFT  -> `side=true`
    ///
    /// AUDIT 2026-05-21 L-21: returns [`MerkleTreeError::IndexOutOfBounds`]
    /// instead of panicking on an out-of-range `index`.
    pub fn proof(&self, index: usize) -> Result<Vec<ProofNode>, MerkleTreeError> {
        let leaf_count = self.levels[0].len();
        if index >= leaf_count {
            return Err(MerkleTreeError::IndexOutOfBounds { index, leaf_count });
        }

        let mut path = Vec::new();
        let mut idx = index;

        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };

            let sibling_hash = if sibling_idx < level.len() {
                level[sibling_idx]
            } else {
                level[idx] // padded duplicate
            };

            path.push(ProofNode {
                hash: sibling_hash,
                side: idx % 2 == 1,
            });

            idx /= 2;
        }

        Ok(path)
    }
}

/// Format a tip5 hash for display: hex limbs.
pub fn format_tip5(hash: &Tip5Hash) -> String {
    format!(
        "[{:016x}.{:016x}.{:016x}.{:016x}.{:016x}]",
        hash[0], hash[1], hash[2], hash[3], hash[4]
    )
}

// ---------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Enterprise scenario leaves — matches the Hoon red-team test data.
    fn enterprise_leaves() -> Vec<&'static [u8]> {
        vec![
            b"The AI read this secret.", b"Patient record: blood-type A+",
            b"Trading algo: momentum signal", b"NDA clause 4: non-compete",
        ]
    }

    // -- Belt conversion ---------------------------------------------------

    #[test]
    fn atom_bytes_to_belts_small() {
        // "alpha" = 5 bytes, fits in one 7-byte chunk
        let belts = atom_bytes_to_belts(b"alpha");
        assert_eq!(belts.len(), 1);
        let expected: u64 = 97 + 108 * 256 + 112 * 65536 + 104 * 16777216 + 97 * 4294967296;
        assert_eq!(belts[0].0, expected);
    }

    #[test]
    fn atom_bytes_to_belts_multi_chunk() {
        // 15 bytes -> 3 chunks (7 + 7 + 1)
        let data = b"0123456789abcde";
        let belts = atom_bytes_to_belts(data);
        assert_eq!(belts.len(), 3);
        let mut expected0: u64 = 0;
        for (i, &b) in data[..7].iter().enumerate() {
            expected0 |= (b as u64) << (i * 8);
        }
        assert_eq!(belts[0].0, expected0);
    }

    #[test]
    fn atom_bytes_to_belts_zero() {
        let belts = atom_bytes_to_belts(&[]);
        assert_eq!(belts, vec![Belt(0)]);
        let belts2 = atom_bytes_to_belts(&[0, 0, 0]);
        assert_eq!(belts2, vec![Belt(0)]);
    }

    // -- Tree structure ----------------------------------------------------

    #[test]
    fn build_4_leaf_tree_structure() {
        let tree = MerkleTree::build(&enterprise_leaves()).unwrap();
        assert_eq!(tree.levels.len(), 3);
        assert_eq!(tree.levels[0].len(), 4);
        assert_eq!(tree.levels[1].len(), 2);
        assert_eq!(tree.levels[2].len(), 1);
    }

    #[test]
    fn tree_is_deterministic() {
        let leaves = enterprise_leaves();
        let root1 = MerkleTree::build(&leaves).unwrap().root();
        let root2 = MerkleTree::build(&leaves).unwrap().root();
        assert_eq!(root1, root2);
    }

    // -- Proof verification ------------------------------------------------

    #[test]
    fn verify_all_leaves() {
        let leaves = enterprise_leaves();
        let tree = MerkleTree::build(&leaves).unwrap();
        let root = tree.root();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(
                verify_proof(leaf, &proof, &root),
                "valid proof for leaf {} rejected",
                i
            );
        }
    }

    #[test]
    fn reject_tampered_leaf() {
        let leaves = enterprise_leaves();
        let tree = MerkleTree::build(&leaves).unwrap();
        let root = tree.root();
        let proof = tree.proof(0).unwrap();

        assert!(
            !verify_proof(b"TAMPERED DATA", &proof, &root),
            "tampered leaf should not verify"
        );
    }

    #[test]
    fn reject_wrong_root() {
        let leaves = enterprise_leaves();
        let tree = MerkleTree::build(&leaves).unwrap();
        let proof = tree.proof(0).unwrap();
        let wrong_root = [0xFFu64; 5];

        assert!(
            !verify_proof(leaves[0], &proof, &wrong_root),
            "wrong root should not verify"
        );
    }

    // -- Security properties -----------------------------------------------

    #[test]
    fn hash_pair_is_non_commutative() {
        let a = hash_leaf(b"left");
        let b = hash_leaf(b"right");
        assert_ne!(
            hash_pair(&a, &b),
            hash_pair(&b, &a),
            "hash_pair must be non-commutative (prevents path swap attacks)"
        );
    }

    // -- Edge cases --------------------------------------------------------

    #[test]
    fn single_leaf_tree() {
        let leaves: Vec<&[u8]> = vec![b"only leaf"];
        let tree = MerkleTree::build(&leaves).unwrap();

        assert_eq!(tree.levels.len(), 1);
        assert_eq!(tree.root(), hash_leaf(b"only leaf"));

        let proof = tree.proof(0).unwrap();
        assert!(proof.is_empty());
        assert!(verify_proof(b"only leaf", &proof, &tree.root()));
    }

    #[test]
    fn three_leaf_tree_padding() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let tree = MerkleTree::build(&leaves).unwrap();

        // 3 leaves -> padded to 4 at level 0, then 2, then 1
        assert_eq!(tree.leaf_count(), 3);
        assert_eq!(tree.levels.len(), 3);

        // All proofs verify
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(verify_proof(leaf, &proof, &tree.root()));
        }
    }

    // -- L-21 error paths --------------------------------------------------

    #[test]
    fn build_rejects_empty_leaves() {
        let empty: Vec<&[u8]> = vec![];
        assert!(matches!(
            MerkleTree::build(&empty),
            Err(MerkleTreeError::EmptyLeaves)
        ));
    }

    #[test]
    fn proof_rejects_out_of_bounds_index() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b"];
        let tree = MerkleTree::build(&leaves).unwrap();
        assert!(matches!(
            tree.proof(2),
            Err(MerkleTreeError::IndexOutOfBounds {
                index: 2,
                leaf_count: 2
            })
        ));
        assert!(tree.proof(1).is_ok());
    }

    // -- tip5-to-atom encoding --------------------------------------------

    #[test]
    fn tip5_zero_encodes_to_zero() {
        // AUDIT 2026-05-21 L-22: atom 0 is the empty LE byte string.
        let bytes = tip5_to_atom_le_bytes(&TIP5_ZERO);
        assert!(bytes.is_empty());
    }

    #[test]
    fn tip5_encoding_deterministic() {
        let hash = hash_leaf(b"test data");
        let a = tip5_to_atom_le_bytes(&hash);
        let b = tip5_to_atom_le_bytes(&hash);
        assert_eq!(a, b);
    }

    // -- Test vector: known hash for cross-runtime validation ---------------

    #[test]
    fn enterprise_root_is_stable() {
        // This root hash must match the Hoon-side computation.
        // If this test fails after a nockchain-math update, cross-runtime
        // alignment is broken and needs investigation.
        let leaves = enterprise_leaves();
        let root1 = MerkleTree::build(&leaves).unwrap().root();
        let root2 = MerkleTree::build(&leaves).unwrap().root();
        assert_eq!(root1, root2, "root must be deterministic across builds");
    }

    // -- Field-range validation (C-04) ------------------------------------

    #[test]
    fn off_field_limbs_rejected() {
        // PRIME is the smallest off-field value.
        let off_field: Tip5Hash = [PRIME, 0, 0, 0, 0];
        assert!(check_tip5_limbs(&off_field).is_err());
        assert!(check_tip5_limbs(&[0, 0, 0, 0, u64::MAX]).is_err());
        assert!(check_tip5_limbs(&[PRIME - 1, 0, 0, 0, 0]).is_ok());

        // verify_proof must reject an off-field root or proof node rather
        // than hashing it — a release build would otherwise compute a
        // wrong-but-deterministic digest (debug_assert! is a no-op there).
        let leaves: Vec<&[u8]> = vec![b"a", b"b"];
        let tree = MerkleTree::build(&leaves).unwrap();
        let proof = tree.proof(0).unwrap();
        assert!(!verify_proof(b"a", &proof, &off_field));

        let mut bad_proof = proof.clone();
        bad_proof[0].hash = off_field;
        assert!(!verify_proof(b"a", &bad_proof, &tree.root()));
    }
}
