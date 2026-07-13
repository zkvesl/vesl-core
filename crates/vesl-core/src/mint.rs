//! Mint — Data Commitment (lightest tier)
//!
//! Commit data, get a root. No kernel boot required.
//! Pure math: tip5 Merkle tree construction and proof generation.

use nockchain_tip5_rs::{MerkleTree, ProofNode, Tip5Hash};

/// Errors from Mint operations.
#[derive(Debug)]
pub enum MintError {
    /// No tree committed — call `commit()` first.
    NoTree,
    /// Leaf index out of range for the committed tree.
    IndexOutOfRange { index: usize, leaf_count: usize },
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTree => write!(f, "no tree committed — call commit() first"),
            Self::IndexOutOfRange { index, leaf_count } => {
                write!(
                    f,
                    "leaf index {index} out of range (tree has {leaf_count} leaves)"
                )
            }
        }
    }
}

impl std::error::Error for MintError {}

pub struct Mint {
    tree: Option<MerkleTree>,
    leaf_count: usize,
}

impl Mint {
    /// Create a new Mint committer.
    pub fn new() -> Self {
        Mint {
            tree: None,
            leaf_count: 0,
        }
    }

    /// Commit a set of data chunks. Returns the Merkle root.
    /// Builds the tree internally and stores it for later proof generation.
    ///
    /// Panics if `data` is empty — committing zero chunks has no
    /// meaningful root. A caller handling untrusted input should check
    /// `!data.is_empty()` first, or use
    /// [`nockchain_tip5_rs::MerkleTree::build`] directly, which returns a
    /// typed [`nockchain_tip5_rs::MerkleTreeError`].
    pub fn commit(&mut self, data: &[&[u8]]) -> Tip5Hash {
        let tree = MerkleTree::build(data).expect("Mint::commit requires a non-empty data set");
        let root = tree.root();
        self.leaf_count = data.len();
        self.tree = Some(tree);
        root
    }

    /// Generate a Merkle proof for a specific leaf index.
    pub fn proof(&self, index: usize) -> Result<Vec<ProofNode>, MintError> {
        let tree = self.tree.as_ref().ok_or(MintError::NoTree)?;
        if index >= self.leaf_count {
            return Err(MintError::IndexOutOfRange {
                index,
                leaf_count: self.leaf_count,
            });
        }
        // The index is bounds-checked above, so MerkleTree::proof cannot
        // fail here; map its (unreachable) error back to MintError anyway.
        tree.proof(index).map_err(|_| MintError::IndexOutOfRange {
            index,
            leaf_count: self.leaf_count,
        })
    }

    /// Get the current root, or None if nothing committed yet.
    pub fn root(&self) -> Option<Tip5Hash> {
        self.tree.as_ref().map(|t| t.root())
    }
}

impl Default for Mint {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use nockchain_tip5_rs::verify_proof;

    use super::*;

    #[test]
    fn commit_and_prove_single_leaf() {
        let mut mint = Mint::new();
        let data: &[&[u8]] = &[b"hello world"];
        let root = mint.commit(data);

        assert!(mint.root().is_some());
        assert_eq!(mint.root().unwrap(), root);

        let proof = mint.proof(0).unwrap();
        assert!(verify_proof(b"hello world", &proof, &root));
    }

    #[test]
    fn commit_and_prove_multiple_leaves() {
        let mut mint = Mint::new();
        let chunks: Vec<&[u8]> = vec![b"alpha", b"bravo", b"charlie", b"delta"];
        let root = mint.commit(&chunks);

        for (i, chunk) in chunks.iter().enumerate() {
            let proof = mint.proof(i).unwrap();
            assert!(verify_proof(chunk, &proof, &root), "failed at leaf {i}");
        }
    }

    #[test]
    fn tampered_data_fails_verification() {
        let mut mint = Mint::new();
        let root = mint.commit(&[b"real data"]);
        let proof = mint.proof(0).unwrap();

        assert!(!verify_proof(b"fake data", &proof, &root));
    }

    #[test]
    fn root_is_none_before_commit() {
        let mint = Mint::new();
        assert!(mint.root().is_none());
    }

    #[test]
    fn recommit_replaces_tree() {
        let mut mint = Mint::new();
        let root1 = mint.commit(&[b"v1"]);
        let root2 = mint.commit(&[b"v2"]);
        assert_ne!(root1, root2);
        assert_eq!(mint.root().unwrap(), root2);
    }
}
