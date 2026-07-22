//! Lock construction and lock-merkle-proof building for v1 spends.
//!
//! Mirrors the Hoon tx-engine's `lock` core: a note's lock root is
//! `hash:lock` over the lock's hashable tree, and a witness proves its
//! spend-condition is a branch of that tree with a merkle proof
//! (`build-lock-merkle-proof-{stub,full}` over
//! `prove-hashable-by-index:merkle`). Two consensus constraints shape
//! this module:
//!
//! - The stub proof form is only valid for a single-condition lock —
//!   `check:lock-merkle-proof-stub` hard-requires `axis == 1`, which
//!   only holds when the leaf is the root.
//! - A multi-branch lock therefore needs the full proof form, and
//!   `check-context` accepts `%full` proofs only at or after the
//!   bythos phase.

use nockchain_types::tx_engine::common::{FirstName, Hash};
use nockchain_types::tx_engine::v1::hashable::{HashHashable, hash_leaf_atom, hash_pair};
use nockchain_types::tx_engine::v1::tx::{
    Lock, LockMerkleProof, LockV2, MerkleProof, SpendCondition,
};

/// Two-branch lock for a work-bounty note.
///
/// Branch 1 is the payout spend-condition (a simple pkh). Branch 2
/// commits to the statement a future proof-verifying branch would
/// check: the commitment hash is rendered as a pkh no key hashes to,
/// so the branch is deliberately unspendable today. Swapping it for a
/// real verifying branch later changes the lock root on newly posted
/// notes — a lock change, not a tx-shape change.
pub fn bounty_lock(payout_pkh: Hash, statement_commitment: Hash) -> Lock {
    Lock::V2(LockV2 {
        p: SpendCondition::simple_pkh(payout_pkh),
        q: SpendCondition::simple_pkh(statement_commitment),
    })
}

/// Consensus lock root (`hash:lock`).
pub fn lock_root(lock: &Lock) -> anyhow::Result<Hash> {
    lock.hash_digest()
        .map_err(|e| anyhow::anyhow!("lock hash: {e:?}"))
}

/// v1 first-name for a note locked under `lock`:
/// `Tip5([leaf+%.y hash+lock-root])` (`new-v1:nname`).
pub fn first_name_for_lock(lock: &Lock) -> anyhow::Result<Hash> {
    let root = lock_root(lock)?;
    FirstName::from_lock_root(&root)
        .map(Hash::from)
        .map_err(|e| anyhow::anyhow!("first-name from lock root: {e:?}"))
}

/// Builds the witness's lock-merkle-proof for branch `leaf_number`
/// (1-based, mirroring `build-lock-merkle-proof-stub`'s traversal).
///
/// Single-condition locks get the trivial proof (axis 1, empty path):
/// stub form before the bythos phase, full form at or after it.
/// Two-branch (`Lock::V2`) locks are only provable with the full form,
/// so `height` must be at or past `bythos_phase`. The constructed
/// proof is folded back to the lock root before returning.
pub fn lock_merkle_proof(
    lock: &Lock,
    leaf_number: u64,
    height: u64,
    bythos_phase: u64,
) -> anyhow::Result<LockMerkleProof> {
    let root = lock_root(lock)?;
    let (spend_condition, axis, proof, full) = match lock {
        Lock::SpendCondition(sc) => {
            anyhow::ensure!(
                leaf_number == 1,
                "single-condition lock has only leaf 1 (got {leaf_number})"
            );
            let proof = MerkleProof { root, path: vec![] };
            (sc.clone(), 1u64, proof, height >= bythos_phase)
        }
        Lock::V2(v2) => {
            anyhow::ensure!(
                height >= bythos_phase,
                "a two-branch lock needs the full lock-merkle-proof form, which \
                 consensus accepts only at or after the bythos phase \
                 (height {height}, bythos {bythos_phase})"
            );
            let p_hash =
                v2.p.hash()
                    .map_err(|e| anyhow::anyhow!("branch-1 hash: {e:?}"))?;
            let q_hash =
                v2.q.hash()
                    .map_err(|e| anyhow::anyhow!("branch-2 hash: {e:?}"))?;
            let tag_hash =
                hash_leaf_atom(2).map_err(|e| anyhow::anyhow!("lock version-tag hash: {e:?}"))?;
            // The %2 lock's hashable tree is [leaf+2 [hash+p hash+q]];
            // `prove-hashable-by-index` yields leaf-to-root sibling paths.
            let (sc, axis, path) = match leaf_number {
                1 => (v2.p.clone(), 6u64, vec![q_hash, tag_hash]),
                2 => (v2.q.clone(), 7u64, vec![p_hash, tag_hash]),
                _ => anyhow::bail!("two-branch lock has leaves 1 and 2 (got {leaf_number})"),
            };
            let proof = MerkleProof { root, path };
            (sc, axis, proof, true)
        }
        Lock::V4(_) | Lock::V8(_) | Lock::V16(_) => {
            anyhow::bail!("only single-condition and two-branch locks are supported")
        }
    };

    let leaf_hash = spend_condition
        .hash()
        .map_err(|e| anyhow::anyhow!("spend-condition hash: {e:?}"))?;
    anyhow::ensure!(
        verify_merk_proof(&leaf_hash, axis, &proof),
        "constructed lock-merkle-proof does not fold back to the lock root"
    );

    Ok(if full {
        LockMerkleProof::new_full(spend_condition, axis, proof)
    } else {
        LockMerkleProof::new_stub(spend_condition, axis, proof)
    })
}

/// Rust mirror of `verify-merk-proof:merkle` (ztd): folds the leaf
/// digest up the sibling path by axis parity and compares the result
/// against the proof's root. The path runs leaf-to-root.
pub fn verify_merk_proof(leaf: &Hash, axis: u64, proof: &MerkleProof) -> bool {
    if axis == 0 {
        return false;
    }
    let mut axis = axis;
    let mut acc = leaf.clone();
    let mut path = proof.path.iter();
    loop {
        if axis == 1 {
            return acc == proof.root && path.next().is_none();
        }
        let Some(sib) = path.next() else {
            return false;
        };
        if axis.is_multiple_of(2) {
            acc = hash_pair(&acc, sib);
            axis /= 2;
        } else {
            acc = hash_pair(sib, &acc);
            axis = (axis - 1) / 2;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkh(n: u64) -> Hash {
        Hash::from_limbs(&[n, n + 1, n + 2, n + 3, n + 4])
    }

    #[test]
    fn two_branch_proofs_fold_to_the_lock_root() {
        let lock = bounty_lock(pkh(100), pkh(200));
        // Both branches build (the constructor self-checks the fold).
        let p1 = lock_merkle_proof(&lock, 1, 10, 1).expect("branch 1");
        let p2 = lock_merkle_proof(&lock, 2, 10, 1).expect("branch 2");
        assert!(matches!(p1, LockMerkleProof::Full(_)));
        assert_eq!(p1.axis(), 6);
        assert_eq!(p2.axis(), 7);
        assert_eq!(p1.proof().root, lock_root(&lock).unwrap());
        // A leaf presented at the sibling branch's axis must not verify.
        let p_leaf = p1.spend_condition().hash().unwrap();
        assert!(!verify_merk_proof(&p_leaf, 7, p1.proof()));
    }

    #[test]
    fn two_branch_lock_is_full_form_only() {
        let lock = bounty_lock(pkh(1), pkh(2));
        let err = lock_merkle_proof(&lock, 1, 0, 1).unwrap_err();
        assert!(err.to_string().contains("bythos"));
    }

    #[test]
    fn single_condition_lock_selects_stub_or_full_by_height() {
        let lock = Lock::SpendCondition(SpendCondition::simple_pkh(pkh(7)));
        let pre = lock_merkle_proof(&lock, 1, 0, 54_000).expect("pre-bythos");
        let post = lock_merkle_proof(&lock, 1, 54_000, 54_000).expect("post-bythos");
        assert!(matches!(pre, LockMerkleProof::Stub(_)));
        assert!(matches!(post, LockMerkleProof::Full(_)));
        assert_eq!(pre.axis(), 1);
        assert!(pre.proof().path.is_empty());
        assert_eq!(pre.proof().root, lock_root(&lock).unwrap());
    }

    #[test]
    fn first_name_matches_the_spend_condition_derivation() {
        // For a single-condition lock the upstream type exposes the same
        // derivation end to end; the helper must agree with it.
        let sc = SpendCondition::simple_pkh(pkh(42));
        let lock = Lock::SpendCondition(sc.clone());
        let via_helper = first_name_for_lock(&lock).unwrap();
        let via_upstream = Hash::from(sc.first_name().unwrap());
        assert_eq!(via_helper, via_upstream);
    }
}
