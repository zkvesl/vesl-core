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
    Lock, LockMerkleProof, LockPrimitive, LockV2, MerkleProof, Pkh, SpendCondition,
};

/// Two-branch lock for a work-bounty note.
///
/// Branch 1 is the settle spend-condition (a simple pkh). Branch 2
/// commits to the statement a future proof-verifying branch would
/// check: the commitment hash is rendered as a pkh no key hashes to,
/// so the branch is deliberately unspendable today. Swapping it for a
/// real verifying branch later changes the lock root on newly posted
/// notes — a lock change, not a tx-shape change.
///
/// ⛔⛔ **`payout_pkh` IS THE MINER'S KEY, NOT THE PLATFORM'S.** Until
/// 2026-08-25 the escrow was posted at job-posting time, before any
/// miner existed, so branch 1 could only pin a deploy constant — and a
/// settling miner had to ask the platform's key to sign the spend it had
/// itself composed. The escrow is now created AFTER the hand-in check,
/// bound to the miner who served, so this argument is the pkh the miner
/// declared inside what it signed, and the miner alone can spend.
///
/// ⛔ **THE DESTINATION HAS THREE CONJUNCTS HERE, AND THIS SHIPS ONE.**
/// The intended settle condition is `[%pkh miner] ∧ [%zkp statement] ∧ [%tim
/// before D]`; `SpendCondition` really is an AND-list upstream, so the
/// shape is expressible — but `%zkp` is not a lock primitive
/// (`+lock-primitive` is a four-way `$%`: `%pkh %tim %hax %brn`,
/// `nockchain/hoon/common/tx-engine-1.hoon:1516-1526`), and neither the
/// deadline `D` nor the refund-key holder is decided. So the statement
/// stays on branch 2 as an unspendable placeholder and the timelock is
/// absent. Named successor: the `%zkp` conjunct when the primitive lands,
/// the `%tim` pair when `D` and the refund key are decided.
/// ⛔ Do not add a second `%pkh` conjunct to close the gap in the
/// meantime — two `%pkh`s in one AND-list are UNSATISFIABLE, because
/// `check:pkh` demands the whole witness map equal its own `m`
/// (`tx-engine-1.hoon:2064-2081`).
pub fn bounty_lock(payout_pkh: Hash, statement_commitment: Hash) -> Lock {
    Lock::V2(LockV2 {
        p: SpendCondition::simple_pkh(payout_pkh),
        q: SpendCondition::simple_pkh(statement_commitment),
    })
}

/// A `%pkh` conjunct that cannot be built in either shape the chain accepts
/// but nobody can use.
///
/// ⚑ *In plain terms: "needs N of these signatures" has two ways of being
/// nonsense — asking for none, and asking for more than were supplied. The
/// chain accepts both and they behave very differently from what they read
/// like, so they are refused here instead.*
///
/// ⛔⛔ **`m = 0` IS SATISFIED BY AN EMPTY WITNESS — a branch anyone can
/// spend, with no signature at all.** · VERIFIED against the chain's own
/// source: `check:pkh`'s count clause is an EQUALITY (`:2069`,
/// `=(m.form ~(wyt z-by pkh.witness.ctx))`) and `wyt` of an empty `z-by` is
/// `0` (`zoon.hoon:299`); the permitted-set clause (`:2071`) is
/// `∅ \ h = ∅`, which **never inspects `h` at all**; `~(rep z-by ~)` returns
/// its bunted accumulator and the bunt of `?` is `%.y` (`zoon.hoon:220`); and
/// `batch-verify` is `(levy batch verify)` (`ztd/three.hoon:1833-1837`),
/// `%.y` on `~`. The Rust mirror agrees, by the same equality
/// (`vesl-labs/services/chain/src/lock_check.rs`, `check_pkh`).
///
/// ⛔ **`m > |distinct members|` is the mirror image**: unsatisfiable by
/// anyone. `ZSet` deduplicates **silently**, so passing one key twice for a
/// 2-of-2 yields a one-element set still demanding two entries drawn from it.
/// The message names how many collapsed, because the caller supplied two
/// things and got one.
///
/// ⚑ Every `%pkh` in [`crate::job_locks`] goes through here. It is `pub` so future
/// lock shapes cannot reintroduce either case by calling `Pkh::new` directly.
pub fn pkh_conjunct(m: u64, members: Vec<Hash>) -> anyhow::Result<LockPrimitive> {
    let supplied = members.len();
    let pkh = Pkh::new(m, members);
    let distinct = pkh.hashes.iter().count();
    if m == 0 {
        anyhow::bail!(
            "a %pkh conjunct with m = 0 is satisfied by an EMPTY witness — the count \
             check is an equality (0 == 0), the permitted-set check never inspects the \
             set, the fold returns its bunted %.y and batch-verify is levy over ~. A \
             zero-threshold branch is spendable by anyone with no signature at all. \
             Refusing to build one."
        );
    }
    if (distinct as u64) < m {
        anyhow::bail!(
            "a %pkh conjunct demands {m} signature(s) from a set of {distinct} distinct \
             key(s) ({supplied} supplied, so {} collapsed through the z-set's silent \
             dedup): check:pkh requires exactly m witness entries drawn from that set, \
             so this branch is unsatisfiable by anyone. Refusing to build it.",
            supplied - distinct
        );
    }
    Ok(LockPrimitive::Pkh(pkh))
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
/// ⭐ **ONE rule for every arity.** A lock's hashable is
/// `[leaf+N <perfect binary tree of the N branch digests>]` for `N ∈
/// {2,4,8,16}`, and a bare spend-condition for `N = 1`
/// (`tx-engine-1.hoon:1719-1760`). `prove-hashable-by-index` therefore
/// puts leaf `k` (1-based) at
///
/// ```text
/// axis  = 3·N + (k − 1)                 (axis 1 when N = 1)
/// path  = log2(N) in-subtree siblings, leaf-first,
///         then hash_leaf_atom(N) — the arity tag is a sibling too
/// ```
///
/// so `|path| = log2(N) + 1`. ⛔ `docs/architecture/tx-engine/
/// 03-taproot-lock-merkle-proofs.md:169` says `log2(N)` and is **wrong**;
/// sizing the path from that doc drops the tag and the fold misses the
/// root. Checked against the shipped two-branch numbers, which fall out
/// of the same formula rather than surviving as a special case: `3·2 + 0
/// = 6` and `3·2 + 1 = 7`.
///
/// ⚑ The arity tag is `hash_leaf_atom(N)` — the **branch count**, not a
/// literal `2`. That distinction is invisible while only `V2` is built.
///
/// Single-condition locks get the trivial proof (axis 1, empty path):
/// stub form before the bythos phase, full form at or after it. Every
/// multi-branch lock needs the full form, because `check:lock-merkle-
/// proof` hard-requires `axis == 1` of a stub (`tx-engine-1.hoon:2022`)
/// and no multi-branch leaf has axis 1 — so `height` must be at or past
/// `bythos_phase`.
///
/// ⚑ The gate is on `height` (consensus reads `now`,
/// `tx-engine-1.hoon:2246`), **not** on the note's origin page. The stock
/// wallet keys on `origin-page` instead (`hoon/apps/wallet/lib/
/// tx-builder.hoon:331-336`), which is why a pre-Bythos multi-branch note
/// is unspendable through it even after activation.
///
/// The constructed proof is folded back to the lock root before
/// returning, so a wrong axis or path fails here rather than at
/// consensus, where it would name nothing.
pub fn lock_merkle_proof(
    lock: &Lock,
    leaf_number: u64,
    height: u64,
    bythos_phase: u64,
) -> anyhow::Result<LockMerkleProof> {
    let root = lock_root(lock)?;
    let branches = lock.spend_condition_count();
    anyhow::ensure!(
        leaf_number >= 1 && leaf_number <= branches,
        "lock has branches 1..={branches} (got {leaf_number})"
    );

    let leaves = lock.flatten_spend_conditions();
    let spend_condition = leaves[(leaf_number - 1) as usize].clone();

    let (axis, path, full) = if branches == 1 {
        (1u64, Vec::new(), height >= bythos_phase)
    } else {
        anyhow::ensure!(
            height >= bythos_phase,
            "a {branches}-branch lock needs the full lock-merkle-proof form, \
             which consensus accepts only at or after the bythos phase \
             (height {height}, bythos {bythos_phase})"
        );

        let mut level = leaves
            .iter()
            .map(|sc| {
                sc.hash()
                    .map_err(|e| anyhow::anyhow!("branch spend-condition hash: {e:?}"))
            })
            .collect::<anyhow::Result<Vec<Hash>>>()?;

        // Leaf to subtree root, taking the sibling at each level. The tree is
        // perfect (N is a power of two), so every level above the leaves is
        // exactly half the one below it.
        let mut index = (leaf_number - 1) as usize;
        let mut path = Vec::with_capacity(level.len().trailing_zeros() as usize + 1);
        while level.len() > 1 {
            let sibling = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            path.push(level[sibling].clone());
            level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
            index /= 2;
        }
        // ...and finally the arity tag, which is the root's left sibling.
        path.push(
            hash_leaf_atom(branches).map_err(|e| anyhow::anyhow!("lock arity-tag hash: {e:?}"))?,
        );

        (3 * branches + (leaf_number - 1), path, true)
    };

    let proof = MerkleProof { root, path };
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
    use nockchain_types::tx_engine::v1::tx::LockV4;

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

    use nockchain_types::tx_engine::v1::tx::LockV8;

    /// A distinct single-`%pkh` branch, for building multi-branch fixtures.
    fn sc(n: u64) -> SpendCondition {
        SpendCondition::simple_pkh(pkh(n))
    }

    /// ⭐ **The re-aimed falsifier (the `f1a_*` tests).**
    ///
    /// The original concern — *"a two-element signature set has a
    /// canonical order our Rust must reproduce exactly; wrong, and the money
    /// is unspendable by anyone"* — is **already proven against Hoon** by
    /// `nockchain-types`' own `lock_hash_matches_known_hoon_vectors`, which
    /// freezes base58 vectors for a 2-of-2 two-element pkh z-set
    /// (`EXPECTED_MULTISIG_2_OF_2_ROOT_B58`) and for two four-branch locks.
    /// The mechanism is a faithful port, not luck: `ZSet` is a treap keyed by
    /// `gor_tip` with `mor_tip` priorities — Hoon's `+put:z-in` — and a treap
    /// with deterministic priorities is canonical in its item set.
    ///
    /// What has **no** evidence on either side is the merkle **path and
    /// axis** for four branches: `lock_merkle_proof` refused `V4` outright,
    /// and every Hoon test is a round trip, so no axis/path KAT exists
    /// anywhere. That is what this pins.
    ///
    /// The rule, from `tx-engine-1.hoon:1762-1805` and
    /// `ztd/three.hoon:2009-2040`: leaf `k` (1-based) of an `N`-branch lock
    /// sits at axis `3·N + (k−1)` with `log2(N) + 1` siblings, the last of
    /// which is always `hash_leaf_atom(N)`.
    /// ⚑ `docs/architecture/tx-engine/03-taproot-lock-merkle-proofs.md:169`
    /// says `log2(N)`; it is wrong — the arity tag is a sibling too.
    #[test]
    fn f1a_four_branch_proofs_fold_to_the_lock_root() {
        let lock = Lock::V4(LockV4 {
            p: LockV2 { p: sc(1), q: sc(2) },
            q: LockV2 { p: sc(3), q: sc(4) },
        });
        let root = lock_root(&lock).expect("v4 lock root");

        for k in 1..=4u64 {
            let proof = lock_merkle_proof(&lock, k, 10, 1)
                .unwrap_or_else(|e| panic!("branch {k} should build: {e}"));
            assert_eq!(proof.axis(), 12 + (k - 1), "branch {k} axis");
            assert_eq!(proof.proof().path.len(), 3, "branch {k} path length");
            assert_eq!(proof.proof().root, root, "branch {k} folds to the root");
            assert!(
                matches!(proof, LockMerkleProof::Full(_)),
                "a multi-branch lock is only provable in the full form"
            );
        }

        // The leaf presented at a sibling's axis must NOT verify — otherwise
        // the axis carries no information and any branch proves any other.
        let p1 = lock_merkle_proof(&lock, 1, 10, 1).expect("branch 1");
        let leaf1 = p1.spend_condition().hash().expect("leaf hash");
        assert!(!verify_merk_proof(&leaf1, 13, p1.proof()));
        assert!(!verify_merk_proof(&leaf1, 12 + 4, p1.proof()));

        // Out-of-range branches are refused, not silently clamped.
        assert!(lock_merkle_proof(&lock, 0, 10, 1).is_err());
        assert!(lock_merkle_proof(&lock, 5, 10, 1).is_err());
    }

    /// The same rule at the next arity, so the generalisation is not fitted to
    /// one case. The escrow needs only `V4`, but a proof fold fitted to the
    /// branch count we happen to use would fail the moment that count changed.
    #[test]
    fn f1a_eight_branch_proofs_fold_to_the_lock_root() {
        let half = |a, b, c, d| LockV4 {
            p: LockV2 { p: sc(a), q: sc(b) },
            q: LockV2 { p: sc(c), q: sc(d) },
        };
        let lock = Lock::V8(LockV8 {
            p: half(1, 2, 3, 4),
            q: half(5, 6, 7, 8),
        });
        let root = lock_root(&lock).expect("v8 lock root");
        for k in 1..=8u64 {
            let proof = lock_merkle_proof(&lock, k, 10, 1)
                .unwrap_or_else(|e| panic!("branch {k} should build: {e}"));
            assert_eq!(proof.axis(), 24 + (k - 1), "branch {k} axis");
            assert_eq!(proof.proof().path.len(), 4, "branch {k} path length");
            assert_eq!(proof.proof().root, root, "branch {k} folds to the root");
        }
    }

    /// The shipped two-branch numbers must fall out of the same formula, not
    /// survive as a special case: `3·2 + (k−1)` is 6 and 7.
    #[test]
    fn f1a_the_two_branch_case_is_the_general_rule() {
        let lock = bounty_lock(pkh(100), pkh(200));
        for (k, axis) in [(1u64, 6u64), (2, 7)] {
            let proof = lock_merkle_proof(&lock, k, 10, 1).expect("branch");
            assert_eq!(proof.axis(), axis);
            assert_eq!(proof.proof().path.len(), 2);
        }
    }

    /// The half of that concern that was already true, pinned so a future port of the
    /// z-set cannot regress it silently. A treap keyed by `gor`/`mor` is
    /// canonical in its item set, so the two insertion orders of a 2-of-2
    /// signature set must produce the same digest — and therefore the same
    /// lock root and the same note address.
    #[test]
    fn the_two_of_two_signature_set_is_insertion_order_invariant() {
        let (a, b) = (pkh(100), pkh(200));
        let ab = SpendCondition::new(vec![LockPrimitive::Pkh(Pkh::new(
            2,
            vec![a.clone(), b.clone()],
        ))]);
        let ba = SpendCondition::new(vec![LockPrimitive::Pkh(Pkh::new(2, vec![b, a]))]);
        assert_eq!(
            ab.hash().expect("ab"),
            ba.hash().expect("ba"),
            "the 2-of-2 z-set must not depend on insertion order"
        );
    }

    /// ⭐⭐ A zero-threshold `%pkh` is spendable by ANYONE with an empty
    /// witness, and nothing in the chain rejects it. `pkh_conjunct` is where
    /// that stops. ⚑ The positive controls are the two shapes the escrow
    /// flow's notes use, so a guard that refused everything would fail here.
    #[test]
    fn a_pkh_conjunct_with_no_threshold_or_too_high_a_threshold_is_refused() {
        assert!(
            pkh_conjunct(2, vec![pkh(1), pkh(2)]).is_ok(),
            "the 2-of-2 builds"
        );
        assert!(pkh_conjunct(1, vec![pkh(1)]).is_ok(), "the 1-of-1 builds");

        assert!(
            pkh_conjunct(0, vec![pkh(1), pkh(2)]).is_err(),
            "m = 0 is satisfied by an EMPTY witness — spendable by anyone"
        );
        assert!(
            pkh_conjunct(0, vec![]).is_err(),
            "m = 0 over an empty set is the same hole"
        );
        // The z-set dedups silently, so this asks two signatures of a
        // one-element set: unsatisfiable by anyone.
        assert!(
            pkh_conjunct(2, vec![pkh(1), pkh(1)]).is_err(),
            "a repeated member collapses the set and strands the branch"
        );
        assert!(
            pkh_conjunct(3, vec![pkh(1), pkh(2)]).is_err(),
            "m greater than the set size is unsatisfiable"
        );
    }
}
