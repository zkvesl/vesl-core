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

use nockchain_math::belt::Belt;
use nockchain_types::tx_engine::common::{
    BlockHeightDelta, FirstName, Hash, TimelockRangeAbsolute, TimelockRangeRelative,
};
use nockchain_types::tx_engine::v1::hashable::{HashHashable, hash_leaf_atom, hash_pair};
use nockchain_types::tx_engine::v1::tx::{
    Hax, Lock, LockMerkleProof, LockPrimitive, LockTim, LockV2, LockV4, MerkleProof, Pkh,
    SpendCondition,
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
/// ⚖️⚖️ **`payout_pkh` IS THE MINER'S KEY, NOT THE PLATFORM'S** (owner,
/// 2026-08-25; zkML `docs/plans/lockstat` `SYSTEM §0d`, `FC-96`). Until
/// that ruling the escrow was posted at job-posting time, before any
/// miner existed, so branch 1 could only pin a deploy constant — and a
/// settling miner had to ask the platform's key to sign the spend it had
/// itself composed (`DV-10`). The escrow is now created AFTER the audit,
/// bound to the miner who served, so this argument is the pkh the miner
/// declared inside what it signed, and the miner alone can spend.
///
/// ⛔ **THE DESTINATION HAS THREE CONJUNCTS HERE, AND THIS SHIPS ONE.**
/// The ruled settle condition is `[%pkh miner] ∧ [%zkp statement] ∧ [%tim
/// before D]`; `SpendCondition` really is an AND-list upstream, so the
/// shape is expressible — but `%zkp` is not a lock primitive
/// (`+lock-primitive` is a four-way `$%`: `%pkh %tim %hax %brn`,
/// `nockchain/hoon/common/tx-engine-1.hoon:1516-1526`), and neither the
/// deadline `D` nor the refund-key holder is decided. So the statement
/// stays on branch 2 as an unspendable placeholder and the timelock is
/// absent. Named successor: the `%zkp` conjunct when the primitive lands,
/// the `%tim` pair when `D` and the refund key are ruled.
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

/// Branch numbers of the buyer's hold (`XD-3`), 1-based, as
/// `lock_merkle_proof` takes them. ⛔ **These are part of the address.**
/// The branch order is baked into the lock root, so renumbering them moves
/// every hold ever created — fail-closed and silent until a live spend.
pub const HOLD_BRANCH_CAPTURE: u64 = 1;
/// See [`HOLD_BRANCH_CAPTURE`].
pub const HOLD_BRANCH_VOID: u64 = 2;
/// See [`HOLD_BRANCH_CAPTURE`].
pub const HOLD_BRANCH_RECLAIM: u64 = 3;
/// See [`HOLD_BRANCH_CAPTURE`]. Unspendable by construction — `check`
/// answers `%|` for `%brn` unconditionally (`tx-engine-1.hoon:2267`).
///
/// ⭐⭐ **IT IS NO LONGER ONLY PADDING — IT CARRIES THE JOB.** A branch is a
/// LIST of conditions, ANDed (`levy` over them, `tx-engine-1.hoon:2260-2267`),
/// and `%brn` answers `%|` *unconditionally*, so a branch holding a burn is
/// unspendable **whatever else sits beside it**. That makes this branch free
/// capacity in the ADDRESS: it now also carries `job_com`, so the address the
/// buyer's money sits at is a statement about the job it was paid for, and one
/// payment cannot back two jobs. ⛔ The burn stays FIRST, and the branch stays
/// exactly as unspendable as it was.
pub const HOLD_BRANCH_PADDING: u64 = 4;

/// Four-branch lock for the buyer's payment note — **the hold** (`XD-3`,
/// ⚖️ RULED S93).
///
/// ⚑ *In plain terms: the buyer's money needs BOTH signatures to move — and
/// to move it to us we must also publish the key that decrypts the answer,
/// so taking the money and delivering become one act. If we go quiet, the
/// buyer recovers its money alone after a wait.*
///
/// ```text
/// B1  CAPTURE  [%pkh m=2 {buyer, platform}]  AND  [%hax {h_k}]
/// B2  VOID     [%pkh m=2 {buyer, platform}]
/// B3  RECLAIM  [%pkh m=1 {buyer}]  AND  [%tim rel.min = r_reclaim]
/// B4  padding  [%brn ~]  AND  [%hax {job_com}]
/// ```
///
/// ⛔⛔ **Capture and void MUST be separate branches.** A void pays the buyer
/// and delivers nothing, so it must not require publishing the key. They
/// could share a branch only while nothing distinguished them — a signature
/// commits to the outputs and the fee and nothing else
/// (`tx-engine-1.hoon:1116-1120`), so the hashlock is precisely what tells
/// the two spends apart. That is what takes the count to three real
/// branches, and the chain has no 3: `from-list` pads to the next power of
/// two with `~[[%brn ~]]` (`tx-engine-1.hoon:1667-1682`), which is what `B4`
/// is. We build the padded shape directly rather than round-tripping through
/// a list, so the padding is explicit at the one site that decides it.
///
/// ⛔ **`h_k` is NOT a hash of the key's bytes.** `check:hax` looks the value
/// up by `hash-noun:hax` — a *structural* fold over the preimage noun
/// (`tx-engine-1.hoon:2105-2119`) — so `h_k` must be
/// `hax_carry::preimage_key` of the very carry noun the spending witness
/// will present. Pass the `key` half of `seal_carry(K)` and nothing else;
/// anything else makes `B1` unsatisfiable by the holder of `K`, and says so
/// only at a live settlement.
///
/// ⛔ **`r_reclaim` is an operand of the lock root**, measured from the
/// note's own origin page (`tx-engine-1.hoon:2149-2164`), so changing its
/// value moves every hold address. A fixture that shortens it is testing the
/// branch's shape, not its address.
///
/// ⚑ Each branch carries at most one `%pkh`: two `%pkh` conjuncts in one
/// AND-list are unsatisfiable, because `check:pkh` demands the whole witness
/// map equal its own `m` (`tx-engine-1.hoon:2064-2081`) — the same trap
/// [`bounty_lock`] documents.
///
/// ⛔ Spendable only at `height >= bythos_phase`, like every multi-branch
/// lock; see [`lock_merkle_proof`].
///
/// ## ⭐⭐ `job_com` — the padding branch carries the job
///
/// ⚑ *In plain terms: the address the money sits at stops being an opaque name
/// and becomes a statement about the job it was paid for. A payment made for
/// one job is arithmetically incapable of sitting at another job's address.*
///
/// `job_com` is the buyer's **order digest** — the value that is also its
/// payment id, so both the buyer building this note and the platform checking
/// it already hold it and no new field crosses the wire. ⛔ It must NOT be
/// `input_com`: the buyer builds the note, and `input_com` is the platform's
/// and does not exist yet at that moment.
///
/// ⛔ It rides `B4` and not a real branch **because `B4` can never be spent**
/// (see [`HOLD_BRANCH_PADDING`]). Putting it on a spendable branch — or on a
/// bare `%hax` of its own — would make the note a bearer instrument: `%hax`
/// alone is satisfied by publishing a preimage, with no signature at all.
///
/// ⛔ It is an operand of the address, so changing what is committed here moves
/// every hold — the same rule `r_reclaim` carries.
///
/// ⚑ Nothing about it reaches the chain in the clear: a spend reveals only the
/// branch it uses, and this branch is never spent.
///
/// ## ⛔⛔ Why this returns a `Result`
///
/// `Pkh::new(2, vec![P, P])` goes through `ZSet`, which **deduplicates
/// silently** (`nockchain-math/src/zoon/zset.rs`, pinned upstream by
/// `quickcheck_owned_zset_ignores_duplicate_items`). Two equal hashes become a
/// ONE-element set still demanding `m=2`, and `check:pkh` requires exactly `m`
/// witness entries whose keys are a subset of that set
/// (`tx-engine-1.hoon:2064-2081`) ⇒ **`B1` and `B2` both become unsatisfiable**,
/// leaving only the buyer's own reclaim. The note is built without complaint and
/// says nothing until a live settlement. ⇒ refuse it here, the one place that
/// can see both halves.
pub fn hold_lock(
    buyer_pkh: Hash,
    platform_pkh: Hash,
    h_k: Hash,
    r_reclaim: u64,
    job_com: Hash,
) -> anyhow::Result<Lock> {
    if buyer_pkh == platform_pkh {
        anyhow::bail!(
            "the buyer and the platform hash to the same address, so the 2-of-2 would \
             collapse to a one-element set still demanding two signatures: capture and \
             void would both be unsatisfiable and only the buyer's reclaim would remain. \
             Refusing to build a note nobody can capture."
        );
    }
    let both = || LockPrimitive::Pkh(Pkh::new(2, vec![buyer_pkh.clone(), platform_pkh.clone()]));

    // B1 — capture. Conjunct order is part of the address; `XD-3` writes the
    // signature check first.
    let capture = SpendCondition::new(vec![both(), LockPrimitive::Hax(Hax::new(vec![h_k]))]);
    // B2 — void. The same 2-of-2, with nothing to publish.
    let void = SpendCondition::new(vec![both()]);
    // B3 — reclaim. The buyer alone, after the wait.
    let reclaim = SpendCondition::new(vec![
        LockPrimitive::Pkh(Pkh::new(1, vec![buyer_pkh])),
        LockPrimitive::Tim(LockTim {
            rel: TimelockRangeRelative::new(Some(BlockHeightDelta(Belt(r_reclaim))), None),
            abs: TimelockRangeAbsolute::none(),
        }),
    ]);
    // B4 — the padding the chain's own `from-list` would have appended, now
    // also carrying the job. ⛔ `Burn` stays FIRST: conjunct order is part of
    // the address, and the burn is what makes the branch unspendable.
    let padding = SpendCondition::new(vec![
        LockPrimitive::Burn,
        LockPrimitive::Hax(Hax::new(vec![job_com])),
    ]);

    Ok(Lock::V4(LockV4 {
        p: LockV2 {
            p: capture,
            q: void,
        },
        q: LockV2 {
            p: reclaim,
            q: padding,
        },
    }))
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

    /// ⭐ **F1a — the re-aimed falsifier.**
    ///
    /// `F1` as the design states it — *"a two-element signature set has a
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
    /// one case. `XD-3` needs only `V4`, but fixing the branch count we happen
    /// to use is the §2.2 point-2 failure one level out.
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

    /// The half of `F1` that was already true, pinned so a future port of the
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

    /// `XD-3`'s shape, branch by branch. This is the address; if any of these
    /// assertions has to be "updated", the hold has moved and every note ever
    /// created under the old shape is stranded.
    #[test]
    fn the_hold_lock_is_xd3s_four_branch_shape() {
        let (buyer, platform, h_k) = (pkh(10), pkh(20), pkh(30));
        let job_com = pkh(40);
        let lock = hold_lock(
            buyer.clone(),
            platform.clone(),
            h_k.clone(),
            576,
            job_com.clone(),
        )
        .expect("two distinct parties");
        let branches = lock.flatten_spend_conditions();
        assert_eq!(lock.spend_condition_count(), 4);

        // B1 capture — the 2-of-2 AND the hashlock, in that order.
        let capture = &branches[(HOLD_BRANCH_CAPTURE - 1) as usize];
        assert_eq!(capture.0.len(), 2);
        assert!(matches!(&capture.0[0], LockPrimitive::Pkh(p) if p.m == 2));
        assert!(matches!(&capture.0[1], LockPrimitive::Hax(_)));

        // B2 void — the same 2-of-2, and NOTHING else. A void delivers
        // nothing, so it must not require publishing the key.
        let void = &branches[(HOLD_BRANCH_VOID - 1) as usize];
        assert_eq!(void.0.len(), 1);
        assert!(matches!(&void.0[0], LockPrimitive::Pkh(p) if p.m == 2));
        assert!(
            !void.0.iter().any(|p| matches!(p, LockPrimitive::Hax(_))),
            "a void must not carry the delivery condition"
        );

        // B3 reclaim — the buyer alone, after the wait.
        let reclaim = &branches[(HOLD_BRANCH_RECLAIM - 1) as usize];
        assert_eq!(reclaim.0.len(), 2);
        assert!(matches!(&reclaim.0[0], LockPrimitive::Pkh(p) if p.m == 1));
        match &reclaim.0[1] {
            LockPrimitive::Tim(t) => {
                assert_eq!(t.rel.min.as_ref().map(|d| d.0.0), Some(576));
                assert!(t.rel.max.is_none() && t.abs.min.is_none() && t.abs.max.is_none());
            }
            other => panic!("reclaim's second conjunct should be %tim, got {other:?}"),
        }

        // B4 padding — what `from-list` would have appended, AND the job. ⛔
        // The burn is FIRST and is what keeps the branch unspendable; the
        // `%hax` beside it never gets a chance to be satisfied, because `levy`
        // over the conjuncts meets `%brn` answering `%|` unconditionally
        // (`tx-engine-1.hoon:2260-2267`).
        assert_eq!(
            branches[(HOLD_BRANCH_PADDING - 1) as usize],
            SpendCondition::new(vec![
                LockPrimitive::Burn,
                LockPrimitive::Hax(Hax::new(vec![job_com.clone()])),
            ]),
            "the padding branch carries the job, with the burn first"
        );

        // Capture and void must be genuinely different branches, or the
        // hashlock distinguishes nothing.
        assert_ne!(capture.hash().unwrap(), void.hash().unwrap());
    }

    /// Every real branch is provable, and each lands on its own axis. Without
    /// this, "fixing the branch we use most" leaves a void or a reclaim that
    /// cannot execute — which strands the money exactly as surely.
    #[test]
    fn every_hold_branch_is_provable() {
        let lock = hold_lock(pkh(10), pkh(20), pkh(30), 576, pkh(40)).expect("hold");
        let root = lock_root(&lock).expect("hold root");
        for (branch, axis) in [
            (HOLD_BRANCH_CAPTURE, 12),
            (HOLD_BRANCH_VOID, 13),
            (HOLD_BRANCH_RECLAIM, 14),
            (HOLD_BRANCH_PADDING, 15),
        ] {
            let proof = lock_merkle_proof(&lock, branch, 10, 1)
                .unwrap_or_else(|e| panic!("branch {branch}: {e}"));
            assert_eq!(proof.axis(), axis);
            assert_eq!(proof.proof().root, root);
        }
    }

    /// The delivery condition is what the whole row exists for: change the
    /// key's hash and the address moves. A hold built against one key cannot
    /// be captured by publishing another.
    #[test]
    fn the_hold_address_binds_the_key() {
        let h = |b, p, k, w, j| hold_lock(b, p, k, w, j).expect("hold");
        let base = h(pkh(10), pkh(20), pkh(30), 576, pkh(40));
        let other_key = h(pkh(10), pkh(20), pkh(31), 576, pkh(40));
        let other_wait = h(pkh(10), pkh(20), pkh(30), 577, pkh(40));
        let other_buyer = h(pkh(11), pkh(20), pkh(30), 576, pkh(40));
        let other_job = h(pkh(10), pkh(20), pkh(30), 576, pkh(41));
        let r = |l: &Lock| lock_root(l).unwrap();
        assert_ne!(r(&base), r(&other_key), "h_k is an operand of the address");
        assert_ne!(r(&base), r(&other_wait), "r_reclaim is an operand too");
        assert_ne!(r(&base), r(&other_buyer));
        // ⭐⭐ And the job. Without this the padding branch commits to nothing:
        // a commitment that does not move the address is decoration.
        assert_ne!(
            r(&base),
            r(&other_job),
            "job_com is an operand of the address — one payment cannot back two jobs"
        );
        // ...and it is a pure function of its operands.
        assert_eq!(r(&base), r(&h(pkh(10), pkh(20), pkh(30), 576, pkh(40))));
    }

    /// ⚑ The 2-of-2 is a threshold over a SET, so the two parties may be
    /// supplied in either order without moving the address. This is the
    /// already-proven half of `F1` reaching the artifact it actually guards.
    #[test]
    fn the_hold_address_does_not_depend_on_which_party_is_named_first() {
        let a = hold_lock(pkh(10), pkh(20), pkh(30), 576, pkh(40)).expect("hold a");
        let b = hold_lock(pkh(20), pkh(10), pkh(30), 576, pkh(40)).expect("hold b");
        // B1 and B2 are symmetric in the pair; B3 names the buyer alone, so
        // the whole lock is not symmetric — compare the branches that are.
        let (ba, bb) = (a.flatten_spend_conditions(), b.flatten_spend_conditions());
        for i in [HOLD_BRANCH_CAPTURE, HOLD_BRANCH_VOID] {
            let i = (i - 1) as usize;
            assert_eq!(ba[i].hash().unwrap(), bb[i].hash().unwrap());
        }
    }
}
