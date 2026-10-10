//! The two bonds as SLICES, and the two notes a slash pays into.
//!
//! ⚑ *In plain terms: a provider (or a checker) puts money at stake by minting many small
//! notes in one transaction — SLICES — one for each job it may have open at once. At each
//! capture the provider signs, in advance, the transaction that would take twice that job's
//! pay out of the slice reserved for it; the platform's verdict key completes it only on a
//! proven fault. What the slash does not take goes back to the provider, but only after a
//! wait, so a staged slash is never a quick way out. The checker's share waits in a REWARD
//! note the verdict key pays onward. With no job open, the provider and the platform can
//! release a slice together; if the platform vanishes, the provider takes it back alone after
//! a long life.*
//!
//! ```text
//! SLICE   1 SLASH     [%pkh 2 {slasher, verdict}]
//!         2 EXIT      [%pkh 2 {holder, platform}]
//!         3 FALLBACK  [%pkh 1 {holder}] AND [%tim rel.min = t_life]
//!         4 RESERVED  [%brn]            AND [%hax {terms, slot(role, index)}]
//! HELD    1 RELEASE   [%pkh 1 {holder}] AND [%tim rel.min = hold]
//!         2 TAG       [%brn]            AND [%hax {terms}]
//! REWARD  1 PAY       [%pkh 1 {verdict}]
//!         2 TAG       [%brn]            AND [%hax {order_digest, record_root}]
//! ```
//!
//! ⛔ **Every operand, branch number and conjunct position is part of the address**, as in
//! [`crate::job_locks`], whose chain-side reasoning (inclusive `%tim` bounds, dropped zero
//! bounds, `%hax` as a z-set, `sig-hash` not covering the branch) applies unchanged here.
//!
//! ⚑ **Why each rule.**
//! - `holder` is the provider for a provider slice and the checker for a checker slice
//!   (a separate bond, the same shape). `verdict` is the platform's verdict key
//!   `Kv`, `platform` its funding key `Kf`. ⛔ The four are refused equal: with
//!   `verdict == platform`, SLASH and EXIT name one pair, and `sig-hash` does not cover the
//!   branch — an exit signature would satisfy the slash and the reverse.
//! - ⛔ **`slasher` is the holder's SLASH-ONLY key**, named in no other branch. While SLASH named `holder`, a stored
//!   advance slash signature satisfied EXIT's holder half, so `Kf` alone completed a slash, and
//!   FALLBACK after `t_life` needed nothing more. The holder's IDENTITY is in the terms; this
//!   key signs, it does not identify.
//! - ⛔ **Nobody moves a slice alone before `t_life`.** SLASH needs the slasher's advance
//!   signature AND the verdict; EXIT needs the holder AND the platform, which signs it
//!   only with no job open on that slice (policy); FALLBACK is the holder's escape if the
//!   platform disappears, and the platform backs no job or vouch with a slice whose
//!   `origin + t_life − 96` does not outlast that liability's window (policy, the
//!   platform's bond gate, checked at the lease, the capture and the draw).
//! - ⚑ Two outputs to one address in one transaction MERGE (`tx-engine-1.hoon:2362-2385`),
//!   and a posting mints every slice in ONE transaction ⇒ RESERVED carries the
//!   slice's `index`, so every slice of a posting has its own address. The same slot carries
//!   the ROLE, so a provider slice and a checker slice of one holder under one terms digest
//!   never share an address.
//! - ⛔ **A lock cannot see an amount.** "Exactly 2× the job's pay" is fixed by the
//!   holder's advance signature, which covers every output and amount
//!   (`tx-engine-1.hoon:708-715`), not by anything here. The slice's VALUE is the platform's
//!   to count (only exact values at exact addresses buy capacity).
//!
//! ⭐ **The exit.** SLASH becomes `%zkp F_slice` ∧ the platform's
//! signature, and EXIT a covenant, when upstream ships them; FALLBACK is then removed. That is
//! a new constructor beside this one and a deletion of this one; every slice rolls into the
//! new template through EXIT.

use nockchain_math::belt::PRIME;
use nockchain_types::tx_engine::common::Hash;
use nockchain_types::tx_engine::v1::tx::{Lock, LockPrimitive, LockV2, SpendCondition};

use crate::job_locks::{facts_hax, four, refuse_same_key, refuse_zero_window, relative};
use crate::lock::pkh_conjunct;

/// Branch numbers of a SLICE, 1-based. ⛔ Part of the address.
pub const SLICE_BRANCH_SLASH: u64 = 1;
/// See [`SLICE_BRANCH_SLASH`]. The holder and the platform, with no job open on the slice.
pub const SLICE_BRANCH_EXIT: u64 = 2;
/// See [`SLICE_BRANCH_SLASH`]. The holder alone, after the slice's life.
pub const SLICE_BRANCH_FALLBACK: u64 = 3;
/// See [`SLICE_BRANCH_SLASH`]. Unspendable: the terms and the slot, in the address.
pub const SLICE_BRANCH_RESERVED: u64 = 4;

/// Branch numbers of a HELD note (a slash's change). ⛔ Part of the address.
pub const HELD_BRANCH_RELEASE: u64 = 1;
/// See [`HELD_BRANCH_RELEASE`]. Unspendable: the terms, in the address.
pub const HELD_BRANCH_TAG: u64 = 2;

/// Branch numbers of a REWARD note (the checker part of a slash). ⛔ Part of the address.
pub const REWARD_BRANCH_PAY: u64 = 1;
/// See [`REWARD_BRANCH_PAY`]. Unspendable: which job's slash it came from.
pub const REWARD_BRANCH_TAG: u64 = 2;

/// Which bond a slice belongs to. ⛔ Its cord is an operand of the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceRole {
    /// Covers one open job the holder serves.
    Provider,
    /// Covers one open vouch (a CLEAN report) the holder made as a checker.
    Checker,
}

impl SliceRole {
    /// Every role, so a test cannot forget one.
    pub const ALL: [SliceRole; 2] = [SliceRole::Provider, SliceRole::Checker];

    /// The 8-byte ASCII cord the slot carries — a cord, never a small integer, so no role
    /// tag can alias an index.
    pub const fn cord(self) -> u64 {
        match self {
            SliceRole::Provider => cord(b"slice-pv"),
            SliceRole::Checker => cord(b"slice-ck"),
        }
    }
}

const fn cord(b: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*b)
}

/// The four keys a slice names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceKeys {
    /// The provider (provider slice) or the checker (checker slice) that posted it.
    pub holder: Hash,
    /// The holder's slash-only key — SLASH's, and no other branch's.
    pub slasher: Hash,
    /// The platform's verdict key `Kv` — the oracle, temporary.
    pub verdict: Hash,
    /// The platform's funding key `Kf`.
    pub platform: Hash,
}

/// The slot a slice's RESERVED branch carries beside its terms: its role and its index in
/// the posting. `[role cord, index, 0, 0, 0]` — not a digest, and refused equal to one.
pub fn slice_slot(role: SliceRole, index: u64) -> anyhow::Result<Hash> {
    anyhow::ensure!(
        index < PRIME,
        "the slice index {index} is not a field element"
    );
    Ok(Hash::from_limbs(&[role.cord(), index, 0, 0, 0]))
}

/// A SLICE of a bond — see the module header for the shape.
///
/// `terms` is the digest of the bond's terms the platform quoted (the protocol layer derives
/// it; it is opaque here). `index` is this slice's position in its posting. `t_life` is the
/// slice's life in blocks from its origin page, after which the holder alone may take it
/// back (ASSUMED value). ⛔ All three are operands of the address.
pub fn slice_lock(
    keys: &SliceKeys,
    role: SliceRole,
    index: u64,
    t_life: u64,
    terms: &Hash,
) -> anyhow::Result<Lock> {
    refuse_distinct_slice_keys(keys)?;
    refuse_zero_window(t_life, "the slice's life t_life", "FALLBACK's rel.min")?;
    let slash = SpendCondition::new(vec![pkh_conjunct(
        2,
        vec![keys.slasher.clone(), keys.verdict.clone()],
    )?]);
    let exit = SpendCondition::new(vec![pkh_conjunct(
        2,
        vec![keys.holder.clone(), keys.platform.clone()],
    )?]);
    let fallback = SpendCondition::new(vec![
        pkh_conjunct(1, vec![keys.holder.clone()])?,
        relative(Some(t_life), None),
    ]);
    let reserved = SpendCondition::new(vec![
        LockPrimitive::Burn,
        facts_hax(&[
            ("the bond's terms", terms.clone()),
            ("the slice's slot", slice_slot(role, index)?),
        ])?,
    ]);
    Ok(four(slash, exit, fallback, reserved))
}

/// The HELD note a slash pays the rest of its slice into (*"the rest of the slice back
/// to the provider as change, timelocked so a slash is never a quick exit"*).
///
/// `hold` is the wait in blocks from the slash's landing (1.248, the exit payout's wait,
/// ASSUMED). ⛔ An operand of the address.
///
/// ⛔ **Not forfeitable today.** A whole-bond forfeit would take this change too; that
/// forfeit is not armed until it is shown to work, and a forfeitable HELD is a new
/// constructor then.
pub fn held_lock(holder: &Hash, hold: u64, terms: &Hash) -> anyhow::Result<Lock> {
    refuse_zero_window(hold, "the change's hold", "RELEASE's rel.min")?;
    let release = SpendCondition::new(vec![
        pkh_conjunct(1, vec![holder.clone()])?,
        relative(Some(hold), None),
    ]);
    let tag = SpendCondition::new(vec![
        LockPrimitive::Burn,
        facts_hax(&[("the bond's terms", terms.clone())])?,
    ]);
    Ok(two(release, tag))
}

/// The REWARD note a slash pays the checker part into. The checker is unknown when
/// the provider signs the slash at capture, so today the verdict key holds it and pays the
/// drawn checker (no trust beyond the verdict key's); in the target, a proof that the
/// claimant holds the drawn ticket replaces the key.
///
/// `statement` is what the slash convicts: a streamed job's signed closing digest, or a
/// voucher's vouched root.
pub fn reward_lock(
    verdict: &Hash,
    order_digest: &Hash,
    statement: &Hash,
) -> anyhow::Result<Lock> {
    let pay = SpendCondition::new(vec![pkh_conjunct(1, vec![verdict.clone()])?]);
    let tag = SpendCondition::new(vec![
        LockPrimitive::Burn,
        facts_hax(&[
            ("the order digest", order_digest.clone()),
            ("the convicted statement", statement.clone()),
        ])?,
    ]);
    Ok(two(pay, tag))
}

fn two(a: SpendCondition, b: SpendCondition) -> Lock {
    Lock::V2(LockV2 { p: a, q: b })
}

fn refuse_distinct_slice_keys(k: &SliceKeys) -> anyhow::Result<()> {
    refuse_same_key(
        &k.slasher, &k.verdict, "the slasher", "the verdict key", "SLASH",
    )?;
    refuse_same_key(
        &k.holder, &k.verdict, "the holder", "the verdict key", "EXIT",
    )?;
    for (other, name) in [(&k.holder, "the holder"), (&k.platform, "the platform")] {
        anyhow::ensure!(
            &k.slasher != other,
            "the slasher and {name} are the same key: a stored slash signature would then \
             satisfy another branch, and sig-hash does not cover which branch is revealed. \
             Refusing to build it."
        );
    }
    refuse_same_key(&k.holder, &k.platform, "the holder", "the platform", "EXIT")?;
    anyhow::ensure!(
        k.verdict != k.platform,
        "the verdict key and the platform's funding key are the same key: SLASH and EXIT would \
         then name one pair, and sig-hash does not cover which branch is revealed — an exit \
         signature would satisfy the slash. Refusing to build it."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use nockchain_math::belt::Belt;
    use nockchain_types::tx_engine::common::BlockHeightDelta;

    use super::*;
    use crate::job_locks::branch_window_open;
    use crate::lock::{lock_merkle_proof, lock_root};

    fn h(n: u64) -> Hash {
        Hash::from_limbs(&[n, n + 1, n + 2, n + 3, n + 4])
    }
    fn keys() -> SliceKeys {
        SliceKeys {
            holder: h(30),
            slasher: h(35),
            verdict: h(70),
            platform: h(20),
        }
    }
    fn root(lock: anyhow::Result<Lock>) -> Hash {
        lock_root(&lock.expect("builds")).expect("hashes")
    }
    fn pkh_keys(sc: &SpendCondition) -> Vec<Hash> {
        match &sc.0[0] {
            LockPrimitive::Pkh(p) => {
                let mut v: Vec<Hash> = p.hashes.iter().cloned().collect();
                v.sort_by_key(|x| x.to_array());
                v
            }
            _ => vec![],
        }
    }

    #[test]
    fn a_slice_is_the_ruled_four_branch_shape_naming_the_keys_it_should() {
        let k = keys();
        let b = slice_lock(&k, SliceRole::Provider, 0, 9_216, &h(90))
            .unwrap()
            .flatten_spend_conditions();
        assert_eq!(b.len(), 4);
        assert!(matches!(&b[0].0[..], [LockPrimitive::Pkh(p)] if p.m == 2));
        assert!(matches!(&b[1].0[..], [LockPrimitive::Pkh(p)] if p.m == 2));
        assert!(
            matches!(&b[2].0[..], [LockPrimitive::Pkh(p), LockPrimitive::Tim(t)]
            if p.m == 1 && t.rel.min == Some(BlockHeightDelta(Belt(9_216))) && t.rel.max.is_none())
        );
        assert!(
            matches!(&b[3].0[..], [LockPrimitive::Burn, LockPrimitive::Hax(x)] if x.0.iter().count() == 2)
        );
        // ⛔ SLASH names the slasher, never the holder; EXIT and FALLBACK never the slasher.
        assert_eq!(pkh_keys(&b[0]), vec![k.slasher.clone(), k.verdict.clone()]);
        assert_eq!(pkh_keys(&b[1]), vec![k.platform.clone(), k.holder.clone()]);
        assert_eq!(pkh_keys(&b[2]), vec![k.holder.clone()]);
    }

    #[test]
    fn the_slash_and_reward_notes_are_the_ruled_two_branch_shapes() {
        let held = held_lock(&h(30), 1_248, &h(90))
            .unwrap()
            .flatten_spend_conditions();
        assert_eq!(held.len(), 2);
        assert!(
            matches!(&held[0].0[..], [LockPrimitive::Pkh(p), LockPrimitive::Tim(t)]
            if p.m == 1 && t.rel.min == Some(BlockHeightDelta(Belt(1_248))))
        );
        assert!(matches!(
            &held[1].0[..],
            [LockPrimitive::Burn, LockPrimitive::Hax(_)]
        ));
        let reward = reward_lock(&h(70), &h(40), &h(60))
            .unwrap()
            .flatten_spend_conditions();
        assert!(matches!(&reward[0].0[..], [LockPrimitive::Pkh(p)] if p.m == 1));
        assert_eq!(pkh_keys(&reward[0]), vec![h(70)]);
        assert!(
            matches!(&reward[1].0[..], [LockPrimitive::Burn, LockPrimitive::Hax(x)] if x.0.iter().count() == 2)
        );
    }

    #[test]
    fn every_real_branch_is_provable() {
        let locks = [
            slice_lock(&keys(), SliceRole::Checker, 7, 9_216, &h(90)).unwrap(),
            held_lock(&h(30), 1_248, &h(90)).unwrap(),
            reward_lock(&h(70), &h(40), &h(60)).unwrap(),
        ];
        for lock in &locks {
            for k in 1..=lock.spend_condition_count() {
                let proof = lock_merkle_proof(lock, k, 10, 1).expect("provable");
                assert_eq!(proof.proof().root, lock_root(lock).unwrap());
            }
        }
    }

    #[test]
    fn every_slice_of_one_posting_has_its_own_address() {
        // ⛔ One posting mints every slice in one transaction; equal addresses would merge.
        let mut seen = std::collections::BTreeSet::new();
        for role in SliceRole::ALL {
            for index in 0..64 {
                let r = root(slice_lock(&keys(), role, index, 9_216, &h(90)));
                assert!(
                    seen.insert(r.to_array()),
                    "{role:?} slice {index} repeats an address"
                );
            }
        }
    }

    #[test]
    fn every_address_binds_every_operand() {
        let k = keys();
        let base = root(slice_lock(&k, SliceRole::Provider, 3, 9_216, &h(90)));
        for q in [
            SliceKeys {
                holder: h(31),
                ..k.clone()
            },
            SliceKeys {
                slasher: h(36),
                ..k.clone()
            },
            SliceKeys {
                verdict: h(71),
                ..k.clone()
            },
            SliceKeys {
                platform: h(21),
                ..k.clone()
            },
        ] {
            assert_ne!(
                base,
                root(slice_lock(&q, SliceRole::Provider, 3, 9_216, &h(90)))
            );
        }
        assert_ne!(
            base,
            root(slice_lock(&k, SliceRole::Checker, 3, 9_216, &h(90)))
        );
        assert_ne!(
            base,
            root(slice_lock(&k, SliceRole::Provider, 4, 9_216, &h(90)))
        );
        assert_ne!(
            base,
            root(slice_lock(&k, SliceRole::Provider, 3, 9_217, &h(90)))
        );
        assert_ne!(
            base,
            root(slice_lock(&k, SliceRole::Provider, 3, 9_216, &h(91)))
        );

        let base = root(held_lock(&h(30), 1_248, &h(90)));
        assert_ne!(base, root(held_lock(&h(31), 1_248, &h(90))));
        assert_ne!(base, root(held_lock(&h(30), 1_249, &h(90))));
        assert_ne!(base, root(held_lock(&h(30), 1_248, &h(91))));

        let base = root(reward_lock(&h(70), &h(40), &h(60)));
        assert_ne!(base, root(reward_lock(&h(71), &h(40), &h(60))));
        assert_ne!(base, root(reward_lock(&h(70), &h(41), &h(60))));
        assert_ne!(base, root(reward_lock(&h(70), &h(40), &h(61))));
    }

    #[test]
    fn nothing_moves_a_slice_alone_before_its_life_ends() {
        let b = slice_lock(&keys(), SliceRole::Provider, 0, 9_216, &h(90))
            .unwrap()
            .flatten_spend_conditions();
        let since = 5_000;
        assert!(!branch_window_open(&b[2], since, since + 9_215));
        assert!(branch_window_open(&b[2], since, since + 9_216));
        let held = held_lock(&h(30), 1_248, &h(90))
            .unwrap()
            .flatten_spend_conditions();
        assert!(!branch_window_open(&held[0], since, since + 1_247));
        assert!(branch_window_open(&held[0], since, since + 1_248));
    }

    #[test]
    fn a_slice_that_would_be_unspendable_or_confusable_is_refused_by_its_own_cause() {
        let k = keys();
        let msg = |r: anyhow::Result<Lock>| format!("{:#}", r.expect_err("refused"));
        let s = |q: &SliceKeys| slice_lock(q, SliceRole::Provider, 0, 9_216, &h(90));
        assert!(
            msg(s(&SliceKeys {
                verdict: k.holder.clone(),
                ..k.clone()
            }))
            .contains("the holder and the verdict key")
        );
        for other in [k.holder.clone(), k.platform.clone()] {
            assert!(
                msg(s(&SliceKeys {
                    slasher: other,
                    ..k.clone()
                }))
                .contains("a stored slash signature would then satisfy another branch")
            );
        }
        assert!(
            msg(s(&SliceKeys {
                slasher: k.verdict.clone(),
                ..k.clone()
            }))
            .contains("the slasher and the verdict key")
        );
        assert!(
            msg(s(&SliceKeys {
                platform: k.holder.clone(),
                ..k.clone()
            }))
            .contains("the holder and the platform")
        );
        assert!(
            msg(s(&SliceKeys {
                platform: k.verdict.clone(),
                ..k.clone()
            }))
            .contains("an exit signature would satisfy the slash")
        );
        assert!(msg(slice_lock(&k, SliceRole::Provider, 0, 0, &h(90))).contains("t_life is zero"));
        assert!(
            msg(slice_lock(&k, SliceRole::Provider, PRIME, 9_216, &h(90))).contains("slice index")
        );
        let slot = slice_slot(SliceRole::Provider, 0).unwrap();
        assert!(
            msg(slice_lock(&k, SliceRole::Provider, 0, 9_216, &slot))
                .contains("are the same value")
        );
        let unbased = Hash::from_limbs(&[1, 2, PRIME, 4, 5]);
        assert!(
            msg(slice_lock(&k, SliceRole::Provider, 0, 9_216, &unbased))
                .contains("the bond's terms has a limb")
        );
        assert!(msg(held_lock(&h(30), 0, &h(90))).contains("hold is zero"));
        assert!(
            msg(reward_lock(&h(70), &h(40), &h(40)))
                .contains("the order digest and the convicted statement are the same value")
        );
    }

    #[test]
    fn the_role_cords_are_cords_not_small_integers() {
        for role in SliceRole::ALL {
            assert!(role.cord() > u64::from(u32::MAX) && role.cord() < PRIME);
        }
        assert_ne!(SliceRole::Provider.cord(), SliceRole::Checker.cord());
    }
}
