//! The escrow flow's three notes — ⚖️ `vesl-engine` `plans/port/STEP4.md` rulings 40–50.
//!
//! ⚑ *In plain terms: the buyer parks its money in a FUNDING note that only it and the
//! platform can move together (or it alone, after a long wait). When a provider takes the
//! job, the buyer's waiting software co-signs moving that money into a JOB note naming that
//! provider. The provider and the platform pay the job out of it together — the moment the
//! answer is served — into a PROVIDER note the provider can spend only after the challenge
//! window, and which the buyer and the platform can claw back inside it if a dispute is
//! decided for the buyer. Nobody can take the money alone, and nobody's absence strands it.*
//!
//! ```text
//! F  funding    1 FAST      [%pkh 2 {buyer_j, platform}]
//!               2 RECOVER   [%pkh 1 {buyer_j}]  AND [%tim rel.min = d_f]
//!               3 TAG       [%brn]              AND [%hax {order_digest, weight_root}]
//!               4 padding   [%brn]
//! J  job        1 CAPTURE   [%pkh 2 {platform, provider}] AND [%tim rel.max = d_j]
//!               2 FAST      [%pkh 2 {buyer_j, platform}]
//!               3 RECOVER   [%pkh 1 {buyer_j}]  AND [%tim rel.min = d_j + 1]
//!               4 TAG       [%brn]              AND [%hax {order_digest, weight_root}]
//! N  provider   1 PAY       [%pkh 1 {provider}] AND [%tim rel.min = c]
//!               2 CLAWBACK  [%pkh 2 {buyer_j, platform}] AND [%tim rel.max = c - 1]
//!               3 RESERVED  [%brn]              AND [%hax {order_digest, weight_root, record_root}]
//!               4 padding   [%brn]
//! ```
//!
//! ⛔ **Every operand, every branch number and every conjunct's position is part of the
//! address.** Renumbering a branch or reordering a conjunct moves every note of that shape,
//! fail-closed and silent until a live spend.
//!
//! ⚑ **Where each rule comes from, on the chain's own terms.**
//! - A `%tim` bound counts from the note's ORIGIN PAGE and both bounds are INCLUSIVE
//!   (`check:tim`, `nockchain/hoon/common/tx-engine-1.hoon:2149-2164`). ⇒ `rel.max = d`
//!   and `rel.min = d + 1` are disjoint and leave no gap; so are `c - 1` and `c`.
//! - ⛔ A zero relative bound is **dropped** (`TimelockRangeRelative::new`,
//!   `nockchain-types/src/tx_engine/common/mod.rs:517-520`), so `rel.max = 0` would open
//!   the CAPTURE branch forever. Every window here is refused at zero; `c` is refused
//!   below 2 because the clawback's bound is `c - 1`.
//! - `%hax` is a z-set: the order of its operands does not change the address and equal
//!   operands collapse (`tx-engine-1.hoon:2086-2103`). ⇒ two facts that are equal are
//!   refused, because the address would then carry one fact where the caller meant two.
//! - A `%brn` answers `%|` unconditionally, so a branch holding one is unspendable whatever
//!   sits beside it — which is what makes TAG and RESERVED free capacity in the ADDRESS
//!   (the same device as the retired hold's padding branch).
//! - ⛔ `sig-hash` covers the seeds and the fee, NOT the branch revealed
//!   (`tx-engine-1.hoon:1116-1120`). From `parent-hash-phase` a seed also names the note it
//!   spends (`:1093-1099`, `:1260-1261`), so a signature cannot be replayed onto another
//!   note; below it, it can (⚖️ ruling 47: named, not engineered around — `buyer_j` is a
//!   per-job key, so a buyer signature never spans two jobs). Within one note, the three
//!   parties are refused equal to one another, because two branches naming the same pair
//!   would accept each other's signatures.
//!
//! ⭐ **The exit.** Everything here composes upstream's four lock primitives; nothing edits
//! them. When upstream ships a proof-verifying primitive, RESERVED is the branch it replaces
//! — a new constructor beside this one, and a deletion of this one.

use nockchain_math::belt::{Belt, PRIME};
use nockchain_types::tx_engine::common::{
    BlockHeightDelta, Hash, TimelockRangeAbsolute, TimelockRangeRelative,
};
use nockchain_types::tx_engine::v1::tx::{
    Hax, Lock, LockPrimitive, LockTim, LockV2, LockV4, SpendCondition,
};

use crate::lock::pkh_conjunct;

/// Branch numbers of the FUNDING note, 1-based, as [`crate::lock::lock_merkle_proof`] takes
/// them. ⛔ Part of the address.
pub const FUNDING_BRANCH_FAST: u64 = 1;
/// See [`FUNDING_BRANCH_FAST`].
pub const FUNDING_BRANCH_RECOVER: u64 = 2;
/// See [`FUNDING_BRANCH_FAST`]. Unspendable: it carries the job's facts in the address.
pub const FUNDING_BRANCH_TAG: u64 = 3;
/// See [`FUNDING_BRANCH_FAST`]. Pure padding: three real branches pad to four.
pub const FUNDING_BRANCH_PADDING: u64 = 4;

/// Branch numbers of the JOB note. ⛔ Part of the address.
pub const JOB_BRANCH_CAPTURE: u64 = 1;
/// See [`JOB_BRANCH_CAPTURE`].
pub const JOB_BRANCH_FAST: u64 = 2;
/// See [`JOB_BRANCH_CAPTURE`].
pub const JOB_BRANCH_RECOVER: u64 = 3;
/// See [`JOB_BRANCH_CAPTURE`]. Unspendable: it carries the job's facts in the address.
pub const JOB_BRANCH_TAG: u64 = 4;

/// Branch numbers of the PROVIDER note. ⛔ Part of the address.
pub const PROVIDER_BRANCH_PAY: u64 = 1;
/// See [`PROVIDER_BRANCH_PAY`].
pub const PROVIDER_BRANCH_CLAWBACK: u64 = 2;
/// See [`PROVIDER_BRANCH_PAY`]. Unspendable today: the slot a future fraud-proof branch
/// reads — the three facts of the job, in the address.
pub const PROVIDER_BRANCH_RESERVED: u64 = 3;
/// See [`PROVIDER_BRANCH_PAY`]. Pure padding.
pub const PROVIDER_BRANCH_PADDING: u64 = 4;

/// The three keys a job names. `buyer_j` is the buyer's PER-JOB key (derived by its wallet
/// from its seed and the order digest), never its long-lived payment key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobParties {
    pub buyer_j: Hash,
    pub platform: Hash,
    pub provider: Hash,
}

/// The facts the escrow flow writes into every address it builds: what was ordered, and
/// which weights. The provider note adds the record root ([`provider_note_lock`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobFacts {
    pub order_digest: Hash,
    pub weight_root: Hash,
}

/// The FUNDING note — ⚖️ ruling 42's first box. The buyer builds it; it names no provider,
/// because none exists yet. See the module header for the shape.
///
/// `d_f` is the funding deadline in blocks, from the note's origin page: the buyer alone
/// recovers from `d_f` on. ⛔ An operand of the address, and a PER-NETWORK value
/// (⚖️ ruling 49) — the caller supplies it from its network's configuration.
pub fn funding_lock(
    buyer_j: &Hash,
    platform: &Hash,
    d_f: u64,
    facts: &JobFacts,
) -> anyhow::Result<Lock> {
    refuse_same_key(buyer_j, platform, "the buyer's job key", "the platform", "FAST")?;
    refuse_zero_window(d_f, "the funding deadline d_f", "RECOVER's rel.min")?;
    let fast = SpendCondition::new(vec![pkh_conjunct(
        2,
        vec![buyer_j.clone(), platform.clone()],
    )?]);
    let recover = SpendCondition::new(vec![
        pkh_conjunct(1, vec![buyer_j.clone()])?,
        relative(Some(d_f), None),
    ]);
    let tag = SpendCondition::new(vec![LockPrimitive::Burn, facts_hax(&facts_list(facts, None))?]);
    let padding = SpendCondition::new(vec![LockPrimitive::Burn]);
    Ok(four(fast, recover, tag, padding))
}

/// The JOB note — ⚖️ ruling 42's second box, created by the co-signed MOVE out of the
/// funding note (or out of the previous job note, on a re-offer).
///
/// `d_j` is the capture deadline in blocks from this note's origin page: platform +
/// provider may capture through `d_j` inclusive, and the buyer alone recovers from `d_j + 1`.
/// ⛔ An operand of the address and a PER-NETWORK value (⚖️ ruling 49).
pub fn job_lock(parties: &JobParties, d_j: u64, facts: &JobFacts) -> anyhow::Result<Lock> {
    refuse_distinct_parties(parties, "the job note")?;
    refuse_zero_window(d_j, "the capture deadline d_j", "CAPTURE's rel.max")?;
    let recover_from = d_j.checked_add(1).filter(|v| *v < PRIME).ok_or_else(|| {
        anyhow::anyhow!("the capture deadline d_j = {d_j} leaves no block for RECOVER to open at")
    })?;
    let capture = SpendCondition::new(vec![
        pkh_conjunct(2, vec![parties.platform.clone(), parties.provider.clone()])?,
        relative(None, Some(d_j)),
    ]);
    let fast = SpendCondition::new(vec![pkh_conjunct(
        2,
        vec![parties.buyer_j.clone(), parties.platform.clone()],
    )?]);
    let recover = SpendCondition::new(vec![
        pkh_conjunct(1, vec![parties.buyer_j.clone()])?,
        relative(Some(recover_from), None),
    ]);
    let tag = SpendCondition::new(vec![LockPrimitive::Burn, facts_hax(&facts_list(facts, None))?]);
    Ok(four(capture, fast, recover, tag))
}

/// The PROVIDER note — what the capture pays the provider into (⚖️ rulings 41, 43).
///
/// `c` is the challenge window in blocks from this note's origin page (the capture's
/// landing): the buyer + platform may claw back through `c - 1`, and the provider alone is
/// paid from `c` on. 1.152 blocks on the live chain (ruling 43); ⛔ an operand of the
/// address and a PER-NETWORK value (ruling 49).
///
/// `record_root` is the provider's working, from its signed release — the third fact, which
/// only exists once the job has been served.
pub fn provider_note_lock(
    parties: &JobParties,
    c: u64,
    facts: &JobFacts,
    record_root: &Hash,
) -> anyhow::Result<Lock> {
    refuse_distinct_parties(parties, "the provider note")?;
    anyhow::ensure!(
        c >= 2,
        "the challenge window c = {c} is too short: CLAWBACK's bound is rel.max = c - 1, and \
         a zero bound is DROPPED by the chain (TimelockRangeRelative::new), which would leave \
         the clawback open forever beside the provider's pay. Refusing to build it."
    );
    anyhow::ensure!(c < PRIME, "the challenge window c = {c} is not a field element");
    let pay = SpendCondition::new(vec![
        pkh_conjunct(1, vec![parties.provider.clone()])?,
        relative(Some(c), None),
    ]);
    let clawback = SpendCondition::new(vec![
        pkh_conjunct(2, vec![parties.buyer_j.clone(), parties.platform.clone()])?,
        relative(None, Some(c - 1)),
    ]);
    let reserved = SpendCondition::new(vec![
        LockPrimitive::Burn,
        facts_hax(&facts_list(facts, Some(record_root)))?,
    ]);
    let padding = SpendCondition::new(vec![LockPrimitive::Burn]);
    Ok(four(pay, clawback, reserved, padding))
}

/// Whether a branch's `%tim` conjuncts are satisfied at height `now` for a note whose
/// origin page is `since` — the Rust mirror of `check:tim` (`tx-engine-1.hoon:2149-2164`),
/// applied to every `%tim` in the branch. A branch with no `%tim` is always open.
///
/// ⚑ It answers only the TIME question. Signatures, preimages and burns are other
/// conjuncts' business; a caller asking "may I submit this spend yet?" wants this.
pub fn branch_window_open(branch: &SpendCondition, since: u64, now: u64) -> bool {
    branch.0.iter().all(|p| match p {
        LockPrimitive::Tim(t) => tim_open(t, since, now),
        _ => true,
    })
}

fn tim_open(t: &LockTim, since: u64, now: u64) -> bool {
    let (since, now) = (u128::from(since), u128::from(now));
    let d = |x: &BlockHeightDelta| u128::from(x.0.0);
    let rmin = t.rel.min.as_ref().is_none_or(|m| now >= since + d(m));
    let rmax = t.rel.max.as_ref().is_none_or(|m| now <= since + d(m));
    let amin = t.abs.min.as_ref().is_none_or(|m| now >= u128::from(m.0.0));
    let amax = t.abs.max.as_ref().is_none_or(|m| now <= u128::from(m.0.0));
    rmin && rmax && amin && amax
}

pub(crate) fn relative(min: Option<u64>, max: Option<u64>) -> LockPrimitive {
    LockPrimitive::Tim(LockTim {
        rel: TimelockRangeRelative::new(
            min.map(|v| BlockHeightDelta(Belt(v))),
            max.map(|v| BlockHeightDelta(Belt(v))),
        ),
        abs: TimelockRangeAbsolute::none(),
    })
}

pub(crate) fn four(a: SpendCondition, b: SpendCondition, c: SpendCondition, d: SpendCondition) -> Lock {
    Lock::V4(LockV4 {
        p: LockV2 { p: a, q: b },
        q: LockV2 { p: c, q: d },
    })
}

fn facts_list(facts: &JobFacts, record_root: Option<&Hash>) -> Vec<(&'static str, Hash)> {
    let mut v = vec![
        ("the order digest", facts.order_digest.clone()),
        ("the weight root", facts.weight_root.clone()),
    ];
    if let Some(r) = record_root {
        v.push(("the record root", r.clone()));
    }
    v
}

/// The `%hax` carrying the job's facts, refusing a fact that is not a digest (a limb at or
/// above the field prime) and two facts that are equal (the z-set would collapse them).
pub(crate) fn facts_hax(facts: &[(&'static str, Hash)]) -> anyhow::Result<LockPrimitive> {
    for (name, h) in facts {
        if let Some(limb) = h.to_array().iter().find(|l| **l >= PRIME) {
            anyhow::bail!(
                "{name} has a limb {limb} at or above the field prime, so it is not a digest \
                 anything could have produced. Refusing to write it into an address."
            );
        }
    }
    for (i, (a, ha)) in facts.iter().enumerate() {
        for (b, hb) in &facts[..i] {
            anyhow::ensure!(
                ha != hb,
                "{b} and {a} are the same value. The address's %hax is a z-set, so the two \
                 would collapse into one entry and the address would carry one fact where \
                 two were meant. Refusing to build it."
            );
        }
    }
    let hax = Hax(nockchain_math::zoon::zset::ZSet::try_from_items(
        facts.iter().map(|(_, h)| h.clone()),
    )
    .map_err(|e| anyhow::anyhow!("the facts' %hax set would not build: {e:?}"))?);
    Ok(LockPrimitive::Hax(hax))
}

pub(crate) fn refuse_same_key(a: &Hash, b: &Hash, an: &str, bn: &str, branch: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        a != b,
        "{an} and {bn} are the same key. {branch}'s 2-of-2 would collapse through the z-set's \
         silent dedup into a one-element set still demanding two signatures, so the branch \
         would be unsatisfiable. Refusing to build it."
    );
    Ok(())
}

/// ⛔ The three parties must be three different keys. Equal pairs collapse a 2-of-2
/// (unsatisfiable), and — the case no shape test sees — a provider equal to the buyer's job
/// key would let one pair's co-signature be revealed on another pair's branch: `sig-hash`
/// does not cover the branch.
fn refuse_distinct_parties(p: &JobParties, note: &str) -> anyhow::Result<()> {
    refuse_same_key(&p.buyer_j, &p.platform, "the buyer's job key", "the platform", "FAST")?;
    anyhow::ensure!(
        p.provider != p.platform,
        "the provider and the platform are the same key in {note}: its platform + provider \
         2-of-2 would collapse into one key demanding two signatures, and the platform would \
         in any case be paying itself. Refusing to build it."
    );
    anyhow::ensure!(
        p.provider != p.buyer_j,
        "the provider and the buyer's job key are the same key in {note}: the buyer + platform \
         co-signature would then satisfy the provider's branch, and the provider's the buyer's \
         — sig-hash does not cover which branch is revealed. Refusing to build it."
    );
    Ok(())
}

pub(crate) fn refuse_zero_window(v: u64, what: &str, bound: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        v != 0,
        "{what} is zero. {bound} would be DROPPED by the chain (TimelockRangeRelative::new \
         filters a zero bound), so the window would not exist at all. Refusing to build it."
    );
    anyhow::ensure!(v < PRIME, "{what} = {v} is not a field element");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{lock_merkle_proof, lock_root};

    fn h(n: u64) -> Hash {
        Hash::from_limbs(&[n, n + 1, n + 2, n + 3, n + 4])
    }
    fn parties() -> JobParties {
        JobParties {
            buyer_j: h(10),
            platform: h(20),
            provider: h(30),
        }
    }
    fn facts() -> JobFacts {
        JobFacts {
            order_digest: h(40),
            weight_root: h(50),
        }
    }
    fn branches(lock: &Lock) -> Vec<SpendCondition> {
        lock.flatten_spend_conditions()
    }
    fn root(lock: anyhow::Result<Lock>) -> Hash {
        lock_root(&lock.expect("builds")).expect("hashes")
    }

    #[test]
    fn each_note_is_the_ruled_four_branch_shape() {
        let f = funding_lock(&h(10), &h(20), 500, &facts()).unwrap();
        let b = branches(&f);
        assert_eq!(b.len(), 4);
        assert!(matches!(&b[0].0[..], [LockPrimitive::Pkh(p)] if p.m == 2));
        assert!(
            matches!(&b[1].0[..], [LockPrimitive::Pkh(p), LockPrimitive::Tim(t)]
            if p.m == 1 && t.rel.min == Some(BlockHeightDelta(Belt(500))) && t.rel.max.is_none())
        );
        assert!(matches!(&b[2].0[..], [LockPrimitive::Burn, LockPrimitive::Hax(_)]));
        assert!(matches!(&b[3].0[..], [LockPrimitive::Burn]));

        let j = job_lock(&parties(), 90, &facts()).unwrap();
        let b = branches(&j);
        assert!(
            matches!(&b[0].0[..], [LockPrimitive::Pkh(p), LockPrimitive::Tim(t)]
            if p.m == 2 && t.rel.max == Some(BlockHeightDelta(Belt(90))) && t.rel.min.is_none())
        );
        assert!(matches!(&b[1].0[..], [LockPrimitive::Pkh(p)] if p.m == 2));
        assert!(
            matches!(&b[2].0[..], [LockPrimitive::Pkh(p), LockPrimitive::Tim(t)]
            if p.m == 1 && t.rel.min == Some(BlockHeightDelta(Belt(91))))
        );
        assert!(matches!(&b[3].0[..], [LockPrimitive::Burn, LockPrimitive::Hax(_)]));

        let n = provider_note_lock(&parties(), 1152, &facts(), &h(60)).unwrap();
        let b = branches(&n);
        assert!(
            matches!(&b[0].0[..], [LockPrimitive::Pkh(p), LockPrimitive::Tim(t)]
            if p.m == 1 && t.rel.min == Some(BlockHeightDelta(Belt(1152))))
        );
        assert!(
            matches!(&b[1].0[..], [LockPrimitive::Pkh(p), LockPrimitive::Tim(t)]
            if p.m == 2 && t.rel.max == Some(BlockHeightDelta(Belt(1151))))
        );
        assert!(matches!(&b[2].0[..], [LockPrimitive::Burn, LockPrimitive::Hax(x)] if x.0.iter().count() == 3));
        assert!(matches!(&b[3].0[..], [LockPrimitive::Burn]));
    }

    #[test]
    fn each_branch_names_the_keys_it_should() {
        let keys = |sc: &SpendCondition| -> Vec<Hash> {
            match &sc.0[0] {
                LockPrimitive::Pkh(p) => {
                    let mut v: Vec<Hash> = p.hashes.iter().cloned().collect();
                    v.sort_by_key(|x| x.to_array());
                    v
                }
                _ => vec![],
            }
        };
        let p = parties();
        let j = branches(&job_lock(&p, 90, &facts()).unwrap());
        assert_eq!(keys(&j[0]), vec![p.platform.clone(), p.provider.clone()]);
        assert_eq!(keys(&j[1]), vec![p.buyer_j.clone(), p.platform.clone()]);
        assert_eq!(keys(&j[2]), vec![p.buyer_j.clone()]);
        let n = branches(&provider_note_lock(&p, 1152, &facts(), &h(60)).unwrap());
        assert_eq!(keys(&n[0]), vec![p.provider.clone()]);
        assert_eq!(keys(&n[1]), vec![p.buyer_j.clone(), p.platform.clone()]);
        let f = branches(&funding_lock(&p.buyer_j, &p.platform, 500, &facts()).unwrap());
        assert_eq!(keys(&f[0]), vec![p.buyer_j.clone(), p.platform.clone()]);
        assert_eq!(keys(&f[1]), vec![p.buyer_j.clone()]);
    }

    #[test]
    fn every_real_branch_of_every_note_is_provable() {
        let locks = [
            funding_lock(&h(10), &h(20), 500, &facts()).unwrap(),
            job_lock(&parties(), 90, &facts()).unwrap(),
            provider_note_lock(&parties(), 1152, &facts(), &h(60)).unwrap(),
        ];
        for lock in &locks {
            for k in 1..=4 {
                let proof = lock_merkle_proof(lock, k, 10, 1).expect("provable");
                assert_eq!(proof.proof().root, lock_root(lock).unwrap());
            }
        }
    }

    #[test]
    fn every_address_binds_every_operand() {
        let p = parties();
        let f = facts();
        let other = |x: &Hash| Hash::from_limbs(&{
            let mut a = x.to_array();
            a[4] += 1000;
            a
        });
        let base = root(funding_lock(&p.buyer_j, &p.platform, 500, &f));
        assert_ne!(base, root(funding_lock(&other(&p.buyer_j), &p.platform, 500, &f)));
        assert_ne!(base, root(funding_lock(&p.buyer_j, &other(&p.platform), 500, &f)));
        assert_ne!(base, root(funding_lock(&p.buyer_j, &p.platform, 501, &f)));
        let f2 = JobFacts { order_digest: other(&f.order_digest), ..f.clone() };
        assert_ne!(base, root(funding_lock(&p.buyer_j, &p.platform, 500, &f2)));
        let f3 = JobFacts { weight_root: other(&f.weight_root), ..f.clone() };
        assert_ne!(base, root(funding_lock(&p.buyer_j, &p.platform, 500, &f3)));

        let base = root(job_lock(&p, 90, &f));
        for q in [
            JobParties { buyer_j: other(&p.buyer_j), ..p.clone() },
            JobParties { platform: other(&p.platform), ..p.clone() },
            JobParties { provider: other(&p.provider), ..p.clone() },
        ] {
            assert_ne!(base, root(job_lock(&q, 90, &f)));
        }
        assert_ne!(base, root(job_lock(&p, 91, &f)));
        assert_ne!(base, root(job_lock(&p, 90, &f2)));
        assert_ne!(base, root(job_lock(&p, 90, &f3)));

        let base = root(provider_note_lock(&p, 1152, &f, &h(60)));
        for q in [
            JobParties { buyer_j: other(&p.buyer_j), ..p.clone() },
            JobParties { platform: other(&p.platform), ..p.clone() },
            JobParties { provider: other(&p.provider), ..p.clone() },
        ] {
            assert_ne!(base, root(provider_note_lock(&q, 1152, &f, &h(60))));
        }
        assert_ne!(base, root(provider_note_lock(&p, 1153, &f, &h(60))));
        assert_ne!(base, root(provider_note_lock(&p, 1152, &f2, &h(60))));
        assert_ne!(base, root(provider_note_lock(&p, 1152, &f3, &h(60))));
        assert_ne!(base, root(provider_note_lock(&p, 1152, &f, &h(61))));
    }

    #[test]
    fn the_three_notes_never_share_an_address() {
        // ⛔ One transaction creates N beside the buyer's change and the commission, and a
        // re-offer creates J from J — equal roots would merge seeds (`build-outputs`).
        let p = parties();
        let f = funding_lock(&p.buyer_j, &p.platform, 90, &facts()).unwrap();
        let j = job_lock(&p, 90, &facts()).unwrap();
        let n = provider_note_lock(&p, 90, &facts(), &h(60)).unwrap();
        let roots = [&f, &j, &n].map(|l| lock_root(l).unwrap());
        assert_ne!(roots[0], roots[1]);
        assert_ne!(roots[1], roots[2]);
        assert_ne!(roots[0], roots[2]);
    }

    #[test]
    fn a_job_note_for_another_provider_is_another_address() {
        // A re-offer moves J to J' naming the next provider; J' must not stand at J's address.
        let p = parties();
        let q = JobParties { provider: h(31), ..p.clone() };
        assert_ne!(root(job_lock(&p, 90, &facts())), root(job_lock(&q, 90, &facts())));
    }

    #[test]
    fn the_facts_do_not_depend_on_the_order_they_are_listed_in() {
        // `%hax` is a z-set: this is the chain's rule, pinned so nobody "fixes" an order.
        let a = facts_hax(&[("a", h(40)), ("b", h(50)), ("c", h(60))]).unwrap();
        let b = facts_hax(&[("c", h(60)), ("a", h(40)), ("b", h(50))]).unwrap();
        let hash = |p: LockPrimitive| SpendCondition::new(vec![LockPrimitive::Burn, p]).hash().unwrap();
        assert_eq!(hash(a), hash(b));
    }

    #[test]
    fn the_windows_meet_without_a_gap_or_an_overlap() {
        let since = 1_000;
        let j = branches(&job_lock(&parties(), 90, &facts()).unwrap());
        let (capture, recover) = (&j[0], &j[2]);
        assert!(branch_window_open(capture, since, since));
        assert!(branch_window_open(capture, since, since + 90));
        assert!(!branch_window_open(capture, since, since + 91));
        assert!(!branch_window_open(recover, since, since + 90));
        assert!(branch_window_open(recover, since, since + 91));
        assert!(branch_window_open(&j[1], since, u64::MAX), "FAST has no clock");

        let n = branches(&provider_note_lock(&parties(), 1152, &facts(), &h(60)).unwrap());
        let (pay, clawback) = (&n[0], &n[1]);
        assert!(branch_window_open(clawback, since, since + 1151));
        assert!(!branch_window_open(clawback, since, since + 1152));
        assert!(!branch_window_open(pay, since, since + 1151));
        assert!(branch_window_open(pay, since, since + 1152));
        for now in since..since + 1300 {
            assert_ne!(
                branch_window_open(pay, since, now),
                branch_window_open(clawback, since, now),
                "at {now} exactly one of pay and clawback is open"
            );
        }

        let f = branches(&funding_lock(&h(10), &h(20), 500, &facts()).unwrap());
        assert!(!branch_window_open(&f[1], since, since + 499));
        assert!(branch_window_open(&f[1], since, since + 500));
    }

    #[test]
    fn a_note_that_would_be_unspendable_or_replayable_is_refused_by_its_own_cause() {
        let p = parties();
        let f = facts();
        let msg = |r: anyhow::Result<Lock>| format!("{:#}", r.expect_err("refused"));

        assert!(msg(funding_lock(&h(10), &h(10), 500, &f)).contains("the buyer's job key and the platform"));
        assert!(msg(funding_lock(&h(10), &h(20), 0, &f)).contains("funding deadline d_f is zero"));

        let same_bp = JobParties { platform: p.buyer_j.clone(), ..p.clone() };
        let same_pp = JobParties { provider: p.platform.clone(), ..p.clone() };
        let same_pb = JobParties { provider: p.buyer_j.clone(), ..p.clone() };
        for build in [
            &(|q: &JobParties| job_lock(q, 90, &f)) as &dyn Fn(&JobParties) -> anyhow::Result<Lock>,
            &|q: &JobParties| provider_note_lock(q, 1152, &f, &h(60)),
        ] {
            assert!(msg(build(&same_bp)).contains("the buyer's job key and the platform"));
            assert!(msg(build(&same_pp)).contains("the provider and the platform are the same key"));
            assert!(msg(build(&same_pb)).contains("sig-hash does not cover which branch"));
        }

        assert!(msg(job_lock(&p, 0, &f)).contains("capture deadline d_j is zero"));
        assert!(msg(job_lock(&p, PRIME - 1, &f)).contains("leaves no block for RECOVER"));
        assert!(msg(provider_note_lock(&p, 1, &f, &h(60))).contains("challenge window c = 1 is too short"));
        assert!(msg(provider_note_lock(&p, 0, &f, &h(60))).contains("too short"));

        let equal = JobFacts { order_digest: h(40), weight_root: h(40) };
        assert!(msg(job_lock(&p, 90, &equal)).contains("the order digest and the weight root are the same value"));
        assert!(msg(provider_note_lock(&p, 1152, &f, &h(50))).contains("the weight root and the record root are the same value"));

        let unbased = Hash::from_limbs(&[1, 2, PRIME, 4, 5]);
        let bad = JobFacts { order_digest: unbased, ..f.clone() };
        assert!(msg(funding_lock(&h(10), &h(20), 500, &bad)).contains("the order digest has a limb"));
    }
}
