//! A re-check's notes, and the demand — ⚖️ `vesl-engine` `plans/port/DISPUTE-DESIGN.md` §4,
//! §5, §7 (rulings 63, 66, 67, 68, 76, 81, 82).
//!
//! ⚑ *In plain terms: a buyer who doubts an answer funds a CHECK the same way it funded the
//! job. Once a checker is drawn, the check's money moves into a TICKET naming that checker.
//! If the checker vouches the record clean, the platform and the checker pay the fee into the
//! checker's VOUCH note — which the checker may spend only once the job's window closes, and
//! which carries, in its address, what it vouched for. If the checker proves a fault, the
//! verdict key and the checker spend the ticket inside the claim. If the checker reports
//! nothing, the buyer takes its fee back alone. A DEMAND asks the provider to open part of
//! its record: the provider takes the checker's deposit by answering in time; after that,
//! only the checker can spend it — so silence is a fact of the chain, not anyone's word.*
//!
//! ```text
//! F_c  funding    = crate::job_locks::funding_lock over {salted digest, weight root}
//! J_c  ticket   1 CAPTURE-CLEAN  [%pkh 2 {platform, checker}] AND [%tim abs.max = report_by]
//!               2 CLAIM          [%pkh 2 {verdict, checker}]  AND [%tim abs.max = claim_by]
//!               3 RETURN         [%pkh 1 {buyer_c}]           AND [%tim abs.min = report_by + 1]
//!               4 TAG            [%brn] AND [%hax {salted digest, weight root}]
//! N_c  vouch    1 PAY            [%pkh 1 {checker}]           AND [%tim abs.min = n_origin + c]
//!               2 CLAWBACK       [%pkh 2 {buyer_c, platform}] AND [%tim abs.max = n_origin + c - 1]
//!               3 VOUCH-FRAUD    [%brn] AND [%hax {salted digest, vouched root, checker}]
//!               4 padding        [%brn]
//! D    demand   1 ANSWER         [%pkh 1 {provider}]          AND [%tim rel.max = answer_by]
//!               2 EXPIRED        [%pkh 1 {checker}]           AND [%tim rel.min = answer_by + 1]
//!               3 RESERVED       [%brn] AND [%hax {salted digest, record root, slot(round)}]
//!               4 padding        [%brn]
//! ```
//!
//! ⭐ **The fleet's first ABSOLUTE timelocks** (`N_c`, `J_c`'s CLAIM). `N_c` is created by a
//! capture long after `N`, yet its pay must open exactly when `N`'s does — at `N`'s origin
//! plus `c` — so the bound is written as a height, not a delay. `check:tim` treats absolute
//! bounds as inclusive, like relative ones (`tx-engine-1.hoon:2149-2164`) ⇒ `c − 1` and `c`
//! still meet without a gap. ⛔ A zero absolute bound is DROPPED too
//! (`TimelockRangeAbsolute::new`, `nockchain-types/src/tx_engine/common/mod.rs:341-345`).
//!
//! ⚑ **Binding refinements of the design, stated.**
//! - §7 says CLAIM is *"checker + platform (82)"*. It is built on the platform's VERDICT key
//!   `Kv`, not its funding key `Kf`: with `Kf` it would name the same pair as CAPTURE-CLEAN,
//!   and `sig-hash` does not cover the branch — so CAPTURE-CLEAN's `rel.max` would bound
//!   nothing. Ruling 69 makes `Kv` the platform's, so ruling 82 holds.
//! - §7 writes the ticket's report deadline as `rel.max`. It is built ABSOLUTE (`request + 240`,
//!   §3): the ticket's address is computed before it lands, when its origin — the base of a
//!   relative bound — is not yet known, and every party can derive the request's height.
//! - CLAIM gains `abs.max = claim_by` (§3's 1.103 after `N`'s origin), so *"a claim after
//!   1.103"* — an ORACLE negative in §13 — is refused by the chain on the ticket's side.
//! - RETURN opens at `report_by + 1` (§7) while CLAIM stays open to `claim_by`: a buyer that
//!   takes its fee back in between spends the ticket a pending claim needs. Only the buyer
//!   can do that, and it forfeits its own refund and slash share by it — named, not closed.
//!
//! ⭐ **The exit (stub register S3, S5).** `N_c`'s CLAWBACK and VOUCH-FRAUD's `%brn` become
//! `%zkp F_vslice`; `D`'s ANSWER gains `%zkp F_answer`; `J_c`'s CLAIM gains the co-spend
//! check. Each is a new constructor beside these and a deletion of these.

use nockchain_math::belt::{Belt, PRIME};
use nockchain_types::tx_engine::common::{
    BlockHeight, Hash, TimelockRangeAbsolute, TimelockRangeRelative,
};
use nockchain_types::tx_engine::v1::tx::{Lock, LockPrimitive, LockTim, SpendCondition};

use crate::job_locks::{JobFacts, facts_hax, four, funding_lock, refuse_zero_window, relative};
use crate::lock::pkh_conjunct;

/// Branch numbers of the TICKET `J_c`. ⛔ Part of the address.
pub const TICKET_BRANCH_CAPTURE_CLEAN: u64 = 1;
/// See [`TICKET_BRANCH_CAPTURE_CLEAN`]. The verdict key and the checker, inside a claim.
pub const TICKET_BRANCH_CLAIM: u64 = 2;
/// See [`TICKET_BRANCH_CAPTURE_CLEAN`]. The buyer alone, once the report is late.
pub const TICKET_BRANCH_RETURN: u64 = 3;
/// See [`TICKET_BRANCH_CAPTURE_CLEAN`]. Unspendable: the check's facts, in the address.
pub const TICKET_BRANCH_TAG: u64 = 4;

/// Branch numbers of the VOUCH note `N_c`. ⛔ Part of the address.
pub const VOUCH_BRANCH_PAY: u64 = 1;
/// See [`VOUCH_BRANCH_PAY`].
pub const VOUCH_BRANCH_CLAWBACK: u64 = 2;
/// See [`VOUCH_BRANCH_PAY`]. Unspendable today: what the checker vouched for, in the address
/// — the slot `%zkp F_vslice` takes.
pub const VOUCH_BRANCH_FRAUD: u64 = 3;
/// See [`VOUCH_BRANCH_PAY`]. Pure padding.
pub const VOUCH_BRANCH_PADDING: u64 = 4;

/// Branch numbers of a DEMAND `D`. ⛔ Part of the address.
pub const DEMAND_BRANCH_ANSWER: u64 = 1;
/// See [`DEMAND_BRANCH_ANSWER`]. A WITHHELD claim spends the demand here.
pub const DEMAND_BRANCH_EXPIRED: u64 = 2;
/// See [`DEMAND_BRANCH_ANSWER`]. Unspendable: which job, which record, which round.
pub const DEMAND_BRANCH_RESERVED: u64 = 3;
/// See [`DEMAND_BRANCH_ANSWER`]. Pure padding.
pub const DEMAND_BRANCH_PADDING: u64 = 4;

/// The cord a demand's round slot carries — a cord, so a round never aliases a slice slot.
pub const DEMAND_ROUND_CORD: u64 = u64::from_le_bytes(*b"demand-r");

/// The four keys a check names. `buyer_c` is the buyer's PER-CHECK key (derived by its
/// wallet, like `buyer_j`), so a buyer signature never spans two checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckParties {
    pub buyer_c: Hash,
    /// The platform's funding key `Kf`.
    pub platform: Hash,
    /// The platform's verdict key `Kv` (ruling 69).
    pub verdict: Hash,
    /// The drawn checker (ruling 63).
    pub checker: Hash,
}

/// What a check writes into its addresses: the PER-CHECK salted job digest (so nobody on
/// chain can tell which checks share a job — H-2) and the job's weight root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckFacts {
    pub salted_digest: Hash,
    pub weight_root: Hash,
}

/// The check's FUNDING note `F_c` — the escrow flow's own funding shape (§2: *"a checker's
/// job on the same flow"*), over the salted digest in place of the order digest.
pub fn check_funding_lock(
    buyer_c: &Hash,
    platform: &Hash,
    d_f: u64,
    facts: &CheckFacts,
) -> anyhow::Result<Lock> {
    funding_lock(buyer_c, platform, d_f, &job_facts(facts))
}

/// The TICKET `J_c`, created by the co-signed move out of `F_c` once the draw names the
/// checker. `report_by` is the absolute height of the report deadline (the request's height
/// + 240, §3) and `claim_by` the absolute height after which no claim is included (`N`'s
/// origin + 1.103, §3); a claim may land after the report, never before it is due, so
/// `claim_by` must lie beyond `report_by`. ⛔ Both are operands of the address.
pub fn ticket_lock(
    parties: &CheckParties,
    report_by: u64,
    claim_by: u64,
    facts: &CheckFacts,
) -> anyhow::Result<Lock> {
    refuse_distinct_check_parties(parties, "the ticket")?;
    refuse_zero_height(
        report_by, "the report deadline report_by", "CAPTURE-CLEAN's abs.max",
    )?;
    refuse_zero_height(claim_by, "the claim deadline claim_by", "CLAIM's abs.max")?;
    anyhow::ensure!(
        claim_by > report_by,
        "the claim deadline {claim_by} is not after the report deadline {report_by}: a fault \
         reported on time could then never be claimed. Refusing to build it."
    );
    let return_from = report_by
        .checked_add(1)
        .filter(|v| *v < PRIME)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the report deadline report_by = {report_by} leaves no block for RETURN"
            )
        })?;
    let capture = SpendCondition::new(vec![
        pkh_conjunct(2, vec![parties.platform.clone(), parties.checker.clone()])?,
        absolute(None, Some(report_by)),
    ]);
    let claim = SpendCondition::new(vec![
        pkh_conjunct(2, vec![parties.verdict.clone(), parties.checker.clone()])?,
        absolute(None, Some(claim_by)),
    ]);
    let ret = SpendCondition::new(vec![
        pkh_conjunct(1, vec![parties.buyer_c.clone()])?,
        absolute(Some(return_from), None),
    ]);
    let tag = SpendCondition::new(vec![LockPrimitive::Burn, facts_hax(&facts_list(facts))?]);
    Ok(four(capture, claim, ret, tag))
}

/// The VOUCH note `N_c`, created by a CLEAN capture. `n_origin` is the origin height of the
/// provider note `N` this check is about, and `c` its window (1.152 live): the checker is
/// paid from exactly the height `N`'s provider is (ruling 55). `vouched_root` is the record
/// root the checker vouched for. ⛔ All are operands of the address.
pub fn vouch_note_lock(
    parties: &CheckParties,
    n_origin: u64,
    c: u64,
    salted_digest: &Hash,
    vouched_root: &Hash,
) -> anyhow::Result<Lock> {
    refuse_distinct_check_parties(parties, "the vouch note")?;
    anyhow::ensure!(
        c >= 2,
        "the challenge window c = {c} is too short: CLAWBACK's bound is n_origin + c - 1, and \
         PAY's is n_origin + c; below 2 they cannot meet as the provider note's do. Refusing \
         to build it."
    );
    let pay_from = n_origin
        .checked_add(c)
        .filter(|v| *v < PRIME)
        .ok_or_else(|| anyhow::anyhow!("N's origin {n_origin} + c {c} is not a field element"))?;
    let pay = SpendCondition::new(vec![
        pkh_conjunct(1, vec![parties.checker.clone()])?,
        absolute(Some(pay_from), None),
    ]);
    let clawback = SpendCondition::new(vec![
        pkh_conjunct(2, vec![parties.buyer_c.clone(), parties.platform.clone()])?,
        absolute(None, Some(pay_from - 1)),
    ]);
    let fraud = SpendCondition::new(vec![
        LockPrimitive::Burn,
        facts_hax(&[
            ("the salted digest", salted_digest.clone()),
            ("the vouched root", vouched_root.clone()),
            ("the checker", parties.checker.clone()),
        ])?,
    ]);
    let padding = SpendCondition::new(vec![LockPrimitive::Burn]);
    Ok(four(pay, clawback, fraud, padding))
}

/// The slot a demand's RESERVED branch carries: its round. `[cord, round, 0, 0, 0]`.
pub fn demand_slot(round: u64) -> anyhow::Result<Hash> {
    anyhow::ensure!(
        round < PRIME,
        "the demand round {round} is not a field element"
    );
    Ok(Hash::from_limbs(&[DEMAND_ROUND_CORD, round, 0, 0, 0]))
}

/// A DEMAND `D` (§5). ⭐ Its address derives from the job and the round alone (H-5): the
/// provider polls the addresses it can compute and ignores any other. `answer_by` is the
/// answer window in blocks from this note's origin (24, ASSUMED). ⛔ All are operands.
pub fn demand_lock(
    provider: &Hash,
    checker: &Hash,
    answer_by: u64,
    salted_digest: &Hash,
    record_root: &Hash,
    round: u64,
) -> anyhow::Result<Lock> {
    anyhow::ensure!(
        provider != checker,
        "the provider and the checker are the same key: a provider may never check its own \
         job (ruling 63), and ANSWER and EXPIRED would then both be its to spend. Refusing \
         to build it."
    );
    refuse_zero_window(answer_by, "the answer window answer_by", "ANSWER's rel.max")?;
    let expired_from = answer_by
        .checked_add(1)
        .filter(|v| *v < PRIME)
        .ok_or_else(|| {
            anyhow::anyhow!("the answer window answer_by = {answer_by} leaves no block for EXPIRED")
        })?;
    let answer = SpendCondition::new(vec![
        pkh_conjunct(1, vec![provider.clone()])?,
        relative(None, Some(answer_by)),
    ]);
    let expired = SpendCondition::new(vec![
        pkh_conjunct(1, vec![checker.clone()])?,
        relative(Some(expired_from), None),
    ]);
    let reserved = SpendCondition::new(vec![
        LockPrimitive::Burn,
        facts_hax(&[
            ("the salted digest", salted_digest.clone()),
            ("the record root", record_root.clone()),
            ("the round's slot", demand_slot(round)?),
        ])?,
    ]);
    let padding = SpendCondition::new(vec![LockPrimitive::Burn]);
    Ok(four(answer, expired, reserved, padding))
}

fn job_facts(f: &CheckFacts) -> JobFacts {
    JobFacts {
        order_digest: f.salted_digest.clone(),
        weight_root: f.weight_root.clone(),
    }
}

fn facts_list(f: &CheckFacts) -> Vec<(&'static str, Hash)> {
    vec![
        ("the salted digest", f.salted_digest.clone()),
        ("the weight root", f.weight_root.clone()),
    ]
}

fn absolute(min: Option<u64>, max: Option<u64>) -> LockPrimitive {
    LockPrimitive::Tim(LockTim {
        rel: TimelockRangeRelative::none(),
        abs: TimelockRangeAbsolute::new(
            min.map(|v| BlockHeight(Belt(v))),
            max.map(|v| BlockHeight(Belt(v))),
        ),
    })
}

fn refuse_zero_height(v: u64, what: &str, bound: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        v != 0,
        "{what} is zero. {bound} would be DROPPED by the chain (TimelockRangeAbsolute::new \
         filters a zero bound), so the deadline would not exist at all. Refusing to build it."
    );
    anyhow::ensure!(v < PRIME, "{what} = {v} is not a field element");
    Ok(())
}

/// ⛔ The four parties must be four different keys: equal pairs collapse a 2-of-2, and —
/// because `sig-hash` does not cover the branch revealed — any key shared between two
/// branches' sets lets one branch's signatures be revealed on another.
fn refuse_distinct_check_parties(p: &CheckParties, note: &str) -> anyhow::Result<()> {
    let named = [
        ("the buyer's check key", &p.buyer_c),
        ("the platform", &p.platform),
        ("the verdict key", &p.verdict),
        ("the checker", &p.checker),
    ];
    for (i, (a, ka)) in named.iter().enumerate() {
        for (b, kb) in &named[..i] {
            anyhow::ensure!(
                ka != kb,
                "{b} and {a} are the same key in {note}: a 2-of-2 naming both would collapse \
                 through the z-set's dedup, and sig-hash does not cover the branch revealed, so \
                 one party's signatures would satisfy another's branch. Refusing to build it."
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job_locks::branch_window_open;
    use crate::lock::{lock_merkle_proof, lock_root};

    fn h(n: u64) -> Hash {
        Hash::from_limbs(&[n, n + 1, n + 2, n + 3, n + 4])
    }
    fn parties() -> CheckParties {
        CheckParties {
            buyer_c: h(10),
            platform: h(20),
            verdict: h(70),
            checker: h(80),
        }
    }
    fn facts() -> CheckFacts {
        CheckFacts {
            salted_digest: h(45),
            weight_root: h(50),
        }
    }
    fn root(lock: anyhow::Result<Lock>) -> Hash {
        lock_root(&lock.expect("builds")).expect("hashes")
    }
    fn branches(lock: anyhow::Result<Lock>) -> Vec<SpendCondition> {
        lock.expect("builds").flatten_spend_conditions()
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
    fn each_note_is_the_ruled_shape_naming_the_keys_it_should() {
        let p = parties();
        let j = branches(ticket_lock(&p, 100_540, 101_103, &facts()));
        assert_eq!(pkh_keys(&j[0]), vec![p.platform.clone(), p.checker.clone()]);
        assert_eq!(pkh_keys(&j[1]), vec![p.verdict.clone(), p.checker.clone()]);
        assert_eq!(pkh_keys(&j[2]), vec![p.buyer_c.clone()]);
        assert!(
            matches!(&j[1].0[..], [LockPrimitive::Pkh(_), LockPrimitive::Tim(t)]
            if t.abs.max == Some(BlockHeight(Belt(101_103))) && t.rel.min.is_none() && t.rel.max.is_none())
        );
        assert!(
            matches!(&j[3].0[..], [LockPrimitive::Burn, LockPrimitive::Hax(x)] if x.0.iter().count() == 2)
        );

        let n = branches(vouch_note_lock(&p, 100_000, 1_152, &h(45), &h(60)));
        assert_eq!(pkh_keys(&n[0]), vec![p.checker.clone()]);
        assert_eq!(pkh_keys(&n[1]), vec![p.buyer_c.clone(), p.platform.clone()]);
        assert!(
            matches!(&n[0].0[..], [LockPrimitive::Pkh(_), LockPrimitive::Tim(t)]
            if t.abs.min == Some(BlockHeight(Belt(101_152))) && t.abs.max.is_none())
        );
        assert!(
            matches!(&n[1].0[..], [LockPrimitive::Pkh(_), LockPrimitive::Tim(t)]
            if t.abs.max == Some(BlockHeight(Belt(101_151))) && t.abs.min.is_none())
        );
        assert!(
            matches!(&n[2].0[..], [LockPrimitive::Burn, LockPrimitive::Hax(x)] if x.0.iter().count() == 3)
        );
        assert!(matches!(&n[3].0[..], [LockPrimitive::Burn]));

        let d = branches(demand_lock(&h(30), &h(80), 24, &h(45), &h(60), 2));
        assert_eq!(pkh_keys(&d[0]), vec![h(30)]);
        assert_eq!(pkh_keys(&d[1]), vec![h(80)]);
        assert!(
            matches!(&d[2].0[..], [LockPrimitive::Burn, LockPrimitive::Hax(x)] if x.0.iter().count() == 3)
        );
    }

    #[test]
    fn the_check_funding_note_is_the_job_funding_shape_over_the_salted_digest() {
        let f = facts();
        let jf = JobFacts {
            order_digest: f.salted_digest.clone(),
            weight_root: f.weight_root.clone(),
        };
        assert_eq!(
            root(check_funding_lock(&h(10), &h(20), 96, &f)),
            root(funding_lock(&h(10), &h(20), 96, &jf))
        );
    }

    #[test]
    fn every_real_branch_of_every_note_is_provable() {
        for lock in [
            ticket_lock(&parties(), 100_540, 101_103, &facts()).unwrap(),
            vouch_note_lock(&parties(), 100_000, 1_152, &h(45), &h(60)).unwrap(),
            demand_lock(&h(30), &h(80), 24, &h(45), &h(60), 0).unwrap(),
        ] {
            for k in 1..=4 {
                let proof = lock_merkle_proof(&lock, k, 10, 1).expect("provable");
                assert_eq!(proof.proof().root, lock_root(&lock).unwrap());
            }
        }
    }

    #[test]
    fn the_vouch_is_paid_exactly_when_the_provider_is() {
        // N lands at 100.000 with c = 1.152 ⇒ its PAY opens at 101.152; N_c lands later
        // (the CLEAN capture) and must still open at 101.152, not a window after itself.
        let n = branches(vouch_note_lock(&parties(), 100_000, 1_152, &h(45), &h(60)));
        let (pay, clawback) = (&n[0], &n[1]);
        for since in [100_000, 100_300, 101_000] {
            assert!(!branch_window_open(pay, since, 101_151));
            assert!(branch_window_open(pay, since, 101_152));
            assert!(branch_window_open(clawback, since, 101_151));
            assert!(!branch_window_open(clawback, since, 101_152));
            for now in since..102_000 {
                assert_ne!(
                    branch_window_open(pay, since, now),
                    branch_window_open(clawback, since, now)
                );
            }
        }
    }

    #[test]
    fn the_ticket_and_the_demand_windows_meet_without_a_gap() {
        let since = 100_020;
        // A request at 100.300 reports by 100.540, wherever the ticket itself landed.
        for landed in [100_303, 100_312] {
            let j = branches(ticket_lock(&parties(), 100_540, 101_103, &facts()));
            assert!(branch_window_open(&j[0], landed, 100_540));
            assert!(!branch_window_open(&j[0], landed, 100_541));
            assert!(!branch_window_open(&j[2], landed, 100_540));
            assert!(branch_window_open(&j[2], landed, 100_541));
        }
        let j = branches(ticket_lock(&parties(), 100_540, 101_103, &facts()));
        assert!(branch_window_open(&j[1], since, 101_103));
        assert!(
            !branch_window_open(&j[1], since, 101_104),
            "no claim after claim-by"
        );

        let d = branches(demand_lock(&h(30), &h(80), 24, &h(45), &h(60), 0));
        for now in since..since + 100 {
            assert_ne!(
                branch_window_open(&d[0], since, now),
                branch_window_open(&d[1], since, now)
            );
        }
        assert!(branch_window_open(&d[0], since, since + 24));
        assert!(branch_window_open(&d[1], since, since + 25));
    }

    #[test]
    fn every_address_binds_every_operand() {
        let p = parties();
        let f = facts();
        let base = root(ticket_lock(&p, 100_540, 101_103, &f));
        for q in [
            CheckParties {
                buyer_c: h(11),
                ..p.clone()
            },
            CheckParties {
                platform: h(21),
                ..p.clone()
            },
            CheckParties {
                verdict: h(71),
                ..p.clone()
            },
            CheckParties {
                checker: h(81),
                ..p.clone()
            },
        ] {
            assert_ne!(base, root(ticket_lock(&q, 100_540, 101_103, &f)));
            // ⚑ N_c names no verdict key — it is refused equal to the others, never bound.
            if q.verdict == p.verdict {
                assert_ne!(
                    root(vouch_note_lock(&p, 100_000, 1_152, &h(45), &h(60))),
                    root(vouch_note_lock(&q, 100_000, 1_152, &h(45), &h(60)))
                );
            }
        }
        assert_ne!(base, root(ticket_lock(&p, 100_541, 101_103, &f)));
        assert_ne!(base, root(ticket_lock(&p, 100_540, 101_104, &f)));
        assert_ne!(
            base,
            root(ticket_lock(
                &p,
                100_540,
                101_103,
                &CheckFacts {
                    salted_digest: h(46),
                    ..f.clone()
                }
            ))
        );
        assert_ne!(
            base,
            root(ticket_lock(
                &p,
                100_540,
                101_103,
                &CheckFacts {
                    weight_root: h(51),
                    ..f.clone()
                }
            ))
        );

        let base = root(vouch_note_lock(&p, 100_000, 1_152, &h(45), &h(60)));
        assert_ne!(
            base,
            root(vouch_note_lock(&p, 100_001, 1_152, &h(45), &h(60)))
        );
        assert_ne!(
            base,
            root(vouch_note_lock(&p, 100_000, 1_153, &h(45), &h(60)))
        );
        assert_ne!(
            base,
            root(vouch_note_lock(&p, 100_000, 1_152, &h(46), &h(60)))
        );
        assert_ne!(
            base,
            root(vouch_note_lock(&p, 100_000, 1_152, &h(45), &h(61)))
        );

        let base = root(demand_lock(&h(30), &h(80), 24, &h(45), &h(60), 0));
        assert_ne!(
            base,
            root(demand_lock(&h(31), &h(80), 24, &h(45), &h(60), 0))
        );
        assert_ne!(
            base,
            root(demand_lock(&h(30), &h(81), 24, &h(45), &h(60), 0))
        );
        assert_ne!(
            base,
            root(demand_lock(&h(30), &h(80), 25, &h(45), &h(60), 0))
        );
        assert_ne!(
            base,
            root(demand_lock(&h(30), &h(80), 24, &h(46), &h(60), 0))
        );
        assert_ne!(
            base,
            root(demand_lock(&h(30), &h(80), 24, &h(45), &h(61), 0))
        );
        assert_ne!(
            base,
            root(demand_lock(&h(30), &h(80), 24, &h(45), &h(60), 1))
        );
    }

    #[test]
    fn a_note_that_would_be_unspendable_or_replayable_is_refused_by_its_own_cause() {
        let p = parties();
        let f = facts();
        let msg = |r: anyhow::Result<Lock>| format!("{:#}", r.expect_err("refused"));
        for (q, want) in [
            (
                CheckParties {
                    platform: p.buyer_c.clone(),
                    ..p.clone()
                },
                "the buyer's check key and the platform",
            ),
            (
                CheckParties {
                    verdict: p.platform.clone(),
                    ..p.clone()
                },
                "the platform and the verdict key",
            ),
            (
                CheckParties {
                    checker: p.verdict.clone(),
                    ..p.clone()
                },
                "the verdict key and the checker",
            ),
            (
                CheckParties {
                    checker: p.buyer_c.clone(),
                    ..p.clone()
                },
                "the buyer's check key and the checker",
            ),
        ] {
            assert!(
                msg(ticket_lock(&q, 100_540, 101_103, &f)).contains(want),
                "{want}"
            );
            assert!(
                msg(vouch_note_lock(&q, 100_000, 1_152, &h(45), &h(60))).contains(want),
                "{want}"
            );
        }
        assert!(msg(ticket_lock(&p, 0, 101_103, &f)).contains("report_by is zero"));
        assert!(msg(ticket_lock(&p, 100_540, 0, &f)).contains("claim_by is zero"));
        assert!(
            msg(ticket_lock(&p, 101_103, 101_103, &f)).contains("is not after the report deadline")
        );
        assert!(
            msg(vouch_note_lock(&p, 100_000, 1, &h(45), &h(60))).contains("c = 1 is too short")
        );
        assert!(
            msg(vouch_note_lock(&p, PRIME - 1, 1_152, &h(45), &h(60)))
                .contains("not a field element")
        );
        assert!(
            msg(vouch_note_lock(&p, 100_000, 1_152, &h(45), &h(45)))
                .contains("the salted digest and the vouched root are the same value")
        );
        assert!(
            msg(demand_lock(&h(30), &h(30), 24, &h(45), &h(60), 0))
                .contains("never check its own job")
        );
        assert!(
            msg(demand_lock(&h(30), &h(80), 0, &h(45), &h(60), 0)).contains("answer_by is zero")
        );
        assert!(
            msg(demand_lock(&h(30), &h(80), 24, &h(45), &h(60), PRIME)).contains("demand round")
        );
        let same = CheckFacts {
            salted_digest: h(50),
            weight_root: h(50),
        };
        assert!(msg(ticket_lock(&p, 100_540, 101_103, &same)).contains("are the same value"));
    }

    #[test]
    fn a_round_never_aliases_a_slice_slot() {
        use crate::bond_locks::{SliceRole, slice_slot};
        for role in SliceRole::ALL {
            for i in 0..8 {
                assert_ne!(demand_slot(i).unwrap(), slice_slot(role, i).unwrap());
            }
        }
    }
}
