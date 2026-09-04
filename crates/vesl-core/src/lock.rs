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
/// B1  CAPTURE  [%pkh m=2 {buyer_pay,  platform}]  AND  [%hax {h_k}]
/// B2  VOID     [%pkh m=2 {buyer_VOID, platform}]
/// B3  RECLAIM  [%pkh m=1 {buyer_pay}] AND [%tim rel.min = r_reclaim] AND [%hax {h_sb}]
/// B4  padding  [%brn ~]  AND  [%hax {job_com}]
/// ```
///
/// ## ⛔⛔ WHY `B2` NAMES A DIFFERENT KEY — the defect this shape closes
///
/// ⚑ *In plain terms: the signature the buyer gives us to be paid could also be
/// used to cancel the payment — and cancelling hands over no key. We would be
/// paid without delivering. The cancel branch therefore needs its own key,
/// which the buyer uses once and can then throw away.*
///
/// `sig-hash` covers the seeds and the fee and **NOT the revealed branch**
/// (`tx-engine-1.hoon:1116-1120`), and a spend reveals **one** branch chosen by
/// whoever submits it. While `B1` and `B2` named the same pair, a capture
/// co-signature was byte-for-byte the signature a void of the same outputs
/// asks for ⇒ the platform could reveal `B2`, add its own signature, carry no
/// preimage, and **publish no delivery key**. · MEASURED 2026-09-03: a live
/// node ACCEPTED exactly that spend, twice
/// (`rust_signed_devnet.rs` `L5`; x402 `records/S118`).
///
/// ⛔ It is **not** a theft of funds — the outputs are pinned by the sig-hash.
/// What it broke is **atomicity**, which is the whole point of `B1`'s hashlock.
///
/// ⚖️ RULED 2026-08-31 (`PLAN_B §D2.2`): `B2` names a dedicated, discardable
/// `buyer_void_pkh`. The buyer pre-signs one void spend at hold confirmation and
/// **may discard the key immediately** — retention is ZERO, which is why the
/// objection that killed this mechanism for `B3` (a key that must survive 24 h)
/// does not transfer. `check:pkh`'s subset test (`:2071`) now refuses the
/// capture co-signature on `B2` **before outputs are considered**.
///
/// ⚑ Conjuncts are a list, so this costs **zero extra branches**: the arity
/// stays four and [`Lock::V4`] is unchanged.
///
/// ⛔ `h_sb` closes the same hole on `B3`, which the buyer could otherwise
/// reach with its ordinary payment key after `r_reclaim`. Like `h_k` it is the
/// digest of the **carry noun**, never a hash of the secret's bytes.
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
/// ## ⛔⛔ Why this returns a `Result` — THREE ways to build a broken hold
///
/// **(1) A collapsed 2-of-2.** `Pkh::new(2, vec![P, P])` goes through `ZSet`,
/// which **deduplicates silently** (`nockchain-math/src/zoon/zset.rs`, pinned
/// upstream by `quickcheck_owned_zset_ignores_duplicate_items`). Two equal
/// hashes become a ONE-element set still demanding `m=2`, and `check:pkh`
/// requires exactly `m` witness entries whose keys are a subset of that set
/// (`tx-engine-1.hoon:2064-2081`) ⇒ that branch becomes **unsatisfiable**. The
/// note is built without complaint and says nothing until a live settlement.
/// This is why `buyer_pkh == platform_pkh` and `buyer_void_pkh ==
/// platform_pkh` are both refused.
///
/// **(2) ⛔⛔ `buyer_void_pkh == buyer_pkh` — THE ONE THAT PASSES EVERY TEST.**
/// It builds cleanly, is fully satisfiable, produces a four-branch lock whose
/// `m` values and conjunct counts are all correct — and **silently restores the
/// defect above**, because the shape assertions check `m` and counts and never
/// *whose* keys. **A wrong hash is inert; a wrong key is live.**
///
/// **(3) A zero threshold.** · VERIFIED against the chain's own source:
/// `Pkh(m = 0, …)` **passes every clause of `check:pkh` with an EMPTY witness**
/// — `:2069` gives `0 == 0` (`wyt` on an empty `z-by` is `0`, `zoon.hoon:299`);
/// `:2071` gives `∅ \ h = ∅`, which **never inspects the permitted set at all**;
/// `~(rep z-by ~)` returns its bunted accumulator, and the bunt of `?` is `%.y`
/// (`zoon.hoon:220`); and `batch-verify` is `(levy batch verify)`
/// (`ztd/three.hoon:1833-1837`), which is `%.y` on `~`. The Rust mirror agrees
/// — `check_pkh`'s `distinct.len() as u64 != pkh.m` is the same equality.
/// ⇒ **a zero-threshold branch is spendable by anyone, with no signature at
/// all.** Nothing rejected it before; it was unreachable only because every
/// call site passed a literal. [`pkh_conjunct`] now refuses it at the
/// constructor, so no future branch can reintroduce it.
pub fn hold_lock(
    buyer_pkh: Hash,
    buyer_void_pkh: Hash,
    platform_pkh: Hash,
    h_k: Hash,
    h_sb: Hash,
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
    if buyer_void_pkh == platform_pkh {
        anyhow::bail!(
            "the buyer's VOID key and the platform hash to the same address, so B2's \
             2-of-2 would collapse to a one-element set still demanding two signatures \
             and the void would be unsatisfiable — leaving a hold that can be captured \
             but never cancelled. Refusing to build it."
        );
    }
    // ⛔⛔ THE ONE THAT IS INVISIBLE TO EVERY SHAPE TEST. With one key on both
    // branches, a capture co-signature satisfies the void — which is the whole
    // defect this lock shape exists to close, restored silently. A wrong hash
    // is inert; a wrong KEY is live.
    if buyer_void_pkh == buyer_pkh {
        anyhow::bail!(
            "the buyer's VOID key is its PAYMENT key. B2 would then name the same pair \
             as B1, so the capture co-signature the buyer hands over could be replayed \
             onto the void branch — taking the money while publishing no delivery key. \
             That is the defect the dedicated void key exists to close, and this lock \
             would pass every shape assertion while reopening it. Refusing to build it."
        );
    }
    // B1 — capture. Conjunct order is part of the address; `XD-3` writes the
    // signature check first.
    let capture = SpendCondition::new(vec![
        pkh_conjunct(2, vec![buyer_pkh.clone(), platform_pkh.clone()])?,
        LockPrimitive::Hax(Hax::new(vec![h_k])),
    ]);
    // B2 — void. A 2-of-2 with the buyer's DEDICATED key, and nothing to
    // publish. It is the different key, not the missing hashlock, that stops a
    // capture co-signature from spending here.
    let void = SpendCondition::new(vec![pkh_conjunct(2, vec![buyer_void_pkh, platform_pkh])?]);
    // B3 — reclaim. The buyer alone, after the wait, publishing its own
    // per-job secret. Without `h_sb` the buyer's ordinary payment signature
    // reaches this branch too (`PLAN_B §D`, route 2).
    let reclaim = SpendCondition::new(vec![
        pkh_conjunct(1, vec![buyer_pkh])?,
        LockPrimitive::Tim(LockTim {
            rel: TimelockRangeRelative::new(Some(BlockHeightDelta(Belt(r_reclaim))), None),
            abs: TimelockRangeAbsolute::none(),
        }),
        LockPrimitive::Hax(Hax::new(vec![h_sb])),
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

/// Branch numbers of the buyer's DEPOSIT (`PLAN_B §C`), 1-based, as
/// [`lock_merkle_proof`] takes them. ⛔ **These are part of the address**, on
/// the same terms as [`HOLD_BRANCH_CAPTURE`]: renumbering them moves every
/// deposit ever created, fail-closed and silent until a live spend.
pub const DEPOSIT_BRANCH_RETURN_ON_CAPTURE: u64 = 1;
/// See [`DEPOSIT_BRANCH_RETURN_ON_CAPTURE`].
///
/// ⛔⛔ **WE MUST NEVER ASK THE BUYER TO SIGN A DEPOSIT SPEND WHOSE OUTPUTS ARE
/// NOT ITS OWN.** This branch is a 2-of-2 the buyer pre-signs when its hold
/// confirms, so the platform holds a live buyer signature over a deposit spend
/// for the life of the job. That is safe for exactly one reason: `sig-hash`
/// pins the OUTPUTS, and the buyer's own wallet built them and they pay the
/// buyer. Ask for a signature over any other output set and every branch of
/// this note becomes ours (`PLAN_B §C`'s replay sweep).
pub const DEPOSIT_BRANCH_RETURN_ON_DEATH: u64 = 2;
/// See [`DEPOSIT_BRANCH_RETURN_ON_CAPTURE`]. Unspendable by construction, and
/// carrying the job for the reason [`HOLD_BRANCH_PADDING`] does.
pub const DEPOSIT_BRANCH_PADDING_JOB: u64 = 3;
/// See [`DEPOSIT_BRANCH_RETURN_ON_CAPTURE`]. Pure padding: `%brn` alone.
pub const DEPOSIT_BRANCH_PADDING: u64 = 4;

/// Four-branch lock for the buyer's DEPOSIT — the deterrent note
/// (`x402 PLAN_B §C`, ⚖️ RULED by the owner 2026-08-31).
///
/// ⚑ *In plain terms: the buyer parks a second, smaller pot beside its payment.
/// It gets that pot back the moment we take our payment, because taking payment
/// publishes the key that also unlocks the pot. If the buyer walks off without
/// co-signing, the pot becomes money nobody on earth can move — us included. We
/// gain nothing from a walk, so we can never have a reason to want one.*
///
/// ```text
/// D1  RETURN-ON-CAPTURE  [%pkh m=1 {buyer_pay}]  AND  [%hax {h_k}]
/// D2  RETURN-ON-DEATH    [%pkh m=2 {buyer_VOID, platform}]
/// D3  padding            [%brn ~]  AND  [%hax {job_com}]
/// D4  padding            [%brn ~]
/// ```
///
/// ## ⭐⭐ THE TWO CONDITIONS THAT OPEN IT ARE BOTH THINGS **WE** MUST DO
///
/// **`D1`** opens when the capture publishes the delivery key's preimage —
/// which [`hold_lock`]'s `B1` forces us to do **in order to be paid at all**.
/// It is not a favour: there is no route to our own money that does not publish
/// it. The buyer then watches the chain and opens `D1` **alone**, needing
/// nothing from us — one 1-input, 1-output spend to itself.
///
/// **`D2`** opens when we agree the job died through nobody's fault and
/// co-sign. ⛔ Nothing forces that one and this shape does not pretend
/// otherwise: no lock can tell a dead job from a walked buyer (`PLAN_B §A3`),
/// so the judgement is ours under every shape, and this is where it lives,
/// visibly.
///
/// ⇒ If neither happens the deposit is spendable by nobody. ⛔ **It is not
/// that we take it — it is GONE, for everyone.** That is what makes the
/// deterrent safe to hold: it **deters and repairs nobody**, it **destroys
/// value rather than redistributing it**, and the miner is still unpaid
/// (`PLAN_B §A6`). ⛔ Its strength is the buyer's cost of capital, and ⚖️
/// **sizing it is board row 7's** — 25 % of the cap is the ruled figure, and it
/// lives in `x402_nockchain_crypto::cap`, never here.
///
/// ## ⛔⛔ WHY `D2` NAMES `buyer_VOID` AND NOT `buyer_pay` — the trigger, not the predicate
///
/// The states where a job dies without fault — `dead_letter`, `expired`,
/// `closing_out`, `failed` — are **exactly** the states where the buyer has
/// stopped watching. A `D2` naming the buyer's live payment key would need the
/// signature that will not arrive: *the branch that insures against the buyer's
/// absence would require the buyer to be present.* It is the same defect
/// [`hold_lock`]'s `B2` closed, and the same fix — the buyer pre-signs one `D2`
/// spend with a dedicated, discardable key **at the same moment it pre-signs
/// the hold's `B2`**, so one exchange covers both notes and no new round trip
/// exists (`PLAN_B §C2`).
///
/// ⚑ **`D2` carries no secret.** An earlier design gated it on a platform-held
/// release secret `h_r`, published by the hold's void — but that void is itself
/// a 2-of-2 needing the buyer. The predicate was right and the trigger was not.
/// A plain 2-of-2 costs no new secret, no new wire field, and no conjunct on
/// the hold's `B2`; `h_r` is deleted and must not be reintroduced.
///
/// ## ⛔ WHAT THIS LOCK DOES **NOT** SHARE WITH THE HOLD
///
/// No `%tim`, and no `h_sb`. The hold's `B3` lets the buyer recover **alone**
/// after 24 h; the deposit deliberately has no such branch, because a deposit a
/// walked buyer can simply wait out is not a deterrent. ⇒ `r_reclaim` and
/// `h_sb` are **not deposit operands**, and every operand this function does
/// take is already an operand of the hold — so **the deposit costs no new field
/// on any wire.**
///
/// ## ⛔⛔ ITS ROOT MUST DIFFER FROM THE HOLD'S
///
/// The chain **merges** two seeds of one transaction that sit at the same lock
/// root (`build-outputs`; and `vesl_core::settle::build_capture_seeds` refuses
/// it on the spend side for the same reason). The hold and the deposit are
/// created by ONE transaction, so an equal root would land them as a single
/// note — and would let one output satisfy both of the platform's existence
/// checks. It holds here by construction (`D1` is `m=1` where `B1` is `m=2`,
/// and `D4` is a bare burn where `B3` is the reclaim), and the derivation sites
/// assert it rather than assume it.
///
/// ## ⛔ THE THREE REFUSALS, AND WHICH ONE IS LOAD-BEARING
///
/// | | |
/// |---|---|
/// | `buyer_void_pkh == platform_pkh` | ⛔⛔ **LOAD-BEARING.** `D2` collapses through the z-set's silent dedup into a one-element set still demanding two signatures ⇒ the deposit could never be returned on death, and an honest buyer would forfeit it on an ordinary miner failure |
/// | `buyer_void_pkh == buyer_pkh` | a NAMED CAUSE, not coverage. `D1` is `m=1` and its outputs are the buyer's, so a `D2` pre-signature replayed onto `D1` still pays the buyer. Refused because it is live on the HOLD and a reader must not have to work out that it is inert here |
/// | `buyer_pkh == platform_pkh` | a NAMED CAUSE, not coverage. No deposit branch collapses on it — but a caller that hit it has confused two parties, and the hold refuses it one line away |
///
/// ⇒ the controls for the two named-cause rows assert the **message**; with
/// `is_err()` they would be green for the wrong reason (`x402 records/S118`).
pub fn deposit_lock(
    buyer_pkh: Hash,
    buyer_void_pkh: Hash,
    platform_pkh: Hash,
    h_k: Hash,
    job_com: Hash,
) -> anyhow::Result<Lock> {
    if buyer_void_pkh == platform_pkh {
        anyhow::bail!(
            "the buyer's VOID key and the platform hash to the same address, so D2's 2-of-2 \
             would collapse to a one-element set still demanding two signatures and the \
             return-on-death would be unsatisfiable — leaving a deposit an honest buyer \
             forfeits the first time a miner fails it. Refusing to build it."
        );
    }
    if buyer_void_pkh == buyer_pkh {
        anyhow::bail!(
            "the buyer's VOID key is its PAYMENT key. On the deposit this is inert — D1 is a \
             1-of-1 and every branch pays the buyer whatever is revealed — but it is a live \
             defect on the HOLD, whose B2 would then accept the capture co-signature, and \
             these two notes are built from one set of operands. Refusing to build it."
        );
    }
    if buyer_pkh == platform_pkh {
        anyhow::bail!(
            "the buyer and the platform hash to the same address. No deposit branch collapses \
             on this — D1 names the buyer alone and D2 names the void key — but the hold built \
             from the same operands is unspendable, so a caller that reached here has \
             confused the two parties. Refusing to build it."
        );
    }
    // D1 — return on capture. The buyer ALONE, publishing the delivery key the
    // capture already put on chain. ⛔ Conjunct order is part of the address;
    // `PLAN_B §C` writes the signature check first, as `hold_lock` does.
    let return_on_capture = SpendCondition::new(vec![
        pkh_conjunct(1, vec![buyer_pkh.clone()])?,
        LockPrimitive::Hax(Hax::new(vec![h_k])),
    ]);
    // D2 — return on death. A 2-of-2 with the buyer's DEDICATED key and
    // nothing to publish, pre-signed in the hold's own exchange.
    let return_on_death =
        SpendCondition::new(vec![pkh_conjunct(2, vec![buyer_void_pkh, platform_pkh])?]);
    // D3 — padding carrying the job, exactly as the hold's B4 does: a branch
    // holding a `%brn` is unspendable whatever else sits beside it, so this is
    // free capacity in the ADDRESS. ⛔ `Burn` stays FIRST.
    let padding_job = SpendCondition::new(vec![
        LockPrimitive::Burn,
        LockPrimitive::Hax(Hax::new(vec![job_com])),
    ]);
    // D4 — the padding the chain's own `from-list` would have appended. ⛔ Two
    // real branches pad to four; the arities are {1,2,4,8,16}.
    let padding = SpendCondition::new(vec![LockPrimitive::Burn]);

    Ok(Lock::V4(LockV4 {
        p: LockV2 {
            p: return_on_capture,
            q: return_on_death,
        },
        q: LockV2 {
            p: padding_job,
            q: padding,
        },
    }))
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
/// ⚑ Every `%pkh` in [`hold_lock`] goes through here. It is `pub` so future
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
        let (buyer, buyer_void, platform, h_k) = (pkh(10), pkh(15), pkh(20), pkh(30));
        let (h_sb, job_com) = (pkh(35), pkh(40));
        let lock = hold_lock(
            buyer.clone(),
            buyer_void.clone(),
            platform.clone(),
            h_k.clone(),
            h_sb.clone(),
            576,
            job_com.clone(),
        )
        .expect("three distinct parties");
        let branches = lock.flatten_spend_conditions();
        assert_eq!(lock.spend_condition_count(), 4);

        // B1 capture — the 2-of-2 AND the hashlock, in that order.
        let capture = &branches[(HOLD_BRANCH_CAPTURE - 1) as usize];
        assert_eq!(capture.0.len(), 2);
        assert!(matches!(&capture.0[0], LockPrimitive::Pkh(p) if p.m == 2));
        assert!(matches!(&capture.0[1], LockPrimitive::Hax(_)));

        // B2 void — a 2-of-2 on the buyer's DEDICATED key, and NOTHING else. A
        // void delivers nothing, so it must not require publishing the key.
        let void = &branches[(HOLD_BRANCH_VOID - 1) as usize];
        assert_eq!(void.0.len(), 1);
        assert!(matches!(&void.0[0], LockPrimitive::Pkh(p) if p.m == 2));
        assert!(
            !void.0.iter().any(|p| matches!(p, LockPrimitive::Hax(_))),
            "a void must not carry the delivery condition"
        );

        // ⭐⭐ THE ASSERTION THE OLD SHAPE TEST DID NOT MAKE, AND ITS ABSENCE IS
        // WHY THE DEFECT SURVIVED: the two branches must name DIFFERENT KEYS.
        // Everything above is about `m` and conjunct counts, and every one of
        // those assertions passes on a lock whose B1 and B2 name the same pair
        // — which is a lock a capture co-signature can spend on the void
        // branch. `assert_ne!(capture.hash(), void.hash())` below does NOT
        // catch it either: B1 carries an extra `%hax`, so the two branch
        // hashes differ whatever the keys are.
        let pkh_set = |c: &SpendCondition| match &c.0[0] {
            LockPrimitive::Pkh(p) => p.hashes.iter().cloned().collect::<Vec<_>>(),
            other => panic!("the first conjunct should be %pkh, got {other:?}"),
        };
        assert_ne!(
            pkh_set(capture),
            pkh_set(void),
            "B1 and B2 must not name the same key set — a capture co-signature would \
             then spend the void branch and publish no delivery key"
        );
        assert!(
            pkh_set(void).contains(&buyer_void) && !pkh_set(void).contains(&buyer),
            "B2 must name the buyer's dedicated VOID key and NOT its payment key"
        );
        assert!(
            pkh_set(capture).contains(&buyer) && !pkh_set(capture).contains(&buyer_void),
            "B1 must name the buyer's PAYMENT key"
        );

        // B3 reclaim — the buyer alone, after the wait, publishing its own
        // per-job secret.
        let reclaim = &branches[(HOLD_BRANCH_RECLAIM - 1) as usize];
        assert_eq!(reclaim.0.len(), 3);
        assert!(matches!(&reclaim.0[0], LockPrimitive::Pkh(p) if p.m == 1));
        match &reclaim.0[1] {
            LockPrimitive::Tim(t) => {
                assert_eq!(t.rel.min.as_ref().map(|d| d.0.0), Some(576));
                assert!(t.rel.max.is_none() && t.abs.min.is_none() && t.abs.max.is_none());
            }
            other => panic!("reclaim's second conjunct should be %tim, got {other:?}"),
        }
        assert_eq!(
            reclaim.0[2],
            LockPrimitive::Hax(Hax::new(vec![h_sb.clone()])),
            "the reclaim publishes the buyer's own per-job secret — without it the \
             buyer's ordinary payment signature reaches this branch too"
        );

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
        let lock =
            hold_lock(pkh(10), pkh(15), pkh(20), pkh(30), pkh(35), 576, pkh(40)).expect("hold");
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
        let h = |b, v, p, k, sb, w, j| hold_lock(b, v, p, k, sb, w, j).expect("hold");
        let base = h(pkh(10), pkh(15), pkh(20), pkh(30), pkh(35), 576, pkh(40));
        let other_key = h(pkh(10), pkh(15), pkh(20), pkh(31), pkh(35), 576, pkh(40));
        let other_wait = h(pkh(10), pkh(15), pkh(20), pkh(30), pkh(35), 577, pkh(40));
        let other_buyer = h(pkh(11), pkh(15), pkh(20), pkh(30), pkh(35), 576, pkh(40));
        let other_job = h(pkh(10), pkh(15), pkh(20), pkh(30), pkh(35), 576, pkh(41));
        // ⭐ The two operands row 10 added. Without these legs the
        // operand-sensitivity guarantee silently loses two members, and a
        // `hold_lock` that ignored either would still pass this test.
        let other_void = h(pkh(10), pkh(16), pkh(20), pkh(30), pkh(35), 576, pkh(40));
        let other_h_sb = h(pkh(10), pkh(15), pkh(20), pkh(30), pkh(36), 576, pkh(40));
        let r = |l: &Lock| lock_root(l).unwrap();
        assert_ne!(r(&base), r(&other_key), "h_k is an operand of the address");
        assert_ne!(r(&base), r(&other_wait), "r_reclaim is an operand too");
        assert_ne!(r(&base), r(&other_buyer));
        assert_ne!(
            r(&base),
            r(&other_void),
            "the buyer's VOID key is an operand of the address"
        );
        assert_ne!(
            r(&base),
            r(&other_h_sb),
            "h_sb is an operand of the address — the reclaim's secret is part of the note"
        );
        // ⭐⭐ And the job. Without this the padding branch commits to nothing:
        // a commitment that does not move the address is decoration.
        assert_ne!(
            r(&base),
            r(&other_job),
            "job_com is an operand of the address — one payment cannot back two jobs"
        );
        // ...and it is a pure function of its operands.
        assert_eq!(
            r(&base),
            r(&h(
                pkh(10),
                pkh(15),
                pkh(20),
                pkh(30),
                pkh(35),
                576,
                pkh(40)
            ))
        );
    }

    /// ⚑ The 2-of-2 is a threshold over a SET, so the two parties may be
    /// supplied in either order without moving the address. This is the
    /// already-proven half of `F1` reaching the artifact it actually guards.
    ///
    /// ⛔⛔ **THIS TEST'S PREMISE CHANGED AT ROW 10 AND THE OLD ONE IS NOW
    /// FALSE.** It read *"B1 and B2 are symmetric in the pair"* and swapped
    /// `buyer_pkh` with `platform_pkh` — which was fine only while both
    /// branches named that one pair. `B2` now names `{buyer_void, platform}`,
    /// so that swap moves B2 to a set it never had. Each branch is symmetric in
    /// **its own** pair, and that is what is asserted: the two swaps are made
    /// separately, and each is checked against the branch it belongs to.
    #[test]
    fn the_hold_address_does_not_depend_on_which_party_is_named_first() {
        let base = hold_lock(pkh(10), pkh(15), pkh(20), pkh(30), pkh(35), 576, pkh(40))
            .expect("hold base");
        // B1's pair swapped: {buyer, platform} -> {platform, buyer}.
        let swap_pay = hold_lock(pkh(20), pkh(15), pkh(10), pkh(30), pkh(35), 576, pkh(40))
            .expect("hold with B1's pair swapped");
        // B2's pair swapped: {buyer_void, platform} -> {platform, buyer_void}.
        let swap_void = hold_lock(pkh(10), pkh(20), pkh(15), pkh(30), pkh(35), 576, pkh(40))
            .expect("hold with B2's pair swapped");
        let br = |l: &Lock, i: u64| {
            l.flatten_spend_conditions()[(i - 1) as usize]
                .hash()
                .unwrap()
        };
        assert_eq!(
            br(&base, HOLD_BRANCH_CAPTURE),
            br(&swap_pay, HOLD_BRANCH_CAPTURE),
            "B1 is a threshold over a set, so its pair's order must not move it"
        );
        assert_eq!(
            br(&base, HOLD_BRANCH_VOID),
            br(&swap_void, HOLD_BRANCH_VOID),
            "B2 is a threshold over a set, so its pair's order must not move it"
        );
    }

    /// ⭐⭐ THE THREE WAYS TO BUILD A BROKEN HOLD, EACH REFUSED — and each with
    /// a positive control beside it, because a builder that refused everything
    /// would pass the refusals alone.
    ///
    /// ⛔ `buyer_void == buyer_pay` is the one no shape assertion can see: it
    /// builds a fully satisfiable four-branch lock with the right `m` values
    /// and the right conjunct counts, and silently restores the defect
    /// `hold_lock`'s own docs describe. **A wrong hash is inert; a wrong key is
    /// live.**
    #[test]
    fn a_hold_that_would_be_unspendable_or_replayable_is_refused() {
        // ⚑ The hold's KEY operands, in the order `hold_lock` takes them. This
        // list is the subject of the sweep below AND of the structural tripwire
        // at the end, which is derived from the LOCK rather than from here.
        const KEYS: [&str; 3] = ["buyer_pkh", "buyer_void_pkh", "platform_pkh"];
        let distinct = || [pkh(10), pkh(15), pkh(20)];
        let ok = |k: [Hash; 3]| {
            hold_lock(
                k[0].clone(),
                k[1].clone(),
                k[2].clone(),
                pkh(30),
                pkh(35),
                576,
                pkh(40),
            )
        };
        // The positive control: three distinct parties build.
        assert!(ok(distinct()).is_ok(), "the honest trio builds");

        // ⭐⭐ EVERY PAIR, SWEPT — not three hand-written cases. Adding a fourth
        // key operand and forgetting its guard fails here rather than shipping a
        // lock that passes every shape assertion.
        //
        // ⛔⛔ AND EACH REFUSAL IS CHECKED BY THE CAUSE IT NAMES, NOT MERELY BY
        // BEING A REFUSAL. `pkh_conjunct`'s cardinality check already refuses two
        // of these three as UNSATISFIABLE, so an `is_err()` assertion would stay
        // green with the dedicated guards deleted and would be testing the wrong
        // thing. The message is what distinguishes "this branch is unspendable"
        // from "this lock is replayable", and they send a reader to different
        // places.
        let cause = |a: usize, b: usize| -> &'static str {
            match (KEYS[a], KEYS[b]) {
                ("buyer_pkh", "platform_pkh") => "buyer and the platform",
                ("buyer_void_pkh", "platform_pkh") => "VOID key and the platform",
                ("buyer_pkh", "buyer_void_pkh") => "VOID key is its PAYMENT key",
                (x, y) => panic!(
                    "no named cause for {x} == {y}: a key operand was added to KEYS \
                     without a guard and without a message that tells a reader which \
                     of the two failures this is"
                ),
            }
        };
        for a in 0..KEYS.len() {
            for b in (a + 1)..KEYS.len() {
                let mut k = distinct();
                k[b] = k[a].clone();
                let e = ok(k)
                    .expect_err(&format!("{} == {} must be refused", KEYS[a], KEYS[b]))
                    .to_string();
                assert!(
                    e.contains(cause(a, b)),
                    "{} == {} must be refused BY ITS OWN CAUSE, got: {e}",
                    KEYS[a],
                    KEYS[b]
                );
            }
        }

        // ⭐⭐ THE TRIPWIRE, DERIVED FROM THE LOCK AND NOT FROM `KEYS`. An honest
        // hold names exactly this many DISTINCT keys across its branches. Add a
        // key operand and this fails without anyone having remembered to extend
        // the sweep — which is the failure mode the sweep alone cannot catch.
        let honest = ok(distinct()).expect("honest");
        let mut members: Vec<Hash> = Vec::new();
        for branch in honest.flatten_spend_conditions() {
            for prim in branch.0.iter() {
                if let LockPrimitive::Pkh(p) = prim {
                    for h in p.hashes.iter() {
                        if !members.contains(h) {
                            members.push(h.clone());
                        }
                    }
                }
            }
        }
        assert_eq!(
            members.len(),
            KEYS.len(),
            "the hold names {} distinct keys across its branches but KEYS lists {} — a \
             key operand was added or two collapsed together. Every pair of them needs \
             a guard and a named cause.",
            members.len(),
            KEYS.len()
        );

        // ⛔ And the reason the third one needs its own guard: without it the
        // lock is BUILDABLE and passes every structural assertion the shape
        // test makes. This is that claim, made explicit rather than argued —
        // the collapsed lock is assembled by hand, exactly as `hold_lock`
        // would have built it, and every shape property still holds.
        let collapsed = Lock::V4(LockV4 {
            p: LockV2 {
                p: SpendCondition::new(vec![
                    pkh_conjunct(2, vec![pkh(10), pkh(20)]).unwrap(),
                    LockPrimitive::Hax(Hax::new(vec![pkh(30)])),
                ]),
                q: SpendCondition::new(vec![pkh_conjunct(2, vec![pkh(10), pkh(20)]).unwrap()]),
            },
            q: LockV2 {
                p: SpendCondition::new(vec![
                    pkh_conjunct(1, vec![pkh(10)]).unwrap(),
                    LockPrimitive::Tim(LockTim {
                        rel: TimelockRangeRelative::new(Some(BlockHeightDelta(Belt(576))), None),
                        abs: TimelockRangeAbsolute::none(),
                    }),
                    LockPrimitive::Hax(Hax::new(vec![pkh(35)])),
                ]),
                q: SpendCondition::new(vec![
                    LockPrimitive::Burn,
                    LockPrimitive::Hax(Hax::new(vec![pkh(40)])),
                ]),
            },
        });
        let b = collapsed.flatten_spend_conditions();
        assert_eq!(collapsed.spend_condition_count(), 4);
        assert!(matches!(&b[0].0[0], LockPrimitive::Pkh(p) if p.m == 2));
        assert!(matches!(&b[1].0[0], LockPrimitive::Pkh(p) if p.m == 2));
        assert_eq!(b[1].0.len(), 1);
        assert_ne!(
            b[0].hash().unwrap(),
            b[1].hash().unwrap(),
            "even the cross-branch check passes: B1's extra %hax separates them"
        );
        assert!(
            lock_root(&collapsed).is_ok(),
            "⛔ it has a perfectly good address — nothing structural rejects it, which \
             is why the refusal must be a check on the KEYS in `hold_lock`"
        );
    }

    /// ⭐⭐ A zero-threshold `%pkh` is spendable by ANYONE with an empty
    /// witness, and nothing in the chain rejects it. `pkh_conjunct` is where
    /// that stops. ⚑ The positive controls are the two shapes the hold itself
    /// uses, so a guard that refused everything would fail here.
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

    /// `PLAN_B §C`'s shape, branch by branch. This is the address; if any of
    /// these assertions has to be "updated", the deposit has moved and every
    /// note ever created under the old shape is stranded.
    #[test]
    fn the_deposit_lock_is_plan_b_cs_four_branch_shape() {
        let (buyer, buyer_void, platform, h_k, job_com) =
            (pkh(10), pkh(15), pkh(20), pkh(30), pkh(40));
        let lock = deposit_lock(
            buyer.clone(),
            buyer_void.clone(),
            platform.clone(),
            h_k.clone(),
            job_com.clone(),
        )
        .expect("three distinct parties");
        let branches = lock.flatten_spend_conditions();
        assert_eq!(lock.spend_condition_count(), 4);

        // D1 return-on-capture — the buyer ALONE, and the hashlock, in that
        // order. ⛔ `m=1`: this is what the buyer opens by itself once the
        // capture has put the key on chain, needing nothing from the platform.
        let d1 = &branches[(DEPOSIT_BRANCH_RETURN_ON_CAPTURE - 1) as usize];
        assert_eq!(d1.0.len(), 2);
        match (&d1.0[0], &d1.0[1]) {
            (LockPrimitive::Pkh(p), LockPrimitive::Hax(h)) => {
                assert_eq!(p.m, 1, "D1 is the buyer alone");
                assert_eq!(p.hashes.iter().count(), 1);
                assert!(p.hashes.iter().any(|x| x == &buyer));
                assert!(
                    !p.hashes.iter().any(|x| x == &platform),
                    "the platform is NOT named by D1: the buyer recovers alone"
                );
                assert_eq!(h.0.iter().count(), 1);
                assert!(h.0.iter().any(|x| x == &h_k), "D1 names the delivery key");
            }
            other => panic!("D1 must be [%pkh m=1] AND [%hax], got {other:?}"),
        }

        // D2 return-on-death — the 2-of-2, and NOTHING to publish. ⛔ A
        // hashlock here would make the platform publish the delivery key to
        // hand back a deposit for a job that was never delivered.
        let d2 = &branches[(DEPOSIT_BRANCH_RETURN_ON_DEATH - 1) as usize];
        assert_eq!(d2.0.len(), 1, "D2 carries no second conjunct");
        match &d2.0[0] {
            LockPrimitive::Pkh(p) => {
                assert_eq!(p.m, 2);
                assert_eq!(p.hashes.iter().count(), 2);
                assert!(
                    p.hashes.iter().any(|x| x == &buyer_void),
                    "D2 names the buyer's DEDICATED void key"
                );
                assert!(p.hashes.iter().any(|x| x == &platform));
                assert!(
                    !p.hashes.iter().any(|x| x == &buyer),
                    "D2 must NOT name the buyer's payment key: the states where a job dies \
                     are the states where that buyer has stopped watching"
                );
            }
            other => panic!("D2 must be a bare [%pkh m=2], got {other:?}"),
        }

        // D3 — the burn FIRST, then the job. Order is part of the address.
        let d3 = &branches[(DEPOSIT_BRANCH_PADDING_JOB - 1) as usize];
        assert_eq!(d3.0.len(), 2);
        assert!(matches!(d3.0[0], LockPrimitive::Burn), "the burn is FIRST");
        match &d3.0[1] {
            LockPrimitive::Hax(h) => assert!(h.0.iter().any(|x| x == &job_com)),
            other => panic!("D3's second conjunct must be the job, got {other:?}"),
        }

        // D4 — pure padding.
        let d4 = &branches[(DEPOSIT_BRANCH_PADDING - 1) as usize];
        assert_eq!(d4.0.len(), 1);
        assert!(matches!(d4.0[0], LockPrimitive::Burn));

        // ⛔⛔ NO TIMELOCK ANYWHERE. The hold's B3 lets the buyer recover alone
        // after 24 h; a deposit a walked buyer can wait out is not a deterrent,
        // and adding a `%tim` here would delete the whole mechanism while every
        // other assertion above stayed green.
        for (i, b) in branches.iter().enumerate() {
            assert!(
                !b.0.iter().any(|p| matches!(p, LockPrimitive::Tim(_))),
                "branch {} carries a timelock; the deposit has no wait-it-out branch",
                i + 1
            );
        }
    }

    /// ⭐⭐ **THE HOLD AND THE DEPOSIT MUST NOT SHARE AN ADDRESS.**
    ///
    /// They are created by ONE transaction, and the chain MERGES two seeds of
    /// one transaction that sit at the same lock root — so an equal root would
    /// land them as a single note, and would let one output satisfy both of the
    /// platform's existence checks. It holds by construction; this is the
    /// tripwire that says so if either shape moves.
    #[test]
    fn the_deposit_does_not_stand_at_the_holds_address() {
        let (b, v, p, k, sb, j) = (pkh(10), pkh(15), pkh(20), pkh(30), pkh(35), pkh(40));
        let hold = hold_lock(
            b.clone(),
            v.clone(),
            p.clone(),
            k.clone(),
            sb,
            576,
            j.clone(),
        )
        .expect("hold");
        let deposit = deposit_lock(b, v, p, k, j).expect("deposit");
        assert_ne!(
            lock_root(&hold).unwrap(),
            lock_root(&deposit).unwrap(),
            "the hold and the deposit share an address: one transaction creating both would \
             land ONE merged note, and one output would satisfy both admission checks"
        );
    }

    /// Every branch can actually produce a merkle proof that folds to the root.
    /// ⛔ Including the two unspendable ones: `%brn` makes a branch unspendable,
    /// it does not make it unprovable, and a padding branch whose proof does
    /// not fold means the tree is not the tree the address commits to.
    #[test]
    fn every_deposit_branch_is_provable() {
        let lock = deposit_lock(pkh(10), pkh(15), pkh(20), pkh(30), pkh(40)).expect("deposit");
        let root = lock_root(&lock).expect("deposit root");
        for (branch, axis) in [
            (DEPOSIT_BRANCH_RETURN_ON_CAPTURE, 12),
            (DEPOSIT_BRANCH_RETURN_ON_DEATH, 13),
            (DEPOSIT_BRANCH_PADDING_JOB, 14),
            (DEPOSIT_BRANCH_PADDING, 15),
        ] {
            let proof = lock_merkle_proof(&lock, branch, 10, 1)
                .unwrap_or_else(|e| panic!("branch {branch}: {e}"));
            assert_eq!(proof.axis(), axis);
            assert_eq!(proof.proof().root, root);
        }
    }

    /// Change any operand and the address moves. A deposit built against one
    /// delivery key cannot be opened by publishing another, and one built for
    /// one job cannot sit at another job's address.
    #[test]
    fn the_deposit_address_binds_every_operand() {
        let d = |b, v, p, k, j| deposit_lock(b, v, p, k, j).expect("deposit");
        let base = d(pkh(10), pkh(15), pkh(20), pkh(30), pkh(40));
        let r = |l: &Lock| lock_root(l).unwrap();
        for (label, other) in [
            ("buyer_pkh", d(pkh(11), pkh(15), pkh(20), pkh(30), pkh(40))),
            (
                "buyer_void_pkh",
                d(pkh(10), pkh(16), pkh(20), pkh(30), pkh(40)),
            ),
            (
                "platform_pkh",
                d(pkh(10), pkh(15), pkh(21), pkh(30), pkh(40)),
            ),
            ("h_k", d(pkh(10), pkh(15), pkh(20), pkh(31), pkh(40))),
            ("job_com", d(pkh(10), pkh(15), pkh(20), pkh(30), pkh(41))),
        ] {
            assert_ne!(
                r(&base),
                r(&other),
                "{label} is an operand of the deposit's address"
            );
        }
    }

    /// ⛔⛔ Every colliding pair is refused **BY THE CAUSE IT NAMES**, not
    /// merely by being a refusal. `pkh_conjunct`'s cardinality check already
    /// refuses one of these as unsatisfiable, so an `is_err()` assertion would
    /// stay green with the dedicated guards deleted — the shape this repo has
    /// already paid for once (`x402 records/S118`).
    #[test]
    fn a_deposit_that_would_be_unreturnable_is_refused_by_its_own_cause() {
        const KEYS: [&str; 3] = ["buyer_pkh", "buyer_void_pkh", "platform_pkh"];
        let distinct = || [pkh(10), pkh(15), pkh(20)];
        let ok =
            |k: [Hash; 3]| deposit_lock(k[0].clone(), k[1].clone(), k[2].clone(), pkh(30), pkh(40));
        assert!(ok(distinct()).is_ok(), "the honest trio builds");

        let cause = |a: usize, b: usize| -> &'static str {
            match (KEYS[a], KEYS[b]) {
                ("buyer_pkh", "platform_pkh") => "buyer and the platform",
                ("buyer_void_pkh", "platform_pkh") => "VOID key and the platform",
                ("buyer_pkh", "buyer_void_pkh") => "VOID key is its PAYMENT key",
                (x, y) => panic!(
                    "no named cause for {x} == {y}: a key operand was added without a guard \
                     and without a message that tells a reader which failure this is"
                ),
            }
        };
        for a in 0..KEYS.len() {
            for b in (a + 1)..KEYS.len() {
                let mut k = distinct();
                k[b] = k[a].clone();
                let e = ok(k)
                    .expect_err(&format!("{} == {} must be refused", KEYS[a], KEYS[b]))
                    .to_string();
                assert!(
                    e.contains(cause(a, b)),
                    "{} == {} must be refused BY ITS OWN CAUSE, got: {e}",
                    KEYS[a],
                    KEYS[b]
                );
            }
        }
    }
}
