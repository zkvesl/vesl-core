//! Settle — Settlement (heavy tier)
//!
//! Two layers:
//! 1. `Settle<V>` struct — verify via CommitmentVerifier, manage root registration
//! 2. Free functions — composable transaction building helpers
//!
//! The hull orchestrates kernel boot and poke dispatch. Settle provides
//! the settlement toolkit: seed construction, signing, tx assembly,
//! chain submission. Kernel interaction (NockApp pokes for sig-hash
//! and tx-id) lives in `tx_builder`.

use std::collections::{HashSet, VecDeque};

use anyhow::Result;
use nock_noun_rs::NounSlab;
use nockchain_client_rs::ChainClient;
use nockchain_tip5_rs::Tip5Hash;

use crate::guard::Guard;
use crate::types::{CommitmentVerifier, GraftPayload, Note};

/// Upper bound on the pre-flight `settled_ids` cache (AUDIT 2026-05-19
/// H-07). The kernel's `settled` set is the authoritative replay
/// defense; this SDK-side cache is a pre-flight diagnostic, so evicting
/// the oldest entry past the cap is safe — a missed pre-flight hit just
/// defers the duplicate rejection to the kernel.
const SETTLED_IDS_CAP: usize = 1_000_000;

/// Upper bound on a [`GraftPayload`]'s `data` field (AUDIT 2026-05-21
/// L-05). `poke_bytes` JAMs the payload into a noun; an unbounded `data`
/// vector lets a caller drive an arbitrarily large allocation. 64 MiB
/// mirrors hull-llm's `MAX_MANIFEST_JSON_BYTES` cap on the RAG path.
const MAX_POKE_DATA_BYTES: usize = 64 * 1024 * 1024;

/// Generic settlement orchestrator parameterized by a domain `CommitmentVerifier`.
///
/// Vesl-core ships only the trait; concrete verifier implementations live in
/// downstream hulls (e.g. hull-llm's `RagVerifier`). Construct via
/// `Settle::with_verifier(your_verifier)`.
pub struct Settle<V: CommitmentVerifier> {
    guard: Guard,
    verifier: V,
    settled_ids: HashSet<u64>,
    /// Insertion order for `settled_ids`, enabling FIFO eviction at the cap.
    settled_order: VecDeque<u64>,
}

impl<V: CommitmentVerifier> Settle<V> {
    /// Create a Settle with a custom verifier (no kernel).
    pub fn with_verifier(verifier: V) -> Self {
        Settle {
            guard: Guard::new(),
            verifier,
            settled_ids: HashSet::new(),
            settled_order: VecDeque::new(),
        }
    }

    /// Register a root as trusted in the local verifier.
    pub fn register_root(&mut self, root: Tip5Hash) -> Result<(), crate::guard::GuardError> {
        self.guard.register_root(root)
    }

    /// Settle a payload: verify via the CommitmentVerifier + state transition.
    ///
    /// Pre-flight checks catch common failures before the kernel sees the
    /// payload. If a poke still crashes after pre-flight, the input violated
    /// a kernel guard that these checks don't cover.
    ///
    /// The SDK builds the poke but does not dispatch it — the hull owns the
    /// NockApp handle. Callers use `poke_bytes()` to get the JAM'd poke for
    /// dispatch, or call `settle()` for local verification only.
    pub async fn settle(&mut self, payload: &GraftPayload) -> Result<Note> {
        // Pre-flight: root registration
        anyhow::ensure!(
            self.guard.is_registered(&payload.expected_root),
            "root not registered: {}",
            crate::types::format_tip5(&payload.expected_root),
        );

        // Pre-flight: duplicate settlement
        anyhow::ensure!(
            !self.settled_ids.contains(&payload.note.id),
            "duplicate settlement: note {} already settled",
            payload.note.id,
        );

        // Pre-flight: note must be pending
        anyhow::ensure!(
            matches!(payload.note.state, crate::types::NoteState::Pending),
            "note {} is not pending (current state: {:?})",
            payload.note.id,
            payload.note.state,
        );

        // Domain verification — note_id passed so gates can enforce
        // pre-commit binding (AUDIT H-03).
        anyhow::ensure!(
            self.verifier
                .verify(payload.note.id, &payload.data, &payload.expected_root),
            "verification failed for note {}",
            payload.note.id,
        );

        let _poke: NounSlab = self.verifier.build_settle_poke(payload)?;

        // Poke is built but not dispatched — kernel interaction needs a
        // NockApp handle, which the hull owns. Use `poke_bytes()` to get
        // the serialized poke for hull-side dispatch.
        // AUDIT 2026-05-19 H-07: bound the pre-flight cache — evict the
        // oldest id once at capacity so a long-running hull does not
        // leak unbounded replay state.
        if self.settled_ids.len() >= SETTLED_IDS_CAP
            && let Some(old) = self.settled_order.pop_front()
        {
            self.settled_ids.remove(&old);
        }
        if self.settled_ids.insert(payload.note.id) {
            self.settled_order.push_back(payload.note.id);
        }
        Ok(Note {
            id: payload.note.id,
            hull: payload.note.hull,
            root: payload.note.root,
            state: crate::types::NoteState::Settled,
        })
    }

    /// Build the settle poke as JAM bytes for hull-side kernel dispatch.
    ///
    /// The SDK cannot dispatch pokes directly — the hull owns the NockApp
    /// handle. This method returns the serialized poke so callers can feed
    /// it to `NockApp::poke()` themselves.
    pub fn poke_bytes(&self, payload: &GraftPayload) -> Result<Vec<u8>> {
        // AUDIT 2026-05-21 L-05: bound the payload before building the poke
        // so an oversized `data` vector can't drive an unbounded JAM alloc.
        anyhow::ensure!(
            payload.data.len() <= MAX_POKE_DATA_BYTES,
            "graft payload data is {} bytes, over the {MAX_POKE_DATA_BYTES}-byte cap",
            payload.data.len()
        );
        let slab = self.verifier.build_settle_poke(payload)?;
        Ok(nock_noun_rs::slab_jam_to_bytes(&slab))
    }

    /// Access the inner Guard verifier.
    pub fn guard(&self) -> &Guard {
        &self.guard
    }

    /// Access the inner CommitmentVerifier.
    pub fn verifier(&self) -> &V {
        &self.verifier
    }
}

// ---------------------------------------------------------------------------
// Composable settlement helpers — free functions
// ---------------------------------------------------------------------------

/// Build the output Seed for a settlement transaction.
///
/// Constructs a single Seed with the given NoteData, lock, gift amount,
/// and parent hash. The caller encodes domain-specific data into NoteData
/// before calling this.
///
/// ⛔ **SINGLE-OUTPUT, AND IT HAS NO CALLERS.** · MEASURED 2026-08-30 across the
/// fleet: every real transaction assembles `Seeds(vec![…])` itself, and nothing
/// outside this module's own tests calls this. It also cannot express a spend
/// that pays more than one party, which every settlement shape now needs. Use
/// [`build_capture_seeds`], which takes a set, refuses a merged pair, and
/// asserts conservation. Left in place rather than removed because deleting a
/// public item is not this row's business.
pub fn build_seeds(
    lock_root: nockchain_types::tx_engine::common::Hash,
    note_data: nockchain_types::tx_engine::v1::note::NoteData,
    parent_hash: nockchain_types::tx_engine::common::Hash,
    amount: u64,
    fee: u64,
) -> Result<nockchain_types::tx_engine::v1::tx::Seeds> {
    anyhow::ensure!(
        fee <= amount / 2,
        "fee ({fee}) exceeds 50% of input amount ({amount})"
    );
    let output_amount = amount.saturating_sub(fee);
    // AUDIT 2026-05-20 M-22: u64 -> usize is lossless on 64-bit but
    // truncates on a 32-bit target (e.g. wasm32). Convert explicitly so an
    // overflow surfaces as an error, not a silently wrong gift amount.
    let gift_nicks = usize::try_from(output_amount)
        .map_err(|_| anyhow::anyhow!("output amount {output_amount} exceeds usize"))?;
    use nockchain_types::tx_engine::v1::tx::Seed;
    let seed = Seed {
        output_source: None,
        lock_root,
        note_data,
        gift: nockchain_types::tx_engine::common::Nicks(gift_nicks),
        parent_hash,
    };
    let mut seeds = nockchain_types::tx_engine::v1::tx::Seeds(vec![seed]);
    pin_output_source(&mut seeds)?; // ⭐ x402 board row `19b`
    Ok(seeds)
}

/// One output of a capture: where it pays, what rides on it, and how much.
///
/// ⚑ *In plain terms: one line of the payout — an address, optional attached
/// data, and an amount.*
#[derive(Debug, Clone)]
pub struct CaptureOutput {
    /// The address this output pays to. ⛔ A lock ROOT, already derived by
    /// whoever owns that shape — this module never restates a lock's operands
    /// (`x402 XD-7`: the escrow's root has one home, `bounty_lock_for`, and
    /// every consumer *calls* it).
    pub lock_root: nockchain_types::tx_engine::common::Hash,
    /// Note-data to attach. Empty for all but the escrow output, which carries
    /// the job's intent entries.
    pub note_data: nockchain_types::tx_engine::v1::note::NoteData,
    /// The amount, in nicks.
    pub amount: u64,
}

/// ⭐⭐ **BUILD A CAPTURE'S OUTPUT SET, AND ASSERT THAT IT CONSERVES — `F7`.**
///
/// ⚑ *In plain terms: assemble the payout lines of one transaction and refuse
/// unless the money going out, plus the fee, is exactly the money coming in.*
///
/// ⛔⛔ **THE CHECK IS ON THE OUTPUTS, NOT ON THE ARITHMETIC THAT PRODUCED
/// THEM.** A capture is authorized by signatures, and the signed digest covers
/// **exactly the outputs and the fee** and nothing else
/// (`sig-hash = Tip5[(sig-hashable:seeds) leaf+fee]`, `tx-engine-1.hoon:1116-1120`).
/// So a conservation check upstream — over the split that was *meant* to be
/// built — establishes nothing about what the parties will actually sign. This
/// function is deliberately given no `cap`, no bill and no commission: it can
/// only see the seeds, which is the only thing whose correctness transfers to
/// the signature.
///
/// Three refusals, in the order a caller wants to hear them:
///
/// 1. **No zero-value output.** A zero seed is consensus-pointless and is
///    almost always a sizing mistake; `vesl-labs`' escrow poster refuses one on
///    the same grounds. ⚑ A capture whose commission rounds to zero drops that
///    output *before* calling here — it does not pass a zero.
/// 2. ⛔⛔ **NO TWO OUTPUTS UNDER ONE LOCK ROOT.** The chain keys a spend's
///    outputs by seed lock-root and **MERGES seeds that share one**, so two
///    outputs under one root are silently ONE output — money to an address
///    nobody intended, with no error anywhere. `x402 XD-5`'s three outputs use
///    three different keys so this holds, but it held *by luck* until asserted.
/// 3. ⭐ **Conservation.** `Σ amount + fee == input_value`.
///
/// ⛔ What this does NOT check, because it cannot see it: that `input_value` is
/// really what the input note holds. The caller reads that from the chain.
pub fn build_capture_seeds(
    outputs: &[CaptureOutput],
    parent_hash: &nockchain_types::tx_engine::common::Hash,
    input_value: u64,
    fee: u64,
) -> Result<nockchain_types::tx_engine::v1::tx::Seeds> {
    use nockchain_types::tx_engine::v1::tx::{Seed, Seeds};

    anyhow::ensure!(
        !outputs.is_empty(),
        "a capture with no outputs would burn the whole hold"
    );

    let mut total: u128 = 0;
    for (i, out) in outputs.iter().enumerate() {
        anyhow::ensure!(
            out.amount != 0,
            "capture output {i} would carry zero assets; drop the output rather \
             than emitting a zero-value seed"
        );
        for (j, other) in outputs.iter().enumerate().take(i) {
            anyhow::ensure!(
                out.lock_root != other.lock_root,
                "capture outputs {j} and {i} share a lock root, and the chain MERGES \
                 seeds that do — this spend would land as one output, not two"
            );
        }
        total += u128::from(out.amount);
    }

    // ⭐ `F7`. u128 so an output set that overflows a u64 is reported as
    // non-conserving rather than wrapping into agreement with the input.
    let paid_out = total + u128::from(fee);
    anyhow::ensure!(
        paid_out == u128::from(input_value),
        "this capture does not conserve: {} nicks of outputs plus a {fee}-nick fee is {paid_out}, \
         against an input holding {input_value}",
        total
    );

    let gift_of = |amount: u64| -> Result<nockchain_types::tx_engine::common::Nicks> {
        // u64 -> usize is lossless on 64-bit and truncates on a 32-bit target;
        // convert explicitly so an overflow surfaces here, not as a silently
        // wrong gift amount. (`build_seeds`' AUDIT M-22, same hazard.)
        Ok(nockchain_types::tx_engine::common::Nicks(
            usize::try_from(amount)
                .map_err(|_| anyhow::anyhow!("output amount {amount} exceeds usize"))?,
        ))
    };

    let mut seeds = Seeds(
        outputs
            .iter()
            .map(|out| {
                Ok(Seed {
                    output_source: None,
                    lock_root: out.lock_root.clone(),
                    note_data: out.note_data.clone(),
                    gift: gift_of(out.amount)?,
                    parent_hash: parent_hash.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?,
    );
    // ⭐ x402 board row `19b`. Every output this fleet signs carries its group's
    // own fingerprint; the refusal above stays because it names a cause where a
    // consensus rejection does not.
    pin_output_source(&mut seeds)?;
    Ok(seeds)
}

/// The neutral name for [`CaptureOutput`] — one payout line of any spend.
pub use self::CaptureOutput as OutputLine;
/// ⭐⭐ **THE NEUTRAL NAME FOR [`build_capture_seeds`] — it is this fleet's ONE
/// home for ANY spend's output set, not only a capture's.**
///
/// ⚑ *In plain terms: the same routine that assembles the payout lines of a
/// settlement also assembles them for a refund, a cancellation, and the buyer's
/// own first payment. Only its name said otherwise.*
///
/// ⛔⛔ **THE NAME WAS ALREADY LYING, · VERIFIED 2026-09-04**: the close-out's
/// refund (`vesl-labs/services/gateway/src/close_out.rs`), the pre-signed void
/// (`services/gateway/src/void_route.rs`) and the buyer's own void co-signature
/// (`vesl-x402/.../void_cosign.rs`) all call it, and none of them is a capture.
/// The **only** production site that did not was the buyer's admission
/// transaction, which hand-rolled the same three steps inline — and that is the
/// `XD-7` one-home defect `records/S124` `§5` filed as *"there is NO shipped
/// builder for the buyer's posting seeds."* There is; it was misnamed.
///
/// ⚑ **A re-export, not a second function.** Two spellings of one *value* is the
/// defect `XD-7` is about; two names for one *item* is checked by the compiler
/// to be the same item, so a caller cannot reach a stale copy. The old name is
/// kept because it is cited by `file:line` across four repositories.
pub use self::build_capture_seeds as build_output_seeds;

/// ⭐⭐ **PIN `output-source` ON EVERY SEED OF A SPEND — x402 board row `19b`.**
///
/// ⚑ *In plain terms: stamp each payout line with a fingerprint of the payout
/// lines it belongs with, so that if anyone folds another payment's line into
/// ours the chain refuses the whole transaction instead of quietly merging
/// them.*
///
/// ⛔⛔ **IT IS A TRIPWIRE, NOT A SEPARATOR, AND THE DIFFERENCE IS THE WHOLE
/// POINT.** `build-outputs` (`tx-engine-1.hoon:2345-2404`) keys the merge on
/// `lock-root` **and nothing else**, and strips `output-source` from every seed
/// before hashing the group (`:2372-2375`). So a pinned seed merges exactly as
/// an unpinned one does. What the pin buys is `validate:output` (`:1399-1427`),
/// which walks the merged group with `levy` and — if any member's claimed
/// source is not the group's actual one — makes `validate:tx` reject the
/// **entire transaction** (`tx-engine.hoon:1349`). Upstream's own negative
/// records this shape: `new:tx` SUCCEEDS and validation then fails
/// (`hoon/tests/dumb/mod/unit/transact-v1.hoon:2626-2674`).
///
/// ⛔ **What it protects against is a seed we did not author.** Our own callers
/// already refuse two outputs under one lock root — [`build_capture_seeds`]
/// here, and the buyer wallet's hold/deposit check — and those refusals should
/// stay, because they fail early and name a cause where consensus does not. The
/// hazard this closes is CROSS-INPUT: the signed digest covers only *this
/// spend's* seeds and fee (`tx-engine-1.hoon:1116-1121`), so another input in
/// the same transaction can land a seed on our lock root without disturbing our
/// signature, and the merged note's note-data is `uni`-merged with the later
/// seed winning.
///
/// ⛔⛔⛔ **THE LIMIT OF THIS HELPER, AND IT CAN REFUSE OUR OWN HONEST
/// PAYMENT: IT SEES ONE SPEND; CONSENSUS GROUPS ACROSS THE WHOLE
/// TRANSACTION.** `build-outputs` creates its accumulator ONCE, before the
/// spend loop, and threads it across every spend (`tx-engine-1.hoon:2350`,
/// `:2404`) — so the group it hashes spans **every seed in the transaction** at
/// that lock root. This function is handed **one spend's** `Seeds` and can only
/// hash those.
///
/// ⛔⛔ **THAT LIMIT EXPIRED ON 2026-09-07 (x402 board row 23), AND THIS
/// FUNCTION IS NOW THE SINGLE-SPEND SPECIAL CASE RATHER THAN THE ONLY ARM.**
/// This header read *"for every transaction this fleet builds the two coincide,
/// because we build single-input transactions and nothing can encode otherwise
/// — `jam_spends_manual` refuses more than one spend ⇒ not reachable today."*
/// [`crate::tx_builder::jam_spends`] now encodes any spend count and the
/// buyer's own builder is multi-input, so the mismatch below IS reachable.
///
/// ✅ **Use [`pin_output_source_across`] for anything multi-input.** This arm
/// stays correct, and is what every single-input caller should keep calling:
/// with one spend the two agree by construction. · MEASURED at consensus
/// (`records/S134 §5`): with THIS function's per-spend value on a two-coin
/// payment the merged note never lands and the node still answers "accepted".
///
/// ⛔ **It becomes reachable the moment anything builds a MULTI-INPUT
/// transaction whose two spends pay the same lock root.** Then each spend would
/// pin a group computed from its own seeds alone, consensus would compute one
/// from both, they would not match, and **consensus would refuse a transaction
/// we authored entirely and correctly.**
///
/// ⛔⛔ **THIS PARAGRAPH NAMED THE WRONG EXAMPLE UNTIL 2026-09-04, AND THE
/// WRONG EXAMPLE IS THE ONE A BUILDER WAS ABOUT TO REACH FOR.** It said *"the
/// address fan-out sketched in `x402 XQ-6a` is exactly that shape"*. It is not:
/// a fan-out is **ONE input paying N outputs**, which `records/S117` `§6` states
/// in as many words — *"one input note funds N fresh addresses in ONE spend …
/// it does not need multi-input support, which is the thing that is actually
/// blocked"*. Its N outputs sit at N **distinct** lock roots, so every group is
/// a singleton and this helper's view and consensus's coincide exactly.
/// ⇒ the fan-out is expressible today and does **not** trip the hazard above.
/// What would trip it is re-funding a batch from **two** notes at once — and
/// that is refused three frames earlier by `jam_spends_manual`. ⚑ A hazard note
/// that names an unreachable example teaches a builder to route around a wall
/// that is not there; the hazard is real, the citation was not.
///
/// ⚑⚑ **The same property is protective outward and a trap inward, and that is
/// not a defect to be designed away.** Pinning only what our own spend can see
/// is *precisely* what makes a stranger's seed on our lock root fatal rather
/// than silent (measured: `output_source_devnet` legs `X1`/`X3`). A version
/// that pinned the whole transaction's group would agree with a stranger's
/// tampering by construction and guard nothing.
///
/// ⇒ **If a multi-input builder is ever added, it must pin across ALL of its
/// own spends at once** — one grouping pass over the assembled `Spends`, not a
/// call per spend — and that is a different function from this one.
///
/// ⛔⛔ **THREE ORDERING RULES, EACH SILENTLY WRONG IF MISSED:**
///
/// 1. **Per lock-root GROUP, not per seed.** Consensus computes one source per
///    group. Our groups are singletons only because of the refusals above,
///    which live one layer up and could be relaxed — so this handles the
///    general case rather than assuming its caller's invariant.
/// 2. **Before signing.** `sig-hashable:seed` covers the field
///    (`tx-engine-1.hoon:707-715`), so a pin written after the signature is a
///    signature over a different object.
/// 3. **Inside the fee loop.** A `seeds_for(fee)` closure re-derives the seed
///    set per candidate fee, so the pin belongs inside it. Applied once
///    outside, it would be computed over a set the accepted fee replaces.
///
/// ⚑ The normalisation Hoon performs by hand is free here: `HashHashable for
/// Seed` already folds only `lock_root`, `note_data`, `gift` and `parent_hash`
/// (`nockchain-types/src/tx_engine/v1/tx.rs:1229-1242`), excluding
/// `output_source` for the hash-loop reason `tx-engine-0.hoon:1971` gives. The
/// `output_source: None` below is therefore belt-and-braces, not load-bearing —
/// it keeps the call honest if that ever changes.
pub fn pin_output_source(seeds: &mut nockchain_types::tx_engine::v1::tx::Seeds) -> Result<()> {
    pin_groups(seeds.0.iter_mut().collect())
}

/// ⭐⭐ **THE MULTI-INPUT PIN — x402 board row 23, closing `D-37`.** One
/// grouping pass over the output sets of ALL the spends of one transaction.
///
/// ⚑ *In plain terms: when we pay one address out of two of our own coins, the
/// chain treats the two payout lines as ONE payout and stamps them with a
/// fingerprint of the pair. Stamping each line with a fingerprint of itself —
/// which is what [`pin_output_source`] does, correctly, for a one-coin payment
/// — makes the chain throw the whole payment away without saying why.*
///
/// ⛔⛔ **THIS IS THE FUNCTION THE PER-SPEND ONE COULD NOT BE.** Consensus
/// builds its output accumulator ONCE, before the spend loop, and threads it
/// across every spend (`tx-engine-1.hoon:2350`, `:2405`), keying on
/// `lock-root.sed` alone (`:2364`); it then re-hashes the WHOLE merged group
/// with every member's field stripped (`:2372-2376`). `validate:output`
/// (`:1410-1419`) rejects if any member's claim differs from that, and
/// `validate:tx` then refuses the entire transaction (`tx-engine.hoon:1349`).
/// A helper handed one spend's `Seeds` can only ever hash those.
///
/// · MEASURED at consensus, `records/S133 §9.7`: two inputs paying two
/// DISTINCT lock roots were accepted and both outputs landed; two inputs paying
/// ONE shared lock root were reported **accepted** and the merged note **never
/// landed**. The legs differ in exactly one thing, so the cause is the
/// grouping.
///
/// ⛔⛔ **AND IT IS NOT A BLIND WIDENING, WHICH IS THE WHOLE DESIGN
/// CONSTRAINT.** The group hashed here contains exactly the seeds **we
/// authored**. A stranger who wraps our signed spends into a larger transaction
/// and lands a seed on one of our lock roots makes consensus's group gain a
/// member ⇒ consensus's hash moves ⇒ our claim no longer matches ⇒ the
/// transaction is REFUSED. That is `XE-163`'s `X1`/`X3` measured at consensus,
/// and it survives this change intact. A version that pinned "whatever ends up
/// in the transaction" would agree with the tamper by construction and guard
/// nothing — which is why this takes the sets WE assembled and never re-reads
/// them from a submitted transaction.
/// `a_strangers_seed_at_our_lock_root_still_breaks_the_group_pin` checks that
/// as a value comparison rather than leaving it as this paragraph.
///
/// ⛔⛔ **CALL IT BEFORE ANY SPEND IS SIGNED.** `sig-hashable:seed` covers the
/// field (`tx-engine-1.hoon:707-715`), so a pin written after a signature is a
/// signature over a different object — and that failure is silent: the node
/// acks the poke and discards the transaction. This entry point takes seed
/// **sets** rather than a `Spends` precisely so it can be called at the only
/// moment that is correct, when the witnesses do not exist yet.
///
/// ⚑ It **overwrites** any per-spend pin already present, and must: the shipped
/// [`build_capture_seeds`] pins internally, so a multi-input builder reusing it
/// arrives with per-spend values. Overwriting is safe because the hash strips
/// the field first — the same normalisation `build-outputs` performs by hand.
pub fn pin_output_source_across(
    sets: Vec<&mut nockchain_types::tx_engine::v1::tx::Seeds>,
) -> Result<()> {
    pin_groups(sets.into_iter().flat_map(|s| s.0.iter_mut()).collect())
}

/// [`pin_output_source_across`] over an already-assembled `Spends`.
///
/// ⛔ Useful for a caller that holds a built transaction (a test, a re-pin, a
/// probe). A **builder** should reach for [`pin_output_source_across`] instead:
/// by the time a `Spends` exists its witnesses do, and a pin applied then is a
/// pin applied after signing.
pub fn pin_output_source_across_spends(
    spends: &mut nockchain_types::tx_engine::v1::tx::Spends,
) -> Result<()> {
    use nockchain_types::tx_engine::v1::tx::Spend;
    pin_groups(
        spends
            .0
            .iter_mut()
            .flat_map(|(_, sp)| match sp {
                Spend::Legacy(s) => s.seeds.0.iter_mut(),
                Spend::Witness(s) => s.seeds.0.iter_mut(),
            })
            .collect(),
    )
}

/// The grouping pass itself — the one home all three entry points share
/// (`XD-7`: one home, every consumer calls it, nobody restates it).
///
/// Groups by lock root, preserving first-seen order so the walk is
/// deterministic. `Vec` rather than a map: a transaction has a handful of
/// seeds, and `Hash` would need a `Hash` impl this crate does not control.
fn pin_groups(mut all: Vec<&mut nockchain_types::tx_engine::v1::tx::Seed>) -> Result<()> {
    use nockchain_types::tx_engine::common::Source;
    use nockchain_types::tx_engine::v1::hashable::HashHashable;
    use nockchain_types::tx_engine::v1::tx::Seeds;

    let mut groups: Vec<(nockchain_types::tx_engine::common::Hash, Vec<usize>)> = Vec::new();
    for (i, seed) in all.iter().enumerate() {
        match groups.iter_mut().find(|(root, _)| root == &seed.lock_root) {
            Some((_, members)) => members.push(i),
            None => groups.push((seed.lock_root.clone(), vec![i])),
        }
    }

    for (_, members) in groups {
        // ⚑ `Seeds` encodes as a z-SET, so two members identical in every other
        // field collapse to one element here — which is exactly what consensus
        // does when it builds the same group, so the two agree by construction.
        let group = Seeds(
            members
                .iter()
                .map(|&i| {
                    let mut s = all[i].clone();
                    s.output_source = None;
                    s
                })
                .collect(),
        );
        let hash = group
            .hash_digest()
            .map_err(|e| anyhow::anyhow!("output-source: hashing the lock-root group: {e}"))?;
        for &i in &members {
            all[i].output_source = Some(Source {
                hash: hash.clone(),
                is_coinbase: false,
            });
        }
    }
    Ok(())
}

/// Sign a sig-hash with a secret key.
///
/// Takes the tip5 hash from `kernel_sig_hash` and produces a Schnorr signature.
pub fn sign_tx(
    signing_key: &[nockchain_math::belt::Belt; 8],
    sig_hash: &nockchain_types::tx_engine::common::Hash,
) -> Result<nockchain_types::tx_engine::common::SchnorrSignature> {
    let msg_belts = sig_hash.to_array().map(nockchain_math::belt::Belt);
    crate::signing::sign(signing_key, &msg_belts)
        .map_err(|e| anyhow::anyhow!("signing failed: {e}"))
}

/// Build a Witness proving authorization to spend an input UTXO.
///
/// ⛔⛔ **SINGLE-CONDITION LOCKS ONLY, AND THE GUARD IS AN IDENTITY CHECK,
/// NOT A TYPE CHECK.** This helper never receives a `Lock` — it takes
/// `is_coinbase` and *constructs* the input's spend-condition itself. So it
/// cannot "refuse a multi-branch lock": handed a note whose real lock is the
/// four-branch hold (`crate::lock::hold_lock`), it would happily build a
/// proof for a lock that is not the note's, and consensus would refuse the
/// spend **naming nothing** — the witness's merkle root simply would not
/// match the note's first-name (`tx-engine-1.hoon:2012-2016`).
///
/// `input_first_name` closes that: the caller passes the note's committed
/// first-name, and we refuse unless the lock we assumed derives it. That is
/// the guard `vesl-labs/services/chain/src/bounty_tx.rs` already uses, and it
/// fails closed **with a cause**, which a type check on a value we never see
/// could not do.
pub fn build_witness(
    signing_key: &[nockchain_math::belt::Belt; 8],
    sig_hash: &nockchain_types::tx_engine::common::Hash,
    is_coinbase: bool,
    coinbase_timelock_min: u64,
    input_first_name: &nockchain_types::tx_engine::common::Hash,
) -> Result<nockchain_types::tx_engine::v1::tx::Witness> {
    use nockchain_types::tx_engine::v1::tx::*;

    let pubkey = crate::signing::derive_pubkey(signing_key)
        .map_err(|e| anyhow::anyhow!("pubkey derivation failed: {e}"))?;
    let pkh = crate::signing::pubkey_hash(&pubkey)
        .map_err(|e| anyhow::anyhow!("pubkey hash failed: {e}"))?;

    let input_condition = if is_coinbase {
        SpendCondition::coinbase_pkh(pkh.clone(), coinbase_timelock_min)
    } else {
        SpendCondition::simple_pkh(pkh.clone())
    };
    let input_lock = Lock::SpendCondition(input_condition.clone());
    let input_lock_root = input_lock
        .hash()
        .map_err(|e| anyhow::anyhow!("input lock hash failed: {e}"))?;

    // ⛔ The note is what it is; this helper only assumed a shape. Refuse
    // before signing if the assumption does not reproduce the note's own
    // first-name — otherwise the mismatch surfaces at consensus as a silent
    // refusal with no cause attached.
    let derived_first = crate::lock::first_name_for_lock(&input_lock)?;
    anyhow::ensure!(
        &derived_first == input_first_name,
        "input note's first-name does not derive from this key's          single-condition lock (wrong key, wrong coinbase flag, or a          multi-branch note this builder cannot spend)"
    );

    let signature = sign_tx(signing_key, sig_hash)?;

    let lock_merkle_proof = LockMerkleProofFull {
        version: nockvm_macros::tas!(b"full"),
        spend_condition: input_condition,
        axis: 1,
        proof: MerkleProof {
            root: input_lock_root,
            path: vec![],
        },
    };

    let pkh_sig_entry = PkhSignatureEntry {
        pkh,
        pubkey,
        signature,
    };

    Ok(Witness::new(
        LockMerkleProof::Full(lock_merkle_proof),
        PkhSignature::new(vec![pkh_sig_entry]),
        vec![],
    ))
}

/// One party's contribution to a hold spend: a signing key.
pub type HoldSigner = [nockchain_math::belt::Belt; 8];

/// One party's **finished** contribution to a hold spend: the public key it
/// signed under, and its signature over the spend's sig-hash.
///
/// ⚑ *In plain terms: what a co-signer sends back. Not its key — the signature
/// it made with it.*
///
/// ⛔⛔ **THIS TYPE IS WHY THE CAPTURE IS BUILDABLE AT ALL.** The hold's capture
/// and void branches are 2-of-2 between the buyer and the platform, and the
/// buyer will never hand the platform a secret key. [`build_hold_witness`]
/// takes `&[HoldSigner]` — keys — so it can only ever assemble a spend by a
/// party that holds *both*, which is a test fixture and not the design
/// (`x402 XD-6`: *an unchecking co-signature is a 1-of-1 with extra steps*, and
/// a co-signature the platform could forge is not one at all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldCosignature {
    /// The public key this signature is checked under. ⛔ Carried rather than
    /// derived, because the verifier has no key to derive it from.
    pub pubkey: nockchain_types::tx_engine::common::SchnorrPubkey,
    /// The signature over the spend's sig-hash.
    pub signature: nockchain_types::tx_engine::common::SchnorrSignature,
}

/// Produce one party's co-signature over a spend's sig-hash.
///
/// ⚑ *In plain terms: this is the whole of what a co-signer does — it is handed
/// the digest of the exact transaction it is agreeing to, and it signs that.*
///
/// ⛔ It signs a digest and nothing else. The digest covers the outputs and the
/// fee and **nothing else** (`tx-engine-1.hoon:1116-1120`), so a signature is
/// branch-agnostic and this function cannot tell an honest spend from a hostile
/// one. **Whatever decides to sign must check the output set first** — that is
/// the co-signer's own job (`x402 XD-6`, board row 5b) and it is not here.
pub fn hold_cosign(
    sk: &HoldSigner,
    sig_hash: &nockchain_types::tx_engine::common::Hash,
) -> Result<HoldCosignature> {
    Ok(HoldCosignature {
        pubkey: crate::signing::derive_pubkey(sk)
            .map_err(|e| anyhow::anyhow!("pubkey derivation failed: {e}"))?,
        signature: sign_tx(sk, sig_hash)?,
    })
}

/// Build the witness that spends one branch of the buyer's hold
/// (`crate::lock::hold_lock`, `XD-3`), from **finished signatures**.
///
/// ⚑ *In plain terms: this assembles the paperwork for moving the buyer's
/// parked money — which branch is being used, who signed, and (for a capture)
/// the key that decrypts the answer — out of signatures the parties made
/// separately, without either handing over its key.*
///
/// ⛔⛔ **EVERY REFUSAL BELOW IS ALSO A CONSENSUS REFUSAL — the difference is
/// that this one names a cause.** A node acks an invalid transaction and
/// discards it silently (`vesl-miner/examples/submit_settlement_devnet.rs`),
/// so a witness that is wrong on any of these counts becomes a spend that
/// simply never lands, with nothing to read. Checking here converts each into
/// a message.
///
/// What is checked, and against what:
///
/// - **the signer count equals the branch's `m`.** `check:pkh` compares the
///   witness map's size with `~(wyt z-by …)` for **equality**
///   (`tx-engine-1.hoon:2069`), so one signature on a 2-of-2 is not a weaker
///   two — it is a different count, and it fails. ⚑ The map is keyed by
///   pubkey-hash, so a **repeated signer is one entry**, not two; that is
///   checked here too, because it silently reduces a 2-of-2 to a 1-of-1.
/// - **every signer is a member of the branch's set** (`:2071`).
/// - ⭐ **every signature actually verifies against `sig_hash`.** This is the
///   check the key-taking wrapper never needed and the co-signature path cannot
///   do without: a counterparty's signature is a value that arrived over a
///   wire, and a bad one is otherwise a spend that vanishes at a node with
///   nothing to read. `verify_chain_signature` is `check:pkh`'s own per-entry
///   predicate. ⚑ On the wrapper's path it is a self-check that cannot fail;
///   it stays uniform because this function cannot see which parts are foreign.
/// - **every `%hax` hash the branch names has a preimage present**
///   (`:2112-2119` demands one for *every* member). ⛔ This is the delivery
///   condition: a capture assembled without the key is refused here rather
///   than vanishing at a node.
///
/// ⛔ Not checked, because this function cannot see it: that `sig_hash` is the
/// digest of the spend you intend. It covers the seeds and the fee and nothing
/// else (`tx-engine-1.hoon:1116-1120`), so a signature is branch-agnostic —
/// the caller must compute it over the real output set.
pub fn build_hold_witness_from_parts(
    lock: &nockchain_types::tx_engine::v1::tx::Lock,
    branch: u64,
    height: u64,
    bythos_phase: u64,
    parts: &[HoldCosignature],
    sig_hash: &nockchain_types::tx_engine::common::Hash,
    hax: Vec<nockchain_types::tx_engine::v1::tx::HaxPreimage>,
) -> Result<nockchain_types::tx_engine::v1::tx::Witness> {
    use nockchain_types::tx_engine::v1::tx::{
        LockPrimitive, PkhSignature, PkhSignatureEntry, Witness,
    };

    let lmp = crate::lock::lock_merkle_proof(lock, branch, height, bythos_phase)?;
    let condition = lmp.spend_condition().clone();

    // The `%pkh` conjunct, if the branch has one. `check:pkh` refuses two in
    // one AND-list anyway (each would demand the whole map), so at most one.
    let pkh_rule = condition.iter().find_map(|p| match p {
        LockPrimitive::Pkh(pkh) => Some(pkh),
        _ => None,
    });

    let entries = if let Some(rule) = pkh_rule {
        let permitted: Vec<_> = rule.hashes.iter().cloned().collect();
        anyhow::ensure!(
            parts.len() as u64 == rule.m,
            "branch {branch} is {}-of-{}: it needs exactly {} signature(s), got {}",
            rule.m,
            permitted.len(),
            rule.m,
            parts.len()
        );
        let msg = sig_hash.to_array().map(nockchain_math::belt::Belt);
        let mut entries: Vec<PkhSignatureEntry> = Vec::with_capacity(parts.len());
        for part in parts {
            let pkh = crate::signing::pubkey_hash(&part.pubkey)
                .map_err(|e| anyhow::anyhow!("pubkey hash failed: {e}"))?;
            anyhow::ensure!(
                permitted.contains(&pkh),
                "a signer is not named by branch {branch}'s %pkh set"
            );
            // ⛔ The witness half is a MAP keyed by pkh, so the same signer
            // twice collapses to one entry and the count check upstream would
            // pass while consensus sees a 1-of-1.
            anyhow::ensure!(
                !entries.iter().any(|e| e.pkh == pkh),
                "the same signer was supplied twice; a repeated signer is ONE \
                 entry in the witness map, not two"
            );
            // ⭐ The signature must be over THIS spend's digest. A co-signature
            // that covers a different output set is a spend consensus refuses
            // by saying nothing at all.
            anyhow::ensure!(
                crate::signing::verify_chain_signature(&part.pubkey, &msg, &part.signature),
                "a co-signature does not verify against this spend's sig-hash — it was \
                 made over a different output set, or under a different key"
            );
            entries.push(PkhSignatureEntry {
                pkh,
                pubkey: part.pubkey.clone(),
                signature: part.signature.clone(),
            });
        }
        entries
    } else {
        anyhow::ensure!(
            parts.is_empty(),
            "branch {branch} carries no %pkh conjunct, so it takes no signatures"
        );
        Vec::new()
    };

    // ⛔⛔ A branch carrying a `%brn` CANNOT BE SPENT, whatever else is in it —
    // `check` walks the conjuncts with `levy` and answers `%|` for `%brn`
    // unconditionally (`tx-engine-1.hoon:2260-2267`). Since the hold's padding
    // branch gained the job commitment it also carries a `%hax`, and demanding a
    // preimage for that would be demanding one that CANNOT EXIST: `job_com` is
    // the order's digest over field elements, not `hash-noun` of any noun. The
    // only reason to build a witness for this branch at all is to demonstrate
    // that consensus refuses it (`hold_lifecycle_devnet`), and that
    // demonstration must stay constructible.
    //
    // ⚑ This does not weaken the capture: `B1` carries no `%brn`, so its
    // preimage requirement below is untouched. What is skipped here is a
    // requirement on a branch no witness can ever spend.
    let unspendable = condition.iter().any(|p| matches!(p, LockPrimitive::Burn));

    // The delivery condition. Fail closed on a missing preimage: this is the
    // one refusal the whole row exists to make certain of.
    for primitive in condition.iter().filter(|_| !unspendable) {
        if let LockPrimitive::Hax(set) = primitive {
            for wanted in set.0.iter() {
                let entry = hax.iter().find(|e| &e.hash == wanted).ok_or_else(|| {
                    anyhow::anyhow!(
                        "branch {branch} requires a hashlock preimage that this \
                         witness does not carry — a capture must publish the key"
                    )
                })?;
                // ⛔ And it must be the RIGHT preimage. `check:hax` recomputes
                // the digest structurally over the value (`:2112-2119`) and
                // compares; a mislabelled entry is a spend that vanishes at a
                // node with nothing to read.
                let digest = nockchain_types::tx_engine::common::Hash::from_limbs(
                    &entry.value.hashable_noun_digest(),
                );
                anyhow::ensure!(
                    &digest == wanted,
                    "the hashlock preimage does not hash to the value branch \
                     {branch} names"
                );
            }
        }
    }

    Ok(Witness::new(lmp, PkhSignature::new(entries), hax))
}

/// Build a hold-spend witness from signing **keys** — the single-party
/// convenience over [`build_hold_witness_from_parts`].
///
/// ⚑ *In plain terms: the same thing, for when one process happens to hold
/// every key involved. That is a test fixture and a demonstration tool, not the
/// production shape.*
///
/// ⛔ **A 2-of-2 assembled here is not a co-signature.** Both keys are in one
/// place, so nothing about the buyer's independent agreement is established.
/// Production builds the buyer's half with [`hold_cosign`] on the buyer's own
/// machine and assembles with [`build_hold_witness_from_parts`]; this wrapper
/// exists so the devnet tools and the unit fixtures keep working unchanged, and
/// so every check has exactly one home.
pub fn build_hold_witness(
    lock: &nockchain_types::tx_engine::v1::tx::Lock,
    branch: u64,
    height: u64,
    bythos_phase: u64,
    signers: &[HoldSigner],
    sig_hash: &nockchain_types::tx_engine::common::Hash,
    hax: Vec<nockchain_types::tx_engine::v1::tx::HaxPreimage>,
) -> Result<nockchain_types::tx_engine::v1::tx::Witness> {
    let parts = signers
        .iter()
        .map(|sk| hold_cosign(sk, sig_hash))
        .collect::<Result<Vec<_>>>()?;
    build_hold_witness_from_parts(lock, branch, height, bythos_phase, &parts, sig_hash, hax)
}

/// Submit a transaction to the chain and optionally wait for acceptance.
///
/// Returns `true` if accepted, `false` if timed out (when `wait` is true).
/// Returns `true` immediately after submission (when `wait` is false).
pub async fn submit_tx(
    chain: &mut ChainClient,
    raw_tx: nockchain_types::tx_engine::v1::RawTx,
    tx_id_b58: &str,
    wait: bool,
) -> Result<bool> {
    if wait {
        chain.submit_and_wait(raw_tx, tx_id_b58).await
    } else {
        chain.submit_transaction(raw_tx).await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GraftPayload, NoteState};

    /// Mock verifier — proves Settle is parameterized cleanly over any
    /// `CommitmentVerifier`. Concrete domain verifiers (RAG, KV, log, etc.)
    /// live in downstream hulls.
    struct MockVerifier {
        should_pass: bool,
    }

    impl CommitmentVerifier for MockVerifier {
        fn verify(&self, _note_id: u64, _data: &[u8], _expected_root: &Tip5Hash) -> bool {
            self.should_pass
        }

        fn build_settle_poke(&self, payload: &GraftPayload) -> anyhow::Result<NounSlab> {
            // Minimal poke: just tag + note id
            use nock_noun_rs::*;
            let mut slab = NounSlab::new();
            let tag = make_atom_in(&mut slab, b"settle");
            let id = nockvm::noun::D(payload.note.id);
            let poke = nockvm::noun::T(&mut slab, &[tag, id]);
            slab.set_root(poke);
            Ok(slab)
        }
    }

    #[tokio::test]
    async fn settle_with_mock_verifier_pass() {
        let root: Tip5Hash = [1, 2, 3, 4, 5];
        let mut settler = Settle::with_verifier(MockVerifier { should_pass: true });
        settler.register_root(root).unwrap();

        let payload = GraftPayload {
            note: Note {
                id: 1,
                hull: 7,
                root,
                state: NoteState::Pending,
            },
            data: vec![],
            expected_root: root,
        };

        let result = settler.settle(&payload).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap().state, NoteState::Settled));
    }

    #[tokio::test]
    async fn settle_with_mock_verifier_fail() {
        let root: Tip5Hash = [1, 2, 3, 4, 5];
        let mut settler = Settle::with_verifier(MockVerifier { should_pass: false });
        settler.register_root(root).unwrap();

        let payload = GraftPayload {
            note: Note {
                id: 1,
                hull: 7,
                root,
                state: NoteState::Pending,
            },
            data: vec![],
            expected_root: root,
        };

        let result = settler.settle(&payload).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn settle_unregistered_root_fails() {
        let mut settler = Settle::with_verifier(MockVerifier { should_pass: true });
        // Don't register any root

        let payload = GraftPayload {
            note: Note {
                id: 1,
                hull: 7,
                root: [9, 9, 9, 9, 9],
                state: NoteState::Pending,
            },
            data: vec![],
            expected_root: [9, 9, 9, 9, 9],
        };

        let result = settler.settle(&payload).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("root not registered")
        );
    }

    // --- Pre-flight validation tests ---

    #[tokio::test]
    async fn settle_duplicate_note_rejected() {
        let root: Tip5Hash = [1, 2, 3, 4, 5];
        let mut settler = Settle::with_verifier(MockVerifier { should_pass: true });
        settler.register_root(root).unwrap();

        let payload = GraftPayload {
            note: Note {
                id: 1,
                hull: 7,
                root,
                state: NoteState::Pending,
            },
            data: vec![],
            expected_root: root,
        };

        // First settle succeeds
        assert!(settler.settle(&payload).await.is_ok());

        // Second settle with same note ID fails
        let result = settler.settle(&payload).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("duplicate settlement"), "got: {err}");
        assert!(err.contains("note 1"), "got: {err}");
    }

    #[tokio::test]
    async fn settle_non_pending_note_rejected() {
        let root: Tip5Hash = [1, 2, 3, 4, 5];
        let mut settler = Settle::with_verifier(MockVerifier { should_pass: true });
        settler.register_root(root).unwrap();

        let payload = GraftPayload {
            note: Note {
                id: 1,
                hull: 7,
                root,
                state: NoteState::Settled,
            },
            data: vec![],
            expected_root: root,
        };

        let result = settler.settle(&payload).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not pending"), "got: {err}");
    }

    #[test]
    fn poke_bytes_produces_nonempty() {
        let root: Tip5Hash = [1, 2, 3, 4, 5];
        let settler = Settle::with_verifier(MockVerifier { should_pass: true });

        let payload = GraftPayload {
            note: Note {
                id: 1,
                hull: 7,
                root,
                state: NoteState::Pending,
            },
            data: vec![],
            expected_root: root,
        };

        let bytes = settler.poke_bytes(&payload).unwrap();
        assert!(!bytes.is_empty(), "poke_bytes must produce non-empty JAM");
    }

    // --- Tests for composable helpers ---

    #[test]
    fn build_seeds_valid() {
        use nockchain_math::owned_based_noun::OwnedBasedNoun;
        use nockchain_types::tx_engine::common::Hash;
        use nockchain_types::tx_engine::v1::note::{NoteData, NoteDataEntry};

        let note_data = NoteData::new(vec![NoteDataEntry::new(
            "test".to_string(),
            OwnedBasedNoun::try_atom(1).unwrap(),
        )]);
        let lock_root = Hash::from_limbs(&[1, 2, 3, 4, 5]);
        let parent = Hash::from_limbs(&[10, 20, 30, 40, 50]);

        let seeds = build_seeds(lock_root, note_data, parent, 100_000, 256).unwrap();
        assert_eq!(seeds.0.len(), 1);
        assert_eq!(seeds.0[0].gift.0, 99_744); // 100000 - 256
    }

    #[test]
    fn build_seeds_excessive_fee_rejected() {
        use nockchain_math::owned_based_noun::OwnedBasedNoun;
        use nockchain_types::tx_engine::common::Hash;
        use nockchain_types::tx_engine::v1::note::{NoteData, NoteDataEntry};

        let note_data = NoteData::new(vec![NoteDataEntry::new(
            "test".to_string(),
            OwnedBasedNoun::try_atom(1).unwrap(),
        )]);
        let lock_root = Hash::from_limbs(&[1, 2, 3, 4, 5]);
        let parent = Hash::from_limbs(&[10, 20, 30, 40, 50]);

        let result = build_seeds(lock_root, note_data, parent, 100, 60);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fee"));
    }

    #[test]
    fn sign_tx_produces_signature() {
        use nockchain_math::belt::Belt;
        use nockchain_types::tx_engine::common::Hash;

        let mut sk = [Belt(0); 8];
        sk[0] = Belt(12345);
        sk[1] = Belt(67890);

        let hash = Hash::from_limbs(&[1, 2, 3, 4, 5]);
        let sig = sign_tx(&sk, &hash).unwrap();
        // Signature components must be non-zero
        assert!(sig.chal.iter().any(|b| b.0 != 0));
        assert!(sig.sig.iter().any(|b| b.0 != 0));
    }

    #[test]
    fn build_witness_produces_valid_witness() {
        use nockchain_math::belt::Belt;
        use nockchain_types::tx_engine::common::Hash;

        let mut sk = [Belt(0); 8];
        sk[0] = Belt(42);

        let hash = Hash::from_limbs(&[9, 8, 7, 6, 5]);
        let pubkey = crate::signing::derive_pubkey(&sk).unwrap();
        let pkh = crate::signing::pubkey_hash(&pubkey).unwrap();
        let first = crate::lock::first_name_for_lock(
            &nockchain_types::tx_engine::v1::tx::Lock::SpendCondition(
                nockchain_types::tx_engine::v1::tx::SpendCondition::simple_pkh(pkh),
            ),
        )
        .unwrap();
        let witness = build_witness(&sk, &hash, false, 1, &first).unwrap();

        // ⛔ The guard, exercised: the same key against a note that is not
        // its own must refuse, and say why.
        let wrong = nockchain_types::tx_engine::common::Hash::from_limbs(&[9, 9, 9, 9, 9]);
        let err = build_witness(&sk, &hash, false, 1, &wrong).unwrap_err();
        assert!(err.to_string().contains("does not derive"), "{err}");
        // Witness was constructed without error
        let _ = witness;
    }

    // -----------------------------------------------------------------------
    // The hold spend builder — every refusal exercised. A derived register is
    // an untested arm.
    // -----------------------------------------------------------------------

    fn hold_fixture() -> HoldFixture {
        use nockchain_math::owned_based_noun::OwnedBasedNoun;
        use nockchain_types::tx_engine::common::Hash;
        use nockchain_types::tx_engine::v1::tx::HaxPreimage;

        let mk = |seed: u64| {
            let mut sk = [nockchain_math::belt::Belt(0); 8];
            sk[0] = nockchain_math::belt::Belt(seed);
            sk
        };
        // ⚑ THREE keys since row 10: the buyer's payment key, the buyer's
        // dedicated VOID key, and the platform's. The void key is what stops a
        // capture co-signature spending B2.
        let (buyer_sk, buyer_void_sk, platform_sk) = (mk(11), mk(17), mk(23));
        let pkh_of = |sk: &[nockchain_math::belt::Belt; 8]| {
            crate::signing::pubkey_hash(&crate::signing::derive_pubkey(sk).unwrap()).unwrap()
        };

        // A minimal, self-consistent preimage: the lock names exactly the
        // digest of the value the witness will carry.
        let value = OwnedBasedNoun::Cell(
            Box::new(OwnedBasedNoun::Atom(nockchain_math::belt::Belt(
                0xdead_beef,
            ))),
            Box::new(OwnedBasedNoun::Atom(nockchain_math::belt::Belt(0x1234))),
        );
        let h_k = Hash::from_limbs(&value.hashable_noun_digest());
        let preimage = HaxPreimage {
            hash: h_k.clone(),
            value,
        };
        // The reclaim's own secret, built the same self-consistent way.
        let sb_value = OwnedBasedNoun::Cell(
            Box::new(OwnedBasedNoun::Atom(nockchain_math::belt::Belt(0xfeed))),
            Box::new(OwnedBasedNoun::Atom(nockchain_math::belt::Belt(0x5678))),
        );
        let h_sb = Hash::from_limbs(&sb_value.hashable_noun_digest());
        let sb_preimage = HaxPreimage {
            hash: h_sb.clone(),
            value: sb_value,
        };
        let lock = crate::lock::hold_lock(
            pkh_of(&buyer_sk),
            pkh_of(&buyer_void_sk),
            pkh_of(&platform_sk),
            h_k,
            h_sb,
            4,
            Hash::from_limbs(&[7, 7, 7, 7, 7]),
        )
        .expect("three distinct keys");
        HoldFixture {
            lock,
            buyer_sk,
            buyer_void_sk,
            platform_sk,
            preimage,
            sb_preimage,
        }
    }

    /// What [`hold_fixture`] hands back. ⚑ A struct rather than a tuple since
    /// row 10 took it to six members — a positional sixth is exactly how a
    /// test ends up signing with the wrong key and still passing.
    struct HoldFixture {
        lock: nockchain_types::tx_engine::v1::tx::Lock,
        buyer_sk: [nockchain_math::belt::Belt; 8],
        buyer_void_sk: [nockchain_math::belt::Belt; 8],
        platform_sk: [nockchain_math::belt::Belt; 8],
        preimage: nockchain_types::tx_engine::v1::tx::HaxPreimage,
        sb_preimage: nockchain_types::tx_engine::v1::tx::HaxPreimage,
    }

    fn sh() -> nockchain_types::tx_engine::common::Hash {
        nockchain_types::tx_engine::common::Hash::from_limbs(&[11, 22, 33, 44, 55])
    }

    #[test]
    fn a_capture_witness_needs_both_signatures_and_the_key() {
        let f = hold_fixture();
        let (lock, buyer, platform, preimage) = (f.lock, f.buyer_sk, f.platform_sk, f.preimage);
        let b = crate::lock::HOLD_BRANCH_CAPTURE;

        // ✅ Both signatures and the key.
        let w = build_hold_witness(
            &lock,
            b,
            10,
            1,
            &[buyer, platform],
            &sh(),
            vec![preimage.clone()],
        )
        .expect("the honest capture must build");
        assert_eq!(w.pkh_signature.0.len(), 2, "a 2-of-2 needs two entries");
        assert_eq!(w.hax.len(), 1);

        // ⛔ Without the key — the delivery condition, refused before it can
        // vanish at a node.
        let err = build_hold_witness(&lock, b, 10, 1, &[buyer, platform], &sh(), vec![])
            .unwrap_err()
            .to_string();
        assert!(err.contains("must publish the key"), "{err}");

        // ⛔ With the wrong key.
        let mut wrong = preimage.clone();
        wrong.hash = nockchain_types::tx_engine::common::Hash::from_limbs(&[1, 2, 3, 4, 5]);
        let err = build_hold_witness(&lock, b, 10, 1, &[buyer, platform], &sh(), vec![wrong])
            .unwrap_err()
            .to_string();
        assert!(err.contains("must publish the key"), "{err}");

        // ⛔ With a preimage whose value does not hash to what the lock names.
        let mut mislabelled = preimage.clone();
        mislabelled.value =
            nockchain_math::owned_based_noun::OwnedBasedNoun::Atom(nockchain_math::belt::Belt(7));
        let err = build_hold_witness(
            &lock,
            b,
            10,
            1,
            &[buyer, platform],
            &sh(),
            vec![mislabelled],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not hash to"), "{err}");
    }

    #[test]
    fn the_two_of_two_refuses_one_signature_and_a_repeated_signer() {
        let f = hold_fixture();
        let (lock, buyer, platform, preimage) = (f.lock, f.buyer_sk, f.platform_sk, f.preimage);
        // ⚑ ROW 10: the two 2-of-2s no longer name the same pair, so each
        // branch is exercised with ITS OWN buyer-side key. Looping with one key
        // would test membership on B2 rather than the count and the collapse —
        // the refusal would still fire, on a different cause, and the leg would
        // silently stop being about what it is named for.
        for (b, signer) in [
            (crate::lock::HOLD_BRANCH_CAPTURE, buyer),
            (crate::lock::HOLD_BRANCH_VOID, f.buyer_void_sk),
        ] {
            // ⛔ One signature is not a weaker two — `check:pkh` compares the
            // map size for EQUALITY.
            let err = build_hold_witness(&lock, b, 10, 1, &[signer], &sh(), vec![preimage.clone()])
                .unwrap_err()
                .to_string();
            assert!(err.contains("2-of-2"), "{err}");

            // ⛔⛔ The same signer twice. The witness half is a MAP keyed by
            // pkh, so this is ONE entry at consensus — a silent downgrade of a
            // 2-of-2 to a 1-of-1, which no test of the honest path can show.
            let err = build_hold_witness(
                &lock,
                b,
                10,
                1,
                &[signer, signer],
                &sh(),
                vec![preimage.clone()],
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("supplied twice"), "{err}");
            let _ = platform;
        }
    }

    #[test]
    fn a_stranger_cannot_sign_a_hold_branch() {
        let f = hold_fixture();
        let (lock, buyer, _platform, preimage) = (f.lock, f.buyer_sk, f.platform_sk, f.preimage);
        let mut stranger = [nockchain_math::belt::Belt(0); 8];
        stranger[0] = nockchain_math::belt::Belt(99);
        let err = build_hold_witness(
            &lock,
            crate::lock::HOLD_BRANCH_CAPTURE,
            10,
            1,
            &[buyer, stranger],
            &sh(),
            vec![preimage],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not named by"), "{err}");
    }

    /// ⛔⛔ **THIS TEST'S NAME AND ITS ASSERTION BOTH CHANGED AT ROW 10.** It
    /// read *"...and no key"* and asserted `w.hax.is_empty()`, *"a reclaim
    /// publishes nothing"* — true only while `B3` was `%pkh` + `%tim`. That
    /// shape let the buyer reach its own recovery with the ORDINARY payment
    /// signature, which is `PLAN_B §D`'s route 2. `B3` now also names
    /// `%hax {h_sb}`, so a reclaim publishes the buyer's own per-job secret and
    /// nothing else.
    #[test]
    fn the_reclaim_branch_takes_the_buyer_alone_and_its_own_secret() {
        let f = hold_fixture();
        let (lock, buyer, platform) = (&f.lock, f.buyer_sk, f.platform_sk);
        let b = crate::lock::HOLD_BRANCH_RECLAIM;
        let w = build_hold_witness(lock, b, 10, 1, &[buyer], &sh(), vec![f.sb_preimage.clone()])
            .expect("the buyer's recovery must build");
        assert_eq!(w.pkh_signature.0.len(), 1);
        assert_eq!(
            w.hax.len(),
            1,
            "a reclaim publishes the buyer's own secret, and only that"
        );

        // ⭐ The row-10 half: without the secret the branch does not build, so
        // a buyer's bare payment signature no longer reaches its own recovery.
        let err = build_hold_witness(lock, b, 10, 1, &[buyer], &sh(), vec![])
            .unwrap_err()
            .to_string();
        assert!(err.contains("hashlock preimage"), "{err}");

        // ⛔ It is 1-of-1 over the buyer, so the platform is not a member and
        // two signatures are the wrong count.
        let sb = || vec![f.sb_preimage.clone()];
        assert!(build_hold_witness(lock, b, 10, 1, &[platform], &sh(), sb()).is_err());
        assert!(build_hold_witness(lock, b, 10, 1, &[buyer, platform], &sh(), sb()).is_err());
    }

    /// ⭐⭐ **THE ROW-10 PROPERTY, AT THE BUILDER.** A capture co-signature is
    /// byte-for-byte the signature a void of the same outputs asks for —
    /// `sig-hash` covers the seeds and the fee and not the branch. What stops
    /// it being replayed onto `B2` is that `B2` names a key the capture
    /// signature was not made with, and `check:pkh`'s subset test refuses it
    /// before outputs are considered.
    ///
    /// ⚑ · MEASURED at consensus before this landed: a live node ACCEPTED
    /// exactly this spend, twice (x402 `records/S118`).
    #[test]
    fn a_capture_cosignature_cannot_spend_the_void_branch() {
        let f = hold_fixture();
        let void = crate::lock::HOLD_BRANCH_VOID;

        // The honest void: the buyer's DEDICATED key plus the platform.
        assert!(
            build_hold_witness(
                &f.lock,
                void,
                10,
                1,
                &[f.buyer_void_sk, f.platform_sk],
                &sh(),
                vec![]
            )
            .is_ok(),
            "the void must still be spendable by the parties it names"
        );

        // ⛔ The attack: the very signatures a capture is made from, on B2.
        let err = build_hold_witness(
            &f.lock,
            void,
            10,
            1,
            &[f.buyer_sk, f.platform_sk],
            &sh(),
            vec![],
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("not named by"),
            "the capture's signer must not be a member of the void branch: {err}"
        );

        // ...and the control, so the refusal above is about the KEY and not
        // about the branch being unusable: the same buyer key spends B1.
        assert!(
            build_hold_witness(
                &f.lock,
                crate::lock::HOLD_BRANCH_CAPTURE,
                10,
                1,
                &[f.buyer_sk, f.platform_sk],
                &sh(),
                vec![f.preimage.clone()],
            )
            .is_ok(),
            "the same co-signature must still capture — that is the point of it"
        );
    }

    /// The padding branch carries no `%pkh` at all, so it takes no signatures —
    /// and it is unspendable at consensus regardless (`%brn` answers `%|`).
    /// Building a witness for it must not look like authorization.
    ///
    /// ⚑ Since the branch gained the job commitment it also carries a `%hax`,
    /// and a witness for it must STILL be constructible without a preimage —
    /// the only reason to build one is to demonstrate that consensus refuses
    /// the branch, and `job_com` has no preimage to supply. A builder that
    /// demanded one would delete row 0's padding control.
    #[test]
    fn the_padding_branch_takes_no_signatures() {
        let f = hold_fixture();
        let (lock, buyer, _p, _k) = (f.lock, f.buyer_sk, f.platform_sk, f.preimage);
        let b = crate::lock::HOLD_BRANCH_PADDING;
        assert!(build_hold_witness(&lock, b, 10, 1, &[buyer], &sh(), vec![]).is_err());
        let w = build_hold_witness(&lock, b, 10, 1, &[], &sh(), vec![]).expect("no signers");
        assert!(w.pkh_signature.0.is_empty());
        assert!(
            w.hax.is_empty(),
            "the padding branch publishes nothing — it cannot be spent, so there is \
             nothing for a preimage to buy"
        );
    }

    /// ⭐⭐ THE CAPTURE'S PREIMAGE REQUIREMENT IS UNTOUCHED BY THE SKIP ABOVE.
    ///
    /// ⚑ *In plain terms: we stopped demanding a key for the dead branch. This
    /// checks we did not stop demanding one for the branch that takes the
    /// money.* Without this the exemption could quietly widen to every branch
    /// and the delivery condition would evaporate — the one thing row 0 exists
    /// to guarantee.
    #[test]
    fn skipping_the_dead_branchs_hashlock_does_not_skip_the_captures() {
        let f = hold_fixture();
        let (lock, buyer, platform, _preimage) = (f.lock, f.buyer_sk, f.platform_sk, f.preimage);
        let b = crate::lock::HOLD_BRANCH_CAPTURE;
        let why = build_hold_witness(&lock, b, 10, 1, &[buyer, platform], &sh(), vec![])
            .expect_err("a capture with no preimage must still be refused");
        assert!(
            why.to_string().contains("must publish the key"),
            "the refusal must name the capture's key, got: {why}"
        );
    }

    // -----------------------------------------------------------------------
    // ⭐ THE CAPTURE'S OUTPUT SET — x402 board row 5, and `F7` lives here.
    // -----------------------------------------------------------------------

    fn root(n: u64) -> nockchain_types::tx_engine::common::Hash {
        nockchain_types::tx_engine::common::Hash::from_limbs(&[n, n, n, n, n])
    }

    fn out(n: u64, amount: u64) -> CaptureOutput {
        CaptureOutput {
            lock_root: root(n),
            note_data: nockchain_types::tx_engine::v1::note::NoteData::new(Vec::new()),
            amount,
        }
    }

    // -----------------------------------------------------------------------
    // ⭐⭐ `output-source` — x402 board row `19b`. See `PROPOSAL-output-source.md`.
    // -----------------------------------------------------------------------

    use nockchain_types::tx_engine::v1::hashable::HashHashable;
    use nockchain_types::tx_engine::v1::tx::{Seed, Seeds};

    fn bare_seed(lock: u64, gift: usize, parent: u64) -> Seed {
        Seed {
            output_source: None,
            lock_root: root(lock),
            note_data: nockchain_types::tx_engine::v1::note::NoteData::new(Vec::new()),
            gift: nockchain_types::tx_engine::common::Nicks(gift),
            parent_hash: root(parent),
        }
    }

    /// ⭐ Every output a capture signs carries a pin. This is the guard that
    /// board row `19b` actually landed; with the `pin_output_source` call
    /// removed from `build_capture_seeds` it fails on its own assertion.
    #[test]
    fn every_capture_output_is_pinned() {
        let outs = [out(1, 94_500), out(2, 5_500), out(3, 899_750)];
        let seeds = build_capture_seeds(&outs, &root(9), 1_000_000, 250).expect("conserves");
        assert_eq!(seeds.0.len(), 3);
        for (i, seed) in seeds.0.iter().enumerate() {
            let src = seed
                .output_source
                .as_ref()
                .unwrap_or_else(|| panic!("capture output {i} declines the pin"));
            assert!(
                !src.is_coinbase,
                "a capture output is not a coinbase, so its source must say so"
            );
        }
    }

    /// ⛔⛔ **THE ONE THAT CATCHES A PER-SEED IMPLEMENTATION.** Consensus
    /// computes ONE source per lock-root GROUP, over every seed in the group
    /// (`build-outputs`, `tx-engine-1.hoon:2364-2380`). A helper that hashed
    /// each seed on its own would produce two different values here, and both
    /// would be wrong — the transaction would be refused by consensus with
    /// nothing to read. So this asserts the two members share ONE value and
    /// that it is the TWO-element group's hash, not either singleton's.
    ///
    /// ⚑ `build_capture_seeds` refuses a same-root pair, deliberately, so this
    /// reaches `pin_output_source` directly. The pair is legal at consensus;
    /// what our builders decline is emitting one.
    #[test]
    fn a_shared_lock_root_gets_one_group_pin_not_two_singleton_pins() {
        let mut seeds = Seeds(vec![bare_seed(1, 10, 9), bare_seed(1, 20, 9)]);
        let singleton_a = Seeds(vec![bare_seed(1, 10, 9)])
            .hash_digest()
            .expect("singleton a");
        let group = Seeds(vec![bare_seed(1, 10, 9), bare_seed(1, 20, 9)])
            .hash_digest()
            .expect("group");
        assert_ne!(
            singleton_a, group,
            "the control: a singleton and the pair must hash differently, or this test \
             could not tell a per-seed pin from a per-group one"
        );

        pin_output_source(&mut seeds).expect("pin");
        let a = seeds.0[0].output_source.clone().expect("a is pinned");
        let b = seeds.0[1].output_source.clone().expect("b is pinned");
        assert_eq!(a, b, "two seeds under one lock root share one source");
        assert_eq!(
            a.hash, group,
            "and it is the GROUP's hash, not a singleton's"
        );
    }

    // -----------------------------------------------------------------------
    // ⭐⭐ ROW 23 — the MULTI-INPUT pin, and the tripwire it must not lose.
    // -----------------------------------------------------------------------

    /// ⭐⭐ Two spends paying ONE address get the GROUP's pin, not two
    /// singletons — which is what `D-37` predicted and `records/S133 §9.7`
    /// measured a node silently dropping.
    ///
    /// ⚑ The controls come first: without them "they are equal" is equally
    /// consistent with a pin that hashes nothing.
    #[test]
    fn two_spends_at_one_lock_root_get_the_group_pin_not_two_singletons() {
        // Two spends of two DIFFERENT input notes, each paying lock root 1.
        let mut a = Seeds(vec![bare_seed(1, 10, 90), bare_seed(2, 5, 90)]);
        let mut b = Seeds(vec![bare_seed(1, 20, 91), bare_seed(3, 5, 91)]);

        let singleton_a = Seeds(vec![bare_seed(1, 10, 90)])
            .hash_digest()
            .expect("singleton a");
        let group = Seeds(vec![bare_seed(1, 10, 90), bare_seed(1, 20, 91)])
            .hash_digest()
            .expect("cross-spend group");
        assert_ne!(
            singleton_a, group,
            "the control: a singleton and the cross-spend pair must hash differently, or this              test could not tell a per-spend pin from a cross-spend one"
        );

        // The control that this is a REAL change: the per-spend helper gets it
        // wrong here, and that wrongness is exactly D-37.
        let mut per_spend = a.clone();
        pin_output_source(&mut per_spend).expect("per-spend pin");
        assert_eq!(
            per_spend.0[0].output_source.clone().expect("pinned").hash,
            singleton_a,
            "the control: the per-spend helper pins the SINGLETON, which is the defect"
        );

        pin_output_source_across(vec![&mut a, &mut b]).expect("cross-spend pin");

        let pa = a.0[0].output_source.clone().expect("a0 pinned");
        let pb = b.0[0].output_source.clone().expect("b0 pinned");
        assert_eq!(pa, pb, "the two spends' seeds at one root share one source");
        assert_eq!(
            pa.hash, group,
            "and it is the CROSS-SPEND group's hash, not either singleton's"
        );

        // The seeds at their own distinct roots are untouched by the merge.
        assert_ne!(
            a.0[1].output_source.clone().expect("a1").hash,
            pa.hash,
            "a seed at a different lock root is a different output group"
        );
    }

    /// ⭐⭐ **THE FIX IS NOT A BLIND WIDENING, CHECKED AS A VALUE COMPARISON.**
    ///
    /// `D-37` warns that pinning "the whole transaction's group" would agree
    /// with a stranger's tampering by construction and guard nothing. The pin
    /// this crate now writes spans exactly the seeds WE assembled, so a
    /// stranger's seed at our lock root still moves consensus's group hash away
    /// from our claim — `XE-163`'s `X1`/`X3`, which measured that refusal at
    /// consensus.
    ///
    /// ⚑ The second half is the discriminator: it computes what a blind
    /// widening WOULD have produced and shows it matching, so "our pin differs"
    /// is a statement about this implementation rather than about arithmetic.
    #[test]
    fn a_strangers_seed_at_our_lock_root_still_breaks_the_group_pin() {
        let mut ours_a = Seeds(vec![bare_seed(1, 10, 90)]);
        let mut ours_b = Seeds(vec![bare_seed(1, 20, 91)]);
        pin_output_source_across(vec![&mut ours_a, &mut ours_b]).expect("pin across ours");
        let our_claim = ours_a.0[0].output_source.clone().expect("pinned").hash;

        // A seed we did NOT author, at OUR lock root, in the same transaction.
        let stranger = bare_seed(1, 7, 77);

        // What consensus would compute over the whole merged group.
        let consensus = Seeds(vec![
            bare_seed(1, 10, 90),
            bare_seed(1, 20, 91),
            stranger.clone(),
        ])
        .hash_digest()
        .expect("consensus group");

        assert_ne!(
            our_claim, consensus,
            "⛔ the tripwire is GONE: our claim matches a group containing a seed we never              authored, so a stranger could land value on our output silently"
        );

        // The discriminator: a BLIND widening — one that pinned whatever ended
        // up in the transaction — would have agreed with the tamper.
        let blind = Seeds(vec![bare_seed(1, 10, 90), bare_seed(1, 20, 91), stranger])
            .hash_digest()
            .expect("blind group");
        assert_eq!(
            blind, consensus,
            "the discriminator: a pin computed over the transaction as it ENDS UP would match              the tampered group exactly — that is the fix this one is not"
        );
    }

    /// The two entry points must agree: pinning the seed sets before the
    /// witnesses exist, and pinning an assembled `Spends`, are the same walk.
    #[test]
    fn pinning_across_seed_sets_and_across_spends_agree() {
        use nockchain_types::tx_engine::common::{Name, Nicks};
        use nockchain_types::tx_engine::v1::tx::{
            LockMerkleProof, MerkleProof, PkhSignature, Spend, Spend1, SpendCondition, Spends,
            Witness,
        };
        let mk = |n: u64, seeds: Seeds| {
            let sc = SpendCondition::simple_pkh(root(n));
            let r = sc.hash().expect("root");
            let w = Witness::new(
                LockMerkleProof::new_stub(
                    sc,
                    1,
                    MerkleProof {
                        root: r,
                        path: vec![],
                    },
                ),
                PkhSignature::new(vec![]),
                vec![],
            );
            (
                Name::new(root(n), root(n + 100)),
                Spend::Witness(Spend1 {
                    witness: w,
                    seeds,
                    fee: Nicks(0),
                }),
            )
        };

        let mut sa = Seeds(vec![bare_seed(1, 10, 90), bare_seed(2, 5, 90)]);
        let mut sb = Seeds(vec![bare_seed(1, 20, 91)]);
        let mut spends = Spends(vec![mk(7, sa.clone()), mk(8, sb.clone())]);

        pin_output_source_across(vec![&mut sa, &mut sb]).expect("across sets");
        pin_output_source_across_spends(&mut spends).expect("across spends");

        let from_spends: Vec<_> = spends
            .0
            .iter()
            .flat_map(|(_, sp)| match sp {
                Spend::Witness(s) => s.seeds.0.clone(),
                Spend::Legacy(s) => s.seeds.0.clone(),
            })
            .collect();
        let from_sets: Vec<_> = sa.0.iter().chain(sb.0.iter()).cloned().collect();
        assert_eq!(from_spends, from_sets, "the two entry points must agree");
        assert!(
            from_sets.iter().all(|s| s.output_source.is_some()),
            "the control: vacuous unless the pin actually landed"
        );
    }

    /// ⚑ The cross-spend pass must OVERWRITE a per-spend pin, because the
    /// shipped `build_output_seeds` writes one internally — so a multi-input
    /// builder that reuses it arrives with the wrong value already in place.
    #[test]
    fn the_cross_spend_pin_overwrites_a_per_spend_one() {
        let mut a = Seeds(vec![bare_seed(1, 10, 90)]);
        let mut b = Seeds(vec![bare_seed(1, 20, 91)]);
        pin_output_source(&mut a).expect("per-spend first");
        pin_output_source(&mut b).expect("per-spend first");
        let stale = a.0[0].output_source.clone().expect("stale");

        pin_output_source_across(vec![&mut a, &mut b]).expect("then across");
        let fresh = a.0[0].output_source.clone().expect("fresh");
        assert_ne!(
            stale, fresh,
            "the cross-spend pass left a per-spend value in place — a builder reusing              build_output_seeds would sign the wrong pin and the node would drop the payment"
        );
        assert_eq!(
            fresh.hash,
            Seeds(vec![bare_seed(1, 10, 90), bare_seed(1, 20, 91)])
                .hash_digest()
                .expect("group"),
            "and the value it left is the cross-spend group's"
        );
    }
    /// Two seeds under DIFFERENT lock roots are different groups, so they must
    /// NOT share a value — the discrimination control for the test above.
    #[test]
    fn different_lock_roots_get_different_pins() {
        let mut seeds = Seeds(vec![bare_seed(1, 10, 9), bare_seed(2, 20, 9)]);
        pin_output_source(&mut seeds).expect("pin");
        let a = seeds.0[0].output_source.clone().expect("a");
        let b = seeds.0[1].output_source.clone().expect("b");
        assert_ne!(
            a, b,
            "seeds at different addresses are different output groups"
        );
    }

    /// ⭐ **THE PIN IS FEE-NEUTRAL, AND THE OBVIOUS GUESS IS THAT IT IS NOT.**
    /// A pinned field is a bigger noun than an empty one and the chain meters
    /// by leaf count, so one would expect every transaction to get dearer and
    /// `U8`'s floors to move. `count_seed_words` walks `seed.note_data` and
    /// nothing else, so it does not — and this pins that rather than leaving it
    /// as a code read, because it is exactly the sort of fact that would go
    /// stale in silence the first time the meter's basis widened.
    #[test]
    fn fee_is_unchanged_by_pinning_output_source() {
        use nockchain_types::tx_engine::common::{Name, Nicks};
        use nockchain_types::tx_engine::v1::tx::{
            LockMerkleProof, LockMerkleProofFull, MerkleProof, PkhSignature, Spend, Spend1, Spends,
            Witness,
        };

        let spends_of = |seeds: Seeds| {
            let lmp = LockMerkleProof::Full(LockMerkleProofFull {
                version: nockvm_macros::tas!(b"full"),
                spend_condition: nockchain_types::tx_engine::v1::tx::SpendCondition::simple_pkh(
                    root(7),
                ),
                axis: 1,
                proof: MerkleProof {
                    root: root(7),
                    path: vec![],
                },
            });
            Spends(vec![(
                Name::new(root(5), root(6)),
                Spend::Witness(Spend1 {
                    witness: Witness::new(lmp, PkhSignature::new(vec![]), vec![]),
                    seeds,
                    fee: Nicks(0),
                }),
            )])
        };

        let bare = Seeds(vec![bare_seed(1, 10, 9), bare_seed(2, 20, 9)]);
        let mut pinned = bare.clone();
        pin_output_source(&mut pinned).expect("pin");
        assert!(
            pinned.0.iter().all(|s| s.output_source.is_some()),
            "the control: this test is vacuous unless the pin actually landed"
        );

        let constants = crate::fee::FeeConstants::fakenet();
        let height = constants.bythos_phase + 1;
        let before =
            crate::fee::calculate_min_fee(&spends_of(bare), height, &constants).expect("before");
        let after =
            crate::fee::calculate_min_fee(&spends_of(pinned), height, &constants).expect("after");
        assert_eq!(
            before, after,
            "pinning output-source must not move the consensus minimum fee"
        );
    }

    /// The honest `XD-5` shape: escrow + commission + the buyer's change, plus
    /// the fee, adding back up to what the hold held.
    #[test]
    fn a_conserving_three_output_capture_builds() {
        // cap 1_000_000, bill 100_000, φ = 5,5 % ⇒ 94_500 / 5_500 / 899_750, fee 250
        let outs = [out(1, 94_500), out(2, 5_500), out(3, 899_750)];
        let seeds = build_capture_seeds(&outs, &root(9), 1_000_000, 250).expect("conserves");
        assert_eq!(seeds.0.len(), 3);
        let gifts: u64 = seeds.0.iter().map(|s| s.gift.0 as u64).sum();
        assert_eq!(gifts + 250, 1_000_000);
        assert!(seeds.0.iter().all(|s| s.parent_hash == root(9)));
    }

    /// ⭐⭐ **`F7` — a capture that does not conserve is REFUSED, in both
    /// directions.** Over-paying invents money the hold does not hold;
    /// under-paying strands the difference where nobody can reach it. Neither is
    /// a rounding question, and neither may reach a signature.
    #[test]
    fn a_capture_that_does_not_conserve_is_refused() {
        // One nick too much.
        let over = [out(1, 94_501), out(2, 5_500), out(3, 899_750)];
        let err = build_capture_seeds(&over, &root(9), 1_000_000, 250)
            .expect_err("one nick over must not build");
        assert!(err.to_string().contains("does not conserve"), "{err}");

        // One nick too little.
        let under = [out(1, 94_499), out(2, 5_500), out(3, 899_750)];
        let err = build_capture_seeds(&under, &root(9), 1_000_000, 250)
            .expect_err("one nick under must not build");
        assert!(err.to_string().contains("does not conserve"), "{err}");

        // ⛔ And it is the FEE that is part of the identity, not decoration: the
        // same outputs against a different fee do not conserve either.
        let honest = [out(1, 94_500), out(2, 5_500), out(3, 899_750)];
        assert!(build_capture_seeds(&honest, &root(9), 1_000_000, 249).is_err());
        assert!(build_capture_seeds(&honest, &root(9), 1_000_000, 250).is_ok());
    }

    /// ⛔⛔ Two outputs under one lock root are ONE output on chain. Without this
    /// the spend still conserves arithmetically and still signs — it simply pays
    /// somebody the wrong amount, with nothing anywhere reporting it.
    #[test]
    fn two_outputs_sharing_a_lock_root_are_refused() {
        let outs = [out(1, 94_500), out(1, 5_500), out(3, 899_750)];
        let err = build_capture_seeds(&outs, &root(9), 1_000_000, 250)
            .expect_err("a merged pair must not build");
        assert!(err.to_string().contains("share a lock root"), "{err}");
    }

    /// A zero output is dropped by the caller, never emitted — the commission
    /// rounds away on a small bill and the capture is then two outputs.
    #[test]
    fn a_zero_value_output_is_refused_and_the_two_output_shape_builds() {
        let with_zero = [out(1, 94_500), out(2, 0), out(3, 905_250)];
        let err = build_capture_seeds(&with_zero, &root(9), 1_000_000, 250)
            .expect_err("a zero seed must not build");
        assert!(err.to_string().contains("zero assets"), "{err}");

        // The shape the caller actually emits when φ rounds to nothing.
        let two = [out(1, 18), out(3, 972)];
        let seeds = build_capture_seeds(&two, &root(9), 1_000, 10).expect("two outputs conserve");
        assert_eq!(seeds.0.len(), 2);
    }

    #[test]
    fn a_capture_with_no_outputs_is_refused() {
        let err = build_capture_seeds(&[], &root(9), 1_000, 10).expect_err("must not build");
        assert!(err.to_string().contains("burn the whole hold"), "{err}");
    }

    /// The note-data rides on exactly the output it was given to — the escrow's
    /// intent entries must not land on the buyer's change.
    #[test]
    fn note_data_stays_on_the_output_it_was_given_to() {
        use nockchain_types::tx_engine::v1::note::{NoteData, NoteDataEntry};
        let entry = NoteDataEntry::new(
            "vint-v".to_string(),
            nockchain_math::owned_based_noun::OwnedBasedNoun::try_atom(42).unwrap(),
        );
        let mut escrow = out(1, 94_500);
        escrow.note_data = NoteData::new(vec![entry]);
        let outs = [escrow, out(2, 5_500), out(3, 899_750)];
        let seeds = build_capture_seeds(&outs, &root(9), 1_000_000, 250).expect("conserves");
        assert!(!seeds.0[0].note_data.is_empty());
        assert!(seeds.0[1].note_data.is_empty());
        assert!(seeds.0[2].note_data.is_empty());
    }

    // -----------------------------------------------------------------------
    // ⭐ THE CO-SIGNATURE PATH — the buyer never hands over a key.
    // -----------------------------------------------------------------------

    /// ⭐⭐ **ONE HOME.** Assembling from separately-made signatures must produce
    /// exactly the witness the key-taking wrapper produces, or the two paths
    /// have drifted and only one of them is the one consensus was pinned
    /// against.
    #[test]
    fn assembling_from_cosignatures_equals_assembling_from_keys() {
        let f = hold_fixture();
        let (lock, buyer, platform, preimage) = (f.lock, f.buyer_sk, f.platform_sk, f.preimage);
        let b = crate::lock::HOLD_BRANCH_CAPTURE;

        let from_keys = build_hold_witness(
            &lock,
            b,
            10,
            1,
            &[buyer, platform],
            &sh(),
            vec![preimage.clone()],
        )
        .expect("keys");

        // What production does: each party signs on its own machine and sends
        // back only a public key and a signature.
        let parts = [
            hold_cosign(&buyer, &sh()).expect("buyer signs"),
            hold_cosign(&platform, &sh()).expect("platform signs"),
        ];
        let from_parts =
            build_hold_witness_from_parts(&lock, b, 10, 1, &parts, &sh(), vec![preimage])
                .expect("cosignatures");

        assert_eq!(from_keys, from_parts);
    }

    /// ⭐ **A CO-SIGNATURE OVER A DIFFERENT OUTPUT SET IS REFUSED, BY NAME.**
    /// This is the check the key-taking path never needed: a counterparty's
    /// signature arrives over a wire, and consensus's answer to a bad one is
    /// silence.
    #[test]
    fn a_cosignature_over_a_different_spend_is_refused() {
        let f = hold_fixture();
        let (lock, buyer, platform, preimage) = (f.lock, f.buyer_sk, f.platform_sk, f.preimage);
        let b = crate::lock::HOLD_BRANCH_CAPTURE;
        let other = nockchain_types::tx_engine::common::Hash::from_limbs(&[99, 88, 77, 66, 55]);
        assert_ne!(other, sh());

        // The buyer signed a different transaction than the one being assembled.
        let parts = [
            hold_cosign(&buyer, &other).expect("buyer signs the wrong spend"),
            hold_cosign(&platform, &sh()).expect("platform signs"),
        ];
        let err =
            build_hold_witness_from_parts(&lock, b, 10, 1, &parts, &sh(), vec![preimage.clone()])
                .expect_err("a signature over another output set must not assemble");
        assert!(err.to_string().contains("does not verify"), "{err}");

        // ⭐ THE CONTROL — the same two parties over the RIGHT digest assemble.
        let good = [
            hold_cosign(&buyer, &sh()).expect("buyer signs"),
            hold_cosign(&platform, &sh()).expect("platform signs"),
        ];
        build_hold_witness_from_parts(&lock, b, 10, 1, &good, &sh(), vec![preimage])
            .expect("the honest pair assembles");
    }

    /// A co-signature from a key the branch does not name is refused before the
    /// signature is even checked — a stranger's valid signature is still a
    /// stranger's.
    #[test]
    fn a_cosignature_from_an_unnamed_key_is_refused() {
        let f = hold_fixture();
        let (lock, buyer, _platform, preimage) = (f.lock, f.buyer_sk, f.platform_sk, f.preimage);
        let b = crate::lock::HOLD_BRANCH_CAPTURE;
        let mut stranger = [nockchain_math::belt::Belt(0); 8];
        stranger[0] = nockchain_math::belt::Belt(4_242);

        let parts = [
            hold_cosign(&buyer, &sh()).expect("buyer signs"),
            hold_cosign(&stranger, &sh()).expect("stranger signs"),
        ];
        let err = build_hold_witness_from_parts(&lock, b, 10, 1, &parts, &sh(), vec![preimage])
            .expect_err("a stranger must not co-sign");
        assert!(err.to_string().contains("not named by branch"), "{err}");
    }

    /// The delivery condition still binds on the co-signature path: a capture
    /// assembled without the key is refused here rather than vanishing at a node.
    #[test]
    fn a_keyless_capture_is_refused_on_the_cosignature_path_too() {
        let f = hold_fixture();
        let (lock, buyer, platform, _preimage) = (f.lock, f.buyer_sk, f.platform_sk, f.preimage);
        let b = crate::lock::HOLD_BRANCH_CAPTURE;
        let parts = [
            hold_cosign(&buyer, &sh()).expect("buyer signs"),
            hold_cosign(&platform, &sh()).expect("platform signs"),
        ];
        let err = build_hold_witness_from_parts(&lock, b, 10, 1, &parts, &sh(), vec![])
            .expect_err("a capture must publish the key");
        assert!(err.to_string().contains("must publish the key"), "{err}");
    }
}
