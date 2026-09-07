//! Generic transaction builder helpers for Nockchain settlement.
//!
//! Provides kernel-poke-based hash computation and manual JAM helpers
//! for constructing settlement transactions. Domain-specific wrappers
//! (e.g. SettlementTxParams, settlement_to_note_data) stay in the hull.

use nockapp::NockApp;
use nockapp::noun::slab::{NockJammer, NounSlab};
use nockapp::wire::{SystemWire, Wire};
use nockchain_math::zoon::zmap::ZMap;
use nockchain_math::zoon::zset::ZSet;
use nockchain_types::tx_engine::common::{Hash, Nicks};
use nockchain_types::tx_engine::v1::tx::{Seeds, Spends};
use nockvm::ext::make_tas;
use nockvm::noun::{D, IndirectAtom, NounAllocator, T};
use noun_serde::{NounDecode, NounEncode};

// ---------------------------------------------------------------------------
// Kernel-based hash computation
// ---------------------------------------------------------------------------

/// Wall-clock bound on a kernel poke (AUDIT 2026-05-19 H-08). A hung
/// graft arm, an infinite loop, or a stalled STARK proof must not block
/// the calling task forever. Matches vesl-hull's `poke_kernel_with_timeout`.
const KERNEL_POKE_TIMEOUT_SECS: u64 = 30;

/// Default poke timeout. `%tx-id` over a proof-carrying witness hashes
/// a multi-megabyte noun; callers on that path should pass a wider
/// bound to the `_with_timeout` variants instead.
pub fn default_poke_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(KERNEL_POKE_TIMEOUT_SECS)
}

/// Compute sig-hash by poking the Hoon kernel's `%sig-hash` handler.
///
/// Sends `[%sig-hash seeds-jam fee]` where `seeds-jam` is the JAM'd noun
/// of the Seeds z-set. Returns the tip5 hash used as the signing message.
pub async fn kernel_sig_hash(
    app: &mut NockApp,
    seeds: &Seeds,
    fee: &Nicks,
) -> anyhow::Result<Hash> {
    kernel_sig_hash_with_timeout(app, seeds, fee, default_poke_timeout()).await
}

/// [`kernel_sig_hash`] with an explicit poke timeout.
pub async fn kernel_sig_hash_with_timeout(
    app: &mut NockApp,
    seeds: &Seeds,
    fee: &Nicks,
    timeout: std::time::Duration,
) -> anyhow::Result<Hash> {
    let seeds_jammed = jam_seeds(seeds)?;

    let mut poke_slab: NounSlab = NounSlab::new();
    let tag = make_tas(&mut poke_slab, "sig-hash").as_noun();
    let seeds_atom = bytes_to_atom(&mut poke_slab, &seeds_jammed);
    // AUDIT 2026-05-21 L-01: route the fee through atom_from_u64 — a fee at
    // or above 2^63 (DIRECT_MAX) would panic the bare `D()` direct-atom
    // constructor. atom_from_u64 picks direct vs indirect atom by size.
    let fee_noun = atom_from_u64(&mut poke_slab, fee.0 as u64);
    let cmd = T(&mut poke_slab, &[tag, seeds_atom, fee_noun]);
    poke_slab.set_root(cmd);

    let effects = tokio::time::timeout(timeout, app.poke(SystemWire.to_wire(), poke_slab))
        .await
        .map_err(|_| anyhow::anyhow!("sig-hash poke timed out after {}s", timeout.as_secs()))?
        .map_err(|e| anyhow::anyhow!("sig-hash poke failed: {e:?}"))?;

    extract_hash_from_effect(&effects, "sig-hash")
}

/// Compute tx-id by poking the Hoon kernel's `%tx-id` handler.
///
/// Sends `[%tx-id spends-jam]` where `spends-jam` is the JAM'd noun
/// of the Spends z-map (including witness with real signatures).
pub async fn kernel_tx_id(app: &mut NockApp, spends: &Spends) -> anyhow::Result<Hash> {
    kernel_tx_id_with_timeout(app, spends, default_poke_timeout()).await
}

/// [`kernel_tx_id`] with an explicit poke timeout.
pub async fn kernel_tx_id_with_timeout(
    app: &mut NockApp,
    spends: &Spends,
    timeout: std::time::Duration,
) -> anyhow::Result<Hash> {
    let spends_jammed = jam_spends(spends)?;

    let mut poke_slab: NounSlab = NounSlab::new();
    let tag = make_tas(&mut poke_slab, "tx-id").as_noun();
    let spends_atom = bytes_to_atom(&mut poke_slab, &spends_jammed);
    let cmd = T(&mut poke_slab, &[tag, spends_atom]);
    poke_slab.set_root(cmd);

    let effects = tokio::time::timeout(timeout, app.poke(SystemWire.to_wire(), poke_slab))
        .await
        .map_err(|_| anyhow::anyhow!("tx-id poke timed out after {}s", timeout.as_secs()))?
        .map_err(|e| anyhow::anyhow!("tx-id poke failed: {e:?}"))?;

    extract_hash_from_effect(&effects, "tx-id")
}

// ---------------------------------------------------------------------------
// Manual noun builders — work around NockStack issue in ZSet/z-map
// ---------------------------------------------------------------------------

/// JAM Seeds by encoder dispatch.
///
/// - A single seed carrying note-data → [`jam_seeds_manual`], which writes the
///   trivial one-element treap `[seed 0 0]` directly. Byte-identical to the
///   canonical encoder for one element (pinned by
///   `jam_seeds_manual_matches_seeds_to_noun`), and it is kept for this case
///   because it does NOT copy the seed through `OwnedBasedNoun::from_noun`, so
///   it has no recursion bound at all — see [`MAX_SEED_NOUN_DEPTH`].
/// - Everything else → [`jam_seeds_canonical`], **including several seeds where
///   one carries note-data.**
///
/// ⛔⛔ THAT LAST CASE USED TO `bail!`, AND THE REASON GIVEN FOR IT WAS FALSE.
/// The refusal read *"the canonical encoder's treap ordering runs each seed
/// through a scratch `NockStack` that cannot absorb `NoteData::to_noun`"*.
/// · MEASURED 2026-08-30 (x402 row 1, falsifier `F2`), three ways:
///
/// 1. that scratch stack is `NOCK_STACK_SIZE_TINY` = **2 GB**
///    (`nockchain/crates/nockvm/rust/nockvm/src/mem.rs:33`) — size cannot be it;
/// 2. `jam_seeds_manual_matches_seeds_to_noun`, in this very file, has been
///    running the canonical encoder over a seed carrying NON-EMPTY note-data
///    the whole time;
/// 3. the ordering's real constraint is a FIELD-ELEMENT check, not a buffer:
///    `Seeds::to_noun` → `ZSet::try_from_items` → `OrderedNoun::encode` →
///    `OwnedBasedNoun::from_noun`, which rejects an atom wider than `u64` or at
///    or above the Goldilocks prime. Note-data built by this fleet is belt-safe
///    by construction, so it was never the obstacle.
///
/// ⇒ several outputs where one carries note-data now encode. That is what makes
/// x402's three-output capture expressible, and it lets the escrow posting drop
/// its funding-split transaction and its second fee.
/// The deepest seed noun `jam_seeds_canonical` will hand to the ordering.
///
/// ⛔⛔ NOT A STYLE LIMIT — IT IS A PROCESS-ABORT GUARD. The canonical z-set
/// ordering copies each seed through `OwnedBasedNoun::from_noun`
/// (`nockchain-math/src/owned_based_noun.rs:54-78`), which recurses on the RUST
/// stack. `vesl-agent-protocol/src/hax_carry.rs:186-190` records the
/// measurement: *"`OwnedBasedNoun::from_noun` aborts a default 2 MiB thread
/// stack at depth 2.072 (debug)"*. Consensus allows a note-data of **2048
/// leaves** (`nockchain/hoon/common/tx-engine-1.hoon:495-497`, enforced
/// `:1236-1237`), so a consensus-LEGAL note-data is within ~1% of that wall.
///
/// A stack overflow is a SIGSEGV, not an `Err`. So the depth is measured
/// iteratively first and refused here, by name.
///
/// ⚑ The platform's real escrow seed measures **19** (· MEASURED, see
/// `the_escrow_note_datas_depth_is_far_below_the_recursion_wall`), so this bound
/// is ~50x anything built today and half the measured wall.
///
/// **NAMED SUCCESSOR:** running the ordering on a thread with an explicit large
/// stack would lift the cap to the consensus one. Nothing needs it yet.
pub const MAX_SEED_NOUN_DEPTH: usize = 1024;

pub fn jam_seeds(seeds: &Seeds) -> anyhow::Result<bytes::Bytes> {
    if seeds.0.len() == 1 && !seeds.0[0].note_data.is_empty() {
        jam_seeds_manual(seeds)
    } else {
        jam_seeds_canonical(seeds)
    }
}

/// JAM Seeds via the canonical `Seeds::to_noun` encoder — **any seed count,
/// with or without note-data.**
///
/// ⛔ It does NOT call `Seeds::to_noun`, and that is deliberate. That impl
/// swallows the ordering's error with `.expect("seed z-set should encode")`
/// (`nockchain-types/src/tx_engine/v1/tx.rs:317-320`), so an unrepresentable
/// atom — a note-data key of nine bytes or more, say, which
/// `NoteData::to_noun` builds with `make_tas` and never checks
/// (`.../v1/note.rs:359-360`, *"TODO error if key is not a belt"*) — would
/// PANIC inside a transaction builder. Calling `ZSet::try_from_items` here
/// makes it an `Err` carrying the ordering's own cause.
///
/// The two refusals, both fail-closed:
/// - a seed noun deeper than [`MAX_SEED_NOUN_DEPTH`] (a process-abort guard);
/// - any atom the canonical ordering cannot represent.
pub fn jam_seeds_canonical(seeds: &Seeds) -> anyhow::Result<bytes::Bytes> {
    anyhow::ensure!(!seeds.0.is_empty(), "seeds must not be empty");
    refuse_deep_seeds(seeds)?;
    let set = ZSet::try_from_items(seeds.0.clone()).map_err(|err| {
        anyhow::anyhow!("the canonical z-set encoder cannot order these seeds: {err}")
    })?;
    let mut slab: NounSlab<NockJammer> = NounSlab::new();
    let noun = set.to_noun(&mut slab);
    slab.set_root(noun);
    Ok(slab.jam())
}

/// Refuse a seed whose noun is deep enough to abort the ordering.
///
/// ⚑ The walk is ITERATIVE. A recursive depth-prober would hit the very wall it
/// is measuring, which is the shape `hax_carry::hash_noun` already learned.
fn refuse_deep_seeds(seeds: &Seeds) -> anyhow::Result<()> {
    for (i, seed) in seeds.0.iter().enumerate() {
        let mut slab: NounSlab<NockJammer> = NounSlab::new();
        let noun = seed.to_noun(&mut slab);
        slab.set_root(noun);
        let space = slab.noun_space();
        let depth = noun_depth(slab_root(&slab), &space);
        anyhow::ensure!(
            depth <= MAX_SEED_NOUN_DEPTH,
            "seed {i}'s noun depth is {depth}, past the {MAX_SEED_NOUN_DEPTH} the canonical \
             ordering can copy without overflowing the stack"
        );
    }
    Ok(())
}

/// The depth of a noun, walked with an explicit work stack.
pub fn noun_depth(root: nockvm::noun::Noun, space: &nockvm::noun::NounSpace) -> usize {
    let mut work = vec![(root, 1usize)];
    let mut max = 0usize;
    while let Some((n, d)) = work.pop() {
        max = max.max(d);
        if let Ok(cell) = n.as_cell() {
            let h = cell.in_space(space);
            work.push((h.head().noun(), d + 1));
            work.push((h.tail().noun(), d + 1));
        }
    }
    max
}

/// JAM a single-seed Seeds by writing the trivial treap directly.
///
/// For a one-element z-set the noun is `[seed 0 0]` — a treap node with null
/// children — so no ordering is needed and `ZSet::try_from_items` is skipped.
///
/// ⛔ This header used to say the canonical encoder *"creates an internal
/// NockStack that fails with NoteData::to_noun()"*. That is false; see
/// [`jam_seeds`] for the three measurements. What IS true, and is why this arm
/// survives, is narrower: skipping the ordering also skips
/// `OwnedBasedNoun::from_noun`'s recursive copy, so this path has no depth bound
/// where the canonical one has [`MAX_SEED_NOUN_DEPTH`].
pub fn jam_seeds_manual(seeds: &Seeds) -> anyhow::Result<bytes::Bytes> {
    anyhow::ensure!(!seeds.0.is_empty(), "seeds must not be empty");
    anyhow::ensure!(
        seeds.0.len() == 1,
        "manual seeds JAM only supports single-seed (have {})",
        seeds.0.len()
    );

    let mut slab: NounSlab<NockJammer> = NounSlab::new();
    let seed_noun = seeds.0[0].to_noun(&mut slab);
    // Single-element z-set: [element null null]
    let zset_noun = T(&mut slab, &[seed_noun, D(0), D(0)]);
    slab.set_root(zset_noun);
    Ok(slab.jam())
}

/// JAM Spends by the canonical `ZMap` encoder — **any spend count.**
///
/// ⭐ x402 board row **23**. `kernel_tx_id` used to reach
/// [`jam_spends_manual`], which hand-writes a one-element treap and refuses
/// more than one spend — so the `%tx-id` kernel poke was single-input **by
/// construction**, and the multi-input transactions `records/S133` put to a
/// node had to compute their id through `RawTx::compute_id` instead.
///
/// ⚑ There is no dispatch here, unlike [`jam_seeds`], and the reason is
/// MEASURED rather than assumed. `jam_seeds` keeps a manual arm because the
/// canonical z-SET ordering copies each **item** through
/// `OwnedBasedNoun::from_noun`, which recurses on the Rust stack — hence
/// [`MAX_SEED_NOUN_DEPTH`]. A z-MAP orders on the **KEY ONLY**:
/// `ZMapEntry::encode` calls `OrderedNoun::encode(&key)` and never touches the
/// value (`nockchain-math/src/zoon/zmap.rs:140-149`). The key is a `Name` —
/// two hashes, fixed shallow depth — so the multi-megabyte proof-carrying
/// witness in the value never goes through that copy at all. ⇒ **the depth
/// hazard does not transfer to spends, and this arm needs no bound.**
///
/// ⛔ It does NOT call `Spends::to_noun`, for the same reason
/// [`jam_seeds_canonical`] avoids `Seeds::to_noun`: that impl swallows the
/// ordering's error with `.expect("spends z-map should encode")`
/// (`nockchain-types/src/tx_engine/v1/tx.rs:277-281`), so an unrepresentable
/// key would PANIC inside a transaction builder. Calling
/// `ZMap::try_from_entries` here makes it an `Err` carrying the cause.
pub fn jam_spends(spends: &Spends) -> anyhow::Result<bytes::Bytes> {
    jam_spends_canonical(spends)
}

/// JAM Spends via the canonical `ZMap` treap — the encoder `Spends` already
/// carries, reached without the `.expect()` its `NounEncode` impl performs.
///
/// ⛔⛔ **IT REFUSES TWO SPENDS OF THE SAME INPUT NOTE, AND THAT REFUSAL IS
/// LOAD-BEARING RATHER THAN TIDY.** `ZMap::try_insert` returns `Ok(added)` and
/// `ZMap::try_from_entries` **discards that flag**
/// (`nockchain-math/src/zoon/zmap.rs:266-283`), so two entries under one `Name`
/// silently collapse to one — `merge_duplicate` keeps the incoming value
/// (`zmap.rs:161-168`). A builder that handed this two spends of one note would
/// get a jam, a `%tx-id`, and a signature for a transaction **it did not
/// build**, with one spend gone and no error anywhere. Consensus would then
/// refuse it for a conservation failure that names nothing. ⇒ fail closed here,
/// where the cause is still in hand.
pub fn jam_spends_canonical(spends: &Spends) -> anyhow::Result<bytes::Bytes> {
    anyhow::ensure!(!spends.0.is_empty(), "spends must not be empty");
    refuse_duplicate_input_names(spends)?;
    let map = ZMap::try_from_entries(spends.0.clone()).map_err(|err| {
        anyhow::anyhow!("the canonical z-map encoder cannot order these spends: {err}")
    })?;
    let mut slab: NounSlab<NockJammer> = NounSlab::new();
    let noun = map.to_noun(&mut slab);
    slab.set_root(noun);
    Ok(slab.jam())
}

/// Refuse a `Spends` naming one input note twice.
///
/// ⚑ Compares the `Name`s by their encoded noun rather than by `PartialEq` on
/// the struct, so it agrees with the z-map's own notion of "the same key"
/// rather than with Rust's.
fn refuse_duplicate_input_names(spends: &Spends) -> anyhow::Result<()> {
    let mut seen: Vec<bytes::Bytes> = Vec::with_capacity(spends.0.len());
    for (i, (name, _)) in spends.0.iter().enumerate() {
        let mut slab: NounSlab<NockJammer> = NounSlab::new();
        let noun = name.to_noun(&mut slab);
        slab.set_root(noun);
        let key = slab.jam();
        if let Some(first) = seen.iter().position(|k| k == &key) {
            anyhow::bail!(
                "spends {first} and {i} name the same input note; the z-map would silently \
                 collapse them and this transaction would not be the one you built"
            );
        }
        seen.push(key);
    }
    Ok(())
}

/// JAM Spends into a noun on a plain NounSlab, bypassing the ZMap machinery.
///
/// For a single-spend z-map, the noun structure is `[[key value] 0 0]`
/// (treap node with null children).
///
/// ⛔ **NO LONGER ON ANY LIVE PATH IN THIS CRATE** (x402 board row 23):
/// `kernel_tx_id` now goes through [`jam_spends`]. It is kept and exported
/// because `vesl-agent/hull/src/tx_builder.rs:24` imports it and pins it
/// byte-identical to the canonical encoder at `:276` — which is the very
/// measurement that makes the switch above safe. `jam_spends_canonical_is_byte_identical_to_manual_for_one_spend`
/// re-states that pin HERE, where this crate's own CI can see it.
pub fn jam_spends_manual(spends: &Spends) -> anyhow::Result<bytes::Bytes> {
    anyhow::ensure!(!spends.0.is_empty(), "spends must not be empty");
    anyhow::ensure!(
        spends.0.len() == 1,
        "manual spends JAM only supports single-spend (have {})",
        spends.0.len()
    );

    let mut slab: NounSlab<NockJammer> = NounSlab::new();
    let (ref name, ref spend) = spends.0[0];
    let name_noun = name.to_noun(&mut slab);
    let spend_noun = spend.to_noun(&mut slab);
    let kv = T(&mut slab, &[name_noun, spend_noun]);
    // Single-element z-map: [kv null null]
    let zmap_noun = T(&mut slab, &[kv, D(0), D(0)]);
    slab.set_root(zmap_noun);
    Ok(slab.jam())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use nock_noun_rs::{atom_from_u64, slab_root};

/// Extract a Hash from a kernel effect of shape `[%expected_tag hash-noun]`.
///
/// Verifies the first effect's head tag matches `expected_tag` via
/// [`crate::peek::effect_head_tag`] before decoding the hash from the
/// cell's tail. Returns an error if no effects were emitted, the first
/// effect isn't a cell with an atom head, the head tag doesn't match,
/// or the tail isn't a valid `Hash` noun.
pub fn extract_hash_from_effect(effects: &[NounSlab], expected_tag: &str) -> anyhow::Result<Hash> {
    let effect_slab = effects
        .first()
        .ok_or_else(|| anyhow::anyhow!("no effects returned from %{expected_tag} poke"))?;

    match crate::peek::effect_head_tag(effect_slab) {
        Some(tag) if tag == expected_tag => {}
        Some(tag) => {
            anyhow::bail!("expected %{expected_tag} effect, got %{tag}");
        }
        None => {
            anyhow::bail!("{expected_tag} effect is not a cell with an atom head");
        }
    }

    // SAFETY-of-shape: effect_head_tag confirmed the slab is a cell.
    let root = slab_root(effect_slab);
    let space = effect_slab.noun_space();
    let cell = root
        .in_space(&space)
        .as_cell()
        .expect("effect_head_tag verified cell shape");
    let hash_noun = cell.tail().noun();
    Hash::from_noun(&hash_noun, &space)
        .map_err(|e| anyhow::anyhow!("{expected_tag} hash decode: {e}"))
}

/// Convert a byte slice (JAM'd output) to a Nock atom.
pub fn bytes_to_atom(slab: &mut NounSlab, bytes: &[u8]) -> nockvm::noun::Noun {
    if bytes.is_empty() {
        return D(0);
    }
    // SAFETY: bytes slice is caller-provided and valid for the duration
    // of this call. new_raw_bytes_ref copies into the slab allocator.
    unsafe {
        let mut indirect = IndirectAtom::new_raw_bytes_ref(slab, bytes);
        let space = slab.noun_space();
        indirect.normalize_as_atom(&space).as_noun()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use nockchain_types::tx_engine::common::Name;
    use nockchain_types::tx_engine::v1::note::{NoteData, NoteDataEntry};
    use nockchain_types::tx_engine::v1::tx::{Seed, Spend};

    use super::*;

    // -----------------------------------------------------------------------
    // ROW 23 — the canonical SPENDS encoder.
    // -----------------------------------------------------------------------

    /// Build a spend carrying one seed, under the input note `Name(a, b)`.
    fn spend_named(a: u64, b: u64, gift: u64) -> (Name, Spend) {
        use nockchain_types::tx_engine::v1::tx::{
            LockMerkleProof, MerkleProof, PkhSignature, Spend1, SpendCondition, Witness,
        };
        let sc = SpendCondition::simple_pkh(Hash::from_limbs(&[a, a, a, a, a]));
        let root = sc.hash().expect("lock root");
        let witness = Witness::new(
            LockMerkleProof::new_stub(
                sc,
                1,
                MerkleProof {
                    root: root.clone(),
                    path: vec![],
                },
            ),
            PkhSignature::new(vec![]),
            vec![],
        );
        let seeds = Seeds(vec![Seed {
            output_source: None,
            lock_root: root,
            note_data: NoteData::new(vec![]),
            gift: Nicks(gift as usize),
            parent_hash: Hash::from_limbs(&[b, b, b, b, b]),
        }]);
        let name = Name::new(
            Hash::from_limbs(&[a, a + 1, a + 2, a + 3, a + 4]),
            Hash::from_limbs(&[b, b + 1, b + 2, b + 3, b + 4]),
        );
        (
            name,
            Spend::Witness(Spend1 {
                witness,
                seeds,
                fee: Nicks(0),
            }),
        )
    }

    /// ⭐⭐ THE PIN THAT MAKES THE `kernel_tx_id` SWITCH SAFE.
    ///
    /// `kernel_tx_id` reached `jam_spends_manual` until board row 23 and now
    /// reaches [`jam_spends`]. That is only a no-op for the single-spend shapes
    /// this fleet has been posting if the two encoders agree BYTE FOR BYTE.
    ///
    /// ⚑ `vesl-agent/hull/src/tx_builder.rs:276` has a twin of this assertion,
    /// and that is exactly why this one exists: **a pin's home is what its own
    /// CI can see.** vesl-core's suite cannot run vesl-agent's.
    #[test]
    fn jam_spends_canonical_is_byte_identical_to_manual_for_one_spend() {
        let spends = Spends(vec![spend_named(1, 2, 100)]);
        let manual = jam_spends_manual(&spends).expect("manual");
        let canonical = jam_spends_canonical(&spends).expect("canonical");
        assert_eq!(
            manual.to_vec(),
            canonical.to_vec(),
            "the canonical z-map encoder must reproduce the hand-written one-element treap, or \
             switching kernel_tx_id onto it changes every single-input transaction id we post"
        );
        assert_eq!(
            jam_spends(&spends).expect("dispatch").to_vec(),
            canonical.to_vec(),
            "the dispatcher must be the canonical arm"
        );
    }

    /// The capability itself: more than one spend encodes at all.
    #[test]
    fn jam_spends_canonical_encodes_two_spends() {
        let spends = Spends(vec![spend_named(1, 2, 100), spend_named(3, 4, 200)]);
        assert!(
            jam_spends_manual(&spends).is_err(),
            "the control: the manual encoder is what refused multi-input, so this test is \
             vacuous unless it still refuses"
        );
        let jam = jam_spends(&spends).expect("two spends must encode");
        assert!(!jam.is_empty());

        // It is the SET we built, not a truncation: decode it back.
        let mut slab: NounSlab<NockJammer> = NounSlab::new();
        let root = slab.cue_into(jam).expect("the jam must cue back");
        slab.set_root(root);
        let space = slab.noun_space();
        let back = Spends::from_noun(&slab_root(&slab), &space).expect("decode");
        assert_eq!(back.0.len(), 2, "both spends must survive the round trip");
    }

    /// ⛔⛔ Two spends of ONE input note must be refused, not silently merged.
    ///
    /// `ZMap::try_from_entries` discards `try_insert`'s `added` flag, so
    /// without this guard the second entry overwrites the first and the caller
    /// signs a transaction with one spend missing — and no error anywhere.
    #[test]
    fn jam_spends_refuses_two_spends_of_the_same_input_note() {
        let (name, spend_a) = spend_named(1, 2, 100);
        let (_, spend_b) = spend_named(1, 2, 999);
        let spends = Spends(vec![(name.clone(), spend_a), (name, spend_b)]);

        let err = jam_spends(&spends).expect_err("a repeated input name must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("same input note"),
            "the refusal must name its cause, got: {msg}"
        );

        // The control: without the guard this would have collapsed silently to
        // ONE entry rather than erroring.
        let collapsed = ZMap::try_from_entries(spends.0.clone()).expect("z-map");
        assert_eq!(
            collapsed.into_entries().len(),
            1,
            "the control: the z-map really does silently collapse the pair, which is what \
             makes the guard above load-bearing rather than tidy"
        );
    }

    /// Verify `jam_seeds_manual` output matches `Seeds::to_noun` -> JAM.
    #[test]
    fn jam_seeds_manual_matches_seeds_to_noun() {
        // Build a Seed with minimal NoteData
        let note_data = NoteData::new(vec![NoteDataEntry::new(
            "test-key".to_string(),
            nockchain_math::owned_based_noun::OwnedBasedNoun::try_atom(42).unwrap(),
        )]);

        let seed = Seed {
            output_source: None,
            lock_root: Hash::from_limbs(&[1, 2, 3, 4, 5]),
            note_data,
            gift: Nicks(62_536),
            parent_hash: Hash::from_limbs(&[10, 20, 30, 40, 50]),
        };
        let seeds = Seeds(vec![seed]);

        // Path 1: manual JAM (what we use for sig-hash)
        let manual_jam = jam_seeds_manual(&seeds).expect("manual JAM should succeed");

        // Path 2: Seeds::to_noun -> JAM (what the chain uses)
        let standard_jam = {
            let mut slab: NounSlab<NockJammer> = NounSlab::new();
            let noun = seeds.to_noun(&mut slab);
            slab.set_root(noun);
            slab.jam()
        };

        assert_eq!(
            manual_jam.to_vec(),
            standard_jam.to_vec(),
            "jam_seeds_manual must produce identical bytes to Seeds::to_noun -> JAM"
        );
    }

    // -----------------------------------------------------------------------
    // ROW 1 — the multi-seed-with-note-data encoder.
    //
    // ⛔ THE STATED CAUSE OF THE REFUSAL IS FALSIFIED. Both doc-comments blamed
    // "a scratch NockStack that cannot absorb NoteData::to_noun". The scratch
    // stack is NOCK_STACK_SIZE_TINY = 2 GB (nockvm/src/mem.rs:33), and the test
    // above already runs the canonical encoder over a seed carrying NON-EMPTY
    // note-data. The real gate is a FIELD-ELEMENT check:
    //
    //   Seeds::to_noun -> ZSet::try_from_items (nockchain-types v1/tx.rs:317)
    //                  -> OrderedNoun::encode  (nockchain-math zoon/common.rs:156)
    //                  -> OwnedBasedNoun::from_noun (owned_based_noun.rs:54)
    //
    // which rejects any atom wider than u64 (`AtomTooLarge`) or >= the
    // Goldilocks prime (`AtomNotBased`). Nothing to do with buffer size.
    // -----------------------------------------------------------------------

    /// The two note-data entries the platform's escrow actually carries, built
    /// the way production builds them.
    ///
    /// ⚑ Reproduced here rather than imported: `vesl-agent-protocol` sits ABOVE
    /// `vesl-core` in the stack, so this crate cannot depend on it. The keys are
    /// `KEY_INTENT_VERSION` / `KEY_INPUT_COM` and the value shapes are
    /// `u64_entry` / `bytes_entry`
    /// (`vesl-agent/crates/vesl-agent-protocol/src/intent_note_data.rs:63,67,607-629`),
    /// which chunk a payload into 7-byte little-endian atoms so every leaf is
    /// below 2^56 and therefore a field element.
    fn escrow_note_data(input_com_hex: &str) -> NoteData {
        NoteData::new(vec![
            NoteDataEntry::from_raw_blob("vint-v".to_string(), jam_u64(2))
                .expect("the version entry is a based noun"),
            NoteDataEntry::from_raw_blob(
                "vint-ic".to_string(),
                jam_len_chunks(input_com_hex.as_bytes()),
            )
            .expect("the input_com entry is a based noun"),
        ])
    }

    /// `u64_entry`'s value shape: a single atom.
    fn jam_u64(v: u64) -> bytes::Bytes {
        let mut slab: NounSlab<NockJammer> = NounSlab::new();
        let noun = atom_from_u64(&mut slab, v);
        slab.set_root(noun);
        slab.jam()
    }

    /// `bytes_entry`'s value shape: `[len chunk-list]`, 7-byte LE chunks.
    fn jam_len_chunks(bytes: &[u8]) -> bytes::Bytes {
        let mut slab: NounSlab<NockJammer> = NounSlab::new();
        let len = atom_from_u64(&mut slab, bytes.len() as u64);
        let mut list = D(0);
        for chunk in bytes.chunks(7).rev() {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            let leaf = atom_from_u64(&mut slab, u64::from_le_bytes(buf));
            list = T(&mut slab, &[leaf, list]);
        }
        let noun = T(&mut slab, &[len, list]);
        slab.set_root(noun);
        slab.jam()
    }

    /// An 80-character Tip5 hex `input_com`, the real field width.
    const IC_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn seed_with(lock: u64, parent: u64, gift: usize, note_data: NoteData) -> Seed {
        Seed {
            output_source: None,
            lock_root: Hash::from_limbs(&[lock, lock + 1, lock + 2, lock + 3, lock + 4]),
            note_data,
            gift: Nicks(gift),
            parent_hash: Hash::from_limbs(&[parent, parent, parent, parent, parent]),
        }
    }

    /// Two seeds, one carrying the real escrow note-data — `XD-5`'s shape in
    /// miniature.
    fn multi_seed_with_note_data() -> Seeds {
        Seeds(vec![
            seed_with(1, 100, 500, escrow_note_data(IC_HEX)),
            seed_with(2, 100, 490, NoteData::new(Vec::new())),
        ])
    }

    /// ⭐⭐ `F2` — THE REFUSAL IS GONE, AND THE HISTORY IS THE POINT.
    ///
    /// Written first as `f2_..._refusal_reproduces`, asserting
    /// `jam_seeds(...).is_err()` with the message *"multi-seed with note-data is
    /// unsupported"*. · MEASURED 2026-08-30: it passed, pinning the starting
    /// state; then the fix landed and it went red, which is what a falsifier
    /// that has done its job looks like. It is kept, inverted, as the standing
    /// guard that the combination stays encodable.
    #[test]
    fn f2_multi_seed_with_note_data_encodes() {
        let jammed = jam_seeds(&multi_seed_with_note_data())
            .expect("several outputs where one carries note-data must encode");
        assert!(!jammed.is_empty(), "the encoding must be non-empty");
        assert_eq!(
            jammed.to_vec(),
            chain_canonical_jam(&multi_seed_with_note_data()).to_vec(),
            "and it must be the chain's own canonical encoding"
        );
    }

    /// ⭐⭐ `F2` — WHAT THE CANONICAL ENCODER ACTUALLY DOES when handed the
    /// combination both guards forbid.
    ///
    /// Both guards are bypassed on purpose: `jam_seeds`'s dispatch AND
    /// `jam_seeds_canonical`'s own empty-note-data `ensure!`. `Seeds::to_noun`
    /// swallows the encoder's error with `.expect("seed z-set should encode")`
    /// (`nockchain-types/src/tx_engine/v1/tx.rs:319`), so this calls
    /// `ZSet::try_from_items` itself — a panic would be no verdict at all.
    #[test]
    fn f2_the_canonical_encoder_on_multi_seed_with_note_data() {
        let seeds = multi_seed_with_note_data();
        let set = ZSet::try_from_items(seeds.0.clone())
            .expect("F2: the canonical z-set encoder must order seeds carrying note-data");

        let mut slab: NounSlab<NockJammer> = NounSlab::new();
        let noun = set.to_noun(&mut slab);
        slab.set_root(noun);
        let jammed = slab.jam();
        assert!(!jammed.is_empty(), "the jammed z-set must be non-empty");

        // Inverse: cue -> Seeds::from_noun, and the note-data must survive.
        let mut decode: NounSlab = NounSlab::new();
        let cued = decode.cue_into(jammed).expect("cue the multi-seed jam");
        let space = decode.noun_space();
        let decoded = Seeds::from_noun(&cued, &space).expect("decode multi-seed Seeds");
        assert_eq!(decoded.0.len(), 2, "both seeds survive");
        let carried: Vec<usize> = decoded.0.iter().map(|s| s.note_data.0.len()).collect();
        assert!(
            carried.contains(&2) && carried.contains(&0),
            "one seed carries the two escrow entries and one carries none, got {carried:?}"
        );
    }

    /// ⛔⛔ THE RECURSION WALL IS REAL AND IT IS ALREADY MEASURED IN THIS FLEET.
    ///
    /// `OwnedBasedNoun::from_noun` (`owned_based_noun.rs:73-76`) recurses on the
    /// RUST stack, and `vesl-agent-protocol/src/hax_carry.rs:186-190` records:
    /// *"· MEASURED, `OwnedBasedNoun::from_noun` aborts a default 2 MiB thread
    /// stack at depth 2.072 (debug)"*. Consensus caps note-data at **2048
    /// leaves** (`nockchain/hoon/common/tx-engine-1.hoon:495-497`,
    /// enforced `:1236-1237`) — so a consensus-legal note-data sits within ~1%
    /// of an UNCATCHABLE process abort.
    ///
    /// A stack overflow is not an `Err`; it is a SIGSEGV. This test records
    /// where the real escrow note-data actually sits, so the guard's bound is a
    /// measurement rather than a guess.
    #[test]
    fn the_escrow_note_datas_depth_is_far_below_the_recursion_wall() {
        let mut slab: NounSlab<NockJammer> = NounSlab::new();
        let seed = seed_with(1, 100, 500, escrow_note_data(IC_HEX));
        let noun = seed.to_noun(&mut slab);
        slab.set_root(noun);
        let space = slab.noun_space();
        let depth = noun_depth(slab_root(&slab), &space);
        assert!(
            depth < 64,
            "the real escrow seed's noun depth is {depth}; the encoder's wall is ~2072"
        );
        println!("MEASURED: the real escrow seed's noun depth = {depth}");
    }

    // -----------------------------------------------------------------------
    // The oracles. ⛔ Each was written to FAIL before the encoder fix, and each
    // has a removal control below.
    // -----------------------------------------------------------------------

    /// splitmix64 — a deterministic stand-in for `rand`, which `vesl-core` does
    /// not depend on. Same shape as `lock_check.rs`'s randomised pin.
    fn mix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `Seeds::to_noun` -> JAM: the chain crate's own canonical encoding, and
    /// the ONLY thing this module's output may be compared against.
    fn chain_canonical_jam(seeds: &Seeds) -> bytes::Bytes {
        let mut slab: NounSlab<NockJammer> = NounSlab::new();
        let noun = seeds.to_noun(&mut slab);
        slab.set_root(noun);
        slab.jam()
    }

    /// ⭐ `F-bytes` — THE BYTE ORACLE.
    ///
    /// Whatever `jam_seeds` produces for a multi-seed-with-note-data set must be
    /// byte-identical to the CHAIN's own `Seeds::to_noun` encoding. Asserted
    /// against `nockchain-types`, never against this module's own output: a
    /// wrong-but-stable encoder is the failure that stays silent until real
    /// money moves. It also forbids the tempting fix of hand-writing a treap —
    /// `XE-94` measured that a naive hand-write disagrees with the chain on the
    /// first random pair.
    ///
    /// ⚑ That encoder is itself pinned against HOON by frozen base58 vectors
    /// (`nockchain-types/src/tx_engine/v1/tx.rs:1882-1984`, `XE-67`), which is
    /// what makes this a cross-implementation oracle rather than a tautology.
    #[test]
    fn f_bytes_multi_seed_with_note_data_matches_the_chains_canonical_encoding() {
        let mut state = 0x5EED_0000_0000_00A1u64;
        for round in 0..16u32 {
            let a = mix(&mut state) >> 2;
            let b = mix(&mut state) >> 2;
            let c = mix(&mut state) >> 2;
            let seeds = Seeds(vec![
                seed_with(a, c, 500, escrow_note_data(IC_HEX)),
                seed_with(b, c, 490, NoteData::new(Vec::new())),
            ]);
            let ours = jam_seeds(&seeds)
                .unwrap_or_else(|e| panic!("round {round}: jam_seeds refused: {e}"));
            assert_eq!(
                ours.to_vec(),
                chain_canonical_jam(&seeds).to_vec(),
                "round {round}: jam_seeds disagrees with the chain's Seeds::to_noun"
            );
        }
    }

    /// ⭐ `F-order` — THE Z-SET IS A TREAP, SO ORDER MUST NOT MOVE THE BYTES.
    ///
    /// Its shape comes from hashing the members and comparing them, not from the
    /// order they were inserted. If that were false the sig-hash would depend on
    /// authoring order — and Hoon's `sig-hashable:seeds` walks the treap
    /// STRUCTURALLY (`nockchain/hoon/common/tx-engine-1.hoon:749-755`), so a
    /// shape disagreement is a signature over a different message.
    ///
    /// ⛔ Randomised, and over THREE seeds so there is a real tree rather than a
    /// single swap: `XE-94` is the measurement that says one fixed case is not
    /// enough.
    #[test]
    fn f_order_the_seed_sets_bytes_do_not_depend_on_insertion_order() {
        let mut state = 0x5EED_0000_0000_00B2u64;
        for round in 0..16u32 {
            let (a, b, c) = (
                mix(&mut state) >> 2,
                mix(&mut state) >> 2,
                mix(&mut state) >> 2,
            );
            let parent = mix(&mut state) >> 2;
            let mk = |lock: u64, gift: usize, data: bool| {
                seed_with(
                    lock,
                    parent,
                    gift,
                    if data {
                        escrow_note_data(IC_HEX)
                    } else {
                        NoteData::new(Vec::new())
                    },
                )
            };
            let (s0, s1, s2) = (mk(a, 500, true), mk(b, 490, false), mk(c, 10, false));

            let orders: [Vec<Seed>; 6] = [
                vec![s0.clone(), s1.clone(), s2.clone()],
                vec![s0.clone(), s2.clone(), s1.clone()],
                vec![s1.clone(), s0.clone(), s2.clone()],
                vec![s1.clone(), s2.clone(), s0.clone()],
                vec![s2.clone(), s0.clone(), s1.clone()],
                vec![s2.clone(), s1.clone(), s0.clone()],
            ];
            let first = jam_seeds(&Seeds(orders[0].clone()))
                .unwrap_or_else(|e| panic!("round {round}: jam_seeds refused: {e}"))
                .to_vec();
            for (i, order) in orders.iter().enumerate().skip(1) {
                let got = jam_seeds(&Seeds(order.clone()))
                    .unwrap_or_else(|e| panic!("round {round} perm {i}: jam_seeds refused: {e}"))
                    .to_vec();
                assert_eq!(
                    got, first,
                    "round {round}: permutation {i} moved the seed z-set's bytes"
                );
            }
        }
    }

    /// ⭐ `F-key` — AN UNREPRESENTABLE NOTE-DATA KEY IS A NAMED REFUSAL, NEVER A
    /// PANIC.
    ///
    /// `NoteData::to_noun` builds each key with `make_tas` and carries
    /// `// TODO error if key is not a belt`
    /// (`nockchain-types/src/tx_engine/v1/note.rs:359-360`) — nothing enforces
    /// it. A key of nine bytes or more is an atom wider than `u64`, so the
    /// ordering rejects it; `Seeds::to_noun` would turn that into
    /// `.expect("seed z-set should encode")` — a PANIC, from inside a
    /// transaction builder. `jam_seeds_canonical` calls `try_from_items` itself
    /// precisely so this is an `Err` with a cause in it.
    #[test]
    fn f_key_a_note_data_key_that_is_not_a_field_element_is_refused_by_name() {
        let over_wide = NoteData::new(vec![
            NoteDataEntry::from_raw_blob("vint-a-key-that-is-far-too-long".to_string(), jam_u64(2))
                .expect("the VALUE is a based noun; the KEY is what this test is about"),
        ]);
        let seeds = Seeds(vec![
            seed_with(1, 100, 500, over_wide),
            seed_with(2, 100, 490, NoteData::new(Vec::new())),
        ]);
        let err = jam_seeds(&seeds).expect_err("an unrepresentable key must be refused");
        let msg = err.to_string();
        // ⛔⛔ THIS ASSERTION HAD TO BE TIGHTENED, AND THAT IS THE POINT. Written
        // as `contains("z-set")` it PASSED before the fix — satisfied by the old
        // blanket bail!, which says "the canonical z-set encoder cannot order
        // seeds carrying note-data" and never reaches a key at all. A falsifier
        // that a generic refusal can satisfy names nothing.
        assert!(
            !msg.contains("multi-seed with note-data is unsupported"),
            "the blanket refusal is not a verdict about the KEY, got: {msg}"
        );
        assert!(
            msg.contains("exceeded u64 range") || msg.contains("not based"),
            "the refusal must carry the ordering's own cause, got: {msg}"
        );
    }

    /// ⛔⛔ `F-depth` — THE ENCODER REFUSES A NOTE-DATA DEEP ENOUGH TO ABORT THE
    /// PROCESS, RATHER THAN ABORTING.
    ///
    /// `OwnedBasedNoun::from_noun` recurses on the Rust stack
    /// (`nockchain-math/src/owned_based_noun.rs:73-76`) and
    /// `vesl-agent-protocol/src/hax_carry.rs:186-190` records: *"· MEASURED,
    /// `OwnedBasedNoun::from_noun` aborts a default 2 MiB thread stack at depth
    /// **2.072** (debug)"*. Consensus allows note-data up to **2048 leaves**
    /// (`nockchain/hoon/common/tx-engine-1.hoon:495-497`, enforced `:1236-1237`)
    /// ⇒ a consensus-LEGAL note-data sits within ~1% of an uncatchable abort.
    ///
    /// A stack overflow is a SIGSEGV, not an `Err`. So the encoder measures the
    /// depth iteratively first and refuses above `MAX_SEED_NOUN_DEPTH`.
    /// ⚑ The real escrow seed measures **19**, so this cap is ~50x anything the
    /// platform builds; the test below proves it does not cut into working
    /// territory.
    #[test]
    fn f_depth_a_deep_but_safe_note_data_still_encodes() {
        // 512 leaves: depth ~520, an order of magnitude past anything real and
        // still far under both the cap and the wall.
        let payload = vec![0xA5u8; 512 * 7];
        let deep = NoteData::new(vec![
            NoteDataEntry::from_raw_blob("vint-ic".to_string(), jam_len_chunks(&payload))
                .expect("a long chunk list is still all-based"),
        ]);
        let seeds = Seeds(vec![
            seed_with(1, 100, 500, deep),
            seed_with(2, 100, 490, NoteData::new(Vec::new())),
        ]);
        let ours = jam_seeds(&seeds).expect("a 512-leaf note-data must still encode");
        assert_eq!(
            ours.to_vec(),
            chain_canonical_jam(&seeds).to_vec(),
            "the deep case must also match the chain's canonical encoding"
        );
    }

    /// ⛔ `F-depth`, the refusing half: past the cap it is an `Err` that names
    /// the bound, not a crash.
    #[test]
    fn f_depth_past_the_cap_is_a_named_refusal() {
        let payload = vec![0x5Au8; (MAX_SEED_NOUN_DEPTH + 64) * 7];
        let too_deep = NoteData::new(vec![
            NoteDataEntry::from_raw_blob("vint-ic".to_string(), jam_len_chunks(&payload))
                .expect("still all-based, just deep"),
        ]);
        let seeds = Seeds(vec![
            seed_with(1, 100, 500, too_deep),
            seed_with(2, 100, 490, NoteData::new(Vec::new())),
        ]);
        let err = jam_seeds(&seeds).expect_err("past the cap must be refused");
        assert!(
            err.to_string().contains("depth"),
            "the refusal must name the depth bound, got: {err}"
        );
    }
}
