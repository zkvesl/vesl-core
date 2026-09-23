//! ⭐⭐ THE HOON/RUST PARITY CORPUS — the shapes, and only the shapes.
//!
//! ⚑ *In plain terms: the blockchain runs its own program to work out the
//! number a buyer signs when it pays, and the identity of the payment. We keep
//! a pure-Rust copy of both calculations — that copy is what lets a wallet pay
//! without booting a 15-second kernel. Nothing checked that the two still
//! agree. This module holds the payments we compare them on.*
//!
//! `nockchain-types` states the problem itself and offers no mechanism for it:
//! *"Keep this direct hashing path in sync with Hoon"*
//! (`nockchain/crates/nockchain-types/src/tx_engine/v1/tx.rs:102-105`). The
//! failure is silent twice over — a node **acks an invalid transaction and
//! discards it** (`vesl-core/src/settle.rs:458-461`), and no suite in this
//! fleet boots a kernel. Design: `zkML/docs/plans/x402/records/S117` `§12`.
//!
//! ⛔⛔ **THE ONE RULE THIS MODULE MUST NEVER BREAK: IT RETURNS INPUTS. IT
//! COMPUTES NO DIGEST.** Both tiers call it — tier 1 (`tests/hoon_rust_parity.rs`,
//! pure Rust, every `cargo test`) and tier 2 (`vesl-labs/services/chain/
//! examples/regen_parity_fixture.rs`, which boots the kernel). The moment a
//! digest is computed *here*, both sides read the same number and the frozen
//! answer sheet becomes a mirror of the thing it is supposed to check.
//!
//! ⛔ **And nothing here may be derived from configuration.** Fees, heights and
//! the bythos phase are literal constants. A fee-formula change must not move
//! a parity digest — that would red this pin for a reason that is not parity,
//! which trains people to regenerate the sheet instead of reading it.

use anyhow::Result;
use nockchain_math::belt::Belt;
use nockchain_math::owned_based_noun::OwnedBasedNoun;
use nockchain_types::tx_engine::common::{Hash, Name, Nicks};
use nockchain_types::tx_engine::v1::note::{NoteData, NoteDataEntry, NoteDataValue};
use nockchain_types::tx_engine::v1::tx::{Seed, Seeds, Spend, Spend1, Spends};

/// A signing key, spelled as `vesl-core` spells it.
pub type Signer = [Belt; 8];

/// ⛔ Literal, never derived — see the module header.
pub const HEIGHT: u64 = 600;
/// ⛔ Literal, never derived.
pub const BYTHOS_PHASE: u64 = 0;

/// One payment we compare the two implementations on.
///
/// ⚑ It carries **inputs only**. The witness cannot be built until a sig-hash
/// exists, and *which* sig-hash is exactly what is under test — so assembly is
/// a separate step ([`assemble`]) that takes the digest as an argument.
#[derive(Debug, Clone)]
pub struct Shape {
    /// Stable identity. This is the key in the frozen fixture, so it may never
    /// be renamed without regenerating.
    pub name: &'static str,
    /// What the payment pays out.
    pub seeds: Seeds,
    /// ⛔ A literal.
    pub fee: u64,
    /// The key that signs the input note.
    pub signer: Signer,
    /// Whether the input note is a coinbase, which changes its spend condition.
    pub is_coinbase: bool,
    /// The input note's `last` name half — free, and fixed so the id is stable.
    pub input_last: Hash,
    /// One line saying what this shape exists to catch.
    pub why: &'static str,
}

/// A fixed signing key. Not a secret: these payments are never submitted.
fn signer(seed: u64) -> Signer {
    let mut k = [Belt(0); 8];
    k[0] = Belt(seed);
    k
}

/// `[n n n n n]`, the spelling the S123 measurement used — kept identical so
/// its kernel-authored digests reproduce here byte for byte.
fn h(n: u64) -> Hash {
    Hash::from_limbs(&[n, n, n, n, n])
}

/// A seed with empty note-data, exactly as `examples/support/devnet.rs:248-256`
/// builds one.
pub fn seed_to(lock_root: Hash, gift: u64, parent_hash: Hash) -> Seed {
    Seed {
        output_source: None,
        lock_root,
        note_data: NoteData::new(Vec::new()),
        gift: Nicks(gift as usize),
        parent_hash,
    }
}

/// The input note's first name, derived from the signer the way
/// [`vesl_core::settle::build_witness`] will re-derive it. Kept here so the
/// corpus never has to guess a name that helper would refuse.
pub fn input_first_name(signer: &Signer, is_coinbase: bool) -> Result<Hash> {
    use nockchain_types::tx_engine::v1::tx::{Lock, SpendCondition};
    let pubkey = vesl_core::signing::derive_pubkey(signer)
        .map_err(|e| anyhow::anyhow!("pubkey derivation failed: {e}"))?;
    let pkh = vesl_core::signing::pubkey_hash(&pubkey)
        .map_err(|e| anyhow::anyhow!("pubkey hash failed: {e}"))?;
    let condition = if is_coinbase {
        SpendCondition::coinbase_pkh(pkh, 1)
    } else {
        SpendCondition::simple_pkh(pkh)
    };
    vesl_core::lock::first_name_for_lock(&Lock::SpendCondition(condition))
}

/// ⭐ Assemble the full transaction for a shape, **around a sig-hash handed in**.
///
/// ⛔⛔ **THE ARGUMENT IS LOAD-BEARING AND SOMEONE WILL TRY TO REMOVE IT.** The
/// witness carries a signature over the sig-hash, and the witness is folded
/// into the transaction id (`HashHashable for Spend1`,
/// `nockchain-types/.../v1/tx.rs:1364-1373`). If each tier computed its own
/// sig-hash and then assembled, the two tiers would build **different
/// witnesses** the instant the two implementations disagreed — which is the
/// very event under test — and the transaction-id comparison would fail for a
/// downstream reason, telling you nothing about the transaction id itself.
///
/// ⇒ Tier 1 assembles from the **fixture's recorded** sig-hash, so the sig-hash
/// leg and the transaction-id leg fail independently.
pub fn assemble(shape: &Shape, sig_hash: &Hash) -> Result<Spends> {
    let first = input_first_name(&shape.signer, shape.is_coinbase)?;
    let witness =
        vesl_core::settle::build_witness(&shape.signer, sig_hash, shape.is_coinbase, 1, &first)?;
    let spend = Spend1 {
        witness,
        seeds: shape.seeds.clone(),
        fee: Nicks(shape.fee as usize),
    };
    Ok(Spends(vec![(
        Name::new(first, shape.input_last.clone()),
        Spend::Witness(spend),
    )]))
}

/// The spend a sig-hash is taken over. The witness plays no part
/// (`SigHashable for Spend1` reads `seeds` and `fee` only,
/// `nockchain-types/.../v1/signatures.rs:45-54`), so this needs no digest and
/// breaks no rule in the module header.
pub fn sig_hash_subject(shape: &Shape) -> Result<Spend1> {
    let first = input_first_name(&shape.signer, shape.is_coinbase)?;
    // A placeholder digest: it reaches only the witness, which the sig-hash
    // does not read. Never let this value escape into `assemble`.
    let witness =
        vesl_core::settle::build_witness(&shape.signer, &h(1), shape.is_coinbase, 1, &first)?;
    Ok(Spend1 {
        witness,
        seeds: shape.seeds.clone(),
        fee: Nicks(shape.fee as usize),
    })
}

/// ⭐ `XD-5`'s three-output capture, through the SHIPPED builder.
///
/// ⚑ These exact literals are the ones the S123 chain run measured a live
/// kernel on, so the kernel's own answers reproduce here offline — see
/// `tests/step0_s123.rs`. Conservation holds by construction:
/// 94.500 + 5.500 + 899.750 + 250 = 1.000.000.
///
/// ⛔ [`vesl_core::settle::build_capture_seeds`] pins `output-source` itself
/// (`settle.rs:319`), so the shipped path can only ever hand back the PINNED
/// value. The unpinned twin is therefore derived by clearing the field — and
/// that derivation is not taken on trust: [`shapes`] asserts that pinning it
/// again reproduces the builder's own output, byte for byte.
fn capture_seeds(out1_note_data: NoteData) -> Result<Seeds> {
    use vesl_core::settle::CaptureOutput;
    let parent = h(9);
    let outputs = vec![
        CaptureOutput {
            lock_root: h(1),
            note_data: out1_note_data,
            amount: 94_500,
        },
        CaptureOutput {
            lock_root: h(2),
            note_data: NoteData::new(Vec::new()),
            amount: 5_500,
        },
        CaptureOutput {
            lock_root: h(3),
            note_data: NoteData::new(Vec::new()),
            amount: 899_750,
        },
    ];
    vesl_core::settle::build_capture_seeds(&outputs, &parent, 1_000_000, 250)
}

/// An OPAQUE note-data entry — the category our own escrow posts.
///
/// ⛔⛔ **`records/S117` `§12.5` CALLS OUR ESCROW NOTE-DATA "TYPED" AND IT IS
/// NOT.** Upstream's TODO (`nockchain-types/.../v1/tx.rs:102-105`) names
/// *"typed note-data (`%lock`, `%bridge`, `%bridge-w`)"*, and those are the
/// three non-`Noun` variants of `NoteDataValue` (`.../v1/note.rs:117-123`),
/// whose keys are the literals `"lock"`, `"bridge"`, `"bridge-w"`
/// (`:156-158`). Our escrow's keys are `"vint-v"`/`"vint-ic"`, which
/// `decode_for_key` (`:287-292`) sends down its DEFAULT branch to
/// `NoteDataValue::Noun` — opaque, the category upstream's fixture already
/// covers. So the gap that justified this corpus was the wrong gap; the real
/// one is closed by [`typed_lock_entry`] below.
///
/// ⚑ **What this shape does and does not stand in for.** The digest path for
/// an opaque entry is fixed by its key and its noun — it does not vary with
/// the payload — so this exercises exactly the encoding our escrow uses. What
/// it does NOT pin is the specific bytes `intent_note_entries_for_input_com`
/// emits; that encoder lives in `vesl-agent-protocol`, ABOVE `vesl-core`, and
/// is a data question rather than a parity one. Named, not smuggled.
fn opaque_entry(key: &str, payload: u64) -> NoteDataEntry {
    NoteDataEntry {
        key: key.to_string(),
        value: NoteDataValue::Noun(OwnedBasedNoun::Atom(Belt(payload))),
    }
}

/// ⭐ A GENUINELY TYPED note-data entry — the gap upstream's own TODO names.
///
/// `NoteDataEntry::lock` (`.../v1/note.rs:175-181`) takes a `Lock`, and
/// `vesl-core` builds `Lock`s — so the one gap upstream actually names is
/// closable here with nothing outside this workspace. Its noun goes down
/// `typed_payload_noun` (`note.rs:233-…`) rather than the raw branch, so it is
/// a different encoding, not a differently-shaped payload.
fn typed_lock_entry() -> Result<NoteDataEntry> {
    Ok(NoteDataEntry::lock(demo_hold_lock()?))
}

/// The buyer's four-branch hold, from the shipped builder, on fixed operands.
fn demo_hold_lock() -> Result<nockchain_types::tx_engine::v1::tx::Lock> {
    vesl_core::lock::hold_lock(
        pkh_of(&signer(11))?,
        pkh_of(&signer(12))?,
        pkh_of(&signer(23))?,
        h(41),
        h(42),
        576,
        h(43),
    )
}

/// The buyer's deposit note, from the shipped builder, on the same operands.
fn demo_deposit_lock() -> Result<nockchain_types::tx_engine::v1::tx::Lock> {
    vesl_core::lock::deposit_lock(
        pkh_of(&signer(11))?,
        pkh_of(&signer(12))?,
        pkh_of(&signer(23))?,
        h(41),
        h(43),
    )
}

fn pkh_of(k: &Signer) -> Result<Hash> {
    let pk = vesl_core::signing::derive_pubkey(k)
        .map_err(|e| anyhow::anyhow!("pubkey derivation failed: {e}"))?;
    vesl_core::signing::pubkey_hash(&pk).map_err(|e| anyhow::anyhow!("pubkey hash failed: {e}"))
}

/// Strip the pin, yielding the pre-row-19 value of the same payment.
fn unpin(seeds: &Seeds) -> Seeds {
    Seeds(
        seeds
            .0
            .iter()
            .map(|s| {
                let mut s = s.clone();
                s.output_source = None;
                s
            })
            .collect(),
    )
}

/// ⭐⭐ THE CORPUS.
///
/// ⛔ Every addition here needs a matching row in the frozen fixture AND a
/// matching name in `DECLARED` (`tests/hoon_rust_parity.rs`). All three are
/// asserted equal, in both directions, so a shape cannot ship uncovered.
pub fn shapes() -> Result<Vec<Shape>> {
    let mut out = Vec::new();

    // ── 1 + 2 · the pinned/unpinned pair ────────────────────────────────────
    // The sharpest control this corpus has: `sig-hashable:seed` covers
    // `output-source` and the seed's own hash does not, so the two digests
    // move for DIFFERENT reasons across this one pair.
    let pinned = capture_seeds(NoteData::new(Vec::new()))?;
    let bare = unpin(&pinned);

    // ⛔ THE DERIVATION IS A CHECKED CLAIM, NOT A COMMENT. Re-pinning the
    // stripped seeds must reproduce the shipped builder's own output; if
    // pinning ever became additive or order-dependent, this fires here rather
    // than leaving the control comparing two objects no builder emits.
    {
        let mut again = bare.clone();
        vesl_core::settle::pin_output_source(&mut again)?;
        anyhow::ensure!(
            again == pinned,
            "the unpinned corpus row is not the shipped builder's pre-image: re-pinning it \
             does not reproduce `build_capture_seeds`. The pinned/unpinned control would be \
             comparing two shapes no builder emits."
        );
    }

    out.push(Shape {
        name: "capture-3out-unpinned",
        seeds: bare,
        fee: 250,
        signer: signer(11),
        is_coinbase: true,
        input_last: h(5),
        why: "the pre-row-19 value: what every seed looked like before we pinned output-source",
    });
    out.push(Shape {
        name: "capture-3out-pinned",
        seeds: pinned,
        fee: 250,
        signer: signer(11),
        is_coinbase: true,
        input_last: h(5),
        why: "today's shipped capture, straight out of build_capture_seeds",
    });

    // ── 3 · opaque note-data, our escrow's own category ─────────────────────
    out.push(Shape {
        name: "capture-3out-opaque-notedata",
        seeds: capture_seeds(NoteData::new(vec![
            opaque_entry("vint-v", 2),
            opaque_entry("vint-ic", 0xdead_beef),
        ]))?,
        fee: 250,
        signer: signer(11),
        is_coinbase: true,
        input_last: h(5),
        why: "the escrow output carries note-data: the digest must see it (S117's positive control)",
    });

    // ── 4 · GENUINELY typed note-data — upstream's named gap ────────────────
    out.push(Shape {
        name: "capture-3out-typed-lock-notedata",
        seeds: capture_seeds(NoteData::new(vec![typed_lock_entry()?]))?,
        fee: 250,
        signer: signer(11),
        is_coinbase: true,
        input_last: h(5),
        why: "a %lock-typed entry — the coverage gap nockchain-types' own TODO names",
    });

    // ── 5 · ONE seed WITH note-data — the OTHER encoder ─────────────────────
    // ⛔⛔ `jam_seeds` DISPATCHES (`vesl-core/src/tx_builder.rs:158-163`): one
    // seed carrying note-data goes through `jam_seeds_manual`, everything else
    // through `jam_seeds_canonical`. A corpus of three-seed shapes alone
    // exercises ONE of the two encoders the kernel is fed by, and the escrow
    // post uses the other. This row is the only thing covering it.
    out.push(Shape {
        name: "single-seed-notedata-manual-jam",
        seeds: {
            let mut s = Seeds(vec![Seed {
                output_source: None,
                lock_root: h(7),
                note_data: NoteData::new(vec![opaque_entry("vint-ic", 7)]),
                gift: Nicks(999_750),
                parent_hash: h(9),
            }]);
            vesl_core::settle::pin_output_source(&mut s)?;
            s
        },
        fee: 250,
        signer: signer(11),
        is_coinbase: true,
        input_last: h(5),
        why: "forces jam_seeds_manual, the encoder the three-seed shapes never reach",
    });

    // ── 6 · the buyer's posting spend: hold + deposit + change ──────────────
    // ✅ **THE RESIDUAL HERE IS CLOSED (2026-09-04), AND THE FIX WAS A NAME.**
    // This comment read: *"there is NO shipped builder for these seeds … which
    // `vesl-core` cannot call without a dependency cycle"*, and the block below
    // mirrored the two-step by hand — the `XD-7` one-home defect `records/S124`
    // `§5` filed. Both halves were wrong about the cause. The builder existed,
    // in this very crate's dependency, as `build_capture_seeds`; only its name
    // claimed it was a capture's, while the close-out's refund and both void
    // paths already called it. It is now also `build_output_seeds`, and the
    // buyer's real posting (`vesl-x402/.../wallet-client/src/lib.rs`) calls it
    // too. ⇒ this corpus entry no longer mirrors production; it IS production's
    // builder, on fixed operands.
    //
    // ⛔ The dependency never ran the way that sentence claimed: `vesl-x402`
    // depends on `vesl-core`, so nothing here ever had to reach the other way.
    out.push(Shape {
        name: "hold-post-3seed-pinned",
        seeds: {
            let parent = h(9);
            vesl_core::settle::build_output_seeds(
                &[
                    vesl_core::settle::OutputLine {
                        lock_root: vesl_core::lock::lock_root(&demo_hold_lock()?)?,
                        note_data: NoteData::new(Vec::new()),
                        amount: 900_000,
                    },
                    vesl_core::settle::OutputLine {
                        lock_root: vesl_core::lock::lock_root(&demo_deposit_lock()?)?,
                        note_data: NoteData::new(Vec::new()),
                        amount: 60_000,
                    },
                    vesl_core::settle::OutputLine {
                        lock_root: h(8),
                        note_data: NoteData::new(Vec::new()),
                        amount: 39_750,
                    },
                ],
                &parent,
                1_000_000,
                250,
            )?
        },
        fee: 250,
        signer: signer(11),
        is_coinbase: true,
        input_last: h(5),
        why: "what a buyer's wallet posts: the hold, the deposit beside it, and the change",
    });

    Ok(out)
}
