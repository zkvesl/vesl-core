//! ⭐⭐ TIER 1 — THE FROZEN ORACLE. No kernel, no node, every `cargo test`.
//!
//! ⚑ *In plain terms: the blockchain's own program and our Rust copy of it must
//! work out the same number from the same payment. This is the checked-in
//! answer sheet the blockchain produced, and this test redoes the sums in Rust
//! and compares. If they ever stop matching, a buyer would sign a number the
//! chain throws away without saying why — a node acks the invalid payment and
//! discards it silently.*
//!
//! Design: `zkML/docs/plans/x402/records/S117` `§12.2`.
//!
//! ## ⛔ WHAT THIS TIER DOES **NOT** CHECK, AND WHERE THAT LIVES
//!
//! A frozen answer sheet pins Rust against a **recorded** Hoon answer. It goes
//! stale the moment the kernel moves, and then reads green for ever. So the
//! sheet records the kernel's own fingerprint and the nockchain revision it was
//! taken against — and **this crate cannot re-derive either of them**:
//!
//! - the kernel lives in `vesl-agent`, which has **no GitHub remote at all**
//!   and is **not** among the three checkouts `vesl-core/.github/workflows/
//!   ci.yml:34-48` makes. A read of it here would fail on every PR, for ever.
//! - `vesl-core`'s CI builds against nockchain `dfc97ecc`, a dev tree is on
//!   `0626e6ab`, and `vesl-core-sync.yml` names a third value. No comparison
//!   against "the" revision can hold in all three places.
//!
//! ⇒ ⭐ **The staleness alarm lives in `vesl-labs/services/chain/src/lib.rs`**
//! (`mod parity_provenance`), whose CI runs on a self-hosted runner deliberately
//! provisioned with the sibling trees, so it can see the answer sheet AND the
//! kernel. It is a plain `cargo test` there — not behind any feature.
//!
//! ⛔⛔ **AND IT IS DELIBERATELY NOT A GATE ON THE ASSERTIONS BELOW.** Consider
//! the exact event this pin exists to catch: nockchain moves, the pure-Rust
//! digest drifts away from the kernel's. If a provenance check ran first and
//! short-circuited, the run would report NO VERDICT where the truth was RED —
//! and the next person would "regenerate the fixture", move the recorded values
//! onto the new Rust answer, and bury the drift under a green tick. The two
//! questions are answered by two independent tests that both always run.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use nockchain_types::tx_engine::common::{Hash, Version};
use nockchain_types::tx_engine::v1::hashable::HashHashable;
use nockchain_types::tx_engine::v1::signatures::SigHashable;
use nockchain_types::tx_engine::v1::tx::RawTx;

/// ⛔ **THE SHAPES THIS CORPUS COVERS, WRITTEN OUT — not counted.**
///
/// A reviewer must add a line here, which is the point: the fleet's own
/// `hoon_consts_kat` pattern (`vesl-labs/services/chain/src/lib.rs:126-173`,
/// *"why it is written out rather than counted"*). Names, not a length, so the
/// failure says which shape appeared or vanished.
const DECLARED: [&str; 6] = [
    "capture-3out-opaque-notedata", "capture-3out-pinned", "capture-3out-typed-lock-notedata",
    "capture-3out-unpinned", "hold-post-3seed-pinned", "single-seed-notedata-manual-jam",
];

const REGEN: &str = "regenerate it by booting the kernel:\n    \
     cd ~/projects/nockchain/vesl-labs && cargo run -p vesl-chain --features escrow-post \\\n       \
     --example regen_parity_fixture > \\\n       \
     ../vesl-core/crates/vesl-parity-corpus/tests/fixtures/hoon_rust_parity.json";

pub fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hoon_rust_parity.json")
}

fn load() -> serde_json::Value {
    let p = fixture_path();
    // ⛔ A MISSING ANSWER SHEET MUST NOT READ AS A PASS. This is the failure
    // shape `zkML/.../ma_class_extents.rs:452-460` names, and the reason the
    // message carries the remedy rather than just the errno.
    let raw = std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "NO VERDICT: the frozen answer sheet is missing or unreadable at {} ({e}).\n\
             A MISSING fixture must never read as a pass — {REGEN}",
            p.display()
        )
    });
    serde_json::from_str(&raw).unwrap_or_else(|e| {
        panic!(
            "NO VERDICT: the answer sheet at {} is not JSON: {e}",
            p.display()
        )
    })
}

/// ⛔ Parse, never string-compare. `Hash::from_base58`
/// (`nockchain-types/.../common/mod.rs:161-190`) is strict: it refuses a
/// non-canonical spelling and a value outside the tip5 domain. A raw string
/// comparison would accept `""` on both sides.
fn digest(v: &serde_json::Value, shape: &str, field: &str) -> Hash {
    let s = v.get(field).and_then(|x| x.as_str()).unwrap_or_else(|| {
        panic!("NO VERDICT: shape {shape:?} has no string {field:?} in the answer sheet — {REGEN}")
    });
    Hash::from_base58(s).unwrap_or_else(|e| {
        panic!(
            "NO VERDICT: shape {shape:?}'s recorded {field} is not a canonical tip5 digest: {e:?}"
        )
    })
}

#[test]
fn the_rust_digests_still_match_the_kernels_own_answers() {
    let fixture = load();
    let rows = fixture
        .get("shapes")
        .and_then(|s| s.as_object())
        .unwrap_or_else(|| panic!("NO VERDICT: the answer sheet has no `shapes` object — {REGEN}"));
    let shapes = vesl_parity_corpus::shapes().expect("the corpus builds");

    // ── fail closed on a shape nobody covered, in BOTH directions ───────────
    let declared: BTreeSet<&str> = DECLARED.iter().copied().collect();
    let in_corpus: BTreeSet<&str> = shapes.iter().map(|s| s.name).collect();
    let in_sheet: BTreeSet<&str> = rows.keys().map(|k| k.as_str()).collect();
    assert_eq!(
        declared, in_corpus,
        "the corpus and the DECLARED list have diverged. A shape was added or renamed without \
         a reviewer bumping the list — which is exactly what the list is for."
    );
    assert_eq!(
        declared, in_sheet,
        "the answer sheet does not carry a row for every declared shape (or carries one for a \
         shape that no longer exists). Neither side may hold a row the other does not — {REGEN}"
    );

    let mut checked = 0usize;
    let mut sig_seen: Vec<(String, Hash)> = Vec::new();
    let mut txid_seen: Vec<(String, Hash)> = Vec::new();

    for shape in &shapes {
        let row = &rows[shape.name];
        let want_sig = digest(row, shape.name, "sig_hash");
        let want_txid = digest(row, shape.name, "tx_id");

        // ── the signing digest ──────────────────────────────────────────────
        // ⛔ No `if let Ok(..)`, no `continue`: a builder error must fail the
        // run, never quietly skip a row.
        let got_sig = vesl_parity_corpus::sig_hash_subject(shape)
            .expect("the corpus assembles its sig-hash subject")
            .sig_hash_digest()
            .expect("the pure-Rust sig-hash computes");
        assert_eq!(
            got_sig.to_base58(),
            want_sig.to_base58(),
            "SIG-HASH PARITY BROKEN for shape {:?} ({}). The pure-Rust path and the chain's own \
             program no longer agree on what a buyer signs. A payment signed on the Rust answer \
             would be acked by a node and silently discarded.",
            shape.name,
            shape.why
        );

        // ── the transaction id ──────────────────────────────────────────────
        // ⛔⛔ ASSEMBLED AROUND THE **RECORDED** SIG-HASH, NOT THE ONE JUST
        // COMPUTED. The witness signs the sig-hash and the witness is folded
        // into the id (`HashHashable for Spend1`, `.../v1/tx.rs:1364-1373`).
        // Building it from `got_sig` would make this leg fail as a CONSEQUENCE
        // of a sig-hash drift, telling you nothing about the id itself.
        let spends = vesl_parity_corpus::assemble(shape, &want_sig)
            .expect("the corpus assembles the transaction");
        let got_txid = RawTx {
            version: Version::V1,
            id: want_txid.clone(),
            spends,
        }
        .compute_id()
        .expect("the pure-Rust transaction id computes");
        assert_eq!(
            got_txid.to_base58(),
            want_txid.to_base58(),
            "TX-ID PARITY BROKEN for shape {:?} ({}). The two implementations disagree about the \
             identity of the payment itself.",
            shape.name,
            shape.why
        );

        sig_seen.push((shape.name.to_string(), got_sig));
        txid_seen.push((shape.name.to_string(), got_txid));
        checked += 1;
    }

    // ── anti-vacuity ────────────────────────────────────────────────────────
    assert!(checked > 0, "NO VERDICT: zero shapes were checked");
    assert_eq!(
        checked,
        rows.len(),
        "NO VERDICT: {checked} shapes checked against {} rows — the loop skipped one",
        rows.len()
    );

    // ── DISCRIMINATION: the comparison must be able to say NO ───────────────
    // Without this, an implementation returning one constant on both sides
    // would satisfy every equality above.
    for (i, (na, a)) in sig_seen.iter().enumerate() {
        for (nb, b) in sig_seen.iter().skip(i + 1) {
            assert_ne!(
                a, b,
                "shapes {na:?} and {nb:?} have the SAME sig-hash — either the corpus has a \
                 duplicate or the digest is not discriminating, and every equality above is vacuous"
            );
        }
    }
    for (i, (na, a)) in txid_seen.iter().enumerate() {
        for (nb, b) in txid_seen.iter().skip(i + 1) {
            assert_ne!(
                a, b,
                "shapes {na:?} and {nb:?} have the SAME transaction id"
            );
        }
    }
}

/// ⭐ THE POSITIVE CONTROL, and it is measured rather than assumed.
///
/// Pinning `output-source` must MOVE what the parties sign — that is the whole
/// cost row 19 accepted, and `records/S123` `§8` `D1` measured a live kernel
/// moving with it.
///
/// ⛔⛔ **AND IT MOVES THE TRANSACTION ID TOO — WHICH THIS PROJECT DID NOT
/// KNOW.** The obvious reading is that the id cannot move: `HashHashable for
/// Seed` (`.../v1/tx.rs:1229-1242`) folds `lock_root`, `note_data`, `gift` and
/// `parent_hash` and pointedly excludes `output_source`. But `Seeds::hash_digest`
/// (`:1244-1258`) folds over the **z-set's TREE SHAPE**, and `ZSetValue::encode`
/// (`nockchain-math/src/zoon/zset.rs:143-146`) orders on the WHOLE seed noun —
/// `output_source` included, it being the first field. Pinning therefore
/// reorders the treap and the aggregate hash moves with it.
///
/// · MEASURED here, witness held constant, so the seeds are the only variable:
/// `4wstur6q…` → `6PkYu91m…`.
/// ⚑ `records/S123` `§8` `D4` measured only our own STAND-IN identity
/// (`det_tx_id`), which is blind to the field by construction. The chain's own
/// id had never been measured across the pin.
#[test]
fn pinning_output_source_moves_both_digests() {
    let shapes = vesl_parity_corpus::shapes().expect("the corpus builds");
    let f = |n: &str| shapes.iter().find(|s| s.name == n).expect("shape").clone();
    let (u, p) = (f("capture-3out-unpinned"), f("capture-3out-pinned"));

    assert!(
        u.seeds.0.iter().all(|s| s.output_source.is_none()),
        "the unpinned row is pinned after all — every leg below is vacuous"
    );
    assert!(
        p.seeds.0.iter().all(|s| s.output_source.is_some()),
        "the pinned row is not pinned — every leg below is vacuous"
    );

    let sig = |s: &vesl_parity_corpus::Shape| {
        vesl_parity_corpus::sig_hash_subject(s)
            .unwrap()
            .sig_hash_digest()
            .unwrap()
    };
    assert_ne!(
        sig(&u),
        sig(&p),
        "pinning output-source did NOT move the signing digest — the field is supposed to be \
         inside what both parties sign (S123 §8 D1 measured a live kernel moving with it)"
    );
    assert_ne!(
        u.seeds.hash_digest().unwrap(),
        p.seeds.hash_digest().unwrap(),
        "pinning output-source did not move the seeds' aggregate hash — the z-set ordering is \
         supposed to cover the field"
    );
}

/// ⭐ THE OTHER POSITIVE CONTROL: note-data is genuinely inside the digest.
///
/// S117 measured a live kernel moving a capture digest `DZB8Q7Lr…` →
/// `DHXVr1Bd…` when the escrow output's note-data went from empty to carrying
/// entries. Without this, the agreements above could be comparing two shapes
/// the digest never actually reads.
#[test]
fn note_data_is_inside_the_digest() {
    let shapes = vesl_parity_corpus::shapes().expect("the corpus builds");
    let f = |n: &str| shapes.iter().find(|s| s.name == n).expect("shape").clone();
    let sig = |s: &vesl_parity_corpus::Shape| {
        vesl_parity_corpus::sig_hash_subject(s)
            .unwrap()
            .sig_hash_digest()
            .unwrap()
    };
    let empty = f("capture-3out-pinned");
    let opaque = f("capture-3out-opaque-notedata");
    let typed = f("capture-3out-typed-lock-notedata");

    assert_ne!(
        sig(&empty),
        sig(&opaque),
        "an OPAQUE note-data entry did not move the digest"
    );
    assert_ne!(
        sig(&empty),
        sig(&typed),
        "a TYPED note-data entry did not move the digest"
    );
    assert_ne!(
        sig(&opaque),
        sig(&typed),
        "the opaque and the %lock-TYPED entry hash alike — they take different encoding paths \
         (`typed_payload_noun`, `.../v1/note.rs:233`) and must not collide"
    );
}

/// ⛔⛔ BOTH SEED ENCODERS ARE REACHED.
///
/// `vesl_core::tx_builder::jam_seeds` (`tx_builder.rs:158-163`) dispatches:
/// exactly one seed carrying note-data goes through `jam_seeds_manual`,
/// everything else through `jam_seeds_canonical`. The kernel is fed by
/// whichever one applies, so a corpus that only ever hits one of them leaves
/// half the encoding the chain sees untested — and the escrow post uses the
/// half the three-seed shapes miss.
#[test]
fn the_corpus_reaches_both_seed_encoders() {
    let shapes = vesl_parity_corpus::shapes().expect("the corpus builds");
    let manual = shapes
        .iter()
        .filter(|s| s.seeds.0.len() == 1 && !s.seeds.0[0].note_data.is_empty())
        .count();
    let canonical = shapes.iter().filter(|s| s.seeds.0.len() != 1).count();
    assert!(
        manual > 0,
        "no shape reaches jam_seeds_manual — one encoder is untested"
    );
    assert!(
        canonical > 0,
        "no shape reaches jam_seeds_canonical — one encoder is untested"
    );
}
