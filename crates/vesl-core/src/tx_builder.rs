//! Generic transaction builder helpers for Nockchain settlement.
//!
//! Provides kernel-poke-based hash computation and manual JAM helpers
//! for constructing settlement transactions. Domain-specific wrappers
//! (e.g. SettlementTxParams, settlement_to_note_data) stay in the hull.

use nockapp::noun::slab::{NockJammer, NounSlab};
use nockapp::wire::{SystemWire, Wire};
use nockapp::NockApp;
use nockchain_types::tx_engine::common::{Hash, Nicks};
use nockchain_types::tx_engine::v1::tx::{Seeds, Spends};
use nockvm::ext::make_tas;
use nockvm::noun::{IndirectAtom, NounAllocator, D, T};
use noun_serde::{NounDecode, NounEncode};

// ---------------------------------------------------------------------------
// Kernel-based hash computation
// ---------------------------------------------------------------------------

/// Wall-clock bound on a kernel poke (AUDIT 2026-05-19 H-08). A hung
/// graft arm, an infinite loop, or a stalled STARK proof must not block
/// the calling task forever. Matches vesl-hull's `poke_kernel_with_timeout`.
const KERNEL_POKE_TIMEOUT_SECS: u64 = 30;

/// Compute sig-hash by poking the Hoon kernel's `%sig-hash` handler.
///
/// Sends `[%sig-hash seeds-jam fee]` where `seeds-jam` is the JAM'd noun
/// of the Seeds z-set. Returns the tip5 hash used as the signing message.
pub async fn kernel_sig_hash(
    app: &mut NockApp,
    seeds: &Seeds,
    fee: &Nicks,
) -> anyhow::Result<Hash> {
    let seeds_jammed = jam_seeds_manual(seeds)?;

    let mut poke_slab: NounSlab = NounSlab::new();
    let tag = make_tas(&mut poke_slab, "sig-hash").as_noun();
    let seeds_atom = bytes_to_atom(&mut poke_slab, &seeds_jammed);
    // AUDIT 2026-05-21 L-01: route the fee through atom_from_u64 — a fee at
    // or above 2^63 (DIRECT_MAX) would panic the bare `D()` direct-atom
    // constructor. atom_from_u64 picks direct vs indirect atom by size.
    let fee_noun = atom_from_u64(&mut poke_slab, fee.0 as u64);
    let cmd = T(&mut poke_slab, &[tag, seeds_atom, fee_noun]);
    poke_slab.set_root(cmd);

    let effects = tokio::time::timeout(
        std::time::Duration::from_secs(KERNEL_POKE_TIMEOUT_SECS),
        app.poke(SystemWire.to_wire(), poke_slab),
    )
    .await
    .map_err(|_| anyhow::anyhow!("sig-hash poke timed out after {KERNEL_POKE_TIMEOUT_SECS}s"))?
    .map_err(|e| anyhow::anyhow!("sig-hash poke failed: {e:?}"))?;

    extract_hash_from_effect(&effects, "sig-hash")
}

/// Compute tx-id by poking the Hoon kernel's `%tx-id` handler.
///
/// Sends `[%tx-id spends-jam]` where `spends-jam` is the JAM'd noun
/// of the Spends z-map (including witness with real signatures).
pub async fn kernel_tx_id(
    app: &mut NockApp,
    spends: &Spends,
) -> anyhow::Result<Hash> {
    let spends_jammed = jam_spends_manual(spends)?;

    let mut poke_slab: NounSlab = NounSlab::new();
    let tag = make_tas(&mut poke_slab, "tx-id").as_noun();
    let spends_atom = bytes_to_atom(&mut poke_slab, &spends_jammed);
    let cmd = T(&mut poke_slab, &[tag, spends_atom]);
    poke_slab.set_root(cmd);

    let effects = tokio::time::timeout(
        std::time::Duration::from_secs(KERNEL_POKE_TIMEOUT_SECS),
        app.poke(SystemWire.to_wire(), poke_slab),
    )
    .await
    .map_err(|_| anyhow::anyhow!("tx-id poke timed out after {KERNEL_POKE_TIMEOUT_SECS}s"))?
    .map_err(|e| anyhow::anyhow!("tx-id poke failed: {e:?}"))?;

    extract_hash_from_effect(&effects, "tx-id")
}

// ---------------------------------------------------------------------------
// Manual noun builders — work around NockStack issue in ZSet/z-map
// ---------------------------------------------------------------------------

/// JAM Seeds into a noun on a plain NounSlab, bypassing ZSet::try_from_items
/// which creates an internal NockStack that fails with NoteData::to_noun().
///
/// For a single-seed z-set, the noun structure is `[seed 0 0]`
/// (treap node with null children).
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

/// JAM Spends into a noun on a plain NounSlab, bypassing the ZMap machinery.
///
/// For a single-spend z-map, the noun structure is `[[key value] 0 0]`
/// (treap node with null children).
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
    use super::*;
    use nockchain_types::tx_engine::v1::note::{NoteData, NoteDataEntry};
    use nockchain_types::tx_engine::v1::tx::Seed;

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
}
