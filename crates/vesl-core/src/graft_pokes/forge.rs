//! Forge-graft poke builders.
//!
//! Forge is the heaviest commitment tier: hash the data with
//! `hash-leaf`, then generate a STARK proof over the hashing
//! computation. The graft is stateless (proof emitted as an effect,
//! nothing persisted); pair with a stateful graft like `settle-graft`
//! if you need registration/replay semantics.
//!
//! Pair with the `%forge-prove` arm installed by `graft-inject`.
//! Hull and note-id route through `atom_from_u64`.

use nock_noun_rs::{NounSlab, atom_from_u64, make_atom_in, make_tag_in};
use nockvm::noun::T;

/// Build a `[%forge-prove hull=@ note-id=@ data=@]` poke.
///
/// `data` is the raw leaf bytes the graft hashes with `hash-leaf`;
/// the resulting root plus `hull` are mixed into the proof's
/// Fiat-Shamir transcript, so modifying either after generation
/// invalidates the proof.
pub fn build_forge_prove_poke(hull: u64, note_id: u64, data: &[u8]) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "forge-prove");
    let hull_noun = atom_from_u64(&mut slab, hull);
    let note_id_noun = atom_from_u64(&mut slab, note_id);
    let data_atom = make_atom_in(&mut slab, data);
    let poke = T(&mut slab, &[tag, hull_noun, note_id_noun, data_atom]);
    slab.set_root(poke);
    slab
}

#[cfg(test)]
mod tests {
    use nock_noun_rs::{new_stack, slab_jam_to_bytes};

    use super::*;

    #[test]
    fn build_forge_prove_poke_emits_nonempty_jam() {
        let slab = build_forge_prove_poke(1, 101, b"hello world");
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn large_hull_and_note_id_do_not_panic() {
        // Hash-derived IDs routinely exceed DIRECT_MAX (2^63 - 1).
        let _slab = build_forge_prove_poke(u64::MAX - 7, u64::MAX - 11, b"x");
    }

    #[test]
    fn empty_data_is_handled() {
        // The graft will still hash empty data; the Rust side just
        // needs to not panic on a 0-byte slice.
        let _slab = build_forge_prove_poke(1, 101, b"");
    }
}
