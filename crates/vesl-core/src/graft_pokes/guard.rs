//! Guard-graft poke builders.
//!
//! Guard is the middle commitment tier — register a root under a
//! hull-id, then verify that hash-leaf(data) matches the registered
//! root. No verify-gate (that's settle), no replay protection (that's
//! settle), no crash-on-bad-leaf (the graft emits `%guard-checked
//! ok=%.n` for mismatches; crash semantics live in settle-graft).
//!
//! Pair with the `%guard-register` / `%guard-check` arms installed by
//! `graft-inject`. Hull IDs route through `atom_from_u64` so callers
//! can pass hash-derived hulls above `DIRECT_MAX`.

use nock_noun_rs::{NounSlab, atom_from_u64, make_atom_in, make_tag_in};
use nockchain_tip5_rs::{Tip5Hash, tip5_to_atom_le_bytes};
use nockvm::noun::T;

/// Build a `[%guard-register hull=@ root=@]` poke.
pub fn build_guard_register_poke(hull: u64, root: &Tip5Hash) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "guard-register");
    let hull_noun = atom_from_u64(&mut slab, hull);
    let root_bytes = tip5_to_atom_le_bytes(root);
    let root_noun = make_atom_in(&mut slab, &root_bytes);
    let poke = T(&mut slab, &[tag, hull_noun, root_noun]);
    slab.set_root(poke);
    slab
}

/// Build a `[%guard-check hull=@ data=@]` poke.
///
/// `data` is the raw leaf bytes the graft will hash with `hash-leaf`
/// before comparing to the root registered under `hull`.
pub fn build_guard_check_poke(hull: u64, data: &[u8]) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "guard-check");
    let hull_noun = atom_from_u64(&mut slab, hull);
    let data_atom = make_atom_in(&mut slab, data);
    let poke = T(&mut slab, &[tag, hull_noun, data_atom]);
    slab.set_root(poke);
    slab
}

#[cfg(test)]
mod tests {
    use nock_noun_rs::{new_stack, slab_jam_to_bytes};

    use super::*;
    use crate::Mint;

    fn fixture_root() -> Tip5Hash {
        let data: [&[u8]; 1] = [b"hello world"];
        let mut mint = Mint::new();
        mint.commit(&data)
    }

    #[test]
    fn build_guard_register_poke_emits_nonempty_jam() {
        let slab = build_guard_register_poke(1, &fixture_root());
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_guard_check_poke_emits_nonempty_jam() {
        let slab = build_guard_check_poke(1, b"hello world");
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn large_hull_id_does_not_panic() {
        // hash-derived hulls routinely exceed DIRECT_MAX (2^63 - 1).
        let hull = u64::MAX - 7;
        let _slab = build_guard_register_poke(hull, &fixture_root());
        let _slab2 = build_guard_check_poke(hull, b"x");
    }
}
