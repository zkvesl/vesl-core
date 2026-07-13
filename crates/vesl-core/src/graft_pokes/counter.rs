//! Counter-graft poke builders.
//!
//! Counter is the second state-graft: named `@ud` counters, init on
//! first touch, saturating at `2^64-1` so callers can keep using
//! `u64`. Pair with the `%counter-increment` / `%counter-reset` /
//! `%counter-set` arms installed by `graft-inject`.

use nock_noun_rs::{NounSlab, atom_from_u64, make_tag_in};
use nockvm::noun::T;

/// Build a `[%counter-increment name=@t]` poke.
pub fn build_counter_increment_poke(name: &str) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "counter-increment");
    let name_noun = make_tag_in(&mut slab, name);
    let poke = T(&mut slab, &[tag, name_noun]);
    slab.set_root(poke);
    slab
}

/// Build a `[%counter-reset name=@t]` poke.
pub fn build_counter_reset_poke(name: &str) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "counter-reset");
    let name_noun = make_tag_in(&mut slab, name);
    let poke = T(&mut slab, &[tag, name_noun]);
    slab.set_root(poke);
    slab
}

/// Build a `[%counter-set name=@t value=@ud]` poke.
pub fn build_counter_set_poke(name: &str, value: u64) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "counter-set");
    let name_noun = make_tag_in(&mut slab, name);
    let value_noun = atom_from_u64(&mut slab, value);
    let poke = T(&mut slab, &[tag, name_noun, value_noun]);
    slab.set_root(poke);
    slab
}

#[cfg(test)]
mod tests {
    use nock_noun_rs::{new_stack, slab_jam_to_bytes};

    use super::*;

    #[test]
    fn build_counter_increment_poke_emits_nonempty_jam() {
        let slab = build_counter_increment_poke("requests");
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_counter_reset_poke_emits_nonempty_jam() {
        let slab = build_counter_reset_poke("requests");
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_counter_set_poke_emits_nonempty_jam() {
        let slab = build_counter_set_poke("requests", 42);
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn large_value_does_not_panic() {
        // `u64::MAX` is the saturation boundary; the helper must
        // accept it cleanly, even though the kernel will reject the
        // following increment with %counter-error.
        let _slab = build_counter_set_poke("near-saturation", u64::MAX);
    }
}
