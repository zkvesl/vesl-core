//! KV-graft poke builders.
//!
//! KV is the loose state-graft store: opaque atom values, overwrite-on-set,
//! noop on delete-missing. Pair with the `%kv-set` / `%kv-delete` arms
//! installed by `graft-inject`.
//!
//! Keys are `@t` cords (UTF-8 bytes); values are opaque `@` atoms whose
//! interpretation is the caller's responsibility. Callers wanting strict
//! semantics or structured records use `registry-graft` instead.

use nock_noun_rs::{NounSlab, make_atom_in, make_tag_in};
use nockvm::noun::T;

/// Build a `[%kv-set key=@t value=@]` poke.
pub fn build_kv_set_poke(key: &str, value: &[u8]) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "kv-set");
    let key_noun = make_tag_in(&mut slab, key);
    let value_noun = make_atom_in(&mut slab, value);
    let poke = T(&mut slab, &[tag, key_noun, value_noun]);
    slab.set_root(poke);
    slab
}

/// Build a `[%kv-delete key=@t]` poke.
pub fn build_kv_delete_poke(key: &str) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "kv-delete");
    let key_noun = make_tag_in(&mut slab, key);
    let poke = T(&mut slab, &[tag, key_noun]);
    slab.set_root(poke);
    slab
}

#[cfg(test)]
mod tests {
    use nock_noun_rs::{new_stack, slab_jam_to_bytes};

    use super::*;

    #[test]
    fn build_kv_set_poke_emits_nonempty_jam() {
        let slab = build_kv_set_poke("greeting", b"hello world");
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_kv_delete_poke_emits_nonempty_jam() {
        let slab = build_kv_delete_poke("greeting");
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn long_key_does_not_panic() {
        let key = "k".repeat(1024);
        let _slab = build_kv_set_poke(&key, b"v");
        let _slab2 = build_kv_delete_poke(&key);
    }

    #[test]
    fn large_value_does_not_panic() {
        let value: Vec<u8> = (0..16_384).map(|i| (i & 0xff) as u8).collect();
        let _slab = build_kv_set_poke("k", &value);
    }
}
