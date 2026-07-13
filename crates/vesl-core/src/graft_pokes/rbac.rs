//! RBAC-graft poke builders.
//!
//! RBAC stores per-pubkey permission sets. Causes carry perms as a
//! `(list @t)` so Rust callers can hand a flat slice of perm names
//! without constructing a treap-shaped Hoon set. The graft `silt`s
//! the list into a set on the way in.

use nock_noun_rs::{NounSlab, atom_from_u64, make_tag_in};
use nockvm::noun::{D, Noun, T};

/// Build a `[%rbac-grant pubkey=@ perms=(list @t)]` poke.
pub fn build_rbac_grant_poke(pubkey: u64, perms: &[&str]) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "rbac-grant");
    let pubkey_noun = atom_from_u64(&mut slab, pubkey);
    let perms_list = build_cord_list_in(&mut slab, perms);
    let poke = T(&mut slab, &[tag, pubkey_noun, perms_list]);
    slab.set_root(poke);
    slab
}

/// Build a `[%rbac-revoke pubkey=@ perms=(list @t)]` poke.
pub fn build_rbac_revoke_poke(pubkey: u64, perms: &[&str]) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "rbac-revoke");
    let pubkey_noun = atom_from_u64(&mut slab, pubkey);
    let perms_list = build_cord_list_in(&mut slab, perms);
    let poke = T(&mut slab, &[tag, pubkey_noun, perms_list]);
    slab.set_root(poke);
    slab
}

/// Build a `(list @t)` from a slice of cord strings.
///
/// Hoon lists are right-nested cells terminated by `~` (atom 0):
/// `[a [b [c ~]]]`. We build right-to-left so the head ends at
/// the outermost cell.
fn build_cord_list_in(slab: &mut NounSlab, items: &[&str]) -> Noun {
    let mut tail: Noun = D(0); // ~
    for item in items.iter().rev() {
        let head = make_tag_in(slab, item);
        tail = T(slab, &[head, tail]);
    }
    tail
}

#[cfg(test)]
mod tests {
    use nock_noun_rs::{new_stack, slab_jam_to_bytes};

    use super::*;

    #[test]
    fn build_rbac_grant_poke_emits_nonempty_jam() {
        let slab = build_rbac_grant_poke(1, &["read", "write"]);
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_rbac_revoke_poke_emits_nonempty_jam() {
        let slab = build_rbac_revoke_poke(1, &["write"]);
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn empty_perms_list_does_not_panic() {
        let _slab = build_rbac_grant_poke(1, &[]);
        let _slab2 = build_rbac_revoke_poke(1, &[]);
    }

    #[test]
    fn large_pubkey_does_not_panic() {
        // Hash-derived pubkeys routinely exceed DIRECT_MAX (2^63 - 1).
        let _slab = build_rbac_grant_poke(u64::MAX - 7, &["x"]);
    }
}
