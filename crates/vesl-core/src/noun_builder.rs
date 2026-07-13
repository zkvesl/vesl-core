//! Generic Nock noun construction helpers for settlement payloads.
//!
//! These helpers build domain-agnostic noun structures (hashes, proof nodes,
//! notes, register pokes) used by any hull. Domain-specific builders
//! (manifest, settlement payload, settle/prove pokes) stay in the domain hull.

use nock_noun_rs::{
    Cell, D, NockStack, Noun, NounAllocator, NounSlab, T, atom_from_u64, make_atom, make_atom_in,
    make_loobean,
};
use nockchain_tip5_rs::tip5_to_atom_le_bytes;

use crate::types::*;

// ---------------------------------------------------------------------------
// Atom builders
// ---------------------------------------------------------------------------

/// Convert a tip5 hash `[u64; 5]` to a Nock atom.
///
/// Uses base-p polynomial encoding: `a + b*P + c*P^2 + d*P^3 + e*P^4`
/// matching Hoon's `digest-to-atom:tip5`.
pub fn hash_to_noun(stack: &mut NockStack, hash: &Tip5Hash) -> Noun {
    let le_bytes = tip5_to_atom_le_bytes(hash);
    make_atom(stack, &le_bytes)
}

/// Convert a tip5 hash to a Nock atom using any allocator.
pub fn hash_to_noun_generic(alloc: &mut impl NounAllocator, hash: &Tip5Hash) -> Noun {
    let le_bytes = tip5_to_atom_le_bytes(hash);
    make_atom_in(alloc, &le_bytes)
}

// ---------------------------------------------------------------------------
// Structure builders — mirror protocol/sur/vesl.hoon
// ---------------------------------------------------------------------------

/// `+$proof-node  [hash=@ side=?]`
pub fn proof_node_to_noun(stack: &mut NockStack, node: &ProofNode) -> Noun {
    let h = hash_to_noun(stack, &node.hash);
    let s = make_loobean(node.side);
    T(stack, &[h, s])
}

/// `(list proof-node)` -> null-terminated right-leaning cell tree.
pub fn proof_list_to_noun(stack: &mut NockStack, proof: &[ProofNode]) -> Noun {
    let mut list = D(0); // null terminator
    for node in proof.iter().rev() {
        let item = proof_node_to_noun(stack, node);
        list = Cell::new(stack, item, list).as_noun();
    }
    list
}

/// `note=[id=@ hull=@ root=@ state=[%pending ~]]`
///
/// In Nock: `[id [hull [root [%pending 0]]]]`
pub fn pending_note_to_noun(stack: &mut NockStack, note: &Note) -> Noun {
    assert!(
        matches!(note.state, NoteState::Pending),
        "settlement payload requires %pending note"
    );
    // id/hull can exceed DIRECT_MAX (hash-derived for replay protection).
    let id = atom_from_u64(stack, note.id);
    let hull = atom_from_u64(stack, note.hull);
    let root = hash_to_noun(stack, &note.root);
    let tag = make_atom(stack, b"pending");
    let state = Cell::new(stack, tag, D(0)).as_noun(); // [%pending ~]
    T(stack, &[id, hull, root, state])
}

// ---------------------------------------------------------------------------
// Poke builders
// ---------------------------------------------------------------------------

/// Build a `%register` poke cause in a NounSlab.
///
/// Constructs `[%register hull=@ root=@]`.
pub fn build_register_poke(hull_id: u64, root: &Tip5Hash) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_atom_in(&mut slab, b"register");
    // Public API: callers may pass hash-derived hull IDs above DIRECT_MAX.
    let id = atom_from_u64(&mut slab, hull_id);
    let root_noun = hash_to_noun_generic(&mut slab, root);
    let cause = T(&mut slab, &[tag, id, root_noun]);
    slab.set_root(cause);
    slab
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use nock_noun_rs::{make_cord, new_stack};

    use super::*;

    #[test]
    fn loobean_encoding() {
        let stack = new_stack();
        let space = stack.noun_space();
        assert_eq!(
            make_loobean(true)
                .in_space(&space)
                .as_atom()
                .unwrap()
                .as_u64()
                .unwrap(),
            0,
        );
        assert_eq!(
            make_loobean(false)
                .in_space(&space)
                .as_atom()
                .unwrap()
                .as_u64()
                .unwrap(),
            1,
        );
    }

    #[test]
    fn cord_encoding() {
        let mut stack = new_stack();
        let abc = make_cord(&mut stack, "abc");
        let space = stack.noun_space();
        let val = abc.in_space(&space).as_atom().unwrap().as_u64().unwrap();
        assert_eq!(val, 97 + 98 * 256 + 99 * 65536);
    }

    #[test]
    fn tag_pending_encoding() {
        let mut stack = new_stack();
        let tag = make_atom(&mut stack, b"pending");
        let expected: u64 = b"pending"
            .iter()
            .enumerate()
            .map(|(i, &b)| (b as u64) << (i * 8))
            .sum();
        let space = stack.noun_space();
        let val = tag.in_space(&space).as_atom().unwrap().as_u64().unwrap();
        assert_eq!(val, expected);
    }

    #[test]
    fn list_encoding_structure() {
        let mut stack = new_stack();

        let proof = vec![
            ProofNode {
                hash: [0xAA; 5],
                side: true,
            },
            ProofNode {
                hash: [0xBB; 5],
                side: false,
            },
        ];
        let list = proof_list_to_noun(&mut stack, &proof);
        let space = stack.noun_space();

        assert!(list.is_cell(), "list must be a cell");
        let first = list.in_space(&space).as_cell().unwrap();
        assert!(
            first.head().is_cell(),
            "first element must be a cell [hash side]"
        );

        let rest = first.tail();
        assert!(rest.is_cell(), "rest must be a cell [node1 0]");
        let second = rest.as_cell().unwrap();
        assert!(second.head().is_cell(), "second element must be a cell");

        let term = second.tail();
        assert!(term.is_atom(), "terminator must be atom 0");
        assert_eq!(term.as_atom().unwrap().as_u64().unwrap(), 0);
    }

    #[test]
    fn register_poke_is_cell() {
        let root: Tip5Hash = [1, 2, 3, 4, 5];
        let slab = build_register_poke(7, &root);
        let root = nock_noun_rs::slab_root(&slab);
        assert!(root.is_cell(), "register poke must be a cell");
    }
}
