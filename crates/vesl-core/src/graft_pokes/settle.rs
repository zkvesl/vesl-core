//! Settle-graft poke builders.
//!
//! Tagged in the graft namespace (`%settle-register`, `%settle-note`,
//! `%settle-verify`), distinct from the RAG-flavored `%register` /
//! `%settle` / `%prove` pokes in `crate::settle`. Use these when wiring
//! a kernel that was composed via `graft-inject` — the marker injection
//! emits `?-` arms matching these tags.
//!
//! Hull IDs are routed through `atom_from_u64` so callers can pass
//! hash-derived hull IDs above `DIRECT_MAX` without crashing the noun
//! constructor. Note IDs likewise — settled note IDs are usually
//! `hash-leaf(jam(payload))` which exceeds `DIRECT_MAX`.
//!
//! The wire shape (`[%settle-* payload=@]`) is unchanged by the H-03
//! audit fix to `verify-gate` — the graft itself extracts `note-id`
//! from the payload and passes it to the gate.
//!
//! Phase 12A renamed the primitive from `vesl-graft` to `settle-graft`
//! across the Hoon + Rust surface. Deprecated `build_vesl_*_poke`
//! aliases are kept for one release cycle in `crate::lib`. The
//! `%vesl-settle` → `%settle-note` rename drops the tautological
//! `%settle-settle` and avoids collision with `%mint-commit`.

use nock_noun_rs::{
    NounSlab, atom_from_u64, make_atom_in, make_list_in, make_loobean, make_tag_in,
    slab_jam_to_bytes,
};
use nockchain_tip5_rs::{ProofNode, Tip5Hash, tip5_to_atom_le_bytes};
use nockchain_types::tx_engine::common::{SchnorrPubkey, SchnorrSignature};
use nockvm::noun::{Noun, T};

use crate::signing::{pack_schnorr_signature, pubkey_canonical_bytes};

/// Build a `[%settle-register hull=@ root=@]` poke.
///
/// Pair with the `%settle-register` arm installed by `graft-inject`.
pub fn build_settle_register_poke(hull: u64, root: &Tip5Hash) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "settle-register");
    let hull_noun = atom_from_u64(&mut slab, hull);
    let root_bytes = tip5_to_atom_le_bytes(root);
    let root_noun = make_atom_in(&mut slab, &root_bytes);
    let poke = T(&mut slab, &[tag, hull_noun, root_noun]);
    slab.set_root(poke);
    slab
}

/// Build a `[%settle-note jammed-graft-payload]` poke for a single-leaf
/// commitment.
///
/// `data` is the raw payload bytes the default hash-gate will hash and
/// compare against the registered root. For single-leaf commits, the
/// registered root equals `hash-leaf(data)`.
///
/// For gate-selected settlement (sig-verify-*, manifest-verify, etc.)
/// the gate casts `data` into a structured cell. Use
/// [`build_settle_note_poke_with_data`] (or one of the per-gate
/// convenience builders) to thread the structured payload through.
pub fn build_settle_note_poke(note_id: u64, hull: u64, root: &Tip5Hash, data: &[u8]) -> NounSlab {
    build_settle_note_poke_with_data(note_id, hull, root, |slab| make_atom_in(slab, data))
}

/// Build a `[%settle-verify jammed-graft-payload]` poke for a single-leaf
/// commitment. Same payload shape as `settle-note` but pure verification:
/// no state transition, no replay check.
pub fn build_settle_verify_poke(note_id: u64, hull: u64, root: &Tip5Hash, data: &[u8]) -> NounSlab {
    build_settle_verify_poke_with_data(note_id, hull, root, |slab| make_atom_in(slab, data))
}

/// Closure-driven `%settle-note` poke builder for catalog gates whose
/// `data` field is a structured cell, not a flat atom.
///
/// `build_data` runs against the slab the poke is being assembled into
/// and returns the data noun (cell or atom). The SDK handles the rest
/// of the graft-payload + cause assembly.
///
/// This is the generic escape hatch over which the per-gate convenience
/// builders ([`build_settle_note_schnorr_poke`],
/// [`build_settle_note_membership_poke`], etc.) are one-liners. Use it
/// directly for future gates that don't yet have a convenience wrapper.
pub fn build_settle_note_poke_with_data<F>(
    note_id: u64,
    hull: u64,
    root: &Tip5Hash,
    build_data: F,
) -> NounSlab
where
    F: FnOnce(&mut NounSlab) -> Noun,
{
    build_settle_payload_poke("settle-note", note_id, hull, root, build_data)
}

/// Closure-driven `%settle-verify` poke builder. See
/// [`build_settle_note_poke_with_data`] for the closure contract.
pub fn build_settle_verify_poke_with_data<F>(
    note_id: u64,
    hull: u64,
    root: &Tip5Hash,
    build_data: F,
) -> NounSlab
where
    F: FnOnce(&mut NounSlab) -> Noun,
{
    build_settle_payload_poke("settle-verify", note_id, hull, root, build_data)
}

// -- per-gate convenience builders (Tier 1a vesl-gates) -----------------

/// Build a `%settle-note` poke whose `data` cell matches the
/// `sig-verify-schnorr` gate's expected payload:
/// `[data=@ sig=@ pubkey=@]`.
///
/// `sig` is packed via [`pack_schnorr_signature`] into the gate's
/// `(chal << 256) | s` atom shape; `pubkey` is encoded via
/// [`pubkey_canonical_bytes`] into the 97-byte `ser-a-pt:cheetah` form.
/// The hull's commitment must bind to that same pubkey encoding, i.e.
/// `expected-root = hash-leaf(pubkey_canonical_bytes(pubkey))`.
///
/// `data` carries the Schnorr-signed bytes — arbitrary `&[u8]`. The
/// gate chunks `data` into 7-byte LE belts via vesl-merkle's
/// `hash-leaf-digest`; [`crate::signing::schnorr_message_digest_for_data`]
/// mirrors that exact reduction so the signature verifies.
pub fn build_settle_note_schnorr_poke(
    note_id: u64,
    hull: u64,
    root: &Tip5Hash,
    data: &[u8],
    sig: &SchnorrSignature,
    pubkey: &SchnorrPubkey,
) -> NounSlab {
    let sig_bytes = pack_schnorr_signature(sig);
    let pubkey_bytes = pubkey_canonical_bytes(pubkey);
    build_settle_note_poke_with_data(note_id, hull, root, move |slab| {
        let data_noun = make_atom_in(slab, data);
        let sig_noun = make_atom_in(slab, &sig_bytes);
        let pubkey_noun = make_atom_in(slab, &pubkey_bytes);
        T(slab, &[data_noun, sig_noun, pubkey_noun])
    })
}

/// Build a `%settle-note` poke whose `data` cell matches the
/// `sig-verify-ed25519` gate's expected payload:
/// `[data=@ sig=@ pubkey=@]`.
///
/// All three fields are flat byte slices; vesl-core has no ed25519
/// signing primitive, so the caller produces `sig` and `pubkey` via
/// their own ed25519 stack (e.g., `ed25519-dalek`). The hull's
/// commitment must equal `hash-leaf(pubkey)`.
pub fn build_settle_note_ed25519_poke(
    note_id: u64,
    hull: u64,
    root: &Tip5Hash,
    data: &[u8],
    sig: &[u8],
    pubkey: &[u8],
) -> NounSlab {
    build_settle_note_poke_with_data(note_id, hull, root, move |slab| {
        let data_noun = make_atom_in(slab, data);
        let sig_noun = make_atom_in(slab, sig);
        let pubkey_noun = make_atom_in(slab, pubkey);
        T(slab, &[data_noun, sig_noun, pubkey_noun])
    })
}

/// Build a `%settle-note` poke whose `data` cell matches the
/// `set-membership-verify` gate's expected payload:
/// `[elem=@ proof=(list [hash=@ side=?])]`.
///
/// `proof` is the merkle path from `elem`'s leaf up to the registered
/// root. [`ProofNode`] encodes the side convention (`true` = sibling on
/// left, `false` = sibling on right).
pub fn build_settle_note_membership_poke(
    note_id: u64,
    hull: u64,
    root: &Tip5Hash,
    elem: &[u8],
    proof: &[ProofNode],
) -> NounSlab {
    build_settle_note_poke_with_data(note_id, hull, root, move |slab| {
        let elem_noun = make_atom_in(slab, elem);
        let proof_list = build_proof_list(slab, proof);
        T(slab, &[elem_noun, proof_list])
    })
}

/// Build a `%settle-note` poke whose `data` cell matches the
/// `bounded-value-verify` gate's expected payload:
/// `[value=@ bounds=[lo=@ hi=@] proof=(list [hash=@ side=?])]`.
///
/// The gate verifies `verify-chunk(jam([value bounds]), proof, root)`
/// internally, so the registered leaf must have been built from
/// `hash-leaf(jam([value bounds]))` — `proof` is the merkle path that
/// rebinds that leaf to `root`.
pub fn build_settle_note_bounded_poke(
    note_id: u64,
    hull: u64,
    root: &Tip5Hash,
    value: u64,
    bounds: (u64, u64),
    proof: &[ProofNode],
) -> NounSlab {
    let (lo, hi) = bounds;
    build_settle_note_poke_with_data(note_id, hull, root, move |slab| {
        let value_noun = atom_from_u64(slab, value);
        let lo_noun = atom_from_u64(slab, lo);
        let hi_noun = atom_from_u64(slab, hi);
        let bounds_noun = T(slab, &[lo_noun, hi_noun]);
        let proof_list = build_proof_list(slab, proof);
        T(slab, &[value_noun, bounds_noun, proof_list])
    })
}

/// Build a `%settle-note` poke whose `data` cell matches the
/// `manifest-verify` gate's expected payload:
/// `[fields=(list [name=@t value=@]) proofs=(list (list [hash=@ side=?]))]`.
///
/// Each `(name, value)` pair is committed as its own merkle leaf, and
/// `proofs[i]` is the path rebinding `fields[i]` to `root`. Domain-
/// agnostic: `fields` and `proofs` are plain byte / proof slices with no
/// dependency on any manifest schema.
pub fn build_settle_note_manifest_poke(
    note_id: u64,
    hull: u64,
    root: &Tip5Hash,
    fields: &[(&[u8], &[u8])],
    proofs: &[Vec<ProofNode>],
) -> NounSlab {
    build_settle_note_poke_with_data(note_id, hull, root, move |slab| {
        let field_nouns: Vec<Noun> = fields
            .iter()
            .map(|(name, value)| {
                // A `@t` cord is raw bytes — build it from `name` directly.
                // The old `from_utf8(name).unwrap_or("")` silently dropped a
                // non-UTF-8 field name to the empty cord, binding the wrong
                // name and failing verification opaquely.
                let name_noun = make_atom_in(slab, name);
                let value_noun = make_atom_in(slab, value);
                T(slab, &[name_noun, value_noun])
            })
            .collect();
        let fields_list = make_list_in(slab, &field_nouns);

        let proof_nouns: Vec<Noun> = proofs
            .iter()
            .map(|proof| build_proof_list(slab, proof))
            .collect();
        let proofs_list = make_list_in(slab, &proof_nouns);

        T(slab, &[fields_list, proofs_list])
    })
}

/// Build a `(list [hash=@ side=?])` from a slice of [`ProofNode`].
///
/// Shared by `set-membership-verify` and `bounded-value-verify`'s
/// inner-proof shape.
fn build_proof_list(slab: &mut NounSlab, proof: &[ProofNode]) -> Noun {
    let nodes: Vec<Noun> = proof
        .iter()
        .map(|node| {
            let hash_bytes = tip5_to_atom_le_bytes(&node.hash);
            let hash_noun = make_atom_in(slab, &hash_bytes);
            let side_noun = make_loobean(node.side);
            T(slab, &[hash_noun, side_noun])
        })
        .collect();
    make_list_in(slab, &nodes)
}

// -- deprecated aliases (Phase 12A) --------------------------------------

/// Deprecated alias for [`build_settle_register_poke`].
#[deprecated(
    since = "0.6.0",
    note = "renamed in Phase 12A; use build_settle_register_poke"
)]
pub fn build_vesl_register_poke(hull: u64, root: &Tip5Hash) -> NounSlab {
    build_settle_register_poke(hull, root)
}

/// Deprecated alias for [`build_settle_note_poke`] (the `%vesl-settle`
/// cause became `%settle-note` in Phase 12A — the new name emphasizes
/// "settle the note" and avoids the tautological `%settle-settle`).
#[deprecated(
    since = "0.6.0",
    note = "renamed in Phase 12A; use build_settle_note_poke"
)]
pub fn build_vesl_settle_poke(note_id: u64, hull: u64, root: &Tip5Hash, data: &[u8]) -> NounSlab {
    build_settle_note_poke(note_id, hull, root, data)
}

/// Deprecated alias for [`build_settle_verify_poke`].
#[deprecated(
    since = "0.6.0",
    note = "renamed in Phase 12A; use build_settle_verify_poke"
)]
pub fn build_vesl_verify_poke(note_id: u64, hull: u64, root: &Tip5Hash, data: &[u8]) -> NounSlab {
    build_settle_verify_poke(note_id, hull, root, data)
}

fn build_settle_payload_poke<F>(
    verb: &str,
    note_id: u64,
    hull: u64,
    root: &Tip5Hash,
    build_data: F,
) -> NounSlab
where
    F: FnOnce(&mut NounSlab) -> Noun,
{
    // Post-PMA: a noun built into a slab cannot be jammed through a foreign
    // NockStack — the arena-pointer check rejects it. Build the payload in its
    // own slab and jam it with that slab's NounSpace, then carry the bytes into
    // the outer poke slab.
    let payload_bytes = {
        let mut payload_slab = NounSlab::new();
        let data = build_data(&mut payload_slab);
        let payload =
            build_graft_single_leaf_payload_in(&mut payload_slab, note_id, hull, root, data);
        payload_slab.set_root(payload);
        slab_jam_to_bytes(&payload_slab)
    };

    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, verb);
    let jammed = make_atom_in(&mut slab, &payload_bytes);
    let poke = T(&mut slab, &[tag, jammed]);
    slab.set_root(poke);
    slab
}

/// Build a single-leaf `graft-payload` noun in `slab`. Shape matches
/// `settle-graft.hoon`'s `+$graft-payload`:
///
/// ```text
/// [note=[id=@ hull=@ root=@ state=[%pending ~]] data=* expected-root=@]
/// ```
///
/// `data` is the caller-supplied noun — flat atom for the default
/// hash-gate, structured cell for catalog gates. Hull / note-id route
/// through `atom_from_u64` so hash-derived IDs above `DIRECT_MAX` don't
/// panic the noun constructor.
pub fn build_graft_single_leaf_payload_in(
    slab: &mut NounSlab,
    note_id: u64,
    hull: u64,
    root: &Tip5Hash,
    data: Noun,
) -> Noun {
    let root_bytes = tip5_to_atom_le_bytes(root);
    let note_root = make_atom_in(slab, &root_bytes);
    let pending = make_tag_in(slab, "pending");
    let state = T(slab, &[pending, nockvm::noun::D(0)]);
    let id = atom_from_u64(slab, note_id);
    let hull_atom = atom_from_u64(slab, hull);
    let note = T(slab, &[id, hull_atom, note_root, state]);
    let exp_root = make_atom_in(slab, &root_bytes);
    T(slab, &[note, data, exp_root])
}

/// Convenience over [`build_graft_single_leaf_payload_in`]: build the
/// payload from raw `data` bytes and return the jammed atom. Use when
/// you need pre-jammed payload bytes (e.g. to wrap in
/// [`build_settle_poke_jammed`] later, or to replay across harness
/// calls).
pub fn build_graft_single_leaf_payload_jammed(
    note_id: u64,
    hull: u64,
    root: &Tip5Hash,
    data: &[u8],
) -> Vec<u8> {
    let mut slab = NounSlab::new();
    let data_atom = make_atom_in(&mut slab, data);
    let payload = build_graft_single_leaf_payload_in(&mut slab, note_id, hull, root, data_atom);
    slab.set_root(payload);
    slab_jam_to_bytes(&slab)
}

/// Build a `[%<verb> jammed]` poke wrapping pre-jammed graft-payload
/// bytes. The verb is one of `settle-note`, `settle-verify`, or any
/// future graft cause tag that consumes a pre-jammed payload atom.
///
/// Production code typically uses [`build_settle_note_poke`] /
/// [`build_settle_verify_poke`] which build the payload inline. Reach
/// for this when you need to construct the payload separately — replay
/// tests, tampered-payload assertions, cross-harness payload re-use.
pub fn build_settle_poke_jammed(verb: &str, payload: &[u8]) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, verb);
    let jammed = make_atom_in(&mut slab, payload);
    let poke = T(&mut slab, &[tag, jammed]);
    slab.set_root(poke);
    slab
}

#[cfg(test)]
mod tests {
    use nock_noun_rs::new_stack;
    use nockvm::noun::NounAllocator;

    use super::*;
    use crate::Mint;

    fn fixture_root() -> Tip5Hash {
        let data: [&[u8]; 1] = [b"hello world"];
        let mut mint = Mint::new();
        mint.commit(&data)
    }

    #[test]
    fn build_settle_register_poke_emits_nonempty_jam() {
        let slab = build_settle_register_poke(1, &fixture_root());
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_settle_note_poke_emits_nonempty_jam() {
        let root = fixture_root();
        let slab = build_settle_note_poke(101, 1, &root, b"hello world");
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_settle_verify_poke_emits_nonempty_jam() {
        let root = fixture_root();
        let slab = build_settle_verify_poke(101, 1, &root, b"hello world");
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn note_and_verify_pokes_share_payload_bytes() {
        // Same wire shape, only the verb tag differs — the jammed payload
        // bytes inside the cell must match.
        let root = fixture_root();
        let s = build_settle_note_poke(7, 3, &root, b"x");
        let v = build_settle_verify_poke(7, 3, &root, b"x");

        // Pull the second slot (the jammed payload atom) from each NounSlab
        // and compare raw atom bytes — both pokes share the same payload bytes
        // by construction, even though their cause tag differs.
        let s_payload = unsafe {
            let space = s.noun_space();
            let cell = (*s.root())
                .in_space(&space)
                .as_cell()
                .expect("note poke is a cell");
            let tail = cell.tail().as_atom().expect("payload is an atom");
            tail.to_ne_bytes()
        };
        let v_payload = unsafe {
            let space = v.noun_space();
            let cell = (*v.root())
                .in_space(&space)
                .as_cell()
                .expect("verify poke is a cell");
            let tail = cell.tail().as_atom().expect("payload is an atom");
            tail.to_ne_bytes()
        };
        assert_eq!(s_payload, v_payload);
    }

    #[test]
    fn large_hull_id_does_not_panic() {
        // hash-derived hulls routinely exceed DIRECT_MAX (2^63 - 1).
        // atom_from_u64 must route through a real atom alloc.
        let hull = u64::MAX - 7;
        let _slab = build_settle_register_poke(hull, &fixture_root());
        let _slab2 = build_settle_note_poke(u64::MAX - 11, hull, &fixture_root(), b"x");
    }

    #[test]
    fn build_graft_single_leaf_payload_jammed_handles_large_ids() {
        // Same DIRECT_MAX guarantee for the standalone jammed-payload
        // builder — vesl-test harnesses pass hash-derived hull/note IDs
        // through this path.
        let bytes = build_graft_single_leaf_payload_jammed(
            u64::MAX - 11,
            u64::MAX - 7,
            &fixture_root(),
            b"x",
        );
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_settle_poke_jammed_wraps_payload() {
        let payload = build_graft_single_leaf_payload_jammed(1, 1, &fixture_root(), b"hello");
        let slab = build_settle_poke_jammed("settle-verify", &payload);
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_settle_note_poke_with_data_emits_nonempty_jam() {
        let root = fixture_root();
        let slab = build_settle_note_poke_with_data(7, 1, &root, |slab| {
            let a = make_atom_in(slab, b"a");
            let b = make_atom_in(slab, b"b");
            T(slab, &[a, b])
        });
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn flat_byte_builder_matches_closure_builder() {
        // build_settle_note_poke is now a closure-builder wrapper. The
        // flat-byte path and the equivalent closure path must emit
        // identical jam output.
        let root = fixture_root();
        let flat = build_settle_note_poke(11, 2, &root, b"x");
        let via_closure =
            build_settle_note_poke_with_data(11, 2, &root, |slab| make_atom_in(slab, b"x"));
        let a = slab_jam_to_bytes(&flat);
        let b = slab_jam_to_bytes(&via_closure);
        assert_eq!(a, b);
    }

    fn fixture_proof() -> Vec<ProofNode> {
        // Two-step path; values are arbitrary — we only assert structural
        // jam output here, not merkle correctness.
        vec![
            ProofNode {
                hash: [1, 2, 3, 4, 5],
                side: true,
            },
            ProofNode {
                hash: [6, 7, 8, 9, 10],
                side: false,
            },
        ]
    }

    fn fixture_schnorr_keypair() -> ([nockchain_math::belt::Belt; 8], SchnorrPubkey) {
        use nockchain_math::belt::Belt;
        let mut sk = [Belt(0); 8];
        sk[0] = Belt(0xabad_f00d);
        let pk = crate::signing::derive_pubkey(&sk).expect("fixture key derives");
        (sk, pk)
    }

    #[test]
    fn build_settle_note_schnorr_poke_emits_nonempty_jam() {
        let root = fixture_root();
        let (sk, pubkey) = fixture_schnorr_keypair();
        let data: &[u8] = b"attest: 32-byte hash fingerprint";
        let digest = crate::signing::schnorr_message_digest_for_data(data);
        let sig = crate::signing::sign(&sk, &digest).expect("sign");
        let slab = build_settle_note_schnorr_poke(101, 1, &root, data, &sig, &pubkey);
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_settle_note_ed25519_poke_emits_nonempty_jam() {
        let root = fixture_root();
        let slab =
            build_settle_note_ed25519_poke(42, 1, &root, b"attestation", &[0u8; 64], &[0u8; 32]);
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_settle_note_membership_poke_emits_nonempty_jam() {
        let root = fixture_root();
        let slab = build_settle_note_membership_poke(7, 1, &root, b"alice", &fixture_proof());
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_settle_note_bounded_poke_emits_nonempty_jam() {
        let root = fixture_root();
        let slab = build_settle_note_bounded_poke(9, 1, &root, 42, (10, 100), &fixture_proof());
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_settle_note_manifest_poke_cause_is_two_element() {
        // The kernel's `+$ settle-cause` accepts only
        // `[%settle-note payload=@]` — a 2-element cell whose tail is a
        // single jammed atom. A 5-element `[%settle-note note hull root
        // data]` cause fails the soft-cast and the poke emits no effects.
        let root = fixture_root();
        let fields: [(&[u8], &[u8]); 2] = [
            (b"name".as_slice(), b"alice".as_slice()),
            (b"role".as_slice(), b"admin".as_slice()),
        ];
        let proofs = [fixture_proof(), fixture_proof()];
        let slab = build_settle_note_manifest_poke(7, 1, &root, &fields, &proofs);
        unsafe {
            let space = slab.noun_space();
            let cell = (*slab.root())
                .in_space(&space)
                .as_cell()
                .expect("cause is a cell");
            cell.tail()
                .as_atom()
                .expect("cause payload must be a single jammed atom, not a cell");
        }
    }

    #[test]
    #[allow(deprecated)]
    fn deprecated_aliases_match_canonical_output() {
        let root = fixture_root();
        let a = build_vesl_register_poke(1, &root);
        let b = build_settle_register_poke(1, &root);
        let ab = slab_jam_to_bytes(&a);
        let bb = slab_jam_to_bytes(&b);
        assert_eq!(ab, bb);

        let c = build_vesl_settle_poke(7, 3, &root, b"x");
        let d = build_settle_note_poke(7, 3, &root, b"x");
        let cb = slab_jam_to_bytes(&c);
        let db = slab_jam_to_bytes(&d);
        assert_eq!(cb, db);
    }
}
