//! The hash of a note — what a spend's seeds must name as their parent.
//!
//! ⚑ *In plain terms: every output of a transaction carries a pointer to the
//! coin it was paid out of, and the chain checks that pointer. The pointer is a
//! hash of the WHOLE coin — its version, the block it landed in, its name, its
//! data and its amount — not a piece of its name.*
//!
//! Mirrors `hash:nnote` (`nockchain/hoon/common/tx-engine-1.hoon:594-606`):
//!
//! ```text
//! [leaf+version leaf+origin-page hash+(hash:nname name) hash+(hash:note-data note-data) leaf+assets]
//! ```
//!
//! ⛔⛔ **WHY THIS FILE EXISTS.**
//! Every builder in the fleet set a seed's `parent_hash` to the spent note's
//! `name.last`. `name.last` is `hash[& source ~]` — a hash of the seeds that
//! CREATED the note — and can never equal `hash:nnote`, whose preimage differs.
//! Consensus compares the two (`verify-parent-hashes`, `tx-engine-1.hoon:1093-1099`)
//! at and after `parent-hash-phase` (`:1260-1261`), which is the AI-PoW activation
//! height (`tx-engine.hoon:973-988`): 126.000 by default, and settable on a fakenet
//! with `--fakenet-ai-pow-activation-height`. Below that height the field is signed
//! but unchecked, which is why every harness this fleet ran stayed green.
//!
//! ⚑ Upstream's wallet builds the field as `(hash:nnote note)` (`tx-engine.hoon:663`)
//! and ships no Rust form of it, so this is ours — a deletion when theirs arrives.

use nockchain_types::tx_engine::common::{Hash, Name};
use nockchain_types::tx_engine::v1::hashable::{HashHashable, hash_leaf_atom, hash_pair};
use nockchain_types::tx_engine::v1::note::{NoteData, NoteV1};

/// `hash:nnote` of a version-1 note.
pub fn note_hash(note: &NoteV1) -> anyhow::Result<Hash> {
    note_hash_parts(
        u32::from(note.version.clone()) as u64,
        note.origin_page.0.0,
        &note.name,
        &note.note_data,
        note.assets.0 as u64,
    )
}

/// `hash:nnote` from its five fields, for a caller that holds them apart.
///
/// ⛔ `version` is the note's own version atom (`1` for every note this fleet
/// spends); it is an operand, not assumed, so a note of another version cannot
/// silently hash as a v1 one.
pub fn note_hash_parts(
    version: u64,
    origin_page: u64,
    name: &Name,
    note_data: &NoteData,
    assets: u64,
) -> anyhow::Result<Hash> {
    let leaf = |atom: u64, what: &str| {
        hash_leaf_atom(atom)
            .map_err(|e| anyhow::anyhow!("note hash: {what} {atom} is not a field element: {e:?}"))
    };
    let name_hash = name
        .hash_digest()
        .map_err(|e| anyhow::anyhow!("note hash: name: {e:?}"))?;
    let data_hash = note_data
        .hash_digest()
        .map_err(|e| anyhow::anyhow!("note hash: note-data: {e:?}"))?;
    // `:*` nests to the right: [a [b [c [d e]]]].
    let tail = hash_pair(&data_hash, &leaf(assets, "assets")?);
    let tail = hash_pair(&name_hash, &tail);
    let tail = hash_pair(&leaf(origin_page, "origin page")?, &tail);
    Ok(hash_pair(&leaf(version, "version")?, &tail))
}

/// The version atom a v1 note carries (`u32::from(Version::V1)`).
pub const NOTE_VERSION_V1: u64 = 1;

#[cfg(test)]
mod tests {
    use nockchain_math::belt::Belt;
    use nockchain_types::tx_engine::common::{BlockHeight, Nicks, Version};

    use super::*;

    fn h(n: u64) -> Hash {
        Hash::from_limbs(&[n, n + 1, n + 2, n + 3, n + 4])
    }

    fn note(origin: u64, assets: usize) -> NoteV1 {
        NoteV1::new(
            BlockHeight(Belt(origin)),
            Name::new(h(10), h(20)),
            NoteData(vec![]),
            Nicks(assets),
        )
    }

    /// The defect this file closes: the value every builder used is not the value
    /// consensus compares.
    #[test]
    fn the_note_hash_is_not_the_last_name() {
        let n = note(7, 1000);
        assert_ne!(note_hash(&n).unwrap(), n.name.last);
    }

    /// Every field is an operand: change any one and the hash moves. The origin
    /// page is the one a builder that reads only a note's name cannot know.
    #[test]
    fn every_field_moves_the_hash() {
        let base = note(7, 1000);
        let b = note_hash(&base).unwrap();
        assert_ne!(b, note_hash(&note(8, 1000)).unwrap(), "origin page");
        assert_ne!(b, note_hash(&note(7, 1001)).unwrap(), "assets");
        let mut other_name = base.clone();
        other_name.name = Name::new(h(10), h(21));
        assert_ne!(b, note_hash(&other_name).unwrap(), "name");
        let mut v2 = base.clone();
        v2.version = Version::V2;
        assert_ne!(b, note_hash(&v2).unwrap(), "version");
    }

    #[test]
    fn the_parts_form_is_the_note_form() {
        let n = note(7, 1000);
        assert_eq!(
            note_hash(&n).unwrap(),
            note_hash_parts(NOTE_VERSION_V1, 7, &n.name, &n.note_data, 1000).unwrap()
        );
    }
}
