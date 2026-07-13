//! Registry-graft poke builders.
//!
//! Registry is the strict structured store: create-only put,
//! modify-only update, error-on-missing delete, opaque `record=*`
//! values. Both put and update cue caller-supplied bytes inside
//! the poke arm under a mule guard — pre-jam your record on the
//! Rust side.

use nock_noun_rs::{NounSlab, atom_from_u64, make_atom_in, make_tag_in, slab_jam_to_bytes};
use nockvm::noun::T;

/// Build a `[%registry-put key=@ payload=@]` poke.
///
/// `record_jammed` is the caller-jammed bytes of the record noun.
/// The kernel re-cue's it inside a mule and emits `%registry-error`
/// on malformed jam.
pub fn build_registry_put_poke(key: u64, record_jammed: &[u8]) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "registry-put");
    let key_noun = atom_from_u64(&mut slab, key);
    let payload = make_atom_in(&mut slab, record_jammed);
    let poke = T(&mut slab, &[tag, key_noun, payload]);
    slab.set_root(poke);
    slab
}

/// Build a `[%registry-update key=@ payload=@]` poke.
pub fn build_registry_update_poke(key: u64, record_jammed: &[u8]) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "registry-update");
    let key_noun = atom_from_u64(&mut slab, key);
    let payload = make_atom_in(&mut slab, record_jammed);
    let poke = T(&mut slab, &[tag, key_noun, payload]);
    slab.set_root(poke);
    slab
}

/// Build a `[%registry-put key=@ payload=@]` poke from an in-process
/// noun.
///
/// Caller constructs the record in `record` (their own `NounSlab`),
/// calls `record.set_root(...)`, and hands the slab in. We jam the
/// root and delegate to `build_registry_put_poke`. Use this when the
/// record originates in-process; for forwarding bytes from a cue-
/// emitting graft, see `vesl_core::rejam_atom` plus the byte-taking
/// builder.
pub fn build_registry_put_poke_from_noun(key: u64, record: &NounSlab) -> NounSlab {
    let jammed = slab_jam_to_bytes(record);
    build_registry_put_poke(key, &jammed)
}

/// Build a `[%registry-update key=@ payload=@]` poke from an in-process
/// noun. Mirrors `build_registry_put_poke_from_noun`.
pub fn build_registry_update_poke_from_noun(key: u64, record: &NounSlab) -> NounSlab {
    let jammed = slab_jam_to_bytes(record);
    build_registry_update_poke(key, &jammed)
}

/// Build a `[%registry-del key=@]` poke.
pub fn build_registry_del_poke(key: u64) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "registry-del");
    let key_noun = atom_from_u64(&mut slab, key);
    let poke = T(&mut slab, &[tag, key_noun]);
    slab.set_root(poke);
    slab
}

#[cfg(test)]
mod tests {
    use nock_noun_rs::new_stack;

    use super::*;

    #[test]
    fn build_registry_put_poke_emits_nonempty_jam() {
        let slab = build_registry_put_poke(1, &[0x02]); // jam(0)
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_registry_update_poke_emits_nonempty_jam() {
        let slab = build_registry_update_poke(1, &[0x02]);
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_registry_del_poke_emits_nonempty_jam() {
        let slab = build_registry_del_poke(1);
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn large_key_does_not_panic() {
        // Hash-derived keys routinely exceed DIRECT_MAX (2^63 - 1).
        let _slab = build_registry_put_poke(u64::MAX - 7, &[0x02]);
    }

    #[test]
    fn large_record_does_not_panic() {
        let record: Vec<u8> = (0..32_768).map(|i| (i & 0xff) as u8).collect();
        let _slab = build_registry_put_poke(1, &record);
    }

    #[test]
    fn put_from_noun_matches_byte_path() {
        let mut record_slab = NounSlab::new();
        let kind_tag = make_tag_in(&mut record_slab, "user");
        let weight = atom_from_u64(&mut record_slab, 42);
        let record = T(&mut record_slab, &[kind_tag, weight]);
        record_slab.set_root(record);

        let _stack = new_stack();
        let record_bytes = slab_jam_to_bytes(&record_slab);
        let from_bytes = build_registry_put_poke(1, &record_bytes);
        let from_noun = build_registry_put_poke_from_noun(1, &record_slab);

        let bytes_a = slab_jam_to_bytes(&from_bytes);
        let bytes_b = slab_jam_to_bytes(&from_noun);
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn update_from_noun_matches_byte_path() {
        let mut record_slab = NounSlab::new();
        let kind_tag = make_tag_in(&mut record_slab, "user");
        let weight = atom_from_u64(&mut record_slab, 99);
        let record = T(&mut record_slab, &[kind_tag, weight]);
        record_slab.set_root(record);

        let _stack = new_stack();
        let record_bytes = slab_jam_to_bytes(&record_slab);
        let from_bytes = build_registry_update_poke(1, &record_bytes);
        let from_noun = build_registry_update_poke_from_noun(1, &record_slab);

        let bytes_a = slab_jam_to_bytes(&from_bytes);
        let bytes_b = slab_jam_to_bytes(&from_noun);
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn from_noun_handles_zero_root() {
        let mut record_slab = NounSlab::new();
        record_slab.set_root(nockvm::noun::D(0));
        let _put = build_registry_put_poke_from_noun(1, &record_slab);
        let _upd = build_registry_update_poke_from_noun(1, &record_slab);
    }
}
