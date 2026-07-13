//! Queue-graft poke builders.
//!
//! Queue is the third state-graft and the first under Phase 02
//! with a C1 mule-wrap site: `%queue-push` carries a jammed
//! `body=@` atom that the kernel cue's inside the poke arm. Pair
//! with the `%queue-push` / `%queue-pop` / `%queue-clear` arms
//! installed by `graft-inject`.
//!
//! Bodies are typed `*` (any noun) on the Hoon side. Callers are
//! responsible for jamming whatever shape they want. Domain-
//! specific shape validation belongs in a Phase 03 validate-graft,
//! not here.

use nock_noun_rs::{NounSlab, make_atom_in, make_tag_in, slab_jam_to_bytes};
use nockvm::noun::T;

/// Build a `[%queue-push payload=@]` poke.
///
/// `body_jammed` is the caller-jammed bytes of whatever noun the
/// queue body should hold. The kernel re-cue's it inside a mule
/// so malformed input surfaces as `%queue-error`.
pub fn build_queue_push_poke(body_jammed: &[u8]) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "queue-push");
    let payload = make_atom_in(&mut slab, body_jammed);
    let poke = T(&mut slab, &[tag, payload]);
    slab.set_root(poke);
    slab
}

/// Build a `[%queue-push payload=@]` poke from an in-process noun.
///
/// Caller constructs the body in `body` (their own `NounSlab`),
/// calls `body.set_root(...)`, and hands the slab in. We jam the
/// root and delegate to `build_queue_push_poke`. Use this when the
/// body originates in-process; for forwarding bytes from a cue-
/// emitting graft, see `vesl_core::rejam_atom` plus the byte-taking
/// builder.
pub fn build_queue_push_poke_from_noun(body: &NounSlab) -> NounSlab {
    let jammed = slab_jam_to_bytes(body);
    build_queue_push_poke(&jammed)
}

/// Build a `[%queue-pop ~]` poke.
pub fn build_queue_pop_poke() -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "queue-pop");
    let poke = T(&mut slab, &[tag, nockvm::noun::D(0)]);
    slab.set_root(poke);
    slab
}

/// Build a `[%queue-clear ~]` poke.
pub fn build_queue_clear_poke() -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "queue-clear");
    let poke = T(&mut slab, &[tag, nockvm::noun::D(0)]);
    slab.set_root(poke);
    slab
}

#[cfg(test)]
mod tests {
    use nock_noun_rs::new_stack;

    use super::*;

    #[test]
    fn build_queue_push_poke_emits_nonempty_jam() {
        let slab = build_queue_push_poke(b"\x02"); // jam(0) = 0x02
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_queue_pop_poke_emits_nonempty_jam() {
        let slab = build_queue_pop_poke();
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_queue_clear_poke_emits_nonempty_jam() {
        let slab = build_queue_clear_poke();
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn empty_body_does_not_panic() {
        let _slab = build_queue_push_poke(b"");
    }

    #[test]
    fn large_body_does_not_panic() {
        let body: Vec<u8> = (0..32_768).map(|i| (i & 0xff) as u8).collect();
        let _slab = build_queue_push_poke(&body);
    }

    #[test]
    fn from_noun_matches_byte_path() {
        // Build the body noun in a slab; jam it; both paths must
        // produce byte-equal pokes.
        let mut body_slab = NounSlab::new();
        let tag = make_tag_in(&mut body_slab, "work");
        let id = nock_noun_rs::atom_from_u64(&mut body_slab, 42);
        let body = T(&mut body_slab, &[tag, id]);
        body_slab.set_root(body);

        let _stack = new_stack();
        let body_bytes = slab_jam_to_bytes(&body_slab);
        let from_bytes = build_queue_push_poke(&body_bytes);
        let from_noun = build_queue_push_poke_from_noun(&body_slab);

        let bytes_a = slab_jam_to_bytes(&from_bytes);
        let bytes_b = slab_jam_to_bytes(&from_noun);
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn from_noun_handles_zero_root() {
        let mut body_slab = NounSlab::new();
        body_slab.set_root(nockvm::noun::D(0));
        let _slab = build_queue_push_poke_from_noun(&body_slab);
    }
}
