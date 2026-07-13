//! Batch-graft poke builders.
//!
//! batch-graft v0.1 is the settlement-flush buffer — accumulates
//! caller-supplied intents and emits a single `%batch-flushed` effect
//! when the configured count threshold trips. The downstream
//! orchestrator listens for the bundled flush and routes each intent
//! into settle-graft on its own time.
//!
//! v0.1 ships ONE trigger: `count`. The other two from the 03 spec
//! (`pages`, `time`) are deferred per `vesl-nockup/.dev/03_DEFERRALS.md`.
//!
//! C1: `%batch-add` carries a jammed intent atom that the kernel
//! re-cues inside its poke arm, wrapped in mule — the canonical
//! pattern from queue-graft / log-graft.

use nock_noun_rs::{NounSlab, atom_from_u64, make_atom_in, make_tag_in, slab_jam_to_bytes};
use nockvm::noun::{D, T};

/// Build a `[%batch-init threshold=@ud]` poke.
///
/// `threshold = 0` disables auto-flush (manual `%batch-flush` only).
/// `threshold = 1` flushes on every add (functionally equivalent to
/// no batching — included so the count knob has a well-defined low
/// end without special-casing).
pub fn build_batch_init_poke(threshold: u64) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "batch-init");
    let value = atom_from_u64(&mut slab, threshold);
    let poke = T(&mut slab, &[tag, value]);
    slab.set_root(poke);
    slab
}

/// Build a `[%batch-add payload=@]` poke.
///
/// `intent_jammed` is the caller-jammed bytes of whatever noun the
/// intent should carry. The kernel re-cues it inside a mule, so
/// malformed input surfaces as `%batch-error`.
pub fn build_batch_add_poke(intent_jammed: &[u8]) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "batch-add");
    let payload = make_atom_in(&mut slab, intent_jammed);
    let poke = T(&mut slab, &[tag, payload]);
    slab.set_root(poke);
    slab
}

/// Build a `[%batch-add payload=@]` poke from an in-process noun.
///
/// Caller constructs the intent in `intent` (their own `NounSlab`),
/// calls `intent.set_root(...)`, and hands the slab in. We jam the
/// root and delegate to `build_batch_add_poke`. Use this when the
/// intent originates in-process; for forwarding bytes from a cue-
/// emitting graft, see `vesl_core::rejam_atom` plus the byte-taking
/// builder.
pub fn build_batch_add_poke_from_noun(intent: &NounSlab) -> NounSlab {
    let jammed = slab_jam_to_bytes(intent);
    build_batch_add_poke(&jammed)
}

/// Build a `[%batch-flush ~]` poke.
pub fn build_batch_flush_poke() -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "batch-flush");
    let poke = T(&mut slab, &[tag, D(0)]);
    slab.set_root(poke);
    slab
}

#[cfg(test)]
mod tests {
    use nock_noun_rs::new_stack;

    use super::*;

    #[test]
    fn build_batch_init_poke_emits_nonempty_jam() {
        let slab = build_batch_init_poke(5);
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_batch_init_poke_handles_disable() {
        // threshold=0 must encode without panic.
        let _slab = build_batch_init_poke(0);
    }

    #[test]
    fn build_batch_init_poke_handles_max() {
        // u64::MAX must encode without panic — manifest's pending-cap
        // gate happens kernel-side, helpers stay ignorant.
        let _slab = build_batch_init_poke(u64::MAX);
    }

    #[test]
    fn build_batch_add_poke_emits_nonempty_jam() {
        let slab = build_batch_add_poke(b"\x02"); // jam(0)
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_batch_add_poke_handles_empty_payload() {
        let _slab = build_batch_add_poke(b"");
    }

    #[test]
    fn build_batch_add_poke_handles_large_payload() {
        let body: Vec<u8> = (0..32_768).map(|i| (i & 0xff) as u8).collect();
        let _slab = build_batch_add_poke(&body);
    }

    #[test]
    fn build_batch_flush_poke_emits_nonempty_jam() {
        let slab = build_batch_flush_poke();
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn from_noun_matches_byte_path() {
        let mut intent_slab = NounSlab::new();
        let tag = make_tag_in(&mut intent_slab, "transfer");
        let amount = atom_from_u64(&mut intent_slab, 1000);
        let intent = T(&mut intent_slab, &[tag, amount]);
        intent_slab.set_root(intent);

        let _stack = new_stack();
        let intent_bytes = slab_jam_to_bytes(&intent_slab);
        let from_bytes = build_batch_add_poke(&intent_bytes);
        let from_noun = build_batch_add_poke_from_noun(&intent_slab);

        let bytes_a = slab_jam_to_bytes(&from_bytes);
        let bytes_b = slab_jam_to_bytes(&from_noun);
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn from_noun_handles_zero_root() {
        let mut intent_slab = NounSlab::new();
        intent_slab.set_root(D(0));
        let _slab = build_batch_add_poke_from_noun(&intent_slab);
    }
}
