//! Log-graft poke builder.
//!
//! log-graft v0.1 is the append-only audit-trail primitive —
//! `%log-append` prepends an entry with a monotonic seq + caller-
//! supplied `tag=@ta` + caller-jammed `data=*` payload. Newest first;
//! oldest evicted past the retention cap (hardcoded at 100k for v0.1
//! — see the graft header for why).
//!
//! C1: payload is jammed by the caller and re-cued inside the kernel
//! arm, wrapped in mule. Malformed input surfaces as `%log-error`
//! rather than a panic.
//!
//! Pair with the `%log-append` arm installed by `graft-inject`.

use nock_noun_rs::{NounSlab, make_atom_in, make_tag_in, slab_jam_to_bytes};
use nockvm::noun::T;

/// Build a `[%log-append tag=@ta payload=@]` poke.
///
/// `tag` is a short ASCII identifier (typically a graft / cause name —
/// e.g. `"settle"`, `"registry-put"`). `data_jammed` is the caller-
/// jammed bytes of whatever noun the entry should carry. The kernel
/// re-cue's it inside a mule so malformed input surfaces as
/// `%log-error`.
pub fn build_log_append_poke(tag: &str, data_jammed: &[u8]) -> NounSlab {
    let mut slab = NounSlab::new();
    let cause_tag = make_tag_in(&mut slab, "log-append");
    let entry_tag = make_tag_in(&mut slab, tag);
    let payload = make_atom_in(&mut slab, data_jammed);
    let poke = T(&mut slab, &[cause_tag, entry_tag, payload]);
    slab.set_root(poke);
    slab
}

/// Build a `[%log-append tag=@ta payload=@]` poke from an in-process
/// noun.
///
/// Caller constructs the payload in `payload` (their own `NounSlab`),
/// calls `payload.set_root(...)`, and hands the slab in. We jam the
/// root and delegate to `build_log_append_poke`. Use this when the
/// payload originates in-process; for forwarding bytes from a cue-
/// emitting graft, see `vesl_core::rejam_atom` plus the byte-taking
/// builder.
pub fn build_log_append_poke_from_noun(tag: &str, payload: &NounSlab) -> NounSlab {
    let jammed = slab_jam_to_bytes(payload);
    build_log_append_poke(tag, &jammed)
}

#[cfg(test)]
mod tests {
    use nock_noun_rs::new_stack;

    use super::*;

    #[test]
    fn build_log_append_poke_emits_nonempty_jam() {
        let slab = build_log_append_poke("settle", b"\x02"); // jam(0) = 0x02
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn empty_data_does_not_panic() {
        let _slab = build_log_append_poke("settle", b"");
    }

    #[test]
    fn large_data_does_not_panic() {
        let body: Vec<u8> = (0..32_768).map(|i| (i & 0xff) as u8).collect();
        let _slab = build_log_append_poke("registry-put", &body);
    }

    #[test]
    fn from_noun_matches_byte_path() {
        let mut payload_slab = NounSlab::new();
        let event_tag = make_tag_in(&mut payload_slab, "settled");
        let amount = nock_noun_rs::atom_from_u64(&mut payload_slab, 250);
        let payload = T(&mut payload_slab, &[event_tag, amount]);
        payload_slab.set_root(payload);

        let _stack = new_stack();
        let payload_bytes = slab_jam_to_bytes(&payload_slab);
        let from_bytes = build_log_append_poke("settle", &payload_bytes);
        let from_noun = build_log_append_poke_from_noun("settle", &payload_slab);

        let bytes_a = slab_jam_to_bytes(&from_bytes);
        let bytes_b = slab_jam_to_bytes(&from_noun);
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn from_noun_handles_zero_root() {
        let mut payload_slab = NounSlab::new();
        payload_slab.set_root(nockvm::noun::D(0));
        let _slab = build_log_append_poke_from_noun("settle", &payload_slab);
    }
}
