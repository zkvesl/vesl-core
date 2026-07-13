//! Validate-graft poke builders.
//!
//! validate-graft v0.1 is the runtime-configured pre-flight rule
//! checker. Rules install per cause-tag via `%validate-init` and the
//! prelude block shorts every poke whose cause-tag has installed
//! rules that fail.
//!
//! v0.1 ships ONE rule shape — `[%non-empty ~]` — applied to the
//! cause-cell body (`+.u.act`). The other four rule shapes (length /
//! in-set / range / unique-in) are reserved tags in the Hoon-side
//! union for v0.2; the helpers here will grow as those land.
//!
//! See `protocol/lib/validate-graft.hoon` for the runtime semantics
//! and the cause-level vs field-level scope rationale.

use nock_noun_rs::{NounSlab, make_tag_in};
use nockvm::noun::{D, T};

/// Build a `[%validate-init cause-tag=@ta rules=(list rule)]` poke.
///
/// `cause_tag` is the cause-tag the rules apply to (e.g. `"counter-set"`,
/// `"registry-put"`). `rules` is a list of v0.1 rule shapes — currently
/// only [`Rule::NonEmpty`].
pub fn build_validate_init_poke(cause_tag: &str, rules: &[Rule]) -> NounSlab {
    let mut slab = NounSlab::new();
    let cause = make_tag_in(&mut slab, "validate-init");
    let tag = make_tag_in(&mut slab, cause_tag);
    let rules_list = build_rules_list(&mut slab, rules);
    let poke = T(&mut slab, &[cause, tag, rules_list]);
    slab.set_root(poke);
    slab
}

/// Build a `[%validate-clear cause-tag=@ta]` poke.
pub fn build_validate_clear_poke(cause_tag: &str) -> NounSlab {
    let mut slab = NounSlab::new();
    let cause = make_tag_in(&mut slab, "validate-clear");
    let tag = make_tag_in(&mut slab, cause_tag);
    let poke = T(&mut slab, &[cause, tag]);
    slab.set_root(poke);
    slab
}

/// A single rule applicable to a cause body.
///
/// v0.1 ships `NonEmpty` only. Future variants (Length, InSet, Range,
/// UniqueIn) will land alongside the corresponding Hoon-side support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Body must not be `~` (the empty list / null noun).
    NonEmpty,
}

/// Encode a single rule as a Hoon-shape noun: `[%<tag> ...args]`.
fn build_rule(slab: &mut NounSlab, rule: Rule) -> nockvm::noun::Noun {
    match rule {
        Rule::NonEmpty => {
            let tag = make_tag_in(slab, "non-empty");
            T(slab, &[tag, D(0)])
        }
    }
}

/// Encode a list of rules as a nock list (right-nested cells terminated
/// by `~`).
fn build_rules_list(slab: &mut NounSlab, rules: &[Rule]) -> nockvm::noun::Noun {
    let mut tail = D(0);
    for rule in rules.iter().rev() {
        let head = build_rule(slab, *rule);
        tail = T(slab, &[head, tail]);
    }
    tail
}

#[cfg(test)]
mod tests {
    use nock_noun_rs::{new_stack, slab_jam_to_bytes};

    use super::*;

    #[test]
    fn build_validate_init_poke_emits_nonempty_jam() {
        let slab = build_validate_init_poke("counter-set", &[Rule::NonEmpty]);
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_validate_init_poke_handles_empty_rules() {
        let slab = build_validate_init_poke("counter-set", &[]);
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_validate_init_poke_handles_multiple_rules() {
        // v0.1 only has NonEmpty, but the list-encoding path must
        // handle multiple identical rules cleanly so v0.2 additions
        // land without surprising the encoder.
        let slab = build_validate_init_poke(
            "counter-set",
            &[Rule::NonEmpty, Rule::NonEmpty, Rule::NonEmpty],
        );
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_validate_clear_poke_emits_nonempty_jam() {
        let slab = build_validate_clear_poke("counter-set");
        let _stack = new_stack();
        let bytes = slab_jam_to_bytes(&slab);
        assert!(!bytes.is_empty());
    }
}
