//! Typed kernel→hull poke outcome.
//!
//! `NockApp::poke` returns `Result<Vec<NounSlab>, NockAppError>` — a shape
//! that conflates several outcomes: a successful poke that emitted effects,
//! a successful poke that emitted nothing (gate-clean-deny, idempotent
//! no-op, hull-side RBAC pre-check that never reached the kernel), a
//! kernel-emitted error cord, a kernel-emitted typed rejection effect, and
//! a driver-level error.
//!
//! [`PokeOutcome`] is the typed wrapper callers (vesl-hull handlers,
//! vesl-test harness) match against to distinguish these without scraping
//! stderr or string-matching effect tags blindly.
//!
//! [`classify_effects`] handles the `Ok(non-empty)` branch of an
//! `app.poke` result; callers wrap timeout/`Err`/empty cases themselves
//! ([`PokeOutcome::Crashed`] / [`RejectionReason::Unknown`]).
//!
//! Per-graft variants of [`RejectionReason`] (typed payload structs per
//! graft) arrive with manifest-driven codegen. Until then, callers decode
//! `raw_effects` with the existing
//! [`crate::peek::decode_effect_cord`] / [`crate::peek::decode_settle_error`]
//! helpers.

use nockapp::NockAppError;
use nockapp::noun::slab::NounSlab;

use crate::peek::{decode_effect_cord, effect_head_tag, effect_head_tags};

/// Outcome of a `NockApp::poke` from the hull/test/SDK perspective.
///
/// Three top-level cases, each carrying enough context for the caller to
/// produce its response (HTTP status, test assertion, retry decision):
///
/// - [`PokeOutcome::Accepted`] — kernel emitted at least one non-error
///   effect. Caller dispatches on effect tags to identify the specific
///   success (e.g. `%settle-noted` vs `%settle-registered`).
/// - [`PokeOutcome::Rejected`] — kernel deterministically refused; the
///   reason discriminates the typed paths.
/// - [`PokeOutcome::Crashed`] — driver-level failure; the kernel did not
///   return a clean verdict and may be in an undefined state.
#[derive(Debug)]
pub enum PokeOutcome {
    /// Kernel accepted the poke and emitted effects whose head tags are
    /// not in the recognized error/rejection set. `effects` is non-empty.
    Accepted { effects: Vec<NounSlab> },

    /// Kernel deterministically rejected the poke.
    Rejected { reason: RejectionReason },

    /// Driver-level failure: timeout, `NockAppError`, or a protocol
    /// violation (kernel emitted an effect head tag the caller cannot
    /// interpret).
    Crashed { error: PokeCrashError },
}

impl PokeOutcome {
    /// Effect head tags from whichever effects this outcome carries.
    ///
    /// Mirrors the pre-typed-outcome convention where a poke returned
    /// `Vec<String>`. Returns:
    /// - the tags from `Accepted::effects`
    /// - the tags from `Rejected`'s `raw_effects` (for `KernelError`,
    ///   `KernelRejected`, `GateDenied`)
    /// - an empty vec for `Rejected::Unknown` / `Rejected::RbacDenied`
    ///   (no kernel effects produced)
    /// - an empty vec for `Crashed::Timeout` / `Crashed::KernelPoke`
    /// - the protocol-violating effects from `Crashed::UnexpectedTag`
    ///
    /// Tests that only check whether a specific success/error tag fired
    /// can call this instead of unpacking the variant.
    pub fn effect_head_tags(&self) -> Vec<String> {
        match self {
            PokeOutcome::Accepted { effects } => effect_head_tags(effects),
            PokeOutcome::Rejected {
                reason: RejectionReason::KernelError { raw_effects, .. },
            }
            | PokeOutcome::Rejected {
                reason: RejectionReason::KernelRejected { raw_effects, .. },
            }
            | PokeOutcome::Rejected {
                reason: RejectionReason::GateDenied { raw_effects, .. },
            } => effect_head_tags(raw_effects),
            PokeOutcome::Rejected {
                reason: RejectionReason::Unknown | RejectionReason::RbacDenied { .. },
            } => Vec::new(),
            PokeOutcome::Crashed {
                error: PokeCrashError::UnexpectedTag { raw_effects, .. },
            } => effect_head_tags(raw_effects),
            PokeOutcome::Crashed {
                error: PokeCrashError::Timeout | PokeCrashError::KernelPoke(_),
            } => Vec::new(),
        }
    }
}

/// Sub-classification of [`PokeOutcome::Rejected`].
///
/// Hand-written variants today; manifest-driven codegen will extend this
/// enum with per-graft typed-payload variants in a follow-up. Callers that
/// need the kernel-emitted cord/payload reach for `raw_effects` and the
/// [`crate::peek`] decoder helpers.
#[derive(Debug)]
pub enum RejectionReason {
    /// Kernel emitted a `[%<graft>-error msg=@t]` effect. `cord` is the
    /// decoded `msg` atom; `raw_effects` is the full effect list so callers
    /// can format response bodies without re-poking.
    KernelError {
        cord: String,
        raw_effects: Vec<NounSlab>,
    },

    /// Kernel emitted a typed rejection effect whose head tag ends in
    /// `-rejected` (e.g. `[%settle-register-rejected hull existing-root]`).
    /// Handler decodes the payload from `raw_effects` per graft.
    KernelRejected {
        tag: String,
        raw_effects: Vec<NounSlab>,
    },

    /// Settle-graft verify-gate deterministically refused (verify-gate
    /// returned `%.n`). Reachable once settle-graft's gate-clean-deny
    /// path emits `[%settle-denied reason=@t]`; the classifier routes
    /// the `-denied` suffix ahead of that kernel change so hull/test
    /// code can match on the variant directly.
    GateDenied {
        reason: String,
        raw_effects: Vec<NounSlab>,
    },

    /// Hull orchestrator's `[%rbac-has-perm pubkey perm]` peek returned
    /// `%.n`; the kernel was never poked. Constructed by the hull, not
    /// produced by [`classify_effects`] — there are no `raw_effects`.
    RbacDenied { pubkey: String, perm: String },

    /// Empty effect list with no error cord and no typed denial.
    /// Pre–typed-denial settle-graft, this collapses gate-clean-deny + any
    /// idempotent-no-op denial path. Post–typed-denial, it should be
    /// unreachable for settle pokes; remains as a catch-all for forward
    /// compatibility (newer kernel, older Rust).
    Unknown,
}

/// Sub-classification of [`PokeOutcome::Crashed`].
#[derive(Debug)]
pub enum PokeCrashError {
    /// The caller-imposed timeout elapsed before the kernel returned.
    Timeout,

    /// `NockApp::poke` returned an `Err`. Includes Hoon-`?>` crashes that
    /// propagated as errors rather than empty effect lists.
    KernelPoke(NockAppError),

    /// Kernel emitted an effect whose head tag is not a recognized
    /// `*-error` / `*-rejected` / `*-denied` / known-success tag, or whose
    /// shape lacks a head atom altogether. Protocol violation.
    UnexpectedTag {
        tag: String,
        raw_effects: Vec<NounSlab>,
    },
}

/// Classify a non-empty effect list returned by `NockApp::poke` into the
/// appropriate [`PokeOutcome`] variant.
///
/// Callers handle the empty-list and `Err` cases themselves (an empty list
/// becomes [`RejectionReason::Unknown`]; an `Err` becomes
/// [`PokeCrashError::KernelPoke`] or [`PokeCrashError::Timeout`]). This
/// function inspects the first effect's head tag and routes by suffix:
///
/// - `*-error` → [`RejectionReason::KernelError`] (cord decoded via
///   [`decode_effect_cord`]).
/// - `*-rejected` → [`RejectionReason::KernelRejected`].
/// - `*-denied` → [`RejectionReason::GateDenied`] (reason cord decoded).
///   Reachable only after settle-graft is rebuilt with typed gate-clean-deny.
/// - Anything else → [`PokeOutcome::Accepted`].
///
/// The suffix convention is established across every shipped graft
/// (`*-error msg=@t` for cord-typed kernel errors, `*-rejected` for typed
/// rejection effects, `*-denied` for the gate-clean-deny addition).
/// Per-graft codegen will later replace this with a static name table.
///
/// An effect whose first slab is not a `[head=@ tail]` cell — no head atom
/// to read — surfaces as [`PokeCrashError::UnexpectedTag`] with an empty
/// `tag`, because a malformed kernel emission is a protocol violation, not
/// a clean rejection.
pub fn classify_effects(effects: Vec<NounSlab>) -> PokeOutcome {
    let Some(first) = effects.first() else {
        return PokeOutcome::Rejected {
            reason: RejectionReason::Unknown,
        };
    };
    let Some(tag) = effect_head_tag(first) else {
        return PokeOutcome::Crashed {
            error: PokeCrashError::UnexpectedTag {
                tag: String::new(),
                raw_effects: effects,
            },
        };
    };

    if tag.ends_with("-error") {
        let cord = decode_effect_cord(first).unwrap_or_default();
        PokeOutcome::Rejected {
            reason: RejectionReason::KernelError {
                cord,
                raw_effects: effects,
            },
        }
    } else if tag.ends_with("-rejected") {
        PokeOutcome::Rejected {
            reason: RejectionReason::KernelRejected {
                tag,
                raw_effects: effects,
            },
        }
    } else if tag.ends_with("-denied") {
        let reason = decode_effect_cord(first).unwrap_or_default();
        PokeOutcome::Rejected {
            reason: RejectionReason::GateDenied {
                reason,
                raw_effects: effects,
            },
        }
    } else {
        PokeOutcome::Accepted { effects }
    }
}

#[cfg(test)]
mod tests {
    use nock_noun_rs::{make_atom_in, make_tag_in};
    use nockvm::noun::{D, T};

    use super::*;

    /// Build a `[<tag> <tail>]` effect slab. `tail_atom_bytes = None`
    /// yields a `~`-tailed effect (atom 0); `Some(bytes)` yields a cord tail.
    fn build_effect(tag_name: &str, tail_atom_bytes: Option<&[u8]>) -> NounSlab {
        let mut slab: NounSlab = NounSlab::new();
        let tag = make_tag_in(&mut slab, tag_name);
        let tail = match tail_atom_bytes {
            Some(bytes) => make_atom_in(&mut slab, bytes),
            None => D(0),
        };
        let effect = T(&mut slab, &[tag, tail]);
        slab.set_root(effect);
        slab
    }

    #[test]
    fn empty_effects_classify_as_unknown_rejection() {
        let outcome = classify_effects(Vec::new());
        assert!(matches!(
            outcome,
            PokeOutcome::Rejected {
                reason: RejectionReason::Unknown
            }
        ));
    }

    #[test]
    fn error_tag_classifies_as_kernel_error() {
        let effect = build_effect("settle-error", Some(b"settle-graft: malformed payload"));
        match classify_effects(vec![effect]) {
            PokeOutcome::Rejected {
                reason: RejectionReason::KernelError { cord, raw_effects },
            } => {
                assert_eq!(cord, "settle-graft: malformed payload");
                assert_eq!(raw_effects.len(), 1);
            }
            other => panic!("expected KernelError, got {other:?}"),
        }
    }

    #[test]
    fn rejected_tag_classifies_as_kernel_rejected() {
        let effect = build_effect("settle-register-rejected", None);
        match classify_effects(vec![effect]) {
            PokeOutcome::Rejected {
                reason: RejectionReason::KernelRejected { tag, raw_effects },
            } => {
                assert_eq!(tag, "settle-register-rejected");
                assert_eq!(raw_effects.len(), 1);
            }
            other => panic!("expected KernelRejected, got {other:?}"),
        }
    }

    #[test]
    fn denied_tag_classifies_as_gate_denied() {
        // Pins the `-denied` suffix routing; reachable for real once
        // settle-graft's gate-clean-deny path emits the typed cord.
        let effect = build_effect("settle-denied", Some(b"verify gate returned false"));
        match classify_effects(vec![effect]) {
            PokeOutcome::Rejected {
                reason:
                    RejectionReason::GateDenied {
                        reason,
                        raw_effects,
                    },
            } => {
                assert_eq!(reason, "verify gate returned false");
                assert_eq!(raw_effects.len(), 1);
            }
            other => panic!("expected GateDenied, got {other:?}"),
        }
    }

    #[test]
    fn success_tag_classifies_as_accepted() {
        let effect = build_effect("settle-noted", Some(b"opaque"));
        match classify_effects(vec![effect]) {
            PokeOutcome::Accepted { effects } => {
                assert_eq!(effects.len(), 1);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn counter_error_tag_routes_to_kernel_error() {
        // Suffix matching is not settle-specific — confirm a sibling graft
        // routes the same way.
        let effect = build_effect("counter-error", Some(b"counter at saturation"));
        assert!(matches!(
            classify_effects(vec![effect]),
            PokeOutcome::Rejected {
                reason: RejectionReason::KernelError { .. }
            }
        ));
    }

    #[test]
    fn atom_only_first_effect_classifies_as_unexpected_tag() {
        // Bare-atom effect — no head to read; protocol violation.
        let mut slab: NounSlab = NounSlab::new();
        slab.set_root(D(42));
        assert!(matches!(
            classify_effects(vec![slab]),
            PokeOutcome::Crashed {
                error: PokeCrashError::UnexpectedTag { .. }
            }
        ));
    }

    #[test]
    fn rbac_denied_is_hand_constructed() {
        // RbacDenied is not produced by classify_effects (the kernel is
        // never poked); the hull builds it directly. Smoke-test the
        // constructor shape.
        let outcome = PokeOutcome::Rejected {
            reason: RejectionReason::RbacDenied {
                pubkey: "0xabc".into(),
                perm: "settle-write".into(),
            },
        };
        match outcome {
            PokeOutcome::Rejected {
                reason: RejectionReason::RbacDenied { pubkey, perm },
            } => {
                assert_eq!(pubkey, "0xabc");
                assert_eq!(perm, "settle-write");
            }
            _ => panic!("expected RbacDenied"),
        }
    }

    #[test]
    fn timeout_crash_is_hand_constructed() {
        // PokeCrashError::Timeout is also a caller-side construction
        // (the wrapper creates it when its tokio::time::timeout fires).
        let outcome = PokeOutcome::Crashed {
            error: PokeCrashError::Timeout,
        };
        assert!(matches!(
            outcome,
            PokeOutcome::Crashed {
                error: PokeCrashError::Timeout
            }
        ));
    }

    #[test]
    fn effect_head_tags_returns_tags_for_each_carrying_variant() {
        // Accepted
        let outcome = classify_effects(vec![build_effect("settle-noted", None)]);
        assert_eq!(outcome.effect_head_tags(), vec!["settle-noted".to_string()]);

        // Rejected::KernelError
        let outcome = classify_effects(vec![build_effect("settle-error", Some(b"x"))]);
        assert_eq!(outcome.effect_head_tags(), vec!["settle-error".to_string()]);

        // Rejected::KernelRejected
        let outcome = classify_effects(vec![build_effect("settle-register-rejected", None)]);
        assert_eq!(
            outcome.effect_head_tags(),
            vec!["settle-register-rejected".to_string()]
        );

        // Rejected::GateDenied
        let outcome = classify_effects(vec![build_effect("settle-denied", Some(b"x"))]);
        assert_eq!(
            outcome.effect_head_tags(),
            vec!["settle-denied".to_string()]
        );
    }

    #[test]
    fn effect_head_tags_returns_empty_for_no_kernel_effects() {
        // Rejected::Unknown (empty effect list)
        let outcome = classify_effects(Vec::new());
        assert!(outcome.effect_head_tags().is_empty());

        // Rejected::RbacDenied (hand-constructed, never reached the kernel)
        let outcome = PokeOutcome::Rejected {
            reason: RejectionReason::RbacDenied {
                pubkey: "0xabc".into(),
                perm: "x".into(),
            },
        };
        assert!(outcome.effect_head_tags().is_empty());

        // Crashed::Timeout
        let outcome = PokeOutcome::Crashed {
            error: PokeCrashError::Timeout,
        };
        assert!(outcome.effect_head_tags().is_empty());
    }
}
