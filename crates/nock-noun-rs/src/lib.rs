//! High-level Nock noun construction from Rust.
//!
//! Provides helpers for building Nock nouns without wrestling the raw
//! NockStack / NounSlab APIs directly. Covers the patterns every NockApp
//! needs: atoms, cords, tags, loobeans, lists, cells, and jam/cue.
//!
//! # Quick Start
//!
//! ```ignore
//! use nock_noun_rs::*;
//!
//! let mut stack = new_stack();
//!
//! // Build a tagged cell: [%hello 'world']
//! let tag  = make_tag(&mut stack, "hello");
//! let body = make_cord(&mut stack, "world");
//! let cell = T(&mut stack, &[tag, body]);
//!
//! // Jam to bytes for wire transmission
//! let bytes = jam_to_bytes(&mut stack, cell);
//! ```
//!
//! # Memory Model
//!
//! NockStack is an arena allocator with two stacks growing toward each
//! other; noun allocations are bump-allocated on the current frame.
//! Allocate one stack up front and pass `&mut stack` through every
//! builder. Simple noun construction needs no frame push/pop — build
//! the whole tree in a single pass.
//!
//! # Nock Encoding Conventions
//!
//! - **Loobeans**: Hoon `%.y` (true) = atom `0`, `%.n` (false) = atom `1`.
//!   Rust `true` maps to `D(0)`, Rust `false` maps to `D(1)`.
//! - **Cords (@t)**: UTF-8 bytes of the string are the LE bytes of the atom.
//!   `"alpha"` -> atom from bytes `[97,108,112,104,97]`.
//! - **Lists**: Null-terminated right-leaning: `[a [b [c 0]]]`. Empty = `D(0)`.
//! - **Tags (@tas)**: ASCII string as atom. `%pending` = atom from `b"pending"`.

// Re-exports — the essentials every NockApp needs.
pub use nockapp::noun::slab::NounSlab;
pub use nockvm::mem::NockStack;
pub use nockvm::noun::{Cell, D, IndirectAtom, Noun, NounAllocator, T};
pub use nockvm::serialization::{cue, jam};

/// Default NockStack size: 8 MB (in 64-bit words).
const STACK_SIZE: usize = 1 << 20;

/// Safe wrapper around `NounSlab::root`.
///
/// AUDIT 2026-04-17 H-06: centralizes the `unsafe { *slab.root() }`
/// pattern that was copy-pasted across eight sites. `root()` is
/// `unsafe` because the returned `Noun` may contain raw pointers into
/// the slab and must not outlive it. Copying the value out immediately
/// is the established convention; this helper makes it the only
/// supported entry point so nobody accidentally holds a `&Noun` past
/// the slab drop.
///
/// ```ignore
/// let slab = build_my_poke();          // must call set_root() internally
/// let noun = slab_root(&slab);         // safe copy
/// // use noun while slab is still alive
/// ```
///
/// # Safety contract
///
/// The caller must ensure `slab.set_root(..)` was called first. A
/// `NounSlab` with no root set has `root == D(0)` (the zero atom); the
/// returned `Noun` is still memory-safe, but it's almost certainly a
/// bug.
pub fn slab_root<J>(slab: &NounSlab<J>) -> Noun {
    // SAFETY: copied out immediately, never stored as a reference that
    // could outlive the slab. The Noun may contain raw pointers into
    // the slab's arena; use it before the slab is dropped.
    unsafe { *slab.root() }
}

/// Create a NockStack for noun construction and jamming.
///
/// 8 MB arena — sufficient for most NockApp payloads.
/// For very large nouns, use `NockStack::new(size, 0)` directly.
pub fn new_stack() -> NockStack {
    NockStack::new(STACK_SIZE, 0)
}

// ---------------------------------------------------------------------------
// NockStack-based builders
// ---------------------------------------------------------------------------

/// Convert a byte slice to a Nock atom (LE interpretation).
///
/// Empty slice returns `D(0)` (null atom).
///
/// ```ignore
/// let noun = make_atom(&mut stack, &[0x42, 0x00, 0x01]);
/// ```
pub fn make_atom(stack: &mut NockStack, bytes: &[u8]) -> Noun {
    if bytes.is_empty() {
        return D(0);
    }
    // SAFETY: new_raw_bytes_ref copies the slice into the NockStack
    // allocator; normalize_as_atom yields a canonical atom.
    unsafe {
        let mut indirect = IndirectAtom::new_raw_bytes_ref(stack, bytes);
        let space = stack.noun_space();
        indirect.normalize_as_atom(&space).as_noun()
    }
}

/// Convert a Rust string to a Hoon cord (`@t`).
///
/// UTF-8 bytes become the LE representation of the atom.
/// `"abc"` -> atom 6513249 (= 97 + 98*256 + 99*65536).
pub fn make_cord(stack: &mut NockStack, s: &str) -> Noun {
    make_atom(stack, s.as_bytes())
}

/// Convert an ASCII string to a Hoon tag (`@tas`).
///
/// Identical to `make_cord` for pure-ASCII inputs but semantically
/// distinct: tags are knots (`%foo`), cords are text (`'foo'`).
pub fn make_tag(stack: &mut NockStack, s: &str) -> Noun {
    make_atom(stack, s.as_bytes())
}

/// Convert a Rust bool to a Hoon loobean.
///
/// `true` (`%.y`) -> `D(0)`, `false` (`%.n`) -> `D(1)`.
///
/// Inverted versus C/Rust: Hoon uses `0` for true because `%.y` is
/// first in the union.
pub fn make_loobean(b: bool) -> Noun {
    if b { D(0) } else { D(1) }
}

/// Build a null-terminated list from a slice of nouns.
///
/// `[a [b [c 0]]]` — the standard Hoon list encoding.
/// Empty slice returns `D(0)` (null / `~`).
pub fn make_list(stack: &mut NockStack, items: &[Noun]) -> Noun {
    let mut list = D(0);
    for item in items.iter().rev() {
        list = Cell::new(stack, *item, list).as_noun();
    }
    list
}

/// Jam a noun into bytes for wire transmission.
///
/// Returns the minimal LE byte representation of the jammed atom.
/// This is the format Hoon's `cue` expects.
pub fn jam_to_bytes(stack: &mut NockStack, noun: Noun) -> Vec<u8> {
    let atom = jam(stack, noun);
    let space = stack.noun_space();
    let handle = atom.in_space(&space);
    let bytes = handle.as_ne_bytes();
    let len = bytes.iter().rposition(|&b| b != 0).map_or(0, |pos| pos + 1);
    bytes[..len].to_vec()
}

/// Jam a `NounSlab`'s root noun to wire bytes.
///
/// Post-PMA the noun-allocator's arena identity is checked at jam time, so a
/// slab-allocated noun cannot be jammed through a foreign `NockStack`. This
/// helper uses the slab's own `NounSpace` for the jam — the same path
/// `NounSlab::jam` follows internally — and returns a `Vec<u8>` for callers
/// that previously consumed `jam_to_bytes(&mut new_stack(), slab_root(&slab))`.
pub fn slab_jam_to_bytes<J: nockapp::noun::slab::Jammer>(slab: &NounSlab<J>) -> Vec<u8> {
    slab.jam().to_vec()
}

/// Cue bytes back into a noun.
///
/// Inverse of `jam_to_bytes`. Returns `None` if the bytes are not
/// a valid jammed noun.
pub fn cue_from_bytes(stack: &mut NockStack, bytes: &[u8]) -> Option<Noun> {
    let atom = make_atom(stack, bytes);
    let a = atom.as_atom().ok()?;
    cue(stack, a).ok()
}

/// Error returned by [`rejam_atom`] when the input bytes are not a
/// valid jam encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejamError;

impl std::fmt::Display for RejamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rejam_atom: input is not valid jam")
    }
}

impl std::error::Error for RejamError {}

/// Re-jam an atom whose bytes came from a cue-emitting graft (e.g.
/// `%queue-popped` body) so they can be fed to a cue-consuming graft
/// (e.g. `%batch-add`) without double-cue corruption.
///
/// Cross-graft seam helper. State-grafts that store opaque payloads
/// (queue, log, batch, registry) cue their input on entry and emit
/// the resulting noun back unchanged. Walking that noun's bytes via
/// `as_ne_bytes()` returns the *atom* representation, not a fresh jam
/// encoding — feeding those bytes verbatim into another cue-consuming
/// graft fails (or, on pathological back-refs, hangs the kernel inside
/// `cue`). `rejam_atom` cues the bytes and re-jams the result so the
/// next graft's `cue` succeeds.
///
/// Canonicalizing: input and output bytes encode the same noun but may
/// not be byte-identical — jam isn't canonical, different jammers pick
/// different back-ref schedules. The output is canonical under
/// nockvm's jammer.
///
/// AUDIT 2026-05-19 H-12: returns `Err(RejamError)` when `bytes` is not
/// valid jam. Previously this `.expect()`-panicked, so a graft emitting
/// malformed bytes could crash the runtime via the next graft's rejam.
pub fn rejam_atom(bytes: &[u8]) -> Result<Vec<u8>, RejamError> {
    let mut stack = new_stack();
    let noun = cue_from_bytes(&mut stack, bytes).ok_or(RejamError)?;
    Ok(jam_to_bytes(&mut stack, noun))
}

// ---------------------------------------------------------------------------
// Generic-allocator builders — work with NockStack or NounSlab
// ---------------------------------------------------------------------------

/// Convert a byte slice to a Nock atom using any allocator.
///
/// Use this with `NounSlab` for poke construction:
/// ```ignore
/// let mut slab = NounSlab::new();
/// let tag = make_atom_in(&mut slab, b"settle");
/// ```
pub fn make_atom_in(alloc: &mut impl NounAllocator, bytes: &[u8]) -> Noun {
    if bytes.is_empty() {
        return D(0);
    }
    // SAFETY: new_raw_bytes_ref copies the slice into the allocator;
    // normalize_as_atom yields a canonical atom.
    unsafe {
        let mut indirect = IndirectAtom::new_raw_bytes_ref(alloc, bytes);
        let space = alloc.noun_space();
        indirect.normalize_as_atom(&space).as_noun()
    }
}

/// Convert a u64 to a Nock atom, safe across the DIRECT_MAX boundary.
///
/// `D(value)` panics when `value > DIRECT_MAX` (= 2^63 - 1). Use this
/// helper whenever the value's upper bit might be set — hashed note IDs,
/// random nonces, etc. Small values are still encoded as direct atoms
/// via `normalize_as_atom`.
pub fn atom_from_u64(alloc: &mut impl NounAllocator, value: u64) -> Noun {
    make_atom_in(alloc, &value.to_le_bytes())
}

/// Convert a string to a cord using any allocator.
pub fn make_cord_in(alloc: &mut impl NounAllocator, s: &str) -> Noun {
    make_atom_in(alloc, s.as_bytes())
}

/// Convert an ASCII string to a tag using any allocator.
pub fn make_tag_in(alloc: &mut impl NounAllocator, s: &str) -> Noun {
    make_atom_in(alloc, s.as_bytes())
}

/// Build a null-terminated list using any allocator.
pub fn make_list_in(alloc: &mut impl NounAllocator, items: &[Noun]) -> Noun {
    let mut list = D(0);
    for item in items.iter().rev() {
        list = Cell::new(alloc, *item, list).as_noun();
    }
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loobean_encoding() {
        // %.y (true) = 0, %.n (false) = 1
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
        // 'abc' in Hoon = 97 + 98*256 + 99*65536 = 6513249
        let abc = make_cord(&mut stack, "abc");
        let space = stack.noun_space();
        let val = abc.in_space(&space).as_atom().unwrap().as_u64().unwrap();
        assert_eq!(val, 97 + 98 * 256 + 99 * 65536);
    }

    #[test]
    fn tag_encoding() {
        let mut stack = new_stack();
        // %pending = atom from bytes "pending"
        let tag = make_tag(&mut stack, "pending");
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
    fn empty_atom() {
        let mut stack = new_stack();
        let noun = make_atom(&mut stack, &[]);
        let space = stack.noun_space();
        assert_eq!(
            noun.in_space(&space).as_atom().unwrap().as_u64().unwrap(),
            0
        );
    }

    #[test]
    fn list_structure() {
        let mut stack = new_stack();
        // [1 [2 [3 0]]]
        let items = [D(1), D(2), D(3)];
        let list = make_list(&mut stack, &items);
        let space = stack.noun_space();

        let c1 = list.in_space(&space).as_cell().unwrap();
        assert_eq!(c1.head().as_atom().unwrap().as_u64().unwrap(), 1);

        let c2 = c1.tail().as_cell().unwrap();
        assert_eq!(c2.head().as_atom().unwrap().as_u64().unwrap(), 2);

        let c3 = c2.tail().as_cell().unwrap();
        assert_eq!(c3.head().as_atom().unwrap().as_u64().unwrap(), 3);

        // Null terminator
        assert_eq!(c3.tail().as_atom().unwrap().as_u64().unwrap(), 0);
    }

    #[test]
    fn empty_list() {
        let mut stack = new_stack();
        let list = make_list(&mut stack, &[]);
        let space = stack.noun_space();
        assert_eq!(
            list.in_space(&space).as_atom().unwrap().as_u64().unwrap(),
            0
        );
    }

    #[test]
    fn jam_cue_round_trip() {
        let mut stack = new_stack();
        let tag = make_tag(&mut stack, "hello");
        let body = make_cord(&mut stack, "world");
        let cell = T(&mut stack, &[tag, body]);

        let bytes = jam_to_bytes(&mut stack, cell);
        assert!(!bytes.is_empty());

        let restored = cue_from_bytes(&mut stack, &bytes).expect("cue must succeed");
        assert!(restored.is_cell());
    }

    #[test]
    fn slab_builders() {
        let mut slab: NounSlab = NounSlab::new();
        let tag = make_tag_in(&mut slab, "settle");
        let payload = make_atom_in(&mut slab, &[0x42, 0x01]);
        let cause = T(&mut slab, &[tag, payload]);
        slab.set_root(cause);
        // Just verify it doesn't panic — slab nouns can't be inspected
        // the same way as stack nouns without converting.
    }

    #[test]
    fn rejam_atom_canonicalizes_atom() {
        let mut stack = new_stack();
        let bytes = jam_to_bytes(&mut stack, D(42));
        let rejammed = rejam_atom(&bytes).expect("rejam output");
        let mut s2 = new_stack();
        let cued = cue_from_bytes(&mut s2, &rejammed).expect("rejam output cues");
        let space = s2.noun_space();
        assert_eq!(
            cued.in_space(&space).as_atom().unwrap().as_u64().unwrap(),
            42
        );
    }

    #[test]
    fn rejam_atom_canonicalizes_cell() {
        let mut stack = new_stack();
        let cell = T(&mut stack, &[D(1), D(2), D(3)]);
        let bytes = jam_to_bytes(&mut stack, cell);
        let rejammed = rejam_atom(&bytes).expect("rejam output");
        let mut s2 = new_stack();
        let cued = cue_from_bytes(&mut s2, &rejammed).expect("rejam output cues");
        let space = s2.noun_space();
        let c1 = cued.in_space(&space).as_cell().unwrap();
        assert_eq!(c1.head().as_atom().unwrap().as_u64().unwrap(), 1);
        let c2 = c1.tail().as_cell().unwrap();
        assert_eq!(c2.head().as_atom().unwrap().as_u64().unwrap(), 2);
        assert_eq!(c2.tail().as_atom().unwrap().as_u64().unwrap(), 3);
    }

    #[test]
    fn rejam_atom_canonicalizes_indirect() {
        // Large indirect atom — jam encoding spans multiple bytes;
        // round-trip through cue+jam must preserve the value.
        let payload: Vec<u8> = (0..1024).map(|i| (i & 0xff) as u8).collect();
        let mut stack = new_stack();
        let big = make_atom(&mut stack, &payload);
        let bytes = jam_to_bytes(&mut stack, big);
        let rejammed = rejam_atom(&bytes).expect("rejam output");
        // Both jams cue back to the same atom value.
        let mut s2 = new_stack();
        let original = cue_from_bytes(&mut s2, &bytes).expect("original cues");
        let space2 = s2.noun_space();
        let mut s3 = new_stack();
        let canonical = cue_from_bytes(&mut s3, &rejammed).expect("rejam cues");
        let space3 = s3.noun_space();
        assert_eq!(
            original.in_space(&space2).as_atom().unwrap().as_ne_bytes(),
            canonical.in_space(&space3).as_atom().unwrap().as_ne_bytes(),
        );
    }

    #[test]
    fn rejam_atom_errors_on_malformed() {
        // 0xff has the high bit pattern of a valid jam prefix but no
        // backing data — cue rejects.
        assert!(rejam_atom(&[0xff, 0xff]).is_err());
    }
}
