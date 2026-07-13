//! Re-exported types for vesl-core consumers.
//!
//! Callers can `use vesl_core::{Ink, Grip, Tip5Hash, ProofNode}`
//! without direct deps on the lower crates.

// tip5 primitives
// Chain/wallet clients (for Settle/Forge users)
pub use nockchain_client_rs::{ChainClient, ChainConfig, WalletClient, WalletConfig};
pub use nockchain_tip5_rs::{
    MerkleTree, ProofNode, TIP5_ZERO, Tip5Hash, format_tip5, hash_leaf, hash_pair,
    tip5_to_atom_le_bytes, verify_proof,
};

// Noun building. Re-exported as a type alias with the default jammer
// bound. The underlying `nockapp::NounSlab` is generic over `J: Jammer`;
// rustc can't always infer the default inside closures, so consumers
// writing `let mut s = NounSlab::new();` need no annotation. Internal
// vesl-core callers still import via `nock_noun_rs::NounSlab` (same
// underlying type).
pub type NounSlab = nockapp::noun::slab::NounSlab<nockapp::noun::slab::NockJammer>;

// Vesl domain types — mirrors of sur/vesl.hoon
use serde::{Deserialize, Serialize};

/// Mirror of `+$nock-zkp  [root=merkle-root prf=@ stamp=@da]`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NockZkp {
    pub root: Tip5Hash,
    pub prf: Vec<u8>,
    pub stamp: u64,
}

/// Mirror of `+$note-state`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NoteState {
    Pending,
    Verified(NockZkp),
    Settled,
}

/// Mirror of `+$note  [id=@ hull=hull-id root=merkle-root state=note-state]`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub id: u64,
    pub hull: u64,
    pub root: Tip5Hash,
    pub state: NoteState,
}

/// Generic settlement payload — mirrors graft-payload in settle-graft.hoon.
/// For RAG, `data` is the serialized manifest. For other domains, whatever
/// the verification gate expects.
#[derive(Debug, Clone)]
pub struct GraftPayload {
    pub note: Note,
    pub data: Vec<u8>,
    pub expected_root: Tip5Hash,
}

/// Commitment verification trait. Implement for your computation type.
///
/// Decides whether `data` binds to `expected_root` under a domain-specific
/// rule. Implementations live in downstream hulls (e.g. hull-llm provides
/// the RAG-manifest verifier). vesl-core ships only the trait + a test
/// MockVerifier; no built-in production implementation.
///
/// This is commitment-layer plumbing — it has nothing to do with intent
/// coordination despite the legacy `IntentVerifier` name retained as a
/// deprecated alias below.
///
/// AUDIT 2026-04-17 H-03: `verify` takes `note_id` so domain verifiers
/// can enforce `note_id == deterministic_fn(data)`, closing the
/// pre-commit race where an attacker predicts a victim's note-id and
/// settles a different manifest under it first. Implementations that
/// don't care about note-id binding can simply ignore the argument.
///
/// AUDIT 2026-05-21 L-07: the trait carries no domain tag, so nothing at
/// the type level stops a caller from wiring one domain's verifier into
/// another domain's flow — `verify` would then answer about the wrong
/// commitment rule, and a mismatched `data` / `expected_root` pair could
/// read as a silent "verified". A caller composing `Settle<V>` MUST
/// ensure `V` is the verifier for the domain the `data` bytes were
/// produced under; the trait cannot enforce that wiring invariant.
pub trait CommitmentVerifier: Send + Sync {
    fn verify(&self, note_id: u64, data: &[u8], expected_root: &Tip5Hash) -> bool;
    fn build_settle_poke(&self, payload: &GraftPayload) -> anyhow::Result<NounSlab>;
}

/// Deprecated alias for `CommitmentVerifier`. The original name conflated
/// intent coordination with commitment verification — see
/// `.dev/BIFURCATE_INTENT.md` and `.dev/GRAFT_REFACTOR.md` for the taxonomy
/// cleanup. Will be removed in the next minor release.
#[deprecated(
    note = "renamed to CommitmentVerifier; IntentVerifier will be removed in the next minor release"
)]
pub use self::CommitmentVerifier as IntentVerifier;
