//! vesl-core — High-level Vesl SDK
//!
//! Four primitives, each a different weight class:
//!
//! - **Mint** — Data commitment. Pure math, zero async. Commit chunks, get a root.
//! - **Guard** — Verification. Prove chunks and manifests against trusted roots.
//! - **Settle** — Settlement. Kernel boot + chain access for note state transitions.
//! - **Forge** — STARK proof. Everything Settle does, plus proof generation.
//!
//! Callers pick the primitive they need. Mint users never touch the kernel.
//! Forge users get the full pipeline.

pub mod config;
pub mod fee;
pub mod graft_pokes;
pub mod guard;
pub mod lock;
pub mod mint;
pub mod noun_builder;
pub mod peek;
pub mod poke;
pub mod settle;
pub mod signing;
pub mod tx_builder;
pub mod types;
pub mod verify_tx;

// Top-level re-exports so callers can write:
//   use vesl_core::{Mint, Guard, Tip5Hash, ProofNode};
pub use config::{SettlementConfig, SettlementMode, SettlementToml};
// Exact v1 fee pricing + lock/lock-merkle-proof construction for
// chain-valid spends. The Tip5 helpers in `types` (hash_leaf/hash_pair)
// are the commitment-tree flavor; the lock module's merkle arithmetic
// is the consensus hashable flavor — they are not interchangeable.
pub use fee::{
    FeeConstants, calculate_min_fee, count_seed_words, count_witness_words, num_of_leaves,
};
pub use graft_pokes::batch::{
    build_batch_add_poke, build_batch_add_poke_from_noun, build_batch_flush_poke,
    build_batch_init_poke,
};
pub use graft_pokes::clock::build_clock_tick_poke;
pub use graft_pokes::counter::{
    build_counter_increment_poke, build_counter_reset_poke, build_counter_set_poke,
};
pub use graft_pokes::forge::build_forge_prove_poke;
pub use graft_pokes::guard::{build_guard_check_poke, build_guard_register_poke};
pub use graft_pokes::kv::{build_kv_delete_poke, build_kv_set_poke};
pub use graft_pokes::log::{build_log_append_poke, build_log_append_poke_from_noun};
pub use graft_pokes::mint::build_mint_commit_poke;
pub use graft_pokes::queue::{
    build_queue_clear_poke, build_queue_pop_poke, build_queue_push_poke,
    build_queue_push_poke_from_noun,
};
pub use graft_pokes::rbac::{build_rbac_grant_poke, build_rbac_revoke_poke};
pub use graft_pokes::registry::{
    build_registry_del_poke, build_registry_put_poke, build_registry_put_poke_from_noun,
    build_registry_update_poke, build_registry_update_poke_from_noun,
};
// Graft poke builders — used by callers that compose grafted kernels via
// `graft-inject` (in vesl-nockup). One submodule per primitive.
//
// Phase 12A renamed the settle helpers from `build_vesl_*_poke` to
// `build_settle_*_poke` to match the `%settle-*` cause-tag rename.
// Deprecated aliases are re-exported below for one release cycle.
pub use graft_pokes::settle::{
    build_graft_single_leaf_payload_in, build_graft_single_leaf_payload_jammed,
    build_settle_note_bounded_poke, build_settle_note_ed25519_poke,
    build_settle_note_manifest_poke, build_settle_note_membership_poke, build_settle_note_poke,
    build_settle_note_poke_with_data, build_settle_note_schnorr_poke, build_settle_poke_jammed,
    build_settle_register_poke, build_settle_verify_poke, build_settle_verify_poke_with_data,
};
#[allow(deprecated)]
pub use graft_pokes::settle::{
    build_vesl_register_poke, build_vesl_settle_poke, build_vesl_verify_poke,
};
pub use graft_pokes::validate::{
    Rule as ValidateRule, build_validate_clear_poke, build_validate_init_poke,
};
pub use guard::{Guard, GuardError};
pub use lock::{bounty_lock, first_name_for_lock, lock_merkle_proof, lock_root, verify_merk_proof};
pub use mint::{Mint, MintError};
// Cross-graft seam helper: cue-then-jam canonicalization for bytes
// pulled from cue-emitting grafts (e.g., %queue-popped body) before
// they're forwarded into cue-consuming grafts (%batch-add, %log-append,
// %registry-put). See zkvesl-docs/reference/sdk.md "Cross-graft pipelines".
pub use nock_noun_rs::{RejamError, rejam_atom};
// Peek-path builders + result decoders. See the `peek` module and
// zkvesl-docs `reference/sdk.md` "Peek calls from Rust" for usage.
pub use peek::{
    PeekError, build_hull_peek_path, build_keyed_peek_path, build_keyless_peek_path,
    decode_effect_cord, decode_effect_loobean, decode_queue_popped, decode_settle_error,
    effect_head_tag, effect_head_tags, peek_atom_u64, peek_atom_u64_strict, peek_loobean,
    peek_unit_atom_strict, peek_unit_list, unwrap_triple_unit_atom,
};
// Typed `NockApp::poke` outcome. See `crates/vesl-core/src/poke.rs` for
// the design rationale.
pub use poke::{PokeCrashError, PokeOutcome, RejectionReason, classify_effects};
pub use settle::Settle;
pub use signing::{
    SigningError, derive_pubkey, key_from_seed_phrase, pack_schnorr_signature,
    pubkey_canonical_bytes, pubkey_from_base58, pubkey_hash, schnorr_message_digest_for_data, sign,
    verify_chain_signature, wire_signature_to_chain,
};
// Deprecated alias — remove in next minor release. Callers should migrate to CommitmentVerifier.
#[allow(deprecated)]
pub use types::IntentVerifier;
pub use types::{
    ChainClient, ChainConfig, CommitmentVerifier, GraftPayload, MerkleTree, NockZkp, Note,
    NoteState, NounSlab, ProofNode, TIP5_ZERO, Tip5Hash, WalletClient, WalletConfig, format_tip5,
    hash_leaf, hash_pair, tip5_to_atom_le_bytes, verify_proof,
};
pub use verify_tx::{TxInputView, TxOutputView, TxReceipt, VerifyTxError, fetch_receipt};
// High-level Hull-author wallet API. Bundles BIP-39 seed handling +
// Cheetah-BIP32-over-Tip5 HD derivation + the BIP-44 layout. Hull
// authors call `VeslWallet::from_seed_phrase(...)`, then drive an
// intent-app or payment-app role from the same code via
// `intent_signer()` / `payment_signer()` (the TOML config-toggle
// pattern; see `SettlementToml::wallet`).
pub use vesl_wallet::{DerivedKey, VESL_COIN_TYPE_PLACEHOLDER, VeslWallet, WalletError};
// Vesl wallet derivation spec — BIP44 5-level layout. Re-exported from the
// `vesl-wallet` workspace so Hull authors get role constants and the typed
// `DerivationPath` via `use vesl_core::*` without depending on the spec
// crate directly.
pub use vesl_wallet_spec::{
    BIP44_PURPOSE, DerivationPath, ROLE_ENCRYPTION, ROLE_INTENT, ROLE_RECEIVING, ROLE_SESSION,
    ROLE_X402,
};
