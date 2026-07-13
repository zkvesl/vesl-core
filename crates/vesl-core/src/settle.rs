//! Settle — Settlement (heavy tier)
//!
//! Two layers:
//! 1. `Settle<V>` struct — verify via CommitmentVerifier, manage root registration
//! 2. Free functions — composable transaction building helpers
//!
//! The hull orchestrates kernel boot and poke dispatch. Settle provides
//! the settlement toolkit: seed construction, signing, tx assembly,
//! chain submission. Kernel interaction (NockApp pokes for sig-hash
//! and tx-id) lives in `tx_builder`.

use std::collections::{HashSet, VecDeque};

use anyhow::Result;
use nock_noun_rs::NounSlab;
use nockchain_client_rs::ChainClient;
use nockchain_tip5_rs::Tip5Hash;

use crate::guard::Guard;
use crate::types::{CommitmentVerifier, GraftPayload, Note};

/// Upper bound on the pre-flight `settled_ids` cache (AUDIT 2026-05-19
/// H-07). The kernel's `settled` set is the authoritative replay
/// defense; this SDK-side cache is a pre-flight diagnostic, so evicting
/// the oldest entry past the cap is safe — a missed pre-flight hit just
/// defers the duplicate rejection to the kernel.
const SETTLED_IDS_CAP: usize = 1_000_000;

/// Upper bound on a [`GraftPayload`]'s `data` field (AUDIT 2026-05-21
/// L-05). `poke_bytes` JAMs the payload into a noun; an unbounded `data`
/// vector lets a caller drive an arbitrarily large allocation. 64 MiB
/// mirrors hull-llm's `MAX_MANIFEST_JSON_BYTES` cap on the RAG path.
const MAX_POKE_DATA_BYTES: usize = 64 * 1024 * 1024;

/// Generic settlement orchestrator parameterized by a domain `CommitmentVerifier`.
///
/// Vesl-core ships only the trait; concrete verifier implementations live in
/// downstream hulls (e.g. hull-llm's `RagVerifier`). Construct via
/// `Settle::with_verifier(your_verifier)`.
pub struct Settle<V: CommitmentVerifier> {
    guard: Guard,
    verifier: V,
    settled_ids: HashSet<u64>,
    /// Insertion order for `settled_ids`, enabling FIFO eviction at the cap.
    settled_order: VecDeque<u64>,
}

impl<V: CommitmentVerifier> Settle<V> {
    /// Create a Settle with a custom verifier (no kernel).
    pub fn with_verifier(verifier: V) -> Self {
        Settle {
            guard: Guard::new(),
            verifier,
            settled_ids: HashSet::new(),
            settled_order: VecDeque::new(),
        }
    }

    /// Register a root as trusted in the local verifier.
    pub fn register_root(&mut self, root: Tip5Hash) -> Result<(), crate::guard::GuardError> {
        self.guard.register_root(root)
    }

    /// Settle a payload: verify via the CommitmentVerifier + state transition.
    ///
    /// Pre-flight checks catch common failures before the kernel sees the
    /// payload. If a poke still crashes after pre-flight, the input violated
    /// a kernel guard that these checks don't cover.
    ///
    /// The SDK builds the poke but does not dispatch it — the hull owns the
    /// NockApp handle. Callers use `poke_bytes()` to get the JAM'd poke for
    /// dispatch, or call `settle()` for local verification only.
    pub async fn settle(&mut self, payload: &GraftPayload) -> Result<Note> {
        // Pre-flight: root registration
        anyhow::ensure!(
            self.guard.is_registered(&payload.expected_root),
            "root not registered: {}",
            crate::types::format_tip5(&payload.expected_root),
        );

        // Pre-flight: duplicate settlement
        anyhow::ensure!(
            !self.settled_ids.contains(&payload.note.id),
            "duplicate settlement: note {} already settled",
            payload.note.id,
        );

        // Pre-flight: note must be pending
        anyhow::ensure!(
            matches!(payload.note.state, crate::types::NoteState::Pending),
            "note {} is not pending (current state: {:?})",
            payload.note.id,
            payload.note.state,
        );

        // Domain verification — note_id passed so gates can enforce
        // pre-commit binding (AUDIT H-03).
        anyhow::ensure!(
            self.verifier
                .verify(payload.note.id, &payload.data, &payload.expected_root),
            "verification failed for note {}",
            payload.note.id,
        );

        let _poke: NounSlab = self.verifier.build_settle_poke(payload)?;

        // Poke is built but not dispatched — kernel interaction needs a
        // NockApp handle, which the hull owns. Use `poke_bytes()` to get
        // the serialized poke for hull-side dispatch.
        // AUDIT 2026-05-19 H-07: bound the pre-flight cache — evict the
        // oldest id once at capacity so a long-running hull does not
        // leak unbounded replay state.
        if self.settled_ids.len() >= SETTLED_IDS_CAP
            && let Some(old) = self.settled_order.pop_front()
        {
            self.settled_ids.remove(&old);
        }
        if self.settled_ids.insert(payload.note.id) {
            self.settled_order.push_back(payload.note.id);
        }
        Ok(Note {
            id: payload.note.id,
            hull: payload.note.hull,
            root: payload.note.root,
            state: crate::types::NoteState::Settled,
        })
    }

    /// Build the settle poke as JAM bytes for hull-side kernel dispatch.
    ///
    /// The SDK cannot dispatch pokes directly — the hull owns the NockApp
    /// handle. This method returns the serialized poke so callers can feed
    /// it to `NockApp::poke()` themselves.
    pub fn poke_bytes(&self, payload: &GraftPayload) -> Result<Vec<u8>> {
        // AUDIT 2026-05-21 L-05: bound the payload before building the poke
        // so an oversized `data` vector can't drive an unbounded JAM alloc.
        anyhow::ensure!(
            payload.data.len() <= MAX_POKE_DATA_BYTES,
            "graft payload data is {} bytes, over the {MAX_POKE_DATA_BYTES}-byte cap",
            payload.data.len()
        );
        let slab = self.verifier.build_settle_poke(payload)?;
        Ok(nock_noun_rs::slab_jam_to_bytes(&slab))
    }

    /// Access the inner Guard verifier.
    pub fn guard(&self) -> &Guard {
        &self.guard
    }

    /// Access the inner CommitmentVerifier.
    pub fn verifier(&self) -> &V {
        &self.verifier
    }
}

// ---------------------------------------------------------------------------
// Composable settlement helpers — free functions
// ---------------------------------------------------------------------------

/// Build the output Seed for a settlement transaction.
///
/// Constructs a single Seed with the given NoteData, lock, gift amount,
/// and parent hash. The caller encodes domain-specific data into NoteData
/// before calling this.
pub fn build_seeds(
    lock_root: nockchain_types::tx_engine::common::Hash,
    note_data: nockchain_types::tx_engine::v1::note::NoteData,
    parent_hash: nockchain_types::tx_engine::common::Hash,
    amount: u64,
    fee: u64,
) -> Result<nockchain_types::tx_engine::v1::tx::Seeds> {
    anyhow::ensure!(
        fee <= amount / 2,
        "fee ({fee}) exceeds 50% of input amount ({amount})"
    );
    let output_amount = amount.saturating_sub(fee);
    // AUDIT 2026-05-20 M-22: u64 -> usize is lossless on 64-bit but
    // truncates on a 32-bit target (e.g. wasm32). Convert explicitly so an
    // overflow surfaces as an error, not a silently wrong gift amount.
    let gift_nicks = usize::try_from(output_amount)
        .map_err(|_| anyhow::anyhow!("output amount {output_amount} exceeds usize"))?;
    use nockchain_types::tx_engine::v1::tx::Seed;
    let seed = Seed {
        output_source: None,
        lock_root,
        note_data,
        gift: nockchain_types::tx_engine::common::Nicks(gift_nicks),
        parent_hash,
    };
    Ok(nockchain_types::tx_engine::v1::tx::Seeds(vec![seed]))
}

/// Sign a sig-hash with a secret key.
///
/// Takes the tip5 hash from `kernel_sig_hash` and produces a Schnorr signature.
pub fn sign_tx(
    signing_key: &[nockchain_math::belt::Belt; 8],
    sig_hash: &nockchain_types::tx_engine::common::Hash,
) -> Result<nockchain_types::tx_engine::common::SchnorrSignature> {
    let msg_belts = sig_hash.to_array().map(nockchain_math::belt::Belt);
    crate::signing::sign(signing_key, &msg_belts)
        .map_err(|e| anyhow::anyhow!("signing failed: {e}"))
}

/// Build a Witness proving authorization to spend an input UTXO.
pub fn build_witness(
    signing_key: &[nockchain_math::belt::Belt; 8],
    sig_hash: &nockchain_types::tx_engine::common::Hash,
    is_coinbase: bool,
    coinbase_timelock_min: u64,
) -> Result<nockchain_types::tx_engine::v1::tx::Witness> {
    use nockchain_types::tx_engine::v1::tx::*;

    let pubkey = crate::signing::derive_pubkey(signing_key)
        .map_err(|e| anyhow::anyhow!("pubkey derivation failed: {e}"))?;
    let pkh = crate::signing::pubkey_hash(&pubkey)
        .map_err(|e| anyhow::anyhow!("pubkey hash failed: {e}"))?;

    let input_condition = if is_coinbase {
        SpendCondition::coinbase_pkh(pkh.clone(), coinbase_timelock_min)
    } else {
        SpendCondition::simple_pkh(pkh.clone())
    };
    let input_lock_root = Lock::SpendCondition(input_condition.clone())
        .hash()
        .map_err(|e| anyhow::anyhow!("input lock hash failed: {e}"))?;

    let signature = sign_tx(signing_key, sig_hash)?;

    let lock_merkle_proof = LockMerkleProofFull {
        version: nockvm_macros::tas!(b"full"),
        spend_condition: input_condition,
        axis: 1,
        proof: MerkleProof {
            root: input_lock_root,
            path: vec![],
        },
    };

    let pkh_sig_entry = PkhSignatureEntry {
        pkh,
        pubkey,
        signature,
    };

    Ok(Witness::new(
        LockMerkleProof::Full(lock_merkle_proof),
        PkhSignature::new(vec![pkh_sig_entry]),
        vec![],
    ))
}

/// Submit a transaction to the chain and optionally wait for acceptance.
///
/// Returns `true` if accepted, `false` if timed out (when `wait` is true).
/// Returns `true` immediately after submission (when `wait` is false).
pub async fn submit_tx(
    chain: &mut ChainClient,
    raw_tx: nockchain_types::tx_engine::v1::RawTx,
    tx_id_b58: &str,
    wait: bool,
) -> Result<bool> {
    if wait {
        chain.submit_and_wait(raw_tx, tx_id_b58).await
    } else {
        chain.submit_transaction(raw_tx).await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GraftPayload, NoteState};

    /// Mock verifier — proves Settle is parameterized cleanly over any
    /// `CommitmentVerifier`. Concrete domain verifiers (RAG, KV, log, etc.)
    /// live in downstream hulls.
    struct MockVerifier {
        should_pass: bool,
    }

    impl CommitmentVerifier for MockVerifier {
        fn verify(&self, _note_id: u64, _data: &[u8], _expected_root: &Tip5Hash) -> bool {
            self.should_pass
        }

        fn build_settle_poke(&self, payload: &GraftPayload) -> anyhow::Result<NounSlab> {
            // Minimal poke: just tag + note id
            use nock_noun_rs::*;
            let mut slab = NounSlab::new();
            let tag = make_atom_in(&mut slab, b"settle");
            let id = nockvm::noun::D(payload.note.id);
            let poke = nockvm::noun::T(&mut slab, &[tag, id]);
            slab.set_root(poke);
            Ok(slab)
        }
    }

    #[tokio::test]
    async fn settle_with_mock_verifier_pass() {
        let root: Tip5Hash = [1, 2, 3, 4, 5];
        let mut settler = Settle::with_verifier(MockVerifier { should_pass: true });
        settler.register_root(root).unwrap();

        let payload = GraftPayload {
            note: Note {
                id: 1,
                hull: 7,
                root,
                state: NoteState::Pending,
            },
            data: vec![],
            expected_root: root,
        };

        let result = settler.settle(&payload).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap().state, NoteState::Settled));
    }

    #[tokio::test]
    async fn settle_with_mock_verifier_fail() {
        let root: Tip5Hash = [1, 2, 3, 4, 5];
        let mut settler = Settle::with_verifier(MockVerifier { should_pass: false });
        settler.register_root(root).unwrap();

        let payload = GraftPayload {
            note: Note {
                id: 1,
                hull: 7,
                root,
                state: NoteState::Pending,
            },
            data: vec![],
            expected_root: root,
        };

        let result = settler.settle(&payload).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn settle_unregistered_root_fails() {
        let mut settler = Settle::with_verifier(MockVerifier { should_pass: true });
        // Don't register any root

        let payload = GraftPayload {
            note: Note {
                id: 1,
                hull: 7,
                root: [9, 9, 9, 9, 9],
                state: NoteState::Pending,
            },
            data: vec![],
            expected_root: [9, 9, 9, 9, 9],
        };

        let result = settler.settle(&payload).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("root not registered")
        );
    }

    // --- Pre-flight validation tests ---

    #[tokio::test]
    async fn settle_duplicate_note_rejected() {
        let root: Tip5Hash = [1, 2, 3, 4, 5];
        let mut settler = Settle::with_verifier(MockVerifier { should_pass: true });
        settler.register_root(root).unwrap();

        let payload = GraftPayload {
            note: Note {
                id: 1,
                hull: 7,
                root,
                state: NoteState::Pending,
            },
            data: vec![],
            expected_root: root,
        };

        // First settle succeeds
        assert!(settler.settle(&payload).await.is_ok());

        // Second settle with same note ID fails
        let result = settler.settle(&payload).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("duplicate settlement"), "got: {err}");
        assert!(err.contains("note 1"), "got: {err}");
    }

    #[tokio::test]
    async fn settle_non_pending_note_rejected() {
        let root: Tip5Hash = [1, 2, 3, 4, 5];
        let mut settler = Settle::with_verifier(MockVerifier { should_pass: true });
        settler.register_root(root).unwrap();

        let payload = GraftPayload {
            note: Note {
                id: 1,
                hull: 7,
                root,
                state: NoteState::Settled,
            },
            data: vec![],
            expected_root: root,
        };

        let result = settler.settle(&payload).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not pending"), "got: {err}");
    }

    #[test]
    fn poke_bytes_produces_nonempty() {
        let root: Tip5Hash = [1, 2, 3, 4, 5];
        let settler = Settle::with_verifier(MockVerifier { should_pass: true });

        let payload = GraftPayload {
            note: Note {
                id: 1,
                hull: 7,
                root,
                state: NoteState::Pending,
            },
            data: vec![],
            expected_root: root,
        };

        let bytes = settler.poke_bytes(&payload).unwrap();
        assert!(!bytes.is_empty(), "poke_bytes must produce non-empty JAM");
    }

    // --- Tests for composable helpers ---

    #[test]
    fn build_seeds_valid() {
        use nockchain_math::owned_based_noun::OwnedBasedNoun;
        use nockchain_types::tx_engine::common::Hash;
        use nockchain_types::tx_engine::v1::note::{NoteData, NoteDataEntry};

        let note_data = NoteData::new(vec![NoteDataEntry::new(
            "test".to_string(),
            OwnedBasedNoun::try_atom(1).unwrap(),
        )]);
        let lock_root = Hash::from_limbs(&[1, 2, 3, 4, 5]);
        let parent = Hash::from_limbs(&[10, 20, 30, 40, 50]);

        let seeds = build_seeds(lock_root, note_data, parent, 100_000, 256).unwrap();
        assert_eq!(seeds.0.len(), 1);
        assert_eq!(seeds.0[0].gift.0, 99_744); // 100000 - 256
    }

    #[test]
    fn build_seeds_excessive_fee_rejected() {
        use nockchain_math::owned_based_noun::OwnedBasedNoun;
        use nockchain_types::tx_engine::common::Hash;
        use nockchain_types::tx_engine::v1::note::{NoteData, NoteDataEntry};

        let note_data = NoteData::new(vec![NoteDataEntry::new(
            "test".to_string(),
            OwnedBasedNoun::try_atom(1).unwrap(),
        )]);
        let lock_root = Hash::from_limbs(&[1, 2, 3, 4, 5]);
        let parent = Hash::from_limbs(&[10, 20, 30, 40, 50]);

        let result = build_seeds(lock_root, note_data, parent, 100, 60);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fee"));
    }

    #[test]
    fn sign_tx_produces_signature() {
        use nockchain_math::belt::Belt;
        use nockchain_types::tx_engine::common::Hash;

        let mut sk = [Belt(0); 8];
        sk[0] = Belt(12345);
        sk[1] = Belt(67890);

        let hash = Hash::from_limbs(&[1, 2, 3, 4, 5]);
        let sig = sign_tx(&sk, &hash).unwrap();
        // Signature components must be non-zero
        assert!(sig.chal.iter().any(|b| b.0 != 0));
        assert!(sig.sig.iter().any(|b| b.0 != 0));
    }

    #[test]
    fn build_witness_produces_valid_witness() {
        use nockchain_math::belt::Belt;
        use nockchain_types::tx_engine::common::Hash;

        let mut sk = [Belt(0); 8];
        sk[0] = Belt(42);

        let hash = Hash::from_limbs(&[9, 8, 7, 6, 5]);
        let witness = build_witness(&sk, &hash, false, 1).unwrap();
        // Witness was constructed without error
        let _ = witness;
    }
}
