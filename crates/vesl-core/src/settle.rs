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
///
/// ⛔⛔ **SINGLE-CONDITION LOCKS ONLY, AND THE GUARD IS AN IDENTITY CHECK,
/// NOT A TYPE CHECK.** This helper never receives a `Lock` — it takes
/// `is_coinbase` and *constructs* the input's spend-condition itself. So it
/// cannot "refuse a multi-branch lock": handed a note whose real lock is the
/// four-branch hold (`crate::lock::hold_lock`), it would happily build a
/// proof for a lock that is not the note's, and consensus would refuse the
/// spend **naming nothing** — the witness's merkle root simply would not
/// match the note's first-name (`tx-engine-1.hoon:2012-2016`).
///
/// `input_first_name` closes that: the caller passes the note's committed
/// first-name, and we refuse unless the lock we assumed derives it. That is
/// the guard `vesl-labs/services/chain/src/bounty_tx.rs` already uses, and it
/// fails closed **with a cause**, which a type check on a value we never see
/// could not do.
pub fn build_witness(
    signing_key: &[nockchain_math::belt::Belt; 8],
    sig_hash: &nockchain_types::tx_engine::common::Hash,
    is_coinbase: bool,
    coinbase_timelock_min: u64,
    input_first_name: &nockchain_types::tx_engine::common::Hash,
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
    let input_lock = Lock::SpendCondition(input_condition.clone());
    let input_lock_root = input_lock
        .hash()
        .map_err(|e| anyhow::anyhow!("input lock hash failed: {e}"))?;

    // ⛔ The note is what it is; this helper only assumed a shape. Refuse
    // before signing if the assumption does not reproduce the note's own
    // first-name — otherwise the mismatch surfaces at consensus as a silent
    // refusal with no cause attached.
    let derived_first = crate::lock::first_name_for_lock(&input_lock)?;
    anyhow::ensure!(
        &derived_first == input_first_name,
        "input note's first-name does not derive from this key's          single-condition lock (wrong key, wrong coinbase flag, or a          multi-branch note this builder cannot spend)"
    );

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

/// One party's contribution to a hold spend: a signing key.
pub type HoldSigner = [nockchain_math::belt::Belt; 8];

/// Build the witness that spends one branch of the buyer's hold
/// (`crate::lock::hold_lock`, `XD-3`).
///
/// ⚑ *In plain terms: this assembles the paperwork for moving the buyer's
/// parked money — which branch is being used, who signed, and (for a capture)
/// the key that decrypts the answer.*
///
/// ⛔⛔ **EVERY REFUSAL BELOW IS ALSO A CONSENSUS REFUSAL — the difference is
/// that this one names a cause.** A node acks an invalid transaction and
/// discards it silently (`vesl-miner/examples/submit_settlement_devnet.rs`),
/// so a witness that is wrong on any of these counts becomes a spend that
/// simply never lands, with nothing to read. Checking here converts each into
/// a message.
///
/// What is checked, and against what:
///
/// - **the signer count equals the branch's `m`.** `check:pkh` compares the
///   witness map's size with `~(wyt z-by …)` for **equality**
///   (`tx-engine-1.hoon:2069`), so one signature on a 2-of-2 is not a weaker
///   two — it is a different count, and it fails. ⚑ The map is keyed by
///   pubkey-hash, so a **repeated signer is one entry**, not two; that is
///   checked here too, because it silently reduces a 2-of-2 to a 1-of-1.
/// - **every signer is a member of the branch's set** (`:2071`).
/// - **every `%hax` hash the branch names has a preimage present**
///   (`:2112-2119` demands one for *every* member). ⛔ This is the delivery
///   condition: a capture assembled without the key is refused here rather
///   than vanishing at a node.
///
/// ⛔ Not checked, because this function cannot see it: that `sig_hash` is the
/// digest of the spend you intend. It covers the seeds and the fee and nothing
/// else (`tx-engine-1.hoon:1116-1120`), so a signature is branch-agnostic —
/// the caller must compute it over the real output set.
pub fn build_hold_witness(
    lock: &nockchain_types::tx_engine::v1::tx::Lock,
    branch: u64,
    height: u64,
    bythos_phase: u64,
    signers: &[HoldSigner],
    sig_hash: &nockchain_types::tx_engine::common::Hash,
    hax: Vec<nockchain_types::tx_engine::v1::tx::HaxPreimage>,
) -> Result<nockchain_types::tx_engine::v1::tx::Witness> {
    use nockchain_types::tx_engine::v1::tx::{
        LockPrimitive, PkhSignature, PkhSignatureEntry, Witness,
    };

    let lmp = crate::lock::lock_merkle_proof(lock, branch, height, bythos_phase)?;
    let condition = lmp.spend_condition().clone();

    // The `%pkh` conjunct, if the branch has one. `check:pkh` refuses two in
    // one AND-list anyway (each would demand the whole map), so at most one.
    let pkh_rule = condition.iter().find_map(|p| match p {
        LockPrimitive::Pkh(pkh) => Some(pkh),
        _ => None,
    });

    let entries = if let Some(rule) = pkh_rule {
        let permitted: Vec<_> = rule.hashes.iter().cloned().collect();
        anyhow::ensure!(
            signers.len() as u64 == rule.m,
            "branch {branch} is {}-of-{}: it needs exactly {} signature(s), got {}",
            rule.m,
            permitted.len(),
            rule.m,
            signers.len()
        );
        let mut entries: Vec<PkhSignatureEntry> = Vec::with_capacity(signers.len());
        for sk in signers {
            let pubkey = crate::signing::derive_pubkey(sk)
                .map_err(|e| anyhow::anyhow!("pubkey derivation failed: {e}"))?;
            let pkh = crate::signing::pubkey_hash(&pubkey)
                .map_err(|e| anyhow::anyhow!("pubkey hash failed: {e}"))?;
            anyhow::ensure!(
                permitted.contains(&pkh),
                "a signer is not named by branch {branch}'s %pkh set"
            );
            // ⛔ The witness half is a MAP keyed by pkh, so the same signer
            // twice collapses to one entry and the count check upstream would
            // pass while consensus sees a 1-of-1.
            anyhow::ensure!(
                !entries.iter().any(|e| e.pkh == pkh),
                "the same signer was supplied twice; a repeated signer is ONE \
                 entry in the witness map, not two"
            );
            entries.push(PkhSignatureEntry {
                pkh,
                pubkey,
                signature: sign_tx(sk, sig_hash)?,
            });
        }
        entries
    } else {
        anyhow::ensure!(
            signers.is_empty(),
            "branch {branch} carries no %pkh conjunct, so it takes no signatures"
        );
        Vec::new()
    };

    // The delivery condition. Fail closed on a missing preimage: this is the
    // one refusal the whole row exists to make certain of.
    for primitive in condition.iter() {
        if let LockPrimitive::Hax(set) = primitive {
            for wanted in set.0.iter() {
                let entry = hax.iter().find(|e| &e.hash == wanted).ok_or_else(|| {
                    anyhow::anyhow!(
                        "branch {branch} requires a hashlock preimage that this \
                         witness does not carry — a capture must publish the key"
                    )
                })?;
                // ⛔ And it must be the RIGHT preimage. `check:hax` recomputes
                // the digest structurally over the value (`:2112-2119`) and
                // compares; a mislabelled entry is a spend that vanishes at a
                // node with nothing to read.
                let digest = nockchain_types::tx_engine::common::Hash::from_limbs(
                    &entry.value.hashable_noun_digest(),
                );
                anyhow::ensure!(
                    &digest == wanted,
                    "the hashlock preimage does not hash to the value branch \
                     {branch} names"
                );
            }
        }
    }

    Ok(Witness::new(lmp, PkhSignature::new(entries), hax))
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
        let pubkey = crate::signing::derive_pubkey(&sk).unwrap();
        let pkh = crate::signing::pubkey_hash(&pubkey).unwrap();
        let first = crate::lock::first_name_for_lock(
            &nockchain_types::tx_engine::v1::tx::Lock::SpendCondition(
                nockchain_types::tx_engine::v1::tx::SpendCondition::simple_pkh(pkh),
            ),
        )
        .unwrap();
        let witness = build_witness(&sk, &hash, false, 1, &first).unwrap();

        // ⛔ The guard, exercised: the same key against a note that is not
        // its own must refuse, and say why.
        let wrong = nockchain_types::tx_engine::common::Hash::from_limbs(&[9, 9, 9, 9, 9]);
        let err = build_witness(&sk, &hash, false, 1, &wrong).unwrap_err();
        assert!(err.to_string().contains("does not derive"), "{err}");
        // Witness was constructed without error
        let _ = witness;
    }

    // -----------------------------------------------------------------------
    // The hold spend builder — every refusal exercised. A derived register is
    // an untested arm.
    // -----------------------------------------------------------------------

    fn hold_fixture() -> (
        nockchain_types::tx_engine::v1::tx::Lock,
        [nockchain_math::belt::Belt; 8],
        [nockchain_math::belt::Belt; 8],
        nockchain_types::tx_engine::v1::tx::HaxPreimage,
    ) {
        use nockchain_math::owned_based_noun::OwnedBasedNoun;
        use nockchain_types::tx_engine::common::Hash;
        use nockchain_types::tx_engine::v1::tx::HaxPreimage;

        let mk = |seed: u64| {
            let mut sk = [nockchain_math::belt::Belt(0); 8];
            sk[0] = nockchain_math::belt::Belt(seed);
            sk
        };
        let (buyer_sk, platform_sk) = (mk(11), mk(23));
        let pkh_of = |sk: &[nockchain_math::belt::Belt; 8]| {
            crate::signing::pubkey_hash(&crate::signing::derive_pubkey(sk).unwrap()).unwrap()
        };

        // A minimal, self-consistent preimage: the lock names exactly the
        // digest of the value the witness will carry.
        let value = OwnedBasedNoun::Cell(
            Box::new(OwnedBasedNoun::Atom(nockchain_math::belt::Belt(
                0xdead_beef,
            ))),
            Box::new(OwnedBasedNoun::Atom(nockchain_math::belt::Belt(0x1234))),
        );
        let h_k = Hash::from_limbs(&value.hashable_noun_digest());
        let preimage = HaxPreimage {
            hash: h_k.clone(),
            value,
        };
        let lock = crate::lock::hold_lock(pkh_of(&buyer_sk), pkh_of(&platform_sk), h_k, 4);
        (lock, buyer_sk, platform_sk, preimage)
    }

    fn sh() -> nockchain_types::tx_engine::common::Hash {
        nockchain_types::tx_engine::common::Hash::from_limbs(&[11, 22, 33, 44, 55])
    }

    #[test]
    fn a_capture_witness_needs_both_signatures_and_the_key() {
        let (lock, buyer, platform, preimage) = hold_fixture();
        let b = crate::lock::HOLD_BRANCH_CAPTURE;

        // ✅ Both signatures and the key.
        let w = build_hold_witness(
            &lock,
            b,
            10,
            1,
            &[buyer, platform],
            &sh(),
            vec![preimage.clone()],
        )
        .expect("the honest capture must build");
        assert_eq!(w.pkh_signature.0.len(), 2, "a 2-of-2 needs two entries");
        assert_eq!(w.hax.len(), 1);

        // ⛔ Without the key — the delivery condition, refused before it can
        // vanish at a node.
        let err = build_hold_witness(&lock, b, 10, 1, &[buyer, platform], &sh(), vec![])
            .unwrap_err()
            .to_string();
        assert!(err.contains("must publish the key"), "{err}");

        // ⛔ With the wrong key.
        let mut wrong = preimage.clone();
        wrong.hash = nockchain_types::tx_engine::common::Hash::from_limbs(&[1, 2, 3, 4, 5]);
        let err = build_hold_witness(&lock, b, 10, 1, &[buyer, platform], &sh(), vec![wrong])
            .unwrap_err()
            .to_string();
        assert!(err.contains("must publish the key"), "{err}");

        // ⛔ With a preimage whose value does not hash to what the lock names.
        let mut mislabelled = preimage.clone();
        mislabelled.value =
            nockchain_math::owned_based_noun::OwnedBasedNoun::Atom(nockchain_math::belt::Belt(7));
        let err = build_hold_witness(
            &lock,
            b,
            10,
            1,
            &[buyer, platform],
            &sh(),
            vec![mislabelled],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not hash to"), "{err}");
    }

    #[test]
    fn the_two_of_two_refuses_one_signature_and_a_repeated_signer() {
        let (lock, buyer, platform, preimage) = hold_fixture();
        for b in [crate::lock::HOLD_BRANCH_CAPTURE, crate::lock::HOLD_BRANCH_VOID] {
            // ⛔ One signature is not a weaker two — `check:pkh` compares the
            // map size for EQUALITY.
            let err = build_hold_witness(&lock, b, 10, 1, &[buyer], &sh(), vec![preimage.clone()])
                .unwrap_err()
                .to_string();
            assert!(err.contains("2-of-2"), "{err}");

            // ⛔⛔ The same signer twice. The witness half is a MAP keyed by
            // pkh, so this is ONE entry at consensus — a silent downgrade of a
            // 2-of-2 to a 1-of-1, which no test of the honest path can show.
            let err = build_hold_witness(
                &lock,
                b,
                10,
                1,
                &[buyer, buyer],
                &sh(),
                vec![preimage.clone()],
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("supplied twice"), "{err}");
            let _ = platform;
        }
    }

    #[test]
    fn a_stranger_cannot_sign_a_hold_branch() {
        let (lock, buyer, _platform, preimage) = hold_fixture();
        let mut stranger = [nockchain_math::belt::Belt(0); 8];
        stranger[0] = nockchain_math::belt::Belt(99);
        let err = build_hold_witness(
            &lock,
            crate::lock::HOLD_BRANCH_CAPTURE,
            10,
            1,
            &[buyer, stranger],
            &sh(),
            vec![preimage],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not named by"), "{err}");
    }

    #[test]
    fn the_reclaim_branch_takes_the_buyer_alone_and_no_key() {
        let (lock, buyer, platform, _preimage) = hold_fixture();
        let b = crate::lock::HOLD_BRANCH_RECLAIM;
        let w = build_hold_witness(&lock, b, 10, 1, &[buyer], &sh(), vec![])
            .expect("the buyer's recovery must build");
        assert_eq!(w.pkh_signature.0.len(), 1);
        assert!(w.hax.is_empty(), "a reclaim publishes nothing");

        // ⛔ It is 1-of-1 over the buyer, so the platform is not a member and
        // two signatures are the wrong count.
        assert!(build_hold_witness(&lock, b, 10, 1, &[platform], &sh(), vec![]).is_err());
        assert!(build_hold_witness(&lock, b, 10, 1, &[buyer, platform], &sh(), vec![]).is_err());
    }

    /// The padding branch carries no `%pkh` at all, so it takes no signatures —
    /// and it is unspendable at consensus regardless (`%brn` answers `%|`).
    /// Building a witness for it must not look like authorization.
    #[test]
    fn the_padding_branch_takes_no_signatures() {
        let (lock, buyer, _p, _k) = hold_fixture();
        let b = crate::lock::HOLD_BRANCH_PADDING;
        assert!(build_hold_witness(&lock, b, 10, 1, &[buyer], &sh(), vec![]).is_err());
        let w = build_hold_witness(&lock, b, 10, 1, &[], &sh(), vec![]).expect("no signers");
        assert!(w.pkh_signature.0.is_empty());
    }
}
