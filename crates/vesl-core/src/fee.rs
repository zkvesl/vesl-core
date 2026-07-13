//! Exact minimum-fee computation for v1 transactions.
//!
//! Mirrors `calculate-min-fee` and the word-counting arms of the Hoon
//! tx-engine: seed words are the leaf count of the note-data folded
//! per lock-root (merged across the transaction at or after the
//! bythos phase, per-seed before it), witness words are the leaf
//! count of each spend's whole witness noun, and
//! `min-fee = max(seed-fee + witness-fee, floor)` with the base fee
//! doubled pre-bythos and the witness discounted by the input-fee
//! divisor post-bythos.
//!
//! The upstream Rust estimator (`wallet-tx-builder::word_count`)
//! prices `hax` at a single word and cannot cost a proof-carrying
//! witness; this module counts the actual nouns.

use std::collections::BTreeMap;

use nockapp::noun::slab::NounSlab;
use nockchain_types::blockchain_constants::{
    BlockchainConstants, FAKENET_BASE_FEE, FAKENET_BYTHOS_PHASE,
};
use nockchain_types::tx_engine::v1::note::{NoteData, NoteDataValue};
use nockchain_types::tx_engine::v1::tx::{Spend, Spends};
use nockvm::noun::{Noun, NounAllocator, NounSpace};
use noun_serde::NounEncode;

/// The fee parameters consensus prices a transaction against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeConstants {
    pub base_fee: u64,
    pub input_fee_divisor: u64,
    pub min_fee: u64,
    pub bythos_phase: u64,
}

impl FeeConstants {
    /// Fakenet constants: bythos active from height 1, base fee 128.
    pub fn fakenet() -> Self {
        Self {
            base_fee: FAKENET_BASE_FEE,
            input_fee_divisor: BlockchainConstants::DEFAULT_INPUT_FEE_DIVISOR,
            min_fee: BlockchainConstants::DEFAULT_NOTE_DATA_MIN_FEE,
            bythos_phase: FAKENET_BYTHOS_PHASE,
        }
    }

    /// Mainnet defaults: bythos at 54k, base fee 2^14.
    pub fn mainnet() -> Self {
        Self {
            base_fee: BlockchainConstants::DEFAULT_BASE_FEE,
            input_fee_divisor: BlockchainConstants::DEFAULT_INPUT_FEE_DIVISOR,
            min_fee: BlockchainConstants::DEFAULT_NOTE_DATA_MIN_FEE,
            bythos_phase: BlockchainConstants::DEFAULT_BYTHOS_PHASE,
        }
    }
}

/// Atom count of a noun (`num-of-leaves:shape`). Iterative — witness
/// nouns carrying a STARK proof run to millions of cells, far past any
/// safe recursion depth.
pub fn num_of_leaves(noun: Noun, space: &NounSpace) -> u64 {
    let mut count = 0u64;
    let mut stack = vec![noun];
    while let Some(n) = stack.pop() {
        match n.as_cell() {
            Ok(cell) => {
                let cell = cell.in_space(space);
                stack.push(cell.head().noun());
                stack.push(cell.tail().noun());
            }
            Err(_) => count += 1,
        }
    }
    count
}

/// Seed word count (`count-seed-words`).
///
/// At or after the bythos phase, note-data is merged per lock-root
/// across every seed in the transaction (`count-seed-words-merged`);
/// before it, each seed is priced alone (`count-seed-words-legacy`).
/// Either way a note-data group costs the leaf count of the Hoon
/// `rep`-fold noun `[k1 v1 [k2 v2 ... 0]]`: one leaf for the fold's
/// terminal atom plus, per entry, one key leaf and the leaves of the
/// value noun.
///
/// Key collisions across merged seeds keep one value (z-map union
/// bias); the builders in this workspace never produce two seeds
/// sharing a lock-root and a note-data key.
pub fn count_seed_words(spends: &Spends, height: u64, bythos_phase: u64) -> anyhow::Result<u64> {
    let mut groups: BTreeMap<[u64; 5], BTreeMap<String, u64>> = BTreeMap::new();
    let mut legacy_words = 0u64;
    for (_, spend) in &spends.0 {
        let seeds = match spend {
            Spend::Witness(s1) => &s1.seeds,
            Spend::Legacy(s0) => &s0.seeds,
        };
        for seed in &seeds.0 {
            if height >= bythos_phase {
                let group = groups.entry(seed.lock_root.to_array()).or_default();
                for entry in seed.note_data.iter() {
                    group.insert(entry.key.clone(), value_leaves(&entry.value)?);
                }
            } else {
                legacy_words += note_data_words(&seed.note_data)?;
            }
        }
    }
    if height >= bythos_phase {
        let mut words = 0u64;
        for group in groups.values() {
            // The rep-fold terminus is a single atom.
            words += 1;
            for leaves in group.values() {
                words += 1 + leaves;
            }
        }
        Ok(words)
    } else {
        Ok(legacy_words)
    }
}

fn note_data_words(note_data: &NoteData) -> anyhow::Result<u64> {
    let mut words = 1u64;
    for entry in note_data.iter() {
        words += 1 + value_leaves(&entry.value)?;
    }
    Ok(words)
}

/// Leaf count of a note-data value.
///
/// A generic value already *is* a based noun, so it is counted directly.
/// The typed payloads (`lock`, `bridge`, `bridge-w`) encode through a path
/// `nockchain-types` keeps crate-private; the jammed form it does expose is
/// the only way in, so those are cue'd back. Both arms count the same noun
/// the chain prices.
fn value_leaves(value: &NoteDataValue) -> anyhow::Result<u64> {
    let mut slab: NounSlab = NounSlab::new();
    let noun = match value {
        NoteDataValue::Noun(noun) => noun.to_noun(&mut slab),
        typed => slab
            .cue_into(typed.raw_blob())
            .map_err(|e| anyhow::anyhow!("cue note-data value: {e:?}"))?,
    };
    let space = slab.noun_space();
    Ok(num_of_leaves(noun, &space))
}

/// Witness word count (`count-witness-words-raw`): the leaf count of
/// each spend's whole witness noun (legacy spends count the signature
/// noun instead).
pub fn count_witness_words(spends: &Spends) -> u64 {
    let mut words = 0u64;
    for (_, spend) in &spends.0 {
        let mut slab: NounSlab = NounSlab::new();
        let noun = match spend {
            Spend::Witness(s1) => s1.witness.to_noun(&mut slab),
            Spend::Legacy(s0) => s0.signature.to_noun(&mut slab),
        };
        let space = slab.noun_space();
        words += num_of_leaves(noun, &space);
    }
    words
}

/// Minimum fee for the transaction at `height` (`calculate-min-fee`).
///
/// Saturating like the upstream planner: a saturated result is far
/// beyond any spendable balance and fails conservation long before it
/// matters here.
pub fn calculate_min_fee(
    spends: &Spends,
    height: u64,
    constants: &FeeConstants,
) -> anyhow::Result<u64> {
    let bythos_active = height >= constants.bythos_phase;
    let effective_base_fee = if bythos_active {
        constants.base_fee
    } else {
        constants.base_fee.saturating_mul(2)
    };
    let witness_divisor = if bythos_active {
        constants.input_fee_divisor.max(1)
    } else {
        1
    };
    let seed_words = count_seed_words(spends, height, constants.bythos_phase)?;
    let witness_words = count_witness_words(spends);
    let seed_fee = seed_words.saturating_mul(effective_base_fee);
    let witness_fee = witness_words.saturating_mul(effective_base_fee) / witness_divisor;
    Ok(seed_fee.saturating_add(witness_fee).max(constants.min_fee))
}

#[cfg(test)]
mod tests {
    use nockchain_math::owned_based_noun::OwnedBasedNoun;
    use nockchain_types::tx_engine::common::{Hash, Name, Nicks};
    use nockchain_types::tx_engine::v1::note::NoteDataEntry;
    use nockchain_types::tx_engine::v1::tx::{
        LockMerkleProof, MerkleProof, PkhSignature, Seed, Seeds, Spend1, SpendCondition, Witness,
    };

    use super::*;

    fn hash(n: u64) -> Hash {
        Hash::from_limbs(&[n, n + 1, n + 2, n + 3, n + 4])
    }

    fn seed(lock_root: Hash, note_data: NoteData) -> Seed {
        Seed {
            output_source: None,
            lock_root,
            note_data,
            gift: Nicks(10),
            parent_hash: hash(90),
        }
    }

    fn atom(value: u64) -> OwnedBasedNoun {
        OwnedBasedNoun::try_atom(value).unwrap()
    }

    fn single_spend(seeds: Seeds) -> Spends {
        let sc = SpendCondition::simple_pkh(hash(1));
        let root = sc.hash().unwrap();
        let witness = Witness::new(
            LockMerkleProof::new_stub(sc, 1, MerkleProof { root, path: vec![] }),
            PkhSignature::new(vec![]),
            vec![],
        );
        let spend = Spend::Witness(Spend1 {
            witness,
            seeds,
            fee: Nicks(0),
        });
        Spends(vec![(Name::new(hash(2), hash(3)), spend)])
    }

    #[test]
    fn empty_note_data_costs_one_word_per_lock_root() {
        let seeds = Seeds(vec![
            seed(hash(10), NoteData::new(vec![])),
            seed(hash(20), NoteData::new(vec![])),
        ]);
        let spends = single_spend(seeds);
        assert_eq!(count_seed_words(&spends, 1, 1).unwrap(), 2);
    }

    #[test]
    fn merged_counting_folds_same_lock_root_seeds_together() {
        let entry = NoteDataEntry::new("vesl-k".into(), atom(7));
        let a = seed(hash(10), NoteData::new(vec![entry.clone()]));
        let b = seed(hash(10), NoteData::new(vec![entry]));
        let spends = single_spend(Seeds(vec![a, b]));
        // Post-bythos: one group, one entry after the union — the
        // terminal atom + key + single-atom value.
        assert_eq!(count_seed_words(&spends, 1, 1).unwrap(), 3);
        // Pre-bythos: each seed priced alone.
        assert_eq!(count_seed_words(&spends, 0, 1).unwrap(), 6);
    }

    #[test]
    fn note_data_value_leaves_follow_the_value_noun() {
        // The cell [1 2] carries two atom leaves.
        let entry = NoteDataEntry::new("vesl-k".into(), OwnedBasedNoun::cell(atom(1), atom(2)));
        let spends = single_spend(Seeds(vec![seed(hash(10), NoteData::new(vec![entry]))]));
        // terminus + key + two value leaves
        assert_eq!(count_seed_words(&spends, 1, 1).unwrap(), 4);
    }

    #[test]
    fn witness_words_count_the_whole_witness_noun() {
        let spends = single_spend(Seeds(vec![seed(hash(10), NoteData::new(vec![]))]));
        let by_module = count_witness_words(&spends);
        // Independent count straight off the encoded noun.
        let Spend::Witness(s1) = &spends.0[0].1 else {
            unreachable!()
        };
        let mut slab: NounSlab = NounSlab::new();
        let noun = s1.witness.to_noun(&mut slab);
        let space = slab.noun_space();
        assert_eq!(by_module, num_of_leaves(noun, &space));
        assert!(by_module > 1);
    }

    #[test]
    fn min_fee_doubles_base_pre_bythos_and_discounts_witness_after() {
        let spends = single_spend(Seeds(vec![seed(hash(10), NoteData::new(vec![]))]));
        let constants = FeeConstants {
            base_fee: 100,
            input_fee_divisor: 4,
            min_fee: 1,
            bythos_phase: 50,
        };
        let seed_words = 1;
        let witness_words = count_witness_words(&spends);
        let pre = calculate_min_fee(&spends, 0, &constants).unwrap();
        assert_eq!(pre, seed_words * 200 + witness_words * 200);
        let post = calculate_min_fee(&spends, 50, &constants).unwrap();
        assert_eq!(post, seed_words * 100 + (witness_words * 100) / 4);
    }

    /// Post-bythos, the formula must agree with the upstream planner's
    /// `compute_minimum_fee` given the same word counts. (Pre-bythos the
    /// planner does not model the doubled base fee, so only the
    /// post-bythos arithmetic is comparable.)
    #[test]
    fn post_bythos_formula_matches_the_upstream_planner() {
        use nockchain_math::belt::Belt;
        use nockchain_types::tx_engine::common::BlockHeight;

        let entry = NoteDataEntry::new("vesl-k".into(), atom(7));
        let spends = single_spend(Seeds(vec![seed(hash(10), NoteData::new(vec![entry]))]));
        let constants = FeeConstants::fakenet();
        let height = 5u64;

        let seed_words = count_seed_words(&spends, height, constants.bythos_phase).unwrap();
        let witness_words = count_witness_words(&spends);
        let upstream =
            wallet_tx_builder::fee::compute_minimum_fee(wallet_tx_builder::fee::FeeInputs {
                seed_words,
                witness_words,
                base_fee: constants.base_fee,
                input_fee_divisor: constants.input_fee_divisor,
                min_fee: constants.min_fee,
                height: BlockHeight(Belt(height)),
                bythos_phase: BlockHeight(Belt(constants.bythos_phase)),
            });
        let ours = calculate_min_fee(&spends, height, &constants).unwrap();
        assert_eq!(ours, upstream.minimum_fee);
    }

    #[test]
    fn min_fee_floor_applies() {
        let spends = single_spend(Seeds(vec![seed(hash(10), NoteData::new(vec![]))]));
        let constants = FeeConstants {
            base_fee: 0,
            input_fee_divisor: 4,
            min_fee: 256,
            bythos_phase: 1,
        };
        assert_eq!(calculate_min_fee(&spends, 1, &constants).unwrap(), 256);
    }
}
