//! NoteData encoding and decoding helpers.
//!
//! Nockchain's NoteV1 carries `NoteData` — a list of key-value entries. A value
//! is a `NoteDataValue`: either one of the chain's typed payloads (a lock, a
//! bridge deposit/withdrawal) or a generic `OwnedBasedNoun`. Every NockApp that
//! puts structured data on-chain needs to encode to and decode from that format.
//!
//! Every atom in a note-data noun must be a **base-field element** (`< PRIME`).
//! The chain enforces this so that Rust and Hoon agree bit-for-bit on the
//! decode, so an off-field value is rejected here rather than silently reduced.
//!
//! # Encoding
//!
//! ```ignore
//! use nockchain_client_rs::note_data::{u64_entry, tip5_entry};
//!
//! let version_entry = u64_entry("my-app-v", 1)?;
//! let hash_entry = tip5_entry("my-app-root", &merkle_root)?;
//! let note_data = NoteData::new(vec![version_entry, hash_entry]);
//! ```
//!
//! # Decoding
//!
//! ```ignore
//! use nockchain_client_rs::note_data::{find_u64_entry, find_hash_entry};
//!
//! let version = find_u64_entry(&note_data, "my-app-v")?;
//! let root = find_hash_entry(&note_data, "my-app-root")?;
//! ```
//!
//! # Tip5 Hash Encoding
//!
//! Tip5 hashes (`[u64; 5]`) are encoded as null-terminated Nock lists:
//! `[limb0 limb1 limb2 limb3 limb4 0]`. Each limb is a Belt-sized u64 value.

use anyhow::Result;
use nockapp::noun::slab::{NockJammer, NounSlab};
use nockchain_math::owned_based_noun::OwnedBasedNoun;
use nockchain_tip5_rs::{Tip5Hash, check_tip5_limbs};
use nockchain_types::tx_engine::v1::note::{NoteData, NoteDataEntry, NoteDataValue};
use nockvm::noun::{D, IndirectAtom, Noun, NounAllocator};

// ---------------------------------------------------------------------------
// Encoding — Rust values to NoteDataEntry
// ---------------------------------------------------------------------------

/// Create a NoteDataEntry holding a single u64 atom.
///
/// Errors if `value` is not a base-field element; the chain would reject it.
pub fn u64_entry(key: &str, value: u64) -> Result<NoteDataEntry> {
    let noun = OwnedBasedNoun::try_atom(value)
        .map_err(|e| anyhow::anyhow!("u64 for key '{key}' is off-field: {e}"))?;
    Ok(NoteDataEntry::new(key.to_string(), noun))
}

/// Create a NoteDataEntry holding a tip5 hash.
///
/// Encodes the `[u64; 5]` digest as a null-terminated list of 5 atoms:
/// `[limb0 limb1 limb2 limb3 limb4 0]`.
pub fn tip5_entry(key: &str, hash: &Tip5Hash) -> Result<NoteDataEntry> {
    check_tip5_limbs(hash)
        .map_err(|e| anyhow::anyhow!("tip5 hash for key '{key}' has off-field limb: {e}"))?;
    let limbs = hash
        .iter()
        .map(|&limb| {
            OwnedBasedNoun::try_atom(limb)
                .map_err(|e| anyhow::anyhow!("tip5 limb for key '{key}' is off-field: {e}"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(NoteDataEntry::new(
        key.to_string(),
        OwnedBasedNoun::list(limbs),
    ))
}

/// Convert a u64 to a Nock noun, using IndirectAtom for values > DIRECT_MAX.
///
/// Nock's `D()` constructor only handles values up to 2^63 - 1. Values above
/// that threshold require indirect atom allocation. Used when building nouns in
/// a slab (kernel pokes); note-data values go through [`u64_entry`] instead.
pub fn u64_to_noun(slab: &mut NounSlab<NockJammer>, val: u64) -> Noun {
    const DIRECT_MAX: u64 = (1u64 << 63) - 1;
    if val <= DIRECT_MAX {
        D(val)
    } else {
        let bytes = val.to_le_bytes();
        unsafe {
            let mut indirect = IndirectAtom::new_raw_bytes_ref(slab, &bytes);
            let space = slab.noun_space();
            indirect.normalize_as_atom(&space).as_noun()
        }
    }
}

// ---------------------------------------------------------------------------
// Decoding — NoteDataEntry to Rust values
// ---------------------------------------------------------------------------

/// The generic noun carried by an entry, or an error if the entry holds one of
/// the chain's typed payloads (lock, bridge deposit/withdrawal) instead.
fn entry_noun(entry: &NoteDataEntry) -> Result<&OwnedBasedNoun> {
    match &entry.value {
        NoteDataValue::Noun(noun) => Ok(noun),
        _ => Err(anyhow::anyhow!(
            "NoteData key '{}' holds a typed chain payload, not a generic noun", entry.key
        )),
    }
}

/// Find a NoteDataEntry by key and decode its value as a u64.
pub fn find_u64_entry(data: &NoteData, key: &str) -> Result<u64> {
    match entry_noun(find_entry(data, key)?)? {
        OwnedBasedNoun::Atom(belt) => Ok(belt.0),
        OwnedBasedNoun::Cell(..) => Err(anyhow::anyhow!("expected atom for key '{key}', got cell")),
    }
}

/// Find a NoteDataEntry by key and decode its value as a tip5 hash.
///
/// Reads a 5-element Nock list `[limb0 limb1 limb2 limb3 limb4 0]` and
/// reconstructs the `[u64; 5]` digest. Every limb is a `Belt`, so it is
/// in-field by construction.
pub fn find_hash_entry(data: &NoteData, key: &str) -> Result<Tip5Hash> {
    let mut node = entry_noun(find_entry(data, key)?)?;
    let mut limbs = [0u64; 5];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let OwnedBasedNoun::Cell(head, tail) = node else {
            return Err(anyhow::anyhow!(
                "tip5 hash list too short at index {i} for key '{key}'"
            ));
        };
        let OwnedBasedNoun::Atom(belt) = head.as_ref() else {
            return Err(anyhow::anyhow!(
                "tip5 limb {i} is not an atom for key '{key}'"
            ));
        };
        *limb = belt.0;
        node = tail.as_ref();
    }
    Ok(limbs)
}

/// Find a NoteDataEntry by its key string.
pub fn find_entry<'a>(data: &'a NoteData, key: &str) -> Result<&'a NoteDataEntry> {
    data.iter()
        .find(|e| e.key == key)
        .ok_or_else(|| anyhow::anyhow!("NoteData key '{key}' not found"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use nockchain_math::belt::PRIME;

    use super::*;

    #[test]
    fn u64_roundtrip() {
        let entry = u64_entry("test-key", 42).unwrap();
        let data = NoteData::new(vec![entry]);
        let decoded = find_u64_entry(&data, "test-key").unwrap();
        assert_eq!(decoded, 42);
    }

    #[test]
    fn u64_zero_roundtrip() {
        let entry = u64_entry("zero", 0).unwrap();
        let data = NoteData::new(vec![entry]);
        assert_eq!(find_u64_entry(&data, "zero").unwrap(), 0);
    }

    #[test]
    fn u64_max_direct_roundtrip() {
        let max_direct = (1u64 << 63) - 1;
        let entry = u64_entry("max", max_direct).unwrap();
        let data = NoteData::new(vec![entry]);
        assert_eq!(find_u64_entry(&data, "max").unwrap(), max_direct);
    }

    #[test]
    fn u64_largest_in_field_roundtrip() {
        let entry = u64_entry("edge", PRIME - 1).unwrap();
        let data = NoteData::new(vec![entry]);
        assert_eq!(find_u64_entry(&data, "edge").unwrap(), PRIME - 1);
    }

    #[test]
    fn u64_off_field_is_rejected() {
        assert!(u64_entry("bad", PRIME).is_err());
        assert!(u64_entry("bad", u64::MAX).is_err());
    }

    #[test]
    fn tip5_hash_roundtrip() {
        let hash: Tip5Hash = [1, 2, 3, 4, 5];
        let entry = tip5_entry("root", &hash).unwrap();
        let data = NoteData::new(vec![entry]);
        let decoded = find_hash_entry(&data, "root").unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn tip5_hash_zero_roundtrip() {
        let hash: Tip5Hash = [0, 0, 0, 0, 0];
        let entry = tip5_entry("zero-root", &hash).unwrap();
        let data = NoteData::new(vec![entry]);
        assert_eq!(find_hash_entry(&data, "zero-root").unwrap(), hash);
    }

    #[test]
    fn tip5_hash_large_limbs_roundtrip() {
        let hash: Tip5Hash = [100, 200, 300, 400, 500];
        let entry = tip5_entry("big", &hash).unwrap();
        let data = NoteData::new(vec![entry]);
        assert_eq!(find_hash_entry(&data, "big").unwrap(), hash);
    }

    #[test]
    fn tip5_off_field_limb_is_rejected() {
        let hash: Tip5Hash = [1, 2, 3, 4, PRIME];
        assert!(tip5_entry("bad", &hash).is_err());
    }

    #[test]
    fn find_entry_missing_key() {
        let data = NoteData::new(vec![]);
        assert!(find_entry(&data, "nonexistent").is_err());
    }

    #[test]
    fn u64_entry_read_as_hash_fails() {
        let data = NoteData::new(vec![u64_entry("scalar", 7).unwrap()]);
        assert!(find_hash_entry(&data, "scalar").is_err());
    }

    #[test]
    fn multiple_entries() {
        let entries = vec![
            u64_entry("version", 1).unwrap(),
            u64_entry("id", 42).unwrap(),
            tip5_entry("root", &[0xAA; 5]).unwrap(),
        ];
        let data = NoteData::new(entries);

        assert_eq!(find_u64_entry(&data, "version").unwrap(), 1);
        assert_eq!(find_u64_entry(&data, "id").unwrap(), 42);
        assert_eq!(find_hash_entry(&data, "root").unwrap(), [0xAA; 5]);
    }
}
