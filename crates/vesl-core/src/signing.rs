//! Schnorr signing over the Cheetah curve — backwards-compat shim over
//! `vesl-signing`, plus a BIP-39 + BIP-44 entry point delegated to
//! `vesl-wallet`.
//!
//! Canonical Schnorr-over-Cheetah primitives live in
//! `github.com/zkvesl/vesl-wallet::vesl-signing`. This module retains
//! the `[Belt; 8]`-flavored API that vesl-core has historically exposed
//! to its callers (`settle.rs`, `config.rs`, `lib.rs` re-exports),
//! translating to/from vesl-signing's `UBig`-based representation at the
//! boundary.
//!
//! Type conversions:
//! - `nockchain_math::belt::Belt(u64)` ↔ `vesl_signing::prelude::Belt(u64)`
//!   is a memcpy through the public tuple field.
//! - `nockchain_math::crypto::cheetah::CheetahPoint` ↔
//!   `vesl_signing::schnorr::CheetahPoint`: structurally identical
//!   (verbatim port). Convert via the public `x: F6lt`, `y: F6lt`,
//!   `inf: bool` fields.
//!
//! `pubkey_hash` stays local because it uses
//! `hash_noun_varlen_digest` from `nockchain-math`, which takes a
//! `NounSlab` (Hoon-noun layer that vesl-signing does not carry).

use std::fmt;

use ibig::UBig;
use nockchain_math::belt::Belt;
use nockchain_math::crypto::cheetah::{CheetahPoint as NockCheetahPoint, F6lt as NockF6lt};
use nockchain_types::tx_engine::common::{Hash, SchnorrPubkey, SchnorrSignature};
use vesl_signing::prelude::Belt as VeslBelt;
use vesl_signing::schnorr::{
    CheetahPoint as VeslCheetahPoint, F6lt as VeslF6lt, SchnorrError, SchnorrPrivateKey,
    SchnorrSignatureJson, schnorr_sign, schnorr_verify,
};
use vesl_wallet::{VESL_COIN_TYPE_PLACEHOLDER, VeslWallet, WalletError};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Error type — pre-shim API plus a BIP-39 mnemonic variant.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SigningError {
    InvalidSecretKey,
    ZeroNonce,
    ZeroChallenge,
    ZeroSignature,
    /// Returned by [`key_from_seed_phrase`] when the input string is not
    /// a valid BIP-39 mnemonic. The previous ad-hoc Tip5-hash variant
    /// accepted any string, but the BIP-39 + BIP-44 derivation that
    /// replaced it requires a real mnemonic.
    InvalidMnemonic(String),
    /// Returned by [`key_from_seed_phrase`] when the BIP-44 derivation
    /// produces a scalar outside `(0, G_ORDER)`. Cryptographically
    /// negligible with Tip5 but typed for completeness.
    DerivationFailure(String),
    /// Returned by the config per-role signer helpers
    /// (`SettlementConfig::intent_signer_belts` / `payment_signer_belts`)
    /// when no wallet seed phrase is configured — either no `[wallet]`
    /// block at all, or a `[wallet]` block without a `seed_phrase`.
    NoSeedPhrase,
    /// Returned by [`pubkey_hash`] if `hash_noun_varlen_digest` rejects the
    /// pubkey noun. Unreachable for a well-formed `SchnorrPubkey` — its noun
    /// is a fixed cell of belts — but surfaced as a typed error rather than
    /// an `.expect()` panic, for defence in depth. AUDIT 2026-05-21 L-02.
    HashFailed(String),
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretKey => write!(f, "secret key must be in (0, g_order)"),
            Self::ZeroNonce => write!(f, "deterministic nonce was zero"),
            Self::ZeroChallenge => write!(f, "challenge was zero"),
            Self::ZeroSignature => write!(f, "signature was zero"),
            Self::InvalidMnemonic(msg) => write!(f, "invalid BIP-39 mnemonic: {msg}"),
            Self::DerivationFailure(msg) => write!(f, "BIP-44 derivation failed: {msg}"),
            Self::NoSeedPhrase => write!(f, "no wallet seed phrase configured"),
            Self::HashFailed(msg) => write!(f, "pubkey hash failed: {msg}"),
        }
    }
}

impl std::error::Error for SigningError {}

impl From<SchnorrError> for SigningError {
    fn from(e: SchnorrError) -> Self {
        match e {
            SchnorrError::BadPrivateKey | SchnorrError::OutOfRange => Self::InvalidSecretKey,
            SchnorrError::BadSignature => Self::ZeroSignature,
            SchnorrError::Curve(_)
            | SchnorrError::ChunkOverflow(_)
            | SchnorrError::BadChunk(_)
            | SchnorrError::BadPubkey(_) => Self::InvalidSecretKey,
        }
    }
}

impl From<WalletError> for SigningError {
    fn from(e: WalletError) -> Self {
        match e {
            WalletError::InvalidMnemonic(msg) => Self::InvalidMnemonic(msg),
            WalletError::InvalidScalar => Self::DerivationFailure(
                "derived scalar landed outside (0, G_ORDER); rotate index".into(),
            ),
            WalletError::NonBip44Purpose(c) => {
                Self::DerivationFailure(format!("non-BIP44 coin_type {c}"))
            }
            WalletError::IndexOverflow(i) => {
                Self::DerivationFailure(format!("hardened index {i} exceeds 31-bit limit"))
            }
            WalletError::ScalarTooWide => {
                Self::DerivationFailure("HD scalar exceeded the 32-byte transcript width".into())
            }
            WalletError::Signing(inner) => Self::from(inner),
        }
    }
}

// ---------------------------------------------------------------------------
// Public API — delegates to vesl-signing
// ---------------------------------------------------------------------------

/// Derive the Schnorr public key from a secret key.
///
/// `sk` is 8 × 32-bit Belt chunks (little-endian, matching Hoon's t8).
///
/// AUDIT 2026-05-19 H-04: returns `Err` instead of panicking when a
/// chunk is out of 32-bit range or the assembled scalar lands outside
/// `(0, G_ORDER)` — attacker-influenced belts cannot crash the caller.
pub fn derive_pubkey(sk: &[Belt; 8]) -> Result<SchnorrPubkey, SigningError> {
    let belts = nock_belts8_to_vesl(sk)?;
    let key = SchnorrPrivateKey::from_belts(&belts)?;
    Ok(SchnorrPubkey(vesl_point_to_nock(&key.public_key()?)))
}

/// Compute the PKH (public-key hash) from a public key.
///
/// Matches Hoon's `hash:schnorr-pubkey` = `(hash-hashable:tip5 leaf+pk)`.
/// This hashes the **entire pubkey noun** (including inf flag and cell
/// structure) through `hash_noun_varlen_digest`, NOT just the coordinate
/// belts. Stays in vesl-core because vesl-signing does not carry the
/// noun layer.
pub fn pubkey_hash(pk: &SchnorrPubkey) -> Result<Hash, SigningError> {
    use nockapp::noun::slab::NounSlab;
    use nockchain_math::tip5::hash::hash_noun_varlen_digest;
    use nockvm::noun::NounAllocator;
    use noun_serde::NounEncode;

    let mut slab: NounSlab = NounSlab::new();
    let noun = pk.to_noun(&mut slab);
    let space = slab.noun_space();
    // AUDIT 2026-05-21 L-02: a well-formed SchnorrPubkey noun never fails to
    // hash, but return the error rather than `.expect()`-panic on it.
    let digest = hash_noun_varlen_digest(&mut slab, noun, &space)
        .map_err(|e| SigningError::HashFailed(format!("{e:?}")))?;
    Ok(Hash::from_limbs(&digest))
}

/// Return the canonical 97-byte serialization of a Schnorr public key.
///
/// Wire shape mirrors Hoon's `ser-a-pt:cheetah`
/// (`(rep 6 [x0 x1 x2 x3 x4 x5 y0 y1 y2 y3 y4 y5 1])`), so when these
/// bytes are passed through `make_atom_in` and decoded by
/// `de-a-pt:cheetah`, the recovered belts match exactly:
///
///   bytes  0..7   = x0 (little-endian u64)
///   bytes  8..15  = x1
///   ...
///   bytes 40..47  = x5
///   bytes 48..55  = y0
///   ...
///   bytes 88..95  = y5
///   byte  96      = 0x01 marker (highest-order byte of the LE atom)
///
/// This is the form the `sig-verify-schnorr` gate's `de-a-pt` step
/// expects. Note: vesl-signing's `CheetahPoint::to_bytes()` produces a
/// *different* layout (BE belts, marker first) used for base58 wire
/// transport — that's not interchangeable with the Hoon-atom path.
///
/// Panics only on the point at infinity, which a `SchnorrPubkey` produced
/// by [`derive_pubkey`] cannot reach (`g * sk` for `sk` in `(0, G_ORDER)`
/// is never the identity). Callers that hold a `SchnorrPubkey` decoded
/// from untrusted input should check `pk.0.inf == false` first.
pub fn pubkey_canonical_bytes(pk: &SchnorrPubkey) -> Vec<u8> {
    assert!(!pk.0.inf, "SchnorrPubkey is the point at infinity");
    let mut out = vec![0u8; 97];
    for (i, belt) in pk.0.x.0.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&belt.0.to_le_bytes());
    }
    for (i, belt) in pk.0.y.0.iter().enumerate() {
        out[48 + i * 8..48 + i * 8 + 8].copy_from_slice(&belt.0.to_le_bytes());
    }
    out[96] = 0x01;
    out
}

/// Pack a Schnorr signature into the gate's wire atom: `(chal << 256) | s`.
///
/// The `sig-verify-schnorr` gate splits this back via `(rsh 8 sig)` and
/// `(end 8 sig)`. Returns canonical little-endian atom bytes (leading
/// zeros stripped), matching Hoon atom serialization.
pub fn pack_schnorr_signature(sig: &SchnorrSignature) -> Vec<u8> {
    let chal_big = belts8_to_ubig(&sig.chal);
    let sig_big = belts8_to_ubig(&sig.sig);
    let packed = (chal_big << 256) | sig_big;
    packed.to_le_bytes()
}

/// Compute the Tip5 noun-digest the `sig-verify-schnorr` gate uses as
/// the signed message.
///
/// Mirrors the gate's `(hash-leaf-digest data)` reduction:
/// `nockchain_tip5_rs::hash_leaf` chunks `data` into 7-byte LE belts
/// (each safely under the Goldilocks prime), prepends the chunk count,
/// and runs `hash-varlen` to produce the 5-belt `noun-digest`. Accepts
/// arbitrary `&[u8]`; no size limit. Pass the result to [`sign`] to
/// produce a signature that verifies under the gate.
pub fn schnorr_message_digest_for_data(data: &[u8]) -> [Belt; 5] {
    let digest: nockchain_tip5_rs::Tip5Hash = nockchain_tip5_rs::hash_leaf(data);
    digest.map(Belt)
}

/// Sign a message digest with a secret key.
///
/// `sk`: secret key as 8 × 32-bit Belt chunks.
/// `message`: tip5 noun-digest (5 × 64-bit limbs).
///
/// Returns a `SchnorrSignature` with challenge and signature components,
/// each stored as 8 × 32-bit Belt chunks. Compatible with Hoon's
/// `sign:affine:belt-schnorr:cheetah`.
///
/// # Deterministic nonce — contract (AUDIT 2026-04-17 M-06)
///
/// The nonce is derived as
/// `trunc_g_order(hash_varlen([pk.x, pk.y, message, sk]))`. This is
/// deterministic: the same `(sk, message)` pair always produces the
/// same signature. Matches the Hoon spec
/// (`sign:affine:belt-schnorr:cheetah`, three.hoon lines 1628-1661).
///
/// Security is only preserved if every call for a given key uses a
/// **distinct** `message` value. Re-signing the same logical document
/// is safe (same signature = no new entropy leaked). Signing two
/// different logical documents that happen to hash to the same `message`
/// is not — and any caller that lets the message be chosen (or reused)
/// adversarially breaks the signature scheme.
///
/// Callers who don't fully control message entropy must include a fresh
/// nonce / counter in the message body before digesting. The signing
/// layer does not add randomness on behalf of the caller.
pub fn sign(sk: &[Belt; 8], message: &[Belt; 5]) -> Result<SchnorrSignature, SigningError> {
    let belts = nock_belts8_to_vesl(sk)?;
    let key = SchnorrPrivateKey::from_belts(&belts)?;
    let m = nock_belts5_to_vesl(message);
    let (chal, sig) = schnorr_sign(&key, &m)?;
    Ok(SchnorrSignature {
        chal: ubig_to_belts8(&chal),
        sig: ubig_to_belts8(&sig),
    })
}

pub fn pubkey_from_base58(b58: &str) -> Result<SchnorrPubkey, SigningError> {
    let point = VeslCheetahPoint::from_base58(b58)
        .map_err(|e| SigningError::HashFailed(format!("pubkey base58 decode: {e}")))?;
    Ok(SchnorrPubkey(vesl_point_to_nock(&point)))
}

pub fn wire_signature_to_chain(
    json: &SchnorrSignatureJson,
) -> Result<(SchnorrPubkey, SchnorrSignature), SigningError> {
    let pubkey = pubkey_from_base58(&json.pubkey)?;
    let parse8 = |limbs: &[String; 8]| -> Result<[Belt; 8], SigningError> {
        let mut out = [Belt(0); 8];
        for (i, s) in limbs.iter().enumerate() {
            let v: u64 = s.parse().map_err(|_| SigningError::InvalidSecretKey)?;
            if v > u32::MAX as u64 {
                return Err(SigningError::InvalidSecretKey);
            }
            out[i] = Belt(v);
        }
        Ok(out)
    };
    let signature = SchnorrSignature {
        chal: parse8(&json.schnorr.chal)?,
        sig: parse8(&json.schnorr.sig)?,
    };
    Ok((pubkey, signature))
}

/// Verify a chain-form Schnorr signature over a 5-limb message — the
/// per-entry predicate of the tx engine's `check:pkh` (minus the batch
/// step): the message is the spend's sig-hash, signed raw, with no
/// domain rebind.
pub fn verify_chain_signature(
    pk: &SchnorrPubkey,
    message: &[Belt; 5],
    sig: &SchnorrSignature,
) -> bool {
    let point = nock_point_to_vesl(&pk.0);
    let m = nock_belts5_to_vesl(message);
    let chal = belts8_to_ubig(&sig.chal);
    let s = belts8_to_ubig(&sig.sig);
    schnorr_verify(&point, &m, &chal, &s).is_ok()
}

// ---------------------------------------------------------------------------
// Key derivation — BIP-39 + BIP-44 via vesl-wallet (replaces the prior
// ad-hoc Tip5 hash). Existing seeds will produce different keys; callers
// that relied on the pre-replacement behavior must migrate to a real
// BIP-39 mnemonic.
// ---------------------------------------------------------------------------

/// Derive a signing key from a BIP-39 mnemonic.
///
/// Internally builds a [`VeslWallet`] with no passphrase and the
/// placeholder coin_type, then returns the intent-role key at
/// `m/44'/<placeholder>'/0'/ROLE_INTENT/0` as a `[Belt; 8]` for
/// callers that haven't moved to the typed wallet API yet.
///
/// Returns [`SigningError::InvalidMnemonic`] if `phrase` is not a valid
/// BIP-39 mnemonic (any word count / wordlist supported by the `bip39`
/// crate). Callers that want a different account / role / index, a
/// non-empty BIP-39 passphrase, or a different coin_type should
/// instantiate `VeslWallet` directly and call `intent_signer` /
/// `payment_signer` / `derive` themselves.
pub fn key_from_seed_phrase(phrase: &str) -> Result<[Belt; 8], SigningError> {
    let wallet = VeslWallet::from_seed_phrase(phrase, "", VESL_COIN_TYPE_PLACEHOLDER)?;
    let intent_key = wallet.intent_signer(0, 0)?;
    Ok(vesl_belts8_to_nock(&intent_key.to_belts()))
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Convert nockchain-math `[Belt; 8]` into vesl-signing's `[Belt; 8]`.
/// Both Belt structs wrap `u64` in a public tuple field.
///
/// AUDIT 2026-05-19 H-04: a well-formed t8 secret key holds eight 32-bit
/// chunks. Reject an out-of-range limb here, at the vesl-core boundary,
/// rather than letting it panic an `.expect()` deeper in the shim.
fn nock_belts8_to_vesl(belts: &[Belt; 8]) -> Result<[VeslBelt; 8], SigningError> {
    for b in belts {
        if b.0 > u32::MAX as u64 {
            return Err(SigningError::InvalidSecretKey);
        }
    }
    Ok(std::array::from_fn(|i| VeslBelt(belts[i].0)))
}

/// Same as [`nock_belts8_to_vesl`] for the 5-Belt message digest shape.
fn nock_belts5_to_vesl(belts: &[Belt; 5]) -> [VeslBelt; 5] {
    std::array::from_fn(|i| VeslBelt(belts[i].0))
}

/// Convert vesl-signing `[Belt; 8]` back into nockchain-math `[Belt; 8]`.
fn vesl_belts8_to_nock(belts: &[VeslBelt; 8]) -> [Belt; 8] {
    std::array::from_fn(|i| Belt(belts[i].0))
}

/// Convert a vesl-signing `CheetahPoint` to the nockchain-math form.
/// The structs are byte-isomorphic by construction (vesl-signing's math
/// is a verbatim port). Both `F6lt` types wrap `[Belt; 6]` in a public
/// tuple field.
fn vesl_point_to_nock(p: &VeslCheetahPoint) -> NockCheetahPoint {
    NockCheetahPoint {
        x: NockF6lt(std::array::from_fn(|i| Belt(p.x.0[i].0))),
        y: NockF6lt(std::array::from_fn(|i| Belt(p.y.0[i].0))),
        inf: p.inf,
    }
}

// Inverse direction — kept available for the round-trip test below
// (`point_conversion_roundtrip`) and for any future shim that needs to
// reach `vesl_signing::schnorr` primitives that take `VeslCheetahPoint`.
#[allow(dead_code)]
fn nock_point_to_vesl(p: &NockCheetahPoint) -> VeslCheetahPoint {
    VeslCheetahPoint {
        x: VeslF6lt(std::array::from_fn(|i| VeslBelt(p.x.0[i].0))),
        y: VeslF6lt(std::array::from_fn(|i| VeslBelt(p.y.0[i].0))),
        inf: p.inf,
    }
}

/// Reconstruct a UBig from 8 × 32-bit Belt chunks (little-endian).
/// Matches Hoon's `rep 5 sk-as-32-bit-belts`.
#[allow(dead_code)]
pub(crate) fn belts8_to_ubig(belts: &[Belt; 8]) -> UBig {
    let mut bytes = [0u8; 32];
    for (i, belt) in belts.iter().enumerate() {
        let chunk = (belt.0 as u32).to_le_bytes();
        bytes[i * 4..i * 4 + 4].copy_from_slice(&chunk);
    }
    let result = UBig::from_le_bytes(&bytes);
    bytes.zeroize();
    result
}

/// Split a UBig into 8 × 32-bit Belt chunks (little-endian). Matches
/// Hoon's `rip 5` with zero-padding to 8 elements.
pub(crate) fn ubig_to_belts8(val: &UBig) -> [Belt; 8] {
    let mut belts = [Belt(0); 8];
    let mut v = val.clone();
    let mask = UBig::from(0xFFFF_FFFFu64);
    for belt in &mut belts {
        let chunk = &v & &mask;
        // AUDIT 2026-04-19 L-18: chunk is `v & 0xFFFF_FFFF`, so it fits
        // in 32 bits (and therefore in u64) by construction. A silent
        // `unwrap_or(0)` would mask any invariant break and zero the
        // limb, producing invalid key material. Prefer a named expect.
        *belt = Belt(u64::try_from(&chunk).expect("chunk is 32-bit by construction"));
        v >>= 32;
    }
    belts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use nockchain_math::crypto::cheetah::{
        A_GEN, F6_ZERO, ch_add, ch_neg, ch_scal_big, trunc_g_order,
    };
    use nockchain_math::tip5::hash::hash_varlen;

    use super::*;

    /// Canonical BIP-39 12-word test vector ("abandon×11 + about").
    const CANONICAL_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about";

    /// A second canonical BIP-39 vector for distinct-input tests.
    const ALT_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    #[test]
    fn derive_pubkey_from_nonzero_key() {
        let mut sk = [Belt(0); 8];
        sk[0] = Belt(42);
        let pk = derive_pubkey(&sk).expect("test key derives");
        assert!(!pk.0.inf);
        assert_ne!(pk.0.x, F6_ZERO);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut sk = [Belt(0); 8];
        sk[0] = Belt(12345);
        sk[1] = Belt(67890);

        let message = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];

        let sig = sign(&sk, &message).expect("signing should succeed");

        let pubkey = derive_pubkey(&sk).expect("test key derives");
        let chal_big = belts8_to_ubig(&sig.chal);
        let sig_big = belts8_to_ubig(&sig.sig);

        let left = ch_scal_big(&sig_big, &A_GEN).expect("valid sig scalar");
        let right = ch_neg(&ch_scal_big(&chal_big, &pubkey.0).expect("valid chal scalar"));
        let r_reconstructed = ch_add(&left, &right).expect("valid point add");
        assert_ne!(r_reconstructed.x, F6_ZERO, "R must not be at infinity");

        let mut hashable: Vec<Belt> = Vec::with_capacity(6 * 4 + 5);
        hashable.extend_from_slice(&r_reconstructed.x.0);
        hashable.extend_from_slice(&r_reconstructed.y.0);
        hashable.extend_from_slice(&pubkey.0.x.0);
        hashable.extend_from_slice(&pubkey.0.y.0);
        hashable.extend_from_slice(&message);
        let recomputed_hash = hash_varlen(&mut hashable);
        let recomputed_chal = trunc_g_order(&recomputed_hash);

        assert_eq!(
            recomputed_chal, chal_big,
            "recomputed challenge must match signed challenge"
        );
    }

    #[test]
    fn belts_roundtrip() {
        let original = UBig::from(0xDEADBEEF_CAFEBABE_u64);
        let belts = ubig_to_belts8(&original);
        let recovered = belts8_to_ubig(&belts);
        assert_eq!(original, recovered);
    }

    #[test]
    fn belts_roundtrip_large() {
        let mut val = UBig::from(1u64);
        for _ in 0..7 {
            val <<= 32;
            val += UBig::from(0xAAAA_BBBBu64);
        }
        let belts = ubig_to_belts8(&val);
        let recovered = belts8_to_ubig(&belts);
        assert_eq!(val, recovered);
    }

    #[test]
    fn pubkey_hash_produces_valid_hash() {
        let mut sk = [Belt(0); 8];
        sk[0] = Belt(999);
        let pk = derive_pubkey(&sk).expect("test key derives");
        let pkh = pubkey_hash(&pk).expect("pubkey hash succeeds for a valid key");
        assert!(pkh.0.iter().any(|b| b.0 != 0));
    }

    #[test]
    fn different_messages_produce_different_signatures() {
        let mut sk = [Belt(0); 8];
        sk[0] = Belt(7777);

        let msg1 = [Belt(1), Belt(0), Belt(0), Belt(0), Belt(0)];
        let msg2 = [Belt(2), Belt(0), Belt(0), Belt(0), Belt(0)];

        let sig1 = sign(&sk, &msg1).expect("signing should succeed");
        let sig2 = sign(&sk, &msg2).expect("signing should succeed");

        assert_ne!(sig1.chal, sig2.chal);
        assert_ne!(sig1.sig, sig2.sig);
    }

    #[test]
    fn key_from_seed_phrase_accepts_canonical_bip39() {
        let sk = key_from_seed_phrase(CANONICAL_MNEMONIC)
            .expect("canonical BIP-39 mnemonic must succeed");
        assert!(sk.iter().any(|b| b.0 != 0));
    }

    #[test]
    fn key_from_seed_phrase_distinct_phrases_distinct_keys() {
        let a = key_from_seed_phrase(CANONICAL_MNEMONIC).unwrap();
        let b = key_from_seed_phrase(ALT_MNEMONIC).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn key_from_seed_phrase_rejects_invalid_mnemonic() {
        let err =
            key_from_seed_phrase("not a real mnemonic").expect_err("invalid mnemonic must fail");
        assert!(matches!(err, SigningError::InvalidMnemonic(_)));
    }

    #[test]
    fn key_from_seed_phrase_is_deterministic() {
        let a = key_from_seed_phrase(CANONICAL_MNEMONIC).unwrap();
        let b = key_from_seed_phrase(CANONICAL_MNEMONIC).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn pubkey_canonical_bytes_round_trips_through_atom_to_de_a_pt() {
        // Layout matches Hoon's `(rep 6 [x0..x5 y0..y5 1])`:
        //   bytes  0..7   = x0 LE
        //   bytes  8..47  = x1..x5 LE
        //   bytes 48..95  = y0..y5 LE
        //   byte  96      = 0x01 marker (highest-order byte of the LE atom)
        // When the bytes are LE-decoded into 64-bit chunks, the first 6
        // chunks should reproduce pk.x and the next 6 chunks pk.y.
        let mut sk = [Belt(0); 8];
        sk[0] = Belt(31_415);
        let pk = derive_pubkey(&sk).expect("test key derives");
        let bytes = pubkey_canonical_bytes(&pk);
        assert_eq!(bytes.len(), 97);
        assert_eq!(bytes[96], 0x01, "LE marker belongs at byte 96");
        for (i, expected) in pk.0.x.0.iter().enumerate() {
            let chunk: [u8; 8] = bytes[i * 8..i * 8 + 8].try_into().unwrap();
            assert_eq!(u64::from_le_bytes(chunk), expected.0, "x[{i}] mismatch");
        }
        for (i, expected) in pk.0.y.0.iter().enumerate() {
            let chunk: [u8; 8] = bytes[48 + i * 8..48 + i * 8 + 8].try_into().unwrap();
            assert_eq!(u64::from_le_bytes(chunk), expected.0, "y[{i}] mismatch");
        }
    }

    #[test]
    fn pack_schnorr_signature_round_trips() {
        let mut sk = [Belt(0); 8];
        sk[0] = Belt(2_718);
        sk[1] = Belt(1_618);
        let message = [Belt(9), Belt(8), Belt(7), Belt(6), Belt(5)];
        let sig = sign(&sk, &message).expect("signing should succeed");

        let packed = pack_schnorr_signature(&sig);
        let packed_big = UBig::from_le_bytes(&packed);

        let mask_256 = (UBig::from(1u64) << 256) - UBig::from(1u64);
        let recovered_chal = &packed_big >> 256;
        let recovered_sig = &packed_big & &mask_256;

        assert_eq!(recovered_chal, belts8_to_ubig(&sig.chal));
        assert_eq!(recovered_sig, belts8_to_ubig(&sig.sig));
    }

    #[test]
    fn schnorr_message_digest_for_data_is_deterministic() {
        // 32-byte fixtures exercise the chunking path (multiple belts)
        // so a regression to a single-belt implementation surfaces here.
        let msg_a: &[u8; 32] = b"attest: revenue Q3 = $47M ----xx";
        let msg_b: &[u8; 32] = b"attest: revenue Q4 = $58M ----xx";
        let a = schnorr_message_digest_for_data(msg_a);
        let a_again = schnorr_message_digest_for_data(msg_a);
        assert_eq!(a, a_again);
        let b = schnorr_message_digest_for_data(msg_b);
        assert_ne!(a, b);
        assert!(a.iter().any(|belt| belt.0 != 0));
    }

    #[test]
    fn sign_against_helper_digest_round_trips() {
        // The helper composes with sign(): produce a signature against
        // schnorr_message_digest_for_data(b), then check the verify
        // equation reconstructs the same challenge. End-to-end
        // gate-side verification is exercised by
        // schnorr_gate_lifecycle.rs in vesl-nockup.
        let mut sk = [Belt(0); 8];
        sk[0] = Belt(11_111);
        sk[1] = Belt(22_222);
        let pubkey = derive_pubkey(&sk).expect("test key derives");
        let digest = schnorr_message_digest_for_data(b"attest: 32-byte hash fingerprint");
        let sig = sign(&sk, &digest).expect("signing should succeed");

        let chal_big = belts8_to_ubig(&sig.chal);
        let sig_big = belts8_to_ubig(&sig.sig);
        let left = ch_scal_big(&sig_big, &A_GEN).expect("valid sig scalar");
        let right = ch_neg(&ch_scal_big(&chal_big, &pubkey.0).expect("valid chal scalar"));
        let r = ch_add(&left, &right).expect("valid point add");

        let mut hashable: Vec<Belt> = Vec::with_capacity(6 * 4 + 5);
        hashable.extend_from_slice(&r.x.0);
        hashable.extend_from_slice(&r.y.0);
        hashable.extend_from_slice(&pubkey.0.x.0);
        hashable.extend_from_slice(&pubkey.0.y.0);
        hashable.extend_from_slice(&digest);
        let recomputed = trunc_g_order(&hash_varlen(&mut hashable));
        assert_eq!(recomputed, chal_big);
    }

    #[test]
    fn wire_round_trip_verifies_as_a_chain_signature() {
        let mut sk = [Belt(0); 8];
        sk[0] = Belt(8_086);
        let message = [Belt(3), Belt(1), Belt(4), Belt(1), Belt(5)];
        let chain_sig = sign(&sk, &message).expect("sign");
        let pk = derive_pubkey(&sk).expect("derive");

        // Encode to the wire form by hand: the b58 point + the chain
        // limbs as decimal strings (the layouts coincide by design).
        let b58 = nock_point_to_vesl(&pk.0).into_base58().expect("b58");
        let to_strings =
            |belts: &[Belt; 8]| -> [String; 8] { std::array::from_fn(|i| belts[i].0.to_string()) };
        let json = SchnorrSignatureJson {
            pubkey: b58,
            schnorr: vesl_signing::schnorr::SchnorrPair {
                chal: to_strings(&chain_sig.chal),
                sig: to_strings(&chain_sig.sig),
            },
        };

        let (pk_back, sig_back) = wire_signature_to_chain(&json).expect("wire decode");
        assert_eq!(pk_back.0.x.0, pk.0.x.0);
        assert_eq!(sig_back, chain_sig);
        assert!(verify_chain_signature(&pk_back, &message, &sig_back));
        let wrong = [Belt(0); 5];
        assert!(!verify_chain_signature(&pk_back, &wrong, &sig_back));
    }

    #[test]
    fn wire_signature_rejects_oversized_limbs() {
        let json = SchnorrSignatureJson {
            pubkey: "x".into(),
            schnorr: vesl_signing::schnorr::SchnorrPair {
                chal: std::array::from_fn(|_| u64::MAX.to_string()),
                sig: std::array::from_fn(|_| "0".to_string()),
            },
        };
        assert!(wire_signature_to_chain(&json).is_err());
    }

    #[test]
    fn point_conversion_roundtrip() {
        // Verify the nock <-> vesl CheetahPoint translation is exact.
        let mut sk = [Belt(0); 8];
        sk[0] = Belt(54321);
        let nock_pk = derive_pubkey(&sk).expect("test key derives");
        let vesl_pk = nock_point_to_vesl(&nock_pk.0);
        let back = vesl_point_to_nock(&vesl_pk);
        assert_eq!(back.x.0, nock_pk.0.x.0);
        assert_eq!(back.y.0, nock_pk.0.y.0);
        assert_eq!(back.inf, nock_pk.0.inf);
    }
}
