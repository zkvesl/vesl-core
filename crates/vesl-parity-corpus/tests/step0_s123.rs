//! ⭐ STEP 0 — reproduce, offline and in pure Rust, the two digests a REAL
//! KERNEL produced on 2026-09-03 (`zkML/docs/plans/x402/records/S123` §8, leg
//! `D1`). If these do not reproduce, nothing else in this crate is worth
//! building, so this runs first and on its own.
//!
//! ⚑ Why these two matter more than any value tier 2 will generate: they were
//! produced by the chain's own program **before a line of this crate existed**.
//! A fixture this crate generates and then checks could, in the worst case, be
//! two spellings of one calculation. These cannot be.
//!
//! ⛔⛔ **THEY ARE LITERALS HERE ON PURPOSE, AND THAT IS THE WHOLE POINT.** The
//! answer sheet next door is regenerable — a kernel change moves it and the
//! tier-1 test follows without a murmur. These two do not follow: if the kernel
//! ever computes something else for this shape, THIS test goes red and stays
//! red until a person looks at it and decides the move was legitimate. That is
//! deliberate friction on the one operation that could otherwise launder a real
//! divergence into a green tick — "regenerate the fixture". ⇒ **Do not "fix"
//! this file by copying new values into it.** A move here is a finding: record
//! what changed in the kernel and why, and only then re-anchor.

use nockchain_types::tx_engine::v1::signatures::SigHashable;

/// The kernel's answer for the unpinned shape (`S123` §8 `D1`, left side).
const S123_UNPINNED: &str = "58W1NyPWnCiUNDUzjLuN2xE3DXLp91gExd3TCtB9yPsJPwkDYx9n2zi";
/// The kernel's answer for the pinned shape (`S123` §8 `D1`, right side).
const S123_PINNED: &str = "3QWFpKPHpy8jcJbRJHJzp7seyCQHexNWPqMN5sUGZddisaD7nKnTHBo";

#[test]
fn the_corpus_reproduces_the_kernels_own_digests_offline() {
    let shapes = vesl_parity_corpus::shapes().expect("the corpus builds");
    let find = |n: &str| {
        shapes
            .iter()
            .find(|s| s.name == n)
            .unwrap_or_else(|| panic!("corpus has no shape {n}"))
    };

    let unpinned = vesl_parity_corpus::sig_hash_subject(find("capture-3out-unpinned"))
        .expect("unpinned subject")
        .sig_hash_digest()
        .expect("unpinned sig-hash")
        .to_base58();
    let pinned = vesl_parity_corpus::sig_hash_subject(find("capture-3out-pinned"))
        .expect("pinned subject")
        .sig_hash_digest()
        .expect("pinned sig-hash")
        .to_base58();

    println!("  unpinned: {unpinned}");
    println!("  pinned:   {pinned}");

    assert_eq!(
        unpinned, S123_UNPINNED,
        "the pure-Rust sig-hash no longer reproduces the kernel's own answer for the \
         UNPINNED capture shape (measured on a live kernel, S123 §8 D1)"
    );
    assert_eq!(
        pinned, S123_PINNED,
        "the pure-Rust sig-hash no longer reproduces the kernel's own answer for the \
         PINNED capture shape (measured on a live kernel, S123 §8 D1)"
    );
    assert_ne!(
        unpinned, pinned,
        "pinning output-source did not move the signing digest — the control is vacuous"
    );
}
