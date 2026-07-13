//! Guard — Verification (mid tier)
//!
//! Verify proofs against roots. Pure math, no kernel.
//!
//! Domain-agnostic.  Domain-specific verifiers (e.g. hull-llm's manifest
//! verifier) build on top of `Guard::check` / `Guard::check_with_reason`,
//! casting their domain payload to a (data, proof, root) triple before
//! invoking these primitives.

use std::collections::HashSet;

use nockchain_tip5_rs::{ProofNode, Tip5Hash, verify_proof};

/// Maximum number of registered roots to prevent unbounded memory growth.
const MAX_ROOTS: usize = 10_000;

/// Errors from Guard operations.
#[derive(Debug)]
pub enum GuardError {
    /// Root store is at capacity (MAX_ROOTS reached).
    CapacityExceeded,
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapacityExceeded => write!(
                f,
                "root store at capacity ({MAX_ROOTS} roots) — revoke unused roots first"
            ),
        }
    }
}

impl std::error::Error for GuardError {}

pub struct Guard {
    roots: HashSet<[u64; 5]>,
}

impl Guard {
    /// Create a Guard verifier (no trusted roots yet).
    pub fn new() -> Self {
        Guard {
            roots: HashSet::new(),
        }
    }

    /// Register a root as trusted.
    ///
    /// Returns `Ok(())` on success (including if the root was already registered).
    /// Returns `Err(GuardError::CapacityExceeded)` if the store is full.
    pub fn register_root(&mut self, root: Tip5Hash) -> Result<(), GuardError> {
        if self.roots.len() >= MAX_ROOTS && !self.roots.contains(&root) {
            return Err(GuardError::CapacityExceeded);
        }
        self.roots.insert(root);
        Ok(())
    }

    /// Revoke a previously registered root. Returns true if the root was present.
    pub fn revoke_root(&mut self, root: &Tip5Hash) -> bool {
        self.roots.remove(root)
    }

    /// Verify a chunk against a registered root. Pure math, no kernel.
    pub fn check(&self, data: &[u8], proof: &[ProofNode], root: &Tip5Hash) -> bool {
        self.is_registered(root) && verify_proof(data, proof, root)
    }

    /// Like `check`, but returns a specific error on failure.
    ///
    /// Pre-flight diagnostic: catches the two most common poke-crash causes
    /// before the payload reaches the kernel.
    pub fn check_with_reason(
        &self,
        data: &[u8],
        proof: &[ProofNode],
        root: &Tip5Hash,
    ) -> Result<(), String> {
        if !self.is_registered(root) {
            return Err(format!(
                "root not registered: {}",
                crate::types::format_tip5(root),
            ));
        }
        if !verify_proof(data, proof, root) {
            return Err("proof invalid against registered root".into());
        }
        Ok(())
    }

    /// Check if a root is registered.
    pub fn is_registered(&self, root: &Tip5Hash) -> bool {
        self.roots.contains(root)
    }
}

impl Default for Guard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mint;

    fn build_test_scenario() -> (Mint, Tip5Hash, Vec<&'static [u8]>) {
        let mut mint = Mint::new();
        let chunks: Vec<&[u8]> = vec![
            b"The fund returned 12% YTD.", b"Risk exposure is within limits.",
            b"No regulatory flags detected.",
        ];
        let root = mint.commit(&chunks);
        (mint, root, chunks)
    }

    #[test]
    fn check_valid_proof() {
        let (mint, root, _chunks) = build_test_scenario();
        let mut guard = Guard::new();
        guard.register_root(root).unwrap();

        let proof = mint.proof(0).unwrap();
        assert!(guard.check(b"The fund returned 12% YTD.", &proof, &root));
    }

    #[test]
    fn check_unregistered_root_fails() {
        let (mint, root, _chunks) = build_test_scenario();
        let guard = Guard::new(); // no roots registered

        let proof = mint.proof(0).unwrap();
        assert!(!guard.check(b"The fund returned 12% YTD.", &proof, &root));
    }

    #[test]
    fn check_tampered_data_fails() {
        let (mint, root, _chunks) = build_test_scenario();
        let mut guard = Guard::new();
        guard.register_root(root).unwrap();

        let proof = mint.proof(0).unwrap();
        assert!(!guard.check(b"TAMPERED DATA", &proof, &root));
    }

    #[test]
    fn is_registered_works() {
        let mut guard = Guard::new();
        let root: Tip5Hash = [1, 2, 3, 4, 5];

        assert!(!guard.is_registered(&root));
        guard.register_root(root).unwrap();
        assert!(guard.is_registered(&root));
    }

    // --- Diagnostic method tests ---

    #[test]
    fn check_with_reason_unregistered_root() {
        let (mint, root, _) = build_test_scenario();
        let guard = Guard::new(); // no roots registered
        let proof = mint.proof(0).unwrap();
        let err = guard
            .check_with_reason(b"The fund returned 12% YTD.", &proof, &root)
            .unwrap_err();
        assert!(err.contains("root not registered"), "got: {err}");
    }

    #[test]
    fn check_with_reason_bad_proof() {
        let (_, root, _) = build_test_scenario();
        let mut guard = Guard::new();
        guard.register_root(root).unwrap();
        let err = guard
            .check_with_reason(b"TAMPERED", &[], &root)
            .unwrap_err();
        assert!(err.contains("proof invalid"), "got: {err}");
    }

    #[test]
    fn check_with_reason_valid() {
        let (mint, root, _) = build_test_scenario();
        let mut guard = Guard::new();
        guard.register_root(root).unwrap();
        let proof = mint.proof(0).unwrap();
        assert!(
            guard
                .check_with_reason(b"The fund returned 12% YTD.", &proof, &root)
                .is_ok()
        );
    }
}
