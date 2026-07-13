//! Nockchain gRPC client for NockApp developers.
//!
//! Provides everything you need to talk to a Nockchain node and wallet
//! from Rust: transaction submission, balance queries, wallet signing
//! coordination, and NoteData encoding/decoding.
//!
//! # Quick Start
//!
//! ```ignore
//! use nockchain_client_rs::{ChainClient, ChainConfig, WalletClient, WalletConfig};
//!
//! // Connect to a local Nockchain node
//! let mut chain = ChainClient::connect(ChainConfig::default()).await?;
//!
//! // Query balance
//! let balance = chain.get_balance("your-address-base58").await?;
//!
//! // Connect to wallet for signing
//! let mut wallet = WalletClient::connect(WalletConfig::default()).await?;
//! ```
//!
//! # Architecture
//!
//! Two gRPC clients, two protocols:
//!
//! - **ChainClient** talks to the Nockchain node's *public* gRPC API
//!   (default port 9090). Submits transactions, queries balances,
//!   polls for acceptance.
//!
//! - **WalletClient** talks to a nockchain-wallet's *private* gRPC API
//!   (default port 5555). Requests signing, queries wallet state,
//!   creates transactions.
//!
//! NoteData helpers encode and decode the key-value entries that ride
//! inside NoteV1 transactions. Every NockApp that puts data on-chain
//! needs these.

pub mod chain;
pub mod note_data;
pub mod types;
pub mod wallet;

// Re-export the main types at crate root for convenience.
pub use chain::{
    ChainClient, ChainConfig, TransactionBlockResult, TransactionDetails,
    TransactionDetailsResult, TxInput, TxOutput,
};
pub use note_data::{find_entry, find_hash_entry, find_u64_entry, tip5_entry, u64_entry};
pub use types::{extract_note_data, extract_spendable_utxos, SpendableUtxo};
pub use wallet::{WalletClient, WalletConfig};

// Re-export nockchain types that callers will need.
pub use nockchain_tip5_rs::Tip5Hash;
pub use nockchain_types::tx_engine::common::Hash as ChainHash;
pub use nockchain_types::tx_engine::v1::note::{NoteData, NoteDataEntry};
pub use nockchain_types::tx_engine::v1::RawTx;

// ---------------------------------------------------------------------------
// Endpoint security (AUDIT 2026-05-19 H-11)
// ---------------------------------------------------------------------------

/// Reject a plaintext (`http://`) endpoint that points at a non-loopback
/// host. `ChainClient` / `WalletClient` carry balance queries, transaction
/// submission, and signing requests — over plaintext to a remote host
/// those are exposed to passive MITM. `https://` endpoints (TLS via tonic's
/// webpki roots) and loopback endpoints pass.
pub(crate) fn reject_insecure_endpoint(endpoint: &str) -> anyhow::Result<()> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("endpoint '{endpoint}' is missing a scheme"))?;
    if scheme.eq_ignore_ascii_case("https") {
        return Ok(());
    }
    let host = if let Some(v6) = rest.strip_prefix('[') {
        v6.split(']').next().unwrap_or(v6)
    } else {
        rest.split(['/', ':']).next().unwrap_or(rest)
    };
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if loopback {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "refusing to connect to non-loopback host '{host}' over plaintext \
             '{scheme}://' — use an 'https://' endpoint (AUDIT 2026-05-19 H-11)"
        ))
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::reject_insecure_endpoint;

    #[test]
    fn loopback_plaintext_allowed() {
        assert!(reject_insecure_endpoint("http://localhost:5555").is_ok());
        assert!(reject_insecure_endpoint("http://127.0.0.1:9090").is_ok());
        assert!(reject_insecure_endpoint("http://[::1]:9090").is_ok());
    }

    #[test]
    fn https_allowed_anywhere() {
        assert!(reject_insecure_endpoint("https://node.example.com").is_ok());
        assert!(reject_insecure_endpoint("https://10.0.0.5:9090").is_ok());
    }

    #[test]
    fn remote_plaintext_rejected() {
        assert!(reject_insecure_endpoint("http://node.example.com:9090").is_err());
        assert!(reject_insecure_endpoint("http://10.0.0.5:9090").is_err());
    }

    #[test]
    fn missing_scheme_rejected() {
        assert!(reject_insecure_endpoint("localhost:5555").is_err());
    }
}
