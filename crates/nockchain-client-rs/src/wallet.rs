//! Wallet coordination — private gRPC client for nockchain-wallet.
//!
//! Communicates with a separately funded nockchain-wallet instance
//! via its private gRPC endpoint (default: `localhost:5555`).
//!
//! The wallet handles all key management and transaction signing.
//! This client coordinates via peek (query) and poke (command) calls.
//!
//! # Usage
//!
//! ```ignore
//! let mut wallet = WalletClient::connect(WalletConfig::default()).await?;
//!
//! // Check wallet is alive
//! let ready = wallet.check_ready().await?;
//!
//! // Query balance
//! let balance = wallet.peek_balance("pubkey-base58").await?;
//!
//! // Request signing
//! wallet.request_sign_hash("tx-hash-base58", 0, false).await?;
//!
//! // Create and broadcast a transaction
//! wallet.request_create_tx("first", "last", "recipient", 100_000, 1_000).await?;
//! ```

use anyhow::Result;
use nockapp::noun::slab::{NockJammer, NounSlab};
use nockvm::ext::make_tas;
use nockvm::noun::{D, Noun, T};
use noun_serde::NounEncode;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for wallet coordination.
#[derive(Debug, Clone)]
pub struct WalletConfig {
    /// Private gRPC endpoint of the wallet instance.
    ///
    /// Security-critical: carries signing requests. A non-loopback host
    /// must use `https://` — `connect` rejects plaintext to a remote
    /// host (AUDIT 2026-05-19 H-11).
    pub endpoint: String,
}

impl WalletConfig {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
        }
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self::new("http://localhost:5555")
    }
}

// ---------------------------------------------------------------------------
// WalletBalance
// ---------------------------------------------------------------------------

/// Wallet balance data returned from a peek query.
#[derive(Debug, Clone)]
pub struct WalletBalance {
    /// Raw JAM-encoded balance data from wallet kernel.
    /// Full decoding depends on wallet kernel state format.
    pub raw_data: Vec<u8>,
}

impl std::fmt::Display for WalletBalance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WalletBalance({} bytes)", self.raw_data.len())
    }
}

// ---------------------------------------------------------------------------
// WalletClient
// ---------------------------------------------------------------------------

/// Client for coordinating with a nockchain-wallet instance.
///
/// Communicates via the wallet's private gRPC API (peek/poke).
/// The wallet handles all key management and signing internally.
pub struct WalletClient {
    client: nockapp_grpc::private_nockapp::PrivateNockAppGrpcClient,
    config: WalletConfig,
    pid_counter: u32,
}

impl WalletClient {
    /// Connect to a wallet's private gRPC endpoint.
    pub async fn connect(config: WalletConfig) -> Result<Self> {
        crate::reject_insecure_endpoint(&config.endpoint)?;
        let client =
            nockapp_grpc::private_nockapp::PrivateNockAppGrpcClient::connect(&config.endpoint)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("failed to connect to wallet at {}: {e:?}", config.endpoint)
                })?;
        Ok(Self {
            client,
            config,
            pid_counter: 0,
        })
    }

    /// Monotonic request id for gRPC peek/poke correlation.
    ///
    /// AUDIT 2026-05-21 L-20: the counter is `u32`, not `i32`, so it
    /// cycles the full 2^32 range cleanly instead of `wrapping_add`-ing
    /// into negative values that the old code patched with an ad-hoc
    /// reset. The gRPC `pid` field is int32, so the reinterpret cast is
    /// the wire encoding — a negative correlation id is a valid distinct
    /// value (it indexes nothing; the wallet only matches on it).
    fn next_pid(&mut self) -> i32 {
        self.pid_counter = self.pid_counter.wrapping_add(1);
        self.pid_counter as i32
    }

    /// Check if the wallet is running and responsive.
    ///
    /// Attempts a peek; returns `true` if the wallet's gRPC server
    /// responds (even with an application-level error).
    pub async fn check_ready(&mut self) -> Result<bool> {
        let path = build_peek_path(&["show"]);
        let pid = self.next_pid();
        match self.client.peek(pid, path).await {
            Ok(_) => Ok(true),
            Err(nockapp_grpc::NockAppGrpcError::Internal(_)) => {
                // Wallet returned an app-level error — gRPC server is alive.
                Ok(true)
            }
            Err(e) => Err(anyhow::anyhow!("wallet not responsive: {e:?}")),
        }
    }

    /// Query wallet balance by public key (base58).
    ///
    /// Returns raw JAM-encoded balance data from the wallet kernel.
    pub async fn peek_balance(&mut self, pubkey_b58: &str) -> Result<WalletBalance> {
        let path = build_peek_path(&["balance-by-pubkey", pubkey_b58]);
        let pid = self.next_pid();
        let data = self
            .client
            .peek(pid, path)
            .await
            .map_err(|e| anyhow::anyhow!("failed to peek wallet balance: {e:?}"))?;
        Ok(WalletBalance { raw_data: data })
    }

    /// Query wallet balance by note first-name (base58 hash).
    pub async fn peek_balance_by_name(&mut self, first_name_b58: &str) -> Result<WalletBalance> {
        let path = build_peek_path(&["balance-by-first-name", first_name_b58]);
        let pid = self.next_pid();
        let data = self
            .client
            .peek(pid, path)
            .await
            .map_err(|e| anyhow::anyhow!("failed to peek wallet balance: {e:?}"))?;
        Ok(WalletBalance { raw_data: data })
    }

    /// Request the wallet to sign a hash.
    ///
    /// Pokes the wallet with `[%sign-hash hash key-index hardened]`.
    /// Returns `true` if the wallet acknowledged the poke.
    pub async fn request_sign_hash(
        &mut self,
        hash_b58: &str,
        key_index: u64,
        hardened: bool,
    ) -> Result<bool> {
        let payload = build_sign_hash_poke(hash_b58, key_index, hardened);
        let wire = nockapp_grpc::wire_conversion::create_grpc_wire();
        let pid = self.next_pid();
        self.client
            .poke(pid, wire, payload)
            .await
            .map_err(|e| anyhow::anyhow!("wallet sign-hash failed: {e:?}"))
    }

    /// Request the wallet to create and broadcast a transaction.
    ///
    /// Spends the specified input UTXO, creates an output to the recipient.
    /// The wallet handles signing and broadcasting internally.
    pub async fn request_create_tx(
        &mut self,
        input_first: &str,
        input_last: &str,
        recipient_address: &str,
        amount_nicks: u64,
        fee_nicks: u64,
    ) -> Result<bool> {
        let payload = build_create_tx_poke(
            input_first, input_last, recipient_address, amount_nicks, fee_nicks,
        );
        let wire = nockapp_grpc::wire_conversion::create_grpc_wire();
        let pid = self.next_pid();
        self.client
            .poke(pid, wire, payload)
            .await
            .map_err(|e| anyhow::anyhow!("wallet create-tx failed: {e:?}"))
    }

    /// Get the wallet config.
    pub fn config(&self) -> &WalletConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Noun construction — free functions for testability
// ---------------------------------------------------------------------------

/// Build a JAM-encoded peek path from string segments.
///
/// The wallet kernel expects peek paths as Nock lists of cord atoms.
/// `["balance-by-pubkey", "abc123"]` becomes `[%balance-by-pubkey %abc123 ~]`.
pub fn build_peek_path(segments: &[&str]) -> Vec<u8> {
    let mut slab: NounSlab<NockJammer> = NounSlab::new();
    let path: Vec<String> = segments.iter().map(|s| s.to_string()).collect();
    let noun = path.to_noun(&mut slab);
    slab.set_root(noun);
    slab.jam().to_vec()
}

/// Build a plain cord atom from a string's bytes.
///
/// AUDIT 2026-05-20 M-17: `make_tas` is byte-identical to this — it is
/// just `Atom::from_bytes` — but its name implies a Hoon `@tas` term.
/// base58 hashes and addresses are not valid `@tas` (they contain
/// uppercase), so build those through this honestly-named constructor.
fn make_cord(slab: &mut NounSlab<NockJammer>, s: &str) -> Noun {
    make_tas(slab, s).as_noun()
}

/// Build a JAM-encoded `sign-hash` poke payload.
///
/// Noun format: `[%sign-hash hash-cord index-atom hardened-loobean]`
pub fn build_sign_hash_poke(hash_b58: &str, key_index: u64, hardened: bool) -> Vec<u8> {
    let mut slab: NounSlab<NockJammer> = NounSlab::new();
    let tag = make_tas(&mut slab, "sign-hash").as_noun();
    let hash = make_cord(&mut slab, hash_b58);
    // AUDIT 2026-05-19 H-09: u64_to_noun picks D() vs indirect atom by
    // size; a bare D() panics the process on key_index >= 2^63.
    let index = crate::note_data::u64_to_noun(&mut slab, key_index);
    let hard: Noun = if hardened { D(0) } else { D(1) };
    let cmd = T(&mut slab, &[tag, hash, index, hard]);
    slab.set_root(cmd);
    slab.jam().to_vec()
}

/// Build a JAM-encoded `create-tx` poke payload.
///
/// Matches the wallet CLI's `create_tx` noun structure:
/// ```text
/// [%create-tx
///   names=[[first last] ~]        :: input UTXOs to spend
///   order=[[amount address] ~]    :: output recipients
///   fee=@ud                       :: miner fee in nicks
///   allow-low-fee=%.n
///   refund-pkh=~
///   sign-keys=[[0 %.n] ~]         :: sign with key index 0, not hardened
///   include-data=%.n
///   save-raw-tx=%.n
///   note-selection=%auto
/// ]
/// ```
pub fn build_create_tx_poke(
    input_first: &str,
    input_last: &str,
    recipient_address: &str,
    amount_nicks: u64,
    fee_nicks: u64,
) -> Vec<u8> {
    let mut slab: NounSlab<NockJammer> = NounSlab::new();

    let tag = make_tas(&mut slab, "create-tx").as_noun();

    // names: list of [first last] pairs
    let first = make_cord(&mut slab, input_first);
    let last = make_cord(&mut slab, input_last);
    let name_pair = T(&mut slab, &[first, last]);
    let names = T(&mut slab, &[name_pair, D(0)]);

    // order: list of [amount address] pairs
    // AUDIT 2026-05-19 H-09: u64_to_noun picks D() vs indirect atom by
    // size; a bare D() panics the process on a tx amount / fee >= 2^63.
    let amt = crate::note_data::u64_to_noun(&mut slab, amount_nicks);
    let addr = make_cord(&mut slab, recipient_address);
    let recipient_pair = T(&mut slab, &[amt, addr]);
    let order = T(&mut slab, &[recipient_pair, D(0)]);

    let fee = crate::note_data::u64_to_noun(&mut slab, fee_nicks);
    let allow_low_fee = D(1); // %.n
    let refund = D(0); // ~
    let key_pair = T(&mut slab, &[D(0), D(1)]); // [0 %.n]
    let sign_keys = T(&mut slab, &[key_pair, D(0)]); // [[0 %.n] ~]
    let include_data = D(1); // %.n
    let save_raw = D(1); // %.n
    let note_sel = make_tas(&mut slab, "auto").as_noun();

    let cmd = T(
        &mut slab,
        &[
            tag, names, order, fee, allow_low_fee, refund, sign_keys, include_data, save_raw,
            note_sel,
        ],
    );
    slab.set_root(cmd);
    slab.jam().to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_config_defaults() {
        let cfg = WalletConfig::default();
        assert_eq!(cfg.endpoint, "http://localhost:5555");
    }

    #[test]
    fn wallet_config_custom() {
        let cfg = WalletConfig::new("http://wallet:6666");
        assert_eq!(cfg.endpoint, "http://wallet:6666");
    }

    #[test]
    fn peek_path_nonempty() {
        let path = build_peek_path(&["balance-by-pubkey", "abc123"]);
        assert!(!path.is_empty());
    }

    #[test]
    fn peek_path_deterministic() {
        let p1 = build_peek_path(&["balance-by-pubkey", "key1"]);
        let p2 = build_peek_path(&["balance-by-pubkey", "key1"]);
        assert_eq!(p1, p2);
    }

    #[test]
    fn peek_path_varies_with_input() {
        let p1 = build_peek_path(&["balance-by-pubkey", "key1"]);
        let p2 = build_peek_path(&["balance-by-pubkey", "key2"]);
        assert_ne!(p1, p2);
    }

    #[test]
    fn sign_hash_poke_nonempty() {
        let payload = build_sign_hash_poke("somehash", 0, false);
        assert!(!payload.is_empty());
    }

    #[test]
    fn sign_hash_poke_deterministic() {
        let p1 = build_sign_hash_poke("hash1", 3, true);
        let p2 = build_sign_hash_poke("hash1", 3, true);
        assert_eq!(p1, p2);
    }

    #[test]
    fn sign_hash_poke_varies_with_hardened() {
        let p1 = build_sign_hash_poke("hash1", 0, false);
        let p2 = build_sign_hash_poke("hash1", 0, true);
        assert_ne!(p1, p2);
    }

    #[test]
    fn create_tx_poke_nonempty() {
        let payload = build_create_tx_poke("first", "last", "recipient", 100_000, 1_000);
        assert!(!payload.is_empty());
    }

    #[test]
    fn create_tx_poke_deterministic() {
        let p1 = build_create_tx_poke("f", "l", "r", 100, 10);
        let p2 = build_create_tx_poke("f", "l", "r", 100, 10);
        assert_eq!(p1, p2);
    }

    #[test]
    fn create_tx_poke_varies_with_amount() {
        let p1 = build_create_tx_poke("f", "l", "r", 100, 10);
        let p2 = build_create_tx_poke("f", "l", "r", 200, 10);
        assert_ne!(p1, p2);
    }

    #[test]
    fn wallet_balance_display() {
        let bal = WalletBalance {
            raw_data: vec![1, 2, 3],
        };
        let s = format!("{bal}");
        assert!(s.contains("3 bytes"));
    }
}
