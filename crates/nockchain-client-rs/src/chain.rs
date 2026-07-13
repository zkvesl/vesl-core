//! Nockchain public gRPC client — transaction submission, balance queries, polling.
//!
//! Wraps `PublicNockchainGrpcClient` with high-level methods for the operations
//! every NockApp needs: submit a transaction, wait for it to land in a block,
//! and query balances.
//!
//! # Usage
//!
//! ```ignore
//! let mut client = ChainClient::connect(ChainConfig::default()).await?;
//!
//! // Submit and wait for block inclusion
//! let accepted = client.submit_and_wait(raw_tx, "tx-id-base58").await?;
//!
//! // Query balance by address or PKH
//! let balance = client.get_balance_by_pkh("pkh-base58", 1).await?;
//! ```

use std::time::Duration;

use anyhow::Result;
use nockapp_grpc::pb::public::v2::nockchain_block_service_client::NockchainBlockServiceClient;
use nockchain_types::tx_engine::common::Hash as ChainHash;
use nockchain_types::tx_engine::v1::tx::SpendCondition;
use tonic::transport::Channel;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for chain interaction.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// gRPC endpoint URL (e.g., `http://localhost:9090`).
    ///
    /// Security-critical: carries balance queries and tx submission. A
    /// non-loopback host must use `https://` — `connect` rejects
    /// plaintext to a remote host (AUDIT 2026-05-19 H-11).
    pub endpoint: String,
    /// How often to poll `transaction_accepted` in `wait_for_acceptance`.
    pub poll_interval: Duration,
    /// Maximum time to wait for transaction acceptance before giving up.
    pub accept_timeout: Duration,
}

impl ChainConfig {
    /// Create a config pointing at a local Nockchain node with sensible defaults.
    ///
    /// Defaults: 5s poll interval, 120s timeout.
    pub fn local(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            poll_interval: Duration::from_secs(5),
            accept_timeout: Duration::from_secs(120),
        }
    }
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self::local("http://localhost:9090")
    }
}

// ---------------------------------------------------------------------------
// ChainClient
// ---------------------------------------------------------------------------

/// Client for interacting with a Nockchain node's public gRPC API.
///
/// Provides methods for:
/// - Submitting pre-signed transactions
/// - Polling for transaction acceptance (block inclusion)
/// - Querying balances by address, PKH, or FirstName
/// - Fetching block-explorer data for an existing tx
pub struct ChainClient {
    client: nockapp_grpc::services::public_nockchain::PublicNockchainGrpcClient,
    // Raw tonic client for the block-explorer service. Upstream's
    // `PublicNockchainGrpcClient` wraps `NockchainService` only;
    // block-explorer RPCs (`get_transaction_block`,
    // `get_transaction_details`) live on the separate
    // `NockchainBlockService`. Drop this once the wrapper covers it.
    block: NockchainBlockServiceClient<Channel>,
    config: ChainConfig,
}

impl ChainClient {
    /// Connect to a Nockchain node's public gRPC endpoint.
    pub async fn connect(config: ChainConfig) -> Result<Self> {
        crate::reject_insecure_endpoint(&config.endpoint)?;
        let client = nockapp_grpc::services::public_nockchain::PublicNockchainGrpcClient::connect(
            &config.endpoint,
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to connect to Nockchain gRPC at {}: {e:?}", config.endpoint
            )
        })?;
        let block = NockchainBlockServiceClient::connect(config.endpoint.clone())
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to connect block-service client to {}: {e:?}", config.endpoint
                )
            })?;
        Ok(Self {
            client,
            block,
            config,
        })
    }

    /// Submit a pre-signed raw transaction to the Nockchain node.
    ///
    /// Returns `Ok(())` on acknowledgment. The transaction is not yet in a
    /// block — call [`wait_for_acceptance`] to confirm inclusion.
    pub async fn submit_transaction(
        &mut self,
        raw_tx: nockchain_types::tx_engine::v1::RawTx,
    ) -> Result<()> {
        self.client
            .wallet_send_transaction(raw_tx)
            .await
            .map_err(|e| anyhow::anyhow!("failed to submit transaction: {e:?}"))?;
        Ok(())
    }

    /// Check if a previously submitted transaction has been accepted into a block.
    ///
    /// Returns `true` if accepted, `false` if not yet accepted.
    pub async fn check_accepted(&mut self, tx_id_base58: &str) -> Result<bool> {
        use nockapp_grpc::pb::public::v2::transaction_accepted_response;

        let tx_id = nockapp_grpc::pb::common::v1::Base58Hash {
            hash: tx_id_base58.to_string(),
        };
        let resp = self
            .client
            .transaction_accepted(tx_id)
            .await
            .map_err(|e| anyhow::anyhow!("failed to check transaction acceptance: {e:?}"))?;

        match resp.result {
            Some(transaction_accepted_response::Result::Accepted(accepted)) => Ok(accepted),
            _ => Ok(false),
        }
    }

    /// Poll until a transaction is accepted into a block, or timeout.
    ///
    /// Uses `config.poll_interval` and `config.accept_timeout`.
    /// Returns `Ok(true)` if accepted, `Ok(false)` if timed out.
    pub async fn wait_for_acceptance(&mut self, tx_id_base58: &str) -> Result<bool> {
        let deadline = tokio::time::Instant::now() + self.config.accept_timeout;

        loop {
            match self.check_accepted(tx_id_base58).await {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(e) => {
                    // AUDIT 2026-05-21 L-19: structured warning, not a raw
                    // stderr print, so the retry surfaces to log filters.
                    tracing::warn!("check_accepted error (will retry): {e}");
                }
            }

            if tokio::time::Instant::now() + self.config.poll_interval > deadline {
                return Ok(false);
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    /// Submit a transaction and wait for it to be accepted.
    ///
    /// Combines `submit_transaction` + `wait_for_acceptance`.
    /// Returns `true` if the transaction was accepted before timeout.
    pub async fn submit_and_wait(
        &mut self,
        raw_tx: nockchain_types::tx_engine::v1::RawTx,
        tx_id_base58: &str,
    ) -> Result<bool> {
        self.submit_transaction(raw_tx).await?;
        self.wait_for_acceptance(tx_id_base58).await
    }

    /// Look up the block that included a given tx, if any.
    ///
    /// Returns:
    /// - `InBlock { ... }` if the tx is confirmed in a block.
    /// - `Pending` if the tx is in the mempool but not yet in a block.
    /// - `NotFound` if the node has no record of this tx.
    ///
    /// The chain serves `NotFound` as a gRPC `Status::not_found` error;
    /// other gRPC errors are returned as `Err`.
    pub async fn get_transaction_block(
        &mut self,
        tx_id_base58: &str,
    ) -> Result<TransactionBlockResult> {
        use nockapp_grpc::pb::common::v1::Base58Hash;
        use nockapp_grpc::pb::public::v2::{
            GetTransactionBlockRequest, get_transaction_block_response,
        };

        let req = GetTransactionBlockRequest {
            tx_id: Some(Base58Hash {
                hash: tx_id_base58.to_string(),
            }),
        };

        let resp = match self.block.get_transaction_block(req).await {
            Ok(r) => r.into_inner(),
            Err(status)
                if status.code() == tonic::Code::NotFound
                    || status.code() == tonic::Code::InvalidArgument =>
            {
                // Malformed or unknown tx_id mean the same thing for a
                // receipt: nothing to attest to. Surface both as `NotFound`.
                return Ok(TransactionBlockResult::NotFound);
            }
            Err(status) => {
                return Err(anyhow::anyhow!(
                    "get_transaction_block({tx_id_base58}) failed: {status}"
                ));
            }
        };

        match resp.result {
            Some(get_transaction_block_response::Result::Block(b)) => {
                let block_id = pb_hash_to_base58(b.block_id, "block_id")?;
                let parent = pb_hash_to_base58(b.parent, "parent")?;
                Ok(TransactionBlockResult::InBlock {
                    block_id,
                    height: b.height,
                    parent,
                    timestamp: b.timestamp,
                })
            }
            Some(get_transaction_block_response::Result::Pending(_)) => {
                Ok(TransactionBlockResult::Pending)
            }
            Some(get_transaction_block_response::Result::Error(err)) => Err(anyhow::anyhow!(
                "get_transaction_block returned error: {}", err.message
            )),
            None => Err(anyhow::anyhow!(
                "get_transaction_block returned an empty response"
            )),
        }
    }

    /// Fetch the inputs/outputs/fees for a given tx.
    ///
    /// Same `NotFound`/`Pending`/`Found` semantics as `get_transaction_block`.
    pub async fn get_transaction_details(
        &mut self,
        tx_id_base58: &str,
    ) -> Result<TransactionDetailsResult> {
        use nockapp_grpc::pb::common::v1::Base58Hash;
        use nockapp_grpc::pb::public::v2::{
            GetTransactionDetailsRequest, get_transaction_details_response, transaction_details,
            transaction_output,
        };

        let req = GetTransactionDetailsRequest {
            tx_id: Some(Base58Hash {
                hash: tx_id_base58.to_string(),
            }),
        };

        let resp = match self.block.get_transaction_details(req).await {
            Ok(r) => r.into_inner(),
            Err(status)
                if status.code() == tonic::Code::NotFound
                    || status.code() == tonic::Code::InvalidArgument =>
            {
                return Ok(TransactionDetailsResult::NotFound);
            }
            Err(status) => {
                return Err(anyhow::anyhow!(
                    "get_transaction_details({tx_id_base58}) failed: {status}"
                ));
            }
        };

        let pb = match resp.result {
            Some(get_transaction_details_response::Result::Details(d)) => d,
            Some(get_transaction_details_response::Result::Pending(_)) => {
                return Ok(TransactionDetailsResult::Pending);
            }
            Some(get_transaction_details_response::Result::Error(err)) => {
                return Err(anyhow::anyhow!(
                    "get_transaction_details returned error: {}", err.message
                ));
            }
            None => {
                return Err(anyhow::anyhow!(
                    "get_transaction_details returned an empty response"
                ));
            }
        };

        let block_id = pb_hash_to_base58(pb.block_id, "block_id")?;
        let parent = pb_hash_to_base58(pb.parent, "parent")?;
        let total_input = pb.total_input.map(|n| n.value).unwrap_or(0);
        let total_output = pb
            .total_output_required
            .map(|transaction_details::TotalOutputRequired::TotalOutput(n)| n.value);
        let fee = pb
            .fee_required
            .map(|transaction_details::FeeRequired::Fee(n)| n.value);

        let inputs = pb
            .inputs
            .into_iter()
            .map(|i| TxInput {
                note_name_b58: i.note_name_b58,
                amount: i.amount.map(|n| n.value).unwrap_or(0),
                source_tx_id: i.source_tx_id,
                coinbase: i.coinbase,
            })
            .collect();

        let outputs = pb
            .outputs
            .into_iter()
            .map(|o| TxOutput {
                note_name_b58: o.note_name_b58,
                amount: o
                    .amount_required
                    .map(|transaction_output::AmountRequired::Amount(n)| n.value),
                lock_summary: o.lock_summary,
            })
            .collect();

        Ok(TransactionDetailsResult::Found(TransactionDetails {
            tx_id: pb.tx_id,
            block_id,
            height: pb.height,
            timestamp: pb.timestamp,
            version: pb.version,
            size_bytes: pb.size_bytes,
            total_input,
            total_output,
            fee,
            inputs,
            outputs,
            parent,
        }))
    }

    /// Get balance by full SchnorrPubkey address (base58, 97 bytes decoded).
    pub async fn get_balance(
        &mut self,
        address: &str,
    ) -> Result<nockapp_grpc::pb::common::v2::Balance> {
        use nockapp_grpc::services::public_nockchain::v2::client::BalanceRequest;
        self.client
            .wallet_get_balance(&BalanceRequest::Address(address.to_string()))
            .await
            .map_err(|e| anyhow::anyhow!("failed to get balance: {e:?}"))
    }

    /// Try to get balance, falling back from Address to FirstName selector.
    ///
    /// The Address selector requires a full SchnorrPubkey (97 bytes base58).
    /// If that fails (e.g., input is a PKH hash), falls back to FirstName.
    pub async fn get_balance_flexible(
        &mut self,
        address: &str,
    ) -> Result<nockapp_grpc::pb::common::v2::Balance> {
        use nockapp_grpc::services::public_nockchain::v2::client::BalanceRequest;
        match self
            .client
            .wallet_get_balance(&BalanceRequest::Address(address.to_string()))
            .await
        {
            Ok(bal) => Ok(bal),
            Err(_) => self
                .client
                .wallet_get_balance(&BalanceRequest::FirstName(address.to_string()))
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to get balance for '{}' (tried Address and FirstName): {e:?}",
                        address
                    )
                }),
        }
    }

    /// Get balance by PKH using FirstName computation.
    ///
    /// Computes the note FirstName from the PKH + spend condition, then
    /// queries via `BalanceRequest::FirstName`. Tries coinbase FirstName
    /// first (mining rewards have a timelock), then simple P2PKH.
    pub async fn get_balance_by_pkh(
        &mut self,
        pkh_b58: &str,
        coinbase_timelock_min: u64,
    ) -> Result<nockapp_grpc::pb::common::v2::Balance> {
        use nockapp_grpc::services::public_nockchain::v2::client::BalanceRequest;

        let coinbase_fn = compute_coinbase_first_name(pkh_b58, coinbase_timelock_min)?;
        let simple_fn = compute_simple_first_name(pkh_b58)?;

        match self
            .client
            .wallet_get_balance(&BalanceRequest::FirstName(coinbase_fn.clone()))
            .await
        {
            Ok(bal) if !bal.notes.is_empty() => Ok(bal),
            _ => self
                .client
                .wallet_get_balance(&BalanceRequest::FirstName(simple_fn))
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to get balance by PKH '{}' (tried coinbase and simple): {e:?}",
                        pkh_b58
                    )
                }),
        }
    }

    /// Get the underlying config.
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Block-explorer result types
// ---------------------------------------------------------------------------

/// Result of `get_transaction_block`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionBlockResult {
    /// Tx is included in a confirmed block.
    InBlock {
        block_id: String,
        height: u64,
        parent: String,
        timestamp: u64,
    },
    /// Tx is in the mempool but not yet in a block.
    Pending,
    /// Node has no record of this tx.
    NotFound,
}

/// Result of `get_transaction_details`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionDetailsResult {
    Found(TransactionDetails),
    Pending,
    NotFound,
}

/// Inputs/outputs/fees for a confirmed tx.
///
/// Mirrors `nockapp_grpc::pb::public::v2::TransactionDetails` with the
/// required-oneof fields lifted into plain `Option`s and `Hash` values
/// rendered as base58 strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionDetails {
    pub tx_id: String,
    pub block_id: String,
    pub height: u64,
    pub timestamp: u64,
    pub version: u64,
    pub size_bytes: u64,
    pub total_input: u64,
    /// `None` if the proto field was unset (proto3 optional semantics).
    pub total_output: Option<u64>,
    /// `None` if the proto field was unset.
    pub fee: Option<u64>,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub parent: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    pub note_name_b58: String,
    pub amount: u64,
    pub source_tx_id: String,
    pub coinbase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub note_name_b58: String,
    /// `None` if the proto field was unset.
    pub amount: Option<u64>,
    pub lock_summary: String,
}

// Convert a proto `common::v1::Hash` (5-belt limbs) to its base58 string form.
// Returns an error if the hash field was unset or any belt was missing.
fn pb_hash_to_base58(
    hash: Option<nockapp_grpc::pb::common::v1::Hash>,
    field: &str,
) -> Result<String> {
    let h = hash.ok_or_else(|| anyhow::anyhow!("{field} hash field was unset"))?;
    let belts = [
        h.belt_1
            .ok_or_else(|| anyhow::anyhow!("{field}.belt_1 unset"))?
            .value,
        h.belt_2
            .ok_or_else(|| anyhow::anyhow!("{field}.belt_2 unset"))?
            .value,
        h.belt_3
            .ok_or_else(|| anyhow::anyhow!("{field}.belt_3 unset"))?
            .value,
        h.belt_4
            .ok_or_else(|| anyhow::anyhow!("{field}.belt_4 unset"))?
            .value,
        h.belt_5
            .ok_or_else(|| anyhow::anyhow!("{field}.belt_5 unset"))?
            .value,
    ];
    use nockchain_math::belt::Belt;
    let chain_hash =
        ChainHash([Belt(belts[0]), Belt(belts[1]), Belt(belts[2]), Belt(belts[3]), Belt(belts[4])]);
    Ok(chain_hash.to_base58())
}

// ---------------------------------------------------------------------------
// FirstName computation — derive note FirstName from a PKH
// ---------------------------------------------------------------------------

/// Compute the FirstName for coinbase (mining reward) notes at a given PKH.
///
/// Coinbase notes have a P2PKH lock + relative timelock. The FirstName is
/// the hash of the lock root, which includes both the PKH and the timelock.
pub fn compute_coinbase_first_name(pkh_b58: &str, coinbase_relative_min: u64) -> Result<String> {
    let pkh = ChainHash::from_base58(pkh_b58)
        .map_err(|e| anyhow::anyhow!("invalid PKH base58 '{}': {e:?}", pkh_b58))?;
    let sc = SpendCondition::coinbase_pkh(pkh, coinbase_relative_min);
    let first_name = sc
        .first_name()
        .map_err(|e| anyhow::anyhow!("failed to compute coinbase FirstName: {e:?}"))?;
    Ok(first_name.to_base58())
}

/// Compute the FirstName for simple P2PKH (transfer) notes at a given PKH.
///
/// Simple P2PKH notes have only a PKH lock (no timelock). Used for regular
/// transfers and settlement outputs.
pub fn compute_simple_first_name(pkh_b58: &str) -> Result<String> {
    let pkh = ChainHash::from_base58(pkh_b58)
        .map_err(|e| anyhow::anyhow!("invalid PKH base58 '{}': {e:?}", pkh_b58))?;
    let sc = SpendCondition::simple_pkh(pkh);
    let first_name = sc
        .first_name()
        .map_err(|e| anyhow::anyhow!("failed to compute simple FirstName: {e:?}"))?;
    Ok(first_name.to_base58())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_config_defaults() {
        let cfg = ChainConfig::default();
        assert_eq!(cfg.endpoint, "http://localhost:9090");
        assert_eq!(cfg.poll_interval, Duration::from_secs(5));
        assert_eq!(cfg.accept_timeout, Duration::from_secs(120));
    }

    #[test]
    fn chain_config_local() {
        let cfg = ChainConfig::local("http://node:8080");
        assert_eq!(cfg.endpoint, "http://node:8080");
        assert_eq!(cfg.poll_interval, Duration::from_secs(5));
    }

    /// Known-good PKH from the Nockchain fakenet.
    const TEST_MINING_PKH: &str = "9yPePjfWAdUnzaQKyxcRXKRa5PpUzKKEwtpECBZsUYt9Jd7egSDEWoV";

    #[test]
    fn coinbase_first_name_computes_from_pkh() {
        let fn_str = compute_coinbase_first_name(TEST_MINING_PKH, 1)
            .expect("coinbase first_name should compute from valid PKH");
        assert!(!fn_str.is_empty());
    }

    #[test]
    fn simple_first_name_computes_from_pkh() {
        let fn_str = compute_simple_first_name(TEST_MINING_PKH)
            .expect("simple first_name should compute from valid PKH");
        assert!(!fn_str.is_empty());
    }

    #[test]
    fn first_names_differ_by_type() {
        let coinbase = compute_coinbase_first_name(TEST_MINING_PKH, 1).unwrap();
        let simple = compute_simple_first_name(TEST_MINING_PKH).unwrap();
        assert_ne!(
            coinbase, simple,
            "coinbase and simple first_names must differ"
        );
    }

    #[test]
    fn coinbase_first_name_rejects_invalid_pkh() {
        let result = compute_coinbase_first_name("not-valid-base58!!!", 1);
        assert!(result.is_err());
    }
}
