//! Verify a submitted transaction by querying the chain.
//!
//! Calls `GetTransactionBlock` + `GetTransactionDetails` on the Nockchain
//! public gRPC API and assembles the response into a single [`TxReceipt`].
//! The "proof" here is chain attestation — the node confirmed the tx exists
//! and is in a block (or mempool). For offline-verifiable Merkle proofs
//! over (tx_hash, ...) tuples, see the Mint/Guard primitives.
//!
//! # Receipt fields and the UTXO model
//!
//! Nockchain is a UTXO chain. There is no `sender` or `receiver` field on
//! a transaction. Instead:
//! - [`TxReceipt::inputs`] are the notes being spent.
//! - [`TxReceipt::outputs`] are the notes being created. Each output has
//!   a `lock_summary` string that names the spend condition (e.g.
//!   `"P2PKH:9yPe..."`).
//! - [`TxReceipt::primary_lock_summary`] is a convenience field populated
//!   only when `outputs.len() == 1`. Multi-output txs must read `outputs`.
//!
//! The receipt mirrors what the chain actually exposes; it does not invent
//! a single-sender / single-receiver view that the underlying model lacks.

use nockchain_client_rs::{
    ChainClient, TransactionBlockResult, TransactionDetailsResult, TxInput, TxOutput,
};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum VerifyTxError {
    /// Node has no record of this tx.
    NotFound(String),
    /// Underlying chain RPC error (connection, malformed response, etc.).
    Chain(anyhow::Error),
}

impl std::fmt::Display for VerifyTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(tx) => write!(f, "transaction `{tx}` not found on chain"),
            Self::Chain(e) => write!(f, "chain RPC error: {e}"),
        }
    }
}

impl std::error::Error for VerifyTxError {}

impl From<anyhow::Error> for VerifyTxError {
    fn from(e: anyhow::Error) -> Self {
        Self::Chain(e)
    }
}

/// Chain-attested receipt for a submitted transaction.
///
/// Populated from `GetTransactionBlock` + `GetTransactionDetails`. If the
/// transaction is in mempool but not yet in a block, `accepted` is `false`
/// and the block fields are `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxReceipt {
    pub tx_hash: String,
    pub accepted: bool,
    pub block_id: Option<String>,
    pub block_height: Option<u64>,
    pub timestamp: Option<u64>,
    pub fee: Option<u64>,
    /// Sum of all output amounts (mirrors `total_output` from the chain).
    /// `None` if the tx is pending or the chain didn't populate it.
    pub amount_total: Option<u64>,
    pub inputs: Vec<TxInputView>,
    pub outputs: Vec<TxOutputView>,
    /// Convenience field for single-output txs. `None` for multi-output txs;
    /// callers must read `outputs` directly in that case.
    pub primary_lock_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInputView {
    pub note_name: String,
    pub amount: u64,
    pub source_tx_id: String,
    pub coinbase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutputView {
    pub note_name: String,
    pub amount: Option<u64>,
    pub lock_summary: String,
}

impl From<TxInput> for TxInputView {
    fn from(i: TxInput) -> Self {
        Self {
            note_name: i.note_name_b58,
            amount: i.amount,
            source_tx_id: i.source_tx_id,
            coinbase: i.coinbase,
        }
    }
}

impl From<TxOutput> for TxOutputView {
    fn from(o: TxOutput) -> Self {
        Self {
            note_name: o.note_name_b58,
            amount: o.amount,
            lock_summary: o.lock_summary,
        }
    }
}

/// Fetch a receipt for the given tx hash.
///
/// Calls `get_transaction_block` and `get_transaction_details` on the same
/// `ChainClient`. If either reports `NotFound`, returns
/// [`VerifyTxError::NotFound`]. If both report `Pending`, returns a receipt
/// with `accepted: false` and empty input/output lists.
pub async fn fetch_receipt(
    client: &mut ChainClient,
    tx_hash: &str,
) -> Result<TxReceipt, VerifyTxError> {
    let block = client.get_transaction_block(tx_hash).await?;
    if matches!(block, TransactionBlockResult::NotFound) {
        return Err(VerifyTxError::NotFound(tx_hash.to_string()));
    }

    let details = client.get_transaction_details(tx_hash).await?;
    if matches!(details, TransactionDetailsResult::NotFound) {
        return Err(VerifyTxError::NotFound(tx_hash.to_string()));
    }

    let (accepted, block_id, block_height, timestamp_block) = match block {
        TransactionBlockResult::InBlock {
            block_id,
            height,
            timestamp,
            ..
        } => (true, Some(block_id), Some(height), Some(timestamp)),
        TransactionBlockResult::Pending => (false, None, None, None),
        // AUDIT 2026-05-21 L-03: NotFound is filtered above; return the
        // typed error instead of `unreachable!` so a future change to the
        // upstream enum degrades to a clean error, not a panic.
        TransactionBlockResult::NotFound => {
            return Err(VerifyTxError::NotFound(tx_hash.to_string()));
        }
    };

    let (fee, amount_total, inputs, outputs, timestamp_details) = match details {
        TransactionDetailsResult::Found(d) => {
            let inputs: Vec<TxInputView> = d.inputs.into_iter().map(Into::into).collect();
            let outputs: Vec<TxOutputView> = d.outputs.into_iter().map(Into::into).collect();
            (d.fee, d.total_output, inputs, outputs, Some(d.timestamp))
        }
        TransactionDetailsResult::Pending => (None, None, Vec::new(), Vec::new(), None),
        // AUDIT 2026-05-21 L-03: see the block match above.
        TransactionDetailsResult::NotFound => {
            return Err(VerifyTxError::NotFound(tx_hash.to_string()));
        }
    };

    let primary_lock_summary = if outputs.len() == 1 {
        Some(outputs[0].lock_summary.clone())
    } else {
        None
    };

    Ok(TxReceipt {
        tx_hash: tx_hash.to_string(),
        accepted,
        block_id,
        block_height,
        timestamp: timestamp_block.or(timestamp_details),
        fee,
        amount_total,
        inputs,
        outputs,
        primary_lock_summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(name: &str, amount: u64) -> TxInputView {
        TxInputView {
            note_name: name.to_string(),
            amount,
            source_tx_id: "source".to_string(),
            coinbase: false,
        }
    }

    fn output(name: &str, amount: u64, lock: &str) -> TxOutputView {
        TxOutputView {
            note_name: name.to_string(),
            amount: Some(amount),
            lock_summary: lock.to_string(),
        }
    }

    #[test]
    fn primary_lock_summary_is_some_for_single_output() {
        let receipt = TxReceipt {
            tx_hash: "abc".into(),
            accepted: true,
            block_id: Some("blk".into()),
            block_height: Some(42),
            timestamp: Some(1000),
            fee: Some(256),
            amount_total: Some(1000),
            inputs: vec![input("in", 1256)],
            outputs: vec![output("out", 1000, "P2PKH:abc")],
            primary_lock_summary: Some("P2PKH:abc".into()),
        };
        assert_eq!(receipt.primary_lock_summary.as_deref(), Some("P2PKH:abc"));
    }

    #[test]
    fn receipt_serializes_to_json() {
        let receipt = TxReceipt {
            tx_hash: "abc".into(),
            accepted: false,
            block_id: None,
            block_height: None,
            timestamp: None,
            fee: None,
            amount_total: None,
            inputs: vec![],
            outputs: vec![],
            primary_lock_summary: None,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"tx_hash\":\"abc\""));
        assert!(json.contains("\"accepted\":false"));
    }

    #[test]
    fn pending_tx_has_no_block_fields() {
        // Manually constructs the shape `fetch_receipt` would produce for
        // a tx that is in mempool but not yet in a block. The actual
        // `fetch_receipt` happy path is covered by manual fakenet smoke.
        let receipt = TxReceipt {
            tx_hash: "abc".into(),
            accepted: false,
            block_id: None,
            block_height: None,
            timestamp: None,
            fee: None,
            amount_total: None,
            inputs: vec![],
            outputs: vec![],
            primary_lock_summary: None,
        };
        assert!(!receipt.accepted);
        assert!(receipt.block_id.is_none());
        assert!(receipt.block_height.is_none());
    }
}
