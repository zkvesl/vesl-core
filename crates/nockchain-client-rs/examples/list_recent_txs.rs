//! List tx_ids from recent blocks on a connected Nockchain node.
//!
//! Smoke-test helper for verify-tx: pulls a real tx_id off the chain so
//! you can hit `GET /tx/<id>` against a running hull. Defaults to a local
//! fakenet endpoint; pass `--endpoint <url>` to override.
//!
//! Run with:
//!   cargo run -p nockchain-client-rs --example list_recent_txs
//!
//! Prints up to 5 tx_ids per block for the most-recent blocks.

use anyhow::Result;
use nockapp_grpc::pb::common::v1::PageRequest;
use nockapp_grpc::pb::public::v2::nockchain_block_service_client::NockchainBlockServiceClient;
use nockapp_grpc::pb::public::v2::{GetBlocksRequest, get_blocks_response};

#[tokio::main]
async fn main() -> Result<()> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:9090".to_string());
    eprintln!("connecting to {endpoint}");

    let mut client = NockchainBlockServiceClient::connect(endpoint).await?;

    let req = GetBlocksRequest {
        page: Some(PageRequest {
            client_page_items_limit: 10,
            page_token: String::new(),
            max_bytes: 0,
        }),
    };
    let resp = client.get_blocks(req).await?.into_inner();

    let blocks = match resp.result {
        Some(get_blocks_response::Result::Blocks(b)) => b,
        Some(get_blocks_response::Result::Error(e)) => {
            anyhow::bail!("server error: {}", e.message);
        }
        None => anyhow::bail!("empty response"),
    };

    println!("current_height={}", blocks.current_height);
    println!("returned_blocks={}", blocks.blocks.len());
    for b in blocks.blocks.iter().rev() {
        println!("height={} txs={}", b.height, b.tx_ids.len());
        for tx in b.tx_ids.iter().take(5) {
            println!("  {}", tx.hash);
        }
    }
    Ok(())
}
