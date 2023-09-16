use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ethers::providers::{Http, Middleware, Provider};
use types::{BlockHeaderWithTransaction, TransactionReceipt, H256};

use crate::common::*;
use crate::config::{Config, WatchAddress};
use crate::db::DB;

pub struct BloomProcessor {
    db: DB,
    watch_addresses: Vec<WatchAddress>,
    fetch_rpc: Provider<Http>,
    term: Arc<AtomicBool>,
}

impl BloomProcessor {
    pub fn new(
        watch_addresses: Vec<WatchAddress>,
        db: DB,
        config: Config,
        term: Arc<AtomicBool>,
    ) -> eyre::Result<Self> {
        let config = prepare_config(&config);
        let fetch_rpc = Provider::<Http>::try_from(config.execution_rpc.as_str())?;
        Ok(Self {
            db,
            watch_addresses,
            fetch_rpc,
            term,
        })
    }

    pub async fn run(&self) {
        log::info!("bloom processor started");
        let mut duration = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            exit_if_term(self.term.clone());
            duration.tick().await;

            let blocks_to_process = self.db.select_blocks_to_process();
            if blocks_to_process.is_err() {
                log::warn!("Error while selecting blocks to process");
                continue;
            }
            let block_to_process = blocks_to_process.unwrap();
            for (block_height, block_hash, block) in block_to_process {
                // Fetch receipts for a bloom positive block
                let receipts = self.fetch_receipts(&block).await;
                if receipts.is_err() {
                    log::warn!("Error while fetching receipts for block {}", block_height);
                    continue;
                }
                let receipts = receipts.unwrap();

                // We need to validate that the bloom filter contains the watch addresses as they might be false positives
                let mut positive_receipts = vec![];
                for (i, receipt) in receipts.iter().enumerate() {
                    if self.watch_addresses.iter().any(|w| {
                        w.try_against(&receipt.bloom)
                            && receipt
                                .receipt
                                .logs
                                .iter()
                                .any(|l| l.address == w.address())
                    }) {
                        // Save index of positive receipt
                        positive_receipts.push(i);
                    }
                }

                // for each positive receipt, we need to create a proof
                for receipt_index in positive_receipts {
                    // TODO: maybe we should not create proof if it's already proved onchain.
                    // There is a chance that after crash, we will process blocks that were already processed by other relayer
                    let proof = build_receipt_proof(block_hash, &block, &receipts, receipt_index);
                    if proof.is_err() {
                        log::warn!(
                            "Error while building proof for block {} receipt {}",
                            block_height,
                            receipt_index
                        );
                        continue;
                    }
                    let proof = proof.unwrap();
                    log::info!("Created a proof for a block");
                    assert!(proof.validate().is_ok());

                    // TODO: send proof to the chain
                }

                // Update block status to processed
                if self.db.mark_block_processed(block_height).is_err() {
                    log::warn!("Error while updating block {} status", block_height);
                    continue;
                }
            }
        }
    }

    async fn fetch_receipts(
        &self,
        block: &BlockHeaderWithTransaction,
    ) -> eyre::Result<Vec<TransactionReceipt>> {
        let mut receipts = Vec::with_capacity(block.transactions.len());
        for transaction in &block.transactions {
            let receipt = self
                .fetch_rpc
                .get_transaction_receipt(ethers::types::H256(transaction.0))
                .await?
                .ok_or_else(|| eyre::eyre!("receipt not found"))?;
            receipts.push(convert_ethers_receipt(receipt)?);
        }
        Ok(receipts)
    }
}

fn build_receipt_proof(
    block_hash: H256,
    block: &BlockHeaderWithTransaction,
    receipts: &[TransactionReceipt],
    receipt_index: usize,
) -> eyre::Result<types::EventProof, eyre::Error> {
    use merkle_generator::IterativeTrie;

    let mut trie = merkle_generator::PatriciaTrie::new();

    for (index, receipt) in receipts.iter().enumerate() {
        let key = alloy_rlp::encode(index);
        trie.insert(key, alloy_rlp::encode(receipt));
    }

    let merkle_proof = trie.merkle_proof(alloy_rlp::encode(receipt_index));
    let event_proof = types::EventProof {
        block_header: block.header.clone(),
        block_hash,
        transaction_receipt: receipts[receipt_index].clone(),
        transaction_receipt_hash: H256::hash(&receipts[receipt_index]),
        merkle_proof_of_receipt: merkle_proof,
    };

    if let Err(e) = event_proof.validate() {
        Err(eyre::eyre!("invalid event proof: {:?}", e))
    } else {
        Ok(event_proof)
    }
}
