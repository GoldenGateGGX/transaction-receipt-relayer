use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ethers::providers::{Http, Middleware, Provider};
use futures::future::join_all;
use types::{BlockHeaderWithTransaction, EventProof, TransactionReceipt, H160, H256};

use crate::common::*;
use crate::config::Config;
use crate::db::DB;
use crate::substrate_client::SubstrateClient;

pub struct BloomProcessor {
    db: DB,
    fetch_rpc: Provider<Http>,
    substrate_client: SubstrateClient,
    term: Arc<AtomicBool>,
    chain_id: u32,

    // Cache of watched addresses
    watched_addresses: Option<Vec<H160>>,
}

impl BloomProcessor {
    pub fn new(
        db: DB,
        config: Config,
        term: Arc<AtomicBool>,
        substrate_client: SubstrateClient,
        chain_id: u32,
    ) -> eyre::Result<Self> {
        let config = prepare_config(&config);
        let fetch_rpc = Provider::<Http>::try_from(config.execution_rpc.as_str())?;
        Ok(Self {
            db,
            fetch_rpc,
            term,
            substrate_client,
            chain_id,
            watched_addresses: None,
        })
    }

    pub async fn run(&mut self) {
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
            if let Ok(watched_addr) = self.substrate_client.watched_addresses(self.chain_id).await {
                self.watched_addresses = Some(watched_addr);
            }

            let watched_address = if let Some(watched_addr) = &self.watched_addresses {
                watched_addr
            } else {
                log::warn!("Watched addresses are not set");
                continue;
            };

            let receipts = block_to_process
                .iter()
                .map(|(_, _, block)| self.fetch_receipts(block));
            let receipts = join_all(receipts).await;

            let merkle_proofs: Vec<EventProof> = block_to_process
                .into_iter()
                .zip(receipts.into_iter())
                .flat_map(|(block_data, receipt_data)| {
                    let (block_height, block_hash, block) = block_data;
                    if receipt_data.is_err() {
                        log::warn!("Error while fetching receipts for block {}", block_height);
                        return None;
                    }
                    let receipts = receipt_data.unwrap();

                    // We need to validate that the bloom filter contains the watch addresses as they might be false positives
                    let mut proofs = vec![];
                    for (i, receipt) in receipts.iter().enumerate() {
                        if watched_address.iter().any(|addr| {
                            receipt.bloom.check_address(addr)
                                && receipt.receipt.logs.iter().any(|l| l.address == *addr)
                        }) {
                            // Save index of positive receipt
                            proofs
                                .push(build_receipt_proof(block_hash, &block, &receipts, i).ok()?);
                        }
                    }

                    Some(proofs)
                })
                .flatten()
                .collect();

            self.substrate_client
                .send_event_proofs(merkle_proofs)
                .await
                .into_iter()
                .for_each(|(height, res)| match res {
                    Ok(_) => {
                        log::info!("Successfully sent event proofs for block {}", height);
                        if let Err(e) = self.db.mark_block_processed(height) {
                            log::warn!("Error while marking block {} as processed: {}", height, e);
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "Error while sending event proofs for block {}: {}",
                            height,
                            e
                        );
                    }
                });
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
