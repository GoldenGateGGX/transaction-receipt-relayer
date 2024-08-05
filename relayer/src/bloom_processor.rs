use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ethers::providers::{Http, Middleware, Provider};
use futures::future::join_all;
use types::{BlockHeaderWithTransaction, TransactionReceipt, H160, H256};

use crate::common::*;
use crate::config::Config;
use crate::consts::SLEEP_DURATION;
use crate::db::DB;
use crate::substrate_client::SubstrateClient;

pub struct BloomProcessor {
    db: DB,
    fetch_rpc: Provider<Http>,
    substrate_client: SubstrateClient,
    term: Arc<AtomicBool>,
    chain_id: u32,
    limit_processing_blocks_per_iteration: u64,
    interval_between_get_of_receipts: Option<u64>,

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
        let limit_processing_blocks_per_iteration = config
            .bloom_processor_limit_per_block
            .unwrap_or(crate::consts::DEFAULT_LIMIT_PROCESSING_BLOCKS_PER_ITERATION);
        let interval_between_get_of_receipts = config.interval_between_get_of_receipts;
        let config = prepare_config(&config);
        let fetch_rpc =
            Provider::<Http>::try_from(config.execution_rpc.as_str()).map_err(|err| {
                eyre::eyre!(
                    "Failed to connect to execution RPC at {} with error: {}",
                    config.execution_rpc,
                    err
                )
            })?;

        Ok(Self {
            db,
            fetch_rpc,
            term,
            substrate_client,
            chain_id,
            watched_addresses: None,
            limit_processing_blocks_per_iteration,
            interval_between_get_of_receipts,
        })
    }

    pub async fn run(&mut self) {
        const TARGET: &str = "relayer::bloom_processor::run";
        log::info!("bloom processor started");

        // Let's allow light client to sync
        let mut sleep = true;
        loop {
            exit_if_term(self.term.clone());
            if sleep {
                log::info!(target: TARGET, "Sleeping for {} secs", SLEEP_DURATION.as_secs());
                tokio::time::sleep(SLEEP_DURATION).await;
            }

            let latest_finalized_block_on_chain = self
                .substrate_client
                .last_known_block_block_number(self.chain_id)
                .await
                .unwrap_or(0);

            let blocks_to_process = self.db.select_blocks_to_process(
                latest_finalized_block_on_chain,
                self.limit_processing_blocks_per_iteration,
            );

            let block_to_process = match blocks_to_process {
                Ok(block) => block,
                Err(err) => {
                    log::warn!(target: TARGET, "Error while selecting blocks to process, reason: {:?}", err);
                    continue;
                }
            };
            if block_to_process.is_empty() {
                log::info!(target: TARGET, "No blocks to process. Sleeping");
                sleep = true;
                continue;
            }
            sleep = block_to_process.len() < self.limit_processing_blocks_per_iteration as usize;

            log::info!(target: TARGET, "Processing {} blocks", block_to_process.len());
            if let Ok(watched_addr) = self.substrate_client.watched_addresses(self.chain_id).await {
                self.watched_addresses = Some(watched_addr);
            }

            let watched_address = if let Some(watched_addr) = &self.watched_addresses {
                watched_addr
            } else {
                log::warn!(target: TARGET, "Watched addresses are not set");
                continue;
            };

            let receipts = block_to_process.iter().map(|(_, _, block)| {
                self.fetch_receipts(block, self.interval_between_get_of_receipts)
            });
            let receipts = join_all(receipts).await;

            log::info!(target: TARGET, "Fetched {} receipts", receipts.len());
            let mut merkle_proofs = Vec::new();

            for (block_data, receipt_data) in block_to_process.into_iter().zip(receipts.into_iter())
            {
                let (block_height, block_hash, block) = block_data;
                if receipt_data.is_err() {
                    log::warn!(target: TARGET, "Error while fetching receipts for block {}", block_height);
                    continue;
                }
                let receipts = receipt_data.unwrap();

                // We need to validate that the bloom filter contains the watch addresses as they might be false positives
                let mut created_proof = false;
                for (i, receipt) in receipts.iter().enumerate() {
                    let event_exist = watched_address.iter().any(|addr| {
                        log::trace!(target: TARGET, "bloom positive: {:?}, but addr is {}", receipt.bloom.check_address(addr), receipt.receipt.logs.iter().any(|l| l.address == *addr));
                        receipt.bloom.check_address(addr)
                            && receipt.receipt.logs.iter().any(|l| l.address == *addr)
                    });

                    if event_exist {
                        log::trace!(target: TARGET, "Found event for address {:?} in block {}", watched_address, block_height);
                        // Check maybe the event is already submitted
                        let receipt_hash = H256::hash(receipt);
                        if self
                            .substrate_client
                            .is_item_proved(self.chain_id, receipt_hash)
                            .await
                            .unwrap_or_default()
                        {
                            log::trace!(target: TARGET, "Event already submitted");
                            continue;
                        }

                        if let Ok(proof) = build_receipt_proof(block_hash, &block, &receipts, i) {
                            created_proof = true;
                            merkle_proofs.push(proof);
                        }
                    }
                }

                if !created_proof {
                    log::info!(target: TARGET, "false positive bloom filter for block {}", block_height);
                    if let Err(e) = self.db.mark_block_processed(block_height) {
                        log::warn!(target: TARGET, "Error while marking block {} as processed: {}", block_height, e);
                    }
                }
            }

            log::info!(target: TARGET, "Created {} event proofs", merkle_proofs.len());

            self.substrate_client
                .send_event_proofs(merkle_proofs)
                .await
                .into_iter()
                .for_each(|(height, res)| match res {
                    Ok(_) => {
                        log::info!(target: TARGET, "Successfully sent event proofs for block {}", height);
                        if let Err(e) = self.db.mark_block_processed(height) {
                            log::warn!(target: TARGET, "Error while marking block {} as processed: {}", height, e);
                        }
                    }
                    Err(e) => {
                        log::warn!(target: TARGET,
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
        interval_between_get_of_receipts: Option<u64>,
    ) -> eyre::Result<Vec<TransactionReceipt>> {
        const TARGET: &str = "relayer::bloom_processor::fetch_receipts";

        let mut receipts = Vec::with_capacity(block.transactions.len());
        let transaction_fut = block.transactions.iter().map(|tx| {
            let tx_hash = ethers::types::H256(tx.0);
            self.fetch_rpc.get_transaction_receipt(tx_hash)
        });
        let transactions = {
            match interval_between_get_of_receipts {
                None => join_all(transaction_fut).await,
                Some(interval) => {
                    let mut buffer = Vec::with_capacity(transaction_fut.len());
                    for fut in transaction_fut {
                        let _ = tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                        buffer.push(fut.await)
                    }
                    buffer
                }
            }
        };

        for transaction in transactions {
            match transaction {
                Ok(Some(receipt)) => {
                    receipts.push(convert_ethers_receipt(receipt)?);
                }
                Ok(None) => {
                    log::warn!(target: TARGET, "Transaction not found");
                    return Err(eyre::eyre!("transaction not found"));
                }
                Err(e) => {
                    log::warn!(target: TARGET, "Error while fetching transaction: {}", e);
                    return Err(e.into());
                }
            }
        }
        log::debug!(target: TARGET,
            "Fetched {} receipts for block {}",
            receipts.len(),
            block.header.number
        );
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
