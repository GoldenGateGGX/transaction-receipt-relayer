use std::{
    process::exit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use ethers::providers::Middleware;
use ethers::{
    providers::{Http, Provider},
    types::Block,
};
use eyre::Result;
use helios::{
    client::ClientBuilder,
    config::Config as HeliosConfig,
    types::{BlockTag, ExecutionBlock},
};
use helios_client::{database::FileDB, Client as HeliosClient};
use types::{BlockHeader, Bloom, H160, H256, U256};

use crate::{
    config::{Config, WatchAddress},
    consts::BLOCK_AMOUNT_TO_STORE,
    db::{BlockType, DB},
};

pub struct Client {
    client: HeliosClient<FileDB>,
    block_rpc: Provider<Http>,
    db: DB,
    term: Arc<AtomicBool>,
    watch_addresses: Vec<WatchAddress>,
}

impl Client {
    pub fn new(
        config: Config,
        db: DB,
        term: Arc<AtomicBool>,
        watch_addresses: Vec<WatchAddress>,
    ) -> Result<Self> {
        let helios_config = prepare_config(&config);
        let block_rpc = Provider::<Http>::try_from(&helios_config.execution_rpc)?;
        let client: HeliosClient<FileDB> = ClientBuilder::new()
            .config(helios_config)
            .data_dir(config.database.join("helios"))
            .build()?;
        Ok(Client {
            client,
            block_rpc,
            db,
            term,
            watch_addresses,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        exit_if_term(self.term.clone());
        self.client.start().await?;
        log::info!(target: "relayer::client::start","client started");

        self.finalization_loop().await?;

        Ok(())
    }

    /// Tries to get finalized block from Helios and updates
    /// latest finalized block in DB every 5 seconds.
    async fn finalization_loop(&mut self) -> Result<()> {
        const TARGET: &str = "relayer::client::finalization_loop";

        let mut latest_finalized_block =
            self.db.select_latest_block_height(BlockType::Finalized)?;
        let mut duration = tokio::time::interval(Duration::from_secs(5));

        loop {
            exit_if_term(self.term.clone());
            duration.tick().await;
            let finalized_block = self
                .client
                .get_block_by_number(BlockTag::Finalized, false)
                .await;
            let finalized_block = if let Ok(Some(finalized_block)) = finalized_block {
                finalized_block
            } else {
                log::warn!(target: TARGET,"Failed to get finalized block, retrying in {} seconds", duration.period().as_secs());
                continue;
            };

            let latest_processed_block =
                self.db.select_latest_block_height(BlockType::Processed)?;
            if Some(finalized_block.number) == latest_finalized_block
                && Some(finalized_block.number) == latest_processed_block
            {
                log::info!(target: TARGET,"No new finalized blocks, retrying in {} seconds", duration.period().as_secs());
                continue;
            }
            log::info!(target: TARGET,"New finalized block: {}", finalized_block.number);

            if let Err(e) = self.db.insert_or_update_finalized_block_info(
                finalized_block.number,
                H256(finalized_block.hash.0),
            ) {
                log::error!(target: TARGET,"Failed to update latest finalized block info: {}", e);
                continue;
            }
            latest_finalized_block = Some(finalized_block.number);
            if let Err(e) = self
                .collect_blocks_after_finality_update(finalized_block)
                .await
            {
                log::error!(target: TARGET,"Failed to process finality update: {}", e);
            } else {
                log::info!(target: TARGET,"Processed finality update");
            };
        }
    }

    /// Fetches all blocks from the web3 provider. The fetching goes backwards from the latest finalized block
    /// to the latest processed block using parent hash.
    async fn collect_blocks_after_finality_update(
        &mut self,
        finalized_block: ExecutionBlock,
    ) -> Result<()> {
        const TARGET: &str = "relayer::client::collect_blocks_after_finality_update";

        log::info!(target: TARGET,"Processing finality update");
        let latest_processed_block = self
            .db
            .select_latest_block_height(BlockType::Processed)?
            .unwrap_or(finalized_block.number - BLOCK_AMOUNT_TO_STORE);

        log::info!(target: TARGET,"Latest processed block: {}", latest_processed_block);

        // Now we have fetch missing blocks using previous block hash until we hit latest processed block.
        // If it's first run, we have to backtrack for BLOCK_AMOUNT_TO_STORE blocks.
        let mut blocks_to_process =
            Vec::with_capacity((finalized_block.number - latest_processed_block) as usize);

        let mut current_block = finalized_block.number - 1;
        let mut prev_block_hash = finalized_block.parent_hash;
        let block = self
            .block_rpc
            .get_block(finalized_block.hash)
            .await?
            .ok_or_else(|| eyre::eyre!("Block not found"))?;
        // push first finalized block to the queue
        blocks_to_process.push((parse_block(block)?, H256(finalized_block.hash.0)));

        let mut repeat = 0;
        let repeat_cycle = |repeat_counter| {
            const RETRIES: u64 = 10;
            if repeat_counter < RETRIES {
                Ok(repeat_counter + 1)
            } else {
                Err(eyre::eyre!("Multiple retries happened"))
            }
        };

        while current_block != latest_processed_block {
            // Fetch block by parent hash using web3 interface
            let execution_block = self.block_rpc.get_block(prev_block_hash).await;
            let execution_block = if let Ok(Some(execution_block)) = execution_block {
                execution_block
            } else {
                log::warn!(target: TARGET,"Failed to get block by hash, retrying in 5 seconds");
                log::warn!(target: TARGET, "Block number: {}", current_block);
                tokio::time::sleep(Duration::from_secs(5)).await;
                repeat = repeat_cycle(repeat)?;
                continue;
            };
            let tmp = execution_block.parent_hash;
            // parse block to our format
            if let Ok(parsed_block) = parse_block(execution_block) {
                // store requested hash to verify later
                blocks_to_process.push((parsed_block, H256(prev_block_hash.0)));
                current_block -= 1;
                prev_block_hash = tmp;
                // reset repeat as we had a success.
                repeat = 0;
            } else {
                log::warn!(target: TARGET,"Failed to parse block, retrying in 5 seconds");
                log::warn!(target: TARGET, "Block number: {}", current_block);
                repeat = repeat_cycle(repeat)?;
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }

        self.process_fetched_blocks(blocks_to_process).await?;

        Ok(())
    }

    /// Process fetched blocks, check the block hash, bloom filter and store records in the database.
    /// The blocks are processed from the latest processed block + 1 to the latest block.
    async fn process_fetched_blocks(&mut self, blocks: Vec<(BlockHeader, H256)>) -> Result<()> {
        const TARGET: &str = "relayer::client::process_fetched_blocks";

        if blocks.is_empty() {
            return Ok(());
        }

        // Load latest processed block hash from the database.
        let mut processed_block_hash = self
            .db
            .select_latest_block_hash(BlockType::Processed)?
            .unwrap_or_else(|| blocks.last().unwrap().0.parent_hash.clone());
        for (block_header, block_hash) in blocks.into_iter().rev() {
            // First initial check that it's in order. And that the parent block hash is expected.
            if processed_block_hash != block_header.parent_hash {
                log::error!(target: TARGET, "Block parent hash mismatch");
                return Err(eyre::eyre!("Block parent hash mismatch"));
            }

            // Verify block hash correctness
            let hash = H256::hash(&block_header);
            if hash != block_hash {
                log::error!(target: TARGET,"Block hash mismatch");
                return Err(eyre::eyre!("Block hash mismatch"));
            }

            let block_number = block_header.number;

            // Check the bloom filter over expected contracts
            let should_process = self
                .watch_addresses
                .iter()
                .any(|address| address.try_against(&block_header.logs_bloom));

            // Store block in the database
            self.db
                .insert_block(block_number, block_hash, block_header, should_process)?;

            processed_block_hash = hash;
        }
        Ok(())
    }
}

fn parse_block(execution_block: Block<ethers::types::H256>) -> Result<BlockHeader> {
    let mut bloom = [0u8; 256];
    let err = || eyre::eyre!("Failed to parse block");
    bloom.copy_from_slice(&execution_block.logs_bloom.ok_or_else(err)?.0);
    let block_header = types::BlockHeader {
        parent_hash: H256(execution_block.parent_hash.0),
        beneficiary: H160(execution_block.author.ok_or_else(err)?.0),
        state_root: H256(execution_block.state_root.0),
        transactions_root: H256(execution_block.transactions_root.0),
        receipts_root: H256(execution_block.receipts_root.0),
        withdrawals_root: execution_block.withdrawals_root.map(|r| H256(r.0)),
        logs_bloom: Bloom::new(bloom),
        number: execution_block.number.ok_or_else(err)?.as_u64(),
        gas_limit: execution_block.gas_limit.as_u64(),
        gas_used: execution_block.gas_used.as_u64(),
        timestamp: execution_block.timestamp.as_u64(),
        mix_hash: H256(execution_block.mix_hash.ok_or_else(err)?.0),
        base_fee_per_gas: Some(execution_block.base_fee_per_gas.ok_or_else(err)?.as_u64()),
        extra_data: execution_block.extra_data.0,

        // Defaults
        ommers_hash: H256(execution_block.uncles_hash.0),
        difficulty: U256(execution_block.difficulty.into()),
        nonce: execution_block.nonce.ok_or_else(err)?.to_low_u64_be(),

        // TODO: add conversion once ExecutionPayload has 4844 fields
        blob_gas_used: None,
        excess_blob_gas: None,
    };

    Ok(block_header)
}

fn prepare_config(config: &Config) -> HeliosConfig {
    let mut helios_config: HeliosConfig = HeliosConfig::from_file(
        &config.helios_config_path,
        &config.network,
        &Default::default(),
    );

    // TODO: should be fetched from DB or take default from config
    helios_config.checkpoint = Some(
        hex::decode("e6894aa5f8a0a6b3a99931e9d6dc3fa5f1bb9f6f65baa1fcd1312e9a4cac60ad").unwrap(),
    );

    helios_config
}

fn exit_if_term(term: Arc<AtomicBool>) {
    if term.load(Ordering::Relaxed) {
        log::info!(target: "relayer::client","caught SIGTERM");
        exit(0);
    }
}
