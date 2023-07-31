use std::{
    path::PathBuf,
    process::exit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use eyre::Result;
use helios::{
    client::ClientBuilder, config::networks::Network, config::Config as HeliosConfig,
    types::BlockTag,
};
use helios_client::{database::FileDB, node::Node, Client};
use tokio::{spawn, sync::RwLock};
use types::{Bloom, H160, H256, U256};

use crate::{config::Config, db::DB};

pub async fn start_client(config: Config, db: DB, term: Arc<AtomicBool>) -> Result<()> {
    println!("{}", config.network);
    let helios_config = prepare_config(&config);
    let network = network(&config);
    let mut client: Client<FileDB> = ClientBuilder::new()
        .config(helios_config)
        .data_dir(
            vec![config.database, PathBuf::from("helios")]
                .iter()
                .collect(),
        )
        .build()?;

    log::info!(target: "relayer::client",
        "Built client on network \"{}\" with external checkpoint fallbacks",
        &config.network
    );
    log::info!(target: "relayer::client","Start syncing blocks from the network");

    exit_if_term(term.clone());
    client.start().await?;

    log::info!(target: "relayer::client","client started");

    let mut latest_processed_block = if let Some(result) = db.select_latest_processed_block()? {
        result
    } else {
        log::info!(target: "relayer::client","No processed blocks found in the database, probably first run. Starting from the latest block.");
        latest_finalized_block_number(&client).await? - 1
    };
    // TODO: should recheck missed blocks on startup
    // TODO: starting point should be fetchable from the db
    let filter = ethers::types::Filter::new()
        .select(ethers::core::types::BlockNumber::Latest)
        // TODO: it might be a range of addresses
        .event("Transfer(address,address,uint256)");

    loop {
        exit_if_term(term.clone());
        let _ = tokio::time::sleep(Duration::from_secs(1)).await;
        log::info!(target: "relayer::client","Latest processed block: {}", latest_processed_block);
        log::info!(target: "relayer::client","Checking for new blocks");
        if let Ok(latest_finalized_block) = latest_finalized_block_number(&client).await {
            log::info!(target: "relayer::client","Latest finalized block: {:?}", latest_finalized_block);
            if latest_finalized_block < latest_processed_block {
                log::info!(target: "relayer::client","Latest finalized block is lower than latest processed block. Waiting for finalization.");
                // TODO: It's not yet finalized
                continue;
            }
        } else {
            log::info!(target: "relayer::client","Failed to get latest finalized block");
            continue;
        }

        log::info!(target: "relayer::client","Fetching block: {}", latest_processed_block);
        // We need to get consensus block.
        let execution_block = client
            .get_block_by_number(BlockTag::Number(latest_processed_block), false)
            .await;

        if let Ok(Some(execution_block)) = execution_block {
            log::info!(target: "relayer::client","Block fetched");
            let mut bloom = [0u8; 256];
            bloom.copy_from_slice(&execution_block.logs_bloom);
            let block_header = types::BlockHeader {
                parent_hash: H256(execution_block.hash.0),
                beneficiary: H160(execution_block.miner.0),
                state_root: H256(execution_block.state_root.0),
                transactions_root: H256(execution_block.transactions_root.0),
                receipts_root: H256(execution_block.receipts_root.0),
                withdrawals_root: None, // TODO: None for now
                logs_bloom: Bloom(bloom),
                number: execution_block.number,
                gas_limit: execution_block.gas_limit,
                gas_used: execution_block.gas_used,
                timestamp: execution_block.timestamp,
                mix_hash: H256(execution_block.mix_hash.0),
                base_fee_per_gas: Some(execution_block.base_fee_per_gas.as_u64()),
                extra_data: execution_block.extra_data.into(),

                // Defaults
                ommers_hash: H256(execution_block.sha3_uncles.0),
                difficulty: U256(execution_block.difficulty.into()),
                nonce: execution_block.nonce.parse().unwrap(),

                // TODO: add conversion once ExecutionPayload has 4844 fields
                blob_gas_used: None,
                excess_blob_gas: None,
            };

            let block_hash = H256::hash(block_header);
            if execution_block.hash.0 == block_hash.0 {
                log::info!(target: "relayer::client",": ) Block hash is same");
                latest_processed_block += 1;
            } else {
                log::info!(target: "relayer::client",": ( Block hash is different");
            }
        } else {
            log::info!(target: "relayer::client","Block not found. {execution_block:?}");
        }

        // let logs = client.get_logs(&filter).await?;
        // log::debug!("logs: {:#?}", logs);
        // 'outer: for log in logs {
        //     if let Some(block_hash) = log.block_hash {
        //         if let Ok(Some(block)) = client.get_block_by_hash(&block_hash.encode(), false).await
        //         {
        //             let mut receipts = vec![];
        //             for hash in transactions_to_hashes(block.transactions) {
        //                 if let Ok(receipt) = client.get_transaction_receipt(&hash).await {
        //                     receipts.push(receipt)
        //                 } else {
        //                     log::warn!(
        //                         "Could not get a transaction receipt for tx {}",
        //                         hash.encode_hex()
        //                     );
        //                     continue 'outer;
        //                 }
        //             }

        //             if !receipts.is_empty() {
        //                 let json = serde_json::to_string(&receipts)?;
        //                 db.insert_receipts(block_hash, &json)?;
        //             } else {
        //                 log::debug!(
        //                     "Block {} does not have any receipts",
        //                     block_hash.encode_hex()
        //                 );
        //             }
        //         } else {
        //             log::info!(target: "relayer::client",
        //                 "Could not get a block by block_hash {}",
        //                 block_hash.encode_hex()
        //             );
        //             continue 'outer;
        //         }
        //         // TODO: Insert latest block as a checkpoint
        //     }
        // }
    }
}

fn network(config: &Config) -> Network {
    match config.network.as_str() {
        "goerli" => Network::GOERLI,
        "mainnet" => Network::MAINNET,
        _ => panic!("Unsupported network"),
    }
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

async fn advance_thread(node: Arc<RwLock<Node>>) {
    loop {
        let res = node.write().await.advance().await;
        if let Err(err) = res {
            log::warn!("consensus error: {}", err);
        }

        let next_update = node.read().await.duration_until_next_update();

        tokio::time::sleep(next_update).await;
    }
}

async fn latest_finalized_block_number(node: &Client<FileDB>) -> Result<u64> {
    let block = node.get_block_by_number(BlockTag::Finalized, false).await?;
    Ok(block
        .ok_or_else(|| eyre::eyre!("Could not get the latest block number from the database"))?
        .number)
}

// fn transactions_to_hashes(transactions: Transactions) -> Vec<H256> {
//     match transactions {
//         Transactions::Hashes(hashes) => hashes,
//         Transactions::Full(txs) => txs.iter().map(|tx| tx.hash).collect(),
//     }
// }
