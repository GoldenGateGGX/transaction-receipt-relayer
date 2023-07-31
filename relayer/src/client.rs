use std::{
    process::exit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use ethers::{
    abi::AbiEncode,
    types::{Address, H256},
};
use eyre::Result;
use helios::{
    client::ClientBuilder, config::networks::Network, config::Config as HeliosConfig,
    types::BlockTag,
};
use helios_client::node::Node;
use tokio::{spawn, sync::RwLock};

use crate::{config::Config, db::DB};

pub async fn start_client(config: Config, db: DB, term: Arc<AtomicBool>) -> Result<()> {
    println!("{}", config.network);
    let helios_config = prepare_config(&config);
    let node = Arc::new(RwLock::new(Node::new(Arc::new(helios_config))?));
    log::info!(
        "Built client on network \"{}\" with external checkpoint fallbacks",
        &config.network
    );
    node.write().await.sync().await.unwrap();

    spawn(advance_thread(node.clone()));

    exit_if_term(term.clone());

    log::info!("client started");

    // TODO: should recheck missed blocks on startup
    // TODO: starting point should be fetchable from the db
    let filter = ethers::types::Filter::new()
        .select(ethers::core::types::BlockNumber::Latest)
        // TODO: it might be a range of addresses
        .event("Transfer(address,address,uint256)");

    loop {
        exit_if_term(term.clone());
        let execution_block = node
            .read()
            .await
            .get_block_by_number(BlockTag::Finalized, false)
            .await;

        if let Ok(Some(execution_block)) = execution_block {
            // let execution_payload_header: ExecutionPayloadHeader = execution_block.into();
            // let block_hash = execution_payload_header.block_hash;
        } else {
            log::warn!("Could not get a block by block_number");
            continue;
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
        //             log::info!(
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

fn prepare_config(config: &Config) -> HeliosConfig {
    let mut helios_config: HeliosConfig = HeliosConfig::from_file(
        &config.helios_config_path,
        &config.network,
        &Default::default(),
    );

    // TODO: should be fetched from DB or take default from config
    helios_config.checkpoint = Some(
        hex::decode("e9f19e8b53a44f25e4ddba6fc86a02a22833299dadc578eb8a4aa3c8932936e5").unwrap(),
    );

    helios_config
}

fn exit_if_term(term: Arc<AtomicBool>) {
    if term.load(Ordering::Relaxed) {
        log::info!("caught SIGTERM");
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

// fn transactions_to_hashes(transactions: Transactions) -> Vec<H256> {
//     match transactions {
//         Transactions::Hashes(hashes) => hashes,
//         Transactions::Full(txs) => txs.iter().map(|tx| tx.hash).collect(),
//     }
// }
