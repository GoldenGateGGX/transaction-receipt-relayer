use std::{
    path::PathBuf,
    process::exit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

// use anyhow::Result;
use ethers::types::Address;
use eyre::Result;
use helios::{client::ClientBuilder, config::networks::Network, prelude::*};
use rusqlite::Connection;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct Config {
    consensus_rpc: String,
    untrusted_rpc: String,
    smart_contract_address: String,
    block_number: Option<u64>,
    db_path: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let config = envy::from_env::<Config>()?;
    let term = Arc::new(AtomicBool::new(false));

    let conn = if let Some(path) = config.db_path {
        Connection::open(path)?
    } else {
        Connection::open_in_memory()?
    };
    conn.execute("CREATE TABLE IF NOT EXISTS logs (log TEXT)", ())?;

    let mut client: Client<FileDB> = ClientBuilder::new()
        .network(Network::MAINNET)
        .consensus_rpc(&config.consensus_rpc)
        .execution_rpc(&config.untrusted_rpc)
        .load_external_fallback()
        .data_dir(PathBuf::from("/tmp/helios"))
        .build()?;

    log::info!(
        "Built client on network \"{}\" with external checkpoint fallbacks",
        Network::MAINNET
    );

    exit_if_term(term.clone());

    client.start().await?;
    log::info!("client started");

    let filter = ethers::types::Filter::new()
        .select(
            config
                .block_number
                .map(Into::into)
                .unwrap_or(ethers::core::types::BlockNumber::Latest)..,
        )
        .address(config.smart_contract_address.parse::<Address>()?)
        .event("Transfer(address,address,uint256)");

    loop {
        exit_if_term(term.clone());
        let logs = client.get_logs(&filter).await?;
        log::info!("logs: {:#?}", logs);
        for log in logs {
            let json = serde_json::to_string(&log)?;
            conn.execute("INSERT INTO logs(log) values (?1)", (json,))?;
        }
    }
}

fn exit_if_term(term: Arc<AtomicBool>) {
    if term.load(Ordering::Relaxed) {
        log::info!("caught SIGTERM");
        exit(0);
    }
}
