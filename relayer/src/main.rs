use std::sync::{atomic::AtomicBool, Arc};

use clap::Parser;
use client::Client;
use eyre::Result;
use tokio::fs;

mod bloom_processor;
mod client;
pub(crate) mod common;
mod config;
pub(crate) mod consts;
mod db;
mod tx_sender;

use config::{Config, WatchAddress};
use db::DB;
use tx_sender::TxSender;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let config = Config::parse();
    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))?;

    if !fs::try_exists(&config.database).await? {
        fs::create_dir(&config.database).await?
    }

    let db = DB::new(&config.database)?;
    db.create_tables()?;

    let watch_addresses = WatchAddress::decode_config(&config.watch_dog_config)?;
    let mut client = Client::new(
        config.clone(),
        db.clone(),
        term.clone(),
        watch_addresses.clone(),
    )?;
    let tx_sender = TxSender::new(
        &config.substrate_config_path,
        network_name_to_id(&config.network)?,
    )
    .await?;
    let bloom_processor =
        bloom_processor::BloomProcessor::new(watch_addresses, db.clone(), config, term, tx_sender)?;

    tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                log::info!("ctrl-c received, shutting down");
            }

            _ = client.start() => {
                log::info!("client was stopped");
            }

            _ = bloom_processor.run() => {
                log::info!("bloom processor was stopped");
            }
    }
    Ok(())
}

fn network_name_to_id(network_name: &str) -> Result<u32> {
    match network_name {
        "mainnet" => Ok(1),
        "testnet" => Ok(5),
        _ => Err(eyre::eyre!("Unknown network name {}", network_name)),
    }
}
