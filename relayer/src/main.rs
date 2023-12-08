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
mod substrate_client;

use config::Config;
use db::DB;
use substrate_client::SubstrateClient;

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

    let chain_id: u32 = network_name_to_id(&config.network)?;
    let substrate_client = SubstrateClient::new(&config.substrate_config_path, chain_id).await?;

    let mut client = Client::new(
        config.clone(),
        db.clone(),
        term.clone(),
        substrate_client.clone(),
    )?;
    let mut bloom_processor =
        bloom_processor::BloomProcessor::new(db.clone(), config, term, substrate_client, chain_id)?;

    tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                log::info!("ctrl-c received, shutting down");
            }

            err = tokio::spawn(async move { client.start().await } ) => {
                log::error!("client was stopped because of {err:?}");
            }

            err = tokio::spawn(async move { bloom_processor.run().await }) => {
                log::error!("bloom processor was stopped because of {err:?}");
            }
    }
    Ok(())
}

fn network_name_to_id(network_name: &str) -> Result<u32> {
    match network_name {
        "mainnet" => Ok(1),
        "goerli" => Ok(5),
        "sepolia" => Ok(11155111),
        _ => Err(eyre::eyre!("Unknown network name {}", network_name)),
    }
}
