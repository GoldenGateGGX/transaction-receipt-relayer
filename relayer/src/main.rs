use std::sync::{atomic::AtomicBool, Arc};

use clap::Parser;
use client::Client;
use eyre::Result;
use tokio::fs;

mod client;
mod config;
pub(crate) mod consts;
mod db;
mod merkle;

use config::{Config, WatchAddress};
use db::DB;

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
    let mut client = Client::new(config.clone(), db.clone(), term, watch_addresses)?;

    let res = client.start().await;
    log::info!("client was stopped, reason: {:?}", res);
    Ok(())
}
