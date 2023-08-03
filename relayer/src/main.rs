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
mod server;

use config::{Config, WatchAddress};
use db::DB;
use server::start_server;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let config = Config::parse();
    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))?;

    if !fs::try_exists(&config.database).await? {
        fs::create_dir(&config.database).await?
    }

    let db = DB::new(&config)?;
    db.create_tables()?;

    let clone_db = db.clone();
    let clone_config = config.clone();
    tokio::spawn(async move {
        let res = start_server(clone_config, clone_db).await;
        log::info!("server was stopped, reason: {:?}", res);
    });

    let watch_addresses = WatchAddress::decode_config(&config.watch_dog_config)?;
    let mut client = Client::new(config.clone(), db.clone(), term, watch_addresses)?;

    tokio::spawn(async move {
        let res = client.start().await;
        log::info!("client was stopped, reason: {:?}", res);
    })
    .await
    .expect("stop client successfully");

    Ok(())
}
