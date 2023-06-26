use std::sync::{
    atomic::AtomicBool,
    Arc,
};

use eyre::Result;

mod client;
mod config;
mod db;
mod server;

use client::start_client;
use config::Config;
use db::DB;
use server::start_server;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let config = envy::from_env::<Config>()?;
    let term = Arc::new(AtomicBool::new(false));

    let db = DB::new(&config)?;
    db.create_table()?;

    tokio::select! {
        _ = start_server(config.clone()) => {
            log::info!("server was stopped")
        }
        _ = start_client(config.clone(), db, term.clone()) => {
            log::info!("client was stopped")
        }
    }

    Ok(())
}

