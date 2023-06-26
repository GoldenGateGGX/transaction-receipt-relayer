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
use db::{create_table, new_connection};
use server::start_server;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let config = envy::from_env::<Config>()?;
    let term = Arc::new(AtomicBool::new(false));

    let conn = new_connection(&config)?;
    create_table(&conn)?;

    tokio::select! {
        _ = start_server(config.clone()) => {
            log::info!("server was stopped")
        }
        _ = start_client(config.clone(), conn, term.clone()) => {
            log::info!("client was stopped")
        }
    }

    Ok(())
}

