use std::path::PathBuf;

use serde::Deserialize;

use clap::Parser;

#[derive(Deserialize, Debug, Clone, Parser)]
pub struct Config {
    #[arg(long)]
    pub network: String,
    #[arg(long)]
    pub database: PathBuf,
    #[arg(long)]
    pub substrate_config_path: PathBuf,
    #[arg(long)]
    pub helios_config_path: PathBuf,
    #[arg(long)]
    pub server_host: Option<String>,
    #[arg(long)]
    pub server_port: Option<u64>,
    #[arg(long)]
    pub blocks_to_store: Option<u64>,
    #[arg(long)]
    pub bloom_processor_limit_per_block: Option<u64>,
    #[arg(long)]
    pub interval_between_get_of_receipts: Option<u64>,
}
