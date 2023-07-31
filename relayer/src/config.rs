use std::path::PathBuf;

use serde::Deserialize;

use clap::Parser;

#[derive(Deserialize, Debug, Clone, Parser)]
pub struct Config {
    #[arg(short, long)]
    pub network: String,
    #[arg(short, long)]
    pub database: PathBuf,
    #[arg(short, long)]
    pub helios_config_path: PathBuf,
    #[arg(short, long)]
    pub server_host: Option<String>,
    #[arg(short, long)]
    pub server_port: Option<u64>,
}
