use std::path::PathBuf;

use eyre::Result;
use serde::Deserialize;

use clap::Parser;
use types::{Bloom, H160};

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
    pub watch_dog_config: PathBuf,
    #[arg(long)]
    pub server_host: Option<String>,
    #[arg(long)]
    pub server_port: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct WatchAddress {
    address: H160,
    name: String,
}

impl WatchAddress {
    pub fn decode_config(path: &PathBuf) -> Result<Vec<WatchAddress>> {
        #[derive(serde::Deserialize)]
        struct Address {
            address: String,
            name: String,
        }

        #[derive(serde::Deserialize)]
        struct PrivateStructure {
            entities: Vec<Address>,
        }

        let decoded: PrivateStructure = toml::from_str(&std::fs::read_to_string(path)?)?;
        decoded
            .entities
            .into_iter()
            .map(|elem| {
                let mut address = [0u8; 20];
                hex::decode_to_slice(&elem.address[2..], &mut address)?;
                Ok(WatchAddress {
                    address: H160(address),
                    name: elem.name,
                })
            })
            .collect()
    }

    pub fn try_against(&self, bloom: &Bloom) -> bool {
        let result = bloom.check_address(&self.address);
        log::debug!(target: "relayer::config::try_against", "Bloom filter check result {result} against {}", self.name);
        result
    }

    pub fn address(&self) -> H160 {
        self.address
    }
}
