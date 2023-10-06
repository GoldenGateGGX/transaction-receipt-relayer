use std::{collections::HashMap, path::Path, time::Duration};

use eyre::Result;
use subxt::{error::DispatchError, tx::TxStatus, OnlineClient, PolkadotConfig};
use subxt_signer::{
    bip39::Mnemonic,
    sr25519::{dev, Keypair},
};
use types::H160;

use crate::consts::UPDATE_WATCHED_ADDRESSES_INTERVAL;

use self::ggxchain::runtime_types::webb_proposals::header::TypedChainId;

#[derive(Debug, Clone)]
pub struct SubstrateClient {
    api: OnlineClient<PolkadotConfig>,
    keypair: Keypair,
    chain_id: u32,

    watched_addresses: HashMap<u32, (Duration, Vec<H160>)>,
}

impl SubstrateClient {
    pub async fn new(substrate_config_path: &Path, chain_id: u32) -> Result<Self> {
        let file_content = std::fs::read_to_string(substrate_config_path)?;
        let config: SubstrateConfig = toml::from_str(&file_content)?;
        let api = OnlineClient::<PolkadotConfig>::from_url(&config.ws_url)
            .await
            .map_err(|err| {
                eyre::eyre!(
                    "Failed to connect to substrate node at {} with error: {}",
                    config.ws_url,
                    err
                )
            })?;
        let keypair = if config.is_dev {
            dev::alice()
        } else {
            Keypair::from_phrase(&config.phrase, config.password.as_deref())?
        };
        Ok(Self {
            api,
            keypair,
            chain_id,
            watched_addresses: HashMap::new(),
        })
    }

    pub async fn send_event_proof(&self, event_proof: types::EventProof, nonce: u64) -> Result<()> {
        // TODO: Ideally we should check if the proof isn't already submitted
        // but let's skip this for now

        let tx = ggxchain::tx().eth_receipt_registry().submit_proof(
            TypedChainId::Evm(self.chain_id),
            serde_json::to_vec(&event_proof)?,
        );
        let mut tx_progress = self
            .api
            .tx()
            .create_signed_with_nonce(&tx, &self.keypair, nonce, Default::default())?
            .submit_and_watch()
            .await?;

        while let Some(event) = tx_progress.next_item().await {
            let e = match event {
                Ok(e) => e,
                Err(err) => {
                    log::error!("failed to watch for tx events {err:?}");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to get hash storage value: {err:?}"),
                    )
                    .into());
                }
            };
            match e {
                TxStatus::Future => {}
                TxStatus::Ready => {
                    log::trace!("tx ready");
                }
                TxStatus::Broadcast(_) => {}
                TxStatus::InBlock(_) => {
                    log::trace!("tx in block");
                }
                TxStatus::Retracted(_) => {
                    log::warn!("tx retracted");
                }
                TxStatus::FinalityTimeout(_) => {
                    log::warn!("tx timeout");
                }
                TxStatus::Finalized(v) => {
                    let maybe_success = v.wait_for_success().await;
                    match maybe_success {
                        Ok(_) => {
                            log::debug!("tx finalized");
                            return Ok(());
                        }
                        Err(err) => {
                            let error_msg = match err {
                                subxt::Error::Runtime(DispatchError::Module(error)) => {
                                    let details = error.details()?;
                                    let pallet = details.pallet.name();
                                    let error = &details.variant;
                                    format!("Extrinsic failed with an error: {pallet}::{error:?}")
                                }
                                _ => {
                                    format!("Extrinsic failed with an error: {}", err)
                                }
                            };

                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Tx failed : {error_msg}"),
                            )
                            .into());
                        }
                    }
                }
                TxStatus::Usurped(_) => {}
                TxStatus::Dropped => {
                    log::warn!("tx dropped");
                }
                TxStatus::Invalid => {
                    log::warn!("tx invalid");
                }
            }
        }

        Err(std::io::Error::new(std::io::ErrorKind::Other, "Transaction stream ended").into())
    }

    // TODO: Re-make it using utility pallet to submit a batch of proofs in single tx, but for now we keep it simple
    /// sends a batch of proofs to the chain and returns a vector of results with a block_height
    pub async fn send_event_proofs(
        &self,
        event_proofs: Vec<types::EventProof>,
    ) -> Vec<(u64, Result<()>)> {
        const TARGET: &str = "relayer::substrate_client::send_event_proofs";
        log::debug!(target: TARGET, "sending event {} proofs", event_proofs.len());

        let block_heights = event_proofs
            .iter()
            .map(|event_proof| event_proof.block_header.number)
            .collect::<Vec<_>>();
        let nonce = self
            .api
            .tx()
            .account_nonce(&self.keypair.public_key().into())
            .await;

        if let Err(err) = nonce {
            log::error!("failed to get nonce: {err:?}");
            return vec![];
        }
        let nonce = nonce.unwrap();

        let events_len = event_proofs.len() as u64;
        let event_proofs_future = event_proofs
            .into_iter()
            .zip(nonce..nonce + events_len)
            .map(|(event_proof, nonce)| self.send_event_proof(event_proof, nonce))
            .collect::<Vec<_>>();

        let results = futures::future::join_all(event_proofs_future).await;
        block_heights.into_iter().zip(results.into_iter()).collect()
    }

    pub async fn watched_addresses(&mut self, chain_id: u32) -> Result<Vec<types::H160>> {
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        if let Some((last_update, data)) = self.watched_addresses.get(&chain_id) {
            if current_time - *last_update < UPDATE_WATCHED_ADDRESSES_INTERVAL {
                return Ok(data.clone());
            }
        }

        let query = ggxchain::storage()
            .eth_receipt_registry()
            .watched_contracts(TypedChainId::Evm(chain_id));
        let result: Vec<H160> = self
            .api
            .storage()
            .at_latest()
            .await?
            .fetch(&query)
            .await?
            .map(|vec| vec.0)
            .ok_or_else(|| eyre::eyre!("Empty watched contracts list"))?
            .into_iter()
            .map(|addr| types::H160(addr.0))
            .collect();
        self.watched_addresses
            .insert(chain_id, (current_time, result.clone()));
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct SubstrateConfig {
    ws_url: String,
    is_dev: bool,
    phrase: Mnemonic,
    password: Option<String>,
}

#[subxt::subxt(runtime_metadata_path = "./metadata/eth-receipt-metadata.scale")]
mod ggxchain {}
