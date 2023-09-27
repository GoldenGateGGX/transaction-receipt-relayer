use std::path::Path;

use eyre::Result;
use subxt::{error::DispatchError, tx::TxStatus, OnlineClient, PolkadotConfig};
use subxt_signer::{
    bip39::Mnemonic,
    sr25519::{dev, Keypair},
};

use self::ggxchain::runtime_types::webb_proposals::header::TypedChainId;

pub struct TxSender {
    api: OnlineClient<PolkadotConfig>,
    keypair: Keypair,
    chain_id: u32,
}

impl TxSender {
    pub async fn new(substrate_config_path: &Path, chain_id: u32) -> Result<Self> {
        let file_content = std::fs::read_to_string(substrate_config_path)?;
        let config: SubstrateConfig = toml::from_str(&file_content)?;
        let api = OnlineClient::<PolkadotConfig>::from_url(config.ws_url).await?;
        let keypair = if config.is_dev {
            dev::alice()
        } else {
            Keypair::from_phrase(&config.phrase, config.password.as_deref())?
        };
        Ok(Self {
            api,
            keypair,
            chain_id,
        })
    }

    // TODO: Re-make it using utility pallet to submit a batch of proofs
    pub async fn send_event_proof(&self, event_proof: types::EventProof) -> Result<()> {
        // TODO: Ideally we should check if the proof isn't already submitted
        // but let's skip this for now

        let tx = ggxchain::tx().eth_receipt_registry().submit_proof(
            TypedChainId::Evm(self.chain_id),
            serde_json::to_vec(&event_proof)?,
        );
        let mut tx_progress = self
            .api
            .tx()
            .sign_and_submit_then_watch_default(&tx, &self.keypair)
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
