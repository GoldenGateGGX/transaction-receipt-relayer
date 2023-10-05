#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use frame_support::{
    dispatch::Encode, inherent::Vec, sp_runtime::DispatchError, sp_std::marker::PhantomData,
};
use pallet_contracts::chain_extension::{ChainExtension, Environment, Ext, InitState, RetVal};

#[derive(parity_scale_codec::Encode, parity_scale_codec::Decode, Debug, Clone, PartialEq)]
pub struct Arguments {
    pub chain_id: u32,
    pub block_number: u64,
    pub receipt_hash: [u8; 32],
    pub contract_address: [u8; 20],
}

enum ReceiptRegistryFuncId {
    LogsForReceipt,
}

impl TryFrom<u16> for ReceiptRegistryFuncId {
    type Error = DispatchError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ReceiptRegistryFuncId::LogsForReceipt),
            _ => Err(DispatchError::Other(
                "Unsupported func id in receipt registry chain extension",
            )),
        }
    }
}

/// ReceiptRegistry chain extension.
pub struct ReceiptRegistryExtension<Runtime>(PhantomData<Runtime>);

impl<Runtime> Default for ReceiptRegistryExtension<Runtime> {
    fn default() -> Self {
        ReceiptRegistryExtension(PhantomData)
    }
}

impl<Runtime> ChainExtension<Runtime> for ReceiptRegistryExtension<Runtime>
where
    Runtime: pallet_contracts::Config + pallet_receipt_registry::Config,
{
    fn call<E: Ext>(&mut self, env: Environment<E, InitState>) -> Result<RetVal, DispatchError>
    where
        E: Ext<T = Runtime>,
    {
        const TARGET: &str = "pallet-chain-extension-receipt-registry::call";

        log::trace!(target: TARGET, "In pallet-chain-extension-receipt-registry chain extension");

        let func_id = env.func_id().try_into()?;
        let mut env = env.buf_in_buf_out();

        match func_id {
            ReceiptRegistryFuncId::LogsForReceipt => {
                // TODO: proper weight calculation

                let Arguments {
                    chain_id,
                    block_number,
                    receipt_hash,
                    contract_address,
                } = env.read_as_unbounded(env.in_len())?;

                log::debug!(
                    target: TARGET,
                    "logs_for_receipt with receipt hash: {receipt_hash:?} and contract address: {contract_address:?}",
                );

                let (chain_id, receipt_hash, contract_address) = (
                    webb_proposals::TypedChainId::Evm(chain_id),
                    types::H256(receipt_hash),
                    types::H160(contract_address),
                );

                let data = if let Some(data) =
                    pallet_receipt_registry::Pallet::<Runtime>::processed_receipts((
                        chain_id,
                        block_number,
                        receipt_hash,
                    )) {
                    data
                } else {
                    return Ok(RetVal::Converging(0));
                };

                let logs: Vec<_> = data
                    .into_iter()
                    .filter(|log| log.address == contract_address)
                    .map(|log| {
                        let topics: Vec<_> = log
                            .topics
                            .into_iter()
                            .map(|topic| sp_core::H256(topic.0))
                            .collect();
                        (topics, log.data)
                    })
                    .collect();

                let logs = logs.encode();
                env.write(&logs, false, None)?;

                Ok(RetVal::Converging(1))
            }
        }
    }
}
