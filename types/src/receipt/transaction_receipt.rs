use alloy_rlp::RlpEncodable;
use serde::{Deserialize, Serialize};

use crate::Bloom;

use super::log::Log;
use super::tx_type::TxType;

/// The receipt structure containing logs from smart contracts we are listening to; adapted from
/// [`reth_primitives::ReceiptWithBloom`][1].
///
/// [1]: https://ethereum.org/en/developers/docs/blocks/#block-anatomy
/// [2]: https://github.com/paradigmxyz/reth/blob/f41386d28e89dd436feea872178452e5302314a5/crates/primitives/src/receipt.rs#L57-L62
#[derive(Debug, RlpEncodable, PartialEq, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Bloom filter build from logs.
    pub bloom: Bloom,
    /// Main receipt body
    pub receipt: Receipt,
}

/// The receipt structure containing logs from smart contracts we are listening to; adapted from
/// [`reth_primitives::Receipt`][1].
///
/// [1]: https://github.com/paradigmxyz/reth/blob/f41386d28e89dd436feea872178452e5302314a5/crates/primitives/src/receipt.rs#L14-L31
#[derive(Debug, RlpEncodable, PartialEq, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Receipt type.
    pub tx_type: TxType,
    /// If transaction is executed successfully.
    ///
    /// This is the `statusCode`
    pub success: bool,
    /// Gas used
    pub cumulative_gas_used: u64,
    /// Logs sent from contracts.
    pub logs: Vec<Log>,
}
