use alloy_rlp::RlpEncodable;

use crate::{H160, H256};
use serde::{Deserialize, Serialize};

#[derive(Debug, RlpEncodable, PartialEq, Clone, Deserialize, Serialize)]
pub struct Log {
    /// Contract that emitted this log.
    pub address: H160,
    /// Topics of the log. The number of logs depend on what `LOG` opcode is used.
    pub topics: Vec<H256>,
    /// Arbitrary length data.
    pub data: Vec<u8>,
}
