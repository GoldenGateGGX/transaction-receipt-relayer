use alloy_rlp::{Encodable, RlpEncodable};

use crate::{H160, H256};

#[derive(Debug, PartialEq, Clone)]
pub struct Log {
    /// Contract that emitted this log.
    pub address: H160,
    /// Topics of the log. The number of logs depend on what `LOG` opcode is used.
    pub topics: Vec<H256>,
    /// Arbitrary length data.
    pub data: Vec<u8>,
}

// We have to implement this as we use Vec<u8> instead of alloy_vec::Bytes, so it encodes a bit differ.
impl Encodable for Log {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        todo!()
    }

    fn length(&self) -> usize {
        todo!()
    }
}
