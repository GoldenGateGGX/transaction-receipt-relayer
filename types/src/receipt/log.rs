use alloc::vec::Vec;
use alloy_rlp::Encodable;

use crate::{encode, H160, H256};

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Log {
    /// Contract that emitted this log.
    pub address: H160,
    /// Topics of the log. The number of logs depend on what `LOG` opcode is used.
    pub topics: Vec<H256>,
    /// Arbitrary length data.
    pub data: Vec<u8>,
}

impl Log {
    fn rlp_header(&self) -> alloy_rlp::Header {
        let payload_length =
            self.address.length() + self.topics.length() + self.data.as_slice().length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
    }
}

// We have to implement this as we use Vec<u8> instead of alloy_vec::Bytes, so it encodes a bit differ.
impl Encodable for Log {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        encode!(
            out,
            self.rlp_header(),
            self.address,
            self.topics,
            self.data.as_slice()
        );
    }

    fn length(&self) -> usize {
        let rlp_head = self.rlp_header();
        alloy_rlp::length_of_length(rlp_head.payload_length) + rlp_head.payload_length
    }
}
