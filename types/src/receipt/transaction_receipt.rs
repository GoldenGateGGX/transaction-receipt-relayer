use alloy_rlp::{BufMut, BytesMut, Encodable};

use crate::Bloom;

use super::log::Log;
use super::tx_type::TxType;

/// The receipt structure containing logs from smart contracts we are listening to; adapted from
/// [`reth_primitives::ReceiptWithBloom`][1].
///
/// [1]: https://ethereum.org/en/developers/docs/blocks/#block-anatomy
/// [2]: https://github.com/paradigmxyz/reth/blob/f41386d28e89dd436feea872178452e5302314a5/crates/primitives/src/receipt.rs#L57-L62
#[derive(Debug, PartialEq, Clone)]
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
#[derive(Debug, PartialEq, Clone)]
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

impl TransactionReceipt {
    fn rlp_header(&self) -> alloy_rlp::Header {
        let payload_length = self.receipt.success.length()
            + self.receipt.cumulative_gas_used.length()
            + self.bloom.length()
            + self.receipt.logs.length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
    }

    fn encode_fields(&self, out: &mut dyn BufMut) {
        let list_encode: [&dyn Encodable; 4] = [
            &self.receipt.success,
            &self.receipt.cumulative_gas_used,
            &self.bloom,
            &self.receipt.logs,
        ];
        alloy_rlp::encode_list::<_, dyn Encodable>(&list_encode, out)
    }
}

impl Encodable for TransactionReceipt {
    fn length(&self) -> usize {
        let rlp_head = self.rlp_header();
        alloy_rlp::length_of_length(rlp_head.payload_length) + rlp_head.payload_length
    }

    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        if matches!(self.receipt.tx_type, TxType::Legacy) {
            self.encode_fields(out);
            return;
        }

        let mut payload = BytesMut::new();
        self.encode_fields(&mut payload);

        match self.receipt.tx_type {
            TxType::EIP2930 => {
                out.put_u8(0x01);
            }
            TxType::EIP1559 => {
                out.put_u8(0x02);
            }
            TxType::EIP4844 => {
                out.put_u8(0x03);
            }
            _ => unreachable!("legacy handled; qed."),
        }
        out.put_slice(payload.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use alloy_rlp::Encodable;
    use hex_literal::hex;

    use crate::{Bloom, Log, Receipt, TransactionReceipt, TxType, H160, H256};

    #[test]
    // Test vector from: https://eips.ethereum.org/EIPS/eip-2481
    fn encode_legacy_receipt() {
        let expected = hex!("f901668001b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f85ff85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff");

        let mut data = vec![];
        let receipt = TransactionReceipt {
            receipt: Receipt {
                tx_type: TxType::Legacy,
                cumulative_gas_used: 0x1u64,
                logs: vec![Log {
                    address: H160(hex!("0000000000000000000000000000000000000011")),
                    topics: vec![
                        H256(hex!(
                            "000000000000000000000000000000000000000000000000000000000000dead"
                        )),
                        H256(hex!(
                            "000000000000000000000000000000000000000000000000000000000000beef"
                        )),
                    ],
                    data: hex!("0100ff").to_vec(),
                }],
                success: false,
            },
            bloom: Bloom::new([0; 256]),
        };

        receipt.encode(&mut data);

        // check that the rlp length equals the length of the expected rlp
        assert_eq!(receipt.length(), expected.len());
        assert_eq!(data, expected);
    }
}
