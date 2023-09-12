use alloy_rlp::{BufMut, Encodable};

use crate::{encode, receipt::trie::nibble::Nibbles, TransactionReceipt};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReceiptLeaf {
    key: Vec<u8>,
    value: Vec<u8>,
}

impl ReceiptLeaf {
    pub fn new(key: Nibbles, value: TransactionReceipt) -> Self {
        Self {
            key: key.encode_path_leaf(true),
            value: alloy_rlp::encode(value),
        }
    }
}

impl ReceiptLeaf {
    fn header(&self) -> alloy_rlp::Header {
        alloy_rlp::Header {
            payload_length: self.key.as_slice().length() + self.value.as_slice().length(),
            list: true,
        }
    }
}

impl Encodable for ReceiptLeaf {
    fn encode(&self, result: &mut dyn BufMut) {
        let header = self.header();
        let mut out = Vec::with_capacity(header.payload_length);
        let out_buf = &mut out;
        encode!(out_buf, header, self.key.as_slice(), self.value.as_slice());

        crate::encode::rlp_node(&out, result);
    }

    fn length(&self) -> usize {
        let header = self.header();
        alloy_rlp::length_of_length(header.payload_length) + header.payload_length
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc, sync::Arc};

    use alloy_rlp::Encodable;
    use hasher::HasherKeccak;
    use merkle_generator::{node::LeafNode, PatriciaTrie};
    use test_strategy::proptest;

    use crate::{
        receipt::trie::{leaf::ReceiptLeaf, nibble::Nibbles},
        Bloom, Log, Receipt, TransactionReceipt, H160, H256,
    };

    #[proptest]
    fn encode_leaf(data: Vec<u8>, number: u8, key: Vec<u8>) {
        let receipt = TransactionReceipt {
            bloom: Bloom::new([number; 256]),
            receipt: Receipt {
                cumulative_gas_used: number as u64,
                logs: vec![Log {
                    address: H160([number; 20]),
                    topics: vec![H256([number; 32])],
                    data,
                }],
                tx_type: crate::TxType::EIP1559,
                success: true,
            },
        };

        let mut receipt_encoded = vec![];
        receipt.encode(&mut receipt_encoded);

        let our_leaf = ReceiptLeaf::new(Nibbles::new(key.clone()), receipt);

        let mut our_leaf_encoded = vec![];
        our_leaf.encode(&mut our_leaf_encoded);

        let trie = PatriciaTrie::new(Arc::new(HasherKeccak::new()));

        let node = LeafNode {
            key: merkle_generator::nibbles::Nibbles::from_raw(key, true),
            value: receipt_encoded,
        };
        let encoded = trie.encode_node(merkle_generator::node::Node::Leaf(Rc::new(RefCell::new(
            node,
        ))));
        assert_eq!(&our_leaf_encoded, &encoded);
    }
}
