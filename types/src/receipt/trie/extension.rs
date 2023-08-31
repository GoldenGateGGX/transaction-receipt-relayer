use alloy_rlp::Encodable;

use crate::{encode, H256};

use super::nibble::Nibbles;

#[derive(Debug)]
pub struct ExtensionNode {
    pub prefix: Vec<u8>,
    pub pointer: H256,
}

impl ExtensionNode {
    pub fn new(prefix: Nibbles, pointer: H256) -> Self {
        Self {
            prefix: prefix.encode_path_leaf(false),
            pointer,
        }
    }
}

impl ExtensionNode {
    fn header(&self) -> alloy_rlp::Header {
        alloy_rlp::Header {
            payload_length: self.prefix.as_slice().length() + self.pointer.length(),
            list: true,
        }
    }
}

impl Encodable for ExtensionNode {
    fn encode(&self, result: &mut dyn alloy_rlp::BufMut) {
        let header = self.header();
        let mut out = Vec::with_capacity(header.payload_length);
        let out_buf = &mut out;
        encode!(out_buf, header, self.prefix.as_slice(), self.pointer);

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

    use cita_trie::MemoryDB;
    use hasher::HasherKeccak;
    use proptest::proptest;

    use crate::{receipt::trie::leaf::ReceiptLeaf, Bloom, Log, Receipt, TransactionReceipt, H160};

    use super::*;

    proptest! {
        #[test]
        fn test_extension_node(mut prefix: Vec<u8>, number:u8, data:Vec<u8>, leaf_key: Vec<u8>) {

            // cita crashes on empty prefix
            prefix.push(0u8);
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

            let our_leaf = ReceiptLeaf::new(Nibbles::new(leaf_key.clone()), receipt);
            let leaf_encoded = alloy_rlp::encode(our_leaf);

            let node = ExtensionNode::new(
                Nibbles::new(prefix.clone()),
                H256(leaf_encoded[..32].try_into().unwrap()),
            );

            let our_encoded = alloy_rlp::encode(node);

            let cita_node = cita_trie::node::ExtensionNode {
                prefix: cita_trie::nibbles::Nibbles::from_raw(prefix, false),
                node: cita_trie::node::Node::Leaf(Rc::new(RefCell::new(cita_trie::node::LeafNode {
                    key: cita_trie::nibbles::Nibbles::from_raw(leaf_key, true),
                    value: receipt_encoded,
                }))),
            };
            let trie = cita_trie::PatriciaTrie::new(
                Arc::new(MemoryDB::new(true)),
                Arc::new(HasherKeccak::new()),
            );

            let cita_encoded = trie.encode_node(cita_trie::node::Node::Extension(Rc::new(
                RefCell::new(cita_node),
            )));

            assert_eq!(our_encoded, cita_encoded);
        }
    }
}
