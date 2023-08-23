use alloy_rlp::{BufMut, Encodable};

use crate::{encode::rlp_node, receipt::trie::nibble::Nibbles, TransactionReceipt};

#[derive(Debug, Clone)]
pub struct ReceiptLeaf {
    pub key: Nibbles,
    pub value: TransactionReceipt,
}

impl Encodable for ReceiptLeaf {
    fn encode(&self, result: &mut dyn BufMut) {
        #[derive(alloy_rlp::RlpEncodable)]
        struct S<'a> {
            encoded_path: &'a [u8],
            value: &'a [u8],
        }
        let mut out = vec![];
        self.value.encode(&mut out);

        let s = S {
            encoded_path: &self.key.encode_path_leaf(true),
            value: &out,
        };

        let mut buff = vec![];

        s.encode(&mut buff);

        rlp_node(&buff, result);
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc, sync::Arc};

    use alloy_rlp::Encodable;
    use cita_trie::{node::LeafNode, MemoryDB, PatriciaTrie};
    use hasher::HasherKeccak;

    use crate::{
        receipt::trie::{leaf::ReceiptLeaf, nibble::Nibbles},
        Bloom, Log, Receipt, TransactionReceipt, H160, H256,
    };

    proptest::proptest! {
        #[test]
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

            let our_leaf = ReceiptLeaf {
                key: Nibbles::new(key.clone()),
                value: receipt,
            };

            let mut our_leaf_encoded = vec![];
            our_leaf.encode(&mut our_leaf_encoded);

            let trie = PatriciaTrie::new(Arc::new(MemoryDB::new(true)), Arc::new(HasherKeccak::new()));

            let node = LeafNode {
                key: cita_trie::nibbles::Nibbles::from_raw(key, true),
                value: receipt_encoded,
            };
            let encoded = trie.encode_node(cita_trie::node::Node::Leaf(Rc::new(RefCell::new(node))));
            assert_eq!(&our_leaf_encoded, &encoded);
        }
    }
}
