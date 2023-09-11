use crate::H256;

use super::{
    transaction_receipt::TransactionReceipt,
    trie::{branch::BranchNode, extension::ExtensionNode, leaf::ReceiptLeaf, nibble::Nibbles},
};

/// Nodes of a Merkle proof that a transaction has been included in a block. Corresponds to `branch`
/// and `extension` nodes for in the [Patricia Merkle Trie][1] used representing included
/// transaction receipts.
///
/// [1]: https://ethereum.org/se/developers/docs/data-structures-and-encoding/patricia-merkle-trie/
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ReceiptMerkleProofNode {
    /// An extension node in the Patricia Merkle Trie.
    ///
    /// The `prefix` is the nibble path to the next node.
    ///
    /// Implicitly, there is a `pointer`, which is a hash resulting from the previous elements of
    /// the Merkle proof.
    ///
    /// See the Ethereum [Yellow Paper][1] for more details.
    ///
    /// Adapted from [`reth_primitives::trie::ExtensionNode`][2].
    ///
    /// [1]: https://ethereum.github.io/yellowpaper/paper.pdf
    /// [2]: https://github.com/paradigmxyz/reth/blob/8c70524fc6031dcc268fd771797f35d6229848e7/crates/primitives/src/trie/nodes/extension.rs#L11-L16
    ExtensionNode { prefix: Vec<u8> },

    /// A branch node in the Patricia Merkle Trie.
    ///
    /// `branches` is an array of 16 (optional) pointers to the next node, corresponding to the 16
    /// possible nibble values.
    ///
    /// `index` is the nibble corresponding to where the hash resulting from the previous elements
    /// of the Merkle proof is to be slotted in.
    ///
    /// See the Ethereum [Yellow Paper][1] for more details.
    ///
    /// Adapted from [`reth_primitives::trie::BranchNode`][2].
    ///
    /// [1]: https://ethereum.github.io/yellowpaper/paper.pdf
    /// [2]: https://github.com/paradigmxyz/reth/blob/8c70524fc6031dcc268fd771797f35d6229848e7/crates/primitives/src/trie/nodes/branch.rs#L8-L15
    BranchNode {
        branches: Box<[Option<H256>; 16]>,
        index: u8,
    },
}

/// A Merkle proof that a transaction receipt has been included in a block.
///
/// Merkle proofs for transaction receipts use Ethereum's [Patricia Merkle Trie][1] data structure.
/// The `receipt_root` field in a block is the root of the trie.
///
/// Requires a [`ReceiptWithBloom`] to generate a leaf node, and the rest of the proof proceeds
/// from the leaf node.
///
/// [1]: https://ethereum.org/se/developers/docs/data-structures-and-encoding/patricia-merkle-trie/
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReceiptMerkleProof {
    pub proof: Vec<ReceiptMerkleProofNode>,
    pub transaction_index: usize,
}

#[cfg(feature = "merkle-proof")]
impl ReceiptMerkleProof {
    pub fn from_transactions(
        transactions: Vec<TransactionReceipt>,
        transaction_to_prove: usize,
    ) -> Self {
        use cita_trie::Trie;
        use std::sync::Arc;

        // key to prove
        let item_to_prove = alloy_rlp::encode(transaction_to_prove);
        let mut cita_trie = cita_trie::PatriciaTrie::new(
            Arc::new(cita_trie::MemoryDB::new(true)),
            Arc::new(hasher::HasherKeccak::new()),
        );

        // populate the trie
        for (i, transaction) in transactions.into_iter().enumerate() {
            let value = alloy_rlp::encode(transaction);
            cita_trie.insert(alloy_rlp::encode(i), value).unwrap();
        }

        // full nibble path to the key
        let key = Nibbles::new(item_to_prove.clone());
        let mut key_slice = key.hex_data.as_slice();

        let mut processing_queue = cita_trie.get_proof(&item_to_prove).unwrap();
        let mut proof = vec![];
        while let Some(node) = processing_queue.pop() {
            match &node {
                cita_trie::node::Node::Extension(node) => {
                    let node = node.borrow();
                    let prefix = node.prefix.get_data();

                    // there is also char that tells either it's leaf or not, but we don't need it
                    let prefix = if node.prefix.is_leaf() {
                        prefix[..prefix.len() - 1].to_vec()
                    } else {
                        prefix.to_vec()
                    };

                    key_slice = &key_slice[prefix.len()..];
                    proof.push(ReceiptMerkleProofNode::ExtensionNode { prefix });
                    processing_queue.push(node.node.clone());
                }
                cita_trie::node::Node::Branch(node) => {
                    let node = node.borrow();
                    let branches = node
                        .children
                        .clone()
                        .into_iter()
                        .enumerate()
                        .map(|(i, node)| {
                            // We don't need to encode the node on the path to the leaf as it will be processed
                            if i == key_slice[0] as usize {
                                return None;
                            }

                            // Encode subtree using cita as it's not on the path to the leaf
                            let encoded_node = cita_trie.encode_node(node);
                            // Cita trie will return a single byte if the node is empty
                            if encoded_node.len() == 1 {
                                None
                            } else {
                                Some(H256::from_slice(&encoded_node))
                            }
                        })
                        .collect::<Vec<_>>();
                    let next = node.children[key_slice[0] as usize].clone();
                    proof.push(ReceiptMerkleProofNode::BranchNode {
                        branches: Box::new(branches.try_into().unwrap()),
                        index: key_slice[0],
                    });
                    processing_queue.push(next);
                    key_slice = &key_slice[1..];
                }

                // We don't need to process them:
                // * Leaf node data is provided by the caller of the verification function
                // * Empty nodes are not included in the proof
                // * Hash nodes are included by cita_trie.get_proof
                cita_trie::node::Node::Empty
                | cita_trie::node::Node::Leaf(_)
                | cita_trie::node::Node::Hash(_) => (),
            };
        }

        ReceiptMerkleProof {
            proof,
            transaction_index: transaction_to_prove,
        }
    }
}

impl ReceiptMerkleProof {
    /// Given a transaction receipt, compute the Merkle root of the Patricia Merkle Trie using the
    /// rest of the Merkle proof.
    pub fn merkle_root(&self, leaf: &TransactionReceipt) -> H256 {
        // Recovering a Merkle root from a Merkle proof involves computing the hash of the leaf node
        // and the hashes of the rest of the nodes in the proof.
        //
        // The final hash is the Merkle root.

        // Full nibble path of the leaf node.
        let key = Nibbles::new(alloy_rlp::encode(self.transaction_index));
        let mut key_slice = key.hex_data.as_slice();

        for node in self.proof.iter() {
            match node {
                ReceiptMerkleProofNode::ExtensionNode { prefix } => {
                    key_slice = &key_slice[prefix.len()..]
                }
                ReceiptMerkleProofNode::BranchNode { .. } => key_slice = &key_slice[1..],
            }
        }

        let mut hash = H256::from_slice(&alloy_rlp::encode(&ReceiptLeaf::new(
            Nibbles::from_hex(key_slice.to_vec()),
            leaf.clone(),
        )));

        for node in self.proof.iter().rev() {
            match node {
                ReceiptMerkleProofNode::ExtensionNode { prefix } => {
                    hash = H256::from_slice(&alloy_rlp::encode(&ExtensionNode::new(
                        Nibbles::from_hex(prefix.to_vec()),
                        hash,
                    )));
                }
                ReceiptMerkleProofNode::BranchNode { branches, index } => {
                    let mut branches = *branches.as_ref();
                    branches[(index & 0x0f) as usize] = Some(hash);
                    hash = H256::from_slice(&alloy_rlp::encode(&BranchNode { branches }));
                }
            }
        }
        hash
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_rlp::Encodable;
    use cita_trie::{MemoryDB, PatriciaTrie, Trie};
    use hasher::HasherKeccak;

    use crate::{Bloom, Receipt, ReceiptMerkleProof, TransactionReceipt, H256};

    fn trie_root(iter: impl Iterator<Item = (Vec<u8>, Vec<u8>)>) -> H256 {
        let mut trie =
            PatriciaTrie::new(Arc::new(MemoryDB::new(true)), Arc::new(HasherKeccak::new()));
        for (k, v) in iter {
            trie.insert(k, v).unwrap();
        }

        H256(trie.root().unwrap()[..32].try_into().unwrap())
    }

    fn transaction_to_key_value(
        (index, transaction): (usize, TransactionReceipt),
    ) -> (Vec<u8>, Vec<u8>) {
        let mut vec = vec![];
        transaction.encode(&mut vec);
        (alloy_rlp::encode(index), vec)
    }

    #[test]
    fn test_merkle_proof() {
        let transactions: Vec<TransactionReceipt> = (0..200)
            .map(|e| TransactionReceipt {
                bloom: Bloom::new([e; 256]),
                receipt: Receipt {
                    tx_type: crate::TxType::EIP1559,
                    logs: vec![],
                    cumulative_gas_used: e as u64,
                    success: true,
                },
            })
            .collect();
        const SEARCHIN_INDEX: usize = 55;
        let searching_for = transactions[SEARCHIN_INDEX].clone();
        let proof = ReceiptMerkleProof::from_transactions(transactions.clone(), SEARCHIN_INDEX);

        let restored_root = proof.merkle_root(&searching_for);

        let root = trie_root(
            transactions
                .into_iter()
                .enumerate()
                .map(transaction_to_key_value),
        );
        assert_eq!(root, restored_root);
    }
}
