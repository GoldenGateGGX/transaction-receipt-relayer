use crate::H256;

use super::{
    transaction_receipt::TransactionReceipt,
    trie::{branch::BranchNode, extension::ExtensionNode, leaf::Leaf, nibble::Nibbles},
};

/// Nodes of a Merkle proof that a transaction has been included in a block. Corresponds to `branch`
/// and `extension` nodes for in the [Patricia Merkle Trie][1] used representing included
/// transaction receipts.
///
/// [1]: https://ethereum.org/se/developers/docs/data-structures-and-encoding/patricia-merkle-trie/
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MerkleProofNode {
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
        value: Option<Vec<u8>>,
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
pub struct MerkleProof {
    pub proof: Vec<MerkleProofNode>,
    pub key: Vec<u8>,
}

impl MerkleProof {
    /// Given a transaction receipt, compute the Merkle root of the Patricia Merkle Trie using the
    /// rest of the Merkle proof.
    pub fn merkle_root(&self, leaf: &TransactionReceipt) -> H256 {
        // Recovering a Merkle root from a Merkle proof involves computing the hash of the leaf node
        // and the hashes of the rest of the nodes in the proof.
        //
        // The final hash is the Merkle root.

        // Full nibble path of the leaf node.
        let key = Nibbles::new(self.key.clone());
        let mut key_slice = key.hex_data.as_slice();

        for node in self.proof.iter() {
            match node {
                MerkleProofNode::ExtensionNode { prefix } => key_slice = &key_slice[prefix.len()..],
                MerkleProofNode::BranchNode { .. } => key_slice = &key_slice[1..],
            }
        }

        let mut hash = H256::from_slice(&alloy_rlp::encode(&Leaf::from_transaction_receipt(
            Nibbles::from_hex(key_slice.to_vec()),
            leaf.clone(),
        )));

        for node in self.proof.iter().rev() {
            match node {
                MerkleProofNode::ExtensionNode { prefix } => {
                    hash = H256::from_slice(&alloy_rlp::encode(&ExtensionNode::new(
                        Nibbles::from_hex(prefix.to_vec()),
                        hash,
                    )));
                }
                MerkleProofNode::BranchNode {
                    branches,
                    index,
                    value,
                } => {
                    let mut branches = *branches.as_ref();
                    branches[(index & 0x0f) as usize] = Some(hash);
                    hash = H256::from_slice(&alloy_rlp::encode(&BranchNode {
                        branches,
                        value: value.clone(),
                    }));
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

    use crate::{Bloom, MerkleProof, Receipt, TransactionReceipt, H256};

    fn trie_root(iter: impl Iterator<Item = (Vec<u8>, Vec<u8>)>) -> H256 {
        let mut trie =
            PatriciaTrie::new(Arc::new(MemoryDB::new(true)), Arc::new(HasherKeccak::new()));
        for (k, v) in iter {
            trie.insert(k, v).unwrap();
        }
        trie.iter().for_each(|e| println!("{:?}", e));

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
        let transactions: Vec<TransactionReceipt> = (0..255)
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

        let proof = MerkleProof::from_transactions(transactions.clone(), SEARCHIN_INDEX);

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
