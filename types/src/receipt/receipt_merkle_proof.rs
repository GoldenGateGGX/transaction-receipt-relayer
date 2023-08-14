use crate::H256;
use alloy_rlp::{Encodable, RlpEncodable};
use bytes::BufMut;
use serde::{Deserialize, Serialize};

use super::transaction_receipt::TransactionReceipt;

/// Nodes of a Merkle proof that a transaction has been included in a block. Corresponds to `branch`
/// and `extension` nodes for in the [Patricia Merkle Trie][1] used representing included
/// transaction receipts.
///
/// [1]: https://ethereum.org/se/developers/docs/data-structures-and-encoding/patricia-merkle-trie/
#[derive(Debug, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiptMerkleProof {
    pub proof: Vec<ReceiptMerkleProofNode>,
}

#[derive(Debug, RlpEncodable, Serialize, Deserialize)]
pub struct ReceiptLeaf {
    pub key: H256,
    pub value: TransactionReceipt,
}

#[derive(Debug, RlpEncodable, Serialize, Deserialize)]
pub struct ExtensionNode {
    pub prefix: Vec<u8>,
    pub pointer: H256,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BranchNode {
    pub branches: [Option<H256>; 16],
}

impl Encodable for BranchNode {
    fn encode(&self, buf: &mut dyn BufMut) {
        // TODO: this is probably not the correct way of encoding branches
        for branch in self.branches.iter() {
            match branch {
                Some(h256) => {
                    h256.encode(buf);
                }
                None => {
                    [0_u8; 32].encode(buf);
                }
            }
        }
    }

    fn length(&self) -> usize {
        32 * 16
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
        let mut hash = H256::hash(&ReceiptLeaf {
            key: H256::hash(leaf),
            value: leaf.clone(),
        });
        for node in self.proof.iter() {
            match node {
                ReceiptMerkleProofNode::ExtensionNode { prefix } => {
                    hash = H256::hash(&ExtensionNode {
                        prefix: prefix.clone(),
                        pointer: hash,
                    });
                }
                ReceiptMerkleProofNode::BranchNode { index, branches } => {
                    let mut branches = branches.as_ref().clone();
                    branches[(*index & 0x0f) as usize] = Some(hash);
                    hash = H256::hash(&BranchNode { branches });
                }
            }
        }
        hash
    }
}
