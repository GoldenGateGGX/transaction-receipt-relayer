pub use ethers::types::{H160, H256, U256};

mod block_header;

pub use block_header::BlockHeader;

pub struct EventProof {
    /// Block corresponding to a [stored block hash][1] in Webb's `pallet-eth2-light-client`.
    /// The hash of this structure is computed using its [rlp][2] representation. In particular, this is the 12th field of `execution_payload`,
    /// which is the 9th field of `body`. See the Ethereum documentation for [What's in a
    /// Block?][4].
    ///
    /// For a reference derivation of this field, see the [`reth` source code][3].
    ///
    /// [1]: https://github.com/webb-tools/pallet-eth2-light-client/blob/4d8a20ad325795a2d166fcd2a6118db3037581d3/pallet/src/lib.rs#L221-L233
    /// [2]: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
    /// [3]: https://ethereum.org/en/developers/docs/blocks/#block-anatomy
    /// [4]: https://github.com/paradigmxyz/reth/blob/15bb1c90b8e60dcaaaa1d2cbc82817d135192cbd/crates/rpc/rpc-types/src/eth/engine/payload.rs#L151-L178
    pub block: BlockHeader,

    pub block_hash: H256,

    /// A transaction receipt. Must contain an event we are configured to listen to emitted by a
    /// configured smart contract.
    pub transaction_receipt: TransactionReceipt,

    /// A Merkle proof that the transaction receipt has been included in the `receipt_root` field in
    /// the `block`.
    pub merkle_proof_of_receipt: ReceiptMerkleProof,
}

/// Error type for validating `EventProofTransaction`s.
pub enum ValidationError {}

impl EventProof {
    /// Check that the `EventProofTransaction` is valid.
    pub fn validate(&self) -> Result<(), ValidationError> {
        unimplemented!()
    }
}

/// The receipt structure containing logs from smart contracts we are listening to; adapted from
/// [`reth_primitives::ReceiptWithBloom`][1].
///
/// [1]: https://ethereum.org/en/developers/docs/blocks/#block-anatomy
/// [2]: https://github.com/paradigmxyz/reth/blob/f41386d28e89dd436feea872178452e5302314a5/crates/primitives/src/receipt.rs#L57-L62
pub struct TransactionReceipt {
    /// Bloom filter build from logs.
    pub bloom: Vec<u8>,
    /// Main receipt body
    pub receipt: Receipt,
}

/// Transaction Type enum; adapted from [`reth_primitives::TxType`][1].
///
/// [1]: https://github.com/paradigmxyz/reth/blob/f41386d28e89dd436feea8721784
pub enum TxType {
    /// Block corresponding to a [stored block hash][1] in Webb's `pallet-eth2-light-client`.
    /// The hash of this structure is computed using its [rlp][2] representation. In particular, this is the 12th field of `exec
    EIP2930 = 1_isize,
    /// Transaction with Priority fee
    EIP1559 = 2_isize,
    /// Shard Blob Transactions - EIP-4844
    EIP4844 = 3_isize,
}

/// The receipt structure containing logs from smart contracts we are listening to; adapted from
/// [`reth_primitives::Receipt`][1].
///
/// [1]: https://github.com/paradigmxyz/reth/blob/f41386d28e89dd436feea872178452e5302314a5/crates/primitives/src/receipt.rs#L14-L31
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

pub struct Log {
    /// Contract that emitted this log.
    pub address: H160,
    /// Topics of the log. The number of logs depend on what `LOG` opcode is used.
    pub topics: Vec<H256>,
    /// Arbitrary length data.
    pub data: Vec<u8>,
}

/// Nodes of a Merkle proof that a transaction has been included in a block. Corresponds to `branch`
/// and `extension` nodes for in the [Patricia Merkle Trie][1] used representing included
/// transaction receipts.
///
/// [1]: https://ethereum.org/se/developers/docs/data-structures-and-encoding/patricia-merkle-trie/
pub enum ReceiptMerkleProofNode {
    ExtensionNode {
        prefix: Vec<u8>,
    },
    BranchNode {
        index: u8,
        branches: [Option<Vec<u8>>; 16],
    },
}

/// A Merkle proof that a transaction receipt has been included in a block.
///
/// Merkle proofs for transaction receipts use Ethereum's [Patricia Merkle Trie][1] data structure.
/// The `receipt_root` field in a block is the root of the trie.
///
/// Requires a [`TransactionReceipt`] to generate a leaf node, and the rest of the proof proceeds
/// from the leaf node.
///
/// [1]: https://ethereum.org/se/developers/docs/data-structures-and-encoding/patricia-merkle-trie/
pub struct ReceiptMerkleProof {
    pub proof: Vec<ReceiptMerkleProofNode>,
}

impl ReceiptMerkleProof {
    /// Given a transaction receipt, compute the Merkle root of the Patricia Merkle Trie using the
    /// rest of the Merkle proof.
    pub fn merkle_root(&self, _leaf: &TransactionReceipt) -> H256 {
        unimplemented!()
    }
}
