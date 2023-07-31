type H256 = [u8; 32];
type U256 = [u8; 32];
type H160 = [u8; 20];

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
    pub block: Block,

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

/// The block structure hashed to generate the `block_hash` field for Ethereum's
/// [`execution_payload`][1]; adapted from [`reth_primitives::Header`][2].
///
/// [1]: https://ethereum.org/en/developers/docs/blocks/#block-anatomy
/// [2]: https://github.com/paradigmxyz/reth/blob/f41386d28e89dd436feea872178452e5302314a5/crates/primitives/src/header.rs#L40-L105
pub struct Block {
    /// The Keccak 256-bit hash of the parent
    /// block's header, in its entirety; formally Hp.
    pub parent_hash: H256,
    /// The Keccak 256-bit hash of the ommers list portion of this block; formally Ho.
    pub ommers_hash: H256,
    /// The 160-bit address to which all fees collected from the successful mining of this block
    /// be transferred; formally Hc.
    pub beneficiary: H160,
    /// The Keccak 256-bit hash of the root node of the state trie, after all transactions are
    /// executed and finalisations applied; formally Hr.
    pub state_root: H256,
    /// The Keccak 256-bit hash of the root node of the trie structure populated with each
    /// transaction in the transactions list portion of the block; formally Ht.
    pub transactions_root: H256,
    /// The Keccak 256-bit hash of the root node of the trie structure populated with the receipts
    /// of each transaction in the transactions list portion of the block; formally He.
    pub receipts_root: H256,
    /// The Keccak 256-bit hash of the withdrawals list portion of this block.
    /// <https://eips.ethereum.org/EIPS/eip-4895>
    pub withdrawals_root: Option<H256>,
    /// The Bloom filter composed from indexable information (logger address and log topics)
    /// contained in each log entry from the receipt of each transaction in the transactions list;
    /// formally Hb.
    pub logs_bloom: Vec<u8>,
    /// A scalar value corresponding to the difficulty level of this block. This can be calculated
    /// from the previous block's difficulty level and the timestamp; formally Hd.
    pub difficulty: U256,
    /// A scalar value equal to the number of ancestor blocks. The genesis block has a number of
    /// zero; formally Hi.
    pub number: u64,
    /// A scalar value equal to the current limit of gas expenditure per block; formally Hl.
    pub gas_limit: u64,
    /// A scalar value equal to the total gas used in transactions in this block; formally Hg.
    pub gas_used: u64,
    /// A scalar value equal to the reasonable output of Unix's time() at this block's inception;
    /// formally Hs.
    pub timestamp: u64,
    /// A 256-bit hash which, combined with the
    /// nonce, proves that a sufficient amount of computation has been carried out on this block;
    /// formally Hm.
    pub mix_hash: H256,
    /// A 64-bit value which, combined with the mixhash, proves that a sufficient amount of
    /// computation has been carried out on this block; formally Hn.
    pub nonce: u64,
    /// A scalar representing EIP1559 base fee which can move up or down each block according
    /// to a formula which is a function of gas used in parent block and gas target
    /// (block gas limit divided by elasticity multiplier) of parent block.
    /// The algorithm results in the base fee per gas increasing when blocks are
    /// above the gas target, and decreasing when blocks are below the gas target. The base fee per
    /// gas is burned.
    pub base_fee_per_gas: Option<u64>,
    /// The total amount of blob gas consumed by the transactions within the block, added in
    /// EIP-4844.
    pub blob_gas_used: Option<u64>,
    /// A running total of blob gas consumed in excess of the target, prior to the block. Blocks
    /// with above-target blob gas consumption increase this value, blocks with below-target blob
    /// gas consumption decrease it (bounded at 0). This was added in EIP-4844.
    pub excess_blob_gas: Option<u64>,
    /// An arbitrary byte array containing data relevant to this block. This must be 32 bytes or
    /// fewer; formally Hx.
    pub extra_data: Vec<u8>,
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
/// [1]: https://github.com/paradigmxyz/reth/blob/f41386d28e89dd436feea872178452e5302314a5/crates/primitives/src/transaction/tx_type.rs#L22-L32
#[derive(Default)]
pub enum TxType {
    /// Legacy transaction pre EIP-2929
    #[default]
    Legacy = 0_isize,
    /// AccessList transaction
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
