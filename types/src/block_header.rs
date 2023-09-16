use alloy_rlp::{length_of_length, BufMut, Encodable, EMPTY_LIST_CODE, EMPTY_STRING_CODE};

use crate::{encode, Bloom, H160, H256, H64, U256};

/// The block structure hashed to generate the `block_hash` field for Ethereum's
/// [`execution_payload`][1]; adapted from [`reth_primitives::Header`][2].
///
/// [1]: https://ethereum.org/en/developers/docs/blocks/#block-anatomy
/// [2]: https://github.com/paradigmxyz/reth/blob/f41386d28e89dd436feea872178452e5302314a5/crates/primitives/src/header.rs#L40-L105

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlockHeader {
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
    pub logs_bloom: Bloom,
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlockHeaderWithTransaction {
    pub header: BlockHeader,
    pub transactions: Vec<H256>,
}

impl BlockHeader {
    fn header_payload_length(&self) -> usize {
        let mut length = 0;
        length += self.parent_hash.length();
        length += self.ommers_hash.length();
        length += self.beneficiary.length();
        length += self.state_root.length();
        length += self.transactions_root.length();
        length += self.receipts_root.length();
        length += self.logs_bloom.length();
        length += self.difficulty.length();
        length += U256::from(self.number).length();
        length += U256::from(self.gas_limit).length();
        length += U256::from(self.gas_used).length();
        length += self.timestamp.length();
        length += self.extra_data.as_slice().length();
        length += self.mix_hash.length();
        length += H64(self.nonce.to_be_bytes()).length();

        if let Some(base_fee) = self.base_fee_per_gas {
            length += U256::from(base_fee).length();
        } else if self.withdrawals_root.is_some()
            || self.blob_gas_used.is_some()
            || self.excess_blob_gas.is_some()
        {
            length += 1; // EMPTY STRING CODE
        }

        if let Some(root) = &self.withdrawals_root {
            length += root.length();
        } else if self.blob_gas_used.is_some() || self.excess_blob_gas.is_some() {
            length += 1; // EMPTY STRING CODE
        }

        if let Some(blob_gas_used) = self.blob_gas_used {
            length += U256::from(blob_gas_used).length();
        } else if self.excess_blob_gas.is_some() {
            length += 1; // EMPTY STRING CODE
        }

        // Encode excess blob gas length. If new fields are added, the above pattern will need to
        // be repeated and placeholder length added. Otherwise, it's impossible to tell _which_
        // fields are missing. This is mainly relevant for contrived cases where a header is
        // created at random, for example:
        //  * A header is created with a withdrawals root, but no base fee. Shanghai blocks are
        //    post-London, so this is technically not valid. However, a tool like proptest would
        //    generate a block like this.
        if let Some(excess_blob_gas) = self.excess_blob_gas {
            length += U256::from(excess_blob_gas).length();
        }

        length
    }
}

impl Encodable for BlockHeader {
    fn encode(&self, out: &mut dyn BufMut) {
        let list_header = alloy_rlp::Header {
            list: true,
            payload_length: self.header_payload_length(),
        };

        encode!(
            out,
            list_header,
            self.parent_hash,
            self.ommers_hash,
            self.beneficiary,
            self.state_root,
            self.transactions_root,
            self.receipts_root,
            self.logs_bloom,
            self.difficulty,
            U256::from(self.number),
            U256::from(self.gas_limit),
            U256::from(self.gas_used),
            self.timestamp,
            self.extra_data.as_slice(),
            self.mix_hash,
            H64(self.nonce.to_be_bytes())
        );
        // Encode base fee. Put empty string if base fee is missing,
        // but withdrawals root is present.
        if let Some(ref base_fee) = self.base_fee_per_gas {
            encode!(out, U256::from(*base_fee));
        } else if self.withdrawals_root.is_some()
            || self.blob_gas_used.is_some()
            || self.excess_blob_gas.is_some()
        {
            encode!(out, EMPTY_STRING_CODE);
        }

        // Encode withdrawals root. Put empty string if withdrawals root is missing,
        // but blob gas used is present.
        if let Some(ref root) = self.withdrawals_root {
            encode!(out, root);
        } else if self.blob_gas_used.is_some() || self.excess_blob_gas.is_some() {
            encode!(out, EMPTY_STRING_CODE);
        }

        // Encode blob gas used. Put empty string if blob gas used is missing,
        // but excess blob gas is present.
        if let Some(ref blob_gas_used) = self.blob_gas_used {
            encode!(out, U256::from(*blob_gas_used));
        } else if self.excess_blob_gas.is_some() {
            encode!(out, EMPTY_LIST_CODE);
        }

        // Encode excess blob gas. If new fields are added, the above pattern will need to be
        // repeated and placeholders added. Otherwise, it's impossible to tell _which_ fields
        // are missing. This is mainly relevant for contrived cases where a header is created
        // at random, for example:
        //  * A header is created with a withdrawals root, but no base fee. Shanghai blocks are
        //    post-London, so this is technically not valid. However, a tool like proptest would
        //    generate a block like this.
        if let Some(ref excess_blob_gas) = self.excess_blob_gas {
            encode!(out, U256::from(*excess_blob_gas));
        }
    }

    fn length(&self) -> usize {
        let mut length = 0;
        length += self.header_payload_length();
        length += length_of_length(length);
        length
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::{BlockHeader, Bloom, H160, H256, U256};

    #[test]
    fn test_eip1559_block_header_hash() {
        let expected_hash = H256(hex!(
            "6a251c7c3c5dca7b42407a3752ff48f3bbca1fab7f9868371d9918daf1988d1f"
        ));
        let header = BlockHeader {
            parent_hash: H256(hex!("e0a94a7a3c9617401586b1a27025d2d9671332d22d540e0af72b069170380f2a")),
            ommers_hash: H256(hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")),
            beneficiary: H160(hex!("ba5e000000000000000000000000000000000000")),
            state_root: H256(hex!("ec3c94b18b8a1cff7d60f8d258ec723312932928626b4c9355eb4ab3568ec7f7")),
            transactions_root: H256(hex!("50f738580ed699f0469702c7ccc63ed2e51bc034be9479b7bff4e68dee84accf")),
            receipts_root: H256(hex!("29b0562f7140574dd0d50dee8a271b22e1a0a7b78fca58f7c60370d8317ba2a9")),
            logs_bloom: Bloom::new(hex!("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
            difficulty: U256::from(0x020000),
            number: 0x01_u64,
            gas_limit: 0x016345785d8a0000_u64,
            gas_used: 0x015534_u64,
            timestamp: 0x079e,
            extra_data: hex_literal::hex!("42").to_vec(),
            mix_hash: H256(hex!("0000000000000000000000000000000000000000000000000000000000000000")),
            nonce: 0,
            base_fee_per_gas: Some(0x036b_u64),
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
        };
        assert_eq!(H256::hash(header), expected_hash);
    }

    // curl https://mainnet.infura.io/v3/{YOUR_API_KEY}   -X POST   -H "Content-Type: application/json"
    //      -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x10FE785",false],"id":1}
    // https://etherscan.io/block/17819525
    #[test]
    fn test_block_17819525() {
        let expected_hash = H256(hex!(
            "ef6f592b69bceca6bf801f0b32a0173007e4e6e9f375c49841c18eacbb5c37ff"
        ));
        let header = BlockHeader {
            parent_hash: H256(hex!("57788a1d18e41704faafe17649d735efa2654e648707246ae78071654db64363")),
            ommers_hash: H256(hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")),
            beneficiary: H160(hex!("95222290dd7278aa3ddd389cc1e1d165cc4bafe5")),
            state_root: H256(hex!("3befce142543d32f9a4aa209d76361a9f14e307c9f3b347a01c3c9cf194f8dcc")),
            transactions_root: H256(hex!("921355a0945f1861fbd6581db1df0b4f59a7937aef800db27b2ceb09a2e63e6f")),
            receipts_root: H256(hex!("65c4e84c69c03bf12c42643cf15b55775a4c62bd7d728a3b641f66673b3b51a2")),
            logs_bloom: Bloom::new(hex!("a36710b1555713853e7c2974af0c5281a2e00270c6bd6020924118016073a543d1609be18c0e068cd1051f2a8ac5319cde07442f8a83ea135336b6b2c82c22a4ec28c49e48440879c8a7419f732832a28c41248527c48936f82006e790731b41da0174ac0219945b0428d1b401b03c15b1db4242a9d9249696745e1711de3100c88783d206dc1922025446f661262c1e049654d3c53924486ead407804de343aa2ac2ce4de8034502e1954c18083948b0d3a44ea9a2c12ac29f198671a1b425d31360812580ecc538301b3850d3ef60026f4aa43342aab191828694a0891f57866302f08d4672408024786b47c22c542a47cf170af40c8412003a80202c97663")),
            difficulty: U256::from(0x0),
            number: 0x10fe785,
            gas_limit: 0x1c9c380,
            gas_used: 0xec8823,
            timestamp: 0x64c8dcf7,
            extra_data: hex_literal::hex!("6265617665726275696c642e6f7267").to_vec(),
            mix_hash: H256(hex!("b3941446d0aa46c87a1117565c922e00e4f4111c602a2583d9a7d25521b0f932")),
            nonce: 0,
            base_fee_per_gas: Some(0x65a3cb387),
            withdrawals_root: Some(H256(hex!("5d908bbdb4303d3be4ec0565005a0bc4ca3ad820143fba16351f1d7fb4dfbfe9"))),
            blob_gas_used: None,
            excess_blob_gas: None,
        };
        assert_eq!(H256::hash(header), expected_hash);
    }
}
