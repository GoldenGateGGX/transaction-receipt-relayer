use types::{BlockHeader, Bloom, TransactionReceipt, H160, H256, U256};

pub fn load_block(test_suit: &str) -> (H256, BlockHeader) {
    let execution_block: ethers::types::Block<ethers::types::H256> =
        serde_json::from_str(test_suit).unwrap();

    let mut bloom = [0u8; 256];
    bloom.copy_from_slice(&execution_block.logs_bloom.unwrap().0);
    let block_header = types::BlockHeader {
        parent_hash: H256(execution_block.parent_hash.0),
        beneficiary: H160(execution_block.author.unwrap().0),
        state_root: H256(execution_block.state_root.0),
        transactions_root: H256(execution_block.transactions_root.0),
        receipts_root: H256(execution_block.receipts_root.0),
        withdrawals_root: execution_block.withdrawals_root.map(|r| H256(r.0)),
        logs_bloom: Bloom::new(bloom),
        number: execution_block.number.unwrap().as_u64(),
        gas_limit: execution_block.gas_limit.as_u64(),
        gas_used: execution_block.gas_used.as_u64(),
        timestamp: execution_block.timestamp.as_u64(),
        mix_hash: H256(execution_block.mix_hash.unwrap().0),
        base_fee_per_gas: execution_block.base_fee_per_gas.map(|a| a.as_u64()),
        extra_data: execution_block.extra_data.0.to_vec(),

        // Defaults
        ommers_hash: H256(execution_block.uncles_hash.0),
        difficulty: U256(execution_block.difficulty.into()),
        nonce: execution_block.nonce.unwrap().to_low_u64_be(),

        blob_gas_used: execution_block.blob_gas_used.map(|a| a.as_u64()),
        excess_blob_gas: execution_block.excess_blob_gas.map(|a| a.as_u64()),
        parent_beacon_block_root: execution_block.parent_beacon_block_root.map(|a| H256(a.0)),
    };

    let hash = H256(execution_block.hash.unwrap().0);
    (hash, block_header)
}

pub fn load_receipts(test_suit: &str) -> Vec<TransactionReceipt> {
    let ethers_recceipts: Vec<ethers::types::TransactionReceipt> =
        serde_json::from_str(test_suit).unwrap();

    ethers_recceipts
        .into_iter()
        .map(|receipt| TransactionReceipt {
            bloom: types::Bloom::new(receipt.logs_bloom.0),
            receipt: types::Receipt {
                tx_type: match receipt.transaction_type.unwrap().as_u64() {
                    0 => types::TxType::Legacy,
                    1 => types::TxType::EIP2930,
                    2 => types::TxType::EIP1559,
                    3 => types::TxType::EIP4844,
                    _ => panic!("Unknown tx type"),
                },
                success: receipt.status.unwrap().as_usize() == 1,
                cumulative_gas_used: receipt.cumulative_gas_used.as_u64(),
                logs: receipt
                    .logs
                    .into_iter()
                    .map(|log| types::Log {
                        address: H160(log.address.0),
                        topics: log.topics.into_iter().map(|topic| H256(topic.0)).collect(),
                        data: log.data.to_vec(),
                    })
                    .collect(),
            },
        })
        .collect::<Vec<_>>()
}
