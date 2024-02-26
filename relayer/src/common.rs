use std::{
    process::exit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use types::{BlockHeaderWithTransaction, Bloom, TransactionReceipt, TxType, H160, H256, U256};

use crate::config::Config;

pub fn convert_ethers_receipt(
    receipt: ethers::types::TransactionReceipt,
) -> eyre::Result<TransactionReceipt> {
    let mut bloom = [0u8; 256];
    bloom.copy_from_slice(&receipt.logs_bloom.0);

    let transaction_receipt = TransactionReceipt {
        bloom: types::Bloom::new(bloom),
        receipt: types::Receipt {
            tx_type: TxType::from_u64(receipt.transaction_type.unwrap_or_default().as_u64())
                .ok_or_else(|| eyre::eyre!("invalid tx type"))?,
            success: receipt.status.map(|e| e.as_u64() == 1).unwrap_or_default(),
            cumulative_gas_used: receipt.cumulative_gas_used.as_u64(),
            logs: receipt
                .logs
                .into_iter()
                .map(convert_ethers_log)
                .collect::<eyre::Result<Vec<_>>>()?,
        },
    };

    Ok(transaction_receipt)
}

pub fn convert_ethers_log(log: ethers::types::Log) -> eyre::Result<types::Log> {
    let log = types::Log {
        address: H160(log.address.0),
        topics: log
            .topics
            .into_iter()
            .map(|e| H256(e.0))
            .collect::<Vec<_>>(),
        data: log.data.0.to_vec(),
    };

    Ok(log)
}

pub fn convert_ethers_block(
    execution_block: ethers::types::Block<ethers::types::H256>,
) -> eyre::Result<BlockHeaderWithTransaction> {
    let mut bloom = [0u8; 256];
    let err = || eyre::eyre!("Failed to parse block");
    bloom.copy_from_slice(&execution_block.logs_bloom.ok_or_else(err)?.0);
    let header = types::BlockHeader {
        parent_hash: H256(execution_block.parent_hash.0),
        beneficiary: H160(execution_block.author.ok_or_else(err)?.0),
        state_root: H256(execution_block.state_root.0),
        transactions_root: H256(execution_block.transactions_root.0),
        receipts_root: H256(execution_block.receipts_root.0),
        withdrawals_root: execution_block.withdrawals_root.map(|r| H256(r.0)),
        logs_bloom: Bloom::new(bloom),
        number: execution_block.number.ok_or_else(err)?.as_u64(),
        gas_limit: execution_block.gas_limit.as_u64(),
        gas_used: execution_block.gas_used.as_u64(),
        timestamp: execution_block.timestamp.as_u64(),
        mix_hash: H256(execution_block.mix_hash.ok_or_else(err)?.0),
        base_fee_per_gas: Some(execution_block.base_fee_per_gas.ok_or_else(err)?.as_u64()),
        extra_data: execution_block.extra_data.0.to_vec(),

        // Defaults
        ommers_hash: H256(execution_block.uncles_hash.0),
        difficulty: U256(execution_block.difficulty.into()),
        nonce: execution_block.nonce.ok_or_else(err)?.to_low_u64_be(),

        blob_gas_used: execution_block.blob_gas_used.map(|a| a.as_u64()),
        excess_blob_gas: execution_block.excess_blob_gas.map(|a| a.as_u64()),
        parent_beacon_block_root: execution_block.parent_beacon_block_root.map(|a| H256(a.0)),
    };

    Ok(BlockHeaderWithTransaction {
        header,
        transactions: execution_block
            .transactions
            .into_iter()
            .map(|h| H256(h.0))
            .collect(),
    })
}

pub fn prepare_config(config: &Config) -> helios::config::Config {
    let helios_config: helios::config::Config = helios::config::Config::from_file(
        &config.helios_config_path,
        &config.network,
        &Default::default(),
    );

    helios_config
}

pub fn exit_if_term(term: Arc<AtomicBool>) {
    if term.load(Ordering::Relaxed) {
        log::info!(target: "relayer::exit_if_term","caught SIGTERM");
        exit(0);
    }
}
