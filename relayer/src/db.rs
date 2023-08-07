use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use ethers::{abi::AbiDecode, abi::AbiEncode};
use eyre::Result;
use rusqlite::Connection;
use types::{BlockHeader, H256};

#[derive(Clone)]
pub struct DB {
    conn: Arc<Mutex<Connection>>,
}

impl DB {
    pub fn new(db_dir: &Path) -> Result<Self> {
        let conn = Connection::open(db_dir.join("db.sqlite"))?;

        Ok(DB {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn create_tables(&self) -> Result<()> {
        let conn = self.conn.lock().expect("acquire mutex");
        let sql = include_str!("./sql/schema.sql");
        Ok(conn.execute_batch(sql)?)
    }

    pub fn select_latest_fetched_block_height(&self) -> Result<Option<u64>> {
        let conn = self.conn.lock().expect("acquire mutex");
        let mut stmt =
            conn.prepare("SELECT block_height FROM blocks ORDER BY block_height DESC LIMIT 1;")?;
        let block_height_iter = stmt.query_map([], |row| row.get::<_, u64>(0))?;

        Ok(block_height_iter
            .flatten()
            .collect::<Vec<_>>()
            .first()
            .cloned())
    }

    pub fn select_latest_fetched_block_hash(&self) -> Result<Option<H256>> {
        let conn = self.conn.lock().expect("acquire mutex");
        let mut stmt =
            conn.prepare("SELECT block_hash FROM blocks ORDER BY block_height DESC LIMIT 1;")?;
        let block_hash_iter = stmt.query_map([], |row| row.get::<_, String>(0))?;

        Ok(block_hash_iter
            .flatten()
            .flat_map(|hash| {
                Ok::<H256, eyre::Report>(H256(ethers::types::H256::decode_hex(hash)?.0))
            })
            .collect::<Vec<_>>()
            .first()
            .cloned())
    }

    pub fn insert_block(
        &self,
        block_number: u64,
        block_hash: H256,
        block_header: BlockHeader,
        bloom_positive: bool,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("acquire mutex");
        let is_processed = !bloom_positive; // We need to process only bloom positive blocks
        conn.execute(
            "INSERT INTO blocks(block_height, block_hash, block_header, is_processed) values (?1, ?2, ?3, ?4)",
            (
                block_number,
                block_hash.0.encode_hex(),
                serde_json::to_string(&block_header)?,
                is_processed,
            ),
        )?;

        Ok(())
    }

    #[allow(dead_code)]
    pub fn select_block_by_block_hash(&self, block_hash: H256) -> Result<Option<BlockHeader>> {
        let conn = self.conn.lock().expect("acquire mutex");
        let mut stmt =
            conn.prepare("SELECT block_header FROM blocks WHERE block_hash = :block_hash")?;
        let raw_blocks_iter = stmt
            .query_map(&[(":block_hash", &block_hash.0.encode_hex())], |row| {
                row.get::<_, String>(0)
            })?;

        Ok(raw_blocks_iter
            .flatten()
            .flat_map(|raw_blocks| serde_json::from_str(&raw_blocks))
            .collect::<Vec<_>>()
            .get(0)
            .cloned())
    }

    #[allow(dead_code)]
    pub fn select_block_by_block_number(&self, block_number: u64) -> Result<Option<BlockHeader>> {
        let conn = self.conn.lock().expect("acquire mutex");
        let mut stmt =
            conn.prepare("SELECT block_header FROM blocks WHERE block_height = :block_height")?;
        let raw_blocks_iter = stmt.query_map(&[(":block_height", &block_number)], |row| {
            row.get::<_, String>(0)
        })?;

        Ok(raw_blocks_iter
            .flatten()
            .flat_map(|raw_blocks| serde_json::from_str(&raw_blocks))
            .collect::<Vec<_>>()
            .get(0)
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use proptest::{prelude::any, prop_assert_eq, proptest, strategy::Strategy};
    use tempdir::TempDir;
    use types::{BlockHeader, Bloom, H160, H256, U256};

    use super::DB;

    fn db() -> (TempDir, DB) {
        let dir = TempDir::new("tmp").unwrap();
        let path = dir.path().to_owned();
        (dir, DB::new(&path).unwrap())
    }

    fn h256_strat() -> impl Strategy<Value = H256> {
        any::<[u8; 32]>().prop_map(H256)
    }

    fn h256_option_strat() -> impl Strategy<Value = Option<H256>> {
        any::<Option<[u8; 32]>>().prop_map(|e| e.map(H256))
    }

    fn h160_strat() -> impl Strategy<Value = H160> {
        any::<[u8; 20]>().prop_map(H160)
    }

    fn u256_strat() -> impl Strategy<Value = U256> {
        any::<[u8; 32]>().prop_map(U256)
    }

    fn bloom_strat() -> impl Strategy<Value = Bloom> {
        any::<[u8; 256]>().prop_map(Bloom::new)
    }

    fn u64_sqlite_strat() -> impl Strategy<Value = u64> {
        any::<u64>().prop_filter("Sqlite has only i64", |e| *e < i64::MAX as u64)
    }

    // TODO: Unfortunately, proptest doesn't work with long tuples, so I had to split it into two.
    // Think more for a better solution.
    #[allow(clippy::type_complexity)]
    pub fn block_header_new(
        (
            (
                parent_hash,
                ommers_hash,
                beneficiary,
                state_root,
                transactions_root,
                receipts_root,
                withdrawals_root,
                logs_bloom,
                difficulty,
            ),
            (
                number,
                gas_limit,
                gas_used,
                timestamp,
                mix_hash,
                nonce,
                base_fee_per_gas,
                blob_gas_used,
                excess_blob_gas,
                extra_data,
            ),
        ): (
            (
                H256,
                H256,
                H160,
                H256,
                H256,
                H256,
                Option<H256>,
                Bloom,
                U256,
            ),
            (
                u64,
                u64,
                u64,
                u64,
                H256,
                u64,
                Option<u64>,
                Option<u64>,
                Option<u64>,
                Vec<u8>,
            ),
        ),
    ) -> BlockHeader {
        BlockHeader {
            parent_hash,
            ommers_hash,
            beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root,
            logs_bloom,
            difficulty,
            number,
            gas_limit,
            gas_used,
            timestamp,
            mix_hash,
            nonce,
            base_fee_per_gas,
            blob_gas_used,
            excess_blob_gas,
            extra_data,
        }
    }

    // TODO: replace after adding reth_storage_codecs integration.
    fn block_header_strat() -> impl Strategy<Value = BlockHeader> {
        (
            (
                h256_strat(),
                h256_strat(),
                h160_strat(),
                h256_strat(),
                h256_strat(),
                h256_strat(),
                h256_option_strat(),
                bloom_strat(),
                u256_strat(),
            ),
            (
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
                h256_strat(),
                any::<u64>(),
                any::<Option<u64>>(),
                any::<Option<u64>>(),
                any::<Option<u64>>(),
                any::<Vec<u8>>(),
            ),
        )
            .prop_map(block_header_new)
    }

    #[test]
    fn create_tables() {
        let (dir, db) = db();
        db.create_tables().unwrap();
        dir.close().unwrap();
    }

    proptest! {
        #[test]
        fn insert(
            block_number in u64_sqlite_strat(),
            block_hash in h256_strat(),
            block_header in block_header_strat(),
            bloom_positive: bool,
        ) {
            let (dir, db) = db();
            db.create_tables().unwrap();
            db.insert_block(block_number, block_hash, block_header, bloom_positive)
                .unwrap();
            dir.close().unwrap();
        }

        #[test]
        fn insert_and_get(
            block_number in u64_sqlite_strat(),
            block_hash in h256_strat(),
            block_header in block_header_strat(),
            bloom_positive: bool,
        ) {
            let (tmp, db) = db();
            db.create_tables().unwrap();
            db.insert_block(block_number, block_hash.clone(), block_header.clone(), bloom_positive)
                .unwrap();
            let block = db.select_block_by_block_hash(block_hash).unwrap().unwrap();
            prop_assert_eq!(&block, &block_header);
            let block = db.select_block_by_block_number(block_number).unwrap().unwrap();
            prop_assert_eq!(block, block_header);

            tmp.close().unwrap();
        }
    }
}
