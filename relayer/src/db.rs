use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use eyre::Result;
use rusqlite::Connection;
use types::{BlockHeaderWithTransaction, H256};

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
        let block_hash_iter = stmt.query_map([], |row| row.get::<_, [u8; 32]>(0))?;

        Ok(block_hash_iter
            .flatten()
            .flat_map(|hash| Ok::<H256, eyre::Report>(H256(hash)))
            .collect::<Vec<_>>()
            .first()
            .cloned())
    }

    pub fn insert_block(
        &self,
        block_number: u64,
        block_hash: H256,
        block_header: BlockHeaderWithTransaction,
        bloom_positive: bool,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("acquire mutex");
        let is_processed = !bloom_positive; // We need to process only bloom positive blocks
        conn.execute(
            "INSERT INTO blocks(block_height, block_hash, block_header, is_processed) values (?1, ?2, ?3, ?4)",
            (
                block_number,
                block_hash.0,
                serde_json::to_string(&block_header)?,
                is_processed,
            ),
        )?;

        Ok(())
    }

    pub fn select_blocks_to_process(
        &self,
        max_block: u64,
    ) -> Result<Vec<(u64, H256, BlockHeaderWithTransaction)>> {
        let conn = self.conn.lock().expect("acquire mutex");
        let mut stmt =
            conn.prepare("SELECT block_height, block_hash, block_Header FROM blocks WHERE is_processed = 0 AND block_height < ?1 ORDER BY block_height")?;
        let blocks_iter = stmt.query_map([(max_block)], |row| {
            let block_height = row.get::<_, u64>(0)?;
            let block_hash = row.get::<_, [u8; 32]>(1)?;
            let block_header = row.get::<_, String>(2)?;
            let block_header = serde_json::from_str(&block_header).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Ok((block_height, H256(block_hash), block_header))
        })?;

        Ok(blocks_iter.flatten().collect::<Vec<_>>())
    }

    pub fn mark_block_processed(&self, block_number: u64) -> Result<()> {
        let conn = self.conn.lock().expect("acquire mutex");
        conn.execute(
            "UPDATE blocks SET is_processed = 1 WHERE block_height = ?1",
            (block_number,),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::{prelude::any, proptest, strategy::Strategy};
    use tempfile::{tempdir, TempDir};
    use types::{BlockHeader, BlockHeaderWithTransaction, Bloom, H160, H256, U256};

    use super::DB;

    fn db() -> (TempDir, DB) {
        let dir = tempdir().unwrap();
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

    fn block_header_with_transaction_strat() -> impl Strategy<Value = BlockHeaderWithTransaction> {
        (block_header_strat(), any::<Vec<[u8; 32]>>()).prop_map(|(header, transaction)| {
            BlockHeaderWithTransaction {
                header,
                transactions: transaction.into_iter().map(H256).collect(),
            }
        })
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
            block_header in block_header_with_transaction_strat(),
            bloom_positive: bool,
        ) {
            let (dir, db) = db();
            db.create_tables().unwrap();
            db.insert_block(block_number, block_hash, block_header, bloom_positive)
                .unwrap();
            dir.close().unwrap();
        }

        #[test]
        fn insert_non_positive_fetch_and_then_mark(
            block_number in u64_sqlite_strat(),
            block_hash in h256_strat(),
            block_header in block_header_with_transaction_strat(),
        ) {
            let (dir, db) = db();
            db.create_tables().unwrap();
            db.insert_block(block_number, block_hash, block_header.clone(), true)
                .unwrap();
            let blocks = db.select_blocks_to_process(block_number + 1).unwrap();
            assert_eq!(blocks.len(), 1);
            let (block_numb, hash, block) = blocks[0].clone();
            assert_eq!(block_numb, block_number);
            assert_eq!(hash, block_hash);
            assert_eq!(block, block_header);

            // Check if specify less max block we receive nothing
            let blocks = db.select_blocks_to_process(block_number - 1).unwrap();
            assert_eq!(blocks.len(), 0);

            // Check that block is not received after processing
            db.mark_block_processed(block_number).unwrap();
            let blocks = db.select_blocks_to_process(block_number + 1).unwrap();
            assert_eq!(blocks.len(), 0);
            dir.close().unwrap();
        }

    }
}
