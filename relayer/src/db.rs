use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use ethers::{abi::AbiDecode, abi::AbiEncode, types::TransactionReceipt};
use eyre::Result;
use rusqlite::Connection;
use types::{BlockHeader, H256};

use crate::config::Config;

#[derive(Clone)]
pub struct DB {
    conn: Arc<Mutex<Connection>>,
}

#[repr(u64)]
pub enum BlockType {
    Finalized = 0_u64,
    Processed = 1_u64,
}

impl DB {
    pub fn new(config: &Config) -> Result<Self> {
        let conn = Connection::open(Path::new(&config.database).join("db.sqlite"))?;

        Ok(DB {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn create_tables(&self) -> Result<()> {
        let conn = self.conn.lock().expect("acquire mutex");
        let sql = include_str!("../sql/create_tables.sql");
        Ok(conn.execute_batch(sql)?)
    }

    pub fn select_latest_block_height(&self, block_type: BlockType) -> Result<Option<u64>> {
        let conn = self.conn.lock().expect("acquire mutex");
        let mut stmt =
            conn.prepare("SELECT block_height FROM latest_block WHERE block_type = (?1)")?;
        let block_height_iter = stmt.query_map([block_type as u64], |row| row.get::<_, u64>(0))?;

        Ok(block_height_iter
            .flatten()
            .collect::<Vec<_>>()
            .first()
            .cloned())
    }

    pub fn select_latest_block_hash(&self, block_type: BlockType) -> Result<Option<H256>> {
        let conn = self.conn.lock().expect("acquire mutex");
        let mut stmt =
            conn.prepare("SELECT block_hash FROM latest_block WHERE block_type = (?1)")?;
        let block_hash_iter = stmt.query_map([block_type as u64], |row| row.get::<_, String>(0))?;

        Ok(block_hash_iter
            .flatten()
            .flat_map(|hash| {
                Ok::<H256, eyre::Report>(H256(ethers::types::H256::decode_hex(hash)?.0))
            })
            .collect::<Vec<_>>()
            .first()
            .cloned())
    }

    pub fn insert_or_update_latest_block_info(
        &self,
        block_type: BlockType,
        block_number: u64,
        block_hash: H256,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("acquire mutex");
        let mut stmt = conn.prepare(
            "INSERT OR REPLACE INTO latest_block(block_type, block_height, block_hash) values (?1, ?2, ?3)",
        )?;
        stmt.execute((block_type as u64, block_number, block_hash.0.encode_hex()))?;
        Ok(())
    }

    pub fn insert_block(
        &self,
        block_number: u64,
        block_hash: H256,
        block_header: BlockHeader,
    ) -> Result<usize> {
        let conn = self.conn.lock().expect("acquire mutex");
        Ok(conn.execute(
            "INSERT INTO blocks(block_height, block_hash, block_header) values (?1, ?2, ?3)",
            (
                block_number,
                block_hash.0.encode_hex(),
                serde_json::to_string(&block_header)?,
            ),
        )?)
    }

    #[allow(dead_code)]
    pub fn insert_receipts(&self, block_hash: H256, receipts: &str) -> Result<usize> {
        let conn = self.conn.lock().expect("acquire mutex");
        Ok(conn.execute(
            "INSERT INTO receipts(block_hash, receipts) values (?1, ?2)",
            (block_hash.0.encode_hex(), receipts),
        )?)
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

    pub fn select_receipts_by_block_hash(
        &self,
        block_hash: H256,
    ) -> Result<Vec<TransactionReceipt>> {
        let conn = self.conn.lock().expect("acquire mutex");
        let mut stmt =
            conn.prepare("SELECT receipts FROM receipts WHERE block_hash = :block_hash")?;
        let raw_receipts_iter = stmt
            .query_map(&[(":block_hash", &block_hash.0.encode_hex())], |row| {
                row.get::<_, String>(0)
            })?;

        Ok(raw_receipts_iter
            .flatten()
            .flat_map(|raw_receipts| serde_json::from_str(&raw_receipts))
            .collect())
    }
}
