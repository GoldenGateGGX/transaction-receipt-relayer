use eyre::Result;
use rusqlite::Connection;

use crate::config::Config;

pub struct DB {
    conn: Connection,
}

impl DB {
    pub fn new(config: &Config) -> Result<Self> {
        let conn = if let Some(path) = config.db_path.clone() {
            Connection::open(path)?
        } else {
            Connection::open_in_memory()?
        };

        Ok(DB { conn })
    }

    pub fn create_table(&self) -> Result<usize> {
        Ok(self
            .conn
            .execute("CREATE TABLE IF NOT EXISTS logs (block_number INTEGER, log_index INTEGER, log TEXT)", ())?)
    }

    pub fn insert_logs(&self, block_number: u64, log_index: u64, log: &str) -> Result<usize> {
        Ok(self
            .conn
            .execute("INSERT INTO logs(block_number, log_index, log) values (?1, ?2, ?3)", (block_number, log_index, log))?)
    }
}
