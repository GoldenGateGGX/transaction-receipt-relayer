use eyre::Result;
use rusqlite::Connection;

use crate::config::Config;

pub struct DB {
    conn: Connection
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
        Ok(self.conn.execute("CREATE TABLE IF NOT EXISTS logs (log TEXT)", ())?)
    }

    pub fn insert_logs(&self, log: &str) -> Result<usize> {
        Ok(self.conn.execute("INSERT INTO logs(log) values (?1)", (log,))?)
    }
}
