use eyre::Result;
use rusqlite::Connection;

use crate::config::Config;

pub fn new_connection(config: &Config) -> Result<Connection> {
    let conn = if let Some(path) = config.db_path.clone() {
        Connection::open(path)?
    } else {
        Connection::open_in_memory()?
    };

    Ok(conn)
}

pub fn create_table(conn: &Connection) -> Result<usize> {
    Ok(conn.execute("CREATE TABLE IF NOT EXISTS logs (log TEXT)", ())?)
}

pub fn insert_logs(conn: &Connection, log: &str) -> Result<usize> {
    Ok(conn.execute("INSERT INTO logs(log) values (?1)", (log,))?)
}