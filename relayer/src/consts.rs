use std::time::Duration;

pub const BLOCK_AMOUNT_TO_STORE: u64 = 100;
pub const UPDATE_WATCHED_ADDRESSES_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub const SLEEP_DURATION: Duration = Duration::from_secs(60);
