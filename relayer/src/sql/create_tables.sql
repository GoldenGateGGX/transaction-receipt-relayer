CREATE TABLE IF NOT EXISTS blocks (
	block_height INTEGER NOT NULL,
	block_hash TEXT NOT NULL,
    block_header TEXT NOT NULL,
	PRIMARY KEY (block_height, block_hash)
);

CREATE INDEX IF NOT EXISTS blocks_block_hash_idx ON blocks (block_hash);

CREATE TABLE IF NOT EXISTS latest_block (
    block_type INTEGER NOT NULL,
	block_height INTEGER NOT NULL,
    block_hash TEXT NOT NULL,
    PRIMARY KEY (block_type)
);

CREATE TABLE IF NOT EXISTS blocks_to_process (
	block_height INTEGER NOT NULL,
    is_processed BOOLEAN NOT NULL DEFAULT 0
);