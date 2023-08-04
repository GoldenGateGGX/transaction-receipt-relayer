CREATE TABLE IF NOT EXISTS blocks (
    block_height INTEGER NOT NULL UNIQUE,
    block_hash TEXT NOT NULL UNIQUE,
    block_header TEXT NOT NULL UNIQUE,
    PRIMARY KEY (block_height)
);

CREATE INDEX IF NOT EXISTS blocks_block_hash_idx ON blocks (block_hash);

CREATE TABLE IF NOT EXISTS latest_block (
    block_type INTEGER NOT NULL UNIQUE,
    block_height INTEGER NOT NULL UNIQUE,
    block_hash TEXT NOT NULL UNIQUE,
    PRIMARY KEY (block_type)
);

CREATE TABLE IF NOT EXISTS blocks_to_process (
    block_height INTEGER NOT NULL UNIQUE,
    is_processed BOOLEAN NOT NULL DEFAULT 0,
    PRIMARY KEY (block_height)
);