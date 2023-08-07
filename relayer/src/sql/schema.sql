CREATE TABLE IF NOT EXISTS blocks (
    block_height INTEGER NOT NULL UNIQUE,
    block_hash TEXT NOT NULL UNIQUE,
    block_header TEXT NOT NULL UNIQUE,
    is_processed BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (block_height)
);

CREATE INDEX IF NOT EXISTS blocks_block_hash_idx ON blocks (block_hash);