# transaction-receipt-relayer

## Install dependencies

```bash
sudo apt install libsqlite3-dev
```

## Run

```bash
RUST_LOG=info cargo run --release -- --network mainnet --database db --helios-config-path helios.toml --watch-dog-config watch-dog-config.toml --substrate-config-path ggxchain-config.toml
```
