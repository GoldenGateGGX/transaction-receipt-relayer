# transaction-receipt-relayer

This repository contains an Ethereum transaction receipt relayer for the GGX network.
The relayer verifies finalized blocks using [Helios light client](https://github.com/a16z/helios).
The relayer requires a Beacon and Consensus RPC node, which updates and blocks will be verified.
It will relay transaction receipts for the smart contracts list managed by the pallet in this repository.

## Install dependencies

```bash
sudo apt install libsqlite3-dev
```

## Run

1. Run 2 [nodes](https://github.com/ggxchain/ggxnode)

```bash
ETH1_INFURA_API_KEY=$(INFURA_API_KEY) ./target/release/ggxchain-node --alice --chain=dev --port=30333 --rpc-port=9944 --base-path=/tmp/alice \
    --rpc-cors=all --node-key=0000000000000000000000000000000000000000000000000000000000000001 \
    --light-client-relay-config-path eth-relay.toml \
    --light-client-init-pallet-config-path eth-init.toml
```

```bash
./target/release/ggxchain-node --bob --chain=dev --port=30334 --rpc-port=9945 --base-path=/tmp/bob \
    --rpc-cors=all --bootnodes=/ip4/127.0.0.1/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp
```

2. Update `INFURA_API_KEY` and `checkpoint` in helios.toml

3. Run `transaction-receipt-relayer`

```bash
RUST_LOG=info cargo run --release -- --network sepolia --database db --helios-config-path helios.toml --substrate-config-path ggxchain-config.toml
```

## How check that it works?

You can see an Ethereum client event in the [explorer](https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944#/explorer) about 1 time per 10 minutes.

![Ethereum client event](/docs/images/ethereum_client_event.png)

## Configs

* GGX config
  | Field | Definition |
  |---|---|
  |is_dev| if set to true the Alice account will be used, and the phrase will be ignored|
  |ws_url| GGX RPC endpoint|
  |phrase| Account for signing transaction.|

* [Helios config](https://github.com/a16z/helios/blob/master/config.md)

Please note that you need to update helios.toml checkpoint from time to time.

## Action points to look

* Check how it works if multiple relayers are working simultaneously.
* Optimize batch sending of receipts.
* Remove blocks older than X
