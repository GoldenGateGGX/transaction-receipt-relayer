FROM rustlang/rust:nightly as builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update --yes && \
    apt-get install --yes --no-install-recommends \
    libsqlite3-dev

WORKDIR /usr/src/app

COPY . .

RUN cargo build --locked --release -p eth-transaction-receipt-relayer --config net.git-fetch-with-cli=true


FROM debian:11 as production

ENV HOME /usr/src/app
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR $HOME   

RUN apt-get update --yes && \
    apt-get install --yes --no-install-recommends \
    curl jq openssl ca-certificates libsqlite3-dev

COPY --from=builder $HOME/target/release/eth-transaction-receipt-relayer ./target/release/eth-transaction-receipt-relayer
COPY helios.toml ggxchain-config.* run_relayer.sh ./

ENTRYPOINT [ "/usr/src/app/run_relayer.sh"]
