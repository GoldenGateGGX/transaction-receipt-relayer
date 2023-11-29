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
    libsqlite3-dev curl jq openssl ca-certificates

COPY --from=builder $HOME/target/release/transaction-receipt-relayer ./target/release/transaction-receipt-relayer
COPY --from=builder $HOME/helios.toml $HOME/ggxchain-config.* $HOME/run_relayer.sh ./

ENTRYPOINT [ "/usr/src/app/run_relayer.sh"]
