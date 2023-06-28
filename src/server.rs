use ethers::abi::AbiEncode;
use eyre::Result;
use salvo::prelude::*;

use crate::config::Config;
use crate::db::DB;
use crate::merkle;

#[handler]
async fn hello() -> &'static str {
    "Hello World"
}

#[handler]
async fn root(dep: &mut Depot) -> String {
    let db = dep.obtain::<DB>().expect("get DB");
    let logs = db.select_logs().expect("get logs");
    let hashes = logs.iter().flat_map(|log| log.transaction_hash).collect::<Vec<_>>();
    merkle::root(&hashes).encode_hex()
}


pub async fn start_server(config: Config, db: DB) -> Result<()> {
    let host_and_port = format!("127.0.0.1:{}", config.server_port.unwrap_or(5800));
    log::info!("server is going to listen {}", host_and_port);

    let router = Router::with_path("/api/v1").hoop(affix::inject(db)).get(hello).get(root);
    let acceptor = TcpListener::new(host_and_port).bind().await;
    Server::new(acceptor).serve(router).await;

    Ok(())
}
