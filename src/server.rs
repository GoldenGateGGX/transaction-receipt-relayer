use eyre::Result;
use salvo::prelude::*;

use crate::config::Config;

#[handler]
async fn hello() -> &'static str {
    "Hello World"
}

pub async fn start_server(config: Config) -> Result<()> {
    let host_and_port = format!("127.0.0.1:{}", config.server_port.unwrap_or(5800));
    log::info!("server is going to listen {}", host_and_port);

    let router = Router::new().get(hello);
    let acceptor = TcpListener::new(host_and_port).bind().await;
    Server::new(acceptor).serve(router).await;

    Ok(())
}
