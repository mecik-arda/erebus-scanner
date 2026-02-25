use anyhow::Result;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use std::net::SocketAddr;

pub async fn connect_via_proxy(proxy_addr: &str, target_addr: SocketAddr) -> Result<TcpStream> {
    let stream = Socks5Stream::connect(proxy_addr, target_addr).await?;
    Ok(stream.into_inner())
}