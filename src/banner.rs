use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub async fn grab_banner(ip: std::net::IpAddr, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = std::net::SocketAddr::new(ip, port);
    let dur = Duration::from_millis(timeout_ms);

    if let Ok(Ok(mut stream)) = timeout(dur, TcpStream::connect(addr)).await {
        let mut buffer = [0; 1024];
        
        match port {
            80 | 8080 => {
                let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
            }
            _ => {}
        }

        if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buffer)).await {
            if n > 0 {
                return Some(String::from_utf8_lossy(&buffer[..n]).trim().to_string());
            }
        }
    }
    None
}