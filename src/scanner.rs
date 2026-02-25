use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use crate::parser::ScanType;
use rand::seq::SliceRandom;
use serde::Serialize;
use crate::proxy;

#[derive(Debug, Clone, Serialize)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub port: u16,
    pub status: PortStatus,
    pub service: String,
    pub banner: Option<String>,
    pub vulns: Vec<String>,
}

pub async fn scan_port(
    ip: IpAddr,
    port: u16,
    scan_type: ScanType,
    timeout_ms: u64,
    semaphore: Arc<Semaphore>,
    proxy_addr: Option<String>,
) -> (ScanResult, Duration) {
    let _permit = semaphore.acquire().await.unwrap();
    let addr = SocketAddr::new(ip, port);
    let timeout_dur = Duration::from_millis(timeout_ms);
    let start_time = std::time::Instant::now();

    let res = match scan_type {
        ScanType::TcpFull => {
            let connection_future = async {
                if let Some(ref p) = proxy_addr {
                    proxy::connect_via_proxy(p, addr).await
                } else {
                    TcpStream::connect(addr).await.map_err(|e| anyhow::anyhow!(e))
                }
            };

            match timeout(timeout_dur, connection_future).await {
                Ok(Ok(_)) => ScanResult {
                    port,
                    status: PortStatus::Open,
                    service: get_service_name(port),
                    banner: None,
                    vulns: Vec::new(),
                },
                Ok(Err(_)) => ScanResult {
                    port,
                    status: PortStatus::Closed,
                    service: get_service_name(port),
                    banner: None,
                    vulns: Vec::new(),
                },
                Err(_) => ScanResult {
                    port,
                    status: PortStatus::Filtered,
                    service: get_service_name(port),
                    banner: None,
                    vulns: Vec::new(),
                },
            }
        },
        ScanType::Udp => {
            let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
            socket.set_read_timeout(Some(timeout_dur)).ok();
            let _ = socket.send_to(&[0; 0], addr);
            let mut buf = [0; 1];
            match socket.recv_from(&mut buf) {
                Ok(_) => ScanResult {
                    port,
                    status: PortStatus::Open,
                    service: get_service_name(port),
                    banner: None,
                    vulns: Vec::new(),
                },
                Err(_) => ScanResult {
                    port,
                    status: PortStatus::Filtered,
                    service: get_service_name(port),
                    banner: None,
                    vulns: Vec::new(),
                },
            }
        },
        ScanType::TcpSyn => {
            unimplemented!("SYN scan requires raw socket privileges")
        }
    };

    (res, start_time.elapsed())
}

pub fn randomize_ports(ports: &mut Vec<u16>) {
    let mut rng = rand::thread_rng();
    ports.shuffle(&mut rng);
}

pub fn get_service_name(port: u16) -> String {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        _ => "Unknown",
    }
    .to_string()
}

pub fn estimate_os(results: &[ScanResult]) -> String {
    for res in results {
        if let Some(ref b) = res.banner {
            let b_lower = b.to_lowercase();
            if b_lower.contains("ubuntu") || b_lower.contains("debian") { return "Linux (Debian/Ubuntu)".to_string(); }
            if b_lower.contains("microsoft") || b_lower.contains("iis") || b_lower.contains("windows") { return "Windows".to_string(); }
            if b_lower.contains("centos") || b_lower.contains("redhat") { return "Linux (CentOS/RHEL)".to_string(); }
        }
    }
    "Generic OS / Unknown".to_string()
}