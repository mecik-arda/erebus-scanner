use anyhow::Result;
use ipnet::Ipv4Net;
use std::net::IpAddr;
use std::str::FromStr;
use hickory_resolver::AsyncResolver;
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::lookup::ReverseLookup;

pub struct TargetHost {
    pub ip: IpAddr,
    pub hostname: Option<String>,
}

pub async fn resolve_targets(input: &str) -> Result<Vec<IpAddr>> {
    if let Ok(net) = Ipv4Net::from_str(input) {
        return Ok(net.hosts().map(IpAddr::V4).collect());
    }

    let resolver = AsyncResolver::tokio_from_system_conf()?;
    let response: LookupIp = resolver.lookup_ip(input).await?;
    
    Ok(response.iter().collect())
}

pub async fn reverse_dns(ip: IpAddr) -> Option<String> {
    let resolver = AsyncResolver::tokio_from_system_conf().ok()?;
    let response: ReverseLookup = resolver.reverse_lookup(ip).await.ok()?;
    response.iter().next().map(|name| name.to_utf8())
}

pub async fn ping_host(ip: IpAddr, timeout: u64) -> bool {
    let timeout_dur = std::time::Duration::from_millis(timeout);
    match tokio::time::timeout(timeout_dur, tokio::net::TcpStream::connect((ip, 80))).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}