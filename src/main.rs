pub mod parser;
pub mod scanner;
pub mod network;
pub mod banner;
pub mod db;
pub mod report;
pub mod adaptive;
pub mod vuln;
pub mod proxy;
pub mod notify;

use anyhow::Result;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use tokio::sync::Semaphore;
use crate::parser::Cli;
use crate::scanner::{scan_port, PortStatus};

fn print_developer_info() {
    println!("{}", "======================================================".bright_blue());
    println!("{}", "                    EREBUS SCANNER                    ".bold().cyan());
    println!("{}", "======================================================".bright_blue());
    println!("{} Arda Meçik", "Developed by:".bold().yellow());
    println!("{} https://github.com/mecik-arda", "GitHub:".bold().yellow());
    println!("{} https://www.linkedin.com/in/arda-mecik/", "LinkedIn:".bold().yellow());
    println!("{}", "======================================================\n".bright_blue());
}

fn print_detailed_help() {
    println!("{}", "======================================================".bright_blue());
    println!("{}", "                EREBUS SCANNER - HELP                 ".bold().cyan());
    println!("{}", "======================================================".bright_blue());
    println!("{} Arda Meçik", "Developed by:".bold().yellow());
    println!("{} https://www.linkedin.com/in/arda-mecik/", "LinkedIn:".bold().yellow());
    println!("{}", "------------------------------------------------------".bright_blue());
    
    println!("\n{}", "COMMANDS & ARGUMENTS:".bold().green());
    println!("  -t, --target <IP/CIDR/HOST>  Target to scan (e.g., 192.168.1.1 or 192.168.1.0/24)");
    println!("  -p, --ports <RANGE>          Port range to scan (default: 1-1024)");
    println!("  -c, --concurrency <NUM>      Max simultaneous connections (default: 1000)");
    println!("  --timeout <MS>               Timeout per port in milliseconds (default: 1000)");
    println!("  -s, --scan-type <TYPE>       Scan method: tcp-full, tcp-syn, udp");
    
    println!("\n{}", "ADVANCED FEATURES:".bold().green());
    println!("  -b, --banner                 Enable Banner Grabbing & CVE Matching (vuln.rs)");
    println!("  -o, --os-fingerprint         Estimate target OS based on banners (scanner.rs)");
    println!("  -r, --randomize              Randomize port order to evade IDS/IPS");
    println!("  -a, --adaptive               Dynamic speed control based on network latency");
    println!("  --proxy <ADDR:PORT>          Route traffic through SOCKS5/Tor proxy");
    println!("  --webhook <URL>              Send scan summary to Discord/Slack");

    println!("\n{}", "REPORTING:".bold().green());
    println!("  --json, --csv, --html, --xml Save results to specified file format");
    println!("  (History is automatically saved to scans/history.db)");

    println!("\n{}", "EXAMPLES:".bold().yellow());
    println!("  erebus -t 127.0.0.1 -p 1-65535 --banner");
    println!("  erebus -t 192.168.1.0/24 -c 2000 --adaptive --html report.html");
    println!("{}", "======================================================\n".bright_blue());
}

async fn run_scanner(cli: Cli) -> Result<()> {
    print_developer_info();

    let targets = network::resolve_targets(&cli.target).await?;
    let ports_base: Vec<u16> = parse_port_range(&cli.ports);
    
    let database = db::Database::new("scans/history.db")?;
    let mut all_results = Vec::new();

    let start_time = std::time::Instant::now();

    for ip in targets {
        let ip_str = ip.to_string();
        println!("\n{} {}", "Target:".bold(), ip_str.cyan());
        
        if !network::ping_host(ip, cli.timeout).await {
            println!("{}", "Host seems down (Ping Sweep failed), but continuing scan...".yellow());
        }

        if let Some(hostname) = network::reverse_dns(ip).await {
            println!("{} {}", "Hostname:".bold(), hostname.magenta());
        }

        let previous_ports = database.get_last_scan_ports(&ip_str).unwrap_or_default();

        let mut current_ports = ports_base.clone();
        if cli.randomize {
            scanner::randomize_ports(&mut current_ports);
        }

        let sem = Arc::new(Semaphore::new(cli.concurrency));
        let pb = ProgressBar::new(current_ports.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?);

        let mut target_results = Vec::new();
        let mut tasks = Vec::new();

        for &port in &current_ports {
            let sem_clone = Arc::clone(&sem);
            let scan_type = cli.scan_type.clone();
            let timeout_val = cli.timeout;
            let banner_flag = cli.banner;
            let proxy_addr = cli.proxy.clone();

            tasks.push(tokio::spawn(async move {
                let (mut res, _latency) = scan_port(ip, port, scan_type, timeout_val, sem_clone, proxy_addr).await;
                if banner_flag && matches!(res.status, PortStatus::Open) {
                    if let Some(b) = banner::grab_banner(ip, port, timeout_val).await {
                        res.vulns = vuln::check_vulnerabilities(&b);
                        res.banner = Some(b);
                    }
                }
                res
            }));
        }

        for task in tasks {
            if let Ok(res) = task.await {
                if matches!(res.status, PortStatus::Open) {
                    println!("{}: {} \t {}", 
                        res.port.to_string().green(), 
                        "OPEN".green().bold(), 
                        res.service.yellow()
                    );

                    for v in &res.vulns {
                        println!("  {} {}", "-> [VULN]".red().bold(), v.bright_red());
                    }
                    
                    if !previous_ports.contains(&res.port) && !previous_ports.is_empty() {
                        println!("  {} {}", "-> [NEW]".bright_green().bold(), "New open port detected since last scan!".white());
                    }

                    let _ = database.save_result(&ip_str, &res);
                    target_results.push(res);
                }
                pb.inc(1);
            }
        }
        
        pb.finish_and_clear();
        target_results.sort_by_key(|r| r.port);
        
        let current_open_ports: Vec<u16> = target_results.iter().map(|r| r.port).collect();
        for old_p in previous_ports {
            if !current_open_ports.contains(&old_p) {
                println!("{}: {} \t {}", 
                    old_p.to_string().red(), 
                    "CLOSED".red().bold(), 
                    "Port was open in previous scan but is now closed".white()
                );
            }
        }

        if cli.os_fingerprint {
            let os = scanner::estimate_os(&target_results);
            println!("{} {}", "Estimated OS:".bold(), os.bright_red());
        }

        all_results.extend(target_results);
    }

    let duration = start_time.elapsed();

    if let Some(ref path) = cli.json { report::save_json(path, &cli.target, &all_results)?; }
    if let Some(ref path) = cli.csv { report::save_csv(path, &all_results)?; }
    if let Some(ref path) = cli.html { report::generate_html(path, &cli.target, &all_results)?; }
    if let Some(ref path) = cli.xml { report::save_xml(path, &cli.target, &all_results)?; }

    let summary = format!("Erebus Scanner Summary\nTarget: {}\nTotal ports scanned: {}\nOpen ports found: {}\nTime elapsed: {:?}", 
        cli.target, ports_base.len(), all_results.len(), duration);

    if let Some(ref webhook) = cli.webhook {
        let _ = notify::send_discord_webhook(webhook, &summary).await;
    }

    println!("\n{}", "--- Scan Summary ---".bold().underline());
    println!("Total ports scanned: {}", ports_base.len());
    println!("Open ports found: {}", all_results.len());
    println!("Time elapsed: {:?}", duration);

    Ok(())
}

fn parse_port_range(range: &str) -> Vec<u16> {
    if let Ok(single) = range.parse::<u16>() {
        return vec![single];
    }
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() == 2 {
        let start = parts[0].parse::<u16>().unwrap_or(1);
        let end = parts[1].parse::<u16>().unwrap_or(1024);
        return (start..=end).collect();
    }
    (1..=1024).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_detailed_help();
        return Ok(());
    }

    let cli = parser::parse_args();
    
    tokio::select! {
        res = run_scanner(cli) => res,
        _ = tokio::signal::ctrl_c() => {
            println!("\n{}", "Shutdown signal received. Exiting gracefully...".red());
            Ok(())
        }
    }
}