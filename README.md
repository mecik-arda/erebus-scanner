# Erebus Scanner

Erebus Scanner is a high-performance, fully asynchronous port scanning and network reconnaissance tool built with Rust and the Tokio runtime. Designed for speed, stealth, and modularity, it provides comprehensive insights into network security targets.

---

## Key Features

* Asynchronous Engine: Leverages tokio for high-concurrency TCP scanning using TcpStream.
* Vulnerability Detection: Built-in banner grabbing and CVE matching engine to identify potential risks.
* Stealth and Evasion: Supports port randomization and SOCKS5/Tor proxying to bypass IDS/IPS systems.
* Adaptive Rate Limiting: Dynamically adjusts scanning speed based on network latency and packet loss.
* Smart Networking: Features CIDR notation support, Reverse DNS lookups, and Ping Sweeps.
* History Tracking: Automatically saves results to an SQLite database (history.db) to detect changes between scans.
* Multi-Format Reporting: Generates reports in JSON, CSV, HTML, and Nmap-compatible XML.
* Real-time Alerts: Integration with Discord Webhooks for instant scan completion notifications.

---

## Installation
### Prerequisites
* [**Rust (Latest stable version)**](https://www.rust-lang.org/tools/install)
* [**Cargo (Rust package manager)**](https://doc.rust-lang.org/cargo/getting-started/installation.html)

### Build
```
git clone https://github.com/mecik-arda/erebus-scanner.git
cd erebus_scanner
cargo build --release
```
Usage

Erebus comes with a detailed built-in help menu. You can access it via:
Bash

./target/release/erebus_scanner -h

Basic Scan

Scan a single target for default ports (1-1024):
Bash

cargo run -- -t 127.0.0.1

Advanced Reconnaissance

Scan a full range of ports, grab banners, estimate OS, and generate an HTML report:
Bash

cargo run -- -t 192.168.1.1 -p 1-65535 --banner -o --html scans/reports/target_scan.html

Stealth Scanning

Scan a network range using a Tor proxy and randomized port order:
Bash

cargo run -- -t 10.0.0.0/24 --proxy 127.0.0.1:9050 --randomize --adaptive

Project Structure

    main.rs: Application entry point and workflow orchestration.

    scanner.rs: Core TCP/UDP scanning logic.

    network.rs: IP resolution, CIDR handling, and ping sweep.

    vuln.rs: Service version to CVE matching logic.

    db.rs: SQLite persistence and scan comparison.

    report.rs: Multi-format file generation.

    proxy.rs: SOCKS5/Tor connection tunneling.

Author

Arda Meçik

    GitHub: mecik-arda

    LinkedIn: https://www.linkedin.com/in/arda-mecik/

    Education: 2nd Year Computer Engineering Student at Trakya University.

Disclaimer

This tool is intended for legal security testing and educational purposes only. Unauthorized scanning of networks is illegal. The author is not responsible for any misuse of this software.
