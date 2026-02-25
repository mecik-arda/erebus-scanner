use clap::{Parser, ValueEnum};

#[derive(Clone, Debug, ValueEnum, Default)]
pub enum ScanType {
    #[default]
    TcpFull,
    TcpSyn,
    Udp,
}

#[derive(Parser, Debug)]
#[command(
    author = "Arda Meçik",
    version = "1.0",
    about = "Erebus Scanner - Advanced Async Network Security Tool",
    disable_help_flag = true // Varsayılan yardımı kapatıyoruz
)]
pub struct Cli {
    #[arg(short, long)]
    pub target: String,

    #[arg(short, long, default_value = "1-1024")]
    pub ports: String,

    #[arg(short = 'c', long, default_value_t = 1000)]
    pub concurrency: usize,

    #[arg(long, default_value_t = 1000)]
    pub timeout: u64,

    #[arg(short = 's', long, value_enum, default_value_t = ScanType::TcpFull)]
    pub scan_type: ScanType,

    #[arg(short, long)]
    pub banner: bool,

    #[arg(short = 'o', long)]
    pub os_fingerprint: bool,

    #[arg(short, long)]
    pub randomize: bool,

    #[arg(long)]
    pub json: Option<String>,

    #[arg(long)]
    pub csv: Option<String>,

    #[arg(long)]
    pub html: Option<String>,

    #[arg(long)]
    pub xml: Option<String>,

    #[arg(long)]
    pub proxy: Option<String>,

    #[arg(long)]
    pub webhook: Option<String>,

    #[arg(short = 'a', long)]
    pub adaptive: bool,

    #[arg(short, long, action = clap::ArgAction::Help)]
    pub help: bool, // Özel yardım bayrağı
}

pub fn parse_args() -> Cli {
    Cli::parse()
}