use crate::scanner::ScanResult;
use serde::Serialize;
use std::fs::File;
use std::io::Write;

#[derive(Serialize)]
struct ReportData {
    target: String,
    results: Vec<ScanResult>,
}

pub fn save_json(path: &str, target: &str, results: &[ScanResult]) -> anyhow::Result<()> {
    let data = ReportData {
        target: target.to_string(),
        results: results.to_vec(),
    };
    let f = File::create(path)?;
    serde_json::to_writer_pretty(f, &data)?;
    Ok(())
}

pub fn save_csv(path: &str, results: &[ScanResult]) -> anyhow::Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    for res in results {
        wtr.serialize(res)?;
    }
    wtr.flush()?;
    Ok(())
}

pub fn generate_html(path: &str, target: &str, results: &[ScanResult]) -> anyhow::Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "<html><head><style>table {{ border-collapse: collapse; width: 100%; }} th, td {{ border: 1px solid #ddd; padding: 8px; }} tr:nth-child(even){{background-color: #f2f2f2;}}</style></head><body>")?;
    writeln!(f, "<h1>Scan Report for {}</h1>", target)?;
    writeln!(f, "<table><tr><th>Port</th><th>Status</th><th>Service</th><th>Banner</th></tr>")?;
    for res in results {
        writeln!(f, "<tr><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td></tr>", 
            res.port, res.status, res.service, res.banner.as_deref().unwrap_or(""))?;
    }
    writeln!(f, "</table></body></html>")?;
    Ok(())
}

pub fn save_xml(path: &str, target: &str, results: &[ScanResult]) -> anyhow::Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(f, "<nmaprun>")?;
    writeln!(f, "  <host><address addr=\"{}\" addrtype=\"ipv4\"/>", target)?;
    writeln!(f, "    <ports>")?;
    for res in results {
        writeln!(f, "      <port protocol=\"tcp\" portid=\"{}\">", res.port)?;
        writeln!(f, "        <state state=\"open\"/>")?;
        writeln!(f, "        <service name=\"{}\"/>", res.service)?;
        writeln!(f, "      </port>")?;
    }
    writeln!(f, "    </ports>")?;
    writeln!(f, "  </host>")?;
    writeln!(f, "</nmaprun>")?;
    Ok(())
}