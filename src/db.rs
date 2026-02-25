use rusqlite::{params, Connection, Result};
use crate::scanner::ScanResult;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let _ = std::fs::create_dir_all("scans");
        let conn = Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                banner TEXT
            )",
            [],
        )?;
        Ok(Database { conn })
    }

    pub fn save_result(&self, ip: &str, res: &ScanResult) -> Result<()> {
        self.conn.execute(
            "INSERT INTO scans (ip, port, status, service, banner) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                ip,
                res.port,
                format!("{:?}", res.status),
                res.service,
                res.banner
            ],
        )?;
        Ok(())
    }

    pub fn get_last_scan_ports(&self, ip: &str) -> Result<Vec<u16>> {
        let mut stmt = self.conn.prepare(
            "SELECT port FROM scans 
             WHERE ip = ?1 AND timestamp < CURRENT_TIMESTAMP 
             ORDER BY timestamp DESC"
        )?;
        let rows = stmt.query_map(params![ip], |row| row.get(0))?;
        let mut ports = Vec::new();
        for port in rows {
            ports.push(port?);
        }
        Ok(ports)
    }
}