use std::collections::HashMap;
use std::sync::LazyLock;

static VULN_DB: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut db = HashMap::new();
    db.insert("vsftpd 2.3.4", "CVE-2011-2523 - Backdoor Command Execution");
    db.insert("apache 2.4.49", "CVE-2021-41773 - Path Traversal & RCE");
    db.insert("openssh 7.2p2", "CVE-2016-6210 - User Enumeration");
    db.insert("proftpd 1.3.5", "CVE-2015-3306 - Mod_Copy Command Execution");
    db.insert("smb 1.0", "CVE-2017-0144 - EternalBlue");
    db
});

pub fn check_vulnerabilities(banner: &str) -> Vec<String> {
    let mut vulns = Vec::new();
    let banner_lower = banner.to_lowercase();

    for (version, cve) in VULN_DB.iter() {
        if banner_lower.contains(version) {
            vulns.push(cve.to_string());
        }
    }

    vulns
}