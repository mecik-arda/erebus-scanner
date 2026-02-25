use std::collections::HashMap;

pub fn check_vulnerabilities(banner: &str) -> Vec<String> {
    let mut vulns = Vec::new();
    let banner_lower = banner.to_lowercase();

    let mut database = HashMap::new();
    database.insert("vsftpd 2.3.4", "CVE-2011-2523 - Backdoor Command Execution");
    database.insert("apache 2.4.49", "CVE-2021-41773 - Path Traversal & RCE");
    database.insert("openssh 7.2p2", "CVE-2016-6210 - User Enumeration");
    database.insert("proftpd 1.3.5", "CVE-2015-3306 - Mod_Copy Command Execution");
    database.insert("smb 1.0", "CVE-2017-0144 - EternalBlue");

    for (version, cve) in database.iter() {
        if banner_lower.contains(version) {
            vulns.push(cve.to_string());
        }
    }

    vulns
}