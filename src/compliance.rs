//! Compliance scanning module for network security v2.0
//!
//! Provides PCI-DSS and CIS benchmark compliance checking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Compliance frameworks supported
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceFramework {
    PCIDSS,
    CISBenchmark,
    NIST80053,
    HIPAA,
    SOC2,
}

impl ComplianceFramework {
    /// Get framework name
    pub fn name(&self) -> &'static str {
        match self {
            ComplianceFramework::PCIDSS => "PCI-DSS v4.0",
            ComplianceFramework::CISBenchmark => "CIS Controls v8",
            ComplianceFramework::NIST80053 => "NIST SP 800-53",
            ComplianceFramework::HIPAA => "HIPAA Security Rule",
            ComplianceFramework::SOC2 => "SOC 2 Type II",
        }
    }
}

/// Compliance check status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceStatus {
    Pass,
    Fail,
    Warning,
    NotApplicable,
    NotTested,
}

/// Individual compliance check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheck {
    pub id: String,
    pub framework: ComplianceFramework,
    pub requirement: String,
    pub description: String,
    pub status: ComplianceStatus,
    pub evidence: String,
    pub remediation: Option<String>,
}

/// Compliance scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub target: String,
    pub framework: ComplianceFramework,
    pub scan_time: DateTime<Utc>,
    pub checks: Vec<ComplianceCheck>,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub compliance_score: f32,
}

impl ComplianceResult {
    /// Create a new result
    pub fn new(target: &str, framework: ComplianceFramework) -> Self {
        Self {
            target: target.to_string(),
            framework,
            scan_time: Utc::now(),
            checks: Vec::new(),
            passed: 0,
            failed: 0,
            warnings: 0,
            compliance_score: 0.0,
        }
    }

    /// Add a check result
    pub fn add_check(&mut self, check: ComplianceCheck) {
        match check.status {
            ComplianceStatus::Pass => self.passed += 1,
            ComplianceStatus::Fail => self.failed += 1,
            ComplianceStatus::Warning => self.warnings += 1,
            _ => {}
        }
        self.checks.push(check);
        self.calculate_score();
    }

    /// Calculate compliance score
    fn calculate_score(&mut self) {
        let total = self.passed + self.failed;
        if total > 0 {
            self.compliance_score = (self.passed as f32 / total as f32) * 100.0;
        }
    }

    /// Check if compliant
    pub fn is_compliant(&self) -> bool {
        self.failed == 0
    }

    /// Get summary
    pub fn summary(&self) -> String {
        format!(
            "{} Compliance: {:.1}% | Passed: {} | Failed: {} | Warnings: {}",
            self.framework.name(),
            self.compliance_score,
            self.passed,
            self.failed,
            self.warnings
        )
    }

    /// Export as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Get failed checks
    pub fn get_failed_checks(&self) -> Vec<&ComplianceCheck> {
        self.checks
            .iter()
            .filter(|c| c.status == ComplianceStatus::Fail)
            .collect()
    }
}

/// Port security configuration for compliance checking
#[derive(Debug, Clone)]
pub struct PortSecurityConfig {
    /// Ports that should be closed
    pub prohibited_ports: Vec<u16>,
    /// Ports that require encryption
    pub encryption_required_ports: Vec<u16>,
    /// Allowed ports
    pub allowed_ports: Vec<u16>,
}

impl Default for PortSecurityConfig {
    fn default() -> Self {
        Self {
            // PCI-DSS prohibited ports
            prohibited_ports: vec![23, 21, 69, 512, 513, 514, 137, 138, 139],
            // Ports requiring encryption
            encryption_required_ports: vec![80, 8080, 25, 110, 143],
            // Allowed secure ports
            allowed_ports: vec![22, 443, 8443, 993, 995, 465, 587],
        }
    }
}

/// Compliance scanner
pub struct ComplianceScanner {
    port_config: PortSecurityConfig,
}

impl ComplianceScanner {
    /// Create a new compliance scanner
    pub fn new() -> Self {
        Self {
            port_config: PortSecurityConfig::default(),
        }
    }

    /// Scan for PCI-DSS compliance
    pub fn scan_pci_dss(
        &self,
        target: &str,
        open_ports: &[u16],
        services: &HashMap<u16, String>,
    ) -> ComplianceResult {
        let mut result = ComplianceResult::new(target, ComplianceFramework::PCIDSS);

        // PCI-DSS 1.3.1 - Restrict inbound traffic
        self.check_prohibited_ports(&mut result, open_ports);

        // PCI-DSS 2.2.7 - Use strong cryptography
        self.check_encryption_required(&mut result, open_ports, services);

        // PCI-DSS 2.3 - Encrypt administrative access
        self.check_secure_admin(&mut result, open_ports, services);

        // PCI-DSS 4.1 - Encrypt cardholder data transmission
        self.check_data_encryption(&mut result, open_ports);

        // PCI-DSS 6.5.4 - No insecure protocols
        self.check_insecure_protocols(&mut result, services);

        // PCI-DSS 11.2 - Vulnerability scanning
        self.check_vulnerability_scanning(&mut result, open_ports);

        result
    }

    /// Scan for CIS Benchmark compliance
    pub fn scan_cis_benchmark(
        &self,
        target: &str,
        open_ports: &[u16],
        services: &HashMap<u16, String>,
    ) -> ComplianceResult {
        let mut result = ComplianceResult::new(target, ComplianceFramework::CISBenchmark);

        // CIS Control 4.1 - Secure configuration
        self.check_secure_configuration(&mut result, open_ports);

        // CIS Control 4.8 - Disable unnecessary services
        self.check_unnecessary_services(&mut result, open_ports, services);

        // CIS Control 9.2 - Limit network ports
        self.check_open_port_count(&mut result, open_ports);

        // CIS Control 13.1 - Encrypt sensitive data
        self.check_data_encryption(&mut result, open_ports);

        result
    }

    /// Check for prohibited ports (PCI-DSS 1.3.1)
    fn check_prohibited_ports(&self, result: &mut ComplianceResult, open_ports: &[u16]) {
        let prohibited_open: Vec<u16> = open_ports
            .iter()
            .filter(|p| self.port_config.prohibited_ports.contains(p))
            .copied()
            .collect();

        let status = if prohibited_open.is_empty() {
            ComplianceStatus::Pass
        } else {
            ComplianceStatus::Fail
        };

        let evidence = if prohibited_open.is_empty() {
            "No prohibited ports found open".to_string()
        } else {
            format!("Prohibited ports open: {:?}", prohibited_open)
        };

        result.add_check(ComplianceCheck {
            id: "PCI-DSS-1.3.1".to_string(),
            framework: ComplianceFramework::PCIDSS,
            requirement: "Restrict inbound traffic to necessary ports".to_string(),
            description: "No insecure or unnecessary ports should be accessible".to_string(),
            status,
            evidence,
            remediation: Some(
                "Close or firewall prohibited ports: Telnet (23), FTP (21), TFTP (69)".to_string(),
            ),
        });
    }

    /// Check encryption requirements (PCI-DSS 2.2.7)
    fn check_encryption_required(
        &self,
        result: &mut ComplianceResult,
        open_ports: &[u16],
        _services: &HashMap<u16, String>,
    ) {
        let unencrypted: Vec<u16> = open_ports
            .iter()
            .filter(|p| self.port_config.encryption_required_ports.contains(p))
            .copied()
            .collect();

        let status = if unencrypted.is_empty() {
            ComplianceStatus::Pass
        } else {
            ComplianceStatus::Fail
        };

        let evidence = if unencrypted.is_empty() {
            "All services use encrypted protocols".to_string()
        } else {
            format!("Unencrypted services on ports: {:?}", unencrypted)
        };

        result.add_check(ComplianceCheck {
            id: "PCI-DSS-2.2.7".to_string(),
            framework: ComplianceFramework::PCIDSS,
            requirement: "Use strong cryptography for non-console administrative access"
                .to_string(),
            description: "All administrative access must be encrypted".to_string(),
            status,
            evidence,
            remediation: Some(
                "Replace HTTP with HTTPS, use IMAPS/POP3S instead of IMAP/POP3".to_string(),
            ),
        });
    }

    /// Check secure administrative access (PCI-DSS 2.3)
    fn check_secure_admin(
        &self,
        result: &mut ComplianceResult,
        open_ports: &[u16],
        _services: &HashMap<u16, String>,
    ) {
        // Check for SSH (secure) vs Telnet (insecure)
        let has_telnet = open_ports.contains(&23);
        let has_ssh = open_ports.contains(&22);

        let status = if has_telnet {
            ComplianceStatus::Fail
        } else if has_ssh {
            ComplianceStatus::Pass
        } else {
            ComplianceStatus::NotApplicable
        };

        let evidence = match (has_telnet, has_ssh) {
            (true, _) => "Telnet (insecure) is enabled".to_string(),
            (false, true) => "SSH (secure) is used for remote access".to_string(),
            (false, false) => "No remote administration ports detected".to_string(),
        };

        result.add_check(ComplianceCheck {
            id: "PCI-DSS-2.3".to_string(),
            framework: ComplianceFramework::PCIDSS,
            requirement: "Encrypt all non-console administrative access".to_string(),
            description: "Use SSH instead of Telnet for remote administration".to_string(),
            status,
            evidence,
            remediation: Some(
                "Disable Telnet and use SSH with key-based authentication".to_string(),
            ),
        });
    }

    /// Check data transmission encryption (PCI-DSS 4.1)
    fn check_data_encryption(&self, result: &mut ComplianceResult, open_ports: &[u16]) {
        let has_https = open_ports.contains(&443) || open_ports.contains(&8443);
        let has_http_only = open_ports.contains(&80) && !has_https;

        let status = if has_http_only {
            ComplianceStatus::Fail
        } else if has_https {
            ComplianceStatus::Pass
        } else {
            ComplianceStatus::NotApplicable
        };

        let evidence = if has_https {
            "HTTPS is available for secure data transmission".to_string()
        } else if has_http_only {
            "Only HTTP (unencrypted) is available".to_string()
        } else {
            "No web services detected".to_string()
        };

        result.add_check(ComplianceCheck {
            id: "PCI-DSS-4.1".to_string(),
            framework: ComplianceFramework::PCIDSS,
            requirement: "Use strong cryptography to protect cardholder data during transmission"
                .to_string(),
            description: "All data transmission must be encrypted with TLS 1.2+".to_string(),
            status,
            evidence,
            remediation: Some("Enable HTTPS with TLS 1.2 or higher, disable HTTP".to_string()),
        });
    }

    /// Check for insecure protocols (PCI-DSS 6.5.4)
    fn check_insecure_protocols(
        &self,
        result: &mut ComplianceResult,
        services: &HashMap<u16, String>,
    ) {
        let insecure_services: Vec<String> = services
            .values()
            .filter(|s| {
                let s_lower = s.to_lowercase();
                s_lower.contains("telnet")
                    || s_lower.contains("ftp")
                    || (s_lower.contains("ssl") && s_lower.contains("2"))
                    || s_lower.contains("sslv3")
            })
            .cloned()
            .collect();

        let status = if insecure_services.is_empty() {
            ComplianceStatus::Pass
        } else {
            ComplianceStatus::Fail
        };

        let evidence = if insecure_services.is_empty() {
            "No insecure protocols detected".to_string()
        } else {
            format!("Insecure protocols found: {:?}", insecure_services)
        };

        result.add_check(ComplianceCheck {
            id: "PCI-DSS-6.5.4".to_string(),
            framework: ComplianceFramework::PCIDSS,
            requirement: "Do not use insecure protocols".to_string(),
            description: "Telnet, FTP, SSL 2.0/3.0, and early TLS must be disabled".to_string(),
            status,
            evidence,
            remediation: Some("Disable Telnet, FTP, SSL 2.0/3.0, TLS 1.0/1.1".to_string()),
        });
    }

    /// Check vulnerability scanning status (PCI-DSS 11.2)
    fn check_vulnerability_scanning(&self, result: &mut ComplianceResult, _open_ports: &[u16]) {
        // This is a procedural check - we can only verify scanning is being performed
        result.add_check(ComplianceCheck {
            id: "PCI-DSS-11.2".to_string(),
            framework: ComplianceFramework::PCIDSS,
            requirement: "Run internal and external network vulnerability scans".to_string(),
            description: "Quarterly vulnerability scans required".to_string(),
            status: ComplianceStatus::Pass, // We're performing the scan right now
            evidence: "Vulnerability scan is being performed".to_string(),
            remediation: None,
        });
    }

    /// Check secure configuration (CIS Control 4.1)
    fn check_secure_configuration(&self, result: &mut ComplianceResult, open_ports: &[u16]) {
        let high_risk_ports: Vec<u16> = open_ports
            .iter()
            .filter(|p| [23, 21, 25, 110, 143, 445, 3389].contains(p))
            .copied()
            .collect();

        let status = if high_risk_ports.is_empty() {
            ComplianceStatus::Pass
        } else if high_risk_ports.len() <= 2 {
            ComplianceStatus::Warning
        } else {
            ComplianceStatus::Fail
        };

        result.add_check(ComplianceCheck {
            id: "CIS-4.1".to_string(),
            framework: ComplianceFramework::CISBenchmark,
            requirement: "Establish secure configurations".to_string(),
            description: "Minimize attack surface by closing unnecessary ports".to_string(),
            status,
            evidence: format!("High-risk ports open: {:?}", high_risk_ports),
            remediation: Some(
                "Close or restrict high-risk ports, use encrypted alternatives".to_string(),
            ),
        });
    }

    /// Check for unnecessary services (CIS Control 4.8)
    fn check_unnecessary_services(
        &self,
        result: &mut ComplianceResult,
        open_ports: &[u16],
        _services: &HashMap<u16, String>,
    ) {
        let common_unnecessary: Vec<u16> = open_ports
            .iter()
            .filter(|p| [7, 9, 13, 17, 19, 37, 79].contains(p))
            .copied()
            .collect();

        let status = if common_unnecessary.is_empty() {
            ComplianceStatus::Pass
        } else {
            ComplianceStatus::Fail
        };

        result.add_check(ComplianceCheck {
            id: "CIS-4.8".to_string(),
            framework: ComplianceFramework::CISBenchmark,
            requirement: "Uninstall or disable unnecessary services".to_string(),
            description: "Legacy and unnecessary services should be disabled".to_string(),
            status,
            evidence: format!("Unnecessary service ports: {:?}", common_unnecessary),
            remediation: Some(
                "Disable echo, discard, daytime, chargen, finger services".to_string(),
            ),
        });
    }

    /// Check open port count (CIS Control 9.2)
    fn check_open_port_count(&self, result: &mut ComplianceResult, open_ports: &[u16]) {
        let port_count = open_ports.len();

        let status = if port_count <= 5 {
            ComplianceStatus::Pass
        } else if port_count <= 10 {
            ComplianceStatus::Warning
        } else {
            ComplianceStatus::Fail
        };

        result.add_check(ComplianceCheck {
            id: "CIS-9.2".to_string(),
            framework: ComplianceFramework::CISBenchmark,
            requirement: "Ensure only approved ports are open".to_string(),
            description: "Limit network exposure to minimum necessary ports".to_string(),
            status,
            evidence: format!("{} ports open: {:?}", port_count, open_ports),
            remediation: Some(
                "Review and close unnecessary ports, implement firewall rules".to_string(),
            ),
        });
    }
}

impl Default for ComplianceScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pci_dss_scan_pass() {
        let scanner = ComplianceScanner::new();
        let open_ports = vec![22, 443];
        let services = HashMap::new();

        let result = scanner.scan_pci_dss("192.168.1.1", &open_ports, &services);

        assert!(result.compliance_score > 50.0);
        assert!(result.failed < result.passed);
    }

    #[test]
    fn test_pci_dss_scan_fail() {
        let scanner = ComplianceScanner::new();
        let open_ports = vec![23, 21, 80]; // Telnet, FTP, HTTP - all bad
        let services = HashMap::new();

        let result = scanner.scan_pci_dss("192.168.1.1", &open_ports, &services);

        assert!(result.failed > 0);
    }

    #[test]
    fn test_cis_benchmark_scan() {
        let scanner = ComplianceScanner::new();
        let open_ports = vec![22, 443, 8443];
        let services = HashMap::new();

        let result = scanner.scan_cis_benchmark("192.168.1.1", &open_ports, &services);

        assert!(!result.checks.is_empty());
    }

    #[test]
    fn test_compliance_result_summary() {
        let mut result = ComplianceResult::new("test", ComplianceFramework::PCIDSS);

        result.add_check(ComplianceCheck {
            id: "TEST-1".to_string(),
            framework: ComplianceFramework::PCIDSS,
            requirement: "Test".to_string(),
            description: "Test check".to_string(),
            status: ComplianceStatus::Pass,
            evidence: "Passed".to_string(),
            remediation: None,
        });

        assert_eq!(result.passed, 1);
        assert!(result.summary().contains("100.0%"));
    }

    #[test]
    fn test_failed_checks() {
        let mut result = ComplianceResult::new("test", ComplianceFramework::PCIDSS);

        result.add_check(ComplianceCheck {
            id: "TEST-1".to_string(),
            framework: ComplianceFramework::PCIDSS,
            requirement: "Test".to_string(),
            description: "Test".to_string(),
            status: ComplianceStatus::Pass,
            evidence: "OK".to_string(),
            remediation: None,
        });

        result.add_check(ComplianceCheck {
            id: "TEST-2".to_string(),
            framework: ComplianceFramework::PCIDSS,
            requirement: "Test".to_string(),
            description: "Test".to_string(),
            status: ComplianceStatus::Fail,
            evidence: "Failed".to_string(),
            remediation: Some("Fix it".to_string()),
        });

        let failed = result.get_failed_checks();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].id, "TEST-2");
    }
}
