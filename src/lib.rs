//! # Rust Network Scanner
//!
//! A memory-safe, asynchronous network security scanner for vulnerability assessment
//! and network monitoring.
//!
//! ## Features
//!
//! - **Memory Safety**: Built with Rust to prevent buffer overflows and memory corruption
//! - **Async/Await**: High-performance concurrent scanning using Tokio
//! - **Port Scanning**: Detect open ports and services
//! - **Service Detection**: Identify running services
//! - **Security Focus**: Designed for financial infrastructure security assessment
//!
//! ## Alignment with Federal Guidance
//!
//! Implements network security tools using memory-safe Rust, aligning with
//! 2024 CISA/FBI guidance for critical infrastructure security tools.

use chrono::{DateTime, Utc};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Scanner errors
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Connection timeout")]
    Timeout,

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Invalid IP address")]
    InvalidIpAddress,

    #[error("Invalid port range")]
    InvalidPortRange,

    #[error("Invalid subnet mask")]
    InvalidSubnetMask,

    #[error("Banner grab failed: {0}")]
    BannerGrabFailed(String),
}

/// Port risk level for security assessment
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortRiskLevel {
    /// Critical risk (telnet, FTP, unencrypted protocols)
    Critical,
    /// High risk (database ports, RDP)
    High,
    /// Medium risk (HTTP, SMTP)
    Medium,
    /// Low risk (HTTPS, SSH with proper config)
    Low,
    /// Unknown risk
    Unknown,
}

/// Port status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

/// Scan result for a single port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub port: u16,
    pub status: PortStatus,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub risk_level: PortRiskLevel,
    pub timestamp: DateTime<Utc>,
    pub response_time_ms: Option<u64>,
}

/// Complete scan result for a target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub scan_start: DateTime<Utc>,
    pub scan_end: DateTime<Utc>,
    pub ports_scanned: usize,
    pub open_ports: Vec<PortScanResult>,
    pub closed_ports: usize,
    pub filtered_ports: usize,
}

impl ScanResult {
    /// Export scan results as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Get summary statistics
    pub fn summary(&self) -> String {
        format!(
            "Target: {} | Scanned: {} ports | Open: {} | Closed: {} | Filtered: {}",
            self.target,
            self.ports_scanned,
            self.open_ports.len(),
            self.closed_ports,
            self.filtered_ports
        )
    }

    /// Get high-risk open ports (Critical and High risk levels)
    pub fn get_high_risk_ports(&self) -> Vec<&PortScanResult> {
        self.open_ports
            .iter()
            .filter(|p| {
                matches!(p.risk_level, PortRiskLevel::Critical | PortRiskLevel::High)
            })
            .collect()
    }

    /// Get ports by risk level
    pub fn get_ports_by_risk(&self, risk: PortRiskLevel) -> Vec<&PortScanResult> {
        self.open_ports
            .iter()
            .filter(|p| p.risk_level == risk)
            .collect()
    }

    /// Calculate scan duration in seconds
    pub fn scan_duration_secs(&self) -> f64 {
        (self.scan_end - self.scan_start).num_milliseconds() as f64 / 1000.0
    }
}

/// Network scanner configuration
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub timeout_ms: u64,
    pub concurrent_scans: usize,
    pub detect_services: bool,
    pub grab_banners: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 1000,
            concurrent_scans: 100,
            detect_services: true,
            grab_banners: false, // Disabled by default for performance
        }
    }
}

/// Network scanner
pub struct NetworkScanner {
    config: ScannerConfig,
}

impl NetworkScanner {
    /// Create a new network scanner with default configuration
    pub fn new() -> Self {
        Self {
            config: ScannerConfig::default(),
        }
    }

    /// Create a new network scanner with custom configuration
    pub fn with_config(config: ScannerConfig) -> Self {
        Self { config }
    }

    /// Scan a single port
    pub async fn scan_port(&self, ip: IpAddr, port: u16) -> PortScanResult {
        let start = std::time::Instant::now();
        let addr = SocketAddr::new(ip, port);

        let mut stream_opt = None;
        let status = match timeout(
            Duration::from_millis(self.config.timeout_ms),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                stream_opt = Some(stream);
                PortStatus::Open
            }
            Ok(Err(_)) => PortStatus::Closed,
            Err(_) => PortStatus::Filtered,
        };

        let response_time = if status == PortStatus::Open {
            Some(start.elapsed().as_millis() as u64)
        } else {
            None
        };

        let service = if status == PortStatus::Open && self.config.detect_services {
            Self::detect_service(port)
        } else {
            None
        };

        let banner = if status == PortStatus::Open && self.config.grab_banners {
            if let Some(mut stream) = stream_opt {
                Self::grab_banner(&mut stream, port).await.ok()
            } else {
                None
            }
        } else {
            None
        };

        let risk_level = Self::assess_port_risk(port);

        PortScanResult {
            port,
            status,
            service,
            banner,
            risk_level,
            timestamp: Utc::now(),
            response_time_ms: response_time,
        }
    }

    /// Scan a range of ports
    pub async fn scan_ports(
        &self,
        ip: IpAddr,
        start_port: u16,
        end_port: u16,
    ) -> Result<ScanResult, ScanError> {
        if start_port > end_port {
            return Err(ScanError::InvalidPortRange);
        }

        let scan_start = Utc::now();
        let target = ip.to_string();

        // Create tasks for all ports
        let mut tasks = Vec::new();
        for port in start_port..=end_port {
            let task = self.scan_port(ip, port);
            tasks.push(task);

            // Limit concurrent scans
            if tasks.len() >= self.config.concurrent_scans {
                let results = join_all(tasks).await;
                tasks = Vec::new();
                // Process results
                for _ in results {
                    // Results processed below
                }
            }
        }

        // Process remaining tasks
        let mut all_results = join_all(tasks).await;

        let scan_end = Utc::now();

        // Separate results by status
        let open_ports: Vec<PortScanResult> = all_results
            .iter()
            .filter(|r| r.status == PortStatus::Open)
            .cloned()
            .collect();

        let closed_ports = all_results
            .iter()
            .filter(|r| r.status == PortStatus::Closed)
            .count();

        let filtered_ports = all_results
            .iter()
            .filter(|r| r.status == PortStatus::Filtered)
            .count();

        Ok(ScanResult {
            target,
            scan_start,
            scan_end,
            ports_scanned: all_results.len(),
            open_ports,
            closed_ports,
            filtered_ports,
        })
    }

    /// Scan common ports (top 20)
    pub async fn scan_common_ports(&self, ip: IpAddr) -> Result<ScanResult, ScanError> {
        let common_ports = vec![
            20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900,
            8080, 8443, 27017,
        ];

        let scan_start = Utc::now();
        let target = ip.to_string();

        let tasks: Vec<_> = common_ports
            .iter()
            .map(|&port| self.scan_port(ip, port))
            .collect();

        let results = join_all(tasks).await;
        let scan_end = Utc::now();

        let open_ports: Vec<PortScanResult> = results
            .iter()
            .filter(|r| r.status == PortStatus::Open)
            .cloned()
            .collect();

        let closed_ports = results
            .iter()
            .filter(|r| r.status == PortStatus::Closed)
            .count();

        let filtered_ports = results
            .iter()
            .filter(|r| r.status == PortStatus::Filtered)
            .count();

        Ok(ScanResult {
            target,
            scan_start,
            scan_end,
            ports_scanned: results.len(),
            open_ports,
            closed_ports,
            filtered_ports,
        })
    }

    /// Simple service detection based on port number
    fn detect_service(port: u16) -> Option<String> {
        let service = match port {
            20 => "FTP-DATA",
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            80 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 => "HTTPS",
            445 => "SMB",
            993 => "IMAPS",
            995 => "POP3S",
            3306 => "MySQL",
            3389 => "RDP",
            5432 => "PostgreSQL",
            5900 => "VNC",
            8080 => "HTTP-Proxy",
            8443 => "HTTPS-Alt",
            27017 => "MongoDB",
            _ => "Unknown",
        };

        Some(service.to_string())
    }

    /// Grab service banner from open port
    async fn grab_banner(stream: &mut TcpStream, port: u16) -> Result<String, ScanError> {
        // Send protocol-specific probes
        let probe = match port {
            80 | 8080 => b"HEAD / HTTP/1.0\r\n\r\n",
            21 | 22 | 23 | 25 => b"", // These typically send banner on connect
            _ => b"", // Default: just read
        };

        if !probe.is_empty() {
            let _ = timeout(
                Duration::from_millis(500),
                stream.write_all(probe),
            )
            .await;
        }

        let mut buffer = vec![0u8; 1024];
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..n])
                    .trim()
                    .to_string();
                if !banner.is_empty() {
                    Ok(banner)
                } else {
                    Err(ScanError::BannerGrabFailed("Empty response".to_string()))
                }
            }
            _ => Err(ScanError::BannerGrabFailed("No response".to_string())),
        }
    }

    /// Assess security risk level of a port
    fn assess_port_risk(port: u16) -> PortRiskLevel {
        match port {
            // Critical: Unencrypted, legacy protocols
            21 | 23 | 69 | 512..=514 => PortRiskLevel::Critical, // FTP, Telnet, TFTP, rlogin/rsh/rexec

            // High: Database ports, RDP, administrative services
            3306 | 5432 | 27017 | 6379 | // MySQL, PostgreSQL, MongoDB, Redis
            3389 | 5900 | // RDP, VNC
            445 | 139 | 135 | // SMB, NetBIOS
            1433 | 1521 => PortRiskLevel::High, // MS-SQL, Oracle

            // Medium: HTTP, mail servers
            80 | 8080 | 8000 | // HTTP
            25 | 110 | 143 => PortRiskLevel::Medium, // SMTP, POP3, IMAP

            // Low: Encrypted protocols
            22 | 443 | 8443 | 465 | 587 | 993 | 995 => PortRiskLevel::Low, // SSH, HTTPS, SMTPS, IMAPS, POP3S

            _ => PortRiskLevel::Unknown,
        }
    }

    /// Scan a subnet (CIDR notation, e.g., "192.168.1.0/24")
    pub async fn scan_subnet(
        &self,
        subnet: &str,
        ports: Vec<u16>,
    ) -> Result<Vec<ScanResult>, ScanError> {
        let (base_ip, mask) = Self::parse_cidr(subnet)?;
        let hosts = Self::generate_host_ips(base_ip, mask);

        let mut results = Vec::new();
        for host_ip in hosts {
            let scan_start = Utc::now();
            let target = host_ip.to_string();

            let tasks: Vec<_> = ports
                .iter()
                .map(|&port| self.scan_port(IpAddr::V4(host_ip), port))
                .collect();

            let port_results = join_all(tasks).await;
            let scan_end = Utc::now();

            let open_ports: Vec<PortScanResult> = port_results
                .iter()
                .filter(|r| r.status == PortStatus::Open)
                .cloned()
                .collect();

            // Only include hosts with open ports
            if !open_ports.is_empty() {
                let closed_ports = port_results
                    .iter()
                    .filter(|r| r.status == PortStatus::Closed)
                    .count();

                let filtered_ports = port_results
                    .iter()
                    .filter(|r| r.status == PortStatus::Filtered)
                    .count();

                results.push(ScanResult {
                    target,
                    scan_start,
                    scan_end,
                    ports_scanned: port_results.len(),
                    open_ports,
                    closed_ports,
                    filtered_ports,
                });
            }
        }

        Ok(results)
    }

    /// Parse CIDR notation (e.g., "192.168.1.0/24")
    fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), ScanError> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(ScanError::InvalidSubnetMask);
        }

        let ip = parts[0]
            .parse::<Ipv4Addr>()
            .map_err(|_| ScanError::InvalidIpAddress)?;

        let mask = parts[1]
            .parse::<u8>()
            .map_err(|_| ScanError::InvalidSubnetMask)?;

        if mask > 32 {
            return Err(ScanError::InvalidSubnetMask);
        }

        Ok((ip, mask))
    }

    /// Generate list of host IPs in a subnet
    fn generate_host_ips(base_ip: Ipv4Addr, mask: u8) -> Vec<Ipv4Addr> {
        let ip_u32 = u32::from(base_ip);
        let network_mask = !((1u32 << (32 - mask)) - 1);
        let network_addr = ip_u32 & network_mask;
        let host_count = (1u32 << (32 - mask)).saturating_sub(2); // Exclude network and broadcast

        let mut ips = Vec::new();
        for i in 1..=host_count.min(254) {
            // Limit to prevent huge scans
            let host_ip = Ipv4Addr::from(network_addr + i);
            ips.push(host_ip);
        }

        ips
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_scan_single_port() {
        let scanner = NetworkScanner::new();
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        // Scan a port that's likely closed
        let result = scanner.scan_port(ip, 9999).await;

        assert!(result.port == 9999);
        // Status could be Closed or Filtered depending on system
        assert!(
            result.status == PortStatus::Closed || result.status == PortStatus::Filtered
        );
    }

    #[tokio::test]
    async fn test_service_detection() {
        assert_eq!(
            NetworkScanner::detect_service(80),
            Some("HTTP".to_string())
        );
        assert_eq!(
            NetworkScanner::detect_service(443),
            Some("HTTPS".to_string())
        );
        assert_eq!(NetworkScanner::detect_service(22), Some("SSH".to_string()));
    }

    #[tokio::test]
    async fn test_scan_result_summary() {
        let result = ScanResult {
            target: "192.168.1.1".to_string(),
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            ports_scanned: 100,
            open_ports: vec![],
            closed_ports: 95,
            filtered_ports: 5,
        };

        let summary = result.summary();
        assert!(summary.contains("192.168.1.1"));
        assert!(summary.contains("100"));
    }

    #[tokio::test]
    async fn test_invalid_port_range() {
        let scanner = NetworkScanner::new();
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        let result = scanner.scan_ports(ip, 100, 50).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_port_risk_assessment() {
        // Critical risk
        assert_eq!(
            NetworkScanner::assess_port_risk(23),
            PortRiskLevel::Critical
        ); // Telnet
        assert_eq!(NetworkScanner::assess_port_risk(21), PortRiskLevel::Critical); // FTP

        // High risk
        assert_eq!(NetworkScanner::assess_port_risk(3389), PortRiskLevel::High); // RDP
        assert_eq!(NetworkScanner::assess_port_risk(3306), PortRiskLevel::High); // MySQL

        // Medium risk
        assert_eq!(NetworkScanner::assess_port_risk(80), PortRiskLevel::Medium); // HTTP

        // Low risk
        assert_eq!(NetworkScanner::assess_port_risk(443), PortRiskLevel::Low); // HTTPS
        assert_eq!(NetworkScanner::assess_port_risk(22), PortRiskLevel::Low); // SSH
    }

    #[test]
    fn test_cidr_parsing() {
        let result = NetworkScanner::parse_cidr("192.168.1.0/24");
        assert!(result.is_ok());
        let (ip, mask) = result.unwrap();
        assert_eq!(ip.to_string(), "192.168.1.0");
        assert_eq!(mask, 24);

        // Invalid CIDR
        assert!(NetworkScanner::parse_cidr("192.168.1.0").is_err());
        assert!(NetworkScanner::parse_cidr("192.168.1.0/33").is_err());
        assert!(NetworkScanner::parse_cidr("invalid/24").is_err());
    }

    #[test]
    fn test_host_ip_generation() {
        let base_ip = Ipv4Addr::new(192, 168, 1, 0);
        let ips = NetworkScanner::generate_host_ips(base_ip, 30); // /30 = 2 usable hosts

        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ips[1], Ipv4Addr::new(192, 168, 1, 2));
    }

    #[tokio::test]
    async fn test_scan_result_high_risk_ports() {
        let result = ScanResult {
            target: "192.168.1.1".to_string(),
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            ports_scanned: 5,
            open_ports: vec![
                PortScanResult {
                    port: 23,
                    status: PortStatus::Open,
                    service: Some("Telnet".to_string()),
                    banner: None,
                    risk_level: PortRiskLevel::Critical,
                    timestamp: Utc::now(),
                    response_time_ms: Some(10),
                },
                PortScanResult {
                    port: 3389,
                    status: PortStatus::Open,
                    service: Some("RDP".to_string()),
                    banner: None,
                    risk_level: PortRiskLevel::High,
                    timestamp: Utc::now(),
                    response_time_ms: Some(15),
                },
                PortScanResult {
                    port: 443,
                    status: PortStatus::Open,
                    service: Some("HTTPS".to_string()),
                    banner: None,
                    risk_level: PortRiskLevel::Low,
                    timestamp: Utc::now(),
                    response_time_ms: Some(5),
                },
            ],
            closed_ports: 2,
            filtered_ports: 0,
        };

        let high_risk = result.get_high_risk_ports();
        assert_eq!(high_risk.len(), 2); // Telnet (Critical) + RDP (High)

        let critical_ports = result.get_ports_by_risk(PortRiskLevel::Critical);
        assert_eq!(critical_ports.len(), 1);
        assert_eq!(critical_ports[0].port, 23);
    }

    #[tokio::test]
    async fn test_scan_duration_calculation() {
        let start = Utc::now();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let end = Utc::now();

        let result = ScanResult {
            target: "127.0.0.1".to_string(),
            scan_start: start,
            scan_end: end,
            ports_scanned: 10,
            open_ports: vec![],
            closed_ports: 10,
            filtered_ports: 0,
        };

        let duration = result.scan_duration_secs();
        assert!(duration >= 0.1 && duration < 1.0);
    }

    #[tokio::test]
    async fn test_json_export() {
        let result = ScanResult {
            target: "192.168.1.100".to_string(),
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            ports_scanned: 3,
            open_ports: vec![PortScanResult {
                port: 80,
                status: PortStatus::Open,
                service: Some("HTTP".to_string()),
                banner: Some("Server: nginx/1.18.0".to_string()),
                risk_level: PortRiskLevel::Medium,
                timestamp: Utc::now(),
                response_time_ms: Some(12),
            }],
            closed_ports: 2,
            filtered_ports: 0,
        };

        let json = result.to_json();
        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("192.168.1.100"));
        assert!(json_str.contains("HTTP"));
        assert!(json_str.contains("nginx"));
    }

    #[test]
    fn test_scanner_config_defaults() {
        let config = ScannerConfig::default();
        assert_eq!(config.timeout_ms, 1000);
        assert_eq!(config.concurrent_scans, 100);
        assert!(config.detect_services);
        assert!(!config.grab_banners); // Disabled by default
    }

    #[tokio::test]
    async fn test_scanner_with_custom_config() {
        let config = ScannerConfig {
            timeout_ms: 500,
            concurrent_scans: 50,
            detect_services: true,
            grab_banners: false,
        };

        let scanner = NetworkScanner::with_config(config);
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        let result = scanner.scan_port(ip, 9999).await;
        assert!(result.port == 9999);
    }
}
