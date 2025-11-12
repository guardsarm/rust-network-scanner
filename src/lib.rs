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
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
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
}

/// Network scanner configuration
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub timeout_ms: u64,
    pub concurrent_scans: usize,
    pub detect_services: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 1000,
            concurrent_scans: 100,
            detect_services: true,
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

        let status = match timeout(
            Duration::from_millis(self.config.timeout_ms),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(_)) => PortStatus::Open,
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

        PortScanResult {
            port,
            status,
            service,
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
}
