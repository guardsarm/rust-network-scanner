//! Service detection and banner grabbing

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Known service signatures
pub struct ServiceSignatures;

impl ServiceSignatures {
    /// Detect service from banner
    pub fn detect_from_banner(banner: &str) -> Option<ServiceInfo> {
        let banner_lower = banner.to_lowercase();

        if banner_lower.contains("ssh") {
            return Some(ServiceInfo {
                name: "SSH".to_string(),
                version: Self::extract_ssh_version(banner),
                vendor: Self::extract_vendor(&banner_lower),
            });
        }

        if banner_lower.contains("http") || banner_lower.contains("server:") {
            return Some(ServiceInfo {
                name: "HTTP".to_string(),
                version: Self::extract_http_version(banner),
                vendor: Self::extract_vendor(&banner_lower),
            });
        }

        if banner_lower.contains("ftp") {
            return Some(ServiceInfo {
                name: "FTP".to_string(),
                version: Self::extract_version_generic(banner),
                vendor: Self::extract_vendor(&banner_lower),
            });
        }

        if banner_lower.contains("smtp") || banner_lower.contains("postfix") {
            return Some(ServiceInfo {
                name: "SMTP".to_string(),
                version: Self::extract_version_generic(banner),
                vendor: Self::extract_vendor(&banner_lower),
            });
        }

        if banner_lower.contains("mysql") {
            return Some(ServiceInfo {
                name: "MySQL".to_string(),
                version: Self::extract_mysql_version(banner),
                vendor: Some("Oracle".to_string()),
            });
        }

        if banner_lower.contains("postgresql") || banner_lower.contains("postgres") {
            return Some(ServiceInfo {
                name: "PostgreSQL".to_string(),
                version: Self::extract_version_generic(banner),
                vendor: Some("PostgreSQL Global Development Group".to_string()),
            });
        }

        None
    }

    fn extract_ssh_version(banner: &str) -> Option<String> {
        if let Some(start) = banner.find("SSH-") {
            let version_str = &banner[start..];
            if let Some(end) =
                version_str.find(|c: char| c.is_whitespace() || c == '\r' || c == '\n')
            {
                return Some(version_str[..end].to_string());
            }
        }
        None
    }

    fn extract_http_version(banner: &str) -> Option<String> {
        for line in banner.lines() {
            if line.to_lowercase().starts_with("server:") {
                return Some(line[7..].trim().to_string());
            }
        }
        None
    }

    fn extract_mysql_version(banner: &str) -> Option<String> {
        // MySQL version typically in format: 5.7.32 or 8.0.23
        let re = regex::Regex::new(r"(\d+\.\d+\.\d+)").ok()?;
        re.captures(banner)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
    }

    fn extract_version_generic(banner: &str) -> Option<String> {
        let re = regex::Regex::new(r"(\d+\.\d+(?:\.\d+)?)").ok()?;
        re.captures(banner)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
    }

    fn extract_vendor(banner: &str) -> Option<String> {
        if banner.contains("apache") {
            Some("Apache Software Foundation".to_string())
        } else if banner.contains("nginx") {
            Some("Nginx Inc.".to_string())
        } else if banner.contains("microsoft") || banner.contains("iis") {
            Some("Microsoft".to_string())
        } else if banner.contains("openssh") {
            Some("OpenSSH".to_string())
        } else if banner.contains("postfix") {
            Some("Postfix".to_string())
        } else {
            None
        }
    }
}

/// Service information
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub vendor: Option<String>,
}

impl ServiceInfo {
    /// Check if this is a known vulnerable version
    pub fn has_known_vulnerabilities(&self) -> bool {
        // Simplified vulnerability check
        if let Some(ref version) = self.version {
            // Example: old SSH versions
            if self.name == "SSH" && version.contains("OpenSSH_7.") {
                return true;
            }
            // Example: old Apache versions
            if self.name == "HTTP" && version.contains("Apache/2.2") {
                return true;
            }
        }
        false
    }

    /// Get severity if vulnerable
    pub fn vulnerability_severity(&self) -> Option<&'static str> {
        if self.has_known_vulnerabilities() {
            Some("HIGH")
        } else {
            None
        }
    }
}

/// Banner grabber
pub struct BannerGrabber;

impl BannerGrabber {
    /// Grab banner from service
    pub async fn grab_banner(host: &str, port: u16, timeout_ms: u64) -> Result<String, String> {
        let addr = format!("{}:{}", host, port);
        let connect_timeout = Duration::from_millis(timeout_ms);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| "Connection timeout".to_string())?
            .map_err(|e| format!("Connection failed: {}", e))?;

        let mut stream = stream;
        let mut buffer = vec![0u8; 1024];

        // Read initial banner
        let read_timeout = Duration::from_millis(timeout_ms);
        let n = timeout(read_timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| "Read timeout".to_string())?
            .map_err(|e| format!("Read failed: {}", e))?;

        if n == 0 {
            return Err("No data received".to_string());
        }

        let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
        Ok(banner)
    }

    /// Grab banner with HTTP probe
    pub async fn grab_http_banner(
        host: &str,
        port: u16,
        timeout_ms: u64,
    ) -> Result<String, String> {
        let addr = format!("{}:{}", host, port);
        let connect_timeout = Duration::from_millis(timeout_ms);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| "Connection timeout".to_string())?
            .map_err(|e| format!("Connection failed: {}", e))?;

        let mut stream = stream;

        // Send HTTP GET request
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: NetworkScanner/1.0\r\n\r\n",
            host
        );

        timeout(
            Duration::from_millis(timeout_ms),
            stream.write_all(request.as_bytes()),
        )
        .await
        .map_err(|_| "Write timeout".to_string())?
        .map_err(|e| format!("Write failed: {}", e))?;

        // Read response
        let mut buffer = vec![0u8; 4096];
        let read_timeout = Duration::from_millis(timeout_ms);
        let n = timeout(read_timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| "Read timeout".to_string())?
            .map_err(|e| format!("Read failed: {}", e))?;

        let response = String::from_utf8_lossy(&buffer[..n]).to_string();
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_detection() {
        let banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
        let service = ServiceSignatures::detect_from_banner(banner).unwrap();
        assert_eq!(service.name, "SSH");
        assert!(service.version.is_some());
    }

    #[test]
    fn test_http_detection() {
        let banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n";
        let service = ServiceSignatures::detect_from_banner(banner).unwrap();
        assert_eq!(service.name, "HTTP");
    }

    #[test]
    fn test_mysql_detection() {
        let _banner = "5.7.32-0ubuntu0.18.04.1";
        let service =
            ServiceSignatures::detect_from_banner("mysql 5.7.32-0ubuntu0.18.04.1").unwrap();
        assert_eq!(service.name, "MySQL");
    }

    #[test]
    fn test_vulnerability_check() {
        let service = ServiceInfo {
            name: "SSH".to_string(),
            version: Some("OpenSSH_7.4".to_string()),
            vendor: Some("OpenSSH".to_string()),
        };
        assert!(service.has_known_vulnerabilities());
        assert_eq!(service.vulnerability_severity(), Some("HIGH"));
    }

    #[test]
    fn test_no_vulnerability() {
        let service = ServiceInfo {
            name: "SSH".to_string(),
            version: Some("OpenSSH_9.0".to_string()),
            vendor: Some("OpenSSH".to_string()),
        };
        assert!(!service.has_known_vulnerabilities());
    }
}
