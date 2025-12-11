//! OS Fingerprinting module for network scanning v2.0
//!
//! Provides operating system detection based on TCP/IP stack analysis.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Operating system categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperatingSystem {
    Windows(WindowsVersion),
    Linux(LinuxDistro),
    MacOS(String),
    BSD(String),
    Cisco,
    Juniper,
    Unknown,
}

/// Windows version detection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WindowsVersion {
    Windows10,
    Windows11,
    WindowsServer2016,
    WindowsServer2019,
    WindowsServer2022,
    Unknown,
}

/// Linux distribution detection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LinuxDistro {
    Ubuntu,
    Debian,
    CentOS,
    RedHat,
    Alpine,
    Unknown,
}

/// OS fingerprint result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSFingerprint {
    pub os: OperatingSystem,
    pub confidence: f32,
    pub ttl: Option<u8>,
    pub window_size: Option<u16>,
    pub mss: Option<u16>,
    pub tcp_options: Vec<String>,
    pub raw_fingerprint: String,
}

impl OSFingerprint {
    /// Get human-readable OS name
    pub fn os_name(&self) -> String {
        match &self.os {
            OperatingSystem::Windows(v) => format!("Windows ({:?})", v),
            OperatingSystem::Linux(d) => format!("Linux ({:?})", d),
            OperatingSystem::MacOS(v) => format!("macOS {}", v),
            OperatingSystem::BSD(v) => format!("BSD {}", v),
            OperatingSystem::Cisco => "Cisco IOS".to_string(),
            OperatingSystem::Juniper => "Juniper JUNOS".to_string(),
            OperatingSystem::Unknown => "Unknown".to_string(),
        }
    }

    /// Check if detection is reliable
    pub fn is_reliable(&self) -> bool {
        self.confidence >= 0.7
    }
}

/// OS fingerprint signatures database
pub struct OSSignatures {
    signatures: HashMap<String, (OperatingSystem, f32)>,
}

impl OSSignatures {
    /// Create a new signature database with defaults
    pub fn new() -> Self {
        let mut signatures = HashMap::new();

        // Windows signatures (TTL 128)
        signatures.insert(
            "ttl:128:win:65535".to_string(),
            (OperatingSystem::Windows(WindowsVersion::Windows10), 0.85),
        );
        signatures.insert(
            "ttl:128:win:8192".to_string(),
            (
                OperatingSystem::Windows(WindowsVersion::WindowsServer2019),
                0.8,
            ),
        );

        // Linux signatures (TTL 64)
        signatures.insert(
            "ttl:64:mss:1460".to_string(),
            (OperatingSystem::Linux(LinuxDistro::Ubuntu), 0.75),
        );
        signatures.insert(
            "ttl:64:mss:1380".to_string(),
            (OperatingSystem::Linux(LinuxDistro::CentOS), 0.7),
        );

        // macOS signatures (TTL 64)
        signatures.insert(
            "ttl:64:win:65535:sack".to_string(),
            (OperatingSystem::MacOS("Unknown".to_string()), 0.7),
        );

        // Cisco signatures (TTL 255)
        signatures.insert("ttl:255:cisco".to_string(), (OperatingSystem::Cisco, 0.9));

        Self { signatures }
    }

    /// Look up a signature
    pub fn lookup(&self, fingerprint: &str) -> Option<&(OperatingSystem, f32)> {
        self.signatures.get(fingerprint)
    }

    /// Add a custom signature
    pub fn add_signature(&mut self, fingerprint: String, os: OperatingSystem, confidence: f32) {
        self.signatures.insert(fingerprint, (os, confidence));
    }
}

impl Default for OSSignatures {
    fn default() -> Self {
        Self::new()
    }
}

/// OS detector for network scanning
pub struct OSDetector {
    signatures: OSSignatures,
}

impl OSDetector {
    /// Create a new OS detector
    pub fn new() -> Self {
        Self {
            signatures: OSSignatures::new(),
        }
    }

    /// Detect OS from TTL value
    pub fn detect_from_ttl(&self, ttl: u8) -> OSFingerprint {
        let (os, confidence) = match ttl {
            128 => (OperatingSystem::Windows(WindowsVersion::Unknown), 0.7),
            64 => (OperatingSystem::Linux(LinuxDistro::Unknown), 0.6),
            255 => (OperatingSystem::Cisco, 0.8),
            _ => (OperatingSystem::Unknown, 0.3),
        };

        OSFingerprint {
            os,
            confidence,
            ttl: Some(ttl),
            window_size: None,
            mss: None,
            tcp_options: Vec::new(),
            raw_fingerprint: format!("ttl:{}", ttl),
        }
    }

    /// Detect OS from TCP parameters
    pub fn detect_from_tcp(&self, ttl: u8, window_size: u16, mss: Option<u16>) -> OSFingerprint {
        // Build fingerprint string
        let mut fingerprint_parts = vec![format!("ttl:{}", ttl)];

        if window_size == 65535 {
            fingerprint_parts.push("win:65535".to_string());
        } else if window_size == 8192 {
            fingerprint_parts.push("win:8192".to_string());
        }

        if let Some(mss_val) = mss {
            fingerprint_parts.push(format!("mss:{}", mss_val));
        }

        let fingerprint = fingerprint_parts.join(":");

        // Look up in signature database
        if let Some((os, confidence)) = self.signatures.lookup(&fingerprint) {
            return OSFingerprint {
                os: os.clone(),
                confidence: *confidence,
                ttl: Some(ttl),
                window_size: Some(window_size),
                mss,
                tcp_options: Vec::new(),
                raw_fingerprint: fingerprint,
            };
        }

        // Fall back to TTL-based detection
        self.detect_from_ttl(ttl)
    }

    /// Detect OS from service banner
    pub fn detect_from_banner(&self, banner: &str) -> Option<OSFingerprint> {
        let banner_lower = banner.to_lowercase();

        // Windows detection
        if banner_lower.contains("windows") || banner_lower.contains("microsoft") {
            let version = if banner_lower.contains("2022") {
                WindowsVersion::WindowsServer2022
            } else if banner_lower.contains("2019") {
                WindowsVersion::WindowsServer2019
            } else if banner_lower.contains("2016") {
                WindowsVersion::WindowsServer2016
            } else {
                WindowsVersion::Unknown
            };

            return Some(OSFingerprint {
                os: OperatingSystem::Windows(version),
                confidence: 0.9,
                ttl: None,
                window_size: None,
                mss: None,
                tcp_options: Vec::new(),
                raw_fingerprint: format!("banner:{}", &banner[..banner.len().min(50)]),
            });
        }

        // Linux detection
        if banner_lower.contains("ubuntu") {
            return Some(OSFingerprint {
                os: OperatingSystem::Linux(LinuxDistro::Ubuntu),
                confidence: 0.95,
                ttl: None,
                window_size: None,
                mss: None,
                tcp_options: Vec::new(),
                raw_fingerprint: "banner:ubuntu".to_string(),
            });
        }

        if banner_lower.contains("debian") {
            return Some(OSFingerprint {
                os: OperatingSystem::Linux(LinuxDistro::Debian),
                confidence: 0.95,
                ttl: None,
                window_size: None,
                mss: None,
                tcp_options: Vec::new(),
                raw_fingerprint: "banner:debian".to_string(),
            });
        }

        if banner_lower.contains("centos") || banner_lower.contains("red hat") {
            return Some(OSFingerprint {
                os: OperatingSystem::Linux(LinuxDistro::CentOS),
                confidence: 0.9,
                ttl: None,
                window_size: None,
                mss: None,
                tcp_options: Vec::new(),
                raw_fingerprint: "banner:centos".to_string(),
            });
        }

        None
    }

    /// Combine multiple detection methods
    pub fn detect_combined(
        &self,
        ttl: Option<u8>,
        window_size: Option<u16>,
        mss: Option<u16>,
        banner: Option<&str>,
    ) -> OSFingerprint {
        // Try banner detection first (most reliable)
        if let Some(b) = banner {
            if let Some(fp) = self.detect_from_banner(b) {
                return fp;
            }
        }

        // Try TCP-based detection
        if let (Some(t), Some(w)) = (ttl, window_size) {
            return self.detect_from_tcp(t, w, mss);
        }

        // Fall back to TTL-only detection
        if let Some(t) = ttl {
            return self.detect_from_ttl(t);
        }

        // Unknown
        OSFingerprint {
            os: OperatingSystem::Unknown,
            confidence: 0.0,
            ttl: None,
            window_size: None,
            mss: None,
            tcp_options: Vec::new(),
            raw_fingerprint: "unknown".to_string(),
        }
    }
}

impl Default for OSDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_detection() {
        let detector = OSDetector::new();

        let windows = detector.detect_from_ttl(128);
        assert!(matches!(windows.os, OperatingSystem::Windows(_)));

        let linux = detector.detect_from_ttl(64);
        assert!(matches!(linux.os, OperatingSystem::Linux(_)));

        let cisco = detector.detect_from_ttl(255);
        assert!(matches!(cisco.os, OperatingSystem::Cisco));
    }

    #[test]
    fn test_banner_detection() {
        let detector = OSDetector::new();

        let ubuntu = detector.detect_from_banner("Ubuntu 22.04 LTS").unwrap();
        assert!(matches!(
            ubuntu.os,
            OperatingSystem::Linux(LinuxDistro::Ubuntu)
        ));
        assert!(ubuntu.confidence >= 0.9);

        let windows = detector
            .detect_from_banner("Microsoft Windows Server 2019")
            .unwrap();
        assert!(matches!(windows.os, OperatingSystem::Windows(_)));
    }

    #[test]
    fn test_combined_detection() {
        let detector = OSDetector::new();

        let result = detector.detect_combined(
            Some(64),
            Some(65535),
            Some(1460),
            Some("OpenSSH 8.2p1 Ubuntu"),
        );

        assert!(matches!(
            result.os,
            OperatingSystem::Linux(LinuxDistro::Ubuntu)
        ));
        assert!(result.confidence >= 0.9);
    }

    #[test]
    fn test_os_name() {
        let fp = OSFingerprint {
            os: OperatingSystem::Windows(WindowsVersion::WindowsServer2022),
            confidence: 0.9,
            ttl: Some(128),
            window_size: None,
            mss: None,
            tcp_options: Vec::new(),
            raw_fingerprint: "test".to_string(),
        };

        assert!(fp.os_name().contains("Windows"));
    }

    #[test]
    fn test_reliability() {
        let reliable = OSFingerprint {
            os: OperatingSystem::Linux(LinuxDistro::Ubuntu),
            confidence: 0.9,
            ttl: None,
            window_size: None,
            mss: None,
            tcp_options: Vec::new(),
            raw_fingerprint: "test".to_string(),
        };

        let unreliable = OSFingerprint {
            confidence: 0.5,
            ..reliable.clone()
        };

        assert!(reliable.is_reliable());
        assert!(!unreliable.is_reliable());
    }
}
