# Rust Network Scanner

A memory-safe, asynchronous network security scanner for vulnerability assessment and network monitoring. Built with Rust and Tokio for high-performance concurrent scanning.

## Security-First Design

Eliminates memory vulnerabilities in network security tools through Rust's ownership system. Aligns with **2024 CISA/FBI guidance** for memory-safe security tooling.

## Features

- **Memory Safety** - No buffer overflows or memory corruption in scanning operations
- **Async/Await** - High-performance concurrent scanning using Tokio runtime
- **Port Scanning** - Detect open, closed, and filtered ports
- **Service Detection** - Identify common services (HTTP, SSH, MySQL, etc.)
- **Configurable** - Adjust timeouts, concurrency, and scanning behavior
- **JSON Export** - Export results in structured JSON format for SIEM integration

## Use Cases

- Financial infrastructure security assessment
- Network vulnerability scanning
- Service discovery and monitoring
- Compliance auditing (PCI-DSS, NIST)
- Penetration testing for authorized engagements

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust-network-scanner = "0.1.0"
```

## Quick Start

### Scan Common Ports

```rust
use rust_network_scanner::NetworkScanner;
use std::net::IpAddr;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let scanner = NetworkScanner::new();
    let ip = IpAddr::from_str("192.168.1.1").unwrap();

    // Scan top 20 common ports
    let result = scanner.scan_common_ports(ip).await.unwrap();

    println!("Scan Results: {}", result.summary());
    for port in &result.open_ports {
        println!("  Port {}: {} ({})",
                 port.port,
                 port.service.as_ref().unwrap_or(&"Unknown".to_string()),
                 port.response_time_ms.unwrap_or(0));
    }
}
```

### Scan Port Range

```rust
use rust_network_scanner::NetworkScanner;
use std::net::IpAddr;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let scanner = NetworkScanner::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    // Scan ports 1-1000
    let result = scanner.scan_ports(ip, 1, 1000).await.unwrap();

    println!("Found {} open ports", result.open_ports.len());

    // Export as JSON
    let json = result.to_json().unwrap();
    std::fs::write("scan_results.json", json).unwrap();
}
```

### Custom Configuration

```rust
use rust_network_scanner::{NetworkScanner, ScannerConfig};

let config = ScannerConfig {
    timeout_ms: 2000,          // 2 second timeout
    concurrent_scans: 200,     // 200 concurrent connections
    detect_services: true,     // Enable service detection
};

let scanner = NetworkScanner::with_config(config);
```

## Security Features

### Memory Safety

Traditional C/C++ network scanners are vulnerable to:
- Buffer overflows in packet parsing
- Use-after-free in connection handling
- Memory leaks in long-running scans

This implementation eliminates these vulnerabilities through Rust's ownership system.

### Concurrent Scanning

Safe concurrent scanning without data races:

```rust
// Scan multiple targets concurrently
let targets = vec!["192.168.1.1", "192.168.1.2", "192.168.1.3"];
let scanner = NetworkScanner::new();

let mut tasks = vec![];
for target in targets {
    let ip = IpAddr::from_str(target).unwrap();
    tasks.push(scanner.scan_common_ports(ip));
}

let results = futures::future::join_all(tasks).await;
```

### Service Detection

Automatically identifies common services:

- Web servers (HTTP/HTTPS)
- Database servers (MySQL, PostgreSQL, MongoDB)
- Remote access (SSH, RDP, VNC)
- Email servers (SMTP, IMAP, POP3)
- File sharing (FTP, SMB)

## Examples

See the `examples/` directory:

```bash
cargo run --example scan_network
```

## Testing

```bash
cargo test
```

## Alignment with Standards

This scanner implements security assessment practices from:

- **NIST SP 800-115** - Technical Guide to Information Security Testing
- **OWASP Testing Guide** - Network and Infrastructure Testing
- **CISA/FBI Joint Guidance (2024)** - Memory-safe security tools
- **PCI-DSS Requirement 11.3** - External and internal penetration testing

## Performance

- **High throughput** - Concurrent scanning with configurable parallelism
- **Low overhead** - Efficient async I/O using Tokio
- **Scalable** - Handles large IP ranges and port ranges
- **Fast** - Typical port scan: 100 ports in <2 seconds

## Ethical Use

This tool is designed for:
- **Authorized security assessments**
- **Penetration testing with written permission**
- **Internal network auditing**
- **Compliance testing**

**Unauthorized scanning is illegal.** Always obtain proper authorization before scanning networks.

## Use in Financial Systems

Designed for financial institutions requiring:
- **PCI-DSS compliance** - Network segmentation verification
- **NIST CSF** - Asset discovery and vulnerability assessment
- **SOX compliance** - IT control testing
- **Regulatory audits** - Network security verification

## License

MIT License - See LICENSE file

## Author

Tony Chuks Awunor
- Former FINMA-regulated forex broker operator (2008-2013)
- M.S. Computer Science (CGPA: 4.52/5.00)
- EC-Council Certified SOC Analyst (CSA)
- Specialization: Memory-safe network security tools for financial infrastructure

## Contributing

Contributions welcome! Please open an issue or pull request.

## Disclaimer

This tool is for authorized security testing only. The author is not responsible for misuse or illegal activity. Always obtain proper authorization before scanning networks you do not own.

## Related Projects

- [rust-secure-logger](https://github.com/your-username/rust-secure-logger) - Secure logging with cryptographic integrity
- [rust-threat-detector](https://github.com/your-username/rust-threat-detector) - SIEM threat detection
- [rust-crypto-utils](https://github.com/your-username/rust-crypto-utils) - Cryptographic utilities

## Citation

If you use this scanner in research or security assessments, please cite:

```
Awunor, T.C. (2024). Rust Network Scanner: Memory-Safe Network Security Assessment.
https://github.com/your-username/rust-network-scanner
```

---

**Built for security assessment. Designed for memory safety. Implemented in Rust.**
