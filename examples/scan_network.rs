//! Network scanning example
//!
//! This example demonstrates network security scanning for vulnerability
//! assessment and service discovery.

use rust_network_scanner::{NetworkScanner, ScannerConfig};
use std::net::IpAddr;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    println!("=== Network Security Scanner ===\n");

    // Scan localhost as a safe example
    let target_ip = "127.0.0.1";

    println!("IMPORTANT: This example scans localhost only.");
    println!("For production use, always obtain authorization before scanning.\n");

    // Create scanner with default configuration
    let scanner = NetworkScanner::new();
    let ip = IpAddr::from_str(target_ip).unwrap();

    // 1. Scan common ports
    println!("1. Scanning Common Ports on {}", target_ip);
    println!("   Scanning top 20 most common ports...\n");

    match scanner.scan_common_ports(ip).await {
        Ok(result) => {
            println!("   {}", result.summary());
            println!("\n   Open Ports:");

            if result.open_ports.is_empty() {
                println!("   No open ports found (this is normal for localhost)");
            } else {
                for port in &result.open_ports {
                    println!(
                        "   ✓ Port {}: {} - Response time: {}ms",
                        port.port,
                        port.service.as_ref().unwrap_or(&"Unknown".to_string()),
                        port.response_time_ms.unwrap_or(0)
                    );
                }
            }

            let duration = result.scan_end.signed_duration_since(result.scan_start);
            println!("\n   Scan completed in {} seconds", duration.num_seconds());
        }
        Err(e) => {
            eprintln!("   Error: {}", e);
        }
    }

    // 2. Scan specific port range
    println!("\n2. Scanning Port Range 8000-8100");
    println!("   (Useful for finding development servers)\n");

    match scanner.scan_ports(ip, 8000, 8100).await {
        Ok(result) => {
            println!("   {}", result.summary());

            if !result.open_ports.is_empty() {
                println!("\n   Open Ports in Range:");
                for port in &result.open_ports {
                    println!(
                        "   ✓ Port {}: {} - {}ms",
                        port.port,
                        port.service.as_ref().unwrap_or(&"Unknown".to_string()),
                        port.response_time_ms.unwrap_or(0)
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("   Error: {}", e);
        }
    }

    // 3. Custom scanner configuration
    println!("\n3. Custom Configuration Scan");
    println!("   Faster scan with 200 concurrent connections\n");

    let custom_config = ScannerConfig {
        timeout_ms: 500,       // Faster timeout
        concurrent_scans: 200, // More concurrent scans
        detect_services: true,
    };

    let fast_scanner = NetworkScanner::with_config(custom_config);

    match fast_scanner.scan_ports(ip, 1, 100).await {
        Ok(result) => {
            let duration = result.scan_end.signed_duration_since(result.scan_start);
            println!("   Scanned 100 ports in {} seconds", duration.num_seconds());
            println!("   Found {} open ports", result.open_ports.len());
        }
        Err(e) => {
            eprintln!("   Error: {}", e);
        }
    }

    // 4. Scan multiple targets (demonstration with localhost only)
    println!("\n4. Multiple Target Scanning (Demo)");
    println!("   Scanning multiple IP addresses concurrently\n");

    let targets = vec!["127.0.0.1"]; // In production, add more IPs

    let mut tasks = vec![];
    for target in &targets {
        let ip = IpAddr::from_str(target).unwrap();
        let scan = scanner.scan_common_ports(ip);
        tasks.push((target, scan));
    }

    for (target, task) in tasks {
        match task.await {
            Ok(result) => {
                println!("   {} - {} open ports", target, result.open_ports.len());
            }
            Err(e) => {
                eprintln!("   {} - Error: {}", target, e);
            }
        }
    }

    // 5. Export results as JSON
    println!("\n5. Exporting Results as JSON");

    match scanner.scan_common_ports(ip).await {
        Ok(result) => {
            match result.to_json() {
                Ok(json) => {
                    println!("   JSON export successful:");
                    println!("{}", json);
                }
                Err(e) => {
                    eprintln!("   JSON export error: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("   Scan error: {}", e);
        }
    }

    println!("\n=== Security Notes ===");
    println!("✓ Memory-safe implementation (no buffer overflows)");
    println!("✓ Async/await for efficient concurrent scanning");
    println!("✓ Service detection for vulnerability assessment");
    println!("✓ JSON export for SIEM integration");
    println!("✓ Configurable timeouts and concurrency");

    println!("\n=== Compliance Use Cases ===");
    println!("✓ PCI-DSS Requirement 11.3 - Network penetration testing");
    println!("✓ NIST SP 800-115 - Technical security testing");
    println!("✓ SOX compliance - IT control verification");
    println!("✓ Internal security audits");

    println!("\n⚠️  IMPORTANT: Always obtain written authorization before scanning networks!");
}
