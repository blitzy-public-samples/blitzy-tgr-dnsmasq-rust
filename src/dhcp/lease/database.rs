// SPDX-License-Identifier: GPL-2.0-or-later

//! DHCP lease database persistence module
//!
//! This module provides functionality for reading and writing DHCP lease records
//! to/from persistent storage. The lease file format is compatible with the
//! original dnsmasq C implementation, ensuring backward compatibility.
//!
//! # Lease File Format
//!
//! The lease file uses a line-based text format with the following structure:
//!
//! ## DHCPv4 Leases
//! ```text
//! <expiration_time> <mac_address> <ip_address> <hostname> <client_id>
//! ```
//!
//! ## DHCPv6 Leases (preceded by "duid" line)
//! ```text
//! duid <server_duid_hex>
//! <expiration_time> <ip_address> <hostname> <client_id>
//! ```
//!
//! ## Additional Lease Information
//! ```text
//! agent-info <ip_address> <agent_id_hex>
//! vendorclass <ip_address> <vendor_class_hex>
//! ```
//!
//! # Example
//! ```text
//! 1234567890 01:23:45:67:89:ab 192.168.1.100 laptop.local 01:01:23:45:67:89:ab
//! duid 00:01:00:01:12:34:56:78:90:ab:cd:ef
//! 1234567890 2001:db8::100 server.local *
//! agent-info 192.168.1.100 01:04:c0:a8:01:01
//! vendorclass 192.168.1.100 4d:53:46:54:20:35:2e:30
//! ```
//!
//! Based on: src/lease.c (lease_init, lease_update_file, read_leases)

use crate::dhcp::lease::{Lease, LeaseFlags};
use crate::error::DhcpError;
use crate::types::MacAddress;
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, info, warn};

/// Read DHCP leases from a persistent lease file
///
/// Parses the lease file line-by-line, reconstructing Lease objects from the
/// stored text format. The function handles both DHCPv4 and DHCPv6 leases,
/// as well as additional lease metadata (agent-info, vendorclass).
///
/// # Arguments
///
/// * `lease_file_path` - Path to the lease file (typically /var/lib/misc/dnsmasq.leases)
/// * `now` - Current system time for determining lease expiration status
///
/// # Returns
///
/// A vector of successfully parsed `Lease` objects. Malformed lines are logged
/// and skipped to maintain service availability with partial data.
///
/// # Errors
///
/// Returns `DhcpError::LeaseDatabaseFailed` if the file cannot be opened or read.
/// Individual parse errors are logged but do not fail the entire operation.
///
/// # Example
///
/// ```ignore
/// use std::time::SystemTime;
/// use std::path::Path;
///
/// let leases = read_leases(Path::new("/var/lib/misc/dnsmasq.leases"), SystemTime::now())?;
/// println!("Loaded {} leases from database", leases.len());
/// ```
///
/// # C Implementation Reference
///
/// Based on: src/lease.c:read_leases() (lines 168-430)
///
/// The C implementation uses fscanf to parse fields and handles multiple lease
/// formats. This Rust version provides equivalent functionality with safe parsing.
pub async fn read_leases(lease_file_path: &Path, now: SystemTime) -> Result<Vec<Lease>, DhcpError> {
    // Check if file exists, return empty vec if not (first startup)
    match tokio::fs::metadata(lease_file_path).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(
                "Lease file {} does not exist, starting with empty lease database",
                lease_file_path.display()
            );
            return Ok(Vec::new());
        }
        Err(e) => {
            error!("Failed to check lease file {}: {}", lease_file_path.display(), e);
            return Err(DhcpError::LeaseDatabaseFailed {
                operation: "read".to_string(),
                reason: e.to_string(),
            });
        }
    }

    let file = File::open(lease_file_path).await.map_err(|e| {
        error!("Failed to open lease file {}: {}", lease_file_path.display(), e);
        DhcpError::LeaseDatabaseFailed { operation: "read".to_string(), reason: e.to_string() }
    })?;

    let reader = BufReader::new(file);
    let mut leases = Vec::new();
    let mut current_duid: Option<Vec<u8>> = None;
    let mut line_number = 0;
    let mut lines = reader.lines();

    while let Some(line_result) = lines.next_line().await.transpose() {
        line_number += 1;

        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                warn!("Error reading line {} from lease file: {}", line_number, e);
                continue;
            }
        };

        // Skip empty lines and comments
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse the line
        if let Err(e) = parse_lease_line(&line, &mut leases, &mut current_duid, now) {
            warn!("Failed to parse line {} in lease file: {} - Line: {}", line_number, e, line);
            // Continue parsing other lines despite this error
        }
    }

    info!("Successfully loaded {} leases from {}", leases.len(), lease_file_path.display());

    Ok(leases)
}

/// Parse a single line from the lease file
///
/// Handles different line types:
/// - Standard DHCPv4/v6 lease entries
/// - "duid" lines declaring server DUID for DHCPv6
/// - "agent-info" lines with relay agent information
/// - "vendorclass" lines with vendor class identifiers
fn parse_lease_line(
    line: &str,
    leases: &mut Vec<Lease>,
    current_duid: &mut Option<Vec<u8>>,
    now: SystemTime,
) -> Result<(), String> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.is_empty() {
        return Ok(()); // Empty line
    }

    match parts[0] {
        "duid" => {
            // DHCPv6 server DUID declaration
            if parts.len() < 2 {
                return Err("duid line missing DUID value".to_string());
            }
            *current_duid = Some(parse_hex_string(parts[1])?);
            debug!("Found DHCPv6 DUID in lease file");
            Ok(())
        }
        "agent-info" => {
            // Relay agent information for existing lease
            if parts.len() < 3 {
                return Err("agent-info line requires IP and agent ID".to_string());
            }
            let ip: IpAddr =
                parts[1].parse().map_err(|e| format!("Invalid IP in agent-info: {}", e))?;
            let agent_id = parse_hex_string(parts[2])?;

            // Find matching lease and update agent_id
            if let Some(lease) = leases.iter_mut().find(|l| l.ip == ip) {
                lease.agent_id = Some(agent_id);
            }
            Ok(())
        }
        "vendorclass" => {
            // Vendor class identifier for existing lease
            if parts.len() < 3 {
                return Err("vendorclass line requires IP and class ID".to_string());
            }
            let ip: IpAddr =
                parts[1].parse().map_err(|e| format!("Invalid IP in vendorclass: {}", e))?;
            let vendor_class = parse_hex_string(parts[2])?;

            // Find matching lease and update vendorclass
            if let Some(lease) = leases.iter_mut().find(|l| l.ip == ip) {
                lease.vendorclass = Some(vendor_class);
            }
            Ok(())
        }
        _ => {
            // Standard lease entry: <expiry> <mac> <ip> <hostname> <client_id>
            // Or DHCPv6 format: <expiry> [T]<iaid> <ip> <hostname> <client_id>
            if parts.len() < 4 {
                return Err(format!("Lease line requires at least 4 fields, got {}", parts.len()));
            }

            parse_standard_lease(parts, leases, current_duid, now)
        }
    }
}

/// Parse a standard DHCPv4 or DHCPv6 lease entry
fn parse_standard_lease(
    parts: Vec<&str>,
    leases: &mut Vec<Lease>,
    _current_duid: &Option<Vec<u8>>,
    now: SystemTime,
) -> Result<(), String> {
    // Parse expiration time
    let expires_timestamp: u64 =
        parts[0].parse().map_err(|e| format!("Invalid expiration time: {}", e))?;

    let expires = UNIX_EPOCH + std::time::Duration::from_secs(expires_timestamp);

    // Check if lease has already expired
    if expires < now {
        debug!("Skipping expired lease with IP {}", parts[2]);
        return Ok(()); // Skip expired leases during load
    }

    // Try to parse as DHCPv4 format first: <expiry> <mac> <ip> <hostname> <client_id>
    if let Ok(ip) = parts[2].parse::<IpAddr>() {
        let mac_str = parts[1];
        let mac = if mac_str != "*" {
            Some(MacAddress::parse(mac_str).map_err(|e| format!("Invalid MAC address: {}", e))?)
        } else {
            None
        };

        let hostname =
            if parts.len() > 3 && parts[3] != "*" { Some(parts[3].to_string()) } else { None };

        let client_id = if parts.len() > 4 && parts[4] != "*" {
            Some(parse_hex_string(parts[4])?)
        } else {
            None
        };

        // Determine if this is DHCPv6 based on IP type and IAID prefix
        let (iaid, flags) = if ip.is_ipv6() {
            // Check if MAC field has IAID prefix (T<number> for TA, or just <number> for NA)
            let iaid_str = parts[1];
            if let Some(stripped) = iaid_str.strip_prefix('T') {
                // Temporary Address (TA)
                let iaid_num: u32 =
                    stripped.parse().map_err(|e| format!("Invalid IAID in TA lease: {}", e))?;
                (Some(iaid_num), LeaseFlags::TA)
            } else {
                // Non-temporary Address (NA)
                let iaid_num: u32 =
                    iaid_str.parse().map_err(|e| format!("Invalid IAID in NA lease: {}", e))?;
                (Some(iaid_num), LeaseFlags::NA)
            }
        } else {
            (None, LeaseFlags::empty())
        };

        let lease = Lease {
            ip,
            mac,
            hostname,
            client_id,
            expires,
            iaid,
            flags,
            interface: String::new(), // Will be updated during interface enumeration
            fqdn: None,               // Will be computed if needed
            vendorclass: None,        // May be set by vendorclass line
            agent_id: None,           // May be set by agent-info line
            slaac_addresses: None,    // DHCPv6 SLAAC addresses loaded separately
        };

        leases.push(lease);
        Ok(())
    } else {
        Err(format!("Invalid IP address: {}", parts[2]))
    }
}

/// Parse a colon-separated hexadecimal string into bytes
///
/// Handles formats like "01:23:45:67:89:ab" or "0123456789ab"
fn parse_hex_string(hex_str: &str) -> Result<Vec<u8>, String> {
    let cleaned = hex_str.replace(':', "");

    if !cleaned.len().is_multiple_of(2) {
        return Err(format!("Hex string must have even number of characters: {}", hex_str));
    }

    let mut bytes = Vec::new();
    for i in (0..cleaned.len()).step_by(2) {
        let byte_str = &cleaned[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|e| format!("Invalid hex byte '{}': {}", byte_str, e))?;
        bytes.push(byte);
    }

    Ok(bytes)
}

/// Write DHCP leases to a persistent lease file
///
/// Serializes all active leases to the lease file in the format compatible
/// with the original dnsmasq C implementation. The file is written atomically
/// by writing to a temporary file and then renaming it.
///
/// # Arguments
///
/// * `lease_file_path` - Path to the lease file (typically /var/lib/misc/dnsmasq.leases)
/// * `leases` - Vector of leases to persist
/// * `server_duid` - Optional DHCPv6 server DUID (written if DHCPv6 leases present)
///
/// # Returns
///
/// `Ok(())` if the file was successfully written, or `DhcpError::LeaseDatabaseFailed` on failure.
///
/// # Errors
///
/// Returns `DhcpError::LeaseDatabaseFailed` if:
/// - The temporary file cannot be created
/// - Writing to the file fails
/// - Flushing or syncing the file fails
/// - Renaming the temporary file fails
///
/// # Example
///
/// ```ignore
/// use std::path::Path;
///
/// let leases = vec![/* ... */];
/// write_leases(Path::new("/var/lib/misc/dnsmasq.leases"), &leases, None).await?;
/// ```
///
/// # C Implementation Reference
///
/// Based on: src/lease.c:lease_update_file() (lines 677-900)
///
/// The C implementation writes the file in-place with careful error handling.
/// This Rust version uses atomic file replacement for better reliability.
pub async fn write_leases(
    lease_file_path: &Path,
    leases: &[Lease],
    server_duid: Option<&[u8]>,
) -> Result<(), DhcpError> {
    // Create temporary file in the same directory for atomic rename
    let temp_path = lease_file_path.with_extension("tmp");

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)
        .await
        .map_err(|e| {
            error!("Failed to create temporary lease file {}: {}", temp_path.display(), e);
            DhcpError::LeaseDatabaseFailed { operation: "write".to_string(), reason: e.to_string() }
        })?;

    // Track if we need to write DHCPv6 section
    let has_v6_leases = leases.iter().any(|l| l.ip.is_ipv6());

    // Write DHCPv4 leases first
    for lease in leases.iter().filter(|l| l.ip.is_ipv4()) {
        if let Err(e) = write_lease_entry(&mut file, lease).await {
            error!("Failed to write DHCPv4 lease entry: {}", e);
            return Err(DhcpError::LeaseDatabaseFailed {
                operation: "write".to_string(),
                reason: e.to_string(),
            });
        }
    }

    // Write DHCPv6 section if we have v6 leases
    if has_v6_leases {
        // Write DUID line if provided
        if let Some(duid) = server_duid {
            write_duid_line(&mut file, duid).await?;
        }

        // Write DHCPv6 leases
        for lease in leases.iter().filter(|l| l.ip.is_ipv6()) {
            if let Err(e) = write_lease_entry(&mut file, lease).await {
                error!("Failed to write DHCPv6 lease entry: {}", e);
                return Err(DhcpError::LeaseDatabaseFailed {
                    operation: "write".to_string(),
                    reason: e.to_string(),
                });
            }
        }
    }

    // Write extra information (agent-info, vendorclass) for all leases
    for lease in leases {
        if let Some(ref agent_id) = lease.agent_id {
            write_agent_info_line(&mut file, &lease.ip, agent_id).await?;
        }
        if let Some(ref vendor_class) = lease.vendorclass {
            write_vendorclass_line(&mut file, &lease.ip, vendor_class).await?;
        }
    }

    // Flush and sync to ensure data is written
    file.flush().await.map_err(|e| {
        error!("Failed to flush lease file: {}", e);
        DhcpError::LeaseDatabaseFailed { operation: "write".to_string(), reason: e.to_string() }
    })?;

    file.sync_all().await.map_err(|e| {
        error!("Failed to sync lease file: {}", e);
        DhcpError::LeaseDatabaseFailed { operation: "write".to_string(), reason: e.to_string() }
    })?;

    // Close the file explicitly
    drop(file);

    // Atomically replace the old file with the new one
    tokio::fs::rename(&temp_path, lease_file_path).await.map_err(|e| {
        error!("Failed to rename {} to {}: {}", temp_path.display(), lease_file_path.display(), e);
        DhcpError::LeaseDatabaseFailed { operation: "write".to_string(), reason: e.to_string() }
    })?;

    debug!("Successfully wrote {} leases to {}", leases.len(), lease_file_path.display());

    Ok(())
}

/// Write a single lease entry to the file
async fn write_lease_entry(file: &mut File, lease: &Lease) -> std::io::Result<()> {
    let expires_secs = lease.expires.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    // Format depends on whether this is DHCPv4 or DHCPv6
    let line = if lease.ip.is_ipv4() {
        // DHCPv4 format: <expiry> <mac> <ip> <hostname> <client_id>
        // MacAddress already implements Display with the correct format
        let mac_str = lease.mac.as_ref().map(|m| m.to_string()).unwrap_or_else(|| "*".to_string());

        let hostname = lease.hostname.as_deref().unwrap_or("*");

        let client_id_str = lease
            .client_id
            .as_ref()
            .map(|c| c.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":"))
            .unwrap_or_else(|| "*".to_string());

        format!("{} {} {} {} {}\n", expires_secs, mac_str, lease.ip, hostname, client_id_str)
    } else {
        // DHCPv6 format: <expiry> [T]<iaid> <ip> <hostname> <client_id>
        let iaid_str = if let Some(iaid) = lease.iaid {
            if lease.flags.contains(LeaseFlags::TA) {
                format!("T{}", iaid)
            } else {
                format!("{}", iaid)
            }
        } else {
            "0".to_string()
        };

        let hostname = lease.hostname.as_deref().unwrap_or("*");

        let client_id_str = lease
            .client_id
            .as_ref()
            .map(|c| c.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":"))
            .unwrap_or_else(|| "*".to_string());

        format!("{} {} {} {} {}\n", expires_secs, iaid_str, lease.ip, hostname, client_id_str)
    };

    file.write_all(line.as_bytes()).await?;
    Ok(())
}

/// Write DHCPv6 DUID line
async fn write_duid_line(file: &mut File, duid: &[u8]) -> Result<(), DhcpError> {
    let duid_hex = duid.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");

    let line = format!("duid {}\n", duid_hex);
    file.write_all(line.as_bytes()).await.map_err(|e| {
        error!("Failed to write DUID line: {}", e);
        DhcpError::LeaseDatabaseFailed { operation: "write".to_string(), reason: e.to_string() }
    })?;

    Ok(())
}

/// Write agent-info line for a lease
async fn write_agent_info_line(
    file: &mut File,
    ip: &IpAddr,
    agent_id: &[u8],
) -> Result<(), DhcpError> {
    let agent_hex = agent_id.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");

    let line = format!("agent-info {} {}\n", ip, agent_hex);
    file.write_all(line.as_bytes()).await.map_err(|e| {
        error!("Failed to write agent-info line: {}", e);
        DhcpError::LeaseDatabaseFailed { operation: "write".to_string(), reason: e.to_string() }
    })?;

    Ok(())
}

/// Write vendorclass line for a lease
async fn write_vendorclass_line(
    file: &mut File,
    ip: &IpAddr,
    vendor_class: &[u8],
) -> Result<(), DhcpError> {
    let vendor_hex =
        vendor_class.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");

    let line = format!("vendorclass {} {}\n", ip, vendor_hex);
    file.write_all(line.as_bytes()).await.map_err(|e| {
        error!("Failed to write vendorclass line: {}", e);
        DhcpError::LeaseDatabaseFailed { operation: "write".to_string(), reason: e.to_string() }
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_hex_string() {
        assert_eq!(parse_hex_string("01:23:45").unwrap(), vec![0x01, 0x23, 0x45]);
        assert_eq!(parse_hex_string("012345").unwrap(), vec![0x01, 0x23, 0x45]);
        assert!(parse_hex_string("0123").is_ok());
        assert!(parse_hex_string("xyz").is_err());
    }

    #[tokio::test]
    async fn test_write_and_read_leases() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        let now = SystemTime::now();
        let expires = now + std::time::Duration::from_secs(3600);

        let lease = Lease {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            mac: Some(MacAddress::new([0x01, 0x23, 0x45, 0x67, 0x89, 0xab])),
            hostname: Some("test-host".to_string()),
            client_id: Some(vec![0x01, 0x23, 0x45]),
            expires,
            iaid: None,
            flags: LeaseFlags::empty(),
            interface: "eth0".to_string(),
            fqdn: None,
            vendorclass: None,
            agent_id: None,
            slaac_addresses: None,
        };

        // Write lease
        write_leases(path, &[lease], None).await.unwrap();

        // Read it back
        let leases = read_leases(path, now).await.unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(leases[0].hostname, Some("test-host".to_string()));
    }
}
