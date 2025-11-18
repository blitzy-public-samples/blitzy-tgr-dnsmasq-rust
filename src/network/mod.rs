// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Network layer for dnsmasq
//!
//! This module provides cross-platform networking abstractions for:
//! - Socket creation and management
//! - Interface enumeration
//! - Platform-specific network operations
//! - Firewall integration (ipset, nftables, PF)
//!
//! # Module Structure
//!
//! - `sockets`: Socket creation and management
//! - `interfaces`: Network interface enumeration
//! - `platform`: Platform-specific networking implementations
//! - `firewall`: Firewall integration (ipset, nftables, PF)
//! - `arp`: ARP table manipulation
//! - `conntrack`: Connection tracking integration
//!
//! # Platform Support
//!
//! - Linux: netlink-based interface monitoring, ipset, nftables
//! - BSD: BPF-based packet capture, PF tables
//! - macOS: BSD-style networking with macOS-specific extensions
//!
//! # Example
//!
//! ```no_run
//! use dnsmasq::network::{create_dns_socket, enumerate_interfaces};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create DNS socket
//! let socket = create_dns_socket("0.0.0.0:53").await?;
//!
//! // Enumerate network interfaces
//! let interfaces = enumerate_interfaces().await?;
//! for iface in interfaces {
//!     println!("Interface: {} ({})", iface.name, iface.index);
//! }
//! # Ok(())
//! # }
//! ```

use crate::error::{DnsmasqError, NetworkError, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

// Declare submodules
pub mod interfaces;
pub mod sockets;

// Platform-specific modules
#[cfg(target_os = "linux")]
pub mod platform;

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
pub mod platform;

// Optional feature modules
#[cfg(feature = "ipset")]
pub mod ipset;

#[cfg(feature = "nftset")]
pub mod nftset;

pub mod arp;

#[cfg(feature = "conntrack")]
pub mod conntrack;

// Re-export commonly used types (but not functions that have wrapper implementations below)
pub use interfaces::NetworkInterface;
pub use sockets::{DhcpSocket, DnsSocket};

/// Create a DNS socket bound to the specified address
///
/// # Arguments
///
/// * `addr` - Address to bind to (e.g., "0.0.0.0:53")
///
/// # Errors
///
/// Returns an error if the socket cannot be created or bound
///
/// # Example
///
/// ```no_run
/// use dnsmasq::network::create_dns_socket;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let socket = create_dns_socket("0.0.0.0:53").await?;
/// # Ok(())
/// # }
/// ```
pub async fn create_dns_socket(addr: &str) -> Result<UdpSocket> {
    let socket_addr: SocketAddr = addr.parse().map_err(|e| {
        DnsmasqError::Network(NetworkError::SocketFailed {
            address: addr.to_string(),
            reason: format!("Invalid address: {}", e),
        })
    })?;

    sockets::create_dns_socket(socket_addr).await
}

/// Create a DHCP socket bound to the specified address
///
/// # Arguments
///
/// * `addr` - Address to bind to (e.g., "0.0.0.0:67")
///
/// # Errors
///
/// Returns an error if the socket cannot be created or bound
pub async fn create_dhcp_socket(addr: &str) -> Result<UdpSocket> {
    let socket_addr: SocketAddr = addr.parse().map_err(|e| {
        DnsmasqError::Network(NetworkError::SocketFailed {
            address: addr.to_string(),
            reason: format!("Invalid address: {}", e),
        })
    })?;

    sockets::create_dhcp_socket(socket_addr).await
}

/// Enumerate all network interfaces
///
/// # Errors
///
/// Returns an error if interfaces cannot be enumerated
///
/// # Example
///
/// ```no_run
/// use dnsmasq::network::enumerate_interfaces;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let interfaces = enumerate_interfaces().await?;
/// for iface in interfaces {
///     println!("Interface: {} (index {})", iface.name, iface.index);
/// }
/// # Ok(())
/// # }
/// ```
pub async fn enumerate_interfaces() -> Result<Vec<NetworkInterface>> {
    interfaces::enumerate_interfaces().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_structure() {
        // Verify all submodules are accessible
        // This is a compile-time test - if it compiles, modules are correctly declared
    }

    #[tokio::test]
    async fn test_parse_dns_address() {
        let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
        assert_eq!(addr.port(), 53);
    }

    #[tokio::test]
    async fn test_parse_dhcp_address() {
        let addr: SocketAddr = "0.0.0.0:67".parse().unwrap();
        assert_eq!(addr.port(), 67);
    }
}
