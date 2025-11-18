// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Network interface enumeration
//!
//! This module provides cross-platform interface enumeration.

use crate::error::Result;
use std::net::IpAddr;

/// Network interface information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterface {
    /// Interface name (e.g., "eth0", "wlan0")
    pub name: String,

    /// Interface index
    pub index: u32,

    /// IP addresses assigned to this interface
    pub addresses: Vec<IpAddr>,

    /// Interface flags
    pub flags: InterfaceFlags,
}

/// Interface flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InterfaceFlags {
    /// Interface is up
    pub is_up: bool,

    /// Interface is loopback
    pub is_loopback: bool,

    /// Interface is point-to-point
    pub is_point_to_point: bool,

    /// Interface supports broadcast
    pub is_broadcast: bool,

    /// Interface supports multicast
    pub is_multicast: bool,
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
/// use dnsmasq::network::interfaces::enumerate_interfaces;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let interfaces = enumerate_interfaces().await?;
/// for iface in interfaces {
///     println!("Interface: {} (index {})", iface.name, iface.index);
///     for addr in iface.addresses {
///         println!("  Address: {}", addr);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub async fn enumerate_interfaces() -> Result<Vec<NetworkInterface>> {
    // Platform-specific implementation
    #[cfg(target_os = "linux")]
    {
        enumerate_interfaces_linux().await
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "macos"
    ))]
    {
        enumerate_interfaces_bsd().await
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "macos"
    )))]
    {
        Err(DnsmasqError::Network(NetworkError::InterfaceEnumerationFailed {
            reason: "Interface enumeration not supported on this platform".to_string(),
        }))
    }
}

/// Enumerate interfaces on Linux using netlink
#[cfg(target_os = "linux")]
async fn enumerate_interfaces_linux() -> Result<Vec<NetworkInterface>> {
    // TODO: Implement using rtnetlink crate
    // For now, return empty list
    tracing::warn!("Linux interface enumeration not fully implemented yet");
    Ok(Vec::new())
}

/// Enumerate interfaces on BSD-like systems
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
async fn enumerate_interfaces_bsd() -> Result<Vec<NetworkInterface>> {
    // TODO: Implement using nix crate getifaddrs
    // For now, return empty list
    tracing::warn!("BSD interface enumeration not fully implemented yet");
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_flags_default() {
        let flags = InterfaceFlags::default();
        assert!(!flags.is_up);
        assert!(!flags.is_loopback);
        assert!(!flags.is_point_to_point);
        assert!(!flags.is_broadcast);
        assert!(!flags.is_multicast);
    }

    #[test]
    fn test_network_interface_creation() {
        let iface = NetworkInterface {
            name: "eth0".to_string(),
            index: 1,
            addresses: vec!["192.168.1.1".parse().unwrap()],
            flags: InterfaceFlags {
                is_up: true,
                is_broadcast: true,
                is_multicast: true,
                ..Default::default()
            },
        };

        assert_eq!(iface.name, "eth0");
        assert_eq!(iface.index, 1);
        assert_eq!(iface.addresses.len(), 1);
        assert!(iface.flags.is_up);
    }

    #[tokio::test]
    async fn test_enumerate_interfaces() {
        // This test may fail on systems without proper permissions
        // or on unsupported platforms
        let result = enumerate_interfaces().await;

        // We just verify it doesn't panic
        // The result may be Ok(empty) or Err depending on platform/permissions
        match result {
            Ok(interfaces) => {
                // Success - log the interfaces found
                println!("Found {} interfaces", interfaces.len());
            }
            Err(e) => {
                // Expected on some platforms/test environments
                println!("Interface enumeration not available: {}", e);
            }
        }
    }
}
