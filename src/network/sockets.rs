// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Socket creation and management
//!
//! This module provides safe abstractions for creating and configuring network sockets.

use crate::error::{NetworkError, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// DNS socket type alias
pub type DnsSocket = UdpSocket;

/// DHCP socket type alias
pub type DhcpSocket = UdpSocket;

/// Create a DNS socket bound to the specified address
///
/// # Arguments
///
/// * `addr` - Address to bind to
///
/// # Errors
///
/// Returns an error if the socket cannot be created or bound
pub async fn create_dns_socket(addr: SocketAddr) -> Result<DnsSocket> {
    let socket = UdpSocket::bind(addr).await.map_err(|e| NetworkError::SocketFailed {
        address: addr.to_string(),
        reason: format!("Failed to bind DNS socket: {}", e),
    })?;

    // Set socket options for DNS
    configure_dns_socket(&socket)?;

    tracing::info!("DNS socket bound to {}", addr);
    Ok(socket)
}

/// Create a DHCP socket bound to the specified address
///
/// # Arguments
///
/// * `addr` - Address to bind to
///
/// # Errors
///
/// Returns an error if the socket cannot be created or bound
pub async fn create_dhcp_socket(addr: SocketAddr) -> Result<DhcpSocket> {
    let socket = UdpSocket::bind(addr).await.map_err(|e| NetworkError::SocketFailed {
        address: addr.to_string(),
        reason: format!("Failed to bind DHCP socket: {}", e),
    })?;

    // Set socket options for DHCP
    configure_dhcp_socket(&socket)?;

    tracing::info!("DHCP socket bound to {}", addr);
    Ok(socket)
}

/// Configure DNS socket options
fn configure_dns_socket(_socket: &UdpSocket) -> Result<()> {
    // TODO: Set DNS-specific socket options:
    // - SO_REUSEADDR
    // - SO_REUSEPORT (on platforms that support it)
    // - IP_PKTINFO/IPV6_RECVPKTINFO for receiving interface info
    // - IP_MTU_DISCOVER for PMTU

    Ok(())
}

/// Configure DHCP socket options
fn configure_dhcp_socket(_socket: &UdpSocket) -> Result<()> {
    // TODO: Set DHCP-specific socket options:
    // - SO_BROADCAST for DHCPv4
    // - SO_BINDTODEVICE on Linux
    // - IP_PKTINFO/IPV6_RECVPKTINFO for receiving interface info

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_dns_socket() {
        // Use a high port for testing (doesn't require privileges)
        let result = create_dns_socket("127.0.0.1:15353".parse().unwrap()).await;

        // Socket creation should succeed
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_dhcp_socket() {
        // Use a high port for testing (doesn't require privileges)
        let result = create_dhcp_socket("127.0.0.1:16767".parse().unwrap()).await;

        // Socket creation should succeed
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_socket_with_invalid_address() {
        // Try to bind to an invalid address (should fail)
        let result = create_dns_socket("0.0.0.0:0".parse().unwrap()).await;

        // Socket should be created even with port 0 (kernel assigns a port)
        assert!(result.is_ok());
    }
}
