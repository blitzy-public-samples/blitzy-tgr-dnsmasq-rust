// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! OpenWrt ubus integration
//!
//! This module provides integration with OpenWrt's ubus (micro bus) IPC system.
//! ubus is a lightweight message bus used in OpenWrt for inter-process
//! communication, similar to D-Bus but designed for embedded systems.
//!
//! # ubus Service
//!
//! - **Service Name**: `dnsmasq`
//! - **Objects**: Various objects for DNS and DHCP control
//!
//! # Methods
//!
//! DNS methods:
//! - `dns.cache_clear`: Clear DNS cache
//! - `dns.cache_dump`: Dump DNS cache contents
//! - `dns.servers_set`: Set upstream DNS servers
//!
//! DHCP methods:
//! - `dhcp.leases`: Get list of DHCP leases
//! - `dhcp.lease_add`: Add static DHCP lease
//! - `dhcp.lease_del`: Remove static DHCP lease
//!
//! System methods:
//! - `system.version`: Get dnsmasq version
//! - `system.metrics`: Get runtime metrics
//! - `system.reload`: Reload configuration
//!
//! # Example
//!
//! ```no_run
//! use dnsmasq::platform::ubus::UbusDaemon;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut ubus = UbusDaemon::new().await?;
//! ubus.start().await?;
//!
//! // ubus interface is now active
//! # Ok(())
//! # }
//! ```
//!
//! # Platform Support
//!
//! This module is only useful on OpenWrt systems. On other platforms, it
//! compiles but has no effect.

use crate::error::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// ubus daemon handler
///
/// This struct manages the ubus connection and implements the dnsmasq ubus
/// service. It maintains state needed to respond to ubus method calls.
pub struct UbusDaemon {
    state: Arc<UbusState>,
    connected: bool,
}

/// Internal state for ubus daemon
struct UbusState {
    servers: RwLock<Vec<String>>,
    version: String,
    metrics: RwLock<HashMap<String, String>>,
}

impl UbusDaemon {
    /// Create a new ubus daemon
    ///
    /// This initializes the ubus state but doesn't connect yet.
    /// Call `start()` to actually connect to ubus and register the service.
    pub async fn new() -> Result<Self> {
        let mut metrics = HashMap::new();
        metrics.insert("dns_queries".to_string(), "0".to_string());
        metrics.insert("cache_hits".to_string(), "0".to_string());
        metrics.insert("dhcp_leases".to_string(), "0".to_string());

        let state = Arc::new(UbusState {
            servers: RwLock::new(Vec::new()),
            version: env!("CARGO_PKG_VERSION").to_string(),
            metrics: RwLock::new(metrics),
        });

        Ok(Self { state, connected: false })
    }

    /// Start the ubus service
    ///
    /// This connects to the ubus daemon and registers the dnsmasq service
    /// with all its methods.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cannot connect to ubus daemon (not running, permission denied)
    /// - Cannot register the service (already registered)
    ///
    /// # Implementation Note
    ///
    /// The actual ubus integration requires libubus C library bindings or
    /// a pure Rust implementation. This is a placeholder that demonstrates
    /// the API but doesn't make actual ubus calls. A full implementation
    /// would use FFI to libubus or a Rust ubus library.
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting ubus service on dnsmasq");

        // In a full implementation, this would:
        // 1. Connect to ubus daemon via Unix socket
        // 2. Register service "dnsmasq"
        // 3. Add all method handlers
        // 4. Start event loop

        // Placeholder: Just mark as connected
        self.connected = true;

        info!("ubus service started (placeholder implementation)");
        warn!("Full ubus integration requires libubus bindings or pure Rust implementation");

        Ok(())
    }

    /// Clear DNS cache (ubus method handler)
    ///
    /// Handler for `dns.cache_clear` ubus method.
    pub async fn dns_cache_clear(&self) -> Result<()> {
        info!("ubus: dns.cache_clear called");

        // In full implementation, this would clear the actual DNS cache
        // For now, just log the call
        debug!("DNS cache clear requested via ubus");

        Ok(())
    }

    /// Dump DNS cache (ubus method handler)
    ///
    /// Handler for `dns.cache_dump` ubus method.
    /// Returns cache contents as a JSON-serializable structure.
    pub async fn dns_cache_dump(&self) -> Result<Vec<HashMap<String, String>>> {
        info!("ubus: dns.cache_dump called");

        // In full implementation, this would return actual cache contents
        // For now, return empty list
        debug!("DNS cache dump requested via ubus");

        Ok(Vec::new())
    }

    /// Set upstream DNS servers (ubus method handler)
    ///
    /// Handler for `dns.servers_set` ubus method.
    ///
    /// # Arguments
    ///
    /// * `servers` - Array of server addresses
    pub async fn dns_servers_set(&self, servers: Vec<String>) -> Result<()> {
        info!("ubus: dns.servers_set called with {} servers", servers.len());

        let mut s = self.state.servers.write().await;
        *s = servers;

        debug!("Updated upstream servers via ubus");

        Ok(())
    }

    /// Get DHCP leases (ubus method handler)
    ///
    /// Handler for `dhcp.leases` ubus method.
    /// Returns list of active DHCP leases.
    pub async fn dhcp_leases(&self) -> Result<Vec<HashMap<String, String>>> {
        info!("ubus: dhcp.leases called");

        // In full implementation, this would return actual lease data
        // For now, return empty list
        debug!("DHCP leases requested via ubus");

        Ok(Vec::new())
    }

    /// Add static DHCP lease (ubus method handler)
    ///
    /// Handler for `dhcp.lease_add` ubus method.
    ///
    /// # Arguments
    ///
    /// * `mac` - MAC address
    /// * `ip` - IP address
    /// * `hostname` - Optional hostname
    pub async fn dhcp_lease_add(
        &self,
        mac: String,
        ip: String,
        hostname: Option<String>,
    ) -> Result<()> {
        info!("ubus: dhcp.lease_add called - MAC: {}, IP: {}, hostname: {:?}", mac, ip, hostname);

        // In full implementation, this would add the lease to configuration
        debug!("Static DHCP lease addition requested via ubus");

        Ok(())
    }

    /// Remove static DHCP lease (ubus method handler)
    ///
    /// Handler for `dhcp.lease_del` ubus method.
    ///
    /// # Arguments
    ///
    /// * `mac` - MAC address of lease to remove
    pub async fn dhcp_lease_del(&self, mac: String) -> Result<()> {
        info!("ubus: dhcp.lease_del called - MAC: {}", mac);

        // In full implementation, this would remove the lease from configuration
        debug!("Static DHCP lease removal requested via ubus");

        Ok(())
    }

    /// Get version (ubus method handler)
    ///
    /// Handler for `system.version` ubus method.
    /// Returns the dnsmasq version string.
    pub async fn system_version(&self) -> Result<String> {
        debug!("ubus: system.version called");
        Ok(self.state.version.clone())
    }

    /// Get metrics (ubus method handler)
    ///
    /// Handler for `system.metrics` ubus method.
    /// Returns runtime metrics as a dictionary.
    pub async fn system_metrics(&self) -> Result<HashMap<String, String>> {
        debug!("ubus: system.metrics called");
        let metrics = self.state.metrics.read().await;
        Ok(metrics.clone())
    }

    /// Reload configuration (ubus method handler)
    ///
    /// Handler for `system.reload` ubus method.
    /// Triggers a configuration reload (equivalent to SIGHUP).
    pub async fn system_reload(&self) -> Result<()> {
        info!("ubus: system.reload called");

        // In full implementation, this would trigger config reload
        debug!("Configuration reload requested via ubus");

        Ok(())
    }

    /// Check if connected to ubus
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

/// ubus method result
///
/// This represents the result of a ubus method call in the format expected
/// by ubus clients.
#[derive(Debug, Clone)]
pub struct UbusResult {
    /// Status code indicating success or error type
    pub status: i32,
    /// Optional data payload or error message
    pub data: Option<String>,
}

impl UbusResult {
    /// Create a success result
    pub fn success() -> Self {
        Self { status: 0, data: None }
    }

    /// Create a success result with data
    pub fn success_with_data(data: String) -> Self {
        Self { status: 0, data: Some(data) }
    }

    /// Create an error result
    pub fn error(status: i32, message: String) -> Self {
        Self { status, data: Some(message) }
    }
}

/// ubus error codes
///
/// Standard ubus error codes used in method responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UbusError {
    /// Operation completed successfully
    Success = 0,
    /// Invalid command received
    InvalidCommand = 1,
    /// Invalid argument provided
    InvalidArgument = 2,
    /// Requested method not found
    MethodNotFound = 3,
    /// Requested object not found
    NotFound = 4,
    /// No data available
    NoData = 5,
    /// Permission denied for operation
    PermissionDenied = 6,
    /// Operation timed out
    Timeout = 7,
    /// Operation not supported
    NotSupported = 8,
    /// Unknown error occurred
    Unknown = 9,
    /// Connection to ubus daemon failed
    ConnectionFailed = 10,
}

impl From<UbusError> for i32 {
    fn from(error: UbusError) -> i32 {
        error as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ubus_daemon_creation() {
        let result = UbusDaemon::new().await;
        assert!(result.is_ok());

        let daemon = result.unwrap();
        assert!(!daemon.is_connected());
    }

    #[tokio::test]
    async fn test_ubus_daemon_start() {
        let mut daemon = UbusDaemon::new().await.unwrap();
        let result = daemon.start().await;
        assert!(result.is_ok());
        assert!(daemon.is_connected());
    }

    #[tokio::test]
    async fn test_dns_servers_set() {
        let daemon = UbusDaemon::new().await.unwrap();
        let servers = vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()];

        let result = daemon.dns_servers_set(servers.clone()).await;
        assert!(result.is_ok());

        let stored_servers = daemon.state.servers.read().await;
        assert_eq!(*stored_servers, servers);
    }

    #[tokio::test]
    async fn test_system_version() {
        let daemon = UbusDaemon::new().await.unwrap();
        let version = daemon.system_version().await.unwrap();
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_ubus_result_creation() {
        let success = UbusResult::success();
        assert_eq!(success.status, 0);
        assert!(success.data.is_none());

        let with_data = UbusResult::success_with_data("test".to_string());
        assert_eq!(with_data.status, 0);
        assert_eq!(with_data.data, Some("test".to_string()));

        let error = UbusResult::error(1, "error message".to_string());
        assert_eq!(error.status, 1);
        assert_eq!(error.data, Some("error message".to_string()));
    }

    #[test]
    fn test_ubus_error_codes() {
        assert_eq!(i32::from(UbusError::Success), 0);
        assert_eq!(i32::from(UbusError::InvalidCommand), 1);
        assert_eq!(i32::from(UbusError::PermissionDenied), 6);
    }
}
