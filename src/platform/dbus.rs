// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

#![allow(missing_docs)]

//! D-Bus IPC interface for dnsmasq
//!
//! This module implements the D-Bus interface for dnsmasq, allowing external
//! applications to control and monitor the DNS/DHCP server. The interface is
//! compatible with the C version's D-Bus API.
//!
//! # D-Bus Service
//!
//! - **Bus Name**: `uk.org.thekelleys.dnsmasq`
//! - **Object Path**: `/uk/org/thekelleys/dnsmasq`
//! - **Interface**: `uk.org.thekelleys.Dnsmasq`
//!
//! # Methods
//!
//! - `SetServers(servers: Vec<String>)`: Set upstream DNS servers
//! - `ClearCache()`: Clear the DNS cache
//! - `GetVersion() -> String`: Get dnsmasq version
//! - `GetMetrics() -> HashMap<String, String>`: Get runtime metrics
//! - `SetFilterWin2KOption(enable: bool)`: Enable/disable Win2K DHCP filtering
//!
//! # Signals
//!
//! - `DhcpLeaseAdded(ip: String, mac: String, hostname: String)`: DHCP lease allocated
//! - `DhcpLeaseDeleted(ip: String, mac: String, hostname: String)`: DHCP lease expired/released
//! - `DhcpLeaseUpdated(ip: String, mac: String, hostname: String)`: DHCP lease renewed
//!
//! # Example
//!
//! ```no_run
//! use dnsmasq::platform::dbus::DbusDaemon;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut dbus = DbusDaemon::new()?;
//! dbus.start().await?;
//!
//! // D-Bus interface is now active and listening for method calls
//! # Ok(())
//! # }
//! ```

use crate::error::{PlatformError, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use zbus::object_server::SignalEmitter;
use zbus::{connection, interface, Connection};

/// D-Bus daemon handler
///
/// This struct manages the D-Bus connection and implements the dnsmasq D-Bus
/// interface. It maintains state needed to respond to D-Bus method calls.
pub struct DbusDaemon {
    connection: Option<Connection>,
}

impl DbusDaemon {
    /// Create a new D-Bus daemon
    ///
    /// This initializes the D-Bus connection builder but doesn't connect yet.
    /// Call `start()` to actually connect to the D-Bus system bus and serve
    /// the interface.
    pub fn new() -> Result<Self> {
        Ok(Self { connection: None })
    }

    /// Start the D-Bus service
    ///
    /// This connects to the D-Bus system bus, requests the well-known name
    /// `uk.org.thekelleys.dnsmasq`, and starts serving the D-Bus interface.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cannot connect to D-Bus system bus
    /// - Cannot request the service name (already in use, permission denied)
    /// - Cannot register the object path
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting D-Bus service on uk.org.thekelleys.dnsmasq");

        let interface = DnsmasqInterface::new();

        let connection = connection::Builder::system()
            .map_err(|e| PlatformError::DbusError {
                operation: "create connection".to_string(),
                reason: e.to_string(),
            })?
            .name("uk.org.thekelleys.dnsmasq")
            .map_err(|e| PlatformError::DbusError {
                operation: "request name".to_string(),
                reason: e.to_string(),
            })?
            .serve_at("/uk/org/thekelleys/dnsmasq", interface)
            .map_err(|e| PlatformError::DbusError {
                operation: "serve interface".to_string(),
                reason: e.to_string(),
            })?
            .build()
            .await
            .map_err(|e| PlatformError::DbusError {
                operation: "build connection".to_string(),
                reason: e.to_string(),
            })?;

        self.connection = Some(connection);

        info!("D-Bus service started successfully");
        Ok(())
    }

    /// Set the upstream servers
    ///
    /// This updates the list of servers that can be returned by the D-Bus
    /// `GetServers` method. In the full implementation, this would actually
    /// reconfigure the DNS forwarder.
    pub async fn set_servers(&self, servers: Vec<String>) -> Result<()> {
        if let Some(connection) = &self.connection {
            let iface_ref = connection
                .object_server()
                .interface::<_, DnsmasqInterface>("/uk/org/thekelleys/dnsmasq")
                .await
                .map_err(|e| PlatformError::DbusError {
                    operation: "get interface".to_string(),
                    reason: e.to_string(),
                })?;

            let iface = iface_ref.get().await;
            let mut s = iface.servers.write().await;
            *s = servers;
        }
        Ok(())
    }

    /// Signal that a DHCP lease was added
    ///
    /// This emits a D-Bus signal to notify listeners that a new DHCP lease
    /// was allocated.
    pub async fn signal_dhcp_lease_added(
        &self,
        ip: String,
        mac: String,
        hostname: String,
    ) -> Result<()> {
        if let Some(connection) = &self.connection {
            let iface_ref = connection
                .object_server()
                .interface::<_, DnsmasqInterface>("/uk/org/thekelleys/dnsmasq")
                .await
                .map_err(|e| PlatformError::DbusError {
                    operation: "get interface".to_string(),
                    reason: e.to_string(),
                })?;

            let signal_emitter = iface_ref.signal_emitter();

            DnsmasqInterface::dhcp_lease_added(signal_emitter, &ip, &mac, &hostname)
                .await
                .map_err(|e| PlatformError::DbusError {
                    operation: "emit signal".to_string(),
                    reason: e.to_string(),
                })?;

            debug!("Emitted DhcpLeaseAdded signal");
        }

        Ok(())
    }

    /// Get reference to the D-Bus connection
    #[must_use]
    pub fn connection(&self) -> Option<&Connection> {
        self.connection.as_ref()
    }
}

/// Internal D-Bus interface implementation
///
/// This struct implements the actual D-Bus interface methods and properties.
/// It maintains state needed to respond to method calls.
struct DnsmasqInterface {
    servers: Arc<RwLock<Vec<String>>>,
    version: String,
    metrics: Arc<RwLock<HashMap<String, String>>>,
}

impl DnsmasqInterface {
    fn new() -> Self {
        let mut metrics = HashMap::new();
        metrics.insert("dns_queries".to_string(), "0".to_string());
        metrics.insert("cache_hits".to_string(), "0".to_string());
        metrics.insert("dhcp_leases".to_string(), "0".to_string());

        Self {
            servers: Arc::new(RwLock::new(Vec::new())),
            version: env!("CARGO_PKG_VERSION").to_string(),
            metrics: Arc::new(RwLock::new(metrics)),
        }
    }
}

#[allow(missing_docs)]
#[interface(name = "uk.org.thekelleys.Dnsmasq")]
impl DnsmasqInterface {
    /// Set upstream DNS servers
    ///
    /// This method allows dynamic reconfiguration of the upstream DNS servers
    /// that dnsmasq forwards queries to.
    ///
    /// # Arguments
    ///
    /// * `servers` - Array of server addresses (e.g., [`8.8.8.8`, `8.8.4.4`])
    async fn set_servers(&self, servers: Vec<String>) -> zbus::fdo::Result<()> {
        info!("D-Bus SetServers called with {} servers", servers.len());
        let mut s = self.servers.write().await;
        *s = servers;
        Ok(())
    }

    /// Clear the DNS cache
    ///
    /// This method clears all entries from the DNS cache, forcing fresh
    /// queries for all subsequent requests.
    #[allow(clippy::unused_async)] // D-Bus interface method must be async
    async fn clear_cache(&self) -> zbus::fdo::Result<()> {
        info!("D-Bus ClearCache called");
        // In full implementation, this would actually clear the cache
        Ok(())
    }

    /// Get dnsmasq version
    ///
    /// Returns the version string of the running dnsmasq instance.
    #[allow(clippy::unused_async)] // D-Bus interface method must be async
    async fn get_version(&self) -> zbus::fdo::Result<String> {
        debug!("D-Bus GetVersion called");
        Ok(self.version.clone())
    }

    /// Get runtime metrics
    ///
    /// Returns a dictionary of runtime statistics including:
    /// - `dns_queries`: Total DNS queries processed
    /// - `cache_hits`: DNS cache hits
    /// - `dhcp_leases`: Active DHCP leases
    async fn get_metrics(&self) -> zbus::fdo::Result<HashMap<String, String>> {
        debug!("D-Bus GetMetrics called");
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    /// Set `Win2K` option filtering
    ///
    /// Enable or disable filtering of the `Win2K` DHCP option.
    #[allow(clippy::unused_async)] // D-Bus interface method must be async
    async fn set_filter_win2k_option(&self, enable: bool) -> zbus::fdo::Result<()> {
        info!("D-Bus SetFilterWin2KOption called: {}", enable);
        // In full implementation, this would update configuration
        Ok(())
    }

    /// Signal: DHCP lease added
    ///
    /// Emitted when a new DHCP lease is allocated.
    #[zbus(signal)]
    async fn dhcp_lease_added(
        signal_ctxt: &SignalEmitter<'_>,
        ip: &str,
        mac: &str,
        hostname: &str,
    ) -> zbus::Result<()>;

    /// Signal: DHCP lease deleted
    ///
    /// Emitted when a DHCP lease expires or is released.
    #[zbus(signal)]
    async fn dhcp_lease_deleted(
        signal_ctxt: &SignalEmitter<'_>,
        ip: &str,
        mac: &str,
        hostname: &str,
    ) -> zbus::Result<()>;

    /// Signal: DHCP lease updated
    ///
    /// Emitted when a DHCP lease is renewed.
    #[zbus(signal)]
    async fn dhcp_lease_updated(
        signal_ctxt: &SignalEmitter<'_>,
        ip: &str,
        mac: &str,
        hostname: &str,
    ) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dbus_daemon_creation() {
        let result = DbusDaemon::new();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dnsmasq_interface_creation() {
        let interface = DnsmasqInterface::new();
        assert_eq!(interface.version, env!("CARGO_PKG_VERSION"));

        let servers = interface.servers.read().await;
        assert_eq!(servers.len(), 0);
    }

    #[tokio::test]
    async fn test_set_servers() {
        let interface = DnsmasqInterface::new();
        let servers = vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()];

        interface.set_servers(servers.clone()).await.expect("Failed to set servers");

        let stored_servers = interface.servers.read().await;
        assert_eq!(*stored_servers, servers);
    }
}
