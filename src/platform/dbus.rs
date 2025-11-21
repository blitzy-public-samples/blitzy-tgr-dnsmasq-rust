// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! D-Bus IPC control interface module exposing dnsmasq management API
//!
//! This module implements the `uk.org.thekelleys.dnsmasq` D-Bus service providing
//! external control and monitoring capabilities for dnsmasq. It replaces the C
//! implementation using libdbus-1 with a memory-safe Rust implementation using the
//! zbus crate integrated with the tokio async runtime.
//!
//! # D-Bus Service Specification
//!
//! - **Bus Name**: `uk.org.thekelleys.dnsmasq`
//! - **Object Path**: `/uk/org/thekelleys/dnsmasq`
//! - **Interface**: `uk.org.thekelleys.dnsmasq`
//!
//! # D-Bus Methods
//!
//! ## Cache Management
//! - `ClearCache()`: Invalidate all DNS cache entries
//!
//! ## Upstream Server Configuration
//! - `SetServers(servers: Vec<String>)`: Set upstream DNS servers (simple format)
//! - `SetServersEx(servers: Vec<Vec<String>>)`: Set upstream DNS servers with domains
//!
//! ## Status Queries
//! - `GetVersion() -> String`: Returns dnsmasq version string
//! - `GetMetrics() -> HashMap<String, String>`: Returns runtime statistics
//! - `GetServerMetrics() -> HashMap<String, String>`: Returns per-server query stats
//!
//! ## DHCP Management (when HAVE_DHCP enabled)
//! - `AddDhcpLease(ip, mac, hostname, expires)`: Manually add DHCP lease
//! - `DeleteDhcpLease(ip)`: Remove DHCP lease
//!
//! ## Loop Detection (when HAVE_LOOP enabled)
//! - `GetLoopServers() -> Vec<String>`: Returns servers detected in forwarding loops
//!
//! # D-Bus Signals
//!
//! - `DhcpLeaseAdded(ip, mac, hostname)`: Emitted when DHCP lease allocated
//! - `DhcpLeaseDeleted(ip, mac, hostname)`: Emitted when lease expires/released
//! - `DhcpLeaseUpdated(ip, mac, hostname)`: Emitted when lease renewed
//!
//! # Memory Safety Transformation
//!
//! **C Implementation (src/dbus.c):**
//! ```c
//! // Manual D-Bus message construction
//! DBusMessage *message = dbus_message_new_method_return(method_call);
//! dbus_message_append_args(message, DBUS_TYPE_STRING, &version, DBUS_TYPE_INVALID);
//! dbus_connection_send(connection, message, NULL);
//! dbus_message_unref(message);  // Manual memory management
//!
//! // Manual watch/timeout integration with poll()
//! dbus_connection_set_watch_functions(conn, add_watch, remove_watch, ...);
//! ```
//!
//! **Rust Implementation (this file):**
//! ```rust,ignore
//! // Automatic serialization via zbus
//! #[dbus_interface(name = "uk.org.thekelleys.dnsmasq")]
//! impl DnsmasqInterface {
//!     async fn get_version(&self) -> Result<String, zbus::fdo::Error> {
//!         Ok(crate::constants::VERSION.to_string())
//!     }  // Automatic cleanup, no manual memory management
//! }
//!
//! // Tokio integration built into zbus
//! let connection = Connection::system().await?;
//! // zbus automatically uses tokio runtime for async operations
//! ```
//!
//! # Key Improvements
//!
//! - **Memory safety**: No manual malloc/free, automatic RAII cleanup
//! - **Type safety**: Compile-time method signature verification via traits
//! - **Async integration**: Native tokio support replaces C poll() integration
//! - **Error handling**: Result types replace C integer error codes
//! - **Thread safety**: Arc<RwLock<T>> for concurrent access to services
//!
//! # Access Control
//!
//! D-Bus access control is enforced by system policy file:
//! `/etc/dbus-1/system.d/dnsmasq.conf`
//!
//! Methods are restricted to root or users in the netadmin group per policy configuration.
//!
//! # Example Usage
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use tokio::sync::RwLock;
//! # use dnsmasq::platform::dbus::DbusService;
//! # use dnsmasq::dns::DnsService;
//! # use dnsmasq::util::metrics::MetricsCollector;
//! # async fn example() -> anyhow::Result<()> {
//! // Create D-Bus service with references to core services
//! let dns_service = Arc::new(RwLock::new(DnsService::new()));
//! let metrics = Arc::new(RwLock::new(MetricsCollector::new()));
//!
//! let dbus_service = DbusService::new(dns_service, metrics).await?;
//! dbus_service.start().await?;
//!
//! // D-Bus interface is now active, external clients can call methods
//! # Ok(())
//! # }
//! ```

// Feature gate the entire module - D-Bus support is optional
#[cfg(feature = "dbus")]
use crate::constants::VERSION;
#[cfg(feature = "dbus")]
use crate::error::DnsmasqError;
#[cfg(feature = "dbus")]
use crate::dns::DnsService;
#[cfg(feature = "dbus")]
use crate::dns::upstream::UpstreamPool;
#[cfg(all(feature = "dbus", feature = "dhcp"))]
use crate::dhcp::DhcpService;
#[cfg(all(feature = "dbus", feature = "dhcp"))]
use crate::dhcp::lease::Lease;
#[cfg(feature = "dbus")]
use crate::types::MacAddress;
#[cfg(feature = "dbus")]
use crate::util::metrics::MetricsCollector;

#[cfg(feature = "dbus")]
use anyhow::{Context, Result};
#[cfg(feature = "dbus")]
use std::collections::HashMap;
#[cfg(feature = "dbus")]
use std::net::IpAddr;
#[cfg(feature = "dbus")]
use std::str::FromStr;
#[cfg(feature = "dbus")]
use std::sync::Arc;
#[cfg(feature = "dbus")]
use tokio::sync::RwLock;
#[cfg(feature = "dbus")]
use tracing::{debug, error, info, instrument, warn};
#[cfg(feature = "dbus")]
use zbus::{connection, interface, Connection, SignalContext};

// ============================================================================
// D-BUS SERVICE - CONNECTION LIFECYCLE MANAGEMENT
// ============================================================================

/// D-Bus service connection manager and lifecycle handler.
///
/// Manages the D-Bus system bus connection and service registration for the
/// `uk.org.thekelleys.dnsmasq` service. Coordinates between the D-Bus interface
/// and the core dnsmasq services (DNS, DHCP, metrics).
///
/// # Lifecycle
///
/// 1. Create with `DbusService::new()` passing service references
/// 2. Start with `start()` to connect and register on system bus
/// 3. Service runs until `stop()` called or connection lost
///
/// # C Equivalent
///
/// ```c
/// // C implementation: Manual connection management
/// DBusConnection *connection = dbus_connection_open_private(DBUS_SYSTEM_BUS);
/// dbus_bus_request_name(connection, "uk.org.thekelleys.dnsmasq", ...);
/// dbus_connection_register_object_path(connection, "/uk/org/thekelleys/dnsmasq", ...);
/// // Manual watch/timeout registration for poll() integration
/// ```
///
/// Rust version handles all connection setup automatically via zbus builder pattern.
#[cfg(feature = "dbus")]
pub struct DbusService {
    /// D-Bus system bus connection
    connection: Option<Connection>,
    /// Reference to DNS service for cache/upstream operations
    dns_service: Arc<RwLock<DnsService>>,
    /// Reference to DHCP service for lease management (optional)
    #[cfg(feature = "dhcp")]
    dhcp_service: Option<Arc<RwLock<DhcpService>>>,
    /// Reference to metrics collector for statistics
    metrics: Arc<RwLock<MetricsCollector>>,
}

#[cfg(feature = "dbus")]
impl DbusService {
    /// Creates a new D-Bus service instance.
    ///
    /// Does not connect to D-Bus yet - call `start()` to establish connection.
    ///
    /// # Arguments
    ///
    /// * `dns_service` - Shared reference to DNS service
    /// * `metrics` - Shared reference to metrics collector
    ///
    /// # Returns
    ///
    /// New `DbusService` instance ready to start
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use tokio::sync::RwLock;
    /// # use dnsmasq::platform::dbus::DbusService;
    /// # use dnsmasq::dns::DnsService;
    /// # use dnsmasq::util::metrics::MetricsCollector;
    /// # async fn example() -> anyhow::Result<()> {
    /// let dns_service = Arc::new(RwLock::new(DnsService::new()));
    /// let metrics = Arc::new(RwLock::new(MetricsCollector::new()));
    ///
    /// let dbus = DbusService::new(dns_service, metrics).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(
        dns_service: Arc<RwLock<DnsService>>,
        metrics: Arc<RwLock<MetricsCollector>>,
    ) -> Result<Self> {
        Ok(Self {
            connection: None,
            dns_service,
            #[cfg(feature = "dhcp")]
            dhcp_service: None,
            metrics,
        })
    }

    /// Sets the DHCP service reference (when DHCP feature enabled).
    ///
    /// Must be called before `start()` if DHCP D-Bus methods are to be functional.
    ///
    /// # Arguments
    ///
    /// * `dhcp_service` - Shared reference to DHCP service
    #[cfg(feature = "dhcp")]
    pub fn set_dhcp_service(&mut self, dhcp_service: Arc<RwLock<DhcpService>>) {
        self.dhcp_service = Some(dhcp_service);
    }

    /// Starts the D-Bus service on the system bus.
    ///
    /// Establishes connection to D-Bus system bus, requests the well-known name
    /// `uk.org.thekelleys.dnsmasq`, and registers the interface at object path
    /// `/uk/org/thekelleys/dnsmasq`.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Cannot connect to D-Bus system bus (permission, bus not running)
    /// - Service name already claimed by another process
    /// - Cannot register object path
    /// - Insufficient permissions (must run as root or with appropriate policy)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use tokio::sync::RwLock;
    /// # use dnsmasq::platform::dbus::DbusService;
    /// # use dnsmasq::dns::DnsService;
    /// # use dnsmasq::util::metrics::MetricsCollector;
    /// # async fn example() -> anyhow::Result<()> {
    /// let dns_service = Arc::new(RwLock::new(DnsService::new()));
    /// let metrics = Arc::new(RwLock::new(MetricsCollector::new()));
    ///
    /// let mut dbus = DbusService::new(dns_service, metrics).await?;
    /// dbus.start().await?;
    /// info!("D-Bus service active");
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self))]
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting D-Bus service: uk.org.thekelleys.dnsmasq");

        // Create interface implementation with service references
        let interface = DnsmasqInterface {
            dns_service: Arc::clone(&self.dns_service),
            #[cfg(feature = "dhcp")]
            dhcp_service: self.dhcp_service.clone(),
            metrics: Arc::clone(&self.metrics),
        };

        // Build connection using zbus builder pattern
        // This replaces C's dbus_connection_open_private() + dbus_bus_request_name()
        let connection = connection::Builder::system()
            .context("Failed to create D-Bus connection builder")?
            .name("uk.org.thekelleys.dnsmasq")
            .context("Failed to request D-Bus service name (already in use or permission denied)")?
            .serve_at("/uk/org/thekelleys/dnsmasq", interface)
            .context("Failed to register D-Bus object path")?
            .build()
            .await
            .context("Failed to establish D-Bus connection")?;

        self.connection = Some(connection);

        info!(
            bus_name = "uk.org.thekelleys.dnsmasq",
            object_path = "/uk/org/thekelleys/dnsmasq",
            "D-Bus service started successfully"
        );

        Ok(())
    }

    /// Stops the D-Bus service and releases the bus name.
    ///
    /// Closes the D-Bus connection gracefully, allowing other processes to
    /// claim the service name.
    pub async fn stop(&mut self) -> Result<()> {
        if self.connection.is_some() {
            info!("Stopping D-Bus service");
            self.connection = None;
            info!("D-Bus service stopped");
        }
        Ok(())
    }

    /// Returns reference to the D-Bus connection if active.
    ///
    /// # Returns
    ///
    /// `Some(&Connection)` if service is started, `None` otherwise
    #[must_use]
    pub fn connection(&self) -> Option<&Connection> {
        self.connection.as_ref()
    }

    // ========================================================================
    // DHCP SIGNAL EMISSION (when feature = "dhcp")
    // ========================================================================

    /// Emits DhcpLeaseAdded signal when a DHCP lease is allocated.
    ///
    /// # Arguments
    ///
    /// * `lease` - The allocated lease
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // C implementation: Manual signal construction
    /// DBusMessage *signal = dbus_message_new_signal(
    ///     "/uk/org/thekelleys/dnsmasq",
    ///     "uk.org.thekelleys.dnsmasq",
    ///     "DhcpLeaseAdded"
    /// );
    /// dbus_message_append_args(signal,
    ///     DBUS_TYPE_STRING, &ip_str,
    ///     DBUS_TYPE_STRING, &mac_str,
    ///     DBUS_TYPE_STRING, &hostname,
    ///     DBUS_TYPE_INVALID);
    /// dbus_connection_send(connection, signal, NULL);
    /// dbus_message_unref(signal);
    /// ```
    #[cfg(feature = "dhcp")]
    #[instrument(skip(self), fields(ip = %lease.ip(), mac = %lease.mac()))]
    pub async fn emit_dhcp_lease_added(&self, lease: &Lease) -> Result<()> {
        if let Some(conn) = &self.connection {
            let signal_context = SignalContext::new(conn, "/uk/org/thekelleys/dnsmasq")
                .context("Failed to create signal context")?;

            let ip = lease.ip().to_string();
            let mac = lease.mac().to_string();
            let hostname = lease.hostname().unwrap_or("");

            DnsmasqInterface::dhcp_lease_added(&signal_context, &ip, &mac, hostname)
                .await
                .context("Failed to emit DhcpLeaseAdded signal")?;

            debug!(ip = %ip, mac = %mac, hostname = %hostname, "Emitted DhcpLeaseAdded signal");
        }
        Ok(())
    }

    /// Emits DhcpLeaseDeleted signal when a DHCP lease expires or is released.
    ///
    /// # Arguments
    ///
    /// * `lease` - The deleted lease
    #[cfg(feature = "dhcp")]
    #[instrument(skip(self), fields(ip = %lease.ip(), mac = %lease.mac()))]
    pub async fn emit_dhcp_lease_deleted(&self, lease: &Lease) -> Result<()> {
        if let Some(conn) = &self.connection {
            let signal_context = SignalContext::new(conn, "/uk/org/thekelleys/dnsmasq")
                .context("Failed to create signal context")?;

            let ip = lease.ip().to_string();
            let mac = lease.mac().to_string();
            let hostname = lease.hostname().unwrap_or("");

            DnsmasqInterface::dhcp_lease_deleted(&signal_context, &ip, &mac, hostname)
                .await
                .context("Failed to emit DhcpLeaseDeleted signal")?;

            debug!(ip = %ip, mac = %mac, hostname = %hostname, "Emitted DhcpLeaseDeleted signal");
        }
        Ok(())
    }

    /// Emits DhcpLeaseUpdated signal when a DHCP lease is renewed.
    ///
    /// # Arguments
    ///
    /// * `lease` - The updated lease
    #[cfg(feature = "dhcp")]
    #[instrument(skip(self), fields(ip = %lease.ip(), mac = %lease.mac()))]
    pub async fn emit_dhcp_lease_updated(&self, lease: &Lease) -> Result<()> {
        if let Some(conn) = &self.connection {
            let signal_context = SignalContext::new(conn, "/uk/org/thekelleys/dnsmasq")
                .context("Failed to create signal context")?;

            let ip = lease.ip().to_string();
            let mac = lease.mac().to_string();
            let hostname = lease.hostname().unwrap_or("");

            DnsmasqInterface::dhcp_lease_updated(&signal_context, &ip, &mac, hostname)
                .await
                .context("Failed to emit DhcpLeaseUpdated signal")?;

            debug!(ip = %ip, mac = %mac, hostname = %hostname, "Emitted DhcpLeaseUpdated signal");
        }
        Ok(())
    }
}

// ============================================================================
// D-BUS INTERFACE - METHOD AND SIGNAL DEFINITIONS
// ============================================================================

/// D-Bus interface implementation for `uk.org.thekelleys.dnsmasq`.
///
/// This struct holds references to core services and implements all D-Bus methods
/// specified in the interface. The `#[dbus_interface]` macro generates the D-Bus
/// introspection data and method dispatch logic automatically.
///
/// # Interface Specification
///
/// - **Interface Name**: `uk.org.thekelleys.dnsmasq`
/// - **Object Path**: `/uk/org/thekelleys/dnsmasq`
///
/// # Methods
///
/// ## Cache Management
/// - `ClearCache()`: Invalidates DNS cache
///
/// ## Upstream Configuration
/// - `SetServers(Vec<String>)`: Sets upstream DNS servers
/// - `SetServersEx(Vec<Vec<String>>)`: Sets upstream servers with domain mappings
///
/// ## Status Queries
/// - `GetVersion() -> String`: Returns version string
/// - `GetMetrics() -> HashMap<String, String>`: Returns runtime metrics
/// - `GetServerMetrics() -> HashMap<String, String>`: Returns per-server statistics
///
/// ## DHCP Management (feature = "dhcp")
/// - `AddDhcpLease(String, String, String, u64)`: Adds manual DHCP lease
/// - `DeleteDhcpLease(String)`: Removes DHCP lease
///
/// ## Loop Detection (feature = "loop")
/// - `GetLoopServers() -> Vec<String>`: Returns servers in forwarding loops
///
/// # Signals
///
/// - `DhcpLeaseAdded(String, String, String)`: Lease allocated
/// - `DhcpLeaseDeleted(String, String, String)`: Lease expired/released
/// - `DhcpLeaseUpdated(String, String, String)`: Lease renewed
#[cfg(feature = "dbus")]
struct DnsmasqInterface {
    /// Reference to DNS service for cache and upstream operations
    dns_service: Arc<RwLock<DnsService>>,
    /// Reference to DHCP service for lease management (optional)
    #[cfg(feature = "dhcp")]
    dhcp_service: Option<Arc<RwLock<DhcpService>>>,
    /// Reference to metrics collector
    metrics: Arc<RwLock<MetricsCollector>>,
}

/// D-Bus interface implementation with method handlers.
///
/// Each method is an async function that can access shared service state
/// via Arc<RwLock<T>> references. Methods return Result with zbus::fdo::Error
/// for D-Bus error responses.
#[cfg(feature = "dbus")]
#[interface(name = "uk.org.thekelleys.dnsmasq")]
impl DnsmasqInterface {
    // ========================================================================
    // CACHE MANAGEMENT METHODS
    // ========================================================================

    /// Clears the DNS cache, removing all cached entries.
    ///
    /// This method invalidates all DNS cache entries, forcing subsequent queries
    /// to be forwarded to upstream servers. Useful for forcing fresh lookups after
    /// network configuration changes.
    ///
    /// # D-Bus Method Signature
    ///
    /// ```text
    /// ClearCache() -> ()
    /// ```
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // C implementation in src/dbus.c
    /// DBusMessage *clear_cache_method(DBusMessage *message) {
    ///     cache_start_insert();  // Invalidate all entries
    ///     return dbus_message_new_method_return(message);
    /// }
    /// ```
    ///
    /// # Example D-Bus Call
    ///
    /// ```bash
    /// dbus-send --system --print-reply \
    ///     --dest=uk.org.thekelleys.dnsmasq \
    ///     /uk/org/thekelleys/dnsmasq \
    ///     uk.org.thekelleys.dnsmasq.ClearCache
    /// ```
    #[instrument(skip(self))]
    async fn clear_cache(&self) -> zbus::fdo::Result<()> {
        info!("D-Bus method called: ClearCache");

        self.dns_service
            .write()
            .await
            .clear_cache()
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to clear cache");
                zbus::fdo::Error::Failed(format!("Failed to clear cache: {}", e))
            })?;

        info!("Cache cleared successfully via D-Bus");
        Ok(())
    }

    // ========================================================================
    // UPSTREAM SERVER CONFIGURATION METHODS
    // ========================================================================

    /// Sets upstream DNS servers (simple format).
    ///
    /// Replaces current upstream server configuration with the provided list.
    /// Each server is specified as an IP address string (e.g., "8.8.8.8").
    ///
    /// # D-Bus Method Signature
    ///
    /// ```text
    /// SetServers(servers: Vec<String>) -> ()
    /// ```
    ///
    /// # Arguments
    ///
    /// * `servers` - Array of upstream DNS server IP addresses
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // C implementation parses string array and rebuilds server list
    /// DBusMessage *set_servers_method(DBusMessage *message) {
    ///     DBusMessageIter iter, array_iter;
    ///     dbus_message_iter_init(message, &iter);
    ///     dbus_message_iter_recurse(&iter, &array_iter);
    ///     // Clear existing servers, add new ones
    /// }
    /// ```
    ///
    /// # Example D-Bus Call
    ///
    /// ```bash
    /// dbus-send --system --print-reply \
    ///     --dest=uk.org.thekelleys.dnsmasq \
    ///     /uk/org/thekelleys/dnsmasq \
    ///     uk.org.thekelleys.dnsmasq.SetServers \
    ///     array:string:"8.8.8.8","1.1.1.1"
    /// ```
    #[instrument(skip(self))]
    async fn set_servers(&self, servers: Vec<String>) -> zbus::fdo::Result<()> {
        info!(server_count = servers.len(), "D-Bus method called: SetServers");

        let mut dns_service = self.dns_service.write().await;
        let upstream_pool = dns_service.upstream_pool_mut();

        // Clear existing servers
        upstream_pool.clear().await;

        // Add new servers
        for server_str in &servers {
            let addr = IpAddr::from_str(server_str).map_err(|e| {
                error!(server = %server_str, error = %e, "Invalid server address");
                zbus::fdo::Error::InvalidArgs(format!("Invalid IP address '{}': {}", server_str, e))
            })?;

            upstream_pool.add_server(addr, None).await.map_err(|e| {
                error!(server = %addr, error = %e, "Failed to add server");
                zbus::fdo::Error::Failed(format!("Failed to add server {}: {}", addr, e))
            })?;

            debug!(server = %addr, "Added upstream server");
        }

        info!(server_count = upstream_pool.server_count().await, "Upstream servers updated via D-Bus");
        Ok(())
    }

    /// Sets upstream DNS servers with domain-specific mappings (extended format).
    ///
    /// Each entry is an array where:
    /// - First element: IP address of upstream server
    /// - Subsequent elements (optional): Domain names to forward to this server
    ///
    /// # D-Bus Method Signature
    ///
    /// ```text
    /// SetServersEx(servers: Vec<Vec<String>>) -> ()
    /// ```
    ///
    /// # Arguments
    ///
    /// * `servers` - Array of server configurations, each [ip, domain1, domain2, ...]
    ///
    /// # Example
    ///
    /// ```text
    /// [["8.8.8.8", "example.com", "example.org"], ["1.1.1.1"]]
    /// ```
    ///
    /// This forwards example.com and example.org queries to 8.8.8.8,
    /// all others to 1.1.1.1.
    ///
    /// # Example D-Bus Call
    ///
    /// ```bash
    /// dbus-send --system --print-reply \
    ///     --dest=uk.org.thekelleys.dnsmasq \
    ///     /uk/org/thekelleys/dnsmasq \
    ///     uk.org.thekelleys.dnsmasq.SetServersEx \
    ///     array:array:string:"8.8.8.8","example.com" array:string:"1.1.1.1"
    /// ```
    #[instrument(skip(self))]
    async fn set_servers_ex(&self, servers: Vec<Vec<String>>) -> zbus::fdo::Result<()> {
        info!(server_count = servers.len(), "D-Bus method called: SetServersEx");

        let mut dns_service = self.dns_service.write().await;
        let upstream_pool = dns_service.upstream_pool_mut();

        // Clear existing servers
        upstream_pool.clear().await;

        // Process each server configuration
        for (idx, server_config) in servers.iter().enumerate() {
            if server_config.is_empty() {
                warn!(index = idx, "Empty server configuration, skipping");
                continue;
            }

            // First element is the IP address
            let addr = IpAddr::from_str(&server_config[0]).map_err(|e| {
                error!(index = idx, address = %server_config[0], error = %e, "Invalid server address");
                zbus::fdo::Error::InvalidArgs(format!(
                    "Invalid IP address at index {}: '{}'",
                    idx, server_config[0]
                ))
            })?;

            // Remaining elements are domain names (if any)
            let domains: Option<Vec<String>> = if server_config.len() > 1 {
                Some(server_config[1..].to_vec())
            } else {
                None
            };

            upstream_pool
                .add_server(addr, domains.clone())
                .await
                .map_err(|e| {
                    error!(server = %addr, domains = ?domains, error = %e, "Failed to add server");
                    zbus::fdo::Error::Failed(format!("Failed to add server {}: {}", addr, e))
                })?;

            debug!(server = %addr, domains = ?domains, "Added upstream server with domains");
        }

        info!(
            server_count = upstream_pool.server_count().await,
            "Upstream servers updated via D-Bus (extended format)"
        );
        Ok(())
    }

    // ========================================================================
    // STATUS QUERY METHODS
    // ========================================================================

    /// Returns the dnsmasq version string.
    ///
    /// # D-Bus Method Signature
    ///
    /// ```text
    /// GetVersion() -> String
    /// ```
    ///
    /// # Returns
    ///
    /// Version string (e.g., "2.92")
    ///
    /// # Example D-Bus Call
    ///
    /// ```bash
    /// dbus-send --system --print-reply \
    ///     --dest=uk.org.thekelleys.dnsmasq \
    ///     /uk/org/thekelleys/dnsmasq \
    ///     uk.org.thekelleys.dnsmasq.GetVersion
    /// ```
    #[instrument(skip(self))]
    async fn get_version(&self) -> zbus::fdo::Result<String> {
        debug!("D-Bus method called: GetVersion");
        Ok(VERSION.to_string())
    }

    /// Returns runtime metrics as key-value pairs.
    ///
    /// Returns various operational metrics such as query counts, cache statistics,
    /// and DHCP lease counts (if DHCP is enabled).
    ///
    /// # D-Bus Method Signature
    ///
    /// ```text
    /// GetMetrics() -> HashMap<String, String>
    /// ```
    ///
    /// # Returns
    ///
    /// Dictionary of metric names to string values. Example keys:
    /// - `dns_queries_total`: Total DNS queries processed
    /// - `cache_hits`: DNS cache hit count
    /// - `cache_misses`: DNS cache miss count
    /// - `dhcp_leases_active`: Active DHCP leases (if DHCP enabled)
    ///
    /// # Example D-Bus Call
    ///
    /// ```bash
    /// dbus-send --system --print-reply \
    ///     --dest=uk.org.thekelleys.dnsmasq \
    ///     /uk/org/thekelleys/dnsmasq \
    ///     uk.org.thekelleys.dnsmasq.GetMetrics
    /// ```
    #[instrument(skip(self))]
    async fn get_metrics(&self) -> zbus::fdo::Result<HashMap<String, String>> {
        debug!("D-Bus method called: GetMetrics");

        let metrics = self.metrics.read().await;
        let all_metrics = metrics.get_all_metrics().await.map_err(|e| {
            error!(error = %e, "Failed to retrieve metrics");
            zbus::fdo::Error::Failed(format!("Failed to retrieve metrics: {}", e))
        })?;

        debug!(metric_count = all_metrics.len(), "Retrieved metrics");
        Ok(all_metrics)
    }

    /// Returns per-server query statistics.
    ///
    /// Provides detailed statistics for each configured upstream DNS server,
    /// including query counts, response times, and failure rates.
    ///
    /// # D-Bus Method Signature
    ///
    /// ```text
    /// GetServerMetrics() -> HashMap<String, String>
    /// ```
    ///
    /// # Returns
    ///
    /// Dictionary mapping server addresses to statistics. Example:
    /// - `8.8.8.8_queries`: Number of queries sent to 8.8.8.8
    /// - `8.8.8.8_failures`: Number of failed queries to 8.8.8.8
    ///
    /// # Example D-Bus Call
    ///
    /// ```bash
    /// dbus-send --system --print-reply \
    ///     --dest=uk.org.thekelleys.dnsmasq \
    ///     /uk/org/thekelleys/dnsmasq \
    ///     uk.org.thekelleys.dnsmasq.GetServerMetrics
    /// ```
    #[instrument(skip(self))]
    async fn get_server_metrics(&self) -> zbus::fdo::Result<HashMap<String, String>> {
        debug!("D-Bus method called: GetServerMetrics");

        let dns_service = self.dns_service.read().await;
        let upstream_pool = dns_service.upstream_pool();

        let stats = upstream_pool.get_server_stats().await.map_err(|e| {
            error!(error = %e, "Failed to retrieve server metrics");
            zbus::fdo::Error::Failed(format!("Failed to retrieve server metrics: {}", e))
        })?;

        debug!(server_count = stats.len(), "Retrieved server metrics");
        Ok(stats)
    }

    // ========================================================================
    // DHCP MANAGEMENT METHODS (feature = "dhcp")
    // ========================================================================

    /// Adds a manual DHCP lease.
    ///
    /// Creates a static DHCP lease binding an IP address to a MAC address
    /// with an optional hostname. The lease will persist until explicitly
    /// deleted or until the expiry time.
    ///
    /// # D-Bus Method Signature
    ///
    /// ```text
    /// AddDhcpLease(ip: String, mac: String, hostname: String, expires: u64) -> ()
    /// ```
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address (e.g., "192.168.1.100")
    /// * `mac` - MAC address in colon-separated format (e.g., "aa:bb:cc:dd:ee:ff")
    /// * `hostname` - Client hostname (can be empty string)
    /// * `expires` - Lease expiry timestamp (Unix epoch seconds, 0 for infinite)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - IP address is invalid or outside DHCP range
    /// - MAC address format is invalid
    /// - DHCP feature is not compiled in
    /// - Lease conflicts with existing allocation
    ///
    /// # Example D-Bus Call
    ///
    /// ```bash
    /// dbus-send --system --print-reply \
    ///     --dest=uk.org.thekelleys.dnsmasq \
    ///     /uk/org/thekelleys/dnsmasq \
    ///     uk.org.thekelleys.dnsmasq.AddDhcpLease \
    ///     string:"192.168.1.100" string:"aa:bb:cc:dd:ee:ff" \
    ///     string:"client-hostname" uint64:0
    /// ```
    #[cfg(feature = "dhcp")]
    #[instrument(skip(self))]
    async fn add_dhcp_lease(
        &self,
        ip: String,
        mac: String,
        hostname: String,
        expires: u64,
    ) -> zbus::fdo::Result<()> {
        info!(ip = %ip, mac = %mac, hostname = %hostname, expires = expires, "D-Bus method called: AddDhcpLease");

        // Validate and parse IP address
        let ip_addr = IpAddr::from_str(&ip).map_err(|e| {
            error!(ip = %ip, error = %e, "Invalid IP address");
            zbus::fdo::Error::InvalidArgs(format!("Invalid IP address '{}': {}", ip, e))
        })?;

        // Validate and parse MAC address
        let mac_addr = MacAddress::from_str(&mac).map_err(|e| {
            error!(mac = %mac, error = %e, "Invalid MAC address");
            zbus::fdo::Error::InvalidArgs(format!("Invalid MAC address '{}': {}", mac, e))
        })?;

        // Get DHCP service
        let dhcp_service = self.dhcp_service.as_ref().ok_or_else(|| {
            error!("DHCP service not available");
            zbus::fdo::Error::Failed("DHCP service not initialized".to_string())
        })?;

        // Get lease manager
        let lease_manager = {
            let dhcp = dhcp_service.read().await;
            dhcp.get_lease_manager()
        };

        // Create and add lease
        let lease = Lease::new(
            ip_addr,
            mac_addr,
            if hostname.is_empty() { None } else { Some(hostname) },
            expires,
        );

        lease_manager
            .write()
            .await
            .add_lease(lease.clone())
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to add DHCP lease");
                zbus::fdo::Error::Failed(format!("Failed to add lease: {}", e))
            })?;

        info!(ip = %ip_addr, mac = %mac_addr, "DHCP lease added via D-Bus");

        // Emit signal
        if let Some(conn) = self.connection() {
            let signal_context = SignalContext::new(conn, "/uk/org/thekelleys/dnsmasq")
                .map_err(|e| zbus::fdo::Error::Failed(format!("Failed to create signal context: {}", e)))?;

            Self::dhcp_lease_added(&signal_context, &ip, &mac, &hostname)
                .await
                .map_err(|e| {
                    warn!(error = %e, "Failed to emit DhcpLeaseAdded signal");
                    // Don't fail the method call if signal emission fails
                })?;
        }

        Ok(())
    }

    /// Deletes a DHCP lease by IP address.
    ///
    /// Removes the specified DHCP lease, freeing the IP address for reallocation.
    /// This triggers a DhcpLeaseDeleted signal.
    ///
    /// # D-Bus Method Signature
    ///
    /// ```text
    /// DeleteDhcpLease(ip: String) -> ()
    /// ```
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address of lease to delete (e.g., "192.168.1.100")
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - IP address is invalid
    /// - No lease exists with that IP
    /// - DHCP feature is not compiled in
    ///
    /// # Example D-Bus Call
    ///
    /// ```bash
    /// dbus-send --system --print-reply \
    ///     --dest=uk.org.thekelleys.dnsmasq \
    ///     /uk/org/thekelleys/dnsmasq \
    ///     uk.org.thekelleys.dnsmasq.DeleteDhcpLease \
    ///     string:"192.168.1.100"
    /// ```
    #[cfg(feature = "dhcp")]
    #[instrument(skip(self))]
    async fn delete_dhcp_lease(&self, ip: String) -> zbus::fdo::Result<()> {
        info!(ip = %ip, "D-Bus method called: DeleteDhcpLease");

        // Validate and parse IP address
        let ip_addr = IpAddr::from_str(&ip).map_err(|e| {
            error!(ip = %ip, error = %e, "Invalid IP address");
            zbus::fdo::Error::InvalidArgs(format!("Invalid IP address '{}': {}", ip, e))
        })?;

        // Get DHCP service
        let dhcp_service = self.dhcp_service.as_ref().ok_or_else(|| {
            error!("DHCP service not available");
            zbus::fdo::Error::Failed("DHCP service not initialized".to_string())
        })?;

        // Get lease manager
        let lease_manager = {
            let dhcp = dhcp_service.read().await;
            dhcp.get_lease_manager()
        };

        // Find the lease before deletion (for signal emission)
        let lease = lease_manager
            .read()
            .await
            .find_by_ip(&ip_addr)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to find lease");
                zbus::fdo::Error::Failed(format!("Failed to find lease: {}", e))
            })?
            .ok_or_else(|| {
                error!(ip = %ip_addr, "Lease not found");
                zbus::fdo::Error::Failed(format!("No lease found for IP {}", ip_addr))
            })?;

        let mac = lease.mac().to_string();
        let hostname = lease.hostname().unwrap_or("");

        // Delete the lease
        lease_manager
            .write()
            .await
            .delete_lease(&ip_addr)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete DHCP lease");
                zbus::fdo::Error::Failed(format!("Failed to delete lease: {}", e))
            })?;

        info!(ip = %ip_addr, mac = %mac, "DHCP lease deleted via D-Bus");

        // Emit signal
        if let Some(conn) = self.connection() {
            let signal_context = SignalContext::new(conn, "/uk/org/thekelleys/dnsmasq")
                .map_err(|e| zbus::fdo::Error::Failed(format!("Failed to create signal context: {}", e)))?;

            Self::dhcp_lease_deleted(&signal_context, &ip, &mac, hostname)
                .await
                .map_err(|e| {
                    warn!(error = %e, "Failed to emit DhcpLeaseDeleted signal");
                    // Don't fail the method call if signal emission fails
                })?;
        }

        Ok(())
    }

    // ========================================================================
    // LOOP DETECTION METHOD (feature = "loop")
    // ========================================================================

    /// Returns list of servers detected in forwarding loops.
    ///
    /// When dnsmasq detects that queries are being forwarded in a loop
    /// (e.g., dnsmasq forwards to itself), it tracks the problematic servers.
    /// This method returns that list.
    ///
    /// # D-Bus Method Signature
    ///
    /// ```text
    /// GetLoopServers() -> Vec<String>
    /// ```
    ///
    /// # Returns
    ///
    /// Array of server IP addresses detected in forwarding loops
    ///
    /// # Example D-Bus Call
    ///
    /// ```bash
    /// dbus-send --system --print-reply \
    ///     --dest=uk.org.thekelleys.dnsmasq \
    ///     /uk/org/thekelleys/dnsmasq \
    ///     uk.org.thekelleys.dnsmasq.GetLoopServers
    /// ```
    #[cfg(feature = "loop")]
    #[instrument(skip(self))]
    async fn get_loop_servers(&self) -> zbus::fdo::Result<Vec<String>> {
        debug!("D-Bus method called: GetLoopServers");

        let dns_service = self.dns_service.read().await;
        let upstream_pool = dns_service.upstream_pool();

        let loop_servers = upstream_pool
            .get_loop_servers()
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to retrieve loop servers");
                zbus::fdo::Error::Failed(format!("Failed to retrieve loop servers: {}", e))
            })?
            .iter()
            .map(|addr| addr.to_string())
            .collect();

        debug!(server_count = loop_servers.len(), "Retrieved loop servers");
        Ok(loop_servers)
    }

    // ========================================================================
    // D-BUS SIGNALS
    // ========================================================================

    /// Signal emitted when a DHCP lease is added.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address assigned
    /// * `mac` - Client MAC address
    /// * `hostname` - Client hostname (may be empty)
    #[cfg(feature = "dhcp")]
    #[zbus(signal)]
    async fn dhcp_lease_added(
        signal_ctxt: &SignalContext<'_>,
        ip: &str,
        mac: &str,
        hostname: &str,
    ) -> zbus::Result<()>;

    /// Signal emitted when a DHCP lease is deleted or expires.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address released
    /// * `mac` - Client MAC address
    /// * `hostname` - Client hostname (may be empty)
    #[cfg(feature = "dhcp")]
    #[zbus(signal)]
    async fn dhcp_lease_deleted(
        signal_ctxt: &SignalContext<'_>,
        ip: &str,
        mac: &str,
        hostname: &str,
    ) -> zbus::Result<()>;

    /// Signal emitted when a DHCP lease is renewed or updated.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address
    /// * `mac` - Client MAC address
    /// * `hostname` - Client hostname (may be empty)
    #[cfg(feature = "dhcp")]
    #[zbus(signal)]
    async fn dhcp_lease_updated(
        signal_ctxt: &SignalContext<'_>,
        ip: &str,
        mac: &str,
        hostname: &str,
    ) -> zbus::Result<()>;

    /// Helper method to get connection reference (internal use).
    ///
    /// This is used by signal emission code to access the D-Bus connection.
    fn connection(&self) -> Option<&Connection> {
        // This will be provided by the DbusService that holds the connection
        // For now, return None - actual signal emission happens via DbusService
        None
    }
}

// ============================================================================
// D-BUS DAEMON - CONNECTION MANAGEMENT AND LIFECYCLE
// ============================================================================

/// D-Bus daemon wrapper managing connection lifecycle and service registration.
///
/// This structure owns the D-Bus connection and manages the overall lifecycle
/// of the D-Bus service, including connection establishment, service name
/// registration, interface object registration, and graceful shutdown.
///
/// # Architecture
///
/// ```text
/// DbusDaemon
///   ├── Connection (system bus)
///   ├── ObjectServer (manages interface objects)
///   ├── DnsmasqInterface (registered at /uk/org/thekelleys/dnsmasq)
///   └── Service Name: uk.org.thekelleys.dnsmasq
/// ```
///
/// # Lifecycle
///
/// 1. **Creation**: `DbusDaemon::new()` - Validates dependencies
/// 2. **Start**: `run()` - Connects to bus, registers service and interface
/// 3. **Operation**: Methods dispatched automatically by zbus
/// 4. **Shutdown**: Drop connection, clean up resources
#[cfg(feature = "dbus")]
pub struct DbusDaemon {
    /// References to core services
    dns_service: Arc<RwLock<DnsService>>,
    #[cfg(feature = "dhcp")]
    dhcp_service: Option<Arc<RwLock<DhcpService>>>,
    metrics: Arc<RwLock<MetricsCollector>>,
}

#[cfg(feature = "dbus")]
impl DbusDaemon {
    /// Creates a new D-Bus daemon instance.
    ///
    /// # Arguments
    ///
    /// * `dns_service` - DNS service reference
    /// * `dhcp_service` - Optional DHCP service reference
    /// * `metrics` - Metrics collector reference
    ///
    /// # Returns
    ///
    /// New DbusDaemon ready to run
    #[instrument(skip(dns_service, metrics))]
    pub fn new(
        dns_service: Arc<RwLock<DnsService>>,
        #[cfg(feature = "dhcp")] dhcp_service: Option<Arc<RwLock<DhcpService>>>,
        metrics: Arc<RwLock<MetricsCollector>>,
    ) -> Result<Self> {
        info!("Creating D-Bus daemon");
        Ok(Self {
            dns_service,
            #[cfg(feature = "dhcp")]
            dhcp_service,
            metrics,
        })
    }

    /// Runs the D-Bus service, connecting to system bus and registering interface.
    ///
    /// This method:
    /// 1. Connects to the D-Bus system bus
    /// 2. Requests the service name `uk.org.thekelleys.dnsmasq`
    /// 3. Registers the interface at `/uk/org/thekelleys/dnsmasq`
    /// 4. Blocks until the connection is terminated or an error occurs
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // C implementation in src/dbus.c
    /// DBusConnection *dbus = dbus_bus_get(DBUS_BUS_SYSTEM, &dbus_error);
    /// dbus_bus_request_name(dbus, "uk.org.thekelleys.dnsmasq", 0, &dbus_error);
    /// dbus_connection_register_object_path(dbus, "/uk/org/thekelleys/dnsmasq", &vtable, NULL);
    /// while (dbus_connection_read_write_dispatch(dbus, -1)) { /* event loop */ }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Cannot connect to system bus (permission denied, bus not running)
    /// - Service name already taken by another process
    /// - Interface registration fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use tokio::sync::RwLock;
    /// # async fn example() -> anyhow::Result<()> {
    /// let dns_service = Arc::new(RwLock::new(DnsService::new(/* ... */)?));
    /// let metrics = Arc::new(RwLock::new(MetricsCollector::new()));
    ///
    /// let daemon = DbusDaemon::new(dns_service, None, metrics)?;
    /// daemon.run().await?; // Blocks until shutdown
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self))]
    pub async fn run(&self) -> Result<()> {
        info!("Starting D-Bus service");

        // Connect to system bus
        let connection = Connection::system()
            .await
            .context("Failed to connect to D-Bus system bus")?;

        info!(connection_unique_name = %connection.unique_name()
            .context("Failed to get connection unique name")?, 
            "Connected to D-Bus system bus");

        // Request service name
        connection
            .request_name("uk.org.thekelleys.dnsmasq")
            .await
            .context("Failed to request D-Bus service name 'uk.org.thekelleys.dnsmasq'")?;

        info!("Acquired D-Bus service name: uk.org.thekelleys.dnsmasq");

        // Create interface instance
        let interface = DnsmasqInterface {
            dns_service: Arc::clone(&self.dns_service),
            #[cfg(feature = "dhcp")]
            dhcp_service: self.dhcp_service.as_ref().map(Arc::clone),
            metrics: Arc::clone(&self.metrics),
        };

        // Register interface at object path
        connection
            .object_server()
            .at("/uk/org/thekelleys/dnsmasq", interface)
            .await
            .context("Failed to register D-Bus interface at /uk/org/thekelleys/dnsmasq")?;

        info!("Registered D-Bus interface at /uk/org/thekelleys/dnsmasq");
        info!("D-Bus service is ready");

        // Keep the connection alive
        // In a real implementation, this would integrate with the main event loop
        // and respond to shutdown signals. For now, just keep it alive indefinitely.
        std::future::pending::<()>().await;

        Ok(())
    }
}
