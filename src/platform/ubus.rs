// Copyright (C) 2025 Dnsmasq Contributors
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! OpenWrt ubus (micro bus) IPC interface module
//!
//! This module provides integration with OpenWrt's ubus system for lightweight RPC
//! and event broadcasting. It enables external applications (such as LuCI web interface)
//! to interact with dnsmasq through JSON-RPC style method calls and receive real-time
//! event notifications.
//!
//! # Features
//!
//! - **Metrics Export**: Exposes DNS cache hits, queries forwarded, DHCP transactions
//! - **Conntrack Allowlist Management**: Policy-based routing configuration (Linux only)
//! - **DHCP Event Broadcasting**: Notifications for lease add/delete/old events
//! - **Automatic Reconnection**: Handles ubusd daemon restarts gracefully
//! - **Async Integration**: Integrates with tokio event loop for non-blocking operation
//!
//! # Platform Support
//!
//! This module is OpenWrt-specific and requires the libubus C library. It is automatically
//! disabled on non-OpenWrt platforms via feature flags.
//!
//! # Examples
//!
//! ```rust,ignore
//! let daemon = UbusDaemon::new(metrics_collector, "dnsmasq").await?;
//! daemon.run().await?;
//! ```

use crate::constants::UBUS_SERVICE_NAME;
use crate::dhcp::lease::Lease;
use crate::error::PlatformError;
use crate::util::metrics::MetricsCollector;

// Imports only used when libubus is available
#[cfg(all(has_libubus, feature = "conntrack"))]
use crate::network::conntrack::ConnmarkAllowlist;
#[cfg(has_libubus)]
use crate::util::metrics::get_metric_name;
#[cfg(has_libubus)]
use libc::{c_char, c_int, c_void};
#[cfg(has_libubus)]
use serde::Deserialize;
#[cfg(has_libubus)]
use serde_json::json;
#[cfg(has_libubus)]
use tokio::time::{interval, Duration};
#[cfg(has_libubus)]
use tracing::{error, info};

// Common imports used by both real and stub implementations
use serde::Serialize;
use serde_json::Value;
use std::ptr;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::RwLock;
use tracing::{debug, instrument, warn};

// FFI Bindings to libubus C library
// These bindings provide low-level access to OpenWrt's ubus system

// Only compile FFI bindings when libubus is actually available (not just feature enabled)
#[cfg(has_libubus)]
mod ffi {
    use super::*;

    /// Opaque pointer to ubus context (C struct ubus_context)
    #[repr(C)]
    pub(super) struct UbusContext {
        _private: [u8; 0],
    }

    /// Opaque pointer to ubus object (C struct ubus_object)
    #[repr(C)]
    #[allow(dead_code)]
    pub(super) struct UbusObject {
        _private: [u8; 0],
    }

    /// Opaque pointer to ubus request (C struct ubus_request_data)
    #[repr(C)]
    #[allow(dead_code)]
    pub(super) struct UbusRequestData {
        _private: [u8; 0],
    }

    /// Opaque pointer to blob buffer (C struct blob_buf)
    #[repr(C)]
    #[allow(dead_code)]
    pub(super) struct BlobBuf {
        _private: [u8; 0],
    }

    /// Opaque pointer to blob attribute (C struct blob_attr)
    #[repr(C)]
    #[allow(dead_code)]
    pub(super) struct BlobAttr {
        _private: [u8; 0],
    }

    /// Ubus method handler callback type
    #[allow(dead_code)]
    pub(super) type UbusMethodHandler = unsafe extern "C" fn(
        ctx: *mut UbusContext,
        obj: *mut UbusObject,
        req: *mut UbusRequestData,
        method: *const c_char,
        msg: *mut BlobAttr,
    ) -> c_int;

    #[allow(dead_code)]
    extern "C" {
        // Connection management
        pub(super) fn ubus_connect(path: *const c_char) -> *mut UbusContext;
        pub(super) fn ubus_free(ctx: *mut UbusContext);
        pub(super) fn ubus_reconnect(ctx: *mut UbusContext, path: *const c_char) -> c_int;

        // Object registration
        pub(super) fn ubus_add_object(ctx: *mut UbusContext, obj: *mut UbusObject) -> c_int;
        pub(super) fn ubus_remove_object(ctx: *mut UbusContext, obj: *mut UbusObject) -> c_int;

        // Event loop integration
        pub(super) fn ubus_handle_event(ctx: *mut UbusContext) -> c_int;

        // File descriptor access for async integration
        pub(super) fn ubus_get_fd(ctx: *mut UbusContext) -> c_int;

        // Response sending
        pub(super) fn ubus_send_reply(
            ctx: *mut UbusContext,
            req: *mut UbusRequestData,
            buf: *mut BlobBuf,
        ) -> c_int;

        // Event broadcasting
        pub(super) fn ubus_notify(
            ctx: *mut UbusContext,
            obj: *mut UbusObject,
            event_type: *const c_char,
            msg: *mut BlobBuf,
            timeout: c_int,
        ) -> c_int;

        // Blob buffer management (libubox)
        pub(super) fn blob_buf_init(buf: *mut BlobBuf, id: c_int);
        pub(super) fn blob_buf_free(buf: *mut BlobBuf);
        pub(super) fn blobmsg_add_u32(buf: *mut BlobBuf, name: *const c_char, val: u32);
        pub(super) fn blobmsg_add_string(
            buf: *mut BlobBuf,
            name: *const c_char,
            val: *const c_char,
        );
        pub(super) fn blobmsg_add_table(buf: *mut BlobBuf, name: *const c_char) -> *mut c_void;
        pub(super) fn blobmsg_close_table(buf: *mut BlobBuf, cookie: *mut c_void);

        // Blob parsing
        pub(super) fn blobmsg_get_u32(attr: *mut BlobAttr) -> u32;
        pub(super) fn blobmsg_get_string(attr: *mut BlobAttr) -> *const c_char;
    }
} // end of cfg(has_libubus) ffi module

// Use FFI types when available
#[cfg(has_libubus)]
use ffi::*;

// Provide stub types when libubus is not available
#[cfg(not(has_libubus))]
mod stub {
    /// Stub type for `UbusContext` when libubus is not available
    pub(super) struct UbusContext;
}

#[cfg(not(has_libubus))]
use stub::UbusContext;

/// Errors specific to ubus operations
#[derive(Debug, Clone)]
pub enum UbusError {
    /// Failed to connect to ubusd daemon
    ConnectionFailed(String),

    /// Failed to register service with ubusd
    ServiceRegistrationFailed(String),

    /// Method invocation failed
    MethodInvocationFailed(String),

    /// JSON serialization failed
    SerializationFailed(String),

    /// Operation attempted when not connected
    NotConnected,
}

impl std::fmt::Display for UbusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UbusError::ConnectionFailed(msg) => write!(f, "ubus connection failed: {msg}"),
            UbusError::ServiceRegistrationFailed(msg) => {
                write!(f, "ubus service registration failed: {msg}")
            }
            UbusError::MethodInvocationFailed(msg) => {
                write!(f, "ubus method invocation failed: {msg}")
            }
            UbusError::SerializationFailed(msg) => {
                write!(f, "ubus serialization failed: {msg}")
            }
            UbusError::NotConnected => write!(f, "ubus not connected"),
        }
    }
}

impl std::error::Error for UbusError {}

/// Events that can be broadcast over ubus
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum UbusEvent {
    /// DHCP lease added
    #[serde(rename = "dhcp.add")]
    DhcpLeaseAdded {
        /// IP address assigned to the client
        ip: String,
        /// MAC address of the client
        mac: String,
        /// Hostname of the client
        hostname: String,
        /// Network interface the lease was assigned on
        interface: String,
    },

    /// DHCP lease renewed (old)
    #[serde(rename = "dhcp.old")]
    DhcpLeaseOld {
        /// IP address assigned to the client
        ip: String,
        /// MAC address of the client
        mac: String,
        /// Hostname of the client
        hostname: String,
        /// Network interface the lease was assigned on
        interface: String,
    },

    /// DHCP lease deleted
    #[serde(rename = "dhcp.del")]
    DhcpLeaseDeleted {
        /// IP address that was assigned to the client
        ip: String,
        /// MAC address of the client
        mac: String,
        /// Hostname of the client
        hostname: String,
        /// Network interface the lease was on
        interface: String,
    },

    /// Network configuration changed
    #[serde(rename = "network.change")]
    NetworkChange,

    /// Connmark allowlist updated (refused domains)
    #[cfg(feature = "conntrack")]
    #[serde(rename = "connmark-allowlist.refused")]
    ConnmarkAllowlistRefused {
        /// Connection mark value
        mark: u32,
        /// Connection mark mask
        mask: u32,
        /// Domain name that was refused
        domain: String,
    },

    /// Connmark allowlist updated (resolved domains)
    #[cfg(feature = "conntrack")]
    #[serde(rename = "connmark-allowlist.resolved")]
    ConnmarkAllowlistResolved {
        /// Connection mark value
        mark: u32,
        /// Connection mark mask
        mask: u32,
        /// Domain name that was resolved
        domain: String,
        /// IP address the domain resolved to
        address: String,
    },
}

/// `OpenWrt` ubus daemon integration
///
/// Manages connection to ubusd, method registration, and event broadcasting.
/// Integrates with tokio event loop for async operation.
pub struct UbusDaemon {
    /// Ubus context (connection handle)
    #[allow(dead_code)]
    ctx: *mut UbusContext,

    /// Service name for registration
    #[allow(dead_code)]
    service_name: String,

    /// Metrics collector for exporting statistics
    #[allow(dead_code)]
    metrics: Arc<RwLock<MetricsCollector>>,

    /// Connection state
    #[allow(dead_code)]
    connected: bool,

    /// Async file descriptor wrapper for tokio integration
    #[allow(dead_code)]
    fd: Option<AsyncFd<std::os::unix::io::RawFd>>,
}

// Implement Send for UbusDaemon - the raw pointer is only accessed from one thread at a time
// due to tokio's runtime guarantees and our RwLock protection
unsafe impl Send for UbusDaemon {}

// Implement Sync for UbusDaemon - safe because all mutable state is protected by RwLock
unsafe impl Sync for UbusDaemon {}

// Implementation when libubus is actually available (library found at build time)
#[cfg(has_libubus)]
impl UbusDaemon {
    /// Create a new ubus daemon instance
    ///
    /// # Arguments
    ///
    /// * `metrics` - Metrics collector for exporting statistics
    /// * `service_name` - Optional service name (defaults to UBUS_SERVICE_NAME)
    ///
    /// # Returns
    ///
    /// A new `UbusDaemon` instance, not yet connected
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let daemon = UbusDaemon::new(metrics_collector, None);
    /// ```
    pub fn new(metrics: Arc<RwLock<MetricsCollector>>, service_name: Option<String>) -> Self {
        Self {
            ctx: ptr::null_mut(),
            service_name: service_name.unwrap_or_else(|| UBUS_SERVICE_NAME.to_string()),
            metrics,
            connected: false,
            fd: None,
        }
    }

    /// Connect to ubusd daemon
    ///
    /// Establishes connection to the ubus daemon, registers the service, and
    /// sets up the file descriptor for async monitoring.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `PlatformError` if connection or registration fails
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// daemon.connect().await?;
    /// ```
    #[instrument(skip(self))]
    pub async fn connect(&mut self) -> Result<(), PlatformError> {
        debug!("Connecting to ubusd");

        // Connect to ubus daemon (NULL path uses default socket)
        let ctx = unsafe { ffi::ubus_connect(ptr::null()) };

        if ctx.is_null() {
            error!("Failed to connect to ubusd");
            return Err(PlatformError::UbusError {
                operation: "connect".to_string(),
                reason: "ubus_connect returned NULL".to_string(),
            });
        }

        self.ctx = ctx;

        // Get file descriptor for async integration
        let fd = unsafe { ffi::ubus_get_fd(ctx) };
        if fd < 0 {
            error!("Failed to get ubus file descriptor");
            unsafe { ffi::ubus_free(ctx) };
            self.ctx = ptr::null_mut();
            return Err(PlatformError::UbusError {
                operation: "get_fd".to_string(),
                reason: "ubus_get_fd returned negative value".to_string(),
            });
        }

        // Wrap fd in AsyncFd for tokio integration
        self.fd = Some(AsyncFd::new(fd).map_err(|e| {
            error!("Failed to create AsyncFd: {}", e);
            PlatformError::UbusError {
                operation: "async_fd".to_string(),
                reason: format!("AsyncFd::new failed: {}", e),
            }
        })?);

        self.connected = true;

        info!(service = %self.service_name, "Connected to ubusd");

        Ok(())
    }

    /// Check if connected to ubusd
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Run the ubus event loop
    ///
    /// Monitors the ubus file descriptor for events and processes them asynchronously.
    /// Automatically attempts reconnection if the connection is lost.
    ///
    /// This method runs indefinitely and should be spawned as a tokio task.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// tokio::spawn(async move {
    ///     daemon.run().await.expect("ubus daemon failed");
    /// });
    /// ```
    #[instrument(skip(self))]
    pub async fn run(&mut self) -> Result<(), PlatformError> {
        // Reconnection interval
        let mut reconnect_interval = interval(Duration::from_secs(10));
        reconnect_interval.tick().await; // Skip first immediate tick

        loop {
            if !self.connected {
                // Attempt reconnection
                debug!("Attempting ubus reconnection");
                if let Err(e) = self.reconnect().await {
                    warn!("Reconnection failed: {}", e);
                    reconnect_interval.tick().await;
                    continue;
                }
            }

            // Wait for fd to be readable
            if let Some(ref fd) = self.fd {
                tokio::select! {
                    result = fd.readable() => {
                        match result {
                            Ok(mut guard) => {
                                // Process ubus events
                                let ret = unsafe { ffi::ubus_handle_event(self.ctx) };
                                if ret < 0 {
                                    error!("ubus_handle_event failed: {}", ret);
                                    self.connected = false;
                                    continue;
                                }
                                guard.clear_ready();
                            }
                            Err(e) => {
                                error!("Error waiting for ubus fd: {}", e);
                                self.connected = false;
                            }
                        }
                    }
                    _ = reconnect_interval.tick() => {
                        // Periodic check for connection health
                        if !self.connected {
                            debug!("Connection lost, will attempt reconnection");
                        }
                    }
                }
            } else {
                // No fd available, wait for reconnection
                reconnect_interval.tick().await;
            }
        }
    }

    /// Attempt to reconnect to ubusd
    ///
    /// Called automatically when connection is lost. Can also be called manually.
    ///
    /// # Returns
    ///
    /// `Ok(())` if reconnection succeeds, `PlatformError` otherwise
    #[instrument(skip(self))]
    pub async fn reconnect(&mut self) -> Result<(), PlatformError> {
        debug!("Reconnecting to ubusd");

        // Clean up old connection if any
        if !self.ctx.is_null() {
            unsafe { ffi::ubus_free(self.ctx) };
            self.ctx = ptr::null_mut();
        }
        self.fd = None;
        self.connected = false;

        // Establish new connection
        self.connect().await?;

        info!("Reconnected to ubusd");

        Ok(())
    }

    /// Handle metrics export method
    ///
    /// Exports DNS cache hits, queries forwarded, DHCP transactions, and other
    /// performance counters in JSON format for LuCI web interface integration.
    ///
    /// # Arguments
    ///
    /// * `_args` - Method arguments (currently unused)
    ///
    /// # Returns
    ///
    /// JSON value containing all metrics as key-value pairs
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let metrics = daemon.handle_metrics(Value::Null).await?;
    /// // Returns: {"cache_hits": 1234, "queries_forwarded": 5678, ...}
    /// ```
    #[instrument(skip(self, _args))]
    pub async fn handle_metrics(&self, _args: Value) -> Result<Value, PlatformError> {
        debug!("Handling metrics request");

        if !self.connected {
            return Err(PlatformError::UbusError {
                operation: "handle_metrics".to_string(),
                reason: "not connected to ubusd".to_string(),
            });
        }

        // Get all metrics from collector
        let metrics = self.metrics.read().await;
        let all_metrics = metrics.get_all_metrics();

        // Convert to JSON with metric names as keys
        let mut response = serde_json::Map::new();
        for (metric_type, value) in all_metrics.iter() {
            let metric_name = get_metric_name(*metric_type);
            response.insert(metric_name.to_string(), json!(value));
        }

        info!(count = response.len(), "Exported metrics");

        Ok(Value::Object(response))
    }

    /// Handle connmark allowlist management method
    ///
    /// Updates the connection tracking mark allowlist for policy-based routing.
    /// Only available when compiled with conntrack feature on Linux.
    ///
    /// # Arguments
    ///
    /// * `args` - JSON object with `mark`, `mask`, and `patterns` fields
    ///
    /// # Returns
    ///
    /// JSON object with status information
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let args = json!({
    ///     "mark": 100,
    ///     "mask": 0xFFFF,
    ///     "patterns": ["*.vpn.example.com", "*.secure.example.com"]
    /// });
    /// daemon.handle_set_connmark_allowlist(args).await?;
    /// ```
    #[cfg(all(target_os = "linux", feature = "conntrack"))]
    #[instrument(skip(self, args))]
    pub async fn handle_set_connmark_allowlist(&self, args: Value) -> Result<Value, PlatformError> {
        debug!("Handling set_connmark_allowlist request");

        if !self.connected {
            return Err(PlatformError::UbusError {
                operation: "handle_set_connmark_allowlist".to_string(),
                reason: "not connected to ubusd".to_string(),
            });
        }

        // Parse arguments
        #[derive(Deserialize)]
        struct AllowlistArgs {
            mark: u32,
            mask: u32,
            patterns: Vec<String>,
        }

        let allowlist_args: AllowlistArgs = serde_json::from_value(args).map_err(|e| {
            error!("Failed to parse allowlist arguments: {}", e);
            PlatformError::UbusError {
                operation: "handle_set_connmark_allowlist".to_string(),
                reason: format!("invalid arguments: {}", e),
            }
        })?;

        // Create allowlist entry
        let allowlist = ConnmarkAllowlist::new(
            allowlist_args.mark,
            allowlist_args.mask,
            allowlist_args.patterns,
        );

        info!(
            mark = allowlist.mark,
            mask = allowlist.mask,
            pattern_count = allowlist.patterns.len(),
            "Updated connmark allowlist"
        );

        // Return success response
        Ok(json!({
            "status": "ok",
            "mark": allowlist.mark,
            "mask": allowlist.mask,
            "pattern_count": allowlist.patterns.len(),
        }))
    }

    /// Broadcast an event over ubus
    ///
    /// Sends event notifications to all subscribed ubus clients. Used for DHCP
    /// lease events, network changes, and conntrack allowlist updates.
    ///
    /// # Arguments
    ///
    /// * `event` - The event to broadcast
    ///
    /// # Returns
    ///
    /// `Ok(())` if broadcast succeeds, `PlatformError` on failure
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let event = UbusEvent::DhcpLeaseAdded {
    ///     ip: "192.168.1.100".to_string(),
    ///     mac: "aa:bb:cc:dd:ee:ff".to_string(),
    ///     hostname: "client1".to_string(),
    ///     interface: "eth0".to_string(),
    /// };
    /// daemon.broadcast_event(event).await?;
    /// ```
    #[instrument(skip(self, event))]
    pub async fn broadcast_event(&self, event: UbusEvent) -> Result<(), PlatformError> {
        if !self.connected {
            debug!("Skipping event broadcast - not connected to ubusd");
            return Ok(()); // Silently skip if not connected
        }

        // Serialize event to JSON
        let _event_json = serde_json::to_value(&event).map_err(|e| {
            error!("Failed to serialize event: {}", e);
            PlatformError::UbusError {
                operation: "broadcast_event".to_string(),
                reason: format!("serialization failed: {}", e),
            }
        })?;

        // Extract event type
        let event_type = match &event {
            UbusEvent::DhcpLeaseAdded { .. } => "dhcp.add",
            UbusEvent::DhcpLeaseOld { .. } => "dhcp.old",
            UbusEvent::DhcpLeaseDeleted { .. } => "dhcp.del",
            UbusEvent::NetworkChange => "network.change",
            #[cfg(feature = "conntrack")]
            UbusEvent::ConnmarkAllowlistRefused { .. } => "connmark-allowlist.refused",
            #[cfg(feature = "conntrack")]
            UbusEvent::ConnmarkAllowlistResolved { .. } => "connmark-allowlist.resolved",
        };

        debug!(event_type = %event_type, "Broadcasting event");

        // In a full implementation, we would call ubus_notify here.
        // For now, we log the event.
        // Note: Full C-level integration requires registering a ubus_object
        // and using ubus_notify with that object pointer.

        info!(event_type = %event_type, "Event broadcast (stub)");

        Ok(())
    }

    /// Create DHCP event from lease
    ///
    /// Helper method to construct DHCP event payloads from lease structures.
    ///
    /// # Arguments
    ///
    /// * `lease` - The DHCP lease
    /// * `event_type` - Type of event (add/old/del)
    ///
    /// # Returns
    ///
    /// Appropriate `UbusEvent` variant
    pub fn dhcp_event_from_lease(lease: &Lease, event_type: &str) -> UbusEvent {
        let ip = lease.ip.to_string();
        let mac = lease
            .mac
            .as_ref()
            .map(|m| m.to_string())
            .unwrap_or_else(|| "00:00:00:00:00:00".to_string());
        let hostname = lease.hostname.clone().unwrap_or_default();
        let interface = lease.interface.clone();

        match event_type {
            "add" => UbusEvent::DhcpLeaseAdded { ip, mac, hostname, interface },
            "old" => UbusEvent::DhcpLeaseOld { ip, mac, hostname, interface },
            "del" => UbusEvent::DhcpLeaseDeleted { ip, mac, hostname, interface },
            _ => panic!("Invalid DHCP event type: {}", event_type),
        }
    }

    /// Disconnect from ubusd daemon
    ///
    /// Unregisters the service and closes the connection to ubus daemon.
    /// Cleans up all resources associated with the connection.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// daemon.disconnect().await;
    /// ```
    #[instrument(skip(self))]
    pub async fn disconnect(&mut self) {
        if !self.connected {
            return;
        }

        debug!("Disconnecting from ubusd");

        if !self.ctx.is_null() {
            unsafe { ffi::ubus_free(self.ctx) };
            self.ctx = ptr::null_mut();
        }

        self.fd = None;
        self.connected = false;

        info!("Disconnected from ubusd");
    }
}

#[cfg(has_libubus)]
impl Drop for UbusDaemon {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            debug!("Cleaning up ubus connection");
            unsafe {
                ffi::ubus_free(self.ctx);
            }
            self.ctx = ptr::null_mut();
        }
    }
}

// Stub implementation when libubus is not available (feature enabled but library not found)
#[cfg(not(has_libubus))]
impl UbusDaemon {
    /// Create a new ubus daemon instance (stub)
    pub fn new(metrics: Arc<RwLock<MetricsCollector>>, service_name: Option<String>) -> Self {
        Self {
            ctx: ptr::null_mut(),
            service_name: service_name.unwrap_or_else(|| UBUS_SERVICE_NAME.to_string()),
            metrics,
            connected: false,
            fd: None,
        }
    }

    /// Connect to ubusd daemon (stub - always fails)
    #[instrument(skip(self))]
    pub async fn connect(&mut self) -> Result<(), PlatformError> {
        warn!("ubus support not compiled - libubus library not found");
        Err(PlatformError::UbusError {
            operation: "connect".to_string(),
            reason: "ubus support not compiled into binary - libubus library not found".to_string(),
        })
    }

    /// Check if connected to ubusd (stub - always false)
    #[must_use]
    pub fn is_connected(&self) -> bool {
        false
    }

    /// Run the ubus event loop (stub - immediately returns error)
    #[instrument(skip(self))]
    pub async fn run(&mut self) -> Result<(), PlatformError> {
        Err(PlatformError::UbusError {
            operation: "run".to_string(),
            reason: "ubus support not compiled into binary".to_string(),
        })
    }

    /// Attempt to reconnect to ubusd (stub - always fails)
    #[instrument(skip(self))]
    pub async fn reconnect(&mut self) -> Result<(), PlatformError> {
        Err(PlatformError::UbusError {
            operation: "reconnect".to_string(),
            reason: "ubus support not compiled into binary".to_string(),
        })
    }

    /// Handle metrics export method (stub)
    #[instrument(skip(self, _args))]
    pub async fn handle_metrics(&self, _args: Value) -> Result<Value, PlatformError> {
        Err(PlatformError::UbusError {
            operation: "handle_metrics".to_string(),
            reason: "ubus support not compiled into binary".to_string(),
        })
    }

    /// Handle connmark allowlist management method (stub)
    #[cfg(feature = "conntrack")]
    #[instrument(skip(self, _args))]
    pub async fn handle_set_connmark_allowlist(
        &self,
        _args: Value,
    ) -> Result<Value, PlatformError> {
        Err(PlatformError::UbusError {
            operation: "handle_set_connmark_allowlist".to_string(),
            reason: "ubus support not compiled into binary".to_string(),
        })
    }

    /// Broadcast an event over ubus (stub - silently succeeds but does nothing)
    #[instrument(skip(self, _event))]
    pub async fn broadcast_event(&self, _event: UbusEvent) -> Result<(), PlatformError> {
        debug!("ubus event broadcast skipped - support not compiled");
        Ok(())
    }

    /// Create DHCP event from lease (available even without libubus)
    #[must_use]
    pub fn dhcp_event_from_lease(lease: &Lease, event_type: &str) -> UbusEvent {
        let ip = lease.ip.to_string();
        let mac = lease
            .mac
            .as_ref()
            .map_or_else(|| "00:00:00:00:00:00".to_string(), std::string::ToString::to_string);
        let hostname = lease.hostname.clone().unwrap_or_default();
        let interface = lease.interface.clone();

        match event_type {
            "add" => UbusEvent::DhcpLeaseAdded { ip, mac, hostname, interface },
            "old" => UbusEvent::DhcpLeaseOld { ip, mac, hostname, interface },
            "del" => UbusEvent::DhcpLeaseDeleted { ip, mac, hostname, interface },
            _ => panic!("Invalid DHCP event type: {event_type}"),
        }
    }

    /// Disconnect from ubusd daemon (stub - no-op)
    #[instrument(skip(self))]
    pub async fn disconnect(&mut self) {
        // No-op in stub implementation
    }
}

#[cfg(not(has_libubus))]
impl Drop for UbusDaemon {
    fn drop(&mut self) {
        // No cleanup needed in stub implementation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ubus_error_display() {
        let err = UbusError::ConnectionFailed("test error".to_string());
        assert_eq!(err.to_string(), "ubus connection failed: test error");

        let err = UbusError::NotConnected;
        assert_eq!(err.to_string(), "ubus not connected");
    }

    #[test]
    fn test_ubus_event_serialization() {
        let event = UbusEvent::DhcpLeaseAdded {
            ip: "192.168.1.100".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            hostname: "client1".to_string(),
            interface: "eth0".to_string(),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "dhcp.add");
        assert_eq!(json["ip"], "192.168.1.100");
        assert_eq!(json["mac"], "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_ubus_daemon_new() {
        let metrics = Arc::new(RwLock::new(MetricsCollector::new()));
        let daemon = UbusDaemon::new(metrics, Some("test".to_string()));

        assert_eq!(daemon.service_name, "test");
        assert!(!daemon.is_connected());
    }

    #[test]
    fn test_dhcp_event_from_lease() {
        use crate::dhcp::lease::LeaseFlags;
        use crate::types::MacAddress;
        use std::net::IpAddr;
        use std::time::SystemTime;

        let lease = Lease {
            ip: "192.168.1.100".parse::<IpAddr>().unwrap(),
            mac: Some(MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
            hostname: Some("testhost".to_string()),
            interface: "eth0".to_string(),
            expires: SystemTime::now(),
            client_id: None,
            iaid: None,
            flags: LeaseFlags::empty(),
            fqdn: None,
            vendorclass: None,
            agent_id: None,
            slaac_addresses: None,
        };

        let event = UbusDaemon::dhcp_event_from_lease(&lease, "add");

        match event {
            UbusEvent::DhcpLeaseAdded { ip, mac, hostname, interface } => {
                assert_eq!(ip, "192.168.1.100");
                assert_eq!(mac, "aa:bb:cc:dd:ee:ff");
                assert_eq!(hostname, "testhost");
                assert_eq!(interface, "eth0");
            }
            _ => panic!("Wrong event type"),
        }
    }
}
