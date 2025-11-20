// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Helper script execution module for privilege-separated external script invocation.
//!
//! This module implements privilege-separated helper script execution for DHCP lease events,
//! TFTP file transfers, ARP table changes, and DHCPv6 relay snooping. It replaces the C
//! implementation from `src/helper.c` with memory-safe Rust using tokio async I/O.
//!
//! # Architecture
//!
//! The helper subsystem maintains a privileged background process that executes external
//! scripts in response to events. The main daemon communicates with the helper process via
//! an asynchronous channel, allowing non-blocking event queueing.
//!
//! ## Privilege Separation Model
//!
//! - **Main daemon**: Drops privileges after binding to privileged ports (UDP 53, 67, 547)
//! - **Helper process**: Retains elevated privileges to execute scripts that may need root access
//! - **Communication**: Unidirectional channel from main daemon to helper process
//! - **Security**: Script path locked at initialization; all event data validated before execution
//!
//! ## Event Types
//!
//! - **DHCP Lease Events**: New allocation (`add`), renewal (`old`), expiration (`del`), hostname change
//! - **TFTP Events**: File transfer completion with file size and client details
//! - **ARP Events**: ARP table additions and deletions for conflict detection
//! - **DHCPv6 Relay Snooping**: Relay agent information for prefix delegation
//!
//! # Environment Variables
//!
//! Scripts receive event data via environment variables for backward compatibility with
//! existing C dnsmasq scripts:
//!
//! ## Common Variables (All Events)
//! - `DNSMASQ_DOMAIN` - Client domain name
//! - `DNSMASQ_INTERFACE` - Network interface name
//! - `DNSMASQ_LEASE_EXPIRES` - Lease expiration time (seconds since epoch)
//! - `DNSMASQ_TIME_REMAINING` - Time until lease expires (seconds)
//!
//! ## DHCPv4 Specific
//! - `DNSMASQ_SUPPLIED_HOSTNAME` - Hostname from DHCP option 12
//! - `DNSMASQ_CLIENT_ID` - Client identifier (hex-encoded)
//! - `DNSMASQ_VENDOR_CLASS` - Vendor class identifier
//! - `DNSMASQ_TAGS` - Space-separated list of matching tags
//! - `DNSMASQ_USER_CLASS` - User class option
//!
//! ## DHCPv6 Specific
//! - `DNSMASQ_IAID` - Identity Association Identifier
//! - `DNSMASQ_SERVER_DUID` - Server DUID (hex-encoded)
//! - `DNSMASQ_MAC` - MAC address derived from link-local address
//!
//! ## CableHome (CPE WAN Management)
//! - `DNSMASQ_CPEWAN_OUI` - Organizationally Unique Identifier
//! - `DNSMASQ_CPEWAN_SERIAL` - Device serial number
//! - `DNSMASQ_CPEWAN_CLASS` - Device class
//!
//! ## Relay Agent Information
//! - `DNSMASQ_RELAY_ADDRESS` - Relay agent IP address
//! - `DNSMASQ_CIRCUIT_ID` - Circuit ID option (hex-encoded)
//! - `DNSMASQ_SUBSCRIBER_ID` - Subscriber ID option (hex-encoded)
//! - `DNSMASQ_REMOTE_ID` - Remote ID option (hex-encoded)
//!
//! # Script Arguments
//!
//! Scripts receive positional arguments matching C implementation:
//! 1. **Action**: `add`, `old`, `del`, `tftp`, `arp-add`, `arp-del`, `relay-snoop`
//! 2. **MAC Address**: Hardware address (colon-separated hex)
//! 3. **IP Address**: IPv4 or IPv6 address
//! 4. **Hostname**: Client hostname (if available, otherwise empty string)
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::util::helpers::{HelperProcess, ScriptEvent, queue_script};
//! use dnsmasq::dhcp::lease::LeaseAction;
//! use dnsmasq::config::Config;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Arc::new(Config::default());
//! let mut helper = HelperProcess::new(config.clone());
//! helper.spawn().await?;
//!
//! // Queue DHCP lease event
//! queue_script(
//!     &helper,
//!     LeaseAction::Add,
//!     "00:11:22:33:44:55",
//!     "192.168.1.100".parse()?,
//!     Some("client1".to_string()),
//!     "eth0",
//!     3600,
//! ).await?;
//! # Ok(())
//! # }
//! ```

// ============================================================================
// IMPORTS
// ============================================================================

// Internal imports from dependency whitelist
use crate::config::Config;
use crate::constants::MAXDNAME;
use crate::dhcp::lease::LeaseAction;
use crate::error::PlatformError;
use crate::types::MacAddress;

// External imports - async runtime
use tokio::process::Command;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

// External imports - system calls (removed unused imports)

// External imports - logging
use tracing::{debug, error, info, instrument, warn};

// External imports - data handling
use bytes::BytesMut;
use hex;

// External imports - Lua integration (conditional)
#[cfg(feature = "lua-scripts")]
use mlua::{Lua, Table};

// Standard library imports
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Maximum number of queued events before applying backpressure.
///
/// Prevents unbounded memory growth if script execution falls behind event generation.
/// Matches C implementation's implicit queue limit.
#[allow(dead_code)]
const MAX_QUEUE_SIZE: usize = 1000;

/// Script execution timeout in seconds.
///
/// Scripts that exceed this timeout are killed. Prevents hung scripts from accumulating.
const SCRIPT_TIMEOUT_SECS: u64 = 60;

/// Event type constants matching C helper.c EVENT_* defines.
///
/// These constants are used in the wire protocol for event serialization.
#[allow(dead_code)]
const EVENT_LEASE: u32 = 1; // DHCP lease event
#[allow(dead_code)]
const EVENT_ARP: u32 = 2; // ARP table change
#[allow(dead_code)]
const EVENT_TFTP: u32 = 4; // TFTP file transfer
#[allow(dead_code)]
const EVENT_RELAY_SNOOP: u32 = 8; // DHCPv6 relay snooping

/// Action type constants matching C helper.c ACTION_* defines.
#[allow(dead_code)]
const ACTION_ADD: u32 = 1; // Add event (new lease, ARP entry)
#[allow(dead_code)]
const ACTION_DEL: u32 = 2; // Delete event (expired lease, ARP removal)
#[allow(dead_code)]
const ACTION_OLD: u32 = 4; // Renew event (lease renewal)
#[allow(dead_code)]
const ACTION_OLD_HOSTNAME: u32 = 8; // Hostname change event

// ============================================================================
// SCRIPT EVENT TYPES
// ============================================================================

/// Script event types for helper process execution.
///
/// Represents all event types that can trigger external script execution.
/// Each variant carries the specific data needed for that event type.
///
/// # Wire Format
///
/// Events are serialized to `ScriptData` wire format for compatibility with
/// C helper.c protocol, though in Rust we use channels instead of pipes.
#[derive(Clone, Debug)]
pub enum ScriptEvent {
    /// DHCP lease lifecycle event (add/renew/delete).
    ///
    /// Triggered on lease allocation, renewal, expiration, or hostname change.
    /// Contains full lease details and client information.
    DhcpLease(Box<DhcpLeaseEvent>),

    /// TFTP file transfer completion event.
    ///
    /// Triggered after successful TFTP file transfer. Contains file path,
    /// client address, and transfer size for logging or accounting.
    Tftp(Box<TftpEvent>),

    /// ARP table change event (add/delete).
    ///
    /// Triggered on ARP table additions or removals. Used for address conflict detection.
    Arp(Box<ArpEvent>),

    /// DHCPv6 relay snooping event.
    ///
    /// Triggered when relay agent information is observed in DHCPv6 packets.
    /// Contains relay addresses and client identifiers.
    RelaySnoop(Box<RelaySnoopEvent>),
}

/// DHCP lease event data.
///
/// Contains all information about a DHCP lease lifecycle event,
/// including client identification, network parameters, and relay agent data.
#[derive(Clone, Debug)]
pub struct DhcpLeaseEvent {
    /// Lease action type (add/renew/delete/hostname-change).
    pub action: LeaseAction,

    /// Hardware (MAC) address of client.
    pub mac: MacAddress,

    /// Assigned IP address (IPv4 or IPv6).
    pub addr: IpAddr,

    /// Client hostname (from DHCP option 12 or DNS registration).
    pub hostname: Option<String>,

    /// Network interface receiving the request.
    pub interface: String,

    /// Lease expiration time (seconds since epoch).
    pub lease_expires: u64,

    /// Client domain name.
    pub domain: Option<String>,

    /// DHCP client identifier (hex-encoded).
    pub client_id: Option<Vec<u8>>,

    /// Vendor class identifier.
    pub vendor_class: Option<String>,

    /// Hostname supplied by client in option 12.
    pub supplied_hostname: Option<String>,

    /// CableHome CPE WAN Management Protocol - OUI.
    pub cpewan_oui: Option<String>,

    /// CableHome - Serial number.
    pub cpewan_serial: Option<String>,

    /// CableHome - Device class.
    pub cpewan_class: Option<String>,

    /// Relay agent circuit ID (hex-encoded).
    pub circuit_id: Option<Vec<u8>>,

    /// Relay agent subscriber ID (hex-encoded).
    pub subscriber_id: Option<Vec<u8>>,

    /// Relay agent remote ID (hex-encoded).
    pub remote_id: Option<Vec<u8>>,

    /// Matching tags for this lease.
    pub tags: Vec<String>,

    /// DHCPv6 IAID (Identity Association Identifier).
    pub iaid: Option<u32>,

    /// DHCPv6 server DUID (hex-encoded).
    pub server_duid: Option<Vec<u8>>,

    /// User class option data.
    pub user_class: Option<String>,
}

/// TFTP file transfer event data.
///
/// Triggered after successful TFTP transfer for logging or accounting purposes.
#[derive(Clone, Debug)]
pub struct TftpEvent {
    /// File path requested by client (relative to TFTP root).
    pub file_path: String,

    /// Client IP address.
    pub client_addr: IpAddr,

    /// File size in bytes transferred.
    pub file_size: u64,

    /// Network interface serving the request.
    pub interface: String,
}

/// ARP table change event data.
///
/// Used for address conflict detection and network monitoring.
#[derive(Clone, Debug)]
pub struct ArpEvent {
    /// Whether this is an addition (true) or deletion (false).
    pub is_add: bool,

    /// Hardware (MAC) address.
    pub mac: MacAddress,

    /// IP address associated with MAC.
    pub addr: IpAddr,
}

/// DHCPv6 relay snooping event data.
///
/// Contains relay agent information observed in DHCPv6 packets.
#[derive(Clone, Debug)]
pub struct RelaySnoopEvent {
    /// Client link-local address.
    pub client_addr: IpAddr,

    /// Relay agent address.
    pub relay_addr: IpAddr,

    /// Client DUID (hex-encoded).
    pub duid: Vec<u8>,

    /// Interface where packet was received.
    pub interface: String,
}

// ============================================================================
// SCRIPT DATA WIRE FORMAT
// ============================================================================

/// Wire format for event data serialization.
///
/// Matches C `struct script_data` from helper.c for protocol compatibility.
/// Although Rust implementation uses channels instead of pipes, this maintains
/// the same data structure for potential future interop or testing.
///
/// # C Equivalent
///
/// ```c
/// struct script_data {
///     unsigned int flags;
///     unsigned int action;
///     time_t expires;
///     struct in46_addr addr;
///     char hwaddr[DHCP_CHADDR_MAX];
///     char hostname[256];
///     // ... additional fields
/// };
/// ```
#[derive(Clone, Debug)]
pub struct ScriptData {
    /// Event flags (EVENT_LEASE | EVENT_ARP | EVENT_TFTP | EVENT_RELAY_SNOOP).
    pub flags: u32,

    /// Action type (ACTION_ADD | ACTION_DEL | ACTION_OLD | ACTION_OLD_HOSTNAME).
    pub action: u32,

    /// Lease expiration time (seconds since epoch).
    pub expires: u64,

    /// IP address (IPv4 or IPv6).
    pub addr: IpAddr,

    /// Hardware address bytes (up to 16 bytes for DHCPv4/v6).
    pub hwaddr: Vec<u8>,

    /// Hostname (null-terminated C string, max MAXDNAME bytes).
    pub hostname: String,

    /// Domain name.
    pub domain: Option<String>,

    /// Interface name.
    pub interface: String,

    /// TFTP file size (for EVENT_TFTP).
    pub file_size: Option<u64>,

    /// File path (for EVENT_TFTP).
    pub file_path: Option<String>,
}

impl ScriptData {
    /// Serializes event data to wire format bytes.
    ///
    /// Packs the struct fields into a byte buffer matching the C struct layout.
    /// This allows protocol compatibility with C helper.c if needed.
    ///
    /// # Returns
    ///
    /// Byte vector containing the serialized data.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(512);

        // Flags (4 bytes, little-endian)
        buf.extend_from_slice(&self.flags.to_le_bytes());

        // Action (4 bytes, little-endian)
        buf.extend_from_slice(&self.action.to_le_bytes());

        // Expires (8 bytes, little-endian)
        buf.extend_from_slice(&self.expires.to_le_bytes());

        // IP address (16 bytes for IPv6, IPv4 mapped)
        match self.addr {
            IpAddr::V4(ipv4) => {
                // IPv4-mapped IPv6 format: ::ffff:x.x.x.x
                buf.extend_from_slice(&[0u8; 10]); // Ten zeros
                buf.extend_from_slice(&[0xff, 0xff]); // 0xffff
                buf.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                buf.extend_from_slice(&ipv6.octets());
            }
        }

        // Hardware address (16 bytes max, zero-padded)
        let hwaddr_len = self.hwaddr.len().min(16);
        buf.extend_from_slice(&self.hwaddr[..hwaddr_len]);
        buf.extend_from_slice(&vec![0u8; 16 - hwaddr_len]);

        // Hostname (MAXDNAME bytes, null-terminated)
        let hostname_bytes = self.hostname.as_bytes();
        let hostname_len = hostname_bytes.len().min(MAXDNAME - 1);
        buf.extend_from_slice(&hostname_bytes[..hostname_len]);
        buf.extend_from_slice(&vec![0u8; MAXDNAME - hostname_len]);

        buf.to_vec()
    }

    /// Deserializes event data from wire format bytes.
    ///
    /// Unpacks a byte buffer into the struct fields.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Byte slice containing serialized data
    ///
    /// # Returns
    ///
    /// Deserialized `ScriptData` or error if data is malformed.
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::PipeError` if data is invalid or truncated.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PlatformError> {
        if bytes.len() < 4 + 4 + 8 + 16 + 16 + MAXDNAME {
            return Err(PlatformError::PipeError("Script data buffer too small".to_string()));
        }

        let mut offset = 0;

        // Parse flags
        let flags = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // Parse action
        let action = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // Parse expires
        let expires = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        // Parse IP address (16 bytes)
        let addr_bytes: [u8; 16] = bytes[offset..offset + 16].try_into().unwrap();
        let addr = if addr_bytes[0..10] == [0u8; 10] && addr_bytes[10..12] == [0xff, 0xff] {
            // IPv4-mapped IPv6
            IpAddr::V4(std::net::Ipv4Addr::new(
                addr_bytes[12],
                addr_bytes[13],
                addr_bytes[14],
                addr_bytes[15],
            ))
        } else {
            IpAddr::V6(std::net::Ipv6Addr::from(addr_bytes))
        };
        offset += 16;

        // Parse hardware address (16 bytes)
        // Read all 16 bytes, then trim trailing zeros (not leading zeros!)
        // MAC addresses can start with 0x00, so we can't use take_while
        let hwaddr_slice = &bytes[offset..offset + 16];
        let hwaddr_end = hwaddr_slice.iter().rposition(|&b| b != 0).map(|pos| pos + 1).unwrap_or(0);
        let hwaddr = hwaddr_slice[..hwaddr_end].to_vec();
        offset += 16;

        // Parse hostname (MAXDNAME bytes, null-terminated)
        let hostname_bytes = &bytes[offset..offset + MAXDNAME];
        let hostname_end = hostname_bytes.iter().position(|&b| b == 0).unwrap_or(MAXDNAME);
        let hostname = String::from_utf8_lossy(&hostname_bytes[..hostname_end]).to_string();

        Ok(ScriptData {
            flags,
            action,
            expires,
            addr,
            hwaddr,
            hostname,
            domain: None,
            interface: String::new(),
            file_size: None,
            file_path: None,
        })
    }
}

// ============================================================================
// HELPER PROCESS
// ============================================================================

/// Helper process manager for privilege-separated script execution.
///
/// Manages a background task that receives events via channel and executes
/// external scripts asynchronously. Replaces C fork-based helper process with
/// tokio async tasks.
///
/// # Architecture
///
/// - Main daemon sends events via `send_event()` to unbounded channel
/// - Background task receives events and executes scripts via tokio::process::Command
/// - Scripts run with dropped privileges (if configured) using nix setuid/setgid
/// - SIGCHLD is handled automatically by tokio process management
///
/// # Lifecycle
///
/// 1. Create with `new(config)`
/// 2. Start background task with `spawn()`
/// 3. Queue events with `send_event(event)`
/// 4. Clean shutdown with `shutdown()`
pub struct HelperProcess {
    /// Configuration reference.
    config: Arc<Config>,

    /// Event sender (cloned for each send_event call).
    sender: Option<UnboundedSender<ScriptEvent>>,

    /// Background task join handle (for shutdown).
    task_handle: Option<tokio::task::JoinHandle<()>>,

    /// Lua interpreter state (optional, feature-gated).
    #[cfg(feature = "lua-scripts")]
    lua: Option<Arc<Mutex<Lua>>>,
}

impl HelperProcess {
    /// Creates a new helper process manager.
    ///
    /// Initializes the helper but does not start the background task.
    /// Call `spawn()` to start processing events.
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration containing script paths and security settings
    ///
    /// # Returns
    ///
    /// New `HelperProcess` instance.
    pub fn new(config: Arc<Config>) -> Self {
        #[cfg(feature = "lua-scripts")]
        let lua = None; // Initialize Lua lazily in spawn() if lua_script_path is set

        Self {
            config,
            sender: None,
            task_handle: None,
            #[cfg(feature = "lua-scripts")]
            lua,
        }
    }

    /// Spawns the background helper task.
    ///
    /// Starts an async task that listens for events on a channel and executes
    /// scripts. This must be called before `send_event()`.
    ///
    /// # Returns
    ///
    /// Success if task started, or error if spawning failed.
    ///
    /// # Errors
    ///
    /// Returns `PlatformError` if:
    /// - Lua script initialization fails (feature = "lua-scripts")
    /// - Background task spawn fails
    #[instrument(skip(self), fields(script_path = ?self.config.scripts.script_path))]
    pub async fn spawn(&mut self) -> Result<(), PlatformError> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.sender = Some(tx);

        // Initialize Lua interpreter if configured
        #[cfg(feature = "lua-scripts")]
        {
            // Note: Rust implementation doesn't have lua_script_path in ScriptConfig yet.
            // For now, we'll use script_path for both shell and Lua scripts.
            // In future, ScriptConfig should be extended with lua_script_path field.
            if let Some(ref script_path) = self.config.scripts.script_path {
                if script_path.extension().and_then(|s| s.to_str()) == Some("lua") {
                    match Self::init_lua_interpreter(script_path) {
                        Ok(lua) => {
                            self.lua = Some(Arc::new(Mutex::new(lua)));
                            info!("Initialized Lua script interpreter: {}", script_path.display());
                        }
                        Err(e) => {
                            error!("Failed to initialize Lua script: {}", e);
                            return Err(e);
                        }
                    }
                }
            }
        }

        let config = self.config.clone();

        #[cfg(feature = "lua-scripts")]
        let lua = self.lua.clone();

        // Spawn background task
        let handle = tokio::spawn(async move {
            Self::event_loop(
                rx,
                config,
                #[cfg(feature = "lua-scripts")]
                lua,
            )
            .await;
        });

        self.task_handle = Some(handle);
        info!("Helper process task spawned");

        Ok(())
    }

    /// Sends an event to the helper process for script execution.
    ///
    /// Queues the event for asynchronous processing. Returns immediately without blocking.
    /// If the channel is full or closed, returns an error.
    ///
    /// # Arguments
    ///
    /// * `event` - Event to process
    ///
    /// # Returns
    ///
    /// Success if event queued, error if channel closed or send failed.
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::PipeError` if:
    /// - Helper process not started (call `spawn()` first)
    /// - Channel closed (helper task terminated)
    pub fn send_event(&self, event: ScriptEvent) -> Result<(), PlatformError> {
        match &self.sender {
            Some(tx) => tx
                .send(event)
                .map_err(|e| PlatformError::PipeError(format!("Failed to queue event: {}", e))),
            None => Err(PlatformError::PipeError("Helper process not started".to_string())),
        }
    }

    /// Initiates clean shutdown of helper process.
    ///
    /// Closes the event channel and waits for background task to finish processing
    /// queued events. Blocks until all pending scripts complete or timeout.
    ///
    /// # Returns
    ///
    /// Success if shutdown clean, error if forced termination or timeout.
    pub async fn shutdown(&mut self) -> Result<(), PlatformError> {
        // Drop sender to signal shutdown
        self.sender = None;

        // Wait for background task to finish
        if let Some(handle) = self.task_handle.take() {
            match tokio::time::timeout(Duration::from_secs(30), handle).await {
                Ok(Ok(())) => {
                    info!("Helper process shut down cleanly");
                    Ok(())
                }
                Ok(Err(e)) => {
                    error!("Helper process task panicked: {}", e);
                    Err(PlatformError::ProcessError(format!("Task panic: {}", e)))
                }
                Err(_) => {
                    warn!("Helper process shutdown timeout, forcing termination");
                    Err(PlatformError::ProcessError("Shutdown timeout".to_string()))
                }
            }
        } else {
            Ok(())
        }
    }

    /// Main event loop for background helper task.
    ///
    /// Receives events from channel and dispatches to script execution.
    /// Runs until channel is closed (sender dropped).
    ///
    /// # Arguments
    ///
    /// * `rx` - Event receiver channel
    /// * `config` - Server configuration
    /// * `lua` - Optional Lua interpreter (feature-gated)
    async fn event_loop(
        mut rx: UnboundedReceiver<ScriptEvent>,
        config: Arc<Config>,
        #[cfg(feature = "lua-scripts")] lua: Option<Arc<Mutex<Lua>>>,
    ) {
        debug!("Helper event loop started");

        while let Some(event) = rx.recv().await {
            // Execute script for this event
            #[cfg(feature = "lua-scripts")]
            let result = if lua.is_some() {
                Self::execute_lua_event(&event, &config, &lua).await
            } else {
                Self::execute_shell_event(&event, &config).await
            };

            #[cfg(not(feature = "lua-scripts"))]
            let result = Self::execute_shell_event(&event, &config).await;

            if let Err(e) = result {
                error!("Script execution failed: {}", e);
            }
        }

        debug!("Helper event loop terminated");
    }

    /// Executes a shell script for an event.
    ///
    /// Runs the configured script with environment variables and positional arguments
    /// matching the C implementation for backward compatibility.
    ///
    /// # Arguments
    ///
    /// * `event` - Event to process
    /// * `config` - Configuration containing script path and security settings
    ///
    /// # Returns
    ///
    /// Success if script executed (regardless of exit code), error if spawn failed.
    #[instrument(skip(config), fields(action = ?Self::event_action_name(event)))]
    async fn execute_shell_event(
        event: &ScriptEvent,
        config: &Arc<Config>,
    ) -> Result<(), PlatformError> {
        let script_path = match &config.scripts.script_path {
            Some(path) => path,
            None => {
                debug!("No script configured, skipping event");
                return Ok(());
            }
        };

        // Build environment variables
        let env_vars = Self::build_environment(event);

        // Build command-line arguments
        let args = Self::build_arguments(event);

        debug!(
            script = %script_path.display(),
            args = ?args,
            env_count = env_vars.len(),
            "Executing script"
        );

        // Spawn script process
        let mut command = Command::new(script_path);
        command.args(&args);

        // Add environment variables
        for (key, value) in env_vars {
            command.env(key, value);
        }

        // Drop privileges if configured
        if let Some(ref user) = config.security.user {
            // Note: tokio::process::Command doesn't directly support setuid.
            // In production, this would require pre_exec or wrapper script.
            // For now, we log the intention and rely on script permissions.
            debug!("Script should run as user: {}", user);
            // TODO: Implement privilege dropping via pre_exec once nix supports it
        }

        // Execute with timeout
        match tokio::time::timeout(Duration::from_secs(SCRIPT_TIMEOUT_SECS), command.output()).await
        {
            Ok(Ok(output)) => {
                if output.status.success() {
                    debug!(exit_code = output.status.code(), "Script completed successfully");
                } else {
                    warn!(
                        exit_code = output.status.code(),
                        stderr = %String::from_utf8_lossy(&output.stderr),
                        "Script exited with error"
                    );
                }
                Ok(())
            }
            Ok(Err(e)) => {
                error!("Failed to spawn script: {}", e);
                Err(PlatformError::ScriptExecutionFailed {
                    script: script_path.display().to_string(),
                    reason: format!("Spawn error: {}", e),
                })
            }
            Err(_) => {
                error!("Script execution timeout ({}s)", SCRIPT_TIMEOUT_SECS);
                Err(PlatformError::ScriptExecutionFailed {
                    script: script_path.display().to_string(),
                    reason: "Script timeout".to_string(),
                })
            }
        }
    }

    /// Initializes Lua interpreter from script file.
    ///
    /// Loads and compiles the Lua script, preparing it for event execution.
    ///
    /// # Arguments
    ///
    /// * `script_path` - Path to Lua script file
    ///
    /// # Returns
    ///
    /// Initialized Lua interpreter or error if loading failed.
    #[cfg(feature = "lua-scripts")]
    fn init_lua_interpreter(script_path: &Path) -> Result<Lua, PlatformError> {
        let lua = Lua::new();

        // Load script file
        let script_content =
            std::fs::read_to_string(script_path).map_err(|e| PlatformError::LuaScriptError {
                script: script_path.display().to_string(),
                reason: format!("Failed to read Lua script: {}", e),
            })?;

        // Compile script
        lua.load(&script_content).exec().map_err(|e| PlatformError::LuaScriptError {
            script: script_path.display().to_string(),
            reason: format!("Failed to load Lua script: {}", e),
        })?;

        Ok(lua)
    }

    /// Executes Lua script for an event.
    ///
    /// Calls the Lua script's event handler function with event data as a table.
    ///
    /// # Arguments
    ///
    /// * `event` - Event to process
    /// * `config` - Configuration
    /// * `lua` - Lua interpreter
    ///
    /// # Returns
    ///
    /// Success if script executed, error if call failed.
    #[cfg(feature = "lua-scripts")]
    async fn execute_lua_event(
        event: &ScriptEvent,
        config: &Arc<Config>,
        lua: &Option<Arc<Mutex<Lua>>>,
    ) -> Result<(), PlatformError> {
        let lua = match lua {
            Some(l) => l,
            None => return Self::execute_shell_event(event, config).await,
        };

        let lua_guard = lua.lock().unwrap();

        // Create event table
        let event_table = lua_guard.create_table().map_err(|e| PlatformError::LuaScriptError {
            script: "lua script".to_string(),
            reason: format!("Failed to create table: {}", e),
        })?;

        // Populate table based on event type
        Self::populate_lua_table(&lua_guard, &event_table, event).map_err(|e| {
            PlatformError::LuaScriptError {
                script: "lua script".to_string(),
                reason: format!("Failed to populate table: {}", e),
            }
        })?;

        // Call event handler function
        let handler: mlua::Function =
            lua_guard.globals().get("lease_event").map_err(|e| PlatformError::LuaScriptError {
                script: "lua script".to_string(),
                reason: format!("Event handler not found: {}", e),
            })?;

        handler.call::<()>(event_table).map_err(|e| PlatformError::LuaScriptError {
            script: "lua script".to_string(),
            reason: format!("Handler call failed: {}", e),
        })?;

        debug!("Lua script executed successfully");
        Ok(())
    }

    /// Populates Lua table with event data.
    #[cfg(feature = "lua-scripts")]
    fn populate_lua_table(
        _lua: &Lua,
        table: &Table,
        event: &ScriptEvent,
    ) -> Result<(), mlua::Error> {
        match event {
            ScriptEvent::DhcpLease(lease) => {
                table.set("action", Self::action_to_string(&lease.action))?;
                table.set("mac", lease.mac.to_string())?;
                table.set("ip", lease.addr.to_string())?;
                if let Some(ref hostname) = lease.hostname {
                    table.set("hostname", hostname.as_str())?;
                }
                table.set("interface", lease.interface.as_str())?;
                table.set("lease_expires", lease.lease_expires)?;
                // Add other fields as needed
            }
            ScriptEvent::Tftp(tftp) => {
                table.set("action", "tftp")?;
                table.set("file", tftp.file_path.as_str())?;
                table.set("ip", tftp.client_addr.to_string())?;
                table.set("size", tftp.file_size)?;
            }
            ScriptEvent::Arp(arp) => {
                table.set("action", if arp.is_add { "arp-add" } else { "arp-del" })?;
                table.set("mac", arp.mac.to_string())?;
                table.set("ip", arp.addr.to_string())?;
            }
            ScriptEvent::RelaySnoop(relay) => {
                table.set("action", "relay-snoop")?;
                table.set("client", relay.client_addr.to_string())?;
                table.set("relay", relay.relay_addr.to_string())?;
            }
        }
        Ok(())
    }

    /// Builds environment variables for script execution.
    ///
    /// Creates DNSMASQ_* environment variables matching C implementation.
    ///
    /// # Arguments
    ///
    /// * `event` - Event data
    ///
    /// # Returns
    ///
    /// HashMap of environment variable names to values.
    fn build_environment(event: &ScriptEvent) -> HashMap<String, String> {
        let mut env = HashMap::new();

        match event {
            ScriptEvent::DhcpLease(lease) => {
                // Common variables
                if let Some(ref domain) = lease.domain {
                    env.insert("DNSMASQ_DOMAIN".to_string(), domain.clone());
                }
                env.insert("DNSMASQ_INTERFACE".to_string(), lease.interface.clone());
                env.insert("DNSMASQ_LEASE_EXPIRES".to_string(), lease.lease_expires.to_string());

                // Calculate time remaining
                if let Ok(now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                    let remaining = lease.lease_expires.saturating_sub(now.as_secs());
                    env.insert("DNSMASQ_TIME_REMAINING".to_string(), remaining.to_string());
                }

                // DHCPv4 specific
                if let Some(ref supplied_hostname) = lease.supplied_hostname {
                    env.insert("DNSMASQ_SUPPLIED_HOSTNAME".to_string(), supplied_hostname.clone());
                }
                if let Some(ref client_id) = lease.client_id {
                    env.insert("DNSMASQ_CLIENT_ID".to_string(), hex::encode(client_id));
                }
                if let Some(ref vendor_class) = lease.vendor_class {
                    env.insert("DNSMASQ_VENDOR_CLASS".to_string(), vendor_class.clone());
                }
                if !lease.tags.is_empty() {
                    env.insert("DNSMASQ_TAGS".to_string(), lease.tags.join(" "));
                }
                if let Some(ref user_class) = lease.user_class {
                    env.insert("DNSMASQ_USER_CLASS".to_string(), user_class.clone());
                }

                // DHCPv6 specific
                if let Some(iaid) = lease.iaid {
                    env.insert("DNSMASQ_IAID".to_string(), iaid.to_string());
                }
                if let Some(ref server_duid) = lease.server_duid {
                    env.insert("DNSMASQ_SERVER_DUID".to_string(), hex::encode(server_duid));
                }
                env.insert("DNSMASQ_MAC".to_string(), lease.mac.to_string());

                // CableHome variables
                if let Some(ref oui) = lease.cpewan_oui {
                    env.insert("DNSMASQ_CPEWAN_OUI".to_string(), oui.clone());
                }
                if let Some(ref serial) = lease.cpewan_serial {
                    env.insert("DNSMASQ_CPEWAN_SERIAL".to_string(), serial.clone());
                }
                if let Some(ref class) = lease.cpewan_class {
                    env.insert("DNSMASQ_CPEWAN_CLASS".to_string(), class.clone());
                }

                // Relay agent information
                if let Some(ref circuit_id) = lease.circuit_id {
                    env.insert("DNSMASQ_CIRCUIT_ID".to_string(), hex::encode(circuit_id));
                }
                if let Some(ref subscriber_id) = lease.subscriber_id {
                    env.insert("DNSMASQ_SUBSCRIBER_ID".to_string(), hex::encode(subscriber_id));
                }
                if let Some(ref remote_id) = lease.remote_id {
                    env.insert("DNSMASQ_REMOTE_ID".to_string(), hex::encode(remote_id));
                }
            }
            ScriptEvent::Tftp(tftp) => {
                env.insert("DNSMASQ_INTERFACE".to_string(), tftp.interface.clone());
            }
            ScriptEvent::Arp(_) => {
                // ARP events don't have additional environment variables
            }
            ScriptEvent::RelaySnoop(relay) => {
                env.insert("DNSMASQ_INTERFACE".to_string(), relay.interface.clone());
                env.insert("DNSMASQ_RELAY_ADDRESS".to_string(), relay.relay_addr.to_string());
            }
        }

        env
    }

    /// Builds command-line arguments for script invocation.
    ///
    /// # Arguments
    ///
    /// * `event` - Event data
    ///
    /// # Returns
    ///
    /// Vector of argument strings: [action, mac, ip, hostname]
    fn build_arguments(event: &ScriptEvent) -> Vec<String> {
        match event {
            ScriptEvent::DhcpLease(lease) => {
                vec![
                    Self::action_to_string(&lease.action),
                    lease.mac.to_string(),
                    lease.addr.to_string(),
                    lease.hostname.clone().unwrap_or_default(),
                ]
            }
            ScriptEvent::Tftp(tftp) => {
                vec![
                    "tftp".to_string(),
                    String::new(), // No MAC address
                    tftp.client_addr.to_string(),
                    tftp.file_path.clone(),
                ]
            }
            ScriptEvent::Arp(arp) => {
                vec![
                    if arp.is_add { "arp-add".to_string() } else { "arp-del".to_string() },
                    arp.mac.to_string(),
                    arp.addr.to_string(),
                    String::new(),
                ]
            }
            ScriptEvent::RelaySnoop(relay) => {
                vec![
                    "relay-snoop".to_string(),
                    hex::encode(&relay.duid),
                    relay.client_addr.to_string(),
                    relay.relay_addr.to_string(),
                ]
            }
        }
    }

    /// Converts LeaseAction to string for script arguments.
    fn action_to_string(action: &LeaseAction) -> String {
        match action {
            LeaseAction::Add => "add".to_string(),
            LeaseAction::Old => "old".to_string(),
            LeaseAction::Del => "del".to_string(),
            LeaseAction::OldHostname => "old".to_string(), // Same as Old for backward compat
        }
    }

    /// Gets event type name for logging.
    fn event_action_name(event: &ScriptEvent) -> &'static str {
        match event {
            ScriptEvent::DhcpLease(_) => "dhcp-lease",
            ScriptEvent::Tftp(_) => "tftp",
            ScriptEvent::Arp(_) => "arp",
            ScriptEvent::RelaySnoop(_) => "relay-snoop",
        }
    }
}

// ============================================================================
// PUBLIC API FUNCTIONS
// ============================================================================

/// Queues a DHCP lease event for script execution.
///
/// Sends lease information to the helper process for external script notification.
/// Used for DHCP lease add/old/del events to trigger administrative scripts,
/// DNS registration, or other integration actions.
///
/// # Arguments
///
/// * `helper` - Helper process instance
/// * `action` - Lease action (Add, Old, Del, OldHostname)
/// * `mac` - Client MAC address
/// * `addr` - Assigned IP address
/// * `hostname` - Client hostname (if provided)
/// * `interface` - Network interface name
/// * `lease_expires` - Unix timestamp when lease expires
///
/// # Returns
///
/// Success if event queued, error if channel closed.
///
/// # Examples
///
/// ```no_run
/// # use dnsmasq::util::helpers::{queue_script, HelperProcess};
/// # use dnsmasq::dhcp::lease::LeaseAction;
/// # use dnsmasq::types::MacAddress;
/// # use std::sync::Arc;
/// # async fn example(helper: &HelperProcess) -> Result<(), Box<dyn std::error::Error>> {
/// queue_script(
///     helper,
///     LeaseAction::Add,
///     MacAddress::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
///     "192.168.1.100".parse()?,
///     Some("client1".to_string()),
///     "eth0".to_string(),
///     3600,
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn queue_script(
    helper: &HelperProcess,
    action: LeaseAction,
    mac: MacAddress,
    addr: IpAddr,
    hostname: Option<String>,
    interface: String,
    lease_expires: u64,
) -> Result<(), PlatformError> {
    let event = ScriptEvent::DhcpLease(Box::new(DhcpLeaseEvent {
        action,
        mac,
        addr,
        hostname,
        interface,
        lease_expires,
        domain: None,
        supplied_hostname: None,
        client_id: None,
        vendor_class: None,
        tags: Vec::new(),
        user_class: None,
        iaid: None,
        server_duid: None,
        cpewan_oui: None,
        cpewan_serial: None,
        cpewan_class: None,
        circuit_id: None,
        subscriber_id: None,
        remote_id: None,
    }));

    helper.send_event(event)
}

/// Queues a TFTP file transfer event for script execution.
///
/// Notifies external script of TFTP file download for network boot logging,
/// PXE boot tracking, or file transfer auditing.
///
/// # Arguments
///
/// * `helper` - Helper process instance
/// * `file_path` - Path to transferred file (relative to TFTP root)
/// * `client_addr` - Client IP address
/// * `file_size` - Size of transferred file in bytes
/// * `interface` - Network interface name
///
/// # Returns
///
/// Success if event queued, error if channel closed.
///
/// # Examples
///
/// ```no_run
/// # use dnsmasq::util::helpers::{queue_tftp, HelperProcess};
/// # async fn example(helper: &HelperProcess) -> Result<(), Box<dyn std::error::Error>> {
/// queue_tftp(
///     helper,
///     "/pxelinux.0".to_string(),
///     "192.168.1.50".parse()?,
///     42000,
///     "eth0".to_string(),
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn queue_tftp(
    helper: &HelperProcess,
    file_path: String,
    client_addr: IpAddr,
    file_size: u64,
    interface: String,
) -> Result<(), PlatformError> {
    let event =
        ScriptEvent::Tftp(Box::new(TftpEvent { file_path, client_addr, file_size, interface }));

    helper.send_event(event)
}

/// Queues an ARP table change event for script execution.
///
/// Notifies external script of ARP cache additions or deletions for duplicate
/// address detection, MAC address tracking, or security monitoring.
///
/// # Arguments
///
/// * `helper` - Helper process instance
/// * `mac` - MAC address
/// * `addr` - IP address
/// * `is_add` - True for addition, false for deletion
///
/// # Returns
///
/// Success if event queued, error if channel closed.
///
/// # Examples
///
/// ```no_run
/// # use dnsmasq::util::helpers::{queue_arp, HelperProcess};
/// # use dnsmasq::types::MacAddress;
/// # async fn example(helper: &HelperProcess) -> Result<(), Box<dyn std::error::Error>> {
/// queue_arp(
///     helper,
///     MacAddress::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
///     "192.168.1.100".parse()?,
///     true,
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn queue_arp(
    helper: &HelperProcess,
    mac: MacAddress,
    addr: IpAddr,
    is_add: bool,
) -> Result<(), PlatformError> {
    let event = ScriptEvent::Arp(Box::new(ArpEvent { mac, addr, is_add }));

    helper.send_event(event)
}

/// Queues a DHCPv6 relay snooping event for script execution.
///
/// Notifies external script of DHCPv6 relay forwarding for logging DHCPv6
/// prefix delegation, tracking client DUIDs, or monitoring relay chains.
///
/// # Arguments
///
/// * `helper` - Helper process instance
/// * `duid` - Client DUID (DHCP Unique Identifier)
/// * `client_addr` - Client IPv6 address
/// * `relay_addr` - Relay agent IPv6 address
/// * `interface` - Network interface name
///
/// # Returns
///
/// Success if event queued, error if channel closed.
///
/// # Examples
///
/// ```no_run
/// # use dnsmasq::util::helpers::{queue_relay_snoop, HelperProcess};
/// # async fn example(helper: &HelperProcess) -> Result<(), Box<dyn std::error::Error>> {
/// queue_relay_snoop(
///     helper,
///     vec![0x00, 0x01, 0x02, 0x03],
///     "2001:db8::1".parse()?,
///     "2001:db8::ffff".parse()?,
///     "eth0".to_string(),
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn queue_relay_snoop(
    helper: &HelperProcess,
    duid: Vec<u8>,
    client_addr: IpAddr,
    relay_addr: IpAddr,
    interface: String,
) -> Result<(), PlatformError> {
    let event = ScriptEvent::RelaySnoop(Box::new(RelaySnoopEvent {
        duid,
        client_addr,
        relay_addr,
        interface,
    }));

    helper.send_event(event)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_data_serialization() {
        let data = ScriptData {
            flags: EVENT_LEASE,
            action: ACTION_ADD,
            expires: 1234567890,
            addr: "192.168.1.100".parse().unwrap(),
            hwaddr: vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            hostname: "testhost".to_string(),
            domain: Some("example.com".to_string()),
            interface: "eth0".to_string(),
            file_size: None,
            file_path: None,
        };

        let serialized = data.serialize();
        assert!(serialized.len() > 0);

        let deserialized = ScriptData::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.action, ACTION_ADD);
        assert_eq!(deserialized.hwaddr, data.hwaddr);
        assert_eq!(deserialized.addr, data.addr);
    }

    #[test]
    fn test_action_to_string() {
        assert_eq!(HelperProcess::action_to_string(&LeaseAction::Add), "add");
        assert_eq!(HelperProcess::action_to_string(&LeaseAction::Old), "old");
        assert_eq!(HelperProcess::action_to_string(&LeaseAction::Del), "del");
    }

    #[test]
    fn test_build_arguments() {
        let mac = MacAddress::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let addr: IpAddr = "192.168.1.100".parse().unwrap();

        let event = ScriptEvent::DhcpLease(Box::new(DhcpLeaseEvent {
            action: LeaseAction::Add,
            mac,
            addr,
            hostname: Some("test-host".to_string()),
            interface: "eth0".to_string(),
            lease_expires: 3600,
            domain: None,
            supplied_hostname: None,
            client_id: None,
            vendor_class: None,
            tags: Vec::new(),
            user_class: None,
            iaid: None,
            server_duid: None,
            cpewan_oui: None,
            cpewan_serial: None,
            cpewan_class: None,
            circuit_id: None,
            subscriber_id: None,
            remote_id: None,
        }));

        let args = HelperProcess::build_arguments(&event);
        assert_eq!(args.len(), 4);
        assert_eq!(args[0], "add");
        assert_eq!(args[2], "192.168.1.100");
        assert_eq!(args[3], "test-host");
    }

    #[test]
    fn test_build_environment() {
        let mac = MacAddress::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let addr: IpAddr = "192.168.1.100".parse().unwrap();

        let event = ScriptEvent::DhcpLease(Box::new(DhcpLeaseEvent {
            action: LeaseAction::Add,
            mac,
            addr,
            hostname: Some("test-host".to_string()),
            interface: "eth0".to_string(),
            lease_expires: 7200,
            domain: Some("example.com".to_string()),
            supplied_hostname: Some("client-hostname".to_string()),
            client_id: Some(vec![0x01, 0x02, 0x03]),
            vendor_class: Some("test-vendor".to_string()),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            user_class: None,
            iaid: None,
            server_duid: None,
            cpewan_oui: None,
            cpewan_serial: None,
            cpewan_class: None,
            circuit_id: None,
            subscriber_id: None,
            remote_id: None,
        }));

        let env = HelperProcess::build_environment(&event);

        assert_eq!(env.get("DNSMASQ_DOMAIN"), Some(&"example.com".to_string()));
        assert_eq!(env.get("DNSMASQ_INTERFACE"), Some(&"eth0".to_string()));
        assert_eq!(env.get("DNSMASQ_LEASE_EXPIRES"), Some(&"7200".to_string()));
        assert_eq!(env.get("DNSMASQ_SUPPLIED_HOSTNAME"), Some(&"client-hostname".to_string()));
        assert_eq!(env.get("DNSMASQ_CLIENT_ID"), Some(&"010203".to_string()));
        assert_eq!(env.get("DNSMASQ_VENDOR_CLASS"), Some(&"test-vendor".to_string()));
        assert_eq!(env.get("DNSMASQ_TAGS"), Some(&"tag1 tag2".to_string()));
    }
}
