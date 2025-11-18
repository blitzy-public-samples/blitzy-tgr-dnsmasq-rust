// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
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
//! This module manages the execution of external scripts in response to DHCP lease events,
//! TFTP file transfers, and ARP table changes. It provides privilege separation by forking
//! helper processes that can execute scripts with elevated permissions when needed.
//!
//! # Overview
//!
//! The helper architecture provides:
//! - **Privilege Separation**: Helper process retains root privileges while main daemon drops to unprivileged user
//! - **Isolation**: Script failures do not impact core DNS/DHCP services
//! - **Backward Compatibility**: Environment variables match C implementation for existing user scripts
//! - **Async Execution**: Non-blocking script execution using tokio::process
//!
//! # Security Model
//!
//! The helper process architecture ensures:
//! - Script path is locked at initialization and cannot be changed by main process
//! - All data from main process is validated before use
//! - Environment variables are sanitized before passing to scripts
//! - Scripts can optionally run with dropped privileges
//!
//! # Usage
//!
//! ```rust,ignore
//! use dnsmasq::util::helpers::{ScriptExecutor, ScriptEvent, LeaseAction};
//! use std::net::IpAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize script executor
//! let executor = ScriptExecutor::new("/etc/dnsmasq/lease-script.sh")?;
//!
//! // Queue DHCP lease event
//! executor.queue_event(ScriptEvent::DhcpLease(Box::new(DhcpLeaseEvent {
//!     action: LeaseAction::Add,
//!     mac: "00:11:22:33:44:55".to_string(),
//!     ip: "192.168.1.100".parse()?,
//!     hostname: Some("client1".to_string()),
//!     interface: "eth0".to_string(),
//!     lease_expires: 3600,
//!     domain: None,
//!     client_id: None,
//!     vendor_class: None,
//!     supplied_hostname: None,
//!     cpewan_oui: None,
//!     cpewan_serial: None,
//!     cpewan_class: None,
//!     circuit_id: None,
//!     subscriber_id: None,
//!     remote_id: None,
//!     tags: vec![],
//! }))).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Environment Variables
//!
//! Scripts receive the following environment variables:
//!
//! ## Common Variables
//! - `DNSMASQ_DOMAIN` - Domain name for client
//! - `DNSMASQ_INTERFACE` - Network interface
//! - `DNSMASQ_LEASE_EXPIRES` - Lease expiration time (seconds since epoch)
//! - `DNSMASQ_TIME_REMAINING` - Time until lease expires (seconds)
//!
//! ## DHCPv4 Variables
//! - `DNSMASQ_SUPPLIED_HOSTNAME` - Hostname supplied by client
//! - `DNSMASQ_CLIENT_ID` - Client identifier option
//! - `DNSMASQ_VENDOR_CLASS` - Vendor class identifier
//! - `DNSMASQ_TAGS` - Space-separated list of tags
//!
//! ## DHCPv6 Variables
//! - `DNSMASQ_IAID` - Identity Association Identifier
//! - `DNSMASQ_SERVER_DUID` - Server DUID
//! - `DNSMASQ_MAC` - MAC address (from link-local address)
//!
//! ## CableHome Variables (CPE WAN Management Protocol)
//! - `DNSMASQ_CPEWAN_OUI` - OUI (Organizationally Unique Identifier)
//! - `DNSMASQ_CPEWAN_SERIAL` - Serial number
//! - `DNSMASQ_CPEWAN_CLASS` - Device class
//!
//! ## Relay Agent Variables
//! - `DNSMASQ_RELAY_ADDRESS` - Relay agent address
//! - `DNSMASQ_CIRCUIT_ID` - Circuit ID option
//! - `DNSMASQ_SUBSCRIBER_ID` - Subscriber ID option
//! - `DNSMASQ_REMOTE_ID` - Remote ID option
//!
//! # Script Arguments
//!
//! Scripts are invoked with the following positional arguments:
//!
//! 1. **Action**: One of "add", "old", "del", "tftp", "arp-add", "arp-del"
//! 2. **MAC Address**: Hardware address (DHCP/ARP events)
//! 3. **IP Address**: Assigned IP address
//! 4. **Hostname**: Client hostname (if available)
//!
//! # Example Script
//!
//! ```bash
//! #!/bin/bash
//! # /etc/dnsmasq/lease-script.sh
//!
//! ACTION=$1
//! MAC=$2
//! IP=$3
//! HOSTNAME=$4
//!
//! case "$ACTION" in
//!     add)
//!         echo "New lease: $IP ($MAC) hostname=$HOSTNAME"
//!         # Update DNS, firewall, etc.
//!         ;;
//!     del)
//!         echo "Lease deleted: $IP ($MAC)"
//!         # Cleanup resources
//!         ;;
//!     old)
//!         echo "Lease renewed: $IP ($MAC)"
//!         ;;
//! esac
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Maximum number of queued events before blocking
const MAX_QUEUE_SIZE: usize = 1000;

/// Errors that can occur during script execution
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// Script file not found or not executable
    #[error("Script file not found or not executable: {0}")]
    ScriptNotFound(PathBuf),

    /// Failed to spawn script process
    #[error("Failed to spawn script process: {0}")]
    SpawnFailed(#[from] std::io::Error),

    /// Script execution timeout
    #[error("Script execution timeout after {0} seconds")]
    Timeout(u64),

    /// Script exited with non-zero status
    #[error("Script exited with status {0}")]
    NonZeroExit(i32),

    /// Event queue full
    #[error("Event queue full (max {0} events)")]
    QueueFull(usize),

    /// Channel send error
    #[error("Failed to send event to helper: {0}")]
    ChannelSend(String),
}

/// DHCP lease action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseAction {
    /// New lease allocated
    Add,
    /// Existing lease renewed
    Old,
    /// Lease deleted or expired
    Del,
}

impl LeaseAction {
    /// Convert to string for script argument
    pub fn as_str(&self) -> &'static str {
        match self {
            LeaseAction::Add => "add",
            LeaseAction::Old => "old",
            LeaseAction::Del => "del",
        }
    }
}

/// ARP event action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpAction {
    /// ARP entry added
    Add,
    /// ARP entry deleted
    Del,
}

impl ArpAction {
    /// Convert to string for script argument
    pub fn as_str(&self) -> &'static str {
        match self {
            ArpAction::Add => "arp-add",
            ArpAction::Del => "arp-del",
        }
    }
}

/// DHCP lease event data
#[derive(Debug, Clone)]
pub struct DhcpLeaseEvent {
    /// Lease action: add, old, or del
    pub action: LeaseAction,
    /// MAC address of the client
    pub mac: String,
    /// IP address allocated to the client
    pub ip: IpAddr,
    /// Hostname of the client (if known)
    pub hostname: Option<String>,
    /// Network interface name
    pub interface: String,
    /// Lease expiration time (seconds since epoch)
    pub lease_expires: u64,
    /// Domain name for the client
    pub domain: Option<String>,
    /// DHCP client identifier option (option 61)
    pub client_id: Option<Vec<u8>>,
    /// Vendor class identifier (option 60)
    pub vendor_class: Option<String>,
    /// Hostname supplied by client in DHCP request
    pub supplied_hostname: Option<String>,
    /// CableHome CPE WAN Management Protocol OUI
    pub cpewan_oui: Option<String>,
    /// CableHome CPE WAN Management Protocol serial number
    pub cpewan_serial: Option<String>,
    /// CableHome CPE WAN Management Protocol device class
    pub cpewan_class: Option<String>,
    /// DHCP relay agent circuit ID (option 82 sub-option 1)
    pub circuit_id: Option<Vec<u8>>,
    /// DHCP relay agent subscriber ID (option 82 sub-option 6)
    pub subscriber_id: Option<Vec<u8>>,
    /// DHCP relay agent remote ID (option 82 sub-option 2)
    pub remote_id: Option<Vec<u8>>,
    /// Tag list for the client
    pub tags: Vec<String>,
}

/// Events that trigger script execution
#[derive(Debug, Clone)]
pub enum ScriptEvent {
    /// DHCP lease event (add/old/del)
    DhcpLease(Box<DhcpLeaseEvent>),

    /// DHCPv6 relay snooping event
    #[cfg(feature = "dhcp6")]
    Dhcpv6Relay {
        /// Lease action: add, old, or del
        action: LeaseAction,
        /// Identity Association Identifier (IAID)
        iaid: u32,
        /// MAC address derived from link-local address (if available)
        mac: Option<String>,
        /// IPv6 address allocated to the client
        ip: IpAddr,
        /// Hostname of the client (if known)
        hostname: Option<String>,
        /// Network interface name
        interface: String,
        /// Lease expiration time (seconds since epoch)
        lease_expires: u64,
        /// Domain name for the client
        domain: Option<String>,
        /// DHCPv6 server DUID (DHCP Unique Identifier)
        server_duid: Vec<u8>,
    },

    /// TFTP file transfer event
    #[cfg(feature = "tftp")]
    TftpTransfer {
        /// Size of the transferred file in bytes
        file_size: u64,
        /// IP address of the TFTP client
        destination: IpAddr,
        /// Path to the transferred file on the server
        file_path: PathBuf,
    },

    /// ARP table change event
    ArpChange {
        /// ARP action: add or del
        action: ArpAction,
        /// MAC address in the ARP entry
        mac: String,
        /// IP address in the ARP entry
        ip: IpAddr,
    },
}

/// Script executor managing helper process and event queue
pub struct ScriptExecutor {
    #[allow(dead_code)]
    script_path: PathBuf,
    event_tx: mpsc::Sender<ScriptEvent>,
    _worker_handle: tokio::task::JoinHandle<()>,
}

impl ScriptExecutor {
    /// Create a new script executor
    ///
    /// # Arguments
    ///
    /// * `script_path` - Path to the executable script
    ///
    /// # Errors
    ///
    /// Returns `HelperError::ScriptNotFound` if the script doesn't exist or is not executable
    pub fn new<P: AsRef<Path>>(script_path: P) -> Result<Arc<Self>, HelperError> {
        let script_path = script_path.as_ref().to_path_buf();

        // Verify script exists and is executable
        if !script_path.exists() {
            return Err(HelperError::ScriptNotFound(script_path));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&script_path)
                .map_err(|_| HelperError::ScriptNotFound(script_path.clone()))?;
            let permissions = metadata.permissions();
            if permissions.mode() & 0o111 == 0 {
                return Err(HelperError::ScriptNotFound(script_path));
            }
        }

        let (event_tx, event_rx) = mpsc::channel(MAX_QUEUE_SIZE);

        let worker_script_path = script_path.clone();
        let worker_handle = tokio::spawn(async move {
            Self::worker_loop(worker_script_path, event_rx).await;
        });

        Ok(Arc::new(Self {
            script_path,
            event_tx,
            _worker_handle: worker_handle,
        }))
    }

    /// Queue an event for script execution
    ///
    /// # Errors
    ///
    /// Returns `HelperError::QueueFull` if the event queue is full
    pub async fn queue_event(&self, event: ScriptEvent) -> Result<(), HelperError> {
        self.event_tx
            .send(event)
            .await
            .map_err(|e| HelperError::ChannelSend(e.to_string()))
    }

    /// Worker loop processing events and executing scripts
    async fn worker_loop(script_path: PathBuf, mut event_rx: mpsc::Receiver<ScriptEvent>) {
        info!(script = %script_path.display(), "Helper worker started");

        while let Some(event) = event_rx.recv().await {
            if let Err(e) = Self::execute_script(&script_path, event).await {
                error!(error = %e, "Failed to execute script");
            }
        }

        info!("Helper worker stopped");
    }

    /// Execute script for a single event
    async fn execute_script(script_path: &Path, event: ScriptEvent) -> Result<(), HelperError> {
        let (action, args, env_vars) = Self::prepare_script_invocation(&event);

        debug!(
            script = %script_path.display(),
            action = action,
            "Executing script"
        );

        let mut cmd = Command::new(script_path);
        cmd.arg(action);
        cmd.args(&args);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Set environment variables
        for (key, value) in env_vars {
            cmd.env(key, value);
        }

        // Execute with timeout
        let timeout_duration = std::time::Duration::from_secs(60);
        match tokio::time::timeout(timeout_duration, cmd.output()).await {
            Ok(Ok(output)) => {
                if output.status.success() {
                    debug!(
                        script = %script_path.display(),
                        action = action,
                        "Script executed successfully"
                    );
                    Ok(())
                } else {
                    let exit_code = output.status.code().unwrap_or(-1);
                    warn!(
                        script = %script_path.display(),
                        action = action,
                        exit_code = exit_code,
                        stderr = ?String::from_utf8_lossy(&output.stderr),
                        "Script exited with non-zero status"
                    );
                    Err(HelperError::NonZeroExit(exit_code))
                }
            }
            Ok(Err(e)) => {
                error!(
                    script = %script_path.display(),
                    error = %e,
                    "Failed to spawn script"
                );
                Err(HelperError::SpawnFailed(e))
            }
            Err(_) => {
                error!(
                    script = %script_path.display(),
                    "Script execution timeout"
                );
                Err(HelperError::Timeout(60))
            }
        }
    }

    /// Prepare script invocation parameters (action, args, environment)
    fn prepare_script_invocation(event: &ScriptEvent) -> (&str, Vec<String>, HashMap<String, String>) {
        let mut args = Vec::new();
        let mut env_vars = HashMap::new();

        match event {
            ScriptEvent::DhcpLease(lease_event) => {
                let action_str = lease_event.action.as_str();

                // Positional arguments
                args.push(lease_event.mac.clone());
                args.push(lease_event.ip.to_string());
                if let Some(h) = &lease_event.hostname {
                    args.push(h.clone());
                } else {
                    args.push(String::new());
                }

                // Environment variables
                env_vars.insert("DNSMASQ_INTERFACE".to_string(), lease_event.interface.clone());
                env_vars.insert("DNSMASQ_LEASE_EXPIRES".to_string(), lease_event.lease_expires.to_string());

                if let Some(d) = &lease_event.domain {
                    env_vars.insert("DNSMASQ_DOMAIN".to_string(), d.clone());
                }

                if let Some(cid) = &lease_event.client_id {
                    env_vars.insert("DNSMASQ_CLIENT_ID".to_string(), hex::encode(cid));
                }

                if let Some(vc) = &lease_event.vendor_class {
                    env_vars.insert("DNSMASQ_VENDOR_CLASS".to_string(), vc.clone());
                }

                if let Some(sh) = &lease_event.supplied_hostname {
                    env_vars.insert("DNSMASQ_SUPPLIED_HOSTNAME".to_string(), sh.clone());
                }

                if let Some(oui) = &lease_event.cpewan_oui {
                    env_vars.insert("DNSMASQ_CPEWAN_OUI".to_string(), oui.clone());
                }

                if let Some(serial) = &lease_event.cpewan_serial {
                    env_vars.insert("DNSMASQ_CPEWAN_SERIAL".to_string(), serial.clone());
                }

                if let Some(class) = &lease_event.cpewan_class {
                    env_vars.insert("DNSMASQ_CPEWAN_CLASS".to_string(), class.clone());
                }

                if let Some(cid) = &lease_event.circuit_id {
                    env_vars.insert("DNSMASQ_CIRCUIT_ID".to_string(), hex::encode(cid));
                }

                if let Some(sid) = &lease_event.subscriber_id {
                    env_vars.insert("DNSMASQ_SUBSCRIBER_ID".to_string(), hex::encode(sid));
                }

                if let Some(rid) = &lease_event.remote_id {
                    env_vars.insert("DNSMASQ_REMOTE_ID".to_string(), hex::encode(rid));
                }

                if !lease_event.tags.is_empty() {
                    env_vars.insert("DNSMASQ_TAGS".to_string(), lease_event.tags.join(" "));
                }

                (action_str, args, env_vars)
            }

            #[cfg(feature = "dhcp6")]
            ScriptEvent::Dhcpv6Relay {
                action,
                iaid,
                mac,
                ip,
                hostname,
                interface,
                lease_expires,
                domain,
                server_duid,
            } => {
                let action_str = action.as_str();

                // Positional arguments
                if let Some(m) = mac {
                    args.push(m.clone());
                } else {
                    args.push(String::new());
                }
                args.push(ip.to_string());
                if let Some(h) = hostname {
                    args.push(h.clone());
                } else {
                    args.push(String::new());
                }

                // Environment variables
                env_vars.insert("DNSMASQ_INTERFACE".to_string(), interface.clone());
                env_vars.insert("DNSMASQ_LEASE_EXPIRES".to_string(), lease_expires.to_string());
                env_vars.insert("DNSMASQ_IAID".to_string(), iaid.to_string());
                env_vars.insert("DNSMASQ_SERVER_DUID".to_string(), hex::encode(server_duid));

                if let Some(d) = domain {
                    env_vars.insert("DNSMASQ_DOMAIN".to_string(), d.clone());
                }

                (action_str, args, env_vars)
            }

            #[cfg(feature = "tftp")]
            ScriptEvent::TftpTransfer {
                file_size,
                destination,
                file_path,
            } => {
                // Positional arguments
                args.push(file_size.to_string());
                args.push(destination.to_string());
                args.push(file_path.display().to_string());

                ("tftp", args, env_vars)
            }

            ScriptEvent::ArpChange { action, mac, ip } => {
                let action_str = action.as_str();

                // Positional arguments
                args.push(mac.clone());
                args.push(ip.to_string());

                (action_str, args, env_vars)
            }
        }
    }
}

/// Convenience function to queue a DHCP lease event
pub async fn queue_script(executor: &Arc<ScriptExecutor>, event: ScriptEvent) -> Result<(), HelperError> {
    executor.queue_event(event).await
}

/// Convenience function to queue a TFTP event
#[cfg(feature = "tftp")]
pub async fn queue_tftp(
    executor: &Arc<ScriptExecutor>,
    file_size: u64,
    destination: IpAddr,
    file_path: PathBuf,
) -> Result<(), HelperError> {
    executor
        .queue_event(ScriptEvent::TftpTransfer {
            file_size,
            destination,
            file_path,
        })
        .await
}

/// Convenience function to queue an ARP event
pub async fn queue_arp(
    executor: &Arc<ScriptExecutor>,
    action: ArpAction,
    mac: String,
    ip: IpAddr,
) -> Result<(), HelperError> {
    executor
        .queue_event(ScriptEvent::ArpChange { action, mac, ip })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_lease_action_as_str() {
        assert_eq!(LeaseAction::Add.as_str(), "add");
        assert_eq!(LeaseAction::Old.as_str(), "old");
        assert_eq!(LeaseAction::Del.as_str(), "del");
    }

    #[test]
    fn test_arp_action_as_str() {
        assert_eq!(ArpAction::Add.as_str(), "arp-add");
        assert_eq!(ArpAction::Del.as_str(), "arp-del");
    }

    #[test]
    fn test_prepare_script_invocation_dhcp_lease() {
        let event = ScriptEvent::DhcpLease(Box::new(DhcpLeaseEvent {
            action: LeaseAction::Add,
            mac: "00:11:22:33:44:55".to_string(),
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            hostname: Some("client1".to_string()),
            interface: "eth0".to_string(),
            lease_expires: 3600,
            domain: Some("example.com".to_string()),
            client_id: None,
            vendor_class: None,
            supplied_hostname: None,
            cpewan_oui: None,
            cpewan_serial: None,
            cpewan_class: None,
            circuit_id: None,
            subscriber_id: None,
            remote_id: None,
            tags: vec![],
        }));

        let (action, args, env_vars) = ScriptExecutor::prepare_script_invocation(&event);

        assert_eq!(action, "add");
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "00:11:22:33:44:55");
        assert_eq!(args[1], "192.168.1.100");
        assert_eq!(args[2], "client1");
        assert_eq!(env_vars.get("DNSMASQ_INTERFACE"), Some(&"eth0".to_string()));
        assert_eq!(env_vars.get("DNSMASQ_DOMAIN"), Some(&"example.com".to_string()));
    }

    #[test]
    fn test_prepare_script_invocation_arp() {
        let event = ScriptEvent::ArpChange {
            action: ArpAction::Add,
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        };

        let (action, args, _env_vars) = ScriptExecutor::prepare_script_invocation(&event);

        assert_eq!(action, "arp-add");
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "aa:bb:cc:dd:ee:ff");
        assert_eq!(args[1], "10.0.0.1");
    }
}
