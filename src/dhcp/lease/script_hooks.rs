// SPDX-License-Identifier: GPL-2.0-or-later

//! DHCP lease script hooks module
//!
//! This module provides functionality for executing external scripts when DHCP
//! lease events occur. This allows system administrators to integrate custom
//! actions (firewall updates, logging, notifications, etc.) with DHCP operations.
//!
//! # Script Events
//!
//! Scripts are invoked for the following lease events:
//!
//! - **add**: New lease allocated
//! - **del**: Lease released or expired
//! - **old**: Lease renewed (same client, same IP)
//! - **init**: Initial script invocation with "*" for restarting behavior
//!
//! # Environment Variables
//!
//! Scripts receive lease information through environment variables:
//!
//! - `DNSMASQ_LEASE_EXPIRES`: Unix timestamp of lease expiration
//! - `DNSMASQ_LEASE_LENGTH`: Lease duration in seconds
//! - `DNSMASQ_IAID`: DHCPv6 Identity Association ID (v6 only)
//! - `DNSMASQ_MAC`: Client MAC address (v4 only)
//! - `DNSMASQ_CLIENT_ID`: Client identifier (hex)
//! - `DNSMASQ_INTERFACE`: Network interface name
//! - `DNSMASQ_TAGS`: Space-separated DHCP tags
//! - `DNSMASQ_DOMAIN`: Domain name
//! - `DNSMASQ_SUPPLIED_HOSTNAME`: Hostname from client
//! - `DNSMASQ_VENDOR_CLASS`: Vendor class identifier (hex)
//! - `DNSMASQ_RELAY_ADDRESS`: Relay agent address (if present)
//!
//! # Example Script
//!
//! ```bash
//! #!/bin/bash
//! # /etc/dnsmasq-lease.sh
//!
//! ACTION="$1"
//! MAC="$2"
//! IP="$3"
//! HOSTNAME="$4"
//!
//! case "$ACTION" in
//!     add|old)
//!         logger "DHCP: $HOSTNAME ($MAC) got $IP, expires $DNSMASQ_LEASE_EXPIRES"
//!         # Update firewall rules
//!         iptables -A FORWARD -s "$IP" -j ACCEPT
//!         ;;
//!     del)
//!         logger "DHCP: $HOSTNAME ($MAC) released $IP"
//!         # Remove firewall rules
//!         iptables -D FORWARD -s "$IP" -j ACCEPT
//!         ;;
//! esac
//! ```
//!
//! Based on: src/lease.c (rerun_scripts, do_script_run, lines 3133-3250)

use crate::dhcp::lease::Lease;
use crate::error::DhcpError;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

/// Script execution action type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptAction {
    /// New lease allocated
    Add,
    /// Lease released or expired
    Del,
    /// Lease renewed (same client, same IP)
    Old,
    /// Initial script invocation (for restart)
    Init,
}

impl ScriptAction {
    /// Convert to string representation for script argument
    pub fn as_str(&self) -> &'static str {
        match self {
            ScriptAction::Add => "add",
            ScriptAction::Del => "del",
            ScriptAction::Old => "old",
            ScriptAction::Init => "init",
        }
    }
}

/// Configuration for lease script execution
#[derive(Debug, Clone)]
pub struct ScriptConfig {
    /// Path to the lease script executable
    pub script_path: PathBuf,
    /// Domain name to pass in DNSMASQ_DOMAIN
    pub domain: Option<String>,
    /// Additional environment variables
    pub extra_env: HashMap<String, String>,
    /// Timeout for script execution (seconds)
    pub timeout_secs: u64,
}

impl ScriptConfig {
    /// Create a new script configuration
    pub fn new(script_path: impl Into<PathBuf>) -> Self {
        Self {
            script_path: script_path.into(),
            domain: None,
            extra_env: HashMap::new(),
            timeout_secs: 10, // Default 10 second timeout
        }
    }

    /// Set the domain name
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Set script timeout
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Add extra environment variable
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_env.insert(key.into(), value.into());
        self
    }
}

/// Execute a lease script for a given event
///
/// Invokes the configured external script with lease information passed as
/// command-line arguments and environment variables. The script runs in a
/// separate process with a configurable timeout.
///
/// # Arguments
///
/// * `config` - Script configuration (path, domain, timeout)
/// * `action` - Type of lease event (add, del, old, init)
/// * `lease` - The lease associated with the event
/// * `old_hostname` - Previous hostname for "old" events (optional)
///
/// # Returns
///
/// `Ok(())` if the script executed successfully (exit code 0), or `DhcpError` on failure.
///
/// # Errors
///
/// Returns `DhcpError::ScriptFailed` if:
/// - The script file does not exist or is not executable
/// - The script process fails to spawn
/// - The script times out
/// - The script returns a non-zero exit code
///
/// # Example
///
/// ```ignore
/// use std::path::PathBuf;
///
/// let config = ScriptConfig::new("/etc/dnsmasq-lease.sh")
///     .with_domain("example.com")
///     .with_timeout(10);
///
/// execute_lease_script(&config, ScriptAction::Add, &lease, None).await?;
/// ```
///
/// # C Implementation Reference
///
/// Based on: src/lease.c:do_script_run() (lines 3160-3250)
///
/// The C implementation uses fork() and execl() to run scripts. This Rust
/// version uses tokio::process::Command for async script execution with
/// proper timeout handling.
pub async fn execute_lease_script(
    config: &ScriptConfig,
    action: ScriptAction,
    lease: &Lease,
    old_hostname: Option<&str>,
) -> Result<(), DhcpError> {
    let script_path = &config.script_path;

    // Check if script exists and is executable
    if !script_path.exists() {
        return Err(DhcpError::ScriptFailed {
            script: script_path.display().to_string(),
            reason: "Script does not exist".to_string(),
        });
    }

    // Prepare command-line arguments
    // Format: <action> <mac_or_iaid> <ip> <hostname>
    let arg1 = action.as_str();

    let arg2 = if let Some(mac) = lease.mac {
        // DHCPv4: MAC address in colon-separated hex
        // MacAddress already implements Display with the correct format
        mac.to_string()
    } else if let Some(iaid) = lease.iaid {
        // DHCPv6: IAID as decimal string
        format!("{}", iaid)
    } else {
        // Fallback: "*"
        "*".to_string()
    };

    let arg3 = lease.ip.to_string();

    let arg4 = lease.hostname.as_deref().unwrap_or("*");

    // Prepare environment variables
    let mut env_vars = config.extra_env.clone();

    // Add standard DHCP environment variables
    if let Ok(expires_secs) = lease.expires.duration_since(UNIX_EPOCH) {
        env_vars.insert(
            "DNSMASQ_LEASE_EXPIRES".to_string(),
            expires_secs.as_secs().to_string(),
        );

        if let Ok(now_secs) = SystemTime::now().duration_since(UNIX_EPOCH) {
            let lease_length = expires_secs.as_secs().saturating_sub(now_secs.as_secs());
            env_vars.insert("DNSMASQ_LEASE_LENGTH".to_string(), lease_length.to_string());
        }
    }

    if let Some(iaid) = lease.iaid {
        env_vars.insert("DNSMASQ_IAID".to_string(), format!("{}", iaid));
    }

    if let Some(mac) = lease.mac {
        // MacAddress already implements Display with the correct format
        env_vars.insert("DNSMASQ_MAC".to_string(), mac.to_string());
    }

    if let Some(ref client_id) = lease.client_id {
        let client_id_hex = client_id
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        env_vars.insert("DNSMASQ_CLIENT_ID".to_string(), client_id_hex);
    }

    env_vars.insert("DNSMASQ_INTERFACE".to_string(), lease.interface.clone());

    if let Some(ref domain) = config.domain {
        env_vars.insert("DNSMASQ_DOMAIN".to_string(), domain.clone());
    }

    if let Some(ref hostname) = lease.hostname {
        env_vars.insert("DNSMASQ_SUPPLIED_HOSTNAME".to_string(), hostname.clone());
    }

    if let Some(ref vendor_class) = lease.vendorclass {
        let vendor_hex = vendor_class
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        env_vars.insert("DNSMASQ_VENDOR_CLASS".to_string(), vendor_hex);
    }

    if let Some(ref agent_id) = lease.agent_id {
        let agent_hex = agent_id
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        env_vars.insert("DNSMASQ_RELAY_ADDRESS".to_string(), agent_hex);
    }

    // For "old" action, pass previous hostname if different
    if action == ScriptAction::Old {
        if let Some(old_name) = old_hostname {
            env_vars.insert("DNSMASQ_OLD_HOSTNAME".to_string(), old_name.to_string());
        }
    }

    debug!(
        "Executing lease script: {} {} {} {} {}",
        script_path.display(),
        arg1,
        arg2,
        arg3,
        arg4
    );

    // Execute the script with timeout
    let mut command = Command::new(script_path);
    command
        .arg(arg1)
        .arg(arg2)
        .arg(arg3)
        .arg(arg4)
        .envs(&env_vars)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Set timeout
    let timeout = tokio::time::Duration::from_secs(config.timeout_secs);

    let output = match tokio::time::timeout(timeout, command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            error!(
                "Failed to execute lease script {}: {}",
                script_path.display(),
                e
            );
            return Err(DhcpError::ScriptFailed {
                script: script_path.display().to_string(),
                reason: format!("Failed to spawn script process: {}", e),
            });
        }
        Err(_) => {
            error!(
                "Lease script {} timed out after {}s",
                script_path.display(),
                config.timeout_secs
            );
            return Err(DhcpError::ScriptFailed {
                script: script_path.display().to_string(),
                reason: format!("Script timed out after {}s", config.timeout_secs),
            });
        }
    };

    // Check exit status
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(
            "Lease script {} exited with status {}: {}",
            script_path.display(),
            output.status,
            stderr
        );
        return Err(DhcpError::ScriptFailed {
            script: script_path.display().to_string(),
            reason: format!("Script exited with status {}: {}", output.status, stderr),
        });
    }

    // Log script output if present
    if !output.stdout.is_empty() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!("Script output: {}", stdout.trim());
    }

    info!(
        "Successfully executed lease script for {} {}",
        action.as_str(),
        lease.ip
    );

    Ok(())
}

/// Execute lease script for all existing leases
///
/// Invokes the script with the "init" action for each lease, allowing the script
/// to initialize its state based on the current lease database. This is typically
/// called after dnsmasq startup or configuration reload.
///
/// # Arguments
///
/// * `config` - Script configuration
/// * `leases` - Current list of active leases
///
/// # Returns
///
/// `Ok(())` if all scripts executed successfully. Individual script failures
/// are logged but do not fail the entire operation.
///
/// # Example
///
/// ```ignore
/// // After loading leases from database
/// execute_init_scripts(&config, &leases).await?;
/// ```
///
/// # C Implementation Reference
///
/// Based on: src/lease.c:rerun_scripts() (lines 3133-3158)
///
/// The C implementation queues all existing leases for script execution with
/// the "old" action. This Rust version uses "init" for clarity and executes
/// them asynchronously.
pub async fn execute_init_scripts(
    config: &ScriptConfig,
    leases: &[Lease],
) -> Result<(), DhcpError> {
    info!("Executing init scripts for {} leases", leases.len());

    let mut success_count = 0;
    let mut error_count = 0;

    for lease in leases {
        // Skip leases without hostnames (script won't have useful info)
        if lease.hostname.is_none() {
            continue;
        }

        match execute_lease_script(config, ScriptAction::Init, lease, None).await {
            Ok(_) => success_count += 1,
            Err(e) => {
                error!("Init script failed for lease {}: {}", lease.ip, e);
                error_count += 1;
                // Continue with other leases
            }
        }
    }

    info!(
        "Init scripts completed: {} succeeded, {} failed",
        success_count, error_count
    );

    Ok(())
}

/// Queue and execute a lease script asynchronously
///
/// Spawns a tokio task to execute the script, allowing the caller to continue
/// without blocking on script execution. This is useful for maintaining
/// responsiveness during DHCP operations.
///
/// # Arguments
///
/// * `config` - Script configuration
/// * `action` - Lease event type
/// * `lease` - Lease to process
/// * `old_hostname` - Previous hostname for "old" events
///
/// # Example
///
/// ```ignore
/// // Execute script asynchronously when allocating lease
/// execute_lease_script_async(config.clone(), ScriptAction::Add, lease.clone(), None);
/// ```
pub fn execute_lease_script_async(
    config: ScriptConfig,
    action: ScriptAction,
    lease: Lease,
    old_hostname: Option<String>,
) {
    tokio::spawn(async move {
        if let Err(e) =
            execute_lease_script(&config, action, &lease, old_hostname.as_deref()).await
        {
            error!(
                "Async lease script execution failed for {} {}: {}",
                action.as_str(),
                lease.ip,
                e
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::lease::LeaseFlags;
    use crate::types::MacAddress;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_script_execution_success() {
        // Create a temporary directory and script file
        let temp_dir = tempfile::tempdir().unwrap();
        let script_path = temp_dir.path().join("test_script.sh");
        let script_content = b"#!/bin/sh\necho \"Success\"\nexit 0\n";
        tokio::fs::write(&script_path, script_content)
            .await
            .unwrap();

        // Make it executable (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
        }

        let config = ScriptConfig::new(&script_path).with_timeout(5);

        let lease = Lease {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            mac: Some(MacAddress::new([0x01, 0x23, 0x45, 0x67, 0x89, 0xab])),
            hostname: Some("test-host".to_string()),
            client_id: None,
            expires: SystemTime::now() + Duration::from_secs(3600),
            iaid: None,
            flags: LeaseFlags::empty(),
            interface: "eth0".to_string(),
            fqdn: None,
            vendorclass: None,
            agent_id: None,
            slaac_addresses: None,
        };

        let result = execute_lease_script(&config, ScriptAction::Add, &lease, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_script_execution_timeout() {
        // Create a temporary directory and script file
        let temp_dir = tempfile::tempdir().unwrap();
        let script_path = temp_dir.path().join("test_script.sh");
        let script_content = b"#!/bin/sh\nsleep 1000\n";
        tokio::fs::write(&script_path, script_content)
            .await
            .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
        }

        let config = ScriptConfig::new(&script_path).with_timeout(1); // 1 second timeout

        let lease = Lease {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            mac: Some(MacAddress::new([0x01, 0x23, 0x45, 0x67, 0x89, 0xab])),
            hostname: Some("test-host".to_string()),
            client_id: None,
            expires: SystemTime::now() + Duration::from_secs(3600),
            iaid: None,
            flags: LeaseFlags::empty(),
            interface: "eth0".to_string(),
            fqdn: None,
            vendorclass: None,
            agent_id: None,
            slaac_addresses: None,
        };

        let result = execute_lease_script(&config, ScriptAction::Add, &lease, None).await;
        assert!(result.is_err());
        if let Err(DhcpError::ScriptFailed { reason, .. }) = result {
            assert!(reason.contains("timed out"));
        }
    }

    #[test]
    fn test_script_action_as_str() {
        assert_eq!(ScriptAction::Add.as_str(), "add");
        assert_eq!(ScriptAction::Del.as_str(), "del");
        assert_eq!(ScriptAction::Old.as_str(), "old");
        assert_eq!(ScriptAction::Init.as_str(), "init");
    }
}
