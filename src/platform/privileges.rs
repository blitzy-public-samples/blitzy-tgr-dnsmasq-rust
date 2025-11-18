// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Privilege management and dropping
//!
//! This module implements privilege separation for dnsmasq. The typical pattern is:
//! 1. Start as root
//! 2. Bind to privileged ports (UDP/TCP 53, 67, 547)
//! 3. Drop root privileges but retain necessary capabilities
//! 4. Run main service loop with minimal privileges
//!
//! On Linux, this uses capabilities(7) to retain only CAP_NET_BIND_SERVICE and
//! CAP_NET_ADMIN while dropping full root privileges.
//!
//! On BSD systems, this uses traditional setuid/setgid privilege dropping.
//!
//! # Example
//!
//! ```no_run
//! use dnsmasq::platform::privileges::{PrivilegeManager, drop_privileges};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Bind to privileged ports while still root
//! // let dns_socket = bind_to_port_53()?;
//!
//! // Drop privileges to 'dnsmasq' user
//! drop_privileges("dnsmasq", None).await?;
//!
//! // Continue running with reduced privileges
//! # Ok(())
//! # }
//! ```

use crate::error::{DnsmasqError, PlatformError, Result};
use nix::unistd::{Gid, Group, Uid, User};
use std::ffi::CString;
use tracing::{debug, info};

/// Manager for privilege operations
///
/// This struct provides methods for dropping privileges, changing users,
/// and managing Linux capabilities. It maintains state about the original
/// and current privilege level.
pub struct PrivilegeManager {
    original_uid: Uid,
    #[allow(dead_code)]
    original_gid: Gid,
    current_uid: Uid,
    current_gid: Gid,
}

impl PrivilegeManager {
    /// Create a new privilege manager
    ///
    /// This captures the current UID and GID to track privilege transitions.
    pub fn new() -> Self {
        let uid = nix::unistd::getuid();
        let gid = nix::unistd::getgid();

        Self { original_uid: uid, original_gid: gid, current_uid: uid, current_gid: gid }
    }

    /// Check if currently running as root
    pub fn is_root(&self) -> bool {
        self.current_uid.is_root()
    }

    /// Check if originally started as root
    pub fn was_root(&self) -> bool {
        self.original_uid.is_root()
    }

    /// Drop privileges to the specified user
    ///
    /// This performs a complete privilege drop:
    /// 1. Look up the target user and group
    /// 2. Initialize supplementary groups
    /// 3. Set GID to the target group
    /// 4. Set UID to the target user
    /// 5. On Linux, retain necessary capabilities
    ///
    /// # Arguments
    ///
    /// * `username` - Name of the user to switch to (e.g., "dnsmasq")
    /// * `groupname` - Optional group name. If None, uses the user's primary group
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The user or group doesn't exist
    /// - We don't have permission to change UID/GID
    /// - Setting capabilities fails (Linux)
    ///
    /// # Security
    ///
    /// This function should be called AFTER binding to privileged ports but BEFORE
    /// processing any network input. Once privileges are dropped, they cannot be
    /// regained except by restarting the process.
    pub async fn drop_to_user(&mut self, username: &str, groupname: Option<&str>) -> Result<()> {
        // Must be root to drop privileges
        if !self.is_root() {
            info!("Not running as root (UID {}), skipping privilege drop", self.current_uid);
            return Ok(());
        }

        // Look up the target user
        let user = User::from_name(username)
            .map_err(|e| {
                PlatformError::PrivilegeDrop(format!(
                    "Failed to look up user '{}': {}",
                    username, e
                ))
            })?
            .ok_or_else(|| {
                PlatformError::PrivilegeDrop(format!("User '{}' does not exist", username))
            })?;

        // Determine target group
        let target_gid = if let Some(groupname) = groupname {
            // Use specified group
            let group = Group::from_name(groupname)
                .map_err(|e| {
                    PlatformError::PrivilegeDrop(format!(
                        "Failed to look up group '{}': {}",
                        groupname, e
                    ))
                })?
                .ok_or_else(|| {
                    PlatformError::PrivilegeDrop(format!("Group '{}' does not exist", groupname))
                })?;
            group.gid
        } else {
            // Use user's primary group
            user.gid
        };

        info!(
            "Dropping privileges from UID {} to UID {} ({}), GID {}",
            self.current_uid, user.uid, username, target_gid
        );

        // Initialize supplementary groups for the user
        #[cfg(target_os = "linux")]
        {
            let username_cstr = CString::new(user.name.as_str()).map_err(|e| {
                DnsmasqError::Platform(PlatformError::PrivilegeDrop(format!(
                    "Invalid username (contains null byte): {}",
                    e
                )))
            })?;
            nix::unistd::initgroups(&username_cstr, target_gid).map_err(|e| {
                DnsmasqError::Platform(PlatformError::PrivilegeDrop(format!(
                    "Failed to initialize supplementary groups: {}",
                    e
                )))
            })?;
            debug!("Initialized supplementary groups for user {}", username);
        }

        // Set GID first (must be done while still root)
        nix::unistd::setgid(target_gid).map_err(|e| {
            PlatformError::PrivilegeDrop(format!("Failed to set GID {}: {}", target_gid, e))
        })?;
        self.current_gid = target_gid;
        debug!("Set GID to {}", target_gid);

        // On Linux, set capabilities before dropping UID
        #[cfg(target_os = "linux")]
        {
            self.set_capabilities()?;
        }

        // Set UID (this is irreversible on most systems)
        nix::unistd::setuid(user.uid).map_err(|e| {
            PlatformError::PrivilegeDrop(format!(
                "Failed to set UID {} ({}): {}",
                user.uid, username, e
            ))
        })?;
        self.current_uid = user.uid;

        // Verify we can't regain root privileges
        if nix::unistd::setuid(Uid::from_raw(0)).is_ok() {
            return Err(DnsmasqError::Platform(PlatformError::PrivilegeDrop(
                "WARNING: Successfully regained root after dropping privileges! This is a security bug.".to_string()
            )));
        }

        info!("Successfully dropped privileges to {} (UID {})", username, user.uid);

        Ok(())
    }

    /// Set Linux capabilities after privilege drop
    ///
    /// This retains only the capabilities needed for dnsmasq to function:
    /// - CAP_NET_BIND_SERVICE: Bind to privileged ports
    /// - CAP_NET_ADMIN: Configure network interfaces, manage routing
    /// - CAP_NET_RAW: Send raw packets (for DHCP)
    ///
    /// All other capabilities are dropped for security.
    #[cfg(target_os = "linux")]
    fn set_capabilities(&self) -> Result<()> {
        use caps::{CapSet, Capability, CapsHashSet};

        // Build set of capabilities to retain
        let mut keep_caps = CapsHashSet::new();
        keep_caps.insert(Capability::CAP_NET_BIND_SERVICE);
        keep_caps.insert(Capability::CAP_NET_ADMIN);
        keep_caps.insert(Capability::CAP_NET_RAW);

        // Clear all capabilities except the ones we want to keep
        caps::clear(None, CapSet::Effective).map_err(|e| {
            DnsmasqError::Platform(PlatformError::PrivilegeDrop(format!(
                "Failed to clear effective capabilities: {}",
                e
            )))
        })?;
        caps::clear(None, CapSet::Permitted).map_err(|e| {
            DnsmasqError::Platform(PlatformError::PrivilegeDrop(format!(
                "Failed to clear permitted capabilities: {}",
                e
            )))
        })?;
        caps::clear(None, CapSet::Inheritable).map_err(|e| {
            DnsmasqError::Platform(PlatformError::PrivilegeDrop(format!(
                "Failed to clear inheritable capabilities: {}",
                e
            )))
        })?;

        // Set permitted capabilities
        caps::set(None, CapSet::Permitted, &keep_caps).map_err(|e| {
            DnsmasqError::Platform(PlatformError::PrivilegeDrop(format!(
                "Failed to set permitted capabilities: {}",
                e
            )))
        })?;

        // Set effective capabilities
        caps::set(None, CapSet::Effective, &keep_caps).map_err(|e| {
            DnsmasqError::Platform(PlatformError::PrivilegeDrop(format!(
                "Failed to set effective capabilities: {}",
                e
            )))
        })?;

        // Set inheritable capabilities
        caps::set(None, CapSet::Inheritable, &keep_caps).map_err(|e| {
            DnsmasqError::Platform(PlatformError::PrivilegeDrop(format!(
                "Failed to set inheritable capabilities: {}",
                e
            )))
        })?;

        debug!("Set capabilities: CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW");

        Ok(())
    }

    /// Get the current UID
    pub fn current_uid(&self) -> Uid {
        self.current_uid
    }

    /// Get the current GID
    pub fn current_gid(&self) -> Gid {
        self.current_gid
    }
}

impl Default for PrivilegeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Drop privileges to the specified user
///
/// This is a convenience function that creates a PrivilegeManager and drops
/// privileges in one call. It's the most common way to use this module.
///
/// # Arguments
///
/// * `username` - Name of the user to switch to (e.g., "dnsmasq", "nobody")
/// * `groupname` - Optional group name. If None, uses the user's primary group
///
/// # Returns
///
/// Returns Ok(()) if privileges were successfully dropped, or if we weren't
/// running as root to begin with.
///
/// # Errors
///
/// Returns an error if:
/// - The user or group doesn't exist
/// - We don't have permission to change UID/GID
/// - Setting capabilities fails (Linux)
///
/// # Example
///
/// ```no_run
/// use dnsmasq::platform::privileges::drop_privileges;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Drop to 'dnsmasq' user with its primary group
/// drop_privileges("dnsmasq", None).await?;
///
/// // Drop to 'nobody' user with 'nogroup' group
/// drop_privileges("nobody", Some("nogroup")).await?;
/// # Ok(())
/// # }
/// ```
pub async fn drop_privileges(username: &str, groupname: Option<&str>) -> Result<()> {
    let mut manager = PrivilegeManager::new();

    if !manager.is_root() {
        info!("Not running as root, no privilege drop needed");
        return Ok(());
    }

    manager.drop_to_user(username, groupname).await?;

    // Verify we're no longer root
    if manager.is_root() {
        return Err(DnsmasqError::Platform(PlatformError::PrivilegeDrop(
            "Still running as root after privilege drop!".to_string(),
        )));
    }

    Ok(())
}

/// Check if we have a specific Linux capability
///
/// This is useful for checking if we have the necessary permissions to
/// perform privileged operations.
///
/// # Arguments
///
/// * `cap` - The capability to check
///
/// # Returns
///
/// Returns `true` if we have the capability, `false` otherwise.
///
/// # Platform Support
///
/// This function only works on Linux. On other platforms, it always returns `false`.
#[cfg(target_os = "linux")]
pub fn has_capability(cap: caps::Capability) -> bool {
    caps::has_cap(None, caps::CapSet::Effective, cap).unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
pub fn has_capability(_cap: u32) -> bool {
    false
}

/// Get the effective user ID
///
/// This is a convenience wrapper around getuid().
pub fn get_effective_uid() -> Uid {
    nix::unistd::getuid()
}

/// Get the effective group ID
///
/// This is a convenience wrapper around getgid().
pub fn get_effective_gid() -> Gid {
    nix::unistd::getgid()
}

/// Check if running as root
///
/// Returns true if the effective UID is 0 (root).
pub fn is_root() -> bool {
    nix::unistd::getuid().is_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_manager_creation() {
        let manager = PrivilegeManager::new();
        // Should successfully create
        assert_eq!(manager.current_uid(), nix::unistd::getuid());
        assert_eq!(manager.current_gid(), nix::unistd::getgid());
    }

    #[test]
    fn test_is_root() {
        let manager = PrivilegeManager::new();
        // This test result depends on whether we're running as root
        assert_eq!(manager.is_root(), nix::unistd::getuid().is_root());
    }

    #[test]
    fn test_get_effective_ids() {
        assert_eq!(get_effective_uid(), nix::unistd::getuid());
        assert_eq!(get_effective_gid(), nix::unistd::getgid());
        assert_eq!(is_root(), nix::unistd::getuid().is_root());
    }

    #[tokio::test]
    async fn test_drop_privileges_not_root() {
        // When not running as root, this should succeed without doing anything
        if !is_root() {
            let result = drop_privileges("nobody", None).await;
            assert!(result.is_ok());
        }
    }
}
