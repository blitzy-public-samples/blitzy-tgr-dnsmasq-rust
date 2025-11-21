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

//! Privilege dropping and capability management for security hardening.
//!
//! This module implements platform-specific privilege separation, allowing dnsmasq to start
//! as root (UID 0) to bind privileged ports (DNS 53, DHCP 67/547, TFTP 69), then drop to
//! an unprivileged user while retaining minimal required capabilities on platforms that
//! support fine-grained privilege management.
//!
//! # Platform Support
//!
//! ## Linux
//!
//! Uses Linux capabilities(7) via the `caps` crate to retain specific capabilities after
//! dropping root privileges:
//!
//! - **CAP_NET_ADMIN**: Required for interface binding, ARP table manipulation, and network
//!   configuration when DHCP is enabled
//! - **CAP_NET_RAW**: Required for ICMP ping in DHCP address conflict detection  
//! - **CAP_NET_BIND_SERVICE**: Required for dynamic port binding if needed
//!
//! ```rust,ignore
//! // Linux privilege drop with capability retention
//! let manager = LinuxPrivilegeManager::new();
//! manager.drop_privileges(&security_config, &[
//!     Capability::CAP_NET_ADMIN,
//!     Capability::CAP_NET_RAW,
//! ]).await?;
//! ```
//!
//! ## OpenBSD
//!
//! Uses `pledge(2)` and `unveil(2)` for promise-based security restrictions:
//!
//! ```rust,ignore
//! let manager = OpenBsdPrivilegeManager::new();
//! manager.pledge("stdio inet dns rpath wpath cpath flock")?;
//! manager.unveil("/etc/dnsmasq.conf", "r")?;
//! manager.drop_privileges(&security_config).await?;
//! ```
//!
//! ## FreeBSD / NetBSD / macOS
//!
//! Uses basic setuid/setgid privilege dropping without fine-grained capabilities:
//!
//! ```rust,ignore
//! let manager = BsdPrivilegeManager::new();
//! manager.drop_privileges(&security_config).await?;
//! ```
//!
//! # C Implementation Reference
//!
//! Replaces manual capability manipulation from C `dnsmasq.c`:
//!
//! ```c
//! // C implementation (dnsmasq.c lines ~1000-1100)
//! struct __user_cap_data_struct data;
//! data.effective = data.permitted = data.inheritable = 0;
//! if (daemon->caps & CAP_NET_ADMIN)
//!     data.effective |= (1 << CAP_NET_ADMIN);
//! if (capset(&header, &data) == -1)
//!     die("cannot set capabilities: %s", strerror(errno), EC_BADNET);
//! if (setuid(ent_pw->pw_uid) == -1)
//!     die("cannot set uid: %s", strerror(errno), EC_BADNET);
//! ```
//!
//! ```rust,ignore
//! // Rust implementation with type safety
//! use caps::{Capability, CapSet};
//! caps::set(None, CapSet::Effective, &[Capability::CAP_NET_ADMIN])?;
//! nix::unistd::setuid(uid)?;
//! ```
//!
//! # Security Model
//!
//! 1. **Startup**: Process starts as root (UID 0, EUID 0)
//! 2. **Socket Binding**: Bind privileged ports (UDP/TCP 53, 67, 547, 69)
//! 3. **Capability Retention**: On Linux, configure capabilities to retain specific caps
//! 4. **User/Group Switch**: Change to configured unprivileged user/group
//! 5. **Capability Application**: Apply retained capabilities to effective set
//! 6. **Runtime**: All packet processing runs as unprivileged user with minimal capabilities
//!
//! # Error Handling
//!
//! All privilege operations return `Result<(), PlatformError>` for proper error propagation:
//!
//! - `UserNotFound`: Configured user does not exist in /etc/passwd
//! - `CapabilityError`: Capability operation failed (missing, cannot set, permission denied)
//! - `PrivilegeDropFailed`: setuid/setgid system call failed
//!
//! # Examples
//!
//! ```rust,ignore
//! use dnsmasq::platform::privileges::{drop_privileges, check_capabilities};
//! use dnsmasq::config::types::SecurityConfig;
//!
//! // Check required capabilities before dropping privileges
//! check_capabilities(&[
//!     Capability::CAP_NET_ADMIN,
//!     Capability::CAP_NET_RAW,
//! ])?;
//!
//! // Drop privileges after binding sockets
//! let security_config = SecurityConfig {
//!     user: Some("dnsmasq".to_string()),
//!     group: Some("dnsmasq".to_string()),
//!     chroot: None,
//! };
//!
//! drop_privileges(&security_config, true, true).await?;
//! ```

use crate::config::types::SecurityConfig;
use crate::error::PlatformError;

// Platform-specific imports
#[cfg(target_os = "linux")]
use caps::{CapSet, Capability};
#[cfg(target_os = "linux")]
use libc::PR_SET_KEEPCAPS;
#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "macos"
))]
use std::collections::HashSet;
use tracing::{debug, error, info, warn};

#[cfg(unix)]
use nix::unistd::{Group, User};

// ============================================================================
// PRIVILEGE MANAGER TRAIT
// ============================================================================

/// Platform-agnostic privilege management interface.
///
/// Provides a unified API for privilege dropping across different operating systems,
/// with platform-specific implementations behind the trait.
pub trait PrivilegeManager: Send + Sync {
    /// Drop privileges from root to configured unprivileged user.
    ///
    /// # Arguments
    ///
    /// * `security_config` - Security configuration containing target user/group
    /// * `retain_net_admin` - Whether to retain `CAP_NET_ADMIN` (Linux only, ignored elsewhere)
    /// * `retain_net_raw` - Whether to retain `CAP_NET_RAW` (Linux only, ignored elsewhere)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Privileges successfully dropped
    /// * `Err(PlatformError)` - Privilege drop failed
    ///
    /// # Errors
    ///
    /// * `UserNotFound` - Target user does not exist
    /// * `CapabilityError` - Capability operation failed (Linux only)
    /// * `PrivilegeDropFailed` - setuid/setgid failed
    fn drop_privileges(
        &self,
        security_config: &SecurityConfig,
        retain_net_admin: bool,
        retain_net_raw: bool,
    ) -> Result<(), PlatformError>;

    /// Check if required capabilities are available before dropping privileges.
    ///
    /// # Arguments
    ///
    /// * `required_caps` - List of capabilities required for operation
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All required capabilities are available
    /// * `Err(PlatformError::CapabilityError)` - Missing required capabilities
    ///
    /// # Platform Support
    ///
    /// - Linux: Checks capability permitted set
    /// - Other platforms: Always returns Ok (no fine-grained capabilities)
    fn check_capabilities(&self, required_caps: &[&str]) -> Result<(), PlatformError>;

    /// Get the list of capabilities required for dnsmasq operation.
    ///
    /// # Arguments
    ///
    /// * `enable_dhcp` - Whether DHCP server is enabled (requires `CAP_NET_ADMIN`, `CAP_NET_RAW`)
    ///
    /// # Returns
    ///
    /// List of capability names required for operation
    fn get_required_capabilities(&self, enable_dhcp: bool) -> Vec<String>;
}

// ============================================================================
// LINUX PRIVILEGE MANAGER
// ============================================================================

#[cfg(target_os = "linux")]
/// Linux-specific privilege manager using capabilities(7).
///
/// Implements fine-grained privilege retention through Linux capabilities,
/// allowing dnsmasq to drop root privileges while retaining specific capabilities
/// required for network operations.
#[derive(Default)]
pub struct LinuxPrivilegeManager;

#[cfg(target_os = "linux")]
impl LinuxPrivilegeManager {
    /// Create a new Linux privilege manager.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Retain specific capabilities after privilege drop.
    ///
    /// Configures the capability bounding set to retain only the specified capabilities,
    /// then sets them in the effective set after dropping to unprivileged user.
    ///
    /// # Arguments
    ///
    /// * `capabilities` - Capabilities to retain (`CAP_NET_ADMIN`, `CAP_NET_RAW`, etc.)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Capabilities successfully configured
    /// * `Err(PlatformError::CapabilityError)` - Capability operation failed
    fn retain_capabilities(capabilities: &[Capability]) -> Result<(), PlatformError> {
        debug!("Retaining capabilities: {:?}", capabilities);

        // Enable capability retention across setuid using prctl(PR_SET_KEEPCAPS)
        // This prevents the kernel from clearing all capabilities when changing from UID 0 to non-zero
        unsafe {
            if libc::prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
                return Err(PlatformError::CapabilityError {
                    operation: "prctl(PR_SET_KEEPCAPS)".to_string(),
                    reason: std::io::Error::last_os_error().to_string(),
                });
            }
        }

        // Clear all capabilities from all sets initially
        caps::clear(None, CapSet::Effective).map_err(|e| PlatformError::CapabilityError {
            operation: "clear effective".to_string(),
            reason: e.to_string(),
        })?;
        caps::clear(None, CapSet::Permitted).map_err(|e| PlatformError::CapabilityError {
            operation: "clear permitted".to_string(),
            reason: e.to_string(),
        })?;
        caps::clear(None, CapSet::Inheritable).map_err(|e| PlatformError::CapabilityError {
            operation: "clear inheritable".to_string(),
            reason: e.to_string(),
        })?;

        // Set requested capabilities in permitted and effective sets
        for cap in capabilities {
            let mut cap_set = HashSet::new();
            cap_set.insert(*cap);
            caps::set(None, CapSet::Permitted, &cap_set).map_err(|e| {
                PlatformError::CapabilityError {
                    operation: format!("set permitted {cap:?}"),
                    reason: e.to_string(),
                }
            })?;
            caps::set(None, CapSet::Effective, &cap_set).map_err(|e| {
                PlatformError::CapabilityError {
                    operation: format!("set effective {cap:?}"),
                    reason: e.to_string(),
                }
            })?;
        }

        debug!("Capabilities retained successfully");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl PrivilegeManager for LinuxPrivilegeManager {
    fn drop_privileges(
        &self,
        security_config: &SecurityConfig,
        retain_net_admin: bool,
        retain_net_raw: bool,
    ) -> Result<(), PlatformError> {
        // Determine target user (required on Linux)
        let username =
            security_config.user.as_ref().ok_or_else(|| PlatformError::UserNotFound {
                user: "unknown".to_string(),
                reason: "No user specified in security configuration".to_string(),
            })?;

        // Look up user information
        let user = User::from_name(username)
            .map_err(|e| PlatformError::UserNotFound {
                user: username.clone(),
                reason: format!("Failed to lookup user '{username}': {e}"),
            })?
            .ok_or_else(|| PlatformError::UserNotFound {
                user: username.clone(),
                reason: format!("User '{username}' not found in /etc/passwd"),
            })?;

        let uid = user.uid;
        let gid = if let Some(ref groupname) = security_config.group {
            // Look up group if specified
            let group = Group::from_name(groupname)
                .map_err(|e| PlatformError::UserNotFound {
                    user: groupname.clone(),
                    reason: format!("Failed to lookup group '{groupname}': {e}"),
                })?
                .ok_or_else(|| PlatformError::UserNotFound {
                    user: groupname.clone(),
                    reason: format!("Group '{groupname}' not found in /etc/group"),
                })?;
            group.gid
        } else {
            // Use primary group from passwd entry
            user.gid
        };

        info!(
            user = %username,
            uid = %uid,
            gid = %gid,
            "Dropping privileges from root to unprivileged user"
        );

        // Build list of capabilities to retain
        let mut capabilities = Vec::new();
        if retain_net_admin {
            capabilities.push(Capability::CAP_NET_ADMIN);
            debug!("Retaining CAP_NET_ADMIN for interface binding and ARP operations");
        }
        if retain_net_raw {
            capabilities.push(Capability::CAP_NET_RAW);
            debug!("Retaining CAP_NET_RAW for ICMP ping in DHCP conflict detection");
        }

        // Retain capabilities before dropping privileges
        if capabilities.is_empty() {
            // Clear all capabilities if none requested
            caps::clear(None, CapSet::Effective).map_err(|e| PlatformError::CapabilityError {
                operation: "clear all effective".to_string(),
                reason: e.to_string(),
            })?;
        } else {
            Self::retain_capabilities(&capabilities)?;
        }

        // Drop to target group first (must be done before setuid on Linux)
        nix::unistd::setgid(gid).map_err(|e| PlatformError::PrivilegeDropFailed {
            reason: format!("setgid({gid}) failed: {e}"),
        })?;

        // Clear supplementary groups
        nix::unistd::setgroups(&[gid]).map_err(|e| PlatformError::PrivilegeDropFailed {
            reason: format!("setgroups failed: {e}"),
        })?;

        // Drop to target user
        nix::unistd::setuid(uid).map_err(|e| PlatformError::PrivilegeDropFailed {
            reason: format!("setuid({uid}) failed: {e}"),
        })?;

        // Re-apply capabilities after setuid (required even with PR_SET_KEEPCAPS)
        if !capabilities.is_empty() {
            for cap in &capabilities {
                let mut cap_set = HashSet::new();
                cap_set.insert(*cap);
                caps::set(None, CapSet::Effective, &cap_set).map_err(|e| {
                    PlatformError::CapabilityError {
                        operation: format!("re-apply effective {cap:?}"),
                        reason: e.to_string(),
                    }
                })?;
            }
        }

        // Verify we're no longer root
        let current_uid = nix::unistd::getuid();
        if current_uid.as_raw() == 0 {
            error!("Privilege drop failed: still running as root after setuid");
            return Err(PlatformError::PrivilegeDropFailed {
                reason: "Still running as root (UID 0) after privilege drop".to_string(),
            });
        }

        info!(
            user = %username,
            uid = %current_uid,
            gid = %nix::unistd::getgid(),
            capabilities = ?capabilities,
            "Privileges dropped successfully"
        );

        Ok(())
    }

    fn check_capabilities(&self, required_caps: &[&str]) -> Result<(), PlatformError> {
        debug!("Checking required capabilities: {:?}", required_caps);

        for cap_name in required_caps {
            let capability = match *cap_name {
                "CAP_NET_ADMIN" => Capability::CAP_NET_ADMIN,
                "CAP_NET_RAW" => Capability::CAP_NET_RAW,
                "CAP_NET_BIND_SERVICE" => Capability::CAP_NET_BIND_SERVICE,
                _ => {
                    warn!("Unknown capability name: {}", cap_name);
                    continue;
                }
            };

            let has_cap = caps::has_cap(None, CapSet::Permitted, capability).map_err(|e| {
                PlatformError::CapabilityError {
                    operation: format!("check permitted {capability:?}"),
                    reason: e.to_string(),
                }
            })?;

            if !has_cap {
                return Err(PlatformError::CapabilityError {
                    operation: format!("verify {capability:?}"),
                    reason: format!("Required capability {cap_name} is not in permitted set"),
                });
            }

            debug!("Capability {} is available", cap_name);
        }

        Ok(())
    }

    fn get_required_capabilities(&self, enable_dhcp: bool) -> Vec<String> {
        let mut caps = Vec::new();
        if enable_dhcp {
            caps.push("CAP_NET_ADMIN".to_string());
            caps.push("CAP_NET_RAW".to_string());
        }
        caps
    }
}

// ============================================================================
// BSD PRIVILEGE MANAGER (FreeBSD, NetBSD, macOS)
// ============================================================================

#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "macos"))]
/// BSD-specific privilege manager using basic setuid/setgid.
///
/// FreeBSD, NetBSD, and macOS do not support Linux-style capabilities,
/// so this implementation performs simple privilege dropping without
/// fine-grained capability retention.
#[derive(Default)]
pub struct BsdPrivilegeManager;

#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "macos"))]
impl BsdPrivilegeManager {
    /// Create a new BSD privilege manager.
    pub fn new() -> Self {
        Self
    }
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "macos"))]
impl PrivilegeManager for BsdPrivilegeManager {
    fn drop_privileges(
        &self,
        security_config: &SecurityConfig,
        _retain_net_admin: bool,
        _retain_net_raw: bool,
    ) -> Result<(), PlatformError> {
        // Determine target user
        let username =
            security_config.user.as_ref().ok_or_else(|| PlatformError::UserNotFound {
                user: "unknown".to_string(),
                reason: "No user specified in security configuration".to_string(),
            })?;

        // Look up user information
        let user = User::from_name(username)
            .map_err(|e| PlatformError::UserNotFound {
                user: username.clone(),
                reason: format!("Failed to lookup user '{}': {}", username, e),
            })?
            .ok_or_else(|| PlatformError::UserNotFound {
                user: username.clone(),
                reason: format!("User '{}' not found in /etc/passwd", username),
            })?;

        let uid = user.uid;
        let gid = if let Some(ref groupname) = security_config.group {
            let group = Group::from_name(groupname)
                .map_err(|e| PlatformError::UserNotFound {
                    user: groupname.clone(),
                    reason: format!("Failed to lookup group '{}': {}", groupname, e),
                })?
                .ok_or_else(|| PlatformError::UserNotFound {
                    user: groupname.clone(),
                    reason: format!("Group '{}' not found in /etc/group", groupname),
                })?;
            group.gid
        } else {
            user.gid
        };

        info!(
            user = %username,
            uid = %uid,
            gid = %gid,
            "Dropping privileges from root to unprivileged user (BSD)"
        );

        // Drop to target group first
        nix::unistd::setgid(gid).map_err(|e| PlatformError::PrivilegeDropFailed {
            reason: format!("setgid({}) failed: {}", gid, e),
        })?;

        // Clear supplementary groups
        nix::unistd::setgroups(&[gid]).map_err(|e| PlatformError::PrivilegeDropFailed {
            reason: format!("setgroups failed: {}", e),
        })?;

        // Drop to target user
        nix::unistd::setuid(uid).map_err(|e| PlatformError::PrivilegeDropFailed {
            reason: format!("setuid({}) failed: {}", uid, e),
        })?;

        // Verify we're no longer root
        let current_uid = nix::unistd::getuid();
        if current_uid.as_raw() == 0 {
            error!("Privilege drop failed: still running as root after setuid");
            return Err(PlatformError::PrivilegeDropFailed {
                reason: "Still running as root (UID 0) after privilege drop".to_string(),
            });
        }

        info!(
            user = %username,
            uid = %current_uid,
            gid = %nix::unistd::getgid(),
            "Privileges dropped successfully (no fine-grained capabilities on BSD)"
        );

        Ok(())
    }

    fn check_capabilities(&self, _required_caps: &[&str]) -> Result<(), PlatformError> {
        // BSD platforms don't have Linux-style capabilities
        // This is a no-op that always succeeds
        debug!("Capability checking not applicable on BSD platforms");
        Ok(())
    }

    fn get_required_capabilities(&self, _enable_dhcp: bool) -> Vec<String> {
        // BSD platforms don't have Linux-style capabilities
        Vec::new()
    }
}

// ============================================================================
// OPENBSD PRIVILEGE MANAGER
// ============================================================================

#[cfg(target_os = "openbsd")]
/// OpenBSD-specific privilege manager using pledge(2) and unveil(2).
///
/// OpenBSD provides promise-based security restrictions through `pledge(2)` and
/// filesystem access restrictions through `unveil(2)`. This manager combines
/// basic privilege dropping with OpenBSD's security features.
#[derive(Default)]
pub struct OpenBsdPrivilegeManager;

#[cfg(target_os = "openbsd")]
impl OpenBsdPrivilegeManager {
    /// Create a new OpenBSD privilege manager.
    pub fn new() -> Self {
        Self
    }

    /// Apply pledge(2) promises to restrict system call availability.
    ///
    /// # Arguments
    ///
    /// * `promises` - Space-separated list of pledge promises
    ///   (e.g., "stdio inet dns rpath wpath cpath flock")
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Pledge successfully applied
    /// * `Err(PlatformError)` - Pledge failed
    ///
    /// # Promises Required for dnsmasq
    ///
    /// - `stdio`: Standard I/O operations
    /// - `inet`: Internet socket operations (DNS, DHCP)
    /// - `dns`: DNS resolution
    /// - `rpath`: Read file paths (configuration, lease files)
    /// - `wpath`: Write file paths (lease files, PID file)
    /// - `cpath`: Create file paths (PID file, lease file)
    /// - `flock`: File locking (lease file)
    /// - `proc`: Process operations (for helper scripts)
    /// - `exec`: Execute helper scripts
    pub fn pledge(&self, promises: &str) -> Result<(), PlatformError> {
        debug!("Applying pledge promises: {}", promises);

        unsafe {
            let promises_cstr = std::ffi::CString::new(promises).map_err(|e| {
                PlatformError::PrivilegeDropFailed {
                    reason: format!("Invalid pledge promises: {}", e),
                }
            })?;

            if libc::pledge(promises_cstr.as_ptr(), std::ptr::null()) != 0 {
                return Err(PlatformError::PrivilegeDropFailed {
                    reason: format!(
                        "pledge('{}') failed: {}",
                        promises,
                        std::io::Error::last_os_error()
                    ),
                });
            }
        }

        info!("Pledge promises applied: {}", promises);
        Ok(())
    }

    /// Apply unveil(2) restrictions to limit filesystem access.
    ///
    /// # Arguments
    ///
    /// * `path` - Filesystem path to allow access to
    /// * `permissions` - Permission string ("r" for read, "w" for write, "x" for execute, "c" for create)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Unveil successfully applied
    /// * `Err(PlatformError)` - Unveil failed
    ///
    /// # Common dnsmasq Paths
    ///
    /// - `/etc/dnsmasq.conf`: "r" (read configuration)
    /// - `/var/lib/misc/dnsmasq.leases`: "rwc" (read/write/create lease file)
    /// - `/run/dnsmasq.pid`: "wc" (write/create PID file)
    /// - `/usr/local/bin/dhcp-script.sh`: "x" (execute helper script)
    pub fn unveil(&self, path: &str, permissions: &str) -> Result<(), PlatformError> {
        debug!("Applying unveil: {} with permissions {}", path, permissions);

        unsafe {
            let path_cstr = std::ffi::CString::new(path).map_err(|e| {
                PlatformError::PrivilegeDropFailed { reason: format!("Invalid unveil path: {}", e) }
            })?;
            let perms_cstr = std::ffi::CString::new(permissions).map_err(|e| {
                PlatformError::PrivilegeDropFailed {
                    reason: format!("Invalid unveil permissions: {}", e),
                }
            })?;

            if libc::unveil(path_cstr.as_ptr(), perms_cstr.as_ptr()) != 0 {
                return Err(PlatformError::PrivilegeDropFailed {
                    reason: format!(
                        "unveil('{}', '{}') failed: {}",
                        path,
                        permissions,
                        std::io::Error::last_os_error()
                    ),
                });
            }
        }

        debug!("Unveil applied: {} ({})", path, permissions);
        Ok(())
    }
}

#[cfg(target_os = "openbsd")]
impl PrivilegeManager for OpenBsdPrivilegeManager {
    fn drop_privileges(
        &self,
        security_config: &SecurityConfig,
        _retain_net_admin: bool,
        _retain_net_raw: bool,
    ) -> Result<(), PlatformError> {
        // Determine target user
        let username =
            security_config.user.as_ref().ok_or_else(|| PlatformError::UserNotFound {
                user: "unknown".to_string(),
                reason: "No user specified in security configuration".to_string(),
            })?;

        // Look up user information
        let user = User::from_name(username)
            .map_err(|e| PlatformError::UserNotFound {
                user: username.clone(),
                reason: format!("Failed to lookup user '{}': {}", username, e),
            })?
            .ok_or_else(|| PlatformError::UserNotFound {
                user: username.clone(),
                reason: format!("User '{}' not found in /etc/passwd", username),
            })?;

        let uid = user.uid;
        let gid = if let Some(ref groupname) = security_config.group {
            let group = Group::from_name(groupname)
                .map_err(|e| PlatformError::UserNotFound {
                    user: groupname.clone(),
                    reason: format!("Failed to lookup group '{}': {}", groupname, e),
                })?
                .ok_or_else(|| PlatformError::UserNotFound {
                    user: groupname.clone(),
                    reason: format!("Group '{}' not found in /etc/group", groupname),
                })?;
            group.gid
        } else {
            user.gid
        };

        info!(
            user = %username,
            uid = %uid,
            gid = %gid,
            "Dropping privileges from root to unprivileged user (OpenBSD)"
        );

        // Apply pledge before dropping privileges (more permissive initially)
        self.pledge("stdio inet dns rpath wpath cpath flock proc exec")?;

        // Drop to target group first
        nix::unistd::setgid(gid).map_err(|e| PlatformError::PrivilegeDropFailed {
            reason: format!("setgid({}) failed: {}", gid, e),
        })?;

        // Clear supplementary groups
        nix::unistd::setgroups(&[gid]).map_err(|e| PlatformError::PrivilegeDropFailed {
            reason: format!("setgroups failed: {}", e),
        })?;

        // Drop to target user
        nix::unistd::setuid(uid).map_err(|e| PlatformError::PrivilegeDropFailed {
            reason: format!("setuid({}) failed: {}", uid, e),
        })?;

        // Verify we're no longer root
        let current_uid = nix::unistd::getuid();
        if current_uid.as_raw() == 0 {
            error!("Privilege drop failed: still running as root after setuid");
            return Err(PlatformError::PrivilegeDropFailed {
                reason: "Still running as root (UID 0) after privilege drop".to_string(),
            });
        }

        // Apply more restrictive pledge after privilege drop (remove proc/exec if scripts not needed)
        self.pledge("stdio inet dns rpath wpath cpath flock")?;

        info!(
            user = %username,
            uid = %current_uid,
            gid = %nix::unistd::getgid(),
            "Privileges dropped successfully with OpenBSD pledge restrictions"
        );

        Ok(())
    }

    fn check_capabilities(&self, _required_caps: &[&str]) -> Result<(), PlatformError> {
        // OpenBSD uses pledge, not capabilities
        debug!("Capability checking not applicable on OpenBSD (using pledge instead)");
        Ok(())
    }

    fn get_required_capabilities(&self, _enable_dhcp: bool) -> Vec<String> {
        // OpenBSD uses pledge, not capabilities
        Vec::new()
    }
}

// ============================================================================
// PLATFORM-INDEPENDENT WRAPPER FUNCTIONS
// ============================================================================

/// Drop privileges from root to configured unprivileged user (platform-independent wrapper).
///
/// This function selects the appropriate platform-specific privilege manager and
/// performs privilege dropping with optional capability retention on Linux.
///
/// # Arguments
///
/// * `security_config` - Security configuration with target user/group
/// * `retain_net_admin` - Retain `CAP_NET_ADMIN` on Linux (ignored on other platforms)
/// * `retain_net_raw` - Retain `CAP_NET_RAW` on Linux (ignored on other platforms)
///
/// # Returns
///
/// * `Ok(())` - Privileges successfully dropped
/// * `Err(PlatformError)` - Privilege drop failed
///
/// # Platform Behavior
///
/// - **Linux**: Uses capabilities to retain `CAP_NET_ADMIN` and `CAP_NET_RAW` if requested
/// - **OpenBSD**: Uses pledge and unveil for promise-based restrictions
/// - **FreeBSD/NetBSD/macOS**: Simple setuid/setgid without capabilities
///
/// # Example
///
/// ```rust,ignore
/// use dnsmasq::platform::privileges::drop_privileges;
/// use dnsmasq::config::types::SecurityConfig;
///
/// let config = SecurityConfig {
///     user: Some("dnsmasq".to_string()),
///     group: Some("dnsmasq".to_string()),
///     chroot: None,
/// };
///
/// // Drop privileges, retaining network capabilities on Linux for DHCP
/// drop_privileges(&config, true, true)?;
/// ```
pub fn drop_privileges(
    security_config: &SecurityConfig,
    retain_net_admin: bool,
    retain_net_raw: bool,
) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        let manager = LinuxPrivilegeManager::new();
        manager.drop_privileges(security_config, retain_net_admin, retain_net_raw)
    }

    #[cfg(target_os = "openbsd")]
    {
        let manager = OpenBsdPrivilegeManager::new();
        manager.drop_privileges(security_config, retain_net_admin, retain_net_raw)
    }

    #[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "macos"))]
    {
        let manager = BsdPrivilegeManager::new();
        manager.drop_privileges(security_config, retain_net_admin, retain_net_raw)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "macos"
    )))]
    {
        warn!("Privilege dropping not implemented for this platform");
        Err(PlatformError::PrivilegeDropFailed {
            reason: "Privilege dropping not supported on this platform".to_string(),
        })
    }
}

/// Check if required capabilities are available before dropping privileges (Linux only).
///
/// This function verifies that all required capabilities are present in the permitted set
/// before attempting privilege drop. On non-Linux platforms, this is a no-op that always succeeds.
///
/// # Arguments
///
/// * `required_caps` - List of capability names (e.g., `["CAP_NET_ADMIN", "CAP_NET_RAW"]`)
///
/// # Returns
///
/// * `Ok(())` - All required capabilities are available (or platform doesn't use capabilities)
/// * `Err(PlatformError::CapabilityError)` - Missing required capabilities on Linux
///
/// # Example
///
/// ```rust,ignore
/// use dnsmasq::platform::privileges::check_capabilities;
///
/// // Verify DHCP-required capabilities are available before binding sockets
/// check_capabilities(&["CAP_NET_ADMIN", "CAP_NET_RAW"])?;
/// ```
pub fn check_capabilities(required_caps: &[&str]) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        let manager = LinuxPrivilegeManager::new();
        manager.check_capabilities(required_caps)
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Non-Linux platforms don't have capabilities - always succeed
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_config_validation() {
        let config = SecurityConfig {
            user: Some("nobody".to_string()),
            group: Some("nogroup".to_string()),
            chroot: None,
        };

        assert_eq!(config.user, Some("nobody".to_string()));
        assert_eq!(config.group, Some("nogroup".to_string()));
        assert_eq!(config.chroot, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_capability_name_mapping() {
        // Verify capability name strings map to correct enums
        let cap_names = vec!["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE"];

        for name in cap_names {
            let _capability = match name {
                "CAP_NET_ADMIN" => Capability::CAP_NET_ADMIN,
                "CAP_NET_RAW" => Capability::CAP_NET_RAW,
                "CAP_NET_BIND_SERVICE" => Capability::CAP_NET_BIND_SERVICE,
                _ => panic!("Unknown capability: {}", name),
            };
        }
    }

    #[test]
    fn test_get_required_capabilities() {
        #[cfg(target_os = "linux")]
        {
            let manager = LinuxPrivilegeManager::new();

            // DHCP enabled - should require network capabilities
            let caps_dhcp = manager.get_required_capabilities(true);
            assert_eq!(caps_dhcp.len(), 2);
            assert!(caps_dhcp.contains(&"CAP_NET_ADMIN".to_string()));
            assert!(caps_dhcp.contains(&"CAP_NET_RAW".to_string()));

            // DHCP disabled - no capabilities required
            let caps_no_dhcp = manager.get_required_capabilities(false);
            assert_eq!(caps_no_dhcp.len(), 0);
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Non-Linux platforms return empty list
            #[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "macos"))]
            {
                let manager = BsdPrivilegeManager::new();
                let caps = manager.get_required_capabilities(true);
                assert_eq!(caps.len(), 0);
            }
        }
    }
}
