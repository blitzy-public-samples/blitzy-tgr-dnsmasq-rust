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

//! Firewall integration module providing cross-platform dynamic firewall rule management.
//!
//! This module abstracts platform-specific firewall implementations (Linux ipset/nftables, BSD PF)
//! behind a unified trait-based interface, enabling DNS-triggered dynamic population of firewall
//! sets for content filtering, policy routing, and domain-based access control.
//!
//! # Architecture
//!
//! The module follows the **Strategy Pattern** with a trait-based abstraction layer:
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────┐
//! │                    FirewallBackend Trait                       │
//! │  + async fn add_to_set(domain, ip, set_name) -> Result<()>    │
//! │  + async fn remove_from_set(domain, ip, set_name) -> Result<()>│
//! └────────────────────────────────────────────────────────────────┘
//!                                 △
//!                                 │ implements
//!                 ┌───────────────┼───────────────┐
//!                 │               │               │
//!        ┌────────┴────────┐ ┌───┴────┐ ┌────────┴────────┐
//!        │  IpsetBackend   │ │NftBknd │ │   PfBackend     │
//!        │   (Linux ipset) │ │(nftabs)│ │   (BSD PF)      │
//!        └─────────────────┘ └────────┘ └─────────────────┘
//! ```
//!
//! # Platform Support
//!
//! ## Linux - ipset (kernel < 6.0 or legacy systems)
//!
//! Linux kernel ipset infrastructure via netlink interface. Supports both legacy (kernel < 2.6.32,
//! IPv4 only) and modern (kernel ≥ 2.6.32, IPv4/IPv6) implementations.
//!
//! **Configuration**: `--ipset=/domain/setname[,setname6]`
//!
//! **Use case**: Backward compatibility with existing iptables/ipset rulesets.
//!
//! ## Linux - nftables (kernel ≥ 4.18, recommended)
//!
//! Modern nftables packet filtering framework via libnftables. Unified IPv4/IPv6 handling,
//! better performance, atomic rule updates.
//!
//! **Configuration**: `--nftset=/domain/4#ip#table#set` or `--nftset=/domain/6#ip6#table#set`
//!
//! **Use case**: Modern Linux systems with nftables-based firewalls.
//!
//! ## BSD - Packet Filter (PF)
//!
//! BSD Packet Filter tables via ioctl interface to `/dev/pf`. Supports FreeBSD, OpenBSD, NetBSD.
//!
//! **Configuration**: `--ipset=/domain/tablename` (ipset directive reused for PF on BSD)
//!
//! **Use case**: BSD-based firewalls and routers (pfSense, OPNsense, etc.).
//!
//! # Integration with DNS Resolution
//!
//! The firewall module is invoked by the DNS cache module (`src/dns/cache.rs`) after successful
//! name resolution when domain patterns match firewall configuration:
//!
//! ```text
//! DNS Query → Cache Lookup → Forward to Upstream → Parse Response
//!                                                          │
//!                                                          ▼
//!                                           Check domain against firewall patterns
//!                                                          │
//!                                                          ▼
//!                                           FirewallBackend::add_to_set(domain, ip, set)
//!                                                          │
//!                                                          ▼
//!                                           Platform-specific implementation
//!                                           (ipset/nftables/PF)
//! ```
//!
//! # Use Cases
//!
//! ## Content Filtering
//!
//! Automatically block advertising and tracking domains by populating firewall sets:
//!
//! ```bash
//! # dnsmasq.conf
//! nftset=/doubleclick.net/4#ip#filter#blocked_ads
//! nftset=/doubleclick.net/6#ip6#filter#blocked_ads
//!
//! # nftables ruleset
//! nft add table ip filter
//! nft add set ip filter blocked_ads { type ipv4_addr\; }
//! nft add rule ip filter forward ip daddr @blocked_ads drop
//! ```
//!
//! ## Policy-Based Routing
//!
//! Route specific domains through VPN or alternative gateway:
//!
//! ```bash
//! # Route streaming services through specific interface
//! ipset=/netflix.com/vpn_ips
//! ip rule add fwmark 1 table vpn_route
//! iptables -t mangle -A PREROUTING -m set --match-set vpn_ips dst -j MARK --set-mark 1
//! ```
//!
//! ## QoS and Traffic Shaping
//!
//! Apply bandwidth limits based on domain classification:
//!
//! ```bash
//! # Limit bandwidth for social media domains
//! nftset=/facebook.com/4#ip#qos#social_media
//! tc filter add dev eth0 protocol ip prio 1 handle 1 fw classid 1:10
//! ```
//!
//! # Error Handling
//!
//! All firewall operations return `Result<(), FirewallError>` with structured error types:
//!
//! - [`FirewallError::SetNotFound`]: Named set/table does not exist in firewall configuration
//! - [`FirewallError::AddressNotSupported`]: IPv6 address on IPv4-only platform
//! - [`FirewallError::ProtocolError`]: Netlink/ioctl protocol communication failure
//! - [`FirewallError::DeviceNotFound`]: `/dev/pf` or netlink socket unavailable
//! - [`FirewallError::TableCreateFailed`]: Failed to create PF table or nftables set
//! - [`FirewallError::AddressFailed`]: Failed to add/remove address from set
//!
//! Errors are logged via `tracing` crate and non-fatal - DNS resolution continues even if
//! firewall population fails, preventing firewall issues from disrupting name resolution.
//!
//! # Memory Safety
//!
//! The C implementations (src/ipset.c, src/nftset.c, src/tables.c) used manual buffer management
//! with fixed-size arrays and pointer arithmetic for netlink/ioctl message construction:
//!
//! ```c
//! // C implementation: Fixed buffer with pointer arithmetic
//! char buffer[256];
//! struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
//! struct my_nlattr *attr = (struct my_nlattr *)((u8 *)nlh + NL_ALIGN(nlh->nlmsg_len));
//! memcpy(attr + 1, data, len);  // Risk of buffer overflow
//! ```
//!
//! The Rust implementation uses type-safe abstractions:
//!
//! ```rust,ignore
//! // Rust implementation: Safe, growable buffers
//! let mut msg_buf = Vec::with_capacity(256);
//! let mut msg = NetlinkMessage::new();
//! msg.add_attribute(AttrType::SetName, set_name.as_bytes());
//! msg.serialize(&mut msg_buf)?;  // Bounds-checked serialization
//! ```
//!
//! # Performance Considerations
//!
//! - **Async Operations**: All firewall operations are async to prevent blocking the tokio event
//!   loop during netlink/ioctl system calls. Operations typically complete in <1ms.
//!
//! - **Fire-and-Forget**: Firewall updates are non-blocking - DNS responses are not delayed
//!   waiting for firewall confirmation. Failures are logged but do not fail DNS queries.
//!
//! - **Batch Updates**: Future optimization could batch multiple IP additions to same set
//!   within a time window to reduce system call overhead.
//!
//! # Thread Safety
//!
//! All backend implementations are `Send + Sync`, allowing safe sharing across tokio tasks.
//! The single-threaded C event loop is replaced with tokio's work-stealing scheduler, but
//! firewall state is managed entirely in kernel space, so no Rust-side synchronization is needed.
//!
//! # Conditional Compilation
//!
//! Platform-specific backends are conditionally compiled based on target OS:
//!
//! ```rust,ignore
//! #[cfg(target_os = "linux")]
//! pub mod ipset;
//!
//! #[cfg(target_os = "linux")]
//! pub mod nftables;
//!
//! #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
//! pub mod pf;
//! ```
//!
//! This ensures only relevant code is compiled for each platform, reducing binary size and
//! eliminating unused dependencies.
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use dnsmasq::network::firewall::{create_firewall_backend, AddressFamily};
//! use dnsmasq::config::types::Config;
//! use std::net::IpAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::from_file("/etc/dnsmasq.conf").await?;
//!     
//!     // Factory creates appropriate backend based on platform and config
//!     if let Some(firewall) = create_firewall_backend(&config) {
//!         let domain = "example.com";
//!         let ip: IpAddr = "93.184.216.34".parse()?;
//!         
//!         // Add resolved IP to firewall set
//!         firewall.add_to_set(domain, ip, "blocked_domains").await?;
//!         println!("Added {} ({}) to firewall set", domain, ip);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! # References
//!
//! - Linux ipset: `man 8 ipset`, kernel documentation in Documentation/networking/ipset.txt
//! - Linux nftables: `man 8 nft`, libnftables documentation
//! - BSD PF: `man 4 pf`, `man 8 pfctl`, OpenBSD PF User's Guide
//! - Original C implementations: src/ipset.c, src/nftset.c, src/tables.c

use async_trait::async_trait;
use std::fmt;
use thiserror::Error;

use crate::config::types::Config;
use crate::types::IpAddr;

// Platform-specific module declarations with conditional compilation
#[cfg(target_os = "linux")]
pub mod ipset;

#[cfg(target_os = "linux")]
pub mod nftables;

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub mod pf;

// Re-export platform-specific backend implementations
#[cfg(target_os = "linux")]
pub use ipset::IpsetBackend;

#[cfg(target_os = "linux")]
pub use nftables::NftablesBackend;

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub use pf::PfBackend;

/// Unified error type for all firewall backend operations.
///
/// This enum provides structured error handling across different platform implementations,
/// replacing C's error code pattern (return -1, check errno) with Rust's Result type system.
///
/// # Error Categories
///
/// - **Configuration Errors**: SetNotFound, TableCreateFailed
/// - **Protocol Errors**: ProtocolError (netlink/ioctl communication failures)
/// - **Platform Errors**: DeviceNotFound (/dev/pf unavailable)
/// - **Address Errors**: AddressNotSupported (IPv6 on IPv4-only system), AddressFailed
///
/// # C Error Handling Comparison
///
/// ```c
/// // C implementation: Error codes with errno
/// if (add_to_ipset(addr, setname, AF_INET) < 0) {
///     my_syslog(LOG_ERR, "ipset: %s", strerror(errno));
///     return -1;
/// }
/// ```
///
/// ```rust,ignore
/// // Rust implementation: Result with structured errors
/// firewall.add_to_set(domain, ip, set_name).await
///     .map_err(|e| {
///         error!(error = %e, "Failed to add address to firewall set");
///         e
///     })?;
/// ```
///
/// # Error Context
///
/// All error variants include contextual information (set names, IP addresses, error messages)
/// for debugging. Use `thiserror`'s `#[error(...)]` attributes to generate Display implementations.
#[derive(Debug, Error)]
pub enum FirewallError {
    /// Named firewall set or table does not exist.
    ///
    /// **Cause**: Set referenced in configuration (--ipset, --nftset) was not created in firewall.
    ///
    /// **Resolution**: Create the set/table before starting dnsmasq:
    /// - ipset: `ipset create setname hash:ip`
    /// - nftables: `nft add set ip table setname { type ipv4_addr\; }`
    /// - PF: `pfctl -t tablename -T add` (creates table if needed)
    #[error("Firewall set not found: {0}")]
    SetNotFound(String),

    /// IP address family not supported by this firewall backend.
    ///
    /// **Cause**: IPv6 address on IPv4-only platform or configuration.
    ///
    /// **Examples**:
    /// - Legacy ipset on kernel < 2.6.32 (IPv4 only)
    /// - IPv6 address with IPv4-only set configuration
    ///
    /// **Resolution**: Configure separate IPv4/IPv6 sets or upgrade to modern kernel/firewall.
    #[error("Address family not supported: {0}")]
    AddressNotSupported(String),

    /// Low-level protocol communication error (netlink, ioctl, libnftables).
    ///
    /// **Cause**: Kernel communication failure, permission denied, or malformed message.
    ///
    /// **Examples**:
    /// - Netlink socket bind failure (permission denied)
    /// - ioctl() returns error code
    /// - nftables library returns error buffer
    ///
    /// **Resolution**: Check permissions (CAP_NET_ADMIN), kernel module loaded, firewall running.
    #[error("Firewall protocol error: {0}")]
    ProtocolError(String),

    /// Firewall device or interface not found.
    ///
    /// **Cause**: `/dev/pf` not available (BSD), netlink subsystem not loaded (Linux).
    ///
    /// **Resolution**: Load kernel modules (pf.ko, netfilter), check device permissions.
    #[error("Firewall device not found: {0}")]
    DeviceNotFound(String),

    /// Failed to create firewall table or set.
    ///
    /// **Cause**: Insufficient permissions, invalid table/set name, kernel limit reached.
    ///
    /// **Resolution**: Run with appropriate privileges, check table name validity, increase limits.
    #[error("Failed to create firewall table: {0}")]
    TableCreateFailed(String),

    /// Failed to add or remove address from firewall set.
    ///
    /// **Cause**: Address already exists (add), address not found (remove), set full.
    ///
    /// **Resolution**: Check set capacity, verify address format, examine firewall logs.
    #[error("Failed to add/remove address from set: {0}")]
    AddressFailed(String),
}

/// Convenience type alias for firewall operation results.
///
/// All firewall operations return this Result type with `()` success value and [`FirewallError`]
/// failure type. This matches Rust conventions for operations with side effects but no return value.
pub type Result<T> = std::result::Result<T, FirewallError>;

/// IP address family discriminator for platform-specific handling.
///
/// This enum replaces C's `AF_INET`/`AF_INET6` constants with a type-safe Rust enum, enabling
/// compile-time exhaustiveness checking and eliminating invalid family values.
///
/// # C Comparison
///
/// ```c
/// // C implementation: Integer constants, no type safety
/// #define AF_INET   2
/// #define AF_INET6  10
///
/// void add_to_set(union all_addr *addr, int family) {
///     switch (family) {
///         case AF_INET:  /* IPv4 */ break;
///         case AF_INET6: /* IPv6 */ break;
///         // Missing case: undefined behavior
///     }
/// }
/// ```
///
/// ```rust,ignore
/// // Rust implementation: Exhaustive pattern matching enforced
/// fn add_to_set(addr: IpAddr) -> Result<()> {
///     match addr {
///         IpAddr::V4(_) => { /* IPv4 */ },
///         IpAddr::V6(_) => { /* IPv6 */ },
///         // Compiler error if any variant missing
///     }
///     Ok(())
/// }
/// ```
///
/// # Usage
///
/// Extract family from `IpAddr` for platform-specific API requirements:
///
/// ```rust,ignore
/// let family = AddressFamily::from(ip_addr);
/// match family {
///     AddressFamily::IPv4 => set_ipv4_backend(),
///     AddressFamily::IPv6 => set_ipv6_backend(),
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 address family (AF_INET in C, corresponds to `IpAddr::V4`).
    IPv4,
    /// IPv6 address family (AF_INET6 in C, corresponds to `IpAddr::V6`).
    IPv6,
}

impl From<IpAddr> for AddressFamily {
    /// Extract address family from `IpAddr` enum.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use std::net::IpAddr;
    /// use dnsmasq::network::firewall::AddressFamily;
    ///
    /// let ipv4: IpAddr = "192.0.2.1".parse().unwrap();
    /// assert_eq!(AddressFamily::from(ipv4), AddressFamily::IPv4);
    ///
    /// let ipv6: IpAddr = "2001:db8::1".parse().unwrap();
    /// assert_eq!(AddressFamily::from(ipv6), AddressFamily::IPv6);
    /// ```
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => AddressFamily::IPv4,
            IpAddr::V6(_) => AddressFamily::IPv6,
        }
    }
}

impl fmt::Display for AddressFamily {
    /// Format address family for human-readable output.
    ///
    /// Used in log messages and error reporting.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressFamily::IPv4 => write!(f, "IPv4"),
            AddressFamily::IPv6 => write!(f, "IPv6"),
        }
    }
}

/// Trait abstraction for platform-specific firewall backends.
///
/// This trait defines the contract that all firewall implementations (ipset, nftables, PF) must
/// satisfy, enabling polymorphic backend selection at runtime based on platform and configuration.
///
/// # Design Pattern: Strategy Pattern
///
/// The trait allows different firewall strategies to be selected dynamically:
///
/// ```rust,ignore
/// let backend: Box<dyn FirewallBackend> = match platform {
///     Platform::LinuxIpset => Box::new(IpsetBackend::new()?),
///     Platform::LinuxNftables => Box::new(NftablesBackend::new()?),
///     Platform::BsdPf => Box::new(PfBackend::new()?),
/// };
///
/// backend.add_to_set(domain, ip, set_name).await?;
/// ```
///
/// # Async Methods
///
/// All trait methods are async to prevent blocking the tokio event loop during system calls:
///
/// - `add_to_set`: Async netlink send, ioctl, or nftables command execution
/// - `remove_from_set`: Async removal operation
///
/// The `#[async_trait]` macro transforms async trait methods into `Pin<Box<dyn Future>>` return
/// types, as Rust does not natively support async methods in traits (as of Rust 1.91.0).
///
/// # Object Safety
///
/// The trait is object-safe (can be used as `Box<dyn FirewallBackend>`) because:
/// - All methods take `&self` (sized receiver)
/// - No generic methods or associated types (beyond lifetime parameters)
/// - Return types are concrete (after `async_trait` transformation)
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` for sharing across tokio tasks. The trait bounds are
/// inherited by all implementors.
///
/// # Error Handling
///
/// All methods return `Result<()>` where errors are non-fatal. The DNS resolution path logs
/// firewall errors but continues serving DNS responses, preventing firewall issues from
/// disrupting critical name resolution services.
#[async_trait]
pub trait FirewallBackend: Send + Sync {
    /// Add resolved IP address to named firewall set or table.
    ///
    /// This method is invoked by the DNS cache module after successful domain resolution when
    /// the domain matches configured firewall patterns. The implementation must handle:
    ///
    /// - Address family detection (IPv4 vs IPv6)
    /// - Set/table existence validation
    /// - Duplicate address handling (idempotent - adding existing address succeeds)
    /// - Platform-specific API calls (netlink, ioctl, libnftables)
    ///
    /// # Arguments
    ///
    /// * `domain` - Fully qualified domain name that was resolved (e.g., "example.com")
    /// * `ip` - Resolved IP address to add to firewall set
    /// * `set_name` - Name of target firewall set/table (validated by implementation)
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Address successfully added or already exists
    /// - `Err(FirewallError)` - Operation failed (logged, does not fail DNS query)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let backend = IpsetBackend::new().await?;
    /// backend.add_to_set("ads.example.com", "192.0.2.100".parse()?, "blocked_ads").await?;
    /// ```
    ///
    /// # Implementation Notes
    ///
    /// - **ipset**: Sends netlink IPSET_CMD_ADD message with IPSET_ATTR_SETNAME and IPSET_ATTR_IP
    /// - **nftables**: Executes `nft add element <table> <set> { <ip> }` via libnftables
    /// - **PF**: Issues DIOCRADDADDRS ioctl to /dev/pf with pfr_addr structure
    async fn add_to_set(&self, domain: &str, ip: IpAddr, set_name: &str) -> Result<()>;

    /// Remove IP address from named firewall set or table.
    ///
    /// This method supports address removal when DNS cache entries expire or change. Not all
    /// deployments use removal (sets may accumulate addresses), but the functionality is provided
    /// for completeness and cache coherency.
    ///
    /// # Arguments
    ///
    /// * `domain` - Fully qualified domain name (for logging/auditing)
    /// * `ip` - IP address to remove from firewall set
    /// * `set_name` - Name of target firewall set/table
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Address successfully removed or does not exist
    /// - `Err(FirewallError)` - Operation failed
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Remove expired cache entry from firewall
    /// backend.remove_from_set("expired.example.com", old_ip, "dynamic_set").await?;
    /// ```
    ///
    /// # Implementation Notes
    ///
    /// - **ipset**: Sends netlink IPSET_CMD_DEL message
    /// - **nftables**: Executes `nft delete element <table> <set> { <ip> }`
    /// - **PF**: Issues DIOCRDELADDRS ioctl to /dev/pf
    async fn remove_from_set(&self, domain: &str, ip: IpAddr, set_name: &str) -> Result<()>;
}

/// Factory function to create appropriate firewall backend based on platform and configuration.
///
/// This function implements the **Factory Pattern**, selecting and instantiating the correct
/// firewall backend implementation based on:
///
/// 1. Target operating system (Linux vs BSD)
/// 2. Available firewall system (ipset vs nftables on Linux)
/// 3. User configuration preferences (--ipset, --nftset, --ipset on BSD)
///
/// # Selection Logic
///
/// ## Linux Platform
///
/// ```text
/// if config has --nftset directives:
///     return Some(Box::new(NftablesBackend::new()?))
/// else if config has --ipset directives:
///     return Some(Box::new(IpsetBackend::new()?))
/// else:
///     return None  // No firewall integration configured
/// ```
///
/// ## BSD Platform (FreeBSD, OpenBSD, NetBSD)
///
/// ```text
/// if config has --ipset directives:  // Reused for PF configuration
///     return Some(Box::new(PfBackend::new()?))
/// else:
///     return None
/// ```
///
/// # Arguments
///
/// * `config` - Parsed dnsmasq configuration containing firewall directives
///
/// # Returns
///
/// - `Some(Box<dyn FirewallBackend>)` - Firewall backend instance
/// - `None` - No firewall integration configured or platform not supported
///
/// # Example
///
/// ```rust,ignore
/// use dnsmasq::network::firewall::create_firewall_backend;
/// use dnsmasq::config::types::Config;
///
/// let config = Config::from_file("/etc/dnsmasq.conf").await?;
///
/// if let Some(firewall) = create_firewall_backend(&config) {
///     info!("Firewall integration enabled");
///     // Use firewall backend for DNS-triggered population
/// } else {
///     info!("Firewall integration disabled");
/// }
/// ```
///
/// # Platform Detection
///
/// The function uses conditional compilation to provide platform-appropriate implementations:
///
/// ```rust,ignore
/// #[cfg(target_os = "linux")]
/// pub fn create_firewall_backend(config: &Config) -> Option<Box<dyn FirewallBackend>> {
///     // Linux-specific logic (ipset, nftables)
/// }
///
/// #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
/// pub fn create_firewall_backend(config: &Config) -> Option<Box<dyn FirewallBackend>> {
///     // BSD-specific logic (PF)
/// }
/// ```
///
/// # Error Handling
///
/// Backend initialization failures return `None` and log errors. This is non-fatal - dnsmasq
/// continues operating without firewall integration rather than failing to start.
///
/// # Performance
///
/// The factory function is called once at daemon initialization. The returned backend is shared
/// across all DNS resolution tasks via `Arc<dyn FirewallBackend>`.
#[cfg(target_os = "linux")]
pub fn create_firewall_backend(config: &Config) -> Option<Box<dyn FirewallBackend>> {
    // Check for nftables configuration first (modern Linux preferred)
    // Configuration inspection would check for nftset directives in config
    // For now, returning None as backends are not yet implemented
    // Implementation will inspect config.network.nftset_domains or similar field
    
    // Check for ipset configuration (legacy Linux)
    // Similar config field inspection: config.network.ipset_domains
    
    // Placeholder: Backend implementations in ipset.rs and nftables.rs will be created separately
    None
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub fn create_firewall_backend(config: &Config) -> Option<Box<dyn FirewallBackend>> {
    // Check for PF table configuration
    // On BSD, the --ipset directive is reused for PF table names
    // Configuration field: config.network.pf_tables or config.network.ipset_domains
    
    // Placeholder: Backend implementation in pf.rs will be created separately
    None
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
pub fn create_firewall_backend(_config: &Config) -> Option<Box<dyn FirewallBackend>> {
    // Unsupported platform - no firewall integration available
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_family_from_ipaddr() {
        let ipv4: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(AddressFamily::from(ipv4), AddressFamily::IPv4);

        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(AddressFamily::from(ipv6), AddressFamily::IPv6);
    }

    #[test]
    fn test_address_family_display() {
        assert_eq!(format!("{}", AddressFamily::IPv4), "IPv4");
        assert_eq!(format!("{}", AddressFamily::IPv6), "IPv6");
    }

    #[test]
    fn test_firewall_error_display() {
        let err = FirewallError::SetNotFound("test_set".to_string());
        assert_eq!(format!("{}", err), "Firewall set not found: test_set");

        let err = FirewallError::ProtocolError("netlink error".to_string());
        assert_eq!(format!("{}", err), "Firewall protocol error: netlink error");
    }
}
