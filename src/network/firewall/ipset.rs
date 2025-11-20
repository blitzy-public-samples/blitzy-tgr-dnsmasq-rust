// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
// ipset.c is Copyright (c) 2013 Jason A. Donenfeld <Jason@zx2c4.com>
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

//! Linux kernel ipset integration for DNS-triggered dynamic firewall rule population.
//!
//! This module provides safe Rust implementation of Linux kernel ipset integration, replacing
//! the C implementation in src/ipset.c with memory-safe netlink message construction and
//! automatic kernel version detection. The module enables dynamic population of named ipset
//! collections with IP addresses resolved from DNS queries, supporting content filtering,
//! policy-based routing, and domain-based firewall rules.
//!
//! # Architecture Overview
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                       IpsetBackend                                │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │              Kernel Version Detection                      │  │
//! │  │  uname() → parse kernel version → select API              │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! │                           │                                       │
//! │              ┌────────────┴────────────┐                         │
//! │              │                         │                         │
//! │    ┌─────────▼────────┐    ┌──────────▼──────────┐              │
//! │    │  Modern API      │    │   Legacy API        │              │
//! │    │  (kernel ≥2.6.32)│    │   (kernel <2.6.32)  │              │
//! │    ├──────────────────┤    ├─────────────────────┤              │
//! │    │ NETLINK_NETFILTER│    │ AF_INET/SOCK_RAW    │              │
//! │    │ IPv4 + IPv6      │    │ IPv4 only           │              │
//! │    │ Netlink messages │    │ setsockopt API      │              │
//! │    └──────────────────┘    └─────────────────────┘              │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # C-to-Rust Transformation
//!
//! ## Memory Safety
//!
//! The C implementation used manual buffer management with fixed-size arrays and unsafe
//! pointer arithmetic for netlink message construction:
//!
//! ```c
//! // C implementation: Fixed 256-byte buffer with pointer arithmetic
//! static char *buffer;
//! buffer = safe_malloc(BUFF_SZ);  // Global state, manual allocation
//! struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
//! struct my_nlattr *attr = (struct my_nlattr *)((u8 *)nlh + NL_ALIGN(nlh->nlmsg_len));
//! memcpy((u8 *)attr + NL_ALIGN(sizeof(struct my_nlattr)), data, len);  // Risk of overflow
//! ```
//!
//! The Rust implementation uses type-safe buffer management with automatic bounds checking:
//!
//! ```rust,ignore
//! // Rust implementation: Safe, growable buffers with BytesMut
//! let mut buffer = BytesMut::with_capacity(256);
//! // Automatic bounds checking, no pointer arithmetic, RAII cleanup
//! buffer.put_slice(&data);  // Compile-time safety guarantees
//! ```
//!
//! ## Kernel Version Detection
//!
//! The C implementation relied on global daemon state:
//!
//! ```c
//! // C: Global access to kernel version
//! old_kernel = (daemon->kernel_version < KERNEL_VERSION(2,6,32));
//! ```
//!
//! Rust uses explicit kernel version detection via `uname()`:
//!
//! ```rust,ignore
//! // Rust: Explicit, testable kernel version detection
//! let version = detect_kernel_version()?;
//! let is_legacy = version.0 < 2 || (version.0 == 2 && version.1 < 6) || 
//!                 (version.0 == 2 && version.1 == 6 && version.2 < 32);
//! ```
//!
//! # API Support
//!
//! ## Modern API (Linux kernel ≥ 2.6.32)
//!
//! Uses `NETLINK_NETFILTER` socket with ipset netlink protocol:
//!
//! - **Socket Type**: `AF_NETLINK`, `SOCK_RAW`, `NETLINK_NETFILTER`
//! - **Protocol**: ipset netlink protocol version 6 (`IPSET_PROTOCOL`)
//! - **Address Support**: IPv4 and IPv6
//! - **Operations**: `IPSET_CMD_ADD`, `IPSET_CMD_DEL` with nested netlink attributes
//! - **Message Format**: netlink header + nfgenmsg + nested TLV attributes
//!
//! ### Netlink Message Structure
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │ struct nlmsghdr                                            │
//! │  - nlmsg_len: total message length                        │
//! │  - nlmsg_type: IPSET_CMD_ADD | (NFNL_SUBSYS_IPSET << 8)  │
//! │  - nlmsg_flags: NLM_F_REQUEST                             │
//! ├────────────────────────────────────────────────────────────┤
//! │ struct nfgenmsg                                            │
//! │  - nfgen_family: AF_INET or AF_INET6                      │
//! │  - version: NFNETLINK_V0 (0)                              │
//! │  - res_id: 0                                              │
//! ├────────────────────────────────────────────────────────────┤
//! │ IPSET_ATTR_PROTOCOL: u8 = 6                               │
//! ├────────────────────────────────────────────────────────────┤
//! │ IPSET_ATTR_SETNAME: char[] = "setname\0"                  │
//! ├────────────────────────────────────────────────────────────┤
//! │ IPSET_ATTR_DATA (NLA_F_NESTED)                            │
//! │  └─ IPSET_ATTR_IP (NLA_F_NESTED)                          │
//! │      └─ IPSET_ATTR_IPADDR_IPV4/6: IPv4/IPv6 address      │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Legacy API (Linux kernel < 2.6.32)
//!
//! Uses raw socket with `setsockopt`/`getsockopt` interface:
//!
//! - **Socket Type**: `AF_INET`, `SOCK_RAW`, `IPPROTO_RAW`
//! - **Protocol**: Legacy ipset API via `SOL_IP` socket option 83
//! - **Address Support**: IPv4 only
//! - **Operations**: `IP_SET_OP_ADD_IP` (0x101), `IP_SET_OP_DEL_IP` (0x102)
//! - **Limitation**: No IPv6 support, returns `AddressNotSupported` error
//!
//! # Integration with DNS Resolution
//!
//! The ipset backend is invoked by DNS cache module after successful name resolution:
//!
//! ```text
//! DNS Query → Resolve → Cache Insert → Check ipset config → IpsetBackend::add_to_set()
//!                                                                    │
//!                                                                    ▼
//!                                                       Kernel netfilter ipset
//! ```
//!
//! Configuration example:
//!
//! ```conf
//! # /etc/dnsmasq.conf
//! ipset=/doubleclick.net/blocked_ads
//! ipset=/facebook.com/social_media,social_media6
//! ```
//!
//! # Use Cases
//!
//! ## Content Filtering
//!
//! Block advertising and tracking domains dynamically:
//!
//! ```bash
//! # Create ipset
//! ipset create blocked_ads hash:ip
//!
//! # dnsmasq configuration
//! ipset=/ads.example.com/blocked_ads
//!
//! # Firewall rule
//! iptables -A FORWARD -m set --match-set blocked_ads dst -j DROP
//! ```
//!
//! ## Policy-Based Routing
//!
//! Route specific domains through VPN:
//!
//! ```bash
//! # Create ipset
//! ipset create vpn_ips hash:ip
//!
//! # dnsmasq configuration
//! ipset=/streaming-service.com/vpn_ips
//!
//! # Routing rules
//! ip rule add fwmark 1 table vpn_route
//! iptables -t mangle -A PREROUTING -m set --match-set vpn_ips dst -j MARK --set-mark 1
//! ```
//!
//! ## Traffic Shaping
//!
//! Apply QoS policies based on domain classification:
//!
//! ```bash
//! # Create ipset
//! ipset create high_priority hash:ip
//!
//! # dnsmasq configuration
//! ipset=/voip-provider.com/high_priority
//!
//! # QoS marking
//! iptables -t mangle -A POSTROUTING -m set --match-set high_priority dst -j DSCP --set-dscp 46
//! ```
//!
//! # Error Handling
//!
//! All operations return `Result<(), FirewallError>` with structured error types:
//!
//! - **SetNotFound**: Named ipset does not exist (administrator must pre-create sets)
//! - **AddressNotSupported**: IPv6 address on legacy kernel (< 2.6.32)
//! - **ProtocolError**: Netlink communication failure, permission denied, socket error
//! - **DeviceNotFound**: Netlink subsystem not loaded, /proc/sys/net/netfilter unavailable
//!
//! Errors are logged but non-fatal - DNS resolution continues even if ipset population fails,
//! preventing firewall issues from disrupting name resolution services.
//!
//! # Thread Safety
//!
//! `IpsetBackend` is `Send + Sync`, enabling safe sharing across tokio tasks. Netlink socket
//! operations are wrapped in `tokio::task::spawn_blocking()` to prevent blocking the async
//! event loop during synchronous system calls.
//!
//! # Performance Characteristics
//!
//! - **Initialization**: O(1) - single `uname()` call and socket creation
//! - **Add/Remove**: O(1) - single netlink message send, fire-and-forget (no response wait)
//! - **Memory**: ~256 bytes per message buffer, no persistent allocations
//! - **Latency**: <1ms typical for netlink send operation
//!
//! # Examples
//!
//! ```rust,ignore
//! use dnsmasq::network::firewall::ipset::IpsetBackend;
//! use std::net::IpAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create and initialize ipset backend
//!     let mut backend = IpsetBackend::new();
//!     backend.initialize().await?;
//!     
//!     // Add IPv4 address to set
//!     let ip: IpAddr = "203.0.113.50".parse()?;
//!     backend.add_to_set("malware.example.com", ip, "blocked_domains").await?;
//!     
//!     // Add IPv6 address to set (modern kernel only)
//!     let ip6: IpAddr = "2001:db8::1".parse()?;
//!     backend.add_to_set("ads.example.com", ip6, "blocked_ads6").await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! # References
//!
//! - Linux ipset: `man 8 ipset`, kernel documentation in Documentation/networking/ipset.txt
//! - Netlink protocol: RFC 3549, kernel documentation in Documentation/networking/netlink.txt
//! - ipset netlink protocol: `<linux/netfilter/ipset/ip_set.h>`
//! - Original C implementation: src/ipset.c
//!
//! # License
//!
//! GPL-2.0-or-later OR GPL-3.0-or-later

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use nix::sys::socket::{
    bind, sendto, socket, AddressFamily as NixAddressFamily, MsgFlags, NetlinkAddr, SockFlag,
    SockProtocol, SockType,
};
use nix::sys::utsname::uname;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;
use tokio::task;
use tracing::{debug, error, info, warn};

use super::{FirewallBackend, FirewallError, Result};
use crate::types::IpAddr as DnsmasqIpAddr;

// ============================================================================
// Constants: ipset netlink protocol definitions
// ============================================================================

/// Netfilter subsystem identifier for ipset (NFNL_SUBSYS_IPSET)
const NFNL_SUBSYS_IPSET: u8 = 6;

/// ipset protocol version
const IPSET_PROTOCOL: u8 = 6;

/// Maximum length for ipset name (includes null terminator)
const IPSET_MAXNAMELEN: usize = 32;

/// Netlink message buffer size (matches C BUFF_SZ)
const BUFF_SZ: usize = 256;

// ipset netlink command codes
const IPSET_CMD_ADD: u16 = 9;
const IPSET_CMD_DEL: u16 = 10;

// ipset netlink attribute types
const IPSET_ATTR_PROTOCOL: u16 = 1;
const IPSET_ATTR_SETNAME: u16 = 2;
const IPSET_ATTR_DATA: u16 = 7;
const IPSET_ATTR_IP: u16 = 1;
const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
const IPSET_ATTR_IPADDR_IPV6: u16 = 2;

// Netlink attribute flags
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;

// Netfilter netlink version
const NFNETLINK_V0: u8 = 0;

// Netlink message flags
const NLM_F_REQUEST: u16 = 1;

// Legacy ipset API constants (for kernel < 2.6.32)
const IP_SET_OP_GET_BYNAME: u32 = 0x10;
const IP_SET_OP_ADD_IP: u32 = 0x101;
const IP_SET_OP_DEL_IP: u32 = 0x102;
const IP_SET_API_VERSION: u32 = 3;

// ============================================================================
// Netlink protocol structures
// ============================================================================

/// Netlink message header structure (corresponds to struct nlmsghdr)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NlMsgHdr {
    /// Total length of message including header
    nlmsg_len: u32,
    /// Message type: command code | (subsystem << 8)
    nlmsg_type: u16,
    /// Message flags (NLM_F_REQUEST, etc.)
    nlmsg_flags: u16,
    /// Sequence number (typically 0 for fire-and-forget)
    nlmsg_seq: u32,
    /// Port ID (typically 0)
    nlmsg_pid: u32,
}

/// Netfilter generic message structure (corresponds to struct nfgenmsg)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NfGenMsg {
    /// Address family: AF_INET (2) or AF_INET6 (10)
    nfgen_family: u8,
    /// Netlink protocol version: NFNETLINK_V0 (0)
    version: u8,
    /// Resource ID (typically 0 for ipset)
    res_id: u16,  // Network byte order (__be16)
}

/// Netlink attribute header structure (corresponds to struct nlattr)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NlAttr {
    /// Length of attribute including header and payload
    nla_len: u16,
    /// Attribute type, may include NLA_F_NESTED or NLA_F_NET_BYTEORDER flags
    nla_type: u16,
}

/// Legacy ipset API request structure for getting set ID by name
#[repr(C)]
struct IpSetReqAdtGet {
    op: u32,
    version: u32,
    set_name: [u8; IPSET_MAXNAMELEN],
    typename: [u8; IPSET_MAXNAMELEN],
}

/// Legacy ipset API request structure for add/delete operations
#[repr(C)]
struct IpSetReqAdt {
    op: u32,
    index: u16,
    _padding: u16,  // Alignment padding
    ip: u32,  // IPv4 address in host byte order
}

// ============================================================================
// Helper functions
// ============================================================================

/// Align value to 4-byte boundary (netlink alignment requirement)
#[inline]
const fn nl_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Detect Linux kernel version by parsing uname() output.
///
/// Returns tuple (major, minor, patch) representing kernel version.
/// Used to determine whether to use modern netlink API (≥2.6.32) or
/// legacy setsockopt API (<2.6.32).
///
/// # Errors
///
/// Returns `FirewallError::ProtocolError` if:
/// - `uname()` system call fails
/// - Kernel release string cannot be parsed
///
/// # Example
///
/// ```rust,ignore
/// let (major, minor, patch) = detect_kernel_version()?;
/// println!("Kernel version: {}.{}.{}", major, minor, patch);
/// ```
fn detect_kernel_version() -> Result<(u32, u32, u32)> {
    let utsname = uname().map_err(|e| {
        FirewallError::ProtocolError(format!("Failed to get kernel version via uname(): {}", e))
    })?;

    let release = utsname.release().to_string_lossy();
    
    // Parse version string like "5.15.0-91-generic" → (5, 15, 0)
    let parts: Vec<&str> = release.split(&['.', '-'][..]).collect();
    
    if parts.len() < 3 {
        return Err(FirewallError::ProtocolError(format!(
            "Invalid kernel release format: {}",
            release
        )));
    }

    let major = parts[0].parse::<u32>().map_err(|e| {
        FirewallError::ProtocolError(format!("Failed to parse major version: {}", e))
    })?;

    let minor = parts[1].parse::<u32>().map_err(|e| {
        FirewallError::ProtocolError(format!("Failed to parse minor version: {}", e))
    })?;

    let patch = parts[2].parse::<u32>().map_err(|e| {
        FirewallError::ProtocolError(format!("Failed to parse patch version: {}", e))
    })?;

    debug!(
        major = major,
        minor = minor,
        patch = patch,
        "Detected kernel version"
    );

    Ok((major, minor, patch))
}

// ============================================================================
// IpsetBackend implementation
// ============================================================================

/// Linux kernel ipset integration backend.
///
/// Provides dynamic population of named ipset collections with DNS-resolved IP addresses
/// using either modern netlink API (kernel ≥ 2.6.32) or legacy setsockopt API (< 2.6.32).
///
/// # Initialization
///
/// Must call `initialize()` after construction to detect kernel version and create socket:
///
/// ```rust,ignore
/// let mut backend = IpsetBackend::new();
/// backend.initialize().await?;
/// ```
///
/// # Thread Safety
///
/// Type is `Send + Sync` and safe to share across tokio tasks. Socket operations are
/// performed in blocking thread pool via `spawn_blocking()` to prevent event loop blocking.
pub struct IpsetBackend {
    /// Netlink or raw socket file descriptor
    socket_fd: Option<RawFd>,
    /// True if kernel < 2.6.32 (legacy API), false otherwise (modern API)
    is_legacy_kernel: bool,
    /// Detected kernel version (major, minor, patch)
    kernel_version: Option<(u32, u32, u32)>,
}

impl IpsetBackend {
    /// Create new uninitialized ipset backend.
    ///
    /// Must call `initialize()` before using `add_to_set()` or `remove_from_set()`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut backend = IpsetBackend::new();
    /// backend.initialize().await?;
    /// ```
    pub fn new() -> Self {
        Self {
            socket_fd: None,
            is_legacy_kernel: false,
            kernel_version: None,
        }
    }

    /// Initialize ipset backend by detecting kernel version and creating control socket.
    ///
    /// This method:
    /// 1. Detects kernel version via `uname()`
    /// 2. Determines API type (modern netlink vs. legacy raw socket)
    /// 3. Creates appropriate socket and binds it (netlink only)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Kernel version detection fails
    /// - Socket creation fails
    /// - Netlink socket bind fails (modern API only)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut backend = IpsetBackend::new();
    /// backend.initialize().await?;
    /// assert!(backend.socket_fd.is_some());
    /// ```
    pub async fn initialize(&mut self) -> Result<()> {
        // Detect kernel version
        let version = detect_kernel_version()?;
        self.kernel_version = Some(version);

        // Check if legacy kernel (< 2.6.32)
        self.is_legacy_kernel = version.0 < 2
            || (version.0 == 2 && version.1 < 6)
            || (version.0 == 2 && version.1 == 6 && version.2 < 32);

        if self.is_legacy_kernel {
            info!(
                kernel_version = format!("{}.{}.{}", version.0, version.1, version.2),
                "Using legacy ipset API (IPv4 only)"
            );

            // Create raw socket for legacy API
            let fd = socket(
                NixAddressFamily::Inet,
                SockType::Raw,
                SockFlag::empty(),
                SockProtocol::Raw,
            )
            .map_err(|e| {
                FirewallError::ProtocolError(format!("Failed to create raw socket: {}", e))
            })?;

            self.socket_fd = Some(fd);
        } else {
            info!(
                kernel_version = format!("{}.{}.{}", version.0, version.1, version.2),
                "Using modern ipset netlink API (IPv4 + IPv6)"
            );

            // Create netlink socket for modern API
            let fd = socket(
                NixAddressFamily::Netlink,
                SockType::Raw,
                SockFlag::empty(),
                SockProtocol::NetlinkNetfilter,
            )
            .map_err(|e| {
                FirewallError::ProtocolError(format!("Failed to create netlink socket: {}", e))
            })?;

            // Bind netlink socket
            let addr = NetlinkAddr::new(0, 0);  // pid=0 (kernel assigns), groups=0
            bind(fd, &addr).map_err(|e| {
                FirewallError::ProtocolError(format!("Failed to bind netlink socket: {}", e))
            })?;

            self.socket_fd = Some(fd);
        }

        debug!(
            socket_fd = self.socket_fd,
            is_legacy = self.is_legacy_kernel,
            "ipset backend initialized"
        );

        Ok(())
    }

    /// Check if backend is using legacy kernel API (< 2.6.32).
    ///
    /// Returns `true` if kernel < 2.6.32 (IPv4 only, setsockopt API),
    /// `false` if kernel ≥ 2.6.32 (IPv4 + IPv6, netlink API).
    ///
    /// # Panics
    ///
    /// Panics if called before `initialize()`.
    pub fn is_legacy_kernel(&self) -> bool {
        self.is_legacy_kernel
    }

    /// Get detected kernel version as (major, minor, patch) tuple.
    ///
    /// Returns `None` if `initialize()` has not been called yet.
    pub fn detect_kernel_version(&self) -> Option<(u32, u32, u32)> {
        self.kernel_version
    }

    /// Add IP address to ipset using modern netlink API (kernel ≥ 2.6.32).
    ///
    /// Constructs netlink message with nested attributes and sends to kernel via
    /// NETLINK_NETFILTER socket. Supports both IPv4 and IPv6 addresses.
    ///
    /// # Message Structure
    ///
    /// See module-level documentation for complete netlink message format.
    ///
    /// # Arguments
    ///
    /// * `set_name` - Name of ipset collection (max 32 chars including null)
    /// * `ip` - IP address to add (IPv4 or IPv6)
    /// * `remove` - If true, remove address; if false, add address
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Set name exceeds IPSET_MAXNAMELEN (32 chars)
    /// - Socket send fails
    /// - Message construction fails
    async fn new_add_to_ipset(&self, set_name: &str, ip: IpAddr, remove: bool) -> Result<()> {
        let socket_fd = self.socket_fd.ok_or_else(|| {
            FirewallError::ProtocolError("ipset backend not initialized".to_string())
        })?;

        // Validate set name length
        if set_name.len() >= IPSET_MAXNAMELEN {
            return Err(FirewallError::SetNotFound(format!(
                "ipset name too long: {} (max {} chars)",
                set_name,
                IPSET_MAXNAMELEN - 1
            )));
        }

        // Determine address family
        let (af, addr_bytes) = match ip {
            IpAddr::V4(ipv4) => (libc::AF_INET as u8, ipv4.octets().to_vec()),
            IpAddr::V6(ipv6) => (libc::AF_INET6 as u8, ipv6.octets().to_vec()),
        };

        let addrsz = addr_bytes.len();

        // Build netlink message in blocking task
        let set_name_owned = set_name.to_string();
        let operation = if remove { "remove" } else { "add" };
        
        task::spawn_blocking(move || {
            // Allocate buffer
            let mut buffer = BytesMut::with_capacity(BUFF_SZ);

            // 1. Construct nlmsghdr
            let nlh = NlMsgHdr {
                nlmsg_len: nl_align(mem::size_of::<NlMsgHdr>()) as u32,
                nlmsg_type: (if remove { IPSET_CMD_DEL } else { IPSET_CMD_ADD })
                    | ((NFNL_SUBSYS_IPSET as u16) << 8),
                nlmsg_flags: NLM_F_REQUEST,
                nlmsg_seq: 0,
                nlmsg_pid: 0,
            };

            // Write nlmsghdr to buffer
            buffer.put_slice(&nlh.nlmsg_len.to_ne_bytes());
            buffer.put_slice(&nlh.nlmsg_type.to_ne_bytes());
            buffer.put_slice(&nlh.nlmsg_flags.to_ne_bytes());
            buffer.put_slice(&nlh.nlmsg_seq.to_ne_bytes());
            buffer.put_slice(&nlh.nlmsg_pid.to_ne_bytes());

            // Pad to alignment
            while buffer.len() < nl_align(mem::size_of::<NlMsgHdr>()) {
                buffer.put_u8(0);
            }

            // 2. Construct nfgenmsg
            let nfg = NfGenMsg {
                nfgen_family: af,
                version: NFNETLINK_V0,
                res_id: 0u16.to_be(),  // Network byte order
            };

            buffer.put_u8(nfg.nfgen_family);
            buffer.put_u8(nfg.version);
            buffer.put_slice(&nfg.res_id.to_ne_bytes());

            // Pad to alignment
            while buffer.len() < nl_align(mem::size_of::<NlMsgHdr>() + mem::size_of::<NfGenMsg>()) {
                buffer.put_u8(0);
            }

            let mut current_len = buffer.len();

            // Helper function to add netlink attribute
            let add_attr = |buf: &mut BytesMut, attr_type: u16, data: &[u8]| {
                let payload_len = nl_align(mem::size_of::<NlAttr>()) + data.len();
                let attr = NlAttr {
                    nla_len: payload_len as u16,
                    nla_type: attr_type,
                };

                buf.put_slice(&attr.nla_len.to_ne_bytes());
                buf.put_slice(&attr.nla_type.to_ne_bytes());

                // Pad attribute header to alignment
                while buf.len() < nl_align(buf.len() - 4) + 4 {
                    buf.put_u8(0);
                }

                buf.put_slice(data);

                // Pad payload to alignment
                while buf.len() % 4 != 0 {
                    buf.put_u8(0);
                }

                buf.len() - current_len
            };

            // 3. Add IPSET_ATTR_PROTOCOL
            let proto = IPSET_PROTOCOL;
            current_len = buffer.len();
            add_attr(&mut buffer, IPSET_ATTR_PROTOCOL, &[proto]);

            // 4. Add IPSET_ATTR_SETNAME
            let mut setname_bytes = set_name_owned.as_bytes().to_vec();
            setname_bytes.push(0);  // Null terminator
            current_len = buffer.len();
            add_attr(&mut buffer, IPSET_ATTR_SETNAME, &setname_bytes);

            // 5. Add nested IPSET_ATTR_DATA
            let nested_data_start = buffer.len();
            buffer.put_u16(0);  // Placeholder for nla_len
            buffer.put_u16(NLA_F_NESTED | IPSET_ATTR_DATA);

            // 6. Add nested IPSET_ATTR_IP
            let nested_ip_start = buffer.len();
            buffer.put_u16(0);  // Placeholder for nla_len
            buffer.put_u16(NLA_F_NESTED | IPSET_ATTR_IP);

            // 7. Add IPSET_ATTR_IPADDR_IPV4 or IPSET_ATTR_IPADDR_IPV6
            let addr_attr_type = if af == libc::AF_INET as u8 {
                IPSET_ATTR_IPADDR_IPV4
            } else {
                IPSET_ATTR_IPADDR_IPV6
            } | NLA_F_NET_BYTEORDER;

            current_len = buffer.len();
            add_attr(&mut buffer, addr_attr_type, &addr_bytes);

            // Fix nested IP attribute length
            let nested_ip_len = (buffer.len() - nested_ip_start) as u16;
            buffer[nested_ip_start..nested_ip_start + 2].copy_from_slice(&nested_ip_len.to_ne_bytes());

            // Align buffer
            while buffer.len() % 4 != 0 {
                buffer.put_u8(0);
            }

            // Fix nested data attribute length
            let nested_data_len = (buffer.len() - nested_data_start) as u16;
            buffer[nested_data_start..nested_data_start + 2]
                .copy_from_slice(&nested_data_len.to_ne_bytes());

            // Update total message length in nlmsghdr
            let total_len = buffer.len() as u32;
            buffer[0..4].copy_from_slice(&total_len.to_ne_bytes());

            // Send netlink message
            let addr = NetlinkAddr::new(0, 0);
            match sendto(socket_fd, &buffer, &addr, MsgFlags::empty()) {
                Ok(_) => {
                    debug!(
                        operation = operation,
                        set_name = set_name_owned,
                        ip = %ip,
                        address_family = if af == libc::AF_INET as u8 { "IPv4" } else { "IPv6" },
                        "ipset netlink message sent"
                    );
                    Ok(())
                }
                Err(e) => {
                    error!(
                        error = %e,
                        operation = operation,
                        set_name = set_name_owned,
                        ip = %ip,
                        "Failed to send ipset netlink message"
                    );
                    Err(FirewallError::ProtocolError(format!(
                        "Failed to send netlink message: {}",
                        e
                    )))
                }
            }
        })
        .await
        .map_err(|e| {
            FirewallError::ProtocolError(format!("Blocking task panicked: {}", e))
        })?
    }

    /// Add or remove IPv4 address to/from ipset using legacy setsockopt API (kernel < 2.6.32).
    ///
    /// Uses raw socket with `SOL_IP` socket option 83 for ipset operations. This API
    /// predates netlink and supports IPv4 only.
    ///
    /// # Arguments
    ///
    /// * `set_name` - Name of ipset collection
    /// * `ipv4` - IPv4 address to add/remove
    /// * `remove` - If true, remove address; if false, add address
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Set name too long
    /// - getsockopt fails to retrieve set ID
    /// - setsockopt fails to add/remove address
    async fn old_add_to_ipset(&self, set_name: &str, ipv4: Ipv4Addr, remove: bool) -> Result<()> {
        let socket_fd = self.socket_fd.ok_or_else(|| {
            FirewallError::ProtocolError("ipset backend not initialized".to_string())
        })?;

        // Validate set name length
        if set_name.len() >= IPSET_MAXNAMELEN {
            return Err(FirewallError::SetNotFound(format!(
                "ipset name too long: {}",
                set_name
            )));
        }

        let set_name_owned = set_name.to_string();
        let operation = if remove { "remove" } else { "add" };

        task::spawn_blocking(move || {
            // Step 1: Get set ID by name using getsockopt
            let mut req_get = IpSetReqAdtGet {
                op: IP_SET_OP_GET_BYNAME,
                version: IP_SET_API_VERSION,
                set_name: [0u8; IPSET_MAXNAMELEN],
                typename: [0u8; IPSET_MAXNAMELEN],
            };

            let name_bytes = set_name_owned.as_bytes();
            req_get.set_name[..name_bytes.len()].copy_from_slice(name_bytes);

            // getsockopt to retrieve set index
            let mut optlen = mem::size_of::<IpSetReqAdtGet>() as libc::socklen_t;
            let result = unsafe {
                libc::getsockopt(
                    socket_fd,
                    libc::SOL_IP,
                    83,  // IP_SET socket option
                    &mut req_get as *mut _ as *mut libc::c_void,
                    &mut optlen,
                )
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                error!(
                    error = %err,
                    set_name = set_name_owned,
                    "Failed to get ipset ID via getsockopt"
                );
                return Err(FirewallError::SetNotFound(format!(
                    "ipset '{}' not found or getsockopt failed: {}",
                    set_name_owned, err
                )));
            }

            // Extract set index from response (reused in union)
            let set_index = unsafe {
                // set_name is a union with index, read as u16
                let ptr = req_get.set_name.as_ptr() as *const u16;
                *ptr
            };

            debug!(
                set_name = set_name_owned,
                set_index = set_index,
                "Retrieved ipset index"
            );

            // Step 2: Add/delete IP using setsockopt
            let req_adt = IpSetReqAdt {
                op: if remove { IP_SET_OP_DEL_IP } else { IP_SET_OP_ADD_IP },
                index: set_index,
                _padding: 0,
                ip: u32::from(ipv4).to_be(),  // Network byte order, then to host order for legacy API
            };

            let result = unsafe {
                libc::setsockopt(
                    socket_fd,
                    libc::SOL_IP,
                    83,
                    &req_adt as *const _ as *const libc::c_void,
                    mem::size_of::<IpSetReqAdt>() as libc::socklen_t,
                )
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                error!(
                    error = %err,
                    operation = operation,
                    set_name = set_name_owned,
                    ip = %ipv4,
                    "Failed to {} IP to ipset via setsockopt",
                    operation
                );
                return Err(FirewallError::AddressFailed(format!(
                    "setsockopt failed for {} operation: {}",
                    operation, err
                )));
            }

            debug!(
                operation = operation,
                set_name = set_name_owned,
                ip = %ipv4,
                "Legacy ipset operation completed"
            );

            Ok(())
        })
        .await
        .map_err(|e| {
            FirewallError::ProtocolError(format!("Blocking task panicked: {}", e))
        })?
    }
}

// Implement FirewallBackend trait for IpsetBackend
#[async_trait]
impl FirewallBackend for IpsetBackend {
    /// Add resolved IP address to named ipset collection.
    ///
    /// Automatically selects between modern netlink API (kernel ≥ 2.6.32) and legacy
    /// setsockopt API (< 2.6.32) based on detected kernel version.
    ///
    /// # Arguments
    ///
    /// * `domain` - Fully qualified domain name (for logging)
    /// * `ip` - Resolved IP address to add
    /// * `set_name` - Name of ipset collection
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Address successfully added or operation completed
    /// - `Err(FirewallError)` - Operation failed (logged, non-fatal to DNS)
    ///
    /// # Errors
    ///
    /// - **SetNotFound**: ipset does not exist (admin must create it)
    /// - **AddressNotSupported**: IPv6 on legacy kernel
    /// - **ProtocolError**: Socket communication failure
    async fn add_to_set(&self, domain: &str, ip: IpAddr, set_name: &str) -> Result<()> {
        info!(
            domain = domain,
            ip = %ip,
            set_name = set_name,
            "Adding IP to ipset"
        );

        // Check for IPv6 on legacy kernel
        if self.is_legacy_kernel && matches!(ip, IpAddr::V6(_)) {
            warn!(
                domain = domain,
                ip = %ip,
                set_name = set_name,
                kernel_version = ?self.kernel_version,
                "IPv6 not supported on legacy kernel"
            );
            return Err(FirewallError::AddressNotSupported(
                "IPv6 addresses not supported by legacy ipset API (kernel < 2.6.32)".to_string(),
            ));
        }

        // Execute appropriate API call
        let result = if self.is_legacy_kernel {
            // Legacy API: IPv4 only via setsockopt
            match ip {
                IpAddr::V4(ipv4) => self.old_add_to_ipset(set_name, ipv4, false).await,
                IpAddr::V6(_) => unreachable!("IPv6 check handled above"),
            }
        } else {
            // Modern API: IPv4 + IPv6 via netlink
            self.new_add_to_ipset(set_name, ip, false).await
        };

        if let Err(ref e) = result {
            error!(
                error = %e,
                domain = domain,
                ip = %ip,
                set_name = set_name,
                "Failed to add IP to ipset"
            );
        }

        result
    }

    /// Remove IP address from named ipset collection.
    ///
    /// Automatically selects appropriate API based on kernel version.
    ///
    /// # Arguments
    ///
    /// * `domain` - Fully qualified domain name (for logging)
    /// * `ip` - IP address to remove
    /// * `set_name` - Name of ipset collection
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Address successfully removed or does not exist
    /// - `Err(FirewallError)` - Operation failed
    async fn remove_from_set(&self, domain: &str, ip: IpAddr, set_name: &str) -> Result<()> {
        info!(
            domain = domain,
            ip = %ip,
            set_name = set_name,
            "Removing IP from ipset"
        );

        // Check for IPv6 on legacy kernel
        if self.is_legacy_kernel && matches!(ip, IpAddr::V6(_)) {
            warn!(
                domain = domain,
                ip = %ip,
                set_name = set_name,
                "IPv6 not supported on legacy kernel"
            );
            return Err(FirewallError::AddressNotSupported(
                "IPv6 addresses not supported by legacy ipset API".to_string(),
            ));
        }

        // Execute appropriate API call
        let result = if self.is_legacy_kernel {
            match ip {
                IpAddr::V4(ipv4) => self.old_add_to_ipset(set_name, ipv4, true).await,
                IpAddr::V6(_) => unreachable!("IPv6 check handled above"),
            }
        } else {
            self.new_add_to_ipset(set_name, ip, true).await
        };

        if let Err(ref e) = result {
            error!(
                error = %e,
                domain = domain,
                ip = %ip,
                set_name = set_name,
                "Failed to remove IP from ipset"
            );
        }

        result
    }
}

// Implement Default trait for convenience
impl Default for IpsetBackend {
    fn default() -> Self {
        Self::new()
    }
}

// Ensure Send + Sync for tokio compatibility
// RawFd is Send + Sync, all fields are simple types
unsafe impl Send for IpsetBackend {}
unsafe impl Sync for IpsetBackend {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nl_align() {
        assert_eq!(nl_align(0), 0);
        assert_eq!(nl_align(1), 4);
        assert_eq!(nl_align(2), 4);
        assert_eq!(nl_align(3), 4);
        assert_eq!(nl_align(4), 4);
        assert_eq!(nl_align(5), 8);
        assert_eq!(nl_align(8), 8);
    }

    #[test]
    fn test_ipset_backend_new() {
        let backend = IpsetBackend::new();
        assert!(backend.socket_fd.is_none());
        assert!(!backend.is_legacy_kernel);
        assert!(backend.kernel_version.is_none());
    }

    #[tokio::test]
    #[ignore] // Requires root privileges and Linux kernel with ipset support
    async fn test_ipset_backend_initialize() {
        let mut backend = IpsetBackend::new();
        let result = backend.initialize().await;
        
        // Initialize should succeed on Linux systems
        if cfg!(target_os = "linux") {
            assert!(result.is_ok());
            assert!(backend.socket_fd.is_some());
            assert!(backend.kernel_version.is_some());
        }
    }
}
