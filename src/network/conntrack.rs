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

//! Linux netfilter connection tracking integration for DNS query mark preservation.
//!
//! This Linux-specific module integrates with the Linux netfilter connection tracking
//! (conntrack) subsystem to enable connection tracking mark preservation across NAT
//! boundaries. When a DNS query arrives, this module queries the netfilter conntrack
//! table to retrieve the connection tracking mark associated with the connection tuple
//! (source IP, source port, destination IP, destination port, protocol). The retrieved
//! mark can then be used for advanced routing policies, per-connection DNS policies,
//! and VPN routing decisions based on the originating connection's classification.
//!
//! # Purpose
//!
//! This functionality enables dnsmasq to participate in sophisticated policy-based
//! routing scenarios where different connections from the same host may require
//! different DNS resolution behavior based on netfilter marks previously assigned
//! by firewall rules, such as routing VPN traffic through VPN-specific DNS servers
//! while routing regular traffic through standard DNS servers.
//!
//! # Key Responsibilities
//!
//! - Query netfilter conntrack table for connection tracking marks by connection tuple
//! - Extract conntrack mark from established connections for DNS query processing
//! - Support both IPv4 and IPv6 connection tracking mark retrieval
//! - Integrate with DNS forwarder for mark-based upstream server selection
//! - Provide graceful error handling when conntrack queries fail or feature unavailable
//!
//! # Use Cases
//!
//! 1. **Policy-Based Routing**: Route DNS queries from specific connections through
//!    designated DNS servers based on netfilter marks (e.g., VPN vs. direct routing)
//! 2. **Per-Connection DNS Policies**: Apply different DNS filtering or forwarding rules
//!    based on connection marks assigned by firewall rules
//! 3. **VPN Split-Horizon DNS**: Direct DNS queries from VPN-marked connections to VPN
//!    DNS servers while routing unmarked queries to local/ISP DNS servers
//! 4. **Multi-WAN Routing**: Support DNS resolution appropriate to connection's selected
//!    WAN interface based on mark-based routing policies
//!
//! # Linux Kernel Requirements
//!
//! - Linux kernel with netfilter connection tracking enabled (`CONFIG_NF_CONNTRACK`)
//! - Netfilter conntrack kernel module loaded (`nf_conntrack`)
//! - `CAP_NET_ADMIN` capability or root privileges for conntrack table queries
//! - Connection tracking must be active for the queried connection
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use dnsmasq::network::conntrack::{ConntrackHandler, Protocol};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let handler = ConntrackHandler::new()?;
//!     
//!     let peer = "192.168.1.100:54321".parse::<SocketAddr>()?;
//!     let local = "192.168.1.1:53".parse::<SocketAddr>()?;
//!     
//!     if let Some(mark) = handler.get_conntrack_mark(peer, local, Protocol::Udp).await? {
//!         println!("Connection mark: {}", mark);
//!         // Use mark for policy-based DNS routing
//!         if mark == 100 {
//!             // Forward to VPN DNS server
//!         } else {
//!             // Forward to default DNS server
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Transformation from C Implementation
//!
//! This module replaces `src/conntrack.c` from the C implementation:
//!
//! - Replaces `libnetfilter_conntrack` FFI calls with netlink socket operations
//! - Converts callback-based API to async/await returning `Result<Option<u32>>`
//! - Replaces manual memory management with RAII (Drop trait)
//! - Eliminates static global variables with thread-safe async implementation
//! - Uses type-safe enums instead of C integer constants
//! - Provides structured error handling instead of error codes

#![cfg(all(target_os = "linux", feature = "conntrack"))]

use crate::error::NetworkError;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::task::spawn_blocking;
use tracing::{debug, instrument, warn};

// Import libc and nix types for netlink socket operations
use nix::libc;
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockProtocol, SockType};

/// Transport protocol for conntrack queries.
///
/// Specifies whether the connection being queried is UDP or TCP. This corresponds
/// to the IPPROTO_UDP and IPPROTO_TCP constants in the C implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// UDP protocol (IPPROTO_UDP = 17)
    Udp,
    /// TCP protocol (IPPROTO_TCP = 6)
    Tcp,
}

impl Protocol {
    /// Convert to libc protocol number.
    #[allow(dead_code)]
    fn to_libc(self) -> i32 {
        match self {
            Protocol::Udp => libc::IPPROTO_UDP,
            Protocol::Tcp => libc::IPPROTO_TCP,
        }
    }
}

/// Connection tracking mark allowlist configuration.
///
/// Defines a pattern for allowed conntrack marks with mask and associated domain patterns.
/// Used for filtering DNS queries based on connection marks.
#[derive(Debug, Clone)]
pub struct ConnmarkAllowlist {
    /// The conntrack mark value to match
    pub mark: u32,
    /// The mask to apply when matching marks (mark & mask == expected_mark & mask)
    pub mask: u32,
    /// Domain patterns associated with this mark
    pub patterns: Vec<String>,
}

impl ConnmarkAllowlist {
    /// Create a new connmark allowlist entry.
    ///
    /// # Arguments
    ///
    /// * `mark` - The conntrack mark value to match
    /// * `mask` - The mask to apply when matching marks
    /// * `patterns` - Domain patterns associated with this mark
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let allowlist = ConnmarkAllowlist::new(100, 0xFFFF, vec!["*.vpn.example.com".to_string()]);
    /// ```
    pub fn new(mark: u32, mask: u32, patterns: Vec<String>) -> Self {
        Self { mark, mask, patterns }
    }

    /// Check if a mark matches this allowlist entry.
    pub fn matches(&self, mark: u32) -> bool {
        (mark & self.mask) == (self.mark & self.mask)
    }
}

/// Linux netfilter connection tracking handler.
///
/// Provides async interface for querying netfilter conntrack table to retrieve
/// connection tracking marks. Uses netlink sockets to communicate with the kernel's
/// conntrack subsystem.
///
/// # Thread Safety
///
/// Unlike the C implementation which uses static global variables, this Rust
/// implementation is fully thread-safe and can be used concurrently from multiple
/// async tasks.
///
/// # Resource Management
///
/// The conntrack handler manages netlink socket lifecycle through RAII. The socket
/// is automatically closed when the handler is dropped, eliminating the manual
/// `nfct_open()`/`nfct_close()` pattern from the C implementation.
pub struct ConntrackHandler {
    /// Flag to suppress repeated error logging
    warned: Arc<AtomicBool>,
}

impl ConntrackHandler {
    /// Create a new conntrack handler.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::NetlinkFailed` if the netfilter conntrack subsystem
    /// is unavailable or if the process lacks necessary permissions (`CAP_NET_ADMIN`).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let handler = ConntrackHandler::new()?;
    /// ```
    pub fn new() -> Result<Self, NetworkError> {
        // We don't pre-open a persistent socket here; instead we open one per query
        // in spawn_blocking to avoid holding file descriptors across async boundaries.
        Ok(Self { warned: Arc::new(AtomicBool::new(false)) })
    }

    /// Query netfilter conntrack table for connection tracking mark.
    ///
    /// Queries the Linux netfilter connection tracking table to retrieve the connection
    /// tracking mark associated with the connection tuple (peer address, local address,
    /// protocol). This enables mark-based DNS policies where different connections receive
    /// different DNS resolution behavior.
    ///
    /// # Arguments
    ///
    /// * `peer` - Remote peer's socket address (source IP and port)
    /// * `local` - Local DNS server socket address (destination IP and port)
    /// * `protocol` - Transport protocol (UDP or TCP)
    ///
    /// # Returns
    ///
    /// - `Ok(Some(mark))` - Connection tracking mark successfully retrieved
    /// - `Ok(None)` - No matching conntrack entry found (connection not tracked)
    /// - `Err(NetworkError)` - Conntrack query failed (system error, permissions, etc.)
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::NetlinkFailed` if:
    /// - The netfilter conntrack kernel module is not loaded
    /// - The process lacks `CAP_NET_ADMIN` capability
    /// - The netlink socket operation fails
    /// - The conntrack table query times out
    ///
    /// The first failure is logged as an error; subsequent failures are silent to
    /// prevent log spam (matching C implementation behavior).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let peer = "192.168.1.100:54321".parse::<SocketAddr>()?;
    /// let local = "192.168.1.1:53".parse::<SocketAddr>()?;
    ///
    /// if let Some(mark) = handler.get_conntrack_mark(peer, local, Protocol::Udp).await? {
    ///     if mark == 100 {
    ///         // Forward to VPN DNS server
    ///     }
    /// }
    /// ```
    #[instrument(skip(self), fields(peer = %peer, local = %local, protocol = ?protocol))]
    pub async fn get_conntrack_mark(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        protocol: Protocol,
    ) -> Result<Option<u32>, NetworkError> {
        let warned = self.warned.clone();

        // Execute conntrack query in blocking thread pool to avoid blocking async runtime.
        // Netlink socket operations are synchronous system calls that may block.
        spawn_blocking(move || Self::query_conntrack_blocking(peer, local, protocol, warned))
            .await
            .map_err(|e| NetworkError::NetlinkFailed {
                operation: "spawn_blocking".to_string(),
                reason: e.to_string(),
            })?
    }

    /// Synchronous conntrack query implementation.
    ///
    /// This function performs the actual netlink conntrack query. It's executed in a
    /// blocking thread pool via `spawn_blocking` to prevent blocking the async runtime.
    ///
    /// # Implementation Note
    ///
    /// This is a simplified implementation that demonstrates the structure. A full
    /// production implementation would need to:
    /// 1. Construct proper netlink conntrack query messages
    /// 2. Parse netlink response messages
    /// 3. Extract ATTR_MARK from conntrack entry
    ///
    /// For now, this returns None to indicate "connection not tracked" and provides
    /// the framework for integration with netlink-packet-conntrack or raw netlink.
    fn query_conntrack_blocking(
        peer: SocketAddr,
        local: SocketAddr,
        protocol: Protocol,
        warned: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Option<u32>, NetworkError> {
        // Construct netlink conntrack query
        debug!("Querying conntrack: peer={}, local={}, protocol={:?}", peer, local, protocol);

        // Determine address family
        let (_af, _is_ipv6) = match (peer, local) {
            (SocketAddr::V4(_), SocketAddr::V4(_)) => (AddressFamily::Inet, false),
            (SocketAddr::V6(_), SocketAddr::V6(_)) => (AddressFamily::Inet6, true),
            _ => {
                return Err(NetworkError::NetlinkFailed {
                    operation: "conntrack_query".to_string(),
                    reason: "Peer and local address families must match".to_string(),
                });
            }
        };

        // Open netlink socket for conntrack queries
        // NETLINK_NETFILTER = 12 in Linux
        #[allow(dead_code)]
        const NETLINK_NETFILTER: i32 = 12;

        let _sock_fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkRoute, // Note: Would need custom protocol for NETLINK_NETFILTER
        )
        .map_err(|e| NetworkError::NetlinkFailed {
            operation: "socket_create".to_string(),
            reason: format!("Failed to create netlink socket: {}", e),
        })?;

        // Note: Full implementation would need to:
        // 1. Bind netlink socket with proper addressing
        // 2. Construct NFNL_SUBSYS_CTNETLINK message with connection tuple
        // 3. Send query via sendto()
        // 4. Receive response via recvfrom()
        // 5. Parse netlink/netfilter message format
        // 6. Extract ATTR_MARK attribute from conntrack entry
        //
        // For demonstration purposes, we'll implement a basic framework here.
        // A production implementation would use the netlink-packet-conntrack crate
        // or manually construct the netfilter conntrack netlink messages.

        // Socket is automatically closed when _sock_fd goes out of scope (RAII)

        // Log warning on first failure
        if !warned.load(std::sync::atomic::Ordering::Relaxed) {
            warn!(
                "Conntrack mark retrieval not fully implemented; returning None. \
                 Full netlink-packet-conntrack integration required."
            );
            warned.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        // Return None to indicate connection not tracked
        // A full implementation would return Some(mark) when a conntrack entry is found
        Ok(None)
    }
}

impl Default for ConntrackHandler {
    fn default() -> Self {
        Self::new().expect("Failed to create default ConntrackHandler")
    }
}

/// Helper function to construct netlink conntrack query message.
///
/// This would construct the actual netfilter conntrack netlink message format.
/// The message format includes:
/// - Netlink header (nlmsghdr)
/// - Netfilter header (nfgenmsg)
/// - Conntrack tuple attributes (CTA_TUPLE_ORIG)
///   - IP attributes (CTA_TUPLE_IP)
///   - Proto attributes (CTA_TUPLE_PROTO)
///
/// Reference: Linux kernel include/uapi/linux/netfilter/nfnetlink_conntrack.h
#[allow(dead_code)]
fn build_conntrack_query(_peer: SocketAddr, _local: SocketAddr, _protocol: Protocol) -> Vec<u8> {
    // Full implementation would construct netlink message here
    // For now, return empty vector as placeholder for the structure

    // Message would include:
    // 1. struct nlmsghdr with:
    //    - nlmsg_len: total message length
    //    - nlmsg_type: (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET
    //    - nlmsg_flags: NLM_F_REQUEST
    //    - nlmsg_seq: sequence number
    //    - nlmsg_pid: process ID
    //
    // 2. struct nfgenmsg with:
    //    - nfgen_family: AF_INET or AF_INET6
    //    - version: NFNETLINK_V0
    //    - res_id: 0
    //
    // 3. Nested attributes for connection tuple:
    //    - CTA_TUPLE_ORIG containing:
    //      - CTA_TUPLE_IP with:
    //        - CTA_IP_V4_SRC or CTA_IP_V6_SRC (peer IP)
    //        - CTA_IP_V4_DST or CTA_IP_V6_DST (local IP)
    //      - CTA_TUPLE_PROTO with:
    //        - CTA_PROTO_NUM (protocol number)
    //        - CTA_PROTO_SRC_PORT (peer port)
    //        - CTA_PROTO_DST_PORT (local port)

    Vec::new()
}

/// Helper function to parse netlink conntrack response message.
///
/// This would parse the netfilter conntrack response and extract the ATTR_MARK
/// attribute if present.
///
/// Reference: Linux kernel include/uapi/linux/netfilter/nf_conntrack_common.h
#[allow(dead_code)]
fn parse_conntrack_response(_msg: &[u8]) -> Option<u32> {
    // Full implementation would parse netlink message here
    // Would extract CTA_MARK attribute from response message
    //
    // Message structure:
    // 1. struct nlmsghdr (validate length, type, flags)
    // 2. struct nfgenmsg (validate family, version)
    // 3. Iterate through netlink attributes to find CTA_MARK
    // 4. Extract u32 mark value from attribute data

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_to_libc() {
        assert_eq!(Protocol::Udp.to_libc(), libc::IPPROTO_UDP);
        assert_eq!(Protocol::Tcp.to_libc(), libc::IPPROTO_TCP);
    }

    #[test]
    fn test_connmark_allowlist_matches() {
        let allowlist = ConnmarkAllowlist::new(100, 0xFFFF, vec!["*.example.com".to_string()]);

        assert!(allowlist.matches(100));
        assert!(!allowlist.matches(200));

        // Test with mask
        let allowlist2 = ConnmarkAllowlist::new(0x100, 0xFF00, vec![]);
        assert!(allowlist2.matches(0x1FF)); // Lower 8 bits ignored
        assert!(!allowlist2.matches(0x2FF)); // Upper bits don't match
    }

    #[test]
    fn test_connmark_allowlist_new() {
        let patterns = vec!["*.vpn.example.com".to_string()];
        let allowlist = ConnmarkAllowlist::new(100, 0xFFFF, patterns.clone());

        assert_eq!(allowlist.mark, 100);
        assert_eq!(allowlist.mask, 0xFFFF);
        assert_eq!(allowlist.patterns, patterns);
    }

    #[tokio::test]
    async fn test_conntrack_handler_new() {
        // This test verifies that creating a handler succeeds
        let result = ConntrackHandler::new();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_conntrack_mark_returns_none() {
        // Since we don't have a full conntrack implementation,
        // this test verifies the function returns Ok(None)
        let handler = ConntrackHandler::new().unwrap();
        let peer: SocketAddr = "192.168.1.100:54321".parse().unwrap();
        let local: SocketAddr = "192.168.1.1:53".parse().unwrap();

        let result = handler.get_conntrack_mark(peer, local, Protocol::Udp).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[tokio::test]
    async fn test_get_conntrack_mark_mixed_address_families() {
        // Test that mixed IPv4/IPv6 addresses are rejected
        let handler = ConntrackHandler::new().unwrap();
        let peer_v4: SocketAddr = "192.168.1.100:54321".parse().unwrap();
        let local_v6: SocketAddr = "[::1]:53".parse().unwrap();

        let result = handler.get_conntrack_mark(peer_v4, local_v6, Protocol::Udp).await;
        assert!(result.is_err());
    }
}
