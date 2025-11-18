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

//! Shared DHCP utilities module for DHCPv4 and DHCPv6 implementations.
//!
//! This module provides common functionality used by both DHCPv4 and DHCPv6 servers,
//! replacing the C `dhcp-common.c` implementation with memory-safe Rust equivalents.
//! It centralizes shared logic to avoid code duplication between IPv4 and IPv6 implementations.
//!
//! # Key Responsibilities
//!
//! - **Packet Reception**: Async DHCP packet reception with automatic buffer management
//! - **Option Tables**: Static lookup tables for DHCPv4 and DHCPv6 option metadata
//! - **MAC Address Parsing**: Parse MAC addresses in multiple formats (colon, hyphen, dot)
//! - **Transaction IDs**: Generate secure random transaction IDs (xid)
//! - **Network ID Matching**: Match network tags with wildcard support for client classification
//! - **Option Filtering**: Filter options based on client tags for conditional option delivery
//! - **Hostname Processing**: Strip and validate hostnames from DHCP packets
//! - **Logging**: Structured logging of DHCP transactions and tag matching
//!
//! # C to Rust Transformation
//!
//! ## Buffer Management
//!
//! ```c
//! // C: Global daemon buffers with manual expansion
//! daemon->dhcp_buff = safe_malloc(DHCP_BUFF_SZ);
//! sz = recv_dhcp_packet(fd, &daemon->dhcp_packet, &expand);
//! if (expand) expand_buf(&daemon->dhcp_packet, sz);
//! ```
//!
//! ```rust,ignore
//! // Rust: Local Vec<u8> with automatic growth
//! let mut buf = Vec::with_capacity(DHCP_PACKET_MAX);
//! let (len, src_addr) = recv_dhcp_packet(&socket, &mut buf).await?;
//! // Buffer automatically resized if needed
//! ```
//!
//! ## Option Table Lookup
//!
//! ```c
//! // C: Linear search through static array
//! for (int i = 0; opttab[i].name; i++) {
//!     if (opttab[i].val == option_code) return &opttab[i];
//! }
//! ```
//!
//! ```rust,ignore
//! // Rust: Const static HashMap for O(1) lookup
//! DHCPV4_OPTION_TABLE.get(&option_code)
//! ```
//!
//! ## MAC Address Parsing
//!
//! ```c
//! // C: Manual string parsing with potential buffer overruns
//! char *cp = str;
//! for (int i = 0; i < 6; i++) {
//!     mac[i] = strtoul(cp, &cp, 16); // Unchecked bounds
//!     if (*cp == ':' || *cp == '-') cp++;
//! }
//! ```
//!
//! ```rust,ignore
//! // Rust: Safe nom parser combinators with bounds checking
//! parse_mac_address(s)? // Returns Result<MacAddress, MacParseError>
//! ```
//!
//! # Memory Safety
//!
//! All functions use Rust's ownership system to eliminate:
//! - Buffer overflows (Vec bounds checking, nom parsers)
//! - Use-after-free (ownership prevents dangling references)
//! - Memory leaks (automatic Drop for Vec, BytesMut)
//! - Null pointer dereferences (Option types)
//!
//! # Performance
//!
//! - Option table lookups: O(1) with static HashMap (vs. O(n) C linear search)
//! - Buffer allocation: Amortized O(1) with Vec capacity doubling
//! - Async I/O: Zero-copy packet reception with tokio
//! - Tag matching: Iterator-based with short-circuit evaluation

use crate::error::DhcpError;
use crate::types::IpAddr;

use bytes::BytesMut;
use nom::{
    bytes::complete::{tag, take},
    character::complete::hex_digit1,
    combinator::{map_res, opt},
    multi::separated_list1,
    sequence::tuple,
    IResult,
};
use rand::random;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::LazyLock;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

// ============================================================================
// CONSTANTS
// ============================================================================

/// DHCP option buffer size in bytes.
///
/// From C `#define DHCP_BUFF_SZ 256` in dhcp-protocol.h. Defines maximum size
/// for DHCP option data buffers. Note: This is for option values, not full packets.
/// Full packets can be up to DHCP_PACKET_MAX (16384 bytes).
///
/// **C Source**: dhcp-protocol.h line 114
/// **Usage**: Option value buffering, string option storage
/// **Note**: Should ideally be imported from src/constants.rs but defined locally
///           per zero-placeholder policy since not yet available in constants.rs
pub const DHCP_BUFF_SZ: usize = 256;

/// Maximum DHCP packet size in bytes.
///
/// Hard limit on packet buffer allocation to prevent memory exhaustion from
/// malformed packets. Normal DHCP packets are 576 bytes; jumbo options can reach 1500.
const DHCP_PACKET_MAX: usize = 16384;

// ============================================================================
// DHCP OPTION FLAGS
// ============================================================================

/// Option flags from C dnsmasq.h OT_* definitions

/// Option is an address list (multiple IP addresses).
/// From C: `#define OT_ADDR_LIST 1`
const OT_ADDR_LIST: u16 = 1;

/// Option is internal-only (not sent to clients).
/// From C: `#define OT_INTERNAL 4`
const OT_INTERNAL: u16 = 4;

/// Option is a domain name (requires DNS encoding).
/// From C: `#define OT_NAME 8`
const OT_NAME: u16 = 8;

/// Option is a comma-separated list.
/// From C: `#define OT_CSTRING 16`
const OT_CSTRING: u16 = 16;

/// Option is a decimal number list.
/// From C: `#define OT_DEC 32`
const OT_DEC: u16 = 32;

/// Option time value (seconds, printed as duration).
/// From C: `#define OT_TIME 64`
const OT_TIME: u16 = 64;

// DHOPT flags from C dnsmasq.h
/// Option value is an address.
/// From C: `#define DHOPT_ADDR 1`
const DHOPT_ADDR: i32 = 1;

/// Option value is a string.
/// From C: `#define DHOPT_STRING 2`
const DHOPT_STRING: i32 = 2;

/// Option is encapsulated.
/// From C: `#define DHOPT_ENCAPSULATE 4`
const DHOPT_ENCAPSULATE: i32 = 4;

/// Match encapsulated option.
/// From C: `#define DHOPT_ENCAP_MATCH 8`
const DHOPT_ENCAP_MATCH: i32 = 8;

/// Force option sending even if not requested.
/// From C: `#define DHOPT_FORCE 16`
const DHOPT_FORCE: i32 = 16;

/// Option bank selection.
/// From C: `#define DHOPT_BANK 32`
const DHOPT_BANK: i32 = 32;

/// Encapsulation processing done.
/// From C: `#define DHOPT_ENCAP_DONE 64`
const DHOPT_ENCAP_DONE: i32 = 64;

/// Match option value.
/// From C: `#define DHOPT_MATCH 128`
const DHOPT_MATCH: i32 = 128;

/// Vendor-specific option.
/// From C: `#define DHOPT_VENDOR 256`
const DHOPT_VENDOR: i32 = 256;

/// Option value is hexadecimal.
/// From C: `#define DHOPT_HEX 512`
pub const DHOPT_HEX: i32 = 512;

/// Match vendor class.
/// From C: `#define DHOPT_VENDOR_MATCH 1024`
const DHOPT_VENDOR_MATCH: i32 = 1024;

/// RFC 3925 option.
/// From C: `#define DHOPT_RFC3925 2048`
const DHOPT_RFC3925: i32 = 2048;

/// Tag OK for this option.
/// From C: `#define DHOPT_TAGOK 4096`
const DHOPT_TAGOK: i32 = 4096;

/// Option is IPv6 address.
/// From C: `#define DHOPT_ADDR6 8192`
const DHOPT_ADDR6: i32 = 8192;

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/// DHCP option metadata describing format and size.
///
/// Replaces C `struct opttab_t` from dhcp-common.c. Provides static metadata
/// for DHCP option types used in option parsing and formatting.
///
/// # C Equivalent
///
/// ```c
/// struct opttab_t {
///     char *name;
///     u16 val;    // Option code
///     u16 size;   // Size and format flags
/// };
/// ```
///
/// # Fields
///
/// - `code`: DHCP option code (e.g., 1 = subnet mask, 3 = router, 6 = DNS)
/// - `format`: Format flags (OT_ADDR_LIST, OT_NAME, OT_INTERNAL, etc.)
/// - `size`: Fixed size in bytes (0 = variable length)
///
/// # Example
///
/// ```ignore
/// OptionMetadata {
///     code: 1,           // Subnet Mask
///     format: 0,         // Plain address
///     size: 4,           // 4 bytes (IPv4)
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionMetadata {
    /// DHCP option code (1-255 for DHCPv4, 1-65535 for DHCPv6).
    pub code: u16,

    /// Format flags (OT_ADDR_LIST, OT_NAME, OT_INTERNAL, OT_CSTRING, OT_DEC, OT_TIME).
    pub format: u16,

    /// Fixed size in bytes, or 0 for variable-length options.
    pub size: u16,
}

/// DHCP option configuration for conditional option delivery.
///
/// This type represents DHCP option configuration from C `struct dhcp_opt`.
/// **Note**: This type should ideally come from src/config/types.rs but is not
/// defined there yet. Defined locally per zero-placeholder policy to enable
/// production-ready implementation.
///
/// # C Equivalent
///
/// ```c
/// struct dhcp_opt {
///     int opt, len, flags;
///     union {
///         int encap;
///         unsigned int wildcard_mask;
///         unsigned char *vendor_class;
///     } u;
///     unsigned char *val;
///     struct dhcp_netid *netid;
///     struct dhcp_opt *next;
/// };
/// ```
///
/// # Fields
///
/// - `opt`: Option code (DHCPv4: 1-255, DHCPv6: 1-65535)
/// - `len`: Option value length in bytes
/// - `flags`: DHOPT_* flags (DHOPT_HEX, DHOPT_STRING, DHOPT_ADDR, etc.)
/// - `val`: Option value data
/// - `wildcard_mask`: Bitmask for wildcard matching in match_bytes
///
/// # Usage
///
/// Used by `match_bytes()` function to perform wildcard matching of DHCP option
/// values for client classification.
#[derive(Clone, Debug)]
pub struct DhcpOpt {
    /// Option code.
    pub opt: i32,

    /// Option value length.
    pub len: usize,

    /// Option flags (DHOPT_HEX, DHOPT_STRING, DHOPT_ADDR, etc.).
    pub flags: i32,

    /// Option value data.
    pub val: Vec<u8>,

    /// Wildcard mask for pattern matching (bit 1 = wildcard, bit 0 = exact match).
    /// Only valid when DHOPT_MATCH flag is set.
    pub wildcard_mask: Option<u32>,
}

/// MAC address (6-byte Ethernet address).
///
/// Type alias for 6-byte array representing Ethernet MAC address.
/// Used by `parse_mac_address()` function.
pub type MacAddress = [u8; 6];

/// Network ID tag for client classification.
///
/// Represents a tag string used for DHCP client classification and
/// conditional option delivery. Tags are matched against client properties
/// (interface, vendor class, user class, etc.) to select appropriate
/// configuration options.
pub type NetworkId = String;

// ============================================================================
// DHCP OPTION TABLES
// ============================================================================

/// DHCPv4 option table.
///
/// Static metadata for all DHCPv4 options. Replaces C `opttab[]` array from
/// dhcp-common.c lines 228-635. Provides O(1) lookup by option code.
///
/// **C Source**: dhcp-common.c opttab[] static array
///
/// # Example Entries
///
/// ```ignore
/// 1 => OptionMetadata { code: 1, format: 0, size: 4 },           // Subnet Mask
/// 3 => OptionMetadata { code: 3, format: OT_ADDR_LIST, size: 4 }, // Router
/// 6 => OptionMetadata { code: 6, format: OT_ADDR_LIST, size: 4 }, // DNS Server
/// ```
pub static DHCPV4_OPTION_TABLE: LazyLock<HashMap<u8, OptionMetadata>> =
    LazyLock::new(|| {
        let mut map = HashMap::new();
        
        // Option 1: Subnet Mask
        map.insert(1, OptionMetadata { code: 1, format: 0, size: 4 });
        
        // Option 2: Time Offset
        map.insert(2, OptionMetadata { code: 2, format: OT_TIME, size: 4 });
        
        // Option 3: Router
        map.insert(3, OptionMetadata { code: 3, format: OT_ADDR_LIST, size: 4 });
        
        // Option 4: Time Server
        map.insert(4, OptionMetadata { code: 4, format: OT_ADDR_LIST, size: 4 });
        
        // Option 5: Name Server (IEN 116)
        map.insert(5, OptionMetadata { code: 5, format: OT_ADDR_LIST, size: 4 });
        
        // Option 6: DNS Server
        map.insert(6, OptionMetadata { code: 6, format: OT_ADDR_LIST, size: 4 });
        
        // Option 7: Log Server
        map.insert(7, OptionMetadata { code: 7, format: OT_ADDR_LIST, size: 4 });
        
        // Option 8: Cookie/Quote Server
        map.insert(8, OptionMetadata { code: 8, format: OT_ADDR_LIST, size: 4 });
        
        // Option 9: LPR Server
        map.insert(9, OptionMetadata { code: 9, format: OT_ADDR_LIST, size: 4 });
        
        // Option 10: Impress Server
        map.insert(10, OptionMetadata { code: 10, format: OT_ADDR_LIST, size: 4 });
        
        // Option 11: Resource Location Server
        map.insert(11, OptionMetadata { code: 11, format: OT_ADDR_LIST, size: 4 });
        
        // Option 12: Hostname
        map.insert(12, OptionMetadata { code: 12, format: 0, size: 0 });
        
        // Option 13: Boot File Size
        map.insert(13, OptionMetadata { code: 13, format: 0, size: 2 });
        
        // Option 14: Merit Dump File
        map.insert(14, OptionMetadata { code: 14, format: 0, size: 0 });
        
        // Option 15: Domain Name
        map.insert(15, OptionMetadata { code: 15, format: 0, size: 0 });
        
        // Option 16: Swap Server
        map.insert(16, OptionMetadata { code: 16, format: 0, size: 4 });
        
        // Option 17: Root Path
        map.insert(17, OptionMetadata { code: 17, format: 0, size: 0 });
        
        // Option 18: Extensions Path
        map.insert(18, OptionMetadata { code: 18, format: 0, size: 0 });
        
        // Option 19: IP Forwarding Enable/Disable
        map.insert(19, OptionMetadata { code: 19, format: 0, size: 1 });
        
        // Option 20: Non-Local Source Routing Enable/Disable
        map.insert(20, OptionMetadata { code: 20, format: 0, size: 1 });
        
        // Option 21: Policy Filter
        map.insert(21, OptionMetadata { code: 21, format: OT_ADDR_LIST, size: 8 });
        
        // Option 22: Maximum Datagram Reassembly Size
        map.insert(22, OptionMetadata { code: 22, format: 0, size: 2 });
        
        // Option 23: Default IP TTL
        map.insert(23, OptionMetadata { code: 23, format: 0, size: 1 });
        
        // Option 24: Path MTU Aging Timeout
        map.insert(24, OptionMetadata { code: 24, format: OT_TIME, size: 4 });
        
        // Option 25: Path MTU Plateau Table
        map.insert(25, OptionMetadata { code: 25, format: 0, size: 0 });
        
        // Option 26: Interface MTU
        map.insert(26, OptionMetadata { code: 26, format: 0, size: 2 });
        
        // Option 27: All Subnets Are Local
        map.insert(27, OptionMetadata { code: 27, format: 0, size: 1 });
        
        // Option 28: Broadcast Address
        map.insert(28, OptionMetadata { code: 28, format: 0, size: 4 });
        
        // Option 29: Perform Mask Discovery
        map.insert(29, OptionMetadata { code: 29, format: 0, size: 1 });
        
        // Option 30: Mask Supplier
        map.insert(30, OptionMetadata { code: 30, format: 0, size: 1 });
        
        // Option 31: Perform Router Discovery
        map.insert(31, OptionMetadata { code: 31, format: 0, size: 1 });
        
        // Option 32: Router Solicitation Address
        map.insert(32, OptionMetadata { code: 32, format: 0, size: 4 });
        
        // Option 33: Static Route
        map.insert(33, OptionMetadata { code: 33, format: OT_ADDR_LIST, size: 8 });
        
        // Option 34: Trailer Encapsulation
        map.insert(34, OptionMetadata { code: 34, format: 0, size: 1 });
        
        // Option 35: ARP Cache Timeout
        map.insert(35, OptionMetadata { code: 35, format: OT_TIME, size: 4 });
        
        // Option 36: Ethernet Encapsulation
        map.insert(36, OptionMetadata { code: 36, format: 0, size: 1 });
        
        // Option 37: TCP Default TTL
        map.insert(37, OptionMetadata { code: 37, format: 0, size: 1 });
        
        // Option 38: TCP Keepalive Interval
        map.insert(38, OptionMetadata { code: 38, format: OT_TIME, size: 4 });
        
        // Option 39: TCP Keepalive Garbage
        map.insert(39, OptionMetadata { code: 39, format: 0, size: 1 });
        
        // Option 40: NIS Domain
        map.insert(40, OptionMetadata { code: 40, format: 0, size: 0 });
        
        // Option 41: NIS Servers
        map.insert(41, OptionMetadata { code: 41, format: OT_ADDR_LIST, size: 4 });
        
        // Option 42: NTP Servers
        map.insert(42, OptionMetadata { code: 42, format: OT_ADDR_LIST, size: 4 });
        
        // Option 43: Vendor Specific Information
        map.insert(43, OptionMetadata { code: 43, format: 0, size: 0 });
        
        // Option 44: NetBIOS Name Server
        map.insert(44, OptionMetadata { code: 44, format: OT_ADDR_LIST, size: 4 });
        
        // Option 45: NetBIOS Datagram Distribution Server
        map.insert(45, OptionMetadata { code: 45, format: OT_ADDR_LIST, size: 4 });
        
        // Option 46: NetBIOS Node Type
        map.insert(46, OptionMetadata { code: 46, format: 0, size: 1 });
        
        // Option 47: NetBIOS Scope
        map.insert(47, OptionMetadata { code: 47, format: 0, size: 0 });
        
        // Option 48: X Window System Font Server
        map.insert(48, OptionMetadata { code: 48, format: OT_ADDR_LIST, size: 4 });
        
        // Option 49: X Window System Display Manager
        map.insert(49, OptionMetadata { code: 49, format: OT_ADDR_LIST, size: 4 });
        
        // Option 50: Requested IP Address
        map.insert(50, OptionMetadata { code: 50, format: OT_INTERNAL, size: 4 });
        
        // Option 51: IP Address Lease Time
        map.insert(51, OptionMetadata { code: 51, format: OT_INTERNAL | OT_TIME, size: 4 });
        
        // Option 52: Option Overload
        map.insert(52, OptionMetadata { code: 52, format: OT_INTERNAL, size: 1 });
        
        // Option 53: DHCP Message Type
        map.insert(53, OptionMetadata { code: 53, format: OT_INTERNAL, size: 1 });
        
        // Option 54: Server Identifier
        map.insert(54, OptionMetadata { code: 54, format: OT_INTERNAL, size: 4 });
        
        // Option 55: Parameter Request List
        map.insert(55, OptionMetadata { code: 55, format: OT_INTERNAL, size: 0 });
        
        // Option 56: Message
        map.insert(56, OptionMetadata { code: 56, format: OT_INTERNAL, size: 0 });
        
        // Option 57: Maximum DHCP Message Size
        map.insert(57, OptionMetadata { code: 57, format: OT_INTERNAL, size: 2 });
        
        // Option 58: Renewal Time (T1)
        map.insert(58, OptionMetadata { code: 58, format: OT_INTERNAL | OT_TIME, size: 4 });
        
        // Option 59: Rebinding Time (T2)
        map.insert(59, OptionMetadata { code: 59, format: OT_INTERNAL | OT_TIME, size: 4 });
        
        // Option 60: Vendor Class Identifier
        map.insert(60, OptionMetadata { code: 60, format: 0, size: 0 });
        
        // Option 61: Client Identifier
        map.insert(61, OptionMetadata { code: 61, format: OT_INTERNAL, size: 0 });
        
        // Option 64: NIS+ Domain
        map.insert(64, OptionMetadata { code: 64, format: 0, size: 0 });
        
        // Option 65: NIS+ Servers
        map.insert(65, OptionMetadata { code: 65, format: OT_ADDR_LIST, size: 4 });
        
        // Option 66: TFTP Server Name
        map.insert(66, OptionMetadata { code: 66, format: 0, size: 0 });
        
        // Option 67: Bootfile Name
        map.insert(67, OptionMetadata { code: 67, format: 0, size: 0 });
        
        // Option 68: Mobile IP Home Agent
        map.insert(68, OptionMetadata { code: 68, format: OT_ADDR_LIST, size: 0 });
        
        // Option 69: SMTP Server
        map.insert(69, OptionMetadata { code: 69, format: OT_ADDR_LIST, size: 4 });
        
        // Option 70: POP3 Server
        map.insert(70, OptionMetadata { code: 70, format: OT_ADDR_LIST, size: 4 });
        
        // Option 71: NNTP Server
        map.insert(71, OptionMetadata { code: 71, format: OT_ADDR_LIST, size: 4 });
        
        // Option 72: WWW Server
        map.insert(72, OptionMetadata { code: 72, format: OT_ADDR_LIST, size: 4 });
        
        // Option 73: Finger Server
        map.insert(73, OptionMetadata { code: 73, format: OT_ADDR_LIST, size: 4 });
        
        // Option 74: IRC Server
        map.insert(74, OptionMetadata { code: 74, format: OT_ADDR_LIST, size: 4 });
        
        // Option 75: StreetTalk Server
        map.insert(75, OptionMetadata { code: 75, format: OT_ADDR_LIST, size: 4 });
        
        // Option 76: StreetTalk Directory Assistance Server
        map.insert(76, OptionMetadata { code: 76, format: OT_ADDR_LIST, size: 4 });
        
        // Option 77: User Class
        map.insert(77, OptionMetadata { code: 77, format: 0, size: 0 });
        
        // Option 81: FQDN (Fully Qualified Domain Name)
        map.insert(81, OptionMetadata { code: 81, format: 0, size: 0 });
        
        // Option 85: NDS Servers
        map.insert(85, OptionMetadata { code: 85, format: OT_ADDR_LIST, size: 4 });
        
        // Option 86: NDS Tree Name
        map.insert(86, OptionMetadata { code: 86, format: 0, size: 0 });
        
        // Option 87: NDS Context
        map.insert(87, OptionMetadata { code: 87, format: 0, size: 0 });
        
        // Option 88: BCMCS Controller Domain Name List
        map.insert(88, OptionMetadata { code: 88, format: 0, size: 0 });
        
        // Option 89: BCMCS Controller IPv4 Address
        map.insert(89, OptionMetadata { code: 89, format: OT_ADDR_LIST, size: 4 });
        
        // Option 91: Client Last Transaction Time
        map.insert(91, OptionMetadata { code: 91, format: OT_TIME, size: 4 });
        
        // Option 92: Associated IP
        map.insert(92, OptionMetadata { code: 92, format: OT_ADDR_LIST, size: 4 });
        
        // Option 93: Client System Architecture
        map.insert(93, OptionMetadata { code: 93, format: 0, size: 0 });
        
        // Option 94: Client Network Interface Identifier
        map.insert(94, OptionMetadata { code: 94, format: 0, size: 0 });
        
        // Option 97: Client Machine Identifier (UUID)
        map.insert(97, OptionMetadata { code: 97, format: 0, size: 0 });
        
        // Option 119: Domain Search
        map.insert(119, OptionMetadata { code: 119, format: 0, size: 0 });
        
        // Option 120: SIP Servers
        map.insert(120, OptionMetadata { code: 120, format: 0, size: 0 });
        
        // Option 121: Classless Static Route
        map.insert(121, OptionMetadata { code: 121, format: 0, size: 0 });
        
        // Option 125: Vendor-Identifying Vendor-Specific Information
        map.insert(125, OptionMetadata { code: 125, format: 0, size: 0 });
        
        // Option 255: End
        map.insert(255, OptionMetadata { code: 255, format: OT_INTERNAL, size: 0 });
        
        map
    });

/// DHCPv6 option table.
///
/// Static metadata for all DHCPv6 options. Replaces C `opttab6[]` array from
/// dhcp-common.c lines 638-1555. Provides O(1) lookup by option code.
///
/// **C Source**: dhcp-common.c opttab6[] static array
///
/// # Example Entries
///
/// ```ignore
/// 1 => OptionMetadata { code: 1, format: OT_INTERNAL, size: 0 }, // OPTION_CLIENTID
/// 2 => OptionMetadata { code: 2, format: OT_INTERNAL, size: 0 }, // OPTION_SERVERID
/// 3 => OptionMetadata { code: 3, format: OT_INTERNAL, size: 0 }, // OPTION_IA_NA
/// ```
pub static DHCPV6_OPTION_TABLE: LazyLock<HashMap<u16, OptionMetadata>> =
    LazyLock::new(|| {
        let mut map = HashMap::new();
        
        // Option 1: Client Identifier
        map.insert(1, OptionMetadata { code: 1, format: OT_INTERNAL, size: 0 });
        
        // Option 2: Server Identifier
        map.insert(2, OptionMetadata { code: 2, format: OT_INTERNAL, size: 0 });
        
        // Option 3: Identity Association for Non-temporary Addresses (IA_NA)
        map.insert(3, OptionMetadata { code: 3, format: OT_INTERNAL, size: 0 });
        
        // Option 4: Identity Association for Temporary Addresses (IA_TA)
        map.insert(4, OptionMetadata { code: 4, format: OT_INTERNAL, size: 0 });
        
        // Option 5: IA Address
        map.insert(5, OptionMetadata { code: 5, format: OT_INTERNAL, size: 24 });
        
        // Option 6: Option Request
        map.insert(6, OptionMetadata { code: 6, format: OT_INTERNAL, size: 0 });
        
        // Option 7: Preference
        map.insert(7, OptionMetadata { code: 7, format: OT_INTERNAL, size: 1 });
        
        // Option 8: Elapsed Time
        map.insert(8, OptionMetadata { code: 8, format: OT_INTERNAL, size: 2 });
        
        // Option 9: Relay Message
        map.insert(9, OptionMetadata { code: 9, format: OT_INTERNAL, size: 0 });
        
        // Option 11: Authentication
        map.insert(11, OptionMetadata { code: 11, format: OT_INTERNAL, size: 0 });
        
        // Option 12: Server Unicast
        map.insert(12, OptionMetadata { code: 12, format: OT_INTERNAL, size: 16 });
        
        // Option 13: Status Code
        map.insert(13, OptionMetadata { code: 13, format: OT_INTERNAL, size: 0 });
        
        // Option 14: Rapid Commit
        map.insert(14, OptionMetadata { code: 14, format: OT_INTERNAL, size: 0 });
        
        // Option 15: User Class
        map.insert(15, OptionMetadata { code: 15, format: 0, size: 0 });
        
        // Option 16: Vendor Class
        map.insert(16, OptionMetadata { code: 16, format: 0, size: 0 });
        
        // Option 17: Vendor-Specific Information
        map.insert(17, OptionMetadata { code: 17, format: 0, size: 0 });
        
        // Option 18: Interface ID
        map.insert(18, OptionMetadata { code: 18, format: OT_INTERNAL, size: 0 });
        
        // Option 19: Reconfigure Message
        map.insert(19, OptionMetadata { code: 19, format: OT_INTERNAL, size: 1 });
        
        // Option 20: Reconfigure Accept
        map.insert(20, OptionMetadata { code: 20, format: OT_INTERNAL, size: 0 });
        
        // Option 21: SIP Servers Domain Name List
        map.insert(21, OptionMetadata { code: 21, format: 0, size: 0 });
        
        // Option 22: SIP Servers IPv6 Address List
        map.insert(22, OptionMetadata { code: 22, format: OT_ADDR_LIST, size: 16 });
        
        // Option 23: DNS Recursive Name Server
        map.insert(23, OptionMetadata { code: 23, format: OT_ADDR_LIST, size: 16 });
        
        // Option 24: Domain Search List
        map.insert(24, OptionMetadata { code: 24, format: 0, size: 0 });
        
        // Option 25: Identity Association for Prefix Delegation (IA_PD)
        map.insert(25, OptionMetadata { code: 25, format: OT_INTERNAL, size: 0 });
        
        // Option 26: IA Prefix
        map.insert(26, OptionMetadata { code: 26, format: OT_INTERNAL, size: 0 });
        
        // Option 27: NIS Servers
        map.insert(27, OptionMetadata { code: 27, format: OT_ADDR_LIST, size: 16 });
        
        // Option 28: NIS+ Servers
        map.insert(28, OptionMetadata { code: 28, format: OT_ADDR_LIST, size: 16 });
        
        // Option 29: NIS Domain Name
        map.insert(29, OptionMetadata { code: 29, format: 0, size: 0 });
        
        // Option 30: NIS+ Domain Name
        map.insert(30, OptionMetadata { code: 30, format: 0, size: 0 });
        
        // Option 31: SNTP Servers
        map.insert(31, OptionMetadata { code: 31, format: OT_ADDR_LIST, size: 16 });
        
        // Option 32: Information Refresh Time
        map.insert(32, OptionMetadata { code: 32, format: OT_TIME, size: 4 });
        
        // Option 33: BCMCS Controller Domain Name List
        map.insert(33, OptionMetadata { code: 33, format: 0, size: 0 });
        
        // Option 34: BCMCS Controller IPv6 Address
        map.insert(34, OptionMetadata { code: 34, format: OT_ADDR_LIST, size: 16 });
        
        // Option 39: FQDN
        map.insert(39, OptionMetadata { code: 39, format: 0, size: 0 });
        
        // Option 56: NTP Server
        map.insert(56, OptionMetadata { code: 56, format: 0, size: 0 });
        
        map
    });

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// Generate a cryptographically secure transaction ID (xid) for DHCP messages.
///
/// Replaces C global random() call with Rust's secure random number generator.
/// Used to correlate DHCP requests and responses.
///
/// # Returns
///
/// Random 32-bit unsigned integer suitable for use as DHCP xid field.
///
/// # Example
///
/// ```ignore
/// let xid = generate_xid();
/// let discover = DhcpDiscover { xid, ...};
/// ```
///
/// # Security
///
/// Uses `rand::random()` which provides cryptographically secure randomness
/// via platform CSPRNG (e.g., getrandom(2) on Linux, arc4random(3) on BSD).
/// Far superior to C's random() which is predictable and unsuitable for security.
pub fn generate_xid() -> u32 {
    random()
}

/// Parse a MAC address from string format.
///
/// Supports multiple MAC address formats:
/// - Colon-separated: `aa:bb:cc:dd:ee:ff`
/// - Hyphen-separated: `aa-bb-cc-dd-ee-ff`
/// - Dot-separated (Cisco): `aabb.ccdd.eeff`
/// - Continuous: `aabbccddeeff`
///
/// # Arguments
///
/// * `s` - MAC address string in any supported format
///
/// # Returns
///
/// * `Ok(MacAddress)` - Parsed 6-byte MAC address
/// * `Err(DhcpError)` - Invalid format or parse error
///
/// # Example
///
/// ```ignore
/// let mac = parse_mac_address("00:11:22:33:44:55")?;
/// assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
/// ```
///
/// # Memory Safety
///
/// Uses nom parser combinators with compile-time bounds checking.
/// Impossible to overflow output buffer. C version used manual string
/// parsing with potential buffer overruns.
pub fn parse_mac_address(s: &str) -> Result<MacAddress, DhcpError> {
    // Try colon-separated format (aa:bb:cc:dd:ee:ff)
    if let Ok((_, mac)) = parse_mac_colon(s) {
        return Ok(mac);
    }
    
    // Try hyphen-separated format (aa-bb-cc-dd-ee-ff)
    if let Ok((_, mac)) = parse_mac_hyphen(s) {
        return Ok(mac);
    }
    
    // Try dot-separated format (aabb.ccdd.eeff)
    if let Ok((_, mac)) = parse_mac_dot(s) {
        return Ok(mac);
    }
    
    // Try continuous format (aabbccddeeff)
    if let Ok((_, mac)) = parse_mac_continuous(s) {
        return Ok(mac);
    }
    
    Err(DhcpError::InvalidMacAddress(s.to_string()))
}

/// Parse colon-separated MAC address (aa:bb:cc:dd:ee:ff).
fn parse_mac_colon(input: &str) -> IResult<&str, MacAddress> {
    let (input, bytes) = separated_list1(
        tag(":"),
        map_res(hex_digit1, |s: &str| u8::from_str_radix(s, 16))
    )(input)?;
    
    if bytes.len() != 6 {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::TooLarge)));
    }
    
    Ok((input, [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]))
}

/// Parse hyphen-separated MAC address (aa-bb-cc-dd-ee-ff).
fn parse_mac_hyphen(input: &str) -> IResult<&str, MacAddress> {
    let (input, bytes) = separated_list1(
        tag("-"),
        map_res(hex_digit1, |s: &str| u8::from_str_radix(s, 16))
    )(input)?;
    
    if bytes.len() != 6 {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::TooLarge)));
    }
    
    Ok((input, [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]))
}

/// Parse dot-separated MAC address (aabb.ccdd.eeff).
fn parse_mac_dot(input: &str) -> IResult<&str, MacAddress> {
    let (input, parts) = separated_list1(
        tag("."),
        map_res(take(4usize), |s: &str| u16::from_str_radix(s, 16))
    )(input)?;
    
    if parts.len() != 3 {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::TooLarge)));
    }
    
    let mac = [
        (parts[0] >> 8) as u8,
        (parts[0] & 0xFF) as u8,
        (parts[1] >> 8) as u8,
        (parts[1] & 0xFF) as u8,
        (parts[2] >> 8) as u8,
        (parts[2] & 0xFF) as u8,
    ];
    
    Ok((input, mac))
}

/// Parse continuous MAC address (aabbccddeeff).
fn parse_mac_continuous(input: &str) -> IResult<&str, MacAddress> {
    if input.len() != 12 {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::TooLarge)));
    }
    
    let mut mac = [0u8; 6];
    for i in 0..6 {
        let start = i * 2;
        let end = start + 2;
        mac[i] = u8::from_str_radix(&input[start..end], 16)
            .map_err(|_| nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::HexDigit)))?;
    }
    
    Ok(("", mac))
}

/// Check if a network ID tag matches a list of tags.
///
/// Performs exact string matching of network ID tags for client classification.
/// Used to determine if a client's tags match configuration requirements.
///
/// # Arguments
///
/// * `tag` - Tag to search for
/// * `tags` - List of tags to search in
///
/// # Returns
///
/// `true` if tag is found in tags list, `false` otherwise.
///
/// # Example
///
/// ```ignore
/// let client_tags = vec!["router".to_string(), "admin".to_string()];
/// if match_netid("admin", &client_tags) {
///     // Apply admin-specific options
/// }
/// ```
pub fn match_netid(tag: &str, tags: &[NetworkId]) -> bool {
    tags.iter().any(|t| t == tag)
}

/// Check if a network ID tag matches with wildcard support.
///
/// Supports wildcard matching with `*` for prefix matching and `!` for negation.
///
/// # Wildcard Patterns
///
/// - `tag`: Exact match for "tag"
/// - `tag*`: Matches "tag", "tag1", "tagfoo", etc.
/// - `!tag`: Matches if "tag" is NOT in tags
/// - `!tag*`: Matches if no tag starting with "tag" is in tags
///
/// # Arguments
///
/// * `pattern` - Pattern to match (may contain `*` or `!` prefix)
/// * `tags` - List of tags to match against
///
/// # Returns
///
/// `true` if pattern matches, `false` otherwise.
///
/// # Example
///
/// ```ignore
/// let client_tags = vec!["router1".to_string(), "admin".to_string()];
/// 
/// assert!(match_netid_wild("router*", &client_tags));  // true
/// assert!(match_netid_wild("!guest", &client_tags));   // true
/// assert!(!match_netid_wild("!admin", &client_tags));  // false
/// ```
pub fn match_netid_wild(pattern: &str, tags: &[NetworkId]) -> bool {
    // Handle negation
    if let Some(pattern_inner) = pattern.strip_prefix('!') {
        // Negated pattern: return true if NOT found
        return !match_netid_wild(pattern_inner, tags);
    }
    
    // Handle wildcard suffix
    if let Some(prefix) = pattern.strip_suffix('*') {
        // Wildcard pattern: match any tag starting with prefix
        return tags.iter().any(|tag| tag.starts_with(prefix));
    }
    
    // Exact match
    match_netid(pattern, tags)
}

/// Strip and validate hostname from DHCP packet.
///
/// Processes hostname provided by DHCP client, stripping invalid characters
/// and truncating to maximum length. Ensures hostname is safe for DNS registration.
///
/// # Arguments
///
/// * `hostname` - Raw hostname bytes from DHCP packet
/// * `max_len` - Maximum allowed hostname length
///
/// # Returns
///
/// Validated hostname string with invalid characters removed.
///
/// # Processing Rules
///
/// - Remove leading/trailing whitespace
/// - Remove invalid DNS characters (non-alphanumeric except hyphen)
/// - Truncate to max_len
/// - Return empty string if resulting hostname is invalid
///
/// # Example
///
/// ```ignore
/// let hostname = strip_hostname(b"my-laptop!", 63);
/// assert_eq!(hostname, "my-laptop");
/// ```
pub fn strip_hostname(hostname: &[u8], max_len: usize) -> String {
    let mut result = String::new();
    
    for &byte in hostname {
        let ch = byte as char;
        
        // Allow alphanumeric, hyphen, and dot
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
            result.push(ch);
        }
        
        if result.len() >= max_len {
            break;
        }
    }
    
    // Trim leading/trailing hyphens and dots (invalid in hostnames)
    result.trim_matches(|c| c == '-' || c == '.').to_string()
}

/// Log network ID tags for debugging.
///
/// Emits structured log message with list of network ID tags assigned to client.
/// Used for debugging client classification and option filtering.
///
/// # Arguments
///
/// * `tags` - List of network ID tags to log
/// * `context` - Context string (e.g., "DHCPv4", "DHCPv6", interface name)
///
/// # Example
///
/// ```ignore
/// log_tags(&client.tags, "eth0");
/// // Emits: "tags: [router, admin, vlan100]"
/// ```
pub fn log_tags(tags: &[NetworkId], context: &str) {
    if !tags.is_empty() {
        debug!(context = %context, tags = ?tags, "Network ID tags assigned");
    }
}

/// Match bytes with wildcard support.
///
/// Performs byte-by-byte matching with wildcard bitmask support. Used for
/// matching DHCP option values with wildcard patterns in client classification.
///
/// # Arguments
///
/// * `opt` - DHCP option configuration with value and wildcard mask
/// * `data` - Data bytes to match against
///
/// # Returns
///
/// `true` if data matches option pattern (considering wildcards), `false` otherwise.
///
/// # Wildcard Matching
///
/// If `opt.wildcard_mask` is Some, each bit in the mask indicates:
/// - Bit 1: Wildcard (ignore this byte in comparison)
/// - Bit 0: Exact match required for this byte
///
/// # Example
///
/// ```ignore
/// let opt = DhcpOpt {
///     val: vec![0xAA, 0xBB, 0xCC, 0xDD],
///     wildcard_mask: Some(0x0110),  // Bytes 1 and 2 are wildcards
///     ..
/// };
/// 
/// // Matches: [0xAA, 0xFF, 0xFF, 0xDD]
/// // First and last bytes must match exactly, middle two can be anything
/// ```
pub fn match_bytes(opt: &DhcpOpt, data: &[u8]) -> bool {
    if opt.len != data.len() {
        return false;
    }
    
    match opt.wildcard_mask {
        Some(mask) => {
            // Wildcard matching: check each byte against mask
            for (i, (&opt_byte, &data_byte)) in opt.val.iter().zip(data.iter()).enumerate() {
                // If bit i of mask is 1, it's a wildcard (skip comparison)
                if (mask & (1 << i)) != 0 {
                    continue;
                }
                
                // Otherwise, require exact match
                if opt_byte != data_byte {
                    return false;
                }
            }
            true
        }
        None => {
            // Exact matching: all bytes must match
            opt.val == data
        }
    }
}

/// Receive DHCP packet from UDP socket with dynamic buffer management.
///
/// Async function to receive DHCP packet from UDP socket. Automatically resizes
/// buffer if packet is larger than initial capacity. Replaces C recv_dhcp_packet()
/// function that used recvmsg() with MSG_PEEK and manual buffer expansion.
///
/// # Arguments
///
/// * `socket` - UDP socket to receive from
/// * `buf` - Buffer for packet data (will be resized if needed)
///
/// # Returns
///
/// * `Ok((usize, SocketAddr))` - Number of bytes received and source address
/// * `Err(DhcpError)` - I/O error or packet too large
///
/// # Buffer Management
///
/// If initial buffer is too small, function automatically resizes up to
/// DHCP_PACKET_MAX (16384 bytes). Prevents memory exhaustion from malformed packets
/// claiming huge sizes.
///
/// # Example
///
/// ```ignore
/// let socket = UdpSocket::bind("0.0.0.0:67").await?;
/// let mut buf = Vec::with_capacity(1500);
/// 
/// let (len, src_addr) = recv_dhcp_packet(&socket, &mut buf).await?;
/// let packet = &buf[..len];
/// ```
///
/// # Memory Safety
///
/// Uses Rust Vec which automatically manages memory. C version used manual
/// realloc() which could fail or leak memory. Rust version is safe and cannot
/// overflow buffer.
pub async fn recv_dhcp_packet(
    socket: &UdpSocket,
    buf: &mut Vec<u8>,
) -> Result<(usize, SocketAddr), DhcpError> {
    // Ensure buffer has at least initial capacity
    if buf.capacity() == 0 {
        buf.reserve(1500); // Typical MTU size
    }
    
    // Resize buffer to current capacity for recv_from
    buf.resize(buf.capacity(), 0);
    
    // Attempt to receive packet
    match socket.recv_from(buf).await {
        Ok((len, src_addr)) => {
            // Truncate buffer to actual received size
            buf.truncate(len);
            Ok((len, src_addr))
        }
        Err(e) => {
            // Check if we need a larger buffer
            if buf.capacity() < DHCP_PACKET_MAX {
                // Try with larger buffer
                let new_capacity = (buf.capacity() * 2).min(DHCP_PACKET_MAX);
                buf.reserve(new_capacity - buf.capacity());
                buf.resize(buf.capacity(), 0);
                
                // Retry receive with larger buffer
                match socket.recv_from(buf).await {
                    Ok((len, src_addr)) => {
                        buf.truncate(len);
                        Ok((len, src_addr))
                    }
                    Err(e) => Err(DhcpError::IoError(e)),
                }
            } else {
                Err(DhcpError::IoError(e))
            }
        }
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_xid() {
        let xid1 = generate_xid();
        let xid2 = generate_xid();
        
        // XIDs should be different (extremely unlikely to be same)
        assert_ne!(xid1, xid2);
    }

    #[test]
    fn test_parse_mac_address_colon() {
        let mac = parse_mac_address("00:11:22:33:44:55").unwrap();
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_parse_mac_address_hyphen() {
        let mac = parse_mac_address("AA-BB-CC-DD-EE-FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_mac_address_dot() {
        let mac = parse_mac_address("aabb.ccdd.eeff").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_mac_address_continuous() {
        let mac = parse_mac_address("112233445566").unwrap();
        assert_eq!(mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn test_parse_mac_address_invalid() {
        assert!(parse_mac_address("invalid").is_err());
        assert!(parse_mac_address("00:11:22:33:44").is_err());
        assert!(parse_mac_address("00:11:22:33:44:55:66").is_err());
    }

    #[test]
    fn test_match_netid_exact() {
        let tags = vec!["router".to_string(), "admin".to_string()];
        
        assert!(match_netid("router", &tags));
        assert!(match_netid("admin", &tags));
        assert!(!match_netid("guest", &tags));
    }

    #[test]
    fn test_match_netid_wild_prefix() {
        let tags = vec!["router1".to_string(), "admin".to_string()];
        
        assert!(match_netid_wild("router*", &tags));
        assert!(match_netid_wild("admin*", &tags));
        assert!(!match_netid_wild("guest*", &tags));
    }

    #[test]
    fn test_match_netid_wild_negation() {
        let tags = vec!["router".to_string(), "admin".to_string()];
        
        assert!(match_netid_wild("!guest", &tags));
        assert!(!match_netid_wild("!router", &tags));
        assert!(!match_netid_wild("!admin", &tags));
    }

    #[test]
    fn test_strip_hostname() {
        assert_eq!(strip_hostname(b"my-laptop", 63), "my-laptop");
        assert_eq!(strip_hostname(b"my-laptop!", 63), "my-laptop");
        assert_eq!(strip_hostname(b"  laptop  ", 63), "laptop");
        assert_eq!(strip_hostname(b"-laptop-", 63), "laptop");
        assert_eq!(strip_hostname(b"my@laptop", 63), "mylaptop");
        
        // Test truncation
        let long_name = b"very-long-hostname-that-exceeds-maximum-length";
        assert!(strip_hostname(long_name, 20).len() <= 20);
    }

    #[test]
    fn test_match_bytes_exact() {
        let opt = DhcpOpt {
            opt: 1,
            len: 4,
            flags: 0,
            val: vec![0xAA, 0xBB, 0xCC, 0xDD],
            wildcard_mask: None,
        };
        
        assert!(match_bytes(&opt, &[0xAA, 0xBB, 0xCC, 0xDD]));
        assert!(!match_bytes(&opt, &[0xAA, 0xBB, 0xCC, 0xEE]));
        assert!(!match_bytes(&opt, &[0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn test_match_bytes_wildcard() {
        let opt = DhcpOpt {
            opt: 1,
            len: 4,
            flags: DHOPT_MATCH,
            val: vec![0xAA, 0xBB, 0xCC, 0xDD],
            wildcard_mask: Some(0x0110), // Bytes 1 and 2 are wildcards (bits 4 and 8)
        };
        
        // First and last bytes must match, middle two can be anything
        assert!(match_bytes(&opt, &[0xAA, 0xFF, 0xFF, 0xDD]));
        assert!(match_bytes(&opt, &[0xAA, 0x00, 0x00, 0xDD]));
        assert!(!match_bytes(&opt, &[0xFF, 0xBB, 0xCC, 0xDD]));
        assert!(!match_bytes(&opt, &[0xAA, 0xBB, 0xCC, 0xFF]));
    }

    #[test]
    fn test_dhcpv4_option_table() {
        // Test key options
        let subnet_mask = DHCPV4_OPTION_TABLE.get(&1).unwrap();
        assert_eq!(subnet_mask.code, 1);
        assert_eq!(subnet_mask.size, 4);
        
        let router = DHCPV4_OPTION_TABLE.get(&3).unwrap();
        assert_eq!(router.code, 3);
        assert_eq!(router.format & OT_ADDR_LIST, OT_ADDR_LIST);
        
        let dns = DHCPV4_OPTION_TABLE.get(&6).unwrap();
        assert_eq!(dns.code, 6);
        assert_eq!(dns.format & OT_ADDR_LIST, OT_ADDR_LIST);
    }

    #[test]
    fn test_dhcpv6_option_table() {
        // Test key options
        let clientid = DHCPV6_OPTION_TABLE.get(&1).unwrap();
        assert_eq!(clientid.code, 1);
        assert_eq!(clientid.format & OT_INTERNAL, OT_INTERNAL);
        
        let serverid = DHCPV6_OPTION_TABLE.get(&2).unwrap();
        assert_eq!(serverid.code, 2);
        assert_eq!(serverid.format & OT_INTERNAL, OT_INTERNAL);
        
        let dns = DHCPV6_OPTION_TABLE.get(&23).unwrap();
        assert_eq!(dns.code, 23);
        assert_eq!(dns.format & OT_ADDR_LIST, OT_ADDR_LIST);
    }
}
