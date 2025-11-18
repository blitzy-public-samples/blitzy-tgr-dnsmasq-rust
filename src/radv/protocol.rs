// Copyright (c) 2000-2025 Simon Kelley
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

//! ICMPv6 Router Advertisement protocol constants and structures per RFC 4861
//!
//! This module defines protocol constants, packet structures, and option definitions for
//! IPv6 Router Advertisement (RA) and Neighbor Discovery (ND) protocols as specified in
//! RFC 4861 (IPv6 Neighbor Discovery Protocol). These definitions enable dnsmasq to
//! construct and transmit ICMPv6 Router Advertisement messages for IPv6 network
//! autoconfiguration, supporting both SLAAC (Stateless Address Autoconfiguration) and
//! managed DHCPv6 address assignment.
//!
//! # Key Responsibilities
//!
//! - Define IPv6 multicast addresses for ND protocol communication (all-nodes, all-routers)
//! - Provide ICMPv6 packet structure definitions for Router Advertisement messages
//! - Define prefix information option structure for advertised IPv6 prefixes
//! - Enumerate ICMPv6 Neighbor Discovery option types (prefix, RDNSS, DNSSL, etc.)
//! - Support neighbor solicitation and advertisement packet structures
//! - Enable ICMP6 Echo Request/Reply (ping) packet construction
//!
//! # RFC Compliance
//!
//! - RFC 4861: IPv6 Neighbor Discovery Protocol (Router Advertisement, Neighbor Solicitation)
//! - RFC 6106: IPv6 Router Advertisement Options for DNS Configuration (RDNSS, DNSSL)
//! - RFC 4443: ICMPv6 for IPv6 (ICMPv6 message format and type codes)
//! - RFC 4191: Default Router Preferences and More-Specific Routes
//! - RFC 6275: Mobility Support in IPv6 (Advertisement Interval option)
//!
//! # Usage
//!
//! This module is used by the `radv` module to construct Router Advertisement messages
//! with configured prefixes and lifetimes, set Managed (M) and Other (O) flags controlling
//! DHCPv6 usage, include RDNSS options advertising DNS servers, and transmit RAs to
//! FF02::1 (all-nodes multicast) for network-wide autoconfiguration.

use std::net::Ipv6Addr;

/// IPv6 link-local all-nodes multicast address (FF02::1)
///
/// This address is used as the destination for Router Advertisement messages that
/// should be received by all IPv6 nodes on the local link. Router Advertisements
/// are sent to this address to enable all hosts to perform Stateless Address
/// Autoconfiguration (SLAAC) and discover router parameters.
///
/// RFC 4861 Section 6.1.2: Routers send unsolicited Router Advertisements to the
/// all-nodes multicast address to advertise their presence and network parameters.
///
/// **Note**: This is a link-local scope multicast address (FF02), meaning it is not
/// forwarded beyond the local network segment.
pub const ALL_NODES: &str = "FF02::1";

/// IPv6 link-local all-routers multicast address (FF02::2)
///
/// This address is used as the destination for Router Solicitation messages sent
/// by hosts to request immediate Router Advertisement messages from routers. This
/// enables faster network autoconfiguration by not waiting for periodic unsolicited
/// Router Advertisements.
///
/// RFC 4861 Section 6.1.1: Hosts send Router Solicitations to the all-routers
/// multicast address when they need to discover routers immediately upon interface
/// initialization.
///
/// **Note**: While defined here for protocol completeness, dnsmasq as a router
/// primarily transmits to ALL_NODES and may listen for solicitations on this address.
pub const ALL_ROUTERS: &str = "FF02::2";

/// ICMPv6 Echo Request message type (128)
///
/// Used for IPv6 ping operations and address conflict detection.
/// Echo Request messages are sent to test address availability.
///
/// RFC 4443 Section 4.1: ICMPv6 Echo Request Message
pub const ICMP6_ECHO_REQUEST: u8 = 128;

/// ICMPv6 Echo Reply message type (129)
///
/// Response to Echo Request, indicating the address is in use.
///
/// RFC 4443 Section 4.2: ICMPv6 Echo Reply Message
pub const ICMP6_ECHO_REPLY: u8 = 129;

/// ICMPv6 Router Advertisement message type (134)
///
/// Used by routers to advertise their presence and network parameters.
///
/// RFC 4861 Section 4.2: Router Advertisement Message Format
pub const ICMP6_ROUTER_ADVERT: u8 = 134;

/// ICMPv6 Neighbor Solicitation message type (135)
///
/// Used for address resolution and duplicate address detection.
///
/// RFC 4861 Section 4.3: Neighbor Solicitation Message Format
pub const ICMP6_NEIGH_SOLICIT: u8 = 135;

/// ICMPv6 Neighbor Advertisement message type (136)
///
/// Response to Neighbor Solicitation or unsolicited announcement.
///
/// RFC 4861 Section 4.4: Neighbor Advertisement Message Format
pub const ICMP6_NEIGH_ADVERT: u8 = 136;

/// Source Link-Layer Address option type (1)
///
/// This option provides the link-layer address (MAC address) of the interface from which
/// the ICMPv6 message is sent. In Router Advertisement messages, this is the router's
/// MAC address, allowing hosts to populate their neighbor cache with the router's
/// link-layer address without requiring separate Neighbor Solicitation/Advertisement
/// exchange.
///
/// Option format (RFC 4861 Section 4.6.1):
/// - Type: 1 (1 octet)
/// - Length: 1 (1 octet) - in units of 8 octets, total 8 bytes
/// - Link-Layer Address: Variable length (6 octets for Ethernet MAC address)
/// - Padding: Pad to multiple of 8 octets if necessary
///
/// RFC 4861 Section 4.6.1
pub const SOURCE_MAC_OPT: u8 = 1;

/// Prefix Information option type (3)
///
/// This option provides information about IPv6 prefixes that are on-link and/or can be
/// used for Stateless Address Autoconfiguration (SLAAC). Router Advertisement messages
/// typically include one or more prefix options to advertise available prefixes.
///
/// Option format: See `PrefixOpt` struct documentation
/// - Type: 3 (1 octet)
/// - Length: 4 (1 octet) - in units of 8 octets, total 32 bytes
/// - Prefix Length: Number of valid prefix bits (1 octet)
/// - Flags: L (on-link), A (autonomous) flags (1 octet)
/// - Valid Lifetime: Prefix/address validity period (4 octets)
/// - Preferred Lifetime: Address preference period (4 octets)
/// - Reserved: Must be zero (4 octets)
/// - Prefix: IPv6 address prefix (16 octets)
///
/// RFC 4861 Section 4.6.2
pub const PREFIX_OPT: u8 = 3;

/// MTU (Maximum Transmission Unit) option type (5)
///
/// This option specifies the Maximum Transmission Unit (MTU) that hosts should use when
/// sending packets on the link. This is useful for links with non-standard MTU values
/// or to avoid path MTU discovery overhead.
///
/// Option format (RFC 4861 Section 4.6.4):
/// - Type: 5 (1 octet)
/// - Length: 1 (1 octet) - in units of 8 octets, total 8 bytes
/// - Reserved: Must be zero (2 octets)
/// - MTU: Maximum transmission unit in octets (4 octets)
///
/// Typical MTU values:
/// - 1500: Standard Ethernet MTU
/// - 1280: IPv6 minimum MTU (RFC 8200)
/// - 9000: Jumbo frames
/// - 1492: PPPoE with overhead
///
/// RFC 4861 Section 4.6.4
pub const MTU_OPT: u8 = 5;

/// Advertisement Interval option type (7)
///
/// This option specifies the maximum time between consecutive unsolicited Router
/// Advertisement messages sent by the router. This information allows hosts to
/// detect router failures more quickly by knowing the expected RA transmission interval.
///
/// Option format (RFC 6275 Section 7.3):
/// - Type: 7 (1 octet)
/// - Length: 1 (1 octet) - in units of 8 octets, total 8 bytes
/// - Reserved: Must be zero (2 octets)
/// - Advertisement Interval: Maximum time between RAs in milliseconds (4 octets)
///
/// Typical intervals:
/// - 200000-600000 ms (3-10 minutes): Standard interval for stable networks
/// - 30000-70000 ms (30-70 seconds): Mobile IPv6 fast handover scenarios
///
/// RFC 6275 Section 7.3 (Mobile IPv6)
pub const INTERVAL_OPT: u8 = 7;

/// Route Information option type (24)
///
/// This option provides information about more-specific routes that should be added
/// to the host's routing table, beyond the default route advertised in the main RA
/// message. This enables routers to advertise multiple routes with different prefixes
/// and preferences.
///
/// Option format (RFC 4191 Section 2.3):
/// - Type: 24 (1 octet)
/// - Length: Variable (1, 2, or 3 depending on prefix length) (1 octet)
/// - Prefix Length: Number of valid prefix bits (1 octet)
/// - Flags: Preference value (1 octet)
/// - Route Lifetime: Validity period for route in seconds (4 octets)
/// - Prefix: Variable length, padded to 8-octet boundary
///
/// Route preference values:
/// - 00: Medium preference (default)
/// - 01: High preference (prefer this route)
/// - 10: Reserved (must not be used)
/// - 11: Low preference (use only if no better routes available)
///
/// RFC 4191 (Default Router Preferences and More-Specific Routes)
pub const ROUTE_OPT: u8 = 24;

/// Recursive DNS Server (RDNSS) option type (25)
///
/// This option provides IPv6 addresses of Recursive DNS Servers that hosts should use
/// for DNS resolution. This enables DNS server configuration via Router Advertisement
/// without requiring DHCPv6, supporting pure SLAAC environments.
///
/// Option format (RFC 6106 Section 5.1):
/// - Type: 25 (1 octet)
/// - Length: Variable (1 octet) - (1 + 2*N) where N = number of DNS servers
/// - Reserved: Must be zero (2 octets)
/// - Lifetime: DNS server validity period in seconds (4 octets)
/// - Addresses: One or more IPv6 addresses of DNS servers (16 octets each)
///
/// Lifetime values:
/// - 0: RDNSS addresses immediately invalid (remove from configuration)
/// - 1-0xFFFFFFFF: Validity period in seconds
/// - Typical: 2 × Router Lifetime to ensure continuity
///
/// RFC 6106 Section 5.1
pub const RDNSS_OPT: u8 = 25;

/// DNS Search List (DNSSL) option type (31)
///
/// This option provides a list of DNS domain suffixes to be used by hosts when resolving
/// hostnames (DNS search list). This enables automatic domain suffix completion for
/// short hostnames, similar to the "search" directive in /etc/resolv.conf.
///
/// Option format (RFC 6106 Section 5.2):
/// - Type: 31 (1 octet)
/// - Length: Variable (1 octet) - depends on number and length of domain names
/// - Reserved: Must be zero (2 octets)
/// - Lifetime: Search list validity period in seconds (4 octets)
/// - Domain Names: One or more domain names in DNS name format (variable length)
///
/// DNS name format:
/// Domain names are encoded in standard DNS format (RFC 1035):
/// - Each label prefixed by length octet
/// - Terminated by zero-length label
/// - Example: "example.com" → 7 "example" 3 "com" 0
/// - Padded to 8-octet boundary
///
/// RFC 6106 Section 5.2
pub const DNSSL_OPT: u8 = 31;

/// ICMPv6 Echo Request/Reply packet structure for IPv6 ping operations
///
/// This structure defines the format of ICMPv6 Echo Request (type 128) and Echo Reply
/// (type 129) messages used for IPv6 reachability testing. In dnsmasq context, this
/// structure is used to perform address conflict detection via ping testing before
/// assigning SLAAC addresses or DHCPv6 addresses to ensure they are not already in use.
///
/// # Layout
///
/// Size: 8 bytes (fixed ICMPv6 echo message header)
///
/// # Usage
///
/// Used for SLAAC address confirmation (ping test for duplicate detection) and
/// for verifying DHCPv6-assigned addresses are not in use. Transmitted to candidate
/// address to check for existing host before assignment.
///
/// # RFC Compliance
///
/// - RFC 4443 Section 4.1: ICMPv6 Echo Request Message (type 128)
/// - RFC 4443 Section 4.2: ICMPv6 Echo Reply Message (type 129)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PingPacket {
    /// ICMPv6 message type
    ///
    /// - 128: Echo Request (ping query sent to test address availability)
    /// - 129: Echo Reply (response from host at tested address, indicating address is in use)
    pub type_: u8,

    /// ICMPv6 message code (always 0 for Echo Request/Reply)
    ///
    /// Must be set to 0 per RFC 4443. Non-zero values are invalid for echo messages.
    pub code: u8,

    /// ICMPv6 checksum covering entire ICMPv6 message and IPv6 pseudo-header
    ///
    /// Computed over ICMPv6 message plus IPv6 pseudo-header (source, destination,
    /// length, next header). Must be validated on receipt and computed on transmission.
    /// Network byte order (big-endian).
    pub checksum: u16,

    /// Echo identifier for matching requests with replies
    ///
    /// Used to distinguish multiple concurrent ping operations. Typically set to
    /// process ID or random value. Echo Reply must copy this value from Echo Request.
    /// Network byte order (big-endian).
    pub identifier: u16,

    /// Echo sequence number for ordering and duplicate detection
    ///
    /// Incremented for each echo request sent. Enables detection of lost packets
    /// and out-of-order delivery. Echo Reply must copy this value from Echo Request.
    /// Network byte order (big-endian).
    pub sequence_no: u16,
}

/// ICMPv6 Router Advertisement message structure per RFC 4861
///
/// This structure defines the base Router Advertisement message format transmitted by
/// IPv6 routers to advertise their presence, network parameters, and address prefixes
/// to hosts on the local link. Router Advertisements enable IPv6 Stateless Address
/// Autoconfiguration (SLAAC) and coordinate with DHCPv6 for managed addressing.
///
/// # Description
///
/// Router Advertisement messages are sent periodically (unsolicited) and in response
/// to Router Solicitation messages (solicited). The RA packet header is followed by
/// zero or more options including prefix information, RDNSS (DNS servers), DNSSL
/// (DNS search list), MTU, and other network parameters.
///
/// # Layout
///
/// Size: 16 bytes (fixed ICMPv6 RA message header, options follow separately)
///
/// # Usage
///
/// Created for periodic RA transmission to FF02::1 (all-nodes). Flags field (M and O bits)
/// control DHCPv6 operational mode (stateful/stateless). Hop limit field advertises
/// suggested default hop limit for outgoing packets. Lifetime field specifies router's
/// validity as default router. Followed by `PrefixOpt` structures advertising on-link prefixes.
///
/// # RFC Compliance
///
/// - RFC 4861 Section 4.2: Router Advertisement Message Format
/// - RFC 4861 Section 6.2.3: Router Advertisement Processing by hosts
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RaPacket {
    /// ICMPv6 message type (134 for Router Advertisement)
    ///
    /// Must be set to 134 (ND_ROUTER_ADVERT) to identify this as a Router Advertisement.
    /// Hosts process only ICMPv6 type 134 messages as Router Advertisements.
    pub type_: u8,

    /// ICMPv6 message code (always 0 for Router Advertisement)
    ///
    /// Must be set to 0 per RFC 4861. Non-zero values cause the message to be discarded.
    pub code: u8,

    /// ICMPv6 checksum covering entire RA message and IPv6 pseudo-header
    ///
    /// Computed over ICMPv6 message (including all options) plus IPv6 pseudo-header.
    /// Receivers must validate checksum; invalid checksums cause message discard.
    /// Network byte order (big-endian).
    pub checksum: u16,

    /// Current Hop Limit field (suggested default hop limit for outgoing packets)
    ///
    /// Advertises the hop limit value hosts should use in outgoing IPv6 packets.
    /// Value 0 means unspecified (router makes no recommendation).
    /// Typical values: 64 (recommended default), 255 (maximum).
    ///
    /// Hosts receiving this value should configure their default hop limit accordingly.
    pub hop_limit: u8,

    /// RA flags byte controlling address configuration behavior
    ///
    /// Bit layout (MSB to LSB):
    /// - Bit 7 (M): Managed address configuration flag (1 = use DHCPv6 for addresses)
    /// - Bit 6 (O): Other configuration flag (1 = use DHCPv6 for non-address config)
    /// - Bit 5 (H): Home Agent flag (Mobile IPv6, not used by dnsmasq)
    /// - Bits 4-3: Router preference (00=medium, 01=high, 11=low)
    /// - Bit 2 (Proxy): Proxy flag (not used by dnsmasq)
    /// - Bits 1-0: Reserved (must be 0)
    ///
    /// # Dnsmasq Usage
    ///
    /// - M=1, O=0: Stateful DHCPv6 (clients get addresses via DHCPv6)
    /// - M=0, O=1: Stateless DHCPv6 (clients use SLAAC for addresses, DHCPv6 for config)
    /// - M=1, O=1: Stateful DHCPv6 with additional configuration
    /// - M=0, O=0: SLAAC only (no DHCPv6 used)
    ///
    /// Configured via dhcp-range option parameters in dnsmasq.conf.
    pub flags: u8,

    /// Router Lifetime in seconds (validity as default router)
    ///
    /// Specifies the maximum time (in seconds) this router should be used as a
    /// default router. Value 0 means the router is not a default router.
    /// Typical values: 1800 seconds (30 minutes) to 9000 seconds (2.5 hours).
    ///
    /// Hosts use this value to determine when to expire the default router entry
    /// from their routing table. Dnsmasq typically sets this to 3 times the RA
    /// transmission interval to ensure continuous router availability.
    ///
    /// Network byte order (big-endian).
    pub lifetime: u16,

    /// Reachable Time in milliseconds for Neighbor Unreachability Detection
    ///
    /// Time a neighbor is considered reachable after receiving a reachability
    /// confirmation. Value 0 means unspecified (router makes no recommendation).
    /// Typical values: 30000 milliseconds (30 seconds).
    ///
    /// Used by hosts for Neighbor Unreachability Detection (NUD) to determine
    /// when to probe neighbors for continued reachability.
    ///
    /// Network byte order (big-endian).
    pub reachable_time: u32,

    /// Retransmit Timer in milliseconds for Neighbor Solicitation retransmissions
    ///
    /// Time between retransmitted Neighbor Solicitation messages when performing
    /// address resolution or Neighbor Unreachability Detection. Value 0 means
    /// unspecified (router makes no recommendation).
    /// Typical values: 1000 milliseconds (1 second).
    ///
    /// Hosts use this value to configure their NS retransmission timer for
    /// address resolution and duplicate address detection.
    ///
    /// Network byte order (big-endian).
    pub retrans_time: u32,
}

/// ICMPv6 Neighbor Solicitation/Advertisement packet structure per RFC 4861
///
/// This structure defines the format of ICMPv6 Neighbor Solicitation (type 135) and
/// Neighbor Advertisement (type 136) messages used for IPv6 address resolution,
/// duplicate address detection, and neighbor reachability verification. In dnsmasq
/// context, this structure is used for duplicate address detection before assigning
/// IPv6 addresses via SLAAC or DHCPv6.
///
/// # Description
///
/// Neighbor Solicitation messages query for the link-layer address of a target IPv6
/// address (address resolution) or test if an address is already in use (duplicate
/// address detection). Neighbor Advertisement messages respond to solicitations or
/// announce address changes.
///
/// # Layout
///
/// Size: 24 bytes (8-byte header + 16-byte IPv6 address)
///
/// # Usage
///
/// Used for duplicate address detection (send NS, wait for NA reply) and to verify
/// DHCPv6-assigned addresses are not already in use. Neighbor Solicitation sent to
/// solicited-node multicast address of target. Neighbor Advertisement response
/// indicates address is in use (conflict detected).
///
/// # RFC Compliance
///
/// - RFC 4861 Section 4.3: Neighbor Solicitation Message Format
/// - RFC 4861 Section 4.4: Neighbor Advertisement Message Format
/// - RFC 4862 Section 5.4: Duplicate Address Detection procedure
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NeighPacket {
    /// ICMPv6 message type
    ///
    /// - 135: Neighbor Solicitation (query for address or duplicate address detection)
    /// - 136: Neighbor Advertisement (response or unsolicited announcement)
    ///
    /// Dnsmasq primarily sends Neighbor Solicitations for duplicate address detection.
    pub type_: u8,

    /// ICMPv6 message code (always 0 for Neighbor Solicitation/Advertisement)
    ///
    /// Must be set to 0 per RFC 4861. Non-zero values cause the message to be discarded.
    pub code: u8,

    /// ICMPv6 checksum covering entire NS/NA message and IPv6 pseudo-header
    ///
    /// Computed over ICMPv6 message (including options) plus IPv6 pseudo-header.
    /// Must be validated on receipt and computed on transmission.
    /// Network byte order (big-endian).
    pub checksum: u16,

    /// Flags field (for Neighbor Advertisement) or reserved (for Neighbor Solicitation)
    ///
    /// For Neighbor Solicitation: Must be set to 0 on transmission, ignored on receipt.
    ///
    /// For Neighbor Advertisement (when type=136):
    /// - Bit 31 (R): Router flag (1 if sender is a router)
    /// - Bit 30 (S): Solicited flag (1 if advertisement is in response to NS)
    /// - Bit 29 (O): Override flag (1 to override existing cache entry)
    /// - Bits 28-0: Reserved (must be 0)
    ///
    /// Network byte order (big-endian).
    pub flags: u32,

    /// Target IPv6 address for resolution or duplicate detection
    ///
    /// For Neighbor Solicitation:
    /// - In address resolution: The IPv6 address for which link-layer address is sought
    /// - In duplicate address detection: The tentative IPv6 address being tested
    ///
    /// For Neighbor Advertisement:
    /// - The IPv6 address being advertised or for which the advertisement is a response
    ///
    /// # Duplicate Address Detection Usage
    ///
    /// When dnsmasq tests if a SLAAC or DHCPv6 address is available, it sends a
    /// Neighbor Solicitation with source address :: (unspecified) and target address
    /// set to the candidate address. If any node responds with Neighbor Advertisement,
    /// the address is in use and must not be assigned.
    ///
    /// Must not be a multicast address (except for DAD, where checks are performed).
    pub target: Ipv6Addr,
}

impl Default for NeighPacket {
    fn default() -> Self {
        Self { type_: 0, code: 0, checksum: 0, flags: 0, target: Ipv6Addr::UNSPECIFIED }
    }
}

/// Prefix Information option for ICMPv6 Router Advertisement per RFC 4861
///
/// This structure defines the Prefix Information option (type 3) included in Router
/// Advertisement messages to advertise IPv6 prefixes available for Stateless Address
/// Autoconfiguration (SLAAC) and to specify whether prefixes are on-link for direct
/// communication. Multiple prefix options can be included in a single RA message to
/// advertise multiple prefixes.
///
/// # Description
///
/// The Prefix Information option communicates IPv6 address prefixes that hosts can
/// use to autoconfigure addresses (via SLAAC), determine on-link destinations, and
/// manage address lifetimes. The A (autonomous) flag indicates whether hosts should
/// use the prefix for SLAAC, while the L (on-link) flag indicates whether the prefix
/// is on the local link.
///
/// # Layout
///
/// Size: 32 bytes (fixed size for RFC 4861 prefix information option)
///
/// # Usage
///
/// Created for each configured prefix to be advertised. Multiple `PrefixOpt` structures
/// can follow `RaPacket` in single RA message. A flag (Autonomous) controls whether
/// hosts use prefix for SLAAC addressing. L flag (On-link) indicates whether prefix
/// destinations are on local link. Valid lifetime specifies how long addresses derived
/// from prefix remain valid. Preferred lifetime specifies how long addresses are
/// preferred for new connections.
///
/// # Integration with DHCPv6
///
/// When M flag in RA is set (stateful DHCPv6), prefix may still be advertised but
/// hosts obtain addresses from DHCPv6 instead of SLAAC. Prefix information is used
/// for on-link determination even when A flag is 0.
///
/// # RFC Compliance
///
/// - RFC 4861 Section 4.6.2: Prefix Information Option Format
/// - RFC 4862 Section 5.5.3: Router Advertisement Processing (prefix information)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PrefixOpt {
    /// Option type identifier (3 for Prefix Information)
    ///
    /// Must be set to 3 (ICMP6_OPT_PREFIX) to identify this as a Prefix Information
    /// option. Hosts process only type 3 options as prefix advertisements.
    pub type_: u8,

    /// Option length in units of 8 octets (always 4 for prefix information)
    ///
    /// Must be set to 4, indicating 32 bytes (4 × 8 octets) for the complete prefix
    /// information option including header and prefix address.
    ///
    /// Used by option parsing code to skip to next option in RA message.
    pub len: u8,

    /// Prefix length in bits (typically 64 for standard IPv6 subnets)
    ///
    /// Number of leading bits in the prefix that are valid. Hosts use this value
    /// when forming addresses via SLAAC (remaining bits are interface identifier).
    ///
    /// Valid range: 0-128 bits
    ///
    /// Common values:
    /// - 64: Standard IPv6 subnet prefix (RFC 4291 recommendation)
    /// - 48: Site-level aggregation prefix
    /// - 32: Provider-level aggregation
    ///
    /// For SLAAC, RFC 4862 requires prefix length ≤ 64 bits to accommodate 64-bit
    /// interface identifiers (EUI-64 or privacy extensions).
    pub prefix_len: u8,

    /// Prefix flags controlling address autoconfiguration and on-link behavior
    ///
    /// Bit layout (MSB to LSB):
    /// - Bit 7 (L): On-link flag (1 = prefix is on-link, 0 = no on-link determination)
    /// - Bit 6 (A): Autonomous address-configuration flag (1 = use for SLAAC, 0 = no SLAAC)
    /// - Bit 5 (R): Router Address flag (not used by dnsmasq, must be 0)
    /// - Bits 4-0: Reserved (must be 0)
    ///
    /// # Dnsmasq Typical Configuration
    ///
    /// - L=1, A=1: Prefix is on-link and should be used for SLAAC (normal SLAAC mode)
    /// - L=1, A=0: Prefix is on-link but addresses assigned via DHCPv6 (stateful mode)
    /// - L=0, A=0: Prefix advertised for route information only
    ///
    /// # On-Link Determination
    ///
    /// When L=1, hosts consider destinations within this prefix to be on the local
    /// link and attempt direct communication without routing through the default router.
    ///
    /// # Autonomous Configuration
    ///
    /// When A=1, hosts use this prefix to autoconfigure IPv6 addresses by combining
    /// the prefix with their interface identifier (EUI-64 or privacy extensions).
    pub flags: u8,

    /// Valid lifetime in seconds (time prefix remains valid for on-link determination)
    ///
    /// Specifies how long (in seconds) the prefix is valid for on-link determination
    /// and how long addresses autoconfigured from this prefix remain valid. When this
    /// lifetime expires, addresses become invalid and must not be used for new
    /// connections or communication.
    ///
    /// Special values:
    /// - 0xFFFFFFFF (infinity): Prefix/addresses never expire
    /// - 0: Prefix/addresses immediately invalid (used to deprecate prefix)
    ///
    /// Typical values: 2592000 seconds (30 days) to 7200 seconds (2 hours)
    ///
    /// # Relationship to Preferred Lifetime
    ///
    /// Must be ≥ preferred_lifetime. Valid lifetime represents the upper bound on
    /// address usability, while preferred lifetime represents when addresses should
    /// stop being used for new connections.
    ///
    /// Network byte order (big-endian).
    pub valid_lifetime: u32,

    /// Preferred lifetime in seconds (time addresses are preferred for new connections)
    ///
    /// Specifies how long (in seconds) addresses autoconfigured from this prefix
    /// should remain preferred for use in new connections. After this time, addresses
    /// become deprecated (still valid but not preferred), and hosts should prefer
    /// other non-deprecated addresses for new communications.
    ///
    /// Special values:
    /// - 0xFFFFFFFF (infinity): Addresses never deprecate
    /// - 0: Addresses immediately deprecated (valid but not preferred)
    ///
    /// Typical values: 604800 seconds (7 days) to 1800 seconds (30 minutes)
    ///
    /// # Address Deprecation
    ///
    /// When preferred lifetime expires but valid lifetime has not, addresses enter
    /// deprecated state: existing connections continue normally, but new connections
    /// should use preferred addresses. This enables graceful prefix renumbering.
    ///
    /// Must be ≤ valid_lifetime per RFC 4861.
    /// Network byte order (big-endian).
    pub preferred_lifetime: u32,

    /// Reserved field (must be 0)
    ///
    /// Reserved for future use. Must be set to 0 on transmission and ignored on receipt.
    /// Positioned after lifetimes, before prefix address in option structure.
    ///
    /// Network byte order (big-endian) as 32-bit field.
    pub reserved: u32,

    /// IPv6 address prefix being advertised
    ///
    /// The IPv6 prefix that hosts use for SLAAC, on-link determination, or routing.
    /// Only the bits specified by prefix_len are significant; remaining bits should
    /// be set to 0 but are ignored by receivers.
    ///
    /// # SLAAC Address Formation
    ///
    /// When A flag is set, hosts form complete IPv6 addresses by combining this prefix
    /// with their 64-bit interface identifier:
    /// - Address = prefix (first prefix_len bits) + interface ID (remaining bits)
    /// - Interface ID derived from MAC address (EUI-64) or random (privacy extensions)
    ///
    /// # On-Link Determination
    ///
    /// When L flag is set, hosts compare destination addresses against this prefix
    /// to determine if destination is on the local link (direct communication) or
    /// off-link (must route through default router).
    ///
    /// # Common Prefixes
    ///
    /// - 2001:db8::/32: Documentation prefix (RFC 3849)
    /// - fd00::/8: Unique Local Addresses (ULA, RFC 4193)
    /// - fe80::/10: Link-local addresses (not typically advertised in prefix options)
    /// - Global Unicast: Provider-assigned prefixes (e.g., 2001::/16 range)
    ///
    /// Must not be a link-local address (fe80::/10) or multicast address (ff00::/8).
    pub prefix: Ipv6Addr,
}

impl Default for PrefixOpt {
    fn default() -> Self {
        Self {
            type_: 0,
            len: 0,
            prefix_len: 0,
            flags: 0,
            valid_lifetime: 0,
            preferred_lifetime: 0,
            reserved: 0,
            prefix: Ipv6Addr::UNSPECIFIED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_packet_size() {
        assert_eq!(std::mem::size_of::<PingPacket>(), 8);
    }

    #[test]
    fn test_ra_packet_size() {
        assert_eq!(std::mem::size_of::<RaPacket>(), 16);
    }

    #[test]
    fn test_neigh_packet_size() {
        assert_eq!(std::mem::size_of::<NeighPacket>(), 24);
    }

    #[test]
    fn test_prefix_opt_size() {
        assert_eq!(std::mem::size_of::<PrefixOpt>(), 32);
    }

    #[test]
    fn test_icmpv6_type_constants() {
        assert_eq!(ICMP6_ECHO_REQUEST, 128);
        assert_eq!(ICMP6_ECHO_REPLY, 129);
        assert_eq!(ICMP6_ROUTER_ADVERT, 134);
        assert_eq!(ICMP6_NEIGH_SOLICIT, 135);
        assert_eq!(ICMP6_NEIGH_ADVERT, 136);
    }

    #[test]
    fn test_nd_option_constants() {
        assert_eq!(SOURCE_MAC_OPT, 1);
        assert_eq!(PREFIX_OPT, 3);
        assert_eq!(MTU_OPT, 5);
        assert_eq!(INTERVAL_OPT, 7);
        assert_eq!(ROUTE_OPT, 24);
        assert_eq!(RDNSS_OPT, 25);
        assert_eq!(DNSSL_OPT, 31);
    }

    #[test]
    fn test_multicast_addresses() {
        assert_eq!(ALL_NODES, "FF02::1");
        assert_eq!(ALL_ROUTERS, "FF02::2");
    }

    #[test]
    fn test_default_implementations() {
        let ping = PingPacket::default();
        assert_eq!(ping.type_, 0);
        assert_eq!(ping.code, 0);

        let ra = RaPacket::default();
        assert_eq!(ra.type_, 0);
        assert_eq!(ra.code, 0);

        let neigh = NeighPacket::default();
        assert_eq!(neigh.type_, 0);
        assert_eq!(neigh.target, Ipv6Addr::UNSPECIFIED);

        let prefix = PrefixOpt::default();
        assert_eq!(prefix.type_, 0);
        assert_eq!(prefix.prefix, Ipv6Addr::UNSPECIFIED);
    }
}
