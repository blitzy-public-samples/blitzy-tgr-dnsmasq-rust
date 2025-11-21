// Copyright (c) 2000-2025 Simon Kelley
// This file is part of the dnsmasq Rust port
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! DHCPv4 Protocol Constants
//!
//! This module provides comprehensive DHCPv4 protocol constants including port numbers,
//! message types, option codes, and buffer sizes per RFC 2131 (Dynamic Host Configuration
//! Protocol) and RFC 2132 (DHCP Options and BOOTP Vendor Extensions).
//!
//! # Purpose
//!
//! This module serves as the authoritative source for all DHCPv4 wire protocol constants,
//! ensuring type-safe protocol implementation without magic numbers. All constants maintain
//! 100% numeric value compatibility with the C implementation for wire protocol correctness.
//!
//! # Organization
//!
//! Constants are grouped into logical sections:
//! - **Network Ports**: Standard and alternate UDP port numbers for DHCP communication
//! - **Message Types**: DHCP protocol state machine message identifiers (Option 53 values)
//! - **Options**: All RFC 2132 option codes and extensions
//! - **Suboptions**: Relay agent and PXE vendor-specific suboption codes
//! - **Buffer Sizes**: Protocol buffer sizing constants
//! - **Operation Codes**: BOOTP operation codes for request/reply distinction
//! - **Flags**: Packet flag bit masks
//! - **Enterprise Numbers**: IANA-assigned vendor identification numbers
//!
//! # RFC Compliance
//!
//! - RFC 2131: Dynamic Host Configuration Protocol (message format and exchange)
//! - RFC 2132: DHCP Options and BOOTP Vendor Extensions
//! - RFC 3046: DHCP Relay Agent Information Option
//! - RFC 3527: Link Selection suboption for DHCP Relay Agent
//! - RFC 4039: Rapid Commit Option
//! - RFC 4388: DHCP Leasequery protocol
//! - Intel PXE Specification 2.1: Network boot protocol extensions
//!
//! # Example Usage
//!
//! ```rust
//! use dnsmasq::dhcp::v4::constants::*;
//! use std::net::Ipv4Addr;
//!
//! // Check message type
//! let msg_type = MSG_TYPE_DISCOVER;
//! if msg_type == MSG_TYPE_DISCOVER {
//!     // Handle DHCPDISCOVER
//! }
//!
//! // Build option list
//! let server_ip = Ipv4Addr::new(192, 168, 1, 1);
//! let lease_time: u32 = 86400; // 24 hours in seconds
//! let options = vec![
//!     (OPTION_MESSAGE_TYPE, vec![MSG_TYPE_OFFER]),
//!     (OPTION_SERVER_IDENTIFIER, server_ip.octets().to_vec()),
//!     (OPTION_LEASE_TIME, lease_time.to_be_bytes().to_vec()),
//! ];
//! # assert_eq!(options.len(), 3);
//! ```

// ================================================================================================
// Network Port Definitions
// ================================================================================================

/// Standard `DHCPv4` server listening port (privileged port, requires root/capabilities)
///
/// Server binds to this port to receive DHCPDISCOVER, DHCPREQUEST, DHCPRELEASE,
/// DHCPDECLINE, and DHCPINFORM messages from clients on port 68.
///
/// # RFC Reference
/// RFC 2131 Section 4.1: "DHCP messages from a client to a server are sent to the
/// 'DHCP server' port (67), and DHCP messages from a server to a client are sent
/// to the 'DHCP client' port (68)."
pub const PORT_SERVER: u16 = 67;

/// Standard `DHCPv4` client listening port
///
/// Clients bind to this port to receive DHCPOFFER and DHCPACK messages from servers.
/// Server sends responses to this port even for clients without IP address yet.
///
/// # RFC Reference
/// RFC 2131 Section 4.1
pub const PORT_CLIENT: u16 = 68;

/// Alternate `DHCPv4` server port for non-privileged or testing deployments
///
/// Non-standard port avoiding privileged binding requirement. Configured via
/// `--dhcp-alternate-port` option. Used in development and specialized scenarios.
///
/// # Note
/// This is a dnsmasq extension, not defined in RFC 2131.
pub const PORT_SERVER_ALT: u16 = 1067;

/// Alternate `DHCPv4` client port corresponding to alternate server port
///
/// Client-side alternate port for use with `PORT_SERVER_ALT` deployments.
///
/// # Note
/// This is a dnsmasq extension, not defined in RFC 2131.
pub const PORT_CLIENT_ALT: u16 = 1068;

/// PXE (Preboot Execution Environment) proxy DHCP port
///
/// PXE proxy mode uses this port to provide boot parameters (boot filename,
/// TFTP server) without providing IP address assignment. Allows coexistence
/// with existing DHCP infrastructure for network boot scenarios.
///
/// # RFC Reference
/// Intel PXE Specification 2.1 Section 2.2.5
pub const PORT_PXE: u16 = 4011;

// ================================================================================================
// Protocol Constants and Buffer Sizes
// ================================================================================================

/// DHCP magic cookie value for option field identification
///
/// Four-byte constant (99.130.83.99 in dotted decimal, 0x63825363 in hex) placed
/// at start of options field to distinguish DHCP packets from legacy BOOTP packets.
///
/// # RFC Reference
/// RFC 2131 Section 3: "The first four octets of the 'options' field of the DHCP
/// message contain the (decimal) values 99, 130, 83 and 99."
pub const MAGIC_COOKIE: u32 = 0x6382_5363;

/// Maximum DHCP option data buffer size including null terminator
///
/// `DHCPv4` options have maximum length of 255 bytes per RFC 2132. This buffer
/// size accommodates the maximum option data length (255) plus a terminating
/// null byte (1) for C string safety when options contain text data.
///
/// # Usage
/// Used for temporary option parsing buffers in packet processing.
///
/// # RFC Reference
/// RFC 2132 Section 2 (option format)
pub const DHCP_BUFF_SZ: usize = 256;

/// Minimum `DHCPv4` packet size to satisfy Linux in-kernel DHCP client
///
/// The Linux kernel's built-in DHCP client silently discards packets smaller
/// than 300 bytes regardless of actual packet validity. Dnsmasq pads outgoing
/// DHCP responses to this minimum size to ensure Linux kernel client compatibility.
///
/// # Note
/// This is a workaround for Linux kernel DHCP client implementation quirk, not
/// an RFC requirement. Standard DHCP minimum is 236 bytes (fixed fields) plus
/// variable options.
///
/// # Source
/// Linux kernel net/ipv4/ipconfig.c behavior, dnsmasq compatibility fix
pub const MIN_PACKETSZ: usize = 300;

/// Maximum hardware address length in DHCP packet
///
/// RFC 2131 specifies the client hardware address field (chaddr) as 16 octets.
/// While Ethernet MAC addresses are 6 octets, the larger field accommodates
/// other hardware types with longer addresses. Unused bytes are zero-padded.
///
/// # Usage
/// For Ethernet (htype=1), only first 6 bytes are used (per hlen=6).
///
/// # RFC Reference
/// RFC 2131 Section 2, Figure 1
pub const DHCP_CHADDR_MAX: usize = 16;

// ================================================================================================
// Operation Codes
// ================================================================================================

/// BOOTP request operation code
///
/// Value for the 'op' field indicating client-to-server message (BOOTREQUEST).
/// Used in DHCPDISCOVER, DHCPREQUEST, DHCPDECLINE, DHCPRELEASE, and DHCPINFORM messages.
///
/// # RFC Reference
/// RFC 2131 Section 2 (inherits from RFC 951 BOOTP)
pub const BOOTREQUEST: u8 = 1;

/// BOOTP reply operation code
///
/// Value for the 'op' field indicating server-to-client message (BOOTREPLY).
/// Used in DHCPOFFER and DHCPACK messages.
///
/// # RFC Reference
/// RFC 2131 Section 2 (inherits from RFC 951 BOOTP)
pub const BOOTREPLY: u8 = 2;

// ================================================================================================
// DHCP Message Types (Option 53 values)
// ================================================================================================

/// DHCP Message Type 1: DHCPDISCOVER
///
/// Client broadcasts to locate available DHCP servers and discover offered
/// network configuration. First message in four-way address allocation exchange.
///
/// # Protocol Flow
/// Client → Broadcast: DHCPDISCOVER
/// - Contains requested options (Option 55)
/// - May suggest IP address (Option 50)
/// - Broadcast to 255.255.255.255 from 0.0.0.0
///
/// # RFC Reference
/// RFC 2131 Section 3.1, Table 4
pub const MSG_TYPE_DISCOVER: u8 = 1;

/// DHCP Message Type 2: DHCPOFFER
///
/// Server unicasts or broadcasts offer of IP address and configuration to client.
/// Response to DHCPDISCOVER.
///
/// # Protocol Flow
/// Server → Client: DHCPOFFER
/// - Contains offered IP (yiaddr)
/// - Lease time (Option 51)
/// - Server identifier (Option 54)
/// - Requested configuration parameters
///
/// # RFC Reference
/// RFC 2131 Section 3.1, Table 4
pub const MSG_TYPE_OFFER: u8 = 2;

/// DHCP Message Type 3: DHCPREQUEST
///
/// Client broadcasts acceptance of server's offer (after DHCPOFFER), requests
/// renewal of existing lease (during RENEWING state), or confirms configuration
/// after reboot.
///
/// # Protocol Flow
/// Client → Broadcast/Server: DHCPREQUEST
/// - Includes server identifier (Option 54) to indicate which server's offer is accepted
/// - MUST include requested IP address (Option 50) in some scenarios
///
/// # RFC Reference
/// RFC 2131 Section 3.1, Table 4
pub const MSG_TYPE_REQUEST: u8 = 3;

/// DHCP Message Type 4: DHCPDECLINE
///
/// Client notifies server that offered address is already in use on network
/// (detected via ARP probe). Server MUST NOT allocate declined address to
/// another client for minimum time period.
///
/// # Protocol Flow
/// Client → Server: DHCPDECLINE
/// - Client restarts discovery process
///
/// # RFC Reference
/// RFC 2131 Section 3.1, Table 4
pub const MSG_TYPE_DECLINE: u8 = 4;

/// DHCP Message Type 5: DHCPACK
///
/// Server acknowledges and confirms client's address allocation or renewal request.
/// Final message in successful four-way exchange (after DHCPREQUEST).
///
/// # Protocol Flow
/// Server → Client: DHCPACK
/// - Contains allocated IP (yiaddr)
/// - Lease time (Option 51)
/// - Complete network configuration
/// - Client enters BOUND state and configures interface
///
/// # RFC Reference
/// RFC 2131 Section 3.1, Table 4
pub const MSG_TYPE_ACK: u8 = 5;

/// DHCP Message Type 6: DHCPNAK
///
/// Server rejects client's DHCPREQUEST. Sent when requested address is not
/// available, not appropriate for network, or lease has expired.
///
/// # Protocol Flow
/// Server → Client: DHCPNAK
/// - Client MUST stop using address
/// - Client returns to initialization (DHCPDISCOVER) state
///
/// # RFC Reference
/// RFC 2131 Section 3.1, Table 4
pub const MSG_TYPE_NAK: u8 = 6;

/// DHCP Message Type 7: DHCPRELEASE
///
/// Client notifies server it is releasing and relinquishing assigned IP address.
/// Sent when client gracefully shuts down or no longer needs address.
///
/// # Protocol Flow
/// Client → Server: DHCPRELEASE
/// - Server marks address available for reallocation
/// - Unicast to server identifier (Option 54)
///
/// # RFC Reference
/// RFC 2131 Section 3.1, Table 4
pub const MSG_TYPE_RELEASE: u8 = 7;

/// DHCP Message Type 8: DHCPINFORM
///
/// Client requests local configuration parameters but already has externally
/// configured IP address. Used when client has static IP but wants DHCP-provided
/// configuration (DNS servers, domain name, etc.).
///
/// # Protocol Flow
/// Client → Server: DHCPINFORM
/// - Server responds with DHCPACK containing configuration but no address assignment
///
/// # RFC Reference
/// RFC 2131 Section 3.4
pub const MSG_TYPE_INFORM: u8 = 8;

/// DHCP Message Type 9: DHCPFORCERENEW
///
/// Server instructs client to renew lease immediately. Enables server to
/// reconfigure clients, force rebinding, or prepare for server maintenance.
///
/// # Security
/// Requires authentication per RFC 3203.
///
/// # Protocol Flow
/// Server → Client: DHCPFORCERENEW
/// - Client MUST enter RENEWING state and send DHCPREQUEST
///
/// # RFC Reference
/// RFC 3203 Section 4
pub const MSG_TYPE_FORCERENEW: u8 = 9;

/// DHCP Message Type 10: DHCPLEASEQUERY
///
/// External query to DHCP server requesting lease information for specific
/// IP address, MAC address, or client identifier. Enables external lease
/// database synchronization, troubleshooting, and network management integration.
///
/// # Protocol Flow
/// External System → Server: DHCPLEASEQUERY
/// - Server responds with DHCPLEASEACTIVE, DHCPLEASEUNKNOWN, or DHCPLEASEUNASSIGNED
///
/// # RFC Reference
/// RFC 4388 Section 6.1
pub const MSG_TYPE_LEASEQUERY: u8 = 10;

/// DHCP Message Type 11: DHCPLEASEUNASSIGNED
///
/// Server response to DHCPLEASEQUERY indicating queried IP address exists in
/// server's address pool but is not currently assigned to any client.
///
/// # Meaning
/// Address is available for allocation.
///
/// # RFC Reference
/// RFC 4388 Section 6.2.1
pub const MSG_TYPE_LEASEUNASSIGNED: u8 = 11;

/// DHCP Message Type 12: DHCPLEASEUNKNOWN
///
/// Server response to DHCPLEASEQUERY indicating queried IP address is not
/// within server's authority or address pools.
///
/// # Meaning
/// Server has no information about the queried address.
///
/// # RFC Reference
/// RFC 4388 Section 6.2.2
pub const MSG_TYPE_LEASEUNKNOWN: u8 = 12;

/// DHCP Message Type 13: DHCPLEASEACTIVE
///
/// Server response to DHCPLEASEQUERY indicating queried address is currently
/// leased to a client. Response includes lease information: client hardware
/// address, client identifier, lease expiration time, hostname (if known).
///
/// # RFC Reference
/// RFC 4388 Section 6.2.3
pub const MSG_TYPE_LEASEACTIVE: u8 = 13;

// ================================================================================================
// DHCP Option Codes (RFC 2132 and extensions)
// ================================================================================================

/// Option 0: Pad option for alignment (no data)
///
/// Used to pad option field to alignment boundaries. Contains no length or data bytes.
///
/// # RFC Reference
/// RFC 2132 Section 3.1: "The pad option can be used to cause subsequent fields
/// to align on word boundaries."
pub const OPTION_PAD: u8 = 0;

/// Option 1: Subnet Mask (4 bytes)
///
/// Specifies the client's subnet mask per RFC 950. Value is 4-byte IPv4 subnet mask.
///
/// # Example
/// 255.255.255.0 for /24 network
///
/// # RFC Reference
/// RFC 2132 Section 3.3
pub const OPTION_NETMASK: u8 = 1;

/// Option 3: Router (4+ bytes, multiple of 4)
///
/// List of router IP addresses on client's subnet, in order of preference.
/// Client typically uses first router as default gateway.
///
/// # Format
/// Minimum one router (4 bytes), multiple routers supported (8, 12, 16... bytes)
///
/// # RFC Reference
/// RFC 2132 Section 3.5
pub const OPTION_ROUTER: u8 = 3;

/// Option 6: Domain Name Server (4+ bytes, multiple of 4)
///
/// List of DNS recursive resolver IP addresses available to client, in order of preference.
///
/// # Format
/// Minimum one DNS server (4 bytes), multiple servers supported (8, 12, 16... bytes)
///
/// # RFC Reference
/// RFC 2132 Section 3.8
pub const OPTION_DNS_SERVER: u8 = 6;

/// Alias for `OPTION_DNS_SERVER` for C compatibility.
/// The C implementation uses `OPTION_DNSSERVER` naming.
pub const OPTION_DNSSERVER: u8 = OPTION_DNS_SERVER;

/// Option 12: Host Name (variable length string)
///
/// Specifies the client's hostname per RFC 1123, without domain suffix.
/// Used by client to inform server of desired hostname, or server to assign hostname.
///
/// # Format
/// Maximum length 255 bytes
///
/// # Example
/// "workstation1"
///
/// # RFC Reference
/// RFC 2132 Section 3.14
pub const OPTION_HOSTNAME: u8 = 12;

/// Option 15: Domain Name (variable length string)
///
/// Specifies the domain name for DNS resolution and hostname qualification.
/// Combined with `OPTION_HOSTNAME` forms FQDN.
///
/// # Example
/// "example.com"
///
/// # RFC Reference
/// RFC 2132 Section 3.17
pub const OPTION_DOMAIN_NAME: u8 = 15;

/// Alias for `OPTION_DOMAIN_NAME` for C compatibility.
/// The C implementation uses `OPTION_DOMAINNAME` naming.
pub const OPTION_DOMAINNAME: u8 = OPTION_DOMAIN_NAME;

/// Option 28: Broadcast Address (4 bytes)
///
/// Specifies the broadcast address for the client's subnet.
/// Used for subnet-directed broadcasts. Typically subnet address with host bits set to 1.
///
/// # Example
/// 192.168.1.255 for 192.168.1.0/24 network
///
/// # RFC Reference
/// RFC 2132 Section 5.3
pub const OPTION_BROADCAST: u8 = 28;

/// Option 43: Vendor-Specific Information (variable length)
///
/// Opaque vendor-specific data. Format and content defined by vendor (identified
/// by `OPTION_VENDOR_ID`). PXE uses this for boot menu and server discovery.
///
/// # RFC Reference
/// RFC 2132 Section 8.4
pub const OPTION_VENDOR_CLASS_OPT: u8 = 43;

/// Option 50: Requested IP Address (4 bytes)
///
/// Used by client in DHCPREQUEST to request specific IP address, or in DHCPDISCOVER
/// to suggest previously allocated address. Server may honor or ignore request.
///
/// # RFC Reference
/// RFC 2132 Section 9.1
pub const OPTION_REQUESTED_IP: u8 = 50;

/// Option 51: IP Address Lease Time (4 bytes, seconds)
///
/// Lease duration in seconds as 32-bit unsigned integer. Value 0xFFFFFFFF means
/// infinite lease.
///
/// # Typical Values
/// 3600 (1 hour) to 86400 (24 hours)
///
/// # Protocol
/// Client must renew before expiration.
///
/// # RFC Reference
/// RFC 2132 Section 9.2
pub const OPTION_LEASE_TIME: u8 = 51;

/// Option 52: Option Overload (1 byte)
///
/// Indicates that 'file' and/or 'sname' fields in DHCP packet contain
/// DHCP options instead of filename/server name.
///
/// # Values
/// - 1: 'file' contains options
/// - 2: 'sname' contains options
/// - 3: both contain options
///
/// # RFC Reference
/// RFC 2132 Section 9.3
pub const OPTION_OVERLOAD: u8 = 52;

/// Option 53: DHCP Message Type (1 byte) - REQUIRED
///
/// Identifies DHCP message type (DHCPDISCOVER=1, DHCPOFFER=2, DHCPREQUEST=3, etc.).
/// This option MUST be present in every DHCP message per RFC 2131.
///
/// # Values
/// See `MSG_TYPE`_* constants (DISCOVER through LEASEACTIVE)
///
/// # RFC Reference
/// RFC 2132 Section 9.6
pub const OPTION_MESSAGE_TYPE: u8 = 53;

/// Option 54: Server Identifier (4 bytes)
///
/// IP address of the DHCP server sending this message. Used by client to identify
/// which server's offer to accept in DHCPREQUEST, and by server to identify itself
/// in DHCPOFFER and DHCPACK.
///
/// # Protocol Requirement
/// MUST be included by server in DHCPOFFER and DHCPACK.
///
/// # RFC Reference
/// RFC 2132 Section 9.7
pub const OPTION_SERVER_IDENTIFIER: u8 = 54;

/// Option 55: Parameter Request List (variable length, list of option codes)
///
/// Client includes this in DHCPDISCOVER and DHCPREQUEST to indicate which options
/// it wants server to include in response. Each byte is an option code.
///
/// # Example
/// {1, 3, 6, 15} requests subnet mask, router, DNS, domain name
///
/// # RFC Reference
/// RFC 2132 Section 9.8
pub const OPTION_PARAMETER_LIST: u8 = 55;

/// Alias for `OPTION_PARAMETER_LIST` for C compatibility.
/// The C implementation uses `OPTION_REQUESTED_OPTIONS` naming.
/// RFC 2132 calls this "Parameter Request List".
pub const OPTION_REQUESTED_OPTIONS: u8 = OPTION_PARAMETER_LIST;

/// Option 56: Message (variable length string)
///
/// Error message string included by server in DHCPNAK to explain rejection,
/// or informational message. Human-readable text for logging/display.
///
/// # RFC Reference
/// RFC 2132 Section 9.9
pub const OPTION_MESSAGE: u8 = 56;

/// Option 57: Maximum DHCP Message Size (2 bytes)
///
/// Maximum DHCP message size client is willing to accept (minimum 576 bytes).
/// Server uses this to avoid fragmenting responses. Client includes in DHCPDISCOVER.
///
/// # RFC Reference
/// RFC 2132 Section 9.10
pub const OPTION_MAXMESSAGE: u8 = 57;

/// Option 58: Renewal Time Value (T1) (4 bytes, seconds)
///
/// Time interval from address assignment until client enters RENEWING state.
/// Typically 50% of lease time. Client begins renewing lease at T1 expiration.
///
/// # RFC Reference
/// RFC 2132 Section 9.11
pub const OPTION_T1: u8 = 58;

/// Option 59: Rebinding Time Value (T2) (4 bytes, seconds)
///
/// Time interval from address assignment until client enters REBINDING state.
/// Typically 87.5% of lease time. Client broadcasts rebind if renewal fails.
///
/// # RFC Reference
/// RFC 2132 Section 9.12
pub const OPTION_T2: u8 = 59;

/// Option 60: Vendor Class Identifier (variable length string)
///
/// Identifies vendor and client type. Used for client classification and
/// vendor-specific option delivery.
///
/// # PXE Usage
/// PXE clients include "`PXEClient`" string.
///
/// # Example
/// "PXEClient:Arch:00000:UNDI:002001"
///
/// # RFC Reference
/// RFC 2132 Section 9.13
pub const OPTION_VENDOR_ID: u8 = 60;

/// Option 61: Client Identifier (variable length)
///
/// Unique client identifier used instead of hardware address for lease binding.
/// Provides persistent identity across hardware changes.
///
/// # Format
/// 1-byte type code + identifier data
///
/// # RFC Reference
/// RFC 2132 Section 9.14
pub const OPTION_CLIENT_ID: u8 = 61;

/// Option 66: TFTP Server Name (variable length string)
///
/// Hostname or IP address (as string) of TFTP server for network boot.
/// Alternative to 'siaddr' field in DHCP packet. Used with `OPTION_FILENAME`.
///
/// # RFC Reference
/// RFC 2132 Section 9.4
pub const OPTION_SNAME: u8 = 66;

/// Option 67: Boot File Name (variable length string)
///
/// Boot filename for network boot clients (PXE, BOOTP). Path relative to
/// TFTP server root.
///
/// # Example
/// "pxelinux.0"
///
/// # Note
/// Alternative to 'file' field in DHCP packet.
///
/// # RFC Reference
/// RFC 2132 Section 9.5
pub const OPTION_FILENAME: u8 = 67;

/// Option 77: User Class (variable length)
///
/// User-defined classification string for grouping clients with similar
/// configuration requirements. Format vendor-specific. Used for policy routing.
///
/// # RFC Reference
/// RFC 3004
pub const OPTION_USER_CLASS: u8 = 77;

/// Option 80: Rapid Commit (0 bytes, flag option)
///
/// Enables two-message exchange (DHCPDISCOVER + DHCPACK) instead of four-message
/// (DISCOVER, OFFER, REQUEST, ACK). Presence of option indicates support/request.
///
/// # Requirement
/// Both client and server must support for use.
///
/// # RFC Reference
/// RFC 4039
pub const OPTION_RAPID_COMMIT: u8 = 80;

/// Option 81: Client FQDN (variable length)
///
/// Fully Qualified Domain Name option for dynamic DNS updates. Contains flags,
/// RCODE values, and FQDN string. Coordinates client hostname registration in DNS.
///
/// # RFC Reference
/// RFC 4702
pub const OPTION_CLIENT_FQDN: u8 = 81;

/// Option 82: Relay Agent Information (variable length, suboptions)
///
/// Added by DHCP relay agents to include circuit identification, remote ID,
/// and other relay-specific information. Contains suboptions (SUBOPT_* constants).
///
/// # RFC Reference
/// RFC 3046
pub const OPTION_AGENT_ID: u8 = 82;

/// Option 91: Client Last Transaction Time (4 bytes, seconds)
///
/// Used in DHCPLEASEQUERY responses to indicate seconds since client's last
/// transaction with server. Part of leasequery protocol for external lease queries.
///
/// # Usage
/// Enables external systems to query DHCP server about client lease status
/// and determine how long ago client last communicated with server.
///
/// # RFC Reference
/// RFC 4388 Section 6.1
pub const OPTION_LAST_TRANSACTION: u8 = 91;

/// Option 92: Associated IP (4+ bytes, multiple of 4)
///
/// Used in DHCPLEASEQUERY to query leases associated with specific IP addresses.
/// Contains one or more IPv4 addresses for bulk lease status queries.
///
/// # Format
/// Multiple of 4 bytes, each 4-byte block represents one IPv4 address.
///
/// # RFC Reference
/// RFC 4388 Section 6.2
pub const OPTION_ASSOCIATED_IP: u8 = 92;

/// Option 93: Client System Architecture (2 bytes)
///
/// Identifies client CPU architecture for PXE network boot.
///
/// # Values
/// - 0: x86 BIOS
/// - 6: x86 UEFI
/// - 7: x64 UEFI
/// - 9: EFI BC
/// - 10: ARM32 UEFI
/// - 11: ARM64 UEFI
///
/// # Usage
/// Used to select appropriate boot image per architecture.
///
/// # RFC Reference
/// RFC 4578 Section 2.1
pub const OPTION_ARCH: u8 = 93;

/// Option 97: UUID/GUID-based Client Identifier (17 bytes)
///
/// PXE client machine identifier. First byte is type (0), followed by 16-byte
/// UUID/GUID. Provides unique client identification for PXE environments.
///
/// # RFC Reference
/// RFC 4578 Section 2.5
pub const OPTION_PXE_UUID: u8 = 97;

/// Option 118: Subnet Selection (4 bytes)
///
/// Allows client to specify which subnet it wants address from when behind
/// relay agent. Used for explicit subnet selection in multi-subnet environments.
///
/// # RFC Reference
/// RFC 3011
pub const OPTION_SUBNET_SELECT: u8 = 118;

/// Option 119: Domain Search (variable length, DNS search list)
///
/// List of domain suffixes for DNS hostname resolution search. Encoded as
/// DNS wire format compressed domain names. Alternative to single `OPTION_DOMAIN_NAME`.
///
/// # Example
/// `["example.com", "internal.example.com"]` for multi-level domain searching
///
/// # Usage
/// Modern alternative to `OPTION_DOMAIN_NAME` (15) supporting multiple search domains.
/// Client tries each domain suffix in order when resolving unqualified hostnames.
///
/// # RFC Reference
/// RFC 3397
pub const OPTION_DOMAIN_SEARCH: u8 = 119;

/// Option 120: SIP Servers (variable length)
///
/// Session Initiation Protocol (SIP) server addresses for `VoIP` configuration.
/// Can contain IPv4 addresses or DNS names for SIP proxy servers.
///
/// # Format
/// Can be encoded as IPv4 addresses (4 bytes each) or DNS names.
///
/// # Usage
/// Enables automatic `VoIP` phone configuration by providing SIP server locations.
///
/// # RFC Reference
/// RFC 3361
pub const OPTION_SIP_SERVER: u8 = 120;

/// Option 124: Vendor-Identifying Vendor Class (variable length)
///
/// Extended vendor identification with enterprise number and vendor-specific data.
/// Format: 4-byte enterprise number + opaque vendor data. Uses IANA enterprise numbers.
///
/// # Format
/// 4-byte IANA enterprise number followed by vendor-specific class information.
///
/// # Usage
/// Allows vendors to provide detailed device classification information
/// beyond simple vendor ID string in `OPTION_VENDOR_ID` (60).
///
/// # RFC Reference
/// RFC 3925 Section 3
pub const OPTION_VENDOR_IDENT: u8 = 124;

/// Option 125: Vendor-Identifying Vendor-Specific Information (variable length)
///
/// Vendor-specific data tagged with IANA enterprise number. Multiple vendors
/// can coexist with unique enterprise numbers distinguishing data ownership.
///
/// # Format
/// Each vendor's data prefixed with 4-byte IANA enterprise number,
/// allowing multiple vendors' data in single option.
///
/// # Usage
/// Used in `OPTION_VENDOR_IDENT` (124) and `OPTION_VENDOR_IDENT_OPT` (125) to
/// enable vendor-specific configuration while maintaining interoperability.
///
/// # RFC Reference
/// RFC 3925 Section 4
pub const OPTION_VENDOR_IDENT_OPT: u8 = 125;

/// Option 161: Manufacturer Usage Description (MUD) URL (variable length)
///
/// URL pointing to manufacturer's device security profile for `IoT` device policy.
/// Enables automated network access control based on manufacturer specifications.
///
/// # Format
/// URL string pointing to MUD file (JSON format) describing device capabilities
/// and required network access patterns.
///
/// # Usage
/// `IoT` devices provide MUD URL during DHCP discovery. Network infrastructure
/// fetches MUD file and applies appropriate security policies automatically.
///
/// # Security
/// MUD files must be served over HTTPS with valid certificates. Network
/// must validate signatures to prevent policy manipulation.
///
/// # RFC Reference
/// RFC 8520
pub const OPTION_MUD_URL_V4: u8 = 161;

/// Option 255: End option (no length or data)
///
/// Marks end of option list in DHCP packet. All options must appear before this.
///
/// # RFC Reference
/// RFC 2132 Section 3.2: "The end option marks the end of valid information
/// in the vendor field."
pub const OPTION_END: u8 = 255;

// ================================================================================================
// DHCP Relay Agent Information Suboptions (Option 82)
// ================================================================================================

/// Relay Agent Suboption 1: Circuit ID
///
/// Identifies the circuit (interface, VLAN, physical port) on which DHCP request
/// arrived at relay agent. Used for subnet selection and client location tracking.
///
/// # Format
/// Agent-specific (typically interface name or port identifier)
///
/// # RFC Reference
/// RFC 3046 Section 2.0
pub const SUBOPT_CIRCUIT_ID: u8 = 1;

/// Relay Agent Suboption 2: Remote ID
///
/// Identifies the remote host (customer endpoint) at the far end of the circuit.
/// Typically contains subscriber identifier, MAC address, or device serial number.
/// Enables per-subscriber policy and billing.
///
/// # RFC Reference
/// RFC 3046 Section 2.0
pub const SUBOPT_REMOTE_ID: u8 = 2;

/// Relay Agent Suboption 5: Link Selection
///
/// Specifies which IP subnet relay agent wants server to allocate address from.
/// Overrides giaddr-based subnet selection. Allows explicit subnet control in
/// complex relay topologies.
///
/// # Format
/// 4-byte IPv4 subnet address
///
/// # RFC Reference
/// RFC 3527
pub const SUBOPT_SUBNET_SELECT: u8 = 5;

/// Relay Agent Suboption 6: Subscriber ID
///
/// Stable subscriber identifier independent of physical location or hardware.
/// Used by access providers for subscriber policy and billing.
///
/// # Format
/// Provider-specific (typically account number or subscriber name)
///
/// # RFC Reference
/// RFC 3993
pub const SUBOPT_SUBSCR_ID: u8 = 6;

/// Relay Agent Suboption 10: Relay Agent Flags (1 byte, bit flags)
///
/// Bit flags indicating relay agent capabilities and request handling.
///
/// # Bit Flags
/// - Bit 0: Unicast flag (server should unicast replies to relay)
///
/// # RFC Reference
/// RFC 5010
pub const SUBOPT_FLAGS: u8 = 10;

/// Relay Agent Suboption 11: Server Identifier Override
///
/// Instructs server to use a different Server Identifier (Option 54) value in
/// response than the server's actual IP. Used in load balancing and failover.
///
/// # Format
/// 4-byte IPv4 address to use as Server Identifier
///
/// # RFC Reference
/// RFC 5107
pub const SUBOPT_SERVER_OR: u8 = 11;

// ================================================================================================
// PXE Vendor-Specific Suboptions (Option 43)
// ================================================================================================

/// PXE Suboption 6: PXE Discovery Control (1 byte, bit flags)
///
/// Controls PXE client boot server discovery behavior.
///
/// # Bit Flags
/// - Bit 3: Disable broadcast discovery
/// - Bit 2: Disable multicast discovery
/// - Bit 1: Use only boot servers from option 43
/// - Bit 0: Use acceptance proxy protocol
///
/// # RFC Reference
/// Intel PXE Specification 2.1 Section 2.3.5
pub const SUBOPT_PXE_DISCOVERY: u8 = 6;

/// PXE Suboption 8: PXE Boot Servers (variable length)
///
/// List of boot servers available for each boot server type. Enables multi-server redundancy.
///
/// # Format
/// Type (2 bytes), IP count (1 byte), IP addresses (4 bytes each)
///
/// # RFC Reference
/// Intel PXE Specification 2.1 Section 2.3.7
pub const SUBOPT_PXE_SERVERS: u8 = 8;

/// PXE Suboption 9: PXE Boot Menu (variable length)
///
/// Defines user-selectable boot menu entries. Each entry corresponds to a boot item type.
/// Client displays menu for user selection at boot time.
///
/// # Format
/// Type (2 bytes), description length (1 byte), description text
///
/// # RFC Reference
/// Intel PXE Specification 2.1 Section 2.3.8
pub const SUBOPT_PXE_MENU: u8 = 9;

/// PXE Suboption 10: PXE Boot Menu Prompt (variable length)
///
/// Configures the boot menu prompt shown to user.
///
/// # Format
/// Timeout (1 byte, seconds), prompt text
///
/// # Timeout Values
/// - 0: No prompt
/// - 255: Wait indefinitely
/// - 1-254: Wait N seconds
///
/// # Behavior
/// If timeout expires without selection, client uses default boot item.
///
/// # RFC Reference
/// Intel PXE Specification 2.1 Section 2.3.9
pub const SUBOPT_PXE_MENU_PROMPT: u8 = 10;

/// PXE Suboption 71: Boot Item (variable length)
///
/// Describes a specific boot option in PXE boot menu. Referenced by `SUBOPT_PXE_MENU` entries.
/// Used to define available boot images per architecture.
///
/// # Format
/// Boot server type (2 bytes), layer number (2 bytes)
///
/// # RFC Reference
/// Intel PXE Specification 2.1 Section 2.3.1
pub const SUBOPT_PXE_BOOT_ITEM: u8 = 71;

// ================================================================================================
// Vendor Enterprise Numbers
// ================================================================================================

/// IANA enterprise number for Broadband Forum (formerly DSL Forum)
///
/// Used in `OPTION_VENDOR_IDENT` (124) and `OPTION_VENDOR_IDENT_OPT` (125) to
/// identify Broadband Forum vendor-specific data. Broadband Forum develops
/// standards for broadband network architectures, including TR-069 CWMP,
/// TR-101 migration to Ethernet, and TR-111 DHCP options.
///
/// # IANA Registry
/// <https://www.iana.org/assignments/enterprise-numbers/>
///
/// # Source
/// IANA Private Enterprise Numbers registry
pub const BRDBAND_FORUM_IANA: u32 = 3561;

// ================================================================================================
// Packet Flags
// ================================================================================================

/// Broadcast flag bit mask for DHCP flags field (0x8000)
///
/// Set by client if unable to receive unicast IP datagrams before IP address
/// configured (typically clients without ARP support or systems that drop unicast
/// until interface configured).
///
/// # Protocol Behavior
/// When set, server broadcasts DHCPOFFER and DHCPACK to 255.255.255.255
/// instead of unicasting to yiaddr.
///
/// # RFC Reference
/// RFC 2131 Section 2, Section 4.1
pub const BROADCAST_FLAG: u16 = 0x8000;
