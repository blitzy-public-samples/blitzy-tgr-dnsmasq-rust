// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! DHCPv6 protocol constants module
//!
//! This module provides all protocol-level constants required for DHCPv6 (Dynamic Host
//! Configuration Protocol for IPv6) implementation per RFC 3315 and related extension RFCs.
//! These constants define the wire protocol for DHCPv6 packet construction, parsing, and
//! validation across stateful and stateless DHCPv6 operations.
//!
//! # Protocol Overview
//!
//! DHCPv6 operates on UDP ports 546 (client) and 547 (server) and uses IPv6 multicast
//! for client-server communication. The protocol supports:
//!
//! - **Stateful address assignment**: Server assigns and tracks IPv6 addresses (IA_NA)
//! - **Stateless configuration**: Server provides configuration without address assignment
//! - **Prefix delegation**: Server delegates IPv6 prefixes to requesting routers (IA_PD)
//! - **Temporary addresses**: Privacy-enhanced temporary addresses (IA_TA)
//!
//! # Message Exchange Patterns
//!
//! ## Stateful (4-message exchange):
//! 1. Client → Server: SOLICIT (locate servers)
//! 2. Server → Client: ADVERTISE (offer addresses)
//! 3. Client → Server: REQUEST (request specific server's addresses)
//! 4. Server → Client: REPLY (confirm assignment)
//!
//! ## Stateful with Rapid Commit (2-message exchange):
//! 1. Client → Server: SOLICIT (with Rapid Commit option)
//! 2. Server → Client: REPLY (immediate assignment)
//!
//! ## Stateless:
//! 1. Client → Server: INFORMATION-REQUEST (request configuration only)
//! 2. Server → Client: REPLY (provide configuration parameters)
//!
//! # RFC Compliance
//!
//! - **RFC 3315**: DHCPv6 core specification (message types, options, status codes)
//! - **RFC 3633**: IPv6 Prefix Options for DHCPv6 (IA_PD, IAPREFIX)
//! - **RFC 3646**: DNS Configuration options (DNS_SERVER, DOMAIN_SEARCH)
//! - **RFC 4242**: Information Refresh Time option
//! - **RFC 4580**: Subscriber-ID option
//! - **RFC 4649**: Remote-ID option
//! - **RFC 4704**: Client FQDN option
//! - **RFC 5908**: Network Time Protocol Server Option
//! - **RFC 6939**: Client Link-layer Address option
//! - **RFC 8520**: MUD URL option
//!
//! # Memory Safety
//!
//! All constants are defined as native Rust primitives (`u16`, `u8`, `Ipv6Addr`) ensuring
//! compile-time type safety and eliminating buffer overflow risks present in C preprocessor
//! definitions. IPv6 multicast addresses use `std::net::Ipv6Addr` for type-safe address
//! representation.

use std::net::Ipv6Addr;

// ============================================================================
// UDP Port Numbers (RFC 3315 Section 5.2)
// ============================================================================

/// DHCPv6 server UDP port number (547)
///
/// Well-known port used by DHCPv6 servers to receive client messages including
/// SOLICIT, REQUEST, RENEW, REBIND, RELEASE, DECLINE, CONFIRM, and INFORMATION-REQUEST.
/// Clients send DHCPv6 messages to this port on servers or multicast addresses.
///
/// # Protocol Usage
/// - Clients send to server port 547 (unicast or multicast)
/// - Servers listen on port 547 for incoming client messages
/// - Relay agents forward messages to servers on port 547
///
/// Per RFC 3315 Section 5.2
pub const PORT_SERVER: u16 = 547;

/// DHCPv6 client UDP port number (546)
///
/// Well-known port used by DHCPv6 clients to receive server messages including
/// ADVERTISE, REPLY, and RECONFIGURE. Servers send DHCPv6 responses to this port
/// on client addresses.
///
/// # Protocol Usage
/// - Servers send to client port 546
/// - Clients listen on port 546 for server responses
/// - Relay agents forward server responses to clients on port 546
///
/// Per RFC 3315 Section 5.2
pub const PORT_CLIENT: u16 = 546;

// ============================================================================
// IPv6 Multicast Addresses (RFC 3315 Section 5.1)
// ============================================================================

/// All_DHCP_Relay_Agents_and_Servers multicast address (FF02::1:2)
///
/// Link-local scope IPv6 multicast address used by DHCPv6 clients to communicate
/// with DHCPv6 relay agents and servers on the local link. This is the primary
/// multicast address for initial DHCPv6 SOLICIT messages.
///
/// # Scope and Usage
/// - **Scope**: Link-local (FF02) - does not traverse routers
/// - **Used by**: DHCPv6 clients for initial SOLICIT messages
/// - **Received by**: DHCPv6 servers and relay agents on local link
/// - **Most common**: This is the most frequently used DHCPv6 multicast address
///
/// # Message Types Using This Address
/// - SOLICIT (initial server discovery)
/// - REBIND (when original server unreachable, sent to any available server)
/// - CONFIRM (address validation after link change)
///
/// Per RFC 3315 Section 5.1
pub const ALL_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// All_DHCP_Servers multicast address (FF05::1:3)
///
/// Site-local scope IPv6 multicast address used by DHCPv6 clients to communicate
/// with DHCPv6 servers when the client knows site-local scope is appropriate.
/// Less commonly used than link-local All_DHCP_Relay_Agents_and_Servers.
///
/// # Scope and Usage
/// - **Scope**: Site-local (FF05) - limited to the local site, may traverse routers
/// - **Used by**: DHCPv6 clients when targeting site-wide server discovery
/// - **Received by**: DHCPv6 servers within the site
/// - **Less common**: Most deployments use link-local FF02::1:2 instead
///
/// # When to Use
/// - Client configured to use site-local scope
/// - Site-wide DHCPv6 server discovery required
/// - Typically not used in standard deployments
///
/// Per RFC 3315 Section 5.1
pub const ALL_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3);

// ============================================================================
// DHCPv6 Message Types (RFC 3315 Section 5.3)
// ============================================================================

/// SOLICIT message type (1)
///
/// Client-to-server message initiating DHCPv6 exchange. Client multicasts SOLICIT
/// to All_DHCP_Relay_Agents_and_Servers to locate available DHCPv6 servers and
/// request addresses (stateful) or configuration parameters (stateless).
///
/// # Message Flow
/// 1. Client multicasts SOLICIT to FF02::1:2
/// 2. Servers respond with ADVERTISE (or REPLY if rapid commit)
/// 3. Client selects server based on ADVERTISE contents and preference values
///
/// # Contents
/// - Client Identifier (DUID)
/// - IA_NA and/or IA_TA (for stateful address requests)
/// - IA_PD (for prefix delegation requests)
/// - Option Request Option (ORO) listing desired configuration options
/// - Elapsed Time option
/// - Rapid Commit option (if 2-message exchange desired)
///
/// # Modes
/// - **Stateful**: Includes IA_NA/IA_TA to request address assignment
/// - **Stateless**: No IA options, only configuration via ORO
/// - **Prefix Delegation**: Includes IA_PD for router prefix requests
///
/// Per RFC 3315 Section 17.1.1
pub const MSG_SOLICIT: u8 = 1;

/// ADVERTISE message type (2)
///
/// Server-to-client message in response to SOLICIT. Server advertises availability
/// and proposes addresses/configuration. Client selects one server and sends REQUEST
/// to complete address assignment. Skipped in rapid commit mode.
///
/// # Message Flow
/// 1. Server receives SOLICIT from client
/// 2. Server sends ADVERTISE with proposed addresses/configuration
/// 3. Client evaluates multiple ADVERTISE messages (if received)
/// 4. Client selects server with highest preference or best offer
///
/// # Contents
/// - Server Identifier (DUID)
/// - Client Identifier (copied from SOLICIT)
/// - IA_NA/IA_TA with IAADDR options (proposed addresses)
/// - IA_PD with IAPREFIX options (proposed prefixes)
/// - Requested configuration options (DNS, NTP, domain search, etc.)
/// - Preference option (0-255, higher values preferred by clients)
/// - Server Unicast option (if server supports direct unicast communication)
///
/// # Server Selection
/// - Preference value 255: Client should select immediately
/// - Lower preference: Client may wait for additional ADVERTISE messages
/// - No preference option: Default preference of 0
///
/// Per RFC 3315 Section 17.1.2
pub const MSG_ADVERTISE: u8 = 2;

/// REQUEST message type (3)
///
/// Client-to-server message requesting assignment of addresses and/or configuration
/// from a specific server selected after receiving ADVERTISE. Server responds with
/// REPLY containing assigned addresses and confirmed configuration.
///
/// # Message Flow
/// 1. Client receives ADVERTISE from one or more servers
/// 2. Client selects server (typically highest preference)
/// 3. Client sends REQUEST to chosen server
/// 4. Server responds with REPLY confirming assignment
///
/// # Contents
/// - Client Identifier (DUID)
/// - Server Identifier (DUID of selected server)
/// - IA_NA/IA_TA from chosen ADVERTISE
/// - IA_PD from chosen ADVERTISE (if prefix delegation)
/// - Option Request Option (ORO) for configuration parameters
/// - Elapsed Time option
///
/// # Purpose
/// - Complete stateful address assignment process
/// - Commit to specific server's offer
/// - Request configuration parameters
///
/// Per RFC 3315 Section 18.1.1
pub const MSG_REQUEST: u8 = 3;

/// CONFIRM message type (4)
///
/// Client-to-server message asking server to verify that client's assigned addresses
/// are still appropriate for the link to which the client is attached. Used when
/// client may have moved to a different network segment.
///
/// # When Sent
/// - Client detects possible network change (link down/up event)
/// - Client reboots and wants to verify existing addresses
/// - Client uncertain if addresses are still valid for current link
///
/// # Message Flow
/// 1. Client sends CONFIRM with current IA_NA/IA_TA to multicast address
/// 2. Any server on link responds with REPLY
/// 3. REPLY contains status code (SUCCESS or NOTONLINK)
///
/// # Server Response
/// - **SUCCESS**: Addresses are valid for current link
/// - **NOTONLINK**: Addresses inappropriate, client must obtain new addresses
///
/// # Contents
/// - Client Identifier
/// - IA_NA/IA_TA with IAADDR (addresses to validate)
/// - Elapsed Time option
///
/// # Note
/// Does NOT renew address lifetimes. Only validates link appropriateness.
///
/// Per RFC 3315 Section 18.1.2
pub const MSG_CONFIRM: u8 = 4;

/// RENEW message type (5)
///
/// Client-to-server message sent to the server that originally provided addresses
/// to extend the lifetimes of assigned addresses. Sent when T1 timer expires
/// (typically 50% of preferred lifetime).
///
/// # Timing
/// - **T1 Timer**: First renewal attempt, typically 0.5 × preferred_lifetime
/// - **T2 Timer**: If RENEW fails, client sends REBIND at T2 (typically 0.8 × preferred_lifetime)
/// - **Destination**: Unicast to original server (if Server Unicast option provided)
///
/// # Message Flow
/// 1. T1 timer expires
/// 2. Client sends RENEW to original server
/// 3. Server responds with REPLY extending lifetimes or indicating failure
///
/// # Server Response Options
/// - **Extend lifetimes**: Server updates preferred/valid lifetimes in REPLY
/// - **Addresses no longer valid**: Server sends status code NOBINDING
/// - **No addresses available**: Server sends status code NOADDRS in IA
///
/// # Contents
/// - Client Identifier
/// - Server Identifier (original server's DUID)
/// - IA_NA/IA_TA/IA_PD to renew
/// - Elapsed Time option
///
/// # Failure Handling
/// If no REPLY received, client continues sending RENEW until T2, then switches to REBIND.
///
/// Per RFC 3315 Section 18.1.3
pub const MSG_RENEW: u8 = 5;

/// REBIND message type (6)
///
/// Client-to-server message sent to any available server (multicast) to extend
/// lifetimes of addresses when original server is unreachable. Sent when T2 timer
/// expires (typically 80% of preferred lifetime) and RENEW attempts have failed.
///
/// # Timing
/// - **Sent when**: T2 timer expires and RENEW has not succeeded
/// - **T2 Timer**: Typically 0.8 × preferred_lifetime
/// - **Destination**: Multicast to All_DHCP_Relay_Agents_and_Servers (FF02::1:2)
///
/// # Message Flow
/// 1. T2 timer expires (RENEW failed to reach original server)
/// 2. Client multicasts REBIND to any available server
/// 3. Any DHCPv6 server can respond with REPLY
///
/// # Difference from RENEW
/// - **RENEW**: Unicast to original server only
/// - **REBIND**: Multicast to any server (original server unreachable)
/// - **RENEW**: Includes Server Identifier
/// - **REBIND**: No Server Identifier (any server can respond)
///
/// # Contents
/// - Client Identifier
/// - IA_NA/IA_TA/IA_PD to rebind
/// - Elapsed Time option
/// - NO Server Identifier (allows any server to respond)
///
/// # Server Response
/// Any server on link can extend lifetimes or indicate failure.
///
/// Per RFC 3315 Section 18.1.4
pub const MSG_REBIND: u8 = 6;

/// REPLY message type (7)
///
/// Server-to-client message containing assigned addresses, configuration parameters,
/// or status information in response to client messages. The REPLY contents depend
/// on the message type being responded to.
///
/// # Response Contexts
///
/// ## In Response to SOLICIT (Rapid Commit)
/// - Immediate address assignment (2-message exchange)
/// - Includes Rapid Commit option confirming rapid commit mode
/// - Contains assigned IA_NA/IA_TA/IA_PD with addresses/prefixes
///
/// ## In Response to REQUEST
/// - Confirms address assignment from ADVERTISE
/// - Provides final addresses and configuration
/// - May include status codes indicating success or failure
///
/// ## In Response to RENEW/REBIND
/// - Extends address lifetimes (updates preferred_lifetime and valid_lifetime)
/// - May indicate addresses no longer valid (status code NOBINDING)
/// - May provide updated configuration parameters
///
/// ## In Response to CONFIRM
/// - Status code SUCCESS (addresses valid for link)
/// - Status code NOTONLINK (addresses inappropriate for link)
///
/// ## In Response to RELEASE
/// - Acknowledges release of addresses
/// - Status code SUCCESS typically
///
/// ## In Response to DECLINE
/// - Acknowledges duplicate address detection
/// - Server marks addresses as unavailable
///
/// ## In Response to INFORMATION-REQUEST
/// - Provides configuration parameters only (stateless DHCPv6)
/// - No address assignment
/// - DNS servers, NTP servers, domain search list, etc.
///
/// # Contents (varies by context)
/// - Server Identifier (always)
/// - Client Identifier (always, copied from request)
/// - IA_NA/IA_TA/IA_PD (for address/prefix responses)
/// - IAADDR/IAPREFIX options (within IA options)
/// - Requested configuration options (DNS, NTP, domain search, etc.)
/// - Status Code option (overall status or per-IA status)
/// - Rapid Commit option (if rapid commit used)
/// - Preference option (in ADVERTISE, not REPLY)
///
/// Per RFC 3315 Sections 18.2.1-18.2.8
pub const MSG_REPLY: u8 = 7;

/// RELEASE message type (8)
///
/// Client-to-server message indicating client no longer needs one or more assigned
/// addresses. Client voluntarily relinquishes addresses before their lifetimes expire.
/// Server responds with REPLY and may immediately reuse the released addresses.
///
/// # When Sent
/// - Client shutting down gracefully
/// - Client no longer needs certain addresses
/// - Administrator manually releases addresses
/// - Client moving to different network permanently
///
/// # Message Flow
/// 1. Client sends RELEASE to server (unicast if possible)
/// 2. Server marks addresses as available for reassignment
/// 3. Server responds with REPLY (status code SUCCESS typically)
///
/// # Contents
/// - Client Identifier
/// - Server Identifier (server that assigned addresses)
/// - IA_NA/IA_TA/IA_PD with IAADDR/IAPREFIX to release
/// - Elapsed Time option
///
/// # Server Actions
/// - Mark released addresses as available
/// - Update lease database
/// - Remove DNS forward/reverse records if DDNS enabled
/// - Respond with REPLY
///
/// # Graceful Shutdown
/// Client should send RELEASE when terminating normally to return addresses
/// to pool promptly rather than waiting for lease expiration.
///
/// Per RFC 3315 Section 18.1.6
pub const MSG_RELEASE: u8 = 8;

/// DECLINE message type (9)
///
/// Client-to-server message indicating one or more assigned addresses are already
/// in use on the link (duplicate address detected via DAD - Duplicate Address Detection).
/// Server responds with REPLY and marks addresses as unavailable for other clients.
///
/// # Duplicate Address Detection Process
/// 1. Client receives addresses from server in REPLY
/// 2. Client performs DAD per RFC 4862 (sends Neighbor Solicitation)
/// 3. If duplicate detected (receives Neighbor Advertisement), address is in use
/// 4. Client sends DECLINE for duplicate address(es)
/// 5. Server marks addresses as unavailable
///
/// # Message Flow
/// 1. Client detects duplicate via DAD
/// 2. Client sends DECLINE with problematic IAADDR
/// 3. Server marks addresses as unavailable (potential misconfiguration)
/// 4. Server responds with REPLY
/// 5. Client may request different addresses with new REQUEST
///
/// # Contents
/// - Client Identifier
/// - Server Identifier
/// - IA_NA/IA_TA with IAADDR for declined addresses
/// - Elapsed Time option
///
/// # Server Actions
/// - Mark declined addresses as unavailable in lease database
/// - Log event (indicates potential address pool conflict or misconfiguration)
/// - Respond with REPLY
/// - Investigate cause (static assignment conflict, rogue DHCP server, etc.)
///
/// # Rare Occurrence
/// DECLINE should be rare in properly configured networks. Frequent DECLINE
/// messages indicate serious configuration or deployment issues.
///
/// Per RFC 3315 Section 18.1.7
pub const MSG_DECLINE: u8 = 9;

/// RECONFIGURE message type (10)
///
/// Server-to-client message telling client to initiate RENEW/REPLY or
/// INFORMATION-REQUEST/REPLY transaction. Allows server to proactively push
/// configuration updates to clients without waiting for client-initiated renewal.
///
/// # Security Requirement
/// Client MUST have accepted Reconfigure Accept option (OPTION6_RECONF_ACCEPT)
/// in previous SOLICIT/REQUEST. Clients opt-in to reconfigure capability.
/// Without opt-in, client MUST silently discard RECONFIGURE messages.
///
/// # Message Flow
/// 1. Server needs to update client configuration
/// 2. Server sends RECONFIGURE to client
/// 3. Client verifies authentication (if authentication configured)
/// 4. Client initiates requested transaction (RENEW or INFORMATION-REQUEST)
/// 5. Server provides updated configuration in REPLY
///
/// # Reconfigure Types (Reconfigure Message option)
/// - **RENEW (5)**: Client should send RENEW for address renewal
/// - **INFORMATION-REQUEST (11)**: Client should send INFORMATION-REQUEST for config refresh
///
/// # Contents
/// - Server Identifier
/// - Client Identifier
/// - Reconfigure Message option (specifies RENEW or INFORMATION-REQUEST)
/// - Authentication option (if authentication required)
///
/// # Use Cases
/// - DNS server addresses changed
/// - NTP server addresses changed
/// - Prefix delegation updates
/// - Policy changes requiring client reconfiguration
///
/// # Security
/// RECONFIGURE is security-sensitive. Rogue RECONFIGURE could cause client
/// to contact malicious server. Authentication strongly recommended.
///
/// Per RFC 3315 Section 19.1.1
pub const MSG_RECONFIGURE: u8 = 10;

/// INFORMATION-REQUEST message type (11)
///
/// Client-to-server message requesting only configuration parameters without
/// address assignment (stateless DHCPv6). Used when client has IPv6 address
/// from SLAAC or static configuration but needs DNS, NTP, or other parameters.
///
/// # Stateless DHCPv6
/// - **Client addressing**: SLAAC (Stateless Address Autoconfiguration) or static
/// - **DHCPv6 role**: Configuration parameters only (DNS, NTP, domain search)
/// - **Server role**: Provide configuration, no address tracking or lease management
///
/// # Message Flow
/// 1. Client has IPv6 address (SLAAC or static)
/// 2. Client sends INFORMATION-REQUEST to multicast address
/// 3. Server responds with REPLY containing requested configuration
/// 4. Client configures DNS servers, NTP servers, domain search list, etc.
///
/// # Refresh Timing
/// - Server may include Information Refresh Time option (OPTION6_REFRESH_TIME)
/// - Client should send new INFORMATION-REQUEST after refresh time expires
/// - Allows server to control configuration update frequency
///
/// # Contents
/// - Client Identifier (optional in INFORMATION-REQUEST)
/// - Option Request Option (ORO) listing desired configuration parameters
/// - Elapsed Time option
/// - NO IA_NA/IA_TA/IA_PD (no address requests in stateless mode)
///
/// # Common Requested Options
/// - DNS Recursive Name Servers (OPTION6_DNS_SERVER)
/// - Domain Search List (OPTION6_DOMAIN_SEARCH)
/// - NTP Servers (OPTION6_NTP_SERVER)
/// - Other configuration options per network policy
///
/// # Router Advertisement Integration
/// Router Advertisement "O" flag (Other configuration) signals clients to use
/// stateless DHCPv6. "M" flag (Managed) signals stateful DHCPv6.
///
/// Per RFC 3315 Section 18.1.5
pub const MSG_INFORMATION_REQUEST: u8 = 11;

/// RELAY-FORW message type (12)
///
/// Relay agent-to-server message encapsulating client message for forwarding to
/// DHCPv6 server on different link. Relay agents bridge DHCPv6 communication between
/// clients and servers across routers. Supports multi-hop relay chains.
///
/// # Relay Agent Role
/// DHCPv6 uses relay agents (similar to DHCPv4 relay/BOOTP relay) when:
/// - Client and server are on different IPv6 subnets/links
/// - Server is not on local link and multicast doesn't reach it
/// - Centralized DHCPv6 server serves multiple network segments
///
/// # Message Flow
/// 1. Client sends SOLICIT/REQUEST/etc. to All_DHCP_Relay_Agents_and_Servers
/// 2. Relay agent receives client message
/// 3. Relay agent encapsulates in RELAY-FORW with metadata
/// 4. Relay agent forwards RELAY-FORW to server (unicast or multicast)
/// 5. Server processes and responds with RELAY-REPL
///
/// # Relay Message Structure
/// - **msg-type**: RELAY-FORW (12)
/// - **hop-count**: Number of relay agents in chain (incremented by each relay)
/// - **link-address**: IPv6 address of link on which client message received
/// - **peer-address**: IPv6 address of client or previous relay
/// - **options**:
///   - Relay Message option (OPTION6_RELAY_MSG) containing encapsulated client message
///   - Interface-Id option (OPTION6_INTERFACE_ID) identifying receiving interface
///   - Remote-Id option (OPTION6_REMOTE_ID) for relay identification
///
/// # Multi-Hop Relay Chains
/// - Each relay adds one layer of encapsulation
/// - Hop count incremented at each relay (max 32 per RFC 3315)
/// - Server decapsulates and processes innermost client message
/// - Server responds with RELAY-REPL having matching encapsulation layers
///
/// # Relay Agent Functions
/// - Forward client messages to server
/// - Add link-address for server to determine appropriate address pool
/// - Add interface-id for relay to identify correct interface for response
/// - Enforce hop count limit to prevent loops
///
/// Per RFC 3315 Section 20.1.1
pub const MSG_RELAY_FORW: u8 = 12;

/// RELAY-REPL message type (13)
///
/// Server-to-relay message containing server's reply to client, encapsulated for
/// forwarding by relay agent back to client. Relay agent extracts reply and forwards
/// to client on appropriate interface. Supports multi-hop relay chains.
///
/// # Message Flow
/// 1. Server receives RELAY-FORW from relay agent
/// 2. Server extracts and processes innermost client message
/// 3. Server constructs REPLY for client
/// 4. Server encapsulates REPLY in RELAY-REPL mirroring RELAY-FORW structure
/// 5. Server sends RELAY-REPL to relay agent
/// 6. Relay agent extracts REPLY and forwards to client
///
/// # Relay Message Structure
/// - **msg-type**: RELAY-REPL (13)
/// - **hop-count**: Copied from RELAY-FORW
/// - **link-address**: Copied from RELAY-FORW
/// - **peer-address**: Copied from RELAY-FORW (relay forwards to this address)
/// - **options**:
///   - Relay Message option containing encapsulated server REPLY
///   - Interface-Id option copied from RELAY-FORW (relay uses to identify interface)
///
/// # Multi-Hop Processing
/// In multi-hop relay chains:
/// 1. Server creates RELAY-REPL with layers matching RELAY-FORW
/// 2. Each relay decapsulates one RELAY-REPL layer
/// 3. Each relay forwards inner RELAY-REPL (or final REPLY) toward client
/// 4. Last relay extracts client REPLY and forwards to client
///
/// # Relay Actions on Receipt
/// 1. Verify hop-count and peer-address match forwarded message
/// 2. Extract Relay Message option (contains client-destined REPLY)
/// 3. Use Interface-Id to identify correct interface
/// 4. Forward REPLY to client on identified interface to peer-address
///
/// # Interface Identification
/// Interface-Id option critical for relay agent with multiple interfaces.
/// Relay must remember which interface received client message and forward
/// server response to same interface.
///
/// Per RFC 3315 Section 20.1.2
pub const MSG_RELAY_REPL: u8 = 13;

// ============================================================================
// DHCPv6 Option Codes (RFC 3315 Section 22, various extension RFCs)
// ============================================================================

/// Client Identifier option (1)
///
/// Contains client's DUID (DHCP Unique Identifier) for client identification across
/// network moves and reboots. DUID must be stable and globally unique per client.
///
/// # DUID Requirements
/// - **Stability**: DUID must not change across reboots or network changes
/// - **Uniqueness**: DUID should be globally unique (or at least unique within administrative domain)
/// - **Generation**: Generated once at install/first boot and persisted
///
/// # DUID Types (see DUID_* constants)
/// - **DUID-LLT (1)**: Link-layer address + timestamp
/// - **DUID-EN (2)**: Enterprise number + vendor-assigned unique ID
/// - **DUID-LL (3)**: Link-layer address only
/// - **DUID-UUID (4)**: UUID-based identifier
///
/// # Usage
/// - **Required in**: All client messages except INFORMATION-REQUEST (optional there)
/// - **Format**: 2-byte DUID type + variable-length DUID data
/// - **Server action**: Server uses Client ID to look up existing leases/bindings
///
/// # Example
/// DUID-LL (type 3) for Ethernet MAC 00:11:22:33:44:55:
/// ```text
/// 0x0003 (DUID type 3)
/// 0x0001 (hardware type 1 = Ethernet)
/// 0x001122334455 (MAC address)
/// ```
///
/// Per RFC 3315 Section 22.2
pub const OPTION_CLIENT_ID: u16 = 1;

/// Server Identifier option (2)
///
/// Contains server's DUID used to identify specific DHCPv6 server. Allows client
/// to direct subsequent messages (REQUEST, RENEW, RELEASE) to specific server.
///
/// # Usage
/// - **Sent by server in**: ADVERTISE, REPLY
/// - **Sent by client in**: REQUEST, RENEW, RELEASE, DECLINE (to identify target server)
/// - **NOT in**: REBIND (any server can respond), client's SOLICIT
///
/// # Server DUID Generation
/// Server should generate stable DUID at installation/first run. Methods:
/// - DUID-LLT using server's MAC + timestamp
/// - DUID-LL using server's MAC
/// - DUID-UUID using generated UUID
/// - Persist DUID in configuration or state file
///
/// # Client Server Selection
/// 1. Client sends SOLICIT (no Server ID)
/// 2. Multiple servers send ADVERTISE with their Server IDs
/// 3. Client selects one server (based on preference, addresses offered)
/// 4. Client sends REQUEST including selected server's Server ID
/// 5. Selected server responds, other servers ignore REQUEST
///
/// Per RFC 3315 Section 22.3
pub const OPTION_SERVER_ID: u16 = 2;

/// Identity Association for Non-temporary Addresses option (3)
///
/// IA_NA (Identity Association - Non-temporary Addresses) contains stateful
/// non-temporary IPv6 addresses assigned to client. Used for standard stateful
/// DHCPv6 address assignment.
///
/// # IA_NA Structure
/// - **IAID**: 4-byte Identity Association Identifier (chosen by client, stable across reboots)
/// - **T1**: 4-byte renewal time in seconds (when client should send RENEW to server)
/// - **T2**: 4-byte rebind time in seconds (when client should send REBIND to any server)
/// - **IA_NA-options**: Encapsulated options, primarily IAADDR options containing addresses
///
/// # Timing Parameters
/// - **T1** (renewal time): Typically 0.5 × preferred_lifetime, when client contacts original server
/// - **T2** (rebind time): Typically 0.8 × preferred_lifetime, when client contacts any server
/// - **T1 < T2**: Always, or server may set T1=T2=0 to let client choose times
///
/// # Multiple Addresses
/// One IA_NA can contain multiple IAADDR options. Client may request multiple
/// addresses within single IA_NA for:
/// - Multihoming
/// - Service-specific addresses
/// - Load balancing
///
/// # Multiple IA_NAs
/// Client can request multiple IA_NA options with different IAIDs for different
/// purposes (different interfaces, different address types, etc.).
///
/// # IAID Selection
/// - Client chooses IAID
/// - Must be unique among client's IAs
/// - Should be stable across reboots for same IA
/// - Often derived from interface index or MAC address
///
/// Per RFC 3315 Section 22.4
pub const OPTION_IA_NA: u16 = 3;

/// Identity Association for Temporary Addresses option (4)
///
/// IA_TA (Identity Association - Temporary Addresses) contains temporary IPv6
/// addresses for privacy. Similar to IPv6 privacy extensions (RFC 4941), prevents
/// address-based tracking of client across networks.
///
/// # IA_TA Structure
/// - **IAID**: 4-byte Identity Association Identifier
/// - **IA_TA-options**: Encapsulated IAADDR options containing temporary addresses
/// - **NO T1/T2**: Temporary addresses are not renewed (no T1/T2 timers)
///
/// # Temporary Address Characteristics
/// - **Short-lived**: Preferred lifetime typically shorter than non-temporary addresses
/// - **Not renewed**: When temporary address expires, client requests new one
/// - **Privacy**: Used for outbound connections to prevent tracking
/// - **Frequent rotation**: Enhances privacy by frequently changing source address
///
/// # Use Cases
/// - Web browsing privacy
/// - Outbound application connections
/// - Preventing address-based location tracking
/// - Compliance with privacy regulations
///
/// # Difference from IA_NA
/// | Feature | IA_NA | IA_TA |
/// |---------|-------|-------|
/// | Renewal | Yes (T1/T2 timers) | No renewal |
/// | Lifetime | Long-lived | Short-lived |
/// | Purpose | Stable addressing | Privacy |
/// | DNS registration | Typically yes | Typically no |
///
/// # Privacy Extensions Comparison
/// IA_TA (DHCPv6 temporary addresses) complements but differs from RFC 4941
/// privacy extensions (SLAAC temporary addresses). Both enhance privacy.
///
/// Per RFC 3315 Section 22.5
pub const OPTION_IA_TA: u16 = 4;

/// IA Address option (5)
///
/// IAADDR option encapsulated within IA_NA or IA_TA, containing single IPv6 address
/// with associated lifetimes. Multiple IAADDR options can exist within one IA.
///
/// # IAADDR Structure
/// - **IPv6 address**: 16-byte IPv6 address assigned to client
/// - **Preferred lifetime**: 4-byte value in seconds
/// - **Valid lifetime**: 4-byte value in seconds
/// - **IAaddr-options**: Encapsulated options (typically Status Code if problems)
///
/// # Lifetime Semantics
///
/// ## Preferred Lifetime
/// - Time address may be used for new connections/communications
/// - After preferred lifetime expires, address becomes "deprecated"
/// - Deprecated addresses can still receive packets but should not initiate new connections
/// - Infinite lifetime: 0xFFFFFFFF
///
/// ## Valid Lifetime
/// - Time address is valid for any use
/// - After valid lifetime expires, address must not be used
/// - Valid lifetime ≥ preferred lifetime (always)
/// - Infinite lifetime: 0xFFFFFFFF
///
/// ## Lifetime Relationships
/// - **valid_lifetime ≥ preferred_lifetime** (required)
/// - When preferred expires but valid hasn't: Address deprecated (receive only)
/// - When valid expires: Address completely invalid
///
/// # Renewal Behavior
/// - Client sends RENEW at T1 to extend lifetimes
/// - Server updates preferred and valid lifetimes in REPLY
/// - Lifetimes can be extended, reduced, or set to 0 (invalidate immediately)
///
/// # Status Code in IAADDR
/// - Per-address Status Code option may be encapsulated
/// - Indicates problems with specific address (NOTONLINK, etc.)
/// - Allows granular status reporting for multi-address IAs
///
/// Per RFC 3315 Section 22.6
pub const OPTION_IAADDR: u16 = 5;

/// Option Request Option (6)
///
/// ORO (Option Request Option) contains list of option codes client is requesting
/// from server. Tells server which configuration parameters client wants to receive.
///
/// # Structure
/// List of 2-byte option codes, each representing an option client desires:
/// ```text
/// [OPTION6_DNS_SERVER, OPTION6_DOMAIN_SEARCH, OPTION6_NTP_SERVER, ...]
/// ```
///
/// # Usage Context
/// Client includes ORO in:
/// - **SOLICIT**: Indicate desired options for ADVERTISE/REPLY
/// - **REQUEST**: Request specific options in assignment REPLY
/// - **RENEW**: Request updated configuration during renewal
/// - **REBIND**: Request configuration from alternate server
/// - **INFORMATION-REQUEST**: Primary mechanism for stateless DHCPv6 config
///
/// # Common Requested Options
/// - **OPTION6_DNS_SERVER (23)**: Recursive DNS server addresses
/// - **OPTION6_DOMAIN_SEARCH (24)**: DNS search domain list
/// - **OPTION6_NTP_SERVER (56)**: NTP server information
/// - **OPTION6_FQDN (39)**: Client FQDN for dynamic DNS
/// - Vendor-specific options
/// - Site-specific options
///
/// # Server Response
/// - Server includes requested options in REPLY if:
///   - Server has configuration data for the option
///   - Client is authorized to receive the option
///   - Option is applicable to client's network/policy
/// - Server may include unrequested options if policy dictates
/// - Server may omit requested options if unavailable or unauthorized
///
/// # Stateless DHCPv6 Critical Role
/// For stateless DHCPv6 (INFORMATION-REQUEST/REPLY), ORO is primary mechanism
/// for client to specify which configuration parameters it needs.
///
/// Per RFC 3315 Section 22.7
pub const OPTION_ORO: u16 = 6;

/// Preference option (7)
///
/// 8-bit unsigned value (0-255) sent by server in ADVERTISE message to indicate
/// server's preference level. Client uses preference to select among multiple
/// servers when multiple ADVERTISE messages received.
///
/// # Preference Values
/// - **0-254**: Normal preference range, higher values more preferred
/// - **255**: Special value indicating server is immediately acceptable
/// - **Default (no option)**: Treated as preference 0
///
/// # Client Selection Algorithm
/// 1. Client sends SOLICIT
/// 2. Client waits for ADVERTISE messages (typically 1 second)
/// 3. If ADVERTISE with preference 255 received: Select immediately
/// 4. Otherwise: Wait for timeout, select highest preference
/// 5. If multiple servers have same preference: Client chooses arbitrarily
///
/// # Server Strategy
/// Servers set preference based on:
/// - **Load balancing**: Less-loaded servers use higher preference
/// - **Capability**: Servers with more resources use higher preference
/// - **Proximity**: Closer/faster servers use higher preference
/// - **Primary/backup**: Primary server uses higher preference
///
/// # Preference 255 Special Case
/// - Indicates server is immediately acceptable
/// - Client should select this server without waiting for other ADVERTISE
/// - Reduces address assignment latency
/// - Use when server has high confidence it's best choice
///
/// # No Preference Option
/// If server doesn't include Preference option, client treats as preference 0.
/// Client may select based on order of receipt or other heuristics.
///
/// # Used Only in ADVERTISE
/// Preference option appears only in ADVERTISE messages. Not used in REPLY
/// or other message types.
///
/// Per RFC 3315 Section 22.8
pub const OPTION_PREFERENCE: u16 = 7;

/// Elapsed Time option (8)
///
/// 16-bit value representing time in hundredths of a second (centiseconds) that
/// client has been trying to complete current DHCPv6 message exchange. Helps
/// servers and relay agents prioritize clients that have been waiting longer.
///
/// # Time Measurement
/// - **Units**: Hundredths of a second (centiseconds)
/// - **Range**: 0 to 65535 centiseconds (0 to 655.35 seconds)
/// - **Special value 0xFFFF**: Indicates elapsed time ≥ 655.35 seconds
/// - **Precision**: Client should measure as accurately as possible
///
/// # When Client Updates Elapsed Time
/// 1. Client starts timer when beginning message exchange (sending first SOLICIT)
/// 2. Each retransmission includes updated elapsed time
/// 3. Elapsed time continues across message types in same transaction:
///    - SOLICIT/ADVERTISE/REQUEST sequence: Timer starts at first SOLICIT
///    - RENEW retransmissions: Timer starts at first RENEW
///
/// # Server/Relay Priority Use
/// - Servers may prioritize clients with higher elapsed time
/// - Indicates client has been waiting longer and may be time-sensitive
/// - Relay agents can use elapsed time to prioritize message forwarding
/// - Helps ensure fairness in server response times
///
/// # Example Timeline
/// ```text
/// T=0.0s: Client sends SOLICIT (elapsed_time=0)
/// T=1.0s: Client retransmits SOLICIT (elapsed_time=100)
/// T=3.0s: Client retransmits SOLICIT (elapsed_time=300)
/// T=7.0s: Client sends REQUEST (elapsed_time=700)
/// ```
///
/// # Overflow Handling
/// When elapsed time exceeds 655.35 seconds (65535 centiseconds):
/// - Client sets elapsed_time field to 0xFFFF
/// - Indicates "at least 655.35 seconds"
/// - Client continues retransmitting with 0xFFFF until exchange completes
///
/// # Usage in All Client Messages
/// Client includes Elapsed Time option in:
/// - SOLICIT, REQUEST, RENEW, REBIND
/// - CONFIRM, RELEASE, DECLINE
/// - INFORMATION-REQUEST
///
/// Per RFC 3315 Section 22.9
pub const OPTION_ELAPSED_TIME: u16 = 8;

/// Status Code option (13)
///
/// Indicates success or reason for failure with numeric status code and optional
/// human-readable UTF-8 status message. Can appear at top level or encapsulated
/// within IA_NA/IA_TA/IA_PD/IAADDR/IAPREFIX for per-IA or per-address status.
///
/// # Structure
/// - **Status code**: 2-byte unsigned value (see DHCP6SUCCESS, DHCP6NOADDRS, etc.)
/// - **Status message**: Variable-length UTF-8 string (may be empty)
///
/// # Status Code Values (see STATUS_* constants)
/// - **SUCCESS (0)**: Operation succeeded
/// - **UNSPEC (1)**: Failure for unspecified reason
/// - **NOADDRS (2)**: No addresses available to assign
/// - **NOBINDING (3)**: Client's IA unknown to server (lease expired/lost)
/// - **NOTONLINK (4)**: Client's addresses not appropriate for link (CONFIRM response)
/// - **USEMULTICAST (5)**: Client should use multicast, not unicast
/// - **NOPREFIXAVAIL (6)**: No prefixes available for delegation (IA_PD)
///
/// # Status Code Placement
///
/// ## Top-Level Status
/// Status Code at REPLY message level indicates overall transaction status.
/// Applies to entire message if no per-IA status codes present.
///
/// ## Per-IA Status
/// Status Code encapsulated within IA_NA/IA_TA/IA_PD indicates status for
/// that specific Identity Association. Multiple IAs can have different statuses.
///
/// ## Per-Address Status
/// Status Code encapsulated within IAADDR or IAPREFIX indicates status for
/// specific address or prefix within IA.
///
/// # Status Message Content
/// - UTF-8 encoded text for human consumption (logging, display)
/// - Should be meaningful to network administrators
/// - May be empty (length 0) if status code is self-explanatory
/// - May be localized based on server configuration
/// - Examples:
///   - "All addresses in pool exhausted"
///   - "Client binding not found in lease database"
///   - "Address already assigned to another client"
///
/// # Multiple Status Codes
/// Single REPLY message may contain multiple Status Code options:
/// - One at message level (overall status)
/// - One per IA_NA (per-IA status)
/// - One per IAADDR within IA (per-address status)
///
/// Per RFC 3315 Section 22.13
pub const OPTION_STATUS_CODE: u16 = 13;

/// Rapid Commit option (14)
///
/// Enables optimized two-message exchange (SOLICIT/REPLY) instead of standard
/// four-message exchange (SOLICIT/ADVERTISE/REQUEST/REPLY). Reduces address
/// assignment latency by 50% when both client and server support rapid commit.
///
/// # Standard 4-Message Exchange
/// ```text
/// Client                Server
///   |                      |
///   |------ SOLICIT ------>|
///   |<---- ADVERTISE ------|
///   |------ REQUEST ------>|
///   |<------ REPLY --------|
///   |                      |
/// ```
///
/// # Rapid Commit 2-Message Exchange
/// ```text
/// Client                Server
///   |                      |
///   |------ SOLICIT ------>|  (with Rapid Commit option)
///   |<------ REPLY --------|  (with Rapid Commit option, assigned addresses)
///   |                      |
/// ```
///
/// # Negotiation
/// 1. Client includes empty Rapid Commit option in SOLICIT to indicate support
/// 2. Server decides whether to honor rapid commit based on:
///    - Server configuration (rapid commit enabled/disabled)
///    - Current load (may fall back to 4-message if overloaded)
///    - Available addresses (needs immediate allocation capability)
/// 3. If server accepts:
///    - Server includes Rapid Commit option in REPLY
///    - Server immediately assigns addresses (no ADVERTISE/REQUEST needed)
/// 4. If server declines rapid commit:
///    - Server sends normal ADVERTISE (without Rapid Commit option)
///    - Client falls back to 4-message exchange
///
/// # Option Format
/// Zero-length option (no option data). Presence indicates rapid commit support/acceptance.
///
/// # Benefits
/// - **Reduced latency**: 2 round-trips instead of 4
/// - **Lower overhead**: Fewer messages, less processing
/// - **Faster connectivity**: Client gets address faster
///
/// # Trade-offs
/// - **No server selection**: Client can't compare multiple ADVERTISE messages
/// - **Commitment risk**: Server commits addresses without REQUEST confirmation
/// - **Best for**: Single-server networks or when latency more critical than selection
///
/// # When to Use
/// - Single DHCPv6 server in network segment
/// - Low-latency requirements (real-time applications, fast boot)
/// - Mobile/roaming clients needing quick address assignment
/// - Server has abundant address pool (low allocation failure risk)
///
/// # When NOT to Use
/// - Multiple DHCPv6 servers (client benefits from server comparison)
/// - Address scarcity (server needs REQUEST confirmation before committing)
/// - Complex address selection policies requiring ADVERTISE review
///
/// Per RFC 3315 Section 22.14
pub const OPTION_RAPID_COMMIT: u16 = 14;

/// User Class option (15)
///
/// Contains one or more opaque fields identifying user class of client. Allows
/// network administrator to classify clients and apply class-specific configuration
/// policies (address pools, options, permissions).
///
/// # Structure
/// List of opaque data fields, each with 2-byte length:
/// ```text
/// [length1][data1][length2][data2]...
/// ```
///
/// # Use Cases
/// - **Department-based addressing**: Engineering, Sales, Guest user classes
/// - **Role-based configuration**: Employees, contractors, visitors
/// - **Service-level policies**: Premium, standard, basic user classes
/// - **VLAN assignment**: User class determines VLAN placement
///
/// # Client Configuration
/// Client sets User Class based on:
/// - OS/device configuration
/// - User login credentials
/// - Application requirements
/// - Network admission control results
///
/// # Server Policy Examples
/// ```text
/// User Class "ENGINEERING":
///   - Address pool: 2001:db8:100::/56
///   - DNS servers: 2001:db8:100::53, 2001:db8:100::54
///   - NTP servers: 2001:db8:100::123
///
/// User Class "GUEST":
///   - Address pool: 2001:db8:200::/56  
///   - DNS servers: 8.8.8.8, 8.8.4.4 (public DNS only)
///   - Limited prefixes (guest isolation)
/// ```
///
/// # DHCPv4 Equivalent
/// Similar to DHCPv4 User Class option (option 77). Provides consistent
/// user classification across IPv4 and IPv6 networks.
///
/// # Multiple User Classes
/// Client may include multiple user class values if belonging to multiple
/// classifications simultaneously.
///
/// Per RFC 3315 Section 22.15
pub const OPTION_USER_CLASS: u16 = 15;

/// Vendor Class option (16)
///
/// Contains IANA enterprise number and one or more opaque fields identifying
/// vendor-specific client class. Allows vendor-specific client identification
/// and configuration (device types, models, firmware versions).
///
/// # Structure
/// - **Enterprise number**: 4-byte IANA-assigned enterprise number
/// - **Vendor class data**: One or more opaque fields with 2-byte lengths
///
/// # Enterprise Numbers
/// - Assigned by IANA (Internet Assigned Numbers Authority)
/// - Uniquely identify vendors/organizations
/// - Examples:
///   - Microsoft: 311
///   - Cisco: 9
///   - Red Hat: 2312
///
/// # Use Cases
/// - **Device type identification**: Phones, printers, IoT devices
/// - **Firmware-specific configuration**: Different settings per firmware version
/// - **Vendor-specific features**: Enable vendor extensions based on client type
/// - **Inventory management**: Track device types in network
///
/// # Server Policy Examples
/// ```text
/// Vendor Class (Enterprise 9, Cisco):
///   - Cisco-specific options
///   - TFTP server for phone provisioning
///   - VLAN assignment per device model
///
/// Vendor Class (IoT vendor):
///   - Restricted addressing (IoT VLAN)
///   - Limited options (minimal configuration)
///   - Firewall rules (IoT segmentation)
/// ```
///
/// # DHCPv4 Equivalent
/// Similar to DHCPv4 Vendor Class Identifier (option 60), but DHCPv6 version
/// includes formal enterprise number for vendor identification.
///
/// Per RFC 3315 Section 22.16
pub const OPTION_VENDOR_CLASS: u16 = 16;

/// Vendor-specific Information option (17)
///
/// Contains enterprise number and vendor-defined options. Allows vendors to
/// define custom options for proprietary features without IANA option code
/// assignment. Vendor options encapsulated within standard DHCPv6 option.
///
/// # Structure
/// - **Enterprise number**: 4-byte IANA enterprise number identifying vendor
/// - **Vendor options**: Variable-length vendor-defined option data
///
/// # Vendor Option Format
/// Within vendor-specific option data:
/// ```text
/// [enterprise_number (4 bytes)]
/// [option_code (2 bytes)][option_length (2 bytes)][option_data]
/// [option_code (2 bytes)][option_length (2 bytes)][option_data]
/// ...
/// ```
///
/// # Use Cases
/// - **Proprietary features**: Vendor-specific functionality not in DHCPv6 RFCs
/// - **Device provisioning**: Phone config, printer settings, IoT parameters
/// - **Vendor extensions**: Custom options without IANA standardization
/// - **Backward compatibility**: Vendor features during standardization process
///
/// # Examples
///
/// ## Cisco IP Phone Provisioning
/// - Enterprise 9 (Cisco)
/// - TFTP server address for config download
/// - VLAN ID for voice VLAN
/// - Call manager addresses
///
/// ## Printer Configuration
/// - Enterprise number for printer vendor
/// - Print server addresses
/// - Default paper size, resolution settings
/// - Firmware update server
///
/// # Multiple Vendor Options
/// Message may contain multiple OPTION6_VENDOR_OPTS options from different
/// vendors (different enterprise numbers). Client processes options matching
/// its vendor enterprise numbers.
///
/// # Vendor Responsibility
/// Vendors define:
/// - Option codes within their enterprise number space
/// - Option data formats
/// - Option semantics
/// - Documentation for network administrators
///
/// Per RFC 3315 Section 22.17
pub const OPTION_VENDOR_OPTS: u16 = 17;

/// DNS Recursive Name Server option (23)
///
/// Contains one or more IPv6 addresses of recursive DNS servers available to
/// client. Essential configuration for network connectivity and name resolution.
///
/// # Structure
/// List of 16-byte IPv6 addresses:
/// ```text
/// [IPv6_addr1][IPv6_addr2][IPv6_addr3]...
/// ```
///
/// # Usage
/// - **Stateless DHCPv6**: Primary option requested in INFORMATION-REQUEST
/// - **Stateful DHCPv6**: Included in REPLY with address assignment
/// - **Critical for connectivity**: Required for DNS name resolution
///
/// # Client Configuration
/// Client receives DNS server addresses and configures system resolver:
/// 1. Add DNS servers to resolver configuration
/// 2. Order servers by preference (typically as listed in option)
/// 3. Use for all DNS queries
///
/// # Multiple DNS Servers
/// - **Redundancy**: Multiple servers for fault tolerance
/// - **Load balancing**: Distribute queries across servers
/// - **Typical deployment**: 2-3 DNS servers (primary, secondary, tertiary)
///
/// # Server Selection by Client
/// Client typically:
/// 1. Tries first DNS server in list
/// 2. Falls back to second server if first unreachable/slow
/// 3. May query multiple servers concurrently for performance
///
/// # Examples
/// ```text
/// Single DNS server:
///   2001:4860:4860::8888 (Google Public DNS)
///
/// Multiple DNS servers (redundant):
///   2001:4860:4860::8888 (Google Public DNS primary)
///   2001:4860:4860::8844 (Google Public DNS secondary)
///
/// Enterprise DNS:
///   2001:db8:100::53 (Internal DNS primary)
///   2001:db8:100::54 (Internal DNS secondary)
/// ```
///
/// # Router Advertisement Integration
/// DHCPv6 DNS servers complement or override DNS servers provided via
/// Router Advertisement RDNSS option (RFC 8106). DHCPv6 typically takes
/// precedence when both present.
///
/// # RFC Reference
/// Per RFC 3646 Section 3 (DNS Configuration Options for DHCPv6)
pub const OPTION_DNS_SERVER: u16 = 23;

/// Domain Search List option (24)
///
/// Contains list of domain names forming DNS search list for hostname resolution.
/// When client resolves non-fully-qualified domain names (no trailing dot),
/// client appends search domains from list.
///
/// # Structure
/// Sequence of domain names in DNS wire format (length-label encoding with
/// compression). Multiple domain names concatenated.
///
/// # DNS Wire Format Example
/// Domain search list [example.com, corp.example.com]:
/// ```text
/// 0x07 "example" 0x03 "com" 0x00
/// 0x04 "corp" 0x07 "example" 0x03 "com" 0x00
/// ```
/// (With DNS name compression, "example.com" in second name uses pointer to first)
///
/// # Usage in Name Resolution
/// When resolving hostname "server":
/// 1. Try "server." (absolute, with trailing dot)
/// 2. Try "server.example.com."
/// 3. Try "server.corp.example.com."
/// 4. If all fail, return NXDOMAIN
///
/// # Client Configuration
/// Client configures resolver search domains:
/// - Linux: /etc/resolv.conf "search" directive
/// - Windows: DNS suffix search list
/// - Order matters: Search domains tried in listed order
///
/// # Search List Length
/// - **Recommended**: 2-4 domains (avoid excessive search list)
/// - **Maximum**: Limited by DHCPv6 option size (65535 bytes)
/// - **Performance**: Longer lists increase query count for failed lookups
///
/// # Examples
///
/// ## Corporate Network
/// ```text
/// Search list: [corp.example.com, example.com]
/// Query "fileserver" →
///   Try fileserver.corp.example.com
///   Try fileserver.example.com
/// ```
///
/// ## Multi-Site Organization
/// ```text
/// Search list: [eng.example.com, sales.example.com, example.com]
/// Query "printserver" →
///   Try printserver.eng.example.com
///   Try printserver.sales.example.com
///   Try printserver.example.com
/// ```
///
/// # Best Practices
/// - Include most specific domains first (eng.example.com before example.com)
/// - Limit list to domains under organization control (avoid public domains)
/// - Consider query overhead for non-existent names
///
/// # RFC Reference
/// Per RFC 3646 Section 4 (DNS Configuration Options for DHCPv6)
pub const OPTION_DOMAIN_SEARCH: u16 = 24;

/// Identity Association for Prefix Delegation option (25)
///
/// IA_PD (Identity Association - Prefix Delegation) used for delegating IPv6
/// prefixes to requesting routers. Router receives prefix(es) to assign addresses
/// on downstream networks. Essential for hierarchical IPv6 addressing.
///
/// # IA_PD Structure
/// - **IAID**: 4-byte Identity Association Identifier (chosen by requesting router)
/// - **T1**: 4-byte renewal time (when requesting router should send RENEW)
/// - **T2**: 4-byte rebind time (when requesting router should send REBIND)
/// - **IA_PD-options**: Encapsulated IAPREFIX options containing delegated prefixes
///
/// # Prefix Delegation Use Case
/// ```text
/// ISP Router (delegating router)
///     |
///     | IA_PD: 2001:db8:1000::/48
///     |
/// Customer Router (requesting router)
///     |
///     |-- LAN1: 2001:db8:1000:1::/64
///     |-- LAN2: 2001:db8:1000:2::/64
///     |-- LAN3: 2001:db8:1000:3::/64
///     |-- DMZ:  2001:db8:1000:10::/64
/// ```
///
/// # Message Flow
/// 1. Requesting router sends SOLICIT with IA_PD
/// 2. Delegating router (DHCPv6 server) responds with ADVERTISE containing IA_PD with IAPREFIX
/// 3. Requesting router sends REQUEST
/// 4. Delegating router responds with REPLY, delegates prefix(es)
/// 5. Requesting router assigns addresses from delegated prefix to downstream networks
///
/// # Multiple Prefixes
/// Single IA_PD can contain multiple IAPREFIX options for multiple prefix delegation:
/// - Different prefix lengths (/56, /60, /64)
/// - Different prefix ranges
/// - Primary and backup prefixes
///
/// # Renewal Timing
/// - **T1**: Requesting router sends RENEW to original delegating router
/// - **T2**: Requesting router sends REBIND to any delegating router
/// - Timers operate identically to IA_NA timers
///
/// # Common Prefix Lengths
/// - **/48**: Typical delegation to small business or power user
/// - **/56**: Common residential delegation (256 /64 subnets)
/// - **/60**: Conservative residential delegation (16 /64 subnets)
/// - **/64**: Single subnet delegation (not recommended, limits flexibility)
///
/// # ISP Deployment
/// ISPs use prefix delegation to:
/// - Automate customer prefix assignment
/// - Enable customer multi-subnet networks
/// - Support IPv6 home routers without manual configuration
/// - Provide hierarchical addressing structure
///
/// # RFC Reference
/// Per RFC 3633 Section 9 (IPv6 Prefix Options for DHCPv6)
pub const OPTION_IA_PD: u16 = 25;

/// IA Prefix option (26)
///
/// IAPREFIX option encapsulated within IA_PD, containing delegated IPv6 prefix,
/// prefix length, and lifetimes. Delegating router assigns prefix to requesting
/// router for use on downstream networks.
///
/// # IAPREFIX Structure
/// - **Preferred lifetime**: 4-byte value in seconds
/// - **Valid lifetime**: 4-byte value in seconds  
/// - **Prefix length**: 1-byte prefix length (CIDR notation, e.g., 48 for /48)
/// - **IPv6 prefix**: 16-byte IPv6 prefix
/// - **IAprefix-options**: Encapsulated options (typically Status Code if problems)
///
/// # Lifetime Semantics
///
/// ## Preferred Lifetime
/// - Time prefix should be used for address assignment on downstream networks
/// - After preferred lifetime expires, prefix becomes "deprecated"
/// - Deprecated prefixes: Don't assign new addresses, existing assignments valid
/// - Infinite lifetime: 0xFFFFFFFF
///
/// ## Valid Lifetime
/// - Time prefix is valid for any use
/// - After valid lifetime expires, prefix must not be used
/// - Valid lifetime ≥ preferred lifetime (always)
/// - Infinite lifetime: 0xFFFFFFFF
///
/// # Example Delegated Prefix
/// ```text
/// Preferred lifetime: 86400 (1 day)
/// Valid lifetime: 172800 (2 days)
/// Prefix length: 56
/// IPv6 prefix: 2001:db8:1000::/56
/// ```
///
/// Requesting router can assign addresses from:
/// - 2001:db8:1000:0::/64 through 2001:db8:10ff::/64 (256 /64 subnets)
///
/// # Prefix Assignment by Requesting Router
/// After receiving delegated prefix, requesting router:
/// 1. Assigns /64 subnets from delegated prefix to downstream interfaces
/// 2. Advertises /64 prefixes via Router Advertisement
/// 3. Clients on downstream networks use SLAAC or DHCPv6 for address assignment
/// 4. Requesting router routes packets for entire delegated prefix
///
/// # Renewal
/// - Requesting router sends RENEW at T1 to extend prefix lifetimes
/// - Delegating router responds with REPLY updating lifetimes
/// - Lifetimes can be extended or reduced based on policy
///
/// # Status Code in IAPREFIX
/// Per-prefix Status Code option may be encapsulated to indicate problems:
/// - NOPREFIXAVAIL: No prefixes available for delegation
/// - NOBINDING: Prefix binding unknown to server
///
/// # Multiple Prefixes in IA_PD
/// Single IA_PD can contain multiple IAPREFIX options:
/// - Larger aggregate prefix split into multiple delegations
/// - Different prefix lengths for different purposes
/// - Primary and backup prefix delegation
///
/// # RFC Reference
/// Per RFC 3633 Section 10 (IPv6 Prefix Options for DHCPv6)
pub const OPTION_IAPREFIX: u16 = 26;

/// Network Time Protocol Servers option (56)
///
/// Provides client with NTP server information for system time synchronization.
/// Contains NTP suboptions specifying server addresses (unicast IPv6), multicast
/// addresses, or server FQDNs.
///
/// # Structure
/// List of NTP suboptions:
/// - **NTP_SUBOPTION_SRV_ADDR (1)**: IPv6 unicast server addresses
/// - **NTP_SUBOPTION_MC_ADDR (2)**: IPv6 multicast addresses  
/// - **NTP_SUBOPTION_SRV_FQDN (3)**: Server fully qualified domain names
///
/// # Suboption Format
/// Each suboption:
/// ```text
/// [suboption_code (2 bytes)][suboption_length (2 bytes)][suboption_data]
/// ```
///
/// # NTP Server Address Suboption (1)
/// Most common suboption. Contains one or more 16-byte IPv6 addresses of
/// unicast NTP servers.
///
/// Example:
/// ```text
/// Suboption 1 (Server Address)
/// Length: 32 (two IPv6 addresses)
/// Data: [2001:db8:100::123][2001:db8:100::124]
/// ```
///
/// # NTP Multicast Address Suboption (2)
/// Contains IPv6 multicast addresses for NTP broadcast/multicast mode.
/// Client listens for NTP broadcasts on these multicast groups.
///
/// Less common than unicast NTP. Used in networks with NTP multicast infrastructure.
///
/// # NTP Server FQDN Suboption (3)
/// Contains fully qualified domain names of NTP servers in DNS wire format.
/// Client resolves FQDNs to IPv6 addresses.
///
/// Example:
/// ```text
/// Suboption 3 (Server FQDN)
/// Data: [0x04 "ntp1" 0x07 "example" 0x03 "com" 0x00]
/// ```
///
/// Benefit: NTP server IP can change without DHCPv6 reconfiguration.
///
/// # Client NTP Configuration
/// Client receives NTP server option and:
/// 1. Extracts NTP server addresses/FQDNs from suboptions
/// 2. Configures NTP client (ntpd, chronyd, systemd-timesyncd)
/// 3. Begins time synchronization with provided servers
///
/// # Multiple NTP Servers
/// Option typically contains 2-4 NTP servers for redundancy and accuracy.
/// Client can:
/// - Query all servers and use best time source
/// - Use multiple servers for improved accuracy (NTP algorithms)
/// - Fall back to secondary servers if primary unreachable
///
/// # Time Synchronization Importance
/// Accurate time synchronization critical for:
/// - Security (Kerberos, TLS certificate validation, log correlation)
/// - Distributed systems (database consistency, cluster coordination)
/// - Compliance (audit logs, financial transactions require time accuracy)
///
/// # Public NTP Servers
/// Organizations may provide public NTP servers via DHCPv6:
/// - NTP Pool Project servers
/// - Vendor time servers (time.google.com, time.windows.com)
/// - National time authority servers (NIST, USNO)
///
/// # RFC Reference
/// Per RFC 5908 (Network Time Protocol (NTP) Server Option for DHCPv6)
pub const OPTION_NTP_SERVER: u16 = 56;

/// Client Link-Layer Address option (79)
///
/// Contains client's link-layer address (typically MAC address). Useful when
/// relay agent operation prevents server from determining client's MAC address
/// through normal packet inspection.
///
/// # Structure
/// - **Link-layer type**: 2-byte hardware type (per IANA ARP Parameters, typically 1 for Ethernet)
/// - **Link-layer address**: Variable-length address (6 bytes for Ethernet MAC)
///
/// # Example (Ethernet)
/// ```text
/// Link-layer type: 0x0001 (Ethernet)
/// Address: 00:11:22:33:44:55
/// ```
///
/// # Use Cases
///
/// ## Relay Agent Scenarios
/// When DHCPv6 relay agent forwards client message to server:
/// - Server receives packet from relay agent, not directly from client
/// - Source IPv6 address is relay agent's, not client's
/// - Link-layer address not accessible from IPv6 packet
/// - Relay agent can add Client Link-Layer Address option
///
/// ## Server Policy Based on MAC
/// Server may use MAC address for:
/// - **Address assignment policies**: Specific MAC gets specific address/prefix
/// - **Access control**: Whitelist/blacklist MAC addresses
/// - **Reservations**: Static address assignments based on MAC
/// - **Logging/auditing**: Correlate DHCPv6 transactions with network access logs
///
/// ## SLAAC Correlation
/// Correlate DHCPv6 stateless configuration with SLAAC addresses:
/// - SLAAC address derived from MAC (EUI-64)
/// - Server knows MAC from Client Link-Layer Address option
/// - Can correlate stateless DHCPv6 client with SLAAC-assigned addresses
///
/// # Relay Agent Insertion
/// - Relay agent MAY add Client Link-Layer Address option if not present in client message
/// - Relay agent extracts MAC from link-layer frame carrying DHCPv6 message
/// - Server uses option if present, ignores if absent
///
/// # Privacy Considerations
/// MAC address is persistent identifier that can track client across networks:
/// - Privacy-conscious clients may randomize MAC addresses
/// - Option reveals MAC even when using privacy addresses (IA_TA)
/// - Relay agents should consider privacy implications before adding option
///
/// # Link-Layer Types
/// Common hardware types (IANA ARP Parameters):
/// - **1**: Ethernet (10 Mb, 100 Mb, 1 Gb, 10 Gb, ...)
/// - **6**: IEEE 802 Networks (Token Ring, etc.)
/// - **24**: Other (Wireless)
///
/// # RFC Reference
/// Per RFC 6939 (Client Link-layer Address Option in DHCPv6)
pub const OPTION_CLIENT_MAC: u16 = 79;

/// Fully Qualified Domain Name option (39)
///
/// Allows client and server to negotiate client's FQDN and responsibility for
/// DNS dynamic updates. Enables automatic DNS registration of DHCPv6 clients.
///
/// # Structure
/// - **Flags**: 1-byte field with S, O, N bits
/// - **Domain name**: Variable-length domain name in DNS wire format
///
/// # Flags
///
/// ## S (Server) Flag (bit 0)
/// - **1**: Server should perform DNS forward (A/AAAA) and reverse (PTR) updates
/// - **0**: Client will perform DNS updates
///
/// ## O (Override) Flag (bit 1)
/// - **1**: Server should override client's S flag preference
/// - **0**: Server should honor client's S flag
///
/// ## N (No-update) Flag (bit 2)
/// - **1**: No party should perform DNS updates for this client
/// - **0**: DNS updates should be performed
///
/// # DNS Update Scenarios
///
/// ## Server Performs Updates (S=1)
/// 1. Client includes FQDN option with S=1 in REQUEST
/// 2. Server responds with FQDN option confirming S=1
/// 3. Server performs DNS updates:
///    - Forward: AAAA record for client's FQDN → IPv6 address
///    - Reverse: PTR record for IPv6 address → client's FQDN
/// 4. Client does not perform DNS updates
///
/// ## Client Performs Updates (S=0)
/// 1. Client includes FQDN option with S=0 in REQUEST
/// 2. Server responds with FQDN option confirming S=0
/// 3. Client performs DNS updates after receiving REPLY
/// 4. Server does not perform DNS updates
///
/// ## No Updates (N=1)
/// 1. Client includes FQDN option with N=1
/// 2. Neither client nor server performs DNS updates
/// 3. Used when DNS updates handled by other mechanism or not desired
///
/// # Domain Name Formats
///
/// ## Fully Qualified Domain Name
/// ```text
/// Client provides: client.example.com
/// DNS wire format: 0x06 "client" 0x07 "example" 0x03 "com" 0x00
/// ```
///
/// ## Partial Domain Name
/// ```text
/// Client provides: client (partial)
/// Server appends domain: client.example.com
/// ```
///
/// # Use Cases
/// - **Enterprise networks**: Automatic DNS registration for DHCP clients
/// - **Dynamic environments**: VMs, containers with dynamic hostnames
/// - **BYOD**: Personal devices automatically get DNS entries
/// - **Troubleshooting**: Hostname resolution for diagnostics
///
/// # Security Considerations
/// - **DNS update authentication**: TSIG or SIG(0) recommended for DNS updates
/// - **Authorization**: Verify client authorized to use requested hostname
/// - **Conflict prevention**: Check for existing DNS records before update
/// - **Stale records**: Remove DNS records when lease expires
///
/// # RFC Reference
/// Per RFC 4704 (The DHCPv6 Client FQDN Option)
pub const OPTION_FQDN: u16 = 39;

// ============================================================================
// NTP Server Option Suboptions (RFC 5908 Section 4)
// ============================================================================

/// NTP Server Address suboption (1)
///
/// Suboption within OPTION6_NTP_SERVER (56) containing one or more IPv6 unicast
/// addresses of NTP servers. Most common NTP suboption type for standard NTP
/// client-server time synchronization.
///
/// # Structure
/// List of 16-byte IPv6 addresses:
/// ```text
/// [suboption_code (2 bytes)][suboption_length (2 bytes)]
/// [IPv6_addr1 (16 bytes)][IPv6_addr2 (16 bytes)]...
/// ```
///
/// # Usage
/// Client receives NTP server addresses and configures NTP client to:
/// 1. Contact specified NTP servers
/// 2. Synchronize system time
/// 3. Maintain accurate time through periodic synchronization
///
/// # Example
/// ```text
/// NTP Server Address suboption (code 1)
/// Length: 32 bytes (two servers)
/// Server 1: 2001:4860:4860::8888 (hypothetical NTP server)
/// Server 2: 2001:4860:4860::8844 (hypothetical NTP server backup)
/// ```
///
/// # Best Practices
/// - **Multiple servers**: Provide 3-4 servers for redundancy and improved accuracy
/// - **Stratum consideration**: Lower stratum (closer to reference clock) preferred
/// - **Geographic proximity**: Closer servers reduce network latency
/// - **Network path diversity**: Different paths improve resilience
///
/// Per RFC 5908 Section 4.1
pub const NTP_SUBOPTION_SRV_ADDR: u16 = 1;

/// NTP Multicast Address suboption (2)
///
/// Suboption within OPTION6_NTP_SERVER containing one or more IPv6 multicast
/// addresses for NTP multicast/broadcast mode. Client listens for NTP time
/// broadcasts on these multicast groups.
///
/// # Structure
/// List of 16-byte IPv6 multicast addresses:
/// ```text
/// [suboption_code (2 bytes)][suboption_length (2 bytes)]
/// [IPv6_multicast_addr1 (16 bytes)][IPv6_multicast_addr2 (16 bytes)]...
/// ```
///
/// # NTP Multicast Mode
/// - **Broadcast model**: NTP servers send periodic time broadcasts to multicast group
/// - **Client role**: Passive listening (no client requests to servers)
/// - **Lower overhead**: Clients don't generate NTP queries
/// - **Scalability**: One multicast serves many clients
///
/// # Multicast Address Example
/// ```text
/// NTP Multicast Address suboption (code 2)
/// Length: 16 bytes
/// Multicast address: FF05::101 (site-local NTP multicast)
/// ```
///
/// # When to Use
/// - Large networks with many NTP clients
/// - Broadcast infrastructure in place
/// - One-way time distribution acceptable
/// - Reduced network traffic priority
///
/// # Trade-offs vs. Unicast
/// | Feature | Unicast (suboption 1) | Multicast (suboption 2) |
/// |---------|----------------------|-------------------------|
/// | Client queries | Yes | No (passive listening) |
/// | Accuracy | Higher (bidirectional) | Lower (one-way) |
/// | Scalability | Limited | Excellent |
/// | Network overhead | Per-client queries | Single multicast |
///
/// # Less Common
/// Multicast NTP less common than unicast NTP in modern deployments. Most
/// networks use unicast NTP for better accuracy and compatibility.
///
/// Per RFC 5908 Section 4.2
pub const NTP_SUBOPTION_MC_ADDR: u16 = 2;

/// NTP Server FQDN suboption (3)
///
/// Suboption within OPTION6_NTP_SERVER containing one or more fully qualified
/// domain names of NTP servers in DNS wire format. Client resolves FQDNs to
/// IPv6 addresses and uses for time synchronization.
///
/// # Structure
/// One or more domain names in DNS wire format (length-label encoding):
/// ```text
/// [suboption_code (2 bytes)][suboption_length (2 bytes)]
/// [FQDN1 in DNS wire format][FQDN2 in DNS wire format]...
/// ```
///
/// # DNS Wire Format Example
/// FQDN "ntp.example.com":
/// ```text
/// 0x03 "ntp" 0x07 "example" 0x03 "com" 0x00
/// ```
///
/// # Client Processing
/// 1. Extract FQDN from suboption
/// 2. Perform DNS AAAA query to resolve FQDN to IPv6 address(es)
/// 3. Configure NTP client with resolved addresses
/// 4. Begin time synchronization
///
/// # Benefits of FQDN vs. IP Address
/// - **Flexibility**: NTP server IP address can change without DHCPv6 reconfiguration
/// - **Load balancing**: DNS can return multiple IPs (round-robin)
/// - **Geographic distribution**: DNS can return closest server based on client location
/// - **Maintenance**: Server IP changes transparent to clients
///
/// # Example Public NTP FQDNs
/// ```text
/// time.cloudflare.com
/// time.google.com
/// pool.ntp.org
/// time.windows.com
/// ```
///
/// # DNS Resolution Requirements
/// - Client must have functional DNS resolver (typically from OPTION6_DNS_SERVER)
/// - AAAA records must exist for NTP server FQDNs
/// - DNS resolution adds latency to initial NTP configuration
///
/// # Use Cases
/// - **Dynamic infrastructure**: NTP servers may change IPs (cloud, virtualized)
/// - **CDN-like NTP**: DNS returns geographically optimal NTP server
/// - **Anycast NTP**: Single FQDN resolves to multiple anycast IPs
/// - **Maintenance windows**: Graceful NTP server migration via DNS updates
///
/// Per RFC 5908 Section 4.3
pub const NTP_SUBOPTION_SRV_FQDN: u16 = 3;

// ============================================================================
// DHCPv6 Status Codes (RFC 3315 Section 24.4, RFC 3633)
// ============================================================================

/// Success status code (0)
///
/// Indicates successful operation. Sent in Status Code option within REPLY message
/// at top level or within IA_NA/IA_TA/IA_PD/IAADDR/IAPREFIX to confirm success.
///
/// # When Used
/// - **Address assignment**: Addresses successfully assigned to client
/// - **Renewal**: Address lifetimes successfully extended
/// - **Release**: Addresses successfully released and available for reassignment
/// - **Prefix delegation**: Prefixes successfully delegated to requesting router
/// - **Configuration**: Configuration parameters successfully provided
///
/// # Placement
/// - **Top-level**: Overall transaction succeeded
/// - **In IA_NA/IA_TA/IA_PD**: Specific Identity Association succeeded
/// - **In IAADDR/IAPREFIX**: Specific address/prefix succeeded
///
/// # Status Message
/// Optional UTF-8 status message may accompany SUCCESS code:
/// - "Address assigned successfully"
/// - "Lease renewed for 7 days"
/// - "Prefix delegated"
///
/// Per RFC 3315 Section 24.4
pub const STATUS_SUCCESS: u16 = 0;

/// Unspecified failure status code (1)
///
/// Indicates operation failed for unspecified or unknown reason. Generic error
/// status when more specific status code doesn't apply.
///
/// # When Used
/// - Server encountered internal error
/// - Database access failed
/// - Configuration error prevents operation
/// - Unknown failure condition
///
/// # Client Action
/// - Log error with status message
/// - May retry operation after delay
/// - May attempt alternate server (REBIND)
/// - Escalate to network administrator if persistent
///
/// # Status Message Examples
/// - "Internal server error"
/// - "Database unavailable"
/// - "Configuration error"
/// - "Unspecified failure occurred"
///
/// # Debugging
/// Server should log detailed error internally even if status message
/// generic. Administrators need specific error information for troubleshooting.
///
/// Per RFC 3315 Section 24.4
pub const STATUS_UNSPEC: u16 = 1;

/// No Addresses Available status code (2)
///
/// Server has no addresses available to assign to client from configured address
/// pools. Indicates address pool exhaustion or all addresses currently allocated.
///
/// # When Used
/// - **Pool exhaustion**: All addresses in pool assigned to other clients
/// - **Policy restriction**: Client doesn't match any pool's assignment criteria
/// - **Resource limits**: Server configured address limit reached
///
/// # Status Code Placement
/// - **Within IA_NA**: No addresses available for non-temporary IA
/// - **Within IA_TA**: No addresses available for temporary IA
/// - **NOT at message level**: Specific to IA, not entire transaction
///
/// # Client Action
/// 1. Log NOADDRS status with status message
/// 2. Continue using existing addresses until valid lifetime expires
/// 3. Attempt REBIND to alternate servers on link
/// 4. If REBIND fails, try SOLICIT to locate server with available addresses
/// 5. May need manual intervention if all servers exhausted
///
/// # Server Actions When Pool Exhausted
/// - Return Status Code NOADDRS in IA_NA/IA_TA
/// - Include helpful status message: "Address pool exhausted"
/// - Log pool exhaustion event (may indicate need to expand pool)
/// - Consider lease time reduction to reclaim addresses faster
/// - Review lease database for stale/expired entries
///
/// # Prevention
/// - **Adequate pool sizing**: Provision addresses for peak + growth
/// - **Lease time tuning**: Shorter leases for transient clients
/// - **Lease reclamation**: Remove expired leases promptly
/// - **Monitoring**: Alert on pool utilization thresholds (80%, 90%)
///
/// # Example Scenarios
///
/// ## Conference Wi-Fi
/// - 1000 attendees, /24 address pool (256 addresses)
/// - Pool exhausts during peak attendance
/// - Later arrivals receive NOADDRS status
/// - Early departures free addresses for late arrivals
///
/// ## Enterprise DHCP
/// - Address pool sized for 1000 devices
/// - Device count grows to 1100
/// - Last 100 devices receive NOADDRS
/// - Administrator expands pool or adjusts lease times
///
/// Per RFC 3315 Section 24.4
pub const STATUS_NOADDRS: u16 = 2;

/// No Binding status code (3)
///
/// Server has no record of client's binding (lease) for the Identity Association
/// referenced in client's message. Sent in response to RENEW, REBIND, RELEASE,
/// or DECLINE when client references unknown IA.
///
/// # Common Causes
/// - **Server restart**: Lease database lost or not persistent across restarts
/// - **Lease expiration**: Client's lease expired, server removed binding
/// - **Database corruption**: Lease database damaged or inconsistent
/// - **Server migration**: Client moved to new server without lease transfer
/// - **Clock skew**: Server and client clocks misaligned, lease appears expired
///
/// # When Sent
/// - **RENEW**: Client attempts to renew unknown/expired binding
/// - **REBIND**: Client attempts to rebind unknown/expired binding
/// - **RELEASE**: Client attempts to release unknown binding
/// - **DECLINE**: Client attempts to decline address from unknown binding
/// - **NOT CONFIRM**: CONFIRM validates addresses, not bindings
///
/// # Status Code Placement
/// - **Within IA_NA/IA_TA/IA_PD**: Specific IA has no binding
/// - **Multiple IAs**: Some IAs may have bindings, others NOBINDING
///
/// # Client Action
/// 1. Log NOBINDING status
/// 2. Stop using addresses/prefixes from affected IA immediately
/// 3. Reinitialize DHCPv6 with SOLICIT to obtain new binding
/// 4. Do NOT continue trying to RENEW unknown binding
///
/// # Server Actions
/// - Return Status Code NOBINDING in IA
/// - Optionally include status message explaining cause:
///   - "Lease expired"
///   - "No record of client binding"
///   - "Server restarted, lease database lost"
/// - Log event for administrator investigation
///
/// # Recovery Example
/// ```text
/// Client: RENEW (IA_NA with IAID 1, address 2001:db8::100)
/// Server: REPLY (IA_NA with NOBINDING status)
/// Client: Stop using 2001:db8::100
/// Client: SOLICIT (request new addresses)
/// Server: ADVERTISE (offer new addresses)
/// Client: REQUEST (accept new binding)
/// Server: REPLY (assign new addresses, create new binding)
/// ```
///
/// # Prevention
/// - **Persistent lease database**: Use storage that survives server restarts
/// - **Lease backups**: Regular backups of lease database
/// - **Adequate lease times**: Long enough to survive brief outages
/// - **Clock synchronization**: NTP ensures consistent time between client/server
///
/// Per RFC 3315 Section 24.4
pub const STATUS_NOBINDING: u16 = 3;

/// Not On Client status code (4)
///
/// The prefix or address is not appropriate for the link to which the client is attached.
/// Server sends this code when client sends CONFIRM asking to verify addresses are
/// appropriate for current link, but addresses are for different link/subnet.
///
/// # Primary Use: CONFIRM Response
/// Client sends CONFIRM message when:
/// - Client reboots and wants to verify existing addresses still valid
/// - Client detects potential network change (link up/down event)
/// - Client uncertain if addresses appropriate for current link
///
/// Server examines client's addresses and link information:
/// - **Addresses match current link**: Respond with SUCCESS
/// - **Addresses don't match current link**: Respond with NOTONCLIENT
///
/// # When Sent
/// - **CONFIRM response only**: This status code specific to CONFIRM/REPLY exchange
/// - **Link mismatch detected**: Addresses belong to different subnet than client's link
/// - **Not sent for**: RENEW, REBIND, REQUEST (those use SUCCESS/NOADDRS/NOBINDING)
///
/// # Client Action on Receipt
/// 1. Immediately stop using all addresses from IA with NOTONCLIENT status
/// 2. Addresses are invalid for current network location
/// 3. Reinitialize DHCPv6 with SOLICIT to obtain addresses appropriate for current link
/// 4. Client has likely moved to different network segment
///
/// # Example Scenario
/// ```text
/// Client configuration:
///   IA_NA with addresses: 2001:db8:100::10, 2001:db8:100::11
///   Client on link: 2001:db8:200::/64
///
/// Client: CONFIRM (verify 2001:db8:100::10 and 2001:db8:100::11)
/// Server: REPLY (Status Code NOTONCLIENT - addresses from wrong subnet)
/// Client: Stop using 2001:db8:100::* addresses
/// Client: SOLICIT (request addresses appropriate for 2001:db8:200::/64)
/// Server: REPLY (assign addresses from 2001:db8:200::/64 pool)
/// ```
///
/// # Mobile/Roaming Clients
/// Common with mobile clients that move between network segments:
/// - Laptop moves from office (subnet A) to home (subnet B)
/// - VM migrates from datacenter 1 to datacenter 2
/// - Mobile device roams between access points on different VLANs
///
/// # Server Link Detection Methods
/// Server determines client's link via:
/// - Link-address in RELAY-FORW (if relayed)
/// - Source IPv6 address (if direct, not relayed)
/// - Interface on which message received
/// - Relay agent Interface-Id option
///
/// Per RFC 3315 Section 24.4
pub const STATUS_NOTONCLIENT: u16 = 4;

/// Not On Link status code (5) 
///
/// Duplicate of STATUS_NOTONCLIENT (4). Both indicate client's addresses are not
/// appropriate for the link. RFC 3315 defines both names for same status value.
///
/// # Usage
/// Identical to STATUS_NOTONCLIENT (4). Used in CONFIRM response when client's
/// addresses don't match the link to which client is attached.
///
/// # Implementation Note
/// Both constant names (STATUS_NOTONCLIENT and STATUS_NOTONLINK) map to same
/// value (4) per RFC 3315. Either name may be used in code for clarity.
///
/// Per RFC 3315 Section 24.4
pub const STATUS_NOTONLINK: u16 = 4;

/// Use Multicast status code (5)
///
/// Server tells client to use All_DHCP_Relay_Agents_and_Servers multicast address
/// (FF02::1:2) instead of unicast when sending messages. Sent when client uses
/// unicast but server requires multicast communication.
///
/// # When Sent
/// - Client sends unicast message (SOLICIT, RENEW, REBIND, etc.) to server
/// - Server policy requires multicast for message type
/// - Server has NOT sent Server Unicast option authorizing unicast
///
/// # Why Server Requires Multicast
/// - **Relay agent coordination**: Server wants relay agents to see client messages
/// - **Server selection**: Multiple servers available, client should multicast for selection
/// - **Load balancing**: Multicast allows multiple servers to receive and respond
/// - **Policy enforcement**: Server restricts unicast to authorized clients only
///
/// # Client Action on Receipt
/// 1. Receive REPLY with USEMULTICAST status
/// 2. Note server requires multicast for this exchange
/// 3. Retransmit same message to multicast address FF02::1:2 instead of unicast
/// 4. Continue using multicast for this transaction
///
/// # Server Unicast Option
/// Server may send Server Unicast option (OPTION6_UNICAST) in ADVERTISE/REPLY
/// to explicitly authorize client to use server's unicast address for subsequent
/// messages. If server sends this option, client may use unicast without
/// receiving USEMULTICAST error.
///
/// # Example Flow
/// ```text
/// Client: RENEW (unicast to server 2001:db8::53)
/// Server: REPLY (Status Code USEMULTICAST)
/// Client: RENEW (multicast to FF02::1:2)
/// Server: REPLY (normal response, renewal accepted)
/// ```
///
/// # Unicast vs. Multicast Trade-offs
///
/// ## Unicast Benefits
/// - Lower network overhead (single destination)
/// - Faster (no multicast processing at routers/switches)
/// - Direct communication with known server
///
/// ## Multicast Benefits
/// - Relay agents can intercept and forward
/// - Multiple servers can respond (redundancy)
/// - Server selection when multiple servers available
/// - Required for initial SOLICIT (server discovery)
///
/// Per RFC 3315 Section 24.4
pub const STATUS_USEMULTICAST: u16 = 5;

/// No Prefix Available status code (6)
///
/// Server has no prefixes available to delegate to requesting router. Indicates
/// prefix pool exhaustion or requesting router doesn't match delegation policy.
/// Sent within IA_PD in response to prefix delegation request.
///
/// # When Used
/// - **Prefix pool exhausted**: All prefixes already delegated
/// - **Policy restriction**: Requesting router not authorized for prefix delegation
/// - **Resource limits**: Server reached maximum delegation count
/// - **Insufficient prefix space**: Available prefixes don't meet requested length
///
/// # Status Code Placement
/// - **Within IA_PD**: No prefixes available for this prefix delegation IA
/// - **NOT at message level**: Specific to IA_PD
/// - **Per-IA**: Multiple IA_PD options may have different statuses
///
/// # Client (Requesting Router) Action
/// 1. Log NOPREFIXAVAIL status with status message
/// 2. Continue using existing delegated prefixes until valid lifetime expires
/// 3. Attempt REBIND to alternate delegating routers
/// 4. If REBIND fails, try SOLICIT to locate server with available prefixes
/// 5. May need manual intervention or configuration
///
/// # Server Actions
/// - Return Status Code NOPREFIXAVAIL in IA_PD
/// - Include helpful status message:
///   - "Prefix pool exhausted"
///   - "No prefixes available for delegation"
///   - "Requesting router not authorized for prefix delegation"
/// - Log delegation failure event
/// - Review prefix pool configuration and utilization
///
/// # Common Scenarios
///
/// ## ISP Prefix Exhaustion
/// - ISP has /32 prefix pool
/// - Delegates /48 to each customer (65536 customers maximum)
/// - New customer requests /48, pool exhausted
/// - Server responds with NOPREFIXAVAIL
///
/// ## Prefix Length Mismatch
/// - Client requests /48 prefix
/// - Server only has /56 prefixes available
/// - Server may:
///   - Delegate available /56 (smaller than requested)
///   - Respond NOPREFIXAVAIL if policy requires exact match
///
/// ## Authorization Failure
/// - Client requests prefix delegation
/// - Server policy requires pre-authorization
/// - Client not in authorized list
/// - Server responds NOPREFIXAVAIL
///
/// # Prevention
/// - **Adequate prefix pool**: Size pool for expected delegation demand
/// - **Delegation monitoring**: Track prefix pool utilization
/// - **Reclamation**: Remove expired prefix delegations
/// - **Prefix length flexibility**: Support multiple delegation sizes
/// - **Hierarchical delegation**: Use larger prefix pool space
///
/// # Prefix Delegation Context
/// Used in DHCPv6 Prefix Delegation (RFC 3633) scenarios:
/// - ISP delegating prefixes to customer routers
/// - Enterprise delegating prefixes to branch routers
/// - Data center delegating prefixes to tenant routers
///
/// Per RFC 3633 (IPv6 Prefix Options for DHCPv6)
pub const STATUS_NOPREFIXAVAIL: u16 = 6;

// ============================================================================
// DUID Types (RFC 3315 Section 9.1-9.4)
// ============================================================================

/// DUID-LLT (Link-layer address plus time) type (1)
///
/// DUID type using link-layer address (typically MAC address) combined with
/// timestamp. Provides globally unique identifier with temporal component.
///
/// # Structure
/// - **DUID type**: 2 bytes (0x0001)
/// - **Hardware type**: 2 bytes (IANA hardware type, typically 1 for Ethernet)
/// - **Time**: 4 bytes (seconds since midnight Jan 1, 2000 UTC)
/// - **Link-layer address**: Variable length (6 bytes for Ethernet MAC)
///
/// # Example (Ethernet MAC 00:11:22:33:44:55 at time 0x12345678)
/// ```text
/// 0x0001 (DUID-LLT type)
/// 0x0001 (Ethernet hardware type)
/// 0x12345678 (timestamp)
/// 0x001122334455 (MAC address)
/// Total: 14 bytes
/// ```
///
/// # Timestamp Epoch
/// - **Epoch**: Midnight (UTC), January 1, 2000
/// - **Units**: Seconds since epoch
/// - **Y2K38**: Will overflow in year 2136 (not 2038 due to 2000 epoch)
///
/// # Uniqueness Guarantee
/// - **Spatial uniqueness**: MAC address globally unique (IEEE allocation)
/// - **Temporal uniqueness**: Timestamp ensures different DUID even if MAC reused
/// - **Collision resistance**: Extremely unlikely two devices have same MAC and time
///
/// # When to Use
/// - **Preferred DUID type**: Good balance of uniqueness and simplicity
/// - **Fresh installations**: Generate DUID-LLT at first boot
/// - **Hardware available**: Device has stable MAC address
/// - **Clock available**: System has reasonable time source (doesn't need to be accurate)
///
/// # Generation Process
/// 1. Read MAC address from network interface (typically first/primary interface)
/// 2. Read current system time (best available, NTP not required)
/// 3. Convert time to seconds since Jan 1, 2000 UTC
/// 4. Construct DUID-LLT structure
/// 5. Persist DUID to stable storage (configuration file, flash, NVRAM)
///
/// # Privacy Consideration
/// DUID-LLT embeds MAC address, making device trackable across networks.
/// Privacy-conscious deployments may prefer DUID-UUID or DUID-LL with
/// randomized MAC.
///
/// Per RFC 3315 Section 9.2
pub const DUID_LLT: u16 = 1;

/// DUID-EN (Enterprise number) type (2)
///
/// DUID type using IANA-assigned enterprise number plus vendor-assigned unique
/// identifier. Allows vendors to generate DUIDs using their own allocation scheme.
///
/// # Structure
/// - **DUID type**: 2 bytes (0x0002)
/// - **Enterprise number**: 4 bytes (IANA-assigned enterprise number)
/// - **Identifier**: Variable length (vendor-defined format)
///
/// # Example (Enterprise 311 [Microsoft], identifier 0x1234567890abcdef)
/// ```text
/// 0x0002 (DUID-EN type)
/// 0x00000137 (Enterprise number 311)
/// 0x1234567890abcdef (Vendor-assigned identifier)
/// Total: 14 bytes
/// ```
///
/// # Enterprise Numbers
/// - Assigned by IANA (Internet Assigned Numbers Authority)
/// - Uniquely identify organizations/vendors globally
/// - Examples:
///   - Microsoft: 311
///   - Cisco: 9
///   - Red Hat: 2312
///   - IBM: 2
///
/// # Vendor Identifier Format
/// - **Vendor-defined**: No standard format required
/// - **Uniqueness responsibility**: Vendor ensures uniqueness within their enterprise number
/// - **Common approaches**:
///   - Serial number
///   - UUID/GUID
///   - MAC address + product code
///   - Incrementing counter + manufacturing site code
///
/// # When to Use
/// - **Vendor products**: Devices manufactured by specific vendor
/// - **Enterprise management**: Organization controls DUID generation centrally
/// - **Custom allocation**: Vendor has specific DUID generation requirements
/// - **No MAC available**: Device lacks stable MAC address
///
/// # Benefits
/// - **Vendor control**: Vendor owns DUID generation process
/// - **Integration**: Can integrate with manufacturing/provisioning systems
/// - **Flexibility**: Vendor chooses identifier format and allocation method
/// - **Trackability**: Vendor can correlate DUID with device inventory
///
/// # Privacy Consideration
/// DUID-EN may embed device serial number or other identifying information
/// depending on vendor's identifier format. Less privacy-preserving than DUID-UUID.
///
/// Per RFC 3315 Section 9.3
pub const DUID_EN: u16 = 2;

/// DUID-LL (Link-layer address) type (3)
///
/// DUID type using link-layer address only (no timestamp). Simplest DUID type,
/// relies solely on MAC address uniqueness.
///
/// # Structure
/// - **DUID type**: 2 bytes (0x0003)
/// - **Hardware type**: 2 bytes (IANA hardware type, typically 1 for Ethernet)
/// - **Link-layer address**: Variable length (6 bytes for Ethernet MAC)
///
/// # Example (Ethernet MAC 00:11:22:33:44:55)
/// ```text
/// 0x0003 (DUID-LL type)
/// 0x0001 (Ethernet hardware type)
/// 0x001122334455 (MAC address)
/// Total: 10 bytes
/// ```
///
/// # Uniqueness Guarantee
/// - **Spatial uniqueness only**: Relies on MAC address global uniqueness
/// - **NO temporal component**: Same MAC always produces same DUID-LL
/// - **Collision possible**: If MAC address reused/cloned, DUID collision occurs
///
/// # When to Use
/// - **Simple devices**: Embedded systems, IoT devices with minimal resources
/// - **No clock**: Device has no reliable time source (not even approximate)
/// - **Stable MAC**: Device has permanent, unique MAC address
/// - **Legacy compatibility**: Some legacy systems expect DUID-LL
///
/// # Advantages
/// - **Simplicity**: Easiest DUID type to generate (no time required)
/// - **Minimal storage**: Only MAC address needs to be stored
/// - **Deterministic**: Same device always generates same DUID-LL
///
/// # Disadvantages
/// - **Collision risk**: If MAC cloned or reused, DUID collision
/// - **Privacy**: MAC address directly embedded, device easily trackable
/// - **No temporal uniqueness**: MAC address change requires DUID change
///
/// # MAC Address Reuse Scenarios
/// - **Virtual machines**: VMs may be cloned, duplicating MAC addresses
/// - **MAC spoofing**: Malicious actor deliberately clones MAC
/// - **Manufacturing errors**: Duplicate MACs from manufacturing process
/// - **Network interface replacement**: New NIC, different MAC, different DUID
///
/// # Comparison with DUID-LLT
/// | Feature | DUID-LL | DUID-LLT |
/// |---------|---------|----------|
/// | Requires clock | No | Yes |
/// | Uniqueness | MAC only | MAC + time |
/// | Collision risk | Higher | Lower |
/// | Size | 10 bytes | 14 bytes |
/// | Complexity | Simpler | More complex |
///
/// Per RFC 3315 Section 9.4
pub const DUID_LL: u16 = 3;

/// DUID-UUID (Universally Unique Identifier) type (4)
///
/// DUID type using UUID (Universally Unique Identifier) per RFC 4122. Provides
/// strong uniqueness guarantee without exposing hardware identifiers.
///
/// # Structure
/// - **DUID type**: 2 bytes (0x0004)
/// - **UUID**: 16 bytes (RFC 4122 UUID in network byte order)
///
/// # Example (UUID 550e8400-e29b-41d4-a716-446655440000)
/// ```text
/// 0x0004 (DUID-UUID type)
/// 0x550e8400e29b41d4a716446655440000 (UUID)
/// Total: 18 bytes
/// ```
///
/// # UUID Generation Methods (RFC 4122)
///
/// ## Version 1: Time-based UUID
/// - Generated from MAC address and timestamp
/// - Embeds MAC (privacy concern similar to DUID-LLT)
///
/// ## Version 4: Random UUID
/// - Generated from random numbers
/// - **Recommended for DUID-UUID**: Best privacy properties
/// - No hardware identifiers exposed
///
/// ## Version 5: Name-based (SHA-1)
/// - Generated from namespace and name using SHA-1
/// - Deterministic (same namespace + name = same UUID)
///
/// # When to Use
/// - **Privacy priority**: Don't want to expose MAC address or hardware identifiers
/// - **Virtual environments**: VMs where MAC address may be duplicated/changed
/// - **BYOD**: Personal devices where privacy important
/// - **Modern deployments**: Recommended for new implementations prioritizing privacy
///
/// # Advantages
/// - **Strong uniqueness**: UUID collision probability extremely low (2^-122)
/// - **Privacy-preserving**: No hardware identifiers embedded (if using UUIDv4)
/// - **Standardized**: UUID format well-defined and widely supported
/// - **Vendor-neutral**: No enterprise number or vendor-specific format required
///
/// # Generation Process (Recommended UUIDv4)
/// 1. Generate 128 bits of cryptographically secure random data
/// 2. Set version field to 4 (bits 48-51)
/// 3. Set variant field to RFC 4122 (bits 64-65)
/// 4. Persist UUID to stable storage
/// 5. Use as DUID for DHCPv6 client identification
///
/// # Collision Probability
/// UUID collision probability so low that UUIDs can be considered unique:
/// - **Random UUIDs**: 2^122 possible values
/// - **Collision probability**: Negligible even with billions of devices
///
/// # Comparison with Other DUID Types
/// | Feature | DUID-UUID | DUID-LLT | DUID-LL |
/// |---------|-----------|----------|---------|
/// | Privacy | Excellent | Poor | Poor |
/// | Uniqueness | Excellent | Good | Fair |
/// | Requires clock | No | Yes | No |
/// | Requires MAC | No | Yes | Yes |
/// | Size | 18 bytes | 14 bytes | 10 bytes |
///
/// # Recommended for New Implementations
/// DUID-UUID (specifically with UUIDv4) recommended for new DHCPv6 client
/// implementations prioritizing privacy and uniqueness without hardware dependency.
///
/// Per RFC 6355 (Definition of the UUID-Based DHCPv6 Unique Identifier)
pub const DUID_UUID: u16 = 4;
