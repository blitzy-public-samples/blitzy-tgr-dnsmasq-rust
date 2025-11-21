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

//! DHCPv6 (Dynamic Host Configuration Protocol for IPv6) subsystem module.
//!
//! This module provides complete DHCPv6 server functionality for stateful and stateless
//! IPv6 address configuration, replacing the C implementation from `src/dhcp6.c`,
//! `src/rfc3315.c`, `src/outpacket.c`, and `src/dhcp6-protocol.h` (totaling approximately
//! 7000 lines of C code) with memory-safe async Rust.
//!
//! # Architecture Overview
//!
//! The DHCPv6 subsystem is organized into five coordinated components:
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────┐
//! │                      DHCPv6 Subsystem                              │
//! │                    (src/dhcp/v6/mod.rs)                            │
//! ├────────────────────────────────────────────────────────────────────┤
//! │                                                                    │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
//! │  │ constants.rs │  │ message.rs   │  │ options.rs   │            │
//! │  │  (protocol)  │  │  (parsing)   │  │ (encoding)   │            │
//! │  └──────────────┘  └──────────────┘  └──────────────┘            │
//! │          ▲                 ▲                 ▲                     │
//! │          └─────────────────┴─────────────────┘                     │
//! │                            │                                       │
//! │  ┌──────────────────────────┴──────────────────────────┐          │
//! │  │             protocol.rs (state machine)             │          │
//! │  │  - SOLICIT→ADVERTISE→REQUEST→REPLY                 │          │
//! │  │  - RENEW, REBIND, RELEASE, DECLINE                 │          │
//! │  │  - INFORMATION-REQUEST (stateless)                 │          │
//! │  │  - Status code generation                          │          │
//! │  │  - DUID validation                                 │          │
//! │  └────────────────────────┬──────────────────────────┘          │
//! │                            │                                       │
//! │  ┌──────────────────────────┴──────────────────────────┐          │
//! │  │               server.rs (core service)              │          │
//! │  │  - tokio UDP socket handling (port 547)             │          │
//! │  │  - IPv6 address allocation (IA_NA)                  │          │
//! │  │  - Prefix delegation (IA_PD)                        │          │
//! │  │  - Lease time management (default 86400s)           │          │
//! │  │  - Router Advertisement M/O flag coordination       │          │
//! │  │  - Lease database integration                       │          │
//! │  └─────────────────────────────────────────────────────┘          │
//! │                                                                    │
//! └────────────────────────────────────────────────────────────────────┘
//!              │                                  │
//!              ▼                                  ▼
//!    ┌──────────────────┐            ┌──────────────────┐
//!    │ Runtime Event    │            │ Router           │
//!    │ Loop Integration │            │ Advertisement    │
//!    │ (tokio select)   │            │ (M/O flags)      │
//!    └──────────────────┘            └──────────────────┘
//! ```
//!
//! # RFC 3315 Compliance
//!
//! This implementation provides full RFC 3315 compliance for DHCPv6 protocol operations:
//!
//! ## Message Types
//!
//! - **SOLICIT (1)**: Client discovers available DHCPv6 servers
//! - **ADVERTISE (2)**: Server announces availability and addresses
//! - **REQUEST (3)**: Client requests specific server's addresses
//! - **CONFIRM (4)**: Client validates addresses after network change
//! - **RENEW (5)**: Client extends lease with original server
//! - **REBIND (6)**: Client extends lease with any server
//! - **REPLY (7)**: Server responds to client requests
//! - **RELEASE (8)**: Client relinquishes addresses
//! - **DECLINE (9)**: Client reports duplicate address detected
//! - **RECONFIGURE (10)**: Server triggers client reconfiguration
//! - **INFORMATION-REQUEST (11)**: Stateless configuration request
//! - **RELAY-FORW (12)**: Relay agent forwards client message
//! - **RELAY-REPL (13)**: Server replies to relay agent
//!
//! ## Identity Association Types
//!
//! - **IA_NA**: Identity Association for Non-temporary Addresses (Option 3)
//! - **IA_TA**: Identity Association for Temporary Addresses (Option 4)
//! - **IA_PD**: Identity Association for Prefix Delegation (Option 25, RFC 3633)
//!
//! ## Operation Modes
//!
//! ### Stateful DHCPv6 (M=1 in Router Advertisement)
//!
//! The server assigns and tracks IPv6 addresses with lease management:
//!
//! ```text
//! Client                          Server
//!   |                                |
//!   |-----SOLICIT------------------->|  (I need an address)
//!   |                                |  - Multicast to FF02::1:2
//!   |                                |  - Contains CLIENT_ID (DUID)
//!   |                                |  - Contains IA_NA (IAID)
//!   |                                |
//!   |<----ADVERTISE------------------|  (I can offer 2001:db8::1)
//!   |                                |  - SERVER_ID (server DUID)
//!   |                                |  - IA_NA with IAADDR option
//!   |                                |  - Preference value
//!   |                                |
//!   |-----REQUEST-------------------> |  (I want your address)
//!   |                                |  - CLIENT_ID + SERVER_ID
//!   |                                |  - IA_NA with requested addr
//!   |                                |
//!   |<----REPLY----------------------|  (Address assigned)
//!   |                                |  - IA_NA with IAADDR
//!   |                                |  - T1=3600s, T2=7200s
//!   |                                |  - Valid lifetime: 86400s
//!   |                                |
//!   | (Use address for T1 duration)  |
//!   |                                |
//!   |-----RENEW--------------------->|  (Extend lease at T1)
//!   |<----REPLY----------------------|  (Lease extended)
//!   |                                |
//! ```
//!
//! ### Stateless DHCPv6 (O=1, M=0 in Router Advertisement)
//!
//! The server provides configuration without address assignment:
//!
//! ```text
//! Client                          Server
//!   |                                |
//!   |-----INFORMATION-REQUEST------->|  (I need DNS/NTP config)
//!   |                                |  - No IA_NA option
//!   |                                |  - CLIENT_ID only
//!   |                                |
//!   |<----REPLY----------------------|  (Here's configuration)
//!   |                                |  - DNS_SERVER option
//!   |                                |  - DOMAIN_SEARCH option
//!   |                                |  - NTP_SERVER option
//!   |                                |
//! ```
//!
//! ### Rapid Commit Optimization (RFC 3315 Section 17.2.1)
//!
//! When both client and server support rapid commit, the four-message exchange
//! reduces to two messages:
//!
//! ```text
//! Client                          Server
//!   |                                |
//!   |-----SOLICIT-------------------> |  (with RAPID_COMMIT option)
//!   |<----REPLY----------------------|  (immediate assignment)
//! ```
//!
//! # Router Advertisement Coordination
//!
//! DHCPv6 operation mode is controlled by M (Managed address) and O (Other configuration)
//! flags in IPv6 Router Advertisement messages (ICMPv6 type 134). The DHCPv6 server
//! coordinates with the Router Advertisement module to ensure consistent behavior:
//!
//! | M Flag | O Flag | Behavior                                          |
//! |--------|--------|---------------------------------------------------|
//! | 0      | 0      | SLAAC only, no DHCPv6                             |
//! | 0      | 1      | SLAAC + stateless DHCPv6 (config only)            |
//! | 1      | 0      | Stateful DHCPv6 for addresses + SLAAC for config  |
//! | 1      | 1      | Stateful DHCPv6 for addresses and configuration   |
//!
//! # Prefix Delegation (IA_PD, RFC 3633)
//!
//! For hierarchical network deployments, DHCPv6 supports prefix delegation allowing
//! routers to obtain IPv6 prefixes for their downstream networks:
//!
//! ```rust,ignore
//! // Request prefix delegation
//! let mut solicit = DhcpV6Message::new(constants::MSG_SOLICIT, xid);
//! solicit.add_option(constants::OPTION_CLIENT_ID, client_duid);
//! solicit.add_option(constants::OPTION_IA_PD, ia_pd_option);
//!
//! // Server responds with delegated prefix
//! let mut reply = DhcpV6Message::new(constants::MSG_REPLY, xid);
//! reply.add_option(constants::OPTION_SERVER_ID, server_duid);
//!
//! // IA_PD contains IAPREFIX option with delegated prefix
//! let mut ia_pd = OptionBuilder::new();
//! ia_pd.start_container(constants::OPTION_IA_PD)?;
//! ia_pd.put_u32(iaid)?;
//! ia_pd.put_u32(t1)?;
//! ia_pd.put_u32(t2)?;
//!
//! ia_pd.start_container(constants::OPTION_IAPREFIX)?;
//! ia_pd.put_u32(preferred_lifetime)?;  // 7200s
//! ia_pd.put_u32(valid_lifetime)?;      // 14400s
//! ia_pd.put_u8(prefix_length)?;        // /56 or /48
//! ia_pd.put_ipv6_addr(&prefix)?;       // 2001:db8:1::/48
//! ia_pd.end_container()?;
//!
//! ia_pd.end_container()?;
//! ```
//!
//! # DUID (DHCP Unique Identifier)
//!
//! DHCPv6 uses DUIDs instead of MAC addresses for client identification, providing
//! stable identity across network changes. Three DUID types are supported:
//!
//! ## DUID-LLT (Link-Layer Time, Type 1)
//!
//! ```text
//! Format: Type (2) || Hardware Type (2) || Time (4) || Link-Layer Address (variable)
//! Example: 00 01 00 01 6b 8e 0f 1c 52 54 00 12 34 56
//!          ^^    ^^    ^^          ^^
//!          Type  HW    Time        MAC Address
//! ```
//!
//! ## DUID-EN (Enterprise Number, Type 2)
//!
//! ```text
//! Format: Type (2) || Enterprise Number (4) || Identifier (variable)
//! Example: 00 02 00 00 09 18 01 02 03 04 05 06 07 08
//!          ^^    ^^          ^^
//!          Type  EN (2328)   Vendor-assigned identifier
//! ```
//!
//! ## DUID-LL (Link-Layer, Type 3)
//!
//! ```text
//! Format: Type (2) || Hardware Type (2) || Link-Layer Address (variable)
//! Example: 00 03 00 01 52 54 00 12 34 56
//!          ^^    ^^    ^^
//!          Type  HW    MAC Address
//! ```
//!
//! # Lease Time Management
//!
//! DHCPv6 uses three timers for lease lifecycle management:
//!
//! - **Preferred Lifetime**: Time until address becomes deprecated (default: T1 = 3600s)
//! - **Valid Lifetime**: Time until address becomes invalid (default: 86400s = DEFLEASE6)
//! - **T1 (Renew Time)**: When client should start renewal with original server (50% of valid)
//! - **T2 (Rebind Time)**: When client should start rebinding with any server (80% of valid)
//!
//! Default values (from C `config.h` DEFLEASE6 = 86400):
//!
//! ```text
//! T1 = 3600s  (1 hour)    - Start RENEW at 50% of lease
//! T2 = 7200s  (2 hours)   - Start REBIND at 80% of lease
//! Valid = 86400s (24 hours) - Lease expiration
//! ```
//!
//! # C Source Transformation
//!
//! This module transforms approximately 7000 lines of C code into memory-safe Rust:
//!
//! ## C Implementation (src/dhcp6.c, src/rfc3315.c, src/outpacket.c)
//!
//! ```c
//! // Global state with manual memory management
//! struct daemon {
//!     int dhcp6fd;
//!     struct iovec dhcp_packet;
//!     unsigned char *outpacket;
//!     struct dhcp_context *dhcp6_contexts;
//!     unsigned char *duid;
//!     int duid_len;
//! } *daemon;
//!
//! // Synchronous packet processing with poll()
//! void dhcp6_packet(time_t now) {
//!     struct in6_addr dst_addr;
//!     struct msghdr msg;
//!     ssize_t sz = recvmsg(daemon->dhcp6fd, &msg, MSG_WAITALL);
//!     
//!     struct state state;
//!     memset(&state, 0, sizeof(state));
//!     
//!     // Manual pointer arithmetic for option parsing
//!     unsigned char *opt = state.opts;
//!     while (opt < state.end) {
//!         unsigned int opt_type = opt6_type(opt);
//!         unsigned int opt_len = opt6_len(opt);
//!         // Process option
//!         opt = opt6_next(opt);
//!     }
//!     
//!     // Manual buffer management for response
//!     save_counter(0);
//!     put_opt6_short(OPTION_SERVER_ID);
//!     put_opt6_short(daemon->duid_len);
//!     put_opt6_bytes(daemon->duid, daemon->duid_len);
//! }
//! ```
//!
//! ## Rust Implementation (This Module)
//!
//! ```rust,ignore
//! // Type-safe state with ownership
//! pub struct DhcpV6Service {
//!     socket: UdpSocket,
//!     config: Arc<Config>,
//!     lease_manager: Arc<RwLock<LeaseManager>>,
//!     protocol: DhcpV6StateMachine,
//!     server_id: Vec<u8>,
//! }
//!
//! impl DhcpV6Service {
//!     // Async packet processing with tokio
//!     pub async fn run(&mut self) -> Result<(), DhcpError> {
//!         let mut buffer = vec![0u8; 1500];
//!         
//!         loop {
//!             tokio::select! {
//!                 result = self.socket.recv_from(&mut buffer) => {
//!                     let (size, peer) = result?;
//!                     self.handle_packet(&buffer[..size], peer).await?;
//!                 }
//!                 _ = self.shutdown_rx.recv() => {
//!                     return Ok(());
//!                 }
//!             }
//!         }
//!     }
//!     
//!     // Type-safe message parsing with nom
//!     pub async fn handle_packet(&mut self, data: &[u8], peer: SocketAddr)
//!         -> Result<(), DhcpError>
//!     {
//!         // Safe parsing with automatic bounds checking
//!         let message = DhcpV6Message::from_bytes(data)?;
//!         
//!         // Extract options with O(1) HashMap lookup
//!         let client_id = message.get_option(constants::OPTION_CLIENT_ID)
//!             .ok_or(DhcpError::MissingClientId)?;
//!         
//!         // Process through state machine
//!         let response = self.protocol.process_message(&message).await?;
//!         
//!         // Safe serialization with OptionBuilder
//!         let response_bytes = response.to_bytes()?;
//!         self.socket.send_to(&response_bytes, peer).await?;
//!         
//!         Ok(())
//!     }
//! }
//! ```
//!
//! # Memory Safety Improvements
//!
//! The Rust implementation eliminates entire classes of memory-safety vulnerabilities
//! present in the C implementation:
//!
//! | Vulnerability Class      | C Risk                           | Rust Protection                    |
//! |--------------------------|----------------------------------|------------------------------------|
//! | Buffer Overflow          | Manual bounds checking failure   | Compile-time slice bounds checking |
//! | Use-After-Free           | Manual lifetime tracking         | Borrow checker enforces lifetimes  |
//! | Double-Free              | Multiple free() on same pointer  | Drop trait executes exactly once   |
//! | Memory Leak              | Missing free() calls             | Automatic Drop on scope exit       |
//! | Null Pointer Deref       | Unchecked NULL pointer access    | Option<T> forces explicit handling |
//! | Data Race                | Unsynchronized global state      | RwLock provides synchronized access|
//! | Integer Overflow         | Unchecked arithmetic             | Checked arithmetic or wrapping ops |
//!
//! ## Example: Buffer Overflow Prevention
//!
//! ```c
//! // C: Buffer overflow risk in option parsing
//! unsigned char buf[512];
//! int len = opt6_len(opt);
//! if (len > 0) {
//!     memcpy(buf, opt6_ptr(opt, 0), len);  // No bounds check!
//! }
//! ```
//!
//! ```rust,ignore
//! // Rust: Compile-time bounds checking prevents overflow
//! let option_data = message.get_option(OPTION_CLIENT_ID)
//!     .ok_or(DhcpError::MissingOption)?;
//! // option_data is &[u8] - length is always valid
//! // Any indexing is bounds-checked at runtime
//! ```
//!
//! # Integration Points
//!
//! ## Runtime Event Loop Integration
//!
//! The DHCPv6 service integrates with the main tokio runtime event loop:
//!
//! ```rust,ignore
//! // In src/runtime/event_loop.rs
//! tokio::select! {
//!     result = dns_service.recv() => { /* Handle DNS */ },
//!     result = dhcpv4_service.recv() => { /* Handle DHCPv4 */ },
//!     result = dhcpv6_service.recv() => { /* Handle DHCPv6 */ },
//!     result = tftp_service.recv() => { /* Handle TFTP */ },
//! }
//! ```
//!
//! ## Lease Database Integration
//!
//! DHCPv6 leases are persisted through the shared lease manager:
//!
//! ```rust,ignore
//! use crate::dhcp::lease::LeaseManager;
//!
//! // Allocate new lease
//! let lease = lease_manager.write().await.allocate_v6(
//!     &client_duid,
//!     iaid,
//!     &requested_addr,
//!     valid_lifetime,
//!     hostname,
//! ).await?;
//!
//! // Register in DNS if configured
//! if config.dhcp.dhcp_leasefile_ro {
//!     dns_service.add_dhcp_name(&lease.hostname, &lease.ip).await?;
//! }
//! ```
//!
//! ## Router Advertisement Coordination
//!
//! DHCPv6 mode is determined by RA flags:
//!
//! ```rust,ignore
//! use crate::radv::RadVService;
//!
//! // Query RA flags for interface
//! let ra_config = radv_service.get_interface_config(interface)?;
//!
//! match (ra_config.managed_flag, ra_config.other_config_flag) {
//!     (true, _) => {
//!         // Stateful DHCPv6: Assign addresses
//!         self.handle_stateful_request(&message).await?
//!     }
//!     (false, true) => {
//!         // Stateless DHCPv6: Config only
//!         self.handle_stateless_request(&message).await?
//!     }
//!     (false, false) => {
//!         // SLAAC only: No DHCPv6 response
//!         return Ok(());
//!     }
//! }
//! ```
//!
//! # Usage Examples
//!
//! ## Basic Server Initialization
//!
//! ```rust,ignore
//! use dnsmasq::dhcp::v6::{DhcpV6Service, constants};
//! use dnsmasq::config::Config;
//! use dnsmasq::dhcp::lease::LeaseManager;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load configuration
//!     let config = Arc::new(Config::from_file("/etc/dnsmasq.conf").await?);
//!     
//!     // Initialize lease manager
//!     let lease_manager = Arc::new(RwLock::new(
//!         LeaseManager::new(&config.dhcp.leasefile).await?
//!     ));
//!     
//!     // Create DHCPv6 server
//!     let mut dhcpv6_server = DhcpV6Service::new(
//!         config.clone(),
//!         lease_manager.clone(),
//!     ).await?;
//!     
//!     // Run server event loop
//!     dhcpv6_server.run().await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Processing SOLICIT Message
//!
//! ```rust,ignore
//! use dnsmasq::dhcp::v6::{DhcpV6Message, OptionBuilder, constants};
//!
//! // Parse incoming SOLICIT
//! let solicit = DhcpV6Message::from_bytes(packet_data)?;
//! assert_eq!(solicit.message_type(), constants::MSG_SOLICIT);
//!
//! // Extract client identifier
//! let client_id = solicit.get_option(constants::OPTION_CLIENT_ID)
//!     .ok_or(DhcpError::MissingClientId)?;
//!
//! // Extract IA_NA to get IAID
//! let ia_na_data = solicit.get_option(constants::OPTION_IA_NA)
//!     .ok_or(DhcpError::MissingIaNa)?;
//! let iaid = u32::from_be_bytes(ia_na_data[0..4].try_into()?);
//!
//! // Allocate address from pool
//! let allocated_addr = allocate_address(interface, &client_id).await?;
//!
//! // Build ADVERTISE response
//! let mut advertise = DhcpV6Message::new(
//!     constants::MSG_ADVERTISE,
//!     solicit.transaction_id().clone()
//! );
//!
//! advertise.add_option(constants::OPTION_SERVER_ID, server_duid.clone());
//! advertise.add_option(constants::OPTION_CLIENT_ID, client_id.to_vec());
//!
//! // Build IA_NA option with allocated address
//! let mut ia_na_builder = OptionBuilder::new();
//! ia_na_builder.start_container(constants::OPTION_IA_NA)?;
//! ia_na_builder.put_u32(iaid)?;
//! ia_na_builder.put_u32(3600)?;  // T1
//! ia_na_builder.put_u32(7200)?;  // T2
//!
//! ia_na_builder.start_container(constants::OPTION_IAADDR)?;
//! ia_na_builder.put_ipv6_addr(&allocated_addr)?;
//! ia_na_builder.put_u32(7200)?;   // Preferred lifetime
//! ia_na_builder.put_u32(86400)?;  // Valid lifetime
//! ia_na_builder.end_container()?;
//!
//! ia_na_builder.end_container()?;
//! advertise.add_option_raw(ia_na_builder.build());
//!
//! // Send ADVERTISE
//! let response_bytes = advertise.to_bytes()?;
//! socket.send_to(&response_bytes, client_addr).await?;
//! ```
//!
//! # Module Organization
//!
//! This module serves as the public API entry point for DHCPv6 functionality, re-exporting
//! the primary types from child modules to provide a clean interface:
//!
//! ```rust,ignore
//! // External usage (clean API)
//! use dnsmasq::dhcp::v6::{DhcpV6Service, DhcpV6Message, constants};
//!
//! // Instead of verbose paths:
//! // use dnsmasq::dhcp::v6::server::DhcpV6Server;
//! // use dnsmasq::dhcp::v6::message::DhcpV6Message;
//! // use dnsmasq::dhcp::v6::constants;
//! ```
//!
//! # Thread Safety
//!
//! All DHCPv6 operations are async-safe and can be used in concurrent contexts:
//!
//! - `Arc<Config>` provides shared immutable configuration
//! - `Arc<RwLock<LeaseManager>>` ensures synchronized lease database access
//! - Message parsing and serialization are stateless and thread-safe
//! - State machine operations use owned data with no shared mutable state
//!
//! # Performance Characteristics
//!
//! - **Message parsing**: O(n) where n is packet size, single-pass nom parsing
//! - **Option lookup**: O(1) HashMap access by option code
//! - **Address allocation**: O(log n) for pool iteration with available addresses
//! - **Lease database**: O(1) lookup by client DUID using HashMap index
//! - **Response serialization**: O(m) where m is number of options, single-pass encoding
//!
//! # Error Handling
//!
//! All DHCPv6 operations return `Result<T, DhcpError>` for explicit error handling:
//!
//! ```rust,ignore
//! pub enum DhcpError {
//!     ParseError(String),          // Malformed packet
//!     MissingClientId,              // Required OPTION_CLIENT_ID absent
//!     MissingServerId,              // Required OPTION_SERVER_ID absent
//!     InvalidDuid(String),          // DUID format violation
//!     NoAddressAvailable,           // Address pool exhausted
//!     LeaseNotFound,                // Client binding not found
//!     NotOnLink,                    // Address not appropriate for link
//!     IoError(std::io::Error),      // Socket I/O failure
//! }
//! ```
//!
//! # Testing Strategy
//!
//! DHCPv6 implementation includes comprehensive test coverage:
//!
//! - **Unit tests**: Protocol message parsing, option encoding, DUID validation
//! - **Integration tests**: Complete SOLICIT→ADVERTISE→REQUEST→REPLY exchanges
//! - **Compatibility tests**: Validates Rust implementation against C test suite
//! - **RFC compliance tests**: Verifies adherence to RFC 3315 requirements
//! - **Fuzzing**: Protocol parser tested with malformed packets
//!
//! # See Also
//!
//! - RFC 3315: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)
//! - RFC 3633: IPv6 Prefix Options for DHCPv6
//! - RFC 4704: The DHCPv6 Client FQDN Option
//! - RFC 8415: Dynamic Host Configuration Protocol for IPv6 (DHCPv6) - obsoletes 3315

// Child module declarations
pub mod constants;
pub mod message;
pub mod options;
pub mod protocol;
pub mod server;

// Re-export primary types for clean external API
// Note: DhcpV6Server is exported as DhcpV6Service for consistency with service naming convention
pub use server::DhcpV6Server as DhcpV6Service;
pub use message::DhcpV6Message;
pub use options::OptionBuilder;
pub use protocol::DhcpV6StateMachine;

// Re-export constants module for convenience
pub use constants::{
    PORT_SERVER, PORT_CLIENT,
    MSG_SOLICIT, MSG_ADVERTISE, MSG_REQUEST, MSG_CONFIRM, MSG_RENEW,
    MSG_REBIND, MSG_REPLY, MSG_RELEASE, MSG_DECLINE, MSG_RECONFIGURE,
    MSG_INFORMATION_REQUEST, MSG_RELAY_FORW, MSG_RELAY_REPL,
    OPTION_CLIENT_ID, OPTION_SERVER_ID, OPTION_IA_NA, OPTION_IA_TA,
    OPTION_IAADDR, OPTION_ORO, OPTION_PREFERENCE, OPTION_ELAPSED_TIME,
    OPTION_STATUS_CODE, OPTION_RAPID_COMMIT, OPTION_USER_CLASS,
    OPTION_VENDOR_CLASS, OPTION_VENDOR_OPTS, OPTION_DNS_SERVER,
    OPTION_DOMAIN_SEARCH, OPTION_IA_PD, OPTION_IAPREFIX,
    OPTION_FQDN, OPTION_NTP_SERVER, OPTION_CLIENT_MAC,
    NTP_SUBOPTION_SRV_ADDR, NTP_SUBOPTION_MC_ADDR, NTP_SUBOPTION_SRV_FQDN,
    STATUS_SUCCESS, STATUS_UNSPEC, STATUS_NOADDRS, STATUS_NOBINDING,
    STATUS_NOTONCLIENT, STATUS_NOTONLINK, STATUS_USEMULTICAST,
    STATUS_NOPREFIXAVAIL,
    DUID_LLT, DUID_EN, DUID_LL, DUID_UUID,
    ALL_RELAY_AGENTS_AND_SERVERS, ALL_SERVERS,
};
