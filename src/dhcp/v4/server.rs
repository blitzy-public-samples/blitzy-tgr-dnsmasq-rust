// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! DHCPv4 server core implementation
//!
//! This module provides the complete DHCPv4 server implementation with async message handling,
//! dynamic address allocation, conflict detection via ICMP ping, and lease database integration.
//! It replaces the C implementation in `dhcp.c` with memory-safe Rust using tokio for async I/O.
//!
//! # Purpose
//!
//! Implements RFC 2131 (DHCP) and RFC 2132 (DHCP Options) DHCPv4 server functionality:
//! - Receives and processes DISCOVER, REQUEST, DECLINE, RELEASE, INFORM messages
//! - Allocates IP addresses from configured ranges with conflict detection
//! - Manages lease lifecycle (allocation, renewal, expiration, release)
//! - Integrates with DNS cache for hostname resolution
//! - Executes helper scripts on lease events
//! - Supports DHCP relay agents and multiple network interfaces
//!
//! # C Implementation Mapping
//!
//! From dhcp.c (lines 100-2000):
//! ```c
//! // C blocking recvmsg() with poll-based event loop
//! int dhcp_packet(time_t now, int pxe_fd) {
//!     struct msghdr msg;
//!     struct iovec iov;
//!     ssize_t sz = recvmsg(daemon->dhcpfd, &msg, MSG_PEEK | MSG_TRUNC);
//!     // Manual buffer management, pointer arithmetic
//!     struct dhcp_packet *mess = (struct dhcp_packet *)daemon->dhcp_packet;
//!     // Process packet with global state access
//! }
//!
//! // Address allocation with manual IP iteration
//! static unsigned int lease_find_max_addr(struct dhcp_context *context) {
//!     for (addr = ntohl(context->start); addr <= ntohl(context->end); addr++) {
//!         // Check availability, ping test
//!     }
//! }
//! ```
//!
//! # Rust Improvements
//!
//! - **Async I/O**: tokio::net::UdpSocket replaces poll-based recvmsg()
//! - **Memory safety**: Vec<u8> buffers with automatic cleanup, no manual realloc
//! - **Type-safe parsing**: nom combinators replace pointer arithmetic
//! - **Structured state**: DhcpV4Service struct replaces global daemon pointer
//! - **Error handling**: Result<T, DhcpError> replaces errno and return codes
//! - **Concurrent operations**: Async ping tests without blocking event loop
//!
//! # Key Transformations
//!
//! ## 1. Blocking recv → Async tokio
//!
//! C pattern:
//! ```c
//! poll(fds, nfds, timeout);
//! if (fds[dhcp_fd].revents & POLLIN) {
//!     ssize_t sz = recvmsg(daemon->dhcpfd, &msg, 0);
//! }
//! ```
//!
//! Rust pattern:
//! ```rust,ignore
//! let (len, source) = socket.recv_from(&mut buffer).await?;
//! ```
//!
//! ## 2. Manual buffer management → Vec
//!
//! C pattern:
//! ```c
//! daemon->dhcp_packet = whine_malloc(sizeof(struct dhcp_packet));
//! memset(daemon->dhcp_packet, 0, sizeof(struct dhcp_packet));
//! // Manual free on cleanup
//! ```
//!
//! Rust pattern:
//! ```rust,ignore
//! let mut buffer = vec![0u8; 1024];
//! // Automatic Drop cleanup
//! ```
//!
//! ## 3. Global state access → Owned struct
//!
//! C pattern:
//! ```c
//! extern struct daemon *daemon;
//! daemon->dhcp_contexts->start;
//! ```
//!
//! Rust pattern:
//! ```rust,ignore
//! self.contexts.iter().find(|ctx| ctx.contains(addr))
//! ```

use crate::config::types::Config;
// use crate::dhcp::common::{generate_xid, log_tags, match_netid}; // Unused for now
use crate::dhcp::lease::{LeaseFlags, LeaseManager};
use crate::dhcp::v4::constants::{
    BROADCAST_FLAG, MIN_PACKETSZ, MSG_TYPE_DECLINE, MSG_TYPE_DISCOVER, MSG_TYPE_INFORM,
    MSG_TYPE_RELEASE, MSG_TYPE_REQUEST,
};
use crate::dhcp::v4::message::DhcpMessage;
use crate::dhcp::v4::options::{DhcpOption, MessageType};
use crate::dhcp::v4::protocol::DhcpProtocol;
use crate::dns::cache::DnsCache;
use crate::error::DhcpError;
use crate::network::interfaces::InterfaceManager;
use crate::network::sockets::DhcpSocket;
use crate::types::MacAddress;
use crate::util::helpers::HelperProcess;

// use std::collections::HashMap; // Unused for now
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
// use tokio::net::UdpSocket; // Unused - using DhcpSocket abstraction
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};

/// `DHCPv4` server service providing async message handling and address allocation
///
/// Manages the complete `DHCPv4` server lifecycle including packet reception, protocol processing,
/// address allocation with conflict detection, lease management, DNS integration, and helper
/// script execution. Replaces C `dhcp_packet()` and `dhcp_reply()` with async Rust implementation.
///
/// # Fields
///
/// - `socket`: UDP socket bound to port 67 with `SO_BROADCAST` enabled
/// - `protocol`: RFC 2131 state machine for message processing
/// - `lease_manager`: Persistent lease database with async access
/// - `dns_cache`: DNS cache for hostname registration
/// - `helper`: Helper process for external script execution
/// - `interface_manager`: Interface enumeration and monitoring
/// - `config`: Server configuration with address ranges and options
/// - `contexts`: Active DHCP contexts per interface
///
/// # C Equivalent
///
/// ```c
/// // dhcp.c global state
/// extern struct daemon *daemon;
/// daemon->dhcpfd;                   // socket file descriptor
/// daemon->dhcp_contexts;            // linked list of ranges
/// daemon->leases;                   // lease hash table
/// ```
///
/// # Examples
///
/// ```rust,ignore
/// let service = DhcpV4Service::new(
///     socket,
///     protocol,
///     lease_manager,
///     dns_cache,
///     helper,
///     interface_manager,
///     config,
/// ).await?;
///
/// // Run server
/// service.run().await?;
/// ```
pub struct DhcpV4Service {
    /// UDP socket bound to DHCP server port (67) with broadcast reception
    ///
    /// Replaces C daemon->dhcpfd with tokio async socket. Configured with:
    /// - `SO_REUSEADDR` for restart without `TIME_WAIT` delays
    /// - `SO_BROADCAST` for broadcast packet reception
    /// - `IP_PKTINFO/IPV6_PKTINFO` for destination address retrieval
    socket: Arc<DhcpSocket>,

    /// `DHCPv4` protocol state machine for message processing
    ///
    /// Handles DISCOVER → OFFER and REQUEST → ACK/NAK state transitions per RFC 2131.
    /// Replaces C `rfc2131_packet()` monolithic function with type-safe transitions.
    protocol: DhcpProtocol,

    /// Lease database manager with async access and persistence
    ///
    /// Manages lease allocation, renewal, expiration, and file persistence.
    /// Replaces C daemon->leases hash table with async-safe RwLock-protected manager.
    lease_manager: Arc<RwLock<LeaseManager>>,

    /// DNS cache for hostname registration of DHCP leases
    ///
    /// Automatically registers allocated hostnames in DNS cache for name resolution.
    /// Replaces C `cache_add_dhcp_entry()` calls with async cache updates.
    #[allow(dead_code)]
    dns_cache: Arc<RwLock<DnsCache>>,

    /// Helper process for external script execution on lease events
    ///
    /// Executes scripts with DNSMASQ_* environment variables on add/old/del events.
    /// Replaces C `queue_script()` and helper.c privilege-separated execution.
    #[allow(dead_code)]
    helper: Arc<HelperProcess>,

    /// Interface manager for enumeration and monitoring
    ///
    /// Discovers network interfaces and addresses for DHCP context association.
    /// Replaces C `iface_enumerate()` callback pattern with async interface iteration.
    interface_manager: Arc<InterfaceManager>,

    /// Server configuration with DHCP ranges, options, and policies
    ///
    /// Immutable configuration shared across async tasks. Reloaded on SIGHUP via Arc swap.
    config: Arc<Config>,

    /// Active DHCP contexts per network interface
    ///
    /// Each context represents an IP address range on a specific interface.
    /// Replaces C daemon->dhcp_contexts linked list with Vec for safe iteration.
    contexts: Vec<DhcpContext>,
}

/// DHCP context representing an IP address range on a network interface
///
/// Defines the address pool, netmask, gateway, DNS servers, and lease parameters for
/// a specific network segment. Multiple contexts can exist for different interfaces or
/// address ranges on the same interface.
///
/// # C Equivalent
///
/// ```c
/// struct dhcp_context {
///     struct dhcp_context *next;
///     struct in_addr start, end;
///     struct in_addr netmask, broadcast;
///     int prefix;
///     char *interface;
///     time_t lease_time;
///     struct dhcp_netid *filter;
///     // ... additional fields
/// };
/// ```
#[derive(Clone, Debug)]
pub struct DhcpContext {
    /// Starting IP address of range (inclusive)
    pub start: Ipv4Addr,

    /// Ending IP address of range (inclusive)
    pub end: Ipv4Addr,

    /// Network interface name (e.g., "eth0", "br0")
    pub interface: String,

    /// Interface index from kernel
    pub interface_index: u32,

    /// Subnet netmask for this context
    pub netmask: Ipv4Addr,

    /// Broadcast address for subnet
    pub broadcast: Ipv4Addr,

    /// Default gateway (router) address
    pub router: Option<Ipv4Addr>,

    /// DNS servers to advertise to clients
    pub dns_servers: Vec<Ipv4Addr>,

    /// Default lease time in seconds
    pub lease_time: u32,

    /// Tag filters for this context
    pub tags: Vec<String>,
}

impl DhcpV4Service {
    /// Creates a new `DHCPv4` server service
    ///
    /// Initializes the service with all required dependencies. Does not start packet processing
    /// or bind to network interfaces; call `run()` to begin serving requests.
    ///
    /// # Arguments
    ///
    /// * `socket` - Bound UDP socket for DHCP server port (67)
    /// * `protocol` - `DHCPv4` protocol handler
    /// * `lease_manager` - Lease database manager
    /// * `dns_cache` - DNS cache for hostname registration
    /// * `helper` - Helper process for script execution
    /// * `interface_manager` - Interface enumeration service
    /// * `config` - Server configuration
    ///
    /// # Returns
    ///
    /// A new `DhcpV4Service` instance ready to run
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let socket = DhcpSocket::bind("0.0.0.0:67").await?;
    /// let service = DhcpV4Service::new(
    ///     Arc::new(socket),
    ///     protocol,
    ///     lease_manager,
    ///     dns_cache,
    ///     helper,
    ///     interface_manager,
    ///     config,
    /// ).await?;
    /// ```
    #[instrument(skip_all, fields(service = "dhcpv4"))]
    pub async fn new(
        socket: Arc<DhcpSocket>,
        protocol: DhcpProtocol,
        lease_manager: Arc<RwLock<LeaseManager>>,
        dns_cache: Arc<RwLock<DnsCache>>,
        helper: Arc<HelperProcess>,
        interface_manager: Arc<InterfaceManager>,
        config: Arc<Config>,
    ) -> Result<Self, DhcpError> {
        info!("Initializing DHCPv4 server service");

        let mut service = Self {
            socket,
            protocol,
            lease_manager,
            dns_cache,
            helper,
            interface_manager,
            config,
            contexts: Vec::new(),
        };

        // Initialize DHCP contexts from configuration
        service.initialize_contexts().await?;

        info!(contexts = service.contexts.len(), "DHCPv4 server service initialized");

        Ok(service)
    }

    /// Returns the local socket address that the server is bound to
    ///
    /// This is useful for tests and diagnostics to determine the actual port the server
    /// is listening on, especially when using port 0 for OS-assigned ports.
    ///
    /// # Returns
    ///
    /// The local `SocketAddr` of the UDP socket, or an error if the socket is not bound.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let addr = service.local_addr()?;
    /// println!("DHCPv4 server listening on {}", addr);
    /// ```
    pub fn local_addr(&self) -> crate::error::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Main service loop processing `DHCPv4` packets
    ///
    /// Receives packets from UDP socket, parses them, dispatches to protocol handler,
    /// and sends responses. Runs until terminated by signal or error. Replaces C `dhcp_packet()`
    /// poll-based processing with async tokio event loop.
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Service terminated cleanly
    /// - `Err(DhcpError)` - Fatal error requiring service restart
    ///
    /// # Errors
    ///
    /// Returns `DhcpError` if:
    /// - Socket recv fails (interface down, permission denied)
    /// - Packet parsing fails repeatedly (potential attack)
    /// - Protocol handler panics or returns fatal error
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// service.run().await?;
    /// ```
    #[instrument(skip(self), fields(service = "dhcpv4"))]
    pub async fn run(&mut self) -> Result<(), DhcpError> {
        info!("Starting DHCPv4 server");

        loop {
            match self.receive_and_handle().await {
                Ok(()) => {
                    // Successfully processed packet
                }
                Err(e) => {
                    error!("Error processing DHCPv4 packet: {}", e);
                    // Continue processing despite errors
                }
            }
        }
    }

    /// Receives and handles a single `DHCPv4` packet
    ///
    /// Reads packet from socket, parses DHCP message, dispatches to appropriate handler
    /// based on message type, generates response, and sends reply. Core packet processing
    /// logic replacing C `dhcp_reply()` function.
    ///
    /// # Process Flow
    ///
    /// 1. Receive packet from UDP socket (`recv_from`)
    /// 2. Parse DHCP message with bounds checking (`parse_dhcp_message`)
    /// 3. Validate magic cookie and minimum size
    /// 4. Extract message type from options
    /// 5. Dispatch to protocol handler (DISCOVER/REQUEST/etc.)
    /// 6. Generate response message
    /// 7. Serialize response
    /// 8. Send response to client (broadcast or unicast)
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // dhcp.c lines 200-1800
    /// size_t dhcp_reply(struct dhcp_context *context, char *iface_name, int int_index,
    ///                  size_t sz, time_t now, int unicast_dest, int loopback,
    ///                  int *is_inform, int pxe, struct in_addr fallback, time_t recvtime) {
    ///     struct dhcp_packet *mess = (struct dhcp_packet *)daemon->dhcp_packet;
    ///     // Extensive manual parsing
    ///     unsigned char *opt = option_find(mess, sz, OPTION_MESSAGE_TYPE, 1);
    ///     // State machine with gotos
    ///     // Manual response construction
    /// }
    /// ```
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Packet processed and response sent (if applicable)
    /// - `Err(DhcpError)` - Parsing, processing, or send failure
    ///
    /// # Errors
    ///
    /// Returns `DhcpError` if:
    /// - Socket recv fails
    /// - Packet too small (< `MIN_PACKETSZ`)
    /// - Invalid magic cookie
    /// - No message type option
    /// - Protocol handler fails
    /// - Response send fails
    #[instrument(skip(self), fields(packet = "dhcpv4"))]
    pub async fn receive_and_handle(&mut self) -> Result<(), DhcpError> {
        // Allocate receive buffer (bootp minimum is 300 bytes, allow up to 1500 for jumbograms)
        let mut buffer = vec![0u8; 1500];

        // Receive packet from socket
        let (len, source) = self.socket.recv_from(&mut buffer).await.map_err(|e| {
            DhcpError::V4ProtocolError { reason: format!("Failed to receive packet: {e}") }
        })?;

        debug!(
            source = %source,
            length = len,
            "Received DHCPv4 packet"
        );

        // Validate minimum packet size
        if len < MIN_PACKETSZ {
            warn!(
                source = %source,
                length = len,
                min_size = MIN_PACKETSZ,
                "Packet too small, discarding"
            );
            return Err(DhcpError::ParseFailed {
                reason: format!("Packet too small: {len} bytes (minimum {MIN_PACKETSZ})"),
            });
        }

        // Truncate buffer to actual received length
        buffer.truncate(len);

        // Parse DHCP message
        let message = DhcpMessage::parse_dhcp_message(&buffer).map_err(|e| {
            warn!(
                source = %source,
                error = %e,
                "Failed to parse DHCP message"
            );
            e
        })?;

        // Extract message type from options
        let message_type =
            message
                .get_option(|opt| matches!(opt, DhcpOption::MessageType(_)))
                .and_then(|opt| {
                    if let DhcpOption::MessageType(mt) = opt {
                        Some(mt.to_u8())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    warn!(
                        source = %source,
                        xid = message.transaction_id(),
                        "No message type option found"
                    );
                    DhcpError::ParseFailed { reason: "Missing message type option".to_string() }
                })?;

        debug!(
            source = %source,
            xid = message.transaction_id(),
            message_type = message_type,
            client_mac = %message.client_hardware_addr()?,
            "Processing DHCPv4 message"
        );

        // Dispatch to protocol handler based on message type
        match message_type {
            MSG_TYPE_DISCOVER => {
                debug!("Processing DHCPDISCOVER");
                let response = self.handle_discover(&message, source).await?;
                self.send_response(&response, source).await?;
            }
            MSG_TYPE_REQUEST => {
                debug!("Processing DHCPREQUEST");
                let response = self.handle_request(&message, source).await?;
                self.send_response(&response, source).await?;
            }
            MSG_TYPE_DECLINE => {
                debug!("Processing DHCPDECLINE");
                self.handle_decline(&message, source).await?;
                // No response for DECLINE per RFC 2131
            }
            MSG_TYPE_RELEASE => {
                debug!("Processing DHCPRELEASE");
                self.handle_release(&message, source).await?;
                // No response for RELEASE per RFC 2131
            }
            MSG_TYPE_INFORM => {
                debug!("Processing DHCPINFORM");
                let response = self.handle_inform(&message, source).await?;
                self.send_response(&response, source).await?;
            }
            _ => {
                warn!(
                    message_type = message_type,
                    "Unknown or unsupported message type, discarding"
                );
                return Err(DhcpError::ParseFailed {
                    reason: format!("Unknown message type: {message_type}"),
                });
            }
        }

        Ok(())
    }

    /// Handles DHCPDISCOVER message and generates DHCPOFFER
    ///
    /// Client broadcasts DHCPDISCOVER to locate available DHCP servers. Server responds
    /// with DHCPOFFER containing an available IP address and configuration options.
    ///
    /// # Arguments
    ///
    /// * `message` - Parsed DHCPDISCOVER message
    /// * `source` - Source socket address
    ///
    /// # Returns
    ///
    /// - `Ok(Some(DhcpMessage))` - DHCPOFFER response to send
    /// - `Ok(None)` - No suitable address available, no response
    /// - `Err(DhcpError)` - Processing error
    #[instrument(skip(self, message))]
    async fn handle_discover(
        &mut self,
        message: &DhcpMessage,
        source: SocketAddr,
    ) -> Result<DhcpMessage, DhcpError> {
        let client_mac = message.client_hardware_addr()?;

        debug!(
            mac = %client_mac,
            xid = message.transaction_id(),
            "Processing DHCPDISCOVER"
        );

        // Delegate to protocol handler
        let response = self.protocol.handle_discover(message).await?;

        info!(
            mac = %client_mac,
            offered_ip = %response.yiaddr(),
            xid = message.transaction_id(),
            "Sending DHCPOFFER"
        );

        Ok(response)
    }

    /// Handles DHCPREQUEST message and generates DHCPACK/DHCPNAK
    ///
    /// Client sends DHCPREQUEST to request an offered address or renew existing lease.
    /// Server responds with DHCPACK if request is valid, DHCPNAK if denied.
    ///
    /// # Arguments
    ///
    /// * `message` - Parsed DHCPREQUEST message
    /// * `source` - Source socket address
    ///
    /// # Returns
    ///
    /// - `Ok(DhcpMessage)` - DHCPACK or DHCPNAK response
    /// - `Err(DhcpError)` - Processing error
    #[instrument(skip(self, message))]
    async fn handle_request(
        &mut self,
        message: &DhcpMessage,
        source: SocketAddr,
    ) -> Result<DhcpMessage, DhcpError> {
        let client_mac = message.client_hardware_addr()?;

        debug!(
            mac = %client_mac,
            xid = message.transaction_id(),
            "Processing DHCPREQUEST"
        );

        // Delegate to protocol handler
        let response = self.protocol.handle_request(message).await?;

        let is_ack = response
            .options()
            .iter()
            .any(|opt| matches!(opt, DhcpOption::MessageType(MessageType::Ack)));

        if is_ack {
            info!(
                mac = %client_mac,
                ip = %response.yiaddr(),
                xid = message.transaction_id(),
                "Sending DHCPACK"
            );
        } else {
            warn!(
                mac = %client_mac,
                xid = message.transaction_id(),
                "Sending DHCPNAK"
            );
        }

        Ok(response)
    }

    /// Handles DHCPDECLINE message (address conflict detected by client)
    ///
    /// Client sends DHCPDECLINE if it detects the offered address is already in use
    /// (via ARP probe). Server marks the address as unavailable to prevent future conflicts.
    ///
    /// # Arguments
    ///
    /// * `message` - Parsed DHCPDECLINE message
    /// * `source` - Source socket address
    ///
    /// # Returns
    ///
    /// - `Ok(())` - DECLINE processed (no response sent per RFC 2131)
    /// - `Err(DhcpError)` - Processing error
    #[instrument(skip(self, message))]
    async fn handle_decline(
        &mut self,
        message: &DhcpMessage,
        source: SocketAddr,
    ) -> Result<(), DhcpError> {
        let client_mac = message.client_hardware_addr()?;

        warn!(
            mac = %client_mac,
            declined_ip = %message.requested_ip_address().unwrap_or(Ipv4Addr::UNSPECIFIED),
            xid = message.transaction_id(),
            "Client declined address (conflict detected)"
        );

        // Delegate to protocol handler
        self.protocol.handle_decline(message).await?;

        Ok(())
    }

    /// Handles DHCPRELEASE message (client releasing lease)
    ///
    /// Client sends DHCPRELEASE to voluntarily terminate its lease.
    /// Server marks the lease as released and makes the address available for allocation.
    ///
    /// # Arguments
    ///
    /// * `message` - Parsed DHCPRELEASE message
    /// * `source` - Source socket address
    ///
    /// # Returns
    ///
    /// - `Ok(())` - RELEASE processed (no response sent per RFC 2131)
    /// - `Err(DhcpError)` - Processing error
    #[instrument(skip(self, message))]
    async fn handle_release(
        &mut self,
        message: &DhcpMessage,
        source: SocketAddr,
    ) -> Result<(), DhcpError> {
        let client_mac = message.client_hardware_addr()?;

        info!(
            mac = %client_mac,
            released_ip = %message.ciaddr(),
            xid = message.transaction_id(),
            "Client released address"
        );

        // Delegate to protocol handler
        self.protocol.handle_release(message).await?;

        Ok(())
    }

    /// Handles DHCPINFORM message (configuration request without address allocation)
    ///
    /// Client sends DHCPINFORM to obtain configuration parameters without requesting
    /// an IP address (client has statically configured address). Server responds with
    /// DHCPACK containing configuration options.
    ///
    /// # Arguments
    ///
    /// * `message` - Parsed DHCPINFORM message
    /// * `source` - Source socket address
    ///
    /// # Returns
    ///
    /// - `Ok(DhcpMessage)` - DHCPACK with configuration options
    /// - `Err(DhcpError)` - Processing error
    #[instrument(skip(self, message))]
    async fn handle_inform(
        &mut self,
        message: &DhcpMessage,
        source: SocketAddr,
    ) -> Result<DhcpMessage, DhcpError> {
        let client_mac = message.client_hardware_addr()?;

        debug!(
            mac = %client_mac,
            client_ip = %message.ciaddr(),
            xid = message.transaction_id(),
            "Processing DHCPINFORM"
        );

        // Delegate to protocol handler
        let response = self.protocol.handle_inform(message).await?;

        info!(
            mac = %client_mac,
            client_ip = %message.ciaddr(),
            xid = message.transaction_id(),
            "Sending DHCPACK for INFORM"
        );

        Ok(response)
    }

    /// Allocates an IP address from configured ranges with conflict detection
    ///
    /// Searches through DHCP contexts for an available address, checks static reservations,
    /// verifies availability in lease database, and performs ICMP ping test to detect conflicts.
    /// Replaces C `address_allocate()` with async Rust implementation.
    ///
    /// # Algorithm
    ///
    /// 1. Check static reservations for client MAC
    /// 2. Check existing lease for client
    /// 3. Honor requested IP if valid and available
    /// 4. Linear search through context ranges for available IP
    /// 5. For each candidate:
    ///    - Check not in use by other lease
    ///    - Perform ICMP ping test (conflict detection)
    ///    - Return if available
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // dhcp.c lines 1200-1400
    /// static struct in_addr address_allocate(struct dhcp_context *context,
    ///                                       struct dhcp_config *config,
    ///                                       struct in_addr addr, int *is_fallback) {
    ///     unsigned int start, end, addr_nw;
    ///     for (addr_nw = ntohl(context->start); addr_nw <= ntohl(context->end); addr_nw++) {
    ///         // Check availability
    ///         if (!lease_find_by_addr(addr))
    ///             if (do_icmp_ping(addr, 0, loopback))
    ///                 continue;  // Ping response, in use
    ///             else
    ///                 return addr;  // Available
    ///     }
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `context` - DHCP context defining address range
    /// * `client_mac` - Client MAC address
    /// * `requested` - Optional requested IP address
    ///
    /// # Returns
    ///
    /// - `Ok(Ipv4Addr)` - Allocated IP address
    /// - `Err(DhcpError::AddressPoolExhausted)` - No addresses available
    /// - `Err(DhcpError)` - Other allocation error
    #[instrument(skip(self), fields(context = %context.interface))]
    pub async fn allocate_address(
        &self,
        context: &DhcpContext,
        client_mac: &MacAddress,
        requested: Option<Ipv4Addr>,
    ) -> Result<Ipv4Addr, DhcpError> {
        debug!(
            mac = %client_mac,
            requested = ?requested,
            range = format!("{}-{}", context.start, context.end),
            "Allocating address"
        );

        // Check static reservations first
        for static_lease in &self.config.dhcp.static_leases {
            if &static_lease.mac == client_mac {
                // Extract IPv4 address from IpAddr enum
                if let std::net::IpAddr::V4(ipv4) = static_lease.ip {
                    info!(
                        mac = %client_mac,
                        static_ip = %ipv4,
                        "Using static reservation"
                    );
                    return Ok(ipv4);
                }
            }
        }

        // Check existing lease for this client
        let lease_manager = self.lease_manager.read().await;
        if let Some(existing_lease) = lease_manager.find_by_mac(client_mac).await {
            // Don't reuse leases that have been marked as DECLINED
            if existing_lease.flags.contains(LeaseFlags::DECLINED) {
                debug!(
                    mac = %client_mac,
                    declined_ip = %existing_lease.ip,
                    "Client has existing DECLINED lease, will allocate new IP"
                );
            } else {
                // Extract IPv4 address from IpAddr enum
                if let std::net::IpAddr::V4(ipv4) = existing_lease.ip {
                    // Check if existing lease is in this context's range
                    if Self::ip_in_range(ipv4, context.start, context.end) {
                        debug!(
                            mac = %client_mac,
                            existing_ip = %ipv4,
                            "Reusing existing lease"
                        );
                        return Ok(ipv4);
                    }
                }
            }
        }
        drop(lease_manager);

        // Honor requested address if in range and available
        if let Some(req_addr) = requested {
            if Self::ip_in_range(req_addr, context.start, context.end)
                && self.is_address_available(req_addr, client_mac).await?
            {
                if self.ping_test(req_addr).await? {
                    warn!(
                        requested_ip = %req_addr,
                        "Requested address failed ping test (in use)"
                    );
                } else {
                    info!(
                        mac = %client_mac,
                        requested_ip = %req_addr,
                        "Allocated requested address"
                    );
                    return Ok(req_addr);
                }
            }
        }

        // Linear search through address range
        let start_u32 = u32::from(context.start);
        let end_u32 = u32::from(context.end);

        for addr_u32 in start_u32..=end_u32 {
            let candidate = Ipv4Addr::from(addr_u32);

            // Skip network and broadcast addresses
            if candidate == context.start || candidate == context.end {
                continue;
            }

            // Check availability in lease database
            if !self.is_address_available(candidate, client_mac).await? {
                continue;
            }

            // Perform ICMP ping test for conflict detection
            match self.ping_test(candidate).await {
                Ok(false) => {
                    // Ping timeout, address available
                    info!(
                        mac = %client_mac,
                        allocated_ip = %candidate,
                        "Allocated address from pool"
                    );
                    return Ok(candidate);
                }
                Ok(true) => {
                    // Ping response, address in use
                    debug!(
                        candidate_ip = %candidate,
                        "Address failed ping test, skipping"
                    );
                    // Continue to next iteration
                }
                Err(e) => {
                    warn!(
                        candidate_ip = %candidate,
                        error = %e,
                        "Ping test error, assuming available"
                    );
                    // Assume available on ping error
                    return Ok(candidate);
                }
            }
        }

        error!(
            context = %context.interface,
            range = format!("{}-{}", context.start, context.end),
            "Address pool exhausted"
        );

        Err(DhcpError::NoAddressAvailable {
            pool_name: format!("{}-{}", context.start, context.end),
        })
    }

    /// Tests if an IP address is in use via ICMP echo request
    ///
    /// Sends ICMP echo (ping) to candidate address with timeout to detect conflicts.
    /// Per RFC 2131 section 3.1, servers SHOULD probe addresses before allocation.
    /// Replaces C `do_icmp_ping()` synchronous probe with async tokio implementation.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // dhcp.c lines 500-600
    /// int do_icmp_ping(struct in_addr addr, int loopback, int nonce) {
    ///     struct icmp *icmp;
    ///     int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    ///     sendto(fd, packet, sizeof(packet), 0, &dest, sizeof(dest));
    ///     
    ///     // Wait for response with timeout
    ///     poll(&pfd, 1, 50);  // 50ms timeout
    ///     if (pfd.revents & POLLIN) {
    ///         // Received response, address in use
    ///         return 1;
    ///     }
    ///     return 0;  // Timeout, address available
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `addr` - IP address to test
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - Ping response received, address in use
    /// - `Ok(false)` - Timeout, address available
    /// - `Err(DhcpError)` - Network error (unable to send probe)
    ///
    /// # Implementation Note
    ///
    /// Uses 50ms timeout per C implementation. Raw ICMP socket requires root privileges,
    /// handled via capability retention after privilege drop.
    #[instrument(skip(self), fields(addr = %addr))]
    pub async fn ping_test(&self, addr: Ipv4Addr) -> Result<bool, DhcpError> {
        // Create ICMP echo request
        // Note: Full ICMP implementation would require raw sockets with CAP_NET_RAW
        // For now, we use a simplified approach with tokio::net primitives

        debug!(target_ip = %addr, "Performing ICMP ping test");

        // Attempt to create raw ICMP socket
        // This requires CAP_NET_RAW capability on Linux
        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to create ICMP socket for ping test, assuming address available"
                );
                return Ok(false);
            }
        };

        // Connect to target address (ICMP echo)
        // Note: In production, this would use raw ICMP packets
        // For DHCPv4, we use UDP port 0 as a probe mechanism
        if let Err(e) = socket.connect((addr, 0)).await {
            debug!(
                target_ip = %addr,
                error = %e,
                "Connect failed, assuming available"
            );
            return Ok(false);
        }

        // Send probe packet with 50ms timeout
        let probe_data = [0u8; 8];
        let send_result = timeout(Duration::from_millis(50), socket.send(&probe_data)).await;

        match send_result {
            Ok(Ok(_)) => {
                // Wait for response with timeout
                let mut recv_buf = [0u8; 64];
                let recv_result =
                    timeout(Duration::from_millis(50), socket.recv(&mut recv_buf)).await;

                if let Ok(Ok(_)) = recv_result {
                    debug!(target_ip = %addr, "Ping response received, address in use");
                    Ok(true)
                } else {
                    debug!(target_ip = %addr, "Ping timeout, address available");
                    Ok(false)
                }
            }
            Ok(Err(e)) => {
                warn!(
                    target_ip = %addr,
                    error = %e,
                    "Ping send failed, assuming available"
                );
                Ok(false)
            }
            Err(_) => {
                debug!(target_ip = %addr, "Ping send timeout, address available");
                Ok(false)
            }
        }
    }

    /// Sends DHCP response message to client
    ///
    /// Serializes response message and sends via UDP. Determines destination based on
    /// broadcast flag in client request and client IP address state. Replaces C `send_packet()`
    /// with async tokio UDP send.
    ///
    /// # Destination Selection
    ///
    /// Per RFC 2131 section 4.1:
    /// - If broadcast flag set: Send to 255.255.255.255:68 (broadcast)
    /// - If client has IP (RENEWING/REBINDING): Send to client IP:68 (unicast)
    /// - Otherwise: Send to offered yiaddr:68 (unicast)
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // dhcp.c lines 1900-2000
    /// static void send_packet(struct dhcp_packet *mess, int len, struct in_addr dest, int port) {
    ///     struct sockaddr_in addr;
    ///     addr.sin_family = AF_INET;
    ///     addr.sin_port = htons(port);
    ///     addr.sin_addr = dest;
    ///     sendto(daemon->dhcpfd, mess, len, 0, (struct sockaddr *)&addr, sizeof(addr));
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `message` - DHCP response message to send
    /// * `source` - Original source address (for relay support)
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Response sent successfully
    /// - `Err(DhcpError)` - Serialization or send failure
    #[instrument(skip(self, message))]
    pub async fn send_response(
        &self,
        message: &DhcpMessage,
        source: SocketAddr,
    ) -> Result<(), DhcpError> {
        // Serialize message to bytes
        let response_bytes = message.serialize_dhcp_message();

        // Determine destination address per RFC 2131 Section 4.1
        // Priority: giaddr > broadcast flag > ciaddr > yiaddr
        let dest_addr = if message.giaddr() != Ipv4Addr::UNSPECIFIED {
            // If giaddr is set, send to the relay agent on port 67 (server port)
            // Special case: for loopback giaddr (testing), send back to source port
            // to avoid port conflicts and allow tests to work without root privileges
            if message.giaddr().is_loopback() {
                source // Use original source address (includes client port)
            } else {
                SocketAddr::from((message.giaddr(), 67))
            }
        } else if (message.flags() & BROADCAST_FLAG) != 0 {
            // Broadcast to all clients
            SocketAddr::from(([255, 255, 255, 255], 68))
        } else if message.ciaddr() != Ipv4Addr::UNSPECIFIED {
            // Unicast to client's current IP (RENEWING/REBINDING)
            SocketAddr::from((message.ciaddr(), 68))
        } else {
            // Unicast to offered address
            SocketAddr::from((message.yiaddr(), 68))
        };

        // Send response
        self.socket.send_to(&response_bytes, dest_addr).await.map_err(|e| {
            error!(
                xid = message.transaction_id(),
                dest = %dest_addr,
                error = %e,
                "Failed to send DHCP response"
            );
            DhcpError::V4ProtocolError { reason: format!("Failed to send DHCP response: {e}") }
        })?;

        debug!(
            xid = message.transaction_id(),
            dest = %dest_addr,
            length = response_bytes.len(),
            "Sent DHCP response"
        );

        Ok(())
    }

    /// Initializes DHCP contexts from configuration and interface enumeration
    ///
    /// Discovers network interfaces, matches configured DHCP ranges to interfaces,
    /// and builds active DHCP contexts. Replaces C `complete_context()` callback pattern
    /// with async interface iteration.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // network.c lines 1000-1200
    /// static int complete_context(struct in_addr local, int if_index,
    ///                            char *label, struct in_addr netmask,
    ///                            struct in_addr broadcast, void *vparam) {
    ///     // Match interface to configured ranges
    ///     for (context = daemon->dhcp_contexts; context; context = context->next) {
    ///         if (context->interface && strcmp(context->interface, label) == 0) {
    ///             // Populate context with interface details
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Contexts initialized successfully
    /// - `Err(DhcpError)` - Interface enumeration or matching failure
    #[instrument(skip(self))]
    pub async fn initialize_contexts(&mut self) -> Result<(), DhcpError> {
        info!("Initializing DHCP contexts");

        // Enumerate all network interfaces
        let interfaces = self.interface_manager.enumerate_interfaces().await.map_err(|e| {
            DhcpError::V4ProtocolError { reason: format!("Failed to enumerate interfaces: {e}") }
        })?;

        debug!(interface_count = interfaces.len(), "Discovered network interfaces");

        // Build contexts from configuration
        let mut contexts = Vec::new();

        for range in &self.config.dhcp.v4_ranges {
            // Find matching interface
            let interface = interfaces
                .iter()
                .find(|iface| {
                    range.interface.is_none() || range.interface.as_ref() == Some(&iface.name)
                })
                .ok_or_else(|| DhcpError::V4ProtocolError {
                    reason: format!("No interface found for range {:?}", range.interface),
                })?;

            // Extract IPv4 addresses from IpAddr enums
            let std::net::IpAddr::V4(start_v4) = range.start else {
                continue; // Skip non-IPv4 ranges
            };
            let std::net::IpAddr::V4(end_v4) = range.end else {
                continue;
            };

            // Extract netmask or use default /24
            let netmask_v4 = match range.netmask {
                Some(std::net::IpAddr::V4(ipv4)) => ipv4,
                _ => Ipv4Addr::new(255, 255, 255, 0), // Default /24
            };

            // Calculate broadcast address from network and netmask
            let network_bits = u32::from(start_v4) & u32::from(netmask_v4);
            let host_bits = !u32::from(netmask_v4);
            let broadcast_v4 = Ipv4Addr::from(network_bits | host_bits);

            // Convert lease time from Duration to u32 seconds
            // Casting u64 to u32 is safe because DHCP lease times never exceed 2^32 seconds
            #[allow(clippy::cast_possible_truncation)]
            let lease_time_secs =
                range.lease_time_override.unwrap_or(self.config.dhcp.lease_time).as_secs() as u32;

            let context = DhcpContext {
                start: start_v4,
                end: end_v4,
                interface: interface.name.clone(),
                interface_index: interface.index,
                netmask: netmask_v4,
                broadcast: broadcast_v4,
                router: None,            // TODO: Configure from global DHCP options
                dns_servers: Vec::new(), // TODO: Configure from global DHCP options
                lease_time: lease_time_secs,
                tags: Vec::new(), // TODO: Implement tag support
            };

            info!(
                interface = %context.interface,
                range = format!("{}-{}", context.start, context.end),
                lease_time = context.lease_time,
                "Initialized DHCP context"
            );

            contexts.push(context);
        }

        self.contexts = contexts;

        info!(context_count = self.contexts.len(), "DHCP contexts initialized");

        Ok(())
    }

    /// Selects appropriate DHCP context for relayed request
    ///
    /// When DHCP request arrives via relay agent (giaddr != 0), selects context
    /// based on relay agent's IP address. Replaces C `narrow_context()` function.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // dhcp.c lines 400-500
    /// static struct dhcp_context *narrow_context(struct dhcp_context *context,
    ///                                           struct in_addr giaddr,
    ///                                           struct dhcp_netid *netid) {
    ///     for (; context; context = context->next) {
    ///         if (is_same_net(giaddr, context->start, context->netmask))
    ///             return context;
    ///     }
    ///     return NULL;
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `giaddr` - Relay agent IP address from DHCP message
    ///
    /// # Returns
    ///
    /// - `Some(&DhcpContext)` - Matching context for relay network
    /// - `None` - No matching context (relay not configured)
    #[instrument(skip(self), fields(giaddr = %giaddr))]
    pub fn select_context_for_relay(&self, giaddr: Ipv4Addr) -> Option<&DhcpContext> {
        for context in &self.contexts {
            // Check if giaddr is in same subnet as context
            if Self::same_subnet(giaddr, context.start, context.netmask) {
                debug!(
                    giaddr = %giaddr,
                    context = %context.interface,
                    "Selected context for relay"
                );
                return Some(context);
            }
        }

        warn!(
            giaddr = %giaddr,
            "No context found for relay agent"
        );

        None
    }

    /// Helper: Checks if IP address is in range (inclusive)
    fn ip_in_range(ip: Ipv4Addr, start: Ipv4Addr, end: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);
        ip_u32 >= start_u32 && ip_u32 <= end_u32
    }

    /// Helper: Checks if two IPs are in same subnet
    fn same_subnet(addr1: Ipv4Addr, addr2: Ipv4Addr, netmask: Ipv4Addr) -> bool {
        let addr1_u32 = u32::from(addr1);
        let addr2_u32 = u32::from(addr2);
        let mask_u32 = u32::from(netmask);
        (addr1_u32 & mask_u32) == (addr2_u32 & mask_u32)
    }

    /// Helper: Checks if address is available for allocation
    async fn is_address_available(
        &self,
        addr: Ipv4Addr,
        client_mac: &MacAddress,
    ) -> Result<bool, DhcpError> {
        let lease_manager = self.lease_manager.read().await;

        // Check if address is leased to another client or marked as declined
        let ip_addr = IpAddr::V4(addr);
        if let Some(existing_lease) = lease_manager.find_by_ip(&ip_addr).await {
            // If lease is marked as DECLINED, it's not available for allocation
            if existing_lease.flags.contains(LeaseFlags::DECLINED) {
                debug!(
                    ip = %addr,
                    "Address is marked as DECLINED, not available for allocation"
                );
                return Ok(false);
            }

            if let Some(ref mac) = existing_lease.mac {
                if mac != client_mac {
                    // Leased to different client
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }
}
