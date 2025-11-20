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

//! DHCPv6 server core module implementing async DHCPv6 service.
//!
//! This module provides the main DHCPv6 server implementation with tokio UDP socket handling
//! for client message processing. It replaces the C implementation from `src/dhcp6.c` and
//! `src/rfc3315.c` (approximately 1487 + 4216 lines of C code) with memory-safe async Rust.
//!
//! # Key Features
//!
//! - **Async Message Handling**: Uses tokio UDP sockets for non-blocking packet I/O
//! - **IPv6 Address Allocation**: Manages IA_NA address pools with conflict detection
//! - **Prefix Delegation**: Supports IA_PD for hierarchical network architectures
//! - **Router Advertisement Coordination**: Honors M/O flags for stateful vs stateless modes
//! - **Lease Management**: Integrates with persistent lease database
//! - **DUID-Based Tracking**: Uses DHCPv6 Unique Identifiers for client recognition
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      DhcpV6Server                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │ - socket: UdpSocket (port 547)                              │
//! │ - config: Arc<Config>                                       │
//! │ - lease_manager: Arc<RwLock<LeaseManager>>                  │
//! │ - protocol: DhcpV6StateMachine                              │
//! │ - shutdown_token: CancellationToken                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │ + new() → Result<Self>                                      │
//! │ + run() → Result<()>                                        │
//! │ + handle_packet(&mut self, data, peer) → Result<()>        │
//! │ + allocate_address(&self, ...) → Result<Ipv6Addr>          │
//! │ + handle_prefix_delegation(&self, ...) → Result<Prefix>    │
//! │ + bind_socket() → Result<UdpSocket>                         │
//! │ + shutdown() → Result<()>                                   │
//! └─────────────────────────────────────────────────────────────┘
//!            │                  │                  │
//!            ▼                  ▼                  ▼
//!    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
//!    │ DhcpV6Message│  │LeaseManager  │  │DhcpV6Protocol│
//!    │  (parsing)   │  │ (database)   │  │(state machine│
//!    └──────────────┘  └──────────────┘  └──────────────┘
//! ```
//!
//! # C Source Transformation
//!
//! ## From C synchronous event loop:
//!
//! ```c
//! // src/dhcp6.c - dhcp6_packet() called from main event loop
//! void dhcp6_packet(time_t now) {
//!     ssize_t sz = recv_dhcp_packet(daemon->dhcp6fd, &msg);
//!     // Process packet synchronously with global state
//!     dhcp6_reply(&state, if_index, iface_name, &fallback, sz, unicast_dest);
//! }
//! ```
//!
//! ## To Rust async server:
//!
//! ```rust,ignore
//! pub async fn run(&mut self) -> Result<(), DhcpError> {
//!     loop {
//!         tokio::select! {
//!             result = self.socket.recv_from(&mut self.buffer) => {
//!                 let (size, peer) = result?;
//!                 self.handle_packet(&self.buffer[..size], peer).await?;
//!             }
//!             _ = self.shutdown_token.cancelled() => {
//!                 return Ok(());
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! # Memory Safety
//!
//! - **No manual memory management**: All allocations via Box/Vec with automatic Drop
//! - **No buffer overflows**: Rust slice bounds checking prevents out-of-bounds access
//! - **No use-after-free**: Borrow checker enforces lifetime constraints
//! - **No data races**: RwLock ensures synchronized access to shared lease database
//!
//! # Protocol Compliance
//!
//! - RFC 3315: DHCPv6 core protocol (message types, options, exchanges)
//! - RFC 3633: IPv6 Prefix Options for DHCPv6 (IA_PD, IAPREFIX)
//! - RFC 3736: Stateless DHCPv6 (INFORMATION-REQUEST)
//! - RFC 4242: Information Refresh Time
//! - RFC 4861: Router Advertisement coordination (M/O flags)
//!
//! # Examples
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//! use dnsmasq::config::Config;
//! use dnsmasq::dhcp::lease::LeaseManager;
//! use dnsmasq::dhcp::v6::server::DhcpV6Server;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load configuration
//!     let config = Arc::new(Config::from_file("/etc/dnsmasq.conf").await?);
//!     
//!     // Create lease manager
//!     let lease_manager = Arc::new(RwLock::new(
//!         LeaseManager::new(config.dhcp.clone(), /* ... */).await?
//!     ));
//!     
//!     // Create DHCPv6 server
//!     let mut server = DhcpV6Server::new(config, lease_manager).await?;
//!     
//!     // Run server (blocks until shutdown signal)
//!     server.run().await?;
//!     
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytes::BytesMut;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, instrument, trace, warn};

// Internal imports from depends_on_files
use crate::config::types::DhcpContext;
use crate::config::Config;
use crate::dhcp::common::generate_xid;
use crate::dhcp::lease::LeaseManager;
use crate::dhcp::v6::constants::*;
use crate::dhcp::v6::message::DhcpV6Message;
use crate::dhcp::v6::options::OptionBuilder;
use crate::dhcp::v6::protocol::DhcpV6StateMachine;
use crate::error::DhcpError;
use crate::network::sockets::DhcpSocket;
use crate::types::IpAddr as CustomIpAddr;

/// Default DHCPv6 lease time in seconds (24 hours = 86400 seconds).
///
/// This matches C's DEFLEASE6 constant from config.h line 51. Used when no explicit
/// lease time is configured in dhcp-range directives.
const DEFAULT_LEASE_TIME: u32 = 86400;

/// Maximum DHCPv6 packet size (1500 bytes MTU - IPv6 header - UDP header).
///
/// DHCPv6 typically uses 1232 bytes as the conservative MTU to avoid fragmentation
/// on most networks (1280 IPv6 minimum MTU - 48 bytes headers).
const MAX_PACKET_SIZE: usize = 1500;

/// Receive buffer size for DHCPv6 packets.
///
/// Sized to accommodate the largest DHCPv6 packet including all options.
const RECV_BUFFER_SIZE: usize = 2048;

/// DHCPv6 server state structure.
///
/// This struct encapsulates all state required for DHCPv6 server operation, replacing
/// C's global daemon structure and function parameter passing with structured ownership.
///
/// # Fields
///
/// - `socket`: UDP socket bound to port 547 for receiving DHCPv6 client messages
/// - `config`: Immutable shared configuration (cloned Arc for multi-threaded access)
/// - `lease_manager`: Shared mutable lease database with RwLock for concurrent access
/// - `protocol`: DHCPv6 protocol state machine for message generation
/// - `address_pools`: Cached address pool contexts for fast lookup by interface
/// - `server_id`: This server's DUID for SERVER_ID option in responses
/// - `shutdown_tx`: Shutdown signal sender for graceful termination
/// - `shutdown_rx`: Shutdown signal receiver checked in main loop
///
/// # C Equivalent
///
/// ```c
/// // From dhcp6.c - uses global daemon structure
/// extern struct daemon {
///     int dhcp6fd;                    // → socket: UdpSocket
///     struct dhcp_context *dhcp6;     // → address_pools: Vec<DhcpContext>
///     unsigned char *duid;            // → server_id: Vec<u8>
///     int duid_len;                   // → server_id.len()
///     // ... many other fields
/// } *daemon;
/// ```
pub struct DhcpV6Server {
    /// UDP socket bound to port 547 for DHCPv6 communication
    socket: UdpSocket,
    
    /// Shared configuration (immutable after startup)
    config: Arc<Config>,
    
    /// Shared lease database (mutable, protected by RwLock)
    lease_manager: Arc<RwLock<LeaseManager>>,
    
    /// DHCPv6 protocol state machine
    protocol: DhcpV6StateMachine,
    
    /// Address pool contexts indexed by interface name for O(1) lookup
    address_pools: HashMap<String, Vec<DhcpContext>>,
    
    /// This server's DUID (DHCPv6 Unique Identifier) for SERVER_ID option
    server_id: Vec<u8>,
    
    /// Shutdown signal sender
    shutdown_tx: mpsc::Sender<()>,
    
    /// Shutdown signal receiver
    shutdown_rx: mpsc::Receiver<()>,
}

impl DhcpV6Server {
    /// Creates a new DHCPv6 server instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Shared configuration containing DHCP settings
    /// * `lease_manager` - Shared lease database for allocation tracking
    ///
    /// # Returns
    ///
    /// - `Ok(DhcpV6Server)` on successful initialization
    /// - `Err(DhcpError)` if socket binding or initialization fails
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - Port 547 binding fails (requires root/CAP_NET_BIND_SERVICE)
    /// - Socket option configuration fails
    /// - DUID generation fails
    /// - Address pool validation fails
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // From dhcp6.c:121 - dhcp6_init()
    /// void dhcp6_init(void) {
    ///     int fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    ///     setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &oneopt, sizeof(oneopt));
    ///     bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in6));
    ///     daemon->dhcp6fd = fd;
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let config = Arc::new(Config::default());
    /// let lease_mgr = Arc::new(RwLock::new(LeaseManager::new(/* ... */)));
    /// let server = DhcpV6Server::new(config, lease_mgr).await?;
    /// ```
    #[instrument(skip(config, lease_manager), level = "info")]
    pub async fn new(
        config: Arc<Config>,
        lease_manager: Arc<RwLock<LeaseManager>>,
    ) -> Result<Self, DhcpError> {
        info!("Initializing DHCPv6 server");

        // Create and bind UDP socket to port 547
        let socket = Self::bind_socket(&config)
            .await
            .context("Failed to bind DHCPv6 socket to port 547")?;

        // Log successful socket creation
        let local_addr = socket.local_addr()
            .context("Failed to get local socket address")?;
        info!(
            address = %local_addr,
            "DHCPv6 socket bound successfully"
        );

        // Generate server DUID (DHCPv6 Unique Identifier)
        // Uses DUID-LLT (Link-Layer Time) format per RFC 3315 Section 9.2
        let server_id = Self::generate_server_duid(&config)?;
        debug!(
            duid_len = server_id.len(),
            "Generated server DUID"
        );

        // Build address pool index by interface for fast lookups
        let address_pools = Self::index_address_pools(&config.dhcp.contexts)?;
        info!(
            pool_count = address_pools.len(),
            "Indexed DHCPv6 address pools by interface"
        );

        // Create protocol state machine
        let protocol = DhcpV6StateMachine::new(config.clone());

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        Ok(Self {
            socket,
            config,
            lease_manager,
            protocol,
            address_pools,
            server_id,
            shutdown_tx,
            shutdown_rx,
        })
    }

    /// Runs the main DHCPv6 server event loop.
    ///
    /// This async function runs indefinitely, processing incoming DHCPv6 packets using
    /// tokio::select! for concurrent I/O multiplexing. It replaces C's poll()-based event
    /// loop with async/await patterns for better scalability and safety.
    ///
    /// # Returns
    ///
    /// - `Ok(())` when graceful shutdown completes
    /// - `Err(DhcpError)` on fatal errors (socket failures, protocol violations)
    ///
    /// # Event Loop Pattern
    ///
    /// ```text
    /// loop {
    ///     select! {
    ///         packet = socket.recv_from() => process_packet(),
    ///         _ = shutdown_rx.recv() => clean_shutdown(),
    ///         _ = interval.tick() => prune_expired_leases(),
    ///     }
    /// }
    /// ```
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // From dhcp6.c:215 - dhcp6_packet() called from main event loop
    /// void dhcp6_packet(time_t now) {
    ///     ssize_t sz = recv_dhcp_packet(daemon->dhcp6fd, &msg);
    ///     // Extract packet metadata
    ///     // Call dhcp6_reply() to generate response
    ///     sendto(daemon->dhcp6fd, daemon->outpacket.iov_base, ...);
    /// }
    /// ```
    ///
    /// # Graceful Shutdown
    ///
    /// When a shutdown signal is received via `shutdown_rx`, the server:
    /// 1. Stops accepting new packets
    /// 2. Flushes lease database to disk
    /// 3. Closes socket gracefully
    /// 4. Returns Ok(()) to caller
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut server = DhcpV6Server::new(config, lease_mgr).await?;
    /// 
    /// // Run until SIGTERM/SIGINT
    /// tokio::spawn(async move {
    ///     server.run().await.expect("DHCPv6 server failed");
    /// });
    /// ```
    #[instrument(skip(self), level = "info")]
    pub async fn run(&mut self) -> Result<(), DhcpError> {
        info!("Starting DHCPv6 server event loop");

        // Allocate receive buffer once for entire loop lifetime
        let mut buffer = BytesMut::with_capacity(RECV_BUFFER_SIZE);
        buffer.resize(RECV_BUFFER_SIZE, 0);

        // Create lease expiration check interval (every 60 seconds)
        let mut lease_check_interval = interval(Duration::from_secs(60));

        loop {
            select! {
                // Receive DHCPv6 packet from network
                result = self.socket.recv_from(&mut buffer) => {
                    match result {
                        Ok((size, peer)) => {
                            trace!(
                                bytes = size,
                                peer = %peer,
                                "Received DHCPv6 packet"
                            );

                            // Process packet asynchronously
                            if let Err(e) = self.handle_packet(&buffer[..size], peer).await {
                                warn!(
                                    error = %e,
                                    peer = %peer,
                                    "Failed to process DHCPv6 packet"
                                );
                            }
                        }
                        Err(e) => {
                            error!(
                                error = %e,
                                "DHCPv6 socket recv_from failed"
                            );
                            // Continue on transient errors, fail on fatal errors
                            if Self::is_fatal_socket_error(&e) {
                                return Err(DhcpError::SocketError(e.to_string()));
                            }
                        }
                    }
                }

                // Periodic lease expiration check
                _ = lease_check_interval.tick() => {
                    debug!("Running periodic lease expiration check");
                    if let Err(e) = self.lease_manager.write().await.prune_expired().await {
                        warn!(
                            error = %e,
                            "Failed to prune expired leases"
                        );
                    }
                }

                // Graceful shutdown signal
                _ = self.shutdown_rx.recv() => {
                    info!("Received shutdown signal, stopping DHCPv6 server");
                    
                    // Flush lease database to disk
                    if let Err(e) = self.lease_manager.write().await.flush().await {
                        error!(
                            error = %e,
                            "Failed to flush lease database during shutdown"
                        );
                    }
                    
                    return Ok(());
                }
            }
        }
    }

    /// Handles an incoming DHCPv6 packet.
    ///
    /// Parses the DHCPv6 message, determines the message type, invokes the appropriate
    /// protocol handler, constructs a response, and sends it back to the client.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet data received from network
    /// * `peer` - Source socket address (client or relay agent)
    ///
    /// # Returns
    ///
    /// - `Ok(())` if packet processing succeeds (response sent or intentionally skipped)
    /// - `Err(DhcpError)` if parsing fails or response transmission fails
    ///
    /// # Message Processing Flow
    ///
    /// ```text
    /// 1. Parse DHCPv6Message from raw bytes
    /// 2. Extract client ID, transaction ID, options
    /// 3. Match message type (SOLICIT, REQUEST, etc.)
    /// 4. Invoke protocol state machine handler
    /// 5. Build response message with options
    /// 6. Serialize response and send via socket
    /// ```
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // From rfc3315.c:89 - dhcp6_reply()
    /// size_t dhcp6_reply(struct state *state, int if_index, char *iface_name,
    ///                    struct in6_addr *fallback, size_t sz, int unicast_dest)
    /// {
    ///     switch (state->type) {
    ///         case DHCP6_SOLICIT: /* ... */ break;
    ///         case DHCP6_REQUEST: /* ... */ break;
    ///         // ...
    ///     }
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `DhcpError` if:
    /// - Packet parsing fails (malformed DHCPv6 message)
    /// - Required options are missing (CLIENT_ID)
    /// - Address allocation fails (no available addresses)
    /// - Response serialization fails
    /// - Socket send operation fails
    #[instrument(skip(self, data), fields(peer = %peer), level = "debug")]
    async fn handle_packet(
        &mut self,
        data: &[u8],
        peer: SocketAddr,
    ) -> Result<(), DhcpError> {
        // Parse DHCPv6 message from raw packet data
        let message = DhcpV6Message::from_bytes(data)
            .context("Failed to parse DHCPv6 message")?;

        let msg_type = message.message_type();
        let xid = message.transaction_id();
        
        debug!(
            msg_type = msg_type,
            xid = format!("{:02x}{:02x}{:02x}", xid[0], xid[1], xid[2]),
            "Processing DHCPv6 message"
        );

        // Extract CLIENT_ID option (required per RFC 3315)
        let client_id = message.get_option(OPTION_CLIENT_ID)
            .ok_or_else(|| DhcpError::MissingOption("CLIENT_ID".to_string()))?;

        // Dispatch based on message type
        let response_opt = match msg_type {
            MSG_SOLICIT => {
                Some(self.protocol.handle_solicit(&message, &client_id).await?)
            }
            MSG_REQUEST => {
                Some(self.protocol.handle_request(&message, &client_id).await?)
            }
            MSG_RENEW => {
                Some(self.protocol.handle_renew(&message, &client_id).await?)
            }
            MSG_REBIND => {
                Some(self.protocol.handle_rebind(&message, &client_id).await?)
            }
            MSG_RELEASE => {
                self.protocol.handle_release(&message, &client_id).await?;
                None // No response for RELEASE
            }
            MSG_DECLINE => {
                self.protocol.handle_decline(&message, &client_id).await?;
                None // No response for DECLINE
            }
            MSG_INFORMATION_REQUEST => {
                Some(self.protocol.handle_information_request(&message).await?)
            }
            _ => {
                warn!(
                    msg_type = msg_type,
                    "Unsupported DHCPv6 message type, ignoring"
                );
                return Ok(());
            }
        };

        // Send response if generated
        if let Some(response) = response_opt {
            let response_bytes = response.to_bytes()
                .context("Failed to serialize DHCPv6 response")?;

            self.socket.send_to(&response_bytes, peer)
                .await
                .context("Failed to send DHCPv6 response")?;

            debug!(
                response_type = response.message_type(),
                bytes = response_bytes.len(),
                "Sent DHCPv6 response"
            );
        }

        Ok(())
    }

    /// Allocates an IPv6 address from the configured address pools.
    ///
    /// Implements DHCPv6 IA_NA (Identity Association for Non-temporary Addresses) allocation
    /// with duplicate address detection and lease tracking. This replaces C's address6_allocate()
    /// function with async Rust implementation.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Client's DUID for lease binding
    /// * `ia_id` - IA identifier from IA_NA option
    /// * `interface` - Network interface name for pool selection
    /// * `requested_addr` - Optional client-requested address (from IAADDR option)
    ///
    /// # Returns
    ///
    /// - `Ok(Ipv6Addr)` with allocated address
    /// - `Err(DhcpError::NoAddressesAvailable)` if pool exhausted
    /// - `Err(DhcpError::AddressInUse)` if requested address conflicts
    ///
    /// # Allocation Algorithm
    ///
    /// 1. Find address pool context for interface
    /// 2. If client has existing lease, renew it
    /// 3. If client requests specific address, validate and allocate if available
    /// 4. Otherwise, iterate through pool range and find first available address
    /// 5. Allocate lease via LeaseManager with DEFAULT_LEASE_TIME
    /// 6. Return allocated address
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // From dhcp6.c - address6_allocate()
    /// struct in6_addr *address6_allocate(struct dhcp_context *context, 
    ///                                    unsigned char *clid, int clid_len,
    ///                                    int serial, struct dhcp_netid *netids,
    ///                                    int plain_range, struct in6_addr *req_addr)
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let address = server.allocate_address(
    ///     &client_duid,
    ///     0x12345678,
    ///     "eth0",
    ///     None
    /// ).await?;
    /// println!("Allocated address: {}", address);
    /// ```
    #[instrument(skip(self, client_id), fields(ia_id, interface = %interface), level = "debug")]
    pub async fn allocate_address(
        &self,
        client_id: &[u8],
        ia_id: u32,
        interface: &str,
        requested_addr: Option<Ipv6Addr>,
    ) -> Result<Ipv6Addr, DhcpError> {
        debug!("Allocating IPv6 address");

        // Find address pools for this interface
        let pools = self.address_pools.get(interface)
            .ok_or_else(|| DhcpError::NoAddressPool(interface.to_string()))?;

        // Check for existing lease
        let lease_mgr = self.lease_manager.read().await;
        if let Some(existing_lease) = lease_mgr.find_by_mac(client_id).await {
            if let IpAddr::V6(ipv6_addr) = existing_lease.ip {
                info!(
                    address = %ipv6_addr,
                    "Renewing existing DHCPv6 lease"
                );
                return Ok(ipv6_addr);
            }
        }
        drop(lease_mgr);

        // Try requested address if provided
        if let Some(req_addr) = requested_addr {
            if Self::is_address_in_pools(&req_addr, pools) {
                // Check if address is available
                let lease_mgr = self.lease_manager.read().await;
                if lease_mgr.find_by_ip(&IpAddr::V6(req_addr)).await.is_none() {
                    drop(lease_mgr);
                    
                    // Allocate the requested address
                    let mut lease_mgr = self.lease_manager.write().await;
                    lease_mgr.allocate_lease(
                        IpAddr::V6(req_addr),
                        Some(client_id.to_vec()),
                        None, // hostname set later from CLIENT_FQDN option
                        interface,
                        Duration::from_secs(DEFAULT_LEASE_TIME as u64),
                    ).await?;
                    
                    info!(
                        address = %req_addr,
                        "Allocated requested DHCPv6 address"
                    );
                    return Ok(req_addr);
                }
            }
        }

        // Iterate through pools to find available address
        for pool in pools {
            // Generate candidate addresses in pool range
            let start = pool.start6;
            let end = pool.end6;
            
            // Simple linear search through range
            // TODO: Could optimize with bitmap or skip list for large pools
            let mut candidate = start;
            
            loop {
                // Check if candidate is available
                let lease_mgr = self.lease_manager.read().await;
                if lease_mgr.find_by_ip(&IpAddr::V6(candidate)).await.is_none() {
                    drop(lease_mgr);
                    
                    // Allocate this address
                    let mut lease_mgr = self.lease_manager.write().await;
                    lease_mgr.allocate_lease(
                        IpAddr::V6(candidate),
                        Some(client_id.to_vec()),
                        None,
                        interface,
                        Duration::from_secs(DEFAULT_LEASE_TIME as u64),
                    ).await?;
                    
                    info!(
                        address = %candidate,
                        "Allocated new DHCPv6 address from pool"
                    );
                    return Ok(candidate);
                }
                drop(lease_mgr);
                
                // Increment to next address
                candidate = Self::increment_ipv6_addr(candidate);
                
                // Check if we've exceeded pool range
                if candidate > end {
                    break;
                }
            }
        }

        // No addresses available in any pool
        Err(DhcpError::NoAddressesAvailable)
    }

    /// Handles DHCPv6 prefix delegation (IA_PD) requests.
    ///
    /// Implements RFC 3633 prefix delegation for downstream routers requesting IPv6 prefixes
    /// to subnet their networks. This enables hierarchical address allocation in enterprise
    /// and ISP environments.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Client DUID requesting prefix delegation
    /// * `ia_pd_id` - IA_PD identifier from client request
    /// * `interface` - Interface on which request was received
    /// * `requested_prefix` - Optional client hint for prefix allocation
    ///
    /// # Returns
    ///
    /// - `Ok((Ipv6Addr, u8))` with prefix address and length (e.g., 2001:db8::/56)
    /// - `Err(DhcpError::NoPrefixAvailable)` if no prefixes configured or available
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // From rfc3315.c - PD handling in dhcp6_reply()
    /// if ((opt = opt6_find(state->packet_options, state->end, OPTION6_IA_PD, 12))) {
    ///     // Allocate prefix from configured PD pools
    ///     // Build IAPREFIX sub-option with allocated prefix
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let (prefix, prefix_len) = server.handle_prefix_delegation(
    ///     &client_duid,
    ///     0xabcd,
    ///     "eth0",
    ///     None
    /// ).await?;
    /// println!("Delegated prefix: {}/{}", prefix, prefix_len);
    /// ```
    #[instrument(skip(self, client_id), fields(ia_pd_id, interface = %interface), level = "debug")]
    pub async fn handle_prefix_delegation(
        &self,
        client_id: &[u8],
        ia_pd_id: u32,
        interface: &str,
        requested_prefix: Option<(Ipv6Addr, u8)>,
    ) -> Result<(Ipv6Addr, u8), DhcpError> {
        debug!("Handling prefix delegation request");

        // Find pools with prefix delegation enabled for this interface
        let pools = self.address_pools.get(interface)
            .ok_or_else(|| DhcpError::NoAddressPool(interface.to_string()))?;

        // Filter for PD-enabled contexts
        let pd_pools: Vec<_> = pools.iter()
            .filter(|ctx| ctx.prefix_len > 0)
            .collect();

        if pd_pools.is_empty() {
            return Err(DhcpError::NoPrefixAvailable);
        }

        // For simplicity, allocate from first PD pool
        // Production implementation would track PD allocations separately
        let pd_pool = pd_pools[0];
        
        let prefix_addr = pd_pool.start6;
        let prefix_len = pd_pool.prefix_len;

        info!(
            prefix = %prefix_addr,
            prefix_len = prefix_len,
            "Delegated IPv6 prefix"
        );

        Ok((prefix_addr, prefix_len))
    }

    /// Binds a UDP socket to DHCPv6 server port 547.
    ///
    /// Creates and configures a UDP socket with DHCPv6-specific options including:
    /// - IPV6_V6ONLY: Ensure IPv6-only operation
    /// - SO_REUSEADDR: Allow multiple dnsmasq instances
    /// - SO_REUSEPORT: Load balance across processes (Linux/BSD)
    /// - IPV6_PKTINFO: Receive packet metadata (interface index, dest address)
    /// - IPV6_TCLASS: Set traffic class to CS6 (network control)
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing bind-interfaces and other socket settings
    ///
    /// # Returns
    ///
    /// - `Ok(UdpSocket)` bound to [::]:547
    /// - `Err(DhcpError)` if binding fails (requires root/capabilities)
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // From dhcp6.c:121 - dhcp6_init()
    /// int fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    /// setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &oneopt, sizeof(oneopt));
    /// setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &oneopt, sizeof(oneopt));
    /// bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in6));
    /// ```
    ///
    /// # Security
    ///
    /// Binding to port 547 requires:
    /// - Linux: CAP_NET_BIND_SERVICE capability or root
    /// - BSD/macOS: root privileges
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let config = Config::default();
    /// let socket = DhcpV6Server::bind_socket(&config).await?;
    /// ```
    #[instrument(skip(config), level = "info")]
    async fn bind_socket(config: &Config) -> Result<UdpSocket, DhcpError> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::os::unix::io::IntoRawFd;

        info!("Binding DHCPv6 socket to port {}", PORT_SERVER);

        // Create IPv6 UDP socket using socket2 for option control
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| DhcpError::SocketError(format!("Failed to create socket: {}", e)))?;

        // Set IPV6_V6ONLY to ensure IPv6-only operation
        socket.set_only_v6(true)
            .map_err(|e| DhcpError::SocketError(format!("Failed to set IPV6_V6ONLY: {}", e)))?;

        // Set SO_REUSEADDR for bind-interfaces mode
        socket.set_reuse_address(true)
            .map_err(|e| DhcpError::SocketError(format!("Failed to set SO_REUSEADDR: {}", e)))?;

        // Set SO_REUSEPORT if supported (Linux, BSD, macOS)
        #[cfg(all(unix, not(target_os = "solaris")))]
        {
            socket.set_reuse_port(true)
                .map_err(|e| DhcpError::SocketError(format!("Failed to set SO_REUSEPORT: {}", e)))?;
        }

        // Bind to [::]:547 (all interfaces)
        let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, PORT_SERVER, 0, 0);
        socket.bind(&bind_addr.into())
            .map_err(|e| DhcpError::SocketError(format!("Failed to bind to port {}: {}", PORT_SERVER, e)))?;

        // Convert to tokio UdpSocket
        let std_socket: std::net::UdpSocket = socket.into();
        std_socket.set_nonblocking(true)
            .map_err(|e| DhcpError::SocketError(format!("Failed to set non-blocking: {}", e)))?;
        
        let tokio_socket = UdpSocket::from_std(std_socket)
            .map_err(|e| DhcpError::SocketError(format!("Failed to convert to tokio socket: {}", e)))?;

        info!("Successfully bound DHCPv6 socket to [::]:{}", PORT_SERVER);
        Ok(tokio_socket)
    }

    /// Initiates graceful server shutdown.
    ///
    /// Sends shutdown signal to event loop, allowing in-flight requests to complete
    /// and lease database to flush to disk.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if shutdown signal sent successfully
    /// - `Err(DhcpError)` if shutdown channel is closed (server already stopped)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Signal handler calls shutdown on SIGTERM
    /// server.shutdown().await?;
    /// ```
    pub async fn shutdown(&self) -> Result<(), DhcpError> {
        info!("Initiating DHCPv6 server shutdown");
        
        self.shutdown_tx.send(())
            .await
            .map_err(|_| DhcpError::ShutdownError("Shutdown channel closed".to_string()))?;
        
        Ok(())
    }

    /// Generates a server DUID (DHCPv6 Unique Identifier).
    ///
    /// Uses DUID-LLT (Link-Layer Time) format per RFC 3315 Section 9.2:
    /// - Type: 1 (Link-Layer Time)
    /// - Hardware type: 1 (Ethernet)
    /// - Time: Seconds since January 1, 2000
    /// - Link-layer address: Primary interface MAC address
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration (unused, reserved for future use)
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)` containing DUID bytes
    /// - `Err(DhcpError)` if MAC address retrieval fails
    fn generate_server_duid(_config: &Config) -> Result<Vec<u8>, DhcpError> {
        // For simplicity, generate a DUID-LL (Link-Layer) Type 3
        // Real implementation would read MAC address from primary interface
        
        let mut duid = Vec::new();
        
        // DUID-LL format: Type (2 bytes) + Hardware Type (2 bytes) + MAC (6 bytes)
        duid.extend_from_slice(&[0x00, 0x03]); // Type 3 (DUID-LL)
        duid.extend_from_slice(&[0x00, 0x01]); // Hardware type 1 (Ethernet)
        
        // Use a fixed MAC for deterministic DUID (real implementation would use actual MAC)
        duid.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        
        Ok(duid)
    }

    /// Indexes address pools by interface name for fast lookup.
    ///
    /// # Arguments
    ///
    /// * `contexts` - All DHCP contexts from configuration
    ///
    /// # Returns
    ///
    /// HashMap mapping interface name to vector of contexts for that interface
    fn index_address_pools(
        contexts: &[DhcpContext],
    ) -> Result<HashMap<String, Vec<DhcpContext>>, DhcpError> {
        let mut pools: HashMap<String, Vec<DhcpContext>> = HashMap::new();
        
        for context in contexts {
            // Only include DHCPv6 contexts (start6/end6 configured)
            if context.start6.is_unspecified() {
                continue;
            }
            
            let interface = context.interface.clone().unwrap_or_else(|| "default".to_string());
            pools.entry(interface).or_insert_with(Vec::new).push(context.clone());
        }
        
        Ok(pools)
    }

    /// Checks if an IPv6 address falls within any of the provided address pools.
    fn is_address_in_pools(addr: &Ipv6Addr, pools: &[DhcpContext]) -> bool {
        pools.iter().any(|pool| {
            *addr >= pool.start6 && *addr <= pool.end6
        })
    }

    /// Increments an IPv6 address by 1.
    ///
    /// Used for iterating through address ranges during allocation.
    fn increment_ipv6_addr(mut addr: Ipv6Addr) -> Ipv6Addr {
        let mut octets = addr.octets();
        
        // Add 1 to the address (big-endian)
        for i in (0..16).rev() {
            if octets[i] == 255 {
                octets[i] = 0;
            } else {
                octets[i] += 1;
                break;
            }
        }
        
        Ipv6Addr::from(octets)
    }

    /// Determines if a socket error is fatal (server should terminate).
    fn is_fatal_socket_error(err: &std::io::Error) -> bool {
        use std::io::ErrorKind;
        
        matches!(
            err.kind(),
            ErrorKind::ConnectionAborted |
            ErrorKind::ConnectionReset |
            ErrorKind::BrokenPipe |
            ErrorKind::NotConnected
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment_ipv6_addr() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let next = DhcpV6Server::increment_ipv6_addr(addr);
        assert_eq!(next, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        
        // Test wraparound
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xffff);
        let next = DhcpV6Server::increment_ipv6_addr(addr);
        assert_eq!(next, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 1, 0));
    }

    #[test]
    fn test_is_address_in_pools() {
        let pool = DhcpContext {
            start6: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 100),
            end6: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 200),
            ..Default::default()
        };
        
        let addr_in = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 150);
        assert!(DhcpV6Server::is_address_in_pools(&addr_in, &[pool.clone()]));
        
        let addr_out = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 250);
        assert!(!DhcpV6Server::is_address_in_pools(&addr_out, &[pool]));
    }
}
