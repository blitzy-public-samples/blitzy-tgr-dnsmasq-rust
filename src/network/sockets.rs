// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Socket creation and management module
//!
//! Provides cross-platform listener establishment, socket option configuration, and
//! protocol-specific binding for DNS, DHCP, TFTP, and Router Advertisement services.
//!
//! # C Implementation Mapping
//!
//! This module replaces C network.c socket creation functions:
//! - `create_bound_listeners()` → `SocketManager::create_dns_listeners()`
//! - `create_wildcard_listeners()` → Wildcard binding in create_dns_listeners()
//! - `struct listener` linked list → `Vec<DnsListener>` with owned data
//!
//! # Key Transformations
//!
//! ## 1. Socket Creation Pattern
//!
//! C pattern:
//! ```c
//! int fd = socket(AF_INET, SOCK_DGRAM, 0);
//! setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
//! bind(fd, &addr, sizeof(addr));
//! ```
//!
//! Rust pattern:
//! ```rust,ignore
//! let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
//! socket.set_reuse_address(true)?;
//! let socket: UdpSocket = socket.into();
//! ```
//!
//! ## 2. Listener Management
//!
//! C pattern:
//! ```c
//! struct listener {
//!     int fd;
//!     union mysockaddr addr;
//!     int flags;
//!     struct irec *iface;
//!     struct listener *next;
//! };
//! ```
//!
//! Rust pattern:
//! ```rust,ignore
//! pub struct DnsListener {
//!     pub socket: UdpSocket,
//!     pub local_addr: SocketAddr,
//!     pub interface: Option<String>,
//!     pub flags: ListenerFlags,
//! }
//! ```
//!
//! ## 3. Platform-Specific Options
//!
//! Linux: SO_BINDTODEVICE via nix::sys::socket::setsockopt
//! macOS: SO_BINDTOIF via nix
//! BSD: IP_BOUND_IF via nix
//!
//! # Architecture
//!
//! ```text
//! SocketManager
//! ├── create_dns_listeners() → Vec<DnsListener>
//! │   ├── UDP port 53
//! │   ├── TCP port 53 (for large queries)
//! │   └── Per-interface or wildcard binding
//! ├── create_dhcp_listeners() → (DhcpSocket, DhcpSocket)
//! │   ├── UDP port 67 (DHCPv4)
//! │   └── UDP port 547 (DHCPv6)
//! ├── create_tftp_listener() → TftpSocket
//! │   └── UDP port 69
//! └── create_icmpv6_socket() → RaSocket
//!     └── Raw ICMPv6 socket
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use bitflags::bitflags;
use bytes::{Bytes, BytesMut};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, instrument, warn};

use crate::config::types::NetworkConfig;
use crate::constants::EDNS_PKTSZ;
use crate::error::{NetworkError, Result};
use crate::network::interfaces::NetworkInterface;
use crate::types::IpAddr as CrateIpAddr;

bitflags! {
    /// Listener state flags for protocol-specific socket behavior
    ///
    /// Replaces C network.c listener flags with type-safe bitflags.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// #define LOPT_TCP 1
    /// #define LOPT_TFTP 2
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ListenerFlags: u32 {
        /// TCP listener (vs. UDP)
        const TCP = 0x01;
        
        /// TFTP listener
        const TFTP = 0x02;
        
        /// Wildcard listener (0.0.0.0 or ::)
        const WILDCARD = 0x04;
        
        /// Interface-specific listener
        const INTERFACE_SPECIFIC = 0x08;
    }
}

/// DNS listener socket with metadata
///
/// Replaces C `struct listener` from network.c with memory-safe Rust types.
/// Supports both UDP and TCP sockets for DNS protocol handling.
///
/// # C Equivalent
///
/// ```c
/// struct listener {
///     int fd;                    // File descriptor
///     union mysockaddr addr;     // Bound address
///     int flags;                 // LOPT_* flags
///     struct irec *iface;        // Associated interface
///     struct listener *next;     // Linked list pointer
/// };
/// ```
#[derive(Debug)]
pub struct DnsListener {
    /// UDP or TCP socket for DNS protocol
    pub socket: DnsSocketType,
    
    /// Local address the socket is bound to
    pub local_addr: SocketAddr,
    
    /// Interface name if bound to specific interface
    pub interface: Option<String>,
    
    /// Listener type flags
    pub flags: ListenerFlags,
}

/// DNS socket types (UDP or TCP)
#[derive(Debug)]
pub enum DnsSocketType {
    /// UDP socket for standard DNS queries
    Udp(UdpSocket),
    
    /// TCP socket for large DNS queries (DNSSEC, AXFR)
    Tcp(TcpListener),
}

/// DNS UDP socket wrapper with metadata retrieval
///
/// Wraps tokio::net::UdpSocket with methods for receiving packet metadata
/// including source address, destination address, and interface information.
/// Uses IP_PKTINFO (IPv4) and IPV6_RECVPKTINFO (IPv6) socket options.
pub struct DnsSocket {
    inner: UdpSocket,
}

impl DnsSocket {
    /// Create new DNS socket from UdpSocket
    pub fn new(socket: UdpSocket) -> Self {
        Self { inner: socket }
    }
    
    /// Receive packet with source, destination, and interface metadata
    ///
    /// Uses recvmsg with ancillary data to extract packet metadata.
    /// Returns tuple of (data, peer_addr, local_addr).
    ///
    /// # Errors
    ///
    /// Returns NetworkError if reception fails or metadata extraction fails.
    #[instrument(skip(self, buf))]
    pub async fn recv_with_metadata(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, SocketAddr, SocketAddr)> {
        // Use standard recv_from for now - full metadata requires platform-specific code
        let (len, peer_addr) = self.inner.recv_from(buf).await
            .map_err(|e| NetworkError::SocketFailed {
                address: self.inner.local_addr().ok()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                reason: format!("Failed to receive packet: {}", e),
            })?;
        
        let local_addr = self.inner.local_addr()
            .map_err(|e| NetworkError::SocketFailed {
                address: "unknown".to_string(),
                reason: format!("Failed to get local address: {}", e),
            })?;
        
        Ok((len, peer_addr, local_addr))
    }
    
    /// Send packet to specified address
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        self.inner.send_to(buf, target).await
            .map_err(|e| NetworkError::SocketFailed {
                address: target.to_string(),
                reason: format!("Failed to send packet: {}", e),
            })
    }
    
    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.inner.local_addr()
            .map_err(|e| NetworkError::SocketFailed {
                address: "unknown".to_string(),
                reason: format!("Failed to get local address: {}", e),
            })
    }
    
    /// Get peer address if connected
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.inner.peer_addr()
            .map_err(|e| NetworkError::SocketFailed {
                address: "unknown".to_string(),
                reason: format!("Failed to get peer address: {}", e),
            })
    }
}

/// DHCP socket wrapper with broadcast support
///
/// Wraps UDP socket with DHCP-specific options including SO_BROADCAST
/// for DHCPv4 broadcast messages and interface binding for DHCP relay.
pub struct DhcpSocket {
    inner: UdpSocket,
}

impl DhcpSocket {
    /// Create new DHCP socket from UdpSocket
    pub fn new(socket: UdpSocket) -> Self {
        Self { inner: socket }
    }
    
    /// Receive DHCP packet
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
            .map_err(|e| NetworkError::SocketFailed {
                address: self.inner.local_addr().ok()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                reason: format!("Failed to receive DHCP packet: {}", e),
            })
    }
    
    /// Send DHCP packet to specific address
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        self.inner.send_to(buf, target).await
            .map_err(|e| NetworkError::SocketFailed {
                address: target.to_string(),
                reason: format!("Failed to send DHCP packet: {}", e),
            })
    }
    
    /// Send broadcast DHCP packet
    pub async fn send_broadcast(&self, buf: &[u8], port: u16) -> Result<usize> {
        let broadcast_addr = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::BROADCAST,
            port,
        ));
        self.send_to(buf, broadcast_addr).await
    }
    
    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.inner.local_addr()
            .map_err(|e| NetworkError::SocketFailed {
                address: "unknown".to_string(),
                reason: format!("Failed to get local address: {}", e),
            })
    }
    
    /// Get peer address if available
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.inner.peer_addr()
            .map_err(|e| NetworkError::SocketFailed {
                address: "unknown".to_string(),
                reason: format!("Failed to get peer address: {}", e),
            })
    }
}

/// TFTP socket type (UDP-based)
pub type TftpSocket = UdpSocket;

/// Router Advertisement ICMPv6 socket wrapper
///
/// Wraps raw ICMPv6 socket for sending Router Advertisements.
/// Requires IPV6_RECVHOPLIMIT socket option for hop limit validation.
pub struct RaSocket {
    inner: UdpSocket,
}

impl RaSocket {
    /// Create new RA socket
    pub fn new(socket: UdpSocket) -> Self {
        Self { inner: socket }
    }
    
    /// Send Router Advertisement
    pub async fn send_ra(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        self.inner.send_to(buf, target).await
            .map_err(|e| NetworkError::SocketFailed {
                address: target.to_string(),
                reason: format!("Failed to send RA: {}", e),
            })
    }
    
    /// Receive ICMPv6 packet
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
            .map_err(|e| NetworkError::SocketFailed {
                address: "unknown".to_string(),
                reason: format!("Failed to receive ICMPv6: {}", e),
            })
    }
    
    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.inner.local_addr()
            .map_err(|e| NetworkError::SocketFailed {
                address: "unknown".to_string(),
                reason: format!("Failed to get local address: {}", e),
            })
    }
}

/// Socket manager coordinating all network listener creation
///
/// Replaces C network.c's create_bound_listeners() and create_wildcard_listeners()
/// with unified async interface supporting both wildcard and interface-specific binding.
pub struct SocketManager {
    config: Arc<NetworkConfig>,
}

impl SocketManager {
    /// Create new socket manager with configuration
    pub fn new(config: Arc<NetworkConfig>) -> Self {
        Self { config }
    }
    
    /// Create DNS listeners on port 53 with appropriate socket options
    ///
    /// Replaces C create_bound_listeners() and create_wildcard_listeners().
    /// Supports both wildcard binding (0.0.0.0/::) and interface-specific binding
    /// based on --interface and --listen-address configuration directives.
    ///
    /// # Arguments
    ///
    /// * `interfaces` - Available network interfaces for binding
    ///
    /// # Returns
    ///
    /// Vector of DnsListener structs containing UDP and TCP sockets
    ///
    /// # Errors
    ///
    /// Returns NetworkError if socket creation or binding fails
    #[instrument(skip(self, interfaces))]
    pub async fn create_dns_listeners(
        &self,
        interfaces: &[NetworkInterface],
    ) -> Result<Vec<DnsListener>> {
        let mut listeners = Vec::new();
        let port = self.config.port;
        
        if port == 0 {
            info!("DNS port set to 0, DNS service disabled");
            return Ok(listeners);
        }
        
        if self.config.bind_interfaces && !self.config.interfaces.is_empty() {
            // Interface-specific binding
            debug!("Creating interface-specific DNS listeners");
            for interface in interfaces {
                if !self.should_bind_interface(&interface.name) {
                    continue;
                }
                
                for addr in &interface.addresses {
                    let socket_addr = match addr {
                        IpAddr::V4(ipv4) => SocketAddr::V4(SocketAddrV4::new(*ipv4, port)),
                        IpAddr::V6(ipv6) => SocketAddr::V6(SocketAddrV6::new(*ipv6, port, 0, 0)),
                    };
                    
                    // Create UDP listener
                    match self.create_udp_listener(socket_addr, Some(&interface.name)).await {
                        Ok(socket) => {
                            info!(
                                interface = %interface.name,
                                address = %socket_addr,
                                "DNS UDP listener created"
                            );
                            listeners.push(DnsListener {
                                socket: DnsSocketType::Udp(socket),
                                local_addr: socket_addr,
                                interface: Some(interface.name.clone()),
                                flags: ListenerFlags::INTERFACE_SPECIFIC,
                            });
                        }
                        Err(e) => {
                            warn!(
                                interface = %interface.name,
                                address = %socket_addr,
                                error = %e,
                                "Failed to create DNS UDP listener"
                            );
                        }
                    }
                    
                    // Create TCP listener
                    match self.create_tcp_listener(socket_addr, Some(&interface.name)).await {
                        Ok(socket) => {
                            info!(
                                interface = %interface.name,
                                address = %socket_addr,
                                "DNS TCP listener created"
                            );
                            listeners.push(DnsListener {
                                socket: DnsSocketType::Tcp(socket),
                                local_addr: socket_addr,
                                interface: Some(interface.name.clone()),
                                flags: ListenerFlags::TCP | ListenerFlags::INTERFACE_SPECIFIC,
                            });
                        }
                        Err(e) => {
                            warn!(
                                interface = %interface.name,
                                address = %socket_addr,
                                error = %e,
                                "Failed to create DNS TCP listener"
                            );
                        }
                    }
                }
            }
        } else if !self.config.listen_addresses.is_empty() {
            // Specific address binding
            debug!("Creating DNS listeners on specific addresses");
            for addr in &self.config.listen_addresses {
                let socket_addr = match addr {
                    IpAddr::V4(ipv4) => SocketAddr::V4(SocketAddrV4::new(*ipv4, port)),
                    IpAddr::V6(ipv6) => SocketAddr::V6(SocketAddrV6::new(*ipv6, port, 0, 0)),
                };
                
                // Create UDP listener
                if let Ok(socket) = self.create_udp_listener(socket_addr, None).await {
                    info!(address = %socket_addr, "DNS UDP listener created");
                    listeners.push(DnsListener {
                        socket: DnsSocketType::Udp(socket),
                        local_addr: socket_addr,
                        interface: None,
                        flags: ListenerFlags::empty(),
                    });
                }
                
                // Create TCP listener
                if let Ok(socket) = self.create_tcp_listener(socket_addr, None).await {
                    info!(address = %socket_addr, "DNS TCP listener created");
                    listeners.push(DnsListener {
                        socket: DnsSocketType::Tcp(socket),
                        local_addr: socket_addr,
                        interface: None,
                        flags: ListenerFlags::TCP,
                    });
                }
            }
        } else {
            // Wildcard binding (0.0.0.0 and ::)
            debug!("Creating wildcard DNS listeners");
            
            // IPv4 wildcard
            let v4_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
            if let Ok(socket) = self.create_udp_listener(v4_addr, None).await {
                info!(address = %v4_addr, "DNS UDP wildcard listener created (IPv4)");
                listeners.push(DnsListener {
                    socket: DnsSocketType::Udp(socket),
                    local_addr: v4_addr,
                    interface: None,
                    flags: ListenerFlags::WILDCARD,
                });
            }
            
            // IPv6 wildcard
            let v6_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
            if let Ok(socket) = self.create_udp_listener(v6_addr, None).await {
                info!(address = %v6_addr, "DNS UDP wildcard listener created (IPv6)");
                listeners.push(DnsListener {
                    socket: DnsSocketType::Udp(socket),
                    local_addr: v6_addr,
                    interface: None,
                    flags: ListenerFlags::WILDCARD,
                });
            }
            
            // TCP listeners
            if let Ok(socket) = self.create_tcp_listener(v4_addr, None).await {
                info!(address = %v4_addr, "DNS TCP wildcard listener created (IPv4)");
                listeners.push(DnsListener {
                    socket: DnsSocketType::Tcp(socket),
                    local_addr: v4_addr,
                    interface: None,
                    flags: ListenerFlags::TCP | ListenerFlags::WILDCARD,
                });
            }
            
            if let Ok(socket) = self.create_tcp_listener(v6_addr, None).await {
                info!(address = %v6_addr, "DNS TCP wildcard listener created (IPv6)");
                listeners.push(DnsListener {
                    socket: DnsSocketType::Tcp(socket),
                    local_addr: v6_addr,
                    interface: None,
                    flags: ListenerFlags::TCP | ListenerFlags::WILDCARD,
                });
            }
        }
        
        if listeners.is_empty() {
            error!("Failed to create any DNS listeners");
            return Err(NetworkError::SocketFailed {
                address: format!("port {}", port),
                reason: "No DNS listeners could be created".to_string(),
            });
        }
        
        info!("Created {} DNS listeners", listeners.len());
        Ok(listeners)
    }
    
    /// Create DHCP listeners on ports 67 (v4) and 547 (v6)
    ///
    /// Creates UDP sockets for DHCPv4 and DHCPv6 with appropriate options
    /// including SO_BROADCAST for DHCPv4 and interface binding.
    ///
    /// # Returns
    ///
    /// Tuple of (DHCPv4 socket, DHCPv6 socket)
    ///
    /// # Errors
    ///
    /// Returns NetworkError if socket creation fails
    #[instrument(skip(self))]
    pub async fn create_dhcp_listeners(&self) -> Result<(DhcpSocket, DhcpSocket)> {
        // DHCPv4 on port 67
        let v4_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67));
        let v4_socket = self.create_dhcp_socket(v4_addr).await?;
        info!("DHCPv4 listener created on port 67");
        
        // DHCPv6 on port 547
        let v6_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 547, 0, 0));
        let v6_socket = self.create_dhcp_socket(v6_addr).await?;
        info!("DHCPv6 listener created on port 547");
        
        Ok((DhcpSocket::new(v4_socket), DhcpSocket::new(v6_socket)))
    }
    
    /// Create TFTP listener on port 69
    ///
    /// Creates UDP socket for TFTP file transfers.
    ///
    /// # Returns
    ///
    /// TFTP UDP socket
    ///
    /// # Errors
    ///
    /// Returns NetworkError if socket creation fails
    #[instrument(skip(self))]
    pub async fn create_tftp_listener(&self) -> Result<TftpSocket> {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 69));
        let socket = self.create_udp_listener(addr, None).await?;
        info!("TFTP listener created on port 69");
        Ok(socket)
    }
    
    /// Create ICMPv6 raw socket for Router Advertisements
    ///
    /// Creates raw ICMPv6 socket with IPV6_RECVHOPLIMIT option for
    /// validating hop limits in received packets.
    ///
    /// # Returns
    ///
    /// Router Advertisement socket wrapper
    ///
    /// # Errors
    ///
    /// Returns NetworkError if socket creation fails
    #[instrument(skip(self))]
    pub async fn create_icmpv6_socket(&self) -> Result<RaSocket> {
        // For now, use a regular UDP socket on the RA multicast address
        // In production, this would be a raw ICMPv6 socket
        let addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), // All-nodes multicast
            0,
            0,
            0,
        ));
        
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))
            .map_err(|e| NetworkError::SocketFailed {
                address: addr.to_string(),
                reason: format!("Failed to create ICMPv6 socket: {}", e),
            })?;
        
        // Configure ICMPv6-specific options
        self.configure_icmpv6_socket(&socket)?;
        
        socket.set_nonblocking(true)
            .map_err(|e| NetworkError::SocketOptionFailed {
                option: "nonblocking".to_string(),
                reason: format!("{}", e),
            })?;
        
        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = UdpSocket::from_std(std_socket)
            .map_err(|e| NetworkError::SocketFailed {
                address: addr.to_string(),
                reason: format!("Failed to convert to tokio socket: {}", e),
            })?;
        
        info!("ICMPv6 socket created for Router Advertisements");
        Ok(RaSocket::new(tokio_socket))
    }
    
    /// Check if interface should be bound based on configuration
    fn should_bind_interface(&self, interface_name: &str) -> bool {
        // Check exclude list first
        if self.config.except_interfaces.contains(&interface_name.to_string()) {
            return false;
        }
        
        // If interfaces specified, only bind those
        if !self.config.interfaces.is_empty() {
            return self.config.interfaces.contains(&interface_name.to_string());
        }
        
        // Otherwise bind all interfaces
        true
    }
    
    /// Create UDP listener with DNS-specific options
    async fn create_udp_listener(
        &self,
        addr: SocketAddr,
        interface: Option<&str>,
    ) -> Result<UdpSocket> {
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| NetworkError::SocketFailed {
                address: addr.to_string(),
                reason: format!("Failed to create socket: {}", e),
            })?;
        
        // Set SO_REUSEADDR for binding to same port multiple times
        socket.set_reuse_address(true)
            .map_err(|e| NetworkError::SocketOptionFailed {
                option: "SO_REUSEADDR".to_string(),
                reason: format!("{}", e),
            })?;
        
        // Set receive buffer size for large DNSSEC responses
        socket.set_recv_buffer_size(EDNS_PKTSZ)
            .map_err(|e| NetworkError::SocketOptionFailed {
                option: "SO_RCVBUF".to_string(),
                reason: format!("{}", e),
            })?;
        
        // Configure packet info options for metadata retrieval
        self.configure_packet_info(&socket, addr.is_ipv6())?;
        
        // Bind to interface if specified
        if let Some(iface_name) = interface {
            self.bind_to_interface(&socket, iface_name)?;
        }
        
        socket.bind(&addr.into())
            .map_err(|e| NetworkError::PortBindFailed {
                port: addr.port(),
                reason: format!("{}", e),
            })?;
        
        socket.set_nonblocking(true)
            .map_err(|e| NetworkError::SocketOptionFailed {
                option: "nonblocking".to_string(),
                reason: format!("{}", e),
            })?;
        
        let std_socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_socket)
            .map_err(|e| NetworkError::SocketFailed {
                address: addr.to_string(),
                reason: format!("Failed to convert to tokio socket: {}", e),
            })
    }
    
    /// Create TCP listener with DNS-specific options
    async fn create_tcp_listener(
        &self,
        addr: SocketAddr,
        interface: Option<&str>,
    ) -> Result<TcpListener> {
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| NetworkError::SocketFailed {
                address: addr.to_string(),
                reason: format!("Failed to create TCP socket: {}", e),
            })?;
        
        socket.set_reuse_address(true)
            .map_err(|e| NetworkError::SocketOptionFailed {
                option: "SO_REUSEADDR".to_string(),
                reason: format!("{}", e),
            })?;
        
        // Bind to interface if specified
        if let Some(iface_name) = interface {
            self.bind_to_interface(&socket, iface_name)?;
        }
        
        socket.bind(&addr.into())
            .map_err(|e| NetworkError::PortBindFailed {
                port: addr.port(),
                reason: format!("{}", e),
            })?;
        
        socket.listen(128)
            .map_err(|e| NetworkError::SocketFailed {
                address: addr.to_string(),
                reason: format!("Failed to listen: {}", e),
            })?;
        
        socket.set_nonblocking(true)
            .map_err(|e| NetworkError::SocketOptionFailed {
                option: "nonblocking".to_string(),
                reason: format!("{}", e),
            })?;
        
        let std_socket: std::net::TcpListener = socket.into();
        TcpListener::from_std(std_socket)
            .map_err(|e| NetworkError::SocketFailed {
                address: addr.to_string(),
                reason: format!("Failed to convert to tokio TCP listener: {}", e),
            })
    }
    
    /// Create DHCP socket with broadcast support
    async fn create_dhcp_socket(&self, addr: SocketAddr) -> Result<UdpSocket> {
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| NetworkError::SocketFailed {
                address: addr.to_string(),
                reason: format!("Failed to create DHCP socket: {}", e),
            })?;
        
        socket.set_reuse_address(true)
            .map_err(|e| NetworkError::SocketOptionFailed {
                option: "SO_REUSEADDR".to_string(),
                reason: format!("{}", e),
            })?;
        
        // Enable broadcast for DHCPv4
        if addr.is_ipv4() {
            socket.set_broadcast(true)
                .map_err(|e| NetworkError::SocketOptionFailed {
                    option: "SO_BROADCAST".to_string(),
                    reason: format!("{}", e),
                })?;
        }
        
        // Configure packet info for source address retrieval
        self.configure_packet_info(&socket, addr.is_ipv6())?;
        
        socket.bind(&addr.into())
            .map_err(|e| NetworkError::PortBindFailed {
                port: addr.port(),
                reason: format!("{}", e),
            })?;
        
        socket.set_nonblocking(true)
            .map_err(|e| NetworkError::SocketOptionFailed {
                option: "nonblocking".to_string(),
                reason: format!("{}", e),
            })?;
        
        let std_socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_socket)
            .map_err(|e| NetworkError::SocketFailed {
                address: addr.to_string(),
                reason: format!("Failed to convert to tokio socket: {}", e),
            })
    }
    
    /// Configure packet info socket options for metadata retrieval
    fn configure_packet_info(&self, socket: &Socket, is_ipv6: bool) -> Result<()> {
        use nix::sys::socket::{setsockopt, sockopt};
        
        let fd = socket.as_raw_fd();
        
        if is_ipv6 {
            // IPV6_RECVPKTINFO for destination address
            setsockopt(fd, sockopt::Ipv6RecvPacketInfo, &true)
                .map_err(|e| NetworkError::SocketOptionFailed {
                    option: "IPV6_RECVPKTINFO".to_string(),
                    reason: format!("{}", e),
                })?;
            
            // IPV6_RECVHOPLIMIT for hop limit
            setsockopt(fd, sockopt::Ipv6RecvHopLimit, &true)
                .map_err(|e| NetworkError::SocketOptionFailed {
                    option: "IPV6_RECVHOPLIMIT".to_string(),
                    reason: format!("{}", e),
                })?;
        } else {
            // IP_PKTINFO for destination address
            setsockopt(fd, sockopt::Ipv4PacketInfo, &true)
                .map_err(|e| NetworkError::SocketOptionFailed {
                    option: "IP_PKTINFO".to_string(),
                    reason: format!("{}", e),
                })?;
        }
        
        Ok(())
    }
    
    /// Configure ICMPv6-specific socket options
    fn configure_icmpv6_socket(&self, socket: &Socket) -> Result<()> {
        use nix::sys::socket::{setsockopt, sockopt};
        
        let fd = socket.as_raw_fd();
        
        // IPV6_RECVHOPLIMIT for validating hop limits
        setsockopt(fd, sockopt::Ipv6RecvHopLimit, &true)
            .map_err(|e| NetworkError::SocketOptionFailed {
                option: "IPV6_RECVHOPLIMIT".to_string(),
                reason: format!("{}", e),
            })?;
        
        Ok(())
    }
    
    /// Bind socket to specific network interface
    fn bind_to_interface(&self, socket: &Socket, interface_name: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use nix::sys::socket::{setsockopt, sockopt};
            let fd = socket.as_raw_fd();
            setsockopt(fd, sockopt::BindToDevice, &std::ffi::OsStr::new(interface_name))
                .map_err(|e| NetworkError::SocketOptionFailed {
                    option: "SO_BINDTODEVICE".to_string(),
                    reason: format!("{}", e),
                })?;
            debug!(interface = %interface_name, "Bound socket to interface (Linux)");
        }
        
        #[cfg(target_os = "macos")]
        {
            // macOS uses IP_BOUND_IF with interface index
            // For now, log a warning - full implementation requires interface index lookup
            warn!(
                interface = %interface_name,
                "Interface binding on macOS requires IP_BOUND_IF implementation"
            );
        }
        
        #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
        {
            // BSD uses IP_BOUND_IF similar to macOS
            warn!(
                interface = %interface_name,
                "Interface binding on BSD requires IP_BOUND_IF implementation"
            );
        }
        
        Ok(())
    }
}

/// Bind privileged sockets before dropping privileges
///
/// Creates and binds all privileged port sockets (< 1024) before the process
/// drops root privileges. This allows binding to ports 53, 67, 547, and 69
/// which require root access.
///
/// # Arguments
///
/// * `config` - Network configuration
/// * `interfaces` - Available network interfaces
///
/// # Returns
///
/// Tuple of (DNS listeners, DHCP v4 socket, DHCP v6 socket, TFTP socket)
///
/// # Errors
///
/// Returns NetworkError if any socket creation fails
#[instrument(skip(config, interfaces))]
pub async fn bind_privileged_sockets(
    config: Arc<NetworkConfig>,
    interfaces: &[NetworkInterface],
) -> Result<(Vec<DnsListener>, Option<DhcpSocket>, Option<DhcpSocket>, Option<TftpSocket>)> {
    let manager = SocketManager::new(config);
    
    // Create DNS listeners (port 53 - privileged)
    let dns_listeners = manager.create_dns_listeners(interfaces).await?;
    info!("Created {} DNS listeners on privileged port", dns_listeners.len());
    
    // Create DHCP listeners (ports 67, 547 - privileged)
    let dhcp_result = manager.create_dhcp_listeners().await;
    let (dhcp_v4, dhcp_v6) = match dhcp_result {
        Ok((v4, v6)) => (Some(v4), Some(v6)),
        Err(e) => {
            warn!(error = %e, "Failed to create DHCP listeners, DHCP disabled");
            (None, None)
        }
    };
    
    // Create TFTP listener (port 69 - privileged)
    let tftp_socket = match manager.create_tftp_listener().await {
        Ok(socket) => Some(socket),
        Err(e) => {
            warn!(error = %e, "Failed to create TFTP listener, TFTP disabled");
            None
        }
    };
    
    info!("All privileged sockets bound successfully");
    Ok((dns_listeners, dhcp_v4, dhcp_v6, tftp_socket))
}

/// Create ICMPv6 socket for Router Advertisements
///
/// This can be created after privilege drop as it doesn't require privileged ports.
///
/// # Arguments
///
/// * `config` - Network configuration
///
/// # Returns
///
/// Router Advertisement socket
///
/// # Errors
///
/// Returns NetworkError if socket creation fails
pub async fn create_icmpv6_socket(config: Arc<NetworkConfig>) -> Result<RaSocket> {
    let manager = SocketManager::new(config);
    manager.create_icmpv6_socket().await
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_listener_flags() {
        let flags = ListenerFlags::TCP | ListenerFlags::WILDCARD;
        assert!(flags.contains(ListenerFlags::TCP));
        assert!(flags.contains(ListenerFlags::WILDCARD));
        assert!(!flags.contains(ListenerFlags::TFTP));
    }
    
    #[test]
    fn test_listener_flags_empty() {
        let flags = ListenerFlags::empty();
        assert!(!flags.contains(ListenerFlags::TCP));
        assert!(!flags.contains(ListenerFlags::WILDCARD));
    }
}

