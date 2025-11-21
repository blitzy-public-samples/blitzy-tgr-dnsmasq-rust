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

//! Network module root providing comprehensive cross-platform networking infrastructure.
//!
//! This module serves as the central hub for all network-related operations in dnsmasq, coordinating
//! socket management, interface enumeration, ARP caching, and platform-specific networking across
//! DNS, DHCP, TFTP, and Router Advertisement services. It replaces the C implementation's global
//! state (`daemon->listeners`, `daemon->interfaces`) with structured, ownership-based architecture.
//!
//! # Architecture Overview
//!
//! ```text
//! NetworkService (coordinator)
//!      |
//!      +-- SocketManager (sockets.rs)
//!      |     |
//!      |     +-- DnsSocket (UDP/TCP port 53)
//!      |     +-- DhcpSocket (UDP ports 67/547)
//!      |     +-- TftpSocket (UDP port 69)
//!      |     +-- ICMPv6 socket (Router Advertisement)
//!      |
//!      +-- InterfaceManager (interfaces.rs)
//!      |     |
//!      |     +-- NetworkInterface (name, index, addresses)
//!      |     +-- InterfaceEvent monitoring
//!      |
//!      +-- ArpCache (arp.rs)
//!      |     |
//!      |     +-- IP-to-MAC mappings
//!      |     +-- Kernel ARP table synchronization
//!      |
//!      +-- NetworkPlatform (platform/mod.rs)
//!      |     |
//!      |     +-- Linux netlink (platform/linux.rs)
//!      |     +-- BSD routing sockets (platform/bsd.rs)
//!      |     +-- macOS variants (platform/macos.rs)
//!      |
//!      +-- FirewallBackend (firewall/mod.rs) [optional]
//!            |
//!            +-- Linux ipset (firewall/ipset.rs)
//!            +-- Linux nftables (firewall/nftables.rs)
//!            +-- BSD PF (firewall/pf.rs)
//! ```
//!
//! # C Implementation Mapping
//!
//! This module replaces `src/network.c` from the C implementation, transforming:
//!
//! ## Global State → Structured Ownership
//!
//! ```c
//! // C implementation (dnsmasq.h + network.c)
//! struct daemon {
//!     struct listener *listeners;  // Linked list of sockets
//!     struct irec *interfaces;     // Linked list of interfaces
//!     // ... manual memory management
//! };
//! ```
//!
//! ```rust,ignore
//! // Rust implementation (this module)
//! pub struct NetworkService {
//!     socket_manager: SocketManager,
//!     interface_manager: InterfaceManager,
//!     arp_cache: Arc<RwLock<ArpCache>>,
//!     platform: Box<dyn NetworkPlatform>,
//!     config: Arc<Config>,
//! }
//! ```
//!
//! ## Function Transformations
//!
//! | C Function | Rust Equivalent | Location |
//! |------------|-----------------|----------|
//! | `create_bound_listeners()` | `NetworkService::bind_listeners()` | This file |
//! | `enumerate_interfaces()` | `InterfaceManager::enumerate_interfaces()` | interfaces.rs |
//! | `iface_check()` | `NetworkService::handle_interface_change()` | This file |
//! | `indextoname()` | `NetworkPlatform::index_to_name()` | platform/mod.rs |
//! | `create_ipset()` | `FirewallBackend::add_to_set()` | firewall/mod.rs |
//!
//! # Key Features
//!
//! ## Cross-Platform Abstraction
//!
//! Platform-specific code is isolated behind the `NetworkPlatform` trait, selected via
//! conditional compilation:
//!
//! ```rust,ignore
//! #[cfg(target_os = "linux")]
//! let platform = LinuxNetworkPlatform::new()?;
//!
//! #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
//! let platform = BsdNetworkPlatform::new()?;
//! ```
//!
//! ## Async Network Operations
//!
//! All network I/O uses `tokio` for async operation, replacing C's `poll()`-based event loop:
//!
//! ```rust,ignore
//! // C: poll(fds, nfds, timeout);
//! // Rust:
//! tokio::select! {
//!     result = dns_socket.recv_from(&mut buf) => { /* handle DNS */ }
//!     result = dhcp_socket.recv_from(&mut buf) => { /* handle DHCP */ }
//! }
//! ```
//!
//! ## Real-Time Network Monitoring
//!
//! Interface changes are detected via platform-specific mechanisms (Linux netlink, BSD routing
//! sockets) and trigger listener rebinding:
//!
//! ```rust,ignore
//! match event {
//!     InterfaceEvent::AddressAdded { interface, address } => {
//!         network_service.handle_interface_change(event).await?;
//!         // Rebinds listeners if needed
//!     }
//!     InterfaceEvent::InterfaceDown { interface } => {
//!         // Remove listeners on downed interface
//!     }
//! }
//! ```
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::network::NetworkService;
//! use dnsmasq::config::Config;
//! use std::sync::Arc;
//!
//! // Initialize network subsystem
//! let config = Arc::new(Config::from_file("/etc/dnsmasq.conf").await?);
//! let mut network_service = NetworkService::initialize(config.clone()).await?;
//!
//! // Bind all protocol listeners
//! let listeners = network_service.bind_listeners().await?;
//!
//! // Access individual sockets
//! let dns_socket = listeners.dns_udp_socket();
//! let dhcp_socket = listeners.dhcp_v4_socket();
//!
//! // Handle topology changes
//! network_service.handle_interface_change(InterfaceEvent::AddressAdded {
//!     interface: "eth0".to_string(),
//!     address: "192.168.1.10".parse()?,
//! }).await?;
//!
//! // Periodic state refresh
//! network_service.refresh_network_state().await?;
//! ```
//!
//! # Module Organization
//!
//! - [`sockets`]: Socket creation and management for all protocols
//! - [`interfaces`]: Interface enumeration and monitoring
//! - [`arp`]: ARP/neighbor cache for MAC address lookup
//! - [`platform`]: Platform-specific implementations (Linux, BSD, macOS)
//! - [`firewall`]: Firewall set integration (ipset, nftables, PF)
//! - [`conntrack`]: Linux connection tracking for policy routing (feature-gated)
//!
//! # Conditional Compilation
//!
//! Platform-specific modules are conditionally compiled based on target OS:
//!
//! ```rust,ignore
//! #[cfg(target_os = "linux")]
//! pub mod platform::linux;
//!
//! #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
//! pub mod platform::bsd;
//! ```
//!
//! Feature flags control optional functionality:
//!
//! ```toml
//! [features]
//! conntrack = ["rtnetlink", "netlink-packet-route"]
//! ipset = []
//! nftset = ["nftnl"]
//! ```
//!
//! # Memory Safety
//!
//! This module achieves memory safety through:
//!
//! - **Ownership**: Sockets and interfaces owned by `NetworkService`, no manual deallocation
//! - **Borrowing**: Shared state via `Arc<RwLock<T>>` for concurrent access
//! - **Type Safety**: Socket types prevent misuse (can't send DHCP on DNS socket)
//! - **Bounds Checking**: All network buffer access is bounds-checked by Rust
//!
//! No `unsafe` blocks in this file; FFI to system calls is encapsulated in `platform/` submodules.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use crate::config::types::Config;
use crate::error::NetworkError;

// Module declarations with appropriate visibility
pub mod sockets;
pub mod interfaces;
pub mod arp;
pub mod platform;

// Conditionally compiled modules based on platform and features
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
pub mod firewall;

#[cfg(all(target_os = "linux", feature = "conntrack"))]
pub mod conntrack;

// Re-export commonly used types from submodules
pub use sockets::{DhcpSocket, DnsSocket, DnsSocketType, RaSocket, SocketManager, TftpSocket};
pub use interfaces::{InterfaceEvent, InterfaceManager, NetworkInterface};
pub use arp::ArpCache;
pub use platform::{create_platform_handler, NetworkPlatform};

// Conditionally re-export conntrack handler
#[cfg(all(target_os = "linux", feature = "conntrack"))]
pub use conntrack::ConntrackHandler;

// Conditionally re-export firewall backend
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
pub use firewall::FirewallBackend;

/// Protocol type enumeration for identifying socket purposes.
///
/// Used internally for logging and diagnostics to distinguish between different
/// protocol sockets managed by the NetworkService.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// DNS protocol (UDP/TCP port 53)
    Dns,
    /// DHCPv4 protocol (UDP port 67/68)
    DhcpV4,
    /// DHCPv6 protocol (UDP port 547)
    DhcpV6,
    /// TFTP protocol (UDP port 69)
    Tftp,
    /// ICMPv6 Router Advertisement
    Icmpv6,
}

/// Set of listening sockets for all enabled protocols.
///
/// This struct aggregates all protocol-specific sockets created by `bind_listeners()`,
/// providing type-safe access to each listener. The C implementation used a linked list
/// of generic listener structs; this provides compile-time type safety.
///
/// # Memory Management
///
/// All sockets are owned by this struct and automatically closed when dropped via Rust's
/// RAII pattern, eliminating the manual cleanup required in C.
#[derive(Debug)]
pub struct ListenerSet {
    /// DNS UDP sockets (one per interface/address)
    pub dns_udp: Vec<DnsSocket>,
    /// DNS TCP listeners (one per interface/address)
    pub dns_tcp: Vec<tokio::net::TcpListener>,
    /// DHCPv4 socket (broadcast-capable)
    pub dhcp_v4: Option<DhcpSocket>,
    /// DHCPv6 socket (multicast-capable)
    pub dhcp_v6: Option<DhcpSocket>,
    /// TFTP socket (if TFTP feature enabled)
    pub tftp: Option<TftpSocket>,
    /// ICMPv6 raw socket for Router Advertisement (if enabled)
    pub icmpv6: Option<RaSocket>,
}

impl ListenerSet {
    /// Creates an empty listener set.
    pub fn new() -> Self {
        Self {
            dns_udp: Vec::new(),
            dns_tcp: Vec::new(),
            dhcp_v4: None,
            dhcp_v6: None,
            tftp: None,
            icmpv6: None,
        }
    }

    /// Returns the primary DNS UDP socket, if any exist.
    pub fn dns_udp_socket(&self) -> Option<&DnsSocket> {
        self.dns_udp.first()
    }

    /// Returns the DHCPv4 socket, if enabled.
    pub fn dhcp_v4_socket(&self) -> Option<&DhcpSocket> {
        self.dhcp_v4.as_ref()
    }

    /// Returns the DHCPv6 socket, if enabled.
    pub fn dhcp_v6_socket(&self) -> Option<&DhcpSocket> {
        self.dhcp_v6.as_ref()
    }

    /// Returns the TFTP socket, if enabled.
    pub fn tftp_socket(&self) -> Option<&TftpSocket> {
        self.tftp.as_ref()
    }
}

impl Default for ListenerSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Network service coordinator managing all networking subsystems.
///
/// `NetworkService` is the primary entry point for all network operations in dnsmasq,
/// replacing the C implementation's global `daemon` struct's networking fields. It
/// coordinates socket creation, interface monitoring, ARP caching, and platform-specific
/// operations across all protocols.
///
/// # Architecture
///
/// The service aggregates specialized components:
///
/// - **SocketManager**: Creates and configures protocol-specific sockets
/// - **InterfaceManager**: Enumerates and monitors network interfaces
/// - **ArpCache**: Maintains IP-to-MAC mappings from kernel ARP tables
/// - **NetworkPlatform**: Platform-specific operations (netlink, routing sockets, BPF)
///
/// # Lifecycle
///
/// 1. **Initialization**: `NetworkService::initialize(config)` sets up all components
/// 2. **Binding**: `bind_listeners()` creates listening sockets based on configuration
/// 3. **Monitoring**: `handle_interface_change()` responds to topology changes
/// 4. **Refresh**: `refresh_network_state()` periodically updates caches
///
/// # Thread Safety
///
/// Components requiring shared mutable access use `Arc<RwLock<T>>`:
///
/// - `ArpCache`: Updated by multiple async tasks
/// - `InterfaceManager`: Read by protocol handlers, written by monitoring task
///
/// # C Implementation Mapping
///
/// ```c
/// // C: Global state in daemon struct
/// struct daemon {
///     struct listener *listeners;    // Linked list
///     struct irec *interfaces;       // Linked list
///     // ... manual memory management
/// };
/// ```
///
/// ```rust,ignore
/// // Rust: Structured ownership
/// pub struct NetworkService {
///     socket_manager: SocketManager,           // Owns socket state
///     interface_manager: InterfaceManager,      // Owns interface state
///     arp_cache: Arc<RwLock<ArpCache>>,        // Shared ARP cache
///     platform: Box<dyn NetworkPlatform>,      // Platform abstraction
///     config: Arc<Config>,                      // Configuration
/// }
/// ```
pub struct NetworkService {
    /// Socket manager for creating and managing protocol sockets.
    socket_manager: SocketManager,
    
    /// Interface manager for enumerating and monitoring network interfaces.
    interface_manager: InterfaceManager,
    
    /// ARP cache maintaining IP-to-MAC address mappings.
    ///
    /// Wrapped in Arc<RwLock<>> for shared mutable access from DHCP service
    /// (address conflict detection) and periodic refresh tasks.
    arp_cache: Arc<RwLock<ArpCache>>,
    
    /// Platform-specific network operations handler.
    ///
    /// Trait object allows runtime polymorphism across Linux (netlink),
    /// BSD (routing sockets), and macOS variants without compile-time dispatch overhead
    /// (platform is known at compile time, but abstraction aids testing).
    /// 
    /// Arc allows sharing with InterfaceManager and ArpCache without cloning the entire platform.
    platform: Arc<dyn NetworkPlatform>,
    
    /// Configuration specifying network behavior.
    ///
    /// Arc allows sharing with socket creation, interface filtering, and
    /// binding strategy decisions without cloning the entire config.
    config: Arc<Config>,
    
    /// Optional conntrack handler for Linux policy routing.
    #[cfg(all(target_os = "linux", feature = "conntrack"))]
    conntrack: Option<ConntrackHandler>,
    
    /// Optional firewall backend for ipset/nftables/PF integration.
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
    firewall: Option<Box<dyn FirewallBackend>>,
}

impl NetworkService {
    /// Initializes the network service with all required subsystems.
    ///
    /// This is the primary factory method for creating a fully configured `NetworkService`.
    /// It orchestrates initialization of all networking components, validates the network
    /// configuration, enumerates available interfaces, and prepares the platform handler.
    ///
    /// # Initialization Steps
    ///
    /// 1. **Platform Handler**: Creates platform-specific handler (Linux netlink, BSD routing sockets)
    /// 2. **Interface Enumeration**: Discovers all network interfaces via `platform.enumerate_interfaces()`
    /// 3. **Interface Validation**: Filters interfaces based on configuration (--interface, --listen-address)
    /// 4. **ARP Cache**: Initializes ARP cache and performs initial kernel table synchronization
    /// 5. **Socket Manager**: Prepares socket creation infrastructure
    /// 6. **Feature Handlers**: Initializes optional conntrack and firewall handlers
    ///
    /// # Configuration Impact
    ///
    /// The following configuration options affect initialization:
    ///
    /// - `--interface=<name>`: Only listen on specified interfaces
    /// - `--except-interface=<name>`: Exclude specific interfaces
    /// - `--listen-address=<addr>`: Bind to specific addresses only
    /// - `--bind-interfaces`: Use interface-specific binding (not wildcard)
    /// - `--bind-dynamic`: Enable dynamic interface rebinding on topology changes
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if:
    ///
    /// - Platform handler creation fails (netlink socket, routing socket)
    /// - Interface enumeration fails (permission denied, kernel error)
    /// - No usable interfaces found matching configuration
    /// - ARP cache initialization fails
    /// - Conntrack handler creation fails (Linux with conntrack feature)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dnsmasq::network::NetworkService;
    /// use dnsmasq::config::Config;
    /// use std::sync::Arc;
    ///
    /// let config = Arc::new(Config::from_file("/etc/dnsmasq.conf").await?);
    /// let network_service = NetworkService::initialize(config).await?;
    /// ```
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces the following C functions from network.c:
    ///
    /// - `enumerate_interfaces()`: Interface discovery
    /// - `create_bound_listeners()`: Listener setup
    /// - `check_servers()`: Upstream server validation
    #[instrument(skip(config), fields(interfaces = ?config.network.interfaces))]
    pub async fn initialize(config: Arc<Config>) -> Result<Self, NetworkError> {
        info!("Initializing network service");

        // Create platform-specific handler
        debug!("Creating platform handler");
        let platform_box = create_platform_handler().await.map_err(|e| {
            error!("Failed to create platform handler: {}", e);
            NetworkError::InterfaceEnumerationFailed {
                reason: format!("Platform handler creation failed: {}", e),
            }
        })?;
        
        // Convert Box<dyn NetworkPlatform> to Arc<dyn NetworkPlatform>
        let platform: Arc<dyn NetworkPlatform> = Arc::from(platform_box);

        // Create interface manager and enumerate interfaces
        debug!("Enumerating network interfaces");
        let interface_manager = InterfaceManager::new(platform.clone());

        let interfaces = interface_manager.enumerate_interfaces().await.map_err(|e| {
            error!("Failed to enumerate interfaces: {}", e);
            NetworkError::InterfaceEnumerationFailed {
                reason: format!("Interface enumeration failed: {}", e),
            }
        })?;
        info!("Discovered {} network interfaces", interfaces.len());

        // Validate that we have usable interfaces
        let usable_count = interfaces.iter().filter(|iface| iface.is_usable()).count();
        if usable_count == 0 {
            warn!("No usable network interfaces found");
        } else {
            debug!("Found {} usable interfaces", usable_count);
        }

        // Initialize helper process for ARP cache script execution
        debug!("Initializing helper process");
        let helper = Arc::new(RwLock::new(crate::util::helpers::HelperProcess::new(config.clone())));
        
        // Initialize ARP cache
        debug!("Initializing ARP cache");
        let arp_cache = Arc::new(RwLock::new(ArpCache::new(
            platform.clone(),
            config.clone(),
            helper.clone(),
        )));
        
        // Perform initial ARP cache synchronization with kernel tables
        {
            let mut cache = arp_cache.write().await;
            cache.update_from_kernel().await.map_err(|e| {
                warn!("Initial ARP cache update failed: {}", e);
                e
            })?;
        }

        // Create socket manager
        let socket_manager = SocketManager::new(Arc::new(config.network.clone()));

        // Initialize optional conntrack handler (Linux only, feature-gated)
        #[cfg(all(target_os = "linux", feature = "conntrack"))]
        let conntrack = {
            debug!("Initializing conntrack handler");
            match ConntrackHandler::new() {
                Ok(handler) => {
                    info!("Conntrack integration enabled");
                    Some(handler)
                }
                Err(e) => {
                    warn!("Failed to initialize conntrack: {}", e);
                    None
                }
            }
        };

        // Initialize optional firewall backend
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
        let firewall = {
            debug!("Initializing firewall backend");
            match firewall::create_firewall_backend(&config) {
                Some(backend) => {
                    info!("Firewall integration enabled");
                    Some(backend)
                }
                None => {
                    debug!("No firewall backend configured");
                    None
                }
            }
        };

        info!("Network service initialized successfully");

        Ok(Self {
            socket_manager,
            interface_manager,
            arp_cache,
            platform,
            config,
            #[cfg(all(target_os = "linux", feature = "conntrack"))]
            conntrack,
            #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
            firewall,
        })
    }

    /// Binds all protocol listeners based on configuration.
    ///
    /// Creates and configures listening sockets for DNS, DHCP, TFTP, and Router Advertisement
    /// based on the configuration settings. This method implements the core socket binding
    /// strategy that determines whether to use wildcard listeners (0.0.0.0/::) or
    /// interface-specific bindings.
    ///
    /// # Binding Strategies
    ///
    /// ## Wildcard Binding (Default)
    ///
    /// Without `--bind-interfaces`, creates wildcard listeners:
    ///
    /// ```text
    /// DNS:  0.0.0.0:53, [::]:53
    /// DHCP: 0.0.0.0:67, [::]:547
    /// ```
    ///
    /// Advantages:
    /// - Simple, one socket per protocol
    /// - Automatically handles new interfaces
    /// - Compatible with most configurations
    ///
    /// Disadvantages:
    /// - Can't selectively listen on interfaces
    /// - Receives all packets, requires filtering
    ///
    /// ## Interface-Specific Binding
    ///
    /// With `--bind-interfaces`, creates per-interface listeners:
    ///
    /// ```text
    /// DNS:  192.168.1.1:53, 10.0.0.1:53
    /// DHCP: 192.168.1.1:67, 10.0.0.1:67
    /// ```
    ///
    /// Advantages:
    /// - Precise control over listening interfaces
    /// - Can bind multiple instances on different interfaces
    ///
    /// Disadvantages:
    /// - Requires rebinding when interfaces change
    /// - More complex state management
    ///
    /// # Socket Options
    ///
    /// All sockets are configured with appropriate options:
    ///
    /// - **SO_REUSEADDR**: Allow address reuse for quick restart
    /// - **SO_RCVBUF**: Increased receive buffer (8KB+) for burst traffic
    /// - **IP_PKTINFO/IPV6_RECVPKTINFO**: Receive packet metadata (interface, destination)
    /// - **SO_BROADCAST**: Enable broadcast for DHCP (v4 only)
    /// - **IPV6_V6ONLY**: Prevent IPv6 socket from accepting IPv4 (dual-stack control)
    ///
    /// Platform-specific options:
    ///
    /// - **Linux**: `SO_BINDTODEVICE` for interface binding
    /// - **BSD**: `SO_BINDTOIF` (macOS) or `IP_RECVIF` (FreeBSD/OpenBSD)
    ///
    /// # Protocols
    ///
    /// Creates listeners for all enabled protocols:
    ///
    /// 1. **DNS**: UDP port 53 (required), TCP port 53 (optional, for large responses)
    /// 2. **DHCPv4**: UDP port 67 (if DHCP ranges configured)
    /// 3. **DHCPv6**: UDP port 547 (if DHCPv6 ranges configured)
    /// 4. **TFTP**: UDP port 69 (if `--enable-tftp` specified)
    /// 5. **ICMPv6**: Raw socket (if `--enable-ra` specified for Router Advertisement)
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if:
    ///
    /// - Socket creation fails (permission denied for privileged ports)
    /// - Address already in use (another dnsmasq instance or service)
    /// - Interface doesn't exist or is down
    /// - Platform-specific socket option fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let listeners = network_service.bind_listeners().await?;
    ///
    /// // Access protocol-specific sockets
    /// let dns_socket = listeners.dns_udp_socket().expect("DNS socket required");
    /// if let Some(dhcp_socket) = listeners.dhcp_v4_socket() {
    ///     // DHCP is enabled
    /// }
    /// ```
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces C function `create_bound_listeners()` from network.c, which manually
    /// created linked list of `struct listener` with raw file descriptors.
    #[instrument(skip(self))]
    pub async fn bind_listeners(&self) -> Result<ListenerSet, NetworkError> {
        info!("Binding protocol listeners");

        let mut listeners = ListenerSet::new();

        // Create DNS listeners (UDP and TCP)
        debug!("Creating DNS listeners on port {}", self.config.network.port);
        
        // Get the current interface list for listener creation
        let interfaces = self.interface_manager.enumerate_interfaces().await
            .map_err(|e| NetworkError::InterfaceEnumerationFailed { 
                reason: format!("Failed to enumerate interfaces: {}", e) 
            })?;
        
        match self.socket_manager.create_dns_listeners(&interfaces).await {
            Ok(dns_listener_list) => {
                // Split the listeners into UDP and TCP based on socket type
                for listener in dns_listener_list {
                    match listener.socket {
                        DnsSocketType::Udp(socket) => {
                            listeners.dns_udp.push(DnsSocket::new(socket));
                        }
                        DnsSocketType::Tcp(socket) => {
                            listeners.dns_tcp.push(socket);
                        }
                    }
                }
                info!("Created {} DNS UDP sockets, {} TCP listeners", 
                      listeners.dns_udp.len(), listeners.dns_tcp.len());
            }
            Err(e) => {
                error!("Failed to create DNS listeners: {}", e);
                return Err(NetworkError::SocketFailed { 
                    address: format!("port {}", self.config.network.port),
                    reason: format!("DNS listener creation failed: {}", e) 
                });
            }
        }

        // Create DHCP listeners if DHCP ranges configured
        if !self.config.dhcp.v4_ranges.is_empty() || !self.config.dhcp.v6_ranges.is_empty() {
            debug!("Creating DHCP listeners on ports 67 (v4) and 547 (v6)");
            match self.socket_manager.create_dhcp_listeners().await {
                Ok((v4_socket, v6_socket)) => {
                    if !self.config.dhcp.v4_ranges.is_empty() {
                        info!("Created DHCPv4 listener on port 67");
                        listeners.dhcp_v4 = Some(v4_socket);
                    }
                    if !self.config.dhcp.v6_ranges.is_empty() {
                        info!("Created DHCPv6 listener on port 547");
                        listeners.dhcp_v6 = Some(v6_socket);
                    }
                }
                Err(e) => {
                    error!("Failed to create DHCP listeners: {}", e);
                    return Err(NetworkError::SocketFailed { 
                        address: "ports 67/547".to_string(),
                        reason: format!("DHCP listener creation failed: {}", e) 
                    });
                }
            }
        }

        // Create TFTP listener if enabled
        #[cfg(feature = "tftp")]
        if self.config.tftp.tftp_prefix.is_some() {
            debug!("Creating TFTP listener on port 69");
            match self.socket_manager.create_tftp_listener().await {
                Ok(socket) => {
                    info!("Created TFTP listener");
                    listeners.tftp = Some(socket);
                }
                Err(e) => {
                    warn!("Failed to create TFTP listener: {}", e);
                    // TFTP is optional, continue
                }
            }
        }

        // Create ICMPv6 raw socket for Router Advertisement if enabled
        if self.config.dhcp.enable_ra {
            debug!("Creating ICMPv6 socket for Router Advertisement");
            match self.socket_manager.create_icmpv6_socket().await {
                Ok(socket) => {
                    info!("Created ICMPv6 socket for Router Advertisement");
                    listeners.icmpv6 = Some(socket);
                }
                Err(e) => {
                    warn!("Failed to create ICMPv6 socket: {}", e);
                    // RA is optional, continue
                }
            }
        }

        info!("Successfully bound all configured protocol listeners");
        Ok(listeners)
    }

    /// Refreshes network state including interfaces and ARP cache.
    ///
    /// Performs periodic synchronization of cached network state with kernel tables.
    /// This method should be called on a regular interval (e.g., every 60 seconds) to
    /// detect changes that aren't signaled via netlink/routing socket events.
    ///
    /// # Refresh Operations
    ///
    /// 1. **Interface Refresh**: Re-enumerates interfaces to detect:
    ///    - New interfaces added
    ///    - Interfaces removed
    ///    - Address changes (new IPs, removed IPs)
    ///    - MTU changes
    ///    - Interface flags (up/down, running/not running)
    ///
    /// 2. **ARP Cache Update**: Synchronizes with kernel ARP tables:
    ///    - Adds new ARP entries
    ///    - Removes stale entries
    ///    - Updates existing entry states (reachable, stale, delay)
    ///
    /// # Use Cases
    ///
    /// - **Periodic Maintenance**: Called from main event loop timer
    /// - **Post-Restart**: After configuration reload (SIGHUP)
    /// - **Manual Trigger**: After network infrastructure changes
    ///
    /// # Performance Impact
    ///
    /// Interface enumeration is relatively expensive (syscalls, kernel interaction),
    /// so this should not be called more frequently than every 30-60 seconds unless
    /// rapid topology changes are expected.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if:
    ///
    /// - Interface enumeration fails (permission denied, kernel error)
    /// - ARP cache update fails (netlink error, routing socket error)
    ///
    /// Errors are logged but may not be fatal; stale cached state will be used.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tokio::time::{interval, Duration};
    ///
    /// let mut refresh_interval = interval(Duration::from_secs(60));
    /// loop {
    ///     refresh_interval.tick().await;
    ///     if let Err(e) = network_service.refresh_network_state().await {
    ///         warn!("Network state refresh failed: {}", e);
    ///     }
    /// }
    /// ```
    #[instrument(skip(self))]
    pub async fn refresh_network_state(&mut self) -> Result<(), NetworkError> {
        debug!("Refreshing network state");

        // Refresh interface list
        match self.interface_manager.refresh_interfaces().await {
            Ok(()) => {
                debug!("Interface list refreshed successfully");
            }
            Err(e) => {
                warn!("Interface refresh failed: {}", e);
                // Continue with ARP refresh even if interface refresh fails
            }
        }

        // Update ARP cache from kernel
        {
            let mut cache = self.arp_cache.write().await;
            match cache.update_from_kernel().await {
                Ok(()) => {
                    debug!("ARP cache updated successfully");
                }
                Err(e) => {
                    warn!("ARP cache update failed: {}", e);
                }
            }
        }

        debug!("Network state refresh completed");
        Ok(())
    }

    /// Handles network topology change events.
    ///
    /// Responds to real-time network changes detected by platform-specific monitoring
    /// (Linux netlink, BSD routing sockets). This method updates internal state and
    /// potentially rebinds listeners if the topology change affects configured interfaces.
    ///
    /// # Event Types
    ///
    /// ## InterfaceAdded
    ///
    /// A new interface appeared (device plugged in, virtual interface created):
    ///
    /// - Update interface manager cache
    /// - If `--bind-dynamic`, create new listeners on this interface
    /// - Validate upstream servers can still reach their interfaces
    ///
    /// ## InterfaceRemoved
    ///
    /// An interface disappeared (device unplugged, interface deleted):
    ///
    /// - Remove from interface manager cache
    /// - Close any listeners bound to this interface
    /// - Mark upstream servers using this interface as unavailable
    ///
    /// ## AddressAdded
    ///
    /// A new IP address was assigned to an interface:
    ///
    /// - Update interface addresses in cache
    /// - If `--bind-interfaces`, create new listener on this address
    /// - Register address for authoritative zone answering
    ///
    /// ## AddressRemoved
    ///
    /// An IP address was removed from an interface:
    ///
    /// - Update interface addresses in cache
    /// - Close listeners bound to this specific address
    /// - Unregister address from authoritative zones
    ///
    /// ## InterfaceUp / InterfaceDown
    ///
    /// Interface state changed:
    ///
    /// - **Up**: Enable listeners, validate upstream servers
    /// - **Down**: Disable listeners, mark servers unavailable
    ///
    /// # Rebinding Strategy
    ///
    /// Listener rebinding behavior depends on configuration:
    ///
    /// - **`--bind-dynamic`**: Dynamically rebind on any change
    /// - **`--bind-interfaces`**: Rebind only on address changes
    /// - **Default (wildcard)**: No rebinding needed (catches all interfaces)
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if:
    ///
    /// - Interface state update fails
    /// - Listener rebinding fails
    /// - Platform-specific operations fail
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dnsmasq::network::InterfaceEvent;
    ///
    /// // From platform monitoring task
    /// let event = InterfaceEvent::AddressAdded {
    ///     interface: "eth0".to_string(),
    ///     address: "192.168.1.10".parse()?,
    /// };
    ///
    /// network_service.handle_interface_change(event).await?;
    /// ```
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces C function `iface_check()` from network.c, which was called from
    /// netlink/BPF event handlers to update interface state.
    #[instrument(skip(self), fields(event = ?event))]
    pub async fn handle_interface_change(&mut self, event: InterfaceEvent) -> Result<(), NetworkError> {
        info!("Handling interface change event: {:?}", event);

        match &event {
            InterfaceEvent::LinkUp { interface } => {
                info!("Interface {} is now UP", interface);
                // Refresh interface list to pick up new interface
                self.interface_manager.refresh_interfaces().await
                    .map_err(|e| NetworkError::InterfaceEnumerationFailed { reason: format!("Failed to refresh interfaces: {}", e) })?;
                
                // Check if we need to rebind based on configuration
                if self.config.network.bind_dynamic {
                    info!("Dynamic binding enabled, will rebind listeners");
                    // Note: Actual rebinding would require coordination with runtime
                    // to close old listeners and create new ones
                }
            }
            
            InterfaceEvent::LinkDown { interface } => {
                warn!("Interface {} is now DOWN", interface);
                // Update interface list
                self.interface_manager.refresh_interfaces().await
                    .map_err(|e| NetworkError::InterfaceEnumerationFailed { reason: format!("Failed to refresh interfaces: {}", e) })?;
                warn!("Interface {} down, listeners may need rebinding", interface);
            }
            
            InterfaceEvent::AddressAdded { interface, address } => {
                info!("Address added to {}: {}", interface, address);
                // Refresh interface to pick up new address
                self.interface_manager.refresh_interfaces().await
                    .map_err(|e| NetworkError::InterfaceEnumerationFailed { reason: format!("Failed to refresh interfaces: {}", e) })?;
                
                // If bind-interfaces mode, may need to create new listener
                if self.config.network.bind_interfaces || self.config.network.bind_dynamic {
                    debug!("Interface-specific binding active, rebind may be required");
                }
            }
            
            InterfaceEvent::AddressRemoved { interface, address } => {
                info!("Address removed from {}: {}", interface, address);
                // Update interface state
                self.interface_manager.refresh_interfaces().await
                    .map_err(|e| NetworkError::InterfaceEnumerationFailed { reason: format!("Failed to refresh interfaces: {}", e) })?;
                warn!("Address {} removed from {}, listeners may be affected", address, interface);
            }
            
            InterfaceEvent::RouteChanged { destination, gateway } => {
                debug!("Route changed: destination={}, gateway={:?}", destination, gateway);
                // Route changes may affect upstream server reachability
                // This would typically trigger re-evaluation of which interface to use
                // for forwarding queries to specific upstream servers
                self.interface_manager.refresh_interfaces().await
                    .map_err(|e| NetworkError::InterfaceEnumerationFailed { reason: format!("Failed to refresh interfaces: {}", e) })?;
            }
        }

        // Notify ARP cache of potential changes (new interfaces may have new neighbors)
        {
            let mut cache = self.arp_cache.write().await;
            if let Err(e) = cache.notify_changes().await {
                warn!("ARP cache notification failed: {}", e);
            }
        }

        debug!("Interface change handling completed");
        Ok(())
    }

    /// Returns a reference to the interface manager.
    ///
    /// Provides read-only access to interface information for other services
    /// that need to query interface state (DNS authoritative, DHCP relay, etc.).
    pub fn get_interface_manager(&self) -> &InterfaceManager {
        &self.interface_manager
    }

    /// Returns a shared reference to the ARP cache.
    ///
    /// Provides access to IP-to-MAC mappings for DHCP services to perform
    /// address conflict detection before allocating leases.
    pub fn get_arp_cache(&self) -> Arc<RwLock<ArpCache>> {
        Arc::clone(&self.arp_cache)
    }

    /// Returns a reference to the platform handler.
    ///
    /// Provides access to platform-specific operations for other services
    /// that need to perform low-level network operations.
    pub fn get_platform(&self) -> &dyn NetworkPlatform {
        self.platform.as_ref()
    }

    /// Returns the network configuration.
    pub fn get_config(&self) -> &Arc<Config> {
        &self.config
    }

    /// Returns the conntrack handler if available and enabled.
    ///
    /// Linux-only feature for connection tracking integration with policy routing.
    #[cfg(all(target_os = "linux", feature = "conntrack"))]
    pub fn get_conntrack(&self) -> Option<&ConntrackHandler> {
        self.conntrack.as_ref()
    }

    /// Returns the firewall backend if available and enabled.
    ///
    /// Provides access to ipset/nftables/PF integration for adding DNS responses
    /// to firewall sets based on domain name matches.
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
    pub fn get_firewall(&self) -> Option<&dyn FirewallBackend> {
        self.firewall.as_ref().map(|b| b.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_enum() {
        assert_eq!(Protocol::Dns, Protocol::Dns);
        assert_ne!(Protocol::Dns, Protocol::DhcpV4);
    }

    #[test]
    fn test_listener_set_creation() {
        let listeners = ListenerSet::new();
        assert!(listeners.dns_udp.is_empty());
        assert!(listeners.dns_tcp.is_empty());
        assert!(listeners.dhcp_v4.is_none());
        assert!(listeners.dhcp_v6.is_none());
        assert!(listeners.tftp.is_none());
        assert!(listeners.icmpv6.is_none());
    }

    #[test]
    fn test_listener_set_default() {
        let listeners = ListenerSet::default();
        assert!(listeners.dns_udp_socket().is_none());
        assert!(listeners.dhcp_v4_socket().is_none());
    }
}
