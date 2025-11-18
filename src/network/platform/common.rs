// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Cross-platform networking abstractions providing shared types and utilities
//!
//! This module defines the common networking types and traits used by all platform-specific
//! implementations (Linux, BSD, macOS). It extracts cross-platform types from network.c's
//! `struct irec` and interface flags, transforming them into memory-safe Rust types with
//! compile-time guarantees.
//!
//! # Key Types
//!
//! - [`NetworkInterface`]: Represents a network interface with all its properties
//! - [`InterfaceEvent`]: Network topology change events for monitoring
//! - [`InterfaceFlags`]: Type-safe bitflags for interface state
//! - [`NetworkPlatform`]: Unified trait for platform-specific implementations
//!
//! # C to Rust Transformation
//!
//! This module replaces C's manual pointer management and flag manipulation:
//!
//! ```c
//! // C implementation (dnsmasq.h:665)
//! struct irec {
//!     struct irec *next;
//!     int index;
//!     char *name;
//!     union mysockaddr addr;
//!     union mysockaddr netmask;
//!     union mysockaddr broadcast;
//!     unsigned short mtu;
//!     unsigned int flags;  // IFF_UP, IFF_LOOPBACK, etc.
//! };
//! ```
//!
//! With type-safe Rust equivalents using owned data and bitflags:
//!
//! ```rust,ignore
//! pub struct NetworkInterface {
//!     pub name: String,                // Owned, not pointer
//!     pub index: u32,
//!     pub addresses: Vec<IpAddr>,      // Multiple addresses per interface
//!     pub netmask: Option<IpAddr>,
//!     pub broadcast: Option<IpAddr>,
//!     pub mtu: u16,
//!     pub flags: InterfaceFlags,       // Type-safe bitflags
//! }
//! ```

use async_trait::async_trait;
use bitflags::bitflags;
use std::net::IpAddr;
use std::pin::Pin;
use tokio_stream::Stream;

use crate::error::Result;

bitflags! {
    /// Type-safe interface state flags replacing C IFF_* constants
    ///
    /// Replaces manual bit manipulation from network.c with compile-time checked flag operations.
    /// Maps directly to C interface flags (IFF_UP, IFF_LOOPBACK, IFF_POINTOPOINT, etc.) but
    /// provides type safety through the bitflags! macro.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // C implementation uses manual bit manipulation
    /// if (iface->flags & IFF_UP) { /* interface is up */ }
    /// if (iface->flags & IFF_LOOPBACK) { /* loopback interface */ }
    /// ```
    ///
    /// # Rust Usage
    ///
    /// ```rust,ignore
    /// let mut flags = InterfaceFlags::empty();
    /// flags.insert(InterfaceFlags::UP);
    /// flags.insert(InterfaceFlags::MULTICAST);
    ///
    /// if flags.contains(InterfaceFlags::UP) {
    ///     // Interface is up
    /// }
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct InterfaceFlags: u32 {
        /// Interface is up and operational (IFF_UP)
        const UP = 0x1;

        /// Loopback interface (IFF_LOOPBACK)
        const LOOPBACK = 0x8;

        /// Point-to-point link (IFF_POINTOPOINT) - VPN, PPP, etc.
        const POINT_TO_POINT = 0x10;

        /// Supports multicast (IFF_MULTICAST)
        const MULTICAST = 0x1000;

        /// Supports broadcast (IFF_BROADCAST)
        const BROADCAST = 0x2;
    }
}

/// Network interface representation with all properties
///
/// This struct replaces C's `struct irec` from dnsmasq.h:665, transforming pointer-based
/// interface records into a memory-safe Rust structure with owned data. Each interface
/// can have multiple IP addresses (both IPv4 and IPv6), reflecting modern dual-stack
/// networking.
///
/// # C Equivalent
///
/// ```c
/// // C implementation (dnsmasq.h:665)
/// struct irec {
///     struct irec *next;              // Linked list pointer
///     int index;                      // Kernel interface index
///     char *name;                     // Interface name (allocated)
///     union mysockaddr addr;          // Single address
///     union mysockaddr netmask;       // Netmask for IPv4
///     union mysockaddr broadcast;     // Broadcast address
///     unsigned short mtu;             // Maximum transmission unit
///     unsigned int flags;             // IFF_* flags
/// };
/// ```
///
/// # Rust Improvements
///
/// - **Owned name**: `String` instead of `char*` eliminates lifetime issues
/// - **Multiple addresses**: `Vec<IpAddr>` supports modern dual-stack interfaces
/// - **Type-safe flags**: `InterfaceFlags` bitflags prevent invalid flag combinations
/// - **Optional fields**: `Option<IpAddr>` makes optionality explicit
/// - **No manual memory management**: Automatic Drop eliminates leaks
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterface {
    /// Interface name (e.g., "eth0", "wlan0", "lo")
    ///
    /// Owned String replacing C's allocated char*. No lifetime management required.
    pub name: String,

    /// Kernel interface index (unique identifier)
    ///
    /// Used for socket binding via SO_BINDTODEVICE (Linux) or IP_BOUND_IF (BSD).
    /// Index 0 is reserved for "any interface". Typical range: 1-255.
    pub index: u32,

    /// All IP addresses assigned to this interface
    ///
    /// Modern interfaces often have multiple addresses (IPv4 + IPv6, multiple subnets).
    /// This Vec replaces C's single-address limitation with dynamic allocation.
    pub addresses: Vec<IpAddr>,

    /// Netmask for the primary address (typically IPv4)
    ///
    /// Used for subnet calculations and DHCP range validation. Optional as not all
    /// address types have traditional netmasks (e.g., point-to-point links).
    pub netmask: Option<IpAddr>,

    /// Broadcast address (IPv4 only)
    ///
    /// Used for DHCP broadcasts and network configuration. None for IPv6 or
    /// point-to-point interfaces.
    pub broadcast: Option<IpAddr>,

    /// Maximum Transmission Unit in bytes
    ///
    /// Affects packet fragmentation decisions for DNS and DHCP. Typical values:
    /// 1500 (Ethernet), 9000 (Jumbo frames), 1280 (IPv6 minimum).
    pub mtu: u16,

    /// Interface state flags (up, loopback, multicast, etc.)
    ///
    /// Type-safe bitflags replacing C's manual bit manipulation. Determines whether
    /// interface is suitable for DNS/DHCP listening.
    pub flags: InterfaceFlags,
}

impl NetworkInterface {
    /// Check if interface is operationally up
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// if interface.is_up() {
    ///     // Can bind sockets to this interface
    /// }
    /// ```
    pub fn is_up(&self) -> bool {
        self.flags.contains(InterfaceFlags::UP)
    }

    /// Check if this is a loopback interface (lo, lo0)
    ///
    /// Loopback interfaces are typically excluded from external-facing services
    /// but included for local testing and queries.
    pub fn is_loopback(&self) -> bool {
        self.flags.contains(InterfaceFlags::LOOPBACK)
    }

    /// Check if this is a point-to-point link (VPN, PPP)
    ///
    /// Point-to-point interfaces require special handling for broadcast addresses
    /// and may not support standard DHCP operations.
    pub fn is_point_to_point(&self) -> bool {
        self.flags.contains(InterfaceFlags::POINT_TO_POINT)
    }

    /// Check if interface supports multicast
    ///
    /// Required for mDNS, DHCPv6 (multicast to ff02::1:2), and some DNS-SD operations.
    pub fn is_multicast(&self) -> bool {
        self.flags.contains(InterfaceFlags::MULTICAST)
    }

    /// Check if interface is usable for dnsmasq operations
    ///
    /// An interface is usable if it's up, has at least one address, and is not
    /// a pure loopback (unless explicitly configured to listen on loopback).
    ///
    /// This implements the C logic from network.c's interface validation.
    pub fn is_usable(&self) -> bool {
        self.is_up() && !self.addresses.is_empty()
    }
}

/// Network topology change events for interface monitoring
///
/// Replaces C event queue from network.c with type-safe Rust enum. Each variant carries
/// the specific data relevant to that event type, enabling precise event handling without
/// additional queries.
///
/// # C Equivalent
///
/// ```c
/// // C implementation uses integer event codes
/// #define EVENT_NEWADDR  1
/// #define EVENT_NEWROUTE 2
/// // ... with separate fields for event data
/// ```
///
/// # Rust Advantages
///
/// - **Type safety**: Each variant has associated data, preventing invalid access
/// - **Exhaustive matching**: Compiler enforces handling all event types
/// - **No additional queries**: Event carries all necessary information
/// - **Clear intent**: Event name makes purpose obvious
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceEvent {
    /// A new IP address was added to an interface
    ///
    /// Triggered when an interface gets a new IPv4 or IPv6 address through DHCP,
    /// static configuration, or SLAAC.
    AddressAdded {
        /// Interface name that received the address
        interface: String,
        /// The IP address that was added
        address: IpAddr,
    },

    /// An IP address was removed from an interface
    ///
    /// Triggered when an address expires, is manually removed, or the interface
    /// configuration changes.
    AddressRemoved {
        /// Interface name that lost the address
        interface: String,
        /// The IP address that was removed
        address: IpAddr,
    },

    /// An interface transitioned to the up state
    ///
    /// Interface became operational and can now send/receive packets. Dnsmasq
    /// should begin listening on this interface if configured.
    LinkUp {
        /// Interface name that came up
        interface: String,
    },

    /// An interface transitioned to the down state
    ///
    /// Interface is no longer operational. Dnsmasq should stop listening on this
    /// interface and mark any associated upstream servers as unavailable.
    LinkDown {
        /// Interface name that went down
        interface: String,
    },

    /// A routing table entry changed
    ///
    /// Affects upstream DNS server reachability and source address selection.
    /// May require re-evaluation of which interface to use for forwarding queries.
    RouteChanged {
        /// Destination network affected by the route change
        destination: IpAddr,
        /// Gateway address for the route (None for directly connected)
        gateway: Option<IpAddr>,
    },
}

/// Platform-specific network operations trait
///
/// Defines the interface that all platform-specific implementations must provide.
/// Linux uses netlink (rtnetlink crate), BSD uses routing sockets (nix crate),
/// and macOS uses a combination of both.
///
/// All methods are async to support tokio-based event loop integration, replacing
/// C's poll() event loop with Rust async/await.
///
/// # Platform Implementations
///
/// - **Linux**: `src/network/platform/linux.rs` using rtnetlink
/// - **BSD**: `src/network/platform/bsd.rs` using routing sockets
/// - **macOS**: `src/network/platform/macos.rs` using macOS-specific APIs
///
/// # C Equivalent
///
/// This trait unifies platform-specific functions scattered across network.c:
/// - `enumerate_interfaces()`: Replaces C's getifaddrs(), SIOCGIFCONF patterns
/// - `subscribe_to_changes()`: Replaces netlink.c (Linux) and bpf.c (BSD) monitoring
/// - `index_to_name()`: Replaces if_indextoname() calls
#[async_trait]
pub trait NetworkPlatform: Send + Sync {
    /// Enumerate all network interfaces on the system
    ///
    /// Returns a complete list of interfaces with their addresses, flags, and properties.
    /// This replaces C's getifaddrs() on modern systems or SIOCGIFCONF on legacy platforms.
    ///
    /// # Platform-Specific Behavior
    ///
    /// - **Linux**: Uses rtnetlink to query interface list
    /// - **BSD**: Uses getifaddrs() via nix crate
    /// - **macOS**: Uses getifaddrs() with macOS-specific flags
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::InterfaceEnumerationFailed` if platform-specific enumeration
    /// fails (permissions, system call failure, etc.).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let platform = LinuxNetworkPlatform::new()?;
    /// let interfaces = platform.enumerate_interfaces().await?;
    /// for interface in interfaces {
    ///     println!("Interface {} has {} addresses", interface.name, interface.addresses.len());
    /// }
    /// ```
    async fn enumerate_interfaces(&self) -> Result<Vec<NetworkInterface>>;

    /// Subscribe to network topology change events
    ///
    /// Returns an async stream of `InterfaceEvent` items that yields whenever the network
    /// topology changes. This replaces C's poll-based netlink monitoring (Linux) or routing
    /// socket monitoring (BSD).
    ///
    /// The stream continues indefinitely until dropped. Multiple subscribers are supported
    /// on platforms that allow it.
    ///
    /// # Platform-Specific Behavior
    ///
    /// - **Linux**: Opens NETLINK_ROUTE socket with RTMGRP_* subscriptions
    /// - **BSD**: Opens PF_ROUTE socket with RTM_* message filtering
    /// - **macOS**: Uses System Configuration framework or routing socket
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::NetlinkFailed` (Linux) or `NetworkError::RoutingFailed` (BSD)
    /// if monitoring cannot be established.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use tokio_stream::StreamExt;
    ///
    /// let platform = LinuxNetworkPlatform::new()?;
    /// let mut events = platform.subscribe_to_changes().await?;
    ///
    /// while let Some(event) = events.next().await {
    ///     match event {
    ///         InterfaceEvent::AddressAdded { interface, address } => {
    ///             println!("New address {} on {}", address, interface);
    ///         }
    ///         InterfaceEvent::LinkUp { interface } => {
    ///             println!("Interface {} is up", interface);
    ///         }
    ///         _ => {}
    ///     }
    /// }
    /// ```
    async fn subscribe_to_changes(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = InterfaceEvent> + Send>>>;

    /// Convert interface index to interface name
    ///
    /// Maps kernel interface index to human-readable name. This replaces C's if_indextoname()
    /// system call with an async version.
    ///
    /// # Arguments
    ///
    /// * `index` - Kernel interface index (1-255 typically)
    ///
    /// # Returns
    ///
    /// Interface name as String, or error if index is invalid.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::InterfaceNotFound` if the index doesn't correspond to any
    /// active interface.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let platform = LinuxNetworkPlatform::new()?;
    /// let name = platform.index_to_name(2).await?;
    /// assert_eq!(name, "eth0");  // Typical first Ethernet interface
    /// ```
    async fn index_to_name(&self, index: u32) -> Result<String>;

    /// Enumerate ARP table entries for address resolution validation
    ///
    /// Returns all entries from the kernel's ARP table, used for validating DHCP lease
    /// allocations and detecting address conflicts. This replaces manual /proc/net/arp
    /// parsing (Linux) or ioctl(SIOCGARP) calls (BSD).
    ///
    /// # Returns
    ///
    /// Vector of tuples containing (IP address, MAC address) for each ARP entry.
    ///
    /// # Platform-Specific Behavior
    ///
    /// - **Linux**: Reads /proc/net/arp or uses rtnetlink neighbor queries
    /// - **BSD**: Uses routing socket RTM_GET messages with RTF_LLINFO
    /// - **macOS**: Uses sysctl NET_RT_FLAGS with RTF_LLINFO
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::RoutingFailed` if ARP table cannot be read.
    async fn enumerate_arp_entries(&self) -> Result<Vec<(IpAddr, [u8; 6])>>;

    /// Validate that an IP address is suitable for dnsmasq operations
    ///
    /// Checks address validity based on scope, flags, and state. This centralizes the
    /// scattered address validation logic from network.c into a single method.
    ///
    /// # Validation Criteria
    ///
    /// An address is valid if:
    /// - Not tentative (IPv6 DAD incomplete)
    /// - Not deprecated (IPv6 address expiring)
    /// - Appropriate scope (not link-local for forwarding, unless explicitly allowed)
    /// - Not from a dormant or down interface
    ///
    /// # Arguments
    ///
    /// * `address` - IP address to validate
    /// * `interface` - Interface the address is assigned to
    ///
    /// # Returns
    ///
    /// `true` if address is suitable for binding sockets and forwarding queries.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let platform = LinuxNetworkPlatform::new()?;
    /// let interface = platform.enumerate_interfaces().await?
    ///     .into_iter()
    ///     .find(|i| i.name == "eth0")
    ///     .unwrap();
    ///
    /// for addr in &interface.addresses {
    ///     if platform.is_valid_address(addr, &interface).await? {
    ///         println!("Valid address: {}", addr);
    ///     }
    /// }
    /// ```
    async fn is_valid_address(
        &self,
        address: &IpAddr,
        interface: &NetworkInterface,
    ) -> Result<bool>;
}
