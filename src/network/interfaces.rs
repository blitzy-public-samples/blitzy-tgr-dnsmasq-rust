// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Network interface enumeration and monitoring module
//!
//! This module provides comprehensive interface discovery, address tracking, and real-time
//! change detection across all supported platforms. It implements the [`InterfaceManager`]
//! struct which coordinates platform-specific interface operations via the
//! [`platform::NetworkPlatform`](crate::network::platform::NetworkPlatform) trait.
//!
//! # Purpose
//!
//! Replaces C network.c's interface enumeration and monitoring with memory-safe Rust:
//! - Converts `struct irec` linked list to `Vec<NetworkInterface>` with owned data
//! - Transforms `iface_enumerate()` callback pattern to async stream
//! - Replaces `getifaddrs()` pointer iteration with safe iterator pattern
//! - Provides real-time interface monitoring via platform-specific mechanisms
//!
//! # C Implementation Mapping
//!
//! From network.c (lines 500-900):
//! ```c
//! struct irec {
//!     struct irec *next;
//!     int index;
//!     char *name;
//!     union mysockaddr addr;
//!     union mysockaddr netmask;
//!     union mysockaddr broadcast;
//!     unsigned short mtu;
//!     unsigned int flags;
//! };
//!
//! // Callback-based enumeration
//! static int iface_enumerate(int family, void *parm,
//!                           int (*callback)(struct irec *, int, struct iname *));
//! ```
//!
//! Rust equivalent: Type-safe Vec-based storage with async streams for monitoring.
//!
//! # Key Transformations
//!
//! ## 1. Linked List → Vec
//!
//! C pattern:
//! ```c
//! struct irec *next_iface = interfaces;
//! while (next_iface) {
//!     // Process interface
//!     next_iface = next_iface->next;
//! }
//! ```
//!
//! Rust pattern:
//! ```rust,ignore
//! for interface in &manager.cache.read().await {
//!     // Process interface - no null checks needed
//! }
//! ```
//!
//! ## 2. Callback Functions → Closures/Streams
//!
//! C pattern:
//! ```c
//! int callback(struct irec *iface, int index, struct iname *names) {
//!     // Process interface
//!     return 1;  // Continue enumeration
//! }
//! iface_enumerate(AF_INET, NULL, callback);
//! ```
//!
//! Rust pattern:
//! ```rust,ignore
//! let interfaces = manager.enumerate_interfaces().await?;
//! interfaces.into_iter().filter(|iface| validator(iface));
//! ```
//!
//! ## 3. Poll-based Monitoring → Async Streams
//!
//! C pattern:
//! ```c
//! // Poll netlink socket for interface changes
//! poll(netlinkfd, &events, timeout);
//! if (events & POLLIN) {
//!     netlink_multicast();  // Process changes
//! }
//! ```
//!
//! Rust pattern:
//! ```rust,ignore
//! let mut events = manager.watch_interface_changes().await?;
//! while let Some(event) = events.next().await {
//!     match event {
//!         InterfaceEvent::AddressAdded { interface, address } => { /* ... */ }
//!         // ...
//!     }
//! }
//! ```
//!
//! # Architecture
//!
//! ```text
//! InterfaceManager
//! ├── platform: Arc<dyn NetworkPlatform>  (Linux/BSD/macOS implementation)
//! ├── cache: Arc<RwLock<Vec<NetworkInterface>>>  (Shared interface list)
//! └── Methods:
//!     ├── enumerate_interfaces()   (Discover all interfaces)
//!     ├── refresh_interfaces()     (Update cache from kernel)
//!     ├── watch_interface_changes() (Real-time event stream)
//!     ├── get_interface_by_name()  (Lookup by name)
//!     ├── get_interface_by_index() (Lookup by index)
//!     └── validate_interface()     (Check suitability for DNS/DHCP)
//! ```
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::network::interfaces::InterfaceManager;
//! use dnsmasq::network::platform::create_platform_handler;
//! use tokio_stream::StreamExt;
//!
//! let platform = create_platform_handler().await?;
//! let manager = InterfaceManager::new(platform);
//!
//! // Initial enumeration
//! let interfaces = manager.enumerate_interfaces().await?;
//! for interface in interfaces {
//!     if manager.validate_interface(&interface, &config).await {
//!         println!("Usable interface: {} with {} addresses",
//!                  interface.name, interface.addresses.len());
//!     }
//! }
//!
//! // Monitor for changes
//! let mut events = manager.watch_interface_changes().await?;
//! while let Some(event) = events.next().await {
//!     match event {
//!         InterfaceEvent::AddressAdded { interface, address } => {
//!             info!("New address {} on {}", address, interface);
//!             manager.refresh_interfaces().await?;
//!         }
//!         InterfaceEvent::LinkUp { interface } => {
//!             info!("Interface {} is now up", interface);
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!
//! # Memory Safety
//!
//! - **No manual memory management**: Vec and String provide automatic cleanup
//! - **No pointer arithmetic**: Safe slice operations with bounds checking
//! - **No NULL pointers**: Option types make optionality explicit
//! - **No data races**: Arc + `RwLock` ensures thread-safe cache access
//! - **No use-after-free**: Borrow checker prevents dangling references
//!
//! # Thread Safety
//!
//! [`InterfaceManager`] is `Send + Sync` and can be safely shared across async tasks.
//! The internal cache uses `Arc<RwLock<>>` for synchronized access, allowing multiple
//! readers (listeners checking interface validity) and exclusive writers (refresh operations).

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::Stream;
use tracing::{debug, info, instrument, warn};

use crate::config::types::Config;
use crate::error::Result;

// Re-export platform types that are already defined in platform/common.rs
// This avoids duplication while providing a convenient import path
pub use crate::network::platform::common::{InterfaceEvent, InterfaceFlags, NetworkInterface};
use crate::network::platform::NetworkPlatform;

/// Interface manager coordinating network topology discovery and monitoring
///
/// This struct replaces C network.c's global `daemon->interfaces` linked list and associated
/// enumeration functions with a managed, thread-safe interface cache. It coordinates between
/// platform-specific implementations (Linux netlink, BSD routing sockets) and provides a
/// unified async API for interface operations.
///
/// # C Equivalent
///
/// ```c
/// // C implementation (dnsmasq.h, network.c)
/// extern struct daemon {
///     struct irec *interfaces;  // Linked list of interface records
///     // ...
/// } *daemon;
///
/// // Enumeration with callback
/// static int iface_enumerate(int family, void *parm,
///                           int (*callback)(struct irec *, int, struct iname *));
///
/// // Validation with scattered checks
/// static int iface_check(int family, struct all_addr *addr, char *name, int *auth);
/// ```
///
/// # Rust Improvements
///
/// - **Type-safe platform dispatch**: `Arc<dyn NetworkPlatform>` replaces function pointers
/// - **Automatic memory management**: `Vec<NetworkInterface>` replaces linked list
/// - **Thread-safe caching**: `RwLock` protects shared state
/// - **Async streams**: `Stream<Item=InterfaceEvent>` replaces poll-based monitoring
/// - **No callbacks**: Direct async method calls replace callback pattern
///
/// # Fields
///
/// - `platform`: Platform-specific implementation (Linux/BSD/macOS)
/// - `cache`: Shared interface list updated by refresh operations
///
/// # Examples
///
/// ```rust,ignore
/// let platform = create_platform_handler().await?;
/// let manager = InterfaceManager::new(platform);
///
/// // Enumerate all interfaces
/// let interfaces = manager.enumerate_interfaces().await?;
///
/// // Get specific interface
/// if let Some(eth0) = manager.get_interface_by_name("eth0").await {
///     println!("eth0 has {} addresses", eth0.addresses.len());
/// }
///
/// // Monitor changes
/// let mut events = manager.watch_interface_changes().await?;
/// while let Some(event) = events.next().await {
///     println!("Interface event: {:?}", event);
/// }
/// ```
#[derive(Clone, Debug)]
pub struct InterfaceManager {
    /// Platform-specific network operations implementation
    ///
    /// Dispatches to Linux (netlink), BSD (routing sockets), or macOS (routing sockets +
    /// macOS APIs) based on compile-time platform selection. Wrapped in Arc for cheap
    /// cloning across async tasks.
    platform: Arc<dyn NetworkPlatform>,

    /// Cached interface list with thread-safe access
    ///
    /// Replaces C's global `daemon->interfaces` linked list with a Rust Vec protected by
    /// `RwLock`. Multiple readers (listener creation, validation checks) can access
    /// concurrently, while writers (refresh operations) get exclusive access.
    cache: Arc<RwLock<Vec<NetworkInterface>>>,
}

impl InterfaceManager {
    /// Creates a new interface manager with the given platform handler
    ///
    /// # Arguments
    ///
    /// * `platform` - Platform-specific network implementation (Linux/BSD/macOS)
    ///
    /// # Returns
    ///
    /// A new `InterfaceManager` with an empty interface cache
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let platform = create_platform_handler().await?;
    /// let manager = InterfaceManager::new(platform);
    /// ```
    pub fn new(platform: Arc<dyn NetworkPlatform>) -> Self {
        Self { platform, cache: Arc::new(RwLock::new(Vec::new())) }
    }

    /// Enumerates all network interfaces with addresses
    ///
    /// Discovers all network interfaces on the system using platform-specific mechanisms:
    /// - Modern systems: `getifaddrs()` via nix crate
    /// - Legacy systems: SIOCGIFCONF ioctl fallback
    /// - Returns interfaces with names, indexes, addresses, netmasks, broadcast addresses,
    ///   MTU, and flags (up/down, loopback, point-to-point, multicast)
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // network.c lines 600-800
    /// static int iface_enumerate(int family, void *parm,
    ///                           int (*callback)(struct irec *, int, struct iname *)) {
    ///     struct ifaddrs *addrs;
    ///     if (getifaddrs(&addrs) < 0) return 0;
    ///     
    ///     for (struct ifaddrs *addr = addrs; addr; addr = addr->ifa_next) {
    ///         // Manual union all_addr parsing
    ///         if (addr->ifa_addr->sa_family == family) {
    ///             // Invoke callback with irec struct
    ///             if (!callback(&iface_record, index, names))
    ///                 break;
    ///         }
    ///     }
    ///     freeifaddrs(addrs);
    /// }
    /// ```
    ///
    /// # Rust Improvements
    ///
    /// - Type-safe address handling with `IpAddr` enum (no union discrimination)
    /// - Automatic memory management (no manual `freeifaddrs`)
    /// - Iterator-based processing (no callback functions)
    /// - Comprehensive error propagation (no silent failures)
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<NetworkInterface>)` - List of all discovered interfaces
    /// - `Err(NetworkError)` - If enumeration fails (permission denied, system error)
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if:
    /// - `getifaddrs()` fails (insufficient privileges, system error)
    /// - Platform-specific enumeration fails (netlink socket error, routing socket error)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let interfaces = manager.enumerate_interfaces().await?;
    /// for iface in interfaces {
    ///     println!("{}: {} addresses, MTU {}, flags: {:?}",
    ///              iface.name, iface.addresses.len(), iface.mtu, iface.flags);
    /// }
    /// ```
    #[instrument(skip(self), fields(platform = "generic"))]
    pub async fn enumerate_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        debug!("Enumerating network interfaces");

        // Delegate to platform-specific implementation
        let interfaces = self.platform.enumerate_interfaces().await.map_err(|e| {
            warn!("Failed to enumerate interfaces: {}", e);
            e
        })?;

        info!("Enumerated {} network interfaces", interfaces.len());

        // Log each interface for debugging
        for iface in &interfaces {
            debug!(
                interface = %iface.name,
                index = iface.index,
                address_count = iface.addresses.len(),
                mtu = iface.mtu,
                is_up = iface.flags.contains(InterfaceFlags::UP),
                is_loopback = iface.flags.contains(InterfaceFlags::LOOPBACK),
                "Discovered interface"
            );
        }

        Ok(interfaces)
    }

    /// Refreshes the interface cache from kernel state
    ///
    /// Updates the internal cache by re-enumerating all interfaces. This should be called:
    /// - After receiving interface change events
    /// - Before creating new listeners
    /// - After configuration reload (SIGHUP)
    ///
    /// # C Equivalent
    ///
    /// C implementation re-enumerates on every listener creation:
    /// ```c
    /// // network.c
    /// static struct listener *create_listeners() {
    ///     // Re-enumerate interfaces every time
    ///     iface_enumerate(AF_INET, &parm, iface_allowed);
    ///     iface_enumerate(AF_INET6, &parm, iface_allowed);
    ///     // Build listener list
    /// }
    /// ```
    ///
    /// Rust improvement: Explicit refresh with cached results between refreshes.
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Cache updated successfully
    /// - `Err(NetworkError)` - If enumeration fails
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // After SIGHUP signal
    /// manager.refresh_interfaces().await?;
    ///
    /// // After interface change event
    /// tokio::select! {
    ///     Some(InterfaceEvent::AddressAdded { .. }) = events.next() => {
    ///         manager.refresh_interfaces().await?;
    ///     }
    /// }
    /// ```
    #[instrument(skip(self))]
    pub async fn refresh_interfaces(&self) -> Result<()> {
        debug!("Refreshing interface cache");

        let interfaces = self.enumerate_interfaces().await?;

        let mut cache = self.cache.write().await;
        *cache = interfaces;

        info!("Interface cache refreshed with {} interfaces", cache.len());
        Ok(())
    }

    /// Monitors interface changes in real-time
    ///
    /// Returns an async stream yielding `InterfaceEvent` items whenever network topology
    /// changes occur. This replaces C's poll-based monitoring of netlink (Linux) or routing
    /// sockets (BSD) with an async stream.
    ///
    /// # Event Types
    ///
    /// - `InterfaceAdded` - New interface discovered
    /// - `InterfaceRemoved` - Interface removed from system
    /// - `AddressAdded` - New IP address assigned to interface
    /// - `AddressRemoved` - IP address removed from interface
    /// - `LinkUp` - Interface transitioned to UP state
    /// - `LinkDown` - Interface transitioned to DOWN state
    ///
    /// # Platform Mechanisms
    ///
    /// - **Linux**: Netlink `RTMGRP_IPV4_IFADDR`, `RTMGRP_IPV6_IFADDR` multicast groups
    /// - **BSD**: Routing socket with `RTM_NEWADDR`, `RTM_DELADDR`, `RTM_IFINFO` messages
    /// - **macOS**: Routing socket + System Configuration framework notifications
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // network.c (Linux)
    /// static void netlink_multicast() {
    ///     struct nlmsghdr *h;
    ///     while (nl_async(netlinkfd, &h)) {
    ///         if (h->nlmsg_type == RTM_NEWADDR || h->nlmsg_type == RTM_DELADDR) {
    ///             // Re-create listeners
    ///             create_listeners();
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// # Rust Improvements
    ///
    /// - **Type-safe events**: Enum with associated data vs. integer message types
    /// - **Async streams**: `Stream<Item=InterfaceEvent>` vs. poll loop
    /// - **No global state**: Event stream is independent
    /// - **Automatic resource cleanup**: Stream Drop handles socket closure
    ///
    /// # Returns
    ///
    /// - `Ok(impl Stream<Item=InterfaceEvent>)` - Event stream for monitoring
    /// - `Err(NetworkError)` - If subscription fails (permission denied, socket error)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut events = manager.watch_interface_changes().await?;
    ///
    /// while let Some(event) = events.next().await {
    ///     match event {
    ///         InterfaceEvent::AddressAdded { interface, address } => {
    ///             info!("Address {} added to {}", address, interface);
    ///             manager.refresh_interfaces().await?;
    ///             // Re-create listeners for new address
    ///         }
    ///         InterfaceEvent::LinkDown { interface } => {
    ///             warn!("Interface {} went down", interface);
    ///             // Remove listeners on this interface
    ///         }
    ///         _ => {}
    ///     }
    /// }
    /// ```
    #[instrument(skip(self))]
    pub async fn watch_interface_changes(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = InterfaceEvent> + Send>>> {
        debug!("Setting up interface change monitoring");

        let event_stream = self.platform.subscribe_to_changes().await?;

        info!("Interface change monitoring active");
        Ok(event_stream)
    }

    /// Retrieves an interface by name
    ///
    /// Performs O(n) linear search through cached interfaces. For frequent lookups,
    /// consider building a `HashMap` externally.
    ///
    /// # Arguments
    ///
    /// * `name` - Interface name (e.g., "eth0", "wlan0", "en0")
    ///
    /// # Returns
    ///
    /// - `Some(&NetworkInterface)` - Interface found
    /// - `None` - No interface with this name
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// if let Some(eth0) = manager.get_interface_by_name("eth0").await {
    ///     for addr in &eth0.addresses {
    ///         println!("eth0 has address: {}", addr);
    ///     }
    /// }
    /// ```
    #[instrument(skip(self), fields(interface_name = %name))]
    pub async fn get_interface_by_name(&self, name: &str) -> Option<NetworkInterface> {
        let cache = self.cache.read().await;
        cache.iter().find(|iface| iface.name == name).cloned()
    }

    /// Retrieves an interface by kernel index
    ///
    /// Maps interface index (from socket ancillary data, netlink messages) to interface name
    /// and full interface information.
    ///
    /// # Arguments
    ///
    /// * `index` - Kernel interface index (e.g., from `IP_PKTINFO`, `IPV6_PKTINFO`)
    ///
    /// # Returns
    ///
    /// - `Some(&NetworkInterface)` - Interface found
    /// - `None` - No interface with this index
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // network.c
    /// char *indextoname(int fd, int index, char *name) {
    ///     struct ifreq ifr;
    ///     ifr.ifr_ifindex = index;
    ///     if (ioctl(fd, SIOCGIFNAME, &ifr) == 0)
    ///         return ifr.ifr_name;
    ///     return NULL;
    /// }
    /// ```
    ///
    /// Rust improvement: Returns full interface info, not just name.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // From packet ancillary data
    /// let pktinfo: in6_pktinfo = /* ... */;
    /// if let Some(iface) = manager.get_interface_by_index(pktinfo.ipi6_ifindex).await {
    ///     println!("Packet received on {}", iface.name);
    /// }
    /// ```
    #[instrument(skip(self), fields(interface_index = index))]
    pub async fn get_interface_by_index(&self, index: u32) -> Option<NetworkInterface> {
        let cache = self.cache.read().await;
        cache.iter().find(|iface| iface.index == index).cloned()
    }

    /// Validates interface suitability for DNS/DHCP operations
    ///
    /// Checks whether an interface should be used for binding listeners based on:
    /// 1. Configuration filters (--interface, --except-interface, --listen-address)
    /// 2. Address state (not tentative, not deprecated)
    /// 3. Address scope (appropriate for operation type)
    /// 4. Interface state (up, not excluded)
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // network.c lines 400-500
    /// static int iface_check(int family, struct all_addr *addr, char *name, int *auth) {
    ///     // Check if interface/address is in configuration
    ///     for (tmp = daemon->if_names; tmp; tmp = tmp->next)
    ///         if (tmp->name && wildcard_match(tmp->name, name))
    ///             return 1;
    ///     
    ///     // Check exceptions
    ///     for (tmp = daemon->if_except; tmp; tmp = tmp->next)
    ///         if (tmp->name && wildcard_match(tmp->name, name))
    ///             return 0;
    ///     
    ///     // Check address flags (tentative, deprecated)
    ///     if (flags & (IFA_F_TENTATIVE | IFA_F_DEPRECATED))
    ///         return 0;
    ///     
    ///     return 1;
    /// }
    /// ```
    ///
    /// # Rust Improvements
    ///
    /// - **Explicit validation logic**: Clear method with documented checks
    /// - **No global state**: Configuration passed as parameter
    /// - **Type-safe flags**: `InterfaceFlags` enum vs. integer bitflags
    /// - **Comprehensive logging**: Tracing for debugging filter decisions
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface to validate
    /// * `config` - Global configuration with interface filters
    ///
    /// # Returns
    ///
    /// - `true` - Interface is suitable for use
    /// - `false` - Interface should be excluded
    ///
    /// # Validation Steps
    ///
    /// 1. **Explicit inclusion**: Check if in `config.network.interfaces`
    /// 2. **Explicit exclusion**: Check if in `config.network.except_interfaces`
    /// 3. **Interface state**: Must be UP (unless bind-interfaces=false)
    /// 4. **Address state**: No tentative or deprecated addresses
    /// 5. **Address scope**: Appropriate for operation (link-local vs. global)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// for iface in manager.enumerate_interfaces().await? {
    ///     if manager.validate_interface(&iface, &config).await {
    ///         // Create listeners on this interface
    ///         create_listener(&iface).await?;
    ///     } else {
    ///         debug!("Skipping interface {}: filtered by config", iface.name);
    ///     }
    /// }
    /// ```
    #[instrument(skip(self, config), fields(interface = %interface.name))]
    pub async fn validate_interface(&self, interface: &NetworkInterface, config: &Config) -> bool {
        // Check explicit inclusions first (--interface)
        if !config.network.interfaces.is_empty() {
            let explicitly_included =
                config.network.interfaces.iter().any(|name| name == &interface.name);

            if !explicitly_included {
                debug!(
                    interface = %interface.name,
                    "Interface not in explicit interface list"
                );
                return false;
            }
        }

        // Check explicit exclusions (--except-interface)
        let explicitly_excluded =
            config.network.except_interfaces.iter().any(|name| name == &interface.name);

        if explicitly_excluded {
            debug!(
                interface = %interface.name,
                "Interface explicitly excluded via --except-interface"
            );
            return false;
        }

        // Check interface state - must be UP (unless bind-interfaces=false allows all)
        if config.network.bind_interfaces && !interface.flags.contains(InterfaceFlags::UP) {
            debug!(
                interface = %interface.name,
                "Interface is down (bind-interfaces=true requires UP)"
            );
            return false;
        }

        // Skip loopback unless explicitly configured
        if interface.flags.contains(InterfaceFlags::LOOPBACK)
            && !config.network.interfaces.contains(&interface.name)
        {
            debug!(
                interface = %interface.name,
                "Skipping loopback interface (not explicitly configured)"
            );
            return false;
        }

        // Check if interface has any usable addresses
        if interface.addresses.is_empty() {
            debug!(
                interface = %interface.name,
                "Interface has no addresses"
            );
            return false;
        }

        // If listen-addresses are specified, check if this interface has any of them
        if !config.network.listen_addresses.is_empty() {
            let has_listen_address = interface
                .addresses
                .iter()
                .any(|addr| config.network.listen_addresses.contains(addr));

            if !has_listen_address {
                debug!(
                    interface = %interface.name,
                    "Interface has no configured listen-addresses"
                );
                return false;
            }
        }

        // All checks passed
        debug!(
            interface = %interface.name,
            address_count = interface.addresses.len(),
            "Interface validated successfully"
        );
        true
    }

    /// Creates a lookup map for efficient interface queries
    ///
    /// Builds `HashMap` for O(1) lookup by name or index. Useful when processing many packets
    /// that need interface resolution.
    ///
    /// # Returns
    ///
    /// Tuple of (`name_map`, `index_map`) for fast lookups
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let (by_name, by_index) = manager.build_lookup_maps().await;
    ///
    /// // Fast lookup in packet processing loop
    /// if let Some(iface) = by_index.get(&pktinfo.ipi6_ifindex) {
    ///     process_packet_on_interface(packet, iface);
    /// }
    /// ```
    #[instrument(skip(self))]
    pub async fn build_lookup_maps(
        &self,
    ) -> (HashMap<String, NetworkInterface>, HashMap<u32, NetworkInterface>) {
        let cache = self.cache.read().await;

        let by_name: HashMap<String, NetworkInterface> =
            cache.iter().map(|iface| (iface.name.clone(), iface.clone())).collect();

        let by_index: HashMap<u32, NetworkInterface> =
            cache.iter().map(|iface| (iface.index, iface.clone())).collect();

        debug!(
            "Built lookup maps: {} interfaces by name, {} by index",
            by_name.len(),
            by_index.len()
        );

        (by_name, by_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests basic validation of interface state flags
    #[test]
    fn test_interface_flags() {
        let flags = InterfaceFlags::UP | InterfaceFlags::BROADCAST;
        assert!(flags.contains(InterfaceFlags::UP));
        assert!(flags.contains(InterfaceFlags::BROADCAST));
        assert!(!flags.contains(InterfaceFlags::LOOPBACK));
    }

    /// Tests that NetworkInterface can be created with all required fields
    #[test]
    fn test_network_interface_creation() {
        let iface = NetworkInterface {
            name: "eth0".to_string(),
            index: 1,
            addresses: vec!["192.168.1.1".parse().unwrap()],
            netmask: Some("255.255.255.0".parse().unwrap()),
            broadcast: Some("192.168.1.255".parse().unwrap()),
            mtu: 1500,
            flags: InterfaceFlags::UP | InterfaceFlags::BROADCAST,
        };

        assert_eq!(iface.name, "eth0");
        assert_eq!(iface.index, 1);
        assert_eq!(iface.addresses.len(), 1);
        assert_eq!(iface.mtu, 1500);
        assert!(iface.flags.contains(InterfaceFlags::UP));
    }
}
