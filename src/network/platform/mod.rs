// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Platform-specific networking module providing OS-specific network interface management
//!
//! This module serves as the platform abstraction layer for dnsmasq's networking operations,
//! providing a unified `NetworkPlatform` trait with platform-specific implementations for
//! Linux (netlink), BSD (routing sockets + BPF), and macOS (routing sockets with macOS-specific
//! socket options).
//!
//! # Purpose
//!
//! This module replaces C's preprocessor-based platform selection from network.c, netlink.c,
//! and bpf.c with Rust's compile-time conditional compilation (`#[cfg(target_os)]`). Instead
//! of maintaining separate code paths with `#ifdef HAVE_LINUX_NETWORK` / `#ifdef HAVE_BSD_NETWORK`,
//! this module uses Rust's module system and trait-based polymorphism to provide type-safe
//! platform abstraction.
//!
//! # Architecture
//!
//! ```text
//! network::platform::mod.rs (this file)
//! ├── common.rs (NetworkPlatform trait, NetworkInterface, InterfaceEvent, InterfaceFlags)
//! ├── linux.rs (LinuxNetworkPlatform using rtnetlink)
//! ├── bsd.rs (BsdNetworkPlatform using routing sockets + BPF)
//! └── macos.rs (MacOSNetworkPlatform with macOS-specific APIs)
//! ```
//!
//! # C Implementation Mapping
//!
//! This module consolidates platform detection and dispatch logic scattered across multiple
//! C files:
//!
//! ## From network.c (platform selection):
//! ```c
//! // Lines 100-130: Platform-specific includes and initialization
//! #ifdef HAVE_LINUX_NETWORK
//!   #include <linux/netlink.h>
//!   #include <linux/rtnetlink.h>
//!   // Linux-specific networking via netlink
//! #elif defined(HAVE_BSD_NETWORK)
//!   #include <net/if_dl.h>
//!   #include <net/route.h>
//!   // BSD-specific networking via routing sockets
//! #elif defined(HAVE_SOLARIS_NETWORK)
//!   #include <sys/sockio.h>
//!   // Solaris-specific networking via SIOCGLIFCONF
//! #endif
//! ```
//!
//! Rust equivalent: `#[cfg(target_os = "linux")]` conditional compilation with trait dispatch.
//!
//! ## From netlink.c (Linux implementation):
//! ```c
//! // Lines 83-740: Complete Linux netlink implementation
//! #ifdef HAVE_LINUX_NETWORK
//! int netlink_init(void) {
//!   if ((netlinkfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
//!     return -1;
//!   // ... netlink socket setup
//! }
//! void netlink_multicast(void) {
//!   // Poll-based netlink message processing
//! }
//! #endif
//! ```
//!
//! Rust equivalent: `linux::LinuxNetworkPlatform` with async netlink via rtnetlink crate.
//!
//! ## From bpf.c (BSD/Solaris implementation):
//! ```c
//! // Lines 85-940: BSD BPF and routing socket implementation
//! #if defined(HAVE_BSD_NETWORK) || defined(HAVE_SOLARIS_NETWORK)
//! int init_bpf(void) {
//!   // Open /dev/bpf* devices for raw packet access
//! }
//! void route_init(void) {
//!   // Create PF_ROUTE socket for interface monitoring
//! }
//! #endif
//! ```
//!
//! Rust equivalent: `bsd::BsdNetworkPlatform` and `macos::MacOSNetworkPlatform` with
//! async routing socket monitoring.
//!
//! # Key Transformations
//!
//! ## 1. Preprocessor Conditionals → Rust cfg Attributes
//!
//! C pattern:
//! ```c
//! #ifdef HAVE_LINUX_NETWORK
//!   // Linux code
//! #elif defined(HAVE_BSD_NETWORK)
//!   // BSD code
//! #endif
//! ```
//!
//! Rust pattern:
//! ```rust,ignore
//! #[cfg(target_os = "linux")]
//! use linux::LinuxNetworkPlatform;
//!
//! #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
//! use bsd::BsdNetworkPlatform;
//! ```
//!
//! ## 2. Function Pointers → Trait Objects
//!
//! C pattern (manual dispatch):
//! ```c
//! int (*enumerate_fn)(void) = NULL;
//! #ifdef HAVE_LINUX_NETWORK
//!   enumerate_fn = netlink_enumerate;
//! #else
//!   enumerate_fn = bpf_enumerate;
//! #endif
//! enumerate_fn();
//! ```
//!
//! Rust pattern (trait-based polymorphism):
//! ```rust,ignore
//! let platform: Box<dyn NetworkPlatform> = create_platform_handler();
//! platform.enumerate_interfaces().await?;
//! ```
//!
//! ## 3. Global State → Structured Ownership
//!
//! C pattern:
//! ```c
//! static int netlinkfd = -1;  // Global netlink socket
//! static struct irec *interfaces = NULL;  // Global interface list
//! ```
//!
//! Rust pattern:
//! ```rust,ignore
//! pub struct LinuxNetworkPlatform {
//!     handle: rtnetlink::Handle,  // Owned connection handle
//!     interface_cache: Arc<Mutex<HashMap<u32, String>>>,  // Shared cache
//! }
//! ```
//!
//! # Platform Support Matrix
//!
//! | Platform   | Implementation Module | Backend Technology         |
//! |------------|----------------------|----------------------------|
//! | Linux      | `linux.rs`           | rtnetlink (NETLINK_ROUTE)  |
//! | FreeBSD    | `bsd.rs`             | PF_ROUTE + BPF             |
//! | OpenBSD    | `bsd.rs`             | PF_ROUTE + BPF             |
//! | NetBSD     | `bsd.rs`             | PF_ROUTE + BPF             |
//! | macOS      | `macos.rs`           | PF_ROUTE + BPF (macOS API) |
//!
//! # Factory Function: `create_platform_handler`
//!
//! The `create_platform_handler` function provides compile-time platform selection,
//! replacing C's runtime `#ifdef` checks with Rust's zero-cost abstraction. The function
//! returns a trait object (`Box<dyn NetworkPlatform>`) that encapsulates the platform-
//! specific implementation.
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::network::platform::create_platform_handler;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Automatically selects correct platform implementation at compile time
//!     let platform = create_platform_handler().await?;
//!     
//!     // Unified interface works across all platforms
//!     let interfaces = platform.enumerate_interfaces().await?;
//!     
//!     for iface in interfaces {
//!         if iface.is_up() && !iface.is_loopback() {
//!             println!("Active interface: {} with {} addresses",
//!                      iface.name, iface.addresses.len());
//!         }
//!     }
//!     
//!     // Subscribe to network topology changes
//!     let mut events = platform.subscribe_to_changes().await?;
//!     while let Some(event) = events.next().await {
//!         println!("Network event: {:?}", event);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Memory Safety Guarantees
//!
//! This module eliminates several classes of memory safety issues present in the C implementation:
//!
//! 1. **No manual memory management**: All structures use Rust's automatic Drop for cleanup
//! 2. **No pointer arithmetic**: Safe slice operations with compile-time bounds checking
//! 3. **No NULL pointer dereferences**: Option types make optionality explicit
//! 4. **No use-after-free**: Rust's borrow checker prevents accessing freed memory
//! 5. **No buffer overflows**: Vec and String provide automatic bounds checking
//! 6. **No data races**: Send/Sync traits ensure thread-safe sharing
//!
//! # Performance Characteristics
//!
//! - **Zero-cost abstraction**: Platform selection happens at compile time with no runtime overhead
//! - **Monomorphization**: Trait methods can be inlined for maximum performance
//! - **Async I/O**: Non-blocking network operations via tokio eliminate polling overhead
//! - **Efficient caching**: Interface name lookups cached to avoid repeated syscalls
//! - **Event-driven**: Push-based notifications (netlink/routing sockets) vs. polling
//!
//! # Thread Safety
//!
//! All platform implementations are `Send + Sync` and can be safely shared across async tasks
//! using `Arc<dyn NetworkPlatform>`. Internal state is protected by appropriate synchronization
//! primitives (Mutex, RwLock) where needed.

use std::boxed::Box;
use std::sync::Arc;

use crate::error::Result;

// Declare all platform-specific submodules
// These are conditionally compiled based on target_os
pub mod common;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub mod bsd;

#[cfg(target_os = "macos")]
pub mod macos;

// Re-export common types that are used across all platforms
// These types form the public API of the platform abstraction layer
pub use common::{InterfaceEvent, InterfaceFlags, NetworkInterface, NetworkPlatform};

/// Create a platform-specific network handler
///
/// This factory function provides compile-time platform selection, returning the appropriate
/// `NetworkPlatform` implementation for the target operating system. The selection happens
/// at compile time through Rust's `#[cfg]` conditional compilation, resulting in zero runtime
/// overhead compared to C's `#ifdef` preprocessor approach.
///
/// # Platform Selection Logic
///
/// - **Linux** (`target_os = "linux"`): Returns `LinuxNetworkPlatform` using rtnetlink
///   - Provides real-time interface monitoring via NETLINK_ROUTE multicast groups
///   - Superior performance through kernel push notifications vs. polling
///   - Supports all modern Linux distributions (kernels 2.6+)
///   - Compatible with Android AOSP builds
///
/// - **BSD** (`target_os = "freebsd" | "openbsd" | "netbsd"`): Returns `BsdNetworkPlatform`
///   - Uses PF_ROUTE routing sockets for interface change monitoring
///   - Berkeley Packet Filter (BPF) for raw packet access via `/dev/bpf*`
///   - ARP table enumeration via sysctl (NET_RT_FLAGS with RTF_LLINFO)
///   - Compatible with all BSD variants (FreeBSD 13+, OpenBSD 7+, NetBSD 9+)
///
/// - **macOS** (`target_os = "macos"`): Returns `MacOSNetworkPlatform`
///   - Similar to BSD but uses macOS-specific APIs (SO_BINDTOIF instead of SO_BINDTODEVICE)
///   - BPF device handling follows macOS patterns
///   - Excludes BSD features not supported on macOS (sysctl ARP enumeration)
///   - Compatible with macOS 10.15+ (Catalina and later)
///
/// # C Implementation Replacement
///
/// This function replaces the scattered platform detection logic from network.c:
///
/// ```c
/// // C implementation (network.c lines 100-180)
/// #ifdef HAVE_LINUX_NETWORK
///   if (netlink_init() == -1)
///     die("Failed to initialize netlink", NULL, EC_MISC);
///   daemon->netlinkfd = netlinkfd;
/// #elif defined(HAVE_BSD_NETWORK)
///   if (route_init() == -1)
///     die("Failed to initialize routing socket", NULL, EC_MISC);
///   daemon->routefd = routefd;
/// #elif defined(HAVE_SOLARIS_NETWORK)
///   // Solaris-specific initialization
/// #else
///   #error "No network platform defined"
/// #endif
/// ```
///
/// Rust equivalent (this function):
/// ```rust,ignore
/// let platform = create_platform_handler().await?;
/// // Platform-specific initialization encapsulated in implementation
/// ```
///
/// # Return Value
///
/// Returns `Box<dyn NetworkPlatform>` which provides dynamic dispatch to the platform-specific
/// implementation. The trait object allows uniform access to platform capabilities without
/// exposing implementation details to calling code.
///
/// The use of `Box` (heap allocation) instead of generic parameters allows this function to
/// be used in contexts where the concrete type cannot be determined at compile time (e.g.,
/// storing in structs with type erasure requirements).
///
/// # Errors
///
/// Returns platform-specific initialization errors:
///
/// - **Linux**: `NetworkError::NetlinkFailed` if netlink socket creation fails
///   - Insufficient permissions (requires CAP_NET_ADMIN or root)
///   - Netlink socket binding failure
///   - Background task spawning failure
///
/// - **BSD**: `NetworkError::RoutingFailed` if routing socket initialization fails
///   - Permission denied (requires root or specific capabilities)
///   - Routing socket creation failure
///   - BPF device access failure
///
/// - **macOS**: `NetworkError::RoutingFailed` similar to BSD
///   - BPF device enumeration failure
///   - SO_BINDTOIF ioctl failure
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust,ignore
/// use dnsmasq::network::platform::create_platform_handler;
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     let platform = create_platform_handler().await?;
///     let interfaces = platform.enumerate_interfaces().await?;
///     println!("Found {} network interfaces", interfaces.len());
///     Ok(())
/// }
/// ```
///
/// ## Storing in a Struct
///
/// ```rust,ignore
/// use dnsmasq::network::platform::{create_platform_handler, NetworkPlatform};
/// use std::sync::Arc;
///
/// struct NetworkManager {
///     platform: Arc<dyn NetworkPlatform>,
/// }
///
/// impl NetworkManager {
///     async fn new() -> Result<Self> {
///         let platform = create_platform_handler().await?;
///         Ok(Self { platform: Arc::from(platform) })
///     }
/// }
/// ```
///
/// ## Cross-Platform Network Monitoring
///
/// ```rust,ignore
/// use dnsmasq::network::platform::create_platform_handler;
/// use tokio_stream::StreamExt;
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     let platform = create_platform_handler().await?;
///     
///     // This code works identically on Linux, BSD, and macOS
///     let mut events = platform.subscribe_to_changes().await?;
///     while let Some(event) = events.next().await {
///         match event {
///             InterfaceEvent::AddressAdded { interface, address } => {
///                 println!("New address {} on {}", address, interface);
///             }
///             InterfaceEvent::LinkUp { interface } => {
///                 println!("Interface {} came up", interface);
///             }
///             _ => {}
///         }
///     }
///     
///     Ok(())
/// }
/// ```
///
/// # Performance Notes
///
/// - Platform selection happens at **compile time** with zero runtime overhead
/// - The returned trait object uses **dynamic dispatch** (vtable indirection)
/// - For maximum performance in hot paths, consider using generic parameters instead:
///   ```rust,ignore
///   async fn process<P: NetworkPlatform>(platform: &P) {
///       // Monomorphized for each platform type - no vtable overhead
///   }
///   ```
///
/// # Thread Safety
///
/// The returned `Box<dyn NetworkPlatform>` is `Send + Sync` and can be wrapped in `Arc`
/// for sharing across async tasks. All platform implementations guarantee thread-safe
/// operation through appropriate internal synchronization.
#[cfg(target_os = "linux")]
pub async fn create_platform_handler() -> Result<Box<dyn NetworkPlatform>> {
    use linux::LinuxNetworkPlatform;
    
    let platform = LinuxNetworkPlatform::new().await?;
    Ok(Box::new(platform) as Box<dyn NetworkPlatform>)
}

/// BSD platform handler creation (FreeBSD, OpenBSD, NetBSD)
///
/// See main function documentation for details. This variant is compiled when building
/// for BSD operating systems (FreeBSD, OpenBSD, NetBSD).
///
/// # Platform-Specific Notes
///
/// - **FreeBSD**: Full support for all features including ARP enumeration via sysctl
/// - **OpenBSD**: Full support with pledge/unveil security restrictions respected
/// - **NetBSD**: Full support with traditional BSD networking stack
///
/// All BSD variants use:
/// - PF_ROUTE routing sockets for interface monitoring (RTM_NEWADDR, RTM_DELADDR, RTM_IFINFO)
/// - Berkeley Packet Filter (BPF) via `/dev/bpf*` for raw packet access
/// - sysctl(NET_RT_FLAGS) for ARP table enumeration (except macOS)
/// - getifaddrs() for interface enumeration
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub async fn create_platform_handler() -> Result<Box<dyn NetworkPlatform>> {
    use bsd::BsdNetworkPlatform;
    
    let platform = BsdNetworkPlatform::new();
    Ok(Box::new(platform) as Box<dyn NetworkPlatform>)
}

/// macOS platform handler creation
///
/// See main function documentation for details. This variant is compiled when building
/// for macOS (Darwin).
///
/// # macOS-Specific Differences
///
/// - Uses **SO_BINDTOIF** instead of **SO_BINDTODEVICE** for interface binding
/// - BPF device enumeration follows macOS patterns (`/dev/bpf0` through `/dev/bpf255`)
/// - **Excludes** sysctl-based ARP enumeration (not supported on macOS)
/// - Routing socket messages have macOS-specific format variations (RTM_IFINFO2)
/// - Compatible with **macOS 10.15+** (Catalina and later recommended)
///
/// # Entitlements
///
/// macOS applications may require specific entitlements for network operations:
/// - `com.apple.security.network.client` for outbound connections
/// - `com.apple.security.network.server` for inbound connections
/// - BPF device access may require running as root or with proper sandbox exceptions
#[cfg(target_os = "macos")]
pub async fn create_platform_handler() -> Result<Box<dyn NetworkPlatform>> {
    use macos::MacOSNetworkPlatform;
    
    let platform = MacOSNetworkPlatform::new();
    Ok(Box::new(platform) as Box<dyn NetworkPlatform>)
}

/// Compile-time verification that at least one platform is supported
///
/// This ensures the crate fails to compile on unsupported platforms with a clear error
/// message, rather than producing a binary with missing functionality.
///
/// Supported platforms:
/// - Linux (all distributions with kernel 2.6+)
/// - FreeBSD 13+
/// - OpenBSD 7+
/// - NetBSD 9+
/// - macOS 10.15+ (Catalina and later)
///
/// If you encounter this error on a platform you believe should be supported, please
/// consider contributing a platform-specific implementation following the pattern of
/// existing implementations (linux.rs, bsd.rs, macos.rs).
#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
)))]
compile_error!(
    "Unsupported platform: dnsmasq requires Linux, FreeBSD, OpenBSD, NetBSD, or macOS. \
     Other Unix platforms may work but require platform-specific implementation in \
     src/network/platform/. Contributions welcome! See src/network/platform/mod.rs for details."
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that create_platform_handler succeeds on supported platforms
    ///
    /// This test verifies that the factory function can successfully create a platform
    /// handler on the current operating system. It doesn't test platform-specific
    /// functionality (that's handled by integration tests), just that the initialization
    /// succeeds without panicking.
    #[tokio::test]
    async fn test_create_platform_handler() {
        let result = create_platform_handler().await;
        assert!(
            result.is_ok(),
            "Platform handler creation should succeed on supported platforms"
        );
    }

    /// Test that NetworkInterface convenience methods work correctly
    ///
    /// This test validates the helper methods on NetworkInterface (is_up, is_loopback, etc.)
    /// to ensure flag checking logic is correct.
    #[test]
    fn test_interface_flags() {
        use common::{InterfaceFlags, NetworkInterface};

        let mut flags = InterfaceFlags::empty();
        flags.insert(InterfaceFlags::UP);
        flags.insert(InterfaceFlags::MULTICAST);

        let interface = NetworkInterface {
            name: "eth0".to_string(),
            index: 2,
            addresses: vec!["192.168.1.10".parse().unwrap()],
            netmask: Some("255.255.255.0".parse().unwrap()),
            broadcast: Some("192.168.1.255".parse().unwrap()),
            mtu: 1500,
            flags,
        };

        assert!(interface.is_up(), "Interface should be up");
        assert!(!interface.is_loopback(), "Interface should not be loopback");
        assert!(interface.is_multicast(), "Interface should support multicast");
        assert!(interface.is_usable(), "Interface should be usable");
    }

    /// Test that InterfaceFlags bitflags operations work correctly
    ///
    /// Validates type-safe flag manipulation replacing C's manual bit operations.
    #[test]
    fn test_interface_flags_operations() {
        use common::InterfaceFlags;

        let mut flags = InterfaceFlags::empty();
        assert!(flags.is_empty());

        flags.insert(InterfaceFlags::UP);
        assert!(flags.contains(InterfaceFlags::UP));
        assert!(!flags.contains(InterfaceFlags::LOOPBACK));

        flags.insert(InterfaceFlags::LOOPBACK);
        assert!(flags.contains(InterfaceFlags::UP | InterfaceFlags::LOOPBACK));

        flags.remove(InterfaceFlags::UP);
        assert!(!flags.contains(InterfaceFlags::UP));
        assert!(flags.contains(InterfaceFlags::LOOPBACK));
    }

    /// Test that InterfaceEvent variants can be constructed and matched
    ///
    /// Validates enum-based event representation for network topology changes.
    #[test]
    fn test_interface_events() {
        use common::InterfaceEvent;
        use std::net::{IpAddr, Ipv4Addr};

        let addr: IpAddr = Ipv4Addr::new(192, 168, 1, 10).into();
        let event = InterfaceEvent::AddressAdded {
            interface: "eth0".to_string(),
            address: addr,
        };

        match event {
            InterfaceEvent::AddressAdded { interface, address } => {
                assert_eq!(interface, "eth0");
                assert_eq!(address, addr);
            }
            _ => panic!("Expected AddressAdded event"),
        }
    }
}
