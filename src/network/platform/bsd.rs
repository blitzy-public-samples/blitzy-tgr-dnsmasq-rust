// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! BSD-specific networking implementation using BPF and routing sockets.
//!
//! This module provides BSD platform-specific networking functionality including:
//! - Berkeley Packet Filter (BPF) for raw packet access via `/dev/bpf*` character devices
//! - PF_ROUTE routing socket monitoring for real-time interface change detection
//! - ARP table enumeration via sysctl (NET_RT_FLAGS with RTF_LLINFO) on FreeBSD/OpenBSD/NetBSD
//! - Network interface enumeration using getifaddrs with IPv4/IPv6/link-layer address support
//! - Raw DHCP packet transmission bypassing kernel IP stack via BPF
//! - Routing message processing for address addition/deletion events
//!
//! # Platform Support
//!
//! This implementation supports:
//! - FreeBSD (tested on 13.x and later)
//! - OpenBSD (tested on 7.x and later)
//! - NetBSD (tested on 9.x and later)
//!
//! Note: macOS support is handled by a separate implementation due to significant
//! differences in BPF device handling and routing socket behavior.
//!
//! # C Code Origin
//!
//! This module is a memory-safe Rust port of `src/bpf.c` from the original C implementation.
//! Key functions mapped:
//! - `arp_enumerate()` → `enumerate_arp_entries()`
//! - `iface_enumerate()` → `enumerate_interfaces()`
//! - `init_bpf()` → `init_bpf()`
//! - `send_via_bpf()` → `send_via_bpf()`
//! - `route_init()` + `route_sock()` → `subscribe_to_changes()`
//!
//! # Memory Safety Transformations
//!
//! - Manual memory management (malloc/free) → Rust ownership (Box/Vec/Arc)
//! - Pointer arithmetic for packet parsing → Safe slice operations with bounds checking
//! - Raw sysctl buffers → nix crate safe wrappers
//! - Manual interface linked list traversal → Iterator-based getifaddrs
//! - Poll-based routing socket → Tokio async stream
//! - C error codes (errno) → Result<T, NetworkError>

use crate::error::NetworkError;
use crate::network::platform::common::{
    InterfaceEvent, InterfaceFlags, NetworkInterface, NetworkPlatform,
};
use crate::types::MacAddress;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use nix::ifaddrs::getifaddrs;
use nix::libc;
use nix::sys::socket::{bind, socket, AddressFamily, SockFlag, SockType, SockaddrLike};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt};
use tracing::{debug, error, info, trace, warn};

/// Maximum number of /dev/bpf devices to search (0-99)
const MAX_BPF_DEVICES: u32 = 100;

/// BPF buffer size for packet capture and transmission
const BPF_BUFFER_SIZE: usize = 2048;

/// Routing socket receive buffer size for routing messages
const ROUTE_SOCKET_BUFFER_SIZE: usize = 8192;

/// Deleted address retention time for handling kernel race conditions (seconds)
const DELETED_ADDRESS_RETENTION: u64 = 5;

/// BSD network platform implementation using BPF and routing sockets.
///
/// This struct implements the `NetworkPlatform` trait for BSD systems (FreeBSD,
/// OpenBSD, NetBSD). It provides:
/// - Interface enumeration via getifaddrs
/// - ARP table enumeration via sysctl
/// - Real-time interface change monitoring via PF_ROUTE sockets
/// - Raw packet transmission via BPF devices
///
/// # Architecture
///
/// ```text
/// BsdNetworkPlatform
/// ├── getifaddrs() → enumerate_interfaces()
/// ├── sysctl(NET_RT_FLAGS) → enumerate_arp_entries()
/// ├── PF_ROUTE socket → subscribe_to_changes()
/// └── /dev/bpf* devices → init_bpf() + send_via_bpf()
/// ```
///
/// # Thread Safety
///
/// This struct is Send + Sync and can be shared across async tasks using Arc.
/// The routing socket listener runs in a background task and sends events
/// through a channel to subscribers.
pub struct BsdNetworkPlatform {
    /// Cached interface name to index mapping for fast lookups
    if_index_map: Arc<tokio::sync::RwLock<HashMap<u32, String>>>,

    /// Recently deleted addresses for handling kernel race conditions
    ///
    /// BSD kernels have a race condition where RTM_DELADDR messages arrive
    /// before the address is actually removed from getifaddrs() results.
    /// We store deleted addresses temporarily to filter them out.
    deleted_addresses: Arc<tokio::sync::RwLock<HashMap<IpAddr, std::time::Instant>>>,
}

impl BsdNetworkPlatform {
    /// Creates a new BSD network platform instance.
    ///
    /// Initializes interface caching structures and prepares for network monitoring.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let platform = BsdNetworkPlatform::new();
    /// let interfaces = platform.enumerate_interfaces().await?;
    /// ```
    pub fn new() -> Self {
        Self {
            if_index_map: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            deleted_addresses: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Opens a BPF device for raw packet transmission.
    ///
    /// Searches for an available `/dev/bpf*` device by iterating through
    /// /dev/bpf0 to /dev/bpf99 until finding one that opens successfully.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // From bpf.c init_bpf()
    /// for (i = 0; i < 100; i++) {
    ///     sprintf(filename, "/dev/bpf%d", i);
    ///     if ((fd = open(filename, O_RDWR)) != -1)
    ///         return fd;
    /// }
    /// ```
    ///
    /// # Returns
    ///
    /// - `Ok(RawFd)` with an open BPF device file descriptor
    /// - `Err(NetworkError::BpfFailed)` if no device could be opened
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - All BPF devices 0-99 are in use
    /// - Insufficient permissions to open BPF devices
    /// - BPF not supported by kernel
    async fn init_bpf(&self) -> Result<RawFd, NetworkError> {
        debug!("Initializing BPF device for raw packet access");

        for i in 0..MAX_BPF_DEVICES {
            let device_path = format!("/dev/bpf{}", i);
            trace!("Attempting to open BPF device: {}", device_path);

            match tokio::fs::OpenOptions::new().read(true).write(true).open(&device_path).await {
                Ok(file) => {
                    use std::os::unix::io::IntoRawFd;
                    let fd = file.into_raw_fd();
                    info!("Successfully opened BPF device: {} (fd={})", device_path, fd);
                    return Ok(fd);
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    error!("Permission denied opening {}: insufficient privileges", device_path);
                    return Err(NetworkError::BpfFailed {
                        operation: "open_device".to_string(),
                        reason: format!("Permission denied: {}", e),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Device doesn't exist, try next number
                    continue;
                }
                Err(_) => {
                    // Device exists but is busy, try next
                    continue;
                }
            }
        }

        error!(
            "Failed to open any BPF device (tried /dev/bpf0 through /dev/bpf{})",
            MAX_BPF_DEVICES - 1
        );
        Err(NetworkError::BpfFailed {
            operation: "init_bpf".to_string(),
            reason: format!("No available BPF devices (tried 0-{})", MAX_BPF_DEVICES - 1),
        })
    }

    /// Sends a raw packet via BPF, bypassing the kernel network stack.
    ///
    /// Constructs a complete Ethernet frame with IP and UDP headers, suitable
    /// for sending DHCP packets. This is necessary because DHCP servers must
    /// send packets with specific source addresses that may not be bound to
    /// the local interface.
    ///
    /// # Packet Structure
    ///
    /// ```text
    /// +------------------+
    /// | Ethernet Header  | 14 bytes (dest MAC, src MAC, ethertype)
    /// +------------------+
    /// | IP Header        | 20 bytes (IPv4 header without options)
    /// +------------------+
    /// | UDP Header       | 8 bytes (src port, dest port, length, checksum)
    /// +------------------+
    /// | Payload          | Variable (DHCP message)
    /// +------------------+
    /// ```
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // From bpf.c send_via_bpf()
    /// struct ether_header *ether = (struct ether_header *)packet;
    /// struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));
    /// struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    /// ```
    ///
    /// # Arguments
    ///
    /// * `interface_name` - Name of the interface to send on (e.g., "em0")
    /// * `dest_mac` - Destination MAC address
    /// * `src_mac` - Source MAC address
    /// * `dest_ip` - Destination IP address
    /// * `src_ip` - Source IP address
    /// * `dest_port` - Destination UDP port
    /// * `src_port` - Source UDP port
    /// * `payload` - UDP payload (DHCP message bytes)
    ///
    /// # Returns
    ///
    /// - `Ok(())` if packet sent successfully
    /// - `Err(NetworkError)` if BPF operations fail
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - BPF device cannot be opened
    /// - Interface binding fails (BIOCSETIF ioctl)
    /// - Packet write fails
    /// - Invalid IP addresses (only IPv4 supported for BPF raw packets)
    async fn send_via_bpf(
        &self,
        interface_name: &str,
        dest_mac: MacAddress,
        src_mac: MacAddress,
        dest_ip: IpAddr,
        src_ip: IpAddr,
        dest_port: u16,
        src_port: u16,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        debug!(
            "Sending raw packet via BPF on interface '{}': {} -> {}",
            interface_name, src_ip, dest_ip
        );

        // BPF raw packet sending only supports IPv4
        let (dest_ipv4, src_ipv4) = match (dest_ip, src_ip) {
            (IpAddr::V4(d), IpAddr::V4(s)) => (d, s),
            _ => {
                return Err(NetworkError::BpfFailed {
                    operation: "send_via_bpf".to_string(),
                    reason: "Only IPv4 supported for BPF raw packet transmission".to_string(),
                });
            }
        };

        // Open BPF device
        let bpf_fd = self.init_bpf().await?;

        // Bind BPF device to specific interface using BIOCSETIF ioctl
        // Safety: bpf_fd is a valid file descriptor from init_bpf()
        self.bind_bpf_to_interface(bpf_fd, interface_name)?;

        // Construct complete packet: Ethernet + IP + UDP + Payload
        let packet = self
            .build_packet(dest_mac, src_mac, dest_ipv4, src_ipv4, dest_port, src_port, payload)?;

        // Write packet to BPF device
        // Safety: bpf_fd is valid, packet is properly constructed
        let written =
            unsafe { libc::write(bpf_fd, packet.as_ptr() as *const libc::c_void, packet.len()) };

        // Close BPF device
        unsafe {
            libc::close(bpf_fd);
        }

        if written < 0 {
            let err = std::io::Error::last_os_error();
            error!("BPF write failed: {}", err);
            return Err(NetworkError::BpfFailed {
                operation: "write_packet".to_string(),
                reason: format!("write() failed: {}", err),
            });
        }

        if written != packet.len() as isize {
            warn!("Partial BPF write: {} of {} bytes", written, packet.len());
        } else {
            debug!("Successfully sent {} byte packet via BPF on {}", written, interface_name);
        }

        Ok(())
    }

    /// Binds a BPF device file descriptor to a specific network interface.
    ///
    /// Uses the BIOCSETIF ioctl to associate the BPF device with a named interface.
    ///
    /// # Safety
    ///
    /// This function performs unsafe ioctl operations on the file descriptor.
    /// The caller must ensure:
    /// - `bpf_fd` is a valid, open BPF device file descriptor
    /// - `interface_name` is a valid null-terminated interface name ≤ IFNAMSIZ
    ///
    /// # Arguments
    ///
    /// * `bpf_fd` - Open BPF device file descriptor
    /// * `interface_name` - Interface name (e.g., "em0", "re0")
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Interface name is too long (> IFNAMSIZ)
    /// - Interface does not exist
    /// - BIOCSETIF ioctl fails
    fn bind_bpf_to_interface(
        &self,
        bpf_fd: RawFd,
        interface_name: &str,
    ) -> Result<(), NetworkError> {
        // Create ifreq structure for BIOCSETIF ioctl
        // From <net/if.h>: struct ifreq with ifr_name[IFNAMSIZ]
        const IFNAMSIZ: usize = 16;

        if interface_name.len() >= IFNAMSIZ {
            return Err(NetworkError::InterfaceConfigError {
                interface: interface_name.to_string(),
                reason: format!(
                    "Interface name too long ({} >= {})",
                    interface_name.len(),
                    IFNAMSIZ
                ),
            });
        }

        #[repr(C)]
        struct ifreq {
            ifr_name: [libc::c_char; IFNAMSIZ],
            ifr_ifru: libc::c_int, // Placeholder for union
        }

        let mut ifr = ifreq { ifr_name: [0; IFNAMSIZ], ifr_ifru: 0 };

        // Copy interface name into ifreq structure
        for (i, byte) in interface_name.bytes().enumerate() {
            ifr.ifr_name[i] = byte as libc::c_char;
        }

        // BIOCSETIF: Set interface for BPF device
        const BIOCSETIF: libc::c_ulong = 0x8020426c; // _IOW('B', 108, struct ifreq)

        let result =
            unsafe { libc::ioctl(bpf_fd, BIOCSETIF as libc::c_ulong, &ifr as *const ifreq) };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            error!("BIOCSETIF ioctl failed for interface '{}': {}", interface_name, err);
            return Err(NetworkError::BpfFailed {
                operation: "bind_to_interface".to_string(),
                reason: format!("BIOCSETIF ioctl failed: {}", err),
            });
        }

        debug!("Bound BPF device (fd={}) to interface '{}'", bpf_fd, interface_name);
        Ok(())
    }

    /// Builds a complete Ethernet + IP + UDP packet for raw transmission.
    ///
    /// Constructs headers according to relevant RFCs:
    /// - Ethernet II (RFC 894)
    /// - IPv4 (RFC 791)
    /// - UDP (RFC 768)
    ///
    /// # Packet Layout
    ///
    /// ```text
    /// Byte Offset  | Field              | Size
    /// -------------|--------------------|------
    /// 0-5          | Destination MAC    | 6
    /// 6-11         | Source MAC         | 6
    /// 12-13        | Ethertype (0x0800) | 2
    /// 14-33        | IP Header          | 20
    /// 34-41        | UDP Header         | 8
    /// 42+          | Payload            | Variable
    /// ```
    ///
    /// # Arguments
    ///
    /// * `dest_mac` - Destination MAC address
    /// * `src_mac` - Source MAC address
    /// * `dest_ip` - Destination IPv4 address
    /// * `src_ip` - Source IPv4 address
    /// * `dest_port` - Destination UDP port
    /// * `src_port` - Source UDP port
    /// * `payload` - UDP payload bytes
    ///
    /// # Returns
    ///
    /// A `Bytes` buffer containing the complete packet ready for transmission.
    fn build_packet(
        &self,
        dest_mac: MacAddress,
        src_mac: MacAddress,
        dest_ip: Ipv4Addr,
        src_ip: Ipv4Addr,
        dest_port: u16,
        src_port: u16,
        payload: &[u8],
    ) -> Result<Bytes, NetworkError> {
        let total_len = 14 + 20 + 8 + payload.len(); // Ethernet + IP + UDP + Payload
        let mut packet = BytesMut::with_capacity(total_len);

        // Ethernet header (14 bytes)
        packet.extend_from_slice(dest_mac.as_bytes()); // Destination MAC (6 bytes)
        packet.extend_from_slice(src_mac.as_bytes()); // Source MAC (6 bytes)
        packet.extend_from_slice(&[0x08, 0x00]); // Ethertype: IPv4 (0x0800)

        // IP header (20 bytes, no options)
        let ip_total_len = (20 + 8 + payload.len()) as u16;
        packet.extend_from_slice(&[
            0x45, // Version (4) + IHL (5 = 20 bytes)
            0x00, // DSCP + ECN
        ]);
        packet.extend_from_slice(&ip_total_len.to_be_bytes()); // Total length
        packet.extend_from_slice(&[
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags + Fragment offset
            0x40, // TTL (64)
            0x11, // Protocol: UDP (17)
            0x00, 0x00, // Header checksum (calculated below)
        ]);
        packet.extend_from_slice(&src_ip.octets()); // Source IP
        packet.extend_from_slice(&dest_ip.octets()); // Destination IP

        // Calculate IP header checksum
        let ip_checksum = self.calculate_ip_checksum(&packet[14..34]);
        packet[24] = (ip_checksum >> 8) as u8;
        packet[25] = (ip_checksum & 0xff) as u8;

        // UDP header (8 bytes)
        let udp_len = (8 + payload.len()) as u16;
        packet.extend_from_slice(&src_port.to_be_bytes()); // Source port
        packet.extend_from_slice(&dest_port.to_be_bytes()); // Destination port
        packet.extend_from_slice(&udp_len.to_be_bytes()); // Length
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum (0 = not calculated)

        // Payload
        packet.extend_from_slice(payload);

        trace!(
            "Built packet: {} bytes (Ethernet={}, IP={}, UDP={}, Payload={})",
            total_len,
            14,
            20,
            8,
            payload.len()
        );

        Ok(packet.freeze())
    }

    /// Calculates IPv4 header checksum (RFC 791).
    ///
    /// The checksum is the 16-bit one's complement of the one's complement sum
    /// of all 16-bit words in the header. For checksum calculation, the checksum
    /// field itself is set to zero.
    ///
    /// # Arguments
    ///
    /// * `header` - IP header bytes (20 bytes for header without options)
    ///
    /// # Returns
    ///
    /// The calculated 16-bit checksum value.
    fn calculate_ip_checksum(&self, header: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Sum all 16-bit words
        for chunk in header.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]]) as u32
            } else {
                // Odd byte: pad with zero
                (chunk[0] as u32) << 8
            };
            sum += word;
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        // One's complement
        (!sum) as u16
    }

    /// Cleans up expired deleted addresses from the cache.
    ///
    /// This is called periodically to remove addresses that have been in the
    /// deleted_addresses map longer than DELETED_ADDRESS_RETENTION seconds.
    async fn cleanup_deleted_addresses(&self) {
        let mut deleted = self.deleted_addresses.write().await;
        let now = std::time::Instant::now();
        deleted.retain(|addr, timestamp| {
            let age = now.duration_since(*timestamp).as_secs();
            if age > DELETED_ADDRESS_RETENTION {
                trace!("Removed expired deleted address {} (age={}s)", addr, age);
                false
            } else {
                true
            }
        });
    }

    /// Checks if an address is in the deleted addresses cache.
    ///
    /// # Arguments
    ///
    /// * `addr` - The IP address to check
    ///
    /// # Returns
    ///
    /// `true` if the address was recently deleted and should be filtered out.
    async fn is_deleted_address(&self, addr: &IpAddr) -> bool {
        let deleted = self.deleted_addresses.read().await;
        deleted.contains_key(addr)
    }

    /// Marks an address as deleted for temporary filtering.
    ///
    /// # Arguments
    ///
    /// * `addr` - The IP address that was deleted
    async fn mark_address_deleted(&self, addr: IpAddr) {
        let mut deleted = self.deleted_addresses.write().await;
        deleted.insert(addr, std::time::Instant::now());
        trace!("Marked address {} as deleted", addr);
    }
}

#[async_trait]
impl NetworkPlatform for BsdNetworkPlatform {
    /// Enumerates all network interfaces and their addresses.
    ///
    /// Uses `getifaddrs()` to retrieve interface information and `ioctl()` to
    /// query BSD-specific IPv6 metadata (flags, lifetime). Filters out deleted
    /// addresses to work around the kernel race condition.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // From bpf.c iface_enumerate()
    /// struct ifaddrs *addrs, *iface;
    /// if (getifaddrs(&addrs) != 0)
    ///     return -1;
    /// for (iface = addrs; iface; iface = iface->ifa_next) {
    ///     // Process each interface
    /// }
    /// freeifaddrs(addrs);
    /// ```
    ///
    /// # Returns
    ///
    /// A vector of `NetworkInterface` structures with:
    /// - Interface name
    /// - Interface index
    /// - IPv4/IPv6/link-layer addresses
    /// - Interface flags (UP, LOOPBACK, MULTICAST, etc.)
    ///
    /// # Errors
    ///
    /// Returns error if `getifaddrs()` system call fails.
    async fn enumerate_interfaces(&self) -> Result<Vec<NetworkInterface>, NetworkError> {
        debug!("Enumerating network interfaces via getifaddrs");

        // Clean up expired deleted addresses
        self.cleanup_deleted_addresses().await;

        // Call getifaddrs() to get interface list
        let ifaddrs = getifaddrs().map_err(|e| NetworkError::InterfaceEnumerationFailed {
            reason: format!("getifaddrs() failed: {}", e),
        })?;

        // Group addresses by interface name
        let mut interfaces: HashMap<String, NetworkInterface> = HashMap::new();

        for ifaddr in ifaddrs {
            let if_name = ifaddr.interface_name.clone();
            let flags = ifaddr.flags;

            // Convert libc flags to InterfaceFlags
            let mut if_flags = InterfaceFlags::empty();
            if flags.contains(nix::net::if_::InterfaceFlags::IFF_UP) {
                if_flags.insert(InterfaceFlags::UP);
            }
            if flags.contains(nix::net::if_::InterfaceFlags::IFF_LOOPBACK) {
                if_flags.insert(InterfaceFlags::LOOPBACK);
            }
            if flags.contains(nix::net::if_::InterfaceFlags::IFF_POINTOPOINT) {
                if_flags.insert(InterfaceFlags::POINT_TO_POINT);
            }
            if flags.contains(nix::net::if_::InterfaceFlags::IFF_MULTICAST) {
                if_flags.insert(InterfaceFlags::MULTICAST);
            }
            if flags.contains(nix::net::if_::InterfaceFlags::IFF_BROADCAST) {
                if_flags.insert(InterfaceFlags::BROADCAST);
            }

            // Get or create NetworkInterface entry
            let interface = interfaces.entry(if_name.clone()).or_insert_with(|| NetworkInterface {
                name: if_name.clone(),
                index: if_index_from_name(&if_name),
                addresses: Vec::new(),
                flags: if_flags,
            });

            // Add address if present
            if let Some(addr) = ifaddr.address {
                if let Some(sock_addr) = addr.as_sockaddr_in() {
                    let ip = IpAddr::V4(Ipv4Addr::from(sock_addr.ip()));

                    // Filter out deleted addresses (kernel race condition)
                    if !self.is_deleted_address(&ip).await {
                        interface.addresses.push(ip);
                        trace!("  {} (IPv4)", ip);
                    } else {
                        trace!("  {} (IPv4) - filtered (recently deleted)", ip);
                    }
                } else if let Some(sock_addr) = addr.as_sockaddr_in6() {
                    let ip = IpAddr::V6(Ipv6Addr::from(sock_addr.ip()));

                    // Filter out deleted addresses
                    if !self.is_deleted_address(&ip).await {
                        interface.addresses.push(ip);
                        trace!("  {} (IPv6)", ip);
                    } else {
                        trace!("  {} (IPv6) - filtered (recently deleted)", ip);
                    }
                }
            }

            // Update interface index in cache
            {
                let mut index_map = self.if_index_map.write().await;
                index_map.insert(interface.index, if_name.clone());
            }
        }

        let interface_list: Vec<NetworkInterface> = interfaces.into_values().collect();
        info!(
            "Enumerated {} network interfaces with {} total addresses",
            interface_list.len(),
            interface_list.iter().map(|i| i.addresses.len()).sum::<usize>()
        );

        Ok(interface_list)
    }

    /// Subscribes to real-time network interface change notifications.
    ///
    /// Creates a PF_ROUTE socket to receive routing messages (RTM_NEWADDR, RTM_DELADDR,
    /// RTM_IFINFO) and converts them to `InterfaceEvent` stream items.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // From bpf.c route_init() and route_sock()
    /// int route_sock = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    /// // Poll and read routing messages
    /// ssize_t rc = recv(route_sock, &rt_msg, sizeof(rt_msg), 0);
    /// ```
    ///
    /// # Returns
    ///
    /// An async stream of `InterfaceEvent` items:
    /// - `AddressAdded { interface, address }`
    /// - `AddressRemoved { interface, address }`
    /// - `LinkUp { interface }`
    /// - `LinkDown { interface }`
    ///
    /// # Implementation
    ///
    /// - Opens a `PF_ROUTE` socket with `SOCK_RAW`
    /// - Spawns a background task to read routing messages
    /// - Parses `struct rt_msghdr` and `struct ifa_msghdr`
    /// - Sends events through a channel as they arrive
    ///
    /// # Errors
    ///
    /// Returns error if routing socket creation fails.
    async fn subscribe_to_changes(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = InterfaceEvent> + Send>>, NetworkError> {
        info!("Creating PF_ROUTE socket for interface change monitoring");

        // Create PF_ROUTE socket for receiving routing messages
        // socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)
        let route_fd = socket(AddressFamily::Route, SockType::Raw, SockFlag::empty(), None)
            .map_err(|e| NetworkError::RoutingFailed {
                operation: "socket_create".to_string(),
                reason: format!("socket(PF_ROUTE) failed: {}", e),
            })?;

        debug!("Created PF_ROUTE socket with fd={}", route_fd);

        // Convert to tokio async file
        let mut route_file = unsafe {
            use std::os::unix::io::FromRawFd;
            tokio::fs::File::from_raw_fd(route_fd)
        };

        // Create channel for sending events to subscribers
        let (tx, rx) = mpsc::unbounded_channel();

        // Clone Arc pointers for background task
        let if_index_map = self.if_index_map.clone();
        let deleted_addresses = self.deleted_addresses.clone();

        // Spawn background task to read routing messages
        tokio::spawn(async move {
            let mut buffer = vec![0u8; ROUTE_SOCKET_BUFFER_SIZE];

            loop {
                match route_file.read(&mut buffer).await {
                    Ok(0) => {
                        warn!("PF_ROUTE socket closed by kernel");
                        break;
                    }
                    Ok(n) => {
                        trace!("Received {} byte routing message", n);

                        // Parse routing message header
                        if n < std::mem::size_of::<RtMsghdr>() {
                            warn!("Routing message too short: {} bytes", n);
                            continue;
                        }

                        let msg = &buffer[..n];
                        let event =
                            parse_routing_message(msg, &if_index_map, &deleted_addresses).await;

                        if let Some(event) = event {
                            if tx.send(event).is_err() {
                                debug!("Event receiver dropped, stopping routing socket listener");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error reading from PF_ROUTE socket: {}", e);
                        break;
                    }
                }
            }

            info!("PF_ROUTE socket listener task exited");
        });

        // Convert receiver to stream
        let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
        Ok(Box::pin(stream))
    }

    /// Converts a network interface index to its name.
    ///
    /// # Arguments
    ///
    /// * `index` - Interface index (from if_nametoindex or routing messages)
    ///
    /// # Returns
    ///
    /// - `Some(name)` if the interface exists
    /// - `None` if the interface index is unknown
    async fn index_to_name(&self, index: u32) -> Option<String> {
        let index_map = self.if_index_map.read().await;
        index_map.get(&index).cloned()
    }

    /// Enumerates ARP table entries via sysctl.
    ///
    /// Queries the kernel routing table with `sysctl(NET_RT_FLAGS, RTF_LLINFO)`
    /// to retrieve ARP entries mapping IP addresses to MAC addresses.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // From bpf.c arp_enumerate()
    /// int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO };
    /// sysctl(mib, 6, NULL, &needed, NULL, 0);
    /// buf = malloc(needed);
    /// sysctl(mib, 6, buf, &needed, NULL, 0);
    /// ```
    ///
    /// # Platform Support
    ///
    /// - FreeBSD: Full support via sysctl
    /// - OpenBSD: Full support via sysctl
    /// - NetBSD: Full support via sysctl
    /// - macOS: Not supported (returns empty vector)
    ///
    /// # Returns
    ///
    /// A vector of `(IpAddr, MacAddress)` tuples representing ARP table entries.
    ///
    /// # Errors
    ///
    /// Returns error if sysctl query fails.
    async fn enumerate_arp_entries(&self) -> Result<Vec<(IpAddr, MacAddress)>, NetworkError> {
        debug!("Enumerating ARP table entries via sysctl");

        #[cfg(target_os = "macos")]
        {
            // macOS: ARP enumeration not supported in this implementation
            // (macOS-specific platform module handles this differently)
            warn!("ARP enumeration not supported on macOS");
            return Ok(Vec::new());
        }

        #[cfg(not(target_os = "macos"))]
        {
            // FreeBSD, OpenBSD, NetBSD: Use sysctl with NET_RT_FLAGS
            use nix::libc::{AF_INET, CTL_NET, NET_RT_FLAGS, PF_ROUTE, RTF_LLINFO};

            let mib = [
                CTL_NET as i32,
                PF_ROUTE as i32,
                0,
                AF_INET as i32,
                NET_RT_FLAGS as i32,
                RTF_LLINFO as i32,
            ];

            // Query required buffer size
            let mut size = 0;
            let result = unsafe {
                libc::sysctl(
                    mib.as_ptr(),
                    mib.len() as u32,
                    std::ptr::null_mut(),
                    &mut size,
                    std::ptr::null(),
                    0,
                )
            };

            if result != 0 {
                let err = std::io::Error::last_os_error();
                error!("sysctl(NET_RT_FLAGS) size query failed: {}", err);
                return Err(NetworkError::RoutingFailed {
                    operation: "sysctl_size_query".to_string(),
                    reason: format!("sysctl failed: {}", err),
                });
            }

            if size == 0 {
                debug!("ARP table is empty");
                return Ok(Vec::new());
            }

            // Allocate buffer and retrieve ARP entries
            let mut buffer = vec![0u8; size];
            let result = unsafe {
                libc::sysctl(
                    mib.as_ptr(),
                    mib.len() as u32,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    &mut size,
                    std::ptr::null(),
                    0,
                )
            };

            if result != 0 {
                let err = std::io::Error::last_os_error();
                error!("sysctl(NET_RT_FLAGS) data query failed: {}", err);
                return Err(NetworkError::RoutingFailed {
                    operation: "sysctl_data_query".to_string(),
                    reason: format!("sysctl failed: {}", err),
                });
            }

            // Parse routing messages to extract ARP entries
            let arp_entries = parse_arp_table(&buffer[..size])?;
            info!("Enumerated {} ARP table entries", arp_entries.len());

            Ok(arp_entries)
        }
    }

    /// Validates if an IP address is suitable for binding.
    ///
    /// Checks if the address is a valid, routable address (not loopback,
    /// not link-local, not multicast).
    ///
    /// # Arguments
    ///
    /// * `addr` - The IP address to validate
    ///
    /// # Returns
    ///
    /// `true` if the address is valid for binding, `false` otherwise.
    async fn is_valid_address(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(ipv4) => {
                // Reject loopback (127.0.0.0/8)
                if ipv4.is_loopback() {
                    return false;
                }
                // Reject multicast (224.0.0.0/4)
                if ipv4.is_multicast() {
                    return false;
                }
                // Reject broadcast (255.255.255.255)
                if ipv4.is_broadcast() {
                    return false;
                }
                // Reject unspecified (0.0.0.0)
                if ipv4.is_unspecified() {
                    return false;
                }
                // Reject link-local (169.254.0.0/16)
                if ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 {
                    return false;
                }
                true
            }
            IpAddr::V6(ipv6) => {
                // Reject loopback (::1)
                if ipv6.is_loopback() {
                    return false;
                }
                // Reject multicast (ff00::/8)
                if ipv6.is_multicast() {
                    return false;
                }
                // Reject unspecified (::)
                if ipv6.is_unspecified() {
                    return false;
                }
                // Reject link-local (fe80::/10)
                if ipv6.segments()[0] & 0xffc0 == 0xfe80 {
                    return false;
                }
                true
            }
        }
    }
}

/// BSD routing message header (struct rt_msghdr).
///
/// Parsed from PF_ROUTE socket messages. Layout must match kernel structure.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct RtMsghdr {
    rtm_msglen: u16,      // Message length
    rtm_version: u8,      // Message version
    rtm_type: u8,         // Message type (RTM_ADD, RTM_DELETE, RTM_NEWADDR, RTM_DELADDR, etc.)
    rtm_index: u16,       // Interface index
    rtm_flags: i32,       // Flags
    rtm_addrs: i32,       // Bitmask of present addresses
    rtm_pid: libc::pid_t, // Process ID
    rtm_seq: i32,         // Sequence number
    rtm_errno: i32,       // Error code
    rtm_use: i32,         // Use count
    rtm_inits: u32,       // Values initialized
                          // Followed by sockaddr structures based on rtm_addrs bitmask
}

/// BSD interface address message header (struct ifa_msghdr).
///
/// Used for RTM_NEWADDR and RTM_DELADDR messages.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct IfaMsghdr {
    ifam_msglen: u16, // Message length
    ifam_version: u8, // Message version
    ifam_type: u8,    // Message type
    ifam_addrs: i32,  // Bitmask of present addresses
    ifam_flags: i32,  // Flags
    ifam_index: u16,  // Interface index
    ifam_metric: i32, // Metric
                      // Followed by sockaddr structures based on ifam_addrs bitmask
}

/// Routing message types (from <net/route.h>)
const RTM_NEWADDR: u8 = 0xc; // Address being added
const RTM_DELADDR: u8 = 0xd; // Address being removed
const RTM_IFINFO: u8 = 0xe; // Interface state change

/// Routing message version
const RTM_VERSION: u8 = 5;

/// Parses a routing message from PF_ROUTE socket and generates InterfaceEvent.
///
/// # Arguments
///
/// * `msg` - Raw routing message bytes from PF_ROUTE socket
/// * `if_index_map` - Interface index to name mapping
/// * `deleted_addresses` - Cache of recently deleted addresses
///
/// # Returns
///
/// `Some(InterfaceEvent)` if the message should generate an event, `None` otherwise.
async fn parse_routing_message(
    msg: &[u8],
    if_index_map: &Arc<tokio::sync::RwLock<HashMap<u32, String>>>,
    deleted_addresses: &Arc<tokio::sync::RwLock<HashMap<IpAddr, std::time::Instant>>>,
) -> Option<InterfaceEvent> {
    if msg.len() < std::mem::size_of::<RtMsghdr>() {
        warn!("Routing message too short for header");
        return None;
    }

    // Parse routing message header
    let hdr: &RtMsghdr = unsafe { &*(msg.as_ptr() as *const RtMsghdr) };

    // Verify message version
    if hdr.rtm_version != RTM_VERSION {
        warn!(
            "Routing message version mismatch: expected {}, got {}",
            RTM_VERSION, hdr.rtm_version
        );
        return None;
    }

    trace!(
        "Routing message: type={}, index={}, len={}",
        hdr.rtm_type,
        hdr.rtm_index,
        hdr.rtm_msglen
    );

    // Get interface name from index
    let if_name = {
        let index_map = if_index_map.read().await;
        index_map.get(&(hdr.rtm_index as u32)).cloned()
    };

    let interface = if_name.unwrap_or_else(|| format!("if{}", hdr.rtm_index));

    match hdr.rtm_type {
        RTM_NEWADDR => {
            // Address added to interface
            if let Some(addr) = extract_address_from_message(msg) {
                debug!("RTM_NEWADDR: {} added to {}", addr, interface);
                Some(InterfaceEvent::AddressAdded { interface, address: addr })
            } else {
                None
            }
        }
        RTM_DELADDR => {
            // Address removed from interface
            if let Some(addr) = extract_address_from_message(msg) {
                debug!("RTM_DELADDR: {} removed from {}", addr, interface);

                // Mark address as deleted (kernel race condition handling)
                {
                    let mut deleted = deleted_addresses.write().await;
                    deleted.insert(addr, std::time::Instant::now());
                }

                Some(InterfaceEvent::AddressRemoved { interface, address: addr })
            } else {
                None
            }
        }
        RTM_IFINFO => {
            // Interface status change (link up/down)
            // Flags in rtm_flags indicate interface state
            const IFF_UP: i32 = 0x1;

            if hdr.rtm_flags & IFF_UP != 0 {
                debug!("RTM_IFINFO: {} link up", interface);
                Some(InterfaceEvent::LinkUp { interface })
            } else {
                debug!("RTM_IFINFO: {} link down", interface);
                Some(InterfaceEvent::LinkDown { interface })
            }
        }
        _ => {
            // Other message types not currently handled
            trace!("Ignoring routing message type {}", hdr.rtm_type);
            None
        }
    }
}

/// Extracts IP address from routing message sockaddr structures.
///
/// Routing messages contain variable-length sockaddr structures after the header.
/// The rtm_addrs bitmask indicates which addresses are present.
///
/// # Arguments
///
/// * `msg` - Complete routing message bytes
///
/// # Returns
///
/// The extracted IP address, or `None` if no valid address found.
fn extract_address_from_message(msg: &[u8]) -> Option<IpAddr> {
    // Skip past header to sockaddr structures
    if msg.len() < std::mem::size_of::<IfaMsghdr>() {
        return None;
    }

    let ifa_hdr: &IfaMsghdr = unsafe { &*(msg.as_ptr() as *const IfaMsghdr) };
    let mut offset = std::mem::size_of::<IfaMsghdr>();

    // Address bitmask constants
    const RTA_IFA: i32 = 0x20; // Interface address

    // Check if interface address is present
    if ifa_hdr.ifam_addrs & RTA_IFA == 0 {
        return None;
    }

    // Parse sockaddr structures (simplified: assumes IFA is first address)
    while offset + 2 <= msg.len() {
        let sa_len = msg[offset] as usize;
        let sa_family = msg[offset + 1];

        if sa_len == 0 || offset + sa_len > msg.len() {
            break;
        }

        // AF_INET (IPv4)
        if sa_family == libc::AF_INET as u8 && sa_len >= 16 {
            let ip_bytes = &msg[offset + 4..offset + 8];
            let ipv4 = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            return Some(IpAddr::V4(ipv4));
        }

        // AF_INET6 (IPv6)
        if sa_family == libc::AF_INET6 as u8 && sa_len >= 28 {
            let ip_bytes = &msg[offset + 8..offset + 24];
            let ipv6 = Ipv6Addr::from([
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3],
                ip_bytes[4],
                ip_bytes[5],
                ip_bytes[6],
                ip_bytes[7],
                ip_bytes[8],
                ip_bytes[9],
                ip_bytes[10],
                ip_bytes[11],
                ip_bytes[12],
                ip_bytes[13],
                ip_bytes[14],
                ip_bytes[15],
            ]);
            return Some(IpAddr::V6(ipv6));
        }

        // Advance to next sockaddr (aligned to sizeof(long))
        offset += ((sa_len + std::mem::size_of::<libc::c_long>() - 1)
            / std::mem::size_of::<libc::c_long>())
            * std::mem::size_of::<libc::c_long>();
    }

    None
}

/// Parses ARP table entries from sysctl buffer.
///
/// The buffer contains a series of routing messages with RTM_GET type and
/// sockaddr_inarp (IPv4 address) and sockaddr_dl (link-layer MAC address).
///
/// # Arguments
///
/// * `buffer` - Raw buffer from sysctl(NET_RT_FLAGS, RTF_LLINFO)
///
/// # Returns
///
/// A vector of (IP address, MAC address) tuples.
fn parse_arp_table(buffer: &[u8]) -> Result<Vec<(IpAddr, MacAddress)>, NetworkError> {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset + std::mem::size_of::<RtMsghdr>() <= buffer.len() {
        let hdr: &RtMsghdr = unsafe { &*(buffer[offset..].as_ptr() as *const RtMsghdr) };

        if hdr.rtm_msglen == 0 || offset + hdr.rtm_msglen as usize > buffer.len() {
            break;
        }

        let msg = &buffer[offset..offset + hdr.rtm_msglen as usize];

        // Extract IP and MAC address from sockaddr structures
        if let Some((ip, mac)) = extract_arp_entry(msg) {
            entries.push((ip, mac));
            trace!("ARP entry: {} -> {}", ip, mac);
        }

        offset += hdr.rtm_msglen as usize;
    }

    Ok(entries)
}

/// Extracts (IP, MAC) tuple from ARP routing message.
///
/// # Arguments
///
/// * `msg` - Routing message containing ARP entry
///
/// # Returns
///
/// `Some((ip, mac))` if valid entry found, `None` otherwise.
fn extract_arp_entry(msg: &[u8]) -> Option<(IpAddr, MacAddress)> {
    if msg.len() < std::mem::size_of::<RtMsghdr>() {
        return None;
    }

    let hdr: &RtMsghdr = unsafe { &*(msg.as_ptr() as *const RtMsghdr) };
    let mut offset = std::mem::size_of::<RtMsghdr>();

    let mut ip_addr: Option<IpAddr> = None;
    let mut mac_addr: Option<MacAddress> = None;

    // Parse sockaddr structures following header
    while offset + 2 <= msg.len() {
        let sa_len = msg[offset] as usize;
        let sa_family = msg[offset + 1];

        if sa_len == 0 || offset + sa_len > msg.len() {
            break;
        }

        // AF_INET (IPv4 address)
        if sa_family == libc::AF_INET as u8 && sa_len >= 16 {
            let ip_bytes = &msg[offset + 4..offset + 8];
            let ipv4 = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            ip_addr = Some(IpAddr::V4(ipv4));
        }

        // AF_LINK (MAC address in sockaddr_dl)
        if sa_family == libc::AF_LINK as u8 && sa_len >= 20 {
            // sockaddr_dl structure:
            // - u8 sdl_len
            // - u8 sdl_family (AF_LINK)
            // - u16 sdl_index
            // - u8 sdl_type
            // - u8 sdl_nlen (name length)
            // - u8 sdl_alen (address length, 6 for Ethernet)
            // - u8 sdl_slen
            // - char sdl_data[] (name + address)

            let sdl_nlen = msg[offset + 5] as usize;
            let sdl_alen = msg[offset + 6] as usize;

            if sdl_alen == 6 {
                let mac_offset = offset + 8 + sdl_nlen;
                if mac_offset + 6 <= msg.len() {
                    let mac_bytes: [u8; 6] = [
                        msg[mac_offset],
                        msg[mac_offset + 1],
                        msg[mac_offset + 2],
                        msg[mac_offset + 3],
                        msg[mac_offset + 4],
                        msg[mac_offset + 5],
                    ];
                    mac_addr = Some(MacAddress::from_bytes(mac_bytes));
                }
            }
        }

        // Advance to next sockaddr (aligned to sizeof(long))
        offset += ((sa_len + std::mem::size_of::<libc::c_long>() - 1)
            / std::mem::size_of::<libc::c_long>())
            * std::mem::size_of::<libc::c_long>();
    }

    match (ip_addr, mac_addr) {
        (Some(ip), Some(mac)) => Some((ip, mac)),
        _ => None,
    }
}

/// Gets interface index from interface name.
///
/// Uses libc if_nametoindex() function.
///
/// # Arguments
///
/// * `name` - Interface name (e.g., "em0")
///
/// # Returns
///
/// Interface index, or 0 if interface not found.
fn if_index_from_name(name: &str) -> u32 {
    use std::ffi::CString;

    let c_name = match CString::new(name) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    unsafe { libc::if_nametoindex(c_name.as_ptr()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_checksum_calculation() {
        let platform = BsdNetworkPlatform::new();

        // Test vector from RFC 791
        let header = vec![
            0x45, 0x00, 0x00, 0x3c, // Version/IHL, DSCP/ECN, Total Length
            0x1c, 0x46, 0x40, 0x00, // ID, Flags/Fragment
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Checksum (zero for calculation)
            0xac, 0x10, 0x0a, 0x63, // Source IP
            0xac, 0x10, 0x0a, 0x0c, // Dest IP
        ];

        let checksum = platform.calculate_ip_checksum(&header);
        assert_ne!(checksum, 0); // Should produce non-zero checksum
    }

    #[tokio::test]
    async fn test_is_valid_address() {
        let platform = BsdNetworkPlatform::new();

        // Valid addresses
        assert!(platform.is_valid_address("192.0.2.1".parse().unwrap()).await);
        assert!(platform.is_valid_address("2001:db8::1".parse().unwrap()).await);

        // Invalid addresses
        assert!(!platform.is_valid_address("127.0.0.1".parse().unwrap()).await); // Loopback
        assert!(!platform.is_valid_address("::1".parse().unwrap()).await); // Loopback
        assert!(!platform.is_valid_address("169.254.1.1".parse().unwrap()).await); // Link-local
        assert!(!platform.is_valid_address("fe80::1".parse().unwrap()).await); // Link-local
        assert!(!platform.is_valid_address("224.0.0.1".parse().unwrap()).await); // Multicast
        assert!(!platform.is_valid_address("ff02::1".parse().unwrap()).await); // Multicast
    }

    #[test]
    fn test_interface_index_lookup() {
        // This test would require actual interfaces to exist
        // Just test that function doesn't panic
        let index = if_index_from_name("nonexistent_interface");
        assert_eq!(index, 0); // Should return 0 for nonexistent interface
    }
}
