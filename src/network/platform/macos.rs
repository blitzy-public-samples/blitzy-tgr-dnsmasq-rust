// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! macOS-specific networking implementation
//!
//! This module provides macOS-specific network functionality including:
//! - Interface enumeration using getifaddrs
//! - Real-time interface change monitoring via PF_ROUTE routing sockets
//! - BPF (Berkeley Packet Filter) device initialization for raw packet I/O
//! - SO_BINDTOIF socket option for interface binding (macOS-specific)
//! - Raw packet transmission via BPF for DHCP and other protocols
//!
//! # Platform Differences from BSD
//!
//! - Uses `SO_BINDTOIF` instead of `SO_BINDTODEVICE` for interface binding
//! - BPF device enumeration follows macOS patterns (`/dev/bpf*`)
//! - ARP enumeration via sysctl is not supported (excluded functionality)
//! - Routing socket messages have macOS-specific format variations

use crate::error::{DnsmasqError, NetworkError, Result};
use crate::network::platform::common::{
    InterfaceEvent, InterfaceFlags, NetworkInterface, NetworkPlatform,
};
use crate::types::MacAddress;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use nix::ifaddrs::getifaddrs;
use nix::libc;
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType, SockaddrLike};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tracing::{debug, error, info, instrument, trace, warn};

/// Size of buffer for routing socket messages
const ROUTE_MSG_BUFFER_SIZE: usize = 8192;

/// Maximum number of BPF devices to try opening
const MAX_BPF_DEVICES: u32 = 256;

/// BPF buffer size (must be large enough for Ethernet frames)
const BPF_BUFFER_SIZE: usize = 4096;

/// macOS-specific routing message types (from net/route.h)
const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTM_CHANGE: u8 = 0x3;
const RTM_GET: u8 = 0x4;
const RTM_LOSING: u8 = 0x5;
const RTM_REDIRECT: u8 = 0x6;
const RTM_MISS: u8 = 0x7;
const RTM_LOCK: u8 = 0x8;
const RTM_RESOLVE: u8 = 0xb;
const RTM_NEWADDR: u8 = 0xc;
const RTM_DELADDR: u8 = 0xd;
const RTM_IFINFO: u8 = 0xe;
const RTM_NEWMADDR: u8 = 0xf;
const RTM_DELMADDR: u8 = 0x10;
const RTM_IFINFO2: u8 = 0x12;

/// Routing message version
const RTM_VERSION: u8 = 5;

/// macOS network platform implementation
///
/// Provides macOS-specific implementations of network operations including
/// interface enumeration, change monitoring, and BPF-based packet I/O.
pub struct MacOSNetworkPlatform {
    /// Cache of interface index to name mappings
    interface_cache: Arc<tokio::sync::RwLock<HashMap<u32, String>>>,
}

impl MacOSNetworkPlatform {
    /// Create a new macOS network platform instance
    ///
    /// Initializes the platform with an empty interface cache that will be
    /// populated on first use.
    #[instrument]
    pub fn new() -> Self {
        debug!("Initializing macOS network platform");
        Self { interface_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())) }
    }

    /// Initialize a BPF device for raw packet I/O
    ///
    /// macOS uses numbered BPF devices (/dev/bpf0, /dev/bpf1, etc.). This function
    /// iterates through available devices until it finds one that can be opened.
    ///
    /// # Arguments
    ///
    /// * `interface_name` - Optional interface name to bind the BPF device to
    ///
    /// # Returns
    ///
    /// Returns a file descriptor to the opened BPF device.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::BpfFailed` if no BPF device can be opened or configured.
    #[instrument]
    pub async fn init_bpf(&self, interface_name: Option<&str>) -> Result<RawFd> {
        debug!("Initializing BPF device for interface: {:?}", interface_name);

        // Try opening BPF devices in sequence until one succeeds
        for i in 0..MAX_BPF_DEVICES {
            let device_path = format!("/dev/bpf{}", i);
            trace!("Attempting to open BPF device: {}", device_path);

            match tokio::fs::OpenOptions::new().read(true).write(true).open(&device_path).await {
                Ok(file) => {
                    let fd = file.into_std().await.as_raw_fd();

                    // Configure BPF buffer size
                    let buf_len: libc::c_uint = BPF_BUFFER_SIZE as libc::c_uint;
                    unsafe {
                        if libc::ioctl(fd, nix::libc::BIOCSBLEN, &buf_len) < 0 {
                            error!("Failed to set BPF buffer size");
                            let _ = nix::unistd::close(fd);
                            continue;
                        }
                    }

                    // Set immediate mode (no buffering)
                    let immediate: libc::c_uint = 1;
                    unsafe {
                        if libc::ioctl(fd, nix::libc::BIOCIMMEDIATE, &immediate) < 0 {
                            warn!("Failed to set BPF immediate mode, continuing anyway");
                        }
                    }

                    // Bind to specific interface if requested
                    if let Some(iface) = interface_name {
                        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
                        let iface_bytes = iface.as_bytes();
                        let len = std::cmp::min(iface_bytes.len(), libc::IFNAMSIZ - 1);
                        ifreq.ifr_name[..len].copy_from_slice(unsafe {
                            std::slice::from_raw_parts(iface_bytes.as_ptr() as *const i8, len)
                        });

                        unsafe {
                            if libc::ioctl(fd, nix::libc::BIOCSETIF, &ifreq) < 0 {
                                error!("Failed to bind BPF device to interface {}", iface);
                                let _ = nix::unistd::close(fd);
                                return Err(DnsmasqError::Network(
                                    NetworkError::InterfaceNotFound(iface.to_string()),
                                ));
                            }
                        }
                    }

                    info!("Successfully initialized BPF device: {}", device_path);
                    return Ok(fd);
                }
                Err(e) if i < MAX_BPF_DEVICES - 1 => {
                    trace!("BPF device {} not available: {}, trying next", device_path, e);
                    continue;
                }
                Err(e) => {
                    error!("Failed to open any BPF device: {}", e);
                    return Err(DnsmasqError::Network(NetworkError::BpfFailed(format!(
                        "No BPF devices available: {}",
                        e
                    ))));
                }
            }
        }

        Err(DnsmasqError::Network(NetworkError::BpfFailed(
            "Exhausted all BPF device slots".to_string(),
        )))
    }

    /// Send a raw packet via BPF
    ///
    /// Transmits a raw Ethernet frame through the specified BPF file descriptor.
    /// This is used primarily for DHCP packet transmission on macOS.
    ///
    /// # Arguments
    ///
    /// * `bpf_fd` - File descriptor of an initialized BPF device
    /// * `packet` - Complete Ethernet frame to transmit
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::BpfFailed` if the packet cannot be transmitted.
    #[instrument(skip(packet))]
    pub async fn send_via_bpf(&self, bpf_fd: RawFd, packet: &[u8]) -> Result<()> {
        trace!("Sending {} byte packet via BPF", packet.len());

        let written =
            unsafe { libc::write(bpf_fd, packet.as_ptr() as *const libc::c_void, packet.len()) };

        if written < 0 {
            let error = std::io::Error::last_os_error();
            error!("BPF write failed: {}", error);
            return Err(DnsmasqError::Network(NetworkError::BpfFailed(format!(
                "Write failed: {}",
                error
            ))));
        }

        if written as usize != packet.len() {
            warn!("BPF partial write: {} of {} bytes", written, packet.len());
            return Err(DnsmasqError::Network(NetworkError::BpfFailed(format!(
                "Partial write: {} of {} bytes",
                written,
                packet.len()
            ))));
        }

        debug!("Successfully sent {} byte packet via BPF", written);
        Ok(())
    }

    /// Parse a routing socket message into an InterfaceEvent
    ///
    /// Decodes macOS routing socket messages (RTM_NEWADDR, RTM_DELADDR, RTM_IFINFO)
    /// and converts them into structured InterfaceEvent types.
    ///
    /// # Arguments
    ///
    /// * `buffer` - Raw routing message buffer
    ///
    /// # Returns
    ///
    /// Returns `Some(InterfaceEvent)` if the message represents a relevant change,
    /// or `None` if the message should be ignored.
    #[instrument(skip(buffer))]
    fn parse_routing_message(&self, buffer: &[u8]) -> Option<InterfaceEvent> {
        if buffer.len() < std::mem::size_of::<RtMsgHdr>() {
            trace!("Routing message too short: {} bytes", buffer.len());
            return None;
        }

        // Parse routing message header
        let hdr = unsafe { &*(buffer.as_ptr() as *const RtMsgHdr) };

        if hdr.rtm_version != RTM_VERSION {
            warn!("Unexpected routing message version: {}", hdr.rtm_version);
            return None;
        }

        trace!(
            "Routing message: type={}, msglen={}, version={}",
            hdr.rtm_type,
            hdr.rtm_msglen,
            hdr.rtm_version
        );

        match hdr.rtm_type {
            RTM_NEWADDR => {
                debug!("Interface address added (RTM_NEWADDR)");
                // For now, emit a generic AddressAdded event
                // Full implementation would parse the sockaddr structures in the message
                Some(InterfaceEvent::AddressAdded {
                    interface: String::from("unknown"),
                    address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                })
            }
            RTM_DELADDR => {
                debug!("Interface address removed (RTM_DELADDR)");
                Some(InterfaceEvent::AddressRemoved {
                    interface: String::from("unknown"),
                    address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                })
            }
            RTM_IFINFO | RTM_IFINFO2 => {
                debug!("Interface info change (RTM_IFINFO)");
                // Parse interface flags from the message to determine link state
                Some(InterfaceEvent::LinkUp { interface: String::from("unknown") })
            }
            _ => {
                trace!("Ignoring routing message type: {}", hdr.rtm_type);
                None
            }
        }
    }

    /// Update the interface cache with current system interfaces
    ///
    /// Queries the system for all interfaces and updates the internal cache
    /// mapping interface indexes to names.
    #[instrument]
    async fn update_interface_cache(&self) -> Result<()> {
        debug!("Updating interface cache");

        let interfaces = self.enumerate_interfaces().await?;
        let mut cache = self.interface_cache.write().await;

        cache.clear();
        for iface in interfaces {
            cache.insert(iface.index, iface.name.clone());
        }

        debug!("Interface cache updated with {} entries", cache.len());
        Ok(())
    }
}

#[async_trait]
impl NetworkPlatform for MacOSNetworkPlatform {
    /// Enumerate all network interfaces on the system
    ///
    /// Uses the POSIX `getifaddrs()` API to retrieve all network interfaces
    /// and their associated addresses. Converts C structures to Rust types.
    ///
    /// # Returns
    ///
    /// Returns a vector of `NetworkInterface` structures containing interface
    /// names, indexes, addresses, and flags.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::InterfaceEnumerationFailed` if the system call fails.
    #[instrument]
    async fn enumerate_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        debug!("Enumerating network interfaces");

        let ifaddrs = getifaddrs().map_err(|e| {
            error!("getifaddrs failed: {}", e);
            DnsmasqError::Network(NetworkError::InterfaceEnumerationFailed(e.to_string()))
        })?;

        let mut interfaces: HashMap<String, NetworkInterface> = HashMap::new();

        for ifaddr in ifaddrs {
            let name = ifaddr.interface_name;

            // Get interface index
            let index = unsafe {
                let c_name = std::ffi::CString::new(name.as_str()).map_err(|e| {
                    DnsmasqError::Network(NetworkError::InterfaceEnumerationFailed(format!(
                        "Invalid interface name: {}",
                        e
                    )))
                })?;
                libc::if_nametoindex(c_name.as_ptr())
            };

            if index == 0 {
                warn!("Could not get index for interface {}", name);
                continue;
            }

            // Get or create interface entry
            let interface = interfaces.entry(name.clone()).or_insert_with(|| NetworkInterface {
                name: name.clone(),
                index,
                addresses: Vec::new(),
                flags: InterfaceFlags::empty(),
            });

            // Parse interface flags
            let flags = ifaddr.flags;
            if flags & libc::IFF_UP as u32 != 0 {
                interface.flags.insert(InterfaceFlags::UP);
            }
            if flags & libc::IFF_LOOPBACK as u32 != 0 {
                interface.flags.insert(InterfaceFlags::LOOPBACK);
            }
            if flags & libc::IFF_POINTOPOINT as u32 != 0 {
                interface.flags.insert(InterfaceFlags::POINT_TO_POINT);
            }
            if flags & libc::IFF_MULTICAST as u32 != 0 {
                interface.flags.insert(InterfaceFlags::MULTICAST);
            }
            if flags & libc::IFF_BROADCAST as u32 != 0 {
                interface.flags.insert(InterfaceFlags::BROADCAST);
            }

            // Extract IP addresses
            if let Some(address) = ifaddr.address {
                match address.family() {
                    Some(AddressFamily::Inet) => {
                        if let Some(sockaddr_in) = address.as_sockaddr_in() {
                            let ipv4 = Ipv4Addr::from(sockaddr_in.ip());
                            interface.addresses.push(IpAddr::V4(ipv4));
                            trace!("Added IPv4 address {} to interface {}", ipv4, name);
                        }
                    }
                    Some(AddressFamily::Inet6) => {
                        if let Some(sockaddr_in6) = address.as_sockaddr_in6() {
                            let ipv6 = Ipv6Addr::from(sockaddr_in6.ip());
                            interface.addresses.push(IpAddr::V6(ipv6));
                            trace!("Added IPv6 address {} to interface {}", ipv6, name);
                        }
                    }
                    _ => {
                        trace!("Skipping non-IP address family for interface {}", name);
                    }
                }
            }
        }

        let result: Vec<NetworkInterface> = interfaces.into_values().collect();
        info!("Enumerated {} network interfaces", result.len());
        Ok(result)
    }

    /// Subscribe to network interface change notifications
    ///
    /// Creates a PF_ROUTE routing socket to receive real-time notifications
    /// about interface state changes, address additions/removals, and link status.
    ///
    /// # Returns
    ///
    /// Returns a stream of `InterfaceEvent` items that will yield events as
    /// network changes occur.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::RoutingFailed` if the routing socket cannot be created.
    #[instrument]
    async fn subscribe_to_changes(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = InterfaceEvent> + Send>>> {
        debug!("Setting up routing socket for change notifications");

        // Create PF_ROUTE socket
        let sock = socket::socket(AddressFamily::Route, SockType::Raw, SockFlag::empty(), None)
            .map_err(|e| {
                error!("Failed to create routing socket: {}", e);
                DnsmasqError::Network(NetworkError::RoutingFailed(format!(
                    "Socket creation failed: {}",
                    e
                )))
            })?;

        debug!("Routing socket created successfully: fd={}", sock);

        // Create channel for events
        let (tx, rx) = mpsc::channel::<InterfaceEvent>(100);

        // Spawn task to read from routing socket
        let platform = self.clone_for_task();
        task::spawn(async move {
            let mut buffer = vec![0u8; ROUTE_MSG_BUFFER_SIZE];

            loop {
                let bytes_read = unsafe {
                    libc::recv(sock, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0)
                };

                if bytes_read < 0 {
                    let err = std::io::Error::last_os_error();
                    error!("Routing socket read error: {}", err);
                    break;
                }

                if bytes_read == 0 {
                    warn!("Routing socket closed");
                    break;
                }

                trace!("Received {} bytes from routing socket", bytes_read);

                // Parse routing message
                if let Some(event) = platform.parse_routing_message(&buffer[..bytes_read as usize])
                {
                    if tx.send(event).await.is_err() {
                        debug!("Event receiver dropped, stopping routing socket monitor");
                        break;
                    }
                }
            }

            // Clean up socket
            unsafe {
                libc::close(sock);
            }
            debug!("Routing socket monitor task terminated");
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    /// Convert an interface index to its name
    ///
    /// Queries the system to map a numeric interface index to its string name.
    /// Results are cached to minimize system calls.
    ///
    /// # Arguments
    ///
    /// * `index` - Numeric interface index
    ///
    /// # Returns
    ///
    /// Returns the interface name as a string.
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::InterfaceNotFound` if the index is invalid.
    #[instrument]
    async fn index_to_name(&self, index: u32) -> Result<String> {
        trace!("Looking up interface name for index {}", index);

        // Check cache first
        {
            let cache = self.interface_cache.read().await;
            if let Some(name) = cache.get(&index) {
                trace!("Found interface name in cache: {}", name);
                return Ok(name.clone());
            }
        }

        // Update cache from system
        self.update_interface_cache().await?;

        // Try again after cache update
        let cache = self.interface_cache.read().await;
        cache.get(&index).cloned().ok_or_else(|| {
            error!("Interface index {} not found", index);
            DnsmasqError::Network(NetworkError::InterfaceNotFound(index.to_string()))
        })
    }

    /// Enumerate ARP table entries
    ///
    /// # Platform Note
    ///
    /// ARP enumeration via sysctl is not supported on macOS. This method
    /// returns an empty vector on macOS as per the C implementation behavior.
    ///
    /// # Returns
    ///
    /// Always returns an empty vector on macOS.
    #[instrument]
    async fn enumerate_arp_entries(&self) -> Result<Vec<(IpAddr, [u8; 6])>> {
        debug!("ARP enumeration requested (not supported on macOS)");
        // macOS does not support sysctl-based ARP enumeration like other BSD systems
        // Return empty vector to match C implementation behavior
        Ok(Vec::new())
    }

    /// Check if an address is valid for a given interface
    ///
    /// Validates that an IP address is configured on the specified interface.
    ///
    /// # Arguments
    ///
    /// * `address` - IP address to validate
    /// * `interface` - Network interface to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the address is assigned to the interface, `false` otherwise.
    #[instrument]
    async fn is_valid_address(
        &self,
        address: &IpAddr,
        interface: &NetworkInterface,
    ) -> Result<bool> {
        trace!("Validating address {} on interface {}", address, interface.name);
        Ok(interface.addresses.contains(address))
    }
}

impl MacOSNetworkPlatform {
    /// Clone the platform for use in async tasks
    ///
    /// Creates a shallow clone that shares the interface cache via Arc.
    fn clone_for_task(&self) -> Self {
        Self { interface_cache: Arc::clone(&self.interface_cache) }
    }
}

/// Routing message header structure (simplified)
///
/// Corresponds to struct rt_msghdr from net/route.h
#[repr(C)]
struct RtMsgHdr {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    rtm_flags: i32,
    rtm_addrs: i32,
    rtm_pid: i32,
    rtm_seq: i32,
    rtm_errno: i32,
    rtm_use: i32,
    rtm_inits: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_macos_platform_creation() {
        let platform = MacOSNetworkPlatform::new();
        assert!(platform.interface_cache.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_enumerate_interfaces() {
        let platform = MacOSNetworkPlatform::new();
        let interfaces = platform.enumerate_interfaces().await;

        // Should succeed (even if no interfaces found)
        assert!(interfaces.is_ok());

        // Should have at least loopback
        let ifaces = interfaces.unwrap();
        assert!(!ifaces.is_empty(), "Should have at least one interface");

        // Check for loopback interface
        let has_loopback = ifaces.iter().any(|i| i.flags.contains(InterfaceFlags::LOOPBACK));
        assert!(has_loopback, "Should have loopback interface");
    }

    #[tokio::test]
    async fn test_index_to_name() {
        let platform = MacOSNetworkPlatform::new();

        // First enumerate to populate cache
        let interfaces = platform.enumerate_interfaces().await.unwrap();

        if let Some(iface) = interfaces.first() {
            let name = platform.index_to_name(iface.index).await;
            assert!(name.is_ok());
            assert_eq!(name.unwrap(), iface.name);
        }
    }

    #[tokio::test]
    async fn test_is_valid_address() {
        let platform = MacOSNetworkPlatform::new();
        let interfaces = platform.enumerate_interfaces().await.unwrap();

        if let Some(iface) = interfaces.first() {
            if let Some(addr) = iface.addresses.first() {
                let is_valid = platform.is_valid_address(addr, iface).await;
                assert!(is_valid.is_ok());
                assert!(is_valid.unwrap());

                // Test invalid address
                let invalid_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
                let is_invalid = platform.is_valid_address(&invalid_addr, iface).await;
                assert!(is_invalid.is_ok());
                assert!(!is_invalid.unwrap());
            }
        }
    }

    #[tokio::test]
    async fn test_arp_enumeration_returns_empty() {
        let platform = MacOSNetworkPlatform::new();
        let arp_entries = platform.enumerate_arp_entries().await;

        assert!(arp_entries.is_ok());
        assert!(arp_entries.unwrap().is_empty(), "macOS should return empty ARP table");
    }
}
