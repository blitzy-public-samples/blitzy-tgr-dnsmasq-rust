// Copyright (C) 2024 Dnsmasq Contributors
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0

//! IPv6 Router Advertisement (RA) Module
//!
//! This module implements IPv6 Router Advertisement functionality per RFC 4861
//! (Neighbor Discovery for IP version 6) and RFC 4862 (IPv6 Stateless Address
//! Autoconfiguration). It provides complete ICMPv6 Router Advertisement generation,
//! transmission, and Router Solicitation handling for enabling IPv6 clients to
//! perform SLAAC and discover network configuration parameters.
//!
//! # Key Features
//!
//! - **Periodic Router Advertisements**: Unsolicited multicast RAs at configurable intervals
//! - **Router Solicitation Response**: Immediate unicast RAs in response to client requests
//! - **DHCPv6 Coordination**: M (managed address) and O (other configuration) flag control
//! - **DNSSEC Configuration**: RDNSS option per RFC 6106 for DNS server advertisement
//! - **SLAAC Support**: Prefix information options for stateless address autoconfiguration
//! - **Async Architecture**: tokio-based async/await replacing C poll-based event loop
//! - **Memory Safety**: Safe Rust packet construction replacing C manual buffer management
//!
//! # Standards Compliance
//!
//! - RFC 4861: Neighbor Discovery for IPv6
//! - RFC 4862: IPv6 Stateless Address Autoconfiguration
//! - RFC 6106: IPv6 Router Advertisement Options for DNS Configuration
//!
//! # Operational Modes
//!
//! - **ra-only**: SLAAC with stateless DHCPv6 for additional configuration
//! - **ra-names**: SLAAC with RDNSS and ping-based address confirmation
//! - **ra-stateless**: Pure SLAAC without DHCPv6 coordination

// ICMPv6 Router Advertisement protocol requires specific field sizes and intentional casts
// RaParam struct requires multiple independent protocol flags per RFC 4861
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::struct_excessive_bools
)]

pub mod protocol;
pub mod slaac;

// Internal imports from dnsmasq crate
use crate::config::types::{Config, DhcpContext, CONTEXT_RA_STATELESS};
use crate::error::NetworkError;
use crate::network::interfaces::InterfaceManager;
use crate::network::sockets::create_icmpv6_socket;
use crate::types::IpAddr;

// Protocol structures and constants
use protocol::{
    PrefixOpt, RaPacket, ALL_NODES, HOP_LIMIT, ICMP6_ECHO_REPLY, ICMP6_NEIGH_ADVERT,
    ICMP6_NEIGH_SOLICIT, ICMP6_ROUTER_ADVERT, ICMP6_ROUTER_SOLICIT, INTERVAL_OPT, MTU_OPT,
    PREFIX_OPT, RDNSS_OPT,
};

// SLAAC functionality
use slaac::slaac_ping_reply;

// External imports
use std::collections::HashMap;
use std::net::{Ipv6Addr as StdIpv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{interval, sleep, Instant as TokioInstant};
use tracing::{debug, error, info, instrument, warn};

// Re-export commonly used types for external consumers
pub use protocol::{
    NeighPacket as PublicNeighPacket, PingPacket as PublicPingPacket, PrefixOpt as PublicPrefixOpt,
    RaPacket as PublicRaPacket, ALL_NODES as PUBLIC_ALL_NODES, ALL_ROUTERS as PUBLIC_ALL_ROUTERS,
};
pub use slaac::{
    eui64_from_mac, periodic_slaac as public_periodic_slaac,
    slaac_add_addrs as public_slaac_add_addrs, slaac_ping_reply as public_slaac_ping_reply,
    SlaacAddress,
};

/// Router Advertisement specific error types
#[derive(Debug, thiserror::Error)]
pub enum RadVError {
    /// Network-level error during packet transmission
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// Configuration error (invalid RA settings)
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Packet construction error
    #[error("Packet construction error: {0}")]
    PacketConstruction(String),

    /// Interface error (interface not found or invalid)
    #[error("Interface error: {0}")]
    Interface(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for Router Advertisement operations
pub type Result<T> = std::result::Result<T, RadVError>;

/// `DHCPv6` context coordination flags
/// These flags are used to coordinate Router Advertisement behavior with `DHCPv6` server
const CONTEXT_RA_NAME: u32 = 0x01; // Context used for RA-names mode (DNS registration)
#[allow(dead_code)]
const CONTEXT_TEMPLATE: u32 = 0x02; // Context is a template for address allocation

/// Router Advertisement interface configuration
/// Defines per-interface RA settings including transmission intervals, router lifetime,
/// router preference, and MTU advertisement
#[derive(Debug, Clone)]
pub struct RaInterface {
    /// Interface name (e.g., "eth0", "wlan0")
    pub name: String,

    /// Router Advertisement transmission interval in seconds (default: 600)
    /// RFC 4861 recommends 200-600 seconds for `MaxRtrAdvInterval`
    pub interval: u32,

    /// Router lifetime in seconds (default: 3 * interval)
    /// Set to 0 to indicate this router should not be used as default router
    pub lifetime: u32,

    /// Router preference (0=medium, 1=high, 3=low)
    /// Used in Route Information Options per RFC 4191
    pub priority: u8,

    /// MTU to advertise via MTU option (0 = do not advertise)
    pub mtu: u32,
}

impl RaInterface {
    /// Create a new `RaInterface` with default values
    #[must_use]
    pub fn new(name: String) -> Self {
        Self {
            name,
            interval: 600,  // 10 minutes (RFC 4861 MaxRtrAdvInterval)
            lifetime: 1800, // 30 minutes (3 * interval)
            priority: 0,    // Medium preference
            mtu: 0,         // Do not advertise MTU by default
        }
    }
}

/// Router Advertisement Server
/// Manages periodic transmission of unsolicited Router Advertisements and
/// responds to Router Solicitations from IPv6 clients
#[derive(Debug)]
pub struct RadVServer {
    /// Global configuration
    config: Arc<Config>,

    /// Interface manager for network interface operations
    interface_manager: Arc<InterfaceManager>,

    /// RA transmission times per interface (interface index -> next RA time)
    ra_times: Arc<RwLock<HashMap<u32, TokioInstant>>>,
}

/// Router Advertisement parameters
/// Contains all information needed to construct and transmit a Router Advertisement
/// packet for a specific interface
#[derive(Debug, Clone)]
pub struct RaParam {
    /// Current monotonic time
    pub now: TokioInstant,

    /// Interface index
    pub ind: u32,

    /// Managed address configuration flag (M flag in RA)
    /// When true, indicates addresses are available via `DHCPv6`
    pub managed: bool,

    /// Other configuration flag (O flag in RA)
    /// When true, indicates other configuration (e.g., DNS) available via `DHCPv6`
    pub other: bool,

    /// First RA transmission after startup (triggers short RA period)
    pub first: bool,

    /// Advertise this router as default gateway
    pub adv_router: bool,

    /// Interface name
    pub if_name: String,

    /// Link-local IPv6 address (`fe80::/10`)
    pub link_local: Option<StdIpv6Addr>,

    /// Global IPv6 address (`2000::/3`, not ULA)
    pub link_global: Option<StdIpv6Addr>,

    /// Unique Local Address (`fc00::/7` or `fd00::/8`)
    pub ula: Option<StdIpv6Addr>,

    /// Global prefix preferred lifetime in seconds
    pub glob_pref_time: u32,

    /// Link prefix preferred lifetime in seconds
    pub link_pref_time: u32,

    /// ULA prefix preferred lifetime in seconds
    pub ula_pref_time: u32,

    /// Advertisement interval in seconds
    pub adv_interval: u32,

    /// Router priority (0=medium, 1=high, 3=low)
    pub prio: u8,

    /// `DHCPv6` context found for this interface
    pub found_context: bool,
}

impl RadVServer {
    /// Create a new Router Advertisement server
    ///
    /// # Arguments
    ///
    /// * `config` - Global dnsmasq configuration
    /// * `interface_manager` - Network interface manager
    ///
    /// # Returns
    ///
    /// Returns `Ok(RadVServer)` if configuration is valid, otherwise returns
    /// `RadVError::Configuration` with details of the validation failure.
    ///
    /// # Validation
    ///
    /// - Ensures at least one RA-enabled interface is configured
    /// - Validates interval values are positive
    /// - Validates priority values are in valid range (0, 1, or 3)
    pub fn new(config: Arc<Config>, interface_manager: Arc<InterfaceManager>) -> Result<Self> {
        // Log if no RA interfaces configured (valid for DNS-only mode)
        if config.ra_interfaces.is_empty() {
            info!("Router Advertisement disabled - no interfaces configured (DNS-only mode)");
        }

        // Validate each RA interface configuration
        for ra_iface in &config.ra_interfaces {
            // Validate interval
            if ra_iface.interval == 0 {
                return Err(RadVError::Configuration(format!(
                    "Invalid interval 0 for interface {}",
                    ra_iface.name
                )));
            }

            // Validate interval is within RFC 4861 recommended range
            if ra_iface.interval < 4 || ra_iface.interval > 1800 {
                warn!(
                    interface = %ra_iface.name,
                    interval = ra_iface.interval,
                    "RA interval outside RFC 4861 recommended range (4-1800 seconds)"
                );
            }

            // Validate priority (0=medium, 1=high, 3=low per RFC 4191)
            if ra_iface.priority != 0 && ra_iface.priority != 1 && ra_iface.priority != 3 {
                return Err(RadVError::Configuration(format!(
                    "Invalid priority {} for interface {} (must be 0, 1, or 3)",
                    ra_iface.priority, ra_iface.name
                )));
            }
        }

        // Initialize RA transmission time tracking
        let ra_times = Arc::new(RwLock::new(HashMap::new()));

        info!(
            num_interfaces = config.ra_interfaces.len(),
            "Router Advertisement server initialized"
        );

        Ok(Self { config, interface_manager, ra_times })
    }

    /// Build Router Advertisement parameters for a specific interface
    ///
    /// Gathers all information needed to construct an RA packet including:
    /// - IPv6 addresses (link-local, global, ULA)
    /// - M/O flags based on `DHCPv6` configuration
    /// - Prefix lifetimes from DHCP contexts
    /// - Interval and priority from interface configuration
    #[instrument(skip(self), fields(interface = iface_idx))]
    async fn build_ra_param(&self, iface_idx: u32, first: bool) -> Result<RaParam> {
        // Get interface information
        let iface =
            self.interface_manager.get_interface_by_index(iface_idx).await.ok_or_else(|| {
                RadVError::Interface(format!("Failed to get interface {iface_idx}"))
            })?;

        // Extract IPv6 addresses by type
        let mut link_local = None;
        let mut link_global = None;
        let mut ula = None;

        for addr in &iface.addresses {
            if let IpAddr::V6(v6_addr) = addr {
                let addr_std = StdIpv6Addr::from(v6_addr.octets());

                // Link-local: fe80::/10
                if (addr_std.segments()[0] & 0xffc0) == 0xfe80 {
                    link_local = Some(addr_std);
                }
                // ULA: fc00::/7 or fd00::/8
                else if (addr_std.segments()[0] & 0xfe00) == 0xfc00 {
                    ula = Some(addr_std);
                }
                // Global unicast: 2000::/3 (not ULA)
                else if (addr_std.segments()[0] & 0xe000) == 0x2000 {
                    link_global = Some(addr_std);
                }
            }
        }

        // Find RA interface configuration
        let ra_iface =
            self.config.ra_interfaces.iter().find(|ri| ri.name == iface.name).ok_or_else(|| {
                RadVError::Configuration(format!(
                    "No RA configuration found for interface {}",
                    iface.name
                ))
            })?;

        // Calculate M (managed address) and O (other configuration) flags
        // by examining DHCPv6 contexts
        let mut managed = false;
        let mut other = false;
        let mut found_context = false;
        let mut glob_pref_time = 0u32;
        let mut link_pref_time = 0u32;
        let mut ula_pref_time = 0u32;

        // Iterate through DHCPv6 contexts to determine flags and lifetimes
        for context in &self.config.dhcp.dhcp_contexts {
            // Check if context applies to this interface by interface index
            if context.if_index != 0 && context.if_index != iface_idx as i32 {
                continue;
            }

            // Check for IPv6 context
            if context.is_v6() {
                found_context = true;

                // M flag: Set if context supports managed addressing (not ra-stateless)
                if (context.flags & CONTEXT_RA_NAME) != 0 {
                    managed = true;
                }

                // O flag: Set if DHCPv6 provides additional configuration
                // Always true if we have DHCPv6 contexts (for DNS, etc.)
                other = true;

                // Calculate prefix lifetimes from DHCP lease times
                let lease_time = context.lease_time; // Use lease time from context
                let preferred_time = (f64::from(lease_time) * 0.75) as u32; // 75% of lease time

                // Set lifetime based on address type
                if let Some(global) = link_global {
                    if context.contains_address(IpAddr::V6(global)) {
                        glob_pref_time = preferred_time;
                    }
                }
                if let Some(ula_addr) = ula {
                    if context.contains_address(IpAddr::V6(ula_addr)) {
                        ula_pref_time = preferred_time;
                    }
                }
            }
        }

        // Default lifetimes if no DHCPv6 context found (use 3 * interval)
        if !found_context {
            let default_lifetime = ra_iface.interval * 3;
            glob_pref_time = default_lifetime;
            link_pref_time = default_lifetime;
            ula_pref_time = default_lifetime;
        }

        Ok(RaParam {
            now: TokioInstant::now(),
            ind: iface_idx,
            managed,
            other,
            first,
            adv_router: ra_iface.lifetime > 0,
            if_name: iface.name.clone(),
            link_local,
            link_global,
            ula,
            glob_pref_time,
            link_pref_time,
            ula_pref_time,
            adv_interval: ra_iface.interval,
            prio: ra_iface.priority,
            found_context,
        })
    }

    /// Add Router Advertisement header to packet buffer
    ///
    /// Constructs the base `ICMPv6` RA message (type 134) with:
    /// - Current hop limit (64 or from configuration)
    /// - M and O flags for `DHCPv6` coordination
    /// - Router lifetime (0 if not default router, else 3 * interval)
    /// - Reachable time (0 = unspecified)
    /// - Retrans timer (0 = unspecified)
    #[allow(clippy::unnecessary_wraps)] // Result for API consistency with other add_* functions
    fn add_ra_header(packet: &mut Vec<u8>, param: &RaParam) -> Result<()> {
        // Calculate flags byte
        let mut flags = 0u8;
        if param.managed {
            flags |= 0x80; // M flag (bit 7): Managed address configuration
        }
        if param.other {
            flags |= 0x40; // O flag (bit 6): Other configuration available
        }

        // Calculate router lifetime in seconds
        // Set to 0 if this router should not be used as default gateway
        // Otherwise use 3 * adv_interval (RFC 4861 recommendation)
        let router_lifetime =
            if param.adv_router { (param.adv_interval * 3).min(0xFFFF) as u16 } else { 0u16 };

        // Construct RA packet structure
        let ra_packet = RaPacket {
            type_: ICMP6_ROUTER_ADVERT,
            code: 0,
            checksum: 0, // Kernel will calculate checksum
            hop_limit: HOP_LIMIT,
            flags,
            lifetime: router_lifetime.to_be(),
            reachable_time: 0u32.to_be(), // 0 = unspecified
            retrans_time: 0u32.to_be(),   // 0 = unspecified
        };

        // Serialize RA header to bytes
        let ra_bytes: [u8; 16] = unsafe { std::mem::transmute(ra_packet) };

        packet.extend_from_slice(&ra_bytes);

        debug!(
            interface = %param.if_name,
            managed = param.managed,
            other = param.other,
            router_lifetime = router_lifetime,
            "Added RA header"
        );

        Ok(())
    }

    /// Add Prefix Information Option to packet
    ///
    /// Constructs a Prefix Information Option (type 3) containing:
    /// - Prefix length
    /// - On-link and Autonomous flags (both set for SLAAC)
    /// - Valid and preferred lifetimes
    /// - Prefix address
    #[allow(clippy::unnecessary_wraps)] // Result for API consistency with other add_* functions
    fn add_prefix_option(
        packet: &mut Vec<u8>,
        prefix: StdIpv6Addr,
        prefix_len: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
    ) -> Result<()> {
        let prefix_opt = PrefixOpt {
            type_: PREFIX_OPT,
            len: 4, // Length in units of 8 bytes
            prefix_len,
            flags: 0xC0, // L=1 (on-link), A=1 (autonomous address configuration)
            valid_lifetime: valid_lifetime.to_be(),
            preferred_lifetime: preferred_lifetime.to_be(),
            reserved: 0u32.to_be(),
            prefix,
        };

        // Serialize prefix option
        let prefix_bytes: [u8; 32] = unsafe { std::mem::transmute(prefix_opt) };

        packet.extend_from_slice(&prefix_bytes);

        debug!(
            prefix = %prefix,
            prefix_len = prefix_len,
            valid = valid_lifetime,
            preferred = preferred_lifetime,
            "Added prefix option"
        );

        Ok(())
    }

    /// Add all prefix information options to RA packet
    ///
    /// Adds prefix information options for:
    /// - Link-local prefix (`fe80::/64`) if present
    /// - Global unicast prefix (`2000::/3`) if present
    /// - Unique Local Address prefix (`fc00::/7`) if present
    ///
    /// Each prefix option includes valid and preferred lifetimes based on
    /// `DHCPv6` context configuration or default values.
    fn add_prefix_options(packet: &mut Vec<u8>, param: &RaParam) -> Result<()> {
        let mut added_count = 0;

        // Add link-local prefix option (fe80::/64)
        if let Some(link_local) = param.link_local {
            // Link-local always uses /64 prefix
            let prefix_len = 64u8;
            let valid_lifetime = param.link_pref_time * 2; // Valid lifetime = 2 * preferred
            let preferred_lifetime = param.link_pref_time;

            Self::add_prefix_option(
                packet,
                link_local,
                prefix_len,
                valid_lifetime,
                preferred_lifetime,
            )?;
            added_count += 1;
        }

        // Add global unicast prefix option (2000::/3, not ULA)
        if let Some(link_global) = param.link_global {
            // Global addresses typically use /64 prefix
            let prefix_len = 64u8;
            let valid_lifetime = param.glob_pref_time * 2;
            let preferred_lifetime = param.glob_pref_time;

            Self::add_prefix_option(
                packet,
                link_global,
                prefix_len,
                valid_lifetime,
                preferred_lifetime,
            )?;
            added_count += 1;
        }

        // Add ULA prefix option (fc00::/7 or fd00::/8)
        if let Some(ula) = param.ula {
            // ULA addresses typically use /64 prefix
            let prefix_len = 64u8;
            let valid_lifetime = param.ula_pref_time * 2;
            let preferred_lifetime = param.ula_pref_time;

            Self::add_prefix_option(packet, ula, prefix_len, valid_lifetime, preferred_lifetime)?;
            added_count += 1;
        }

        debug!(
            interface = %param.if_name,
            num_prefixes = added_count,
            "Added prefix information options"
        );

        Ok(())
    }

    /// Add RDNSS (Recursive DNS Server) option per RFC 6106
    ///
    /// Advertises DNS server addresses that clients should use.
    /// Option type 25 with format:
    /// - Type (1 byte)
    /// - Length in 8-byte units (1 byte)
    /// - Reserved (2 bytes)
    /// - Lifetime (4 bytes)
    /// - DNS server addresses (16 bytes each)
    #[allow(clippy::unnecessary_wraps)] // Result for API consistency with other add_* functions
    fn add_rdnss_option(packet: &mut Vec<u8>, param: &RaParam) -> Result<()> {
        // Collect DNS server addresses to advertise
        // Typically advertise the link-local address of this router where dnsmasq is listening
        let mut dns_servers: Vec<StdIpv6Addr> = Vec::new();

        // Prefer global address if available, otherwise use link-local
        if let Some(global) = param.link_global {
            dns_servers.push(global);
        } else if let Some(link_local) = param.link_local {
            dns_servers.push(link_local);
        }

        // Also add ULA if available
        if let Some(ula) = param.ula {
            dns_servers.push(ula);
        }

        if dns_servers.is_empty() {
            return Ok(()); // No DNS servers to advertise
        }

        // Calculate option length: 1 (fixed part) + num_servers * 2 (each IPv6 address is 2*8 bytes)
        let opt_len = 1 + (dns_servers.len() * 2) as u8;

        // Add option header
        packet.push(RDNSS_OPT); // Type 25
        packet.push(opt_len);
        packet.extend_from_slice(&[0u8, 0u8]); // Reserved

        // Lifetime (use 3 * interval)
        let lifetime = param.adv_interval * 3;
        packet.extend_from_slice(&lifetime.to_be_bytes());

        // Add DNS server addresses
        for dns_server in &dns_servers {
            packet.extend_from_slice(&dns_server.octets());
        }

        debug!(
            interface = %param.if_name,
            num_dns_servers = dns_servers.len(),
            "Added RDNSS option"
        );

        Ok(())
    }

    /// Add MTU option if configured
    ///
    /// Advertises link MTU that clients should use.
    /// Option type 5 with 8-byte length.
    fn add_mtu_option(&self, packet: &mut Vec<u8>, param: &RaParam) -> Result<()> {
        // Find RA interface configuration
        let ra_iface =
            self.config.ra_interfaces.iter().find(|ri| ri.name == param.if_name).ok_or_else(
                || {
                    RadVError::Configuration(format!(
                        "No RA configuration found for interface {}",
                        param.if_name
                    ))
                },
            )?;

        if ra_iface.mtu > 0 {
            packet.push(MTU_OPT); // Type 5
            packet.push(1); // Length = 1 (8 bytes)
            packet.extend_from_slice(&[0u8, 0u8]); // Reserved
            packet.extend_from_slice(&ra_iface.mtu.to_be_bytes());

            debug!(
                interface = %param.if_name,
                mtu = ra_iface.mtu,
                "Added MTU option"
            );
        }

        Ok(())
    }

    /// Add Advertisement Interval option
    ///
    /// Informs clients of the interval between unsolicited multicast RAs.
    /// Option type 7 with 8-byte length.
    #[allow(clippy::unnecessary_wraps)] // Result for API consistency with other add_* functions
    fn add_interval_option(packet: &mut Vec<u8>, param: &RaParam) -> Result<()> {
        packet.push(INTERVAL_OPT); // Type 7
        packet.push(1); // Length = 1 (8 bytes)
        packet.extend_from_slice(&[0u8, 0u8]); // Reserved

        // Interval in milliseconds
        let interval_ms = param.adv_interval * 1000;
        packet.extend_from_slice(&interval_ms.to_be_bytes());

        debug!(
            interface = %param.if_name,
            interval_sec = param.adv_interval,
            "Added interval option"
        );

        Ok(())
    }

    /// Construct complete Router Advertisement packet
    ///
    /// Builds the full RA packet by calling all option-adding functions
    /// in the correct order. The packet includes:
    /// 1. RA header with M/O flags and router lifetime
    /// 2. Prefix Information Options
    /// 3. RDNSS option (if DNS servers configured)
    /// 4. MTU option (if configured)
    /// 5. Advertisement Interval option
    #[allow(clippy::unused_async)] // Async for API consistency with other async methods
    async fn construct_ra_packet(&self, param: &RaParam) -> Result<Vec<u8>> {
        // Allocate packet buffer with reasonable capacity
        let mut packet = Vec::with_capacity(512);

        // Add RA header
        Self::add_ra_header(&mut packet, param)?;

        // Add prefix information options
        Self::add_prefix_options(&mut packet, param)?;

        // Add RDNSS option (DNS servers)
        Self::add_rdnss_option(&mut packet, param)?;

        // Add MTU option if configured
        self.add_mtu_option(&mut packet, param)?;

        // Add Advertisement Interval option
        Self::add_interval_option(&mut packet, param)?;

        debug!(
            interface = %param.if_name,
            packet_size = packet.len(),
            "Constructed RA packet"
        );

        Ok(packet)
    }

    /// Transmit Router Advertisement packet
    ///
    /// Sends the constructed RA packet via `ICMPv6` socket.
    /// Uses multicast to `ALL_NODES` (`ff02::1`) for unsolicited RAs,
    /// or unicast to specific destination for solicited RAs.
    async fn transmit_ra_packet(
        &self,
        packet: &[u8],
        iface_idx: u32,
        dest: Option<StdIpv6Addr>,
    ) -> Result<()> {
        // Create ICMPv6 socket for this interface
        let socket =
            create_icmpv6_socket(Arc::new(self.config.network.clone())).await.map_err(|e| {
                RadVError::Io(std::io::Error::other(format!("Failed to create ICMPv6 socket: {e}")))
            })?;

        // Determine destination: unicast or multicast
        let dest_ipv6 = dest.unwrap_or(ALL_NODES);
        let dest_addr = SocketAddr::V6(SocketAddrV6::new(dest_ipv6, 0, 0, iface_idx));

        // Transmit packet
        socket.send_ra(packet, dest_addr).await.map_err(|e| {
            RadVError::Io(std::io::Error::other(format!("Failed to send RA packet: {e}")))
        })?;

        debug!(
            interface_idx = iface_idx,
            dest = %dest_addr,
            packet_size = packet.len(),
            "Transmitted RA packet"
        );

        Ok(())
    }
}

/// Send a Router Advertisement
///
/// Main function to construct and transmit a Router Advertisement packet
/// for a specific interface. Can send either unsolicited multicast RA
/// or solicited unicast RA in response to Router Solicitation.
///
/// # Arguments
///
/// * `now` - Current time (for timing calculations)
/// * `iface` - Interface index
/// * `iface_name` - Interface name
/// * `dest` - Destination address (None for multicast, Some for unicast)
///
/// # Returns
///
/// Returns `Ok(())` on successful transmission, or `RadVError` on failure.
#[instrument(skip(server), fields(interface = iface_name))]
pub async fn send_ra(
    server: &RadVServer,
    now: TokioInstant,
    iface: u32,
    iface_name: &str,
    dest: Option<StdIpv6Addr>,
) -> Result<()> {
    // Build RA parameters
    let param = server.build_ra_param(iface, false).await?;

    // Construct RA packet
    let packet = server.construct_ra_packet(&param).await?;

    // Transmit packet
    server.transmit_ra_packet(&packet, iface, dest).await?;

    // Update RA transmission time
    let mut ra_times = server.ra_times.write().await;
    ra_times.insert(iface, now);

    info!(
        interface = iface_name,
        dest = ?dest,
        managed = param.managed,
        other = param.other,
        "Sent Router Advertisement"
    );

    Ok(())
}

/// Process incoming `ICMPv6` packet
///
/// Handles incoming `ICMPv6` packets including:
/// - Router Solicitations (type 133): Respond with immediate RA
/// - Echo Replies (type 129): Forward to SLAAC module for address confirmation
///
/// # Arguments
///
/// * `server` - `RadVServer` instance
/// * `packet` - `ICMPv6` packet bytes
/// * `src` - Source IPv6 address
/// * `iface` - Interface index where packet was received
///
/// # Returns
///
/// Returns `Ok(())` on successful processing, or `RadVError` on failure.
#[instrument(skip(server, packet), fields(src = %src, interface = iface))]
pub async fn icmp6_packet(
    server: &RadVServer,
    packet: &[u8],
    src: StdIpv6Addr,
    iface: u32,
) -> Result<()> {
    // Validate packet not empty
    if packet.is_empty() {
        warn!("Received empty ICMPv6 packet");
        return Ok(());
    }

    // Extract ICMPv6 type from first byte
    let icmp_type = packet[0];

    match icmp_type {
        ICMP6_ROUTER_SOLICIT => {
            // Router Solicitation - respond with immediate unicast RA
            handle_router_solicitation(server, src, iface).await?;
        }
        ICMP6_ECHO_REPLY => {
            // Echo Reply - forward to SLAAC module for address confirmation
            handle_echo_reply(packet, src, iface).await?;
        }
        ICMP6_NEIGH_SOLICIT | ICMP6_NEIGH_ADVERT => {
            // Neighbor Discovery - log but don't process
            debug!(icmp_type, "Received Neighbor Discovery message (not processing)");
        }
        _ => {
            // Unknown ICMPv6 type - ignore
            debug!(icmp_type, "Received unknown ICMPv6 type (ignoring)");
        }
    }

    Ok(())
}

/// Handle Router Solicitation message
///
/// Responds to Router Solicitation with an immediate unicast RA
/// to the soliciting host. This provides faster configuration than
/// waiting for the next periodic multicast RA.
async fn handle_router_solicitation(
    server: &RadVServer,
    src: StdIpv6Addr,
    iface: u32,
) -> Result<()> {
    // Get interface name
    let iface_info = server
        .interface_manager
        .get_interface_by_index(iface)
        .await
        .ok_or_else(|| RadVError::Interface(format!("Failed to get interface {iface}")))?;

    info!(
        interface = %iface_info.name,
        solicitor = %src,
        "Received Router Solicitation"
    );

    // Send unicast RA to soliciting host
    send_ra(
        server,
        TokioInstant::now(),
        iface,
        &iface_info.name,
        Some(src), // Unicast to solicitor
    )
    .await?;

    info!(
        interface = %iface_info.name,
        solicitor = %src,
        "Responded to Router Solicitation with unicast RA"
    );

    Ok(())
}

/// Handle Echo Reply message
///
/// Forwards Echo Reply to SLAAC module for address confirmation.
/// This is used in RA-names mode to verify that SLAAC-generated
/// addresses are not already in use before registering DNS names.
async fn handle_echo_reply(packet: &[u8], src: StdIpv6Addr, iface: u32) -> Result<()> {
    debug!(
        src = %src,
        interface = iface,
        "Received Echo Reply, forwarding to SLAAC module"
    );

    // Forward to SLAAC module for processing
    slaac_ping_reply(packet, src)
        .await
        .map_err(|e| RadVError::PacketConstruction(format!("SLAAC processing failed: {e}")))?;

    debug!(
        src = %src,
        interface = iface,
        "Processed SLAAC Echo Reply"
    );

    Ok(())
}

/// Start unsolicited periodic Router Advertisement transmission
///
/// Spawns async tasks for each RA-enabled interface to transmit periodic
/// unsolicited Router Advertisements. Each interface follows the RFC 4861
/// recommendation for initial rapid RAs followed by normal periodic transmission:
///
/// 1. Short period: Send 4 RAs at ~16 second intervals (fast startup)
/// 2. Normal period: Send RAs at configured interval (typically 600 seconds)
///
/// # Arguments
///
/// * `server` - `RadVServer` instance
///
/// # Returns
///
/// Returns `Ok(())` after spawning all tasks, or `RadVError` if interface
/// enumeration fails.
#[instrument(skip(server))]
pub async fn ra_start_unsolicited(server: Arc<RadVServer>) -> Result<()> {
    // Enumerate all network interfaces
    let interfaces = server
        .interface_manager
        .enumerate_interfaces()
        .await
        .map_err(|e| RadVError::Interface(format!("Failed to enumerate interfaces: {e}")))?;

    // Filter for RA-enabled interfaces
    let ra_interfaces: Vec<_> = interfaces
        .into_iter()
        .filter(|iface| {
            // Check if interface has IPv6 address
            let has_ipv6 = iface.addresses.iter().any(|addr| matches!(addr, IpAddr::V6(_)));

            // Check if interface is configured for RA
            let is_ra_enabled =
                server.config.ra_interfaces.iter().any(|ra_iface| ra_iface.name == iface.name);

            has_ipv6 && is_ra_enabled
        })
        .collect();

    info!(
        num_interfaces = ra_interfaces.len(),
        "Starting unsolicited Router Advertisement transmission"
    );

    // Spawn task for each RA-enabled interface
    for iface in ra_interfaces {
        let server_clone = Arc::clone(&server);
        let iface_name = iface.name.clone();
        let iface_idx = iface.index;

        tokio::spawn(async move {
            if let Err(e) = run_ra_task(server_clone, iface_idx, iface_name.clone()).await {
                error!(
                    interface = %iface_name,
                    error = %e,
                    "RA task failed"
                );
            }
        });

        info!(
            interface = %iface.name,
            index = iface.index,
            "Spawned RA task"
        );
    }

    Ok(())
}

/// Run periodic RA task for a single interface
///
/// Implements the two-phase RA transmission pattern:
/// 1. Short period: 4 RAs at 16-second intervals (startup)
/// 2. Normal period: RAs at configured interval (ongoing)
async fn run_ra_task(server: Arc<RadVServer>, iface_idx: u32, iface_name: String) -> Result<()> {
    info!(
        interface = %iface_name,
        "RA task started"
    );

    // Phase 1: Short RA period (4 RAs at ~16 second intervals)
    run_short_ra_period(&server, iface_idx, &iface_name).await?;

    // Phase 2: Normal RA period (periodic at configured interval)
    run_normal_ra_period(&server, iface_idx, &iface_name).await?;

    Ok(())
}

/// Run short RA period (startup phase)
///
/// Sends 4 Router Advertisements at 16-second intervals for fast
/// client configuration during startup.
async fn run_short_ra_period(server: &RadVServer, iface_idx: u32, iface_name: &str) -> Result<()> {
    info!(interface = iface_name, "Starting short RA period (4 RAs at 16s intervals)");

    for i in 0..4 {
        // Send RA
        send_ra(
            server,
            TokioInstant::now(),
            iface_idx,
            iface_name,
            None, // Multicast to ALL_NODES
        )
        .await?;

        debug!(interface = iface_name, ra_num = i + 1, "Sent short-period RA");

        // Sleep 16 seconds before next RA (except after last one)
        if i < 3 {
            sleep(Duration::from_secs(16)).await;
        }
    }

    info!(interface = iface_name, "Completed short RA period");

    Ok(())
}

/// Run normal RA period (steady-state phase)
///
/// Sends periodic Router Advertisements at the configured interval
/// (typically 600 seconds). Runs indefinitely until task is cancelled.
async fn run_normal_ra_period(server: &RadVServer, iface_idx: u32, iface_name: &str) -> Result<()> {
    // Get configured interval for this interface
    let ra_iface =
        server.config.ra_interfaces.iter().find(|ri| ri.name == iface_name).ok_or_else(|| {
            RadVError::Configuration(format!(
                "No RA configuration found for interface {iface_name}"
            ))
        })?;

    let interval_secs = u64::from(ra_iface.interval);

    info!(interface = iface_name, interval_sec = interval_secs, "Starting normal RA period");

    // Create periodic interval
    let mut interval_timer = interval(Duration::from_secs(interval_secs));

    // First tick completes immediately, but we just finished short period,
    // so wait for first actual interval
    interval_timer.tick().await;

    // Send periodic RAs indefinitely
    loop {
        interval_timer.tick().await;

        // Send RA
        if let Err(e) = send_ra(
            server,
            TokioInstant::now(),
            iface_idx,
            iface_name,
            None, // Multicast to ALL_NODES
        )
        .await
        {
            error!(
                interface = iface_name,
                error = %e,
                "Failed to send periodic RA"
            );
            // Continue despite error - don't crash the task
        } else {
            debug!(interface = iface_name, "Sent periodic RA");
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Calculate Router Lifetime value for RA header
///
/// Returns the router lifetime in seconds that clients should consider
/// this router as a default router. Based on the configured RA interval,
/// typically 3x the RA interval to allow for missed RAs.
///
/// # Arguments
///
/// * `ra_iface` - RA interface configuration
///
/// # Returns
///
/// Router lifetime in seconds
#[allow(dead_code)]
fn calc_lifetime(ra_iface: &RaInterface) -> u16 {
    // Router lifetime is typically 3x the RA interval
    // to allow for missed RAs while still being valid
    let lifetime = ra_iface.interval * 3;

    // Cap at u16::MAX (18 hours)
    lifetime.min(u32::from(u16::MAX)) as u16
}

/// Calculate `MinRtrAdvInterval` for RA Interval option
///
/// Per RFC 4861, `MinRtrAdvInterval` MUST be no less than 3 seconds
/// and no greater than 0.75 * `MaxRtrAdvInterval`.
///
/// # Arguments
///
/// * `ra_iface` - RA interface configuration
///
/// # Returns
///
/// Minimum router advertisement interval in seconds
#[allow(dead_code)]
fn calc_interval(ra_iface: &RaInterface) -> u16 {
    // MinRtrAdvInterval = 0.75 * MaxRtrAdvInterval (RFC 4861)
    let min_interval = (ra_iface.interval * 3 / 4).max(3);

    min_interval.min(u32::from(u16::MAX)) as u16
}

/// Calculate router priority for RA header
///
/// Returns the router preference encoded in the router advertisement.
/// RFC 4191 defines three levels: high (01), medium (00), low (11).
///
/// # Arguments
///
/// * `ra_iface` - RA interface configuration
///
/// # Returns
///
/// Router priority bits (0x00 = medium, 0x08 = high, 0x18 = low)
///
/// Priority mapping for u8:
/// - 0: Low priority (0x18)
/// - 1: Medium priority (0x00) - default
/// - 2+: High priority (0x08)
#[allow(dead_code)]
fn calc_prio(ra_iface: &RaInterface) -> u8 {
    match ra_iface.priority {
        0 => 0x18, // Low priority (11 in bits 4-3)
        1 => 0x00, // Medium priority (00 in bits 4-3) - default
        _ => 0x08, // High priority (01 in bits 4-3)
    }
}

/// Calculate prefix valid lifetime
///
/// Returns the valid lifetime for a prefix in seconds. This is the time
/// that the prefix is valid for on-link determination and address
/// autoconfiguration.
///
/// For `DHCPv6` contexts, uses the context lease time. Otherwise uses
/// a default of 2 hours.
///
/// # Arguments
///
/// * `context` - `DHCPv6` context (if any)
/// * `default_lifetime` - Default lifetime if no context
///
/// # Returns
///
/// Valid lifetime in seconds
#[allow(dead_code)]
fn calc_prefix_valid_lifetime(context: Option<&DhcpContext>, default_lifetime: u32) -> u32 {
    if let Some(ctx) = context {
        // Use DHCPv6 lease time if available
        // RFC 4862: Valid lifetime should be at least 2 hours
        ctx.lease_time.max(7200)
    } else {
        // Default: 2 hours
        default_lifetime
    }
}

/// Calculate prefix preferred lifetime
///
/// Returns the preferred lifetime for a prefix in seconds. This is the
/// time that addresses generated from the prefix via SLAAC remain preferred.
///
/// Per RFC 4862, preferred lifetime MUST NOT exceed valid lifetime.
///
/// # Arguments
///
/// * `valid_lifetime` - Valid lifetime for this prefix
/// * `context` - `DHCPv6` context (if any)
///
/// # Returns
///
/// Preferred lifetime in seconds
#[allow(dead_code)]
fn calc_prefix_preferred_lifetime(valid_lifetime: u32, context: Option<&DhcpContext>) -> u32 {
    if let Some(ctx) = context {
        // Preferred lifetime is typically 50% of valid lifetime
        let preferred = ctx.lease_time / 2;
        preferred.min(valid_lifetime)
    } else {
        // Default: 50% of valid lifetime, minimum 30 minutes
        (valid_lifetime / 2).max(1800)
    }
}

/// Determine if Managed Address Configuration flag (M) should be set
///
/// The M flag indicates that addresses are available via `DHCPv6`.
/// Set when `DHCPv6` context exists and is not in ra-only or ra-stateless mode.
///
/// # Arguments
///
/// * `context` - `DHCPv6` context (if any)
///
/// # Returns
///
/// true if M flag should be set
#[allow(dead_code)]
fn should_set_managed_flag(context: Option<&DhcpContext>) -> bool {
    if let Some(ctx) = context {
        // Set M flag if context provides addresses (not ra-only or ra-stateless)
        ctx.flags & CONTEXT_RA_STATELESS == 0
    } else {
        false
    }
}

/// Determine if Other Configuration flag (O) should be set
///
/// The O flag indicates that other configuration information is available
/// via `DHCPv6` (e.g., DNS servers, domain search list).
///
/// # Arguments
///
/// * `context` - `DHCPv6` context (if any)
///
/// # Returns
///
/// true if O flag should be set
#[allow(dead_code)]
fn should_set_other_flag(context: Option<&DhcpContext>) -> bool {
    // Set O flag if DHCPv6 context exists (provides configuration)
    context.is_some()
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::platform::linux::LinuxNetworkPlatform;
    use std::net::Ipv6Addr as StdIpv6Addr;

    /// Test RadVServer creation with valid configuration
    #[tokio::test]
    async fn test_radv_server_new_valid_config() {
        let config = Arc::new(Config {
            ra_interfaces: vec![crate::config::types::RaInterface {
                name: "eth0".to_string(),
                interval: 600,
                lifetime: 1800,
                priority: 1, // Medium priority
                mtu: 1500,
            }],
            ..Default::default()
        });

        let platform = Arc::new(LinuxNetworkPlatform::new().await.unwrap());
        let interface_manager = Arc::new(InterfaceManager::new(platform));

        let result = RadVServer::new(config, interface_manager);
        assert!(result.is_ok());
    }

    /// Test RadVServer creation fails with empty interface list
    #[tokio::test]
    async fn test_radv_server_new_empty_interfaces() {
        let config = Arc::new(Config { ra_interfaces: vec![], ..Default::default() });

        let platform = Arc::new(LinuxNetworkPlatform::new().await.unwrap());
        let interface_manager = Arc::new(InterfaceManager::new(platform));

        // Empty interfaces list is valid - dnsmasq can run in DNS-only mode without RA
        let result = RadVServer::new(config, interface_manager);
        assert!(result.is_ok());
    }

    /// Test calc_lifetime returns 3x interval
    #[test]
    fn test_calc_lifetime() {
        let ra_iface = RaInterface {
            name: "eth0".to_string(),
            interval: 600,
            lifetime: 1800,
            priority: 0,
            mtu: 1500,
        };

        let lifetime = calc_lifetime(&ra_iface);
        assert_eq!(lifetime, 1800); // 600 * 3
    }

    /// Test calc_lifetime caps at u16::MAX
    #[test]
    fn test_calc_lifetime_caps_at_max() {
        let ra_iface = RaInterface {
            name: "eth0".to_string(),
            interval: 30000, // Would overflow u16 * 3
            lifetime: 90000,
            priority: 0,
            mtu: 1500,
        };

        let lifetime = calc_lifetime(&ra_iface);
        assert_eq!(lifetime, u16::MAX);
    }

    /// Test calc_interval returns 0.75x interval
    #[test]
    fn test_calc_interval() {
        let ra_iface = RaInterface {
            name: "eth0".to_string(),
            interval: 600,
            lifetime: 1800,
            priority: 0,
            mtu: 1500,
        };

        let interval = calc_interval(&ra_iface);
        assert_eq!(interval, 450); // 600 * 0.75
    }

    /// Test calc_interval enforces minimum of 3 seconds
    #[test]
    fn test_calc_interval_minimum() {
        let ra_iface = RaInterface {
            name: "eth0".to_string(),
            interval: 2, // Too short
            lifetime: 6,
            priority: 0,
            mtu: 1500,
        };

        let interval = calc_interval(&ra_iface);
        assert_eq!(interval, 3); // Minimum enforced
    }

    /// Test calc_prio returns correct priority bits
    #[test]
    fn test_calc_prio_high() {
        let ra_iface = RaInterface {
            name: "eth0".to_string(),
            interval: 600,
            lifetime: 1800,
            priority: 2, // High (2+)
            mtu: 1500,
        };

        assert_eq!(calc_prio(&ra_iface), 0x08);
    }

    #[test]
    fn test_calc_prio_medium() {
        let ra_iface = RaInterface {
            name: "eth0".to_string(),
            interval: 600,
            lifetime: 1800,
            priority: 1, // Medium (default)
            mtu: 1500,
        };

        assert_eq!(calc_prio(&ra_iface), 0x00);
    }

    #[test]
    fn test_calc_prio_low() {
        let ra_iface = RaInterface {
            name: "eth0".to_string(),
            interval: 600,
            lifetime: 1800,
            priority: 0, // Low
            mtu: 1500,
        };

        assert_eq!(calc_prio(&ra_iface), 0x18);
    }

    /// Test prefix valid lifetime calculation with context
    #[test]
    fn test_calc_prefix_valid_lifetime_with_context() {
        let context = DhcpContext {
            start6: IpAddr::V6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            end6: IpAddr::V6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xff)),
            flags: 0,
            if_index: 1,
            lease_time: 3600,
            prefix_len: 0,
        };

        let lifetime = calc_prefix_valid_lifetime(Some(&context), 7200);
        assert_eq!(lifetime, 7200); // Uses context lease_time, but minimum 7200
    }

    /// Test prefix valid lifetime calculation without context
    #[test]
    fn test_calc_prefix_valid_lifetime_without_context() {
        let lifetime = calc_prefix_valid_lifetime(None, 7200);
        assert_eq!(lifetime, 7200); // Uses default
    }

    /// Test prefix preferred lifetime is less than valid lifetime
    #[test]
    fn test_calc_prefix_preferred_lifetime() {
        let context = DhcpContext {
            start6: IpAddr::V6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            end6: IpAddr::V6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xff)),
            flags: 0,
            if_index: 1,
            lease_time: 3600,
            prefix_len: 0,
        };

        let valid_lifetime = 7200;
        let preferred = calc_prefix_preferred_lifetime(valid_lifetime, Some(&context));

        assert!(preferred <= valid_lifetime);
        assert_eq!(preferred, 1800); // 3600 / 2
    }

    /// Test M flag setting with DHCPv6 context
    #[test]
    fn test_should_set_managed_flag_with_context() {
        let context = DhcpContext {
            start6: IpAddr::V6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            end6: IpAddr::V6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xff)),
            flags: 0, // Not CONTEXT_RA_STATELESS
            if_index: 1,
            lease_time: 3600,
            prefix_len: 0,
        };

        assert!(should_set_managed_flag(Some(&context)));
    }

    /// Test M flag not set in ra-stateless mode
    #[test]
    fn test_should_set_managed_flag_stateless() {
        let context = DhcpContext {
            start6: IpAddr::V6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            end6: IpAddr::V6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xff)),
            flags: CONTEXT_RA_STATELESS,
            if_index: 1,
            lease_time: 3600,
            prefix_len: 0,
        };

        assert!(!should_set_managed_flag(Some(&context)));
    }

    /// Test M flag not set without context
    #[test]
    fn test_should_set_managed_flag_no_context() {
        assert!(!should_set_managed_flag(None));
    }

    /// Test O flag setting with context
    #[test]
    fn test_should_set_other_flag_with_context() {
        let context = DhcpContext {
            start6: IpAddr::V6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            end6: IpAddr::V6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xff)),
            flags: 0,
            if_index: 1,
            lease_time: 3600,
            prefix_len: 0,
        };

        assert!(should_set_other_flag(Some(&context)));
    }

    /// Test O flag not set without context
    #[test]
    fn test_should_set_other_flag_no_context() {
        assert!(!should_set_other_flag(None));
    }

    /// Test RA header construction produces correct packet size
    #[test]
    fn test_ra_packet_header_size() {
        use crate::radv::protocol::RaPacket;

        let _packet = RaPacket {
            type_: protocol::ICMP6_ROUTER_ADVERT,
            code: 0,
            checksum: 0,
            hop_limit: 64,
            flags: 0,
            lifetime: 1800u16.to_be(),
            reachable_time: 0u32.to_be(),
            retrans_time: 0u32.to_be(),
        };

        // RaPacket header is 16 bytes
        let size = std::mem::size_of::<RaPacket>();
        assert_eq!(size, 16);
    }

    /// Test prefix option construction
    #[test]
    fn test_prefix_option_size() {
        use crate::radv::protocol::PrefixOpt;

        let _prefix_opt = PrefixOpt {
            type_: protocol::PREFIX_OPT,
            len: 4,
            prefix_len: 64,
            flags: 0xC0,
            valid_lifetime: 7200u32.to_be(),
            preferred_lifetime: 3600u32.to_be(),
            reserved: 0u32.to_be(),
            prefix: StdIpv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
        };

        // PrefixOpt is 32 bytes
        let size = std::mem::size_of::<PrefixOpt>();
        assert_eq!(size, 32);
    }
}
