// Copyright (C) 2024 Dnsmasq Contributors
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0

//! IPv6 Router Advertisement (RA) Module
//!
//! This module implements IPv6 Router Advertisement functionality as defined in
//! RFC 4861 (Neighbor Discovery for IP version 6). It provides the protocol
//! structures and constants needed for generating and handling ICMPv6 Router
//! Advertisement messages.
//!
//! # Components
//!
//! - `protocol`: Protocol constants and wire-format packet structures
//!
//! # Standards Compliance
//!
//! This implementation follows:
//! - RFC 4861: Neighbor Discovery for IPv6
//! - RFC 4862: IPv6 Stateless Address Autoconfiguration
//! - RFC 6106: IPv6 Router Advertisement Options for DNS Configuration

pub mod protocol;
pub mod slaac;

// Re-export commonly used types for convenience
pub use protocol::{
    NeighPacket,
    // Packet structures
    PingPacket,
    PrefixOpt,
    RaPacket,
    // Multicast addresses
    ALL_NODES,
    ALL_ROUTERS,
    DNSSL_OPT,
    ICMP6_ECHO_REPLY,
    // ICMPv6 type constants
    ICMP6_ECHO_REQUEST,
    ICMP6_NEIGH_ADVERT,
    ICMP6_NEIGH_SOLICIT,
    ICMP6_ROUTER_ADVERT,
    INTERVAL_OPT,
    MTU_OPT,
    PREFIX_OPT,
    RDNSS_OPT,
    ROUTE_OPT,
    // Neighbor Discovery option types
    SOURCE_MAC_OPT,
};

// Re-export SLAAC functionality
pub use slaac::{eui64_from_mac, periodic_slaac, slaac_add_addrs, slaac_ping_reply, SlaacAddress};
