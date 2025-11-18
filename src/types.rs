// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Common types used throughout dnsmasq
//!
//! This module defines foundational types, enums, and structures that are
//! shared across multiple modules. These replace the type definitions from
//! the C implementation's `dnsmasq.h` header file.
//!
//! # Key Types
//!
//! - `DomainName`: DNS domain name representation
//! - `IpAddress`: Unified IPv4/IPv6 address type
//! - `MacAddress`: Ethernet MAC address
//! - `Timestamp`: Time representation for leases and caching
//! - `RecordType`: DNS resource record types
//! - `ProtocolFamily`: Address family (IPv4/IPv6)
//!
//! # Type Conversions
//!
//! The C implementation used type aliases like `u8`, `u16`, `u32`, `u64`.
//! In Rust, we use the native `u8`, `u16`, `u32`, `u64` types directly,
//! which provide the same guarantees with better language integration.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime};

/// DNS domain name
///
/// Represents a fully-qualified or relative domain name. Domain names in DNS
/// have specific constraints: maximum length 255 bytes, labels maximum 63 bytes,
/// case-insensitive comparison.
///
/// This type replaces the C implementation's `char*` domain name handling with
/// memory-safe ownership semantics.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainName {
    /// The domain name as a string
    name: String,
}

impl DomainName {
    /// Create a new domain name
    ///
    /// # Arguments
    ///
    /// * `name` - The domain name string
    ///
    /// # Errors
    ///
    /// Returns an error if the name exceeds DNS limits (255 bytes total,
    /// 63 bytes per label).
    pub fn new(name: impl Into<String>) -> Result<Self, String> {
        let name = name.into();

        // Validate DNS name constraints
        if name.len() > 255 {
            return Err(format!("Domain name too long: {} bytes (max 255)", name.len()));
        }

        // Validate label lengths
        for label in name.split('.') {
            if label.len() > 63 {
                return Err(format!(
                    "Domain label '{}' too long: {} bytes (max 63)",
                    label,
                    label.len()
                ));
            }
        }

        Ok(Self { name })
    }

    /// Create a domain name without validation (for internal use)
    pub fn new_unchecked(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Get the domain name as a string slice
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Check if this is a subdomain of another domain
    pub fn is_subdomain_of(&self, parent: &DomainName) -> bool {
        self.name.ends_with(&parent.name)
    }

    /// Get the number of labels in the domain name
    pub fn label_count(&self) -> usize {
        self.name.split('.').filter(|s| !s.is_empty()).count()
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl From<DomainName> for String {
    fn from(name: DomainName) -> String {
        name.name
    }
}

/// Unified IP address type
///
/// This is a re-export of `std::net::IpAddr` for consistency with the rest
/// of the codebase. It provides a type-safe union of IPv4 and IPv6 addresses,
/// replacing the C implementation's `union all_addr`.
pub type IpAddress = IpAddr;

/// IPv4 address type
///
/// Re-export of `std::net::Ipv4Addr` for consistency.
pub type Ipv4Address = Ipv4Addr;

/// IPv6 address type
///
/// Re-export of `std::net::Ipv6Addr` for consistency.
pub type Ipv6Address = Ipv6Addr;

/// Socket address (IP + port)
///
/// Re-export of `std::net::SocketAddr` for consistency.
pub type SocketAddress = SocketAddr;

/// MAC address (Ethernet hardware address)
///
/// Represents a 48-bit Ethernet MAC address. This replaces the C implementation's
/// use of raw byte arrays for hardware addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress {
    /// The 6-byte MAC address
    pub octets: [u8; 6],
}

impl MacAddress {
    /// Create a new MAC address from octets
    pub fn new(octets: [u8; 6]) -> Self {
        Self { octets }
    }

    /// Create a MAC address from a slice
    ///
    /// Returns None if the slice is not exactly 6 bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == 6 {
            let mut octets = [0u8; 6];
            octets.copy_from_slice(slice);
            Some(Self { octets })
        } else {
            None
        }
    }

    /// Parse a MAC address from a string
    ///
    /// Accepts formats like "00:11:22:33:44:55" or "00-11-22-33-44-55"
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = if s.contains(':') {
            s.split(':').collect()
        } else if s.contains('-') {
            s.split('-').collect()
        } else {
            return Err("Invalid MAC address format".to_string());
        };

        if parts.len() != 6 {
            return Err(format!("MAC address must have 6 octets, got {}", parts.len()));
        }

        let mut octets = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            octets[i] = u8::from_str_radix(part, 16)
                .map_err(|e| format!("Invalid hex octet '{}': {}", part, e))?;
        }

        Ok(Self { octets })
    }

    /// Check if this is a broadcast MAC address
    pub fn is_broadcast(&self) -> bool {
        self.octets == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    }

    /// Check if this is a multicast MAC address
    pub fn is_multicast(&self) -> bool {
        (self.octets[0] & 0x01) != 0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5]
        )
    }
}

/// Timestamp for lease times and cache entries
///
/// Wraps `SystemTime` for consistent time representation throughout dnsmasq.
/// The C implementation used `time_t` (seconds since epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub SystemTime);

impl Timestamp {
    /// Get the current timestamp
    pub fn now() -> Self {
        Self(SystemTime::now())
    }

    /// Create a timestamp from seconds since UNIX epoch
    pub fn from_secs(secs: u64) -> Self {
        Self(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
    }

    /// Get seconds since UNIX epoch
    pub fn as_secs(&self) -> u64 {
        self.0.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    /// Add a duration to this timestamp
    pub fn add(&self, duration: Duration) -> Self {
        Self(self.0 + duration)
    }

    /// Subtract a duration from this timestamp
    pub fn sub(&self, duration: Duration) -> Self {
        Self(self.0 - duration)
    }

    /// Get duration since another timestamp
    pub fn duration_since(&self, earlier: Timestamp) -> Duration {
        self.0.duration_since(earlier.0).unwrap_or_default()
    }

    /// Check if this timestamp is in the past
    pub fn is_past(&self) -> bool {
        self.0 < SystemTime::now()
    }

    /// Check if this timestamp is in the future
    pub fn is_future(&self) -> bool {
        self.0 > SystemTime::now()
    }
}

impl From<SystemTime> for Timestamp {
    fn from(time: SystemTime) -> Self {
        Self(time)
    }
}

impl From<Timestamp> for SystemTime {
    fn from(ts: Timestamp) -> Self {
        ts.0
    }
}

/// DNS record type
///
/// Represents DNS resource record (RR) types as defined in RFC 1035 and
/// subsequent RFCs. This replaces the C implementation's integer constants
/// with a type-safe enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordType {
    /// IPv4 address
    A = 1,
    /// Name server
    NS = 2,
    /// Canonical name (alias)
    CNAME = 5,
    /// Start of authority
    SOA = 6,
    /// Pointer record (reverse DNS)
    PTR = 12,
    /// Mail exchange
    MX = 15,
    /// Text record
    TXT = 16,
    /// IPv6 address
    AAAA = 28,
    /// Service locator
    SRV = 33,
    /// DNSSEC signature
    RRSIG = 46,
    /// Next secure record
    NSEC = 47,
    /// DNSSEC key
    DNSKEY = 48,
    /// DNSSEC next secure record (hashed)
    NSEC3 = 50,
    /// DNSSEC next secure record parameters
    NSEC3PARAM = 51,
    /// Certificate authority authorization
    CAA = 257,
}

impl RecordType {
    /// Convert from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(RecordType::A),
            2 => Some(RecordType::NS),
            5 => Some(RecordType::CNAME),
            6 => Some(RecordType::SOA),
            12 => Some(RecordType::PTR),
            15 => Some(RecordType::MX),
            16 => Some(RecordType::TXT),
            28 => Some(RecordType::AAAA),
            33 => Some(RecordType::SRV),
            46 => Some(RecordType::RRSIG),
            47 => Some(RecordType::NSEC),
            48 => Some(RecordType::DNSKEY),
            50 => Some(RecordType::NSEC3),
            51 => Some(RecordType::NSEC3PARAM),
            257 => Some(RecordType::CAA),
            _ => None,
        }
    }

    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::NS => write!(f, "NS"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::PTR => write!(f, "PTR"),
            RecordType::MX => write!(f, "MX"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::SRV => write!(f, "SRV"),
            RecordType::RRSIG => write!(f, "RRSIG"),
            RecordType::NSEC => write!(f, "NSEC"),
            RecordType::DNSKEY => write!(f, "DNSKEY"),
            RecordType::NSEC3 => write!(f, "NSEC3"),
            RecordType::NSEC3PARAM => write!(f, "NSEC3PARAM"),
            RecordType::CAA => write!(f, "CAA"),
        }
    }
}

/// Protocol family (address family)
///
/// Distinguishes between IPv4 and IPv6 protocols. Replaces the C implementation's
/// AF_INET/AF_INET6 constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolFamily {
    /// IPv4 (AF_INET)
    IPv4,
    /// IPv6 (AF_INET6)
    IPv6,
}

impl ProtocolFamily {
    /// Get the protocol family for an IP address
    pub fn from_ip(addr: IpAddress) -> Self {
        match addr {
            IpAddress::V4(_) => ProtocolFamily::IPv4,
            IpAddress::V6(_) => ProtocolFamily::IPv6,
        }
    }
}

/// DHCP transaction ID (XID)
///
/// 32-bit transaction identifier used in DHCP messages to match requests
/// and responses. The C implementation used `u32` directly.
pub type TransactionId = u32;

/// DNS query ID
///
/// 16-bit identifier used in DNS messages to match queries and responses.
/// The C implementation used `u16` directly.
pub type QueryId = u16;

/// Time-to-live (TTL) for DNS records
///
/// 32-bit value representing the number of seconds a DNS record should be
/// cached. The C implementation used `u32` directly.
pub type Ttl = u32;

/// Port number
///
/// 16-bit port number for network services. The C implementation used `u16`
/// directly.
pub type Port = u16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_name_creation() {
        let name = DomainName::new("example.com").unwrap();
        assert_eq!(name.as_str(), "example.com");
        assert_eq!(name.label_count(), 2);
    }

    #[test]
    fn test_domain_name_too_long() {
        let long_name = "a".repeat(256);
        assert!(DomainName::new(long_name).is_err());
    }

    #[test]
    fn test_domain_name_label_too_long() {
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(DomainName::new(long_label).is_err());
    }

    #[test]
    fn test_domain_name_subdomain() {
        let parent = DomainName::new("example.com").unwrap();
        let subdomain = DomainName::new("sub.example.com").unwrap();
        assert!(subdomain.is_subdomain_of(&parent));
        assert!(!parent.is_subdomain_of(&subdomain));
    }

    #[test]
    fn test_mac_address_creation() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(mac.to_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn test_mac_address_parse() {
        let mac = MacAddress::parse("00:11:22:33:44:55").unwrap();
        assert_eq!(mac.octets, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let mac2 = MacAddress::parse("00-11-22-33-44-55").unwrap();
        assert_eq!(mac2.octets, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_mac_address_broadcast() {
        let broadcast = MacAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert!(broadcast.is_broadcast());

        let normal = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(!normal.is_broadcast());
    }

    #[test]
    fn test_mac_address_multicast() {
        let multicast = MacAddress::new([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        assert!(multicast.is_multicast());

        let normal = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(!normal.is_multicast());
    }

    #[test]
    fn test_timestamp_now() {
        let ts1 = Timestamp::now();
        let ts2 = Timestamp::now();
        assert!(ts2.as_secs() >= ts1.as_secs());
    }

    #[test]
    fn test_timestamp_from_secs() {
        let ts = Timestamp::from_secs(1609459200); // 2021-01-01 00:00:00 UTC
        assert_eq!(ts.as_secs(), 1609459200);
    }

    #[test]
    fn test_timestamp_arithmetic() {
        let ts = Timestamp::now();
        let future = ts.add(Duration::from_secs(3600)); // 1 hour in future
        assert!(future.is_future());

        let past = ts.sub(Duration::from_secs(3600)); // 1 hour in past
        assert!(past.is_past());
    }

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::from_u16(1), Some(RecordType::A));
        assert_eq!(RecordType::from_u16(28), Some(RecordType::AAAA));
        assert_eq!(RecordType::from_u16(999), None);

        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::AAAA.to_u16(), 28);
    }

    #[test]
    fn test_protocol_family_from_ip() {
        let ipv4 = IpAddress::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ProtocolFamily::from_ip(ipv4), ProtocolFamily::IPv4);

        let ipv6 = IpAddress::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(ProtocolFamily::from_ip(ipv6), ProtocolFamily::IPv6);
    }
}
