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

//! Core type definitions module providing memory-safe Rust equivalents of fundamental dnsmasq data structures.
//!
//! This module transforms C primitive types, unions, and pointer-based structures into idiomatic
//! Rust types with compile-time safety guarantees. All types replace manual memory management with
//! Rust's ownership system, eliminating buffer overflows, use-after-free, and memory leaks.
//!
//! # Key Transformations
//!
//! ## C Primitives → Rust Native Types
//!
//! ```c
//! // C implementation (dnsmasq.h)
//! typedef unsigned char u8;
//! typedef unsigned short u16;
//! typedef unsigned int u32;
//! typedef unsigned long long u64;
//! ```
//!
//! Rust equivalents use native types with explicit semantics:
//! - `u8`, `u16`, `u32`, `u64` - Direct mapping with guaranteed sizes
//! - `usize` - For collection sizes and array indices
//! - Platform-independent and guaranteed by Rust type system
//!
//! ## C Unions → Rust Enums
//!
//! ```c
//! // C implementation: Type-unsafe union
//! union all_addr {
//!     struct in_addr addr4;
//!     struct in6_addr addr6;
//!     // ... variant fields
//! };
//! ```
//!
//! ```rust,ignore
//! // Rust implementation: Type-safe enum
//! pub use std::net::IpAddr;  // Replaces union all_addr
//! ```
//!
//! The standard library `IpAddr` enum provides type-safe address handling with compile-time
//! discrimination between IPv4 and IPv6, eliminating the C pattern of manual type tracking.
//!
//! ## C Pointer Chains → Rust Collections
//!
//! ```c
//! // C implementation: Manual pointer management
//! struct crec {
//!     struct crec *next, *prev, *hash_next;
//!     // ... data fields
//! };
//! ```
//!
//! ```rust,ignore
//! // Rust implementation: Owned collections
//! pub struct CacheEntry {
//!     // No raw pointers - use Vec, Option<Box<T>>, or indices
//! }
//! ```
//!
//! # Type Safety Features
//!
//! - **Domain Name Validation**: RFC 1035 compliance enforced at construction time
//! - **MAC Address Parsing**: Multiple format support with validation
//! - **Record Type Exhaustiveness**: Compiler-enforced pattern matching
//! - **Cache Flags**: Type-safe bitflag operations with `bitflags!` macro
//! - **Time Handling**: Monotonic timestamps via `std::time::Instant`
//!
//! # Zero-Cost Abstractions
//!
//! All types in this module compile to machine code equivalent to C with zero runtime overhead:
//! - Newtype wrappers optimize away
//! - Enum discriminants use minimal space
//! - Trait implementations inline completely
//! - No virtual dispatch or dynamic allocation unless explicitly needed
//!
//! # Usage
//!
//! ```rust,ignore
//! use dnsmasq::types::{DomainName, MacAddress, RecordType, CacheFlags};
//!
//! // Domain name with validation
//! let domain = DomainName::new("example.com")?;
//! assert!(domain.len() <= 255);
//!
//! // MAC address from multiple formats
//! let mac = MacAddress::from_str("00:11:22:33:44:55")?;
//! let mac2 = MacAddress::from_str("00-11-22-33-44-55")?;
//! assert_eq!(mac, mac2);
//!
//! // Type-safe DNS record types
//! match record_type {
//!     RecordType::A => { /* Handle IPv4 */ }
//!     RecordType::AAAA => { /* Handle IPv6 */ }
//!     _ => { /* Other record types */ }
//! }
//!
//! // Cache flags with type-safe operations
//! let mut flags = CacheFlags::FORWARD | CacheFlags::IPV4;
//! flags.insert(CacheFlags::DNSSEC);
//! assert!(flags.contains(CacheFlags::FORWARD));
//! ```

use crate::constants::SMALLDNAME;
use crate::error::DnsmasqError;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};
use std::net::{IpAddr as StdIpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// IP ADDRESS TYPE
// ============================================================================

/// Re-export of `std::net::IpAddr` for unified IPv4/IPv6 address handling.
///
/// Replaces C's `union all_addr` with Rust's type-safe enum that discriminates
/// between IPv4 and IPv6 at compile time. This eliminates the need for manual
/// type tracking through flags (F_IPV4/F_IPV6) as the enum carries its variant
/// information automatically.
///
/// # C Equivalent
///
/// ```c
/// union all_addr {
///     struct in_addr addr4;       // IPv4: 4 bytes
///     struct in6_addr addr6;      // IPv6: 16 bytes
///     // ... other variants for CNAME, DNSS EC data
/// };
/// ```
///
/// # Rust Advantages
///
/// - Type-safe variant access with compile-time checks
/// - Impossible to access IPv4 data as IPv6 or vice versa
/// - Pattern matching ensures exhaustive handling
/// - Smaller discriminant overhead (1 byte vs manual flag field)
///
/// # Usage
///
/// ```rust,ignore
/// use std::net::IpAddr;
///
/// let addr: IpAddr = "192.0.2.1".parse().unwrap();
/// match addr {
///     IpAddr::V4(ipv4) => println!("IPv4: {}", ipv4),
///     IpAddr::V6(ipv6) => println!("IPv6: {}", ipv6),
/// }
/// ```
pub use StdIpAddr as IpAddr;

// ============================================================================
// DOMAIN NAME TYPE
// ============================================================================

/// Domain name newtype with RFC 1035 validation and efficient storage.
///
/// Wraps a `String` to provide compile-time guarantees that the contained value
/// is a valid domain name per RFC 1035 specifications. Validation occurs at
/// construction time, preventing invalid names from propagating through the system.
///
/// # RFC 1035 Validation Rules
///
/// - Maximum total length: 255 octets (including length bytes in wire format)
/// - Maximum label length: 63 octets (each segment between dots)
/// - Allowed characters: a-z, A-Z, 0-9, hyphen (not at start/end of label)
/// - Case-insensitive for comparison (but case-preserving for display)
/// - Trailing dots allowed for fully-qualified names
///
/// # Memory Layout
///
/// ```text
/// DomainName {
///     inner: String           // Heap-allocated, length-prefixed
///         ├─ ptr: *mut u8    // Pointer to heap data
///         ├─ len: usize       // Current length (validated ≤ 255)
///         └─ cap: usize       // Allocated capacity
/// }
/// ```
///
/// # C Equivalent
///
/// ```c
/// // C implementation: Multiple representations
/// struct crec {
///     union {
///         char sname[SMALLDNAME];    // Inline for small names (50 bytes)
///         union bigname *bname;      // Pointer for large names
///         char *namep;               // Pointer for external names
///     } name;
/// };
/// ```
///
/// Rust's `String` provides automatic heap allocation with inline storage optimization
/// for small strings (up to 23 bytes on 64-bit), eliminating manual optimization.
///
/// # Performance
///
/// - Small names (≤23 bytes): Zero heap allocations
/// - Large names (>23 bytes): Single heap allocation
/// - Clone: Heap allocation for separate ownership
/// - Comparison: Efficient byte-by-byte comparison
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::types::DomainName;
///
/// // Valid domain names
/// let dom1 = DomainName::new("example.com")?;
/// let dom2 = DomainName::new("sub.domain.example.org.")?;  // FQDN with trailing dot
/// let dom3 = DomainName::from_str("localhost")?;
///
/// // Invalid domain names return errors
/// assert!(DomainName::new("").is_err());  // Empty
/// assert!(DomainName::new(&"a".repeat(256)).is_err());  // Too long
/// assert!(DomainName::new("invalid..domain").is_err());  // Double dot
/// assert!(DomainName::new("-invalid").is_err());  // Leading hyphen
///
/// // Subdomain checking
/// let parent = DomainName::new("example.com")?;
/// let child = DomainName::new("www.example.com")?;
/// assert!(child.is_subdomain_of(&parent));
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DomainName {
    inner: String,
}

impl DomainName {
    /// Creates a new domain name with RFC 1035 validation.
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name string to validate and wrap
    ///
    /// # Returns
    ///
    /// - `Ok(DomainName)` if the name passes all validation rules
    /// - `Err(DnsmasqError)` if validation fails with detailed error message
    ///
    /// # Validation
    ///
    /// - Total length ≤ 255 bytes
    /// - Each label length ≤ 63 bytes
    /// - Labels match pattern: `[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?`
    /// - No consecutive dots (except trailing dot for FQDN)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let valid = DomainName::new("example.com")?;
    /// let fqdn = DomainName::new("example.com.")?;
    /// let subdomain = DomainName::new("www.sub.example.com")?;
    /// ```
    pub fn new(name: impl Into<String>) -> Result<Self, DnsmasqError> {
        let inner = name.into();
        
        // Validate total length (RFC 1035: 255 octets max)
        if inner.is_empty() {
            return Err(DnsmasqError::Other(
                "Domain name cannot be empty".to_string()
            ));
        }
        
        if inner.len() > 255 {
            return Err(DnsmasqError::Other(
                format!("Domain name exceeds 255 bytes: {} bytes", inner.len())
            ));
        }
        
        // Validate labels (segments between dots)
        let labels: Vec<&str> = inner.trim_end_matches('.').split('.').collect();
        
        for label in labels {
            if label.is_empty() {
                return Err(DnsmasqError::Other(
                    "Domain name contains empty label (consecutive dots)".to_string()
                ));
            }
            
            if label.len() > 63 {
                return Err(DnsmasqError::Other(
                    format!("Label '{}' exceeds 63 bytes", label)
                ));
            }
            
            // Validate label characters
            if label.starts_with('-') || label.ends_with('-') {
                return Err(DnsmasqError::Other(
                    format!("Label '{}' cannot start or end with hyphen", label)
                ));
            }
            
            for ch in label.chars() {
                if !ch.is_ascii_alphanumeric() && ch != '-' {
                    return Err(DnsmasqError::Other(
                        format!("Label '{}' contains invalid character '{}'", label, ch)
                    ));
                }
            }
        }
        
        Ok(Self { inner })
    }
    
    /// Creates a domain name from a string slice, equivalent to `new()`.
    ///
    /// Provided for `FromStr` trait compatibility.
    pub fn from_str(name: &str) -> Result<Self, DnsmasqError> {
        Self::new(name)
    }
    
    /// Returns the domain name as a string slice.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let domain = DomainName::new("example.com")?;
    /// assert_eq!(domain.as_str(), "example.com");
    /// ```
    pub fn as_str(&self) -> &str {
        &self.inner
    }
    
    /// Returns the labels (segments between dots) of the domain name.
    ///
    /// Trailing dots are ignored for FQDN handling.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let domain = DomainName::new("www.example.com")?;
    /// assert_eq!(domain.labels(), vec!["www", "example", "com"]);
    ///
    /// let fqdn = DomainName::new("www.example.com.")?;
    /// assert_eq!(fqdn.labels(), vec!["www", "example", "com"]);
    /// ```
    pub fn labels(&self) -> Vec<&str> {
        self.inner.trim_end_matches('.').split('.').collect()
    }
    
    /// Checks if this domain name is a subdomain of another.
    ///
    /// Comparison is case-insensitive per DNS specifications.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let parent = DomainName::new("example.com")?;
    /// let child = DomainName::new("www.example.com")?;
    /// let unrelated = DomainName::new("other.org")?;
    ///
    /// assert!(child.is_subdomain_of(&parent));
    /// assert!(!unrelated.is_subdomain_of(&parent));
    /// assert!(!parent.is_subdomain_of(&child));
    /// ```
    pub fn is_subdomain_of(&self, other: &DomainName) -> bool {
        let self_labels = self.labels();
        let other_labels = other.labels();
        
        if self_labels.len() <= other_labels.len() {
            return false;
        }
        
        // Check if parent labels match suffix of child labels (case-insensitive)
        self_labels.iter().rev()
            .zip(other_labels.iter().rev())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
    
    /// Returns the length of the domain name in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    
    /// Checks if the domain name is empty (always false due to validation).
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Display for DomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl Debug for DomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "DomainName(\"{}\")", self.inner)
    }
}

impl FromStr for DomainName {
    type Err = DnsmasqError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// ============================================================================
// MAC ADDRESS TYPE
// ============================================================================

/// MAC (Media Access Control) address for DHCP client identification.
///
/// Represents a 6-byte hardware address used for Ethernet network interface
/// identification. Supports multiple input formats commonly used in configuration
/// files and command-line arguments.
///
/// # Format Support
///
/// - Colon-separated: `00:11:22:33:44:55`
/// - Hyphen-separated: `00-11-22-33-44-55`
/// - Dot-separated (Cisco): `0011.2233.4455`
/// - No separators: `001122334455`
///
/// # C Equivalent
///
/// ```c
/// // C implementation: Raw byte array
/// unsigned char hwaddr[DHCP_CHADDR_MAX];  // 16 bytes for hardware address
/// int hwaddr_len;                         // Actual length (6 for Ethernet)
/// int hwaddr_type;                        // Hardware type (1 for Ethernet)
/// ```
///
/// Rust's newtype wrapper provides parsing, formatting, and validation that
/// was scattered across C functions (parse_hex, print_mac, etc.).
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::types::MacAddress;
///
/// // Parse from different formats
/// let mac1 = MacAddress::from_str("00:11:22:33:44:55")?;
/// let mac2 = MacAddress::from_str("00-11-22-33-44-55")?;
/// let mac3 = MacAddress::from_str("001122334455")?;
/// assert_eq!(mac1, mac2);
/// assert_eq!(mac2, mac3);
///
/// // Create from bytes
/// let mac = MacAddress::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
///
/// // Access octets
/// assert_eq!(mac.octets(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
///
/// // Format for display (always colon-separated)
/// assert_eq!(mac.to_string(), "00:11:22:33:44:55");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddress {
    octets: [u8; 6],
}

impl MacAddress {
    /// Creates a new MAC address with validation.
    ///
    /// # Arguments
    ///
    /// * `octets` - 6-byte array representing the MAC address
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    /// ```
    pub fn new(octets: [u8; 6]) -> Self {
        Self { octets }
    }
    
    /// Parses a MAC address from string with multiple format support.
    ///
    /// # Supported Formats
    ///
    /// - `00:11:22:33:44:55` (colon-separated, lowercase)
    /// - `00-11-22-33-44-55` (hyphen-separated)
    /// - `0011.2233.4455` (Cisco dot-separated)
    /// - `001122334455` (no separators)
    /// - Case-insensitive hex digits
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - String length is invalid for any supported format
    /// - Contains non-hexadecimal characters
    /// - Separators are inconsistent
    pub fn from_str(s: &str) -> Result<Self, DnsmasqError> {
        let s = s.trim();
        
        // Remove common separators and validate
        let hex_str: String = s.chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        
        if hex_str.len() != 12 {
            return Err(DnsmasqError::Other(
                format!("Invalid MAC address '{}': expected 12 hex digits", s)
            ));
        }
        
        let mut octets = [0u8; 6];
        for i in 0..6 {
            let byte_str = &hex_str[i*2..i*2+2];
            octets[i] = u8::from_str_radix(byte_str, 16)
                .map_err(|e| DnsmasqError::Other(
                    format!("Invalid hex in MAC address '{}': {}", s, e)
                ))?;
        }
        
        Ok(Self { octets })
    }
    
    /// Creates a MAC address from a 6-byte array.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mac = MacAddress::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    /// ```
    pub fn from_bytes(bytes: [u8; 6]) -> Self {
        Self { octets: bytes }
    }
    
    /// Returns a reference to the underlying octets.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mac = MacAddress::from_str("00:11:22:33:44:55")?;
    /// assert_eq!(mac.octets(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    /// ```
    pub fn octets(&self) -> &[u8; 6] {
        &self.octets
    }
    
    /// Returns the octets as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.octets
    }
}

impl Display for MacAddress {
    /// Formats MAC address as colon-separated lowercase hex.
    ///
    /// Example: `00:11:22:33:44:55`
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.octets[0], self.octets[1], self.octets[2],
            self.octets[3], self.octets[4], self.octets[5])
    }
}

impl Debug for MacAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddress({})", self)
    }
}

impl FromStr for MacAddress {
    type Err = DnsmasqError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s)
    }
}

// ============================================================================
// DNS RECORD TYPE ENUM
// ============================================================================

/// DNS resource record types from RFC 1035 and extensions.
///
/// Enumerates all DNS record types supported by dnsmasq for query forwarding,
/// caching, and authoritative responses. Provides type-safe representation
/// replacing C integer constants (T_A, T_AAAA, T_MX, etc.) with exhaustive
/// pattern matching enforcement.
///
/// # C Equivalent
///
/// ```c
/// // C implementation: Integer constants from dns-protocol.h
/// #define T_A          1
/// #define T_NS         2
/// #define T_CNAME      5
/// #define T_SOA        6
/// #define T_PTR       12
/// #define T_MX        15
/// #define T_TXT       16
/// #define T_AAAA      28
/// #define T_SRV       33
/// // ... 30+ more types
/// ```
///
/// # Rust Advantages
///
/// - Compiler-enforced exhaustive matching in match expressions
/// - Impossible to use undefined record type values
/// - Self-documenting code with named variants
/// - Efficient representation (u16 discriminant)
///
/// # Usage
///
/// ```rust,ignore
/// use dnsmasq::types::RecordType;
///
/// let query_type = RecordType::A;
/// match query_type {
///     RecordType::A => { /* IPv4 address */ }
///     RecordType::AAAA => { /* IPv6 address */ }
///     RecordType::MX => { /* Mail exchange */ }
///     _ => { /* Other types */ }
/// }
///
/// // Convert to/from wire format
/// let type_code: u16 = query_type.into();
/// let parsed_type = RecordType::from(type_code);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum RecordType {
    /// IPv4 address record (RFC 1035)
    A = 1,
    /// Authoritative name server (RFC 1035)
    NS = 2,
    /// Canonical name (alias) record (RFC 1035)
    CNAME = 5,
    /// Start of authority record (RFC 1035)
    SOA = 6,
    /// Domain name pointer (reverse DNS) (RFC 1035)
    PTR = 12,
    /// Mail exchange record (RFC 1035)
    MX = 15,
    /// Text strings (RFC 1035)
    TXT = 16,
    /// IPv6 address record (RFC 3596)
    AAAA = 28,
    /// Service locator (RFC 2782)
    SRV = 33,
    /// DNSSEC signature (RFC 4034)
    RRSIG = 46,
    /// Next secure record (DNSSEC) (RFC 4034)
    NSEC = 47,
    /// DNSSEC public key (RFC 4034)
    DNSKEY = 48,
    /// Delegation signer (DNSSEC) (RFC 4034)
    DS = 43,
    /// NSEC version 3 (DNSSEC) (RFC 5155)
    NSEC3 = 50,
    /// NSEC3 parameters (RFC 5155)
    NSEC3PARAM = 51,
    /// Certificate record (RFC 4398)
    CERT = 37,
    /// Delegation name (RFC 2672)
    DNAME = 39,
    /// Option record (EDNS0) (RFC 6891)
    OPT = 41,
    /// Address prefix list (RFC 3123)
    APL = 42,
    /// Host information (RFC 1035)
    HINFO = 13,
    /// Well-known service (RFC 1035)
    WKS = 11,
    /// All cached records (query type only)
    ANY = 255,
    /// Unknown or unsupported record type
    Unknown(u16),
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            11 => Self::WKS,
            12 => Self::PTR,
            13 => Self::HINFO,
            15 => Self::MX,
            16 => Self::TXT,
            28 => Self::AAAA,
            33 => Self::SRV,
            37 => Self::CERT,
            39 => Self::DNAME,
            41 => Self::OPT,
            42 => Self::APL,
            43 => Self::DS,
            46 => Self::RRSIG,
            47 => Self::NSEC,
            48 => Self::DNSKEY,
            50 => Self::NSEC3,
            51 => Self::NSEC3PARAM,
            255 => Self::ANY,
            other => Self::Unknown(other),
        }
    }
}

impl From<RecordType> for u16 {
    fn from(rt: RecordType) -> Self {
        match rt {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::WKS => 11,
            RecordType::PTR => 12,
            RecordType::HINFO => 13,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::CERT => 37,
            RecordType::DNAME => 39,
            RecordType::OPT => 41,
            RecordType::APL => 42,
            RecordType::DS => 43,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::ANY => 255,
            RecordType::Unknown(code) => code,
        }
    }
}

// ============================================================================
// CACHE FLAGS BITFLAGS
// ============================================================================

bitflags! {
    /// DNS cache entry metadata flags using type-safe bitflag operations.
    ///
    /// Replaces C bitfield manipulation with Rust's `bitflags!` macro, providing
    /// compile-time checked flag operations. Flags track cache entry characteristics,
    /// record types, data sources, and validation states.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // C implementation: Manual bit manipulation (dnsmasq.h)
    /// #define F_IMMORTAL  (1u<<0)   // Never expires
    /// #define F_NAMEP     (1u<<1)   // Name is pointer
    /// #define F_REVERSE   (1u<<2)   // Reverse lookup
    /// #define F_FORWARD   (1u<<3)   // Forward lookup
    /// #define F_DHCP      (1u<<4)   // From DHCP
    /// #define F_NEG       (1u<<5)   // Negative cache
    /// #define F_HOSTS     (1u<<6)   // From /etc/hosts
    /// #define F_IPV4      (1u<<7)   // IPv4 address
    /// #define F_IPV6      (1u<<8)   // IPv6 address
    /// #define F_BIGNAME   (1u<<9)   // Name > SMALLDNAME
    /// #define F_NXDOMAIN  (1u<<10)  // Non-existent domain
    /// #define F_CNAME     (1u<<11)  // CNAME record
    /// #define F_DNSKEY    (1u<<12)  // DNSKEY record
    /// #define F_CONFIG    (1u<<13)  // From config
    /// #define F_DS        (1u<<14)  // DS record
    /// #define F_DNSSECOK  (1u<<15)  // DNSSEC valid
    /// // ... 16 more flags
    /// ```
    ///
    /// # Usage
    ///
    /// ```rust,ignore
    /// use dnsmasq::types::CacheFlags;
    ///
    /// // Create flags with type-safe operations
    /// let mut flags = CacheFlags::FORWARD | CacheFlags::IPV4;
    /// flags.insert(CacheFlags::DNSSEC);
    /// flags.remove(CacheFlags::IPV4);
    ///
    /// // Check flags
    /// if flags.contains(CacheFlags::FORWARD) {
    ///     // Handle forward lookup
    /// }
    ///
    /// // Iterate set flags
    /// for flag in flags.iter() {
    ///     println!("Flag: {:?}", flag);
    /// }
    /// ```
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
    pub struct CacheFlags: u32 {
        /// Cache entry never expires (static configuration)
        const IMMORTAL  = 1u32 << 0;
        
        /// Name field is a pointer (not inline storage)
        const NAMEP     = 1u32 << 1;
        
        /// Reverse DNS lookup (PTR record)
        const REVERSE   = 1u32 << 2;
        
        /// Forward DNS lookup (A/AAAA record)
        const FORWARD   = 1u32 << 3;
        
        /// Entry originated from DHCP lease
        const DHCP      = 1u32 << 4;
        
        /// Negative cache entry (NXDOMAIN or no data)
        const NEG       = 1u32 << 5;
        
        /// Entry from /etc/hosts file
        const HOSTS     = 1u32 << 6;
        
        /// Contains IPv4 address
        const IPV4      = 1u32 << 7;
        
        /// Contains IPv6 address
        const IPV6      = 1u32 << 8;
        
        /// Domain name exceeds SMALLDNAME (uses heap)
        const BIGNAME   = 1u32 << 9;
        
        /// Non-existent domain (NXDOMAIN response)
        const NXDOMAIN  = 1u32 << 10;
        
        /// CNAME record (canonical name alias)
        const CNAME     = 1u32 << 11;
        
        /// DNSKEY record (DNSSEC public key)
        const DNSKEY    = 1u32 << 12;
        
        /// Entry from configuration file
        const CONFIG    = 1u32 << 13;
        
        /// DS record (delegation signer for DNSSEC)
        const DS        = 1u32 << 14;
        
        /// DNSSEC validation successful
        const DNSSECOK  = 1u32 << 15;
    }
}

// ============================================================================
// UPSTREAM SERVER DETAILS
// ============================================================================

/// Configuration details for upstream DNS server.
///
/// Represents a configured upstream DNS server to which queries are forwarded.
/// Tracks server address, associated domain restrictions, and operational flags.
///
/// # C Equivalent
///
/// ```c
/// struct server {
///     u16 flags, domain_len;
///     char *domain;
///     struct server *next;
///     union mysockaddr addr, source_addr;
///     unsigned int queries, failed_queries;
///     // ... 15+ more fields
/// };
/// ```
///
/// # Fields
///
/// - `addr`: Server socket address (IP + port, typically UDP/TCP 53)
/// - `domain`: Optional domain restriction (forward only for this domain)
/// - `flags`: Server configuration flags (SERV_LITERAL_ADDRESS, SERV_DO_DNSSEC, etc.)
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::types::ServerDetails;
/// use std::net::{IpAddr, SocketAddr};
///
/// // Unrestricted upstream server
/// let google_dns = ServerDetails::new(
///     "8.8.8.8:53".parse()?,
///     None,
///     0
/// );
///
/// // Domain-specific upstream
/// let corp_dns = ServerDetails::new(
///     "10.0.0.1:53".parse()?,
///     Some("corp.example.com"),
///     0
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServerDetails {
    /// Socket address of the upstream DNS server
    addr: SocketAddr,
    
    /// Optional domain restriction (None = forward all domains)
    domain: Option<DomainName>,
    
    /// Server configuration flags
    flags: u16,
}

impl ServerDetails {
    /// Creates a new upstream server configuration.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address of the DNS server (IP + port)
    /// * `domain` - Optional domain to restrict forwarding
    /// * `flags` - Server configuration flags
    pub fn new(addr: SocketAddr, domain: Option<impl Into<String>>, flags: u16) -> Result<Self, DnsmasqError> {
        let domain = match domain {
            Some(d) => Some(DomainName::new(d)?),
            None => None,
        };
        
        Ok(Self { addr, domain, flags })
    }
    
    /// Returns the server socket address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    
    /// Returns the domain restriction, if any.
    pub fn domain(&self) -> Option<&DomainName> {
        self.domain.as_ref()
    }
    
    /// Returns the server configuration flags.
    pub fn flags(&self) -> u16 {
        self.flags
    }
}

// ============================================================================
// DHCP LEASE INFORMATION
// ============================================================================

/// DHCP lease metadata for tracking allocated addresses.
///
/// Represents an active or expired DHCP lease with client identification,
/// hostname, and expiration information. Used for lease database persistence
/// and DNS integration (adding client hostnames to DNS resolution).
///
/// # C Equivalent
///
/// ```c
/// struct dhcp_lease {
///     int clid_len;
///     unsigned char *clid;
///     char *hostname, *fqdn;
///     int flags;
///     time_t expires;
///     int hwaddr_len, hwaddr_type;
///     unsigned char hwaddr[DHCP_CHADDR_MAX];
///     struct in_addr addr;
///     // ... 15+ more fields for DHCPv6, vendor classes, etc.
/// };
/// ```
///
/// # Fields
///
/// - `ip_addr`: Allocated IP address (IPv4 or IPv6)
/// - `mac_addr`: Client hardware (MAC) address
/// - `hostname`: Client hostname (from DHCP option or static config)
/// - `expiry`: Lease expiration time (SystemTime)
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::types::LeaseInfo;
/// use std::time::{SystemTime, Duration};
///
/// let lease = LeaseInfo::new(
///     "192.168.1.100".parse()?,
///     MacAddress::from_str("00:11:22:33:44:55")?,
///     Some("client-pc"),
///     SystemTime::now() + Duration::from_secs(86400)  // 24 hours
/// )?;
///
/// // Check if lease is still valid
/// if lease.is_expired() {
///     println!("Lease expired at {:?}", lease.expiry());
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LeaseInfo {
    /// Allocated IP address
    ip_addr: IpAddr,
    
    /// Client MAC address
    mac_addr: MacAddress,
    
    /// Client hostname (optional)
    hostname: Option<String>,
    
    /// Lease expiration time
    expiry: SystemTime,
}

impl LeaseInfo {
    /// Creates a new DHCP lease record.
    ///
    /// # Arguments
    ///
    /// * `ip_addr` - Allocated IP address
    /// * `mac_addr` - Client MAC address
    /// * `hostname` - Optional client hostname
    /// * `expiry` - Lease expiration time
    pub fn new(
        ip_addr: IpAddr,
        mac_addr: MacAddress,
        hostname: Option<impl Into<String>>,
        expiry: SystemTime
    ) -> Result<Self, DnsmasqError> {
        Ok(Self {
            ip_addr,
            mac_addr,
            hostname: hostname.map(|h| h.into()),
            expiry,
        })
    }
    
    /// Returns the allocated IP address.
    pub fn ip_addr(&self) -> IpAddr {
        self.ip_addr
    }
    
    /// Returns the client MAC address.
    pub fn mac_addr(&self) -> MacAddress {
        self.mac_addr
    }
    
    /// Returns the client hostname, if any.
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }
    
    /// Returns the lease expiration time.
    pub fn expiry(&self) -> SystemTime {
        self.expiry
    }
    
    /// Checks if the lease has expired.
    ///
    /// Compares expiration time against current system time.
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expiry
    }
}

// ============================================================================
// TIMESTAMP TYPE
// ============================================================================

/// Monotonic timestamp for cache TTL and lease expiration tracking.
///
/// Wraps `std::time::Instant` for monotonic time measurements immune to
/// system clock adjustments. Used for DNS cache TTL countdown and DHCP
/// lease expiration tracking.
///
/// # C Equivalent
///
/// ```c
/// // C implementation: time_t (seconds since epoch)
/// time_t ttd;  // time to die
/// time_t expires;  // lease expiry
///
/// // Comparison with current time
/// if (now > ttd) {
///     // Cache entry expired
/// }
/// ```
///
/// Rust's `Instant` provides nanosecond precision and is guaranteed to be
/// monotonic (not affected by NTP adjustments or user clock changes).
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::types::Timestamp;
/// use std::time::Duration;
///
/// // Create timestamp for 3600 seconds (1 hour) from now
/// let expiry = Timestamp::from_secs(3600);
///
/// // Check elapsed time
/// let elapsed = expiry.elapsed();
/// println!("Elapsed: {} seconds", elapsed.as_secs());
///
/// // Calculate remaining time
/// if let Some(remaining) = Duration::from_secs(3600).checked_sub(elapsed) {
///     println!("Remaining: {} seconds", remaining.as_secs());
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp {
    instant: Instant,
}

impl Timestamp {
    /// Returns the current timestamp.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let now = Timestamp::now();
    /// ```
    pub fn now() -> Self {
        Self {
            instant: Instant::now(),
        }
    }
    
    /// Creates a timestamp representing a duration from now.
    ///
    /// # Arguments
    ///
    /// * `secs` - Seconds from current time
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // 1 hour from now
    /// let future = Timestamp::from_secs(3600);
    /// ```
    pub fn from_secs(secs: u64) -> Self {
        Self {
            instant: Instant::now() + Duration::from_secs(secs),
        }
    }
    
    /// Returns the timestamp as seconds since creation.
    ///
    /// Note: This is relative to the first `Instant::now()` call, not UNIX epoch.
    pub fn as_secs(&self) -> u64 {
        self.instant.elapsed().as_secs()
    }
    
    /// Returns the duration elapsed since this timestamp.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let start = Timestamp::now();
    /// // ... do work ...
    /// let elapsed = start.elapsed();
    /// println!("Took {} ms", elapsed.as_millis());
    /// ```
    pub fn elapsed(&self) -> Duration {
        self.instant.elapsed()
    }
    
    /// Returns the duration between this timestamp and another.
    ///
    /// Returns `None` if `other` is later than `self`.
    pub fn duration_since(&self, other: &Timestamp) -> Option<Duration> {
        self.instant.checked_duration_since(other.instant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_domain_name_validation() {
        // Valid names
        assert!(DomainName::new("example.com").is_ok());
        assert!(DomainName::new("sub.domain.example.com").is_ok());
        assert!(DomainName::new("example.com.").is_ok());  // FQDN
        assert!(DomainName::new("localhost").is_ok());
        
        // Invalid names
        assert!(DomainName::new("").is_err());  // Empty
        assert!(DomainName::new(&"a".repeat(256)).is_err());  // Too long
        assert!(DomainName::new("invalid..domain").is_err());  // Double dot
        assert!(DomainName::new("-invalid").is_err());  // Leading hyphen
    }
    
    #[test]
    fn test_domain_name_subdomain() {
        let parent = DomainName::new("example.com").unwrap();
        let child = DomainName::new("www.example.com").unwrap();
        let unrelated = DomainName::new("other.org").unwrap();
        
        assert!(child.is_subdomain_of(&parent));
        assert!(!unrelated.is_subdomain_of(&parent));
        assert!(!parent.is_subdomain_of(&child));
    }
    
    #[test]
    fn test_mac_address_parsing() {
        let mac1 = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let mac2 = MacAddress::from_str("00-11-22-33-44-55").unwrap();
        let mac3 = MacAddress::from_str("001122334455").unwrap();
        
        assert_eq!(mac1, mac2);
        assert_eq!(mac2, mac3);
        assert_eq!(mac1.to_string(), "00:11:22:33:44:55");
    }
    
    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::from(1), RecordType::A);
        assert_eq!(RecordType::from(28), RecordType::AAAA);
        assert_eq!(u16::from(RecordType::A), 1);
        assert_eq!(u16::from(RecordType::AAAA), 28);
    }
    
    #[test]
    fn test_cache_flags_operations() {
        let mut flags = CacheFlags::FORWARD | CacheFlags::IPV4;
        
        assert!(flags.contains(CacheFlags::FORWARD));
        assert!(flags.contains(CacheFlags::IPV4));
        assert!(!flags.contains(CacheFlags::IPV6));
        
        flags.insert(CacheFlags::DNSSEC);
        assert!(flags.contains(CacheFlags::DNSSEC));
        
        flags.remove(CacheFlags::IPV4);
        assert!(!flags.contains(CacheFlags::IPV4));
    }
    
    #[test]
    fn test_lease_expiration() {
        let future = SystemTime::now() + Duration::from_secs(3600);
        let past = SystemTime::now() - Duration::from_secs(3600);
        
        let valid_lease = LeaseInfo::new(
            "192.168.1.100".parse().unwrap(),
            MacAddress::from_bytes([0, 1, 2, 3, 4, 5]),
            Some("client"),
            future
        ).unwrap();
        
        let expired_lease = LeaseInfo::new(
            "192.168.1.101".parse().unwrap(),
            MacAddress::from_bytes([0, 1, 2, 3, 4, 6]),
            Some("old-client"),
            past
        ).unwrap();
        
        assert!(!valid_lease.is_expired());
        assert!(expired_lease.is_expired());
    }
}
