// Copyright (c) 2000-2025 Simon Kelley
// Copyright (c) 2025 Dnsmasq Rust Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

//! DNS Resource Record type-safe representation and wire format parsing.
//!
//! This module implements RFC 1035-compliant resource record handling with
//! comprehensive support for all standard DNS record types plus DNSSEC extensions
//! (RFC 4034, RFC 5155). It replaces C pointer arithmetic from rfc1035.c with
//! memory-safe Rust implementations using nom parser combinators.
//!
//! # Supported Record Types
//!
//! ## Basic DNS Records (RFC 1035)
//! - **A**: IPv4 host address (32-bit)
//! - **NS**: Authoritative name server
//! - **CNAME**: Canonical name for an alias
//! - **SOA**: Start of authority zone record
//! - **PTR**: Domain name pointer (reverse DNS)
//! - **MX**: Mail exchange
//! - **TXT**: Text strings
//!
//! ## IPv6 and Service Discovery
//! - **AAAA**: IPv6 host address (RFC 3596)
//! - **SRV**: Service locator (RFC 2782)
//! - **NAPTR**: Naming authority pointer (RFC 3403)
//!
//! ## DNSSEC Records (RFC 4034, RFC 5155)
//! - **DNSKEY**: DNS public key
//! - **DS**: Delegation signer
//! - **RRSIG**: Resource record signature
//! - **NSEC**: Next secure record (authenticated denial)
//! - **NSEC3**: Hashed authenticated denial
//!
//! ## Extensions
//! - **OPT**: EDNS0 pseudo-RR (RFC 6891)
//! - **CAA**: Certification authority authorization (RFC 6844)
//! - **Unknown**: Extensibility for unsupported types
//!
//! # Architecture
//!
//! The module provides two main types:
//!
//! - [`ResourceRecord`]: Container holding RR metadata (name, type, class, TTL)
//!   and parsed RDATA via the [`RData`] enum
//! - [`RData`]: Type-safe enum with variants for each supported record type's
//!   RDATA section
//!
//! # Memory Safety
//!
//! Replaces C implementation patterns:
//!
//! ```c
//! // C: Manual pointer arithmetic with GETSHORT/GETLONG macros
//! GETSHORT(pref, p);  // Increments p by 2, potential overflow
//! p = skip_name(p, header, plen, 0);  // Manual bounds checking
//! ```
//!
//! ```rust,ignore
//! // Rust: Safe parsing with compile-time bounds checking
//! let (input, preference) = be_u16(input)?;  // nom combinator, auto bounds check
//! let (input, exchange) = DomainName::from_wire(input, message)?;
//! ```
//!
//! # Wire Format Parsing
//!
//! ```rust,ignore
//! use dnsmasq::dns::protocol::record::ResourceRecord;
//!
//! let message = &dns_packet[..];
//! let offset = 12; // After DNS header
//!
//! let rr = ResourceRecord::from_wire(&message[offset..], message)?;
//! match rr.rdata() {
//!     RData::A(addr) => println!("IPv4: {}", addr),
//!     RData::AAAA(addr) => println!("IPv6: {}", addr),
//!     RData::Mx { preference, exchange } => {
//!         println!("MX {} {}", preference, exchange);
//!     }
//!     _ => {}
//! }
//! ```
//!
//! # Implementation Notes
//!
//! - All wire format fields use network byte order (big-endian)
//! - Domain names support compression per RFC 1035 §4.1.4
//! - RDATA length is validated before parsing to prevent buffer overruns
//! - Unknown record types preserve RDATA as opaque bytes for transparency
//! - OPT pseudo-RR uses class field for UDP payload size, TTL for extended flags

use crate::dns::edns0::Edns0Option;
use crate::dns::protocol::constants::{IN6ADDRSZ, INADDRSZ};
use crate::dns::protocol::name::DomainName;
use crate::error::{DnsError, Result};
use crate::types::RecordType;

#[cfg(test)]
use crate::dns::protocol::constants::{C_IN, T_A};

use bytes::{BufMut, Bytes, BytesMut};
use nom::{
    bytes::complete::take,
    error::{Error as NomError, ErrorKind},
    multi::length_data,
    number::complete::{be_u16, be_u32, be_u8},
    sequence::tuple,
    Err as NomErr, IResult,
};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Type alias for nom parser error type used throughout this module
type NomErrorType<'a> = NomError<&'a [u8]>;

/// Helper function to parse a domain name using `DomainName::from_wire` within a nom parser context.
///
/// This function bridges the gap between nom's `&[u8]` based parsing and `DomainName::from_wire`'s
/// `Bytes`-based API. It calculates the offset of the current input position within the full message
/// and calls the appropriate API.
///
/// # Arguments
///
/// * `input` - Current parsing position (nom's remaining input)
/// * `message` - Full DNS message buffer (for compression pointer resolution)
///
/// # Returns
///
/// Returns an `IResult` containing the parsed `DomainName` and remaining input, compatible with nom parsers.
fn parse_domain_name<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], DomainName> {
    // Convert slices to Bytes for DomainName::from_wire
    let message_bytes = Bytes::copy_from_slice(message);

    // Calculate offset of input within message
    let input_ptr = input.as_ptr() as usize;
    let message_ptr = message.as_ptr() as usize;

    // Ensure input is within message bounds
    if input_ptr < message_ptr || input_ptr > message_ptr + message.len() {
        return Err(NomErr::Error(NomError::new(input, ErrorKind::Fail)));
    }

    let offset = input_ptr - message_ptr;

    // Call DomainName::from_wire
    match DomainName::from_wire(&message_bytes, offset) {
        Ok((domain_name, next_offset)) => {
            // Calculate how many bytes were consumed
            let bytes_consumed = next_offset - offset;

            // Ensure we don't consume more than available
            if bytes_consumed > input.len() {
                return Err(NomErr::Error(NomError::new(input, ErrorKind::Eof)));
            }

            // Return remaining input and parsed name
            Ok((&input[bytes_consumed..], domain_name))
        }
        Err(_e) => {
            // Convert DnsError to nom error
            Err(NomErr::Error(NomError::new(input, ErrorKind::Fail)))
        }
    }
}

/// Helper function to parse a domain name in `parse_rdata` context (non-nom).
///
/// This variant returns `Result` instead of `IResult` for use in functions that
/// don't use nom parser combinators.
///
/// # Arguments
///
/// * `input` - RDATA bytes to parse from
/// * `message` - Full DNS message buffer (for compression pointer resolution)
///
/// # Returns
///
/// Returns a tuple of (`remaining_bytes`, `parsed_domain_name`) or an error.
fn parse_domain_name_rdata<'a>(
    input: &'a [u8],
    message: &'a [u8],
) -> Result<(&'a [u8], DomainName)> {
    // Convert slices to Bytes for DomainName::from_wire
    let message_bytes = Bytes::copy_from_slice(message);

    // Calculate offset of input within message
    let input_ptr = input.as_ptr() as usize;
    let message_ptr = message.as_ptr() as usize;

    // Ensure input is within message bounds
    if input_ptr < message_ptr || input_ptr > message_ptr + message.len() {
        return Err(crate::error::DnsmasqError::Dns(DnsError::ParseFailed {
            server: "local".to_string(),
            reason: "Input not within message bounds".to_string(),
        }));
    }

    let offset = input_ptr - message_ptr;

    // Call DomainName::from_wire
    match DomainName::from_wire(&message_bytes, offset) {
        Ok((domain_name, next_offset)) => {
            // Calculate how many bytes were consumed
            let bytes_consumed = next_offset - offset;

            // Ensure we don't consume more than available
            if bytes_consumed > input.len() {
                return Err(crate::error::DnsmasqError::Dns(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: "Domain name parsing consumed more bytes than available".to_string(),
                }));
            }

            // Return remaining input and parsed name
            Ok((&input[bytes_consumed..], domain_name))
        }
        Err(e) => Err(crate::error::DnsmasqError::Dns(e)),
    }
}

/// DNS Resource Record with type-safe RDATA representation.
///
/// A resource record consists of:
/// - **Name**: Domain name this record refers to
/// - **Type**: Record type (A, AAAA, MX, etc.) from [`RecordType`]
/// - **Class**: Protocol family (almost always IN for Internet)
/// - **TTL**: Time to live in seconds (cache lifetime)
/// - **`RData`**: Type-specific data via [`RData`] enum
///
/// # C Equivalent
///
/// Replaces C struct pattern from rfc1035.c:
///
/// ```c
/// // C: Inline RR parsing in extract_addresses()
/// unsigned short type, class;
/// unsigned long ttl;
/// unsigned short rdlen;
/// GETSHORT(type, p);
/// GETSHORT(class, p);
/// GETLONG(ttl, p);
/// GETSHORT(rdlen, p);
/// // ... type-specific parsing with pointer arithmetic
/// ```
///
/// # Example
///
/// ```rust,ignore
/// use dnsmasq::dns::protocol::record::{ResourceRecord, RData};
/// use dnsmasq::dns::protocol::name::DomainName;
/// use dnsmasq::types::RecordType;
/// use std::net::Ipv4Addr;
///
/// let rr = ResourceRecord::new(
///     DomainName::from_str("example.com").unwrap(),
///     RecordType::A,
///     1, // Class IN
///     300, // TTL
///     RData::A(Ipv4Addr::new(93, 184, 216, 34)),
/// );
///
/// assert_eq!(rr.name().as_str(), "example.com");
/// assert_eq!(rr.ttl(), 300);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceRecord {
    /// Domain name this record refers to
    name: DomainName,
    /// Record type discriminator
    rtype: RecordType,
    /// Protocol class (1 = IN for Internet)
    class: u16,
    /// Time to live in seconds
    ttl: u32,
    /// Type-specific resource data
    rdata: RData,
}

/// Type-safe RDATA representation for all supported DNS record types.
///
/// Each variant contains the parsed, validated fields for its record type.
/// This enum replaces C's type-punned unions and manual parsing with
/// compiler-verified type safety.
///
/// # Variant Data Layouts
///
/// Follows RFC 1035 RDATA specifications:
///
/// - **A**: 4-byte IPv4 address
/// - **AAAA**: 16-byte IPv6 address
/// - **CNAME/PTR/NS**: Domain name (compressed)
/// - **MX**: 16-bit preference + domain name
/// - **TXT**: Sequence of length-prefixed character strings
/// - **SOA**: Seven fields (mname, rname, serial, refresh, retry, expire, minimum)
/// - **SRV**: Priority, weight, port, target domain
/// - **DNSSEC records**: Binary keys, signatures, digests
///
/// # Memory Layout
///
/// Unlike C's fixed-size buffers, Rust uses owned types:
/// - Domain names: `DomainName` (String-based)
/// - Binary data: `Bytes` (reference-counted, zero-copy)
/// - Addresses: `std::net::Ipv4Addr` and `Ipv6Addr`
///
/// # Example
///
/// ```rust,ignore
/// match rr.rdata() {
///     RData::A(addr) => {
///         println!("IPv4 address: {}", addr);
///     }
///     RData::Mx { preference, exchange } => {
///         println!("Mail server: {} (priority {})", exchange, preference);
///     }
///     RData::Txt { txt_data } => {
///         for string in txt_data {
///             println!("TXT: {}", String::from_utf8_lossy(string));
///         }
///     }
///     _ => {}
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    /// IPv4 address record (RFC 1035 §3.4.1)
    ///
    /// RDATA format: 4-byte IPv4 address in network byte order
    A(Ipv4Addr),

    /// IPv6 address record (RFC 3596 §2.2)
    ///
    /// RDATA format: 16-byte IPv6 address in network byte order
    AAAA(Ipv6Addr),

    /// Canonical name record (RFC 1035 §3.3.1)
    ///
    /// RDATA format: Domain name (can be compressed)
    Cname {
        /// The canonical name for the alias
        cname: DomainName,
    },

    /// Pointer record for reverse DNS (RFC 1035 §3.3.12)
    ///
    /// RDATA format: Domain name (can be compressed)
    Ptr {
        /// Domain name pointer target
        ptrdname: DomainName,
    },

    /// Mail exchange record (RFC 1035 §3.3.9)
    ///
    /// RDATA format: 16-bit preference + domain name
    Mx {
        /// Lower preference value = higher priority
        preference: u16,
        /// Mail server domain name
        exchange: DomainName,
    },

    /// Text record (RFC 1035 §3.3.14)
    ///
    /// RDATA format: Sequence of <length, data> character strings
    /// Each string: 1-byte length (0-255) + data bytes
    Txt {
        /// Vector of text strings (each max 255 bytes)
        txt_data: Vec<Vec<u8>>,
    },

    /// Start of authority record (RFC 1035 §3.3.13)
    ///
    /// RDATA format: Two domain names + five 32-bit integers
    Soa {
        /// Primary name server for this zone
        mname: DomainName,
        /// Responsible person email (@ replaced with .)
        rname: DomainName,
        /// Zone serial number (for change detection)
        serial: u32,
        /// Refresh interval in seconds
        refresh: u32,
        /// Retry interval in seconds
        retry: u32,
        /// Expiry time in seconds
        expire: u32,
        /// Minimum TTL for negative caching
        minimum: u32,
    },

    /// Name server record (RFC 1035 §3.3.11)
    ///
    /// RDATA format: Domain name (can be compressed)
    Ns {
        /// Name server domain name
        nsdname: DomainName,
    },

    /// Service locator record (RFC 2782)
    ///
    /// RDATA format: priority(16) + weight(16) + port(16) + target(name)
    Srv {
        /// Lower priority value = higher priority
        priority: u16,
        /// Weight for load balancing (higher = more load)
        weight: u16,
        /// TCP/UDP port number for service
        port: u16,
        /// Target host providing the service
        target: DomainName,
    },

    /// Naming authority pointer record (RFC 3403)
    ///
    /// RDATA format: order(16) + preference(16) + flags + service + regexp + replacement
    Naptr {
        /// Processing order (lower processed first)
        order: u16,
        /// Preference for records with same order
        preference: u16,
        /// Flags controlling processing (e.g., "S", "A", "U")
        flags: String,
        /// Service parameters (e.g., "E2U+sip")
        service: String,
        /// Regular expression for rewriting
        regexp: String,
        /// Replacement domain name
        replacement: DomainName,
    },

    /// DNSSEC public key record (RFC 4034 §2)
    ///
    /// RDATA format: flags(16) + protocol(8) + algorithm(8) + `public_key(variable)`
    Dnskey {
        /// Key flags (bit 7 = zone key, bit 15 = secure entry point)
        flags: u16,
        /// Protocol value (must be 3 for DNSSEC)
        protocol: u8,
        /// Cryptographic algorithm identifier (RSA, ECDSA, `EdDSA`)
        algorithm: u8,
        /// Public key material
        public_key: Bytes,
    },

    /// Delegation signer record (RFC 4034 §5)
    ///
    /// RDATA format: `key_tag(16)` + algorithm(8) + `digest_type(8)` + digest(variable)
    Ds {
        /// Key tag of referenced DNSKEY (CRC-like value)
        key_tag: u16,
        /// Algorithm of referenced DNSKEY
        algorithm: u8,
        /// Digest algorithm (SHA-1, SHA-256, SHA-384)
        digest_type: u8,
        /// Hash digest of DNSKEY
        digest: Bytes,
    },

    /// DNSSEC signature record (RFC 4034 §3)
    ///
    /// RDATA format: `type_covered(16)` + algorithm(8) + labels(8) + `original_ttl(32)` +
    ///               expiration(32) + inception(32) + `key_tag(16)` + signer + signature
    Rrsig {
        /// Record type this signature covers
        type_covered: u16,
        /// Cryptographic algorithm used
        algorithm: u8,
        /// Number of labels in original name
        labels: u8,
        /// Original TTL of covered `RRset`
        original_ttl: u32,
        /// Signature expiration time (Unix timestamp)
        expiration: u32,
        /// Signature inception time (Unix timestamp)
        inception: u32,
        /// Key tag of signing DNSKEY
        key_tag: u16,
        /// Domain name of signing zone
        signer: DomainName,
        /// Cryptographic signature
        signature: Bytes,
    },

    /// Next secure record (RFC 4034 §4)
    ///
    /// RDATA format: `next_domain` + `type_bitmap`
    Nsec {
        /// Next domain name in canonical order
        next_domain: DomainName,
        /// Bitmap of record types present at this name
        type_bitmap: Bytes,
    },

    /// Hashed next secure record (RFC 5155 §3)
    ///
    /// RDATA format: `hash_algorithm(8)` + flags(8) + iterations(16) + `salt_length(8)` +
    ///               salt + `hash_length(8)` + `next_hashed` + `type_bitmap`
    Nsec3 {
        /// Hash algorithm identifier (1 = SHA-1)
        hash_algorithm: u8,
        /// NSEC3 flags (bit 0 = opt-out)
        flags: u8,
        /// Hash iteration count
        iterations: u16,
        /// Salt value for hashing
        salt: Bytes,
        /// Hash of next owner name in zone
        next_hashed: Bytes,
        /// Bitmap of record types present
        type_bitmap: Bytes,
    },

    /// EDNS0 option pseudo-RR (RFC 6891)
    ///
    /// Special pseudo-record type. Class field holds UDP payload size,
    /// TTL field holds extended RCODE and flags (DO bit).
    /// RDATA contains sequence of EDNS0 options.
    Opt(Vec<Edns0Option>),

    /// Certification authority authorization (RFC 6844)
    ///
    /// RDATA format: flags(8) + `tag_length(8)` + tag + value
    Caa {
        /// CAA flags (bit 0 = critical)
        flags: u8,
        /// Property tag (e.g., "issue", "issuewild", "iodef")
        tag: String,
        /// Property value (e.g., CA domain name)
        value: String,
    },

    /// Unknown or unsupported record type
    ///
    /// Preserves RDATA as opaque bytes for transparency.
    /// Allows forwarding of unrecognized record types without parsing.
    Unknown {
        /// Numeric record type value
        rtype: u16,
        /// Raw RDATA bytes
        rdata: Bytes,
    },
}

impl ResourceRecord {
    /// Constructs a new resource record with the given fields.
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name this record refers to
    /// * `rtype` - Record type discriminator
    /// * `class` - Protocol class (typically 1 for IN/Internet)
    /// * `ttl` - Time to live in seconds
    /// * `rdata` - Parsed record data
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let rr = ResourceRecord::new(
    ///     DomainName::from_str("example.com")?,
    ///     RecordType::A,
    ///     1, // IN
    ///     300, // TTL
    ///     RData::A(Ipv4Addr::new(93, 184, 216, 34)),
    /// );
    /// ```
    pub fn new(name: DomainName, rtype: RecordType, class: u16, ttl: u32, rdata: RData) -> Self {
        Self { name, rtype, class, ttl, rdata }
    }

    /// Returns the domain name this record refers to.
    pub fn name(&self) -> &DomainName {
        &self.name
    }

    /// Returns the record type.
    pub fn rtype(&self) -> RecordType {
        self.rtype
    }

    /// Returns the protocol class.
    pub fn class(&self) -> u16 {
        self.class
    }

    /// Returns the time to live in seconds.
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns a reference to the parsed RDATA.
    pub fn rdata(&self) -> &RData {
        &self.rdata
    }

    /// Builder method to create a record with a different TTL.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let modified_rr = rr.with_ttl(3600);
    /// ```
    #[must_use]
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    /// Builder method to create a record with a different class.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let modified_rr = rr.with_class(C_IN);
    /// ```
    #[must_use]
    pub fn with_class(mut self, class: u16) -> Self {
        self.class = class;
        self
    }

    /// Parses a resource record from wire format.
    ///
    /// This is the main entry point for parsing RRs from DNS packets.
    /// It reads the RR header (name, type, class, TTL, rdlength) and
    /// dispatches to type-specific RDATA parsers.
    ///
    /// # Arguments
    ///
    /// * `input` - Byte slice positioned at start of RR
    /// * `message` - Full DNS message for name decompression
    ///
    /// # Returns
    ///
    /// On success, returns `(remaining_input, parsed_rr)`.
    /// On failure, returns nom error with context.
    ///
    /// # Wire Format
    ///
    /// ```text
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                                               |
    /// /                     NAME                      /
    /// |                                               |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                     TYPE                      |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                     CLASS                     |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                      TTL                      |
    /// |                                               |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                   RDLENGTH                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /// /                     RDATA                     /
    /// /                                               /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// # C Equivalent
    ///
    /// Replaces manual parsing from rfc1035.c:
    ///
    /// ```c
    /// // C: extract_addresses() function
    /// if ((p = skip_name(p, header, plen, 0)) == NULL)
    ///     return 0;
    /// GETSHORT(qtype, p);
    /// GETSHORT(qclass, p);
    /// GETLONG(ttl, p);
    /// GETSHORT(rdlen, p);
    /// // ... type-specific pointer arithmetic
    /// ```
    pub fn parse<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], Self> {
        // Parse RR header fields
        let (input, name) = parse_domain_name(input, message)?;
        let (input, type_code) = be_u16(input)?;
        let (input, class) = be_u16(input)?;
        let (input, ttl) = be_u32(input)?;
        let (input, rdlength) = be_u16(input)?;

        // Take exactly rdlength bytes for RDATA parsing
        let (input, rdata_bytes) = take(rdlength as usize)(input)?;

        // Convert type code to RecordType enum
        let rtype = RecordType::from(type_code);

        // Parse RDATA based on record type
        let rdata = Self::parse_rdata(rdata_bytes, message, rtype, rdlength)
            .map_err(|_| NomErr::Error(NomError::new(input, ErrorKind::Fail)))?;

        Ok((input, Self { name, rtype, class, ttl, rdata }))
    }

    /// Alias for `parse()` for API consistency.
    pub fn from_wire<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], Self> {
        Self::parse(input, message)
    }

    /// Parses RDATA section based on record type.
    ///
    /// This function dispatches to type-specific parsers using pattern matching
    /// on the `RecordType` enum. Each parser validates RDATA length and structure.
    ///
    /// # Arguments
    ///
    /// * `rdata_bytes` - Slice containing exactly rdlength bytes
    /// * `message` - Full DNS message for name decompression
    /// * `rtype` - Record type discriminator
    /// * `rdlength` - Expected RDATA length in bytes
    ///
    /// # Returns
    ///
    /// Parsed `RData` enum variant on success, error on malformed data.
    ///
    /// # Validation
    ///
    /// - A records: Must be exactly 4 bytes
    /// - AAAA records: Must be exactly 16 bytes
    /// - Domain name records: Names must be valid and properly terminated
    /// - Integer fields: Must have sufficient bytes for extraction
    ///
    /// # C Equivalent
    ///
    /// Replaces type-specific parsing blocks in `extract_addresses()`:
    ///
    /// ```c
    /// // C: Manual type discrimination
    /// if (qtype == T_A) {
    ///     if (rdlen != INADDRSZ) return 0;
    ///     GETLONG(addr.addr4.s_addr, p);
    /// }
    /// else if (qtype == T_AAAA) {
    ///     if (rdlen != IN6ADDRSZ) return 0;
    ///     memcpy(&addr.addr6, p, IN6ADDRSZ);
    /// }
    /// ```
    #[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
    pub fn parse_rdata(
        rdata_bytes: &[u8],
        message: &[u8],
        rtype: RecordType,
        rdlength: u16,
    ) -> Result<RData> {
        match rtype {
            RecordType::A => {
                // A record: 4-byte IPv4 address
                if rdlength != INADDRSZ as u16 {
                    return Err(crate::error::DnsmasqError::Dns(
                        crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!(
                                "A record RDATA must be {INADDRSZ} bytes, got {rdlength}"
                            ),
                        },
                    ));
                }
                let addr =
                    Ipv4Addr::new(rdata_bytes[0], rdata_bytes[1], rdata_bytes[2], rdata_bytes[3]);
                Ok(RData::A(addr))
            }

            RecordType::AAAA => {
                // AAAA record: 16-byte IPv6 address
                if rdlength != IN6ADDRSZ as u16 {
                    return Err(crate::error::DnsmasqError::Dns(
                        crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!(
                                "AAAA record RDATA must be {IN6ADDRSZ} bytes, got {rdlength}"
                            ),
                        },
                    ));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&rdata_bytes[0..16]);
                let addr = Ipv6Addr::from(octets);
                Ok(RData::AAAA(addr))
            }

            RecordType::CNAME => {
                // CNAME record: Domain name (can be compressed)
                let (_remaining, cname) = parse_domain_name_rdata(rdata_bytes, message)?;
                Ok(RData::Cname { cname })
            }

            RecordType::PTR => {
                // PTR record: Domain name (can be compressed)
                let (_remaining, ptrdname) = parse_domain_name_rdata(rdata_bytes, message)?;
                Ok(RData::Ptr { ptrdname })
            }

            RecordType::MX => {
                // MX record: 16-bit preference + domain name
                if rdlength < 2 {
                    return Err(crate::error::DnsmasqError::Dns(
                        crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: "MX record RDATA too short for preference field".to_string(),
                        },
                    ));
                }
                let (input, preference) =
                    be_u16::<_, NomErrorType<'_>>(rdata_bytes).map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse MX preference: {e:?}"),
                        })
                    })?;
                let (_remaining, exchange) = parse_domain_name_rdata(input, message)?;
                Ok(RData::Mx { preference, exchange })
            }

            RecordType::TXT => {
                // TXT record: Sequence of length-prefixed strings
                let mut txt_data = Vec::new();
                let mut input = rdata_bytes;

                while !input.is_empty() {
                    // Parse length-prefixed string
                    let (remaining, txt_string) = length_data::<_, _, NomErrorType<'_>, _>(
                        be_u8::<_, NomErrorType<'_>>,
                    )(input)
                    .map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse TXT string: {e:?}"),
                        })
                    })?;
                    txt_data.push(txt_string.to_vec());
                    input = remaining;
                }

                Ok(RData::Txt { txt_data })
            }

            RecordType::SOA => {
                // SOA record: mname + rname + serial + refresh + retry + expire + minimum
                let (input, mname) = parse_domain_name_rdata(rdata_bytes, message)?;
                let (input, rname) = parse_domain_name_rdata(input, message)?;
                let (_input, (serial, refresh, retry, expire, minimum)) =
                    tuple::<_, _, NomErrorType<'_>, _>((
                        be_u32::<_, NomErrorType<'_>>,
                        be_u32::<_, NomErrorType<'_>>,
                        be_u32::<_, NomErrorType<'_>>,
                        be_u32::<_, NomErrorType<'_>>,
                        be_u32::<_, NomErrorType<'_>>,
                    ))(input)
                    .map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse SOA integers: {e:?}"),
                        })
                    })?;

                Ok(RData::Soa { mname, rname, serial, refresh, retry, expire, minimum })
            }

            RecordType::NS => {
                // NS record: Domain name (can be compressed)
                let (_remaining, nsdname) = parse_domain_name_rdata(rdata_bytes, message)?;
                Ok(RData::Ns { nsdname })
            }

            RecordType::SRV => {
                // SRV record: priority + weight + port + target
                if rdlength < 6 {
                    return Err(crate::error::DnsmasqError::Dns(
                        crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: "SRV record RDATA too short".to_string(),
                        },
                    ));
                }
                let (input, (priority, weight, port)) = tuple::<_, _, NomErrorType<'_>, _>((
                    be_u16::<_, NomErrorType<'_>>,
                    be_u16::<_, NomErrorType<'_>>,
                    be_u16::<_, NomErrorType<'_>>,
                ))(rdata_bytes)
                .map_err(|e| {
                    crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                        server: "local".to_string(),
                        reason: format!("Failed to parse SRV fields: {e:?}"),
                    })
                })?;
                let (_remaining, target) =
                    parse_domain_name_rdata(input, message).map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse SRV target: {e:?}"),
                        })
                    })?;

                Ok(RData::Srv { priority, weight, port, target })
            }

            RecordType::NAPTR => {
                // NAPTR record: order + preference + flags + service + regexp + replacement
                if rdlength < 7 {
                    return Err(crate::error::DnsmasqError::Dns(
                        crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: "NAPTR record RDATA too short".to_string(),
                        },
                    ));
                }
                let (input, (order, preference)) = tuple::<_, _, NomErrorType<'_>, _>((
                    be_u16::<_, NomErrorType<'_>>,
                    be_u16::<_, NomErrorType<'_>>,
                ))(rdata_bytes)
                .map_err(|e| {
                    crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                        server: "local".to_string(),
                        reason: format!("Failed to parse NAPTR order/preference: {e:?}"),
                    })
                })?;

                // Parse flags (length-prefixed string)
                let (input, flags_bytes) =
                    length_data::<_, _, NomErrorType<'_>, _>(be_u8::<_, NomErrorType<'_>>)(input)
                        .map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse NAPTR flags: {e:?}"),
                        })
                    })?;
                let flags = String::from_utf8_lossy(flags_bytes).to_string();

                // Parse service (length-prefixed string)
                let (input, service_bytes) =
                    length_data::<_, _, NomErrorType<'_>, _>(be_u8::<_, NomErrorType<'_>>)(input)
                        .map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse NAPTR service: {e:?}"),
                        })
                    })?;
                let service = String::from_utf8_lossy(service_bytes).to_string();

                // Parse regexp (length-prefixed string)
                let (input, regexp_bytes) =
                    length_data::<_, _, NomErrorType<'_>, _>(be_u8::<_, NomErrorType<'_>>)(input)
                        .map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse NAPTR regexp: {e:?}"),
                        })
                    })?;
                let regexp = String::from_utf8_lossy(regexp_bytes).to_string();

                // Parse replacement domain name
                let (_remaining, replacement) =
                    parse_domain_name_rdata(input, message).map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse NAPTR replacement: {e:?}"),
                        })
                    })?;

                Ok(RData::Naptr { order, preference, flags, service, regexp, replacement })
            }

            RecordType::DNSKEY => {
                // DNSKEY record: flags + protocol + algorithm + public_key
                if rdlength < 4 {
                    return Err(crate::error::DnsmasqError::Dns(
                        crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: "DNSKEY record RDATA too short".to_string(),
                        },
                    ));
                }
                let (input, (flags, protocol, algorithm)) = tuple::<_, _, NomErrorType<'_>, _>((
                    be_u16::<_, NomErrorType<'_>>,
                    be_u8::<_, NomErrorType<'_>>,
                    be_u8::<_, NomErrorType<'_>>,
                ))(rdata_bytes)
                .map_err(|e| {
                    crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                        server: "local".to_string(),
                        reason: format!("Failed to parse DNSKEY header: {e:?}"),
                    })
                })?;

                // Remaining bytes are the public key
                let public_key = Bytes::copy_from_slice(input);

                Ok(RData::Dnskey { flags, protocol, algorithm, public_key })
            }

            RecordType::DS => {
                // DS record: key_tag + algorithm + digest_type + digest
                if rdlength < 4 {
                    return Err(crate::error::DnsmasqError::Dns(
                        crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: "DS record RDATA too short".to_string(),
                        },
                    ));
                }
                let (input, (key_tag, algorithm, digest_type)) =
                    tuple::<_, _, NomErrorType<'_>, _>((
                        be_u16::<_, NomErrorType<'_>>,
                        be_u8::<_, NomErrorType<'_>>,
                        be_u8::<_, NomErrorType<'_>>,
                    ))(rdata_bytes)
                    .map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse DS header: {e:?}"),
                        })
                    })?;

                // Remaining bytes are the digest
                let digest = Bytes::copy_from_slice(input);

                Ok(RData::Ds { key_tag, algorithm, digest_type, digest })
            }

            RecordType::RRSIG => {
                // RRSIG record: type_covered + algorithm + labels + original_ttl +
                //               expiration + inception + key_tag + signer + signature
                if rdlength < 18 {
                    return Err(crate::error::DnsmasqError::Dns(
                        crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: "RRSIG record RDATA too short".to_string(),
                        },
                    ));
                }
                let (
                    input,
                    (type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag),
                ) = tuple::<_, _, NomErrorType<'_>, _>((
                    be_u16::<_, NomErrorType<'_>>,
                    be_u8::<_, NomErrorType<'_>>,
                    be_u8::<_, NomErrorType<'_>>,
                    be_u32::<_, NomErrorType<'_>>,
                    be_u32::<_, NomErrorType<'_>>,
                    be_u32::<_, NomErrorType<'_>>,
                    be_u16::<_, NomErrorType<'_>>,
                ))(rdata_bytes)
                .map_err(|e| {
                    crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                        server: "local".to_string(),
                        reason: format!("Failed to parse RRSIG header: {e:?}"),
                    })
                })?;

                // Parse signer domain name
                let (input, signer) = parse_domain_name_rdata(input, message).map_err(|e| {
                    crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                        server: "local".to_string(),
                        reason: format!("Failed to parse RRSIG signer: {e:?}"),
                    })
                })?;

                // Remaining bytes are the signature
                let signature = Bytes::copy_from_slice(input);

                Ok(RData::Rrsig {
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    key_tag,
                    signer,
                    signature,
                })
            }

            RecordType::NSEC => {
                // NSEC record: next_domain + type_bitmap
                let (input, next_domain) =
                    parse_domain_name_rdata(rdata_bytes, message).map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse NSEC next domain: {e:?}"),
                        })
                    })?;

                // Remaining bytes are the type bitmap
                let type_bitmap = Bytes::copy_from_slice(input);

                Ok(RData::Nsec { next_domain, type_bitmap })
            }

            RecordType::NSEC3 => {
                // NSEC3 record: hash_algorithm + flags + iterations + salt_length + salt +
                //               hash_length + next_hashed + type_bitmap
                if rdlength < 6 {
                    return Err(crate::error::DnsmasqError::Dns(
                        crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: "NSEC3 record RDATA too short".to_string(),
                        },
                    ));
                }
                let (input, (hash_algorithm, flags, iterations)) =
                    tuple::<_, _, NomErrorType<'_>, _>((
                        be_u8::<_, NomErrorType<'_>>,
                        be_u8::<_, NomErrorType<'_>>,
                        be_u16::<_, NomErrorType<'_>>,
                    ))(rdata_bytes)
                    .map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse NSEC3 header: {e:?}"),
                        })
                    })?;

                // Parse salt (length-prefixed)
                let (input, salt_bytes) =
                    length_data::<_, _, NomErrorType<'_>, _>(be_u8::<_, NomErrorType<'_>>)(input)
                        .map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse NSEC3 salt: {e:?}"),
                        })
                    })?;
                let salt = Bytes::copy_from_slice(salt_bytes);

                // Parse next hashed owner name (length-prefixed)
                let (input, next_hashed_bytes) =
                    length_data::<_, _, NomErrorType<'_>, _>(be_u8::<_, NomErrorType<'_>>)(input)
                        .map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse NSEC3 next hash: {e:?}"),
                        })
                    })?;
                let next_hashed = Bytes::copy_from_slice(next_hashed_bytes);

                // Remaining bytes are the type bitmap
                let type_bitmap = Bytes::copy_from_slice(input);

                Ok(RData::Nsec3 {
                    hash_algorithm,
                    flags,
                    iterations,
                    salt,
                    next_hashed,
                    type_bitmap,
                })
            }

            RecordType::OPT => {
                // OPT pseudo-RR: Parse EDNS0 options
                let mut options = Vec::new();
                let mut input = rdata_bytes;

                while input.len() >= 4 {
                    // Each option: code(16) + length(16) + data(length)
                    let (remaining, (option_code, option_length)) =
                        tuple::<_, _, NomErrorType<'_>, _>((
                            be_u16::<_, NomErrorType<'_>>,
                            be_u16::<_, NomErrorType<'_>>,
                        ))(input)
                        .map_err(|e| {
                            crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                                server: "local".to_string(),
                                reason: format!("Failed to parse OPT option header: {e:?}"),
                            })
                        })?;

                    let (remaining, option_data) = take::<_, _, NomErrorType<'_>>(
                        option_length as usize,
                    )(remaining)
                    .map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse OPT option data: {e:?}"),
                        })
                    })?;

                    // Parse EDNS0 option based on code
                    let option =
                        Edns0Option::from_wire_format(option_code, option_data).map_err(|e| {
                            crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                                server: "local".to_string(),
                                reason: format!("Failed to parse EDNS0 option: {e:?}"),
                            })
                        })?;

                    options.push(option);
                    input = remaining;
                }

                Ok(RData::Opt(options))
            }

            RecordType::CAA => {
                // CAA record: flags + tag_length + tag + value
                if rdlength < 2 {
                    return Err(crate::error::DnsmasqError::Dns(
                        crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: "CAA record RDATA too short".to_string(),
                        },
                    ));
                }
                let (input, flags) = be_u8::<_, NomErrorType<'_>>(rdata_bytes).map_err(|e| {
                    crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                        server: "local".to_string(),
                        reason: format!("Failed to parse CAA flags: {e:?}"),
                    })
                })?;

                // Parse tag (length-prefixed string)
                let (input, tag_bytes) =
                    length_data::<_, _, NomErrorType<'_>, _>(be_u8::<_, NomErrorType<'_>>)(input)
                        .map_err(|e| {
                        crate::error::DnsmasqError::Dns(crate::error::DnsError::ParseFailed {
                            server: "local".to_string(),
                            reason: format!("Failed to parse CAA tag: {e:?}"),
                        })
                    })?;
                let tag = String::from_utf8_lossy(tag_bytes).to_string();

                // Remaining bytes are the value
                let value = String::from_utf8_lossy(input).to_string();

                Ok(RData::Caa { flags, tag, value })
            }

            _ => {
                // Unknown record type: preserve RDATA as opaque bytes
                Ok(RData::Unknown {
                    rtype: rtype.into(),
                    rdata: Bytes::copy_from_slice(rdata_bytes),
                })
            }
        }
    }

    /// Serializes the complete resource record to wire format.
    ///
    /// Produces the full RR encoding including name, type, class, TTL,
    /// rdlength, and RDATA suitable for inclusion in DNS messages.
    ///
    /// # Returns
    ///
    /// Byte vector containing wire format representation.
    ///
    /// # Wire Format
    ///
    /// See `parse()` documentation for format specification.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let wire_bytes = rr.serialize()?;
    /// // Append to DNS message additional section
    /// ```
    #[allow(clippy::cast_possible_truncation)]
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // Serialize name (with compression potential in full message context)
        self.name.to_wire(&mut buf, None)?;

        // Serialize type, class, TTL
        buf.put_u16(self.rtype.into());
        buf.put_u16(self.class);
        buf.put_u32(self.ttl);

        // Serialize RDATA
        let rdata_bytes = self.serialize_rdata()?;
        buf.put_u16(rdata_bytes.len() as u16); // rdlength
        buf.put_slice(&rdata_bytes);

        Ok(buf.to_vec())
    }

    /// Alias for `serialize()` for API consistency.
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        self.serialize()
    }

    /// Serializes only the RDATA section to wire format.
    ///
    /// Returns RDATA bytes without the RR header. Useful for packet
    /// construction when header fields are managed separately.
    ///
    /// # Returns
    ///
    /// Byte vector containing wire format RDATA.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let rdata_bytes = rr.serialize_rdata()?;
    /// let rdlength = rdata_bytes.len();
    /// ```
    #[allow(clippy::cast_possible_truncation)]
    pub fn serialize_rdata(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        match &self.rdata {
            RData::A(addr) => {
                buf.put_slice(&addr.octets());
            }

            RData::AAAA(addr) => {
                buf.put_slice(&addr.octets());
            }

            RData::Cname { cname } => {
                cname.to_wire(&mut buf, None)?;
            }

            RData::Ptr { ptrdname } => {
                ptrdname.to_wire(&mut buf, None)?;
            }

            RData::Mx { preference, exchange } => {
                buf.put_u16(*preference);
                exchange.to_wire(&mut buf, None)?;
            }

            RData::Txt { txt_data } => {
                for txt_string in txt_data {
                    buf.put_u8(txt_string.len() as u8);
                    buf.put_slice(txt_string);
                }
            }

            RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
                mname.to_wire(&mut buf, None)?;
                rname.to_wire(&mut buf, None)?;
                buf.put_u32(*serial);
                buf.put_u32(*refresh);
                buf.put_u32(*retry);
                buf.put_u32(*expire);
                buf.put_u32(*minimum);
            }

            RData::Ns { nsdname } => {
                nsdname.to_wire(&mut buf, None)?;
            }

            RData::Srv { priority, weight, port, target } => {
                buf.put_u16(*priority);
                buf.put_u16(*weight);
                buf.put_u16(*port);
                target.to_wire(&mut buf, None)?;
            }

            RData::Naptr { order, preference, flags, service, regexp, replacement } => {
                buf.put_u16(*order);
                buf.put_u16(*preference);

                // Serialize flags (length-prefixed string)
                let flags_bytes = flags.as_bytes();
                buf.put_u8(flags_bytes.len() as u8);
                buf.put_slice(flags_bytes);

                // Serialize service (length-prefixed string)
                let service_bytes = service.as_bytes();
                buf.put_u8(service_bytes.len() as u8);
                buf.put_slice(service_bytes);

                // Serialize regexp (length-prefixed string)
                let regexp_bytes = regexp.as_bytes();
                buf.put_u8(regexp_bytes.len() as u8);
                buf.put_slice(regexp_bytes);

                // Serialize replacement domain name
                replacement.to_wire(&mut buf, None)?;
            }

            RData::Dnskey { flags, protocol, algorithm, public_key } => {
                buf.put_u16(*flags);
                buf.put_u8(*protocol);
                buf.put_u8(*algorithm);
                buf.put_slice(public_key);
            }

            RData::Ds { key_tag, algorithm, digest_type, digest } => {
                buf.put_u16(*key_tag);
                buf.put_u8(*algorithm);
                buf.put_u8(*digest_type);
                buf.put_slice(digest);
            }

            RData::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer,
                signature,
            } => {
                buf.put_u16(*type_covered);
                buf.put_u8(*algorithm);
                buf.put_u8(*labels);
                buf.put_u32(*original_ttl);
                buf.put_u32(*expiration);
                buf.put_u32(*inception);
                buf.put_u16(*key_tag);
                signer.to_wire(&mut buf, None)?;
                buf.put_slice(signature);
            }

            RData::Nsec { next_domain, type_bitmap } => {
                next_domain.to_wire(&mut buf, None)?;
                buf.put_slice(type_bitmap);
            }

            RData::Nsec3 { hash_algorithm, flags, iterations, salt, next_hashed, type_bitmap } => {
                buf.put_u8(*hash_algorithm);
                buf.put_u8(*flags);
                buf.put_u16(*iterations);

                // Serialize salt (length-prefixed)
                buf.put_u8(salt.len() as u8);
                buf.put_slice(salt);

                // Serialize next hashed (length-prefixed)
                buf.put_u8(next_hashed.len() as u8);
                buf.put_slice(next_hashed);

                // Serialize type bitmap
                buf.put_slice(type_bitmap);
            }

            RData::Opt(options) => {
                // Serialize EDNS0 options
                for option in options {
                    let (option_code, option_data) = option.serialize()?;
                    buf.put_u16(option_code);
                    buf.put_u16(option_data.len() as u16);
                    buf.put_slice(&option_data);
                }
            }

            RData::Caa { flags, tag, value } => {
                buf.put_u8(*flags);

                // Serialize tag (length-prefixed string)
                let tag_bytes = tag.as_bytes();
                buf.put_u8(tag_bytes.len() as u8);
                buf.put_slice(tag_bytes);

                // Serialize value (not length-prefixed, rest of RDATA)
                buf.put_slice(value.as_bytes());
            }

            RData::Unknown { rdata, .. } => {
                buf.put_slice(rdata);
            }
        }

        Ok(buf.to_vec())
    }
}

impl fmt::Display for ResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {:?}",
            self.name.as_str(),
            self.ttl,
            self.class,
            u16::from(self.rtype),
            self.rdata
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_resource_record_a_parsing() {
        // Test A record: example.com A 192.0.2.1
        let name = DomainName::from_str("example.com").unwrap();
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::A,
            C_IN,
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        );

        assert_eq!(rr.name().as_str(), "example.com");
        assert_eq!(rr.rtype(), RecordType::A);
        assert_eq!(rr.class(), C_IN);
        assert_eq!(rr.ttl(), 300);

        match rr.rdata() {
            RData::A(addr) => assert_eq!(*addr, Ipv4Addr::new(192, 0, 2, 1)),
            _ => panic!("Expected A record"),
        }
    }

    #[test]
    fn test_resource_record_aaaa_parsing() {
        // Test AAAA record: example.com AAAA 2001:db8::1
        let name = DomainName::from_str("example.com").unwrap();
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::AAAA,
            C_IN,
            300,
            RData::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );

        match rr.rdata() {
            RData::AAAA(addr) => {
                assert_eq!(*addr, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            }
            _ => panic!("Expected AAAA record"),
        }
    }

    #[test]
    fn test_resource_record_mx_parsing() {
        // Test MX record: example.com MX 10 mail.example.com
        let name = DomainName::from_str("example.com").unwrap();
        let exchange = DomainName::from_str("mail.example.com").unwrap();
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::MX,
            C_IN,
            300,
            RData::Mx { preference: 10, exchange: exchange.clone() },
        );

        match rr.rdata() {
            RData::Mx { preference, exchange: ex } => {
                assert_eq!(*preference, 10);
                assert_eq!(ex.as_str(), "mail.example.com");
            }
            _ => panic!("Expected MX record"),
        }
    }

    #[test]
    fn test_resource_record_txt() {
        // Test TXT record with multiple strings
        let name = DomainName::from_str("example.com").unwrap();
        let txt_data = vec![b"v=spf1 mx ~all".to_vec(), b"another string".to_vec()];
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::TXT,
            C_IN,
            300,
            RData::Txt { txt_data: txt_data.clone() },
        );

        match rr.rdata() {
            RData::Txt { txt_data: data } => {
                assert_eq!(data.len(), 2);
                assert_eq!(data[0], b"v=spf1 mx ~all");
                assert_eq!(data[1], b"another string");
            }
            _ => panic!("Expected TXT record"),
        }
    }

    #[test]
    fn test_resource_record_builder_methods() {
        let name = DomainName::from_str("example.com").unwrap();
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::A,
            C_IN,
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        );

        let modified = rr.with_ttl(3600).with_class(1);
        assert_eq!(modified.ttl(), 3600);
        assert_eq!(modified.class(), 1);
    }

    #[test]
    fn test_resource_record_srv() {
        // Test SRV record: _http._tcp.example.com SRV 10 60 80 www.example.com
        let name = DomainName::from_str("_http._tcp.example.com").unwrap();
        let target = DomainName::from_str("www.example.com").unwrap();
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::SRV,
            C_IN,
            300,
            RData::Srv { priority: 10, weight: 60, port: 80, target: target.clone() },
        );

        match rr.rdata() {
            RData::Srv { priority, weight, port, target: t } => {
                assert_eq!(*priority, 10);
                assert_eq!(*weight, 60);
                assert_eq!(*port, 80);
                assert_eq!(t.as_str(), "www.example.com");
            }
            _ => panic!("Expected SRV record"),
        }
    }

    #[test]
    fn test_resource_record_soa() {
        // Test SOA record
        let name = DomainName::from_str("example.com").unwrap();
        let mname = DomainName::from_str("ns1.example.com").unwrap();
        let rname = DomainName::from_str("admin.example.com").unwrap();
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::SOA,
            C_IN,
            300,
            RData::Soa {
                mname: mname.clone(),
                rname: rname.clone(),
                serial: 2024010101,
                refresh: 3600,
                retry: 600,
                expire: 86400,
                minimum: 300,
            },
        );

        match rr.rdata() {
            RData::Soa { mname: m, rname: r, serial, refresh, retry, expire, minimum } => {
                assert_eq!(m.as_str(), "ns1.example.com");
                assert_eq!(r.as_str(), "admin.example.com");
                assert_eq!(*serial, 2024010101);
                assert_eq!(*refresh, 3600);
                assert_eq!(*retry, 600);
                assert_eq!(*expire, 86400);
                assert_eq!(*minimum, 300);
            }
            _ => panic!("Expected SOA record"),
        }
    }

    #[test]
    fn test_resource_record_cname() {
        // Test CNAME record: www.example.com CNAME example.com
        let name = DomainName::from_str("www.example.com").unwrap();
        let cname = DomainName::from_str("example.com").unwrap();
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::CNAME,
            C_IN,
            300,
            RData::Cname { cname: cname.clone() },
        );

        match rr.rdata() {
            RData::Cname { cname: c } => {
                assert_eq!(c.as_str(), "example.com");
            }
            _ => panic!("Expected CNAME record"),
        }
    }

    #[test]
    fn test_resource_record_ptr() {
        // Test PTR record: 1.2.0.192.in-addr.arpa PTR example.com
        let name = DomainName::from_str("1.2.0.192.in-addr.arpa").unwrap();
        let ptrdname = DomainName::from_str("example.com").unwrap();
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::PTR,
            C_IN,
            300,
            RData::Ptr { ptrdname: ptrdname.clone() },
        );

        match rr.rdata() {
            RData::Ptr { ptrdname: p } => {
                assert_eq!(p.as_str(), "example.com");
            }
            _ => panic!("Expected PTR record"),
        }
    }

    #[test]
    fn test_resource_record_ns() {
        // Test NS record: example.com NS ns1.example.com
        let name = DomainName::from_str("example.com").unwrap();
        let nsdname = DomainName::from_str("ns1.example.com").unwrap();
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::NS,
            C_IN,
            300,
            RData::Ns { nsdname: nsdname.clone() },
        );

        match rr.rdata() {
            RData::Ns { nsdname: n } => {
                assert_eq!(n.as_str(), "ns1.example.com");
            }
            _ => panic!("Expected NS record"),
        }
    }

    #[test]
    fn test_resource_record_dnskey() {
        // Test DNSKEY record with sample key data
        let name = DomainName::from_str("example.com").unwrap();
        let public_key = Bytes::from_static(b"sample_public_key_data");
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::DNSKEY,
            C_IN,
            300,
            RData::Dnskey {
                flags: 257,    // Zone Key + Secure Entry Point
                protocol: 3,   // DNSSEC
                algorithm: 13, // ECDSAP256SHA256
                public_key: public_key.clone(),
            },
        );

        match rr.rdata() {
            RData::Dnskey { flags, protocol, algorithm, public_key: pk } => {
                assert_eq!(*flags, 257);
                assert_eq!(*protocol, 3);
                assert_eq!(*algorithm, 13);
                assert_eq!(pk, &public_key);
            }
            _ => panic!("Expected DNSKEY record"),
        }
    }

    #[test]
    fn test_resource_record_ds() {
        // Test DS record with sample digest
        let name = DomainName::from_str("example.com").unwrap();
        let digest = Bytes::from_static(b"sample_digest_sha256_32bytes");
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::DS,
            C_IN,
            300,
            RData::Ds {
                key_tag: 12345,
                algorithm: 13,  // ECDSAP256SHA256
                digest_type: 2, // SHA-256
                digest: digest.clone(),
            },
        );

        match rr.rdata() {
            RData::Ds { key_tag, algorithm, digest_type, digest: d } => {
                assert_eq!(*key_tag, 12345);
                assert_eq!(*algorithm, 13);
                assert_eq!(*digest_type, 2);
                assert_eq!(d, &digest);
            }
            _ => panic!("Expected DS record"),
        }
    }

    #[test]
    fn test_resource_record_rrsig() {
        // Test RRSIG record
        let name = DomainName::from_str("example.com").unwrap();
        let signer = DomainName::from_str("example.com").unwrap();
        let signature = Bytes::from_static(b"sample_signature_data");
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::RRSIG,
            C_IN,
            300,
            RData::Rrsig {
                type_covered: T_A, // Covering A records
                algorithm: 13,     // ECDSAP256SHA256
                labels: 2,
                original_ttl: 300,
                expiration: 1704110400, // 2024-01-01 12:00:00 UTC
                inception: 1704024000,  // 2023-12-31 12:00:00 UTC
                key_tag: 12345,
                signer: signer.clone(),
                signature: signature.clone(),
            },
        );

        match rr.rdata() {
            RData::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration: _,
                inception: _,
                key_tag,
                signer: s,
                signature: sig,
            } => {
                assert_eq!(*type_covered, T_A);
                assert_eq!(*algorithm, 13);
                assert_eq!(*labels, 2);
                assert_eq!(*original_ttl, 300);
                assert_eq!(*key_tag, 12345);
                assert_eq!(s.as_str(), "example.com");
                assert_eq!(sig, &signature);
            }
            _ => panic!("Expected RRSIG record"),
        }
    }

    #[test]
    fn test_resource_record_nsec() {
        // Test NSEC record
        let name = DomainName::from_str("example.com").unwrap();
        let next_domain = DomainName::from_str("mail.example.com").unwrap();
        let type_bitmap = Bytes::from_static(&[0x40, 0x01, 0x00, 0x00, 0x00, 0x03]); // A, NS, SOA, RRSIG
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::NSEC,
            C_IN,
            300,
            RData::Nsec { next_domain: next_domain.clone(), type_bitmap: type_bitmap.clone() },
        );

        match rr.rdata() {
            RData::Nsec { next_domain: nd, type_bitmap: tb } => {
                assert_eq!(nd.as_str(), "mail.example.com");
                assert_eq!(tb, &type_bitmap);
            }
            _ => panic!("Expected NSEC record"),
        }
    }

    #[test]
    fn test_resource_record_nsec3() {
        // Test NSEC3 record
        let name = DomainName::from_str("example.com").unwrap();
        let salt = Bytes::from_static(b"SALT");
        let next_hashed = Bytes::from_static(b"NextHashedOwner");
        let type_bitmap = Bytes::from_static(&[0x40, 0x01]);
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::NSEC3,
            C_IN,
            300,
            RData::Nsec3 {
                hash_algorithm: 1, // SHA-1
                flags: 0,
                iterations: 10,
                salt: salt.clone(),
                next_hashed: next_hashed.clone(),
                type_bitmap: type_bitmap.clone(),
            },
        );

        match rr.rdata() {
            RData::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt: s,
                next_hashed: nh,
                type_bitmap: tb,
            } => {
                assert_eq!(*hash_algorithm, 1);
                assert_eq!(*flags, 0);
                assert_eq!(*iterations, 10);
                assert_eq!(s, &salt);
                assert_eq!(nh, &next_hashed);
                assert_eq!(tb, &type_bitmap);
            }
            _ => panic!("Expected NSEC3 record"),
        }
    }

    #[test]
    fn test_resource_record_caa() {
        // Test CAA record: example.com CAA 0 issue "letsencrypt.org"
        let name = DomainName::from_str("example.com").unwrap();
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::CAA,
            C_IN,
            300,
            RData::Caa { flags: 0, tag: "issue".to_string(), value: "letsencrypt.org".to_string() },
        );

        match rr.rdata() {
            RData::Caa { flags, tag, value } => {
                assert_eq!(*flags, 0);
                assert_eq!(tag, "issue");
                assert_eq!(value, "letsencrypt.org");
            }
            _ => panic!("Expected CAA record"),
        }
    }

    #[test]
    fn test_resource_record_unknown() {
        // Test unknown record type preservation
        let name = DomainName::from_str("example.com").unwrap();
        let rdata = Bytes::from_static(b"opaque_data");
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::Unknown(65535), // Max type value
            C_IN,
            300,
            RData::Unknown { rtype: 65535, rdata: rdata.clone() },
        );

        match rr.rdata() {
            RData::Unknown { rtype, rdata: rd } => {
                assert_eq!(*rtype, 65535);
                assert_eq!(rd, &rdata);
            }
            _ => panic!("Expected Unknown record"),
        }
    }

    #[test]
    fn test_resource_record_display() {
        // Test Display trait implementation
        let name = DomainName::from_str("example.com").unwrap();
        let rr = ResourceRecord::new(
            name.clone(),
            RecordType::A,
            C_IN,
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        );

        let display_str = format!("{}", rr);
        assert!(display_str.contains("example.com"));
        assert!(display_str.contains("300"));
    }

    #[test]
    fn test_parse_rdata_invalid_a_length() {
        // Test A record with invalid length
        let rdata_bytes = &[192, 0, 2]; // Only 3 bytes, should be 4
        let result = ResourceRecord::parse_rdata(rdata_bytes, &[], RecordType::A, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rdata_invalid_aaaa_length() {
        // Test AAAA record with invalid length
        let rdata_bytes = &[0x20, 0x01, 0x0d, 0xb8]; // Only 4 bytes, should be 16
        let result = ResourceRecord::parse_rdata(rdata_bytes, &[], RecordType::AAAA, 4);
        assert!(result.is_err());
    }
}
