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

//! DNS Protocol Constants
//!
//! This module provides a comprehensive set of DNS protocol constants per RFC 1035
//! and subsequent DNS-related RFCs. These constants define the wire format elements
//! of the DNS protocol including response codes, resource record types, class codes,
//! EDNS0 option codes, and Extended DNS Error codes.
//!
//! # Key Responsibilities
//!
//! - Define all DNS protocol port numbers and size limits per RFC 1035
//! - Enumerate DNS response codes (NOERROR, NXDOMAIN, SERVFAIL, etc.)
//! - Enumerate DNS resource record types (A, AAAA, CNAME, MX, DNSSEC types, etc.)
//! - Enumerate DNS class codes (IN, CHAOS, HESIOD, ANY)
//! - Define EDNS0 option codes per RFC 6891 and IANA registry
//! - Define RFC 8914 Extended DNS Error (EDE) codes for detailed error reporting
//! - Provide DNS header flag bit masks for protocol handling
//!
//! # RFC Compliance
//!
//! - RFC 1035: Domain Names - Implementation and Specification (base DNS protocol)
//! - RFC 2929: Domain Name System (DNS) IANA Considerations (registry procedures)
//! - RFC 4034: Resource Records for DNSSEC (DNSKEY, RRSIG, NSEC, DS)
//! - RFC 5155: NSEC3 for DNSSEC Authenticated Denial of Existence
//! - RFC 6891: Extension Mechanisms for DNS (EDNS0)
//! - RFC 7871: Client Subnet in DNS Queries
//! - RFC 8914: Extended DNS Errors (detailed error reporting)
//!
//! # Memory Safety
//!
//! All constants in this module are primitive types (u8, u16, i32, usize) providing
//! compile-time type safety and zero runtime overhead. These replace C preprocessor
//! macros with strongly-typed Rust constants.

// ============================================================================
// DNS and Network Service Port Numbers
// ============================================================================

/// DNS protocol standard port number (UDP and TCP) per RFC 1035 Section 4.2.
///
/// This is the well-known port for DNS servers. DNS queries and responses are
/// typically sent to and from this port.
pub const NAMESERVER_PORT: u16 = 53;

/// TFTP protocol standard port number per RFC 1350.
///
/// Used for network boot operations, particularly PXE boot sequences where
/// clients fetch boot files via TFTP.
pub const TFTP_PORT: u16 = 69;

/// First non-privileged port number.
///
/// Ports 1-1023 require root/administrator privileges to bind on UNIX-like systems.
/// This constant marks the beginning of the non-privileged port range.
pub const MIN_PORT: u16 = 1024;

/// Maximum valid port number.
///
/// Represents the upper limit of the 16-bit port number range (2^16 - 1).
pub const MAX_PORT: u16 = 65535;

// ============================================================================
// DNS Protocol Size Constants
// ============================================================================

/// IPv6 address size in bytes (128 bits = 16 bytes).
///
/// Used for buffer sizing and validation when handling IPv6 addresses in AAAA records.
pub const IN6ADDRSZ: usize = 16;

/// IPv4 address size in bytes (32 bits = 4 bytes).
///
/// Used for buffer sizing and validation when handling IPv4 addresses in A records.
pub const INADDRSZ: usize = 4;

/// Default maximum DNS UDP packet size per RFC 1035 (512 bytes without EDNS0).
///
/// Traditional DNS UDP messages are limited to 512 bytes. EDNS0 (RFC 6891) allows
/// larger sizes to be negotiated via the OPT pseudo-RR.
pub const PACKETSZ: usize = 512;

/// Maximum domain name length in presentation format including null terminator.
///
/// RFC 1035 specifies 255 bytes maximum for encoded domain names. The presentation
/// format can expand this due to escaping, hence 1025 bytes for safe buffer allocation.
pub const MAXDNAME: usize = 1025;

/// Fixed size of resource record metadata in bytes.
///
/// Represents the fixed portion of an RR: name compression pointer (variable),
/// type (2 bytes), class (2 bytes), TTL (4 bytes), and rdlength (2 bytes) = 10 bytes
/// of fixed fields excluding the variable-length name.
pub const RRFIXEDSZ: usize = 10;

/// Maximum length of a single DNS label per RFC 1035 Section 2.3.4.
///
/// DNS labels (components between dots in domain names) are limited to 63 characters.
/// This is enforced in the DNS wire format by using a 6-bit length field.
pub const MAXLABEL: usize = 63;

// ============================================================================
// DNS Response Codes (RCODE)
// ============================================================================

/// No error condition - query was successful (RFC 1035 Section 4.1.1).
///
/// Indicates that the query was processed successfully and the response contains
/// valid answer data.
pub const NOERROR: u8 = 0;

/// Format error - name server unable to interpret query (RFC 1035 Section 4.1.1).
///
/// The name server was unable to interpret the query due to a format problem.
/// This typically indicates malformed DNS packets.
pub const FORMERR: u8 = 1;

/// Server failure - name server unable to process query (RFC 1035 Section 4.1.1).
///
/// The name server encountered an internal error preventing query processing.
/// This is a temporary error condition.
pub const SERVFAIL: u8 = 2;

/// Name error (NXDOMAIN) - domain name does not exist (RFC 1035 Section 4.1.1).
///
/// The domain name referenced in the query does not exist in the DNS namespace.
/// This is an authoritative answer from the zone owner.
pub const NXDOMAIN: u8 = 3;

/// Not implemented - query type not supported (RFC 1035 Section 4.1.1).
///
/// The name server does not support the requested query type (OPCODE).
pub const NOTIMP: u8 = 4;

/// Query refused - operation refused for policy reasons (RFC 1035 Section 4.1.1).
///
/// The name server refuses to perform the requested operation for policy reasons,
/// such as access control restrictions.
pub const REFUSED: u8 = 5;

// ============================================================================
// DNS Operation Codes (OPCODE)
// ============================================================================

/// Standard query (QUERY) - the default DNS operation (RFC 1035 Section 4.1.1).
///
/// Represents a standard DNS query operation. This is the most common OPCODE value.
pub const QUERY: u8 = 0;

// ============================================================================
// DNS Class Codes
// ============================================================================

/// Internet class (IN) - standard class for Internet IP addresses (RFC 1035 Section 3.2.4).
///
/// The IN class is used for nearly all modern DNS queries and represents the Internet
/// protocol family namespace.
pub const C_IN: u16 = 1;

/// Chaos class - originally for MIT's Chaosnet (RFC 1035 Section 3.2.4).
///
/// Rarely used in modern DNS, originally intended for the Chaosnet protocol family.
pub const C_CHAOS: u16 = 3;

/// Hesiod class - used by MIT's Hesiod information service (RFC 1035 Section 3.2.4).
///
/// Hesiod is a name service system that uses DNS infrastructure for configuration
/// data distribution.
pub const C_HESIOD: u16 = 4;

/// Wildcard class (ANY) - matches any class (RFC 1035 Section 3.2.5).
///
/// Used in queries to request records of any class. Not valid in resource records,
/// only in queries.
pub const C_ANY: u16 = 255;

// ============================================================================
// DNS Resource Record Types
// ============================================================================

/// A record - IPv4 host address (RFC 1035).
///
/// Maps a domain name to a 32-bit IPv4 address.
pub const T_A: u16 = 1;

/// NS record - authoritative name server (RFC 1035).
///
/// Identifies an authoritative name server for a DNS zone.
pub const T_NS: u16 = 2;

/// MD record - mail destination (obsolete, RFC 1035).
///
/// Historical record type, now obsolete. Do not use.
pub const T_MD: u16 = 3;

/// MF record - mail forwarder (obsolete, RFC 1035).
///
/// Historical record type, now obsolete. Do not use.
pub const T_MF: u16 = 4;

/// CNAME record - canonical name for an alias (RFC 1035).
///
/// Provides the canonical (true) name for a domain name alias.
pub const T_CNAME: u16 = 5;

/// SOA record - start of authority zone record (RFC 1035).
///
/// Marks the start of a zone of authority and contains zone parameters like
/// serial number, refresh interval, and retry interval.
pub const T_SOA: u16 = 6;

/// MB record - mailbox domain name (experimental, RFC 1035).
///
/// Experimental record type for mailbox identification. Rarely used.
pub const T_MB: u16 = 7;

/// MG record - mail group member (experimental, RFC 1035).
///
/// Experimental record type for mail group membership. Rarely used.
pub const T_MG: u16 = 8;

/// MR record - mail rename domain name (experimental, RFC 1035).
///
/// Experimental record type for mail renaming. Rarely used.
pub const T_MR: u16 = 9;

/// PTR record - pointer to canonical name (RFC 1035).
///
/// Used primarily for reverse DNS lookups, mapping IP addresses to domain names.
pub const T_PTR: u16 = 12;

/// MINFO record - mailbox or mail list information (experimental, RFC 1035).
///
/// Experimental record type for mailbox information. Rarely used.
pub const T_MINFO: u16 = 14;

/// MX record - mail exchange (RFC 1035).
///
/// Specifies the mail server responsible for accepting email for a domain.
/// Includes a priority value for multiple MX records.
pub const T_MX: u16 = 15;

/// TXT record - text strings (RFC 1035).
///
/// Contains arbitrary text data. Commonly used for SPF records, domain verification,
/// and other text-based metadata.
pub const T_TXT: u16 = 16;

/// RP record - responsible person (RFC 1183).
///
/// Identifies the responsible person for a domain or host.
pub const T_RP: u16 = 17;

/// AFSDB record - AFS database location (RFC 1183).
///
/// Provides location information for AFS (Andrew File System) database servers.
pub const T_AFSDB: u16 = 18;

/// RT record - route through (RFC 1183).
///
/// Specifies intermediate routing hosts for systems without direct network connectivity.
pub const T_RT: u16 = 21;

/// SIG record - security signature (RFC 2535, obsoleted by RRSIG).
///
/// Original DNSSEC signature record type. Obsoleted by RRSIG in DNSSEC (RFC 4034).
pub const T_SIG: u16 = 24;

/// PX record - pointer to X.400/RFC822 mapping (RFC 2163).
///
/// Maps between X.400 and RFC 822 (email) addressing.
pub const T_PX: u16 = 26;

/// AAAA record - IPv6 host address (RFC 3596).
///
/// Maps a domain name to a 128-bit IPv6 address.
pub const T_AAAA: u16 = 28;

/// NXT record - next domain (obsolete DNSSEC, RFC 2535).
///
/// Original DNSSEC authenticated denial of existence record. Replaced by NSEC (RFC 4034).
pub const T_NXT: u16 = 30;

/// SRV record - service location (RFC 2761).
///
/// Specifies the location of services, including priority, weight, port, and target host.
/// Commonly used for SIP, XMPP, and other service discovery.
pub const T_SRV: u16 = 33;

/// NAPTR record - naming authority pointer (RFC 2915).
///
/// Provides rule-based rewriting of domain names. Used in ENUM and other dynamic
/// delegation systems.
pub const T_NAPTR: u16 = 35;

/// KX record - key exchange delegation (RFC 2230).
///
/// Delegates key exchange information for `IPsec` and other security protocols.
pub const T_KX: u16 = 36;

/// DNAME record - delegation name (RFC 6672).
///
/// Provides redirection for an entire subtree of the DNS namespace, similar to
/// CNAME but for whole zones.
pub const T_DNAME: u16 = 39;

/// OPT pseudo-record - EDNS0 option (RFC 6891).
///
/// Not a true RR type. Used as a pseudo-record to signal EDNS0 capability and
/// carry EDNS0 options like buffer size and extended RCODE.
pub const T_OPT: u16 = 41;

/// DS record - delegation signer (RFC 4034).
///
/// Establishes the DNSSEC chain of trust by holding a hash of a DNSKEY record
/// in the child zone. Used for secure delegation.
pub const T_DS: u16 = 43;

/// RRSIG record - DNSSEC signature (RFC 4034).
///
/// Contains a cryptographic signature for a set of resource records. Core component
/// of DNSSEC validation.
pub const T_RRSIG: u16 = 46;

/// NSEC record - next secure record (RFC 4034).
///
/// Provides authenticated denial of existence in DNSSEC by linking the zone's
/// names in a chain. Proves that a queried name does not exist.
pub const T_NSEC: u16 = 47;

/// DNSKEY record - DNS public key (RFC 4034).
///
/// Contains the public key used for DNSSEC validation. Zones use DNSKEY records
/// to publish their zone signing keys and key signing keys.
pub const T_DNSKEY: u16 = 48;

/// NSEC3 record - hashed authenticated denial of existence (RFC 5155).
///
/// Enhanced version of NSEC that uses cryptographic hashing to provide authenticated
/// denial of existence while preventing zone enumeration.
pub const T_NSEC3: u16 = 50;

/// TKEY record - transaction key (RFC 2930).
///
/// Provides a mechanism for establishing shared secret keys for secure DNS
/// transactions.
pub const T_TKEY: u16 = 249;

/// TSIG record - transaction signature (RFC 2845).
///
/// Authenticates DNS messages using shared secret keys. Commonly used for
/// securing zone transfers and dynamic updates.
pub const T_TSIG: u16 = 250;

/// AXFR query type - zone transfer request (RFC 1035).
///
/// Requests a complete zone transfer. This is a query type, not a resource record type.
/// Only valid in queries.
pub const T_AXFR: u16 = 252;

/// MAILB query type - mailbox-related records (RFC 1035).
///
/// Requests all mailbox-related records (MB, MG, MR). Query type only.
pub const T_MAILB: u16 = 253;

/// ANY query type - request for all records (RFC 1035).
///
/// Wildcard query requesting all records of all types for a name. Query type only,
/// not valid in resource records.
pub const T_ANY: u16 = 255;

/// CAA record - certification authority authorization (RFC 6844).
///
/// Allows domain owners to specify which certificate authorities are permitted
/// to issue certificates for their domain.
pub const T_CAA: u16 = 257;

// ============================================================================
// EDNS0 Option Codes
// ============================================================================

/// Client subnet option - client IP prefix for geo-aware responses (RFC 7871).
///
/// IANA-assigned EDNS0 option code 8. Provides the client's IP subnet to
/// authoritative servers for geographically-aware DNS responses.
pub const EDNS0_OPTION_CLIENT_SUBNET: u16 = 8;

/// Extended DNS Error option - detailed error information (RFC 8914).
///
/// IANA-assigned EDNS0 option code 15. Carries Extended DNS Error (EDE) codes
/// providing detailed diagnostic information about DNS failures.
pub const EDNS0_OPTION_EDE: u16 = 15;

/// MAC address option - dyndns.org temporary assignment.
///
/// Private use range option for carrying MAC addresses. Vendor-specific extension.
pub const EDNS0_OPTION_MAC: u16 = 65001;

/// Nominum device ID option - device identification.
///
/// Nominum temporary assignment in private use range for device identification.
pub const EDNS0_OPTION_NOMDEVICEID: u16 = 65073;

/// Nominum CPE ID option - customer premises equipment identification.
///
/// Nominum temporary assignment in private use range for CPE identification.
pub const EDNS0_OPTION_NOMCPEID: u16 = 65074;

/// Cisco Umbrella option - Umbrella security platform integration.
///
/// Cisco temporary assignment for OpenDNS/Cisco Umbrella security platform.
pub const EDNS0_OPTION_UMBRELLA: u16 = 20292;

// ============================================================================
// Extended DNS Error Codes (RFC 8914)
// ============================================================================

/// Internal: No extended DNS error available (dnsmasq-specific).
///
/// This is an internal dnsmasq code (not in RFC 8914) indicating that no
/// extended error information is available. Negative value prevents wire format
/// transmission.
pub const EDE_UNSET: i32 = -1;

/// Other error - general catch-all (RFC 8914, code 0).
///
/// General error code for unspecified or uncategorized errors.
pub const EDE_OTHER: i32 = 0;

/// Unsupported DNSKEY algorithm (RFC 8914, code 1).
///
/// DNSSEC validation failed because the DNSKEY uses an unsupported or unknown
/// cryptographic algorithm.
pub const EDE_USUPDNSKEY: i32 = 1;

/// Unsupported DS digest type (RFC 8914, code 2).
///
/// DS record uses an unsupported or unknown hash algorithm for the digest.
pub const EDE_USUPDS: i32 = 2;

/// Stale answer (RFC 8914, code 3).
///
/// Resolver is returning cached data that has passed its TTL expiration time.
pub const EDE_STALE: i32 = 3;

/// Forged answer (RFC 8914, code 4).
///
/// Response appears to be fake or manipulated, potentially indicating a
/// man-in-the-middle attack.
pub const EDE_FORGED: i32 = 4;

/// DNSSEC indeterminate (RFC 8914, code 5).
///
/// Unable to determine DNSSEC validation status due to missing or incomplete
/// information.
pub const EDE_DNSSEC_IND: i32 = 5;

/// DNSSEC bogus (RFC 8914, code 6).
///
/// DNSSEC validation conclusively failed. The response is provably invalid.
pub const EDE_DNSSEC_BOGUS: i32 = 6;

/// Signature expired (RFC 8914, code 7).
///
/// RRSIG signature has passed its expiration time.
pub const EDE_SIG_EXP: i32 = 7;

/// Signature not yet valid (RFC 8914, code 8).
///
/// RRSIG signature is before its inception time (not yet valid).
pub const EDE_SIG_NYV: i32 = 8;

/// DNSKEY missing (RFC 8914, code 9).
///
/// No DNSKEY record found for validation of the signature.
pub const EDE_NO_DNSKEY: i32 = 9;

/// RRSIGs missing (RFC 8914, code 10).
///
/// Expected RRSIG records are not present in the response.
pub const EDE_NO_RRSIG: i32 = 10;

/// No zone key bit set (RFC 8914, code 11).
///
/// DNSKEY lacks the zone signing key flag required for validation.
pub const EDE_NO_ZONEKEY: i32 = 11;

/// NSEC missing (RFC 8914, code 12).
///
/// Expected NSEC record is not present for authenticated denial of existence.
pub const EDE_NO_NSEC: i32 = 12;

/// Cached error (RFC 8914, code 13).
///
/// Resolver is returning a cached error response.
pub const EDE_CACHED_ERR: i32 = 13;

/// Not ready (RFC 8914, code 14).
///
/// Server is not ready to answer the query (warming up caches, loading zones).
pub const EDE_NOT_READY: i32 = 14;

/// Blocked (RFC 8914, code 15).
///
/// Query was blocked by security or access control policy.
pub const EDE_BLOCKED: i32 = 15;

/// Censored (RFC 8914, code 16).
///
/// Answer was censored by policy (content filtering).
pub const EDE_CENSORED: i32 = 16;

/// Filtered (RFC 8914, code 17).
///
/// Query was filtered by policy before resolution.
pub const EDE_FILTERED: i32 = 17;

/// Prohibited (RFC 8914, code 18).
///
/// Query is prohibited by policy configuration.
pub const EDE_PROHIBITED: i32 = 18;

/// Stale NXDOMAIN (RFC 8914, code 19).
///
/// Returning a stale NXDOMAIN answer from cache.
pub const EDE_STALE_NXD: i32 = 19;

/// Not authoritative (RFC 8914, code 20).
///
/// Server is not authoritative for the requested zone.
pub const EDE_NOT_AUTH: i32 = 20;

/// Not supported (RFC 8914, code 21).
///
/// Query type is not supported by the server.
pub const EDE_NOT_SUP: i32 = 21;

/// No reachable authority (RFC 8914, code 22).
///
/// Unable to reach authoritative name servers for the zone.
pub const EDE_NO_AUTH: i32 = 22;

/// Network error (RFC 8914, code 23).
///
/// Network error prevented successful resolution.
pub const EDE_NETERR: i32 = 23;

/// Invalid data (RFC 8914, code 24).
///
/// Response data is invalid or malformed.
pub const EDE_INVALID_DATA: i32 = 24;

/// Signature expired before valid (RFC 8914, code 25).
///
/// RRSIG expiration time is before the inception time (impossible time range).
pub const EDE_SIG_E_B_V: i32 = 25;

/// Too early (RFC 8914, code 26).
///
/// Response was generated before acceptable processing time.
pub const EDE_TOO_EARLY: i32 = 26;

/// Unsupported NSEC3 iterations value (RFC 8914, code 27).
///
/// NSEC3 iterations count exceeds policy-defined limit.
pub const EDE_UNS_NS3_ITER: i32 = 27;

/// Unable to conform to policy (RFC 8914, code 28).
///
/// Policy requirements cannot be satisfied for this query.
pub const EDE_UNABLE_POLICY: i32 = 28;

/// Synthesized (RFC 8914, code 29).
///
/// Answer was synthesized by the resolver (e.g., from wildcards or DNAME).
pub const EDE_SYNTHESIZED: i32 = 29;

// Aliases for compatibility with dnsmasq C implementation
/// Alias for `EDE_DNSSEC_BOGUS` (code 6).
pub const EDE_BOGUS: i32 = EDE_DNSSEC_BOGUS;

/// Alias for `EDE_DNSSEC_IND` (code 5) - DNSSEC Indeterminate.
pub const EDE_INDET: i32 = EDE_DNSSEC_IND;

/// Alias for `EDE_NO_RRSIG` (code 10) - Missing RRSIG.
pub const EDE_RRSIG_MISS: i32 = EDE_NO_RRSIG;

/// No reachable authority - custom dnsmasq extension.
/// Maps to network error for compatibility.
pub const EDE_NO_REACHABLE: i32 = EDE_NETERR;

/// Missing expected name - custom dnsmasq extension.
/// Maps to DNSSEC indeterminate for compatibility.
pub const EDE_SXNAME_MISS: i32 = EDE_DNSSEC_IND;

// ============================================================================
// DNS Header Flag Bits
// ============================================================================

/// QR flag - Query (0) or Response (1) indicator (RFC 1035 Section 4.1.1).
///
/// Bit 7 of header byte 3 (hb3). Set to 0 for queries, 1 for responses.
pub const HB3_QR: u8 = 0x80;

/// OPCODE mask - Operation code field (RFC 1035 Section 4.1.1).
///
/// Bits 6-3 of header byte 3 (hb3). Extract via: (hb3 & `HB3_OPCODE`) >> 3
pub const HB3_OPCODE: u8 = 0x78;

/// AA flag - Authoritative Answer (RFC 1035 Section 4.1.1).
///
/// Bit 2 of header byte 3 (hb3). Set by name servers for authoritative responses.
pub const HB3_AA: u8 = 0x04;

/// TC flag - `TrunCation` (RFC 1035 Section 4.1.1).
///
/// Bit 1 of header byte 3 (hb3). Indicates message was truncated due to length
/// exceeding transmission channel capacity.
pub const HB3_TC: u8 = 0x02;

/// RD flag - Recursion Desired (RFC 1035 Section 4.1.1).
///
/// Bit 0 of header byte 3 (hb3). Set by query sender to request recursive resolution.
pub const HB3_RD: u8 = 0x01;

/// RA flag - Recursion Available (RFC 1035 Section 4.1.1).
///
/// Bit 7 of header byte 4 (hb4). Set by name server if recursive service is available.
pub const HB4_RA: u8 = 0x80;

/// AD flag - Authenticated Data (RFC 4035 Section 3.1.6).
///
/// Bit 5 of header byte 4 (hb4). Set if resolver validated the answer with DNSSEC.
pub const HB4_AD: u8 = 0x20;

/// CD flag - Checking Disabled (RFC 4035 Section 3.1.6).
///
/// Bit 4 of header byte 4 (hb4). Set by query sender to disable DNSSEC validation.
pub const HB4_CD: u8 = 0x10;

/// RCODE mask - Response Code field (RFC 1035 Section 4.1.1).
///
/// Bits 3-0 of header byte 4 (hb4). Extract via: hb4 & `HB4_RCODE`
pub const HB4_RCODE: u8 = 0x0f;

// ============================================================================
// DNS Name Encoding
// ============================================================================

/// Escape character for DNS name presentation format encoding.
///
/// Character used as escape prefix in dnsmasq's internal presentation format
/// for DNS domain names. Value 1 (0x01, SOH control character) is used because:
/// - It cannot be '.' (0x2E) which is the label separator
/// - It cannot be null (0x00) which would terminate C strings
/// - It must be non-printable to distinguish from normal characters
///
/// # Encoding Scheme
///
/// Non-printable or special characters are encoded as a two-byte sequence:
/// `[NAME_ESCAPE, original_char + 1]`. Adding 1 ensures null byte (0x00)
/// encodes as 0x01, preventing embedded nulls in C strings.
///
/// # Examples
///
/// - Null byte (0x00): Encoded as `[0x01, 0x01]`
/// - Tab (0x09): Encoded as `[0x01, 0x0A]`
/// - DEL (0x7F): Encoded as `[0x01, 0x80]`
pub const NAME_ESCAPE: u8 = 1;
