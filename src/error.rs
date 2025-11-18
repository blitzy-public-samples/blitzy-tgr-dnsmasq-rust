// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Comprehensive error type definitions for dnsmasq Rust implementation.
//!
//! This module defines structured error enums using the `thiserror` crate to replace
//! C error codes with Rust's type-safe `Result<T, E>` pattern. Each error type provides
//! detailed context, automatic error message generation, and support for error chaining
//! through the `std::error::Error` trait.
//!
//! # Error Types
//!
//! - [`DnsmasqError`]: Top-level error type that aggregates all domain-specific errors
//! - [`DnsError`]: DNS query and cache operation failures
//! - [`DhcpError`]: DHCPv4/DHCPv6 allocation and lease management errors
//! - [`DnssecError`]: DNSSEC validation failures with detailed diagnostic information
//! - [`NetworkError`]: Socket, interface, and network layer errors
//! - [`ConfigError`]: Configuration parsing and validation errors
//! - [`TftpError`]: TFTP file transfer operation errors
//! - [`PlatformError`]: System integration and platform-specific errors
//!
//! # Design Patterns
//!
//! This module replaces several C error handling patterns:
//!
//! ## C Error Codes → Rust Result Types
//!
//! ```c
//! // C pattern: Return -1 on error, 0 on success
//! if (forward_query(query) < 0) {
//!     log_error("Query forwarding failed");
//!     return -1;
//! }
//! ```
//!
//! ```rust,ignore
//! // Rust pattern: Result with ? operator
//! forward_query(query).await?;
//! ```
//!
//! ## C errno → Rust std::io::Error
//!
//! ```c
//! // C pattern: errno global variable
//! if (socket(AF_INET, SOCK_DGRAM, 0) < 0) {
//!     int err = errno;
//!     log_error("Socket creation failed: %s", strerror(err));
//! }
//! ```
//!
//! ```rust,ignore
//! // Rust pattern: From<io::Error> conversion
//! let socket = UdpSocket::bind(addr).await
//!     .map_err(NetworkError::from)?;
//! ```
//!
//! ## C Bitflags → Rust Enum Variants
//!
//! ```c
//! // C pattern: DNSSEC_FAIL_* bitflags
//! if (status & DNSSEC_FAIL_NYV) {
//!     return STAT_BOGUS;
//! }
//! ```
//!
//! ```rust,ignore
//! // Rust pattern: Enum variants with data
//! match validate_dnssec(record).await {
//!     Err(DnssecError::NotYetValid { valid_from }) => {
//!         // Handle with type-safe information
//!     }
//!     Ok(validated) => {
//!         // Proceed with validated record
//!     }
//! }
//! ```
//!
//! # Error Context and Chaining
//!
//! All error types support the `source()` method for error chain traversal:
//!
//! ```rust,ignore
//! use std::error::Error;
//!
//! fn process_config(path: &str) -> Result<Config> {
//!     Config::from_file(path)
//!         .map_err(|e| {
//!             eprintln!("Error: {}", e);
//!             if let Some(source) = e.source() {
//!                 eprintln!("Caused by: {}", source);
//!             }
//!             e
//!         })
//! }
//! ```

use std::io;
use thiserror::Error;

/// Type alias for Results with `DnsmasqError` as the error type.
///
/// This provides a convenient shorthand for functions returning dnsmasq operations:
///
/// ```rust,ignore
/// use dnsmasq::error::Result;
///
/// async fn start_server() -> Result<()> {
///     // ... implementation
///     Ok(())
/// }
/// ```
pub type Result<T> = std::result::Result<T, DnsmasqError>;

/// Top-level error type aggregating all domain-specific errors.
///
/// This enum serves as the primary error type for the dnsmasq application, providing
/// variants for each subsystem. It implements automatic conversions from domain-specific
/// error types using `#[from]` attributes, enabling seamless error propagation with the
/// `?` operator.
///
/// # Error Propagation
///
/// ```rust,ignore
/// use dnsmasq::error::{Result, DnsError, DhcpError};
///
/// async fn handle_request() -> Result<()> {
///     // DNS errors automatically convert to DnsmasqError
///     let response = resolve_dns_query().await?;
///     
///     // DHCP errors also convert automatically
///     allocate_dhcp_lease().await?;
///     
///     Ok(())
/// }
/// ```
#[derive(Debug, Error)]
pub enum DnsmasqError {
    /// DNS query, forwarding, or cache operation error.
    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),

    /// DHCP lease allocation or management error.
    #[error("DHCP error: {0}")]
    Dhcp(#[from] DhcpError),

    /// DNSSEC validation failure.
    #[error("DNSSEC error: {0}")]
    Dnssec(#[from] DnssecError),

    /// Network socket or interface error.
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// Configuration parsing or validation error.
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// TFTP file transfer error.
    #[error("TFTP error: {0}")]
    Tftp(#[from] TftpError),

    /// Platform-specific system integration error.
    #[error("Platform error: {0}")]
    Platform(#[from] PlatformError),

    /// Generic I/O error from standard library operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Generic error with custom message.
    #[error("{0}")]
    Other(String),
}

/// DNS query and cache operation errors.
///
/// Covers failures in DNS query forwarding, cache operations, upstream server
/// communication, and response processing. Maps C return codes from forward.c,
/// cache.c, and rfc1035.c to structured error variants.
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::error::DnsError;
///
/// async fn forward_query(name: &str) -> std::result::Result<DnsResponse, DnsError> {
///     if name.is_empty() {
///         return Err(DnsError::InvalidName {
///             name: name.to_string(),
///             reason: "Empty domain name".to_string(),
///         });
///     }
///     // ... implementation
///     # todo!()
/// }
/// ```
#[derive(Debug, Error)]
pub enum DnsError {
    /// DNS query forwarding to upstream server failed.
    #[error("Failed to forward query to upstream server '{server}': {reason}")]
    ForwardFailed {
        /// The upstream DNS server that the query was forwarded to
        server: String,
        /// The reason why the forwarding operation failed
        reason: String,
    },

    /// DNS cache operation failed (insert, lookup, eviction).
    #[error("Cache operation failed: {operation} - {reason}")]
    CacheFailed {
        /// The cache operation that failed (e.g., "insert", "lookup", "evict")
        operation: String,
        /// The reason why the cache operation failed
        reason: String,
    },

    /// No upstream servers available for query forwarding.
    #[error("No upstream DNS servers available")]
    NoUpstreamServers,

    /// DNS response parsing failed (malformed packet).
    #[error("Failed to parse DNS response from '{server}': {reason}")]
    ParseFailed {
        /// The DNS server that sent the malformed response
        server: String,
        /// The reason why parsing failed
        reason: String,
    },

    /// Invalid domain name format.
    #[error("Invalid domain name '{name}': {reason}")]
    InvalidName {
        /// The invalid domain name that was provided
        name: String,
        /// The reason why the domain name is invalid
        reason: String,
    },

    /// DNS query timeout exceeded.
    #[error("Query timeout for '{query}' after {timeout_ms}ms")]
    Timeout {
        /// The DNS query that timed out
        query: String,
        /// The timeout duration in milliseconds
        timeout_ms: u64,
    },

    /// DNS response indicated server failure (SERVFAIL).
    #[error("Server '{server}' returned SERVFAIL for query '{query}'")]
    ServerFailure {
        /// The DNS server that returned SERVFAIL
        server: String,
        /// The query that resulted in SERVFAIL
        query: String,
    },

    /// DNS response indicated format error (FORMERR).
    #[error("Server '{server}' returned FORMERR for query '{query}'")]
    FormatError {
        /// The DNS server that returned FORMERR
        server: String,
        /// The query that resulted in FORMERR
        query: String,
    },

    /// DNS response indicated name error (NXDOMAIN).
    #[error("Domain '{domain}' does not exist (NXDOMAIN)")]
    NxDomain {
        /// The domain name that does not exist
        domain: String,
    },

    /// Authoritative zone answering failed.
    #[error("Authoritative answer failed for zone '{zone}': {reason}")]
    AuthFailed {
        /// The authoritative zone name
        zone: String,
        /// The reason why the authoritative answer failed
        reason: String,
    },

    /// EDNS0 option processing error.
    #[error("EDNS0 option processing failed: {reason}")]
    Edns0Failed {
        /// The reason why EDNS0 option processing failed
        reason: String,
    },

    /// DNS forwarding loop detected.
    #[error("DNS forwarding loop detected for query '{query}'")]
    LoopDetected {
        /// The DNS query that caused the forwarding loop
        query: String,
    },
}

/// DHCP lease allocation and management errors.
///
/// Covers DHCPv4 and DHCPv6 server operations including lease allocation, renewal,
/// release, and persistence. Maps C return codes from dhcp.c, dhcp6.c, rfc2131.c,
/// rfc3315.c, and lease.c to structured error variants.
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::error::DhcpError;
/// use std::net::Ipv4Addr;
///
/// fn allocate_lease(mac: &str) -> std::result::Result<Ipv4Addr, DhcpError> {
///     // Check address pool
///     if pool_exhausted() {
///         return Err(DhcpError::NoAddressAvailable {
///             pool_name: "default".to_string(),
///         });
///     }
///     // ... implementation
///     # todo!()
/// }
/// # fn pool_exhausted() -> bool { false }
/// ```
#[derive(Debug, Error)]
pub enum DhcpError {
    /// No IP addresses available in the configured range.
    #[error("No addresses available in DHCP pool '{pool_name}'")]
    NoAddressAvailable {
        /// The name of the DHCP address pool that is exhausted
        pool_name: String,
    },

    /// DHCP message parsing failed (malformed packet).
    #[error("Failed to parse DHCP message: {reason}")]
    ParseFailed {
        /// The reason why DHCP message parsing failed
        reason: String,
    },

    /// Invalid DHCP option encoding.
    #[error("Invalid DHCP option {option_code}: {reason}")]
    InvalidOption {
        /// The numeric code of the invalid DHCP option
        option_code: u8,
        /// The reason why the option is invalid
        reason: String,
    },

    /// Lease database operation failed (read/write/update).
    #[error("Lease database operation failed: {operation} - {reason}")]
    LeaseDatabaseFailed {
        /// The database operation that failed (e.g., "read", "write", "update")
        operation: String,
        /// The reason why the database operation failed
        reason: String,
    },

    /// DHCP relay operation failed.
    #[error("DHCP relay failed for relay '{relay}': {reason}")]
    RelayFailed {
        /// The DHCP relay agent identifier or address
        relay: String,
        /// The reason why the relay operation failed
        reason: String,
    },

    /// Address conflict detected (duplicate IP).
    #[error("Address conflict detected for IP '{ip}': already assigned to '{existing_mac}'")]
    AddressConflict {
        /// The IP address that has a conflict
        ip: String,
        /// The MAC address of the existing lease holder
        existing_mac: String,
    },

    /// DHCPv6 prefix delegation failed.
    #[error("DHCPv6 prefix delegation failed: {reason}")]
    PrefixDelegationFailed {
        /// The reason why prefix delegation failed
        reason: String,
    },

    /// Invalid DHCP client identifier.
    #[error("Invalid client identifier: {reason}")]
    InvalidClientId {
        /// The reason why the client identifier is invalid
        reason: String,
    },

    /// Helper script execution failed.
    #[error("Helper script '{script}' execution failed: {reason}")]
    ScriptFailed {
        /// The path or name of the helper script that failed
        script: String,
        /// The reason why script execution failed
        reason: String,
    },

    /// Lease renewal rejected (policy violation).
    #[error("Lease renewal rejected for '{client_id}': {reason}")]
    RenewalRejected {
        /// The DHCP client identifier of the rejected renewal
        client_id: String,
        /// The reason why the renewal was rejected
        reason: String,
    },

    /// DHCPv4-specific protocol error.
    #[error("DHCPv4 protocol error: {reason}")]
    V4ProtocolError {
        /// The reason for the DHCPv4 protocol error
        reason: String,
    },

    /// DHCPv6-specific protocol error.
    #[error("DHCPv6 protocol error: {reason}")]
    V6ProtocolError {
        /// The reason for the DHCPv6 protocol error
        reason: String,
    },
}

/// DNSSEC validation errors with detailed failure diagnostics.
///
/// Maps C DNSSEC_FAIL_* bitflags from dnssec.c to structured enum variants providing
/// type-safe information about validation failures. Each variant includes context
/// about why validation failed, enabling proper error handling and logging.
///
/// # DNSSEC Validation Workflow
///
/// ```rust,ignore
/// use dnsmasq::error::DnssecError;
/// use std::time::SystemTime;
///
/// async fn validate_record(record: &DnsRecord) -> std::result::Result<(), DnssecError> {
///     // Check signature timing
///     let now = SystemTime::now();
///     if record.signature_valid_from > now {
///         return Err(DnssecError::NotYetValid {
///             valid_from: record.signature_valid_from,
///             current_time: now,
///         });
///     }
///     
///     // ... more validation steps
///     Ok(())
/// }
/// # struct DnsRecord {
/// #     signature_valid_from: SystemTime,
/// # }
/// ```
#[derive(Debug, Error)]
pub enum DnssecError {
    /// Signature not yet valid (DNSSEC_FAIL_NYV).
    ///
    /// The RRSIG record's inception time is in the future. This may indicate
    /// clock skew or a premature signature.
    #[error(
        "DNSSEC signature not yet valid until {valid_from:?} (current time: {current_time:?})"
    )]
    NotYetValid {
        /// The timestamp when the signature becomes valid
        valid_from: std::time::SystemTime,
        /// The current system time
        current_time: std::time::SystemTime,
    },

    /// Signature expired (DNSSEC_FAIL_EXP).
    ///
    /// The RRSIG record's expiration time has passed. The zone needs re-signing.
    #[error("DNSSEC signature expired at {expired_at:?} (current time: {current_time:?})")]
    Expired {
        /// The timestamp when the signature expired
        expired_at: std::time::SystemTime,
        /// The current system time
        current_time: std::time::SystemTime,
    },

    /// Indeterminate validation result (DNSSEC_FAIL_INDET).
    ///
    /// Validation could not definitively prove the record is secure or insecure.
    /// This may require additional queries or indicate a validation path problem.
    #[error("DNSSEC validation indeterminate for '{name}': {reason}")]
    Indeterminate {
        /// The domain name being validated
        name: String,
        /// The reason why validation is indeterminate
        reason: String,
    },

    /// No supported key algorithm (DNSSEC_FAIL_NOKEYSUP).
    ///
    /// The DNSKEY uses an algorithm not supported by this implementation.
    #[error("No supported DNSSEC key algorithm: {algorithm_id}")]
    NoKeysSupported {
        /// The numeric identifier of the unsupported algorithm
        algorithm_id: u8,
    },

    /// No signatures present (DNSSEC_FAIL_NOSIG).
    ///
    /// DNSSEC validation requested but no RRSIG records found for the record set.
    #[error("No DNSSEC signatures found for '{name}' type {record_type}")]
    NoSignatures {
        /// The domain name for which signatures are missing
        name: String,
        /// The DNS record type (numeric identifier)
        record_type: u16,
    },

    /// No DNSSEC zone (DNSSEC_FAIL_NOZONE).
    ///
    /// The zone is unsigned or no delegation signer (DS) records found.
    #[error("No DNSSEC zone found for '{name}'")]
    NoZone {
        /// The domain name of the zone that lacks DNSSEC configuration
        name: String,
    },

    /// Non-secure delegation (DNSSEC_FAIL_NONSEC).
    ///
    /// Proven insecure delegation via NSEC/NSEC3 records indicating no DS.
    #[error("Non-secure delegation to '{name}' (proven insecure)")]
    NonSecure {
        /// The domain name with proven insecure delegation
        name: String,
    },

    /// No DS support (DNSSEC_FAIL_NODSSUP).
    ///
    /// The DS record uses an unsupported digest algorithm.
    #[error("No supported DS digest algorithm: {digest_algorithm_id}")]
    NoDsSupported {
        /// The unsupported DS digest algorithm identifier (IANA registry value)
        digest_algorithm_id: u8,
    },

    /// No trusted keys available (DNSSEC_FAIL_NOKEY).
    ///
    /// No trust anchor or trusted DNSKEY found to validate the chain.
    #[error("No trusted DNSSEC keys found for '{name}'")]
    NoKey {
        /// The domain name for which no trusted keys were found
        name: String,
    },

    /// Too many NSEC3 iterations (DNSSEC_FAIL_NSEC3_ITERS).
    ///
    /// NSEC3 iteration count exceeds the configured maximum, indicating a
    /// potential DoS attack or misconfiguration.
    #[error("NSEC3 iteration count {iterations} exceeds maximum {max_iterations}")]
    TooManyIterations {
        /// The NSEC3 iteration count specified in the response
        iterations: u32,
        /// The maximum allowed iteration count from configuration
        max_iterations: u32,
    },

    /// Malformed DNSSEC packet (DNSSEC_FAIL_BADPACKET).
    ///
    /// The DNSSEC-related records are malformed or cannot be parsed.
    #[error("Malformed DNSSEC record in response: {reason}")]
    BadPacket {
        /// The reason why the packet is malformed or cannot be parsed
        reason: String,
    },

    /// Validation work limit exceeded (DNSSEC_FAIL_WORK).
    ///
    /// The validation process exceeded the maximum allowed work units,
    /// preventing algorithmic complexity attacks.
    #[error("DNSSEC validation work limit exceeded ({work_units} units)")]
    TooMuchWork {
        /// The number of work units consumed during validation
        work_units: u64,
    },

    /// Cryptographic signature verification failed.
    ///
    /// The signature is correctly formatted but cryptographically invalid.
    #[error("Cryptographic signature verification failed for '{name}': {reason}")]
    SignatureVerificationFailed {
        /// The domain name whose signature failed verification
        name: String,
        /// The reason why signature verification failed
        reason: String,
    },

    /// Trust anchor parsing or loading failed.
    #[error("Trust anchor loading failed: {reason}")]
    TrustAnchorFailed {
        /// The reason why trust anchor loading or parsing failed
        reason: String,
    },

    /// Chain of trust validation failed.
    #[error("DNSSEC chain of trust broken at '{name}': {reason}")]
    ChainOfTrustBroken {
        /// The domain name where the chain of trust was broken
        name: String,
        /// The reason why the chain of trust validation failed
        reason: String,
    },
}

/// Network socket, interface, and platform networking errors.
///
/// Covers socket creation, binding, interface enumeration, routing operations,
/// and platform-specific networking (netlink, BPF). Maps C return codes from
/// network.c, netlink.c, bpf.c, and platform-specific network modules.
///
/// # Automatic io::Error Conversion
///
/// ```rust,ignore
/// use dnsmasq::error::NetworkError;
/// use tokio::net::UdpSocket;
///
/// async fn bind_dns_socket() -> std::result::Result<UdpSocket, NetworkError> {
///     // io::Error automatically converts to NetworkError
///     let socket = UdpSocket::bind("0.0.0.0:53").await?;
///     Ok(socket)
/// }
/// ```
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Socket creation or binding failed.
    #[error("Socket operation failed on '{address}': {reason}")]
    SocketFailed {
        /// The socket address that the operation was attempted on
        address: String,
        /// The reason why the socket operation failed
        reason: String,
    },

    /// Network interface enumeration failed.
    #[error("Interface enumeration failed: {reason}")]
    InterfaceEnumerationFailed {
        /// The reason why interface enumeration failed
        reason: String,
    },

    /// Specified interface not found.
    #[error("Interface '{interface}' not found")]
    InterfaceNotFound {
        /// The name of the network interface that was not found
        interface: String,
    },

    /// Interface configuration error.
    #[error("Interface '{interface}' configuration error: {reason}")]
    InterfaceConfigError {
        /// The name of the network interface with configuration issues
        interface: String,
        /// The reason why interface configuration failed
        reason: String,
    },

    /// Linux netlink operation failed.
    #[error("Netlink operation failed: {operation} - {reason}")]
    NetlinkFailed {
        /// The netlink operation that failed (e.g., "route_add", "addr_list")
        operation: String,
        /// The reason why the netlink operation failed
        reason: String,
    },

    /// BSD BPF (Berkeley Packet Filter) operation failed.
    #[error("BPF operation failed: {operation} - {reason}")]
    BpfFailed {
        /// The BPF operation that failed (e.g., "filter_set", "device_open")
        operation: String,
        /// The reason why the BPF operation failed
        reason: String,
    },

    /// Routing table operation failed.
    #[error("Routing operation failed: {operation} - {reason}")]
    RoutingFailed {
        /// The routing operation that failed (e.g., "route_get", "route_add")
        operation: String,
        /// The reason why the routing operation failed
        reason: String,
    },

    /// IP address parsing or validation error.
    #[error("Invalid IP address '{address}': {reason}")]
    InvalidAddress {
        /// The invalid IP address string that failed parsing
        address: String,
        /// The reason why the address is invalid
        reason: String,
    },

    /// Port binding error (privilege or conflict).
    #[error("Failed to bind to port {port}: {reason}")]
    PortBindFailed {
        /// The port number that failed to bind
        port: u16,
        /// The reason why port binding failed
        reason: String,
    },

    /// Socket option configuration failed.
    #[error("Failed to set socket option '{option}': {reason}")]
    SocketOptionFailed {
        /// The socket option that failed to set (e.g., "SO_REUSEADDR", "SO_BINDTODEVICE")
        option: String,
        /// The reason why the socket option could not be set
        reason: String,
    },

    /// Multicast group operation failed.
    #[error("Multicast operation failed on '{interface}' for group '{group}': {reason}")]
    MulticastFailed {
        /// The network interface used for multicast operations
        interface: String,
        /// The multicast group address
        group: String,
        /// The reason why the multicast operation failed
        reason: String,
    },

    /// Generic I/O error from standard library.
    #[error("Network I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Configuration file parsing and validation errors.
///
/// Covers dnsmasq.conf parsing, command-line argument processing, configuration
/// validation, and include directive handling. Maps C return codes from option.c
/// to structured error variants.
///
/// # Configuration Error Context
///
/// ```rust,ignore
/// use dnsmasq::error::ConfigError;
///
/// fn parse_config_line(line: &str, line_number: usize) -> std::result::Result<(), ConfigError> {
///     if line.starts_with("invalid-directive") {
///         return Err(ConfigError::UnknownDirective {
///             directive: "invalid-directive".to_string(),
///             line_number,
///             file_path: "/etc/dnsmasq.conf".to_string(),
///         });
///     }
///     Ok(())
/// }
/// ```
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Configuration file not found or inaccessible.
    #[error("Configuration file not found: '{path}'")]
    FileNotFound {
        /// The path to the configuration file that was not found
        path: String,
    },

    /// Configuration file parsing error (syntax error).
    #[error("Parse error in '{file_path}' line {line_number}: {reason}")]
    ParseError {
        /// The path to the configuration file with the parse error
        file_path: String,
        /// The line number where the parse error occurred
        line_number: usize,
        /// The reason why parsing failed
        reason: String,
    },

    /// Unknown configuration directive.
    #[error("Unknown directive '{directive}' in '{file_path}' line {line_number}")]
    UnknownDirective {
        /// The unknown configuration directive that was encountered
        directive: String,
        /// The path to the configuration file containing the unknown directive
        file_path: String,
        /// The line number where the unknown directive was found
        line_number: usize,
    },

    /// Invalid directive argument or value.
    #[error("Invalid value for directive '{directive}': {reason}")]
    InvalidValue {
        /// The configuration directive with an invalid value
        directive: String,
        /// The reason why the value is invalid
        reason: String,
    },

    /// Missing required configuration option.
    #[error("Required configuration option '{option}' is missing")]
    MissingRequired {
        /// The name of the required configuration option that is missing
        option: String,
    },

    /// Conflicting configuration directives.
    #[error("Configuration conflict: {reason}")]
    Conflict {
        /// The reason why the configuration directives conflict
        reason: String,
    },

    /// Include directive processing failed.
    #[error("Failed to include file '{path}': {reason}")]
    IncludeFailed {
        /// The path to the include file that failed to load
        path: String,
        /// The reason why the include operation failed
        reason: String,
    },

    /// Configuration validation failed.
    #[error("Configuration validation failed: {reason}")]
    ValidationFailed {
        /// The reason why configuration validation failed
        reason: String,
    },

    /// Invalid IP address or network range.
    #[error("Invalid IP address or range '{value}' for directive '{directive}': {reason}")]
    InvalidIpRange {
        /// The configuration directive that requires an IP range
        directive: String,
        /// The invalid IP address or range value
        value: String,
        /// The reason why the IP range is invalid
        reason: String,
    },

    /// Invalid port number.
    #[error("Invalid port number '{port}' for directive '{directive}'")]
    InvalidPort {
        /// The configuration directive that requires a port number
        directive: String,
        /// The invalid port number value
        port: String,
    },

    /// Command-line argument parsing error.
    #[error("Command-line argument error: {reason}")]
    CommandLineError {
        /// The reason why command-line argument parsing failed
        reason: String,
    },

    /// Environment variable error.
    #[error("Environment variable '{variable}' error: {reason}")]
    EnvironmentError {
        /// The name of the environment variable with an error
        variable: String,
        /// The reason why the environment variable has an error
        reason: String,
    },
}

/// TFTP file transfer operation errors.
///
/// Covers TFTP server operations including file transfer initiation, block
/// transmission, timeout handling, and error responses. Maps C return codes
/// from tftp.c to structured error variants.
///
/// # TFTP Error Codes
///
/// TFTP protocol defines specific error codes (RFC 1350) which are represented
/// in these error variants.
#[derive(Debug, Error)]
pub enum TftpError {
    /// File not found on TFTP server.
    #[error("TFTP file not found: '{path}'")]
    FileNotFound {
        /// The path to the file that was not found on the TFTP server
        path: String,
    },

    /// Access violation (permission denied).
    #[error("TFTP access violation for '{path}': {reason}")]
    AccessViolation {
        /// The path to the file with access violations
        path: String,
        /// The reason why access was denied
        reason: String,
    },

    /// Disk full or allocation exceeded.
    #[error("TFTP disk full error: {reason}")]
    DiskFull {
        /// The reason why the disk full error occurred
        reason: String,
    },

    /// Illegal TFTP operation.
    #[error("TFTP illegal operation: {reason}")]
    IllegalOperation {
        /// The reason why the TFTP operation is illegal
        reason: String,
    },

    /// Unknown transfer ID.
    #[error("TFTP unknown transfer ID: {transfer_id}")]
    UnknownTransferId {
        /// The unknown TFTP transfer identifier
        transfer_id: u16,
    },

    /// File already exists (write mode).
    #[error("TFTP file already exists: '{path}'")]
    FileExists {
        /// The path to the file that already exists
        path: String,
    },

    /// No such user (TFTP with authentication).
    #[error("TFTP no such user: '{user}'")]
    NoSuchUser {
        /// The username that does not exist
        user: String,
    },

    /// Transfer timeout.
    #[error("TFTP transfer timeout for '{path}' after {timeout_ms}ms")]
    Timeout {
        /// The path to the file being transferred
        path: String,
        /// The timeout duration in milliseconds
        timeout_ms: u64,
    },

    /// Unsupported option.
    #[error("TFTP unsupported option: '{option}'")]
    UnsupportedOption {
        /// The unsupported TFTP option name
        option: String,
    },

    /// Block size negotiation failed.
    #[error("TFTP blocksize negotiation failed: requested {requested}, max {max}")]
    BlocksizeNegotiationFailed {
        /// The requested block size
        requested: u16,
        /// The maximum allowed block size
        max: u16,
    },

    /// Network error during transfer.
    #[error("TFTP network error: {reason}")]
    NetworkError {
        /// The reason for the network error
        reason: String,
    },

    /// File I/O error.
    #[error("TFTP file I/O error for '{path}': {reason}")]
    IoError {
        /// The path to the file that caused the I/O error
        path: String,
        /// The reason for the I/O error
        reason: String,
    },
}

/// Platform-specific system integration errors.
///
/// Maps C EVENT_* error codes from dnsmasq.c, helper.c, and platform-specific
/// modules to structured error variants. Covers privilege management, process
/// execution, system integration (D-Bus, systemd), and platform-specific APIs.
///
/// # Event Code Mapping
///
/// These variants correspond to C EVENT_* codes:
/// - EVENT_EXEC_ERR → `ScriptExecutionFailed`
/// - EVENT_PIPE_ERR → `PipeCreationFailed`
/// - EVENT_USER_ERR → `UserNotFound`
/// - EVENT_CAP_ERR → `CapabilityError`
/// - EVENT_LOG_ERR → `LoggingFailed`
/// - EVENT_FORK_ERR → `ForkFailed`
/// - EVENT_LUA_ERR → `LuaScriptError`
/// - EVENT_TFTP_ERR → Mapped to `TftpError` variants
#[derive(Debug, Error)]
pub enum PlatformError {
    /// Helper script execution failed (EVENT_EXEC_ERR).
    #[error("Script execution failed for '{script}': {reason}")]
    ScriptExecutionFailed {
        /// The path to the helper script that failed
        script: String,
        /// The reason for the execution failure
        reason: String,
    },

    /// Pipe creation failed for IPC (EVENT_PIPE_ERR).
    #[error("Pipe creation failed: {reason}")]
    PipeCreationFailed {
        /// The reason for the pipe creation failure
        reason: String,
    },

    /// User lookup or switching failed (EVENT_USER_ERR).
    #[error("User '{user}' not found or cannot switch: {reason}")]
    UserNotFound {
        /// The username that could not be found or switched to
        user: String,
        /// The reason for the failure
        reason: String,
    },

    /// Linux capability operation failed (EVENT_CAP_ERR).
    #[error("Capability operation failed: {operation} - {reason}")]
    CapabilityError {
        /// The capability operation that failed (e.g., "drop", "set")
        operation: String,
        /// The reason for the capability operation failure
        reason: String,
    },

    /// Logging system initialization failed (EVENT_LOG_ERR).
    #[error("Logging initialization failed: {reason}")]
    LoggingFailed {
        /// The reason for the logging initialization failure
        reason: String,
    },

    /// Process fork failed (EVENT_FORK_ERR).
    #[error("Fork failed: {reason}")]
    ForkFailed {
        /// The reason for the fork failure
        reason: String,
    },

    /// Lua script execution error (EVENT_LUA_ERR).
    #[error("Lua script error in '{script}': {reason}")]
    LuaScriptError {
        /// The path to the Lua script that encountered an error
        script: String,
        /// The reason for the Lua script error
        reason: String,
    },

    /// D-Bus integration error.
    #[error("D-Bus error: {operation} - {reason}")]
    DbusError {
        /// The D-Bus operation that failed
        operation: String,
        /// The reason for the D-Bus error
        reason: String,
    },

    /// UBus (OpenWrt) integration error.
    #[error("UBus error: {operation} - {reason}")]
    UbusError {
        /// The UBus operation that failed
        operation: String,
        /// The reason for the UBus error
        reason: String,
    },

    /// Systemd integration error (socket activation, notify).
    #[error("Systemd integration error: {operation} - {reason}")]
    SystemdError {
        /// The systemd operation that failed
        operation: String,
        /// The reason for the systemd error
        reason: String,
    },

    /// Inotify file monitoring error.
    #[error("Inotify error for '{path}': {reason}")]
    InotifyError {
        /// The path to the file or directory being monitored
        path: String,
        /// The reason for the inotify error
        reason: String,
    },

    /// Signal handling setup error.
    #[error("Signal handling setup failed: {reason}")]
    SignalError {
        /// The reason for the signal handling setup failure
        reason: String,
    },

    /// Privilege dropping failed.
    #[error("Privilege drop failed: {reason}")]
    PrivilegeDropFailed {
        /// The reason for the privilege drop failure
        reason: String,
    },

    /// PID file operation failed.
    #[error("PID file operation failed for '{path}': {reason}")]
    PidFileFailed {
        /// The path to the PID file
        path: String,
        /// The reason for the PID file operation failure
        reason: String,
    },

    /// Daemonization failed.
    #[error("Daemonization failed: {reason}")]
    DaemonizationFailed {
        /// The reason for the daemonization failure
        reason: String,
    },

    /// Conntrack (connection tracking) operation failed.
    #[error("Conntrack operation failed: {reason}")]
    ConntrackFailed {
        /// The reason for the conntrack operation failure
        reason: String,
    },

    /// IPSet (firewall set) operation failed.
    #[error("IPSet operation failed for set '{set_name}': {reason}")]
    IpsetFailed {
        /// The name of the ipset that failed
        set_name: String,
        /// The reason for the ipset operation failure
        reason: String,
    },

    /// NFTables set operation failed.
    #[error("NFTables operation failed for set '{set_name}': {reason}")]
    NftsetFailed {
        /// The name of the nftables set that failed
        set_name: String,
        /// The reason for the nftables operation failure
        reason: String,
    },

    /// PF (Packet Filter) tables operation failed.
    #[error("PF tables operation failed for table '{table_name}': {reason}")]
    PfTablesFailed {
        /// The name of the PF table that failed
        table_name: String,
        /// The reason for the PF tables operation failure
        reason: String,
    },
}
