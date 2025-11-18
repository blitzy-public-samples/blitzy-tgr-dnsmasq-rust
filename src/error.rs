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
//! ```rust
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
//! ```rust
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
//! ```rust
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
//! ```rust
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
/// ```rust
/// use crate::error::Result;
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
/// ```rust
/// use crate::error::{Result, DnsError, DhcpError};
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
/// ```rust
/// use crate::error::DnsError;
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
        server: String,
        reason: String,
    },

    /// DNS cache operation failed (insert, lookup, eviction).
    #[error("Cache operation failed: {operation} - {reason}")]
    CacheFailed {
        operation: String,
        reason: String,
    },

    /// No upstream servers available for query forwarding.
    #[error("No upstream DNS servers available")]
    NoUpstreamServers,

    /// DNS response parsing failed (malformed packet).
    #[error("Failed to parse DNS response from '{server}': {reason}")]
    ParseFailed {
        server: String,
        reason: String,
    },

    /// Invalid domain name format.
    #[error("Invalid domain name '{name}': {reason}")]
    InvalidName {
        name: String,
        reason: String,
    },

    /// DNS query timeout exceeded.
    #[error("Query timeout for '{query}' after {timeout_ms}ms")]
    Timeout {
        query: String,
        timeout_ms: u64,
    },

    /// DNS response indicated server failure (SERVFAIL).
    #[error("Server '{server}' returned SERVFAIL for query '{query}'")]
    ServerFailure {
        server: String,
        query: String,
    },

    /// DNS response indicated format error (FORMERR).
    #[error("Server '{server}' returned FORMERR for query '{query}'")]
    FormatError {
        server: String,
        query: String,
    },

    /// DNS response indicated name error (NXDOMAIN).
    #[error("Domain '{domain}' does not exist (NXDOMAIN)")]
    NxDomain {
        domain: String,
    },

    /// Authoritative zone answering failed.
    #[error("Authoritative answer failed for zone '{zone}': {reason}")]
    AuthFailed {
        zone: String,
        reason: String,
    },

    /// EDNS0 option processing error.
    #[error("EDNS0 option processing failed: {reason}")]
    Edns0Failed {
        reason: String,
    },

    /// DNS forwarding loop detected.
    #[error("DNS forwarding loop detected for query '{query}'")]
    LoopDetected {
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
/// ```rust
/// use crate::error::DhcpError;
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
        pool_name: String,
    },

    /// DHCP message parsing failed (malformed packet).
    #[error("Failed to parse DHCP message: {reason}")]
    ParseFailed {
        reason: String,
    },

    /// Invalid DHCP option encoding.
    #[error("Invalid DHCP option {option_code}: {reason}")]
    InvalidOption {
        option_code: u8,
        reason: String,
    },

    /// Lease database operation failed (read/write/update).
    #[error("Lease database operation failed: {operation} - {reason}")]
    LeaseDatabaseFailed {
        operation: String,
        reason: String,
    },

    /// DHCP relay operation failed.
    #[error("DHCP relay failed for relay '{relay}': {reason}")]
    RelayFailed {
        relay: String,
        reason: String,
    },

    /// Address conflict detected (duplicate IP).
    #[error("Address conflict detected for IP '{ip}': already assigned to '{existing_mac}'")]
    AddressConflict {
        ip: String,
        existing_mac: String,
    },

    /// DHCPv6 prefix delegation failed.
    #[error("DHCPv6 prefix delegation failed: {reason}")]
    PrefixDelegationFailed {
        reason: String,
    },

    /// Invalid DHCP client identifier.
    #[error("Invalid client identifier: {reason}")]
    InvalidClientId {
        reason: String,
    },

    /// Helper script execution failed.
    #[error("Helper script '{script}' execution failed: {reason}")]
    ScriptFailed {
        script: String,
        reason: String,
    },

    /// Lease renewal rejected (policy violation).
    #[error("Lease renewal rejected for '{client_id}': {reason}")]
    RenewalRejected {
        client_id: String,
        reason: String,
    },

    /// DHCPv4-specific protocol error.
    #[error("DHCPv4 protocol error: {reason}")]
    V4ProtocolError {
        reason: String,
    },

    /// DHCPv6-specific protocol error.
    #[error("DHCPv6 protocol error: {reason}")]
    V6ProtocolError {
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
/// ```rust
/// use crate::error::DnssecError;
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
    #[error("DNSSEC signature not yet valid until {valid_from:?} (current time: {current_time:?})")]
    NotYetValid {
        valid_from: std::time::SystemTime,
        current_time: std::time::SystemTime,
    },

    /// Signature expired (DNSSEC_FAIL_EXP).
    ///
    /// The RRSIG record's expiration time has passed. The zone needs re-signing.
    #[error("DNSSEC signature expired at {expired_at:?} (current time: {current_time:?})")]
    Expired {
        expired_at: std::time::SystemTime,
        current_time: std::time::SystemTime,
    },

    /// Indeterminate validation result (DNSSEC_FAIL_INDET).
    ///
    /// Validation could not definitively prove the record is secure or insecure.
    /// This may require additional queries or indicate a validation path problem.
    #[error("DNSSEC validation indeterminate for '{name}': {reason}")]
    Indeterminate {
        name: String,
        reason: String,
    },

    /// No supported key algorithm (DNSSEC_FAIL_NOKEYSUP).
    ///
    /// The DNSKEY uses an algorithm not supported by this implementation.
    #[error("No supported DNSSEC key algorithm: {algorithm_id}")]
    NoKeysSupported {
        algorithm_id: u8,
    },

    /// No signatures present (DNSSEC_FAIL_NOSIG).
    ///
    /// DNSSEC validation requested but no RRSIG records found for the record set.
    #[error("No DNSSEC signatures found for '{name}' type {record_type}")]
    NoSignatures {
        name: String,
        record_type: u16,
    },

    /// No DNSSEC zone (DNSSEC_FAIL_NOZONE).
    ///
    /// The zone is unsigned or no delegation signer (DS) records found.
    #[error("No DNSSEC zone found for '{name}'")]
    NoZone {
        name: String,
    },

    /// Non-secure delegation (DNSSEC_FAIL_NONSEC).
    ///
    /// Proven insecure delegation via NSEC/NSEC3 records indicating no DS.
    #[error("Non-secure delegation to '{name}' (proven insecure)")]
    NonSecure {
        name: String,
    },

    /// No DS support (DNSSEC_FAIL_NODSSUP).
    ///
    /// The DS record uses an unsupported digest algorithm.
    #[error("No supported DS digest algorithm: {digest_algorithm_id}")]
    NoDsSupported {
        digest_algorithm_id: u8,
    },

    /// No trusted keys available (DNSSEC_FAIL_NOKEY).
    ///
    /// No trust anchor or trusted DNSKEY found to validate the chain.
    #[error("No trusted DNSSEC keys found for '{name}'")]
    NoKey {
        name: String,
    },

    /// Too many NSEC3 iterations (DNSSEC_FAIL_NSEC3_ITERS).
    ///
    /// NSEC3 iteration count exceeds the configured maximum, indicating a
    /// potential DoS attack or misconfiguration.
    #[error("NSEC3 iteration count {iterations} exceeds maximum {max_iterations}")]
    TooManyIterations {
        iterations: u32,
        max_iterations: u32,
    },

    /// Malformed DNSSEC packet (DNSSEC_FAIL_BADPACKET).
    ///
    /// The DNSSEC-related records are malformed or cannot be parsed.
    #[error("Malformed DNSSEC record in response: {reason}")]
    BadPacket {
        reason: String,
    },

    /// Validation work limit exceeded (DNSSEC_FAIL_WORK).
    ///
    /// The validation process exceeded the maximum allowed work units,
    /// preventing algorithmic complexity attacks.
    #[error("DNSSEC validation work limit exceeded ({work_units} units)")]
    TooMuchWork {
        work_units: u64,
    },

    /// Cryptographic signature verification failed.
    ///
    /// The signature is correctly formatted but cryptographically invalid.
    #[error("Cryptographic signature verification failed for '{name}': {reason}")]
    SignatureVerificationFailed {
        name: String,
        reason: String,
    },

    /// Trust anchor parsing or loading failed.
    #[error("Trust anchor loading failed: {reason}")]
    TrustAnchorFailed {
        reason: String,
    },

    /// Chain of trust validation failed.
    #[error("DNSSEC chain of trust broken at '{name}': {reason}")]
    ChainOfTrustBroken {
        name: String,
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
/// ```rust
/// use crate::error::NetworkError;
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
        address: String,
        reason: String,
    },

    /// Network interface enumeration failed.
    #[error("Interface enumeration failed: {reason}")]
    InterfaceEnumerationFailed {
        reason: String,
    },

    /// Specified interface not found.
    #[error("Interface '{interface}' not found")]
    InterfaceNotFound {
        interface: String,
    },

    /// Interface configuration error.
    #[error("Interface '{interface}' configuration error: {reason}")]
    InterfaceConfigError {
        interface: String,
        reason: String,
    },

    /// Linux netlink operation failed.
    #[error("Netlink operation failed: {operation} - {reason}")]
    NetlinkFailed {
        operation: String,
        reason: String,
    },

    /// BSD BPF (Berkeley Packet Filter) operation failed.
    #[error("BPF operation failed: {operation} - {reason}")]
    BpfFailed {
        operation: String,
        reason: String,
    },

    /// Routing table operation failed.
    #[error("Routing operation failed: {operation} - {reason}")]
    RoutingFailed {
        operation: String,
        reason: String,
    },

    /// IP address parsing or validation error.
    #[error("Invalid IP address '{address}': {reason}")]
    InvalidAddress {
        address: String,
        reason: String,
    },

    /// Port binding error (privilege or conflict).
    #[error("Failed to bind to port {port}: {reason}")]
    PortBindFailed {
        port: u16,
        reason: String,
    },

    /// Socket option configuration failed.
    #[error("Failed to set socket option '{option}': {reason}")]
    SocketOptionFailed {
        option: String,
        reason: String,
    },

    /// Multicast group operation failed.
    #[error("Multicast operation failed on '{interface}' for group '{group}': {reason}")]
    MulticastFailed {
        interface: String,
        group: String,
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
/// ```rust
/// use crate::error::ConfigError;
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
        path: String,
    },

    /// Configuration file parsing error (syntax error).
    #[error("Parse error in '{file_path}' line {line_number}: {reason}")]
    ParseError {
        file_path: String,
        line_number: usize,
        reason: String,
    },

    /// Unknown configuration directive.
    #[error("Unknown directive '{directive}' in '{file_path}' line {line_number}")]
    UnknownDirective {
        directive: String,
        file_path: String,
        line_number: usize,
    },

    /// Invalid directive argument or value.
    #[error("Invalid value for directive '{directive}': {reason}")]
    InvalidValue {
        directive: String,
        reason: String,
    },

    /// Missing required configuration option.
    #[error("Required configuration option '{option}' is missing")]
    MissingRequired {
        option: String,
    },

    /// Conflicting configuration directives.
    #[error("Configuration conflict: {reason}")]
    Conflict {
        reason: String,
    },

    /// Include directive processing failed.
    #[error("Failed to include file '{path}': {reason}")]
    IncludeFailed {
        path: String,
        reason: String,
    },

    /// Configuration validation failed.
    #[error("Configuration validation failed: {reason}")]
    ValidationFailed {
        reason: String,
    },

    /// Invalid IP address or network range.
    #[error("Invalid IP address or range '{value}' for directive '{directive}': {reason}")]
    InvalidIpRange {
        directive: String,
        value: String,
        reason: String,
    },

    /// Invalid port number.
    #[error("Invalid port number '{port}' for directive '{directive}'")]
    InvalidPort {
        directive: String,
        port: String,
    },

    /// Command-line argument parsing error.
    #[error("Command-line argument error: {reason}")]
    CommandLineError {
        reason: String,
    },

    /// Environment variable error.
    #[error("Environment variable '{variable}' error: {reason}")]
    EnvironmentError {
        variable: String,
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
        path: String,
    },

    /// Access violation (permission denied).
    #[error("TFTP access violation for '{path}': {reason}")]
    AccessViolation {
        path: String,
        reason: String,
    },

    /// Disk full or allocation exceeded.
    #[error("TFTP disk full error: {reason}")]
    DiskFull {
        reason: String,
    },

    /// Illegal TFTP operation.
    #[error("TFTP illegal operation: {reason}")]
    IllegalOperation {
        reason: String,
    },

    /// Unknown transfer ID.
    #[error("TFTP unknown transfer ID: {transfer_id}")]
    UnknownTransferId {
        transfer_id: u16,
    },

    /// File already exists (write mode).
    #[error("TFTP file already exists: '{path}'")]
    FileExists {
        path: String,
    },

    /// No such user (TFTP with authentication).
    #[error("TFTP no such user: '{user}'")]
    NoSuchUser {
        user: String,
    },

    /// Transfer timeout.
    #[error("TFTP transfer timeout for '{path}' after {timeout_ms}ms")]
    Timeout {
        path: String,
        timeout_ms: u64,
    },

    /// Unsupported option.
    #[error("TFTP unsupported option: '{option}'")]
    UnsupportedOption {
        option: String,
    },

    /// Block size negotiation failed.
    #[error("TFTP blocksize negotiation failed: requested {requested}, max {max}")]
    BlocksizeNegotiationFailed {
        requested: u16,
        max: u16,
    },

    /// Network error during transfer.
    #[error("TFTP network error: {reason}")]
    NetworkError {
        reason: String,
    },

    /// File I/O error.
    #[error("TFTP file I/O error for '{path}': {reason}")]
    IoError {
        path: String,
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
        script: String,
        reason: String,
    },

    /// Pipe creation failed for IPC (EVENT_PIPE_ERR).
    #[error("Pipe creation failed: {reason}")]
    PipeCreationFailed {
        reason: String,
    },

    /// User lookup or switching failed (EVENT_USER_ERR).
    #[error("User '{user}' not found or cannot switch: {reason}")]
    UserNotFound {
        user: String,
        reason: String,
    },

    /// Linux capability operation failed (EVENT_CAP_ERR).
    #[error("Capability operation failed: {operation} - {reason}")]
    CapabilityError {
        operation: String,
        reason: String,
    },

    /// Logging system initialization failed (EVENT_LOG_ERR).
    #[error("Logging initialization failed: {reason}")]
    LoggingFailed {
        reason: String,
    },

    /// Process fork failed (EVENT_FORK_ERR).
    #[error("Fork failed: {reason}")]
    ForkFailed {
        reason: String,
    },

    /// Lua script execution error (EVENT_LUA_ERR).
    #[error("Lua script error in '{script}': {reason}")]
    LuaScriptError {
        script: String,
        reason: String,
    },

    /// D-Bus integration error.
    #[error("D-Bus error: {operation} - {reason}")]
    DbusError {
        operation: String,
        reason: String,
    },

    /// UBus (OpenWrt) integration error.
    #[error("UBus error: {operation} - {reason}")]
    UbusError {
        operation: String,
        reason: String,
    },

    /// Systemd integration error (socket activation, notify).
    #[error("Systemd integration error: {operation} - {reason}")]
    SystemdError {
        operation: String,
        reason: String,
    },

    /// Inotify file monitoring error.
    #[error("Inotify error for '{path}': {reason}")]
    InotifyError {
        path: String,
        reason: String,
    },

    /// Signal handling setup error.
    #[error("Signal handling setup failed: {reason}")]
    SignalError {
        reason: String,
    },

    /// Privilege dropping failed.
    #[error("Privilege drop failed: {reason}")]
    PrivilegeDropFailed {
        reason: String,
    },

    /// PID file operation failed.
    #[error("PID file operation failed for '{path}': {reason}")]
    PidFileFailed {
        path: String,
        reason: String,
    },

    /// Daemonization failed.
    #[error("Daemonization failed: {reason}")]
    DaemonizationFailed {
        reason: String,
    },

    /// Conntrack (connection tracking) operation failed.
    #[error("Conntrack operation failed: {reason}")]
    ConntrackFailed {
        reason: String,
    },

    /// IPSet (firewall set) operation failed.
    #[error("IPSet operation failed for set '{set_name}': {reason}")]
    IpsetFailed {
        set_name: String,
        reason: String,
    },

    /// NFTables set operation failed.
    #[error("NFTables operation failed for set '{set_name}': {reason}")]
    NftsetFailed {
        set_name: String,
        reason: String,
    },

    /// PF (Packet Filter) tables operation failed.
    #[error("PF tables operation failed for table '{table_name}': {reason}")]
    PfTablesFailed {
        table_name: String,
        reason: String,
    },
}
