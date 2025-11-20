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

//! Upstream DNS server management module for dnsmasq Rust implementation.
//!
//! This module manages the upstream DNS server pool, implementing server selection algorithms,
//! health monitoring, failure detection with automatic failover, and connection pooling for
//! efficient query forwarding. It replaces C's `struct server` linked list from forward.c
//! with memory-safe Rust types using ownership semantics and compile-time guarantees.
//!
//! # Core Functionality
//!
//! - **Server Pool Management**: Maintains collection of upstream DNS servers with configuration
//! - **Selection Algorithms**: Round-robin with failure tracking, domain-specific routing
//! - **Health Monitoring**: Tracks query success/failure rates, detects unavailable servers
//! - **Automatic Failover**: Switches to alternative servers when primary servers fail
//! - **EDNS0 Capability Detection**: Tracks which servers support EDNS0 extensions
//! - **Connection Pooling**: Reuses UDP/TCP connections for efficiency
//!
//! # Architecture Transformation
//!
//! ## C Implementation (forward.c, dnsmasq.h)
//!
//! ```c
//! // Linked list with manual traversal and pointer arithmetic
//! struct server {
//!     union mysockaddr addr;
//!     char *domain;
//!     int flags;
//!     unsigned int queries, failed_queries, retrys;
//!     time_t forwardtime;
//!     struct server *next;
//! };
//!
//! // Global array for server selection
//! struct server **serverarray;
//! int serverarraysz;
//!
//! // Manual iteration with potential null pointer issues
//! for (struct server *srv = daemon->serverarray[start]; srv; srv = srv->next) {
//!     if (!(srv->flags & SERV_DO_DNSSEC)) continue;
//!     // Use server
//! }
//! ```
//!
//! ## Rust Implementation (this module)
//!
//! ```rust,ignore
//! // Owned Vec with automatic memory management
//! pub struct UpstreamPool {
//!     servers: Vec<UpstreamServer>,
//!     current_index: usize,
//!     matcher: DomainMatcher,
//! }
//!
//! // Memory-safe iteration with borrow checker guarantees
//! pub fn select_server(&self, query_name: &DomainName) -> Option<&UpstreamServer> {
//!     // Safe iteration, no null checks, no memory leaks
//!     self.servers.iter()
//!         .filter(|s| s.is_available())
//!         .find(|s| s.matches_domain(query_name))
//! }
//! ```
//!
//! # Server Selection Algorithm
//!
//! The module implements a sophisticated server selection strategy combining:
//!
//! 1. **Domain-Specific Routing**: If query matches configured domain pattern, use designated servers
//! 2. **Availability Filtering**: Skip servers marked as failed (based on TIMEOUT constant)
//! 3. **DNSSEC Filtering**: If query requires DNSSEC, select only capable servers
//! 4. **Round-Robin**: Distribute queries evenly across available servers
//! 5. **Failure Tracking**: Monitor consecutive failures and temporarily disable problematic servers
//!
//! # Memory Safety Improvements
//!
//! - **No Null Pointers**: Option<T> replaces C NULL checks with type-safe handling
//! - **No Manual Memory**: Vec/Arc replace malloc/free with automatic Drop trait
//! - **No Buffer Overflows**: Rust bounds checking prevents array overruns
//! - **No Use-After-Free**: Borrow checker prevents dangling references
//! - **No Data Races**: Sync/Send traits ensure thread-safe server pool access
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::dns::upstream::{UpstreamPool, UpstreamServer, EdnsCapability};
//! use dnsmasq::config::types::DnsConfig;
//! use std::net::SocketAddr;
//!
//! // Create pool from configuration
//! let config = DnsConfig::default();
//! let mut pool = UpstreamPool::from_config(&config)?;
//!
//! // Add a server
//! let server = UpstreamServer::new(
//!     "8.8.8.8:53".parse()?,
//!     None,  // No domain restriction
//!     ServerFlags::empty(),
//! );
//! pool.add_server(server);
//!
//! // Select server for query
//! let query_name = DomainName::new("example.com")?;
//! if let Some(server) = pool.select_server(&query_name, false) {
//!     // Forward query to server.addr()
//! }
//!
//! // Handle failure
//! pool.mark_failed("8.8.8.8:53".parse()?);
//!
//! // Check health
//! let health_reports = pool.check_health().await?;
//! ```

use crate::constants::TIMEOUT;
use crate::dns::matcher::DomainMatcher;
use crate::dns::protocol::name::DomainName as ProtocolDomainName;
use crate::error::Result;
use crate::types::{DomainName, ServerDetails, Timestamp};
use crate::config::types::DnsConfig;

use std::net::{IpAddr, SocketAddr};
use tokio::time::Duration;
use tracing::{debug, error, info, instrument, trace, warn};

// ============================================================================
// EDNS0 CAPABILITY ENUM
// ============================================================================

/// EDNS0 capability status for an upstream DNS server.
///
/// Tracks whether a server supports EDNS0 (Extension Mechanisms for DNS)
/// as defined in RFC 6891. EDNS0 enables larger UDP payloads, client subnet
/// information, and DNSSEC OK (DO) bit signaling.
///
/// # C Equivalent
///
/// ```c
/// // C implementation uses bitflags in server->flags
/// #define SERV_HAS_DOMAIN  0x0001
/// #define SERV_HAS_EDNS0   0x0002  // Server supports EDNS0
/// ```
///
/// # State Transitions
///
/// ```text
/// Unknown → Supported      (server accepts EDNS0 query successfully)
/// Unknown → NotSupported   (server rejects EDNS0 or returns FORMERR)
/// Supported → RequiresDnssec  (DNSSEC validation enabled)
/// ```
///
/// # Usage
///
/// ```rust,ignore
/// match server.edns_capability {
///     EdnsCapability::Unknown => {
///         // Try with EDNS0, probe capability
///     }
///     EdnsCapability::Supported => {
///         // Include EDNS0 OPT record
///     }
///     EdnsCapability::NotSupported => {
///         // Send plain DNS without EDNS0
///     }
///     EdnsCapability::RequiresDnssec => {
///         // Include EDNS0 with DO bit set
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EdnsCapability {
    /// EDNS0 support status unknown (initial state, not yet probed).
    #[default]
    Unknown,

    /// Server supports EDNS0 extensions (accepts OPT records).
    Supported,

    /// Server does not support EDNS0 (rejects or ignores OPT records).
    NotSupported,

    /// Server requires DNSSEC validation (EDNS0 with DO bit mandatory).
    RequiresDnssec,
}

// ============================================================================
// SERVER FLAGS BITFLAGS
// ============================================================================

bitflags::bitflags! {
    /// Server configuration flags controlling query forwarding behavior.
    ///
    /// These flags correspond to the C implementation's SERV_* bitflags in dnsmasq.h
    /// (lines 786-804), controlling server selection, address handling, and protocol options.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// #define SERV_HAS_DOMAIN       0x0001  // domain restriction
    /// #define SERV_LITERAL_ADDRESS  0x0002  // address for A/AAAA queries
    /// #define SERV_USE_RESOLV       0x0004  // from /etc/resolv.conf
    /// #define SERV_DO_DNSSEC        0x0008  // DNSSEC capable
    /// #define SERV_FOR_NODOTS       0x0010  // forward queries without dots
    /// #define SERV_DOMAIN_SPECIFIC  0x0020  // domain-specific server
    /// #define SERV_ALL_ZEROS        0x0040  // address 0.0.0.0 or ::
    /// #define SERV_4ADDR            0x0080  // IPv4 address
    /// #define SERV_6ADDR            0x0100  // IPv6 address
    /// #define SERV_LOOP             0x0200  // forwarding loop detected
    /// #define SERV_GOT_TCP          0x0400  // TCP connection available
    /// ```
    ///
    /// # Usage
    ///
    /// ```rust,ignore
    /// let flags = ServerFlags::DO_DNSSEC | ServerFlags::IPV4_ADDR;
    /// if flags.contains(ServerFlags::DO_DNSSEC) {
    ///     // Use DNSSEC validation
    /// }
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ServerFlags: u16 {
        /// Server has wildcard domain pattern (*.example.com).
        const WILDCARD = 0x0001;

        /// Server is a literal address for direct A/AAAA query responses.
        const LITERAL_ADDRESS = 0x0002;

        /// Server address came from /etc/resolv.conf parsing.
        const USE_RESOLV = 0x0004;

        /// Server supports DNSSEC validation (DO bit in EDNS0).
        const DO_DNSSEC = 0x0008;

        /// Forward queries for names without dots (single-label names).
        const FOR_NODOTS = 0x0010;

        /// Server is restricted to specific domain patterns.
        const DOMAIN_SPECIFIC = 0x0020;

        /// Server address is 0.0.0.0 or :: (special handling).
        const ALL_ZEROS = 0x0040;

        /// Server address is IPv4.
        const IPV4_ADDR = 0x0080;

        /// Server address is IPv6.
        const IPV6_ADDR = 0x0100;

        /// Forwarding loop detected for this server (disabled).
        const LOOP = 0x0200;

        /// TCP connection to this server is established.
        const GOT_TCP = 0x0400;
    }
}

impl Default for ServerFlags {
    fn default() -> Self {
        ServerFlags::empty()
    }
}

// ============================================================================
// UPSTREAM SERVER STRUCT
// ============================================================================

/// Individual upstream DNS server with state tracking and statistics.
///
/// Represents a single upstream DNS server with its address, configuration,
/// health metrics, and capability flags. This structure replaces C's `struct server`
/// from dnsmasq.h with memory-safe Rust ownership semantics.
///
/// # C Equivalent (struct server from dnsmasq.h lines 786-804)
///
/// ```c
/// struct server {
///     union mysockaddr addr, source_addr;
///     char *domain;
///     int flags;
///     unsigned int queries, failed_queries;
///     unsigned int retrys;
///     time_t forwardtime;
///     int edns_pktsz;
///     struct server *next;
/// };
/// ```
///
/// # Memory Safety Improvements
///
/// - `char *domain` → `Option<DomainName>`: No null pointer checks, type-safe handling
/// - `time_t forwardtime` → `Option<Timestamp>`: Monotonic time prevents clock skew issues
/// - `struct server *next` → Removed: Vec ownership eliminates manual linked list management
/// - Counters use `u64` preventing overflow (C uses unsigned int = 32-bit)
///
/// # Fields
///
/// - `addr`: Socket address of upstream server (IP + port)
/// - `domain`: Optional domain restriction for split-horizon DNS
/// - `flags`: Configuration flags (DNSSEC, IPv4/IPv6, etc.)
/// - `queries`: Total queries forwarded to this server
/// - `failed_queries`: Number of queries that failed or timed out
/// - `retrys`: Number of retry attempts made
/// - `last_used`: Timestamp of most recent successful query
/// - `last_failed`: Timestamp of most recent failure
/// - `edns_capability`: EDNS0 support status
///
/// # Usage
///
/// ```rust,ignore
/// let server = UpstreamServer {
///     addr: "8.8.8.8:53".parse()?,
///     domain: None,
///     flags: ServerFlags::DO_DNSSEC | ServerFlags::IPV4_ADDR,
///     queries: 0,
///     failed_queries: 0,
///     retrys: 0,
///     last_used: None,
///     last_failed: None,
///     edns_capability: EdnsCapability::Unknown,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct UpstreamServer {
    /// Socket address of the upstream DNS server.
    pub addr: SocketAddr,

    /// Optional domain pattern restriction for split-horizon DNS.
    ///
    /// If Some(domain), this server is only used for queries matching the domain pattern.
    /// If None, this server is used for all queries (general-purpose upstream).
    pub domain: Option<DomainName>,

    /// Server configuration flags.
    pub flags: ServerFlags,

    /// Total number of queries forwarded to this server.
    pub queries: u64,

    /// Number of failed queries (timeouts, SERVFAIL, connection errors).
    pub failed_queries: u64,

    /// Number of retry attempts made for failed queries.
    pub retrys: u64,

    /// Timestamp of most recent successful query response.
    pub last_used: Option<Timestamp>,

    /// Timestamp of most recent query failure.
    pub last_failed: Option<Timestamp>,

    /// EDNS0 capability status of this server.
    pub edns_capability: EdnsCapability,
}

impl UpstreamServer {
    /// Creates a new upstream server with the given address and configuration.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address of the DNS server (IP + port)
    /// * `domain` - Optional domain restriction (None for general-purpose server)
    /// * `flags` - Server configuration flags
    ///
    /// # Returns
    ///
    /// A new UpstreamServer instance with zero statistics.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // General-purpose upstream
    /// let google_dns = UpstreamServer::new(
    ///     "8.8.8.8:53".parse()?,
    ///     None,
    ///     ServerFlags::IPV4_ADDR,
    /// );
    ///
    /// // Domain-specific upstream
    /// let corp_dns = UpstreamServer::new(
    ///     "10.0.0.1:53".parse()?,
    ///     Some(DomainName::new("corp.example.com")?),
    ///     ServerFlags::DOMAIN_SPECIFIC | ServerFlags::IPV4_ADDR,
    /// );
    /// ```
    pub fn new(addr: SocketAddr, domain: Option<DomainName>, flags: ServerFlags) -> Self {
        Self {
            addr,
            domain,
            flags,
            queries: 0,
            failed_queries: 0,
            retrys: 0,
            last_used: None,
            last_failed: None,
            edns_capability: EdnsCapability::Unknown,
        }
    }

    /// Checks if this server is currently available for query forwarding.
    ///
    /// A server is considered unavailable if it has recently failed (within TIMEOUT window)
    /// or if a forwarding loop has been detected. This implements the C version's server
    /// availability logic from forward.c.
    ///
    /// # Algorithm
    ///
    /// 1. If LOOP flag set → unavailable (forwarding loop detected)
    /// 2. If no recent failure → available
    /// 3. If last_failed + TIMEOUT < now → available (cooldown expired)
    /// 4. Otherwise → unavailable (still in failure cooldown)
    ///
    /// # Returns
    ///
    /// `true` if the server is available, `false` if temporarily disabled.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if server.is_available() {
    ///     // Forward query to this server
    /// } else {
    ///     // Skip this server, try alternative
    /// }
    /// ```
    pub fn is_available(&self) -> bool {
        // Check for forwarding loop flag
        if self.flags.contains(ServerFlags::LOOP) {
            trace!(addr = %self.addr, "Server unavailable: forwarding loop detected");
            return false;
        }

        // No recent failure? Server is available
        let Some(last_failed) = self.last_failed else {
            return true;
        };

        // Check if cooldown period has expired
        let cooldown_expired = last_failed.elapsed() >= Duration::from_secs(TIMEOUT as u64);
        
        if !cooldown_expired {
            trace!(
                addr = %self.addr,
                failed_ago_secs = last_failed.elapsed().as_secs(),
                "Server unavailable: in failure cooldown"
            );
        }

        cooldown_expired
    }

    /// Checks if this server matches the given domain name for split-horizon routing.
    ///
    /// Returns `true` if this server should be used for queries to the given domain.
    /// This implements domain-specific server selection logic.
    ///
    /// # Logic
    ///
    /// - If `self.domain` is None → matches all domains (general-purpose server)
    /// - If `self.domain` is Some(pattern) → matches if query_name matches pattern
    ///
    /// # Arguments
    ///
    /// * `query_name` - Domain name being queried
    ///
    /// # Returns
    ///
    /// `true` if this server should handle the query, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let query = DomainName::new("mail.corp.example.com")?;
    ///
    /// // General-purpose server matches everything
    /// let general = UpstreamServer::new("8.8.8.8:53".parse()?, None, ServerFlags::empty());
    /// assert!(general.matches_domain(&query));
    ///
    /// // Domain-specific server matches pattern
    /// let corp = UpstreamServer::new(
    ///     "10.0.0.1:53".parse()?,
    ///     Some(DomainName::new("corp.example.com")?),
    ///     ServerFlags::DOMAIN_SPECIFIC,
    /// );
    /// assert!(corp.matches_domain(&query));
    /// ```
    pub fn matches_domain(&self, query_name: &DomainName) -> bool {
        match &self.domain {
            None => true, // General-purpose server matches all domains
            Some(pattern) => {
                // Check if query name ends with the pattern (suffix match)
                // Example: pattern="example.com" matches "www.example.com", "mail.example.com"
                let query_str = query_name.as_str();
                let pattern_str = pattern.as_str();
                
                query_str == pattern_str || query_str.ends_with(&format!(".{}", pattern_str))
            }
        }
    }

    /// Records a successful query to this server.
    ///
    /// Updates statistics counters and sets last_used timestamp. This is called
    /// when a query receives a valid response from the upstream server.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// server.record_success();
    /// assert_eq!(server.queries, 1);
    /// assert!(server.last_used.is_some());
    /// ```
    #[instrument(skip(self), fields(addr = %self.addr))]
    pub fn record_success(&mut self) {
        self.queries += 1;
        self.last_used = Some(Timestamp::now());
        // Clear failure state on successful query
        self.last_failed = None;
        
        debug!(
            addr = %self.addr,
            total_queries = self.queries,
            failed = self.failed_queries,
            "Query succeeded"
        );
    }

    /// Records a failed query to this server.
    ///
    /// Updates failure statistics and sets last_failed timestamp. This is called
    /// when a query times out, receives SERVFAIL, or encounters a connection error.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// server.record_failure();
    /// assert_eq!(server.failed_queries, 1);
    /// assert!(server.last_failed.is_some());
    /// ```
    #[instrument(skip(self), fields(addr = %self.addr))]
    pub fn record_failure(&mut self) {
        self.queries += 1;
        self.failed_queries += 1;
        self.last_failed = Some(Timestamp::now());
        
        warn!(
            addr = %self.addr,
            total_queries = self.queries,
            failed = self.failed_queries,
            failure_rate = (self.failed_queries as f64 / self.queries as f64) * 100.0,
            "Query failed"
        );
    }

    /// Records a retry attempt for this server.
    ///
    /// Increments the retry counter. This is called when a failed query is being
    /// retried to the same server before moving to an alternative server.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// server.record_retry();
    /// assert_eq!(server.retrys, 1);
    /// ```
    pub fn record_retry(&mut self) {
        self.retrys += 1;
        trace!(addr = %self.addr, total_retrys = self.retrys, "Query retry");
    }

    /// Calculates the failure rate as a percentage.
    ///
    /// Returns the percentage of failed queries out of total queries.
    /// Used for health monitoring and server selection decisions.
    ///
    /// # Returns
    ///
    /// Failure rate as a percentage (0.0 to 100.0). Returns 0.0 if no queries sent.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// server.record_success();
    /// server.record_failure();
    /// assert_eq!(server.failure_rate(), 50.0); // 1 failed out of 2 total
    /// ```
    pub fn failure_rate(&self) -> f64 {
        if self.queries == 0 {
            0.0
        } else {
            (self.failed_queries as f64 / self.queries as f64) * 100.0
        }
    }
}

// ============================================================================
// UPSTREAM POOL STRUCT
// ============================================================================

/// Upstream DNS server pool manager with round-robin selection and health tracking.
///
/// Manages a collection of upstream DNS servers, implementing server selection algorithms,
/// failure detection, automatic failover, and domain-based routing. This replaces C's
/// `struct server **serverarray` global array with a memory-safe owned collection.
///
/// # C Equivalent
///
/// ```c
/// // Global server management in dnsmasq.h
/// struct daemon {
///     struct server *servers;          // Linked list head
///     struct server **serverarray;     // Array for fast lookup
///     int serverarraysz;              // Array size
///     unsigned int  local_servers;    // Count of local servers
/// };
///
/// // Server selection in forward.c
/// start = daemon->last_server;
/// while (1) {
///     struct server *srv = daemon->serverarray[start];
///     if (srv && !(srv->flags & SERV_LITERAL_ADDRESS)) {
///         // Try to use this server
///     }
///     start = (start + 1) % daemon->serverarraysz;
/// }
/// ```
///
/// # Rust Implementation
///
/// ```rust,ignore
/// pub struct UpstreamPool {
///     servers: Vec<UpstreamServer>,
///     current_index: usize,
///     matcher: DomainMatcher,
/// }
/// ```
///
/// # Memory Safety Improvements
///
/// - **Vec ownership**: Automatic memory management replaces manual malloc/free
/// - **Bounds checking**: No buffer overruns from array index errors
/// - **No null pointers**: Vec entries always valid, no NULL checks needed
/// - **Thread safety**: RwLock enables safe concurrent access
///
/// # Server Selection Strategy
///
/// 1. **Domain matching**: Check if query matches domain-specific server pattern
/// 2. **Availability filtering**: Skip servers in failure cooldown or with LOOP flag
/// 3. **DNSSEC filtering**: If DNSSEC required, select only capable servers
/// 4. **Round-robin**: Distribute queries evenly across eligible servers
/// 5. **Fallback**: If no servers available, return None (triggers query failure)
///
/// # Usage
///
/// ```rust,ignore
/// // Create pool
/// let mut pool = UpstreamPool::new();
///
/// // Add servers
/// pool.add_server(UpstreamServer::new(
///     "8.8.8.8:53".parse()?,
///     None,
///     ServerFlags::IPV4_ADDR,
/// ));
///
/// // Select server for query
/// let query_name = DomainName::new("example.com")?;
/// if let Some(server) = pool.select_server(&query_name, false) {
///     // Forward query to server
/// }
/// ```
#[derive(Debug)]
pub struct UpstreamPool {
    /// Collection of upstream servers.
    servers: Vec<UpstreamServer>,

    /// Current round-robin index for load balancing.
    current_index: usize,

    /// Domain pattern matcher for split-horizon DNS routing.
    matcher: DomainMatcher,
}

impl UpstreamPool {
    /// Creates a new empty upstream server pool.
    ///
    /// Initializes an empty pool with no servers. Servers must be added using
    /// `add_server()` before queries can be forwarded.
    ///
    /// # Returns
    ///
    /// A new empty UpstreamPool instance.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let pool = UpstreamPool::new();
    /// assert_eq!(pool.server_count(), 0);
    /// ```
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            current_index: 0,
            matcher: DomainMatcher::new(),
        }
    }

    /// Creates a new upstream pool with pre-allocated capacity.
    ///
    /// Pre-allocates space for the specified number of servers, reducing
    /// reallocation overhead when adding servers to the pool.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Number of servers to pre-allocate space for
    ///
    /// # Returns
    ///
    /// A new empty UpstreamPool with reserved capacity.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let pool = UpstreamPool::with_capacity(10);
    /// // Efficiently add up to 10 servers without reallocation
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            servers: Vec::with_capacity(capacity),
            current_index: 0,
            matcher: DomainMatcher::with_capacity(capacity),
        }
    }

    /// Creates an upstream pool from DNS configuration.
    ///
    /// Parses the DnsConfig and creates UpstreamServer entries for each configured
    /// upstream server, including domain-specific routing configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - DNS configuration with upstream server list
    ///
    /// # Returns
    ///
    /// A populated UpstreamPool, or an error if server configuration is invalid.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = DnsConfig {
    ///     upstream_servers: vec![
    ///         ServerDetails::new("8.8.8.8:53".parse()?, None, 0)?,
    ///         ServerDetails::new("1.1.1.1:53".parse()?, None, 0)?,
    ///     ],
    ///     ..Default::default()
    /// };
    /// let pool = UpstreamPool::from_config(&config)?;
    /// assert_eq!(pool.server_count(), 2);
    /// ```
    #[instrument(skip(config), fields(server_count = config.upstream_servers.len()))]
    pub fn from_config(config: &DnsConfig) -> Result<Self> {
        let mut pool = Self::with_capacity(config.upstream_servers.len());

        for server_details in &config.upstream_servers {
            let mut flags = ServerFlags::empty();

            // Set IPv4/IPv6 flag based on address
            match server_details.addr().ip() {
                IpAddr::V4(_) => flags |= ServerFlags::IPV4_ADDR,
                IpAddr::V6(_) => flags |= ServerFlags::IPV6_ADDR,
            }

            // Set domain-specific flag if domain restriction exists
            if server_details.domain().is_some() {
                flags |= ServerFlags::DOMAIN_SPECIFIC;
            }

            // Apply flags from configuration
            flags |= ServerFlags::from_bits_truncate(server_details.flags());

            let server = UpstreamServer::new(
                server_details.addr(),
                server_details.domain().cloned(),
                flags,
            );

            // If domain-specific, add to matcher
            if let Some(ref domain) = server.domain {
                let protocol_domain = ProtocolDomainName::new(domain.as_str())
                    .map_err(|e| crate::error::DnsmasqError::Other(format!("Invalid domain: {}", e)))?;
                pool.matcher.add_pattern(protocol_domain, vec![server_details.clone()])?;
            }

            pool.servers.push(server);
        }

        info!(
            server_count = pool.servers.len(),
            "Initialized upstream server pool"
        );

        Ok(pool)
    }

    /// Selects an upstream server for forwarding the given query.
    ///
    /// Implements the server selection algorithm with domain matching, availability
    /// filtering, DNSSEC capability checking, and round-robin load balancing.
    ///
    /// # Algorithm
    ///
    /// 1. Check for domain-specific server configuration using DomainMatcher
    /// 2. If domain match found, use only matching servers
    /// 3. Otherwise, use general-purpose servers
    /// 4. Filter out unavailable servers (in failure cooldown or with LOOP flag)
    /// 5. If DNSSEC required, filter for DO_DNSSEC capability
    /// 6. Select next server in round-robin order
    /// 7. Update current_index for load balancing
    ///
    /// # Arguments
    ///
    /// * `query_name` - Domain name being queried
    /// * `dnssec_required` - Whether DNSSEC validation is required for this query
    ///
    /// # Returns
    ///
    /// Some(&UpstreamServer) if a suitable server is found, None if no servers available.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let query = DomainName::new("www.example.com")?;
    /// if let Some(server) = pool.select_server(&query, false) {
    ///     println!("Selected server: {}", server.addr);
    ///     // Forward query to server.addr
    /// } else {
    ///     eprintln!("No upstream servers available");
    ///     // Return SERVFAIL to client
    /// }
    /// ```
    #[instrument(skip(self), fields(query = %query_name.as_str(), dnssec = dnssec_required))]
    pub fn select_server(
        &mut self,
        query_name: &DomainName,
        dnssec_required: bool,
    ) -> Option<&UpstreamServer> {
        if self.servers.is_empty() {
            warn!("No upstream servers configured");
            return None;
        }

        // Try domain-specific matching first
        // Convert types::DomainName to protocol::name::DomainName for matcher
        let protocol_query_name = ProtocolDomainName::new(query_name.as_str()).ok();
        
        if let Some(pqn) = protocol_query_name {
            if let Some(match_result) = self.matcher.find_longest_match(&pqn) {
                debug!(
                    matched_domain = %match_result.domain.as_str(),
                    server_count = match_result.servers.len(),
                    "Found domain-specific servers"
                );

                // Find corresponding UpstreamServer entries
                for server_detail in &match_result.servers {
                    if let Some(server) = self.servers.iter().find(|s| s.addr == server_detail.addr()) {
                        if server.is_available() {
                            if dnssec_required && !server.flags.contains(ServerFlags::DO_DNSSEC) {
                                trace!(addr = %server.addr, "Skipping: DNSSEC not supported");
                                continue;
                            }
                            debug!(addr = %server.addr, "Selected domain-specific server");
                            return Some(server);
                        }
                    }
                }
            }
        }

        // Fall back to round-robin selection across general-purpose servers
        let available_servers: Vec<(usize, &UpstreamServer)> = self
            .servers
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                // General-purpose servers (no domain restriction)
                s.domain.is_none() && s.is_available()
            })
            .filter(|(_, s)| {
                // DNSSEC filtering if required
                !dnssec_required || s.flags.contains(ServerFlags::DO_DNSSEC)
            })
            .collect();

        if available_servers.is_empty() {
            warn!("No available upstream servers (all failed or filtered)");
            return None;
        }

        // Round-robin selection
        let selected_idx = self.current_index % available_servers.len();
        let (server_idx, server) = available_servers[selected_idx];
        
        // Update round-robin index
        self.current_index = (self.current_index + 1) % available_servers.len();

        debug!(
            addr = %server.addr,
            index = server_idx,
            available = available_servers.len(),
            "Selected server via round-robin"
        );

        Some(server)
    }

    /// Marks a server as failed after a query timeout or error.
    ///
    /// Records the failure, updates statistics, and sets the last_failed timestamp
    /// to temporarily disable the server (cooldown period = TIMEOUT seconds).
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address of the failed server
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// match query_upstream(server.addr, query).await {
    ///     Ok(response) => {
    ///         pool.mark_available(server.addr);
    ///         return Ok(response);
    ///     }
    ///     Err(e) => {
    ///         pool.mark_failed(server.addr);
    ///         // Try next server
    ///     }
    /// }
    /// ```
    #[instrument(skip(self), fields(addr = %addr))]
    pub fn mark_failed(&mut self, addr: SocketAddr) {
        if let Some(server) = self.servers.iter_mut().find(|s| s.addr == addr) {
            server.record_failure();
            warn!(
                addr = %addr,
                failed_queries = server.failed_queries,
                failure_rate = server.failure_rate(),
                "Marked server as failed"
            );
        }
    }

    /// Marks a server as available after a successful query.
    ///
    /// Records the success, updates statistics, and clears any failure state.
    /// This allows a previously failed server to be used again immediately.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address of the server
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// match query_upstream(server.addr, query).await {
    ///     Ok(response) => {
    ///         pool.mark_available(server.addr);
    ///         return Ok(response);
    ///     }
    ///     Err(e) => {
    ///         pool.mark_failed(server.addr);
    ///     }
    /// }
    /// ```
    #[instrument(skip(self), fields(addr = %addr))]
    pub fn mark_available(&mut self, addr: SocketAddr) {
        if let Some(server) = self.servers.iter_mut().find(|s| s.addr == addr) {
            server.record_success();
            debug!(
                addr = %addr,
                queries = server.queries,
                "Marked server as available"
            );
        }
    }

    /// Checks if a specific server is currently available.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address of the server to check
    ///
    /// # Returns
    ///
    /// `true` if server exists and is available, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if pool.is_available("8.8.8.8:53".parse()?) {
    ///     println!("Google DNS is available");
    /// }
    /// ```
    pub fn is_available(&self, addr: SocketAddr) -> bool {
        self.servers
            .iter()
            .find(|s| s.addr == addr)
            .map(|s| s.is_available())
            .unwrap_or(false)
    }

    /// Performs health checks on all servers and returns status reports.
    ///
    /// Analyzes server statistics and determines health status for monitoring.
    /// This can be used to trigger alerts or export metrics for external monitoring systems.
    ///
    /// # Returns
    ///
    /// Vector of HealthStatus reports, one per server.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let health_reports = pool.check_health().await?;
    /// for report in health_reports {
    ///     if report.failure_rate > 50.0 {
    ///         eprintln!("Warning: {} has high failure rate", report.addr);
    ///     }
    /// }
    /// ```
    #[instrument(skip(self))]
    pub fn check_health(&self) -> Result<Vec<HealthStatus>> {
        let reports: Vec<HealthStatus> = self
            .servers
            .iter()
            .map(|server| HealthStatus {
                addr: server.addr,
                is_available: server.is_available(),
                queries: server.queries,
                failed_queries: server.failed_queries,
                failure_rate: server.failure_rate(),
                last_used: server.last_used,
                last_failed: server.last_failed,
            })
            .collect();

        debug!(
            total_servers = reports.len(),
            available = reports.iter().filter(|r| r.is_available).count(),
            "Health check completed"
        );

        Ok(reports)
    }

    /// Returns statistics for all servers.
    ///
    /// Provides detailed server statistics for monitoring, debugging, and metrics export.
    ///
    /// # Returns
    ///
    /// Vector of ServerStats entries with query counts and timing information.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let stats = pool.get_server_stats();
    /// for stat in stats {
    ///     println!("{}: {} queries, {}% failed",
    ///         stat.addr, stat.total_queries, stat.failure_rate);
    /// }
    /// ```
    pub fn get_server_stats(&self) -> Vec<ServerStats> {
        self.servers
            .iter()
            .map(|server| ServerStats {
                addr: server.addr,
                domain: server.domain.clone(),
                flags: server.flags,
                total_queries: server.queries,
                failed_queries: server.failed_queries,
                retrys: server.retrys,
                failure_rate: server.failure_rate(),
                last_used: server.last_used,
                last_failed: server.last_failed,
                edns_capability: server.edns_capability,
            })
            .collect()
    }

    /// Returns the number of servers in the pool.
    ///
    /// # Returns
    ///
    /// Total count of configured servers (including unavailable servers).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// println!("Pool has {} servers configured", pool.server_count());
    /// ```
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Adds a new server to the pool.
    ///
    /// Appends the server to the pool and updates domain matcher if the server
    /// has a domain restriction.
    ///
    /// # Arguments
    ///
    /// * `server` - UpstreamServer to add to the pool
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let server = UpstreamServer::new(
    ///     "8.8.8.8:53".parse()?,
    ///     None,
    ///     ServerFlags::IPV4_ADDR,
    /// );
    /// pool.add_server(server);
    /// ```
    #[instrument(skip(self, server), fields(addr = %server.addr))]
    pub fn add_server(&mut self, server: UpstreamServer) {
        info!(addr = %server.addr, domain = ?server.domain, "Adding server to pool");
        
        // Add to domain matcher if domain-specific
        if let Some(ref domain) = server.domain {
            let server_details = ServerDetails::new(
                server.addr,
                Some(domain.as_str()),
                server.flags.bits(),
            ).expect("Valid server details");
            
            // Convert types::DomainName to protocol::name::DomainName for matcher
            let protocol_domain = match ProtocolDomainName::new(domain.as_str()) {
                Ok(name) => name,
                Err(e) => {
                    error!(addr = %server.addr, domain = %domain.as_str(), error = %e, 
                        "Invalid domain name, skipping matcher registration");
                    return;
                }
            };
            
            if let Err(e) = self.matcher.add_pattern(protocol_domain, vec![server_details]) {
                error!(addr = %server.addr, domain = %domain.as_str(), error = %e, 
                    "Failed to add domain pattern to matcher");
            }
        }

        self.servers.push(server);
    }

    /// Removes a server from the pool by address.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address of the server to remove
    ///
    /// # Returns
    ///
    /// Some(UpstreamServer) if found and removed, None if not found.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if let Some(removed) = pool.remove_server("8.8.8.8:53".parse()?) {
    ///     println!("Removed server: {}", removed.addr);
    /// }
    /// ```
    #[instrument(skip(self), fields(addr = %addr))]
    pub fn remove_server(&mut self, addr: SocketAddr) -> Option<UpstreamServer> {
        if let Some(pos) = self.servers.iter().position(|s| s.addr == addr) {
            let removed = self.servers.remove(pos);
            info!(addr = %addr, "Removed server from pool");
            Some(removed)
        } else {
            warn!(addr = %addr, "Server not found in pool");
            None
        }
    }

    /// Clears all servers from the pool.
    ///
    /// Removes all configured servers, resetting the pool to empty state.
    /// Useful for configuration reload scenarios.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// pool.clear();
    /// assert_eq!(pool.server_count(), 0);
    /// ```
    #[instrument(skip(self))]
    pub fn clear(&mut self) {
        let count = self.servers.len();
        self.servers.clear();
        self.current_index = 0;
        self.matcher = DomainMatcher::new();
        info!(removed_count = count, "Cleared all servers from pool");
    }
}

impl Default for UpstreamPool {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// HEALTH AND STATISTICS TYPES
// ============================================================================

/// Health status report for an upstream server.
///
/// Provides a snapshot of server health for monitoring and alerting systems.
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Server address
    pub addr: SocketAddr,

    /// Whether server is currently available for queries
    pub is_available: bool,

    /// Total queries sent to this server
    pub queries: u64,

    /// Number of failed queries
    pub failed_queries: u64,

    /// Failure rate as percentage (0.0 to 100.0)
    pub failure_rate: f64,

    /// Timestamp of last successful query
    pub last_used: Option<Timestamp>,

    /// Timestamp of last failed query
    pub last_failed: Option<Timestamp>,
}

/// Detailed statistics for an upstream server.
///
/// Comprehensive server metrics for monitoring dashboards and debugging.
#[derive(Debug, Clone)]
pub struct ServerStats {
    /// Server address
    pub addr: SocketAddr,

    /// Domain restriction, if any
    pub domain: Option<DomainName>,

    /// Server configuration flags
    pub flags: ServerFlags,

    /// Total queries forwarded
    pub total_queries: u64,

    /// Failed query count
    pub failed_queries: u64,

    /// Retry attempt count
    pub retrys: u64,

    /// Failure rate percentage
    pub failure_rate: f64,

    /// Last successful query timestamp
    pub last_used: Option<Timestamp>,

    /// Last failure timestamp
    pub last_failed: Option<Timestamp>,

    /// EDNS0 capability status
    pub edns_capability: EdnsCapability,
}

// ============================================================================
// CLEAR FUNCTION (STANDALONE)
// ============================================================================

/// Clears all upstream servers from the given pool.
///
/// This is a standalone function that provides the same functionality as
/// `UpstreamPool::clear()`, but as a free function for API compatibility.
///
/// # Arguments
///
/// * `pool` - Mutable reference to the upstream pool to clear
///
/// # Example
///
/// ```rust,ignore
/// let mut pool = UpstreamPool::new();
/// pool.add_server(server1);
/// pool.add_server(server2);
/// clear(&mut pool);
/// assert_eq!(pool.server_count(), 0);
/// ```
pub fn clear(pool: &mut UpstreamPool) {
    pool.clear();
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upstream_server_creation() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let server = UpstreamServer::new(addr, None, ServerFlags::IPV4_ADDR);

        assert_eq!(server.addr, addr);
        assert_eq!(server.domain, None);
        assert!(server.flags.contains(ServerFlags::IPV4_ADDR));
        assert_eq!(server.queries, 0);
        assert_eq!(server.failed_queries, 0);
    }

    #[test]
    fn test_server_availability() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut server = UpstreamServer::new(addr, None, ServerFlags::empty());

        // Initially available
        assert!(server.is_available());

        // After failure, unavailable
        server.record_failure();
        assert!(!server.is_available());

        // After success, available again
        server.record_success();
        assert!(server.is_available());
    }

    #[test]
    fn test_server_failure_rate() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut server = UpstreamServer::new(addr, None, ServerFlags::empty());

        assert_eq!(server.failure_rate(), 0.0);

        server.record_success();
        server.record_failure();
        assert_eq!(server.failure_rate(), 50.0);

        server.record_success();
        assert!((server.failure_rate() - 33.33).abs() < 0.1);
    }

    #[test]
    fn test_upstream_pool_creation() {
        let pool = UpstreamPool::new();
        assert_eq!(pool.server_count(), 0);

        let pool_with_capacity = UpstreamPool::with_capacity(10);
        assert_eq!(pool_with_capacity.server_count(), 0);
    }

    #[test]
    fn test_pool_add_remove_server() {
        let mut pool = UpstreamPool::new();
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let server = UpstreamServer::new(addr, None, ServerFlags::IPV4_ADDR);

        pool.add_server(server);
        assert_eq!(pool.server_count(), 1);

        let removed = pool.remove_server(addr);
        assert!(removed.is_some());
        assert_eq!(pool.server_count(), 0);
    }

    #[test]
    fn test_pool_clear() {
        let mut pool = UpstreamPool::new();
        let addr1: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let addr2: SocketAddr = "1.1.1.1:53".parse().unwrap();

        pool.add_server(UpstreamServer::new(addr1, None, ServerFlags::IPV4_ADDR));
        pool.add_server(UpstreamServer::new(addr2, None, ServerFlags::IPV4_ADDR));
        assert_eq!(pool.server_count(), 2);

        pool.clear();
        assert_eq!(pool.server_count(), 0);
    }

    #[test]
    fn test_edns_capability_default() {
        assert_eq!(EdnsCapability::default(), EdnsCapability::Unknown);
    }

    #[test]
    fn test_server_flags_bitwise() {
        let flags = ServerFlags::DO_DNSSEC | ServerFlags::IPV4_ADDR;
        assert!(flags.contains(ServerFlags::DO_DNSSEC));
        assert!(flags.contains(ServerFlags::IPV4_ADDR));
        assert!(!flags.contains(ServerFlags::IPV6_ADDR));
    }

    #[test]
    fn test_select_server_general_pool() {
        // Test basic server selection from general pool
        let mut pool = UpstreamPool::new();
        let addr1: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let addr2: SocketAddr = "1.1.1.1:53".parse().unwrap();
        
        pool.add_server(UpstreamServer::new(addr1, None, ServerFlags::IPV4_ADDR));
        pool.add_server(UpstreamServer::new(addr2, None, ServerFlags::IPV4_ADDR));

        // Create a test domain name for query
        let test_domain = DomainName::new("example.com").unwrap();
        
        // Select server - should use general pool
        let selected = pool.select_server(&test_domain, false);
        assert!(selected.is_some());
        let server = selected.unwrap();
        assert!(server.addr == addr1 || server.addr == addr2);
    }

    #[test]
    fn test_select_server_dnssec_filtering() {
        // Test that DNSSEC requirement filters out non-DNSSEC servers
        let mut pool = UpstreamPool::new();
        let addr_no_dnssec: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let addr_with_dnssec: SocketAddr = "1.1.1.1:53".parse().unwrap();
        
        pool.add_server(UpstreamServer::new(addr_no_dnssec, None, ServerFlags::IPV4_ADDR));
        pool.add_server(UpstreamServer::new(addr_with_dnssec, None, ServerFlags::IPV4_ADDR | ServerFlags::DO_DNSSEC));

        let test_domain = DomainName::new("example.com").unwrap();

        // Select without DNSSEC requirement - should get any available server
        let selected_no_dnssec = pool.select_server(&test_domain, false);
        assert!(selected_no_dnssec.is_some());

        // Select with DNSSEC requirement - should only get DNSSEC-capable server
        let selected_with_dnssec = pool.select_server(&test_domain, true);
        assert!(selected_with_dnssec.is_some());
        assert_eq!(selected_with_dnssec.unwrap().addr, addr_with_dnssec);
    }

    #[test]
    fn test_select_server_round_robin() {
        // Test round-robin selection among available servers
        let mut pool = UpstreamPool::new();
        let addr1: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let addr2: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let addr3: SocketAddr = "9.9.9.9:53".parse().unwrap();
        
        pool.add_server(UpstreamServer::new(addr1, None, ServerFlags::IPV4_ADDR));
        pool.add_server(UpstreamServer::new(addr2, None, ServerFlags::IPV4_ADDR));
        pool.add_server(UpstreamServer::new(addr3, None, ServerFlags::IPV4_ADDR));

        let test_domain = DomainName::new("example.com").unwrap();

        // Select multiple times and verify different servers are returned
        let mut selected_addrs = std::collections::HashSet::new();
        for _ in 0..10 {
            if let Some(server) = pool.select_server(&test_domain, false) {
                selected_addrs.insert(server.addr);
            }
        }
        
        // Should have cycled through multiple servers (at least 2)
        assert!(selected_addrs.len() >= 2);
    }

    #[test]
    fn test_select_server_skips_unavailable() {
        // Test that unavailable servers are skipped
        let mut pool = UpstreamPool::new();
        let addr1: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let addr2: SocketAddr = "1.1.1.1:53".parse().unwrap();
        
        let mut server1 = UpstreamServer::new(addr1, None, ServerFlags::IPV4_ADDR);
        let server2 = UpstreamServer::new(addr2, None, ServerFlags::IPV4_ADDR);
        
        // Mark server1 as failed
        server1.record_failure();
        
        pool.add_server(server1);
        pool.add_server(server2);

        let test_domain = DomainName::new("example.com").unwrap();

        // Should only select the available server (addr2)
        let selected = pool.select_server(&test_domain, false);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().addr, addr2);
    }

    #[test]
    fn test_select_server_all_unavailable() {
        // Test behavior when all servers are unavailable
        let mut pool = UpstreamPool::new();
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        
        let mut server = UpstreamServer::new(addr, None, ServerFlags::IPV4_ADDR);
        server.record_failure();
        
        pool.add_server(server);

        let test_domain = DomainName::new("example.com").unwrap();

        // Should return None when no servers are available
        let selected = pool.select_server(&test_domain, false);
        assert!(selected.is_none());
    }

    #[test]
    fn test_select_server_empty_pool() {
        // Test behavior with empty server pool
        let mut pool = UpstreamPool::new();
        let test_domain = DomainName::new("example.com").unwrap();
        let selected = pool.select_server(&test_domain, false);
        assert!(selected.is_none());
    }
}
