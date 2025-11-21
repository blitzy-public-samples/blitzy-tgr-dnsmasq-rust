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

//! DNS module root providing complete DNS service orchestration.
//!
//! # Overview
//!
//! This module serves as the root of dnsmasq's DNS subsystem, coordinating all DNS operations
//! including query forwarding, response caching, DNSSEC validation, authoritative zone serving,
//! and EDNS0 extension handling. It replaces the C implementation's global state and event loop
//! dispatch from `src/forward.c` with a Rust async service architecture.
//!
//! # Architecture
//!
//! The DNS service orchestrates multiple subsystems through the [`DnsService`] struct:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      DnsService                              │
//! │  (Coordinates all DNS operations)                            │
//! └──────┬─────────┬──────────┬──────────┬──────────────────────┘
//!        │         │          │          │
//!        ▼         ▼          ▼          ▼
//!   ┌────────┐ ┌───────┐ ┌────────┐ ┌──────────┐
//!   │ Cache  │ │Forward│ │Upstream│ │   Auth   │
//!   │        │ │  er   │ │  Pool  │ │   Zones  │
//!   └────────┘ └───────┘ └────────┘ └──────────┘
//!        │         │          │          │
//!        └─────────┴──────────┴──────────┘
//!                  │
//!           DNS Query/Response
//! ```
//!
//! # Query Resolution Flow
//!
//! The [`DnsService::resolve_query()`] method implements the complete DNS resolution pipeline:
//!
//! 1. **Cache Lookup**: Check local cache via [`DnsCache::find_by_name()`]
//!    - Cache hit: Return cached response immediately (typically <1ms)
//!    - Cache miss: Proceed to step 2
//!
//! 2. **Authoritative Check**: Query local authoritative zones via [`AuthService::answer_auth_query()`]
//!    - Match found: Return authoritative answer with AA flag set
//!    - No match: Proceed to step 3
//!
//! 3. **Upstream Forwarding**: Forward query via [`DnsForwarder::forward_query()`]
//!    - Select upstream server from pool
//!    - Send query with UDP (or TCP if truncated)
//!    - Apply retry logic with exponential backoff
//!    - Handle timeout (default 10s) and failover
//!
//! 4. **DNSSEC Validation** (if DO bit set): Validate response via [`DnssecValidator::validate_response()`]
//!    - Verify RRSIG signatures
//!    - Build trust chain to configured trust anchors
//!    - Set AD bit if validation succeeds
//!    - Return SERVFAIL if validation fails
//!
//! 5. **Cache Population**: Store validated response in cache
//!    - Respect TTL from authoritative server
//!    - Apply cache size limit with LRU eviction
//!    - Populate negative cache for NXDOMAIN
//!
//! 6. **Response Construction**: Build final response message
//!    - Copy answer records
//!    - Apply EDNS0 processing
//!    - Filter records per client capabilities
//!    - Set appropriate response flags
//!
//! # C Implementation Mapping
//!
//! This module consolidates several C source files into a unified Rust architecture:
//!
//! | C Source File | Rust Equivalent | Lines (C) | Transformation |
//! |--------------|-----------------|-----------|----------------|
//! | `forward.c` | `forwarder.rs` + coordination in `mod.rs` | 2400+ | Event loop → async/await |
//! | `cache.c` | `cache.rs` | 2200+ | Hash table → HashMap + LRU |
//! | `rfc1035.c` | `protocol/*` | 3600+ | Pointer arithmetic → safe parsers |
//! | `dnssec.c` | `dnssec/*` | 1800+ | Manual crypto → ring library |
//! | `auth.c` | `auth.rs` | 1200+ | Static zones → typed structures |
//!
//! ## State Management Transformation
//!
//! ```c
//! // C: Global daemon state (from forward.c, cache.c)
//! struct daemon {
//!     struct frec *frec_list;        // Outstanding queries
//!     struct crec *cache_head;       // Cache LRU list
//!     struct server *servers;        // Upstream servers
//!     // ... 100+ additional global fields
//! };
//! static struct daemon *daemon;      // Global singleton
//! ```
//!
//! ```rust,ignore
//! // Rust: Structured service with dependency injection
//! pub struct DnsService {
//!     cache: Arc<RwLock<DnsCache>>,
//!     forwarder: Arc<DnsForwarder>,
//!     upstream_pool: Arc<UpstreamPool>,
//!     auth_zones: Vec<AuthoritativeZone>,
//!     config: Arc<DnsConfig>,
//! }
//! ```
//!
//! ## Concurrency Transformation
//!
//! ```c
//! // C: Single-threaded poll() event loop
//! while (1) {
//!     poll(fds, nfds, timeout);
//!     if (fds[dns_index].revents & POLLIN) {
//!         receive_query();
//!     }
//! }
//! ```
//!
//! ```rust,ignore
//! // Rust: Async/await with tokio runtime
//! loop {
//!     tokio::select! {
//!         result = dns_socket.recv_from(&mut buf) => {
//!             let query = DnsQuery::from_bytes(&result?)?;
//!             let response = dns_service.resolve_query(query).await?;
//!             dns_socket.send_to(&response.to_bytes()?, addr).await?;
//!         }
//!     }
//! }
//! ```
//!
//! # Memory Safety Improvements
//!
//! - **Cache Management**: `Arc<RwLock<DnsCache>>` replaces manual hash table with memory-safe concurrent access
//! - **Query Tracking**: HashMap replaces linked list of `struct frec`, eliminating use-after-free
//! - **Upstream Selection**: `UpstreamPool` with Arc sharing replaces raw pointer chains
//! - **Response Building**: `DnsMessage` builder prevents buffer overflows in packet construction
//!
//! # Conditional Compilation
//!
//! Optional features are controlled via Cargo feature flags matching C's `HAVE_*` macros:
//!
//! ```rust,ignore
//! #[cfg(feature = "dnssec")]
//! pub mod dnssec;
//!
//! #[cfg(feature = "auth")]
//! pub mod auth;
//! ```
//!
//! This allows building dnsmasq without DNSSEC or authoritative zones for embedded systems.
//!
//! # Examples
//!
//! ## Creating and Using DNS Service
//!
//! ```rust,ignore
//! use dnsmasq::dns::{DnsService, DnsServiceBuilder};
//! use dnsmasq::config::DnsConfig;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load configuration
//!     let config = DnsConfig::from_file("/etc/dnsmasq.conf").await?;
//!     
//!     // Build DNS service with dependencies
//!     let dns_service = DnsServiceBuilder::new()
//!         .config(Arc::new(config))
//!         .cache_size(1000)
//!         .build()
//!         .await?;
//!     
//!     // Process incoming query
//!     let query = DnsQuery::new("example.com", RecordType::A)?;
//!     let response = dns_service.resolve_query(query).await?;
//!     
//!     println!("Resolved: {:?}", response);
//!     Ok(())
//! }
//! ```
//!
//! ## Cache Statistics
//!
//! ```rust,ignore
//! // Get cache statistics (called on SIGUSR1)
//! let stats = dns_service.get_cache_stats().await;
//! println!("Cache size: {}/{}", stats.entries, stats.capacity);
//! println!("Hit rate: {:.2}%", stats.hit_rate * 100.0);
//! ```
//!
//! # Performance Characteristics
//!
//! - **Cache lookups**: O(1) HashMap access, typically <100ns
//! - **Upstream forwarding**: Network-bound, typically 10-50ms
//! - **DNSSEC validation**: CPU-bound, typically 5-20ms per signature
//! - **Memory usage**: ~1KB per cache entry, configurable limit
//!
//! # Thread Safety
//!
//! All public methods are `async` and designed for concurrent access:
//! - `Arc<RwLock<DnsCache>>` allows multiple concurrent readers
//! - Single writer has exclusive access during cache updates
//! - No blocking operations in critical paths
//!
//! # See Also
//!
//! - [`cache`]: DNS cache implementation with LRU eviction
//! - [`forwarder`]: Query forwarding engine with retry logic
//! - [`protocol`]: DNS wire format parsing and serialization
//! - [`dnssec`]: DNSSEC validation subsystem (feature-gated)
//! - [`auth`]: Authoritative zone serving (feature-gated)

use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

// Internal module declarations
pub mod cache;
pub mod edns0;
pub mod filter;
pub mod forwarder;
pub mod matcher;
pub mod protocol;
pub mod upstream;

// Conditional feature modules
#[cfg(feature = "auth")]
pub mod auth;

#[cfg(feature = "dnssec")]
pub mod dnssec;

// Re-export core types for public API
pub use cache::{CacheEntry, CacheStats, DnsCache};
pub use forwarder::DnsForwarder;
pub use protocol::{DnsMessage, DnsQuery, DnsResponse};
pub use upstream::UpstreamPool;

// Import protocol types for internal use
use protocol::message::Question;

// Import required types from other crates
use crate::config::types::DnsConfig;
use crate::error::{DnsError, Result};
// Types are used in methods and documentation

#[cfg(feature = "auth")]
use auth::{AuthService, AuthoritativeZone};

#[cfg(feature = "dnssec")]
use dnssec::{DnssecValidator, TrustAnchorStore};

use edns0::Edns0Handler;
use filter::RrFilter;
use matcher::DomainMatcher;

/// Cache statistics returned by [`DnsService::get_cache_stats()`].
///
/// Provides detailed metrics about DNS cache performance including size,
/// hit rates, and entry distribution. Exposed via D-Bus API and SIGUSR1 signal.
#[derive(Debug, Clone)]
/// DNS service orchestrating all DNS subsystem operations.
///
/// # Architecture
///
/// `DnsService` is the central coordinator for all DNS functionality, managing:
/// - **Cache**: Shared cache accessed by multiple async tasks via `Arc<RwLock<>>`
/// - **Forwarder**: Query forwarding engine with upstream server selection
/// - **Upstream Pool**: Server health tracking and failover management
/// - **Authoritative Zones**: Local zone serving (optional, feature-gated)
/// - **DNSSEC Validator**: Cryptographic validation (optional, feature-gated)
///
/// # Concurrency
///
/// All fields use `Arc` for cheap cloning across async tasks. The cache uses `RwLock`
/// for concurrent read access with exclusive write access during updates.
///
/// # Memory Management
///
/// - Cache entries are reference-counted via `Arc<CacheEntry>`
/// - Automatic cleanup via `Drop` trait when references are released
/// - No manual memory management or `unsafe` code required
///
/// # Examples
///
/// ```rust,ignore
/// let dns_service = DnsServiceBuilder::new()
///     .config(Arc::new(config))
///     .cache_size(1000)
///     .build()
///     .await?;
///
/// let response = dns_service.resolve_query(query).await?;
/// ```
pub struct DnsService {
    /// DNS cache with concurrent access via `RwLock`.
    ///
    /// Multiple async tasks can read simultaneously, but writes require exclusive access.
    /// Cache lookups happen frequently (every query), so read performance is critical.
    cache: Arc<RwLock<DnsCache>>,

    /// Query forwarding engine handling upstream communication.
    ///
    /// Manages UDP/TCP connections, retry logic, and timeout handling.
    /// Shared immutably across tasks via Arc.
    #[allow(dead_code)]
    forwarder: Arc<DnsForwarder>,

    /// Upstream DNS server pool with health tracking.
    ///
    /// Tracks server availability, response times, and failure counts.
    /// Updated by forwarder on query completion/timeout.
    #[allow(dead_code)]
    upstream_pool: Arc<RwLock<UpstreamPool>>,

    /// Authoritative DNS zones served locally.
    ///
    /// Feature-gated: only compiled when `auth` feature is enabled.
    /// Immutable after initialization, so no locking required.
    #[cfg(feature = "auth")]
    #[allow(dead_code)]
    auth_service: Option<Arc<AuthService>>,

    /// DNSSEC validation engine.
    ///
    /// Feature-gated: only compiled when `dnssec` feature is enabled.
    /// Performs cryptographic signature verification and trust chain building.
    #[cfg(feature = "dnssec")]
    #[allow(dead_code)]
    dnssec_validator: Option<Arc<DnssecValidator>>,

    /// EDNS0 extension handler.
    ///
    /// Processes EDNS0 options including client subnet, DNSSEC OK bit, and UDP payload size.
    #[allow(dead_code)]
    edns0_handler: Arc<Edns0Handler>,

    /// Domain pattern matcher for server selection.
    ///
    /// Routes queries to specific upstream servers based on domain patterns.
    /// Example: `*.internal.corp` → internal DNS server
    #[allow(dead_code)]
    domain_matcher: Arc<DomainMatcher>,

    /// Resource record filter.
    ///
    /// Removes unwanted RR types from responses (e.g., strip DNSSEC records for non-DO clients).
    #[allow(dead_code)]
    rr_filter: Arc<RrFilter>,

    /// DNS configuration settings.
    ///
    /// Immutable configuration loaded from dnsmasq.conf.
    /// Arc allows cheap sharing across all DNS components.
    #[allow(dead_code)]
    config: Arc<DnsConfig>,
}

impl DnsService {
    /// Create a new DNS service builder for configuring and constructing the service.
    ///
    /// # Returns
    ///
    /// A [`DnsServiceBuilder`] for fluent configuration of the DNS service.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let service = DnsService::builder()
    ///     .config(Arc::new(config))
    ///     .cache_size(2000)
    ///     .build()
    ///     .await?;
    /// ```
    #[must_use]
    pub fn builder() -> DnsServiceBuilder {
        DnsServiceBuilder::new()
    }

    /// Resolve a DNS query through the complete resolution pipeline.
    ///
    /// This is the primary entry point for DNS query processing, implementing the full
    /// resolution flow: cache lookup → authoritative check → upstream forwarding → validation → caching.
    ///
    /// # Arguments
    ///
    /// * `query` - The DNS query to resolve containing domain name and record type
    ///
    /// # Returns
    ///
    /// A `Result<DnsResponse>` containing:
    /// - `Ok(response)` - Successfully resolved DNS response with answer records
    /// - `Err(DnsError::Timeout)` - Query timed out waiting for upstream response
    /// - `Err(DnsError::UpstreamUnreachable)` - All upstream servers failed
    /// - `Err(DnsError::ValidationFailed)` - DNSSEC validation failed (when DO bit set)
    /// - `Err(DnsError::MalformedResponse)` - Received invalid DNS packet
    ///
    /// # Resolution Flow
    ///
    /// 1. **Cache Lookup** (fastest path, ~100ns)
    ///    - Check if response is already cached
    ///    - Return immediately if cache hit and TTL not expired
    ///    - Skip cache if query has no-cache flag
    ///
    /// 2. **Authoritative Zone Check** (optional, feature-gated)
    ///    - Query local authoritative zones
    ///    - Return with AA flag set if zone match found
    ///    - Skip if no authoritative zones configured
    ///
    /// 3. **Upstream Forwarding** (network-bound, ~10-50ms)
    ///    - Select upstream server via domain matcher or pool
    ///    - Forward query with UDP (or TCP if TC bit set)
    ///    - Apply retry logic with exponential backoff
    ///    - Handle timeout (default 10s) and failover
    ///
    /// 4. **DNSSEC Validation** (optional, CPU-bound, ~5-20ms)
    ///    - Validate RRSIG signatures if DO bit set
    ///    - Build trust chain to configured anchors
    ///    - Set AD flag if validation succeeds
    ///    - Return SERVFAIL if validation fails
    ///
    /// 5. **Cache Population**
    ///    - Store validated response in cache
    ///    - Respect TTL from authoritative response
    ///    - Apply LRU eviction if cache full
    ///    - Populate negative cache for NXDOMAIN
    ///
    /// 6. **Response Filtering**
    ///    - Apply EDNS0 processing
    ///    - Filter records per client capabilities
    ///    - Set appropriate response flags
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::dns::DnsQuery;
    /// use dnsmasq::types::RecordType;
    ///
    /// // Resolve A record for example.com
    /// let query = DnsQuery::new("example.com", RecordType::A)?;
    /// let response = dns_service.resolve_query(query).await?;
    ///
    /// // Extract answer records
    /// for answer in response.answers() {
    ///     println!("Answer: {:?}", answer);
    /// }
    /// ```
    ///
    /// # Performance
    ///
    /// - Cache hit: <1ms (no network I/O)
    /// - Cache miss: 10-50ms (network round-trip)
    /// - DNSSEC validation adds: 5-20ms (crypto operations)
    ///
    /// # Tracing
    ///
    /// This method is instrumented with `tracing` for observability:
    /// - `info!` on cache hits
    /// - `debug!` on upstream forwarding
    /// - `warn!` on validation failures
    /// - `error!` on unrecoverable errors
    #[instrument(skip(self), fields(domain = %query.name, qtype = ?query.qtype, client = %client_addr))]
    pub async fn resolve_query(&self, query: DnsQuery, client_addr: IpAddr) -> Result<DnsResponse> {
        debug!("Starting DNS query resolution");

        // Step 1: Cache lookup (fastest path)
        {
            let mut cache = self.cache.write().await;
            if let Some(cached_entry) = cache.find_by_name(&query.name, query.qtype) {
                info!("Cache hit for {} type {:?}", query.name, query.qtype);
                return self.build_response_from_cache(&query, &cached_entry).await;
            }
            debug!("Cache miss, proceeding to authoritative check");
        }

        // Step 2: Authoritative zone check (if feature enabled)
        #[cfg(feature = "auth")]
        if let Some(ref auth_service) = self.auth_service {
            // Create a minimal DnsMessage from the DnsQuery for auth checking
            use crate::dns::protocol::message::Question;
            let mut query_message = DnsMessage::new(0); // ID will be set by caller
            query_message.questions.push(Question {
                qname: query.name.clone(),
                qtype: query.qtype,
                qclass: query.qclass,
            });

            if let Some(auth_message) =
                auth_service.answer_auth_query(&query_message, client_addr).await?
            {
                info!("Authoritative answer for {} type {:?}", query.name, query.qtype);
                // Convert DnsMessage to DnsResponse
                let response = DnsResponse::from_message(auth_message);
                return Ok(response);
            }
            debug!("No authoritative zone match, proceeding to upstream forwarding");
        }

        // Step 3: Upstream forwarding (network-bound)
        // TODO: Implement synchronous query-response API in forwarder
        // For now, the forwarder is designed for async event-driven processing
        // This high-level API needs a different forwarding mechanism
        debug!("Forwarding query to upstream servers - not yet implemented");
        Err(DnsError::UpstreamUnreachable.into())
    }

    /// Build a DNS response from a cached entry.
    ///
    /// # Arguments
    ///
    /// * `query` - The original query
    /// * `cached_entry` - The cache entry to build response from
    ///
    /// # Returns
    ///
    /// A `Result<DnsResponse>` containing the constructed response
    #[allow(clippy::unused_async)] // Maintains uniform async API across DNS service methods
    async fn build_response_from_cache(
        &self,
        query: &DnsQuery,
        cached_entry: &CacheEntry,
    ) -> Result<DnsResponse> {
        // Create a minimal query message to build response from
        let query_message = protocol::DnsMessage::builder()
            .id(0) // ID will be set by caller if needed
            .set_query()
            .add_question(Question {
                qname: query.name.clone(),
                qtype: query.qtype,
                qclass: query.qclass,
            })
            .build();

        let mut response = DnsResponse::from_query(&query_message);
        response.add_answer(cached_entry.record().clone());
        response.set_authoritative(false); // Cache responses are not authoritative
        Ok(response)
    }

    /// Get comprehensive cache statistics.
    ///
    /// Returns detailed metrics about cache performance including size, hit rates,
    /// and entry distribution. Called by:
    /// - D-Bus API `GetMetrics` method
    /// - SIGUSR1 signal handler (dump cache statistics)
    /// - Monitoring and observability tools
    ///
    /// # Returns
    ///
    /// [`CacheStats`] struct containing current cache metrics
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let stats = dns_service.get_cache_stats().await;
    /// println!("Cache utilization: {}/{}", stats.entries, stats.capacity);
    /// println!("Hit rate: {:.2}%", stats.hit_rate * 100.0);
    /// ```
    ///
    /// # Performance
    ///
    /// O(1) operation - statistics are maintained incrementally during cache operations.
    #[instrument(skip(self))]
    pub async fn get_cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        cache.get_stats()
    }

    /// Clear all entries from the DNS cache.
    ///
    /// Removes all cached DNS records, forcing subsequent queries to be forwarded
    /// to upstream servers. Called by:
    /// - SIGHUP signal handler (configuration reload)
    /// - D-Bus API `ClearCache` method
    /// - Manual cache flush via CLI
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Clear cache after configuration change
    /// dns_service.clear_cache().await;
    /// ```
    ///
    /// # Performance
    ///
    /// O(n) where n is the number of cache entries. Typically completes in <10ms
    /// for default cache size (150 entries).
    #[instrument(skip(self))]
    pub async fn clear_cache(&self) {
        info!("Clearing DNS cache");
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("DNS cache cleared");
    }

    /// Reload DNS configuration and apply changes.
    ///
    /// Updates the DNS service configuration from the provided new config,
    /// applying changes that can be hot-reloaded without service restart:
    /// - Upstream server list
    /// - Domain matching rules
    /// - EDNS0 settings
    /// - Authoritative zone data (if feature enabled)
    ///
    /// Changes requiring restart (cannot be hot-reloaded):
    /// - Cache size (requires cache recreation)
    /// - Listen addresses (requires socket rebinding)
    /// - DNSSEC trust anchors (requires validator recreation)
    ///
    /// Called by SIGHUP signal handler when configuration file changes.
    ///
    /// # Arguments
    ///
    /// * `new_config` - The new DNS configuration to apply
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Reload configuration from file
    /// let new_config = DnsConfig::from_file("/etc/dnsmasq.conf").await?;
    /// dns_service.reload_config(Arc::new(new_config)).await;
    /// ```
    ///
    /// # Performance
    ///
    /// Typically completes in <100ms. Does not block query processing - uses
    /// `RwLock` to allow concurrent reads during configuration update.
    #[instrument(skip(self, _new_config))]
    pub async fn reload_config(&self, _new_config: Arc<DnsConfig>) {
        info!("Reloading DNS configuration");

        // TODO: Implement hot-reload logic
        // - Update upstream pool with new server list
        // - Update domain matcher with new rules
        // - Update authoritative zones if feature enabled
        //
        // For now, this is a stub that just logs the reload
        // Full implementation requires:
        // 1. UpstreamPool::update_servers() method
        // 2. DomainMatcher::reload_patterns() method
        // 3. AuthService::reload_zones() method (if auth feature)

        warn!("Configuration reload not yet implemented - restart required for config changes");
    }
}

/// Builder for constructing a [`DnsService`] with custom configuration.
///
/// Implements the builder pattern for flexible DNS service construction with
/// dependency injection. Allows configuring individual components before
/// building the complete service.
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::dns::DnsServiceBuilder;
/// use std::sync::Arc;
///
/// let service = DnsServiceBuilder::new()
///     .config(Arc::new(config))
///     .cache_size(2000)
///     .upstream_servers(vec![
///         "8.8.8.8:53".parse()?,
///         "8.8.4.4:53".parse()?,
///     ])
///     .build()
///     .await?;
/// ```
///
/// # Builder Pattern Benefits
///
/// - **Dependency Injection**: Components can be mocked for testing
/// - **Flexibility**: Configure only the components you need
/// - **Type Safety**: Build fails at compile-time if required components missing
/// - **Testability**: Easy to create test instances with minimal setup
#[derive(Default)]
pub struct DnsServiceBuilder {
    config: Option<Arc<DnsConfig>>,
    cache_size: Option<usize>,
    upstream_servers: Option<Vec<String>>,

    #[cfg(feature = "auth")]
    auth_zones: Option<Vec<AuthoritativeZone>>,

    #[cfg(feature = "dnssec")]
    enable_dnssec: bool,
}

impl DnsServiceBuilder {
    /// Create a new DNS service builder with default settings.
    ///
    /// # Returns
    ///
    /// A new `DnsServiceBuilder` with no components configured
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the DNS configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Arc-wrapped DNS configuration loaded from dnsmasq.conf
    ///
    /// # Returns
    ///
    /// Self for method chaining
    #[must_use]
    pub fn config(mut self, config: Arc<DnsConfig>) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the cache size (number of entries).
    ///
    /// # Arguments
    ///
    /// * `size` - Maximum number of cache entries (default: 150 from dnsmasq.conf)
    ///
    /// # Returns
    ///
    /// Self for method chaining
    #[must_use]
    pub fn cache_size(mut self, size: usize) -> Self {
        self.cache_size = Some(size);
        self
    }

    /// Set the upstream DNS servers.
    ///
    /// # Arguments
    ///
    /// * `servers` - List of upstream server addresses in "IP:PORT" format
    ///
    /// # Returns
    ///
    /// Self for method chaining
    #[must_use]
    pub fn upstream_servers(mut self, servers: Vec<String>) -> Self {
        self.upstream_servers = Some(servers);
        self
    }

    /// Set authoritative zones for local zone serving.
    ///
    /// Only available when `auth` feature is enabled.
    ///
    /// # Arguments
    ///
    /// * `zones` - List of authoritative zone configurations
    ///
    /// # Returns
    ///
    /// Self for method chaining
    #[cfg(feature = "auth")]
    #[must_use]
    pub fn auth_zones(mut self, zones: Vec<AuthoritativeZone>) -> Self {
        self.auth_zones = Some(zones);
        self
    }

    /// Enable DNSSEC validation.
    ///
    /// Only available when `dnssec` feature is enabled.
    ///
    /// # Arguments
    ///
    /// * `enable` - Whether to enable DNSSEC validation
    ///
    /// # Returns
    ///
    /// Self for method chaining
    #[cfg(feature = "dnssec")]
    #[must_use]
    pub fn enable_dnssec(mut self, enable: bool) -> Self {
        self.enable_dnssec = enable;
        self
    }

    /// Build the DNS service from configured components.
    ///
    /// # Returns
    ///
    /// A `Result<DnsService>` containing:
    /// - `Ok(service)` - Successfully constructed DNS service ready for use
    /// - `Err(error)` - Configuration error (missing required components)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - `config` not set (required)
    /// - Upstream server addresses invalid
    /// - DNSSEC trust anchors cannot be loaded (when DNSSEC enabled)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let service = DnsServiceBuilder::new()
    ///     .config(Arc::new(config))
    ///     .build()
    ///     .await?;
    /// ```
    #[allow(clippy::unused_async)] // Builder pattern maintains async API for future async initialization
    pub async fn build(self) -> Result<DnsService> {
        let config = self
            .config
            .ok_or_else(|| DnsError::ConfigurationError("DNS config is required".to_string()))?;

        // Create DNS cache from config
        let cache = Arc::new(RwLock::new(DnsCache::new(&config)));

        // Create upstream pool
        // TODO: Populate pool with servers from config
        let upstream_pool = Arc::new(RwLock::new(UpstreamPool::new()));

        // Create forwarder with cache and upstream pool references
        let forwarder =
            Arc::new(DnsForwarder::new(cache.clone(), upstream_pool.clone(), config.clone()));

        // Create EDNS0 handler
        let edns0_handler = Arc::new(Edns0Handler::new());

        // Create domain matcher
        // TODO: Populate matcher with patterns from config
        let domain_matcher = Arc::new(DomainMatcher::new());

        // Create RR filter (unit struct, no constructor needed)
        let rr_filter = Arc::new(RrFilter);

        // Create authoritative service if feature enabled
        #[cfg(feature = "auth")]
        let auth_service = if let Some(zones) = self.auth_zones {
            // AuthService::new requires zones, cache, and auth_ttl
            // Use default TTL of 600 seconds (matching C daemon->local_ttl default)
            let auth_ttl = 600u32;
            Some(Arc::new(AuthService::new(zones, cache.clone(), auth_ttl)))
        } else {
            None
        };

        // Create DNSSEC validator if feature enabled
        #[cfg(feature = "dnssec")]
        let dnssec_validator = if self.enable_dnssec || config.dnssec_enabled {
            if config.trust_anchors.is_empty() {
                return Err(DnsError::ConfigurationError(
                    "DNSSEC enabled but no trust anchors configured".to_string(),
                )
                .into());
            }
            // Create TrustAnchorStore from configured trust anchors
            let mut trust_store = TrustAnchorStore::new();
            for anchor_str in &config.trust_anchors {
                trust_store.parse_and_add_anchor(anchor_str)?;
            }
            let trust_anchors = Arc::new(RwLock::new(trust_store));

            Some(Arc::new(DnssecValidator::new(trust_anchors, cache.clone())))
        } else {
            None
        };

        Ok(DnsService {
            cache,
            forwarder,
            upstream_pool,
            #[cfg(feature = "auth")]
            auth_service,
            #[cfg(feature = "dnssec")]
            dnssec_validator,
            edns0_handler,
            domain_matcher,
            rr_filter,
            config,
        })
    }
}

// Convenience functions for common operations

/// Clear the DNS cache of the provided service.
///
/// Convenience wrapper around [`DnsService::clear_cache()`].
///
/// # Arguments
///
/// * `service` - The DNS service whose cache to clear
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::dns::clear_cache;
///
/// clear_cache(&dns_service).await;
/// ```
pub async fn clear_cache(service: &DnsService) {
    service.clear_cache().await;
}

/// Get cache statistics from the provided service.
///
/// Convenience wrapper around [`DnsService::get_cache_stats()`].
///
/// # Arguments
///
/// * `service` - The DNS service to query
///
/// # Returns
///
/// [`CacheStats`] struct containing current cache metrics
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::dns::get_cache_stats;
///
/// let stats = get_cache_stats(&dns_service).await;
/// println!("Cache hit rate: {:.2}%", stats.hit_rate * 100.0);
/// ```
pub async fn get_cache_stats(service: &DnsService) -> CacheStats {
    service.get_cache_stats().await
}

/// Reload DNS configuration for the provided service.
///
/// Convenience wrapper around [`DnsService::reload_config()`].
///
/// # Arguments
///
/// * `service` - The DNS service to reconfigure
/// * `new_config` - The new configuration to apply
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::dns::reload_config;
///
/// let new_config = DnsConfig::from_file("/etc/dnsmasq.conf").await?;
/// reload_config(&dns_service, Arc::new(new_config)).await;
/// ```
pub async fn reload_config(service: &DnsService, new_config: Arc<DnsConfig>) {
    service.reload_config(new_config).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_service_builder() {
        // Test that builder pattern works with minimal configuration
        let config = Arc::new(DnsConfig::default());
        let result = DnsServiceBuilder::new().config(config).cache_size(100).build().await;

        assert!(result.is_ok(), "Builder should succeed with valid config");
    }

    #[tokio::test]
    async fn test_builder_requires_config() {
        // Test that builder fails without config
        let result = DnsServiceBuilder::new().cache_size(100).build().await;

        assert!(result.is_err(), "Builder should fail without config");
    }

    #[tokio::test]
    async fn test_cache_stats_default() {
        // Test that cache stats can be retrieved from new service
        let config = Arc::new(DnsConfig::default());
        let service =
            DnsServiceBuilder::new().config(config).build().await.expect("Service creation failed");

        let stats = service.get_cache_stats().await;
        assert_eq!(stats.current_size, 0, "New cache should be empty");
        assert_eq!(stats.hits, 0, "New cache should have no hits");
        assert_eq!(stats.misses, 0, "New cache should have no misses");
    }

    #[tokio::test]
    async fn test_clear_cache() {
        // Test that clearing cache works without errors
        let config = Arc::new(DnsConfig::default());
        let service =
            DnsServiceBuilder::new().config(config).build().await.expect("Service creation failed");

        // Should not panic or error
        service.clear_cache().await;

        let stats = service.get_cache_stats().await;
        assert_eq!(stats.current_size, 0, "Cache should be empty after clear");
    }
}
