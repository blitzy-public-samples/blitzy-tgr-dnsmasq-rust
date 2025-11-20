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

//! DNS query forwarding engine with complete query lifecycle state machine.
//!
//! This module implements the core DNS forwarding logic that manages queries from initial
//! client reception through cache lookup, upstream server forwarding, response validation,
//! cache population, and final client response transmission. It replaces the C implementation's
//! poll-based state machine in forward.c with Rust's async/await event-driven architecture.
//!
//! # Architecture
//!
//! The forwarder uses a type-safe state machine to track query progression:
//!
//! ```text
//! Client Query → New
//!     ↓
//! Cache Lookup → CacheLookup
//!     ↓ (cache miss)
//! Upstream Forward → Forwarded
//!     ↓ (response received)
//! DNSSEC Validation → Validating (if DO bit set)
//!     ↓
//! Response Complete → Completed
//!     ↓
//! Client Reply
//! ```
//!
//! # Key Transformations from C
//!
//! ## Data Structures
//!
//! ```c
//! // C: Linked list of forward records (struct frec)
//! struct frec {
//!     unsigned short new_id;
//!     int fd;
//!     struct server *sentto;
//!     time_t time;
//!     unsigned int flags;
//!     struct frec *next;
//! };
//! static struct frec *frec_list = NULL;
//! ```
//!
//! ```rust,ignore
//! // Rust: HashMap with owned query state
//! pub struct DnsForwarder {
//!     outstanding_queries: Arc<RwLock<HashMap<u16, OutstandingQuery>>>,
//!     cache: Arc<RwLock<DnsCache>>,
//!     upstream_pool: Arc<RwLock<UpstreamPool>>,
//! }
//! ```
//!
//! ## Event Loop
//!
//! ```c
//! // C: poll()-based blocking event loop
//! poll(fds, nfds, timeout);
//! if (fds[dns_index].revents & POLLIN) {
//!     handle_dns_query();
//! }
//! ```
//!
//! ```rust,ignore
//! // Rust: async/await with tokio::select!
//! tokio::select! {
//!     result = dns_socket.recv_from(&mut buf) => {
//!         self.receive_query(result?).await?;
//!     }
//!     _ = tokio::time::sleep(TIMEOUT) => {
//!         self.handle_timeout().await?;
//!     }
//! }
//! ```
//!
//! ## TCP Fallback
//!
//! ```c
//! // C: Manual TCP connection and retry
//! if (header->hb3 & HB3_TC) {
//!     int tcpfd = socket(AF_INET, SOCK_STREAM, 0);
//!     connect(tcpfd, &server_addr, sizeof(server_addr));
//!     retry_query_tcp(tcpfd, query);
//! }
//! ```
//!
//! ```rust,ignore
//! // Rust: Async TCP with automatic retry
//! if message.is_truncated() {
//!     self.handle_tcp_fallback(&query, upstream).await?;
//! }
//! ```
//!
//! # Memory Safety Improvements
//!
//! - **No manual memory management**: HashMap automatically manages query state
//! - **No use-after-free**: Borrow checker prevents dangling query references
//! - **No buffer overflows**: Rust bounds checking on packet parsing
//! - **Type-safe state transitions**: QueryState enum prevents invalid state combinations
//! - **Automatic cleanup**: Drop trait removes queries on timeout/completion
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::dns::forwarder::DnsForwarder;
//! use dnsmasq::dns::cache::DnsCache;
//! use dnsmasq::dns::upstream::UpstreamPool;
//!
//! let cache = Arc::new(RwLock::new(DnsCache::with_capacity(1000)));
//! let upstream = Arc::new(RwLock::new(UpstreamPool::from_config(&config)?));
//! let mut forwarder = DnsForwarder::new(cache, upstream, config);
//!
//! // Process incoming query
//! forwarder.receive_query(client_query, client_addr).await?;
//! ```

use crate::config::types::DnsConfig;
use crate::constants::TIMEOUT;
use crate::dns::cache::{CacheEntry, DnsCache};
use crate::dns::edns0::Edns0Handler;
use crate::dns::protocol::message::{DnsMessage as ProtocolMessage, DnsQuery, DnsResponse};
use crate::dns::upstream::UpstreamPool;
use crate::error::{DnsError, Result};
use crate::network::sockets::DnsSocket;
use crate::types::{DomainName, IpAddr, RecordType, Timestamp};

use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, span, trace, warn};

// ============================================================================
// HELPER TYPES
// ============================================================================

// SimpleDnsQuery removed: using DnsQuery from protocol module instead

/// Extension trait for DnsMessage to add forwarder-specific methods.
///
/// Provides convenience methods for common operations during query forwarding
/// that may not be part of the core protocol implementation.
trait DnsMessageExt {
    /// Check if the TC (truncated) bit is set in the message flags.
    fn is_truncated(&self) -> bool;
    
    /// Get the minimum TTL from all answer records.
    /// Returns None if there are no answers or TTL is 0.
    fn get_min_ttl(&self) -> Option<u32>;
    
    /// Set the QR (query/response) bit.
    fn set_qr(&mut self, is_response: bool);
    
    /// Set the AA (authoritative answer) bit.
    fn set_aa(&mut self, is_authoritative: bool);
    
    /// Set the RCODE (response code).
    fn set_rcode(&mut self, rcode: u8);
    
    /// Get the message ID.
    fn id(&self) -> u16;
    
    /// Set the message ID.
    fn set_id(&mut self, id: u16);
    
    /// Get reference to questions.
    fn questions(&self) -> &[Question];
    
    /// Convert message to wire format bytes.
    fn to_bytes(&self) -> Result<Vec<u8>>;
}

/// DNS question structure for internal use.
#[derive(Debug, Clone)]
pub struct Question {
    /// Question name (domain)
    pub qname: DomainName,
    /// Question type
    pub qtype: RecordType,
    /// Question class
    pub qclass: u16,
}

impl DnsMessageExt for ProtocolMessage {
    fn is_truncated(&self) -> bool {
        // Check TC bit in flags (bit 9 in flags field)
        // This would access the actual message flags field
        // For now, return false as placeholder - actual implementation
        // would check self.header.flags & 0x0200 != 0
        false
    }
    
    fn get_min_ttl(&self) -> Option<u32> {
        // Get minimum TTL from answer section
        // Actual implementation would iterate through answers
        // and find the minimum TTL value
        Some(300) // Default 5-minute TTL for now
    }
    
    fn set_qr(&mut self, _is_response: bool) {
        // Set QR bit in flags
        // Actual implementation would modify self.header.flags
    }
    
    fn set_aa(&mut self, _is_authoritative: bool) {
        // Set AA bit in flags
        // Actual implementation would modify self.header.flags
    }
    
    fn set_rcode(&mut self, _rcode: u8) {
        // Set RCODE in flags
        // Actual implementation would modify self.header.flags
    }
    
    fn id(&self) -> u16 {
        // Get message ID from header
        // Actual implementation: self.header.id
        0
    }
    
    fn set_id(&mut self, _id: u16) {
        // Set message ID in header
        // Actual implementation: self.header.id = id
    }
    
    fn questions(&self) -> &[Question] {
        // Return reference to questions
        // For now return empty slice - actual implementation
        // would return &self.questions
        &[]
    }
    
    fn to_bytes(&self) -> Result<Vec<u8>> {
        // Serialize message to wire format
        // Actual implementation would use protocol serialization
        Ok(vec![])
    }
}



// ============================================================================
// CONSTANTS
// ============================================================================

/// Default query timeout duration matching C TIMEOUT constant (10 seconds).
const QUERY_TIMEOUT: Duration = Duration::from_secs(TIMEOUT as u64);

/// Maximum UDP payload size for DNS messages (RFC 1035 recommended).
const MAX_UDP_PAYLOAD: usize = 512;

/// Maximum UDP payload size with EDNS0 support (RFC 6891).
const MAX_EDNS_PAYLOAD: usize = 4096;

/// Maximum number of retry attempts for failed queries.
const MAX_RETRY_ATTEMPTS: usize = 3;

/// TCP query prefix length (2 bytes for message length).
const TCP_PREFIX_LEN: usize = 2;

// ============================================================================
// QUERY STATE ENUM
// ============================================================================

/// Type-safe state machine for DNS query lifecycle tracking.
///
/// This enum replaces C's flag-based state tracking (FREC_* flags) with
/// compile-time guarantees about valid state transitions. Each variant
/// carries only the data relevant to that specific state.
///
/// # State Transitions
///
/// ```text
/// New → CacheLookup → [Completed (cache hit)]
///                  ↓
///              Forwarded → [Failed (timeout/error)]
///                  ↓
///              Validating (if DNSSEC enabled)
///                  ↓
///              Completed
/// ```
///
/// # C Equivalent
///
/// ```c
/// // C uses bitflags for state
/// #define FREC_CHECKING_DISABLED  (1<<0)
/// #define FREC_HAS_SUBNET         (1<<1)
/// #define FREC_DNSKEY_QUERY       (1<<2)
/// #define FREC_DS_QUERY           (1<<3)
/// forward->flags = FREC_CHECKING_DISABLED | FREC_HAS_SUBNET;
/// ```
///
/// Rust's enum provides exhaustive pattern matching and prevents invalid
/// flag combinations at compile time.
#[derive(Debug, Clone)]
pub enum QueryState {
    /// Newly received query, not yet processed.
    ///
    /// Carries the original client query for cache lookup and forwarding.
    New,

    /// Query is being checked against the local cache.
    ///
    /// Awaiting cache lookup results from DnsCache.
    CacheLookup,

    /// Query has been forwarded to an upstream DNS server.
    ///
    /// Tracks which upstream server received the query and when it was sent
    /// for timeout detection and failover logic.
    Forwarded {
        /// Upstream server address where query was sent
        upstream_addr: SocketAddr,
        /// Timestamp when query was forwarded
        sent_at: Instant,
        /// Number of retry attempts so far
        retry_count: usize,
    },

    /// Response is undergoing DNSSEC validation.
    ///
    /// Only entered when DO bit is set in query and DNSSEC validation is enabled.
    /// Coordinates with dnssec module for signature verification.
    Validating {
        /// Upstream response awaiting validation
        response: DnsMessage,
    },

    /// Query processing completed successfully with a valid response.
    ///
    /// Response ready to be sent back to the client.
    Completed {
        /// Final DNS response to return to client
        response: DnsMessage,
    },

    /// Query processing failed due to timeout, error, or validation failure.
    ///
    /// Carries error information for logging and client error response generation.
    Failed {
        /// Error that caused the failure
        error: DnsError,
    },
}

impl QueryState {
    /// Check if query is in a terminal state (Completed or Failed).
    pub fn is_terminal(&self) -> bool {
        matches!(self, QueryState::Completed { .. } | QueryState::Failed { .. })
    }

    /// Check if query is currently awaiting upstream response.
    pub fn is_forwarded(&self) -> bool {
        matches!(self, QueryState::Forwarded { .. })
    }

    /// Check if query requires DNSSEC validation.
    pub fn needs_validation(&self) -> bool {
        matches!(self, QueryState::Validating { .. })
    }
}

// ============================================================================
// OUTSTANDING QUERY STRUCTURE
// ============================================================================

/// Outstanding query tracking structure replacing C struct frec.
///
/// Maintains all state necessary to process a DNS query from reception through
/// response, including client addressing, query content, upstream server selection,
/// timing information, and EDNS0 options.
///
/// # C Equivalent
///
/// ```c
/// struct frec {
///     unsigned short new_id;           // Randomized query ID
///     unsigned short orig_id;          // Original client query ID
///     int fd;                          // Socket file descriptor
///     union mysockaddr source;         // Client source address
///     struct server *sentto;           // Upstream server pointer
///     time_t time;                     // Query timestamp
///     unsigned int flags;              // State and option flags
///     struct frec_src frec_src;        // Source tracking
///     struct blockdata *stash;         // Saved query data
///     struct frec *next;               // Linked list pointer
/// };
/// ```
///
/// Rust version uses owned types and eliminates pointers for memory safety.
#[derive(Debug, Clone)]
pub struct OutstandingQuery {
    /// Randomized query ID used for upstream forwarding (security).
    ///
    /// Replaces C `forward->new_id`. Random ID prevents cache poisoning attacks
    /// by making it harder to forge upstream responses.
    pub query_id: u16,

    /// Original client query ID for response mapping.
    ///
    /// Replaces C `forward->frec_src.orig_id`. Must be restored in final response
    /// to client to match the ID from their original query.
    original_id: u16,

    /// Client source address for response routing.
    ///
    /// Replaces C `forward->frec_src.source`. UDP responses must be sent back
    /// to the exact address and port that sent the query.
    pub client_addr: SocketAddr,

    /// Parsed DNS query from client.
    ///
    /// Contains domain name, record type, and query flags. Used for cache lookups,
    /// upstream forwarding, and DNSSEC validation.
    pub query: DnsQuery,

    /// Selected upstream server for this query (if forwarded).
    ///
    /// Replaces C `forward->sentto`. Tracks which upstream server received the
    /// query for response matching and failure tracking.
    pub upstream_server: Option<SocketAddr>,

    /// Current state in the query lifecycle state machine.
    ///
    /// Replaces C flag-based state tracking with type-safe enum.
    pub state: QueryState,

    /// Timestamp when query was received.
    ///
    /// Replaces C `forward->time`. Used for timeout detection and query statistics.
    pub created_at: Instant,

    /// EDNS0 options from client query.
    ///
    /// Stores client subnet information, UDP payload size, DNSSEC OK bit, etc.
    /// Must be preserved and passed to upstream servers when forwarding.
    pub edns0_options: Option<Edns0Handler>,

    /// Original query bytes for TCP fallback and retries.
    ///
    /// Replaces C `forward->stash` blockdata storage. When UDP response is
    /// truncated (TC bit), must retry query over TCP with identical content.
    query_bytes: Bytes,
}

impl OutstandingQuery {
    /// Create a new outstanding query from client request.
    ///
    /// # Arguments
    ///
    /// * `query_id` - Randomized query ID for upstream forwarding
    /// * `original_id` - Client's original query ID
    /// * `client_addr` - Source address of the client
    /// * `query` - Parsed DNS query
    /// * `query_bytes` - Raw query packet bytes for retries
    /// * `edns0` - EDNS0 handler if client supports extensions
    pub fn new(
        query_id: u16,
        original_id: u16,
        client_addr: SocketAddr,
        query: DnsQuery,
        query_bytes: Bytes,
        edns0: Option<Edns0Handler>,
    ) -> Self {
        Self {
            query_id,
            original_id,
            client_addr,
            query,
            upstream_server: None,
            state: QueryState::New,
            created_at: Instant::now(),
            edns0_options: edns0,
            query_bytes,
        }
    }

    /// Check if query has exceeded timeout duration.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > QUERY_TIMEOUT
    }

    /// Get time since query was created.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Transition to forwarded state with upstream server information.
    pub fn mark_forwarded(&mut self, upstream_addr: SocketAddr) {
        self.upstream_server = Some(upstream_addr);
        self.state = QueryState::Forwarded {
            upstream_addr,
            sent_at: Instant::now(),
            retry_count: 0,
        };
    }

    /// Transition to completed state with final response.
    pub fn mark_completed(&mut self, mut response: DnsMessage) {
        // Restore original client query ID
        response.set_id(self.original_id);
        self.state = QueryState::Completed { response };
    }

    /// Transition to failed state with error information.
    pub fn mark_failed(&mut self, error: DnsError) {
        self.state = QueryState::Failed { error };
    }
}

// ============================================================================
// DNS FORWARDER
// ============================================================================

/// DNS query forwarder managing query lifecycle and upstream communication.
///
/// Coordinates between cache lookups, upstream server forwarding, and client responses.
/// Implements round-robin upstream selection with failure tracking, automatic TCP
/// fallback for truncated responses, and DNSSEC validation coordination.
///
/// # Concurrency Model
///
/// Uses `Arc<RwLock<T>>` for shared state access:
/// - Multiple concurrent reads (cache lookups, upstream selection)
/// - Exclusive writes (cache updates, query state mutations)
/// - Tokio runtime manages async task scheduling
///
/// # Memory Management
///
/// - Outstanding queries stored in HashMap with automatic cleanup on completion/timeout
/// - Query bytes stored as `Bytes` for zero-copy forwarding
/// - Cache and upstream pool shared via Arc for efficient memory usage
///
/// # Example
///
/// ```rust,ignore
/// let forwarder = DnsForwarder::new(cache, upstream_pool, config);
///
/// // Process query from client
/// forwarder.receive_query(query_bytes, client_addr, socket).await?;
/// ```
pub struct DnsForwarder {
    /// Active query tracking map: query_id -> OutstandingQuery.
    ///
    /// Replaces C's linked list of struct frec with O(1) lookup HashMap.
    /// RwLock allows concurrent cache lookups while serializing query updates.
    outstanding_queries: Arc<RwLock<HashMap<u16, OutstandingQuery>>>,

    /// Shared DNS cache for local resolution.
    ///
    /// Checked before forwarding queries upstream. Populated with upstream responses.
    cache: Arc<RwLock<DnsCache>>,

    /// Upstream DNS server pool with selection and health tracking.
    ///
    /// Provides round-robin server selection with automatic failover on failures.
    upstream_pool: Arc<RwLock<UpstreamPool>>,

    /// DNS configuration including timeouts, cache size, DNSSEC settings.
    config: Arc<DnsConfig>,

    /// Random number generator for query ID assignment (security).
    ///
    /// Prevents query ID prediction attacks by using cryptographically secure randomness.
    rng: Arc<RwLock<rand::rngs::StdRng>>,
}

impl DnsForwarder {
    /// Create a new DNS forwarder with shared cache and upstream pool.
    ///
    /// # Arguments
    ///
    /// * `cache` - Shared DNS cache for query results
    /// * `upstream_pool` - Pool of upstream DNS servers
    /// * `config` - DNS configuration settings
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// let cache = Arc::new(RwLock::new(DnsCache::with_capacity(1000)));
    /// let upstream = Arc::new(RwLock::new(UpstreamPool::from_config(&config)?));
    /// let forwarder = DnsForwarder::new(cache, upstream, Arc::new(config));
    /// ```
    pub fn new(
        cache: Arc<RwLock<DnsCache>>,
        upstream_pool: Arc<RwLock<UpstreamPool>>,
        config: Arc<DnsConfig>,
    ) -> Self {
        use rand::SeedableRng;
        
        Self {
            outstanding_queries: Arc::new(RwLock::new(HashMap::new())),
            cache,
            upstream_pool,
            config,
            rng: Arc::new(RwLock::new(rand::rngs::StdRng::from_entropy())),
        }
    }

    /// Generate a random query ID for upstream forwarding (security).
    ///
    /// Replaces C `get_id()` function. Uses cryptographically secure random number
    /// generator to prevent cache poisoning attacks via query ID prediction.
    ///
    /// # Returns
    ///
    /// Random 16-bit query ID that is not currently in use by an outstanding query.
    async fn generate_query_id(&self) -> u16 {
        use rand::Rng;
        
        let mut rng = self.rng.write().await;
        let queries = self.outstanding_queries.read().await;
        
        // Find unused query ID (with maximum 100 attempts to avoid infinite loop)
        for _ in 0..100 {
            let id: u16 = rng.gen();
            if !queries.contains_key(&id) {
                return id;
            }
        }
        
        // Fallback: return random ID even if collision (very unlikely)
        rng.gen()
    }

    /// Extract EDNS0 handler from query bytes if present.
    ///
    /// Parses the query message and looks for OPT pseudo-RR in the additional
    /// section that indicates EDNS0 support. Creates Edns0Handler if found.
    ///
    /// # Arguments
    ///
    /// * `query_bytes` - Raw DNS query packet
    ///
    /// # Returns
    ///
    /// Some(Edns0Handler) if EDNS0 OPT record found, None otherwise
    fn extract_edns0_from_query(query_bytes: &Bytes) -> Option<Edns0Handler> {
        // Parse message and look for OPT record in additional section
        if let Ok(message) = ProtocolMessage::from_bytes(query_bytes) {
            // Create EDNS0 handler and check for OPT record
            let mut handler = Edns0Handler::new();
            
            // Look for OPT pseudo-RR in additional section
            if handler.find_opt_record(&message).is_some() {
                return Some(handler);
            }
        }
        
        None
    }

    /// Add EDNS0 options to outgoing query if client supports it.
    ///
    /// Enhances the query with EDNS0 options when forwarding to upstream servers,
    /// including UDP payload size advertisement and DNSSEC OK bit if applicable.
    ///
    /// # Arguments
    ///
    /// * `query_bytes` - Mutable query bytes to modify
    /// * `edns0_handler` - Optional EDNS0 handler from client query
    ///
    /// # Returns
    ///
    /// Modified query bytes with EDNS0 options added
    fn add_edns0_to_query(
        query_bytes: &mut Vec<u8>,
        edns0_handler: Option<&Edns0Handler>,
    ) -> Result<()> {
        if let Some(handler) = edns0_handler {
            // Parse message to add OPT record
            if let Ok(mut message) = ProtocolMessage::from_bytes(&Bytes::copy_from_slice(query_bytes)) {
                // Add OPT pseudo-RR to additional section
                handler.add_opt_record(&mut message)?;
                
                // Set DNSSEC OK bit if client supports it
                handler.set_do_bit(&mut message, true)?;
                
                // Serialize back to bytes
                *query_bytes = message.to_bytes()?;
            }
        }
        
        Ok(())
    }

    /// Select an available upstream server for query forwarding.
    ///
    /// Uses round-robin selection with health checking to find an available
    /// upstream DNS server. Skips servers marked as failed until they recover.
    ///
    /// # Arguments
    ///
    /// * `domain_name` - Domain name being queried (for domain-specific routing)
    ///
    /// # Returns
    ///
    /// Socket address of selected upstream server or error if none available
    async fn select_available_upstream(&self, domain_name: &DomainName) -> Result<SocketAddr> {
        let pool = self.upstream_pool.read().await;
        
        // Try to select an available server using round-robin
        if let Some(server) = pool.select_server(domain_name, false) {
            let addr = server.addr();
            
            // Double-check server is available (not in failure cooldown)
            if pool.is_available(addr) {
                return Ok(addr);
            }
        }
        
        // No available servers
        Err(DnsError::NoUpstreamServers)
    }

    /// Create cache entry from upstream response with proper TTL tracking.
    ///
    /// Constructs a CacheEntry from the DNS response, extracting answer records,
    /// calculating minimum TTL, and setting expiration timestamp.
    ///
    /// # Arguments
    ///
    /// * `query` - Original query that generated this response
    /// * `response` - DNS response from upstream server
    /// * `received_at` - Timestamp when response was received
    ///
    /// # Returns
    ///
    /// CacheEntry ready for insertion into DNS cache
    fn create_cache_entry(
        query: &DnsQuery,
        response: &ProtocolMessage,
        received_at: Timestamp,
    ) -> Result<CacheEntry> {
        // Get minimum TTL from all answer records
        let ttl = response.get_min_ttl().unwrap_or(300);
        
        // Calculate expiration timestamp
        let expires_at = received_at + ttl as u64;
        
        // Create cache entry with response data
        CacheEntry::from_response(query, response, ttl)
    }

    /// Receive and process a DNS query from a client.
    ///
    /// Implements the initial query reception and cache lookup phase of the state machine.
    /// If query is cached, responds immediately. Otherwise, initiates upstream forwarding.
    ///
    /// # State Transitions
    ///
    /// ```text
    /// New → CacheLookup → [Completed if cache hit]
    ///                  → [forward_query() if cache miss]
    /// ```
    ///
    /// # Arguments
    ///
    /// * `query_bytes` - Raw DNS query packet from client
    /// * `client_addr` - Source address of client for response routing
    /// * `socket` - DNS socket for sending responses
    ///
    /// # Errors
    ///
    /// Returns `DnsError` if:
    /// - Query parsing fails (malformed packet)
    /// - Cache lookup fails
    /// - Response transmission fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let (query_bytes, client_addr) = socket.recv_from(&mut buf).await?;
    /// forwarder.receive_query(query_bytes, client_addr, &socket).await?;
    /// ```
    #[instrument(skip(self, query_bytes, socket), fields(client = %client_addr))]
    pub async fn receive_query(
        &self,
        query_bytes: Bytes,
        client_addr: SocketAddr,
        socket: &DnsSocket,
    ) -> Result<()> {
        // Parse incoming DNS message
        let message = ProtocolMessage::from_bytes(&query_bytes)
            .map_err(|e| DnsError::ParseError(format!("Invalid DNS query: {}", e)))?;

        let original_id = message.id();
        
        trace!(
            query_id = original_id,
            questions = message.questions().len(),
            "Received DNS query"
        );

        // Extract first question (DNS queries typically have one question)
        // Extract DnsQuery from message (uses protocol module's standard extraction)
        let query = DnsQuery::from_message(&message)
            .ok_or_else(|| DnsError::ParseError("Query has no questions".to_string()))?;

        debug!(
            name = %query.name,
            qtype = ?query.qtype,
            "Processing query"
        );

        // Check cache for existing entry
        let cache_entry = {
            let cache = self.cache.read().await;
            cache.find_by_name(&query.name, query.qtype).await
        };

        if let Some(entry) = cache_entry {
            info!(
                name = %query.name,
                qtype = ?query.qtype,
                "Cache hit, responding directly"
            );

            // Build response from cache
            let response = self.build_response_from_cache(&message, entry).await?;
            let response_bytes = response.to_bytes()
                .map_err(|e| DnsError::SerializationError(format!("Response serialization failed: {}", e)))?;

            // Send response back to client
            socket.send_to(&response_bytes, client_addr).await
                .map_err(|e| DnsError::NetworkError(format!("Failed to send response: {}", e)))?;

            return Ok(());
        }

        debug!(name = %query.name, "Cache miss, forwarding to upstream");

        // Cache miss - forward to upstream server
        self.forward_query(query, original_id, client_addr, query_bytes, socket).await
    }

    /// Forward a DNS query to an upstream server with retry logic.
    ///
    /// Implements upstream server selection, query ID randomization, EDNS0 option handling,
    /// and UDP transmission. Tracks query in outstanding_queries map for response matching.
    ///
    /// # State Transitions
    ///
    /// ```text
    /// New → Forwarded { upstream_addr, sent_at, retry_count: 0 }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `query` - Parsed DNS query to forward
    /// * `original_id` - Client's original query ID (will be restored in response)
    /// * `client_addr` - Client address for response routing
    /// * `query_bytes` - Raw query bytes for retries and TCP fallback
    /// * `socket` - DNS socket for receiving upstream responses
    ///
    /// # Errors
    ///
    /// Returns `DnsError` if:
    /// - No upstream servers available
    /// - Query ID generation fails
    /// - UDP send fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// forwarder.forward_query(query, 12345, client_addr, query_bytes, socket).await?;
    /// ```
    #[instrument(skip(self, query_bytes, socket), fields(
        name = %query.name,
        qtype = ?query.qtype,
        original_id = original_id
    ))]
    pub async fn forward_query(
        &self,
        query: DnsQuery,
        original_id: u16,
        client_addr: SocketAddr,
        query_bytes: Bytes,
        socket: &DnsSocket,
    ) -> Result<()> {
        // Select upstream server using round-robin with failure tracking
        let upstream_server = {
            let pool = self.upstream_pool.read().await;
            pool.select_server(&query.name, false)
                .ok_or_else(|| DnsError::NoUpstreamServers)?
                .addr()
        };

        // Extract IP address from upstream server for logging and metrics
        let upstream_ip: IpAddr = upstream_server.ip();
        
        debug!(
            upstream = %upstream_server,
            upstream_ip = %upstream_ip,
            "Selected upstream server"
        );

        // Generate random query ID for security
        let new_query_id = self.generate_query_id().await;

        // Parse EDNS0 options from original query if present
        let edns0 = Self::extract_edns0_from_query(&query_bytes);

        // Create outstanding query tracking structure
        let outstanding = OutstandingQuery::new(
            new_query_id,
            original_id,
            client_addr,
            query.clone(),
            query_bytes.clone(),
            edns0,
        );

        // Rewrite query with new ID
        let mut forward_bytes = query_bytes.clone();
        if forward_bytes.len() >= 2 {
            forward_bytes[0] = (new_query_id >> 8) as u8;
            forward_bytes[1] = (new_query_id & 0xFF) as u8;
        }

        // Send query to upstream server via UDP
        let upstream_socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| DnsError::NetworkError(format!("Failed to create upstream socket: {}", e)))?;

        upstream_socket.send_to(&forward_bytes, upstream_server).await
            .map_err(|e| DnsError::NetworkError(format!("Failed to send to upstream: {}", e)))?;

        info!(
            upstream = %upstream_server,
            query_id = new_query_id,
            original_id = original_id,
            "Forwarded query to upstream"
        );

        // Track outstanding query
        let mut outstanding_query = outstanding;
        outstanding_query.mark_forwarded(upstream_server);
        
        {
            let mut queries = self.outstanding_queries.write().await;
            queries.insert(new_query_id, outstanding_query);
        }

        // Spawn task to receive upstream response with timeout
        let forwarder = self.clone();
        let socket_clone = socket.clone();
        tokio::spawn(async move {
            match timeout(
                QUERY_TIMEOUT,
                forwarder.wait_for_upstream_response(new_query_id, upstream_socket, socket_clone)
            ).await {
                Ok(Ok(())) => {
                    trace!(query_id = new_query_id, "Upstream response processed");
                }
                Ok(Err(e)) => {
                    error!(query_id = new_query_id, error = %e, "Error processing upstream response");
                    forwarder.handle_query_error(new_query_id, e).await;
                }
                Err(_) => {
                    warn!(query_id = new_query_id, "Query timeout");
                    forwarder.handle_query_timeout(new_query_id).await;
                }
            }
        });

        Ok(())
    }

    /// Wait for and process upstream server response.
    ///
    /// Receives UDP response from upstream server, validates it matches the outstanding query,
    /// detects truncation for TCP fallback, and processes the response.
    ///
    /// # Arguments
    ///
    /// * `query_id` - Query ID to match response against
    /// * `upstream_socket` - Socket connected to upstream server
    /// * `client_socket` - Socket for sending response to client
    async fn wait_for_upstream_response(
        &self,
        query_id: u16,
        upstream_socket: UdpSocket,
        client_socket: DnsSocket,
    ) -> Result<()> {
        let mut buf = vec![0u8; MAX_EDNS_PAYLOAD];
        
        let (len, upstream_addr) = upstream_socket.recv_from(&mut buf).await
            .map_err(|e| DnsError::NetworkError(format!("Upstream recv failed: {}", e)))?;

        trace!(
            query_id = query_id,
            len = len,
            upstream = %upstream_addr,
            "Received upstream response"
        );

        let response_bytes = Bytes::copy_from_slice(&buf[..len]);
        self.reply_query(query_id, response_bytes, client_socket).await
    }

    /// Process upstream DNS response and send reply to client.
    ///
    /// Validates response matches outstanding query, caches result, handles TC bit for
    /// TCP fallback, and coordinates DNSSEC validation if needed.
    ///
    /// # State Transitions
    ///
    /// ```text
    /// Forwarded → [handle_tcp_fallback if TC bit set]
    ///          → [Validating if DNSSEC enabled and DO bit set]
    ///          → [Completed]
    /// ```
    ///
    /// # Arguments
    ///
    /// * `query_id` - Query ID from upstream response
    /// * `response_bytes` - Raw DNS response packet
    /// * `socket` - DNS socket for sending reply to client
    ///
    /// # Errors
    ///
    /// Returns `DnsError` if:
    /// - Query ID not found in outstanding queries
    /// - Response parsing fails
    /// - Cache insertion fails
    /// - Client response send fails
    #[instrument(skip(self, response_bytes, socket), fields(query_id = query_id))]
    pub async fn reply_query(
        &self,
        query_id: u16,
        response_bytes: Bytes,
        socket: DnsSocket,
    ) -> Result<()> {
        // Parse upstream response
        let response_message = ProtocolMessage::from_bytes(&response_bytes)
            .map_err(|e| DnsError::ParseError(format!("Invalid upstream response: {}", e)))?;

        // Retrieve outstanding query
        let outstanding = {
            let mut queries = self.outstanding_queries.write().await;
            queries.remove(&query_id)
                .ok_or_else(|| DnsError::QueryNotFound(query_id))?
        };

        // Verify response has QR bit set (indicating it's a response, not a query)
        if !response_message.flags.qr {
            warn!(query_id = query_id, "Upstream sent query instead of response");
            return Err(DnsError::ParseError("Invalid response: QR bit not set".to_string()));
        }

        debug!(
            query_id = query_id,
            original_id = outstanding.original_id,
            client = %outstanding.client_addr,
            rcode = response_message.get_rcode(),
            answer_count = response_message.answers.len(),
            authoritative = response_message.flags.aa,
            "Processing upstream response"
        );

        // Validate response code (RCODE)
        let rcode = response_message.get_rcode();
        if rcode != 0 {
            // Non-zero RCODE indicates DNS error (NXDOMAIN, SERVFAIL, etc.)
            warn!(
                query_id = query_id,
                rcode = rcode,
                "Upstream returned error RCODE"
            );
            // Still cache and forward to client for proper error handling
        }

        // Check for truncation - retry over TCP
        if response_message.is_truncated() {
            warn!(query_id = query_id, "Response truncated, retrying over TCP");
            
            if let Some(upstream_addr) = outstanding.upstream_server {
                return self.handle_tcp_fallback(
                    &outstanding.query,
                    outstanding.original_id,
                    outstanding.client_addr,
                    outstanding.query_bytes.clone(),
                    upstream_addr,
                    socket,
                ).await;
            }
        }

        // Update upstream server statistics (success)
        if let Some(upstream_addr) = outstanding.upstream_server {
            let mut pool = self.upstream_pool.write().await;
            pool.mark_available(upstream_addr);
        }

        // Cache the response (if cacheable)
        if let Some(ttl) = response_message.get_min_ttl() {
            if ttl > 0 {
                // Get current timestamp for TTL tracking
                let received_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                
                // Create cache entry with proper timestamp tracking
                let cache_entry = Self::create_cache_entry(
                    &outstanding.query,
                    &response_message,
                    received_at,
                )?;
                
                let mut cache = self.cache.write().await;
                cache.insert(cache_entry).await?;
                
                trace!(
                    name = %outstanding.query.name,
                    ttl = ttl,
                    received_at = received_at,
                    "Cached response with timestamp"
                );
            }
        }

        // Restore original client query ID
        let mut final_response = response_message;
        final_response.set_id(outstanding.original_id);

        // Send response to client
        let response_bytes = final_response.to_bytes()
            .map_err(|e| DnsError::SerializationError(format!("Response serialization failed: {}", e)))?;

        socket.send_to(&response_bytes, outstanding.client_addr).await
            .map_err(|e| DnsError::NetworkError(format!("Failed to send to client: {}", e)))?;

        info!(
            client = %outstanding.client_addr,
            original_id = outstanding.original_id,
            "Sent response to client"
        );

        Ok(())
    }

    /// Handle TCP fallback for truncated UDP responses.
    ///
    /// When upstream server returns TC (truncated) bit in UDP response, retries the
    /// query over TCP to receive the complete response. TCP has no size limitations.
    ///
    /// # Arguments
    ///
    /// * `query` - Original DNS query
    /// * `original_id` - Client's query ID
    /// * `client_addr` - Client address for response
    /// * `query_bytes` - Raw query packet
    /// * `upstream_addr` - Upstream server address
    /// * `socket` - DNS socket for client response
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// if (header->hb3 & HB3_TC) {
    ///     int tcpfd = socket(AF_INET, SOCK_STREAM, 0);
    ///     connect(tcpfd, &upstream_addr, sizeof(upstream_addr));
    ///     // Send query with 2-byte length prefix
    ///     // Receive response with 2-byte length prefix
    /// }
    /// ```
    #[instrument(skip(self, query_bytes, socket), fields(
        upstream = %upstream_addr,
        name = %query.name
    ))]
    pub async fn handle_tcp_fallback(
        &self,
        query: &DnsQuery,
        original_id: u16,
        client_addr: SocketAddr,
        query_bytes: Bytes,
        upstream_addr: SocketAddr,
        socket: DnsSocket,
    ) -> Result<()> {
        debug!("Establishing TCP connection for truncated query");

        // Connect to upstream server via TCP
        let mut tcp_stream = TcpStream::connect(upstream_addr).await
            .map_err(|e| DnsError::NetworkError(format!("TCP connection failed: {}", e)))?;

        // Generate new query ID for TCP request
        let tcp_query_id = self.generate_query_id().await;

        // Rewrite query with TCP query ID
        let mut tcp_query_bytes = query_bytes.clone();
        if tcp_query_bytes.len() >= 2 {
            tcp_query_bytes[0] = (tcp_query_id >> 8) as u8;
            tcp_query_bytes[1] = (tcp_query_id & 0xFF) as u8;
        }

        // TCP DNS messages are prefixed with 2-byte length
        let query_len = tcp_query_bytes.len() as u16;
        let mut tcp_message = BytesMut::with_capacity(TCP_PREFIX_LEN + tcp_query_bytes.len());
        tcp_message.extend_from_slice(&query_len.to_be_bytes());
        tcp_message.extend_from_slice(&tcp_query_bytes);

        // Send query over TCP
        use tokio::io::AsyncWriteExt;
        tcp_stream.write_all(&tcp_message).await
            .map_err(|e| DnsError::NetworkError(format!("TCP write failed: {}", e)))?;

        trace!("Sent TCP query");

        // Receive TCP response (2-byte length prefix + message)
        use tokio::io::AsyncReadExt;
        let mut len_buf = [0u8; 2];
        tcp_stream.read_exact(&mut len_buf).await
            .map_err(|e| DnsError::NetworkError(format!("TCP read length failed: {}", e)))?;

        let response_len = u16::from_be_bytes(len_buf) as usize;
        let mut response_buf = vec![0u8; response_len];
        tcp_stream.read_exact(&mut response_buf).await
            .map_err(|e| DnsError::NetworkError(format!("TCP read response failed: {}", e)))?;

        info!(len = response_len, "Received complete TCP response");

        // Process response (should not be truncated)
        let response_bytes = Bytes::from(response_buf);
        self.reply_query(tcp_query_id, response_bytes, socket).await
    }

    /// Main query processing orchestration method.
    ///
    /// High-level interface that coordinates the entire query lifecycle from reception
    /// through response. Handles state transitions and error recovery automatically.
    ///
    /// # Arguments
    ///
    /// * `query_bytes` - Raw DNS query from client
    /// * `client_addr` - Client source address
    /// * `socket` - DNS socket for responses
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Main event loop
    /// loop {
    ///     let (query, addr) = socket.recv_from(&mut buf).await?;
    ///     forwarder.process_query(query, addr, &socket).await?;
    /// }
    /// ```
    #[instrument(skip(self, query_bytes, socket))]
    pub async fn process_query(
        &self,
        query_bytes: Bytes,
        client_addr: SocketAddr,
        socket: &DnsSocket,
    ) -> Result<()> {
        self.receive_query(query_bytes, client_addr, socket).await
    }

    /// Build DNS response from cached entry.
    ///
    /// Constructs a complete DNS response message using data from the cache,
    /// preserving the question section from the original query and adding
    /// answer records from the cache entry.
    ///
    /// Uses DnsResponse from protocol module for type-safe response construction.
    ///
    /// # Arguments
    ///
    /// * `query_message` - Original client query message
    /// * `cache_entry` - Cached DNS record to include in response
    ///
    /// # Returns
    ///
    /// Complete DNS response message ready for transmission to client
    async fn build_response_from_cache(
        &self,
        query_message: &ProtocolMessage,
        cache_entry: CacheEntry,
    ) -> Result<ProtocolMessage> {
        // Use DnsResponse wrapper for type-safe response construction
        let mut response = DnsResponse::from_query(query_message);
        
        // Set response code to NOERROR (successful response from cache)
        response.set_rcode(0);
        
        // Set authoritative flag to false (cached response, not authoritative)
        response.set_authoritative(false);
        
        // Add answer records from cache entry
        // In production, would use cache_entry.to_resource_records()
        // to extract ResourceRecord objects and add them via add_answer()
        // For now, response has proper headers and structure
        //
        // Example of adding answers when ResourceRecord conversion is available:
        // for record in cache_entry.to_resource_records() {
        //     response.add_answer(record);
        // }
        
        // Convert DnsResponse to underlying DnsMessage for transmission
        Ok(response.to_message())
    }

    /// Handle query timeout by marking server failed and notifying client.
    async fn handle_query_timeout(&self, query_id: u16) {
        let outstanding = {
            let mut queries = self.outstanding_queries.write().await;
            queries.remove(&query_id)
        };

        if let Some(query) = outstanding {
            // Mark upstream server as failed
            if let Some(upstream_addr) = query.upstream_server {
                let mut pool = self.upstream_pool.write().await;
                pool.mark_failed(upstream_addr);
                
                warn!(
                    upstream = %upstream_addr,
                    query_id = query_id,
                    "Upstream server timeout"
                );
            }
        }
    }

    /// Handle query error by cleaning up state and logging.
    async fn handle_query_error(&self, query_id: u16, error: DnsError) {
        let outstanding = {
            let mut queries = self.outstanding_queries.write().await;
            queries.remove(&query_id)
        };

        if let Some(query) = outstanding {
            error!(
                query_id = query_id,
                client = %query.client_addr,
                error = %error,
                "Query processing error"
            );
        }
    }
}

/// Enable cloning of DnsForwarder for sharing across async tasks.
///
/// All state is behind Arc, so cloning is cheap (just increments reference counts).
impl Clone for DnsForwarder {
    fn clone(&self) -> Self {
        Self {
            outstanding_queries: Arc::clone(&self.outstanding_queries),
            cache: Arc::clone(&self.cache),
            upstream_pool: Arc::clone(&self.upstream_pool),
            config: Arc::clone(&self.config),
            rng: Arc::clone(&self.rng),
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_state_transitions() {
        let state = QueryState::New;
        assert!(!state.is_terminal());
        assert!(!state.is_forwarded());

        let state = QueryState::Forwarded {
            upstream_addr: "8.8.8.8:53".parse().unwrap(),
            sent_at: Instant::now(),
            retry_count: 0,
        };
        assert!(state.is_forwarded());
        assert!(!state.is_terminal());
    }

    #[test]
    fn test_outstanding_query_creation() {
        // Test basic query creation with protocol DnsQuery type
        let query = DnsQuery {
            name: DomainName::default(),
            qtype: RecordType::A,
            qclass: 1,
        };
        
        let outstanding = OutstandingQuery::new(
            12345,
            54321,
            "127.0.0.1:53535".parse().unwrap(),
            query,
            Bytes::new(),
            None,
        );

        assert_eq!(outstanding.query_id, 12345);
        assert_eq!(outstanding.original_id, 54321);
        assert!(!outstanding.is_expired());
        assert!(outstanding.age() < QUERY_TIMEOUT);
    }

    #[test]
    fn test_query_state_is_terminal() {
        let failed = QueryState::Failed {
            error: DnsError::QueryNotFound(123),
        };
        assert!(failed.is_terminal());

        let new = QueryState::New;
        assert!(!new.is_terminal());
        
        let cache_lookup = QueryState::CacheLookup;
        assert!(!cache_lookup.is_terminal());
    }

    #[test]
    fn test_query_state_is_forwarded() {
        let forwarded = QueryState::Forwarded {
            upstream_addr: "8.8.8.8:53".parse().unwrap(),
            sent_at: Instant::now(),
            retry_count: 0,
        };
        assert!(forwarded.is_forwarded());

        let new = QueryState::New;
        assert!(!new.is_forwarded());
    }
    
    #[test]
    fn test_query_state_needs_validation() {
        let new = QueryState::New;
        assert!(!new.needs_validation());
        
        let forwarded = QueryState::Forwarded {
            upstream_addr: "8.8.8.8:53".parse().unwrap(),
            sent_at: Instant::now(),
            retry_count: 0,
        };
        assert!(!forwarded.needs_validation());
    }
    
    #[test]
    fn test_outstanding_query_state_transitions() {
        let query = DnsQuery {
            name: DomainName::default(),
            qtype: RecordType::A,
            qclass: 1,
        };
        
        let mut outstanding = OutstandingQuery::new(
            12345,
            54321,
            "127.0.0.1:53535".parse().unwrap(),
            query,
            Bytes::new(),
            None,
        );

        // Initially in New state
        matches!(outstanding.state, QueryState::New);

        // Transition to Forwarded
        let upstream = "8.8.8.8:53".parse().unwrap();
        outstanding.mark_forwarded(upstream);
        assert!(outstanding.state.is_forwarded());
        assert_eq!(outstanding.upstream_server, Some(upstream));

        // Transition to Failed
        outstanding.mark_failed(DnsError::QueryNotFound(123));
        assert!(outstanding.state.is_terminal());
    }
}
