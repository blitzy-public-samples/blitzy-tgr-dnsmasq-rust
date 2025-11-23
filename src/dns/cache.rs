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

//! DNS cache implementation with hash table and LRU eviction.
//!
//! This module provides memory-safe DNS caching with O(1) lookups, replacing the C
//! implementation's manual hash table from cache.c with Rust's `HashMap` and LRU eviction.
//!
//! # Architecture
//!
//! The cache integrates DNS records from multiple sources:
//! - **Upstream DNS responses**: Cached with TTL from authoritative servers
//! - **/etc/hosts file**: Static hostname mappings loaded at startup/reload
//! - **DHCP leases**: Dynamic hostname assignments from DHCP server
//!
//! # Key Features
//!
//! - **O(1) lookups**: `HashMap` provides constant-time access by domain name + type
//! - **LRU eviction**: Least-recently-used entries removed when cache reaches capacity
//! - **TTL expiration**: Automatic removal of expired entries via background task
//! - **Multi-source integration**: Unified namespace across DNS, hosts, and DHCP
//! - **Concurrent access**: `RwLock` enables multiple concurrent readers with exclusive writer
//!
//! # C Implementation Mapping
//!
//! ## Data Structures
//!
//! ```c
//! // C: Manual hash table with chaining
//! struct crec {
//!     union {
//!         struct all_addr addr;    // IPv4/IPv6 address
//!         struct {
//!             union namelist *namelist;
//!             int is_name_ptr;
//!         } cname;
//!         struct {
//!             struct blockdata *key;
//!             unsigned short keylen, keytag;
//!             unsigned char algo, digest;
//!         } ds;
//!     } addr;
//!     time_t ttd;                  // Time to die (expiration)
//!     unsigned int flags;          // Record type and source flags
//!     struct crec *hash_next;      // Collision chain
//!     struct crec *prev, *next;    // LRU list
//! };
//!
//! static struct crec *cache_head = NULL, *cache_tail = NULL;
//! static struct crec **hash_table = NULL;
//! static int cache_size = CACHESIZ;
//! ```
//!
//! ```rust,ignore
//! // Rust: Type-safe collections with automatic memory management
//! pub struct DnsCache {
//!     entries: HashMap<CacheKey, Arc<CacheEntry>>,  // O(1) lookup
//!     lru: LruCache<CacheKey, Arc<CacheEntry>>,     // Automatic eviction
//!     capacity: usize,
//! }
//!
//! pub struct CacheEntry {
//!     domain_name: DomainName,
//!     record: ResourceRecord,
//!     expiry: Timestamp,
//!     flags: CacheFlags,
//! }
//! ```
//!
//! ## Memory Safety Improvements
//!
//! - **Eliminates manual memory management**: No malloc/free, automatic Drop
//! - **Prevents use-after-free**: Borrow checker tracks all references
//! - **No dangling pointers**: LRU removal safely drops entries
//! - **Type-safe unions**: `RData` enum replaces C discriminated union
//! - **Bounds-checked access**: `HashMap` prevents buffer overflows
//!
//! # Examples
//!
//! ```rust,ignore
//! use dnsmasq::dns::cache::DnsCache;
//! use dnsmasq::dns::protocol::name::DomainName;
//! use dnsmasq::types::RecordType;
//!
//! // Create cache with 1000 entry capacity
//! let mut cache = DnsCache::with_capacity(1000);
//!
//! // Lookup by domain name
//! let name = DomainName::new("example.com")?;
//! if let Some(entry) = cache.find_by_name(&name, RecordType::A).await {
//!     println!("Cached IP: {:?}", entry.ip_addr());
//! }
//!
//! // Insert new entry
//! cache.insert(entry).await?;
//!
//! // Get cache statistics
//! let stats = cache.get_stats().await;
//! println!("Hits: {}, Misses: {}", stats.hits, stats.misses);
//! ```

use crate::config::types::DnsConfig;
use crate::constants::HOSTSFILE;
use crate::dns::protocol::name::DomainName;
use crate::dns::protocol::record::{RData, ResourceRecord};
use crate::error::Result;
use crate::types::{CacheFlags, RecordType, Timestamp};

use ahash::AHashMap;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, info, instrument, trace, warn};

/// Cache key combining domain name and record type for `HashMap` lookups.
///
/// Provides efficient hashing and equality comparison for cache entries.
/// Case-insensitive domain name matching per DNS specification (RFC 1035).
///
/// # Examples
///
/// ```rust,ignore
/// let key = CacheKey::new(
///     DomainName::new("example.com")?,
///     RecordType::A,
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
    /// Domain name for this cache entry (case-insensitive)
    pub domain: DomainName,
    /// DNS record type (A, AAAA, CNAME, etc.)
    pub record_type: RecordType,
}

impl CacheKey {
    /// Creates a new cache key from domain name and record type.
    #[must_use]
    pub fn new(domain: DomainName, record_type: RecordType) -> Self {
        Self { domain, record_type }
    }
}

/// Cached DNS record entry with metadata and expiration tracking.
///
/// Replaces C `struct crec` from cache.c with type-safe Rust structure.
/// Stores complete DNS record data plus cache-specific metadata like
/// TTL expiration time, source flags, and access timestamps.
///
/// # C Equivalent
///
/// ```c
/// struct crec {
///     union { /* addr, cname, ds, key */ } addr;
///     time_t ttd;               // Time to die
///     unsigned int flags;       // F_FORWARD, F_REVERSE, F_IPV4, etc.
///     struct crec *hash_next;   // Collision chain
///     struct crec *prev, *next; // LRU doubly-linked list
/// };
/// ```
///
/// # Fields
///
/// - `domain_name`: Domain this record refers to (from `ResourceRecord`)
/// - `record`: Complete DNS resource record with type-specific data
/// - `expiry`: Absolute time when this entry expires (for TTL enforcement)
/// - `flags`: Source and type metadata (hosts file, DHCP, forward, reverse)
/// - `insert_time`: When this entry was added (for LRU tracking)
///
/// # Examples
///
/// ```rust,ignore
/// let entry = CacheEntry::new(
///     DomainName::new("example.com")?,
///     RecordType::A,
///     IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
///     300, // TTL seconds
///     CacheFlags::FORWARD | CacheFlags::IPV4,
/// );
///
/// if entry.is_expired() {
///     // Remove from cache
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Domain name this entry refers to
    domain_name: DomainName,
    /// DNS record type (A, AAAA, CNAME, etc.)
    record_type: RecordType,
    /// IP address for A/AAAA records, None for other types
    ip_addr: Option<IpAddr>,
    /// Complete DNS resource record
    #[allow(dead_code)]
    record: ResourceRecord,
    /// Time when this entry expires (TTL enforcement)
    expiry: Timestamp,
    /// Cache source and type flags
    flags: CacheFlags,
    /// Time when entry was inserted (for LRU)
    #[allow(dead_code)]
    insert_time: Timestamp,
}

impl CacheEntry {
    /// Creates a new cache entry from DNS record with TTL.
    ///
    /// # Arguments
    ///
    /// * `domain_name` - Domain name for this entry
    /// * `record_type` - DNS record type
    /// * `ip_addr` - IP address (for A/AAAA records only)
    /// * `ttl` - Time to live in seconds
    /// * `flags` - Cache source flags (`F_FORWARD`, `F_HOSTS`, `F_DHCP`, etc.)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let entry = CacheEntry::new(
    ///     DomainName::new("example.com")?,
    ///     RecordType::A,
    ///     Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
    ///     300,
    ///     CacheFlags::FORWARD | CacheFlags::IPV4,
    /// );
    /// ```
    #[must_use]
    pub fn new(
        domain_name: DomainName,
        record_type: RecordType,
        ip_addr: Option<IpAddr>,
        ttl: u32,
        flags: CacheFlags,
    ) -> Self {
        let now = Timestamp::now();
        let expiry = now + std::time::Duration::from_secs(u64::from(ttl));

        // Create minimal ResourceRecord for the cache entry
        let rdata = match (record_type, ip_addr) {
            (RecordType::A, Some(IpAddr::V4(addr))) => RData::A(addr),
            (RecordType::AAAA, Some(IpAddr::V6(addr))) => RData::AAAA(addr),
            _ => RData::Unknown { rtype: u16::from(record_type), rdata: bytes::Bytes::new() },
        };

        let record = ResourceRecord::new(domain_name.clone(), record_type, 1, ttl, rdata);

        Self { domain_name, record_type, ip_addr, record, expiry, flags, insert_time: now }
    }

    /// Returns the domain name for this entry.
    pub fn domain_name(&self) -> &DomainName {
        &self.domain_name
    }

    /// Returns the record type for this entry.
    pub fn record_type(&self) -> RecordType {
        self.record_type
    }

    /// Returns the IP address if this is an A or AAAA record.
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.ip_addr
    }

    /// Returns a reference to the resource record.
    pub fn record(&self) -> &ResourceRecord {
        &self.record
    }

    /// Returns the TTL in seconds remaining until expiry.
    pub fn ttl(&self) -> u32 {
        let now = Timestamp::now();
        let remaining = self.expiry.duration_since(&now);
        // Clamp to u32::MAX since DNS TTLs are 32-bit values
        remaining
            .unwrap_or(Duration::ZERO)
            .as_secs()
            .min(u64::from(u32::MAX))
            .try_into()
            .expect("clamped to u32::MAX")
    }

    /// Returns the absolute expiry time.
    pub fn expiry(&self) -> Timestamp {
        self.expiry
    }

    /// Returns the cache flags.
    pub fn flags(&self) -> CacheFlags {
        self.flags
    }

    /// Checks if this entry has expired.
    pub fn is_expired(&self) -> bool {
        Timestamp::now() >= self.expiry
    }

    /// Checks if this entry is from a DHCP lease.
    pub fn is_dhcp(&self) -> bool {
        self.flags.contains(CacheFlags::DHCP)
    }

    /// Checks if this entry is from /etc/hosts file.
    pub fn is_hosts(&self) -> bool {
        self.flags.contains(CacheFlags::HOSTS)
    }

    /// Checks if this is a forward lookup entry.
    pub fn is_forward(&self) -> bool {
        self.flags.contains(CacheFlags::FORWARD)
    }

    /// Checks if this is a reverse lookup entry.
    pub fn is_reverse(&self) -> bool {
        self.flags.contains(CacheFlags::REVERSE)
    }
}

/// Cache statistics for monitoring and debugging.
///
/// Tracks cache performance metrics including hit/miss rates,
/// current size, evictions, and expirations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total cache lookup attempts
    pub lookups: u64,
    /// Successful cache hits
    pub hits: u64,
    /// Cache misses requiring upstream query
    pub misses: u64,
    /// Number of entries currently in cache
    pub current_size: usize,
    /// Maximum cache capacity
    pub capacity: usize,
    /// Number of entries evicted due to capacity
    pub evictions: u64,
    /// Number of entries removed due to TTL expiration
    pub expirations: u64,
    /// Number of entries inserted
    pub insertions: u64,
}

/// DNS cache with hash table and LRU eviction.
///
/// Memory-safe replacement for C cache.c implementation providing:
/// - O(1) lookups via `HashMap` with `CacheKey` hashing
/// - LRU eviction when cache reaches capacity
/// - Automatic TTL expiration via background task
/// - Multi-source integration (DNS, hosts file, DHCP)
/// - Concurrent access via `RwLock`
///
/// # C Implementation Mapping
///
/// Replaces these C global variables from cache.c:
/// ```c
/// static struct crec **hash_table = NULL;  // Hash table with chaining
/// static struct crec *cache_head = NULL;   // LRU list head
/// static struct crec *cache_tail = NULL;   // LRU list tail
/// static int cache_size = CACHESIZ;        // Default 150 entries
/// static int cache_inserted = 0, cache_live_freed = 0;
/// ```
///
/// With type-safe Rust collections:
/// ```rust,ignore
/// pub struct DnsCache {
///     entries: AHashMap<CacheKey, Arc<CacheEntry>>,
///     lru: LruCache<CacheKey, Arc<CacheEntry>>,
///     capacity: usize,
///     stats: CacheStats,
/// }
/// ```
///
/// # Thread Safety
///
/// Wrapped in Arc<`RwLock`<DnsCache>> for concurrent access:
/// - Multiple async tasks can read simultaneously (DNS forwarder queries)
/// - Exclusive write access for insertions and evictions
/// - No data races or memory unsafety
///
/// # Examples
///
/// ```rust,ignore
/// // Create cache with default capacity
/// let cache = Arc::new(RwLock::new(DnsCache::new(&config)));
///
/// // Lookup entry (multiple readers can do this concurrently)
/// let cache_read = cache.read().await;
/// if let Some(entry) = cache_read.find_by_name(&name, RecordType::A) {
///     // Use cached entry
/// }
///
/// // Insert new entry (requires exclusive write lock)
/// let mut cache_write = cache.write().await;
/// cache_write.insert(entry).await?;
/// ```
#[derive(Debug)]
pub struct DnsCache {
    /// Hash table for O(1) lookups by domain name + record type
    entries: AHashMap<CacheKey, Arc<CacheEntry>>,
    /// LRU cache for automatic eviction of least-recently-used entries
    lru: LruCache<CacheKey, Arc<CacheEntry>>,
    /// Maximum number of entries (from --cache-size option)
    capacity: usize,
    /// Cache performance statistics
    stats: CacheStats,
}

impl DnsCache {
    /// Creates a new DNS cache with default capacity from configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - DNS configuration containing `cache_size` parameter
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cache = DnsCache::new(&config);
    /// ```
    #[must_use]
    pub fn new(config: &DnsConfig) -> Self {
        let capacity =
            if config.cache_size == 0 { crate::constants::CACHESIZ } else { config.cache_size };
        Self::with_capacity(capacity)
    }

    /// Creates a new DNS cache with specified capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of cache entries
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cache = DnsCache::with_capacity(1000);
    /// ```
    #[instrument(skip(capacity))]
    pub fn with_capacity(capacity: usize) -> Self {
        info!(capacity, "Initializing DNS cache");

        let lru_capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(150).unwrap());

        Self {
            entries: AHashMap::with_capacity(capacity),
            lru: LruCache::new(lru_capacity),
            capacity,
            stats: CacheStats { capacity, ..Default::default() },
        }
    }

    /// Finds a cache entry by domain name and record type.
    ///
    /// Implements forward lookup (name → address) matching C `cache_find_by_name()`.
    /// Increments cache hit/miss statistics.
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to look up
    /// * `record_type` - DNS record type (A, AAAA, CNAME, etc.)
    ///
    /// # Returns
    ///
    /// Some(entry) if found and not expired, None otherwise
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// if let Some(entry) = cache.find_by_name(&name, RecordType::A) {
    ///     println!("Cached IP: {:?}", entry.ip_addr());
    /// }
    /// ```
    #[instrument(skip(self), fields(domain = %domain, record_type = ?record_type))]
    pub fn find_by_name(
        &mut self,
        domain: &DomainName,
        record_type: RecordType,
    ) -> Option<Arc<CacheEntry>> {
        self.stats.lookups += 1;

        let key = CacheKey::new(domain.clone(), record_type);

        // DEBUG: Log all cache keys to understand what's in the cache
        eprintln!(
            "[CACHE DEBUG] Looking up key: domain={}, type={:?}. Cache contains {} entries",
            domain,
            record_type,
            self.entries.len()
        );
        for (cache_key, cache_entry) in &self.entries {
            eprintln!(
                "[CACHE DEBUG]   Cache entry: domain={}, type={:?}, flags={:?}, expired={}",
                cache_key.domain,
                cache_key.record_type,
                cache_entry.flags(),
                cache_entry.is_expired()
            );
        }

        // Check LRU cache (promotes entry to most-recently-used)
        if let Some(entry) = self.lru.get(&key) {
            // Check if expired
            if entry.is_expired() {
                eprintln!("[CACHE DEBUG] Cache entry expired, removing");
                info!(domain = %domain, record_type = ?record_type, "Cache entry expired, removing");
                self.lru.pop(&key);
                self.entries.remove(&key);
                self.stats.expirations += 1;
                self.stats.misses += 1;
                return None;
            }

            eprintln!("[CACHE DEBUG] Cache hit for domain={domain}, type={record_type:?}");
            info!(domain = %domain, record_type = ?record_type, "Cache HIT - entry promoted");
            self.stats.hits += 1;
            return Some(Arc::clone(entry));
        }

        eprintln!("[CACHE DEBUG] Cache miss for domain={}, type={:?}", domain, record_type);
        info!(domain = %domain, record_type = ?record_type, "Cache MISS");
        self.stats.misses += 1;
        None
    }

    /// Finds a cache entry by IP address for reverse lookup.
    ///
    /// Scans cache for matching IP address in A/AAAA records.
    /// Less efficient than forward lookup but necessary for PTR queries.
    ///
    /// # Arguments
    ///
    /// * `addr` - IP address to look up
    ///
    /// # Returns
    ///
    /// Some(entry) if found and not expired, None otherwise
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// if let Some(entry) = cache.find_by_addr(&addr) {
    ///     println!("Reverse lookup: {:?}", entry.domain_name());
    /// }
    /// ```
    #[instrument(skip(self), fields(addr = %addr))]
    pub fn find_by_addr(&mut self, addr: &IpAddr) -> Option<Arc<CacheEntry>> {
        self.stats.lookups += 1;

        // Scan entries for matching IP address
        for (key, entry) in &self.entries {
            if let Some(entry_addr) = entry.ip_addr() {
                if entry_addr == *addr {
                    // Check if expired
                    if entry.is_expired() {
                        debug!("Cache entry expired");
                        self.stats.expirations += 1;
                        self.stats.misses += 1;
                        return None;
                    }

                    // Promote in LRU
                    self.lru.get(key);

                    trace!("Reverse lookup cache hit");
                    self.stats.hits += 1;
                    return Some(Arc::clone(entry));
                }
            }
        }

        trace!("Reverse lookup cache miss");
        self.stats.misses += 1;
        None
    }

    /// Inserts a new entry into the cache.
    ///
    /// If cache is at capacity, evicts least-recently-used entry first.
    /// Replaces existing entry with same key if present.
    ///
    /// # Arguments
    ///
    /// * `entry` - Cache entry to insert
    ///
    /// # Returns
    ///
    /// Ok(()) on success, Err on failure
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let entry = CacheEntry::new(
    ///     DomainName::new("example.com")?,
    ///     RecordType::A,
    ///     Some(addr),
    ///     300,
    ///     CacheFlags::FORWARD,
    /// );
    /// cache.insert(entry)?;
    /// ```
    #[instrument(skip(self, entry), fields(domain = %entry.domain_name(), record_type = ?entry.record_type()))]
    pub fn insert(&mut self, entry: CacheEntry) -> Result<()> {
        let key = CacheKey::new(entry.domain_name().clone(), entry.record_type());

        eprintln!(
            "[CACHE DEBUG] Inserting entry: domain={}, type={:?}, flags={:?}",
            entry.domain_name(),
            entry.record_type(),
            entry.flags()
        );

        // Check if we need to evict before inserting
        eprintln!(
            "[INSERT] Checking eviction: len={}, capacity={}, contains_key={}",
            self.entries.len(),
            self.capacity,
            self.entries.contains_key(&key)
        );
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&key) {
            eprintln!("[INSERT] Cache at capacity, calling evict_lru()");
            info!(
                current_size = self.entries.len(),
                capacity = self.capacity,
                "Cache at capacity, evicting LRU entry"
            );
            if let Some(evicted) = self.evict_lru() {
                eprintln!("[INSERT] Successfully evicted: {}", evicted.domain_name());
                info!(evicted_domain = %evicted.domain_name(), "Evicted entry from cache");
            } else {
                eprintln!("[INSERT] ERROR: evict_lru() returned None");
                warn!("Cache at capacity but evict_lru() returned None");
            }
        } else {
            eprintln!("[INSERT] No eviction needed");
        }

        let entry_arc = Arc::new(entry);
        let domain_name = entry_arc.domain_name().clone();

        eprintln!("[EPRINTLN BEFORE INSERT] About to insert into HashMap and LRU");
        eprintln!("[EPRINTLN BEFORE INSERT] Current HashMap size: {}", self.entries.len());
        eprintln!("[EPRINTLN BEFORE INSERT] Max capacity: {}", self.capacity);

        // Insert into both hash map and LRU
        self.entries.insert(key.clone(), Arc::clone(&entry_arc));
        self.lru.put(key, entry_arc);

        self.stats.insertions += 1;
        self.stats.current_size = self.entries.len();

        eprintln!(
            "[EPRINTLN AFTER INSERT] Entry inserted: domain={}, cache_size={}",
            domain_name,
            self.entries.len()
        );
        info!(
            domain = %domain_name,
            cache_size = self.entries.len(),
            "Entry inserted into cache"
        );
        trace!("Entry inserted into cache");
        Ok(())
    }

    /// Evicts the least-recently-used entry from the cache.
    ///
    /// Replaces C implementation's manual LRU list traversal with
    /// `LruCache`'s automatic tracking.
    ///
    /// # Returns
    ///
    /// The evicted entry if cache was non-empty, None if empty
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// if let Some(evicted) = cache.evict_lru() {
    ///     println!("Evicted: {:?}", evicted.domain_name());
    /// }
    /// ```
    #[instrument(skip(self))]
    pub fn evict_lru(&mut self) -> Option<Arc<CacheEntry>> {
        eprintln!("[EVICT_LRU] Called, LRU cache len before pop: {}", self.lru.len());
        if let Some((key, entry)) = self.lru.pop_lru() {
            eprintln!("[EVICT_LRU] Popped LRU entry: domain={}", entry.domain_name());
            self.entries.remove(&key);
            self.stats.evictions += 1;
            self.stats.current_size = self.entries.len();
            eprintln!("[EVICT_LRU] HashMap size after removal: {}", self.entries.len());

            debug!(domain = %entry.domain_name(), "Evicted LRU entry");
            return Some(entry);
        }

        eprintln!("[EVICT_LRU] No LRU entry to evict");
        None
    }

    /// Removes a single expired entry if found.
    ///
    /// Scans cache for first expired entry and removes it.
    /// For bulk expiration cleanup, use `prune_expired()`.
    ///
    /// # Returns
    ///
    /// The expired entry if found, None if no expired entries
    #[instrument(skip(self))]
    pub fn evict_expired(&mut self) -> Option<Arc<CacheEntry>> {
        let now = Timestamp::now();

        // Find first expired entry
        let expired_key = self
            .entries
            .iter()
            .find(|(_, entry)| entry.expiry() <= now)
            .map(|(key, _)| key.clone());

        if let Some(key) = expired_key {
            if let Some(entry) = self.entries.remove(&key) {
                self.lru.pop(&key);
                self.stats.expirations += 1;
                self.stats.current_size = self.entries.len();

                debug!(domain = %entry.domain_name(), "Evicted expired entry");
                return Some(entry);
            }
        }

        None
    }

    /// Removes all expired entries from the cache.
    ///
    /// Called periodically by background task to clean up expired entries.
    /// Replaces C implementation's `cache_scan()` function.
    ///
    /// # Returns
    ///
    /// Number of entries removed
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let removed = cache.prune_expired();
    /// println!("Removed {} expired entries", removed);
    /// ```
    #[instrument(skip(self))]
    pub fn prune_expired(&mut self) -> usize {
        let now = Timestamp::now();
        let mut removed = 0;

        // Collect expired keys
        let expired_keys: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expiry() <= now)
            .map(|(key, _)| key.clone())
            .collect();

        // Remove expired entries
        for key in expired_keys {
            if self.entries.remove(&key).is_some() {
                self.lru.pop(&key);
                removed += 1;
                self.stats.expirations += 1;
            }
        }

        if removed > 0 {
            self.stats.current_size = self.entries.len();
            info!(removed, "Pruned expired cache entries");
        }

        removed
    }

    /// Refreshes cache from /etc/hosts file.
    ///
    /// Loads host entries from system hosts file and adds them to cache
    /// with `F_HOSTS` flag. Entries from hosts file never expire.
    ///
    /// Replaces C implementation's `read_hosts()` function.
    ///
    /// # Arguments
    ///
    /// * `hosts_path` - Optional path to hosts file (defaults to /etc/hosts)
    ///
    /// # Returns
    ///
    /// Ok(count) with number of hosts loaded, Err on I/O failure
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let count = cache.refresh_from_hosts(None).await?;
    /// println!("Loaded {} hosts entries", count);
    /// ```
    #[instrument(skip(self))]
    pub async fn refresh_from_hosts(&mut self, hosts_path: Option<&Path>) -> Result<usize> {
        let path = hosts_path.unwrap_or_else(|| Path::new(HOSTSFILE));

        info!(path = %path.display(), "Loading hosts file");

        let file = match File::open(path).await {
            Ok(f) => f,
            Err(e) => {
                warn!(error = %e, "Failed to open hosts file");
                return Ok(0);
            }
        };

        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut count = 0;

        while let Some(line) = lines.next_line().await? {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse line: "127.0.0.1 localhost"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let addr_str = parts[0];
            let hostnames = &parts[1..];

            // Parse IP address
            let Ok(addr) = addr_str.parse::<IpAddr>() else {
                debug!(line, "Invalid IP address in hosts file");
                continue;
            };

            // Add entry for each hostname
            for hostname in hostnames {
                let Ok(domain) = DomainName::new(hostname) else {
                    debug!(hostname, "Invalid hostname in hosts file");
                    continue;
                };

                let record_type = match addr {
                    IpAddr::V4(_) => RecordType::A,
                    IpAddr::V6(_) => RecordType::AAAA,
                };

                let flags = CacheFlags::HOSTS | CacheFlags::FORWARD;

                // Hosts entries never expire (use max TTL)
                let entry = CacheEntry::new(domain, record_type, Some(addr), u32::MAX, flags);

                self.insert(entry)?;
                count += 1;
            }
        }

        info!(count, "Loaded hosts entries");
        Ok(count)
    }

    /// Adds a DHCP lease hostname to the cache.
    ///
    /// Called by DHCP server when allocating/renewing leases.
    /// Entry is marked with `F_DHCP` flag and has TTL matching lease duration.
    ///
    /// # Arguments
    ///
    /// * `hostname` - DHCP client hostname
    /// * `addr` - IP address assigned to client
    /// * `ttl` - Lease duration in seconds
    ///
    /// # Returns
    ///
    /// Ok(()) on success, Err on failure
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// cache.add_dhcp_entry(
    ///     DomainName::new("client.lan")?,
    ///     IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
    ///     3600,
    /// )?;
    /// ```
    #[instrument(skip(self), fields(hostname = %hostname, addr = %addr, ttl = ttl))]
    pub fn add_dhcp_entry(&mut self, hostname: DomainName, addr: IpAddr, ttl: u32) -> Result<()> {
        let record_type = match addr {
            IpAddr::V4(_) => RecordType::A,
            IpAddr::V6(_) => RecordType::AAAA,
        };

        let flags = CacheFlags::DHCP | CacheFlags::FORWARD;

        let entry = CacheEntry::new(hostname, record_type, Some(addr), ttl, flags);

        debug!("Adding DHCP entry to cache");
        self.insert(entry)
    }

    /// Removes a DHCP lease hostname from the cache.
    ///
    /// Called when DHCP lease expires or is released.
    ///
    /// # Arguments
    ///
    /// * `hostname` - DHCP client hostname to remove
    /// * `record_type` - Record type to remove (A or AAAA)
    ///
    /// # Returns
    ///
    /// true if entry was removed, false if not found
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// cache.remove_dhcp_entry(&hostname, RecordType::A);
    /// ```
    #[instrument(skip(self), fields(hostname = %hostname, record_type = ?record_type))]
    pub fn remove_dhcp_entry(&mut self, hostname: &DomainName, record_type: RecordType) -> bool {
        let key = CacheKey::new(hostname.clone(), record_type);

        if let Some(entry) = self.entries.get(&key) {
            if entry.is_dhcp() {
                self.entries.remove(&key);
                self.lru.pop(&key);
                self.stats.current_size = self.entries.len();

                debug!("Removed DHCP entry from cache");
                return true;
            }
        }

        false
    }

    /// Clears all entries from the cache.
    ///
    /// Used for SIGHUP configuration reload and testing.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// cache.clear();
    /// ```
    #[instrument(skip(self))]
    pub fn clear(&mut self) {
        let count = self.entries.len();
        self.entries.clear();
        self.lru.clear();
        self.stats.current_size = 0;

        info!(count, "Cleared cache");
    }

    /// Returns the current number of entries in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Checks if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the maximum cache capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns cache statistics for monitoring.
    ///
    /// Used by SIGUSR2 signal handler and D-Bus `GetMetrics` method.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let stats = cache.get_stats();
    /// println!("Hit rate: {:.2}%",
    ///     (stats.hits as f64 / stats.lookups as f64) * 100.0);
    /// ```
    #[must_use]
    pub fn get_stats(&self) -> CacheStats {
        self.stats.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_config(cache_size: usize) -> DnsConfig {
        DnsConfig { cache_size, ..Default::default() }
    }

    #[test]
    fn test_cache_creation() {
        let config = create_test_config(100);
        let cache = DnsCache::new(&config);

        assert_eq!(cache.capacity(), 100);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_insert_and_find() {
        let config = create_test_config(10);
        let mut cache = DnsCache::new(&config);

        let domain = DomainName::new("example.com").unwrap();
        let addr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

        let entry =
            CacheEntry::new(domain.clone(), RecordType::A, Some(addr), 300, CacheFlags::FORWARD);

        cache.insert(entry).unwrap();
        assert_eq!(cache.len(), 1);

        let found = cache.find_by_name(&domain, RecordType::A);
        assert!(found.is_some());
        assert_eq!(found.unwrap().ip_addr(), Some(addr));
    }

    #[test]
    fn test_cache_find_by_addr() {
        let config = create_test_config(10);
        let mut cache = DnsCache::new(&config);

        let domain = DomainName::new("example.com").unwrap();
        let addr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

        let entry = CacheEntry::new(
            domain.clone(),
            RecordType::A,
            Some(addr),
            300,
            CacheFlags::FORWARD | CacheFlags::REVERSE,
        );

        cache.insert(entry).unwrap();

        let found = cache.find_by_addr(&addr);
        assert!(found.is_some());
        assert_eq!(found.unwrap().domain_name(), &domain);
    }

    #[test]
    fn test_lru_eviction() {
        let config = create_test_config(3);
        let mut cache = DnsCache::new(&config);

        // Insert 3 entries
        for i in 1..=3 {
            let domain = DomainName::new(&format!("test{}.com", i)).unwrap();
            let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8));
            let entry =
                CacheEntry::new(domain, RecordType::A, Some(addr), 300, CacheFlags::FORWARD);
            cache.insert(entry).unwrap();
        }

        assert_eq!(cache.len(), 3);

        // Insert 4th entry, should evict LRU
        let domain = DomainName::new("test4.com").unwrap();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4));
        let entry = CacheEntry::new(domain, RecordType::A, Some(addr), 300, CacheFlags::FORWARD);
        cache.insert(entry).unwrap();

        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get_stats().evictions, 1);
    }

    #[test]
    fn test_dhcp_entry() {
        let config = create_test_config(10);
        let mut cache = DnsCache::new(&config);

        let hostname = DomainName::new("client.lan").unwrap();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        cache.add_dhcp_entry(hostname.clone(), addr, 3600).unwrap();

        let found = cache.find_by_name(&hostname, RecordType::A);
        assert!(found.is_some());
        assert!(found.unwrap().is_dhcp());

        let removed = cache.remove_dhcp_entry(&hostname, RecordType::A);
        assert!(removed);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_stats() {
        let config = create_test_config(10);
        let mut cache = DnsCache::new(&config);

        let domain = DomainName::new("example.com").unwrap();

        // Miss
        cache.find_by_name(&domain, RecordType::A);

        let stats = cache.get_stats();
        assert_eq!(stats.lookups, 1);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);

        // Insert and hit
        let addr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let entry =
            CacheEntry::new(domain.clone(), RecordType::A, Some(addr), 300, CacheFlags::FORWARD);
        cache.insert(entry).unwrap();

        cache.find_by_name(&domain, RecordType::A);

        let stats = cache.get_stats();
        assert_eq!(stats.lookups, 2);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.insertions, 1);
    }

    #[test]
    fn test_clear() {
        let config = create_test_config(10);
        let mut cache = DnsCache::new(&config);

        let domain = DomainName::new("example.com").unwrap();
        let addr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let entry = CacheEntry::new(domain, RecordType::A, Some(addr), 300, CacheFlags::FORWARD);

        cache.insert(entry).unwrap();
        assert_eq!(cache.len(), 1);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }
}
