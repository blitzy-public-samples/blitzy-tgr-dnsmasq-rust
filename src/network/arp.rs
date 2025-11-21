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

//! ARP/Neighbor cache management module for MAC address resolution and network topology tracking.
//!
//! This module provides an internal ARP (Address Resolution Protocol) and IPv6 Neighbor Discovery
//! cache that maintains mappings between IP addresses (both IPv4 and IPv6) and hardware MAC
//! addresses. The cache is populated by synchronizing with the kernel's ARP/neighbor tables and
//! provides MAC address lookup services primarily for DHCP operations.
//!
//! # Key Responsibilities
//!
//! - **MAC Address Lookup**: Primary interface for DHCP code to resolve IP addresses to MAC
//!   addresses for address-in-use testing and client identification
//! - **Kernel Synchronization**: Periodically reads kernel ARP/neighbor tables to maintain
//!   an up-to-date internal cache
//! - **Topology Change Detection**: Identifies new devices appearing on the network and
//!   existing devices disappearing
//! - **Script Notifications**: Triggers external helper script execution for network
//!   topology changes when configured
//!
//! # Architecture
//!
//! The module implements a three-phase cache update algorithm matching the C implementation:
//!
//! 1. **Mark Phase**: All existing non-empty cache entries are marked with `ArpStatus::Mark`
//! 2. **Enumerate Phase**: Kernel ARP table is enumerated via platform-specific APIs:
//!    - Existing entries with matching MAC addresses: marked `ArpStatus::Found`
//!    - Existing entries with changed MAC addresses or new IPs: marked `ArpStatus::New`
//!    - Empty entries that now have MAC addresses: promoted to `ArpStatus::New`
//! 3. **Cleanup Phase**: Entries still marked `ArpStatus::Mark` (not found in kernel)
//!    are removed and script notifications triggered for disappeared devices
//!
//! # Platform Support
//!
//! - **Linux**: Uses rtnetlink for neighbor table queries (RTM_GETNEIGH)
//! - **BSD**: Uses routing sockets with CTL_NET.PF_ROUTE.0.AF_INET.NET_RT_FLAGS.RTF_LLINFO
//! - **macOS**: Uses sysctl NET_RT_FLAGS with RTF_LLINFO for ARP table access
//!
//! # Memory Safety Improvements
//!
//! Compared to the C implementation (src/arp.c):
//!
//! - **Linked List → Vec**: C's manual pointer-based `struct arp_record` linked list replaced
//!   with `Vec<ArpRecord>`, eliminating use-after-free and memory leak vulnerabilities
//! - **Status Flags → Enum**: C integer constants (ARP_MARK=0, ARP_FOUND=1, etc.) replaced
//!   with type-safe `ArpStatus` enum preventing invalid state values
//! - **Manual Memory Management → RAII**: C's malloc/free with freelist replaced with Rust's
//!   automatic memory management via Vec growth/shrinkage
//! - **Callback → Method**: C's filter_mac() callback function replaced with internal method
//!   eliminating function pointer safety concerns
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::network::arp::ArpCache;
//! use dnsmasq::network::platform::create_platform_handler;
//! use std::net::IpAddr;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! // Initialize ARP cache
//! let platform = create_platform_handler().await?;
//! let cache = Arc::new(RwLock::new(ArpCache::new(platform)));
//!
//! // Start periodic refresh task
//! let cache_clone = cache.clone();
//! tokio::spawn(async move {
//!     let mut interval = tokio::time::interval(Duration::from_secs(90));
//!     loop {
//!         interval.tick().await;
//!         if let Err(e) = cache_clone.write().await.update_from_kernel().await {
//!             error!("ARP cache refresh failed: {}", e);
//!         }
//!     }
//! });
//!
//! // Lookup MAC address for DHCP address-in-use testing
//! let ip: IpAddr = "192.168.1.100".parse()?;
//! let cache_read = cache.read().await;
//! if let Some(mac) = cache_read.find_mac(&ip) {
//!     info!("IP {} is in use by MAC {}", ip, mac);
//! }
//! ```
//!
//! # Configuration
//!
//! Script notifications are controlled by the `enable_arp_script` configuration option:
//!
//! ```conf
//! # Enable ARP change notifications to helper script
//! script-arp
//! ```
//!
//! # Performance Characteristics
//!
//! - **Refresh Interval**: 90 seconds (matches C INTERVAL constant)
//! - **Lookup Complexity**: O(n) linear search through cache entries (matches C behavior)
//! - **Memory Overhead**: ~48 bytes per cache entry (IP + MAC + status + metadata)
//! - **Script Notification**: Incremental processing prevents event loop blocking
//!
//! # RFC Compliance
//!
//! - **RFC 826**: ARP (Address Resolution Protocol) for IPv4
//! - **RFC 4861**: Neighbor Discovery for IPv6
//!
//! # Thread Safety
//!
//! The `ArpCache` struct is `Send + Sync` and designed to be wrapped in `Arc<RwLock<>>` for
//! shared access from DHCP services and background refresh tasks. All methods are non-blocking
//! and use async/await for I/O operations.

use crate::config::types::Config;
use crate::error::NetworkError;
use crate::network::platform::NetworkPlatform;
use crate::types::MacAddress;
use crate::util::helpers::queue_arp;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument};

/// Time interval in seconds between forced reloads of ARP cache from kernel ARP/neighbor tables.
///
/// The kernel ARP/neighbor table is re-read periodically to detect network topology changes
/// even when no explicit `find_mac()` calls are made. This ensures the internal cache remains
/// synchronized with actual network state.
///
/// This constant matches the C implementation's `INTERVAL` value (90 seconds) from src/arp.c
/// line 68, maintaining behavioral equivalence with the original dnsmasq.
const ARP_CACHE_REFRESH_INTERVAL_SECS: u64 = 90;

/// ARP cache entry status tracking lifecycle state during cache synchronization.
///
/// Replaces C implementation's integer constants (ARP_MARK=0, ARP_FOUND=1, ARP_NEW=2, ARP_EMPTY=3)
/// with type-safe enum providing compile-time validation and exhaustive pattern matching.
///
/// # State Transitions
///
/// Cache refresh implements a three-phase algorithm using these status values:
///
/// 1. **Mark Phase**: All non-empty entries set to `Mark`
/// 2. **Enumerate Phase**: Kernel table enumeration updates entries:
///    - `Mark` → `Found`: Entry confirmed with matching MAC address
///    - `Mark` → (removed): Entry not found in kernel, moved to deletion queue
///    - `Empty` → `New`: MAC address became available for previously empty entry
///    - (none) → `New`: New IP-to-MAC mapping discovered in kernel
/// 3. **Cleanup Phase**: `Mark` entries removed, `New` entries promoted to `Found`
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::network::arp::ArpStatus;
///
/// let mut status = ArpStatus::Mark;
/// // After kernel enumeration confirms entry exists
/// status = ArpStatus::Found;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpStatus {
    /// Initial mark state for existing entries before cache reload.
    ///
    /// Entries with this status after kernel enumeration are considered deleted/disappeared
    /// and will be moved to the removal queue for script notification.
    Mark,

    /// Entry confirmed - found in kernel cache during reload with matching MAC address.
    ///
    /// Stable entries that existed in previous refresh and were confirmed in current refresh
    /// transition to this state.
    Found,

    /// Newly created - entry added or changed during current cache reload.
    ///
    /// Either a brand new IP-to-MAC mapping discovered in kernel, or an existing entry with
    /// a changed MAC address. Triggers script notification for new device arrival.
    New,

    /// Empty - IP address known but no MAC address available yet.
    ///
    /// Represents negative caching: we queried the kernel for this IP but no ARP/neighbor
    /// entry exists yet. Prevents repeated kernel queries for non-existent mappings.
    Empty,
}

/// Internal cache entry mapping IP address to hardware MAC address.
///
/// Records the relationship between a network layer address (IPv4 or IPv6) and a data link
/// layer hardware address (typically 6-byte Ethernet MAC address). Used for DHCP address
/// conflict detection, client identification, and network topology change tracking.
///
/// Replaces C's `struct arp_record` (src/arp.c lines 114-121) with memory-safe Rust struct:
///
/// ```c
/// struct arp_record {
///     unsigned short hwlen;
///     unsigned short status;
///     int family;
///     unsigned char hwaddr[DHCP_CHADDR_MAX];
///     union all_addr addr;
///     struct arp_record *next;  // Replaced with Vec index
/// };
/// ```
///
/// # Memory Layout
///
/// - Size: ~48 bytes (16-byte IpAddr + 6-byte MAC + 8-byte Instant + status + padding)
/// - No raw pointers unlike C version's `next` field
/// - Automatic memory management via Vec ownership
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::network::arp::{ArpRecord, ArpStatus};
/// use dnsmasq::types::MacAddress;
///
/// let record = ArpRecord {
///     ip: "192.168.1.100".parse()?,
///     mac: Some(MacAddress::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
///     status: ArpStatus::Found,
///     last_seen: Instant::now(),
/// };
/// ```
#[derive(Debug, Clone)]
struct ArpRecord {
    /// IP address (IPv4 or IPv6).
    ///
    /// Rust's `IpAddr` enum provides type-safe address handling, replacing C's `union all_addr`
    /// with compile-time discrimination between IPv4 and IPv6.
    ip: IpAddr,

    /// Hardware MAC address (6 bytes for Ethernet).
    ///
    /// `None` represents ARP_EMPTY state (IP known but no MAC address available yet).
    /// `Some(MacAddress)` represents entries with confirmed MAC addresses.
    mac: Option<MacAddress>,

    /// Cache entry lifecycle status.
    ///
    /// Tracks entry state during cache refresh algorithm: Mark → Found/New or removal.
    status: ArpStatus,

    /// Timestamp when entry was last confirmed in kernel ARP table.
    ///
    /// Used for cache aging and staleness detection, though current implementation relies
    /// on kernel table synchronization rather than entry-level TTLs.
    last_seen: Instant,
}

/// ARP/Neighbor cache providing MAC address lookup and network topology tracking.
///
/// Maintains an internal cache of IP-to-MAC address mappings synchronized with the kernel's
/// ARP (IPv4) and neighbor (IPv6) tables. Provides the primary interface for DHCP code to
/// perform address-in-use testing and client identification.
///
/// Replaces C implementation's global static variables (src/arp.c lines 123-124):
///
/// ```c
/// static struct arp_record *arps = NULL, *old = NULL, *freelist = NULL;
/// static time_t last = 0;
/// ```
///
/// With memory-safe Rust struct managing all cache state:
///
/// - `arps` linked list → `entries: Vec<ArpRecord>`
/// - `old` linked list → handled during `notify_changes()` processing
/// - `freelist` → eliminated (Vec handles memory reuse automatically)
/// - `last` timestamp → `last_refresh: Instant`
///
/// # Concurrency Model
///
/// Designed to be wrapped in `Arc<RwLock<ArpCache>>` for shared access:
///
/// - **Read Access**: Multiple DHCP worker tasks can call `find_mac()` concurrently
/// - **Write Access**: Single periodic refresh task updates cache via `update_from_kernel()`
/// - **Platform Access**: `Arc<dyn NetworkPlatform>` allows shared platform handler
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::network::arp::ArpCache;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
///
/// // Create cache with platform handler
/// let cache = Arc::new(RwLock::new(
///     ArpCache::new(platform, config, helper)
/// ));
///
/// // Background refresh task
/// let cache_clone = cache.clone();
/// tokio::spawn(async move {
///     loop {
///         tokio::time::sleep(Duration::from_secs(90)).await;
///         cache_clone.write().await.update_from_kernel().await.ok();
///     }
/// });
/// ```
pub struct ArpCache {
    /// Vector of active cache entries mapping IP addresses to MAC addresses.
    ///
    /// Replaces C's `arps` linked list with dynamic Vec providing:
    /// - Automatic memory management (no manual malloc/free)
    /// - Cache locality for linear search performance
    /// - Safe bounds checking for all accesses
    entries: Vec<ArpRecord>,

    /// Timestamp of last kernel ARP table refresh.
    ///
    /// Compared against current time to determine if cache needs refreshing. Cache is
    /// considered fresh if `now - last_refresh < 90 seconds`.
    last_refresh: Instant,

    /// Platform-specific network handler for kernel ARP table access.
    ///
    /// Provides `enumerate_arp_entries()` method abstracting Linux netlink, BSD routing
    /// sockets, and macOS sysctl interfaces.
    platform: Arc<dyn NetworkPlatform>,

    /// Global configuration for script notification control.
    ///
    /// Used to check `config.enable_arp_script` before triggering helper script execution
    /// for ARP topology changes.
    config: Arc<Config>,

    /// Helper process handle for script execution.
    ///
    /// Wrapped in Arc<RwLock> to allow shared access from cache and potentially other
    /// components that queue script events.
    helper: Arc<RwLock<crate::util::helpers::HelperProcess>>,

    /// Entries pending deletion notification.
    ///
    /// Accumulates entries removed during cache refresh that need script notification.
    /// Processed incrementally by `notify_changes()` to avoid blocking event loop.
    pending_deletions: Vec<ArpRecord>,
}

impl ArpCache {
    /// Creates a new ARP cache instance with empty initial state.
    ///
    /// Initializes the cache with no entries and sets last refresh time to "beginning of time"
    /// to force immediate kernel synchronization on first `find_mac()` call.
    ///
    /// # Arguments
    ///
    /// * `platform` - Platform-specific network handler for kernel ARP table access
    /// * `config` - Global configuration containing `enable_arp_script` setting
    /// * `helper` - Helper process handle for script execution
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::network::arp::ArpCache;
    /// use dnsmasq::network::platform::create_platform_handler;
    ///
    /// let platform = create_platform_handler().await?;
    /// let cache = ArpCache::new(platform, config, helper);
    /// ```
    pub fn new(
        platform: Arc<dyn NetworkPlatform>,
        config: Arc<Config>,
        helper: Arc<RwLock<crate::util::helpers::HelperProcess>>,
    ) -> Self {
        Self {
            entries: Vec::new(),
            last_refresh: Instant::now() - Duration::from_secs(ARP_CACHE_REFRESH_INTERVAL_SECS + 1),
            platform,
            config,
            helper,
            pending_deletions: Vec::new(),
        }
    }

    /// Looks up hardware MAC address for given IP address with automatic kernel cache refresh.
    ///
    /// This is the primary public API for MAC address lookup, used extensively by DHCP code
    /// for address-in-use testing and client identification. Implements a two-tier lookup
    /// strategy matching C implementation's `find_mac()` (src/arp.c lines 300-393):
    ///
    /// 1. If cache is fresh (last refresh < 90 seconds ago), consult internal cache
    /// 2. If not found or cache stale, trigger kernel ARP table reload via platform handler
    ///
    /// # Negative Caching
    ///
    /// The `lazy` parameter controls negative caching behavior:
    ///
    /// - **lazy = false**: Reject ARP_EMPTY entries (no MAC address), force kernel refresh
    /// - **lazy = true**: Accept ARP_EMPTY entries as negative cache hits (prevents repeated
    ///   kernel queries for non-existent mappings)
    ///
    /// If no MAC address found after kernel refresh, creates ARP_EMPTY entry to cache the
    /// negative result.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address to lookup (IPv4 or IPv6)
    /// * `lazy` - Accept negative cache entries if true
    ///
    /// # Returns
    ///
    /// - `Some(MacAddress)` if mapping exists in kernel ARP table
    /// - `None` if no ARP/neighbor entry exists for this IP address
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if kernel ARP table enumeration fails due to permissions,
    /// system call failure, or platform-specific API errors.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::network::arp::ArpCache;
    ///
    /// // Strict lookup (no negative caching) for DHCP address conflict detection
    /// let ip: IpAddr = "192.168.1.100".parse()?;
    /// if let Some(mac) = cache.find_mac(&ip, false).await? {
    ///     warn!("IP {} already in use by MAC {}", ip, mac);
    ///     return Err(DhcpError::AddressInUse);
    /// }
    ///
    /// // Lazy lookup (accept negative cache) for routine client identification
    /// let mac = cache.find_mac(&ip, true).await?;
    /// ```
    #[instrument(skip(self), fields(ip = %ip, lazy = lazy))]
    pub async fn find_mac(&mut self, ip: &IpAddr, lazy: bool) -> Result<Option<MacAddress>, NetworkError> {
        let now = Instant::now();
        let cache_age = now.duration_since(self.last_refresh);

        // Check if cache needs refresh
        if cache_age >= Duration::from_secs(ARP_CACHE_REFRESH_INTERVAL_SECS) {
            debug!("ARP cache stale (age: {:?}), refreshing from kernel", cache_age);
            self.update_from_kernel().await?;
        }

        // Search internal cache for matching entry
        for entry in &self.entries {
            if &entry.ip != ip {
                continue;
            }

            match entry.status {
                ArpStatus::Empty if !lazy => {
                    // Non-lazy mode: reject negative cache, will create new empty entry below
                    debug!("Found ARP_EMPTY entry for {} in non-lazy mode, treating as cache miss", ip);
                    continue;
                }
                ArpStatus::Empty => {
                    // Lazy mode: accept negative cache result
                    debug!("Found ARP_EMPTY entry for {} in lazy mode, returning None", ip);
                    return Ok(None);
                }
                _ => {
                    // Return MAC address if available
                    debug!("Found ARP entry for {}: mac={:?}, status={:?}", ip, entry.mac, entry.status);
                    return Ok(entry.mac);
                }
            }
        }

        // Not found in cache - create negative cache entry to prevent repeated kernel queries
        debug!("No ARP entry found for {}, creating ARP_EMPTY entry", ip);
        self.entries.push(ArpRecord {
            ip: *ip,
            mac: None,
            status: ArpStatus::Empty,
            last_seen: now,
        });

        Ok(None)
    }

    /// Synchronizes internal cache with kernel ARP/neighbor table using three-phase algorithm.
    ///
    /// Implements the cache update algorithm from C's `find_mac()` (src/arp.c lines 338-366):
    ///
    /// 1. **Mark Phase**: Set all non-empty entries to `ArpStatus::Mark`
    /// 2. **Enumerate Phase**: Query kernel table via `platform.enumerate_arp_entries()`:
    ///    - Update existing entries: `Mark` → `Found` (if MAC matches) or `New` (if changed)
    ///    - Promote empty entries: `Empty` → `New` (if MAC now available)
    ///    - Create new entries with `ArpStatus::New` for unknown IPs
    /// 3. **Cleanup Phase**: Move all still-marked entries to `pending_deletions` queue
    ///
    /// # Platform-Specific Behavior
    ///
    /// - **Linux**: Uses rtnetlink RTM_GETNEIGH to enumerate neighbor table
    /// - **BSD**: Uses routing socket RTM_GET with RTF_LLINFO flag
    /// - **macOS**: Uses sysctl NET_RT_FLAGS with RTF_LLINFO
    ///
    /// # Errors
    ///
    /// Returns `NetworkError::RoutingFailed` if kernel ARP table cannot be read due to:
    /// - Insufficient permissions (requires CAP_NET_ADMIN on Linux)
    /// - System call failure
    /// - Platform-specific API errors
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Periodic refresh task
    /// let mut interval = tokio::time::interval(Duration::from_secs(90));
    /// loop {
    ///     interval.tick().await;
    ///     if let Err(e) = cache.update_from_kernel().await {
    ///         error!("ARP cache refresh failed: {}", e);
    ///     }
    /// }
    /// ```
    #[instrument(skip(self))]
    pub async fn update_from_kernel(&mut self) -> Result<(), NetworkError> {
        let now = Instant::now();
        info!("Starting ARP cache refresh from kernel");

        // Phase 1: Mark all non-empty entries
        let mut marked_count = 0;
        for entry in &mut self.entries {
            if entry.status != ArpStatus::Empty {
                entry.status = ArpStatus::Mark;
                marked_count += 1;
            }
        }
        debug!("Marked {} non-empty entries for refresh validation", marked_count);

        // Phase 2: Enumerate kernel ARP table and update cache
        let kernel_entries = self.platform.enumerate_arp_entries().await
            .map_err(|e| {
                error!("Failed to enumerate kernel ARP table: {}", e);
                NetworkError::RoutingFailed {
                    operation: "enumerate_arp_entries".to_string(),
                    reason: e.to_string(),
                }
            })?;

        debug!("Enumerated {} entries from kernel ARP table", kernel_entries.len());

        let mut found_count = 0;
        let mut new_count = 0;
        let mut updated_count = 0;

        for (kernel_ip, kernel_mac_bytes) in kernel_entries {
            let kernel_mac = MacAddress::from_bytes(kernel_mac_bytes);

            // Search for existing entry with matching IP
            let mut entry_found = false;
            for entry in &mut self.entries {
                if entry.ip != kernel_ip {
                    continue;
                }

                // Skip entries already marked as new in this refresh cycle
                if entry.status == ArpStatus::New {
                    entry_found = true;
                    continue;
                }

                entry_found = true;

                if entry.status == ArpStatus::Empty {
                    // Empty entry now has MAC address - promote to new
                    debug!("Empty entry for {} now has MAC {}, promoting to New", kernel_ip, kernel_mac);
                    entry.mac = Some(kernel_mac);
                    entry.status = ArpStatus::New;
                    entry.last_seen = now;
                    new_count += 1;
                } else if let Some(ref existing_mac) = entry.mac {
                    if existing_mac.octets() == kernel_mac.octets() {
                        // MAC matches - confirm entry
                        entry.status = ArpStatus::Found;
                        entry.last_seen = now;
                        found_count += 1;
                    } else {
                        // MAC changed - mark as new
                        debug!("MAC changed for {}: {} -> {}, marking as New", 
                            kernel_ip, existing_mac, kernel_mac);
                        entry.mac = Some(kernel_mac);
                        entry.status = ArpStatus::New;
                        entry.last_seen = now;
                        updated_count += 1;
                    }
                }

                break;
            }

            // No existing entry - create new one
            if !entry_found {
                debug!("New ARP entry discovered: {} -> {}", kernel_ip, kernel_mac);
                self.entries.push(ArpRecord {
                    ip: kernel_ip,
                    mac: Some(kernel_mac),
                    status: ArpStatus::New,
                    last_seen: now,
                });
                new_count += 1;
            }
        }

        info!("ARP cache refresh complete: {} confirmed, {} new, {} updated", 
            found_count, new_count, updated_count);

        // Phase 3: Remove unconfirmed entries (still marked)
        let mut removed_count = 0;
        self.entries.retain(|entry| {
            if entry.status == ArpStatus::Mark {
                // Entry not found in kernel - schedule for deletion notification
                debug!("ARP entry disappeared: {} -> {:?}", entry.ip, entry.mac);
                self.pending_deletions.push(entry.clone());
                removed_count += 1;
                false
            } else {
                true
            }
        });

        if removed_count > 0 {
            info!("Removed {} disappeared ARP entries", removed_count);
        }

        self.last_refresh = now;
        Ok(())
    }

    /// Processes pending ARP cache changes and triggers external script notifications.
    ///
    /// Implements incremental notification processing matching C's `do_arp_script_run()`
    /// (src/arp.c lines 445-475). Each invocation processes at most one pending change:
    ///
    /// 1. If deletion queue not empty: notify one deletion (ACTION_ARP_DEL)
    /// 2. Else if entries have `ArpStatus::New`: notify one addition (ACTION_ARP), promote to `Found`
    /// 3. Else: all notifications complete, return false
    ///
    /// This incremental design prevents blocking the event loop during large topology changes
    /// by processing one notification per call.
    ///
    /// # Script Notification Control
    ///
    /// Notifications only occur if `config.enable_arp_script` is true (matching C's
    /// `option_bool(OPT_SCRIPT_ARP)` check). When disabled, entries are processed but no
    /// scripts executed.
    ///
    /// # Return Value
    ///
    /// - `true`: More changes pending, call again
    /// - `false`: All notifications complete
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if helper script queueing fails (channel closed, process dead).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Process all pending notifications incrementally
    /// while cache.notify_changes().await? {
    ///     // Allow other event loop tasks to run
    ///     tokio::task::yield_now().await;
    /// }
    /// ```
    #[instrument(skip(self))]
    pub async fn notify_changes(&mut self) -> Result<bool, NetworkError> {
        // Process deletion notifications first
        if let Some(deleted_entry) = self.pending_deletions.pop() {
            if self.config.scripts.enable_arp_script {
                if let Some(mac) = deleted_entry.mac {
                    info!("Notifying script: device disappeared - {} ({})", deleted_entry.ip, mac);
                    let helper = self.helper.read().await;
                    queue_arp(&helper, mac, deleted_entry.ip, false)
                        .map_err(|e| {
                            error!("Failed to queue ARP deletion script: {}", e);
                            NetworkError::RoutingFailed {
                                operation: "queue_arp_deletion".to_string(),
                                reason: e.to_string(),
                            }
                        })?;
                }
            }
            return Ok(true); // More deletions may remain
        }

        // Process new entry notifications
        for entry in &mut self.entries {
            if entry.status == ArpStatus::New {
                if self.config.scripts.enable_arp_script {
                    if let Some(ref mac) = entry.mac {
                        info!("Notifying script: new device discovered - {} ({})", entry.ip, mac);
                        let helper = self.helper.read().await;
                        queue_arp(&helper, *mac, entry.ip, true)
                            .map_err(|e| {
                                error!("Failed to queue ARP addition script: {}", e);
                                NetworkError::RoutingFailed {
                                    operation: "queue_arp_addition".to_string(),
                                    reason: e.to_string(),
                                }
                            })?;
                    }
                }
                entry.status = ArpStatus::Found;
                return Ok(true); // More new entries may remain
            }
        }

        // All notifications complete
        debug!("All ARP change notifications processed");
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_status_transitions() {
        let mut status = ArpStatus::Mark;
        assert_eq!(status, ArpStatus::Mark);

        status = ArpStatus::Found;
        assert_eq!(status, ArpStatus::Found);

        status = ArpStatus::New;
        assert_eq!(status, ArpStatus::New);
    }

    #[test]
    fn test_arp_record_creation() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let mac = MacAddress::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let record = ArpRecord {
            ip,
            mac: Some(mac),
            status: ArpStatus::Found,
            last_seen: Instant::now(),
        };

        assert_eq!(record.ip, ip);
        assert_eq!(record.mac.unwrap().octets(), mac.octets());
        assert_eq!(record.status, ArpStatus::Found);
    }
}
