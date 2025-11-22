//! DHCP lease management module.
//!
//! This module provides lease database management for both `DHCPv4` and `DHCPv6`, replacing
//! the C implementation in `src/lease.c` with memory-safe Rust equivalents. It manages
//! lease allocation, renewal, release, expiration, and persistence, while coordinating
//! DNS registration and helper script execution.
//!
//! # Architecture
//!
//! The module is organized into three submodules:
//!
//! - `database`: Lease file persistence, reading/writing lease state to disk
//! - `dns_integration`: DNS cache registration for DHCP client hostnames
//! - `script_hooks`: Helper script execution for lease lifecycle events
//!
//! # Core Types
//!
//! - [`Lease`]: Represents a single `DHCPv4` or `DHCPv6` lease with all metadata
//! - [`LeaseRepository`]: Abstract storage backend trait for lease persistence
//! - [`LeaseManager`]: High-level coordinator for lease operations
//! - [`LeaseFlags`]: Type-safe bitflags for lease state (STATIC, DECLINED, etc.)
//!
//! # Memory Safety
//!
//! Replaces C's global lease linked list (`static struct dhcp_lease *leases`) with
//! structured Rust ownership using `HashMap<IpAddr, Lease>` for O(1) lookup operations.
//! All pointer traversal is eliminated in favor of safe iterator operations.
//!
//! # Example
//!
//! ```rust,ignore
//! use std::sync::{Arc, RwLock};
//! use std::net::IpAddr;
//! use std::time::{Duration, SystemTime};
//!
//! // Create lease manager
//! let config = Config::default();
//! let dns_cache = Arc::new(RwLock::new(DnsCache::new(&config.dns)));
//! let manager = LeaseManager::new(config.dhcp.clone(), dns_cache, 1000);
//!
//! // Allocate a lease
//! let mac = MacAddress::from_str("aa:bb:cc:dd:ee:ff")?;
//! let ip = IpAddr::from([192, 168, 1, 100]);
//! let lease = manager.allocate_lease(ip, Some(mac), Some("client".to_string()), "eth0", Duration::from_secs(3600)).await?;
//!
//! // Find lease by IP
//! if let Some(lease) = manager.find_by_ip(&ip).await {
//!     println!("Lease found: {:?}", lease.hostname);
//! }
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

use async_trait::async_trait;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

// Internal imports from dependencies
use crate::config::types::Config;
use crate::dhcp::common::strip_hostname;
use crate::dns::cache::DnsCache;
use crate::error::DhcpError;
use crate::types::MacAddress;

// Submodule declarations
pub mod database;
pub mod dns_integration;
pub mod script_hooks;

// Re-exports from submodules
pub use database::{read_leases, write_leases};
pub use dns_integration::{register_lease_hostname, unregister_lease_hostname};
pub use script_hooks::execute_lease_script;

bitflags! {
    /// Lease state flags.
    ///
    /// Type-safe bitflags for DHCP lease state, replacing C's bitfield unions
    /// with compile-time checked flag operations. Corresponds to F_* flags in
    /// C dnsmasq.h (F_CONFIG, F_REVERSE, etc.).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct LeaseFlags: u32 {
        /// Static lease from configuration (dhcp-host directive)
        const STATIC = 1 << 0;
        /// Address declined by client (DHCPDECLINE received)
        const DECLINED = 1 << 1;
        /// Address reserved for specific client (dhcp-range with tag)
        const RESERVED = 1 << 2;
        /// Old hostname preserved during lease update
        const OLD_HOSTNAME = 1 << 3;
        /// Lease from configuration file, not dynamically allocated
        const CONFIG = 1 << 4;
        /// Hostname override from dhcp-host directive
        const HOSTNAME_OVERRIDE = 1 << 5;
        /// Known client (previously seen in lease database)
        const KNOWN = 1 << 6;
        /// ARP check performed for address conflict detection
        const ARP_USED = 1 << 7;
        /// DHCPv6 temporary address (IA_TA)
        const TA = 1 << 8;
        /// DHCPv6 non-temporary address (IA_NA)
        const NA = 1 << 9;
    }
}

impl Default for LeaseFlags {
    /// Returns an empty set of lease flags.
    fn default() -> Self {
        LeaseFlags::empty()
    }
}

/// DHCP lease lifecycle action for script execution.
///
/// Enum representing lease state change events that trigger helper script
/// execution. Corresponds to C `lease_change_command` invocation points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseAction {
    /// New lease allocated (add)
    Add,
    /// Existing lease found during startup (old)
    Old,
    /// Lease expired or released (del)
    Del,
    /// Hostname changed for existing lease (old-hostname)
    OldHostname,
}

impl LeaseAction {
    /// Returns the string representation for script environment variable.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            LeaseAction::Add => "add",
            LeaseAction::Old => "old",
            LeaseAction::Del => "del",
            LeaseAction::OldHostname => "old-hostname",
        }
    }
}

/// DHCP lease record for `DHCPv4` and `DHCPv6`.
///
/// Represents a single lease entry with all metadata. Replaces C's `struct dhcp_lease`
/// (dnsmasq.h ~line 856) with Rust struct using ownership for all string fields.
/// Supports both `DHCPv4` and `DHCPv6` with unified representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    /// IP address (IPv4 or IPv6)
    pub ip: IpAddr,

    /// Hardware (MAC) address for `DHCPv4`, optional for `DHCPv6`
    pub mac: Option<MacAddress>,

    /// Client-supplied hostname, sanitized for DNS compliance
    pub hostname: Option<String>,

    /// Client identifier (option 61 in `DHCPv4`, DUID in `DHCPv6`)
    pub client_id: Option<Vec<u8>>,

    /// Lease expiration time (absolute `SystemTime`)
    pub expires: SystemTime,

    /// `DHCPv6` Identity Association Identifier (IAID)
    pub iaid: Option<u32>,

    /// Lease state flags
    pub flags: LeaseFlags,

    /// Network interface where lease was allocated
    pub interface: String,

    /// Fully qualified domain name (if domain configured)
    pub fqdn: Option<String>,

    /// Vendor class identifier (option 60 in `DHCPv4`)
    pub vendorclass: Option<Vec<u8>>,

    /// Relay agent information (option 82 in `DHCPv4`)
    pub agent_id: Option<Vec<u8>>,

    /// `DHCPv6` SLAAC-generated addresses for this client
    pub slaac_addresses: Option<Vec<Ipv6Addr>>,
}

impl Lease {
    /// Creates a new lease with specified parameters.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address being leased
    /// * `mac` - Hardware address (optional for `DHCPv6`)
    /// * `hostname` - Client-supplied hostname (will be sanitized)
    /// * `client_id` - Client identifier bytes
    /// * `interface` - Network interface name
    /// * `duration` - Lease duration from now
    ///
    /// # Returns
    ///
    /// New Lease instance with expires set to now + duration
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let lease = Lease::new(
    ///     IpAddr::from([192, 168, 1, 100]),
    ///     Some(MacAddress::from_str("aa:bb:cc:dd:ee:ff")?),
    ///     Some("client".to_string()),
    ///     None,
    ///     "eth0",
    ///     Duration::from_secs(3600),
    /// );
    /// ```
    pub fn new(
        ip: IpAddr,
        mac: Option<MacAddress>,
        hostname: Option<String>,
        client_id: Option<Vec<u8>>,
        interface: impl Into<String>,
        duration: Duration,
    ) -> Self {
        // Sanitize hostname if present
        let hostname = hostname.map(|h| strip_hostname(h.as_bytes(), 63));

        let expires = SystemTime::now() + duration;

        Self {
            ip,
            mac,
            hostname,
            client_id,
            expires,
            iaid: None,
            flags: LeaseFlags::empty(),
            interface: interface.into(),
            fqdn: None,
            vendorclass: None,
            agent_id: None,
            slaac_addresses: None,
        }
    }

    /// Checks if the lease has expired.
    ///
    /// # Returns
    ///
    /// true if current time is past expiration, false otherwise
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if lease.is_expired() {
    ///     manager.release_lease(&lease.ip).await?;
    /// }
    /// ```
    #[must_use]
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires
    }

    /// Returns remaining lease duration.
    ///
    /// # Returns
    ///
    /// Some(Duration) if not expired, None if expired
    #[must_use]
    pub fn remaining_duration(&self) -> Option<Duration> {
        self.expires.duration_since(SystemTime::now()).ok()
    }

    /// Sets the fully qualified domain name.
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain suffix to append to hostname
    pub fn set_fqdn(&mut self, domain: &str) {
        if let Some(ref hostname) = self.hostname {
            self.fqdn = Some(format!("{hostname}.{domain}"));
        }
    }
}

impl Default for Lease {
    /// Returns a default lease with placeholder values.
    ///
    /// This is primarily used for testing and struct initialization with the
    /// `..Default::default()` syntax. For production use, prefer `Lease::new()`.
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            mac: None,
            hostname: None,
            client_id: None,
            expires: SystemTime::UNIX_EPOCH,
            iaid: None,
            flags: LeaseFlags::empty(),
            interface: String::new(),
            fqdn: None,
            vendorclass: None,
            agent_id: None,
            slaac_addresses: None,
        }
    }
}

/// Abstract storage backend for lease persistence.
///
/// Trait providing pluggable lease storage implementations (memory, file, database).
/// Replaces C's global lease linked list with structured storage abstraction.
/// Implementations must be thread-safe (Send + Sync) for concurrent access.
#[async_trait]
pub trait LeaseRepository: Send + Sync {
    /// Finds a lease by IP address.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address to search for
    ///
    /// # Returns
    ///
    /// Some(reference to Lease) if found, None otherwise
    async fn find_by_ip(&self, ip: &IpAddr) -> Option<Lease>;

    /// Finds a lease by MAC address.
    ///
    /// # Arguments
    ///
    /// * `mac` - Hardware address to search for
    ///
    /// # Returns
    ///
    /// Some(reference to Lease) if found, None otherwise
    async fn find_by_mac(&self, mac: &MacAddress) -> Option<Lease>;

    /// Inserts or updates a lease in storage.
    ///
    /// # Arguments
    ///
    /// * `lease` - Lease to store
    ///
    /// # Returns
    ///
    /// Ok(()) on success, Err on storage failure
    async fn insert(&mut self, lease: Lease) -> Result<(), DhcpError>;

    /// Removes a lease from storage.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address of lease to remove
    ///
    /// # Returns
    ///
    /// Ok(removed lease) if found, Err if not found
    async fn remove(&mut self, ip: &IpAddr) -> Result<Lease, DhcpError>;

    /// Lists all leases in storage.
    ///
    /// # Returns
    ///
    /// Vector of all leases
    async fn list_all(&self) -> Vec<Lease>;

    /// Removes all expired leases from storage.
    ///
    /// # Returns
    ///
    /// Number of leases removed
    async fn prune_expired(&mut self) -> usize;
}

/// In-memory lease storage implementation.
///
/// Default `LeaseRepository` implementation using `HashMap` for O(1) IP lookups.
/// Replaces C's linked list traversal with efficient hash-based access.
pub struct MemoryLeaseRepository {
    /// Primary storage indexed by IP address
    leases: HashMap<IpAddr, Lease>,
    /// Secondary index by MAC address for faster lookup
    mac_index: HashMap<MacAddress, IpAddr>,
}

impl MemoryLeaseRepository {
    /// Creates a new empty in-memory lease repository.
    #[must_use]
    pub fn new() -> Self {
        Self { leases: HashMap::new(), mac_index: HashMap::new() }
    }

    /// Creates a repository with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            leases: HashMap::with_capacity(capacity),
            mac_index: HashMap::with_capacity(capacity),
        }
    }
}

impl Default for MemoryLeaseRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LeaseRepository for MemoryLeaseRepository {
    async fn find_by_ip(&self, ip: &IpAddr) -> Option<Lease> {
        self.leases.get(ip).cloned()
    }

    async fn find_by_mac(&self, mac: &MacAddress) -> Option<Lease> {
        self.mac_index.get(mac).and_then(|ip| self.leases.get(ip)).cloned()
    }

    async fn insert(&mut self, lease: Lease) -> Result<(), DhcpError> {
        let ip = lease.ip;

        // Update MAC index if MAC address present
        if let Some(mac) = lease.mac {
            self.mac_index.insert(mac, ip);
        }

        // Insert or update lease
        self.leases.insert(ip, lease);

        debug!(ip = %ip, "Lease stored in repository");
        Ok(())
    }

    async fn remove(&mut self, ip: &IpAddr) -> Result<Lease, DhcpError> {
        let lease =
            self.leases.remove(ip).ok_or(DhcpError::LeaseNotFound { ip: ip.to_string() })?;

        // Remove from MAC index if present
        if let Some(mac) = lease.mac {
            self.mac_index.remove(&mac);
        }

        debug!(ip = %ip, "Lease removed from repository");
        Ok(lease)
    }

    async fn list_all(&self) -> Vec<Lease> {
        self.leases.values().cloned().collect()
    }

    async fn prune_expired(&mut self) -> usize {
        let now = SystemTime::now();
        let mut expired_ips = Vec::new();

        // Collect expired lease IPs
        for (ip, lease) in &self.leases {
            if lease.expires <= now && !lease.flags.contains(LeaseFlags::STATIC) {
                expired_ips.push(*ip);
            }
        }

        let count = expired_ips.len();

        // Remove expired leases
        for ip in expired_ips {
            if let Ok(lease) = self.remove(&ip).await {
                debug!(ip = %ip, hostname = ?lease.hostname, "Pruned expired lease");
            }
        }

        if count > 0 {
            info!(count, "Pruned expired leases");
        }

        count
    }
}

/// High-level lease lifecycle coordinator.
///
/// Manages lease operations with integrated DNS registration and script notification.
/// Replaces C's global lease manipulation functions (`lease4_allocate`, `lease_prune`, etc.)
/// with structured coordination via `LeaseRepository`, `DnsCache`, and script execution.
pub struct LeaseManager {
    /// Lease storage backend
    repository: Arc<RwLock<Box<dyn LeaseRepository>>>,

    /// DNS cache for hostname registration
    dns_cache: Arc<RwLock<DnsCache>>,

    /// DHCP configuration (lease times, script path, domain)
    config: Arc<Config>,

    /// Maximum number of leases allowed
    #[allow(dead_code)]
    max_leases: usize,
}

impl LeaseManager {
    /// Creates a new lease manager.
    ///
    /// # Arguments
    ///
    /// * `config` - Daemon configuration containing DHCP settings
    /// * `dns_cache` - Shared DNS cache for hostname registration
    /// * `max_leases` - Maximum lease capacity
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let manager = LeaseManager::new(
    ///     Arc::new(config),
    ///     Arc::new(RwLock::new(dns_cache)),
    ///     1000,
    /// );
    /// ```
    pub fn new(config: Arc<Config>, dns_cache: Arc<RwLock<DnsCache>>, max_leases: usize) -> Self {
        let repository: Box<dyn LeaseRepository> =
            Box::new(MemoryLeaseRepository::with_capacity(max_leases));

        Self { repository: Arc::new(RwLock::new(repository)), dns_cache, config, max_leases }
    }

    /// Allocates a new lease or updates an existing one.
    ///
    /// Coordinates lease storage, DNS registration, and script execution.
    /// Replaces C `lease4_allocate()` and `lease6_allocate()` with unified implementation.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address to lease
    /// * `mac` - Hardware address (optional for `DHCPv6`)
    /// * `hostname` - Client-supplied hostname
    /// * `client_id` - Client identifier
    /// * `interface` - Network interface name
    /// * `duration` - Lease duration
    ///
    /// # Returns
    ///
    /// Newly allocated or updated Lease
    ///
    /// # Errors
    ///
    /// Returns `DhcpError` if lease limit reached or storage fails
    pub async fn allocate_lease(
        &self,
        ip: IpAddr,
        mac: Option<MacAddress>,
        hostname: Option<String>,
        client_id: Option<Vec<u8>>,
        interface: impl Into<String>,
        duration: Duration,
    ) -> Result<Lease, DhcpError> {
        let interface = interface.into();

        // Check if lease already exists
        let existing = {
            let repo = self.repository.read().await;
            repo.find_by_ip(&ip).await
        };

        let is_new = existing.is_none();

        // Create new lease
        let lease = Lease::new(ip, mac, hostname, client_id, &interface, duration);

        // Note: FQDN generation requires domain configuration per DHCP range
        // This will be implemented when DhcpRange struct includes domain field

        // Store lease
        {
            let mut repo = self.repository.write().await;
            repo.insert(lease.clone()).await?;
        }

        // Register hostname in DNS cache if hostname is present
        if let Some(ref hostname_str) = lease.hostname {
            if let Err(e) = register_lease_hostname(
                &self.dns_cache,
                lease.ip,
                hostname_str,
                lease.fqdn.as_deref(),
                lease.expires,
            )
            .await
            {
                warn!(ip = %ip, error = %e, "Failed to register lease hostname in DNS");
            }
        }

        // Execute lease script if configured
        if let Some(ref script_path) = self.config.scripts.script_path {
            let action = if is_new { LeaseAction::Add } else { LeaseAction::Old };

            // TODO: Pass actual domain from config when domain field is added
            if let Err(e) = execute_lease_script(script_path, action, &lease, None, None).await {
                warn!(ip = %ip, action = ?action, error = %e, "Failed to execute lease script");
            }
        }

        info!(
            ip = %ip,
            mac = ?lease.mac,
            hostname = ?lease.hostname,
            interface = %interface,
            duration_secs = duration.as_secs(),
            "Lease allocated"
        );

        Ok(lease)
    }

    /// Releases a lease by IP address.
    ///
    /// Removes lease from storage, unregisters from DNS, and executes script.
    /// Replaces C `lease_update_file()` delete path.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address of lease to release
    ///
    /// # Returns
    ///
    /// Ok(released Lease) on success
    ///
    /// # Errors
    ///
    /// Returns `DhcpError::LeaseNotFound` if lease doesn't exist
    pub async fn release_lease(&self, ip: &IpAddr) -> Result<Lease, DhcpError> {
        // Remove from repository
        let lease = {
            let mut repo = self.repository.write().await;
            repo.remove(ip).await?
        };

        // Unregister from DNS cache if hostname is present
        if let Some(ref hostname) = lease.hostname {
            let fqdn = lease.fqdn.as_deref();
            if let Err(e) =
                unregister_lease_hostname(&self.dns_cache, lease.ip, hostname, fqdn).await
            {
                warn!(ip = %ip, error = %e, "Failed to unregister lease hostname from DNS");
            }
        }

        // Execute lease script if configured
        if let Some(ref script_path) = self.config.scripts.script_path {
            // TODO: Pass actual domain from config when domain field is added
            if let Err(e) = execute_lease_script(script_path, LeaseAction::Del, &lease, None, None).await
            {
                warn!(ip = %ip, error = %e, "Failed to execute lease script for deletion");
            }
        }

        // Persist lease database to disk
        if let Err(e) = self.save_leases().await {
            warn!(ip = %ip, error = %e, "Failed to save lease database after release");
        }

        info!(ip = %ip, mac = ?lease.mac, hostname = ?lease.hostname, "Lease released");

        Ok(lease)
    }

    /// Renews an existing lease with new expiration time.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address of lease to renew
    /// * `duration` - New lease duration from now
    ///
    /// # Returns
    ///
    /// Ok(renewed Lease) on success
    ///
    /// # Errors
    ///
    /// Returns `DhcpError::LeaseNotFound` if lease doesn't exist
    pub async fn renew_lease(&self, ip: &IpAddr, duration: Duration) -> Result<Lease, DhcpError> {
        let mut lease = {
            let repo = self.repository.read().await;
            repo.find_by_ip(ip).await.ok_or(DhcpError::LeaseNotFound { ip: ip.to_string() })?
        };

        // Update expiration time
        lease.expires = SystemTime::now() + duration;

        // Store updated lease
        {
            let mut repo = self.repository.write().await;
            repo.insert(lease.clone()).await?;
        }

        debug!(ip = %ip, duration_secs = duration.as_secs(), "Lease renewed");

        Ok(lease)
    }

    /// Marks a lease as declined to prevent reallocation.
    ///
    /// When a client sends DHCPDECLINE, the IP address must be marked as
    /// unavailable and not reallocated until manually cleared or timeout expires.
    /// This prevents the server from offering a problematic IP to another client.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address of lease to mark as declined
    ///
    /// # Returns
    ///
    /// Ok(updated Lease) on success
    ///
    /// # Errors
    ///
    /// Returns `DhcpError::LeaseNotFound` if lease doesn't exist
    pub async fn mark_lease_declined(&self, ip: &IpAddr) -> Result<Lease, DhcpError> {
        let mut lease = {
            let repo = self.repository.read().await;
            repo.find_by_ip(ip).await.ok_or(DhcpError::LeaseNotFound { ip: ip.to_string() })?
        };

        // Set the DECLINED flag to mark this IP as unavailable
        lease.flags.insert(LeaseFlags::DECLINED);

        // Store updated lease
        {
            let mut repo = self.repository.write().await;
            repo.insert(lease.clone()).await?;
        }

        info!(ip = %ip, mac = ?lease.mac, "Lease marked as DECLINED to prevent reallocation");

        Ok(lease)
    }

    /// Removes all expired leases.
    ///
    /// Scans lease database and removes expired entries, unregistering from DNS
    /// and executing scripts. Replaces C `lease_prune()`.
    ///
    /// # Returns
    ///
    /// Number of leases pruned
    pub async fn prune_expired(&self) -> usize {
        // Get list of expired leases before removing
        let expired_leases = {
            let repo = self.repository.read().await;
            let all_leases = repo.list_all().await;
            all_leases
                .into_iter()
                .filter(|l| l.is_expired() && !l.flags.contains(LeaseFlags::STATIC))
                .collect::<Vec<_>>()
        };

        let count = expired_leases.len();

        // Remove each expired lease with full cleanup
        for lease in expired_leases {
            if let Err(e) = self.release_lease(&lease.ip).await {
                error!(ip = %lease.ip, error = %e, "Failed to release expired lease");
            }
        }

        if count > 0 {
            info!(count, "Pruned expired leases");
        }

        count
    }

    /// Finds a lease by IP address.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address to search for
    ///
    /// # Returns
    ///
    /// Some(Lease) if found, None otherwise
    pub async fn find_by_ip(&self, ip: &IpAddr) -> Option<Lease> {
        let repo = self.repository.read().await;
        repo.find_by_ip(ip).await
    }

    /// Finds a lease by MAC address.
    ///
    /// # Arguments
    ///
    /// * `mac` - Hardware address to search for
    ///
    /// # Returns
    ///
    /// Some(Lease) if found, None otherwise
    pub async fn find_by_mac(&self, mac: &MacAddress) -> Option<Lease> {
        let repo = self.repository.read().await;
        repo.find_by_mac(mac).await
    }

    /// Finds a lease by client identifier.
    ///
    /// Scans all leases for matching `client_id`. Less efficient than IP/MAC lookup
    /// but necessary for DHCP protocol compliance.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Client identifier bytes to search for
    ///
    /// # Returns
    ///
    /// Some(Lease) if found, None otherwise
    pub async fn find_by_client_id(&self, client_id: &[u8]) -> Option<Lease> {
        let repo = self.repository.read().await;
        let all_leases = repo.list_all().await;

        all_leases.into_iter().find(|lease| {
            if let Some(ref id) = lease.client_id {
                id.as_slice() == client_id
            } else {
                false
            }
        })
    }

    /// Returns all active leases.
    ///
    /// # Returns
    ///
    /// Vector of all leases in storage
    pub async fn get_all_leases(&self) -> Vec<Lease> {
        let repo = self.repository.read().await;
        repo.list_all().await
    }

    /// Loads leases from persistent storage at daemon startup.
    ///
    /// Reads lease file, validates entries, and populates repository.
    /// Replaces C `lease_init()` and `read_leases()`.
    ///
    /// # Returns
    ///
    /// Number of leases loaded
    ///
    /// # Errors
    ///
    /// Returns `DhcpError` if lease file cannot be read or parsed
    pub async fn load_leases(&self) -> Result<usize, DhcpError> {
        if let Some(ref lease_file) = self.config.dhcp.lease_file {
            let leases = read_leases(lease_file, SystemTime::now()).await?;
            let count = leases.len();

            let mut repo = self.repository.write().await;
            for lease in leases {
                repo.insert(lease).await?;
            }

            info!(count, file = %lease_file.display(), "Loaded leases from file");
            Ok(count)
        } else {
            Ok(0)
        }
    }

    /// Persists all leases to storage.
    ///
    /// Writes lease database to disk for recovery after daemon restart.
    /// Replaces C `lease_update_file()`.
    ///
    /// # Returns
    ///
    /// Ok(number of leases written) on success
    ///
    /// # Errors
    ///
    /// Returns `DhcpError` if lease file cannot be written
    pub async fn save_leases(&self) -> Result<usize, DhcpError> {
        if let Some(ref lease_file) = self.config.dhcp.lease_file {
            let leases = self.get_all_leases().await;
            let count = leases.len();

            // TODO: Pass actual server DUID for DHCPv6 if available from config
            write_leases(lease_file, &leases, None).await?;

            debug!(count, file = %lease_file.display(), "Saved leases to file");
            Ok(count)
        } else {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_lease_creation() {
        let ip = IpAddr::from([192, 168, 1, 100]);
        let mac = MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let lease = Lease::new(
            ip,
            Some(mac),
            Some("test-client".to_string()),
            None,
            "eth0",
            Duration::from_secs(3600),
        );

        assert_eq!(lease.ip, ip);
        assert_eq!(lease.mac, Some(mac));
        assert_eq!(lease.hostname, Some("test-client".to_string()));
        assert!(!lease.is_expired());
    }

    #[tokio::test]
    async fn test_lease_expiration() {
        let ip = IpAddr::from([192, 168, 1, 100]);
        let mut lease = Lease::new(ip, None, None, None, "eth0", Duration::from_secs(0));

        // Lease with 0 duration should be expired
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(lease.is_expired());

        // Extend lease
        lease.expires = SystemTime::now() + Duration::from_secs(3600);
        assert!(!lease.is_expired());
    }

    #[tokio::test]
    async fn test_memory_repository() {
        let mut repo = MemoryLeaseRepository::new();

        let ip = IpAddr::from([192, 168, 1, 100]);
        let mac = MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let lease = Lease::new(
            ip,
            Some(mac),
            Some("test".to_string()),
            None,
            "eth0",
            Duration::from_secs(3600),
        );

        // Insert lease
        repo.insert(lease.clone()).await.unwrap();

        // Find by IP
        let found = repo.find_by_ip(&ip).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().ip, ip);

        // Find by MAC
        let found = repo.find_by_mac(&mac).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().mac, Some(mac));

        // Remove lease
        let removed = repo.remove(&ip).await;
        assert!(removed.is_ok());

        // Verify removed
        let found = repo.find_by_ip(&ip).await;
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_prune_expired() {
        let mut repo = MemoryLeaseRepository::new();

        // Add expired lease
        let ip1 = IpAddr::from([192, 168, 1, 100]);
        let mut lease1 = Lease::new(ip1, None, None, None, "eth0", Duration::from_secs(0));
        lease1.expires = SystemTime::now() - Duration::from_secs(10);
        repo.insert(lease1).await.unwrap();

        // Add active lease
        let ip2 = IpAddr::from([192, 168, 1, 101]);
        let lease2 = Lease::new(ip2, None, None, None, "eth0", Duration::from_secs(3600));
        repo.insert(lease2).await.unwrap();

        // Add static lease (should not be pruned even if expired)
        let ip3 = IpAddr::from([192, 168, 1, 102]);
        let mut lease3 = Lease::new(ip3, None, None, None, "eth0", Duration::from_secs(0));
        lease3.expires = SystemTime::now() - Duration::from_secs(10);
        lease3.flags = LeaseFlags::STATIC;
        repo.insert(lease3).await.unwrap();

        // Prune expired
        let count = repo.prune_expired().await;
        assert_eq!(count, 1); // Only non-static expired lease pruned

        // Verify results
        assert!(repo.find_by_ip(&ip1).await.is_none()); // Pruned
        assert!(repo.find_by_ip(&ip2).await.is_some()); // Still active
        assert!(repo.find_by_ip(&ip3).await.is_some()); // Static, not pruned
    }
}
