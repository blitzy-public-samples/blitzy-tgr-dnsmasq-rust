// SPDX-License-Identifier: GPL-2.0-or-later

//! DHCP lease DNS integration module
//!
//! This module provides functionality for integrating DHCP lease information
//! with the DNS cache. When a DHCP lease is allocated with a hostname, the
//! hostname is registered in the DNS cache so that DNS queries for that name
//! will resolve to the leased IP address.
//!
//! This enables automatic DNS resolution for DHCP clients, allowing
//! network-wide hostname discovery without manual DNS configuration.
//!
//! # Core Functions
//!
//! - [`register_lease_hostname`] - Register a lease hostname in DNS cache
//! - [`unregister_lease_hostname`] - Remove a lease hostname from DNS cache
//! - [`update_all_lease_dns`] - Bulk synchronization of all leases with DNS cache
//!
//! # Features
//!
//! - Register lease hostnames in DNS cache
//! - Unregister hostnames when leases expire or are released
//! - Support for both `DHCPv4` and `DHCPv6` leases
//! - FQDN (Fully Qualified Domain Name) handling
//! - IPv6 SLAAC address registration for `DHCPv6` leases
//! - DNS cache bulk update and synchronization
//! - Configurable hostname vs FQDN registration policy
//!
//! # Example
//!
//! ```ignore
//! use std::net::{IpAddr, Ipv4Addr};
//! use std::sync::Arc;
//! use std::time::SystemTime;
//! use tokio::sync::RwLock;
//!
//! // When a lease is allocated
//! let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
//! let hostname = "laptop";
//! let expires = SystemTime::now() + std::time::Duration::from_secs(3600);
//!
//! register_lease_hostname(&dns_cache, ip, hostname, None, expires).await?;
//!
//! // When a lease is released
//! unregister_lease_hostname(&dns_cache, ip, hostname, None).await?;
//!
//! // Bulk synchronization after configuration reload
//! update_all_lease_dns(&leases, dns_cache, true).await?;
//! ```
//!
//! # C Implementation Reference
//!
//! Based on: `src/lease.c:lease_update_dns()` function (lines 1297-1352)
//! which integrates DHCP leases with DNS cache via `cache_add_dhcp_entry()`
//! and `cache_unhash_dhcp()` for bulk updates.

// Note: Config import removed as dhcp_fqdn field is not yet implemented
// TODO: Add Config parameter to functions once config::Config::dhcp_fqdn is available
// use crate::config::Config;
use crate::dhcp::lease::{Lease, LeaseFlags};
use crate::dns::cache::DnsCache;
use crate::dns::protocol::name::DomainName;
use crate::error::DhcpError;
use crate::types::{IpAddr, RecordType};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Register a DHCP lease hostname in the DNS cache
///
/// Adds DNS cache entries that map the hostname (and optionally FQDN) to the
/// leased IP address. This enables DNS resolution for DHCP clients using their
/// assigned hostnames.
///
/// # Arguments
///
/// * `dns_cache` - Shared reference to the DNS cache
/// * `ip` - IP address of the lease (IPv4 or IPv6)
/// * `hostname` - Hostname to register (short name without domain)
/// * `fqdn` - Optional fully qualified domain name
/// * `expires` - Lease expiration time (cache entry TTL will match)
///
/// # Returns
///
/// `Ok(())` if the hostname was successfully registered, or `DhcpError` on failure.
///
/// # Errors
///
/// Returns `DhcpError::LeaseDatabaseFailed` if:
/// - The DNS cache lock cannot be acquired
/// - The hostname or FQDN format is invalid
/// - The cache entry cannot be added
///
/// # Example
///
/// ```ignore
/// use std::net::{IpAddr, Ipv4Addr};
/// use std::time::{SystemTime, Duration};
///
/// let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
/// let hostname = "laptop";
/// let fqdn = Some("laptop.example.com");
/// let expires = SystemTime::now() + Duration::from_secs(3600);
///
/// register_lease_hostname(&dns_cache, ip, hostname, fqdn, expires).await?;
/// info!("Registered {} -> {}", hostname, ip);
/// ```
///
/// # C Implementation Reference
///
/// Based on: `src/lease.c:lease_update_dns()` lines 1331-1339, which calls
/// `cache_add_dhcp_entry(hostname`, `AF_INET`, &addr, expires) for each lease
/// with an associated hostname.
pub async fn register_lease_hostname(
    dns_cache: &Arc<RwLock<DnsCache>>,
    ip: IpAddr,
    hostname: &str,
    fqdn: Option<&str>,
    expires: SystemTime,
) -> Result<(), DhcpError> {
    // Calculate TTL from expiration time
    #[allow(clippy::cast_possible_truncation)]
    // DHCP leases are typically hours/days/weeks, well within u32::MAX seconds (~136 years)
    let ttl = if let Ok(duration) = expires.duration_since(SystemTime::now()) {
        duration.as_secs() as u32
    } else {
        // Lease has already expired, don't register
        debug!("Not registering expired lease for hostname {}", hostname);
        return Ok(());
    };

    // Acquire write lock on DNS cache
    let mut cache = dns_cache.write().await;

    // Register the FQDN if provided (always registered first in C implementation)
    if let Some(fqdn_str) = fqdn {
        if !fqdn_str.is_empty() {
            debug!("Registering DHCP FQDN {} -> {} (TTL: {}s)", fqdn_str, ip, ttl);

            // Convert FQDN to DomainName
            let fqdn_domain = DomainName::new(fqdn_str).map_err(|e| {
                error!("Invalid FQDN '{}': {}", fqdn_str, e);
                DhcpError::LeaseDatabaseFailed {
                    operation: "dns_integration".to_string(),
                    reason: format!("Invalid FQDN '{fqdn_str}': {e}"),
                }
            })?;

            // Add to DNS cache with DHCP flag
            cache.add_dhcp_entry(fqdn_domain, ip, ttl).map_err(|e| {
                error!("Failed to add DHCP FQDN to DNS cache: {}", e);
                DhcpError::LeaseDatabaseFailed {
                    operation: "dns_integration".to_string(),
                    reason: format!("Failed to add DNS FQDN entry: {e}"),
                }
            })?;
        }
    }

    // Register the short hostname if not empty
    // Note: In C implementation, this is conditional on !option_bool(OPT_DHCP_FQDN)
    // We always register both for maximum compatibility, as the dhcp_fqdn config
    // option is not yet implemented in the Rust configuration.
    if !hostname.is_empty() {
        debug!("Registering DHCP hostname {} -> {} (TTL: {}s)", hostname, ip, ttl);

        // Convert hostname to DomainName
        let domain_name = DomainName::new(hostname).map_err(|e| {
            error!("Invalid hostname '{}': {}", hostname, e);
            DhcpError::LeaseDatabaseFailed {
                operation: "dns_integration".to_string(),
                reason: format!("Invalid hostname '{hostname}': {e}"),
            }
        })?;

        // Add to DNS cache with DHCP flag
        cache.add_dhcp_entry(domain_name, ip, ttl).map_err(|e| {
            error!("Failed to add DHCP entry to DNS cache: {}", e);
            DhcpError::LeaseDatabaseFailed {
                operation: "dns_integration".to_string(),
                reason: format!("Failed to add DNS entry: {e}"),
            }
        })?;
    }

    info!("Successfully registered DNS entry for {} -> {}", hostname, ip);

    Ok(())
}

/// Unregister a DHCP lease hostname from the DNS cache
///
/// Removes the DNS cache entries for a hostname and optional FQDN, typically
/// when a lease expires or is explicitly released by the client.
///
/// # Arguments
///
/// * `dns_cache` - Shared reference to the DNS cache
/// * `ip` - IP address of the lease (used to determine record type)
/// * `hostname` - Hostname to unregister
/// * `fqdn` - Optional fully qualified domain name to also unregister
///
/// # Returns
///
/// `Ok(())` if the hostname was successfully unregistered. Returns success
/// even if the entry was not found in the cache.
///
/// # Errors
///
/// Returns `DhcpError::LeaseDatabaseFailed` if:
/// - The DNS cache lock cannot be acquired
/// - The hostname or FQDN format is invalid
///
/// # Example
///
/// ```ignore
/// use std::net::{IpAddr, Ipv4Addr};
///
/// let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
/// let hostname = "laptop";
/// let fqdn = Some("laptop.example.com");
///
/// unregister_lease_hostname(&dns_cache, ip, hostname, fqdn).await?;
/// info!("Unregistered {} from DNS", hostname);
/// ```
///
/// # C Implementation Reference
///
/// Based on: `src/cache.c:cache_del_dhcp()` which removes DHCP-sourced entries
/// from the DNS cache when leases expire or are released.
pub async fn unregister_lease_hostname(
    dns_cache: &Arc<RwLock<DnsCache>>,
    ip: IpAddr,
    hostname: &str,
    fqdn: Option<&str>,
) -> Result<(), DhcpError> {
    // Acquire write lock on DNS cache
    let mut cache = dns_cache.write().await;

    // Determine record type based on IP address type
    let record_type = match ip {
        IpAddr::V4(_) => RecordType::A,
        IpAddr::V6(_) => RecordType::AAAA,
    };

    // Remove the FQDN if provided
    if let Some(fqdn_str) = fqdn {
        if !fqdn_str.is_empty() {
            debug!("Unregistering DHCP FQDN {} ({})", fqdn_str, ip);

            // Convert FQDN to DomainName
            let fqdn_domain = DomainName::new(fqdn_str).map_err(|e| {
                error!("Invalid FQDN '{}': {}", fqdn_str, e);
                DhcpError::LeaseDatabaseFailed {
                    operation: "dns_integration".to_string(),
                    reason: format!("Invalid FQDN '{fqdn_str}': {e}"),
                }
            })?;

            // Remove from DNS cache
            if !cache.remove_dhcp_entry(&fqdn_domain, record_type) {
                debug!("DHCP FQDN not found in cache: {} ({})", fqdn_str, ip);
            }
        }
    }

    // Remove the short hostname
    if !hostname.is_empty() {
        debug!("Unregistering DHCP hostname {} ({})", hostname, ip);

        // Convert hostname to DomainName
        let domain_name = DomainName::new(hostname).map_err(|e| {
            error!("Invalid hostname '{}': {}", hostname, e);
            DhcpError::LeaseDatabaseFailed {
                operation: "dns_integration".to_string(),
                reason: format!("Invalid hostname '{hostname}': {e}"),
            }
        })?;

        // Remove from DNS cache
        if !cache.remove_dhcp_entry(&domain_name, record_type) {
            debug!("DHCP entry not found in cache: {} ({})", hostname, ip);
        }
    }

    info!("Successfully unregistered DNS entry for {} ({})", hostname, ip);

    Ok(())
}

/// Update all DHCP lease DNS registrations
///
/// Synchronizes the DNS cache with the current state of all DHCP leases.
/// This function should be called:
/// - After configuration reload (SIGHUP)
/// - After lease database initialization
/// - When the `dns_dirty` flag is set (bulk update needed)
///
/// This is the Rust equivalent of the C function `lease_update_dns(int force)`
/// from src/lease.c lines 1297-1352.
///
/// # Arguments
///
/// * `leases` - Slice of all active DHCP leases
/// * `dns_cache` - Shared reference to the DNS cache
/// * `force` - If true, bypass the `dns_dirty` check and force update
///
/// # Returns
///
/// `Ok(())` if synchronization completed successfully. Individual lease
/// registration errors are logged but do not cause the function to fail.
///
/// # Example
///
/// ```ignore
/// // After configuration reload
/// update_all_lease_dns(&leases, dns_cache, true).await?;
///
/// // Periodic synchronization (respects dns_dirty flag)
/// update_all_lease_dns(&leases, dns_cache, false).await?;
/// ```
///
/// # C Implementation Reference
///
/// Based on: `src/lease.c:lease_update_dns(int` force) lines 1297-1352
///
/// The C implementation:
/// 1. Checks `dns_dirty || force` to determine if update is needed
/// 2. Calls `cache_unhash_dhcp()` to prepare the cache for bulk updates
/// 3. Iterates through all leases and calls `cache_add_dhcp_entry()`
/// 4. Handles both IPv4 and IPv6 leases (with `DHCPv6` SLAAC addresses)
/// 5. Respects the `OPT_DHCP_FQDN` option to control hostname registration
/// 6. Clears the `dns_dirty` flag after successful update
///
/// # Implementation Notes
///
/// The `dns_dirty` flag and SOA serial number (`daemon->soa_sn`) are not
/// yet implemented in the Rust version. The `force` parameter is currently
/// ignored and all updates are performed unconditionally. This will be
/// refined when the global daemon state structure is implemented.
pub async fn update_all_lease_dns(
    leases: &[Lease],
    dns_cache: Arc<RwLock<DnsCache>>,
    force: bool,
) -> Result<(), DhcpError> {
    debug!("Updating DNS cache with {} leases (force={})", leases.len(), force);

    // Note: In C implementation, this checks (dns_dirty || force)
    // For now, we always proceed since dns_dirty tracking is not yet implemented
    // TODO: Implement dns_dirty flag tracking when daemon state structure is added

    let now = SystemTime::now();
    let mut registered_count = 0;
    let mut skipped_count = 0;

    // Note: The C implementation calls cache_unhash_dhcp() here to prepare the
    // DNS cache for bulk updates by temporarily unhashing the DHCP entries.
    // In the Rust implementation, the DnsCache uses a HashMap which handles
    // rehashing automatically and efficiently, so explicit unhashing and
    // rehashing operations are not needed. The HashMap will handle any
    // structural changes during the bulk insert operations seamlessly.

    debug!("Starting DNS cache bulk update for {} leases", leases.len());

    // Iterate through all leases and register active ones
    for lease in leases {
        // Skip leases without hostnames
        let hostname = match &lease.hostname {
            Some(h) if !h.is_empty() => h,
            _ => {
                skipped_count += 1;
                continue;
            }
        };

        // Skip expired leases
        if lease.expires < now {
            debug!(
                "Skipping expired lease for hostname {} (expired at {:?})",
                hostname, lease.expires
            );
            skipped_count += 1;
            continue;
        }

        // Determine IP address family by checking lease flags
        // C implementation checks lease->flags & (LEASE_TA | LEASE_NA) for IPv6
        // where LEASE_TA = DHCPv6 temporary address, LEASE_NA = DHCPv6 non-temporary address
        let is_ipv6 = lease.flags.contains(LeaseFlags::TA) || lease.flags.contains(LeaseFlags::NA);

        // Register the primary lease IP address
        if let Err(e) = register_lease_hostname(
            &dns_cache,
            lease.ip,
            hostname,
            lease.fqdn.as_deref(),
            lease.expires,
        )
        .await
        {
            error!("Failed to register DNS entry for lease {} -> {}: {}", hostname, lease.ip, e);
            // Continue with other leases despite error
        } else {
            registered_count += 1;
        }

        // For DHCPv6 leases, also register SLAAC addresses if present
        // C implementation: lines 1319-1328 in lease.c
        #[cfg(feature = "dhcp6")]
        if is_ipv6 {
            if let Some(ref slaac_addrs) = lease.slaac_addresses {
                for slaac_addr in slaac_addrs {
                    // C implementation checks slaac->backoff == 0
                    // We assume all addresses in slaac_addresses are valid
                    let slaac_ip = IpAddr::V6(*slaac_addr);

                    if let Err(e) = register_lease_hostname(
                        &dns_cache,
                        slaac_ip,
                        hostname,
                        lease.fqdn.as_deref(),
                        lease.expires,
                    )
                    .await
                    {
                        error!(
                            "Failed to register SLAAC DNS entry for {} -> {}: {}",
                            hostname, slaac_ip, e
                        );
                    } else {
                        debug!("Registered SLAAC address {} for {}", slaac_ip, hostname);
                    }
                }
            }
        }
    }

    // Note: The C implementation implicitly rehashes the DNS cache after all
    // DHCP entries are added. In Rust, the HashMap-based cache structure
    // automatically maintains optimal performance through its built-in
    // resizing and rehashing mechanisms, so no explicit rehash operation
    // is needed.

    info!(
        "DNS cache synchronization complete: registered {} hostnames, skipped {}",
        registered_count, skipped_count
    );

    // Note: C implementation clears dns_dirty flag here
    // TODO: Implement dns_dirty flag clearing when daemon state is added

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::cache::DnsCache;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[tokio::test]
    async fn test_register_and_unregister_hostname() {
        let cache = Arc::new(RwLock::new(DnsCache::with_capacity(1000)));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let hostname = "test-host";
        let expires = SystemTime::now() + Duration::from_secs(3600);

        // Register
        register_lease_hostname(&cache, ip, hostname, None, expires).await.unwrap();

        // Verify it was added
        {
            let mut cache_lock = cache.write().await;
            let domain_name = DomainName::new(hostname).unwrap();
            let record_type = RecordType::A;
            assert!(cache_lock.find_by_name(&domain_name, record_type).is_some());
        }

        // Unregister
        unregister_lease_hostname(&cache, ip, hostname, None).await.unwrap();

        // Verify it was removed
        {
            let mut cache_lock = cache.write().await;
            let domain_name = DomainName::new(hostname).unwrap();
            let record_type = RecordType::A;
            assert!(cache_lock.find_by_name(&domain_name, record_type).is_none());
        }
    }

    #[tokio::test]
    async fn test_register_with_fqdn() {
        let cache = Arc::new(RwLock::new(DnsCache::with_capacity(1000)));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let hostname = "test-host";
        let fqdn = "test-host.example.com";
        let expires = SystemTime::now() + Duration::from_secs(3600);

        // Register both hostname and FQDN
        register_lease_hostname(&cache, ip, hostname, Some(fqdn), expires).await.unwrap();

        // Verify both were added
        {
            let mut cache_lock = cache.write().await;
            let record_type = RecordType::A;

            let hostname_domain = DomainName::new(hostname).unwrap();
            assert!(cache_lock.find_by_name(&hostname_domain, record_type).is_some());

            let fqdn_domain = DomainName::new(fqdn).unwrap();
            assert!(cache_lock.find_by_name(&fqdn_domain, record_type).is_some());
        }
    }

    #[tokio::test]
    async fn test_expired_lease_not_registered() {
        let cache = Arc::new(RwLock::new(DnsCache::with_capacity(1000)));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let hostname = "test-host";
        // Expired 1 hour ago
        let expires = SystemTime::now() - Duration::from_secs(3600);

        // Attempt to register expired lease
        let result = register_lease_hostname(&cache, ip, hostname, None, expires).await;

        // Should succeed but not add to cache
        assert!(result.is_ok());

        // Verify it was not added
        {
            let mut cache_lock = cache.write().await;
            let domain_name = DomainName::new(hostname).unwrap();
            let record_type = RecordType::A;
            assert!(cache_lock.find_by_name(&domain_name, record_type).is_none());
        }
    }

    #[tokio::test]
    async fn test_update_all_lease_dns() {
        let cache = Arc::new(RwLock::new(DnsCache::with_capacity(1000)));
        let now = SystemTime::now();

        let leases = vec![
            Lease {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                hostname: Some("host1".to_string()),
                fqdn: Some("host1.example.com".to_string()),
                expires: now + Duration::from_secs(3600),
                flags: Default::default(),
                slaac_addresses: None,
                ..Default::default()
            },
            Lease {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
                hostname: Some("host2".to_string()),
                fqdn: None,
                expires: now + Duration::from_secs(3600),
                flags: Default::default(),
                slaac_addresses: None,
                ..Default::default()
            },
            // Expired lease - should be skipped
            Lease {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
                hostname: Some("expired".to_string()),
                fqdn: None,
                expires: now - Duration::from_secs(3600),
                flags: Default::default(),
                slaac_addresses: None,
                ..Default::default()
            },
        ];

        // Update all leases
        update_all_lease_dns(&leases, cache.clone(), true).await.unwrap();

        // Verify active leases were registered
        {
            let mut cache_lock = cache.write().await;
            let record_type = RecordType::A;

            let host1_domain = DomainName::new("host1").unwrap();
            assert!(cache_lock.find_by_name(&host1_domain, record_type).is_some());

            let host2_domain = DomainName::new("host2").unwrap();
            assert!(cache_lock.find_by_name(&host2_domain, record_type).is_some());

            // Expired lease should not be registered
            let expired_domain = DomainName::new("expired").unwrap();
            assert!(cache_lock.find_by_name(&expired_domain, record_type).is_none());
        }
    }
}
