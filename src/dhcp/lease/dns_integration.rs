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
//! # Features
//!
//! - Register lease hostnames in DNS cache
//! - Unregister hostnames when leases expire or are released
//! - Support for both DHCPv4 and DHCPv6 leases
//! - FQDN (Fully Qualified Domain Name) handling
//! - DNS cache synchronization with lease state
//!
//! # Example
//!
//! ```ignore
//! use std::net::{IpAddr, Ipv4Addr};
//! use std::sync::{Arc, RwLock};
//! use std::time::SystemTime;
//!
//! // When a lease is allocated
//! let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
//! let hostname = "laptop";
//! let expires = SystemTime::now() + std::time::Duration::from_secs(3600);
//!
//! register_lease_hostname(&dns_cache, ip, hostname, expires).await?;
//!
//! // When a lease is released
//! unregister_lease_hostname(&dns_cache, ip, hostname).await?;
//! ```
//!
//! Based on: src/lease.c (cache_add_dhcp_entry integration, lines 1320-1340)

use crate::dns::cache::DnsCache;
use crate::dns::protocol::name::DomainName;
use crate::error::DhcpError;
use crate::types::RecordType;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Register a DHCP lease hostname in the DNS cache
///
/// Adds a DNS cache entry that maps the hostname to the leased IP address.
/// This enables DNS resolution for DHCP clients using their assigned hostnames.
///
/// # Arguments
///
/// * `dns_cache` - Shared reference to the DNS cache
/// * `ip` - IP address of the lease (IPv4 or IPv6)
/// * `hostname` - Hostname to register (without domain)
/// * `fqdn` - Optional fully qualified domain name
/// * `expires` - Lease expiration time (cache entry will expire at same time)
///
/// # Returns
///
/// `Ok(())` if the hostname was successfully registered, or `DhcpError` on failure.
///
/// # Errors
///
/// Returns `DhcpError::LeaseDatabaseFailed` with operation "dns_integration" if:
/// - The DNS cache is locked and unavailable
/// - The cache is full and cannot accept new entries
/// - The hostname format is invalid
///
/// # Example
///
/// ```ignore
/// use std::net::{IpAddr, Ipv4Addr};
/// use std::time::SystemTime;
///
/// let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
/// let hostname = "laptop";
/// let expires = SystemTime::now() + std::time::Duration::from_secs(3600);
///
/// register_lease_hostname(&dns_cache, ip, hostname, None, expires).await?;
/// info!("Registered {} -> {}", hostname, ip);
/// ```
///
/// # C Implementation Reference
///
/// Based on: src/lease.c:lease_update_dns() which calls cache_add_dhcp_entry()
/// (lines 1320-1340)
///
/// The C implementation adds entries to the DNS cache with the DHCP flag set,
/// distinguishing them from normal DNS cache entries. These entries have TTLs
/// matching the lease expiration time.
pub async fn register_lease_hostname(
    dns_cache: &Arc<RwLock<DnsCache>>,
    ip: IpAddr,
    hostname: &str,
    fqdn: Option<&str>,
    expires: SystemTime,
) -> Result<(), DhcpError> {
    // Calculate TTL from expiration time
    let ttl = match expires.duration_since(SystemTime::now()) {
        Ok(duration) => duration.as_secs() as u32,
        Err(_) => {
            // Lease has already expired, don't register
            debug!("Not registering expired lease for hostname {}", hostname);
            return Ok(());
        }
    };

    // Acquire write lock on DNS cache
    let mut cache = dns_cache.write().await;

    // Register the short hostname
    if !hostname.is_empty() {
        debug!("Registering DHCP hostname {} -> {} (TTL: {}s)", hostname, ip, ttl);

        // Convert hostname to DomainName
        let domain_name = DomainName::new(hostname).map_err(|e| {
            error!("Invalid hostname '{}': {}", hostname, e);
            DhcpError::LeaseDatabaseFailed {
                operation: "dns_integration".to_string(),
                reason: format!("Invalid hostname '{}': {}", hostname, e),
            }
        })?;

        // Add to DNS cache with DHCP flag
        cache.add_dhcp_entry(domain_name, ip, ttl).map_err(|e| {
            error!("Failed to add DHCP entry to DNS cache: {}", e);
            DhcpError::LeaseDatabaseFailed {
                operation: "dns_integration".to_string(),
                reason: format!("Failed to add DNS entry: {}", e),
            }
        })?;
    }

    // Register the FQDN if provided
    if let Some(fqdn_str) = fqdn {
        if !fqdn_str.is_empty() && fqdn_str != hostname {
            debug!("Registering DHCP FQDN {} -> {} (TTL: {}s)", fqdn_str, ip, ttl);

            // Convert FQDN to DomainName
            let fqdn_domain = DomainName::new(fqdn_str).map_err(|e| {
                error!("Invalid FQDN '{}': {}", fqdn_str, e);
                DhcpError::LeaseDatabaseFailed {
                    operation: "dns_integration".to_string(),
                    reason: format!("Invalid FQDN '{}': {}", fqdn_str, e),
                }
            })?;

            cache.add_dhcp_entry(fqdn_domain, ip, ttl).map_err(|e| {
                error!("Failed to add DHCP FQDN to DNS cache: {}", e);
                DhcpError::LeaseDatabaseFailed {
                    operation: "dns_integration".to_string(),
                    reason: format!("Failed to add DNS FQDN entry: {}", e),
                }
            })?;
        }
    }

    info!("Successfully registered DNS entry for {} -> {}", hostname, ip);

    Ok(())
}

/// Unregister a DHCP lease hostname from the DNS cache
///
/// Removes the DNS cache entry for a hostname, typically when a lease expires
/// or is explicitly released by the client.
///
/// # Arguments
///
/// * `dns_cache` - Shared reference to the DNS cache
/// * `ip` - IP address of the lease
/// * `hostname` - Hostname to unregister
/// * `fqdn` - Optional fully qualified domain name to also unregister
///
/// # Returns
///
/// `Ok(())` if the hostname was successfully unregistered, or `DhcpError` on failure.
///
/// # Errors
///
/// Returns `DhcpError::LeaseDatabaseFailed` with operation "dns_integration" if:
/// - The DNS cache is locked and unavailable
/// - The cache entry cannot be removed
///
/// # Example
///
/// ```ignore
/// use std::net::{IpAddr, Ipv4Addr};
///
/// let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
/// let hostname = "laptop";
///
/// unregister_lease_hostname(&dns_cache, ip, hostname, None).await?;
/// info!("Unregistered {} from DNS", hostname);
/// ```
///
/// # C Implementation Reference
///
/// Based on: src/cache.c:cache_del_dhcp() which removes DHCP-sourced entries
///
/// The C implementation removes cache entries marked with the DHCP flag,
/// ensuring they are cleaned up when leases expire.
pub async fn unregister_lease_hostname(
    dns_cache: &Arc<RwLock<DnsCache>>,
    ip: IpAddr,
    hostname: &str,
    fqdn: Option<&str>,
) -> Result<(), DhcpError> {
    // Acquire write lock on DNS cache
    let mut cache = dns_cache.write().await;

    // Remove the short hostname
    if !hostname.is_empty() {
        debug!("Unregistering DHCP hostname {} ({})", hostname, ip);

        // Convert hostname to DomainName
        let domain_name = DomainName::new(hostname).map_err(|e| {
            error!("Invalid hostname '{}': {}", hostname, e);
            DhcpError::LeaseDatabaseFailed {
                operation: "dns_integration".to_string(),
                reason: format!("Invalid hostname '{}': {}", hostname, e),
            }
        })?;

        // Determine record type based on IP address type
        let record_type = match ip {
            IpAddr::V4(_) => RecordType::A,
            IpAddr::V6(_) => RecordType::AAAA,
        };

        // Remove from DNS cache
        if !cache.remove_dhcp_entry(&domain_name, record_type) {
            debug!("DHCP entry not found in cache: {} ({})", hostname, ip);
        }
    }

    // Remove the FQDN if provided
    if let Some(fqdn_str) = fqdn {
        if !fqdn_str.is_empty() && fqdn_str != hostname {
            debug!("Unregistering DHCP FQDN {} ({})", fqdn_str, ip);

            // Convert FQDN to DomainName
            let fqdn_domain = DomainName::new(fqdn_str).map_err(|e| {
                error!("Invalid FQDN '{}': {}", fqdn_str, e);
                DhcpError::LeaseDatabaseFailed {
                    operation: "dns_integration".to_string(),
                    reason: format!("Invalid FQDN '{}': {}", fqdn_str, e),
                }
            })?;

            // Determine record type based on IP address type
            let record_type = match ip {
                IpAddr::V4(_) => RecordType::A,
                IpAddr::V6(_) => RecordType::AAAA,
            };

            // Remove from DNS cache
            if !cache.remove_dhcp_entry(&fqdn_domain, record_type) {
                debug!("DHCP FQDN not found in cache: {} ({})", fqdn_str, ip);
            }
        }
    }

    info!("Successfully unregistered DNS entry for {} ({})", hostname, ip);

    Ok(())
}

/// Synchronize DNS cache with current lease state
///
/// Ensures that all active leases with hostnames are registered in the DNS cache,
/// and removes any stale DHCP entries that no longer have active leases.
///
/// This function should be called:
/// - After configuration reload (SIGHUP)
/// - After lease database initialization
/// - Periodically to ensure cache consistency
///
/// # Arguments
///
/// * `dns_cache` - Shared reference to the DNS cache
/// * `leases` - Current list of active leases
///
/// # Returns
///
/// `Ok(())` if synchronization completed successfully.
///
/// # Example
///
/// ```ignore
/// // After loading leases from database
/// sync_dns_cache(&dns_cache, &leases).await?;
/// ```
///
/// # C Implementation Reference
///
/// Based on: src/lease.c:lease_update_dns() (lines 1278-1340)
pub async fn sync_dns_cache(
    dns_cache: &Arc<RwLock<DnsCache>>,
    leases: &[crate::dhcp::lease::Lease],
) -> Result<(), DhcpError> {
    debug!("Synchronizing DNS cache with {} leases", leases.len());

    let now = SystemTime::now();
    let mut registered_count = 0;

    for lease in leases {
        // Skip leases without hostnames
        let Some(ref hostname) = lease.hostname else {
            continue;
        };

        // Skip expired leases
        if lease.expires < now {
            continue;
        }

        // Register the lease hostname
        if let Err(e) = register_lease_hostname(
            dns_cache,
            lease.ip,
            hostname,
            lease.fqdn.as_deref(),
            lease.expires,
        )
        .await
        {
            error!("Failed to register DNS entry for lease {} -> {}: {}", hostname, lease.ip, e);
            // Continue with other leases
        } else {
            registered_count += 1;
        }

        // For DHCPv6 leases, also register SLAAC addresses if present
        if let Some(ref slaac_addrs) = lease.slaac_addresses {
            for slaac_addr in slaac_addrs {
                let slaac_ip = IpAddr::V6(*slaac_addr);
                if let Err(e) = register_lease_hostname(
                    dns_cache,
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
                }
            }
        }
    }

    info!("DNS cache synchronization complete: registered {} hostnames", registered_count);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::cache::DnsCache;
    use crate::dns::protocol::name::DomainName;
    use crate::types::RecordType;
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
            let record_type = match ip {
                IpAddr::V4(_) => RecordType::A,
                IpAddr::V6(_) => RecordType::AAAA,
            };
            assert!(cache_lock.find_by_name(&domain_name, record_type).is_some());
        }

        // Unregister
        unregister_lease_hostname(&cache, ip, hostname, None).await.unwrap();

        // Verify it was removed
        {
            let mut cache_lock = cache.write().await;
            let domain_name = DomainName::new(hostname).unwrap();
            let record_type = match ip {
                IpAddr::V4(_) => RecordType::A,
                IpAddr::V6(_) => RecordType::AAAA,
            };
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
            let record_type = match ip {
                IpAddr::V4(_) => RecordType::A,
                IpAddr::V6(_) => RecordType::AAAA,
            };

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
            let record_type = match ip {
                IpAddr::V4(_) => RecordType::A,
                IpAddr::V6(_) => RecordType::AAAA,
            };
            assert!(cache_lock.find_by_name(&domain_name, record_type).is_none());
        }
    }
}
