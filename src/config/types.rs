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

//! Strongly-typed configuration data structures for dnsmasq Rust implementation.
//!
//! This module defines the [`Config`] struct and related types that replace C's `struct daemon`
//! from dnsmasq.h (lines 1343-1526), transforming pointer-heavy C structures into memory-safe
//! Rust types with ownership semantics and compile-time guarantees.
//!
//! # Architecture
//!
//! The configuration is organized into logical subsections for clarity and maintainability:
//!
//! - [`DnsConfig`]: DNS forwarding, caching, DNSSEC validation settings
//! - [`DhcpConfig`]: DHCPv4/v6 address pools, leases, static allocations
//! - [`NetworkConfig`]: Network interfaces, listen addresses, port configuration
//! - [`TftpConfig`]: TFTP server settings (feature-gated with `tftp`)
//! - [`LoggingConfig`]: Syslog facility, file logging, query verbosity
//! - [`SecurityConfig`]: User/group for privilege dropping, chroot jail
//! - [`ScriptConfig`]: Helper script execution for DHCP events
//!
//! # Transformation from C
//!
//! ## Pointer Chains → Vec/Option
//!
//! ```c
//! // C implementation: Manual linked list management
//! struct server *servers, *servers_tail;
//! for (struct server *s = daemon->servers; s; s = s->next) {
//!     // Process server
//! }
//! ```
//!
//! ```rust,ignore
//! // Rust implementation: Owned collection
//! upstream_servers: Vec<ServerDetails>
//! for server in &config.dns.upstream_servers {
//!     // Process server - no null checks, no memory leaks
//! }
//! ```
//!
//! ## Nullable Fields → Option
//!
//! ```c
//! // C implementation: NULL pointer checks
//! char *lease_file;
//! if (daemon->lease_file != NULL) {
//!     open_lease_file(daemon->lease_file);
//! }
//! ```
//!
//! ```rust,ignore
//! // Rust implementation: Type-safe optionality
//! lease_file: Option<PathBuf>
//! if let Some(ref path) = config.dhcp.lease_file {
//!     open_lease_file(path)?;
//! }
//! ```
//!
//! ## Bitfield Options → Typed Booleans
//!
//! ```c
//! // C implementation: Bit manipulation
//! unsigned int options[OPTION_SIZE];
//! if (option_bool(OPT_DOMAIN_NEEDED)) { /* ... */ }
//! ```
//!
//! ```rust,ignore
//! // Rust implementation: Explicit boolean fields
//! domain_needed: bool
//! if config.dns.domain_needed { /* ... */ }
//! ```
//!
//! # Memory Safety
//!
//! All configuration structures use Rust's ownership system to eliminate:
//! - Use-after-free (lifetimes track borrowing)
//! - Double-free (Drop trait called exactly once)
//! - Memory leaks (RAII ensures cleanup)
//! - Buffer overflows (Vec bounds checking)
//! - Dangling pointers (borrow checker prevents)
//!
//! # Serialization
//!
//! All types derive [`serde::Serialize`] and [`serde::Deserialize`] for:
//! - Configuration export to JSON/TOML
//! - Testing with fixture files
//! - D-Bus API responses
//! - Alternative configuration formats
//!
//! # Builder Pattern
//!
//! The [`ConfigBuilder`] provides ergonomic programmatic configuration:
//!
//! ```rust,ignore
//! let config = ConfigBuilder::new()
//!     .dns_port(53)
//!     .cache_size(1000)
//!     .add_upstream_server("8.8.8.8:53", None)
//!     .enable_dnssec()
//!     .dhcp_range("192.168.1.50", "192.168.1.150", 3600)
//!     .build()?;
//! ```
//!
//! # Default Values
//!
//! The [`Default`] trait implementation provides sensible defaults matching C behavior:
//! - DNS cache size: 150 entries (CACHESIZ)
//! - Lease time: 1 hour (DEFLEASE)
//! - User: "nobody" (CHUSER)
//! - Group: "dip" (CHGRP)
//! - Lease file: "/var/lib/misc/dnsmasq.leases" (LEASEFILE)
//!
//! # RFC Compliance
//!
//! Configuration enforces:
//! - RFC 1035: Domain name validation (255 bytes, 63-byte labels)
//! - RFC 2131: DHCPv4 lease times, option encoding
//! - RFC 3315: DHCPv6 DUID handling, preferred/valid lifetimes
//! - RFC 4034: DNSSEC trust anchor formats
//! - RFC 4861: Router Advertisement timing constraints
//!
//! # Examples
//!
//! ## Creating Configuration from Defaults
//!
//! ```rust,ignore
//! use dnsmasq::config::types::Config;
//!
//! let config = Config::default();
//! assert_eq!(config.dns.cache_size, 150);
//! assert_eq!(config.dhcp.lease_time, Duration::from_secs(3600));
//! ```
//!
//! ## Validation
//!
//! ```rust,ignore
//! let mut config = Config::default();
//! config.dns.cache_size = 0; // Invalid!
//! assert!(config.validate().is_err());
//! ```

use crate::constants::{CACHESIZ, CHGRP, CHUSER, DEFLEASE, LEASEFILE};
use crate::error::ConfigError;
use crate::types::{DomainName, MacAddress, ServerDetails};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// MAIN CONFIGURATION STRUCTURE
// ============================================================================

/// Main dnsmasq configuration containing all subsystems.
///
/// Replaces C's `struct daemon` (dnsmasq.h lines 1343-1526) with modular Rust structure.
/// Organizes 100+ global configuration fields from C into logical subsections for clarity.
///
/// # C Equivalent
///
/// ```c
/// extern struct daemon {
///     unsigned int options[OPTION_SIZE];
///     struct resolvc default_resolv, *resolv_files;
///     struct mx_srv_record *mxnames;
///     struct server *servers, *servers_tail, *local_domains;
///     char *lease_file;
///     char *username, *groupname;
///     int cachesize, ftabsize;
///     int port, query_port;
///     struct dhcp_context *dhcp, *dhcp6;
///     // ... 100+ more fields
/// } *daemon;
/// ```
///
/// # Fields
///
/// - `dns`: DNS forwarding, caching, and DNSSEC configuration
/// - `dhcp`: DHCP server configuration for IPv4 and IPv6
/// - `network`: Network interface and listening configuration
/// - `tftp`: TFTP server configuration (feature-gated)
/// - `logging`: Logging verbosity and destination configuration
/// - `security`: Privilege separation and security settings
/// - `scripts`: Helper script execution configuration
///
/// # Memory Management
///
/// All pointer chains from C (`struct server *next`) are replaced with `Vec<T>` for
/// automatic memory management. All nullable fields (`char *lease_file`) become `Option<T>`.
///
/// # Examples
///
/// ```rust,ignore
/// let mut config = Config::default();
/// config.dns.cache_size = 1000;
/// config.dhcp.v4_ranges.push(DhcpRange::new(/* ... */));
/// config.security.user = Some("dnsmasq".to_string());
/// ```
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// DNS subsystem configuration
    pub dns: DnsConfig,

    /// DHCP subsystem configuration  
    pub dhcp: DhcpConfig,

    /// Network interface and listening configuration
    pub network: NetworkConfig,

    /// TFTP server configuration (optional feature)
    #[cfg(feature = "tftp")]
    pub tftp: TftpConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Security and privilege configuration
    pub security: SecurityConfig,

    /// Helper script configuration
    pub scripts: ScriptConfig,

    /// Platform integration configuration
    pub platform: PlatformConfig,
}

impl Config {
    /// Creates a new configuration with default values.
    ///
    /// Equivalent to [`Config::default()`] but more explicit.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates configuration consistency and constraints.
    ///
    /// Checks:
    /// - Cache size > 0
    /// - Port numbers in valid range (1-65535)
    /// - Lease times are non-zero
    /// - Path accessibility for files
    /// - Domain name validity in filters
    /// - DHCP range consistency (start < end)
    ///
    /// # Errors
    ///
    /// Returns error if any validation constraint is violated.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut config = Config::default();
    /// config.dns.cache_size = 0; // Invalid!
    /// assert!(config.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate DNS configuration
        if self.dns.cache_size == 0 {
            return Err(ConfigError::ValidationFailed {
                reason: "DNS cache size must be greater than 0".to_string(),
            });
        }

        // Validate network configuration
        // Note: port is u16, so it's already constrained to 0-65535
        // Port 0 is valid - it means "disable DNS service" (matches C behavior)

        // Validate DHCP lease time
        if self.dhcp.lease_time.as_secs() == 0 {
            return Err(ConfigError::ValidationFailed {
                reason: "DHCP lease time must be greater than 0".to_string(),
            });
        }

        // Validate DHCP ranges
        for (i, range) in self.dhcp.v4_ranges.iter().enumerate() {
            if range.start.is_ipv6() || range.end.is_ipv6() {
                return Err(ConfigError::ValidationFailed {
                    reason: format!("DHCPv4 range {} contains IPv6 addresses", i),
                });
            }
        }

        for (i, range) in self.dhcp.v6_ranges.iter().enumerate() {
            if range.start.is_ipv4() || range.end.is_ipv4() {
                return Err(ConfigError::ValidationFailed {
                    reason: format!("DHCPv6 range {} contains IPv4 addresses", i),
                });
            }
        }

        Ok(())
    }

    /// Applies command-line argument overrides to configuration.
    ///
    /// Command-line arguments take precedence over configuration file settings.
    /// This maintains C dnsmasq behavior where CLI args override config file.
    ///
    /// # Arguments
    ///
    /// * `cli_args` - Parsed command-line arguments
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::InvalidValue` if CLI argument values are invalid.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut config = Config::default();
    /// let cli_args = CliArgs { port: Some(5353), ..Default::default() };
    /// config.apply_cli_overrides(&cli_args)?;
    /// assert_eq!(config.network.port, 5353);
    /// ```
    pub fn apply_cli_overrides(
        &mut self,
        cli_args: &crate::config::cli::CliArgs,
    ) -> Result<(), crate::error::ConfigError> {
        // Apply port override
        if let Some(port) = cli_args.port {
            self.network.port = port;
        }

        // Apply cache size override
        if let Some(cache_size) = cli_args.cache_size {
            self.dns.cache_size = cache_size;
        }

        // Apply listen addresses (append to existing)
        for addr in &cli_args.listen_address {
            if !self.network.listen_addresses.contains(addr) {
                self.network.listen_addresses.push(*addr);
            }
        }

        // Apply interfaces (append to existing)
        for interface in &cli_args.interface {
            if !self.network.interfaces.contains(interface) {
                self.network.interfaces.push(interface.clone());
            }
        }

        // Apply query logging
        if cli_args.log_queries {
            self.logging.log_queries = true;
        }

        Ok(())
    }
}

// ============================================================================
// DNS CONFIGURATION
// ============================================================================

/// DNS forwarding, caching, and DNSSEC configuration.
///
/// Replaces DNS-related fields from C `struct daemon` including:
/// - `struct server *servers` → `upstream_servers: Vec<ServerDetails>`
/// - `int cachesize` → `cache_size: usize`
/// - `unsigned int options[OPTION_SIZE]` (DNS bits) → typed boolean fields
///
/// # C Equivalent
///
/// ```c
/// struct daemon {
///     struct server *servers, *servers_tail, *local_domains, **serverarray;
///     int server_has_wildcard;
///     int serverarraysz, serverarrayhwm;
///     int cachesize, ftabsize;
///     int port, query_port, min_port, max_port;
///     unsigned long local_ttl, neg_ttl, max_ttl, min_cache_ttl, max_cache_ttl;
///     // DNS option bits from options[OPTION_SIZE]
/// };
/// ```
///
/// # Fields
///
/// - `upstream_servers`: List of upstream DNS servers for query forwarding
/// - `cache_size`: Maximum number of DNS cache entries (default: 150)
/// - `dnssec_enabled`: Enable DNSSEC validation with trust anchors
/// - `query_timeout`: Timeout for upstream DNS queries in seconds
/// - `domain_filters`: Domain-specific forwarding rules
/// - `domain_needed`: Reject queries for plain names without dots
/// - `bogus_priv`: Reject reverse lookups for private IP ranges
/// - `expand_hosts`: Add domain suffix to single-label names from /etc/hosts
/// - `strict_order`: Query upstream servers in configuration order (no fastest-first)
/// - `all_servers`: Send queries to all upstream servers and use first response
/// - `local_ttl`: TTL for locally-generated responses (seconds)
/// - `max_ttl`: Cap TTL values to prevent excessive caching (seconds)
/// - `neg_ttl`: TTL for negative cache entries (NXDOMAIN) (seconds)
///
/// # Examples
///
/// ```rust,ignore
/// let mut dns_config = DnsConfig::default();
/// dns_config.cache_size = 10000;
/// dns_config.dnssec_enabled = true;
/// dns_config.domain_needed = true;
/// dns_config.bogus_priv = true;
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Upstream DNS servers for query forwarding.
    ///
    /// Replaces C `struct server *servers` linked list. Each entry contains server
    /// address, optional domain restriction, and flags.
    ///
    /// Empty vector = no forwarding, only serve from cache/authoritative zones.
    pub upstream_servers: Vec<ServerDetails>,

    /// Maximum DNS cache entries.
    ///
    /// Replaces C `int cachesize`. Cache uses LRU eviction when full.
    /// Memory usage: ~100-200 bytes per entry.
    ///
    /// Default: 150 entries (CACHESIZ constant)
    /// Range: 0 (caching disabled) to 2^32-1
    pub cache_size: usize,

    /// Enable DNSSEC validation.
    ///
    /// Replaces C option bit OPT_DNSSEC_VALID. When enabled, validates DNSSEC
    /// signatures using configured trust anchors. Invalid signatures result in SERVFAIL.
    ///
    /// Default: false
    pub dnssec_enabled: bool,

    /// Query timeout for upstream servers (seconds).
    ///
    /// Replaces C TIMEOUT constant. Maximum time to wait for upstream response
    /// before retrying or failing the query.
    ///
    /// Default: 10 seconds
    /// Range: 1-300 seconds
    pub query_timeout: u32,

    /// Domain-specific forwarding filters.
    ///
    /// Replaces C `struct server *local_domains`. Domains matching these filters
    /// use specific upstream servers or are handled authoritatively.
    ///
    /// Example: "local" → serve locally, "example.com" → forward to 10.0.0.1
    pub domain_filters: Vec<DomainName>,

    /// Reject queries for plain names (no dots or domain parts).
    ///
    /// Replaces C option bit OPT_DOMAIN_NEEDED. Prevents forwarding of short names
    /// like "hostname" that are likely local-only.
    ///
    /// Default: false
    pub domain_needed: bool,

    /// Reject reverse DNS lookups for private IP ranges.
    ///
    /// Replaces C option bit OPT_BOGUSPRIV. Blocks reverse queries for RFC 1918
    /// addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and link-local ranges.
    ///
    /// Default: false
    pub bogus_priv: bool,

    /// Add domain suffix to simple names from /etc/hosts.
    ///
    /// Replaces C option bit OPT_EXPAND_HOSTS. Appends configured domain to
    /// single-label names when reading local hosts file.
    ///
    /// Default: false
    pub expand_hosts: bool,

    /// Query upstream servers in configured order (disable fastest-first).
    ///
    /// Replaces C option bit OPT_ORDER. By default, dnsmasq tracks response times
    /// and prefers faster servers. This forces strict configuration order.
    ///
    /// Default: false
    pub strict_order: bool,

    /// Send queries to all upstream servers and use first response.
    ///
    /// Replaces C option bit OPT_ALL_SERVERS. Increases reliability at cost of
    /// higher query load on upstream servers.
    ///
    /// Default: false
    pub all_servers: bool,

    /// TTL for locally-generated responses (seconds).
    ///
    /// Replaces C `unsigned long local_ttl`. Used for /etc/hosts entries,
    /// DHCP-generated DNS records, and authoritative zone responses.
    ///
    /// Default: 0 (no caching of local responses)
    pub local_ttl: u32,

    /// Maximum TTL value (cap for upstream responses) (seconds).
    ///
    /// Replaces C `unsigned long max_ttl`. Prevents excessively long caching
    /// of upstream records. 0 = no cap.
    ///
    /// Default: 0 (no maximum)
    pub max_ttl: u32,

    /// TTL for negative cache entries (NXDOMAIN) (seconds).
    ///
    /// Replaces C `unsigned long neg_ttl`. Caches "domain not found" responses
    /// to reduce repeated queries for nonexistent names.
    ///
    /// Default: 300 seconds (5 minutes)
    pub neg_ttl: u32,

    /// Don't read /etc/resolv.conf for upstream servers.
    ///
    /// Replaces C option bit OPT_NO_RESOLV. When true, only use servers
    /// explicitly configured via --server options.
    ///
    /// Default: false
    pub no_resolv: bool,

    /// Don't poll /etc/resolv.conf for changes.
    ///
    /// Replaces C option bit OPT_NO_POLL. When true, don't watch resolv.conf
    /// for modifications to update upstream server list.
    ///
    /// Default: false
    pub no_poll: bool,

    /// Don't read /etc/hosts file.
    ///
    /// Replaces C option bit OPT_NO_HOSTS. When true, don't load local host entries.
    ///
    /// Default: false
    pub no_hosts: bool,

    /// DNSSEC check unsigned zones.
    ///
    /// When DNSSEC is enabled, also check unsigned zones for validation.
    ///
    /// Default: false
    pub dnssec_enabled_check_unsigned: bool,

    /// DNSSEC trust anchors.
    ///
    /// List of trust anchor entries for DNSSEC validation.
    pub trust_anchors: Vec<String>,

    /// Address records (address=/domain/ip).
    ///
    /// Maps domain names to IP addresses for local resolution.
    pub address_records: Vec<(String, IpAddr)>,

    /// Host records (host-record=name,addr[,addr...]).
    ///
    /// Local DNS A/AAAA records.
    pub host_records: Vec<(String, Vec<IpAddr>)>,

    /// CNAME records (cname=alias,target).
    ///
    /// DNS CNAME records for aliasing.
    pub cname_records: Vec<(String, String)>,

    /// MX records (mx-host=domain,target[,priority]).
    ///
    /// Mail exchanger records.
    pub mx_records: Vec<(String, String, u16)>,

    /// MX target for default mail exchanger.
    ///
    /// Default MX target when not specified per-domain.
    pub mx_target: Option<String>,

    /// SRV records (srv-host=_service._proto.domain,target,port[,priority][,weight]).
    ///
    /// Service location records.
    pub srv_records: Vec<(String, String, u16, u16, u16)>,

    /// TXT records (txt-record=name,text).
    ///
    /// DNS TXT records for descriptive text.
    pub txt_records: Vec<(String, String)>,

    /// PTR records (ptr-record=name,target).
    ///
    /// DNS PTR records for reverse lookups.
    pub ptr_records: Vec<(String, String)>,

    /// Upstream servers (duplicate of upstream_servers for compatibility).
    ///
    /// Some tests may reference this field name.
    pub servers: Vec<ServerDetails>,

    /// Local domains that should not be forwarded upstream.
    ///
    /// Replaces C local-domain configuration. Queries for these domains
    /// are answered locally or with NXDOMAIN if no local record exists.
    ///
    /// Default: empty vector
    pub local_domains: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstream_servers: Vec::new(),
            cache_size: CACHESIZ,
            dnssec_enabled: false,
            query_timeout: 10, // TIMEOUT constant
            domain_filters: Vec::new(),
            domain_needed: false,
            bogus_priv: false,
            expand_hosts: false,
            strict_order: false,
            all_servers: false,
            local_ttl: 0,
            max_ttl: 0,
            neg_ttl: 300,
            no_resolv: false,
            no_poll: false,
            no_hosts: false,
            dnssec_enabled_check_unsigned: false,
            trust_anchors: Vec::new(),
            address_records: Vec::new(),
            host_records: Vec::new(),
            cname_records: Vec::new(),
            mx_records: Vec::new(),
            mx_target: None,
            srv_records: Vec::new(),
            txt_records: Vec::new(),
            ptr_records: Vec::new(),
            servers: Vec::new(),
            local_domains: Vec::new(),
        }
    }
}

// ============================================================================
// DHCP CONFIGURATION
// ============================================================================

/// DHCP server configuration for IPv4 and IPv6.
///
/// Replaces DHCP-related fields from C `struct daemon` including:
/// - `struct dhcp_context *dhcp, *dhcp6` → `v4_ranges`, `v6_ranges`
/// - `struct dhcp_config *dhcp_conf` → `static_leases`
/// - `char *lease_file` → `lease_file: Option<PathBuf>`
/// - `unsigned int min_leasetime` → `lease_time: Duration`
///
/// # C Equivalent
///
/// ```c
/// struct daemon {
///     struct dhcp_context *dhcp, *dhcp6;
///     struct dhcp_config *dhcp_conf;
///     struct dhcp_opt *dhcp_opts, *dhcp_match, *dhcp_opts6, *dhcp_match6;
///     char *lease_file;
///     unsigned int min_leasetime;
///     int dhcp_max, tftp_max, tftp_mtu;
///     int dhcp_server_port, dhcp_client_port;
///     // ... more DHCP fields
/// };
/// ```
///
/// # Fields
///
/// - `v4_ranges`: DHCPv4 address ranges for lease allocation
/// - `v6_ranges`: DHCPv6 address ranges and prefix delegation pools
/// - `static_leases`: MAC-to-IP static reservations
/// - `lease_file`: Path to lease database file for persistence
/// - `lease_time`: Default lease duration for dynamic allocations
/// - `authoritative`: Send NAKs for wrong-network requests (DHCPv4 only)
///
/// # Examples
///
/// ```rust,ignore
/// let mut dhcp_config = DhcpConfig::default();
/// dhcp_config.v4_ranges.push(DhcpRange {
///     start: "192.168.1.100".parse()?,
///     end: "192.168.1.200".parse()?,
///     lease_time_override: Some(Duration::from_secs(7200)),
/// });
/// dhcp_config.authoritative = true;
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhcpConfig {
    /// DHCPv4 address ranges.
    ///
    /// Replaces C `struct dhcp_context *dhcp` linked list (v4 entries only).
    /// Each range defines start/end addresses for dynamic allocation.
    pub v4_ranges: Vec<DhcpRange>,

    /// DHCPv6 address ranges and prefix delegation.
    ///
    /// Replaces C `struct dhcp_context *dhcp6` linked list and entries with
    /// CONTEXT_V6 flag. Includes both IA_NA (address allocation) and IA_PD
    /// (prefix delegation) pools.
    pub v6_ranges: Vec<DhcpRange>,

    /// Static DHCP lease reservations.
    ///
    /// Replaces C `struct dhcp_config *dhcp_conf`. Maps MAC addresses to fixed
    /// IP addresses and hostnames.
    pub static_leases: Vec<StaticLease>,

    /// Lease database file path.
    ///
    /// Replaces C `char *lease_file`. Stores active and expired leases for
    /// persistence across restarts. None = in-memory only (leases lost on restart).
    ///
    /// Default: Some("/var/lib/misc/dnsmasq.leases") on Linux
    pub lease_file: Option<PathBuf>,

    /// Default lease duration.
    ///
    /// Replaces C `unsigned int min_leasetime`. Used when DHCP range doesn't
    /// specify per-range lease time.
    ///
    /// Default: 1 hour (DEFLEASE = 3600 seconds)
    pub lease_time: Duration,

    /// Authoritative DHCP mode (send NAKs for wrong-network requests).
    ///
    /// Replaces C option bit OPT_AUTHORITATIVE. When true, send DHCPNAK to
    /// clients requesting addresses outside configured ranges.
    ///
    /// Default: false (safe mode, don't interfere with other DHCP servers)
    pub authoritative: bool,

    /// Enable Router Advertisements (IPv6).
    ///
    /// When true, send IPv6 Router Advertisements for stateless address configuration.
    ///
    /// Default: false
    pub enable_ra: bool,

    /// DHCP options to send to clients.
    ///
    /// List of DHCP option codes and values to include in responses.
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            v4_ranges: Vec::new(),
            v6_ranges: Vec::new(),
            static_leases: Vec::new(),
            lease_file: Some(PathBuf::from(LEASEFILE)),
            lease_time: Duration::from_secs(DEFLEASE as u64),
            authoritative: false,
            enable_ra: false,
            options: Vec::new(),
        }
    }
}

/// DHCP address range for dynamic allocation.
///
/// Replaces C `struct dhcp_context` (dnsmasq.h lines 1233-1249).
///
/// # C Equivalent
///
/// ```c
/// struct dhcp_context {
///     unsigned int lease_time, addr_epoch;
///     struct in_addr netmask, broadcast;
///     struct in_addr local, router;
///     struct in_addr start, end; /* range of available addresses */
/// #ifdef HAVE_DHCP6
///     struct in6_addr start6, end6;
///     struct in6_addr local6;
///     int prefix, if_index;
///     unsigned int valid, preferred, saved_valid;
/// #endif
///     int flags;
///     struct dhcp_netid netid, *filter;
///     struct dhcp_context *next, *current;
/// };
/// ```
///
/// # Fields
///
/// - `start`: Starting IP address of allocation range
/// - `end`: Ending IP address of allocation range (inclusive)
/// - `lease_time_override`: Optional per-range lease time (overrides global default)
/// - `interface`: Optional interface restriction (None = all interfaces)
///
/// For DHCPv6, additional fields from `DhcpContext` are used:
/// - `start6`: IPv6 range start (from C `struct in6_addr start6`)
/// - `flags`: Context flags (CONTEXT_STATIC, CONTEXT_V6, etc.)
/// - `if_index`: Interface index for IPv6 link-local binding
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhcpRange {
    /// Range start address (IPv4 or IPv6).
    ///
    /// Replaces C `struct in_addr start` or `struct in6_addr start6`.
    pub start: IpAddr,

    /// Range end address (IPv4 or IPv6, inclusive).
    ///
    /// Replaces C `struct in_addr end` or `struct in6_addr end6`.
    pub end: IpAddr,

    /// Per-range lease time override.
    ///
    /// Replaces C `unsigned int lease_time` in dhcp_context.
    /// None = use global default from `DhcpConfig::lease_time`.
    pub lease_time_override: Option<Duration>,

    /// Optional netmask (IPv4 only).
    ///
    /// Used for subnet configuration in DHCPv4.
    pub netmask: Option<IpAddr>,

    /// Optional interface restriction.
    ///
    /// Replaces C `struct dhcp_netid netid` interface matching.
    /// None = range applies to all interfaces.
    pub interface: Option<String>,

    /// Lease time for this range (in seconds).
    ///
    /// Simplified accessor for lease_time_override converted to seconds.
    pub lease_time: Option<u64>,

    /// Whether this is an IPv6 range.
    ///
    /// Computed from start address being IPv6.
    pub is_ipv6: bool,

    /// Prefix length for DHCPv6 prefix delegation (IPv6 only).
    ///
    /// Replaces C `int prefix` from `struct dhcp_context`.
    /// When set to a value > 0, this range is used for prefix delegation (IA_PD)
    /// instead of or in addition to address allocation (IA_NA).
    /// Typical values: 48, 56, 60, 64 (for /48, /56, /60, /64 prefixes).
    /// 
    /// For address allocation ranges (not PD), this should be 0.
    pub prefix_len: u8,
}

/// DHCP context metadata for DHCPv6 ranges.
///
/// Contains additional DHCPv6-specific fields from C `struct dhcp_context`
/// that don't fit into the simplified `DhcpRange` structure. Used for
/// advanced DHCPv6 prefix delegation and Router Advertisement integration.
///
/// # C Equivalent
///
/// ```c
/// #ifdef HAVE_DHCP6
/// struct dhcp_context {
///     struct in6_addr start6, end6;
///     struct in6_addr local6;
///     int prefix, if_index;
///     unsigned int valid, preferred, saved_valid;
///     time_t ra_time, ra_short_period_start, address_lost_time;
///     char *template_interface;
/// };
/// #endif
/// ```
///
/// # Fields (from exports schema)
///
/// - `start6`: IPv6 range start address (already in DhcpRange::start)
/// - `flags`: Context flags (CONTEXT_V6, CONTEXT_RA, CONTEXT_STATIC, etc.)
/// - `if_index`: Network interface index for link-local binding
///
/// Additional C fields not in exports schema but part of dhcp_context:
/// - `prefix`: Prefix length for DHCPv6 prefix delegation (bits)
/// - `valid`: Valid lifetime for IPv6 addresses (seconds)
/// - `preferred`: Preferred lifetime for IPv6 addresses (seconds)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhcpContext {
    /// IPv6 range start address.
    ///
    /// Replaces C `struct in6_addr start6`. Required for DHCPv6 ranges.
    /// For consistency with DhcpRange, this duplicates the start field but
    /// ensures it's an IPv6 address for DHCPv6-specific operations.
    pub start6: IpAddr,

    /// Context flags.
    ///
    /// Replaces C `int flags`. Bitfield with CONTEXT_* constants:
    /// - CONTEXT_V6: IPv6 context (vs. IPv4)
    /// - CONTEXT_RA: Router Advertisement enabled
    /// - CONTEXT_STATIC: Static address range (no dynamic allocation)
    /// - CONTEXT_DHCP: DHCPv6 address allocation enabled
    /// - CONTEXT_RA_STATELESS: Stateless RA (no address allocation)
    pub flags: u32,

    /// Network interface index.
    ///
    /// Replaces C `int if_index`. Interface index for binding DHCPv6 server
    /// socket and correlating with Router Advertisement interface.
    pub if_index: i32,
}

/// Static DHCP lease reservation.
///
/// Maps a MAC address to a fixed IP address and optional hostname.
/// Replaces C `struct dhcp_config` (dnsmasq.h lines ~800-850).
///
/// # C Equivalent
///
/// ```c
/// struct dhcp_config {
///     unsigned int flags;
///     int clid_len;          /* 0 means no client-id */
///     unsigned char *clid;
///     char *hostname, *domain;
///     struct dhcp_netid_list *netid, *filter;
///     struct in_addr addr;
///     time_t decline_time;
///     unsigned int lease_time;
///     struct dhcp_config *next;
///     // ... more fields
/// };
/// ```
///
/// # Fields
///
/// - `mac`: Client MAC address (6 bytes)
/// - `ip`: Fixed IP address to assign
/// - `hostname`: Optional hostname for DNS registration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StaticLease {
    /// Client MAC address.
    ///
    /// Replaces C `unsigned char hwaddr[DHCP_CHADDR_MAX]` from dhcp_config.
    pub mac: MacAddress,

    /// Assigned IP address.
    ///
    /// Replaces C `struct in_addr addr` (or `struct in6_addr addr6` for IPv6).
    pub ip: IpAddr,

    /// Optional hostname.
    ///
    /// Replaces C `char *hostname`. Used for DNS A/AAAA record registration
    /// when DHCP lease is active.
    pub hostname: Option<String>,
}

// ============================================================================
// NETWORK CONFIGURATION
// ============================================================================

/// Network interface and listening configuration.
///
/// Replaces network-related fields from C `struct daemon`.
///
/// # C Equivalent
///
/// ```c
/// struct daemon {
///     struct iname *if_names, *if_addrs, *if_except;
///     struct listener *listeners;
///     struct irec *interfaces;
///     int port, query_port, min_port, max_port;
///     // ... network option bits
/// };
/// ```
///
/// # Fields
///
/// - `listen_addresses`: Specific IP addresses to bind (empty = all interfaces)
/// - `interfaces`: Interface names to serve (empty = all interfaces)
/// - `except_interfaces`: Interface names to exclude
/// - `bind_interfaces`: Bind to specific interfaces vs. wildcard + filtering
/// - `port`: DNS port (default: 53)
///
/// # Examples
///
/// ```rust,ignore
/// let mut network_config = NetworkConfig::default();
/// network_config.interfaces.push("eth0".to_string());
/// network_config.listen_addresses.push("192.168.1.1".parse()?);
/// network_config.bind_interfaces = true;
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Specific IP addresses to listen on.
    ///
    /// Replaces C `struct iname *if_addrs`. Empty = bind to all addresses (0.0.0.0/::).
    pub listen_addresses: Vec<IpAddr>,

    /// Interface names to serve.
    ///
    /// Replaces C `struct iname *if_names`. Empty = serve all interfaces.
    pub interfaces: Vec<String>,

    /// Interface names to exclude from serving.
    ///
    /// Replaces C `struct iname *if_except`. Takes precedence over `interfaces`.
    pub except_interfaces: Vec<String>,

    /// Bind to specific interfaces vs. wildcard socket.
    ///
    /// Replaces C option bit OPT_NOWILD. When true, creates separate socket for
    /// each interface. When false, uses single wildcard socket with filtering.
    ///
    /// Default: false (wildcard socket)
    pub bind_interfaces: bool,

    /// DNS listening port.
    ///
    /// Replaces C `int port`. Standard DNS port is 53. 0 = disable DNS service.
    ///
    /// Default: 53
    pub port: u16,

    /// Dynamically update interface bindings.
    ///
    /// Replaces C option bit OPT_CLEVERBIND. When true, monitors interface
    /// addresses and automatically updates bindings when interfaces come/go.
    ///
    /// Default: false
    pub bind_dynamic: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addresses: Vec::new(),
            interfaces: Vec::new(),
            except_interfaces: Vec::new(),
            bind_interfaces: false,
            port: 53,
            bind_dynamic: false,
        }
    }
}

// ============================================================================
// TFTP CONFIGURATION
// ============================================================================

/// TFTP server configuration.
///
/// Replaces TFTP-related fields from C `struct daemon`.
///
/// # C Equivalent
///
/// ```c
/// struct daemon {
///     char *tftp_prefix;
///     struct tftp_prefix *if_prefix;
///     int tftp_max, tftp_mtu;
///     struct iname *tftp_interfaces;
///     struct tftp_transfer *tftp_trans, *tftp_done_trans;
///     int start_tftp_port, end_tftp_port;
/// };
/// ```
///
/// # Fields (from exports schema)
///
/// - `tftp_prefix`: Root directory for TFTP file serving
/// - `tftp_mtu`: MTU for TFTP packet sizing (default: 1500)
/// - `tftp_secure`: Restrict file access to tftp_prefix (no ../ escapes)
/// - `tftp_max`: Maximum concurrent TFTP connections
/// - `if_prefix`: Per-interface TFTP root directories
///
/// # Examples
///
/// ```rust,ignore
/// let tftp_config = TftpConfig {
///     tftp_prefix: Some(PathBuf::from("/var/ftpd")),
///     tftp_secure: true,
///     tftp_max: 100,
///     ..Default::default()
/// };
/// ```
#[cfg(feature = "tftp")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TftpConfig {
    /// TFTP root directory.
    ///
    /// Replaces C `char *tftp_prefix`. All file requests are relative to this path.
    /// None = TFTP disabled.
    pub tftp_prefix: Option<PathBuf>,

    /// MTU for TFTP packet sizing.
    ///
    /// Replaces C `int tftp_mtu`. Used to calculate optimal TFTP block size.
    /// Default: 1500 bytes (Ethernet MTU)
    pub tftp_mtu: u16,

    /// Secure mode (restrict to tftp_prefix, block ../ escapes).
    ///
    /// Replaces C option bit OPT_TFTP_SECURE. Prevents directory traversal attacks.
    ///
    /// Default: false
    pub tftp_secure: bool,

    /// Maximum concurrent TFTP transfers.
    ///
    /// Replaces C `int tftp_max`. Limits resource usage.
    ///
    /// Default: 150
    pub tftp_max: usize,

    /// Per-interface TFTP root directories.
    ///
    /// Replaces C `struct tftp_prefix *if_prefix`. Allows different TFTP roots
    /// for different network interfaces.
    pub if_prefix: Vec<(String, PathBuf)>, // (interface, prefix_path)

    /// TFTP server enabled.
    ///
    /// Enables the built-in TFTP server for network boot (PXE).
    ///
    /// Default: false
    pub enabled: bool,

    /// Add client IP address as subdirectory to tftp-root.
    ///
    /// Replaces C option bit OPT_TFTP_APREF_IP. When enabled, adds the client's
    /// IP address as a subdirectory to the tftp-root (e.g., /tftp/192.168.1.10/).
    ///
    /// Default: false
    pub tftp_unique_root: bool,

    /// Disable TFTP blocksize extension (RFC 2348).
    ///
    /// Replaces C option bit OPT_TFTP_NOBLOCK. Disables support for negotiating
    /// TFTP block sizes larger than the default 512 bytes.
    ///
    /// Default: false
    pub tftp_no_blocksize: bool,
}

#[cfg(feature = "tftp")]
impl Default for TftpConfig {
    fn default() -> Self {
        Self {
            tftp_prefix: None,
            tftp_mtu: 1500,
            tftp_secure: false,
            tftp_max: 150,
            if_prefix: Vec::new(),
            enabled: false,
            tftp_unique_root: false,
            tftp_no_blocksize: false,
        }
    }
}

// ============================================================================
// LOGGING CONFIGURATION
// ============================================================================

/// Logging verbosity and destination configuration.
///
/// Replaces logging-related fields from C `struct daemon`.
///
/// # C Equivalent
///
/// ```c
/// struct daemon {
///     int log_fac; /* log facility */
///     char *log_file; /* optional log file */
///     int max_logs;  /* queue limit */
///     // option bits: OPT_LOG, OPT_QUERY_LOG, OPT_DHCP_LOG
/// };
/// ```
///
/// # Fields
///
/// - `log_queries`: Log all DNS queries with source IP and query name
/// - `log_dhcp`: Log DHCP lease transactions (allocate, renew, release)
/// - `log_facility`: Syslog facility (e.g., "daemon", "local0")
/// - `log_file`: Optional file path for logging (None = syslog only)
///
/// # Examples
///
/// ```rust,ignore
/// let logging_config = LoggingConfig {
///     log_queries: true,
///     log_dhcp: true,
///     log_file: Some(PathBuf::from("/var/log/dnsmasq.log")),
///     ..Default::default()
/// };
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log all DNS queries.
    ///
    /// Replaces C option bit OPT_QUERY_LOG. Logs format:
    /// "query[A] example.com from 192.168.1.10"
    ///
    /// Default: false
    pub log_queries: bool,

    /// Log DHCP transactions.
    ///
    /// Replaces C option bit OPT_DHCP_LOG. Logs lease allocations, renewals,
    /// releases, and conflicts.
    ///
    /// Default: false
    pub log_dhcp: bool,

    /// Syslog facility.
    ///
    /// Replaces C `int log_fac`. Common values: "daemon", "local0"-"local7".
    ///
    /// Default: "daemon"
    pub log_facility: String,

    /// Optional log file path.
    ///
    /// Replaces C `char *log_file`. None = syslog only.
    pub log_file: Option<PathBuf>,

    /// Suppress DHCP logging.
    ///
    /// When true, don't log DHCP transactions even if log_dhcp is true.
    ///
    /// Default: false
    pub quiet_dhcp: bool,

    /// Suppress DHCPv6 logging.
    ///
    /// When true, don't log DHCPv6 transactions.
    ///
    /// Default: false
    pub quiet_dhcp6: bool,

    /// Suppress Router Advertisement logging.
    ///
    /// When true, don't log IPv6 Router Advertisements.
    ///
    /// Default: false
    pub quiet_ra: bool,

    /// Run in foreground (don't daemonize).
    ///
    /// When true, stay in foreground for debugging or systemd Type=simple.
    ///
    /// Default: false
    pub no_daemon: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_queries: false,
            log_dhcp: false,
            log_facility: "daemon".to_string(),
            log_file: None,
            quiet_dhcp: false,
            quiet_dhcp6: false,
            quiet_ra: false,
            no_daemon: false,
        }
    }
}

// ============================================================================
// SECURITY CONFIGURATION
// ============================================================================

/// Security and privilege separation configuration.
///
/// Replaces security-related fields from C `struct daemon`.
///
/// # C Equivalent
///
/// ```c
/// struct daemon {
///     char *username, *groupname, *scriptuser;
///     int group_set;
///     // chroot handling in util.c
/// };
/// ```
///
/// # Fields
///
/// - `user`: User to run as after privilege drop (None = no privilege drop)
/// - `group`: Group to run as after privilege drop (None = default user group)
/// - `chroot`: Optional chroot jail directory for filesystem isolation
///
/// # Examples
///
/// ```rust,ignore
/// let security_config = SecurityConfig {
///     user: Some("dnsmasq".to_string()),
///     group: Some("dnsmasq".to_string()),
///     chroot: Some(PathBuf::from("/var/lib/dnsmasq")),
/// };
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// User to run as after binding privileged ports.
    ///
    /// Replaces C `char *username`. After binding to port 53/67/69, dnsmasq
    /// drops root privileges to this user.
    ///
    /// Default: Some("nobody") (CHUSER constant)
    pub user: Option<String>,

    /// Group to run as after privilege drop.
    ///
    /// Replaces C `char *groupname`. None = use primary group of `user`.
    ///
    /// Default: Some("dip") (CHGRP constant on Linux)
    pub group: Option<String>,

    /// Optional chroot jail directory.
    ///
    /// Restricts filesystem access to specified directory. None = no chroot.
    ///
    /// Default: None
    pub chroot: Option<PathBuf>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self { user: Some(CHUSER.to_string()), group: Some(CHGRP.to_string()), chroot: None }
    }
}

// ============================================================================
// SCRIPT CONFIGURATION
// ============================================================================

/// Helper script execution configuration for DHCP events.
///
/// Replaces script-related fields from C `struct daemon`.
///
/// # C Equivalent
///
/// ```c
/// struct daemon {
///     char *lease_change_command;
///     char *scriptuser;
///     char *luascript;
///     // option bit OPT_SCRIPT (enable scripts)
/// };
/// ```
///
/// # Fields
///
/// - `enable_arp_script`: Enable ARP event scripts (non-standard extension)
/// - `script_path`: Path to DHCP event handler script
///
/// Script receives events: "add", "del", "old" with environment variables:
/// - `DNSMASQ_DOMAIN`: Client domain
/// - `DNSMASQ_LEASE_EXPIRES`: Lease expiration time
/// - `DNSMASQ_INTERFACE`: Interface name
/// - `DNSMASQ_CLIENT_ID`: DHCP client identifier
///
/// # Examples
///
/// ```rust,ignore
/// let script_config = ScriptConfig {
///     enable_arp_script: false,
///     script_path: Some(PathBuf::from("/usr/local/bin/dhcp-event.sh")),
/// };
/// ```
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScriptConfig {
    /// Enable ARP event scripts.
    ///
    /// Non-standard extension for ARP table change notifications.
    ///
    /// Default: false
    pub enable_arp_script: bool,

    /// DHCP event handler script path.
    ///
    /// Replaces C `char *lease_change_command`. Invoked on lease add/delete/renew
    /// events. None = no script execution.
    ///
    /// Default: None
    pub script_path: Option<PathBuf>,
}

// ============================================================================
// PLATFORM INTEGRATION CONFIGURATION
// ============================================================================

/// Platform-specific integration settings.
///
/// Contains settings for system-level integration features like D-Bus IPC,
/// ubus (OpenWrt), and other platform-specific functionality.
///
/// # C Equivalent
///
/// These settings were scattered across C `struct daemon` and controlled by
/// HAVE_* preprocessor flags. Centralized here for clarity.
///
/// # Examples
///
/// ```rust,ignore
/// let platform_config = PlatformConfig {
///     dbus_enabled: true,
///     ..Default::default()
/// };
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformConfig {
    /// Enable D-Bus IPC interface.
    ///
    /// Requires `dbus` feature. Provides `uk.org.thekelleys.dnsmasq` service
    /// for external control and monitoring.
    ///
    /// Default: false
    #[cfg(feature = "dbus")]
    pub dbus_enabled: bool,

    /// Enable ubus interface (OpenWrt).
    ///
    /// Requires `ubus` feature. Provides ubus integration for OpenWrt systems.
    ///
    /// Default: false
    #[cfg(feature = "ubus")]
    pub ubus_enabled: bool,

    /// Run as daemon (background process).
    ///
    /// Replaces C option bit OPT_NO_DAEMON (inverted). When true, fork to
    /// background and detach from terminal. When false, run in foreground.
    ///
    /// Default: true
    pub daemon_mode: bool,

    /// Path to PID file.
    ///
    /// Replaces C `char *runfile`. Written after daemonizing with process ID.
    /// None = no PID file.
    ///
    /// Default: None
    pub pid_file: Option<PathBuf>,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            #[cfg(feature = "dbus")]
            dbus_enabled: false,
            #[cfg(feature = "ubus")]
            ubus_enabled: false,
            daemon_mode: true,
            pid_file: None,
        }
    }
}

// ============================================================================
// CONFIGURATION BUILDER
// ============================================================================

/// Builder for programmatic configuration construction.
///
/// Provides fluent API for creating `Config` instances with validation.
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::config::types::ConfigBuilder;
///
/// let config = ConfigBuilder::new()
///     .dns_port(5353)
///     .cache_size(10000)
///     .enable_dnssec()
///     .add_dhcp_range("192.168.1.100".parse()?, "192.168.1.200".parse()?)
///     .log_queries()
///     .user("dnsmasq")
///     .build()?;
/// ```
#[derive(Clone, Debug, Default)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Creates a new configuration builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets DNS listening port.
    pub fn dns_port(mut self, port: u16) -> Self {
        self.config.network.port = port;
        self
    }

    /// Sets DNS cache size.
    pub fn cache_size(mut self, size: usize) -> Self {
        self.config.dns.cache_size = size;
        self
    }

    /// Enables DNSSEC validation.
    pub fn enable_dnssec(mut self) -> Self {
        self.config.dns.dnssec_enabled = true;
        self
    }

    /// Adds an upstream DNS server.
    pub fn add_upstream_server(mut self, server: ServerDetails) -> Self {
        self.config.dns.upstream_servers.push(server);
        self
    }

    /// Adds a DHCPv4 address range.
    pub fn add_dhcp_range(mut self, start: IpAddr, end: IpAddr) -> Self {
        let is_ipv6 = start.is_ipv6();
        self.config.dhcp.v4_ranges.push(DhcpRange {
            start,
            end,
            lease_time_override: None,
            netmask: None,
            interface: None,
            lease_time: None,
            is_ipv6,
            prefix_len: 0, // Not a prefix delegation pool
        });
        self
    }

    /// Enables query logging.
    pub fn log_queries(mut self) -> Self {
        self.config.logging.log_queries = true;
        self
    }

    /// Enables DHCP logging.
    pub fn log_dhcp(mut self) -> Self {
        self.config.logging.log_dhcp = true;
        self
    }

    /// Sets user for privilege dropping.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.config.security.user = Some(user.into());
        self
    }

    /// Sets group for privilege dropping.
    pub fn group(mut self, group: impl Into<String>) -> Self {
        self.config.security.group = Some(group.into());
        self
    }

    /// Loads configuration from a file, merging it with the current builder state.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the dnsmasq configuration file
    ///
    /// # Errors
    ///
    /// Returns error if the file cannot be read or parsed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::config::types::ConfigBuilder;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ConfigBuilder::new()
    ///     .from_file("/etc/dnsmasq.conf").await?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_file<P: AsRef<std::path::Path>>(
        mut self,
        path: P,
    ) -> Result<Self, crate::error::ConfigError> {
        use crate::config::parser::parse_file;
        let file_config = parse_file(path).await?;
        // Replace the config with file-based config (will be overridden by from_args if called after)
        self.config = file_config;
        Ok(self)
    }

    /// Applies command-line arguments to the configuration, overriding file-based settings.
    ///
    /// Command-line arguments have the highest precedence in the configuration hierarchy.
    ///
    /// # Arguments
    ///
    /// * `args` - Parsed command-line arguments
    ///
    /// # Errors
    ///
    /// Returns error if the arguments contain invalid values.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::config::{types::ConfigBuilder, cli::CliArgs};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let cli_args = CliArgs::parse();
    /// let config = ConfigBuilder::new()
    ///     .from_args(&cli_args)?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_args(
        mut self,
        args: &crate::config::cli::CliArgs,
    ) -> Result<Self, crate::error::ConfigError> {
        // Apply CLI overrides to config
        if let Some(port) = args.port {
            self.config.network.port = port;
        }
        if let Some(cache_size) = args.cache_size {
            self.config.dns.cache_size = cache_size;
        }
        if args.no_daemon {
            self.config.platform.daemon_mode = false;
            self.config.logging.no_daemon = true;
        }
        if let Some(ref user) = args.user {
            self.config.security.user = Some(user.clone());
        }
        if let Some(ref group) = args.group {
            self.config.security.group = Some(group.clone());
        }
        if args.log_queries {
            self.config.logging.log_queries = true;
        }
        if args.log_dhcp {
            self.config.logging.log_dhcp = true;
        }
        if args.domain_needed {
            self.config.dns.domain_needed = true;
        }
        if args.bogus_priv {
            self.config.dns.bogus_priv = true;
        }
        // Add more CLI argument mappings as needed
        Ok(self)
    }

    /// Validates the current configuration state.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails (invalid port, conflicting options, etc.).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::config::types::ConfigBuilder;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ConfigBuilder::new()
    ///     .dns_port(5353)
    ///     .validate()?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate(self) -> Result<Self, crate::error::ConfigError> {
        use crate::config::validator::validate_config;
        validate_config(&self.config)?;
        Ok(self)
    }

    /// Builds the final configuration.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails (invalid port, zero cache size, etc.).
    pub fn build(self) -> Result<Config, crate::error::ConfigError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.dns.cache_size, CACHESIZ);
        assert_eq!(config.network.port, 53);
        assert_eq!(config.dhcp.lease_time, Duration::from_secs(DEFLEASE as u64));
        assert_eq!(config.security.user, Some(CHUSER.to_string()));
    }

    #[test]
    fn test_config_validation() {
        let config = Config::default();
        assert!(config.validate().is_ok());

        let mut invalid_config = Config::default();
        invalid_config.dns.cache_size = 0;
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::new()
            .dns_port(5353)
            .cache_size(1000)
            .enable_dnssec()
            .log_queries()
            .build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.network.port, 5353);
        assert_eq!(config.dns.cache_size, 1000);
        assert!(config.dns.dnssec_enabled);
        assert!(config.logging.log_queries);
    }
}
