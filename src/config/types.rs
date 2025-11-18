// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Configuration data structures
//!
//! This module defines the strongly-typed configuration structures for dnsmasq.
//! All configuration options from dnsmasq.conf and command-line arguments are
//! represented here with proper Rust types.

use crate::error::Result;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

/// Main dnsmasq configuration
///
/// This structure holds the complete configuration for dnsmasq, encompassing
/// DNS, DHCP, TFTP, and platform integration settings.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// DNS configuration
    pub dns: DnsConfig,

    /// DHCP configuration
    pub dhcp: DhcpConfig,

    /// TFTP configuration
    #[cfg(feature = "tftp")]
    pub tftp: TftpConfig,

    /// General server configuration
    pub server: ServerConfig,

    /// Platform integration configuration
    pub platform: PlatformConfig,
}

impl Config {
    /// Apply command-line argument overrides to this configuration
    pub fn apply_cli_overrides(&mut self, _cli_args: &crate::config::cli::CliArgs) -> Result<()> {
        // TODO: Implement CLI override logic
        Ok(())
    }
}

/// DNS-specific configuration
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// DNS port (default: 53)
    pub port: u16,

    /// Cache size (default: 150 entries)
    pub cache_size: usize,

    /// Upstream DNS servers
    pub upstream_servers: Vec<UpstreamServer>,

    /// Enable DNSSEC validation
    pub dnssec_enabled: bool,

    /// Domain-needed: never forward plain names (no dots)
    pub domain_needed: bool,

    /// Bogus-priv: never forward private IP reverse lookups
    pub bogus_priv: bool,

    /// Enable query logging
    pub log_queries: bool,

    /// Local domains (authoritative zones)
    pub local_domains: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            port: 53,
            cache_size: 150,
            upstream_servers: Vec::new(),
            dnssec_enabled: false,
            domain_needed: false,
            bogus_priv: false,
            log_queries: false,
            local_domains: Vec::new(),
        }
    }
}

/// Upstream DNS server configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamServer {
    /// Server address
    pub address: SocketAddr,

    /// Optional domain for which this server should be used
    pub domain: Option<String>,

    /// Optional source address/interface
    pub source: Option<String>,
}

/// DHCP-specific configuration
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    /// Enable DHCPv4
    pub dhcp_enabled: bool,

    /// Enable DHCPv6
    pub dhcp6_enabled: bool,

    /// DHCP address ranges
    pub ranges: Vec<DhcpRange>,

    /// Static DHCP leases
    pub static_leases: Vec<StaticLease>,

    /// DHCP options to send
    pub options: Vec<DhcpOption>,

    /// Lease file path
    pub lease_file: Option<PathBuf>,

    /// Default lease time
    pub lease_time: Duration,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            dhcp_enabled: false,
            dhcp6_enabled: false,
            ranges: Vec::new(),
            static_leases: Vec::new(),
            options: Vec::new(),
            lease_file: Some(PathBuf::from("/var/lib/misc/dnsmasq.leases")),
            lease_time: Duration::from_secs(3600), // 1 hour default
        }
    }
}

/// DHCP address range configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpRange {
    /// Start address
    pub start: IpAddr,

    /// End address
    pub end: IpAddr,

    /// Lease time for this range
    pub lease_time: Option<Duration>,

    /// Interface to serve on
    pub interface: Option<String>,
}

/// Static DHCP lease configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticLease {
    /// MAC address
    pub mac: [u8; 6],

    /// Assigned IP address
    pub ip: IpAddr,

    /// Hostname
    pub hostname: Option<String>,
}

/// DHCP option to send to clients
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpOption {
    /// Option number
    pub option_num: u8,

    /// Option value
    pub value: Vec<u8>,

    /// Optional tag to match clients
    pub tag: Option<String>,
}

/// TFTP-specific configuration
#[cfg(feature = "tftp")]
#[derive(Debug, Clone)]
pub struct TftpConfig {
    /// Enable TFTP server
    pub enabled: bool,

    /// TFTP root directory
    pub root: PathBuf,

    /// TFTP port (default: 69)
    pub port: u16,

    /// Maximum block size
    pub max_blocksize: u16,
}

#[cfg(feature = "tftp")]
impl Default for TftpConfig {
    fn default() -> Self {
        Self { enabled: false, root: PathBuf::from("/var/ftpd"), port: 69, max_blocksize: 1468 }
    }
}

/// General server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Run as daemon (fork to background)
    pub daemon: bool,

    /// User to run as after privilege drop
    pub user: Option<String>,

    /// Group to run as after privilege drop
    pub group: Option<String>,

    /// PID file path
    pub pid_file: Option<PathBuf>,

    /// Interfaces to listen on
    pub interfaces: Vec<String>,

    /// Interfaces to exclude
    pub except_interfaces: Vec<String>,

    /// Listen addresses
    pub listen_addresses: Vec<IpAddr>,

    /// Bind to interfaces (vs. wildcard)
    pub bind_interfaces: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            daemon: true,
            user: Some("dnsmasq".to_string()),
            group: Some("dnsmasq".to_string()),
            pid_file: Some(PathBuf::from("/var/run/dnsmasq.pid")),
            interfaces: Vec::new(),
            except_interfaces: Vec::new(),
            listen_addresses: Vec::new(),
            bind_interfaces: false,
        }
    }
}

/// Platform integration configuration
#[derive(Debug, Clone, Default)]
pub struct PlatformConfig {
    /// Enable D-Bus integration
    #[cfg(feature = "dbus")]
    pub dbus_enabled: bool,

    /// Enable ubus integration (OpenWrt)
    #[cfg(feature = "ubus")]
    pub ubus_enabled: bool,

    /// Enable inotify file monitoring
    #[cfg(target_os = "linux")]
    pub inotify_enabled: bool,

    /// Enable systemd socket activation
    pub systemd_activation: bool,
}

/// Configuration builder for programmatic config creation
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Create a new configuration builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set DNS port
    pub fn port(mut self, port: u16) -> Self {
        self.config.dns.port = port;
        self
    }

    /// Set cache size
    pub fn cache_size(mut self, size: usize) -> Self {
        self.config.dns.cache_size = size;
        self
    }

    /// Add an upstream DNS server
    pub fn upstream_server(mut self, address: SocketAddr, domain: Option<String>) -> Self {
        self.config.dns.upstream_servers.push(UpstreamServer { address, domain, source: None });
        self
    }

    /// Enable DNSSEC
    pub fn enable_dnssec(mut self) -> Self {
        self.config.dns.dnssec_enabled = true;
        self
    }

    /// Add a DHCP range
    pub fn dhcp_range(mut self, start: IpAddr, end: IpAddr, lease_time: Option<Duration>) -> Self {
        self.config.dhcp.dhcp_enabled = true;
        self.config.dhcp.ranges.push(DhcpRange { start, end, lease_time, interface: None });
        self
    }

    /// Build the final configuration
    pub fn build(self) -> Result<Config> {
        // Validate configuration
        crate::config::validator::validate_config(&self.config)?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.dns.port, 53);
        assert_eq!(config.dns.cache_size, 150);
        assert!(!config.dns.dnssec_enabled);
        assert!(!config.dhcp.dhcp_enabled);
    }

    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::new().port(5353).cache_size(1000).enable_dnssec().build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.dns.port, 5353);
        assert_eq!(config.dns.cache_size, 1000);
        assert!(config.dns.dnssec_enabled);
    }

    #[test]
    fn test_upstream_server_equality() {
        let server1 =
            UpstreamServer { address: "8.8.8.8:53".parse().unwrap(), domain: None, source: None };

        let server2 =
            UpstreamServer { address: "8.8.8.8:53".parse().unwrap(), domain: None, source: None };

        assert_eq!(server1, server2);
    }
}
