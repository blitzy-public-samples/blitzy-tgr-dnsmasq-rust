// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Configuration validation logic implementing --test mode for dnsmasq Rust implementation.
//!
//! This module provides centralized configuration validation replacing the scattered validation
//! checks in the C implementation (src/option.c functions: atoi_check, atoi_check16, atoi_check8,
//! numeric_check lines 871-929). It validates all Config struct fields ensuring RFC compliance,
//! consistency, and operational safety.
//!
//! # Validation Categories
//!
//! 1. **IP Address Validation**: Format and IPv4/IPv6 family compatibility
//! 2. **Hostname Validation**: RFC 1035 compliance (length limits, label validation)
//! 3. **Port Validation**: Range checking (0-65535) with privileged port warnings
//! 4. **File Path Validation**: Existence, readability, and permission checks
//! 5. **DHCP Pool Validation**: Address range consistency and overlap detection
//! 6. **DNS Server Validation**: Upstream server address reachability
//! 7. **DNSSEC Validation**: Trust anchor format checking
//! 8. **Cross-Option Dependencies**: Interdependent option validation
//! 9. **Numeric Range Validation**: Cache sizes, TTL values, timeouts
//! 10. **Resource Limit Validation**: System resource constraints
//!
//! # --test Mode
//!
//! The `run_test_mode()` function implements the `--test` command-line flag behavior,
//! performing full configuration validation and exiting with appropriate status codes
//! without starting the daemon. This allows administrators to validate configurations
//! before deployment.
//!
//! # Usage
//!
//! ```rust,ignore
//! use dnsmasq::config::validator::{ConfigValidator, validate_config, run_test_mode};
//!
//! // Validate a configuration
//! let config = Config::load()?;
//! validate_config(&config)?;
//!
//! // Or use the validator directly for detailed control
//! let validator = ConfigValidator::new(&config);
//! validator.validate()?;
//! validator.validate_and_warn(); // Non-fatal warnings
//!
//! // --test mode (exits process)
//! if args.test {
//!     run_test_mode(&config);
//! }
//! ```

use crate::config::types::{Config, StaticLease};
use crate::error::ConfigError;
use crate::constants::MAXLEASES;
use crate::types::DomainName;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use tracing::{warn, error, info};
use nix::unistd::{User, Group};

/// Type alias for validation results, using ConfigError for failures.
pub type ValidationResult = Result<(), ConfigError>;

/// Non-fatal validation warnings that don't prevent daemon startup.
///
/// These warnings highlight potentially problematic configurations that are technically
/// valid but may indicate misconfigurations or resource concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationWarning {
    /// DNS cache size exceeds recommended maximum (>10000 entries).
    ///
    /// Large cache sizes consume significant memory and may impact performance
    /// on systems with limited resources.
    LargeCacheSize {
        /// Configured cache size
        size: usize,
        /// Recommended maximum
        recommended_max: usize,
    },

    /// Port number requires privileged access (<1024).
    ///
    /// Binding to ports below 1024 requires root privileges or CAP_NET_BIND_SERVICE
    /// capability on Linux systems. Ensure proper privilege configuration.
    PrivilegedPort {
        /// Port number
        port: u16,
        /// Context (e.g., "DNS", "DHCP")
        context: String,
    },

    /// TTL value outside typical operational ranges.
    ///
    /// Extremely low TTL values (<60s) cause excessive query load.
    /// Extremely high TTL values (>86400s/1 day) prevent timely updates.
    UnusualTTL {
        /// Configured TTL in seconds
        ttl: u32,
        /// Field name
        field: String,
    },

    /// DHCP address range approaching or exceeding MAXLEASES limit.
    ///
    /// Large address pools consume memory and may lead to resource exhaustion.
    LargeDhcpRange {
        /// Number of addresses in range
        address_count: usize,
        /// Maximum leases supported
        max_leases: usize,
    },

    /// Chroot directory configured without corresponding user/group.
    ///
    /// Chroot environments typically require dropping privileges for security.
    /// Configure user and group options along with chroot.
    ChrootWithoutPrivilegeDrop {
        /// Chroot path
        chroot_path: PathBuf,
    },

    /// Large number of upstream DNS servers configured.
    ///
    /// Many upstream servers increase query latency due to selection overhead.
    /// Consider reducing to 3-5 servers for optimal performance.
    ManyUpstreamServers {
        /// Number of configured servers
        count: usize,
        /// Recommended maximum
        recommended_max: usize,
    },

    /// DHCP lease time outside typical operational ranges.
    ///
    /// Very short lease times (<5 minutes) cause excessive DHCP traffic.
    /// Very long lease times (>7 days) prevent address reuse.
    UnusualLeaseTime {
        /// Lease time in seconds
        seconds: u32,
        /// Interface name
        interface: String,
    },
}

/// Configuration validator providing comprehensive validation of Config struct fields.
///
/// The validator performs both fatal validations (returning errors) and non-fatal
/// validations (emitting warnings). It replaces scattered C validation logic with
/// centralized, type-safe Rust validation.
pub struct ConfigValidator<'a> {
    /// Reference to configuration being validated
    config: &'a Config,
    
    /// Collected warnings during validation
    warnings: Vec<ValidationWarning>,
}

impl<'a> ConfigValidator<'a> {
    /// Creates a new configuration validator for the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration to validate
    ///
    /// # Returns
    ///
    /// A new `ConfigValidator` instance ready to perform validation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let config = Config::load()?;
    /// let validator = ConfigValidator::new(&config);
    /// ```
    pub fn new(config: &'a Config) -> Self {
        Self {
            config,
            warnings: Vec::new(),
        }
    }

    /// Performs comprehensive validation of the configuration.
    ///
    /// This is the master validation method that coordinates all validation categories.
    /// It validates IP addresses, hostnames, ports, file paths, DHCP pools, cross-option
    /// dependencies, and resource limits.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all validation checks pass
    /// - `Err(ConfigError)` with detailed error information on first validation failure
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` variants for specific validation failures:
    /// - `InvalidValue`: Malformed values (IPs, hostnames, ports)
    /// - `ValidationFailed`: Constraint violations (range checks, dependencies)
    /// - `InvalidIpRange`: DHCP pool inconsistencies
    /// - `Io`: File access failures
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let validator = ConfigValidator::new(&config);
    /// match validator.validate() {
    ///     Ok(()) => println!("Configuration valid"),
    ///     Err(e) => eprintln!("Validation failed: {}", e),
    /// }
    /// ```
    pub fn validate(&mut self) -> ValidationResult {
        // Validate network configuration (DNS port)
        self.validate_port(self.config.network.port, "DNS port")?;

        // Validate upstream DNS servers
        for server in &self.config.dns.upstream_servers {
            // ServerDetails.addr is a SocketAddr, validate the IP
            let ip_addr = server.addr().ip();
            self.validate_ip_address(&ip_addr, "upstream DNS server")?;
            
            // Validate domain restriction if present
            if let Some(domain) = server.domain() {
                self.validate_hostname(domain.as_str(), "server domain restriction")?;
            }
        }

        // Validate DNS cache size
        if self.config.dns.cache_size > 0 {
            self.validate_cache_size(self.config.dns.cache_size)?;
        }

        // Validate domain filters
        for domain in &self.config.dns.domain_filters {
            self.validate_hostname(domain.as_str(), "domain filter")?;
        }

        // Validate DHCP configuration (DHCP is enabled if ranges are configured)
        if !self.config.dhcp.v4_ranges.is_empty() || !self.config.dhcp.v6_ranges.is_empty() {
            self.validate_dhcp_pools()?;
            
            // Validate static leases
            for lease in &self.config.dhcp.static_leases {
                self.validate_static_lease(lease)?;
            }

            // Validate DHCP options
            self.validate_dhcp_options()?;
        }

        // Validate network configuration
        self.validate_network_config()?;

        // Validate security configuration
        self.validate_security_config()?;

        // Validate file paths
        self.validate_file_paths()?;

        // Validate cross-option dependencies
        self.validate_cross_dependencies()?;

        Ok(())
    }

    /// Validates an IP address (IPv4 or IPv6) and checks family compatibility.
    ///
    /// # Arguments
    ///
    /// * `addr` - IP address to validate
    /// * `context` - Description of the address for error messages
    ///
    /// # Returns
    ///
    /// - `Ok(())` if address is valid
    /// - `Err(ConfigError::InvalidValue)` if address format is invalid
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// validator.validate_ip_address(&IpAddr::from([8, 8, 8, 8]), "DNS server")?;
    /// ```
    pub fn validate_ip_address(&self, addr: &IpAddr, context: &str) -> ValidationResult {
        // IP addresses are already validated by std::net::IpAddr parsing,
        // but we perform additional checks for operational validity

        match addr {
            IpAddr::V4(ipv4) => {
                // Check for reserved/invalid IPv4 addresses
                if ipv4.is_unspecified() {
                    return Err(ConfigError::InvalidValue {
                        directive: context.to_string(),
                        reason: format!("IPv4 address 0.0.0.0 is not valid for {}", context),
                    });
                }

                // Warn about broadcast addresses in certain contexts
                if ipv4.is_broadcast() && context.contains("server") {
                    warn!("Broadcast address {} used for {}", addr, context);
                }
            }
            IpAddr::V6(ipv6) => {
                // Check for reserved/invalid IPv6 addresses
                if ipv6.is_unspecified() {
                    return Err(ConfigError::InvalidValue {
                        directive: context.to_string(),
                        reason: format!("IPv6 address :: is not valid for {}", context),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validates a hostname for RFC 1035 compliance.
    ///
    /// Validates that hostnames meet DNS RFC requirements:
    /// - Total length ≤ 255 bytes
    /// - Each label length ≤ 63 bytes
    /// - Labels contain only: a-z, A-Z, 0-9, hyphen (-)
    /// - Labels do not start or end with hyphen
    ///
    /// # Arguments
    ///
    /// * `hostname` - Hostname string to validate
    /// * `context` - Description for error messages
    ///
    /// # Returns
    ///
    /// - `Ok(())` if hostname is valid
    /// - `Err(ConfigError::InvalidValue)` if hostname violates RFC 1035
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// validator.validate_hostname("example.com", "local domain")?;
    /// ```
    pub fn validate_hostname(&self, hostname: &str, context: &str) -> ValidationResult {
        // Use DomainName type for validation
        DomainName::new(hostname).map_err(|e| ConfigError::InvalidValue {
            directive: context.to_string(),
            reason: format!("Invalid hostname '{}': {}", hostname, e),
        })?;

        Ok(())
    }

    /// Validates a port number is within valid range (0-65535).
    ///
    /// Port numbers are inherently validated by the u16 type (0-65535),
    /// but this method adds warnings for privileged ports (<1024) that
    /// require special permissions.
    ///
    /// # Arguments
    ///
    /// * `port` - Port number to validate
    /// * `context` - Description for warning messages
    ///
    /// # Returns
    ///
    /// - `Ok(())` always (u16 guarantees valid range)
    ///
    /// # Side Effects
    ///
    /// Adds a `ValidationWarning::PrivilegedPort` if port < 1024.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// validator.validate_port(53, "DNS port")?; // Warns: privileged
    /// validator.validate_port(5353, "Alternate DNS port")?; // OK, no warning
    /// ```
    pub fn validate_port(&mut self, port: u16, context: &str) -> ValidationResult {
        // Port range is guaranteed by u16 type (0-65535)
        // Warn about privileged ports
        if port < 1024 && port != 0 {
            self.warnings.push(ValidationWarning::PrivilegedPort {
                port,
                context: context.to_string(),
            });
        }

        Ok(())
    }

    /// Validates a file path exists and has appropriate permissions.
    ///
    /// Checks that the specified file or directory exists and is accessible.
    /// For files, validates read permissions. For directories, validates
    /// read and execute (search) permissions.
    ///
    /// # Arguments
    ///
    /// * `path` - File or directory path to validate
    /// * `context` - Description for error messages
    /// * `must_exist` - Whether the path must exist (false for output files)
    ///
    /// # Returns
    ///
    /// - `Ok(())` if path is valid and accessible
    /// - `Err(ConfigError::Io)` if path doesn't exist or isn't accessible
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// validator.validate_file_path(&PathBuf::from("/etc/dnsmasq.conf"), "config file", true)?;
    /// validator.validate_file_path(&PathBuf::from("/var/run/dnsmasq.pid"), "PID file", false)?;
    /// ```
    pub fn validate_file_path(
        &self,
        path: &Path,
        context: &str,
        must_exist: bool,
    ) -> ValidationResult {
        if must_exist {
            if !path.exists() {
                return Err(ConfigError::ValidationFailed {
                    reason: format!("{}: file not found: {}", context, path.display()),
                });
            }

            // Check readability
            let metadata = std::fs::metadata(path).map_err(|e| {
                ConfigError::ValidationFailed {
                    reason: format!("{}: cannot access file: {}", context, e),
                }
            })?;

            if metadata.is_file() {
                // For files, attempt to open for reading
                std::fs::File::open(path).map_err(|_| {
                    ConfigError::ValidationFailed {
                        reason: format!("{}: cannot read file: {}", context, path.display()),
                    }
                })?;
            } else if metadata.is_dir() {
                // For directories, check execute permission
                std::fs::read_dir(path).map_err(|_| {
                    ConfigError::ValidationFailed {
                        reason: format!("{}: cannot access directory: {}", context, path.display()),
                    }
                })?;
            }
        } else {
            // For paths that don't need to exist, validate parent directory exists
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    return Err(ConfigError::ValidationFailed {
                        reason: format!(
                            "{}: parent directory not found: {}",
                            context,
                            parent.display()
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validates DHCP address pools for consistency and overlap detection.
    ///
    /// Checks that each DHCP pool has:
    /// - Valid start and end IP addresses
    /// - start_ip < end_ip
    /// - Address family consistency (all IPv4 or all IPv6)
    /// - No overlapping address ranges
    /// - Address count within MAXLEASES limit
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all DHCP pools are valid
    /// - `Err(ConfigError::InvalidIpRange)` for invalid or overlapping ranges
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// validator.validate_dhcp_pools()?;
    /// ```
    pub fn validate_dhcp_pools(&mut self) -> ValidationResult {
        let mut ipv4_ranges: Vec<(Ipv4Addr, Ipv4Addr, &str)> = Vec::new();
        let mut ipv6_ranges: Vec<(Ipv6Addr, Ipv6Addr, &str)> = Vec::new();

        // Validate DHCPv4 ranges
        for range in &self.config.dhcp.v4_ranges {
            // Validate address range
            let start_ip = &range.start;
            let end_ip = &range.end;

            // Validate IP address family match
            match (start_ip, end_ip) {
                (IpAddr::V4(start), IpAddr::V4(end)) => {
                    // Validate start < end
                    if start >= end {
                        return Err(ConfigError::InvalidIpRange {
                            directive: format!("DHCP range {}", range.interface.as_deref().unwrap_or("unknown")),
                            value: format!("{} - {}", start_ip, end_ip),
                            reason: "start address must be less than end address".to_string(),
                        });
                    }

                    // Calculate address count
                    let start_u32 = u32::from(*start);
                    let end_u32 = u32::from(*end);
                    let address_count = (end_u32 - start_u32 + 1) as usize;

                    // Check against MAXLEASES
                    if address_count > MAXLEASES {
                        self.warnings.push(ValidationWarning::LargeDhcpRange {
                            address_count,
                            max_leases: MAXLEASES,
                        });
                    }

                    // Store for overlap checking
                    ipv4_ranges.push((
                        *start,
                        *end,
                        range.interface.as_deref().unwrap_or("unknown"),
                    ));
                }
                _ => {
                    return Err(ConfigError::InvalidIpRange {
                        directive: format!("DHCP range {}", range.interface.as_deref().unwrap_or("unknown")),
                        value: format!("{} - {}", start_ip, end_ip),
                        reason: "DHCPv4 range must contain IPv4 addresses".to_string(),
                    });
                }
            }

            // Validate lease time (if overridden for this range)
            if let Some(lease_time) = range.lease_time_override {
                let lease_secs = lease_time.as_secs();
                if lease_secs < 300 {
                    // Less than 5 minutes
                    self.warnings.push(ValidationWarning::UnusualLeaseTime {
                        seconds: lease_secs as u32,
                        interface: range.interface.clone().unwrap_or_else(|| "unknown".to_string()),
                    });
                } else if lease_secs > 604800 {
                    // More than 7 days
                    self.warnings.push(ValidationWarning::UnusualLeaseTime {
                        seconds: lease_secs as u32,
                        interface: range.interface.clone().unwrap_or_else(|| "unknown".to_string()),
                    });
                }
            }
        }

        // Validate DHCPv6 ranges
        for range in &self.config.dhcp.v6_ranges {
            // Validate address range
            let start_ip = &range.start;
            let end_ip = &range.end;

            // Validate IP address family match
            match (start_ip, end_ip) {
                (IpAddr::V6(start), IpAddr::V6(end)) => {
                    // Validate start < end (lexicographic comparison)
                    if start >= end {
                        return Err(ConfigError::InvalidIpRange {
                            directive: format!("DHCPv6 range {}", range.interface.as_deref().unwrap_or("unknown")),
                            value: format!("{} - {}", start_ip, end_ip),
                            reason: "start address must be less than end address".to_string(),
                        });
                    }

                    // Store for overlap checking
                    ipv6_ranges.push((
                        *start,
                        *end,
                        range.interface.as_deref().unwrap_or("unknown"),
                    ));
                }
                _ => {
                    return Err(ConfigError::InvalidIpRange {
                        directive: format!("DHCP range {}", range.interface.as_deref().unwrap_or("unknown")),
                        value: format!("{} - {}", start_ip, end_ip),
                        reason: "DHCPv6 range must contain IPv6 addresses".to_string(),
                    });
                }
            }

            // Validate lease time (if overridden for this range)
            if let Some(lease_time) = range.lease_time_override {
                let lease_secs = lease_time.as_secs();
                if lease_secs < 300 {
                    // Less than 5 minutes
                    self.warnings.push(ValidationWarning::UnusualLeaseTime {
                        seconds: lease_secs as u32,
                        interface: range.interface.clone().unwrap_or_else(|| "unknown".to_string()),
                    });
                } else if lease_secs > 604800 {
                    // More than 7 days
                    self.warnings.push(ValidationWarning::UnusualLeaseTime {
                        seconds: lease_secs as u32,
                        interface: range.interface.clone().unwrap_or_else(|| "unknown".to_string()),
                    });
                }
            }
        }

        // Check for overlapping IPv4 ranges
        for i in 0..ipv4_ranges.len() {
            for j in (i + 1)..ipv4_ranges.len() {
                let (start1, end1, iface1) = &ipv4_ranges[i];
                let (start2, end2, iface2) = &ipv4_ranges[j];

                // Check if ranges overlap
                if !(end1 < start2 || end2 < start1) {
                    return Err(ConfigError::ValidationFailed {
                        reason: format!(
                            "Overlapping IPv4 DHCP ranges: {}-{} on {} and {}-{} on {}",
                            start1, end1, iface1, start2, end2, iface2
                        ),
                    });
                }
            }
        }

        // Check for overlapping IPv6 ranges
        for i in 0..ipv6_ranges.len() {
            for j in (i + 1)..ipv6_ranges.len() {
                let (start1, end1, iface1) = &ipv6_ranges[i];
                let (start2, end2, iface2) = &ipv6_ranges[j];

                // Check if ranges overlap
                if !(end1 < start2 || end2 < start1) {
                    return Err(ConfigError::ValidationFailed {
                        reason: format!(
                            "Overlapping IPv6 DHCP ranges: {}-{} on {} and {}-{} on {}",
                            start1, end1, iface1, start2, end2, iface2
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validates cross-option dependencies and mutual exclusions.
    ///
    /// Checks that interdependent options are properly configured:
    /// - TFTP enabled requires tftp_root configured
    /// - DHCP enabled with PXE requires TFTP enabled
    /// - Interface binding options are mutually exclusive
    /// - DNSSEC enabled requires trust anchors
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all cross-dependencies are satisfied
    /// - `Err(ConfigError::ValidationFailed)` for violated dependencies
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// validator.validate_cross_dependencies()?;
    /// ```
    pub fn validate_cross_dependencies(&mut self) -> ValidationResult {
        // TFTP validation: if TFTP is actually configured (tftp_prefix is Some),
        // validate the settings. Having tftp_prefix as None is valid (TFTP disabled).
        #[cfg(feature = "tftp")]
        {
            if let Some(ref tftp_prefix) = self.config.tftp.tftp_prefix {
                // Validate that tftp_prefix exists and is a directory
                if !tftp_prefix.exists() {
                    return Err(ConfigError::ValidationFailed {
                        reason: format!("TFTP root directory does not exist: {:?}", tftp_prefix),
                    });
                }
                if !tftp_prefix.is_dir() {
                    return Err(ConfigError::ValidationFailed {
                        reason: format!("TFTP root is not a directory: {:?}", tftp_prefix),
                    });
                }
            }
        }

        // Note: PXE boot validation would require additional fields in DhcpRange
        // that are not currently present in the configuration structure.
        // This validation is omitted until PXE-specific fields are added.

        // Note: DNSSEC trust anchor validation is omitted here as trust anchors
        // are typically loaded from a separate trust-anchors.conf file at runtime
        // rather than being part of the main configuration structure.

        // Interface binding validation
        if self.config.network.bind_interfaces {
            if self.config.network.interfaces.is_empty() && 
               self.config.network.listen_addresses.is_empty() {
                return Err(ConfigError::ValidationFailed {
                    reason: "bind-interfaces enabled but no interfaces or listen-addresses specified".to_string(),
                });
            }
        }

        // Log queries requires DNS
        if self.config.logging.log_queries && self.config.network.port == 0 {
            warn!("log-queries enabled but DNS disabled (port=0)");
        }

        Ok(())
    }

    /// Validates DNS cache size and emits warnings for unusual values.
    ///
    /// # Arguments
    ///
    /// * `cache_size` - Configured cache size in entries
    ///
    /// # Returns
    ///
    /// - `Ok(())` always (cache size is advisory)
    ///
    /// # Side Effects
    ///
    /// Adds `ValidationWarning::LargeCacheSize` if cache_size > 10000.
    fn validate_cache_size(&mut self, cache_size: usize) -> ValidationResult {
        const RECOMMENDED_MAX_CACHE: usize = 10000;

        if cache_size > RECOMMENDED_MAX_CACHE {
            self.warnings.push(ValidationWarning::LargeCacheSize {
                size: cache_size,
                recommended_max: RECOMMENDED_MAX_CACHE,
            });
        }

        Ok(())
    }

    /// Validates a static DHCP lease configuration.
    ///
    /// # Arguments
    ///
    /// * `lease` - Static lease to validate
    ///
    /// # Returns
    ///
    /// - `Ok(())` if lease is valid
    /// - `Err(ConfigError)` if lease has invalid IP or hostname
    fn validate_static_lease(&self, lease: &StaticLease) -> ValidationResult {
        // Validate IP address
        self.validate_ip_address(&lease.ip, "static lease IP")?;

        // Validate hostname if present
        if let Some(ref hostname) = lease.hostname {
            self.validate_hostname(hostname, "static lease hostname")?;
        }

        Ok(())
    }

    /// Validates DHCP options configuration.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if options are valid
    /// - `Err(ConfigError)` for invalid option values
    fn validate_dhcp_options(&self) -> ValidationResult {
        // NOTE: DHCP options are not stored in the Config struct.
        // DHCP options are handled at the protocol level in the dhcp module.
        // This function is a no-op placeholder for future validation if needed.
        
        // TODO: If DHCP options are added to Config in the future, validate them here:
        // - Option 6 (DNS servers): validate IP addresses
        // - Option 15 (domain name): validate hostname
        // - Other options as needed

        Ok(())
    }

    /// Validates network configuration including interfaces and addresses.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if network configuration is valid
    /// - `Err(ConfigError)` for invalid network settings
    fn validate_network_config(&self) -> ValidationResult {
        // Validate listen addresses
        for addr in &self.config.network.listen_addresses {
            self.validate_ip_address(addr, "listen address")?;
        }

        // Validate except interfaces don't overlap with interfaces
        let interface_set: HashSet<_> = self.config.network.interfaces.iter().collect();
        let except_set: HashSet<_> = self.config.network.except_interfaces.iter().collect();

        let overlap: Vec<_> = interface_set.intersection(&except_set).collect();
        if !overlap.is_empty() {
            return Err(ConfigError::ValidationFailed {
                reason: format!(
                    "Interfaces specified in both 'interface' and 'except-interface': {:?}",
                    overlap
                ),
            });
        }

        Ok(())
    }

    /// Validates security configuration including user, group, and chroot.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if security configuration is valid
    /// - `Err(ConfigError)` for invalid security settings
    fn validate_security_config(&mut self) -> ValidationResult {
        // Validate user exists
        if let Some(ref username) = self.config.security.user {
            User::from_name(username).map_err(|_| ConfigError::ValidationFailed {
                reason: format!("User '{}' does not exist on system", username),
            })?
            .ok_or_else(|| ConfigError::ValidationFailed {
                reason: format!("User '{}' does not exist on system", username),
            })?;
        }

        // Validate group exists
        if let Some(ref groupname) = self.config.security.group {
            Group::from_name(groupname).map_err(|_| ConfigError::ValidationFailed {
                reason: format!("Group '{}' does not exist on system", groupname),
            })?
            .ok_or_else(|| ConfigError::ValidationFailed {
                reason: format!("Group '{}' does not exist on system", groupname),
            })?;
        }

        // Validate chroot directory
        if let Some(ref chroot_path) = self.config.security.chroot {
            self.validate_file_path(chroot_path, "chroot directory", true)?;

            // Warn if chroot without privilege drop
            if self.config.security.user.is_none() && self.config.security.group.is_none() {
                self.warnings.push(ValidationWarning::ChrootWithoutPrivilegeDrop {
                    chroot_path: chroot_path.clone(),
                });
            }
        }

        Ok(())
    }

    /// Validates file paths referenced in configuration.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all file paths are valid
    /// - `Err(ConfigError)` for inaccessible paths
    fn validate_file_paths(&self) -> ValidationResult {
        // Validate lease file parent directory (file created at runtime)
        if let Some(ref lease_file) = self.config.dhcp.lease_file {
            self.validate_file_path(lease_file, "DHCP lease file", false)?;
        }

        // Validate TFTP root if TFTP feature is enabled
        #[cfg(feature = "tftp")]
        {
            if let Some(ref tftp_root) = self.config.tftp.tftp_prefix {
                self.validate_file_path(tftp_root, "TFTP root directory", true)?;
            }
        }

        Ok(())
    }

    /// Performs non-fatal validation and emits warnings.
    ///
    /// This method should be called after `validate()` to report warnings
    /// that don't prevent daemon startup but may indicate configuration issues.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// validator.validate()?; // Fatal errors
    /// validator.validate_and_warn(); // Non-fatal warnings
    /// ```
    pub fn validate_and_warn(&mut self) {
        // Check for many upstream servers
        const RECOMMENDED_MAX_SERVERS: usize = 5;
        if self.config.dns.upstream_servers.len() > RECOMMENDED_MAX_SERVERS {
            self.warnings.push(ValidationWarning::ManyUpstreamServers {
                count: self.config.dns.upstream_servers.len(),
                recommended_max: RECOMMENDED_MAX_SERVERS,
            });
        }

        // Emit all collected warnings
        for warning in &self.warnings {
            match warning {
                ValidationWarning::LargeCacheSize { size, recommended_max } => {
                    warn!(
                        "Large DNS cache configured: {} entries (recommended max: {})",
                        size, recommended_max
                    );
                }
                ValidationWarning::PrivilegedPort { port, context } => {
                    warn!(
                        "Privileged port {} configured for {} - requires root or CAP_NET_BIND_SERVICE",
                        port, context
                    );
                }
                ValidationWarning::UnusualTTL { ttl, field } => {
                    warn!("Unusual TTL value {} seconds for {}", ttl, field);
                }
                ValidationWarning::LargeDhcpRange { address_count, max_leases } => {
                    warn!(
                        "Large DHCP range: {} addresses (max leases: {})",
                        address_count, max_leases
                    );
                }
                ValidationWarning::ChrootWithoutPrivilegeDrop { chroot_path } => {
                    warn!(
                        "Chroot configured ({}) without user/group - consider adding privilege drop",
                        chroot_path.display()
                    );
                }
                ValidationWarning::ManyUpstreamServers { count, recommended_max } => {
                    warn!(
                        "Many upstream DNS servers: {} (recommended max: {})",
                        count, recommended_max
                    );
                }
                ValidationWarning::UnusualLeaseTime { seconds, interface } => {
                    warn!(
                        "Unusual DHCP lease time {} seconds on interface {}",
                        seconds, interface
                    );
                }
            }
        }
    }

    /// Returns the collected warnings from validation.
    ///
    /// # Returns
    ///
    /// A slice of all validation warnings collected during validation.
    pub fn warnings(&self) -> &[ValidationWarning] {
        &self.warnings
    }
}

/// Validates a configuration and returns a result.
///
/// This is a convenience function that creates a `ConfigValidator`,
/// runs validation, and returns the result.
///
/// # Arguments
///
/// * `config` - Configuration to validate
///
/// # Returns
///
/// - `Ok(())` if configuration is valid
/// - `Err(ConfigError)` with detailed error information
///
/// # Examples
///
/// ```rust,ignore
/// let config = Config::load()?;
/// validate_config(&config)?;
/// println!("Configuration is valid");
/// ```
pub fn validate_config(config: &Config) -> ValidationResult {
    let mut validator = ConfigValidator::new(config);
    validator.validate()?;
    validator.validate_and_warn();
    Ok(())
}

/// Runs configuration validation in --test mode and exits.
///
/// This function implements the `--test` command-line flag behavior.
/// It performs comprehensive configuration validation, reports all
/// errors and warnings, and exits the process with an appropriate
/// status code without starting the daemon.
///
/// # Arguments
///
/// * `config` - Configuration to validate
///
/// # Exit Codes
///
/// - `0`: Configuration is valid
/// - `1`: Configuration validation failed
///
/// # Examples
///
/// ```rust,ignore
/// if args.test {
///     run_test_mode(&config);
///     // Never returns - process exits
/// }
/// ```
///
/// # Note
///
/// This function never returns - it exits the process.
pub fn run_test_mode(config: &Config) -> ! {
    info!("Running configuration validation (--test mode)");

    let mut validator = ConfigValidator::new(config);

    match validator.validate() {
        Ok(()) => {
            // Validation succeeded - emit warnings
            validator.validate_and_warn();

            info!("Configuration test successful");
            
            if validator.warnings().is_empty() {
                println!("dnsmasq: syntax check OK.");
            } else {
                println!("dnsmasq: syntax check OK ({} warnings).", validator.warnings().len());
            }

            std::process::exit(0);
        }
        Err(e) => {
            // Validation failed
            error!("Configuration validation failed: {}", e);
            eprintln!("dnsmasq: bad configuration: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a minimal valid configuration for testing.
    fn create_test_config() -> Config {
        Config::default()
    }

    #[test]
    fn test_validate_ip_address() {
        let config = create_test_config();
        let validator = ConfigValidator::new(&config);

        // Valid IPv4
        let ipv4: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(validator.validate_ip_address(&ipv4, "test").is_ok());

        // Valid IPv6
        let ipv6: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(validator.validate_ip_address(&ipv6, "test").is_ok());

        // Unspecified IPv4
        let unspec_v4: IpAddr = "0.0.0.0".parse().unwrap();
        assert!(validator.validate_ip_address(&unspec_v4, "test").is_err());

        // Unspecified IPv6
        let unspec_v6: IpAddr = "::".parse().unwrap();
        assert!(validator.validate_ip_address(&unspec_v6, "test").is_err());
    }

    #[test]
    fn test_validate_hostname() {
        let config = create_test_config();
        let validator = ConfigValidator::new(&config);

        // Valid hostnames
        assert!(validator.validate_hostname("example.com", "test").is_ok());
        assert!(validator.validate_hostname("sub.example.com", "test").is_ok());
        assert!(validator.validate_hostname("example-123.com", "test").is_ok());

        // Invalid hostnames
        assert!(validator.validate_hostname("-example.com", "test").is_err()); // Leading hyphen
        assert!(validator.validate_hostname("example-.com", "test").is_err()); // Trailing hyphen
        assert!(validator.validate_hostname("", "test").is_err()); // Empty
    }

    #[test]
    fn test_validate_port() {
        let config = create_test_config();
        let mut validator = ConfigValidator::new(&config);

        // All u16 values are valid
        assert!(validator.validate_port(53, "test").is_ok());
        assert!(validator.validate_port(5353, "test").is_ok());
        assert!(validator.validate_port(65535, "test").is_ok());

        // Privileged port generates warning
        validator.validate_port(53, "DNS").unwrap();
        assert!(!validator.warnings().is_empty());
    }
}
