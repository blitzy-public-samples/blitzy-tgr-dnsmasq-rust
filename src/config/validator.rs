// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Configuration validation
//!
//! This module validates dnsmasq configuration for correctness and consistency.

use crate::config::types::Config;
use crate::error::{ConfigError, DnsmasqError, Result};

/// Configuration validation error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Invalid port number
    InvalidPort(u16),

    /// Invalid cache size
    InvalidCacheSize(usize),

    /// Conflicting options
    ConflictingOptions(String, String),

    /// Missing required option
    MissingRequiredOption(String),

    /// Invalid DHCP range
    InvalidDhcpRange(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidPort(port) => {
                write!(f, "Invalid port number: {}", port)
            }
            ValidationError::InvalidCacheSize(size) => {
                write!(f, "Invalid cache size: {}", size)
            }
            ValidationError::ConflictingOptions(opt1, opt2) => {
                write!(f, "Conflicting options: {} and {}", opt1, opt2)
            }
            ValidationError::MissingRequiredOption(opt) => {
                write!(f, "Missing required option: {}", opt)
            }
            ValidationError::InvalidDhcpRange(msg) => {
                write!(f, "Invalid DHCP range: {}", msg)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validate a configuration
///
/// # Arguments
///
/// * `config` - Configuration to validate
///
/// # Errors
///
/// Returns an error if the configuration is invalid
///
/// # Example
///
/// ```no_run
/// use dnsmasq::config::{Config, validate_config};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::default();
/// validate_config(&config)?;
/// # Ok(())
/// # }
/// ```
pub fn validate_config(config: &Config) -> Result<()> {
    // Validate DNS configuration
    validate_dns_config(config)?;

    // Validate DHCP configuration
    validate_dhcp_config(config)?;

    // Validate server configuration
    validate_server_config(config)?;

    // Validate platform configuration
    validate_platform_config(config)?;

    Ok(())
}

/// Validate DNS configuration
fn validate_dns_config(config: &Config) -> Result<()> {
    // Validate port number
    if config.dns.port == 0 {
        return Err(DnsmasqError::Config(ConfigError::ValidationFailed {
            reason: ValidationError::InvalidPort(config.dns.port).to_string(),
        }));
    }

    // Validate cache size
    if config.dns.cache_size == 0 {
        return Err(DnsmasqError::Config(ConfigError::ValidationFailed {
            reason: ValidationError::InvalidCacheSize(config.dns.cache_size).to_string(),
        }));
    }

    // Cache size should be reasonable (not too large)
    const MAX_CACHE_SIZE: usize = 1_000_000;
    if config.dns.cache_size > MAX_CACHE_SIZE {
        return Err(DnsmasqError::Config(ConfigError::ValidationFailed {
            reason: format!(
                "Cache size {} exceeds maximum of {}",
                config.dns.cache_size, MAX_CACHE_SIZE
            ),
        }));
    }

    Ok(())
}

/// Validate DHCP configuration
fn validate_dhcp_config(config: &Config) -> Result<()> {
    // Validate DHCP ranges
    for range in &config.dhcp.ranges {
        // Ensure start and end are the same IP version
        match (&range.start, &range.end) {
            (std::net::IpAddr::V4(_), std::net::IpAddr::V6(_))
            | (std::net::IpAddr::V6(_), std::net::IpAddr::V4(_)) => {
                return Err(DnsmasqError::Config(ConfigError::ValidationFailed {
                    reason: ValidationError::InvalidDhcpRange(
                        "Start and end addresses must be the same IP version".to_string(),
                    )
                    .to_string(),
                }));
            }
            _ => {}
        }

        // Ensure start < end (for IPv4)
        if let (std::net::IpAddr::V4(start), std::net::IpAddr::V4(end)) = (&range.start, &range.end)
        {
            if start >= end {
                return Err(DnsmasqError::Config(ConfigError::ValidationFailed {
                    reason: ValidationError::InvalidDhcpRange(format!(
                        "Start address {} must be less than end address {}",
                        start, end
                    ))
                    .to_string(),
                }));
            }
        }
    }

    Ok(())
}

/// Validate server configuration
fn validate_server_config(config: &Config) -> Result<()> {
    // Validate interfaces and listen addresses are not both empty if binding
    if config.server.bind_interfaces
        && config.server.interfaces.is_empty()
        && config.server.listen_addresses.is_empty()
    {
        return Err(DnsmasqError::Config(ConfigError::ValidationFailed {
            reason: "bind-interfaces requires at least one interface or listen-address".to_string(),
        }));
    }

    Ok(())
}

/// Validate platform configuration
fn validate_platform_config(_config: &Config) -> Result<()> {
    // No specific platform validation needed yet
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{Config, DhcpRange};
    use std::net::IpAddr;

    #[test]
    fn test_validate_default_config() {
        let config = Config::default();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_invalid_port() {
        let mut config = Config::default();
        config.dns.port = 0;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_invalid_cache_size() {
        let mut config = Config::default();
        config.dns.cache_size = 0;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_cache_size_too_large() {
        let mut config = Config::default();
        config.dns.cache_size = 2_000_000;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_invalid_dhcp_range_mixed_ip_versions() {
        let mut config = Config::default();
        config.dhcp.ranges.push(DhcpRange {
            start: "192.168.1.100".parse::<IpAddr>().unwrap(),
            end: "fe80::1".parse::<IpAddr>().unwrap(),
            lease_time: None,
            interface: None,
        });
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_invalid_dhcp_range_start_greater_than_end() {
        let mut config = Config::default();
        config.dhcp.ranges.push(DhcpRange {
            start: "192.168.1.200".parse::<IpAddr>().unwrap(),
            end: "192.168.1.100".parse::<IpAddr>().unwrap(),
            lease_time: None,
            interface: None,
        });
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_bind_interfaces_without_interface() {
        let mut config = Config::default();
        config.server.bind_interfaces = true;
        config.server.interfaces.clear();
        config.server.listen_addresses.clear();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::InvalidPort(0);
        assert_eq!(err.to_string(), "Invalid port number: 0");

        let err = ValidationError::ConflictingOptions("opt1".to_string(), "opt2".to_string());
        assert_eq!(err.to_string(), "Conflicting options: opt1 and opt2");
    }
}
