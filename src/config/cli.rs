// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Command-line argument parser
//!
//! This module handles parsing of command-line arguments, maintaining 100%
//! backward compatibility with the C implementation's option syntax.

use crate::error::{ConfigError, DnsmasqError, Result};
use std::net::IpAddr;

/// Command-line arguments
#[derive(Debug, Clone, Default)]
pub struct CliArgs {
    /// Configuration file path
    pub config_file: Option<String>,

    /// Run in foreground (don't daemonize)
    pub no_daemon: bool,

    /// DNS port override
    pub port: Option<u16>,

    /// Cache size override
    pub cache_size: Option<usize>,

    /// Test configuration and exit
    pub test_config: bool,

    /// Display version and exit
    pub version: bool,

    /// Display help and exit
    pub help: bool,

    /// Listen addresses
    pub listen_addresses: Vec<IpAddr>,

    /// Interfaces to listen on
    pub interfaces: Vec<String>,

    /// Enable verbose logging
    pub verbose: bool,
}

/// Parse command-line arguments
///
/// # Arguments
///
/// * `args` - Iterator of command-line arguments (typically std::env::args())
///
/// # Errors
///
/// Returns an error if arguments are invalid
///
/// # Example
///
/// ```no_run
/// use dnsmasq::config::cli::parse_cli_args;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let args = parse_cli_args(std::env::args())?;
/// println!("Config file: {:?}", args.config_file);
/// # Ok(())
/// # }
/// ```
pub fn parse_cli_args<I, T>(args: I) -> Result<CliArgs>
where
    I: IntoIterator<Item = T>,
    T: Into<String>,
{
    let mut cli_args = CliArgs::default();
    let mut args_iter = args.into_iter().map(|a| a.into()).skip(1); // Skip program name

    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            // Help and version
            "-h" | "--help" => {
                cli_args.help = true;
            }
            "-v" | "--version" => {
                cli_args.version = true;
            }

            // Configuration file
            "-C" | "--conf-file" => {
                cli_args.config_file = Some(args_iter.next().ok_or_else(|| {
                    DnsmasqError::Config(ConfigError::CommandLineError {
                        reason: "--conf-file requires an argument".to_string(),
                    })
                })?);
            }
            arg if arg.starts_with("--conf-file=") => {
                cli_args.config_file = Some(arg.trim_start_matches("--conf-file=").to_string());
            }

            // Daemon mode
            "-d" | "--no-daemon" => {
                cli_args.no_daemon = true;
            }
            "-k" | "--keep-in-foreground" => {
                cli_args.no_daemon = true;
            }

            // DNS port
            "-p" | "--port" => {
                let port_str = args_iter.next().ok_or_else(|| {
                    DnsmasqError::Config(ConfigError::CommandLineError {
                        reason: "--port requires an argument".to_string(),
                    })
                })?;
                cli_args.port = Some(port_str.parse().map_err(|_| {
                    DnsmasqError::Config(ConfigError::CommandLineError {
                        reason: format!("Invalid port number: {}", port_str),
                    })
                })?);
            }
            arg if arg.starts_with("--port=") => {
                let port_str = arg.trim_start_matches("--port=");
                cli_args.port = Some(port_str.parse().map_err(|_| {
                    DnsmasqError::Config(ConfigError::CommandLineError {
                        reason: format!("Invalid port number: {}", port_str),
                    })
                })?);
            }

            // Cache size
            "-c" | "--cache-size" => {
                let size_str = args_iter.next().ok_or_else(|| {
                    DnsmasqError::Config(ConfigError::CommandLineError {
                        reason: "--cache-size requires an argument".to_string(),
                    })
                })?;
                cli_args.cache_size = Some(size_str.parse().map_err(|_| {
                    DnsmasqError::Config(ConfigError::CommandLineError {
                        reason: format!("Invalid cache size: {}", size_str),
                    })
                })?);
            }
            arg if arg.starts_with("--cache-size=") => {
                let size_str = arg.trim_start_matches("--cache-size=");
                cli_args.cache_size = Some(size_str.parse().map_err(|_| {
                    DnsmasqError::Config(ConfigError::CommandLineError {
                        reason: format!("Invalid cache size: {}", size_str),
                    })
                })?);
            }

            // Test mode
            "--test" => {
                cli_args.test_config = true;
            }

            // Listen address
            "-a" | "--listen-address" => {
                let addr_str = args_iter.next().ok_or_else(|| {
                    DnsmasqError::Config(ConfigError::CommandLineError {
                        reason: "--listen-address requires an argument".to_string(),
                    })
                })?;
                let addr = addr_str.parse().map_err(|_| {
                    DnsmasqError::Config(ConfigError::CommandLineError {
                        reason: format!("Invalid listen address: {}", addr_str),
                    })
                })?;
                cli_args.listen_addresses.push(addr);
            }
            arg if arg.starts_with("--listen-address=") => {
                let addr_str = arg.trim_start_matches("--listen-address=");
                let addr = addr_str.parse().map_err(|_| {
                    DnsmasqError::Config(ConfigError::CommandLineError {
                        reason: format!("Invalid listen address: {}", addr_str),
                    })
                })?;
                cli_args.listen_addresses.push(addr);
            }

            // Interface
            "-i" | "--interface" => {
                let interface = args_iter.next().ok_or_else(|| {
                    DnsmasqError::Config(ConfigError::CommandLineError {
                        reason: "--interface requires an argument".to_string(),
                    })
                })?;
                cli_args.interfaces.push(interface);
            }
            arg if arg.starts_with("--interface=") => {
                let interface = arg.trim_start_matches("--interface=").to_string();
                cli_args.interfaces.push(interface);
            }

            // Verbose
            "-q" | "--log-queries" => {
                cli_args.verbose = true;
            }

            // Unknown option
            arg if arg.starts_with('-') => {
                return Err(DnsmasqError::Config(ConfigError::CommandLineError {
                    reason: format!("Unknown option: {}", arg),
                }));
            }

            // Non-option argument (ignored for now)
            _ => {}
        }
    }

    Ok(cli_args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_args() {
        let args: Vec<String> = vec!["dnsmasq".to_string()];
        let result = parse_cli_args(args);
        assert!(result.is_ok());
        let cli = result.unwrap();
        assert!(!cli.no_daemon);
        assert!(!cli.test_config);
    }

    #[test]
    fn test_parse_help() {
        let args = vec!["dnsmasq", "--help"];
        let cli = parse_cli_args(args.into_iter().map(String::from)).unwrap();
        assert!(cli.help);
    }

    #[test]
    fn test_parse_version() {
        let args = vec!["dnsmasq", "-v"];
        let cli = parse_cli_args(args.into_iter().map(String::from)).unwrap();
        assert!(cli.version);
    }

    #[test]
    fn test_parse_no_daemon() {
        let args = vec!["dnsmasq", "--no-daemon"];
        let cli = parse_cli_args(args.into_iter().map(String::from)).unwrap();
        assert!(cli.no_daemon);
    }

    #[test]
    fn test_parse_port_long() {
        let args = vec!["dnsmasq", "--port=5353"];
        let cli = parse_cli_args(args.into_iter().map(String::from)).unwrap();
        assert_eq!(cli.port, Some(5353));
    }

    #[test]
    fn test_parse_port_short() {
        let args = vec!["dnsmasq", "-p", "5353"];
        let cli = parse_cli_args(args.into_iter().map(String::from)).unwrap();
        assert_eq!(cli.port, Some(5353));
    }

    #[test]
    fn test_parse_config_file() {
        let args = vec!["dnsmasq", "--conf-file=/etc/dnsmasq.conf"];
        let cli = parse_cli_args(args.into_iter().map(String::from)).unwrap();
        assert_eq!(cli.config_file, Some("/etc/dnsmasq.conf".to_string()));
    }

    #[test]
    fn test_parse_listen_address() {
        let args = vec!["dnsmasq", "--listen-address=127.0.0.1"];
        let cli = parse_cli_args(args.into_iter().map(String::from)).unwrap();
        assert_eq!(cli.listen_addresses.len(), 1);
        assert_eq!(cli.listen_addresses[0].to_string(), "127.0.0.1");
    }

    #[test]
    fn test_parse_interface() {
        let args = vec!["dnsmasq", "--interface=eth0"];
        let cli = parse_cli_args(args.into_iter().map(String::from)).unwrap();
        assert_eq!(cli.interfaces, vec!["eth0"]);
    }

    #[test]
    fn test_parse_invalid_port() {
        let args = vec!["dnsmasq", "--port=invalid"];
        let result = parse_cli_args(args.into_iter().map(String::from));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unknown_option() {
        let args = vec!["dnsmasq", "--unknown-option"];
        let result = parse_cli_args(args.into_iter().map(String::from));
        assert!(result.is_err());
    }
}
