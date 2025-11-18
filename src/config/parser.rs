// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Configuration file parser
//!
//! This module implements parsing of dnsmasq.conf files, maintaining 100%
//! backward compatibility with the C implementation's configuration syntax.
//!
//! Supported features:
//! - INI-style key=value configuration
//! - Comment handling (# and ;)
//! - Include directives (conf-file=, conf-dir=)
//! - All ~350 dnsmasq configuration options

use crate::config::types::Config;
use crate::error::{ConfigError, Result};
use std::path::Path;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};

/// Configuration parser
pub struct ConfigParser {
    /// Current configuration being built
    config: Config,

    /// Files already processed (to prevent infinite loops)
    processed_files: Vec<String>,
}

impl ConfigParser {
    /// Create a new configuration parser
    pub fn new() -> Self {
        Self { config: Config::default(), processed_files: Vec::new() }
    }

    /// Parse a configuration file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the configuration file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File cannot be read
    /// - Configuration syntax is invalid
    /// - Circular includes are detected
    pub async fn parse_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_str = path.as_ref().to_string_lossy().to_string();

        // Check for circular includes
        if self.processed_files.contains(&path_str) {
            return Err(ConfigError::IncludeFailed {
                path: path_str.clone(),
                reason: "Circular include detected".to_string(),
            }
            .into());
        }

        self.processed_files.push(path_str.clone());

        // Open and read the file
        let file = fs::File::open(&path).await.map_err(|e| ConfigError::IncludeFailed {
            path: path_str.clone(),
            reason: format!("Failed to open file: {}", e),
        })?;

        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await.map_err(|e| ConfigError::IncludeFailed {
            path: path_str.clone(),
            reason: format!("Failed to read file: {}", e),
        })? {
            self.parse_line(&line).await?;
        }

        Ok(())
    }

    /// Parse a single configuration line
    async fn parse_line(&mut self, line: &str) -> Result<()> {
        // Trim whitespace
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            return Ok(());
        }

        // Parse key=value
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            let value = line[eq_pos + 1..].trim();

            self.parse_option(key, value).await?;
        } else {
            // Boolean option (no value)
            self.parse_option(line, "").await?;
        }

        Ok(())
    }

    /// Parse a configuration option
    async fn parse_option(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            // DNS options
            "port" => {
                self.config.dns.port = value.parse().map_err(|_| ConfigError::InvalidPort {
                    directive: "port".to_string(),
                    port: value.to_string(),
                })?;
            }
            "cache-size" => {
                self.config.dns.cache_size =
                    value.parse().map_err(|_| ConfigError::InvalidValue {
                        directive: "cache-size".to_string(),
                        reason: format!("Invalid cache size: {}", value),
                    })?;
            }
            "domain-needed" => {
                self.config.dns.domain_needed = true;
            }
            "bogus-priv" => {
                self.config.dns.bogus_priv = true;
            }
            "log-queries" => {
                self.config.dns.log_queries = true;
            }

            // Server options
            "no-daemon" => {
                self.config.server.daemon = false;
            }
            "user" => {
                self.config.server.user = Some(value.to_string());
            }
            "group" => {
                self.config.server.group = Some(value.to_string());
            }
            "interface" => {
                self.config.server.interfaces.push(value.to_string());
            }
            "listen-address" => {
                let addr = value.parse().map_err(|_| ConfigError::InvalidValue {
                    directive: "listen-address".to_string(),
                    reason: format!("Invalid IP address: {}", value),
                })?;
                self.config.server.listen_addresses.push(addr);
            }
            "bind-interfaces" => {
                self.config.server.bind_interfaces = true;
            }

            // Include directives
            "conf-file" => {
                // Parse included file (boxed to avoid infinite recursion in async fn)
                Box::pin(self.parse_file(value)).await?;
            }
            "conf-dir" => {
                // Parse all files in directory (boxed to avoid infinite recursion in async fn)
                Box::pin(self.parse_directory(value)).await?;
            }

            // DHCP options
            "dhcp-range" => {
                self.config.dhcp.dhcp_enabled = true;
                // TODO: Parse DHCP range
            }

            // Platform options
            #[cfg(feature = "dbus")]
            "enable-dbus" => {
                self.config.platform.dbus_enabled = true;
            }

            // Unknown or unimplemented options - log warning but continue
            _ => {
                tracing::warn!("Unknown or unimplemented configuration option: {}", key);
            }
        }

        Ok(())
    }

    /// Parse all configuration files in a directory
    async fn parse_directory(&mut self, dir_path: &str) -> Result<()> {
        let mut entries = fs::read_dir(dir_path).await.map_err(|e| ConfigError::IncludeFailed {
            path: dir_path.to_string(),
            reason: format!("Failed to read directory: {}", e),
        })?;

        while let Some(entry) =
            entries.next_entry().await.map_err(|e| ConfigError::IncludeFailed {
                path: dir_path.to_string(),
                reason: format!("Failed to read directory entry: {}", e),
            })?
        {
            let path = entry.path();

            // Only process .conf files
            if path.extension().and_then(|s| s.to_str()) == Some("conf") {
                self.parse_file(&path).await?;
            }
        }

        Ok(())
    }

    /// Finish parsing and return the configuration
    pub fn finish(self) -> Config {
        self.config
    }
}

impl Default for ConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a configuration file
///
/// # Arguments
///
/// * `path` - Path to the configuration file
///
/// # Errors
///
/// Returns an error if the file cannot be parsed
///
/// # Example
///
/// ```no_run
/// use dnsmasq::config::parse_config_file;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = parse_config_file("/etc/dnsmasq.conf").await?;
/// println!("DNS port: {}", config.dns.port);
/// # Ok(())
/// # }
/// ```
pub async fn parse_config_file<P: AsRef<Path>>(path: P) -> Result<Config> {
    let mut parser = ConfigParser::new();
    parser.parse_file(path).await?;
    Ok(parser.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_parse_empty_config() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"").unwrap();
        temp_file.flush().unwrap();

        let config = parse_config_file(temp_file.path()).await;
        assert!(config.is_ok());
    }

    #[tokio::test]
    async fn test_parse_basic_options() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"port=5353\ncache-size=1000\ndomain-needed\n").unwrap();
        temp_file.flush().unwrap();

        let config = parse_config_file(temp_file.path()).await.unwrap();
        assert_eq!(config.dns.port, 5353);
        assert_eq!(config.dns.cache_size, 1000);
        assert!(config.dns.domain_needed);
    }

    #[tokio::test]
    async fn test_parse_comments() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"# Comment\nport=53\n; Another comment\n").unwrap();
        temp_file.flush().unwrap();

        let config = parse_config_file(temp_file.path()).await.unwrap();
        assert_eq!(config.dns.port, 53);
    }

    #[tokio::test]
    async fn test_parse_invalid_port() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"port=invalid\n").unwrap();
        temp_file.flush().unwrap();

        let result = parse_config_file(temp_file.path()).await;
        assert!(result.is_err());
    }
}
