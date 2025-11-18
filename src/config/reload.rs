// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Configuration reload handling
//!
//! This module handles dynamic configuration reload triggered by SIGHUP signal.

use crate::config::{parse_config_file, Config};
use crate::error::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration reloader
///
/// Handles dynamic reloading of configuration in response to SIGHUP signals.
pub struct ConfigReloader {
    /// Current configuration
    config: Arc<RwLock<Config>>,

    /// Configuration file path
    config_path: PathBuf,
}

impl ConfigReloader {
    /// Create a new configuration reloader
    ///
    /// # Arguments
    ///
    /// * `config` - Shared configuration to update
    /// * `config_path` - Path to configuration file
    pub fn new(config: Arc<RwLock<Config>>, config_path: PathBuf) -> Self {
        Self { config, config_path }
    }

    /// Reload configuration from file
    ///
    /// This method:
    /// 1. Parses the configuration file
    /// 2. Validates the new configuration
    /// 3. Atomically updates the shared configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Configuration file cannot be read
    /// - Configuration syntax is invalid
    /// - Validation fails
    ///
    /// On error, the current configuration remains unchanged.
    pub async fn reload(&self) -> Result<()> {
        tracing::info!("Reloading configuration from {:?}", self.config_path);

        // Parse new configuration
        let new_config = parse_config_file(&self.config_path).await?;

        // Validate new configuration
        crate::config::validator::validate_config(&new_config)?;

        // Atomically update configuration
        let mut config = self.config.write().await;
        *config = new_config;

        tracing::info!("Configuration reloaded successfully");

        Ok(())
    }

    /// Get the current configuration
    pub async fn get_config(&self) -> Config {
        self.config.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_config_reloader_creation() {
        let config = Arc::new(RwLock::new(Config::default()));
        let path = PathBuf::from("/etc/dnsmasq.conf");
        let reloader = ConfigReloader::new(config, path);

        let current_config = reloader.get_config().await;
        assert_eq!(current_config.network.port, 53);
    }

    #[tokio::test]
    async fn test_reload_valid_config() {
        let config = Arc::new(RwLock::new(Config::default()));

        // Create a temporary config file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"port=5353\ncache-size=1000\n").unwrap();
        temp_file.flush().unwrap();

        let reloader = ConfigReloader::new(config.clone(), temp_file.path().to_path_buf());

        // Reload configuration
        let result = reloader.reload().await;
        assert!(result.is_ok());

        // Verify configuration was updated
        let current_config = config.read().await;
        assert_eq!(current_config.network.port, 5353);
        assert_eq!(current_config.dns.cache_size, 1000);
    }

    #[tokio::test]
    async fn test_reload_invalid_config() {
        let config = Arc::new(RwLock::new(Config::default()));

        // Create a temporary config file with invalid content
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"port=invalid\n").unwrap();
        temp_file.flush().unwrap();

        let original_port = config.read().await.network.port;

        let reloader = ConfigReloader::new(config.clone(), temp_file.path().to_path_buf());

        // Attempt reload
        let result = reloader.reload().await;
        assert!(result.is_err());

        // Verify configuration was NOT updated
        let current_config = config.read().await;
        assert_eq!(current_config.network.port, original_port);
    }

    #[tokio::test]
    async fn test_reload_missing_file() {
        let config = Arc::new(RwLock::new(Config::default()));
        let reloader = ConfigReloader::new(config, PathBuf::from("/nonexistent/config.conf"));

        let result = reloader.reload().await;
        assert!(result.is_err());
    }
}
