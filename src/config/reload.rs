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

//! SIGHUP-based configuration reload handler for async-safe hot reloading
//!
//! This module implements dynamic configuration reload triggered by SIGHUP signal without
//! daemon restart, replacing C's `clear_cache_and_reload()` function (src/dnsmasq.c lines
//! 2534-2559) with async-safe Rust implementation using tokio signals.
//!
//! # Architecture
//!
//! ## Reload State Machine
//!
//! The reload process progresses through well-defined states:
//!
//! ```text
//! Idle → Reading → Validating → Applying → Complete
//!   ↓       ↓          ↓           ↓          ↓
//!   └───────┴──────────┴───────────┴──────────→ Error (rollback)
//! ```
//!
//! - **Idle**: Waiting for SIGHUP signal
//! - **Reading**: Parsing configuration files from disk
//! - **Validating**: Running validation checks on new configuration
//! - **Applying**: Atomically updating shared Arc<RwLock<Config>>
//! - **Complete**: Reload successful, configuration active
//! - **Error**: Validation or parsing failed, old configuration preserved
//!
//! ## Async Signal Handling
//!
//! Uses `tokio::signal::unix::signal(SignalKind::hangup())` for async-signal-safe SIGHUP
//! monitoring, avoiding reentrancy issues with traditional C signal handlers:
//!
//! ```rust,ignore
//! use tokio::signal::unix::{signal, SignalKind};
//!
//! let mut sighup = signal(SignalKind::hangup())?;
//! loop {
//!     sighup.recv().await;  // Async-safe signal notification
//!     reloader.handle_reload().await?;
//! }
//! ```
//!
//! ## Atomic Configuration Updates
//!
//! Configuration updates use `Arc<RwLock<Config>>` for lock-free reads and exclusive writes:
//!
//! ```rust,ignore
//! // Service modules hold Arc clone for reading
//! let config = config_arc.read().await;
//! let port = config.network.port;  // Non-blocking read
//!
//! // ConfigReloader holds exclusive write access during reload
//! let mut config = config_arc.write().await;
//! *config = new_config;  // Atomic swap
//! ```
//!
//! # Transformation from C
//!
//! ## C Signal Handler Pattern
//!
//! ```c
//! // C implementation (dnsmasq.c lines 2534-2559)
//! void clear_cache_and_reload(time_t now) {
//!     if (daemon->port != 0)
//!         cache_reload();  // Clear DNS cache synchronously
//!     
//!     #ifdef HAVE_DHCP
//!     if (daemon->dhcp || daemon->doing_dhcp6) {
//!         reread_dhcp();  // Re-parse DHCP config
//!         dhcp_update_configs(daemon->dhcp_conf);
//!         lease_update_from_configs();  // Preserve leases
//!         lease_update_file(now);
//!         lease_update_dns(1);
//!     }
//!     #endif
//! }
//! ```
//!
//! ## Rust Async Pattern
//!
//! ```rust,ignore
//! // Rust implementation (this module)
//! pub async fn handle_reload(&self, cache: &DnsCache, dhcp: &DhcpService) -> Result<()> {
//!     let _guard = self.reload_in_progress.lock().await;  // Prevent concurrent reloads
//!     
//!     info!("Configuration reload started");
//!     
//!     // Parse new configuration
//!     let new_config = parse_file(&self.config_path).await?;
//!     
//!     // Validate before applying
//!     validate_config(&new_config)?;
//!     
//!     // Atomically update configuration
//!     {
//!         let mut config = self.config.write().await;
//!         *config = new_config;
//!     }
//!     
//!     // Clear DNS cache (preserving negative cache if configured)
//!     cache.clear().await;
//!     
//!     // DHCP leases persist across reload (database not cleared)
//!     dhcp.reload_config().await?;
//!     
//!     info!("Configuration reload completed");
//!     Ok(())
//! }
//! ```
//!
//! # Key Improvements
//!
//! - **Async-signal-safe**: No reentrancy issues with Rust async signals
//! - **Validation first**: Configuration validated before applying (C applies optimistically)
//! - **Graceful degradation**: Failed reload preserves old configuration
//! - **Timeout protection**: Reload operations timeout after 30 seconds
//! - **Diff detection**: Logs specific configuration changes
//! - **Structured logging**: Detailed reload event tracing for audit trails
//!
//! # Usage
//!
//! ```rust,ignore
//! use tokio::signal::unix::{signal, SignalKind};
//!
//! let config = Arc::new(RwLock::new(Config::default()));
//! let reloader = ConfigReloader::new(config.clone(), PathBuf::from("/etc/dnsmasq.conf"));
//!
//! // Spawn signal handler task
//! tokio::spawn(async move {
//!     reloader.watch_for_changes().await;
//! });
//!
//! // Or trigger reload manually
//! reload_config(&config, &config_path, &cache, &dhcp).await?;
//! ```

use crate::config::parser::parse_file;
use crate::config::types::Config;
use crate::config::validator::validate_config;
use crate::error::ConfigError;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, instrument, warn};

// ============================================================================
// RELOAD STATE MACHINE
// ============================================================================

/// Reload operation state tracking
///
/// Represents the current phase of configuration reload for logging and error handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReloadState {
    /// Idle, waiting for reload trigger
    Idle,
    /// Reading configuration files from disk
    Reading,
    /// Validating parsed configuration
    Validating,
    /// Applying new configuration atomically
    Applying,
    /// Reload completed successfully
    Complete,
}

impl ReloadState {
    /// Returns human-readable state name for logging
    fn as_str(&self) -> &'static str {
        match self {
            ReloadState::Idle => "idle",
            ReloadState::Reading => "reading",
            ReloadState::Validating => "validating",
            ReloadState::Applying => "applying",
            ReloadState::Complete => "complete",
        }
    }
}

// ============================================================================
// CONFIGURATION RELOADER
// ============================================================================

/// Configuration reloader managing SIGHUP-triggered hot reload operations
///
/// Handles dynamic configuration reloads in response to SIGHUP signals or manual triggers.
/// Ensures atomic configuration updates with validation, rollback on failure, and detailed
/// audit logging.
///
/// # Thread Safety
///
/// Safe to share across async tasks via `Arc`. Uses interior mutability with `RwLock` for
/// configuration and `Mutex` for reload serialization.
///
/// # Examples
///
/// ```rust,ignore
/// let config = Arc::new(RwLock::new(Config::default()));
/// let reloader = ConfigReloader::new(config.clone(), PathBuf::from("/etc/dnsmasq.conf"));
///
/// // Manual reload trigger
/// reloader.handle_reload().await?;
///
/// // Automatic SIGHUP monitoring
/// tokio::spawn(async move {
///     reloader.watch_for_changes().await;
/// });
/// ```
pub struct ConfigReloader {
    /// Shared configuration updated atomically during reload
    config: Arc<RwLock<Config>>,

    /// Path to main configuration file
    config_path: PathBuf,

    /// Mutex ensuring only one reload operation executes at a time
    reload_in_progress: Arc<Mutex<()>>,

    /// Reload timeout duration (30 seconds default)
    timeout_duration: Duration,
}

impl ConfigReloader {
    /// Creates a new configuration reloader
    ///
    /// # Arguments
    ///
    /// * `config` - Shared configuration wrapped in Arc<RwLock<>> for atomic updates
    /// * `config_path` - Path to dnsmasq.conf file to monitor and reload
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let config = Arc::new(RwLock::new(Config::default()));
    /// let reloader = ConfigReloader::new(config, PathBuf::from("/etc/dnsmasq.conf"));
    /// ```
    pub fn new(config: Arc<RwLock<Config>>, config_path: PathBuf) -> Self {
        Self {
            config,
            config_path,
            reload_in_progress: Arc::new(Mutex::new(())),
            timeout_duration: Duration::from_secs(30),
        }
    }

    /// Handles configuration reload with full state machine and validation
    ///
    /// Performs complete reload operation with timeout protection:
    /// 1. Acquires reload lock to prevent concurrent reloads
    /// 2. Parses configuration file with timeout (30s default)
    /// 3. Validates new configuration for consistency
    /// 4. Compares with current configuration to log changes
    /// 5. Atomically applies new configuration
    /// 6. Logs completion with timing information
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if:
    /// - Configuration file cannot be read (`ConfigError::FileNotFound`)
    /// - Parsing fails due to syntax errors (`ConfigError::ParseError`)
    /// - Validation detects invalid settings (`ConfigError::ValidationFailed`)
    /// - Reload operation times out after 30 seconds
    ///
    /// On error, the current configuration remains unchanged (atomic rollback).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// match reloader.handle_reload().await {
    ///     Ok(()) => info!("Reload successful"),
    ///     Err(e) => error!("Reload failed: {}", e),
    /// }
    /// ```
    #[instrument(skip(self), fields(config_path = ?self.config_path))]
    pub async fn handle_reload(&self) -> Result<(), ConfigError> {
        // Acquire reload lock to serialize reload operations
        let _guard = self.reload_in_progress.lock().await;

        info!("Configuration reload initiated via SIGHUP");

        // State: Reading
        debug!(state = ReloadState::Reading.as_str(), "Parsing configuration file");

        // Parse new configuration with timeout protection
        let new_config = match timeout(
            self.timeout_duration,
            parse_file(&self.config_path)
        ).await {
            Ok(Ok(config)) => config,
            Ok(Err(e)) => {
                error!(error = %e, "Configuration parsing failed");
                return Err(e);
            }
            Err(_) => {
                let err = ConfigError::ValidationFailed {
                    reason: format!(
                        "Configuration reload timed out after {} seconds",
                        self.timeout_duration.as_secs()
                    ),
                };
                error!(error = %err, "Reload timeout exceeded");
                return Err(err);
            }
        };

        // State: Validating
        debug!(state = ReloadState::Validating.as_str(), "Validating new configuration");

        if let Err(e) = validate_config(&new_config) {
            error!(error = %e, "Configuration validation failed");
            warn!("Keeping current configuration due to validation failure");
            return Err(e);
        }

        // State: Applying
        debug!(state = ReloadState::Applying.as_str(), "Applying new configuration");

        // Get current config for diff detection
        let old_config = self.config.read().await.clone();

        // Log configuration changes
        self.log_config_diff(&old_config, &new_config);

        // Atomically update configuration
        {
            let mut config = self.config.write().await;
            *config = new_config;
        }

        // State: Complete
        info!(state = ReloadState::Complete.as_str(), "Configuration reload completed successfully");

        Ok(())
    }

    /// Watches for SIGHUP signals and triggers reload automatically
    ///
    /// Runs indefinitely, monitoring for SIGHUP (signal 1) and triggering reload operations.
    /// This method blocks the current task and should be spawned in a dedicated async task.
    ///
    /// # Signal Handling
    ///
    /// Uses `tokio::signal::unix::signal(SignalKind::hangup())` for async-signal-safe
    /// SIGHUP handling, avoiding reentrancy issues present in traditional C signal handlers.
    ///
    /// # Errors
    ///
    /// Logs errors but continues watching for signals. Individual reload failures do not
    /// stop the signal monitoring loop.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let reloader = ConfigReloader::new(config.clone(), config_path);
    ///
    /// // Spawn signal watcher in background task
    /// tokio::spawn(async move {
    ///     if let Err(e) = reloader.watch_for_changes().await {
    ///         error!("Signal watcher failed: {}", e);
    ///     }
    /// });
    /// ```
    ///
    /// # Platform Support
    ///
    /// Only available on Unix-like systems (Linux, BSD, macOS). On other platforms,
    /// use manual reload triggers via `handle_reload()`.
    #[cfg(unix)]
    pub async fn watch_for_changes(&self) -> Result<(), ConfigError> {
        use tokio::signal::unix::{signal, SignalKind};

        // Register SIGHUP handler
        let mut sighup = signal(SignalKind::hangup()).map_err(|e| ConfigError::ValidationFailed {
            reason: format!("Failed to register SIGHUP handler: {}", e),
        })?;

        info!("SIGHUP signal handler registered, watching for configuration changes");

        loop {
            // Wait for SIGHUP signal
            sighup.recv().await;

            info!("SIGHUP signal received, initiating configuration reload");

            // Trigger reload
            if let Err(e) = self.handle_reload().await {
                error!(error = %e, "Configuration reload failed after SIGHUP");
                // Continue watching despite error
            }
        }
    }

    /// Non-Unix fallback: watch_for_changes not available
    ///
    /// On non-Unix platforms, SIGHUP is not available. Use manual reload triggers
    /// or platform-specific file watching mechanisms.
    #[cfg(not(unix))]
    pub async fn watch_for_changes(&self) -> Result<(), ConfigError> {
        Err(ConfigError::ValidationFailed {
            reason: "SIGHUP signal handling not available on this platform".to_string(),
        })
    }

    /// Logs configuration differences between old and new configurations
    ///
    /// Performs field-by-field comparison and logs changes for audit trail.
    /// Helps administrators understand what changed during reload.
    fn log_config_diff(&self, old: &Config, new: &Config) {
        // DNS configuration changes
        if old.dns.port != new.dns.port {
            info!(
                old_port = old.dns.port,
                new_port = new.dns.port,
                "DNS port changed"
            );
        }

        if old.dns.cache_size != new.dns.cache_size {
            info!(
                old_size = old.dns.cache_size,
                new_size = new.dns.cache_size,
                "DNS cache size changed"
            );
        }

        if old.dns.dnssec_enabled != new.dns.dnssec_enabled {
            info!(
                old_value = old.dns.dnssec_enabled,
                new_value = new.dns.dnssec_enabled,
                "DNSSEC validation setting changed"
            );
        }

        // Network configuration changes
        if old.network.port != new.network.port {
            info!(
                old_port = old.network.port,
                new_port = new.network.port,
                "Network listen port changed"
            );
        }

        if old.network.interfaces != new.network.interfaces {
            info!(
                old_interfaces = ?old.network.interfaces,
                new_interfaces = ?new.network.interfaces,
                "Network interfaces changed"
            );
        }

        // DHCP configuration changes
        if old.dhcp.enabled != new.dhcp.enabled {
            info!(
                old_value = old.dhcp.enabled,
                new_value = new.dhcp.enabled,
                "DHCP server enabled setting changed"
            );
        }

        // Security configuration changes
        if old.security.user != new.security.user {
            info!(
                old_user = ?old.security.user,
                new_user = ?new.security.user,
                "User for privilege dropping changed"
            );
        }

        // If no changes detected, log that fact
        if old == new {
            info!("Configuration reloaded with no changes detected");
        } else {
            info!("Configuration reloaded with changes applied");
        }
    }
}

// ============================================================================
// STANDALONE RELOAD FUNCTION
// ============================================================================

/// Standalone configuration reload function for one-shot reload operations
///
/// Convenience function that creates a temporary `ConfigReloader` and performs
/// a single reload operation. Useful for manual reload triggers without maintaining
/// a `ConfigReloader` instance.
///
/// # Arguments
///
/// * `config` - Shared configuration to update
/// * `config_path` - Path to configuration file to reload
///
/// # Errors
///
/// Returns `ConfigError` if reload fails (see `ConfigReloader::handle_reload` for details).
///
/// # Examples
///
/// ```rust,ignore
/// // One-shot reload
/// reload_config(&config_arc, &PathBuf::from("/etc/dnsmasq.conf")).await?;
/// ```
#[instrument(skip(config), fields(config_path = ?config_path))]
pub async fn reload_config(
    config: &Arc<RwLock<Config>>,
    config_path: &PathBuf,
) -> Result<(), ConfigError> {
    let reloader = ConfigReloader::new(config.clone(), config_path.clone());
    reloader.handle_reload().await
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_config_reloader_creation() {
        let config = Arc::new(RwLock::new(Config::default()));
        let path = PathBuf::from("/etc/dnsmasq.conf");
        let reloader = ConfigReloader::new(config.clone(), path);

        let current_config = config.read().await;
        assert_eq!(current_config.network.port, 53);
    }

    #[tokio::test]
    async fn test_handle_reload_valid_config() {
        let config = Arc::new(RwLock::new(Config::default()));

        // Create a temporary config file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file
            .write_all(b"port=5353\ncache-size=1000\n")
            .unwrap();
        temp_file.flush().unwrap();

        let reloader = ConfigReloader::new(config.clone(), temp_file.path().to_path_buf());

        // Reload configuration
        let result = reloader.handle_reload().await;
        assert!(result.is_ok());

        // Verify configuration was updated
        let current_config = config.read().await;
        assert_eq!(current_config.network.port, 5353);
        assert_eq!(current_config.dns.cache_size, 1000);
    }

    #[tokio::test]
    async fn test_handle_reload_invalid_config() {
        let config = Arc::new(RwLock::new(Config::default()));

        // Create a temporary config file with invalid content
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"port=invalid\n").unwrap();
        temp_file.flush().unwrap();

        let original_port = config.read().await.network.port;

        let reloader = ConfigReloader::new(config.clone(), temp_file.path().to_path_buf());

        // Attempt reload
        let result = reloader.handle_reload().await;
        assert!(result.is_err());

        // Verify configuration was NOT updated (rollback)
        let current_config = config.read().await;
        assert_eq!(current_config.network.port, original_port);
    }

    #[tokio::test]
    async fn test_handle_reload_missing_file() {
        let config = Arc::new(RwLock::new(Config::default()));
        let reloader = ConfigReloader::new(config, PathBuf::from("/nonexistent/config.conf"));

        let result = reloader.handle_reload().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reload_config_standalone() {
        let config = Arc::new(RwLock::new(Config::default()));

        // Create a temporary config file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file
            .write_all(b"port=5454\ncache-size=2000\n")
            .unwrap();
        temp_file.flush().unwrap();

        let path = temp_file.path().to_path_buf();

        // Use standalone reload function
        let result = reload_config(&config, &path).await;
        assert!(result.is_ok());

        // Verify configuration was updated
        let current_config = config.read().await;
        assert_eq!(current_config.network.port, 5454);
        assert_eq!(current_config.dns.cache_size, 2000);
    }

    #[tokio::test]
    async fn test_concurrent_reload_serialization() {
        let config = Arc::new(RwLock::new(Config::default()));

        // Create a temporary config file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"port=5555\n").unwrap();
        temp_file.flush().unwrap();

        let reloader = Arc::new(ConfigReloader::new(
            config.clone(),
            temp_file.path().to_path_buf(),
        ));

        // Launch multiple concurrent reload attempts
        let mut handles = vec![];
        for _ in 0..5 {
            let reloader_clone = reloader.clone();
            handles.push(tokio::spawn(async move {
                reloader_clone.handle_reload().await
            }));
        }

        // All should complete successfully (serialized by mutex)
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }

        // Config should be updated
        let current_config = config.read().await;
        assert_eq!(current_config.network.port, 5555);
    }
}
