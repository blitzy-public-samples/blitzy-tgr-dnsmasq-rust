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

//! Configuration module root exporting public configuration API for dnsmasq Rust implementation.
//!
//! This module serves as the unified entry point for all configuration operations in dnsmasq,
//! replacing the C implementation's `option.c` (6314+ lines) with a modular, type-safe Rust
//! architecture. It declares and re-exports all configuration submodules providing parsing,
//! validation, and dynamic reload capabilities while maintaining 100% backward compatibility
//! with the C version's dnsmasq.conf syntax and command-line options.
//!
//! # Module Organization
//!
//! The configuration subsystem is organized into specialized modules:
//!
//! - **[`types`]**: Core configuration data structures ([`Config`], [`DnsConfig`], [`DhcpConfig`], etc.)
//!   replacing C's `struct daemon` with memory-safe Rust types featuring ownership semantics
//!   and compile-time guarantees. Eliminates manual memory management and pointer arithmetic.
//!
//! - **[`parser`]**: dnsmasq.conf file parser ([`ConfigParser`], [`parse_file()`]) implementing
//!   exact compatibility with C's `one_file()` function including quote handling, escape sequences,
//!   comment stripping, line continuation, and recursive include directive processing with cycle
//!   detection.
//!
//! - **[`cli`]**: Command-line argument parser ([`CliArgs`], [`parse_args()`]) using clap derive
//!   API to replace C's getopt_long() with type-safe parsing. Maintains all ~350 short and long
//!   options with identical semantics including option negation, accumulation, and help text.
//!
//! - **[`validator`]**: Configuration validation logic ([`ConfigValidator`], [`validate_config()`])
//!   implementing --test mode with comprehensive checks for IP addresses, hostnames, port ranges,
//!   DHCP pool consistency, cross-field dependencies, and RFC compliance.
//!
//! - **[`reload`]**: SIGHUP-based configuration reload handler ([`ConfigReloader`], [`reload_config()`])
//!   providing async-safe hot reload without daemon restart. Uses `Arc<RwLock<Config>>` for atomic
//!   configuration updates while preserving DHCP leases and validating new configuration before
//!   applying.
//!
//! # Configuration Precedence Rules
//!
//! Configuration values are resolved with the following precedence (highest to lowest):
//!
//! 1. **Command-line arguments** (highest precedence): Override all other sources
//! 2. **Configuration file directives**: Processed in order (last occurrence wins for singular options)
//! 3. **Include files**: Processed recursively at point of inclusion (conf-file=, conf-dir=)
//! 4. **Compile-time defaults** (lowest precedence): From constants.rs when options unspecified
//!
//! Special handling:
//! - List-based options (servers, dhcp-host, etc.) accumulate across all sources
//! - Boolean options support negation with `no-` prefix (e.g., `--no-resolv`)
//! - Some options trigger implicit configuration (e.g., `enable-ra` implies DHCPv6)
//!
//! # Primary API: ConfigBuilder Pattern
//!
//! The recommended approach for configuration construction uses the builder pattern from [`types`]:
//!
//! ```rust,ignore
//! use dnsmasq::config::{ConfigBuilder, Config};
//!
//! # async fn example() -> Result<Config, Box<dyn std::error::Error>> {
//! // Create builder with compile-time defaults
//! let config = ConfigBuilder::new()
//!     // Load from configuration file (async I/O)
//!     .from_file("/etc/dnsmasq.conf").await?
//!     // Apply command-line overrides (highest precedence)
//!     .from_args(std::env::args())?
//!     // Run validation checks
//!     .validate()?
//!     // Build final Config instance
//!     .build()?;
//!
//! println!("DNS port: {}", config.network.port);
//! println!("Cache size: {}", config.dns.cache_size);
//! # Ok(config)
//! # }
//! ```
//!
//! # Convenience API: load_config()
//!
//! For typical daemon initialization, use the [`load_config()`] convenience function that chains
//! builder methods automatically:
//!
//! ```rust,ignore
//! use dnsmasq::config::load_config;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse args, load config file, merge, validate - all in one call
//! let config = load_config(std::env::args()).await?;
//!
//! // Configuration is ready to use
//! println!("Running on port {}", config.network.port);
//! # Ok(())
//! # }
//! ```
//!
//! # Test Mode (--test)
//!
//! Configuration validation without daemon startup:
//!
//! ```rust,ignore
//! use dnsmasq::config::{load_config, validate_config};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = load_config(std::env::args()).await?;
//!
//! // Perform comprehensive validation
//! validate_config(&config)?;
//! println!("Configuration is valid");
//! std::process::exit(0);
//! # Ok(())
//! # }
//! ```
//!
//! # Dynamic Configuration Reload (SIGHUP)
//!
//! Hot reload configuration without daemon restart:
//!
//! ```rust,ignore
//! use dnsmasq::config::{reload_config, ConfigReloader};
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//! use tokio::signal::unix::{signal, SignalKind};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Arc::new(RwLock::new(load_config(std::env::args()).await?));
//! let reloader = ConfigReloader::new(config.clone());
//!
//! // Set up SIGHUP handler
//! let mut sighup = signal(SignalKind::hangup())?;
//! tokio::spawn(async move {
//!     loop {
//!         sighup.recv().await;
//!         if let Err(e) = reload_config(&reloader).await {
//!             eprintln!("Configuration reload failed: {}", e);
//!         }
//!     }
//! });
//! # Ok(())
//! # }
//! ```
//!
//! # Transformation from C Implementation
//!
//! This module transforms C's monolithic `option.c` with several critical improvements:
//!
//! ## Memory Safety
//!
//! ```c
//! // C implementation: Manual memory management with malloc/free
//! struct daemon *daemon = safe_malloc(sizeof(struct daemon));
//! memset(daemon, 0, sizeof(struct daemon));
//! // ... populate fields with malloc'd data
//! // Manual cleanup required, risk of leaks and use-after-free
//! ```
//!
//! ```rust,ignore
//! // Rust implementation: Automatic memory management with ownership
//! let config = Config::default();  // Stack or Box allocation
//! // Automatic Drop cleanup, no leaks possible
//! // Borrow checker prevents use-after-free at compile time
//! ```
//!
//! ## Error Handling
//!
//! ```c
//! // C implementation: Return codes and error globals
//! if (read_opts(argc, argv, &daemon) < 0) {
//!     fprintf(stderr, "Bad option: %s\n", last_error);
//!     return 1;
//! }
//! ```
//!
//! ```rust,ignore
//! // Rust implementation: Result types with ? operator
//! let config = load_config(std::env::args()).await?;
//! // Errors propagate with full context and stack traces
//! ```
//!
//! ## Type Safety
//!
//! ```c
//! // C implementation: Bitfield options with manual bit manipulation
//! unsigned int options[OPTION_SIZE];
//! set_option_bool(OPT_DOMAIN_NEEDED);
//! if (option_bool(OPT_DOMAIN_NEEDED)) { /* ... */ }
//! ```
//!
//! ```rust,ignore
//! // Rust implementation: Explicit boolean fields
//! config.dns.domain_needed = true;
//! if config.dns.domain_needed { /* ... */ }
//! ```
//!
//! # Re-exported Public API
//!
//! This module re-exports the following items for external consumption:
//!
//! ## Core Types
//! - [`Config`]: Main configuration struct with all subsections
//! - [`DnsConfig`]: DNS forwarding, caching, DNSSEC settings
//! - [`DhcpConfig`]: DHCPv4/v6 address pools, leases, static allocations
//! - [`NetworkConfig`]: Network interfaces, listen addresses, port configuration
//! - [`TftpConfig`]: TFTP server settings (feature-gated)
//! - [`LoggingConfig`]: Syslog facility, file logging, query verbosity
//! - [`SecurityConfig`]: User/group for privilege dropping, chroot jail
//!
//! ## Builder Pattern
//! - [`ConfigBuilder`]: Fluent API for configuration construction with validation
//!
//! ## Parsing Functions
//! - [`parse_args()`]: Parse command-line arguments from std::env::args()
//! - [`parse_file()`]: Parse dnsmasq.conf configuration file asynchronously
//!
//! ## Validation
//! - [`validate_config()`]: Comprehensive configuration validation
//! - [`ConfigValidator`]: Stateful validator for advanced validation scenarios
//!
//! ## Reload
//! - [`reload_config()`]: Reload configuration from disk (SIGHUP handler)
//! - [`ConfigReloader`]: Async configuration reload coordinator
//!
//! ## Constants
//! - [`DEFAULT_CONFIG_PATH`]: Default configuration file path (/etc/dnsmasq.conf or platform-specific)

// ============================================================================
// SUBMODULE DECLARATIONS
// ============================================================================

/// Configuration data structure definitions providing Config struct and subsection types.
///
/// Exports: [`Config`], [`DnsConfig`], [`DhcpConfig`], [`NetworkConfig`], [`TftpConfig`],
/// [`LoggingConfig`], [`SecurityConfig`], [`ConfigBuilder`]
pub mod types;

/// dnsmasq.conf configuration file parser with async I/O support.
///
/// Exports: [`ConfigParser`], [`parse_file()`]
pub mod parser;

/// Command-line argument parser using clap derive API.
///
/// Exports: [`CliArgs`], [`parse_args()`]
pub mod cli;

/// Configuration validation logic implementing --test mode.
///
/// Exports: [`ConfigValidator`], [`validate_config()`]
pub mod validator;

/// SIGHUP-based configuration reload handler for async-safe hot reloading.
///
/// Exports: [`ConfigReloader`], [`reload_config()`]
pub mod reload;

// ============================================================================
// PUBLIC RE-EXPORTS
// ============================================================================

// Core configuration types from types.rs
pub use types::{
    Config, ConfigBuilder, DhcpConfig, DnsConfig, LoggingConfig, NetworkConfig, SecurityConfig,
};

#[cfg(feature = "tftp")]
pub use types::TftpConfig;

// Parsing functionality from parser.rs
pub use parser::{parse_file, ConfigParser};

// Command-line argument parsing from cli.rs
pub use cli::{parse_args, parse_args_from, CliArgs};

// Validation functionality from validator.rs
pub use validator::{validate_config, ConfigValidator, ValidationResult};

// Reload functionality from reload.rs
pub use reload::{reload_config, ConfigReloader};

// ============================================================================
// EXTERNAL IMPORTS
// ============================================================================

use crate::error::ConfigError;

// ============================================================================
// PUBLIC CONSTANTS
// ============================================================================

/// Default configuration file path.
///
/// Platform-specific default location for dnsmasq.conf:
/// - Linux: `/etc/dnsmasq.conf`
/// - FreeBSD/OpenBSD/NetBSD: `/usr/local/etc/dnsmasq.conf`
/// - macOS: `/usr/local/etc/dnsmasq.conf`
///
/// This constant matches the C implementation's CONFFILE from config.h.
pub const DEFAULT_CONFIG_PATH: &str = crate::constants::CONFFILE;

// ============================================================================
// PRIMARY API: load_config() CONVENIENCE FUNCTION
// ============================================================================

/// Load and validate dnsmasq configuration from command-line arguments and configuration file.
///
/// This is the primary convenience function for initializing dnsmasq configuration during
/// daemon startup. It replicates the C implementation's `read_opts()` workflow by:
///
/// 1. Parsing command-line arguments with clap
/// 2. Determining configuration file path (CLI arg, default, or --no-conf)
/// 3. Loading and parsing configuration file if present (async I/O)
/// 4. Merging CLI overrides with highest precedence
/// 5. Validating final configuration for consistency and RFC compliance
///
/// # Configuration Precedence
///
/// Values are resolved with the following precedence (highest to lowest):
/// - Command-line arguments (highest)
/// - Configuration file directives  
/// - Compile-time defaults (lowest)
///
/// List-based options (servers, dhcp-host) accumulate across all sources.
///
/// # Arguments
///
/// * `args` - Command-line arguments iterator (typically `std::env::args()`)
///
/// # Returns
///
/// Returns `Ok(Config)` with fully validated configuration ready for daemon operation,
/// or `Err(ConfigError)` if parsing or validation fails.
///
/// # Errors
///
/// This function returns [`ConfigError`] variants for:
///
/// - **FileNotFound**: Configuration file specified but not readable
/// - **ParseError**: Syntax error in configuration file (line number included)
/// - **UnknownDirective**: Unrecognized configuration option
/// - **InvalidValue**: Configuration value fails validation (type mismatch, out of range)
/// - **Conflict**: Conflicting configuration directives detected
/// - **ValidationError**: Configuration fails semantic validation (DHCP pool overlap, etc.)
///
/// # Example
///
/// Basic daemon initialization:
///
/// ```rust,ignore
/// use dnsmasq::config::load_config;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = load_config(std::env::args()).await?;
///     
///     println!("Loaded configuration:");
///     println!("  DNS port: {}", config.network.port);
///     println!("  Cache size: {}", config.dns.cache_size);
///     println!("  Upstream servers: {}", config.dns.upstream_servers.len());
///     
///     // Start daemon with validated configuration
///     start_dnsmasq_daemon(config).await
/// }
/// ```
///
/// With error handling:
///
/// ```rust,ignore
/// use dnsmasq::config::{load_config, ConfigError};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// match load_config(std::env::args()).await {
///     Ok(config) => {
///         println!("Configuration loaded successfully");
///         // Proceed with daemon initialization
///     }
///     Err(ConfigError::ParseError { file_path, line_number, reason }) => {
///         eprintln!("Parse error in {}:{}: {}", file_path, line_number, reason);
///         std::process::exit(1);
///     }
///     Err(e) => {
///         eprintln!("Configuration error: {}", e);
///         std::process::exit(1);
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Implementation Notes
///
/// This function chains the builder pattern methods internally:
/// ```rust,ignore
/// ConfigBuilder::new()
///     .from_args(args)?
///     .from_file(config_path).await?
///     .validate()?
///     .build()
/// ```
///
/// For more control over the configuration loading process, use [`ConfigBuilder`] directly.
pub async fn load_config<I, T>(args: I) -> Result<Config, ConfigError>
where
    I: IntoIterator<Item = T>,
    T: Into<String> + Clone,
{
    // Parse command-line arguments first (to check for --no-conf and --conf-file)
    let args_vec: Vec<String> = args.into_iter().map(|s| s.into()).collect();
    let cli_args = parse_args_from(args_vec)?;

    // Start with builder using compile-time defaults
    let mut builder = ConfigBuilder::new();

    // Load configuration file unless --no-conf specified
    if !cli_args.no_conf {
        let config_path = cli_args
            .conf_file
            .as_deref()
            .unwrap_or_else(|| std::path::Path::new(DEFAULT_CONFIG_PATH));

        // Check if configuration file exists and is readable
        if config_path.exists() {
            // Use async file I/O for non-blocking read
            builder = builder.from_file(config_path).await?;
        } else if cli_args.conf_file.is_some() {
            // User explicitly specified a config file that doesn't exist - error
            return Err(ConfigError::FileNotFound {
                path: config_path.display().to_string(),
            });
        }
        // If default config path doesn't exist and wasn't explicitly specified, just skip it
    }

    // Apply command-line overrides (highest precedence)
    builder = builder.from_args(&cli_args)?;

    // Validate and build final configuration
    builder = builder.validate()?;
    let config = builder.build()?;

    Ok(config)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Compile-time verification that all required exports are accessible
        // This test ensures the module API contract is maintained

        // Core types should be accessible
        let _: Config;
        let _: DnsConfig;
        let _: DhcpConfig;
        let _: NetworkConfig;
        #[cfg(feature = "tftp")]
        let _: TftpConfig;
        let _: LoggingConfig;
        let _: SecurityConfig;

        // Builder pattern should be accessible
        let _: ConfigBuilder;

        // Parsing functions should be accessible
        let _: fn() -> CliArgs = parse_args;

        // Validation should be accessible
        let _: fn(&Config) -> ValidationResult = validate_config;
        let _: ConfigValidator<'_>;

        // Reload should be accessible
        let _: ConfigReloader;
    }

    #[test]
    fn test_default_config_path_constant() {
        // Verify DEFAULT_CONFIG_PATH is defined and non-empty
        assert!(!DEFAULT_CONFIG_PATH.is_empty());
        assert!(
            DEFAULT_CONFIG_PATH.contains("dnsmasq.conf"),
            "Default config path should reference dnsmasq.conf"
        );
    }

    #[tokio::test]
    async fn test_load_config_with_minimal_args() {
        // Test loading configuration with minimal arguments (--no-conf to skip file)
        let args = vec!["dnsmasq", "--no-conf", "--no-daemon"];

        let result = load_config(args.into_iter()).await;

        // Should succeed with default configuration
        assert!(
            result.is_ok(),
            "load_config should succeed with --no-conf: {:?}",
            result.err()
        );

        let config = result.unwrap();

        // Verify default values are applied
        assert!(
            config.network.port > 0,
            "Default DNS port should be set"
        );
        assert!(
            config.dns.cache_size > 0,
            "Default cache size should be set"
        );
    }

    #[tokio::test]
    async fn test_load_config_with_nonexistent_file() {
        // Test that explicitly specifying a non-existent config file fails
        let args = vec![
            "dnsmasq",
            "--conf-file=/tmp/nonexistent_dnsmasq_test.conf",
        ];

        let result = load_config(args.into_iter()).await;

        // Should fail with FileNotFound error
        assert!(
            result.is_err(),
            "load_config should fail with non-existent config file"
        );

        if let Err(ConfigError::FileNotFound { path }) = result {
            assert!(
                path.contains("nonexistent"),
                "Error should reference the non-existent file"
            );
        } else {
            panic!("Expected FileNotFound error");
        }
    }

    #[tokio::test]
    async fn test_cli_precedence_over_defaults() {
        // Test that CLI arguments override default values
        let args = vec!["dnsmasq", "--no-conf", "--port=5353"];

        let result = load_config(args.into_iter()).await;
        assert!(result.is_ok());

        let config = result.unwrap();

        // CLI-specified port should override default
        assert_eq!(
            config.network.port, 5353,
            "CLI port argument should override default"
        );
    }

    #[test]
    #[allow(unused_imports)]
    fn test_re_exported_types_accessible() {
        // Verify all re-exported types from submodules are accessible
        // This ensures the public API surface is correctly exposed

        use crate::config::{
            parse_args, parse_file, reload_config, validate_config, CliArgs, Config,
            ConfigBuilder, ConfigParser, ConfigReloader, ConfigValidator, DhcpConfig, DnsConfig,
            LoggingConfig, NetworkConfig, SecurityConfig, ValidationResult,
        };
        
        #[cfg(feature = "tftp")]
        use crate::config::TftpConfig;

        // If this compiles, all re-exports are working correctly
    }
}
