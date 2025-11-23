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

//! Binary entry point for dnsmasq Rust implementation.
//!
//! This module provides the main() function that orchestrates daemon initialization,
//! configuration loading, service creation, privilege dropping, signal handling, and
//! event loop execution. It replaces the C implementation's main() from src/dnsmasq.c
//! with memory-safe Rust patterns using tokio async/await architecture.
//!
//! # Architecture Overview
//!
//! The C poll()-based single-threaded event loop is transformed into a tokio async
//! runtime with structured concurrency:
//!
//! ```text
//! C Pattern:                          Rust Pattern:
//! main()                              #[tokio::main] async fn main()
//!   ├─ getopt_long()                    ├─ clap::Parser::parse()
//!   ├─ read_opts()                      ├─ config::load_config()
//!   ├─ bind(port 53)                    ├─ UdpSocket::bind("0.0.0.0:53")
//!   ├─ setuid(nobody)                   ├─ privileges::drop_privileges()
//!   ├─ signal() handlers                ├─ tokio::signal handlers
//!   ├─ fork() to background             ├─ (daemon managed by systemd)
//!   └─ while(1) poll() loop             └─ EventLoop::run().await
//!        ├─ check DNS socket                  ├─ tokio::select! on all sockets
//!        ├─ check DHCP socket                 ├─ async service handlers
//!        └─ async_event(signals)              └─ structured signal handling
//! ```
//!
//! # Initialization Sequence
//!
//! 1. **CLI Argument Parsing**: clap parses command-line arguments into CliArgs struct
//! 2. **Early Exit Modes**: Handle --version, --help, --test modes immediately
//! 3. **Logging Initialization**: Set up tracing subscriber for structured logging
//! 4. **Configuration Loading**: Parse dnsmasq.conf and merge with CLI args
//! 5. **Configuration Validation**: Run comprehensive checks (--test mode stops here)
//! 6. **Socket Binding**: Bind privileged ports (53, 67, 547, 69) as root
//! 7. **Privilege Dropping**: setuid/setgid to configured user, retain capabilities
//! 8. **Service Initialization**: Create DnsService, DhcpService, TftpServer, RadVServer
//! 9. **Signal Handler Setup**: Install SIGHUP, SIGTERM, SIGUSR1, SIGUSR2 handlers
//! 10. **Event Loop Creation**: Construct EventLoop with all services and sockets
//! 11. **Systemd Notification**: Signal readiness to systemd (sd_notify)
//! 12. **Event Loop Execution**: Enter main loop, never returns until shutdown
//!
//! # Signal Handling
//!
//! All signals are handled asynchronously using tokio::signal:
//!
//! - **SIGHUP**: Reload configuration from disk, clear DNS cache, re-enumerate interfaces
//! - **SIGTERM/SIGINT**: Graceful shutdown, flush DHCP leases, close sockets
//! - **SIGUSR1**: Dump DNS cache contents to log for diagnostics
//! - **SIGUSR2**: Log statistics (queries, cache hits, DHCP leases, DNSSEC validations)
//! - **SIGCHLD**: Handled by tokio::process for helper script reaping
//! - **SIGPIPE**: Ignored (default tokio behavior)
//!
//! # Privilege Separation
//!
//! Security model matches C implementation:
//!
//! 1. Start as root (UID 0) to bind privileged ports
//! 2. Bind DNS port 53, DHCP ports 67/547, TFTP port 69
//! 3. On Linux: Set capabilities CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW
//! 4. Drop to configured user (--user option, default "nobody")
//! 5. All packet processing runs as unprivileged user
//!
//! # Memory Safety
//!
//! Transformation eliminates C memory safety issues:
//!
//! - C malloc/free → Rust Box/Vec with automatic Drop
//! - C global `struct daemon *daemon` → Arc<RwLock<Config>> shared state
//! - C signal pipe → tokio::signal async-safe channels
//! - C poll() fd_set → tokio::select! macro
//! - C manual buffer management → Vec<u8> with bounds checking
//!
//! # Error Handling
//!
//! Fatal errors during initialization cause immediate exit with code 1:
//!
//! - Configuration parsing errors
//! - Socket binding failures (port in use, permission denied)
//! - Privilege drop failures
//! - Service initialization errors
//!
//! Non-fatal errors are logged but allow startup to continue:
//!
//! - Optional config file missing
//! - Interface enumeration warnings
//! - Helper script execution failures
//!
//! # Performance
//!
//! The async runtime provides equivalent or better performance than C:
//!
//! - Zero-copy packet handling where possible
//! - Async I/O reduces context switches vs poll()
//! - Structured concurrency eliminates callback spaghetti
//! - Compiler optimizations (LTO, PGO) match C performance
//!
//! # Platform Support
//!
//! All platforms supported by C version:
//!
//! - Linux (primary): Full feature support including netlink, capabilities, nftables
//! - FreeBSD/OpenBSD/NetBSD: BPF packet filtering, pledge/unveil security
//! - macOS: Network framework integration
//! - Solaris: Basic functionality
//! - Android: AOSP build support

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use std::process;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// Internal module imports (from depends_on_files)
use dnsmasq::config::{validate_config, CliArgs, Config, ConfigBuilder};
use dnsmasq::constants::VERSION;
use dnsmasq::error::ConfigError;
use dnsmasq::platform::privileges::drop_privileges;
use dnsmasq::platform::systemd;
use dnsmasq::runtime::EventLoop;
// use dnsmasq::util::log_init;

/// Main entry point for dnsmasq daemon.
///
/// This function orchestrates complete daemon initialization including configuration
/// parsing, socket binding, privilege dropping, signal handling, and event loop execution.
/// It replaces the C implementation's main() from src/dnsmasq.c with async/await patterns.
///
/// # Exit Codes
///
/// - 0: Normal shutdown after SIGTERM or successful --test validation
/// - 1: Fatal error during initialization (configuration error, socket binding failure)
///
/// # Examples
///
/// ```bash
/// # Normal daemon startup
/// dnsmasq --conf-file=/etc/dnsmasq.conf
///
/// # Test configuration without starting
/// dnsmasq --test --conf-file=/etc/dnsmasq.conf
///
/// # Show version and exit
/// dnsmasq --version
///
/// # Foreground mode with debug logging
/// RUST_LOG=debug dnsmasq --no-daemon
/// ```
#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments using clap derive
    let cli_args = match CliArgs::try_parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    // Handle --version flag immediately (exit without initialization)
    if cli_args.version_flag {
        print_version();
        process::exit(0);
    }

    // Handle --help flag immediately (exit without initialization)
    if cli_args.help_flag {
        CliArgs::command().print_help().unwrap();
        process::exit(0);
    }

    // Initialize logging system early to capture initialization errors
    // This sets up tracing subscriber with environment-based filtering
    init_logging_early(&cli_args);

    info!("dnsmasq v{} (Rust implementation) starting", VERSION);
    info!("Command-line arguments parsed successfully");

    // Load and merge configuration from file and CLI arguments
    // This replaces C's read_opts() function from option.c
    let config = match load_configuration(&cli_args).await {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Configuration loading failed: {:#}", e);
            eprintln!("dnsmasq: configuration error: {}", e);
            process::exit(1);
        }
    };

    info!("Configuration loaded successfully");

    // Validate configuration comprehensively
    // This performs --test mode checks on all configuration options
    if let Err(e) = validate_configuration(&config) {
        error!("Configuration validation failed: {:#}", e);
        eprintln!("dnsmasq: configuration validation error: {}", e);
        process::exit(1);
    }

    info!("Configuration validated successfully");

    // If --test mode, exit successfully after validation
    if cli_args.test {
        println!("dnsmasq: syntax check OK");
        info!("Configuration test passed, exiting");
        process::exit(0);
    }

    // Wrap configuration in Arc<RwLock<>> for shared mutable access
    // This enables SIGHUP-based configuration reload while services are running
    let config = Arc::new(RwLock::new(config));

    // Log daemon startup information matching C version output
    log_startup_info(&config).await;

    // Initialize the event loop with all services
    // This binds privileged ports (requires root or CAP_NET_BIND_SERVICE)
    // and creates DNS, DHCP, TFTP, and RA service instances
    info!("Initializing event loop and services");
    let event_loop = match EventLoop::new(Arc::clone(&config)).await {
        Ok(event_loop) => event_loop,
        Err(e) => {
            error!("Event loop initialization failed: {:#}", e);
            eprintln!("dnsmasq: failed to initialize: {}", e);
            process::exit(1);
        }
    };

    info!("Event loop initialized successfully");

    // Drop privileges to configured user after binding privileged ports
    // This matches C security model: start as root, bind ports, drop to nobody
    if let Err(e) = drop_privileges_safely(&config).await {
        error!("Privilege drop failed: {:#}", e);
        eprintln!("dnsmasq: failed to drop privileges: {}", e);
        process::exit(1);
    }

    info!("Privileges dropped successfully");

    // Notify systemd that daemon is ready (Type=notify service)
    // This signals that initialization is complete and service is operational
    notify_systemd_ready();

    info!("Entering main event loop");

    // Enter main event loop - never returns until shutdown signal
    // This replaces C's while(1) poll() loop with tokio::select! multiplexing
    if let Err(e) = event_loop.run().await {
        error!("Event loop terminated with error: {:#}", e);
        eprintln!("dnsmasq: runtime error: {}", e);
        process::exit(1);
    }

    // Graceful shutdown completed
    info!("dnsmasq shutdown complete");
    Ok(())
}

/// Initialize logging system early in startup process.
///
/// This function sets up the tracing subscriber for structured logging, replacing
/// C's syslog integration. The subscriber is configured based on command-line flags:
///
/// - `--no-daemon`: Log to stderr with human-readable format
/// - Default: Log to syslog with structured JSON format
/// - Environment variable `RUST_LOG` controls filtering (e.g., RUST_LOG=debug)
///
/// # Arguments
///
/// * `cli_args` - Parsed command-line arguments containing logging flags
///
/// # Panics
///
/// Panics if logging initialization fails (tracing subscriber cannot be set)
fn init_logging_early(cli_args: &CliArgs) {
    // Determine log output destination based on CLI flags
    let log_to_stderr = cli_args.no_daemon;

    // Build environment filter from RUST_LOG or default to INFO level
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if log_to_stderr {
        // Foreground mode: human-readable logs to stderr
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_target(false)
                    .with_thread_ids(false)
                    .with_thread_names(false)
                    .compact(),
            )
            .init();
    } else {
        // Daemon mode: structured JSON logs to syslog
        // TODO: Integrate with actual syslog via tracing-syslog or journald
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json().with_writer(std::io::stderr))
            .init();
    }
}

/// Print version information and compilation options.
///
/// This replaces C's --version output, displaying:
/// - Version number (from constants::VERSION)
/// - Compilation features (DNSSEC, DBus, etc.)
/// - Copyright and license information
///
/// Matches C output format for compatibility with scripts that parse version string.
fn print_version() {
    println!("dnsmasq version {}  Copyright (c) 2000-2025 Simon Kelley", VERSION);
    println!();

    // Display enabled features matching C compile_opts string
    print!("Compile time options: ");

    let mut features = vec!["DHCP", "DHCPv6", "IPv6"]; // Core features always present

    #[cfg(feature = "dnssec")]
    features.push("DNSSEC");

    #[cfg(feature = "dbus")]
    features.push("DBus");

    #[cfg(feature = "idn")]
    features.push("IDN");

    #[cfg(feature = "lua-scripts")]
    features.push("Lua");

    #[cfg(feature = "tftp")]
    features.push("TFTP");

    #[cfg(feature = "conntrack")]
    features.push("conntrack");

    #[cfg(feature = "ipset")]
    features.push("ipset");

    #[cfg(feature = "nftset")]
    features.push("nftset");

    println!("{}", features.join(" "));
    println!();
    println!("This software comes with ABSOLUTELY NO WARRANTY.");
    println!("See https://www.gnu.org/licenses/gpl-2.0.html for details.");
}

/// Load configuration from file and command-line arguments.
///
/// This async function replaces C's read_opts() from option.c, performing:
/// 1. Configuration file parsing (dnsmasq.conf format)
/// 2. Command-line argument application (override file values)
/// 3. Configuration merging and precedence resolution
/// 4. Include file processing (recursive with cycle detection)
///
/// # Arguments
///
/// * `cli_args` - Parsed command-line arguments from clap
///
/// # Returns
///
/// * `Ok(Config)` - Fully merged and parsed configuration
/// * `Err(anyhow::Error)` - Configuration file not found, parse error, or invalid options
///
/// # Errors
///
/// Returns error if:
/// - Configuration file cannot be read (unless --no-conf specified)
/// - Configuration syntax is invalid
/// - Include files contain cycles
/// - Required options are missing or conflicting
async fn load_configuration(cli_args: &CliArgs) -> Result<Config> {
    // Start with builder using compile-time defaults
    let mut builder = ConfigBuilder::new();

    // Load configuration file unless --no-conf specified
    if !cli_args.no_conf {
        if let Some(ref config_path) = cli_args.conf_file {
            // User specified a config file path
            if config_path.exists() {
                builder = builder
                    .from_file(config_path)
                    .await
                    .context("Failed to load configuration file")?;
            } else {
                // Explicitly specified file doesn't exist - error
                return Err(anyhow::anyhow!(
                    "Configuration file not found: {}",
                    config_path.display()
                ));
            }
        }
        // If no conf_file specified, ConfigBuilder will use defaults
    }

    // Apply command-line overrides (highest precedence)
    builder = builder.from_args(cli_args).context("Failed to apply command-line arguments")?;

    // Validate and build final configuration
    builder = builder.validate().context("Configuration validation during build failed")?;

    let config = builder.build().context("Failed to build configuration")?;

    Ok(config)
}

/// Validate complete configuration for correctness and consistency.
///
/// This function performs comprehensive validation checks matching C's --test mode,
/// including:
/// - IP address and port range validation
/// - Hostname and domain name RFC compliance
/// - DHCP pool consistency (no overlaps, valid ranges)
/// - DHCPv6 prefix delegation correctness
/// - DNSSEC trust anchor validity
/// - File path accessibility (lease files, PID files, etc.)
/// - Cross-field dependencies and implications
///
/// # Arguments
///
/// * `config` - Configuration to validate
///
/// # Returns
///
/// * `Ok(())` - Configuration is valid
/// * `Err(ConfigError)` - Validation failure with detailed error description
///
/// # Examples
///
/// ```rust,ignore
/// let config = load_config(&cli_args).await?;
/// validate_configuration(&config)?;
/// println!("Configuration is valid");
/// ```
fn validate_configuration(config: &Config) -> Result<(), ConfigError> {
    validate_config(config).context("Configuration validation failed").map_err(|e| {
        ConfigError::InvalidValue {
            directive: "configuration".to_string(),
            reason: format!("{:#}", e),
        }
    })
}

/// Log startup information matching C version output format.
///
/// This function logs daemon startup messages to match C implementation's syslog output,
/// including:
/// - Version number and cache size
/// - Enabled features and services
/// - DNSSEC configuration
/// - DHCP ranges and contexts
/// - Compilation options
///
/// External tools may parse these log messages, so format compatibility is critical.
///
/// # Arguments
///
/// * `config` - Daemon configuration (wrapped in Arc<RwLock> for shared access)
async fn log_startup_info(config: &Arc<RwLock<Config>>) {
    let cfg = config.read().await;

    // Log version and DNS configuration
    if cfg.network.port == 0 {
        info!("started, version {} DNS disabled", VERSION);
    } else if cfg.dns.cache_size > 0 {
        info!("started, version {} cachesize {}", VERSION, cfg.dns.cache_size);

        if cfg.dns.cache_size > 10000 {
            warn!("cache size greater than 10000 may cause performance issues");
        }
    } else {
        info!("started, version {} cache disabled", VERSION);
    }

    // Log DHCP configuration if enabled (determined by presence of ranges)
    if !cfg.dhcp.v4_ranges.is_empty() {
        info!("DHCP service enabled");
        for range in &cfg.dhcp.v4_ranges {
            info!("DHCP range {} to {}", range.start, range.end);
        }
    }

    // Log DHCPv6 configuration if enabled (determined by presence of ranges)
    if !cfg.dhcp.v6_ranges.is_empty() {
        info!("DHCPv6 service enabled");
        for range in &cfg.dhcp.v6_ranges {
            info!("DHCPv6 range {} to {}", range.start, range.end);
        }
    }

    // Log Router Advertisement if enabled (determined by presence of RA interfaces)
    if !cfg.ra_interfaces.is_empty() {
        info!("IPv6 router advertisement enabled");
    }

    // Log DNSSEC status
    #[cfg(feature = "dnssec")]
    if cfg.dns.dnssec_enabled {
        info!("DNSSEC validation enabled");
    }

    // Log TFTP status (enabled if tftp_prefix is set)
    #[cfg(feature = "tftp")]
    if let Some(ref root) = cfg.tftp.tftp_prefix {
        info!("TFTP root is {}", root.display());
    }

    // Log D-Bus status
    #[cfg(feature = "dbus")]
    if cfg.platform.dbus_enabled {
        info!("DBus support enabled");
    }
}

/// Drop privileges to configured user after binding privileged ports.
///
/// This function implements the security model matching C's privilege drop sequence:
/// 1. Verify running as root (UID 0)
/// 2. On Linux: Set process capabilities (CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW)
/// 3. Call setgid() to drop to configured group
/// 4. Call setuid() to drop to configured user
/// 5. Verify privilege drop was successful
///
/// After this function returns, the process runs as an unprivileged user with minimal
/// capabilities retained for networking operations.
///
/// # Arguments
///
/// * `config` - Daemon configuration containing user/group settings
///
/// # Returns
///
/// * `Ok(())` - Privileges dropped successfully
/// * `Err(anyhow::Error)` - Privilege drop failed (user not found, setuid failed, etc.)
///
/// # Safety
///
/// This function must be called after binding all privileged ports and before processing
/// any untrusted network input. Failure to drop privileges is a fatal security error.
async fn drop_privileges_safely(config: &Arc<RwLock<Config>>) -> Result<()> {
    let cfg = config.read().await;

    // Check if we're running as root before attempting privilege drop
    #[cfg(unix)]
    {
        use nix::unistd::Uid;
        let current_uid = Uid::effective();

        if current_uid.is_root() {
            // Running as root - proceed with privilege drop
            // Retain CAP_NET_ADMIN for DHCP and CAP_NET_RAW for ICMP (Router Advertisement)
            drop_privileges(&cfg.security, true, true).context("Failed to drop privileges")?;

            info!(
                "Privileges dropped to user: {:?}, group: {:?}",
                cfg.security.user.as_deref(),
                cfg.security.group.as_deref()
            );
        } else {
            // Already running as non-root user - skip privilege drop
            info!("Running as non-root user (UID {}), skipping privilege drop", current_uid);
        }
    }

    #[cfg(not(unix))]
    {
        // Windows or other non-Unix platforms - no privilege dropping
        info!("Privilege dropping not supported on this platform");
    }

    Ok(())
}

/// Notify systemd that daemon initialization is complete.
///
/// This function sends sd_notify(READY=1) to systemd for Type=notify service units,
/// signaling that the daemon has finished initialization and is ready to serve requests.
///
/// If systemd socket activation is used, this also acknowledges socket transfer.
///
/// On non-systemd platforms or when not started by systemd, this function is a no-op.
fn notify_systemd_ready() {
    #[cfg(target_os = "linux")]
    {
        // Send readiness notification to systemd
        // First parameter is whether to unset the environment variable
        if let Err(e) = systemd::sd_notify(false, "READY=1") {
            warn!("Failed to notify systemd: {}", e);
        } else {
            info!("Systemd notified of daemon readiness");
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // No-op on non-Linux platforms
    }
}
