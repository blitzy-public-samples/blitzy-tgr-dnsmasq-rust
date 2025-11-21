// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Platform integration and operating system abstraction layer.
//!
//! This module provides a unified interface to operating system services, IPC mechanisms,
//! and security frameworks, replacing the scattered C `#ifdef` blocks from dnsmasq.c,
//! dbus.c, and platform-specific files with clean Rust module organization using `cfg` attributes.
//!
//! # Architecture
//!
//! The platform module establishes the integration boundary between portable Rust code
//! and OS-specific APIs, ensuring that core dnsmasq business logic remains platform-agnostic.
//! All platform-specific code is confined to submodules with appropriate conditional
//! compilation attributes.
//!
//! ## Design Principles
//!
//! 1. **Isolation**: Platform-specific code never leaks into core business logic modules
//! 2. **Conditional Compilation**: Features and platform-specific modules enabled via `#[cfg]`
//! 3. **Unified Interface**: Common abstractions exposed regardless of underlying platform
//! 4. **Memory Safety**: All unsafe platform FFI calls are confined to submodules with safety documentation
//!
//! # Module Organization
//!
//! ```text
//! platform/
//! ├── mod.rs          ← You are here (module root, re-exports only)
//! ├── signals.rs      ← POSIX signal handling (all platforms)
//! ├── privileges.rs   ← Capability/privilege management (all platforms)
//! ├── dbus.rs         ← D-Bus control interface (feature = "dbus")
//! ├── ubus.rs         ← OpenWrt ubus interface (feature = "ubus")
//! ├── inotify.rs      ← Linux file monitoring (target_os = "linux")
//! └── systemd.rs      ← systemd integration (all platforms)
//! ```
//!
//! # Submodule Responsibilities
//!
//! ## Core Platform Services (Always Available)
//!
//! ### signals
//! - POSIX signal handling with tokio async integration
//! - Converts OS signals (SIGHUP, SIGTERM, SIGUSR1, SIGUSR2, SIGCHLD, SIGALRM) to Rust events
//! - Replaces C signal handlers from dnsmasq.c:sig_handler() with async-signal-safe implementation
//! - Provides [`SignalEvent`] enum for type-safe signal dispatch
//!
//! ### privileges
//! - Capability-based privilege dropping after binding to privileged ports
//! - User/group switching with security validation
//! - Platform-specific implementations:
//!   - Linux: capabilities(7) via caps crate (CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW)
//!   - BSD: pledge(2) / unveil(2) via nix crate
//!   - macOS: sandbox-exec or privilege drop
//! - Replaces C privilege code from dnsmasq.c (lines ~600-750)
//!
//! ### systemd
//! - systemd socket activation (sd_listen_fds)
//! - Readiness notification (sd_notify "READY=1")
//! - Watchdog support (sd_notify "WATCHDOG=1")
//! - Status updates (sd_notify "STATUS=...")
//! - Available on all platforms (no-op on non-systemd systems)
//!
//! ## Optional Platform Services (Conditionally Compiled)
//!
//! ### dbus (feature = "dbus")
//! - D-Bus control interface on `uk.org.thekelleys.dnsmasq` service name
//! - Methods: SetServers, ClearCache, GetVersion, GetMetrics
//! - Signals: DhcpLeaseAdded, DhcpLeaseDeleted
//! - Replaces C D-Bus code from dbus.c
//! - Uses zbus crate for pure Rust implementation (no FFI)
//!
//! ### ubus (feature = "ubus")
//! - OpenWrt ubus control interface
//! - Exposes metrics and control methods via ubus JSON-RPC
//! - Replaces C ubus code from ubus.c
//! - May use custom implementation or FFI to libubus
//!
//! ### inotify (target_os = "linux")
//! - Linux inotify file system monitoring
//! - Watches /etc/dnsmasq.conf and include directories for changes
//! - Triggers SIGHUP-equivalent config reload on file modification
//! - Replaces C inotify code from inotify.c
//! - Uses notify crate for safe inotify access
//!
//! # C Code Mapping
//!
//! This module replaces scattered platform-specific C code:
//!
//! ## From dnsmasq.c
//! ```c
//! // C signal handler (dnsmasq.c:1330)
//! static void sig_handler(int sig) {
//!     if (sig == SIGHUP)
//!         send_event(EVENT_RELOAD, 0, NULL);
//!     else if (sig == SIGTERM)
//!         send_event(EVENT_TERM, 0, NULL);
//!     // ...
//! }
//! ```
//!
//! Becomes:
//! ```rust,ignore
//! use crate::platform::{setup_signal_handlers, SignalEvent};
//!
//! let mut signal_rx = setup_signal_handlers().await?;
//! match signal_rx.recv().await {
//!     Some(SignalEvent::Reload) => reload_config().await?,
//!     Some(SignalEvent::Terminate) => shutdown().await?,
//!     // ...
//! }
//! ```
//!
//! ## From dnsmasq.c (privilege drop)
//! ```c
//! // C privilege drop (dnsmasq.c:~700)
//! if (daemon->username) {
//!     if (setuid(ent_pw->pw_uid) == -1)
//!         die("failed to change user to %s: %s", daemon->username, EC_PRIVS);
//! }
//! #ifdef HAVE_LINUX_NETWORK
//! capng_apply(CAPNG_SELECT_BOTH);
//! #endif
//! ```
//!
//! Becomes:
//! ```rust,ignore
//! use crate::platform::drop_privileges;
//!
//! drop_privileges(&config.user, &config.group).await?;
//! // Capabilities automatically managed based on platform
//! ```
//!
//! ## From dbus.c
//! ```c
//! // C D-Bus interface (dbus.c:~50)
//! #ifdef HAVE_DBUS
//! DBusConnection *dbus_connection;
//! dbus_bus_request_name(connection, "uk.org.thekelleys.dnsmasq", ...);
//! #endif
//! ```
//!
//! Becomes:
//! ```rust,ignore
//! #[cfg(feature = "dbus")]
//! use crate::platform::DbusDaemon;
//!
//! #[cfg(feature = "dbus")]
//! let dbus = DbusDaemon::new().await?;
//! dbus.run().await?;
//! ```
//!
//! # Feature Flags
//!
//! Enable platform features in Cargo.toml:
//!
//! ```toml
//! [features]
//! default = []
//! dbus = ["zbus"]
//! ubus = []
//! inotify = ["notify"]
//! ```
//!
//! Conditional compilation ensures only needed code is compiled:
//!
//! ```rust,ignore
//! // D-Bus only compiled when feature = "dbus" enabled
//! #[cfg(feature = "dbus")]
//! pub mod dbus;
//!
//! // inotify only on Linux
//! #[cfg(target_os = "linux")]
//! pub mod inotify;
//! ```
//!
//! # Platform Compatibility Matrix
//!
//! | Module     | Linux | FreeBSD | OpenBSD | NetBSD | macOS | Solaris |
//! |------------|-------|---------|---------|--------|-------|---------|
//! | signals    | ✓     | ✓       | ✓       | ✓      | ✓     | ✓       |
//! | privileges | ✓     | ✓       | ✓       | ✓      | ✓     | ✓       |
//! | systemd    | ✓     | ✓*      | ✓*      | ✓*     | ✓*    | ✓*      |
//! | dbus       | ✓     | ✓       | ✓       | ✓      | ✓     | ✓       |
//! | ubus       | ✓     | ✗       | ✗       | ✗      | ✗     | ✗       |
//! | inotify    | ✓     | ✗       | ✗       | ✗      | ✗     | ✗       |
//!
//! *systemd module available but no-op on non-systemd platforms
//!
//! # Memory Safety
//!
//! This module root contains **zero unsafe code**. All platform FFI interactions
//! are confined to submodules with explicit safety documentation:
//!
//! - `signals.rs`: Uses tokio::signal (safe async signal handling)
//! - `privileges.rs`: Uses nix/caps crates (unsafe confined to capability FFI)
//! - `dbus.rs`: Uses zbus crate (pure Rust, no unsafe)
//! - `ubus.rs`: May contain unsafe FFI if using libubus (documented in submodule)
//! - `inotify.rs`: Uses notify crate (safe wrapper around inotify syscalls)
//! - `systemd.rs`: Uses libsystemd FFI (unsafe confined to sd_notify calls)
//!
//! # Examples
//!
//! ## Signal Handling
//!
//! ```rust,ignore
//! use crate::platform::{setup_signal_handlers, SignalEvent};
//! use tokio::sync::mpsc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut signal_rx = setup_signal_handlers().await?;
//!     
//!     loop {
//!         tokio::select! {
//!             Some(signal) = signal_rx.recv() => {
//!                 match signal {
//!                     SignalEvent::Reload => {
//!                         println!("SIGHUP received, reloading config");
//!                         // reload_config().await?;
//!                     }
//!                     SignalEvent::Terminate => {
//!                         println!("SIGTERM received, shutting down");
//!                         break;
//!                     }
//!                     SignalEvent::DumpCache => {
//!                         println!("SIGUSR1 received, dumping cache");
//!                         // dump_cache().await?;
//!                     }
//!                     _ => {}
//!                 }
//!             }
//!         }
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Privilege Dropping
//!
//! ```rust,ignore
//! use crate::platform::drop_privileges;
//! use tokio::net::UdpSocket;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Bind to privileged port while running as root
//!     let dns_socket = UdpSocket::bind("0.0.0.0:53").await?;
//!     
//!     // Drop privileges (Linux: retain CAP_NET_BIND_SERVICE if needed)
//!     drop_privileges("dnsmasq", "dnsmasq").await?;
//!     
//!     println!("Now running as unprivileged user");
//!     
//!     // Continue processing as unprivileged user
//!     Ok(())
//! }
//! ```
//!
//! ## D-Bus Integration
//!
//! ```rust,ignore
//! #[cfg(feature = "dbus")]
//! use crate::platform::DbusDaemon;
//!
//! #[cfg(feature = "dbus")]
//! async fn start_dbus_interface() -> Result<(), Box<dyn std::error::Error>> {
//!     let dbus = DbusDaemon::new().await?;
//!     
//!     // Spawn D-Bus task in background
//!     tokio::spawn(async move {
//!         if let Err(e) = dbus.run().await {
//!             eprintln!("D-Bus error: {}", e);
//!         }
//!     });
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Relationship to Other Modules
//!
//! - **config**: Platform module reads privilege settings (user, group) from config
//! - **runtime**: Event loop integrates signal events from platform module
//! - **dns/dhcp/tftp**: Core logic uses platform abstractions without direct OS dependencies
//! - **util**: Logging and helper script execution may use platform services
//!
//! # Thread Safety
//!
//! All public APIs in this module are `Send + Sync` compatible for use in tokio's
//! async runtime. Signal handling is async-signal-safe using tokio's signal
//! infrastructure. D-Bus and systemd integrations use thread-safe primitives.

// Core platform services (always available on all platforms)

/// POSIX signal handling with tokio async integration.
///
/// Provides async-signal-safe signal handling for SIGHUP (config reload),
/// SIGTERM/SIGINT (graceful shutdown), SIGUSR1 (cache dump), SIGUSR2 (metrics),
/// SIGCHLD (helper process reaping), and SIGALRM (timer events).
///
/// Replaces C signal handlers from dnsmasq.c:sig_handler() with type-safe
/// [`SignalEvent`] enum dispatched via tokio channels.
///
/// # Platform Support
/// - Linux: Full support via tokio::signal::unix
/// - BSD: Full support via tokio::signal::unix
/// - macOS: Full support via tokio::signal::unix
/// - Other UNIX: Full support via tokio::signal::unix
pub mod signals;

/// Capability-based privilege management and user switching.
///
/// Implements privilege dropping after binding to privileged ports (53, 67, 547),
/// matching the C implementation's security model from dnsmasq.c:~700.
///
/// Platform-specific implementations:
/// - **Linux**: Uses capabilities(7) via caps crate (CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW)
/// - **BSD**: Uses pledge(2)/unveil(2) via nix crate where available
/// - **macOS**: Standard privilege dropping
/// - **Other**: Standard POSIX setuid/setgid
///
/// # Platform Support
/// All UNIX-like platforms. Fine-grained capabilities available on Linux only.
pub mod privileges;

/// systemd integration for socket activation and service notification.
///
/// Provides systemd-specific functionality:
/// - **Socket Activation**: Receive pre-bound sockets from systemd via sd_listen_fds
/// - **Readiness Notification**: Signal service startup completion via sd_notify
/// - **Watchdog**: Periodic heartbeat via sd_notify for systemd watchdog
/// - **Status Updates**: Service status messages via sd_notify
///
/// On non-systemd platforms, these functions are no-ops that return success,
/// allowing portable code without platform-specific conditionals.
///
/// # Platform Support
/// All platforms (no-op on non-systemd systems).
pub mod systemd;

// Optional platform services (conditionally compiled)

/// D-Bus control interface (uk.org.thekelleys.dnsmasq service).
///
/// Replaces C D-Bus code from dbus.c with pure Rust implementation using zbus crate.
///
/// **Methods:**
/// - `SetServers(servers: Vec<String>)`: Update upstream DNS servers
/// - `ClearCache()`: Flush DNS cache
/// - `GetVersion() -> String`: Return dnsmasq version
/// - `GetMetrics() -> HashMap<String, String>`: Return DNS/DHCP metrics
///
/// **Signals:**
/// - `DhcpLeaseAdded(ip: String, mac: String, hostname: String)`
/// - `DhcpLeaseDeleted(ip: String, mac: String)`
///
/// # Feature Flag
/// Only compiled when `feature = "dbus"` is enabled in Cargo.toml.
///
/// # Platform Support
/// All platforms with D-Bus support (typically Linux, BSD, macOS).
#[cfg(feature = "dbus")]
pub mod dbus;

/// OpenWrt ubus control interface.
///
/// Replaces C ubus code from ubus.c, providing JSON-RPC control interface
/// for embedded OpenWrt systems.
///
/// **Methods:**
/// - `metrics`: Return DNS/DHCP statistics
/// - `ipset`: Manage ipset/nftset entries
/// - `config_reload`: Trigger configuration reload
///
/// # Feature Flag
/// Only compiled when `feature = "ubus"` is enabled in Cargo.toml.
///
/// # Platform Support
/// OpenWrt only (may compile on other platforms but requires libubus).
#[cfg(feature = "ubus")]
pub mod ubus;

/// Linux inotify file system monitoring for configuration reload.
///
/// Replaces C inotify code from inotify.c, watching /etc/dnsmasq.conf
/// and include directories for changes, triggering automatic config reload.
///
/// Uses notify crate for safe inotify(7) syscall access.
///
/// # Platform Target
/// Only compiled on `target_os = "linux"`.
///
/// # Platform Support
/// Linux only (other platforms use polling or manual reload).
#[cfg(target_os = "linux")]
pub mod inotify;

// Re-export commonly used types and functions for ergonomic API
// This allows users to write `use crate::platform::setup_signal_handlers;`
// instead of `use crate::platform::signals::setup_signal_handlers;`

/// Setup async signal handlers and return a channel for receiving signal events.
///
/// Initializes tokio signal handlers for SIGHUP, SIGTERM, SIGINT, SIGUSR1,
/// SIGUSR2, SIGCHLD, and SIGALRM. Returns a receiver channel that yields
/// [`SignalEvent`] variants when OS signals are received.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::platform::{setup_signal_handlers, SignalEvent};
///
/// let mut signal_rx = setup_signal_handlers().await?;
/// match signal_rx.recv().await {
///     Some(SignalEvent::Reload) => reload_config().await?,
///     Some(SignalEvent::Terminate) => shutdown().await?,
///     _ => {}
/// }
/// ```
///
/// # Errors
///
/// Returns [`PlatformError::SignalError`] if signal handler registration fails.
///
/// # Platform Support
///
/// All UNIX-like platforms via `tokio::signal::unix`.
pub use signals::setup_signal_handlers;

/// Signal event enum for type-safe signal dispatch.
///
/// Represents OS signals as strongly-typed Rust enum variants,
/// replacing C signal numbers (SIGHUP=1, SIGTERM=15, etc.) with
/// semantic event types.
///
/// # Variants
///
/// - **Reload**: SIGHUP received (reload configuration)
/// - **Terminate**: SIGTERM/SIGINT received (graceful shutdown)
/// - **`DumpCache`**: SIGUSR1 received (dump DNS cache to log)
/// - **`ReportMetrics`**: SIGUSR2 received (log statistics)
/// - **`ChildExited`**: SIGCHLD received (helper process exited)
/// - **`AlarmFired`**: SIGALRM received (timer event)
///
/// # Examples
///
/// ```rust,ignore
/// use crate::platform::SignalEvent;
///
/// match signal_event {
///     SignalEvent::Reload => {
///         tracing::info!("Reloading configuration");
///         config.reload().await?;
///     }
///     SignalEvent::Terminate => {
///         tracing::info!("Shutting down gracefully");
///         return Ok(());
///     }
///     SignalEvent::DumpCache => {
///         tracing::info!("Dumping DNS cache");
///         dns_cache.dump_to_log().await?;
///     }
///     _ => {}
/// }
/// ```
pub use signals::SignalEvent;

/// Drop privileges to specified user and group after binding privileged ports.
///
/// Implements the security pattern from C dnsmasq where the daemon:
/// 1. Starts as root (UID 0)
/// 2. Binds privileged ports (53, 67, 547)
/// 3. Drops to unprivileged user
/// 4. Retains minimal capabilities (Linux only) if needed
///
/// # Arguments
///
/// * `user` - Target username (e.g., "dnsmasq", "nobody")
/// * `group` - Target group name (e.g., "dnsmasq", "nogroup")
///
/// # Linux Capabilities
///
/// On Linux, the following capabilities may be retained:
/// - **`CAP_NET_BIND_SERVICE`**: Bind to ports < 1024 (if needed)
/// - **`CAP_NET_ADMIN`**: Configure network interfaces, routes
/// - **`CAP_NET_RAW`**: Send ICMP packets for DHCP conflict detection
///
/// # Examples
///
/// ```rust,ignore
/// use crate::platform::drop_privileges;
/// use tokio::net::UdpSocket;
///
/// // Bind privileged port as root
/// let socket = UdpSocket::bind("0.0.0.0:53").await?;
///
/// // Drop to unprivileged user
/// drop_privileges("dnsmasq", "dnsmasq").await?;
///
/// // Continue running as dnsmasq:dnsmasq
/// ```
///
/// # Errors
///
/// Returns [`PlatformError::PrivilegeDropFailed`] if:
/// - User or group not found
/// - setuid/setgid syscalls fail
/// - Capability operations fail (Linux)
///
/// # Platform Support
///
/// All UNIX-like platforms. Fine-grained capabilities only on Linux.
pub use privileges::drop_privileges;

/// Privilege manager for controlling capability sets and user contexts.
///
/// Provides a type-safe interface to privilege management operations,
/// encapsulating platform-specific privilege APIs.
///
/// # Platform-Specific Behavior
///
/// - **Linux**: Manages capabilities via caps crate
/// - **OpenBSD**: Manages pledge/unveil restrictions
/// - **FreeBSD**: Manages Capsicum capabilities
/// - **Other**: Standard POSIX privilege dropping
///
/// # Examples
///
/// ```rust,ignore
/// use crate::platform::PrivilegeManager;
///
/// let mut privs = PrivilegeManager::new();
/// privs.drop_to_user("dnsmasq", "dnsmasq").await?;
/// privs.retain_net_admin_capability()?;
/// privs.apply().await?;
/// ```
pub use privileges::PrivilegeManager;

// Conditional re-exports for optional features

/// D-Bus daemon control interface (feature = "dbus").
///
/// Provides the main D-Bus service implementation on the
/// `uk.org.thekelleys.dnsmasq` bus name.
///
/// # Methods
///
/// - **`new()`**: Create new D-Bus daemon instance
/// - **`run()`**: Start D-Bus service (blocking async)
/// - **`clear_cache()`**: Clear DNS cache via D-Bus
/// - **`set_servers()`**: Update upstream DNS servers via D-Bus
///
/// # Examples
///
/// ```rust,ignore
/// #[cfg(feature = "dbus")]
/// use crate::platform::DbusDaemon;
///
/// #[cfg(feature = "dbus")]
/// let dbus = DbusDaemon::new().await?;
/// dbus.run().await?;
/// ```
///
/// # Feature Flag
///
/// Only available when `feature = "dbus"` is enabled.
#[cfg(feature = "dbus")]
pub use dbus::DbusDaemon;

/// `OpenWrt` ubus daemon control interface (feature = "ubus").
///
/// Provides ubus JSON-RPC integration for `OpenWrt` embedded systems.
///
/// # Methods
///
/// - **`new()`**: Create new ubus daemon instance
/// - **`run()`**: Start ubus service (blocking async)
/// - **`handle_metrics()`**: Handle metrics request via ubus
/// - **`reconnect()`**: Reconnect to ubus after connection loss
///
/// # Examples
///
/// ```rust,ignore
/// #[cfg(feature = "ubus")]
/// use crate::platform::UbusDaemon;
///
/// #[cfg(feature = "ubus")]
/// let ubus = UbusDaemon::new().await?;
/// ubus.run().await?;
/// ```
///
/// # Feature Flag
///
/// Only available when `feature = "ubus"` is enabled.
#[cfg(feature = "ubus")]
pub use ubus::UbusDaemon;

/// Linux inotify file watcher for configuration reload (`target_os` = "linux").
///
/// Monitors configuration files and directories for changes, triggering
/// automatic reload events when modifications are detected.
///
/// # Methods
///
/// - **`new()`**: Create new inotify watcher
/// - **`watch_file()`**: Add file to watch list
/// - **`watch_directory()`**: Add directory to watch list (recursive)
/// - **`run()`**: Start watching (blocking async, yields events)
///
/// # Examples
///
/// ```rust,ignore
/// #[cfg(target_os = "linux")]
/// use crate::platform::InotifyWatcher;
///
/// #[cfg(target_os = "linux")]
/// let mut watcher = InotifyWatcher::new().await?;
/// watcher.watch_file("/etc/dnsmasq.conf").await?;
/// watcher.watch_directory("/etc/dnsmasq.d").await?;
///
/// while let Some(event) = watcher.run().await? {
///     tracing::info!("Config file changed, reloading");
///     reload_config().await?;
/// }
/// ```
///
/// # Platform Target
///
/// Available on all platforms but fully functional only on Linux with the `inotify` feature enabled.
/// On other platforms or when the feature is disabled, returns a stub that errors on creation.
pub use inotify::InotifyWatcher;

/// Notify systemd of service readiness or status updates.
///
/// Sends notification messages to systemd via `sd_notify` protocol.
///
/// # Common Notifications
///
/// - `"READY=1"`: Service initialization complete
/// - `"STOPPING=1"`: Service is shutting down
/// - `"RELOADING=1"`: Configuration reload in progress
/// - `"STATUS=..."`: Human-readable status message
/// - `"WATCHDOG=1"`: Watchdog keepalive heartbeat
///
/// # Examples
///
/// ```rust,ignore
/// use crate::platform::sd_notify;
///
/// // Signal startup complete
/// sd_notify("READY=1").await?;
///
/// // Update status
/// sd_notify("STATUS=Processing DNS queries").await?;
///
/// // Watchdog keepalive
/// loop {
///     sd_notify("WATCHDOG=1").await?;
///     tokio::time::sleep(Duration::from_secs(5)).await;
/// }
/// ```
///
/// # Errors
///
/// Returns [`PlatformError::SystemdError`] if notification fails.
/// On non-systemd platforms, this is a no-op that returns `Ok(())`.
///
/// # Platform Support
///
/// All platforms (no-op on non-systemd systems).
pub use systemd::sd_notify;

/// Retrieve file descriptors passed by systemd socket activation.
///
/// Systemd can pre-bind sockets and pass them to the service via file
/// descriptor passing, avoiding the need for privileged port binding.
///
/// # Returns
///
/// Returns a vector of listening file descriptors (typically 0 or more).
/// Empty vector indicates no socket activation.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::platform::sd_listen_fds;
/// use tokio::net::UdpSocket;
/// use std::os::unix::io::FromRawFd;
///
/// let fds = sd_listen_fds().await?;
/// for fd in fds {
///     // SAFETY: fd comes from systemd, guaranteed to be valid listening socket
///     let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
///     let socket = UdpSocket::from_std(socket)?;
///     // Use socket...
/// }
/// ```
///
/// # Errors
///
/// Returns [`PlatformError::SystemdError`] if fd retrieval fails.
/// On non-systemd platforms, returns empty vector.
///
/// # Platform Support
///
/// All platforms (returns empty vector on non-systemd systems).
pub use systemd::sd_listen_fds;
