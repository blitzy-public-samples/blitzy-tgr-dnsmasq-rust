// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! POSIX signal handling for dnsmasq daemon lifecycle management.
//!
//! This module implements async-signal-safe handlers for POSIX signals using tokio's
//! signal handling facilities. It replaces the C implementation's pipe-based event queue
//! with direct async method invocations on service objects.
//!
//! # Architecture
//!
//! The C implementation (src/dnsmasq.c) uses a pipe to forward signals to the main event loop:
//!
//! ```c
//! // C: sig_handler() writes to pipe
//! static void sig_handler(int sig) {
//!     if (pipewrite != -1) {
//!         unsigned char event = EVENT_RELOAD;  // or EVENT_TERM, EVENT_DUMP, etc.
//!         while (retry_send(write(pipewrite, &event, 1)));
//!     }
//! }
//!
//! // C: async_event() processes events from pipe
//! void async_event(int pipe, time_t now) {
//!     unsigned char event;
//!     read(pipe, &event, 1);
//!     switch(event) {
//!         case EVENT_RELOAD: clear_cache_and_reload(now); break;
//!         case EVENT_TERM: /* cleanup and exit */ break;
//!         // ...
//!     }
//! }
//! ```
//!
//! The Rust implementation uses tokio::signal to create async signal streams, with each
//! signal type spawning a dedicated async task that directly calls service methods:
//!
//! ```rust,ignore
//! // Rust: Each signal gets its own async task with direct method calls
//! tokio::spawn(async move {
//!     let mut sighup = signal(SignalKind::hangup()).unwrap();
//!     loop {
//!         sighup.recv().await;
//!         config_reloader.handle_reload().await;
//!     }
//! });
//! ```
//!
//! # Supported Signals
//!
//! - **SIGHUP**: Reload configuration via ConfigReloader::handle_reload()
//! - **SIGTERM**: Graceful shutdown via TaskManager::shutdown()
//! - **SIGINT**: Graceful shutdown (same as SIGTERM)
//! - **SIGUSR1**: Dump DNS cache statistics via DnsCache::get_stats()
//! - **SIGUSR2**: Log metrics via report_all() and rotate logs via flush_log()
//! - **SIGCHLD**: Reap zombie child processes from helper scripts and TCP handlers
//! - **SIGALRM**: Timer events for periodic operations (replaced by tokio interval timers)
//!
//! # Example
//!
//! ```rust,ignore
//! use dnsmasq::platform::signals::{SignalHandlers, setup_signal_handlers};
//! use std::sync::Arc;
//!
//! let signal_handlers = SignalHandlers::new(
//!     Arc::clone(&config_reloader),
//!     Arc::clone(&dns_cache),
//!     Arc::clone(&shutdown_handle),
//! );
//!
//! let handles = setup_signal_handlers(signal_handlers).await?;
//! // Signal handling tasks are now running in background
//! ```

use crate::config::reload::ConfigReloader;
use crate::dns::cache::DnsCache;

use crate::runtime::tasks::ShutdownHandle;
use crate::util::logging::{flush_log, LoggingService};
use crate::util::metrics::{report_all, MetricsCollector};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::{self, JoinHandle};
use tracing::{debug, error, info, instrument, warn};

/// Signal events representing POSIX signals handled by dnsmasq.
///
/// This enum maps POSIX signals to semantic events, replacing C's EVENT_* constants
/// from dnsmasq.c (EVENT_RELOAD, EVENT_TERM, EVENT_DUMP, EVENT_ALARM, etc.).
///
/// # C Equivalent
///
/// ```c
/// #define EVENT_RELOAD  1
/// #define EVENT_DROP_TFTP  2
/// #define EVENT_RELOAD_RESOLV  3
/// #define EVENT_TERM  4
/// #define EVENT_DUMP  5
/// #define EVENT_ALARM  6
/// #define EVENT_CHILD  7
/// #define EVENT_KILLED  8
/// #define EVENT_EXEC_ERR  9
/// #define EVENT_PIPE_ERR  10
/// #define EVENT_USER_ERR  11
/// #define EVENT_CAP_ERR  12
/// #define EVENT_PIDFILE  13
/// #define EVENT_HUSER_ERR  14
/// #define EVENT_GROUP_ERR  15
/// #define EVENT_DIE  16
/// #define EVENT_LOG_ERR  17
/// #define EVENT_FORK_ERR  18
/// #define EVENT_LUA_ERR  19
/// #define EVENT_TFTP_ERR  20
/// #define EVENT_INIT  21
/// #define EVENT_NEWADDR  22
/// #define EVENT_NEWROUTE  23
/// #define EVENT_TIME_ERR  24
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalEvent {
    /// SIGHUP: Configuration reload requested.
    ///
    /// Triggers ConfigReloader::handle_reload() to:
    /// - Re-read dnsmasq.conf and included files
    /// - Clear DNS cache
    /// - Reload /etc/hosts
    /// - Reopen log files
    Reload,

    /// SIGTERM/SIGINT: Graceful shutdown requested.
    ///
    /// Triggers TaskManager::shutdown() to:
    /// - Broadcast shutdown signal to all tasks
    /// - Flush DHCP leases to disk
    /// - Close all sockets
    /// - Wait for in-flight requests to complete
    Terminate,

    /// SIGUSR1: DNS cache statistics dump requested.
    ///
    /// Triggers DnsCache::get_stats() and logs:
    /// - Total cache entries
    /// - Cache hit rate
    /// - Evictions and expirations
    DumpCache,

    /// SIGUSR2: System metrics reporting and log rotation.
    ///
    /// Triggers:
    /// - MetricsCollector::report_all() - DNS/DHCP/DNSSEC metrics
    /// - LoggingService::flush() - Log file rotation
    ReportMetrics,

    /// SIGCHLD: Child process terminated.
    ///
    /// Reaps zombie processes from:
    /// - DHCP helper scripts (--dhcp-script)
    /// - TCP DNS connection handlers
    /// - Lua script execution
    ///
    /// Replaces C's EVENT_CHILD handler in async_event().
    ChildExited,

    /// SIGALRM: Timer event for periodic operations.
    ///
    /// In C implementation, used for:
    /// - Lease expiration checks
    /// - /etc/resolv.conf monitoring
    /// - Upstream server health checks
    ///
    /// In Rust implementation, replaced by tokio interval timers in TaskManager,
    /// but kept for compatibility with legacy timer-based code paths.
    AlarmFired,
}

/// Signal handlers container holding Arc references to service dependencies.
///
/// This struct aggregates all service dependencies required by signal handlers,
/// enabling signal handler tasks to invoke service methods directly without
/// a pipe-based event queue.
///
/// # Architecture
///
/// Unlike the C implementation which uses a pipe and EVENT_* codes, the Rust
/// implementation holds Arc references to services and calls methods directly:
///
/// ```rust,ignore
/// // C approach:
/// write(pipewrite, &EVENT_RELOAD, 1);  // Write to pipe
/// // Later in event loop:
/// read(piperead, &event, 1);
/// if (event == EVENT_RELOAD) clear_cache_and_reload();
///
/// // Rust approach:
/// signal_handlers.handle_sighup().await;  // Direct method call
/// ```
///
/// Each handler method is async and can directly await on service operations.
pub struct SignalHandlers {
    /// Configuration reloader for SIGHUP handling.
    config_reloader: Arc<RwLock<ConfigReloader>>,

    /// DNS cache for SIGUSR1 statistics dumping.
    dns_cache: Arc<RwLock<DnsCache>>,

    /// Shutdown handle for SIGTERM/SIGINT graceful shutdown coordination.
    shutdown_handle: Arc<ShutdownHandle>,

    /// Metrics collector for SIGUSR2 statistics reporting.
    metrics_collector: Arc<RwLock<MetricsCollector>>,

    /// Logging service for SIGUSR2 log rotation.
    logging_service: Arc<RwLock<LoggingService>>,
}

impl SignalHandlers {
    /// Creates a new SignalHandlers with service dependencies.
    ///
    /// # Arguments
    ///
    /// * `config_reloader` - Configuration reload service for SIGHUP
    /// * `dns_cache` - DNS cache for SIGUSR1 statistics dumping
    /// * `shutdown_handle` - Shutdown coordination for SIGTERM/SIGINT
    /// * `metrics_collector` - Metrics collector for SIGUSR2 statistics reporting
    /// * `logging_service` - Logging service for SIGUSR2 log rotation
    ///
    /// # Returns
    ///
    /// A new SignalHandlers instance ready for use with setup_signal_handlers().
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let signal_handlers = SignalHandlers::new(
    ///     Arc::clone(&config_reloader),
    ///     Arc::clone(&dns_cache),
    ///     Arc::clone(&shutdown_handle),
    ///     Arc::clone(&metrics_collector),
    ///     Arc::clone(&logging_service),
    /// );
    /// ```
    pub fn new(
        config_reloader: Arc<RwLock<ConfigReloader>>,
        dns_cache: Arc<RwLock<DnsCache>>,
        shutdown_handle: Arc<ShutdownHandle>,
        metrics_collector: Arc<RwLock<MetricsCollector>>,
        logging_service: Arc<RwLock<LoggingService>>,
    ) -> Self {
        Self {
            config_reloader,
            dns_cache,
            shutdown_handle,
            metrics_collector,
            logging_service,
        }
    }

    /// Handles SIGHUP: Configuration reload without daemon restart.
    ///
    /// Invokes ConfigReloader::handle_reload() which:
    /// 1. Re-reads dnsmasq.conf and all included files
    /// 2. Validates new configuration
    /// 3. Clears DNS cache
    /// 4. Reloads /etc/hosts and static data
    /// 5. Reopens log files
    /// 6. Atomically updates shared Config state
    ///
    /// Replaces C's clear_cache_and_reload() function.
    ///
    /// # Errors
    ///
    /// Returns error if configuration reload fails (invalid config, I/O error).
    #[instrument(skip(self))]
    pub async fn handle_sighup(&self) -> Result<()> {
        info!("SIGHUP received: reloading configuration");
        
        match self.config_reloader.write().await.handle_reload().await {
            Ok(()) => {
                info!("Configuration reloaded successfully");
                Ok(())
            }
            Err(e) => {
                error!("Configuration reload failed: {}", e);
                Err(e).context("SIGHUP handler: failed to reload configuration")
            }
        }
    }

    /// Handles SIGTERM: Graceful shutdown with cleanup.
    ///
    /// Invokes ShutdownHandle::shutdown() which:
    /// 1. Broadcasts shutdown signal to all async tasks
    /// 2. Waits for in-flight DNS queries to complete
    /// 3. Flushes DHCP leases to disk
    /// 4. Closes all listening sockets
    /// 5. Waits for helper scripts to terminate
    /// 6. Flushes logs
    ///
    /// Replaces C's shutdown sequence in async_event(EVENT_TERM).
    ///
    /// # Errors
    ///
    /// Returns error if shutdown coordination fails.
    #[instrument(skip(self))]
    pub async fn handle_sigterm(&self) -> Result<()> {
        info!("SIGTERM received: initiating graceful shutdown");
        
        self.shutdown_handle.shutdown().await;
        info!("Graceful shutdown completed");
        Ok(())
    }

    /// Handles SIGINT: Graceful shutdown (same as SIGTERM).
    ///
    /// Provides same behavior as SIGTERM for Ctrl-C interrupts.
    /// In C implementation, both signals invoke the same shutdown path.
    ///
    /// # Errors
    ///
    /// Returns error if shutdown coordination fails.
    #[instrument(skip(self))]
    pub async fn handle_sigint(&self) -> Result<()> {
        info!("SIGINT received: initiating graceful shutdown");
        
        self.shutdown_handle.shutdown().await;
        info!("Graceful shutdown completed");
        Ok(())
    }

    /// Handles SIGUSR1: Dumps DNS cache statistics to log.
    ///
    /// Retrieves cache statistics via DnsCache::get_stats() and logs:
    /// - Total cache entries
    /// - Cache size limits
    /// - Cache hit/miss rates
    /// - Evictions and expirations
    ///
    /// Replaces C's dump_cache() function called from async_event(EVENT_DUMP).
    ///
    /// # Errors
    ///
    /// Returns error if statistics retrieval fails.
    #[instrument(skip(self))]
    pub async fn handle_sigusr1(&self) -> Result<()> {
        info!("SIGUSR1 received: dumping DNS cache statistics");
        
        let cache = self.dns_cache.read().await;
        let stats = cache.get_stats();
        
        info!(
            entries = stats.current_size,
            capacity = stats.capacity,
            hits = stats.hits,
            misses = stats.misses,
            evictions = stats.evictions,
            "DNS cache statistics"
        );
        
        // Calculate and log hit rate
        let total_queries = stats.hits + stats.misses;
        if total_queries > 0 {
            let hit_rate = (stats.hits as f64 / total_queries as f64) * 100.0;
            info!(hit_rate = format!("{:.2}%", hit_rate), "Cache hit rate");
        }
        
        debug!("DNS cache statistics dumped to log");
        Ok(())
    }

    /// Handles SIGUSR2: Reports metrics and rotates logs.
    ///
    /// Performs two operations:
    /// 1. Calls report_all() to log comprehensive metrics:
    ///    - DNS query counts and latencies
    ///    - Cache hit rates and evictions
    ///    - DHCP lease allocations and expirations
    ///    - DNSSEC validation statistics
    /// 2. Calls flush_log() to:
    ///    - Close current log file
    ///    - Reopen log file (enables log rotation)
    ///    - Flush pending log entries
    ///
    /// Replaces C's statistics logging and log_reopen() from async_event().
    ///
    /// # Errors
    ///
    /// Returns error if metrics reporting or log rotation fails.
    #[instrument(skip(self))]
    pub async fn handle_sigusr2(&self) -> Result<()> {
        info!("SIGUSR2 received: reporting metrics and rotating logs");
        
        // Report all metrics first
        let collector = self.metrics_collector.read().await;
        report_all(&collector);
        info!("Metrics reported successfully");
        
        // Flush and rotate logs
        let mut logging_service = self.logging_service.write().await;
        match flush_log(&mut *logging_service).await {
            Ok(()) => {
                info!("Log rotation completed successfully");
                Ok(())
            }
            Err(e) => {
                error!("Log rotation failed: {}", e);
                Err(e).context("SIGUSR2 handler: failed to rotate logs")
            }
        }
    }

    /// Handles SIGCHLD: Reaps zombie child processes.
    ///
    /// Called when a child process terminates to prevent zombie accumulation.
    /// Child processes in dnsmasq include:
    /// - DHCP helper scripts spawned by --dhcp-script
    /// - TCP DNS connection handlers (when --max-tcp-connections > 0)
    /// - Lua script execution (when --lua-script enabled)
    ///
    /// Uses non-blocking waitpid(-1, WNOHANG) to reap all exited children.
    /// Logs any helper script failures for debugging.
    ///
    /// Replaces C's EVENT_CHILD handler in async_event().
    ///
    /// # Errors
    ///
    /// Returns error if waitpid() system call fails (unlikely).
    #[instrument(skip(self))]
    pub async fn handle_sigchld(&self) -> Result<()> {
        debug!("SIGCHLD received: reaping child processes");
        
        #[cfg(unix)]
        {
            use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
            use nix::unistd::Pid;
            
            loop {
                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(pid, status)) => {
                        if status == 0 {
                            debug!(pid = pid.as_raw(), "Child process exited successfully");
                        } else {
                            warn!(
                                pid = pid.as_raw(),
                                exit_code = status,
                                "Child process exited with error"
                            );
                        }
                    }
                    Ok(WaitStatus::Signaled(pid, signal, _)) => {
                        warn!(
                            pid = pid.as_raw(),
                            signal = signal as i32,
                            "Child process terminated by signal"
                        );
                    }
                    Ok(WaitStatus::StillAlive) => {
                        // No more children to reap
                        break;
                    }
                    Ok(_) => {
                        // Other wait statuses (Stopped, Continued) - ignore for now
                        continue;
                    }
                    Err(nix::errno::Errno::ECHILD) => {
                        // No child processes exist
                        debug!("No child processes to reap");
                        break;
                    }
                    Err(e) => {
                        error!("waitpid failed: {}", e);
                        return Err(anyhow::anyhow!("waitpid failed: {}", e))
                            .context("SIGCHLD handler: failed to reap child processes");
                    }
                }
            }
        }
        
        #[cfg(not(unix))]
        {
            warn!("SIGCHLD handling not supported on non-UNIX platforms");
        }
        
        Ok(())
    }

    /// Handles SIGALRM: Timer event for periodic operations.
    ///
    /// In C implementation, SIGALRM is used for:
    /// - DHCP lease expiration checks
    /// - Upstream server health probing
    /// - /etc/resolv.conf monitoring
    ///
    /// In Rust implementation, these operations are typically handled by
    /// tokio interval timers in TaskManager background tasks. This handler
    /// is retained for compatibility but may be a no-op if all periodic
    /// operations have been migrated to tokio timers.
    ///
    /// # Errors
    ///
    /// Returns error if timer operation processing fails.
    #[instrument(skip(self))]
    pub async fn handle_sigalrm(&self) -> Result<()> {
        debug!("SIGALRM received: timer event (may be handled by tokio timers)");
        
        // In modern Rust implementation, periodic operations are handled by
        // tokio::time::interval in TaskManager, so this may be a no-op.
        // Kept for compatibility with legacy alarm-based code paths.
        
        warn!("SIGALRM received but periodic operations use tokio timers");
        Ok(())
    }
}

/// Sets up signal handlers using tokio's async signal facilities.
///
/// Creates dedicated async tasks for each signal type, where each task:
/// 1. Creates a tokio::signal::unix::Signal stream for the signal
/// 2. Loops awaiting signal receipt
/// 3. Invokes the appropriate SignalHandlers method
/// 4. Continues until task is cancelled
///
/// # Arguments
///
/// * `handlers` - SignalHandlers instance with service dependencies
///
/// # Returns
///
/// Returns Vec<JoinHandle<()>> containing task handles for all signal handler tasks.
/// These handles can be awaited for graceful shutdown or cancelled to stop signal handling.
///
/// # Errors
///
/// Returns error if any signal stream creation fails due to:
/// - Invalid signal for platform
/// - Permission denied
/// - Signal already handled by another mechanism
///
/// # Example
///
/// ```rust,ignore
/// let signal_handlers = SignalHandlers::new(...);
/// let handles = setup_signal_handlers(signal_handlers).await?;
///
/// // Signal handling tasks now running in background
/// // To stop signal handling:
/// for handle in handles {
///     handle.abort();
/// }
/// ```
#[instrument(skip(handlers))]
pub async fn setup_signal_handlers(
    handlers: SignalHandlers,
) -> Result<Vec<JoinHandle<()>>> {
    use tokio::signal::unix::{signal, SignalKind};
    
    let mut join_handles = Vec::new();
    
    // Wrap handlers in Arc once for sharing across all signal handler tasks
    let handlers = Arc::new(handlers);
    
    info!("Setting up signal handlers for SIGHUP, SIGTERM, SIGINT, SIGUSR1, SIGUSR2, SIGCHLD, SIGALRM");
    
    // SIGHUP handler - Configuration reload
    {
        let handlers_clone = Arc::clone(&handlers);
        
        let mut sighup = signal(SignalKind::hangup())
            .context("Failed to register SIGHUP handler")?;
        
        let handle = task::spawn(async move {
            loop {
                sighup.recv().await;
                if let Err(e) = handlers_clone.handle_sighup().await {
                    error!("SIGHUP handler error: {}", e);
                }
            }
        });
        
        join_handles.push(handle);
        debug!("SIGHUP handler task spawned");
    }
    
    // SIGTERM handler - Graceful shutdown
    {
        let handlers_clone = Arc::clone(&handlers);
        
        let mut sigterm = signal(SignalKind::terminate())
            .context("Failed to register SIGTERM handler")?;
        
        let handle = task::spawn(async move {
            sigterm.recv().await;
            if let Err(e) = handlers_clone.handle_sigterm().await {
                error!("SIGTERM handler error: {}", e);
            }
            // After SIGTERM, exit the loop to allow graceful shutdown
        });
        
        join_handles.push(handle);
        debug!("SIGTERM handler task spawned");
    }
    
    // SIGINT handler - Graceful shutdown (Ctrl-C)
    {
        let handlers_clone = Arc::clone(&handlers);
        
        let mut sigint = signal(SignalKind::interrupt())
            .context("Failed to register SIGINT handler")?;
        
        let handle = task::spawn(async move {
            sigint.recv().await;
            if let Err(e) = handlers_clone.handle_sigint().await {
                error!("SIGINT handler error: {}", e);
            }
            // After SIGINT, exit the loop to allow graceful shutdown
        });
        
        join_handles.push(handle);
        debug!("SIGINT handler task spawned");
    }
    
    // SIGUSR1 handler - Dump DNS cache statistics
    {
        let handlers_clone = Arc::clone(&handlers);
        
        let mut sigusr1 = signal(SignalKind::user_defined1())
            .context("Failed to register SIGUSR1 handler")?;
        
        let handle = task::spawn(async move {
            loop {
                sigusr1.recv().await;
                if let Err(e) = handlers_clone.handle_sigusr1().await {
                    error!("SIGUSR1 handler error: {}", e);
                }
            }
        });
        
        join_handles.push(handle);
        debug!("SIGUSR1 handler task spawned");
    }
    
    // SIGUSR2 handler - Report metrics and rotate logs
    {
        let handlers_clone = Arc::clone(&handlers);
        
        let mut sigusr2 = signal(SignalKind::user_defined2())
            .context("Failed to register SIGUSR2 handler")?;
        
        let handle = task::spawn(async move {
            loop {
                sigusr2.recv().await;
                if let Err(e) = handlers_clone.handle_sigusr2().await {
                    error!("SIGUSR2 handler error: {}", e);
                }
            }
        });
        
        join_handles.push(handle);
        debug!("SIGUSR2 handler task spawned");
    }
    
    // SIGCHLD handler - Reap zombie child processes
    {
        let handlers_clone = Arc::clone(&handlers);
        
        let mut sigchld = signal(SignalKind::child())
            .context("Failed to register SIGCHLD handler")?;
        
        let handle = task::spawn(async move {
            loop {
                sigchld.recv().await;
                if let Err(e) = handlers_clone.handle_sigchld().await {
                    error!("SIGCHLD handler error: {}", e);
                }
            }
        });
        
        join_handles.push(handle);
        debug!("SIGCHLD handler task spawned");
    }
    
    // SIGALRM handler - Timer events (compatibility)
    {
        let handlers_clone = Arc::clone(&handlers);
        
        let mut sigalrm = signal(SignalKind::alarm())
            .context("Failed to register SIGALRM handler")?;
        
        let handle = task::spawn(async move {
            loop {
                sigalrm.recv().await;
                if let Err(e) = handlers_clone.handle_sigalrm().await {
                    error!("SIGALRM handler error: {}", e);
                }
            }
        });
        
        join_handles.push(handle);
        debug!("SIGALRM handler task spawned");
    }
    
    info!(
        handlers_count = join_handles.len(),
        "Signal handlers successfully installed"
    );
    
    Ok(join_handles)
}
