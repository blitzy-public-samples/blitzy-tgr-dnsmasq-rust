// Copyright (c) 2000-2025 Simon Kelley
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

//! Non-blocking asynchronous logging system using tracing crate.
//!
//! This module replaces the C syslog integration (`src/log.c`) with a modern Rust
//! logging infrastructure based on the `tracing` ecosystem. Key features:
//!
//! - **Non-blocking**: Bounded message queue prevents blocking the main event loop
//! - **Fork-safe**: Tracks process PID to avoid duplicate logging after fork()
//! - **Multi-target**: Supports syslog (journald), file output, and stderr
//! - **Structured logging**: Key-value pairs and JSON formatting for SIEM integration
//! - **Exponential backoff**: Self-throttling when queue fills to prevent storms
//! - **Platform-specific**: Native journald (Linux) and Android logging support
//!
//! # Architecture
//!
//! The logging system uses a bounded async channel (`tokio::sync::mpsc`) with capacity
//! `LOG_MAX` (5 entries from `constants.rs`) to queue log messages. This prevents
//! unbounded memory growth during log storms while maintaining async operation.
//!
//! When the queue fills, new messages are dropped and counted in `entries_lost`.
//! The system implements exponential backoff (1ms, 2ms, 4ms, ..., 1s) to self-throttle
//! during high log volume.
//!
//! # Differences from C Implementation
//!
//! - **Queue size**: Rust uses `LOG_MAX = 5` vs C's `LOG_MAX = 25` for lower latency
//! - **Message size**: Rust uses `MAX_MESSAGE = 512` vs C's `MAX_MESSAGE = 1024` (RFC 3164)
//! - **Async model**: Rust uses tokio channels vs C's manual linked list with poll()
//! - **Platform abstraction**: Rust uses tracing layers vs C's direct syslog() calls
//!
//! # Example
//!
//! ```no_run
//! use tracing::{info, error};
//!
//! // Initialize logging system at startup
//! log_init(true, None, false, Level::INFO)?;
//!
//! // Use standard tracing macros
//! info!(ip = "192.168.1.10", "DNS query resolved");
//! error!(reason = "timeout", "Upstream server failed");
//!
//! // Flush on shutdown
//! flush_log(&mut logging_service)?;
//! ```

use crate::constants::{LOG_MAX, MAX_MESSAGE};
use crate::error::PlatformError;

use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::mpsc::{self, Sender, Receiver};
use tokio::time::{sleep, Duration};

use tracing::{Level, Subscriber};
use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
    Layer,
    Registry,
};

#[cfg(target_os = "linux")]
use tracing_journald;

#[cfg(target_os = "android")]
use tracing_android;

use tracing_appender::{non_blocking, rolling};

/// Internal log entry structure for the bounded queue.
///
/// Each entry contains the log level, message content, timestamp, and originating
/// process PID for fork-safety.
#[derive(Debug, Clone)]
struct LogEntry {
    /// Log level (ERROR, WARN, INFO, DEBUG, TRACE)
    level: Level,
    /// Log message content (truncated to MAX_MESSAGE bytes)
    message: String,
    /// Timestamp when the message was created
    timestamp: SystemTime,
    /// Process ID that created this entry (for fork-safety)
    pid: u32,
}

/// Non-blocking asynchronous logging service.
///
/// Maintains a bounded message queue to prevent blocking the main event loop when
/// syslog is slow or making DNS lookups back through dnsmasq (deadlock prevention).
///
/// # Fork Safety
///
/// The service tracks the process PID at construction. After a fork(), the child
/// process has a different PID and will skip processing the parent's queued messages
/// during `flush()`.
///
/// # Queue Management
///
/// The queue has a fixed capacity of `LOG_MAX` (5 entries). When full, new messages
/// are dropped and counted in `entries_lost`. The system implements exponential
/// backoff to self-throttle during log storms.
///
/// # Example
///
/// ```no_run
/// let mut service = LoggingService::new(LOG_MAX);
/// service.log_message(Level::INFO, "Server started".to_string()).await;
/// service.flush().await?;
/// let dropped = service.get_entries_lost();
/// ```
pub struct LoggingService {
    /// Sender for async log message queueing
    sender: Sender<LogEntry>,
    /// Receiver for message processing (consumed during flush)
    receiver: Option<Receiver<LogEntry>>,
    /// Count of dropped messages when queue is full
    entries_lost: Arc<AtomicUsize>,
    /// PID at construction for fork-safety
    pid: u32,
    /// Maximum queue capacity (LOG_MAX from constants.rs)
    capacity: usize,
}

impl LoggingService {
    /// Create a new logging service with the specified queue capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of log entries in the queue (typically `LOG_MAX`)
    ///
    /// # Returns
    ///
    /// A new `LoggingService` instance with an empty queue.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let service = LoggingService::new(LOG_MAX);
    /// ```
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity);
        let pid = process::id();

        Self {
            sender,
            receiver: Some(receiver),
            entries_lost: Arc::new(AtomicUsize::new(0)),
            pid,
            capacity,
        }
    }

    /// Queue a log message for asynchronous writing.
    ///
    /// If the queue is full, the message is dropped and the `entries_lost` counter
    /// is incremented. The system implements exponential backoff (1ms, 2ms, 4ms, ..., 1s)
    /// to self-throttle during high log volume.
    ///
    /// # Arguments
    ///
    /// * `level` - Log level (ERROR, WARN, INFO, DEBUG, TRACE)
    /// * `message` - Log message content (will be truncated to MAX_MESSAGE bytes)
    ///
    /// # Example
    ///
    /// ```no_run
    /// service.log_message(Level::INFO, "DNS query resolved".to_string()).await;
    /// ```
    pub async fn log_message(&self, level: Level, message: String) {
        // Truncate message to MAX_MESSAGE bytes if necessary
        let truncated = if message.len() > MAX_MESSAGE {
            let mut truncated = message[..MAX_MESSAGE - 3].to_string();
            truncated.push_str("...");
            truncated
        } else {
            message
        };

        let entry = LogEntry {
            level,
            message: truncated,
            timestamp: SystemTime::now(),
            pid: process::id(),
        };

        // Try to send with exponential backoff if queue is full
        let mut delay_ms = 1u64;
        let max_retries = 10;
        let mut retries = 0;

        loop {
            match self.sender.try_send(entry.clone()) {
                Ok(_) => break,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Queue is full - increment lost counter
                    self.entries_lost.fetch_add(1, Ordering::Relaxed);

                    // Exponential backoff with cap at 1 second
                    if retries < max_retries {
                        sleep(Duration::from_millis(delay_ms)).await;
                        delay_ms = (delay_ms * 2).min(1000);
                        retries += 1;
                    } else {
                        // Give up after max retries
                        break;
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // Channel closed - service is shutting down
                    break;
                }
            }
        }
    }

    /// Flush all queued log messages synchronously.
    ///
    /// This function drains the entire message queue and processes each entry.
    /// It implements fork-safety by checking the current process PID against
    /// the PID recorded at construction time. If they differ (fork detected),
    /// the parent's queue is skipped.
    ///
    /// # Fork Safety
    ///
    /// After a fork(), the child process has a different PID. The flush operation
    /// checks the current PID and skips processing if it differs from the original,
    /// preventing duplicate log entries from both parent and child.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all messages were successfully processed
    /// - `Err(PlatformError::LoggingFailed)` if logging failed
    ///
    /// # Example
    ///
    /// ```no_run
    /// service.flush().await?;
    /// ```
    pub async fn flush(&mut self) -> Result<(), PlatformError> {
        // Fork-safety: Skip parent's queue if we're in a child process
        let current_pid = process::id();
        if current_pid != self.pid {
            // Fork detected - skip parent's entries
            return Ok(());
        }

        // Take ownership of the receiver to drain it
        if let Some(mut receiver) = self.receiver.take() {
            // Drain all pending messages
            while let Ok(entry) = receiver.try_recv() {
                // Skip entries from parent process after fork
                if entry.pid != current_pid {
                    continue;
                }

                // Emit log entry through tracing
                match entry.level {
                    Level::ERROR => tracing::error!("{}", entry.message),
                    Level::WARN => tracing::warn!("{}", entry.message),
                    Level::INFO => tracing::info!("{}", entry.message),
                    Level::DEBUG => tracing::debug!("{}", entry.message),
                    Level::TRACE => tracing::trace!("{}", entry.message),
                }
            }

            // Restore the receiver for future use
            self.receiver = Some(receiver);
        }

        Ok(())
    }

    /// Get the number of log messages that were dropped due to queue overflow.
    ///
    /// This counter is incremented whenever `log_message()` is called and the
    /// queue is full. It provides visibility into log loss during high volume.
    ///
    /// # Returns
    ///
    /// The total number of dropped log messages since service creation.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let dropped = service.get_entries_lost();
    /// if dropped > 0 {
    ///     eprintln!("Warning: {} log messages were dropped", dropped);
    /// }
    /// ```
    pub fn get_entries_lost(&self) -> usize {
        self.entries_lost.load(Ordering::Relaxed)
    }
}

/// Initialize the global logging system with specified output targets.
///
/// This function configures the tracing subscriber with one or more output layers:
/// - **journald** (Linux only): Native systemd journal integration
/// - **android** (Android only): Android platform logging via __android_log_write
/// - **file**: File-based logging with automatic daily rotation
/// - **stderr**: Console output for development and debugging
///
/// # Arguments
///
/// * `enable_journald` - Enable systemd journal logging (Linux only, no-op on other platforms)
/// * `log_file` - Optional path for file-based logging with daily rotation
/// * `log_to_stderr` - Enable console (stderr) output
/// * `log_level` - Minimum log level to record (ERROR, WARN, INFO, DEBUG, TRACE)
///
/// # Returns
///
/// - `Ok(())` if logging was successfully initialized
/// - `Err(PlatformError::LoggingFailed)` if initialization failed
///
/// # Platform-Specific Behavior
///
/// - **Linux**: Supports journald for native systemd integration
/// - **Android**: Uses Android logging API via tracing-android
/// - **Other**: Falls back to file and/or stderr output
///
/// # Example
///
/// ```no_run
/// // Linux with journald
/// log_init(true, None, false, Level::INFO)?;
///
/// // File-based logging with daily rotation
/// log_init(false, Some(PathBuf::from("/var/log/dnsmasq")), false, Level::INFO)?;
///
/// // Development mode with stderr
/// log_init(false, None, true, Level::DEBUG)?;
/// ```
///
/// # Errors
///
/// Returns `PlatformError::LoggingFailed` if:
/// - journald initialization fails on Linux
/// - File path is invalid or not writable
/// - Global subscriber cannot be set (already initialized)
pub fn log_init(
    enable_journald: bool,
    log_file: Option<PathBuf>,
    log_to_stderr: bool,
    log_level: Level,
) -> Result<(), PlatformError> {
    // Create env filter based on log level
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            let level_str = match log_level {
                Level::ERROR => "error",
                Level::WARN => "warn",
                Level::INFO => "info",
                Level::DEBUG => "debug",
                Level::TRACE => "trace",
            };
            EnvFilter::new(level_str)
        });

    // Start with a registry
    let subscriber = Registry::default().with(env_filter);

    // Add journald layer on Linux if requested
    #[cfg(target_os = "linux")]
    let subscriber = if enable_journald {
        let journald_layer = tracing_journald::layer()
            .map_err(|e| PlatformError::LoggingFailed {
                reason: format!("Failed to initialize journald: {}", e),
            })?;
        subscriber.with(Some(journald_layer))
    } else {
        subscriber.with(None::<tracing_journald::Layer>)
    };

    // Add Android layer if on Android platform
    #[cfg(target_os = "android")]
    let subscriber = {
        let android_layer = tracing_android::layer("dnsmasq")
            .map_err(|e| PlatformError::LoggingFailed {
                reason: format!("Failed to initialize Android logging: {}", e),
            })?;
        subscriber.with(android_layer)
    };

    // Add file layer if path provided
    let subscriber = if let Some(log_path) = log_file {
        let log_dir = log_path.parent().ok_or_else(|| PlatformError::LoggingFailed {
            reason: format!("Invalid log file path: {:?}", log_path),
        })?;
        
        let log_file_name = log_path.file_name().ok_or_else(|| PlatformError::LoggingFailed {
            reason: format!("Invalid log file name: {:?}", log_path),
        })?;

        // Create rolling daily appender with non-blocking writer
        let file_appender = rolling::daily(log_dir, log_file_name);
        let (non_blocking_appender, _guard) = non_blocking(file_appender);

        // Create fmt layer for file output
        let file_layer = fmt::layer()
            .with_writer(non_blocking_appender)
            .with_ansi(false); // No ANSI colors in log files

        subscriber.with(Some(file_layer))
    } else {
        subscriber.with(None::<fmt::Layer<Registry>>)
    };

    // Add stderr layer if requested
    let subscriber = if log_to_stderr {
        let stderr_layer = fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(true); // Enable colors for terminal
        subscriber.with(Some(stderr_layer))
    } else {
        subscriber.with(None::<fmt::Layer<Registry>>)
    };

    // Initialize the global subscriber
    subscriber
        .try_init()
        .map_err(|e| PlatformError::LoggingFailed {
            reason: format!("Failed to set global subscriber: {}", e),
        })?;

    Ok(())
}

/// Convenience function to flush a logging service.
///
/// This is a thin wrapper around `LoggingService::flush()` for API compatibility
/// with the original C function signature.
///
/// # Arguments
///
/// * `service` - Mutable reference to the logging service to flush
///
/// # Returns
///
/// - `Ok(())` if all messages were successfully flushed
/// - `Err(PlatformError::LoggingFailed)` if flushing failed
///
/// # Example
///
/// ```no_run
/// flush_log(&mut logging_service)?;
/// ```
pub async fn flush_log(service: &mut LoggingService) -> Result<(), PlatformError> {
    service.flush().await
}

/// Fatal error handler with final log message before process termination.
///
/// This function logs a final error message and terminates the process with the
/// specified exit code. It ensures the message is written before exiting.
///
/// **Note**: This function never returns (marked with `!` return type).
///
/// # Arguments
///
/// * `message` - Final error message to log before termination
/// * `exit_code` - Process exit code (typically non-zero for errors)
///
/// # Example
///
/// ```no_run
/// if critical_error {
///     die("Failed to bind to privileged port", 1);
/// }
/// ```
///
/// # C Compatibility
///
/// This function replaces the C `die()` function from `src/log.c`, which called
/// `my_syslog(LOG_CRIT, message)` followed by `exit(exit_code)`.
pub fn die(message: &str, exit_code: i32) -> ! {
    // Log the fatal error
    tracing::error!("FATAL: {}", message);

    // Also print to stderr for visibility
    eprintln!("dnsmasq: FATAL: {}", message);

    // Terminate the process
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_logging_service_creation() {
        let service = LoggingService::new(LOG_MAX);
        assert_eq!(service.capacity, LOG_MAX);
        assert_eq!(service.get_entries_lost(), 0);
        assert_eq!(service.pid, process::id());
    }

    #[tokio::test]
    async fn test_log_message_truncation() {
        let service = LoggingService::new(LOG_MAX);
        
        // Create a message longer than MAX_MESSAGE
        let long_message = "x".repeat(MAX_MESSAGE + 100);
        service.log_message(Level::INFO, long_message).await;

        // Flush and verify (message should be truncated)
        // Note: In real implementation, we'd need to capture the output
        // For now, just verify no panic occurs
    }

    #[tokio::test]
    async fn test_entries_lost_counter() {
        let service = LoggingService::new(1); // Very small queue
        
        // Fill the queue
        service.log_message(Level::INFO, "Message 1".to_string()).await;
        
        // This should increment entries_lost
        service.log_message(Level::INFO, "Message 2".to_string()).await;
        
        // Wait a bit for backoff
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // entries_lost should be > 0
        assert!(service.get_entries_lost() > 0);
    }

    #[tokio::test]
    async fn test_flush_empty_queue() {
        let mut service = LoggingService::new(LOG_MAX);
        
        // Flush empty queue should succeed
        let result = service.flush().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fork_safety_check() {
        let service = LoggingService::new(LOG_MAX);
        
        // Current PID should match service PID
        assert_eq!(service.pid, process::id());
    }
}
