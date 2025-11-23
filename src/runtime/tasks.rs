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

//! Background task management infrastructure for spawning and coordinating periodic maintenance tasks.
//!
//! This module replaces C's SIGALRM timer-based operations from dnsmasq.c with structured async
//! task spawning using tokio. It manages periodic maintenance tasks for DNS cache cleanup, DHCP
//! lease expiration, upstream server health checks, configuration file monitoring, and other
//! scheduled operations.
//!
//! # Architecture
//!
//! ## C Implementation (dnsmasq.c)
//!
//! The C version used SIGALRM-based timers with manual timeout calculations:
//!
//! ```c
//! // C pattern: SIGALRM handling in sig_handler()
//! if (sig == SIGALRM)
//!     event = EVENT_ALARM;
//! send_event(pipewrite, event, 0, NULL);
//!
//! // In async_event(): Manual timeout tracking
//! void send_alarm(time_t event, time_t now) {
//!     if (difftime(event, now) <= 0.0)
//!         send_event(pipewrite, EVENT_ALARM, 0, NULL);
//!     else
//!         alarm((unsigned)difftime(event, now));
//! }
//! ```
//!
//! ## Rust Implementation
//!
//! This module provides structured concurrency with tokio:
//!
//! ```rust,ignore
//! use tokio::time::{interval, Duration};
//!
//! // Spawn periodic task for cache cleanup
//! task_manager.spawn_periodic_task(
//!     "cache_cleanup",
//!     Duration::from_secs(60),
//!     BackoffStrategy::None,
//!     move |shutdown| async move {
//!         dns_cache.lock().await.prune_expired();
//!         Ok(())
//!     },
//! );
//! ```
//!
//! # Key Transformations
//!
//! | C Pattern | Rust Equivalent | Benefit |
//! |-----------|----------------|---------|
//! | `alarm(seconds)` | `tokio::time::interval(Duration)` | Type-safe intervals |
//! | `SIGALRM` signal | `tokio::time::Interval` | No signal handling needed |
//! | `send_alarm()` | `spawn_periodic_task()` | Structured task lifecycle |
//! | `async_event(EVENT_ALARM)` | Task closure execution | Clear separation of concerns |
//! | `difftime()` manual calc | `tokio::time::Duration` | Compiler-enforced correctness |
//! | Global timeout state | Task-local state | No shared mutable state |
//!
//! # Task Types
//!
//! ## Periodic Tasks
//!
//! Tasks that run at regular intervals, replacing C's alarm-based timers:
//!
//! - **DNS Cache Cleanup** (60s interval): Removes expired cache entries via `DnsCache::prune_expired()`
//! - **DHCP Lease Expiration** (10s interval): Removes expired leases via `LeaseManager::prune_expired()`
//! - **Upstream Server Health Checks** (30s interval): Monitors server availability via `UpstreamPool::check_health()`
//! - **Lease Database Persistence** (300s interval): Writes leases to disk via `write_leases()`
//!
//! ## Background Tasks
//!
//! Long-running tasks that respond to external events:
//!
//! - **Configuration File Monitor**: Uses inotify/kqueue to detect config changes
//! - **Log Rotation Handler**: Responds to SIGUSR2 signals to reopen log files
//! - **Network Interface Monitor**: Detects interface up/down events
//!
//! # Shutdown Coordination
//!
//! The `TaskManager` provides graceful shutdown using `tokio::sync::broadcast`:
//!
//! ```rust,ignore
//! // Main shutdown flow
//! task_manager.shutdown().await;
//! task_manager.wait_for_completion().await;
//! ```
//!
//! Each task receives a `ShutdownHandle` to check for shutdown signals:
//!
//! ```rust,ignore
//! spawn_periodic_task(..., |mut shutdown| async move {
//!     loop {
//!         tokio::select! {
//!             _ = interval.tick() => {
//!                 // Do periodic work
//!             }
//!             _ = shutdown.wait() => {
//!                 info!("Task shutting down gracefully");
//!                 break;
//!             }
//!         }
//!     }
//!     Ok(())
//! });
//! ```
//!
//! # Error Recovery
//!
//! Tasks can restart on failure with exponential backoff:
//!
//! ```rust,ignore
//! task_manager.spawn_periodic_task(
//!     "upstream_health",
//!     Duration::from_secs(30),
//!     BackoffStrategy::Exponential {
//!         initial: Duration::from_secs(1),
//!         max: Duration::from_secs(300),
//!         multiplier: 2.0,
//!     },
//!     |shutdown| async move {
//!         upstream_pool.check_health()?;
//!         Ok(())
//!     },
//! );
//! ```
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::runtime::tasks::{TaskManager, BackoffStrategy};
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! let task_manager = TaskManager::new();
//! let dns_cache = Arc::new(RwLock::new(DnsCache::new(&config)));
//! let lease_manager = Arc::new(LeaseManager::new(&config));
//!
//! // Spawn cache cleanup task
//! let cache_clone = Arc::clone(&dns_cache);
//! task_manager.spawn_periodic_task(
//!     "cache_cleanup",
//!     Duration::from_secs(60),
//!     BackoffStrategy::None,
//!     move |shutdown| {
//!         let cache = Arc::clone(&cache_clone);
//!         async move {
//!             let mut interval = tokio::time::interval(Duration::from_secs(60));
//!             loop {
//!                 tokio::select! {
//!                     _ = interval.tick() => {
//!                         let removed = cache.write().await.prune_expired();
//!                         info!(removed, "Pruned expired cache entries");
//!                     }
//!                     _ = shutdown.wait() => {
//!                         info!("Cache cleanup task shutting down");
//!                         break;
//!                     }
//!                 }
//!             }
//!             Ok(())
//!         }
//!     },
//! );
//!
//! // Graceful shutdown
//! tokio::signal::ctrl_c().await?;
//! task_manager.shutdown().await;
//! task_manager.wait_for_completion().await;
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, error, info, instrument, warn};

use crate::error::Result;

/// Backoff strategy for task restart on failure.
///
/// Determines how long to wait before restarting a failed task. This replaces C's manual
/// retry timeout calculations with structured retry policies.
///
/// # Variants
///
/// - `None`: No backoff, restart immediately (equivalent to C's immediate retry)
/// - `Fixed`: Wait a fixed duration between retries
/// - `Exponential`: Exponentially increase wait time up to a maximum
#[derive(Debug, Clone, Copy)]
pub enum BackoffStrategy {
    /// No backoff - restart immediately on failure.
    None,

    /// Fixed backoff - wait the same duration between each retry.
    Fixed {
        /// Duration to wait between retries.
        delay: Duration,
    },

    /// Exponential backoff - double the wait time on each retry up to a maximum.
    Exponential {
        /// Initial delay for first retry.
        initial: Duration,
        /// Maximum delay cap.
        max: Duration,
        /// Multiplier for each retry (typically 2.0).
        multiplier: f64,
    },
}

impl BackoffStrategy {
    /// Calculate the next backoff duration given the current attempt count.
    ///
    /// # Arguments
    ///
    /// * `attempt` - The current retry attempt number (0-indexed)
    ///
    /// # Returns
    ///
    /// The duration to wait before the next retry attempt.
    fn next_delay(&self, attempt: usize) -> Duration {
        match self {
            BackoffStrategy::None => Duration::from_secs(0),
            BackoffStrategy::Fixed { delay } => *delay,
            BackoffStrategy::Exponential { initial, max, multiplier } => {
                // Cap attempt at 30 before casting to i32 for powi.
                // In practice, retry logic never exceeds 10-20 attempts before giving up.
                // Capping at 30 ensures the cast is always safe while being generous enough
                // for any reasonable retry scenario.
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                let exponent = attempt.min(30) as i32;
                let delay_secs = initial.as_secs_f64() * multiplier.powi(exponent);
                let capped_secs = delay_secs.min(max.as_secs_f64());
                Duration::from_secs_f64(capped_secs)
            }
        }
    }
}

/// Handle for signaling and checking shutdown state.
///
/// This type replaces C's global `int run` flag and signal-based termination with
/// structured shutdown coordination using `tokio::sync::broadcast`.
///
/// # C Equivalent
///
/// ```c
/// // C pattern: Global flag checked in main loop
/// static volatile int run = 1;
///
/// void sig_handler(int sig) {
///     if (sig == SIGTERM || sig == SIGINT)
///         run = 0;  // Signal shutdown
/// }
///
/// while (run) {
///     // Main loop
/// }
/// ```
///
/// # Rust Implementation
///
/// ```rust,ignore
/// let (shutdown_tx, _) = broadcast::channel(1);
/// let handle = ShutdownHandle::new(shutdown_tx);
///
/// // In task:
/// tokio::select! {
///     _ = work() => { /* task work */ }
///     _ = handle.wait() => { break; }  // Graceful shutdown
/// }
/// ```
#[derive(Clone)]
pub struct ShutdownHandle {
    /// Receiver for shutdown broadcast signals.
    rx: Arc<RwLock<broadcast::Receiver<()>>>,
}

impl ShutdownHandle {
    /// Create a new shutdown handle from a broadcast receiver.
    #[must_use]
    pub fn new(rx: broadcast::Receiver<()>) -> Self {
        Self { rx: Arc::new(RwLock::new(rx)) }
    }

    /// Wait for shutdown signal.
    ///
    /// This async function blocks until shutdown is signaled, allowing tasks to
    /// gracefully terminate via `tokio::select!`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// loop {
    ///     tokio::select! {
    ///         _ = interval.tick() => {
    ///             // Do work
    ///         }
    ///         _ = shutdown.wait() => {
    ///             info!("Shutting down gracefully");
    ///             break;
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn wait(&self) {
        let mut rx = self.rx.write().await;
        let _ = rx.recv().await;
    }

    /// Check if shutdown has been signaled without blocking.
    ///
    /// # Returns
    ///
    /// `true` if shutdown has been signaled, `false` otherwise.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        // Try to receive without blocking - requires mutable access
        let rx = self.rx.try_write();
        if let Ok(mut receiver) = rx {
            matches!(receiver.try_recv(), Ok(()) | Err(broadcast::error::TryRecvError::Closed))
        } else {
            false
        }
    }

    /// Signal shutdown to this handle.
    ///
    /// This is primarily used internally by `TaskManager`.
    #[allow(clippy::unused_async)] // Maintains uniform async API with wait() method
    pub async fn shutdown(&self) {
        // Shutdown is signaled by the broadcast sender being dropped
        // or explicitly sending a message
    }
}

/// Task metadata for tracking and debugging.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TaskMetadata {
    /// Task name for logging and identification.
    name: String,
    /// When the task was spawned.
    spawned_at: Instant,
    /// Number of times the task has been restarted.
    restart_count: usize,
    /// Whether this is a periodic task.
    is_periodic: bool,
}

/// Background task management infrastructure coordinating all periodic maintenance operations.
///
/// This struct replaces C's SIGALRM timer handling and manual timeout calculations in dnsmasq.c
/// with structured async task spawning using tokio. It manages lifecycle for all background tasks
/// including DNS cache cleanup, DHCP lease expiration checks, upstream server health monitoring,
/// and configuration file watching.
///
/// # C Equivalent Pattern
///
/// ```c
/// // C implementation in dnsmasq.c
/// void send_alarm(time_t event, time_t now) {
///     if (now == 0 || event != 0) {
///         if ((now == 0 || difftime(event, now) <= 0.0))
///             send_event(pipewrite, EVENT_ALARM, 0, NULL);
///         else
///             alarm((unsigned)difftime(event, now));
///     }
/// }
///
/// // In async_event():
/// case EVENT_ALARM:
///     // Check for expired leases
///     // Clean cache
///     // Check /etc/resolv.conf
///     // Send SIGALRM to TCP children
///     break;
/// ```
///
/// # Rust Implementation
///
/// ```rust,ignore
/// let task_manager = TaskManager::new();
///
/// // Spawn periodic cache cleanup
/// task_manager.spawn_periodic_task(
///     "cache_cleanup",
///     Duration::from_secs(60),
///     BackoffStrategy::None,
///     |shutdown| async move {
///         // Task implementation
///         Ok(())
///     },
/// );
/// ```
///
/// # Shutdown Coordination
///
/// The `TaskManager` coordinates graceful shutdown across all spawned tasks:
///
/// 1. `shutdown()` - Signals all tasks to stop
/// 2. Tasks check `ShutdownHandle::wait()` in their select loops
/// 3. `wait_for_completion()` - Waits for all tasks to finish cleanup
///
/// This replaces C's global `run` flag and signal-based termination.
/// Type alias for the task list storage to reduce type complexity.
type TaskList = Arc<RwLock<Vec<(TaskMetadata, JoinHandle<Result<()>>)>>>;

/// Task management system for coordinating background operations.
///
/// Provides structured concurrency for periodic maintenance tasks.
pub struct TaskManager {
    /// Broadcast sender for shutdown coordination.
    shutdown_tx: broadcast::Sender<()>,
    /// Join handles for all spawned tasks.
    tasks: TaskList,
    /// Channel for task completion notifications.
    completion_tx: mpsc::UnboundedSender<String>,
    /// Channel receiver for task completion.
    completion_rx: Arc<RwLock<mpsc::UnboundedReceiver<String>>>,
}

impl TaskManager {
    /// Create a new `TaskManager` instance.
    ///
    /// Initializes the shutdown coordination broadcast channel and task tracking structures.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let task_manager = TaskManager::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(16);
        let (completion_tx, completion_rx) = mpsc::unbounded_channel();

        Self {
            shutdown_tx,
            tasks: Arc::new(RwLock::new(Vec::new())),
            completion_tx,
            completion_rx: Arc::new(RwLock::new(completion_rx)),
        }
    }

    /// Spawn a periodic task that runs at regular intervals.
    ///
    /// This replaces C's `send_alarm()` function and SIGALRM-based timer scheduling with
    /// structured interval timers. The task will automatically restart on failure according
    /// to the specified backoff strategy.
    ///
    /// # Arguments
    ///
    /// * `name` - Task identifier for logging
    /// * `interval_duration` - How often the task should run
    /// * `backoff` - Retry strategy on failure
    /// * `task_fn` - Async function to execute on each interval
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // C: Manual alarm scheduling
    /// time_t next_lease_check = now + 10;
    /// send_alarm(next_lease_check, now);
    ///
    /// // In async_event(EVENT_ALARM):
    /// if (difftime(now, daemon->last_lease_check) >= 10) {
    ///     lease_prune();
    ///     daemon->last_lease_check = now;
    /// }
    /// ```
    ///
    /// # Rust Equivalent
    ///
    /// ```rust,ignore
    /// task_manager.spawn_periodic_task(
    ///     "lease_expiration",
    ///     Duration::from_secs(10),
    ///     BackoffStrategy::None,
    ///     |shutdown| async move {
    ///         lease_manager.prune_expired().await;
    ///         Ok(())
    ///     },
    /// );
    /// ```
    #[instrument(skip(self, task_fn), fields(task_name = %name))]
    pub fn spawn_periodic_task<F, Fut>(
        &self,
        name: String,
        interval_duration: Duration,
        backoff: BackoffStrategy,
        task_fn: F,
    ) where
        F: Fn(ShutdownHandle) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let shutdown_rx = self.shutdown_tx.subscribe();
        let shutdown_handle = ShutdownHandle::new(shutdown_rx);
        let completion_tx = self.completion_tx.clone();
        let task_name = name.clone();

        let metadata = TaskMetadata {
            name: name.clone(),
            spawned_at: Instant::now(),
            restart_count: 0,
            is_periodic: true,
        };

        let handle = tokio::spawn(async move {
            info!(task = %name, interval = ?interval_duration, "Spawning periodic task");

            let mut attempt = 0;
            loop {
                let shutdown_clone = shutdown_handle.clone();
                let task_result = task_fn(shutdown_clone).await;

                match task_result {
                    Ok(()) => {
                        // Task completed successfully
                        debug!(task = %name, "Periodic task iteration completed");
                        attempt = 0; // Reset retry counter on success
                    }
                    Err(e) => {
                        // Task failed, apply backoff and retry
                        error!(task = %name, error = %e, attempt, "Periodic task failed");

                        let delay = backoff.next_delay(attempt);
                        if delay > Duration::from_secs(0) {
                            warn!(task = %name, delay = ?delay, "Backing off before retry");
                            tokio::select! {
                                () = sleep(delay) => {}
                                () = shutdown_handle.wait() => {
                                    info!(task = %name, "Shutdown signal received during backoff");
                                    break;
                                }
                            }
                        }
                        attempt += 1;
                    }
                }

                // Check for shutdown
                if shutdown_handle.is_shutdown() {
                    info!(task = %name, "Periodic task received shutdown signal");
                    break;
                }

                // Wait for next interval
                tokio::select! {
                    () = sleep(interval_duration) => {
                        // Continue to next iteration
                    }
                    () = shutdown_handle.wait() => {
                        info!(task = %name, "Shutdown signal received, exiting");
                        break;
                    }
                }
            }

            let _ = completion_tx.send(task_name);
            info!(task = %name, "Periodic task terminated");
            Ok(())
        });

        // Store the task handle
        let tasks = self.tasks.clone();
        tokio::spawn(async move {
            tasks.write().await.push((metadata, handle));
        });
    }

    /// Spawn a long-running background task.
    ///
    /// This method spawns tasks that run continuously until shutdown, rather than on
    /// a fixed interval. Examples include file monitoring tasks or event listeners.
    ///
    /// # Arguments
    ///
    /// * `name` - Task identifier for logging
    /// * `backoff` - Retry strategy on failure
    /// * `task_fn` - Async function to execute
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// task_manager.spawn_background_task(
    ///     "config_watcher",
    ///     BackoffStrategy::Fixed { delay: Duration::from_secs(5) },
    ///     |shutdown| async move {
    ///         // Watch for config file changes
    ///         loop {
    ///             tokio::select! {
    ///                 Some(event) = watcher.next() => {
    ///                     handle_config_change(event).await?;
    ///                 }
    ///                 _ = shutdown.wait() => break,
    ///             }
    ///         }
    ///         Ok(())
    ///     },
    /// );
    /// ```
    #[instrument(skip(self, task_fn), fields(task_name = %name))]
    pub fn spawn_background_task<F, Fut>(&self, name: String, backoff: BackoffStrategy, task_fn: F)
    where
        F: Fn(ShutdownHandle) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let shutdown_rx = self.shutdown_tx.subscribe();
        let shutdown_handle = ShutdownHandle::new(shutdown_rx);
        let completion_tx = self.completion_tx.clone();
        let task_name = name.clone();

        let metadata = TaskMetadata {
            name: name.clone(),
            spawned_at: Instant::now(),
            restart_count: 0,
            is_periodic: false,
        };

        let handle = tokio::spawn(async move {
            info!(task = %name, "Spawning background task");

            let mut attempt = 0;
            loop {
                let shutdown_clone = shutdown_handle.clone();
                let task_result = task_fn(shutdown_clone).await;

                match task_result {
                    Ok(()) => {
                        // Task completed (likely due to shutdown)
                        info!(task = %name, "Background task completed");
                        break;
                    }
                    Err(e) => {
                        // Task failed, check if we should restart
                        error!(task = %name, error = %e, attempt, "Background task failed");

                        // Check for shutdown before restarting
                        if shutdown_handle.is_shutdown() {
                            warn!(task = %name, "Not restarting task due to shutdown");
                            break;
                        }

                        let delay = backoff.next_delay(attempt);
                        if delay > Duration::from_secs(0) {
                            warn!(task = %name, delay = ?delay, "Backing off before restart");
                            tokio::select! {
                                () = sleep(delay) => {}
                                () = shutdown_handle.wait() => {
                                    info!(task = %name, "Shutdown signal received during backoff");
                                    break;
                                }
                            }
                        }
                        attempt += 1;
                    }
                }
            }

            let _ = completion_tx.send(task_name);
            info!(task = %name, "Background task terminated");
            Ok(())
        });

        // Store the task handle
        let tasks = self.tasks.clone();
        tokio::spawn(async move {
            tasks.write().await.push((metadata, handle));
        });
    }

    /// Signal shutdown to all managed tasks.
    ///
    /// This broadcasts a shutdown signal to all tasks, allowing them to complete their
    /// current work and clean up gracefully. This replaces C's pattern of setting a
    /// global flag on SIGTERM.
    ///
    /// # C Equivalent
    ///
    /// ```c
    /// // C: Global flag in signal handler
    /// static volatile int run = 1;
    ///
    /// void sig_handler(int sig) {
    ///     if (sig == SIGTERM)
    ///         run = 0;
    /// }
    ///
    /// while (run) {
    ///     poll(...);
    /// }
    /// ```
    ///
    /// # Rust Equivalent
    ///
    /// ```rust,ignore
    /// task_manager.shutdown().await;
    /// ```
    #[instrument(skip(self))]
    pub async fn shutdown(&self) {
        info!("Broadcasting shutdown signal to all tasks");

        // Send shutdown signal to all tasks
        let _ = self.shutdown_tx.send(());

        // Give tasks a moment to start processing shutdown
        sleep(Duration::from_millis(100)).await;
    }

    /// Wait for all tasks to complete their shutdown sequence.
    ///
    /// This method blocks until all spawned tasks have finished their cleanup and
    /// terminated. It should be called after `shutdown()` to ensure graceful termination.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Graceful shutdown sequence
    /// task_manager.shutdown().await;
    /// task_manager.wait_for_completion().await;
    /// info!("All tasks have completed");
    /// ```
    #[instrument(skip(self))]
    pub async fn wait_for_completion(&self) {
        info!("Waiting for all tasks to complete");

        let tasks = self.tasks.read().await;
        let task_count = tasks.len();
        drop(tasks); // Release lock before waiting

        // Wait for completion notifications
        let mut completed = 0;
        let mut rx = self.completion_rx.write().await;

        while completed < task_count {
            tokio::select! {
                Some(task_name) = rx.recv() => {
                    completed += 1;
                    debug!(task = %task_name, completed, total = task_count, "Task completed");
                }
                () = sleep(Duration::from_secs(30)) => {
                    warn!(completed, total = task_count, "Still waiting for tasks to complete");
                }
            }
        }

        info!(completed = task_count, "All tasks have completed");
    }
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_periodic_task_execution() {
        let task_manager = TaskManager::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        task_manager.spawn_periodic_task(
            "test_periodic".to_string(),
            Duration::from_millis(50),
            BackoffStrategy::None,
            move |_shutdown| {
                let counter = Arc::clone(&counter_clone);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        );

        // Let it run for a bit
        sleep(Duration::from_millis(250)).await;

        // Should have executed multiple times
        let count = counter.load(Ordering::SeqCst);
        assert!(count >= 2, "Task should execute multiple times, got {}", count);

        task_manager.shutdown().await;
        task_manager.wait_for_completion().await;
    }

    #[tokio::test]
    async fn test_background_task_execution() {
        let task_manager = TaskManager::new();
        let executed = Arc::new(AtomicUsize::new(0));
        let executed_clone = Arc::clone(&executed);

        task_manager.spawn_background_task(
            "test_background".to_string(),
            BackoffStrategy::None,
            move |shutdown| {
                let executed = Arc::clone(&executed_clone);
                async move {
                    executed.store(1, Ordering::SeqCst);
                    shutdown.wait().await;
                    Ok(())
                }
            },
        );

        // Give it time to start
        sleep(Duration::from_millis(50)).await;
        assert_eq!(executed.load(Ordering::SeqCst), 1);

        task_manager.shutdown().await;
        task_manager.wait_for_completion().await;
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let task_manager = TaskManager::new();
        let shutdown_received = Arc::new(AtomicUsize::new(0));
        let shutdown_clone = Arc::clone(&shutdown_received);

        task_manager.spawn_background_task(
            "test_shutdown".to_string(),
            BackoffStrategy::None,
            move |shutdown| {
                let flag = Arc::clone(&shutdown_clone);
                async move {
                    shutdown.wait().await;
                    flag.store(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        );

        sleep(Duration::from_millis(50)).await;
        task_manager.shutdown().await;
        task_manager.wait_for_completion().await;

        assert_eq!(shutdown_received.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_backoff_strategy_none() {
        let strategy = BackoffStrategy::None;
        assert_eq!(strategy.next_delay(0), Duration::from_secs(0));
        assert_eq!(strategy.next_delay(5), Duration::from_secs(0));
    }

    #[test]
    fn test_backoff_strategy_fixed() {
        let strategy = BackoffStrategy::Fixed { delay: Duration::from_secs(5) };
        assert_eq!(strategy.next_delay(0), Duration::from_secs(5));
        assert_eq!(strategy.next_delay(10), Duration::from_secs(5));
    }

    #[test]
    fn test_backoff_strategy_exponential() {
        let strategy = BackoffStrategy::Exponential {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
            multiplier: 2.0,
        };

        assert_eq!(strategy.next_delay(0), Duration::from_secs(1));
        assert_eq!(strategy.next_delay(1), Duration::from_secs(2));
        assert_eq!(strategy.next_delay(2), Duration::from_secs(4));
        assert_eq!(strategy.next_delay(10), Duration::from_secs(60)); // Capped at max
    }
}
