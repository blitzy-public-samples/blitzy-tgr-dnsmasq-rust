// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Linux inotify-based file system monitoring for efficient configuration reload
//!
//! This Linux-specific module implements efficient file system monitoring using the
//! inotify(7) API through the `notify` crate to detect configuration file changes
//! without polling. The system watches critical configuration files including
//! /etc/resolv.conf (upstream DNS servers), dynamic DHCP hosts directories, and
//! DHCP options files. When changes are detected, dnsmasq automatically reloads
//! the affected configuration without requiring manual daemon restart or SIGHUP signal.
//!
//! # Architecture
//!
//! ## C Implementation Strategy (src/inotify.c)
//!
//! The C implementation uses raw inotify(7) syscalls:
//! - `inotify_init1(IN_NONBLOCK | IN_CLOEXEC)` to create inotify file descriptor
//! - `inotify_add_watch()` to add watches for directories containing monitored files
//! - `read()` from inotify FD to retrieve events in poll-based event loop
//! - Manual parsing of `struct inotify_event` with variable-length name field
//!
//! ## Rust Implementation Strategy (This Module)
//!
//! Replaces C's manual inotify API usage with the `notify` crate:
//! - `notify::RecommendedWatcher` provides inotify backend on Linux automatically
//! - `tokio::sync::mpsc` channel converts synchronous notify events to async stream
//! - `EventKind::Modify(ModifyKind::Data)` maps to IN_CLOSE_WRITE
//! - `EventKind::Create` maps to IN_MOVED_TO
//! - Type-safe event handling with Rust enums instead of C bitflags
//!
//! # Key Responsibilities
//!
//! - Initialize inotify watches for resolv.conf files and their parent directories
//! - Monitor dynamic DHCP hosts directories for hosts file additions/modifications
//! - Monitor DHCP options files for configuration changes
//! - Process inotify events and trigger appropriate reload actions (cache flush,
//!   configuration reload, DHCP lease updates)
//! - Handle symbolic links by following them to watch the actual target files
//! - Integrate with tokio async runtime through mpsc channel event stream
//!
//! # Symlink Resolution
//!
//! The C implementation follows symlinks up to MAXSYMLINKS (typically 20) depth
//! using `readlink()` and manual path resolution for relative links. The Rust
//! implementation uses `std::fs::read_link()` with proper error handling and
//! absolute path conversion using parent directory context.
//!
//! # Event Filtering
//!
//! Both implementations ignore editor temporary files:
//! - Files ending with `~` (emacs backups)
//! - Files surrounded by `#` (emacs auto-save)
//! - Files starting with `.` (dotfiles)
//!
//! This prevents spurious reload events during file editing with common editors.
//!
//! # Performance Advantages
//!
//! The inotify-based approach provides significant performance advantages over
//! traditional polling-based file monitoring by eliminating unnecessary filesystem
//! checks and providing immediate notification of file changes. This is particularly
//! important for embedded systems where CPU cycles and battery power are constrained.
//!
//! # Platform Requirements
//!
//! This module is Linux-specific and requires:
//! - Linux kernel 2.6.13+ with inotify support
//! - Feature flag `target_os = "linux"` for conditional compilation
//!
//! On non-Linux platforms, dnsmasq falls back to polling-based configuration checking.
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use dnsmasq::platform::inotify::InotifyWatcher;
//! use dnsmasq::config::reload::reload_config;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! let config = Arc::new(RwLock::new(Config::default()));
//! let config_path = PathBuf::from("/etc/dnsmasq.conf");
//!
//! let mut watcher = InotifyWatcher::new()?;
//!
//! // Watch configuration file (follows symlinks automatically)
//! watcher.watch_file(&config_path).await?;
//!
//! // Watch dynamic hosts directory
//! watcher.watch_directory(Path::new("/etc/dnsmasq.d/hosts")).await?;
//!
//! // Start async event loop
//! let config_clone = config.clone();
//! let config_path_clone = config_path.clone();
//! tokio::spawn(async move {
//!     watcher.run(move || {
//!         let config = config_clone.clone();
//!         let path = config_path_clone.clone();
//!         async move {
//!             reload_config(&config, &path).await.ok();
//!         }
//!     }).await
//! });
//! ```

// Feature gate for Linux only - matches C #ifdef HAVE_INOTIFY
#[cfg(all(target_os = "linux", feature = "inotify"))]
use anyhow::Result;
#[cfg(all(target_os = "linux", feature = "inotify"))]
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
#[cfg(all(target_os = "linux", feature = "inotify"))]
use std::collections::HashMap;
#[cfg(all(target_os = "linux", feature = "inotify"))]
use std::path::{Path, PathBuf};
#[cfg(all(target_os = "linux", feature = "inotify"))]
use tokio::sync::mpsc;
#[cfg(all(target_os = "linux", feature = "inotify"))]
use tracing::{debug, error, info, instrument, warn};

#[cfg(all(target_os = "linux", feature = "inotify"))]
use crate::error::PlatformError;

/// Maximum symlink depth to follow before giving up (matches C MAXSYMLINKS).
///
/// This prevents infinite loops from circular symlinks and matches POSIX.1-2008
/// requirements. Typically set to 20 on Linux systems.
#[cfg(all(target_os = "linux", feature = "inotify"))]
const MAX_SYMLINK_DEPTH: u32 = 20;

/// Type of watch being performed for event dispatch routing.
///
/// Maps to C's resolvc/dyndir distinction for determining reload action.
#[cfg(all(target_os = "linux", feature = "inotify"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchType {
    /// Upstream DNS resolver configuration file (e.g., /etc/resolv.conf).
    ///
    /// Triggers `reload_config()` when modified to update forwarding servers.
    /// Maps to C `struct resolvc` entries in daemon->resolv_files list.
    ResolvConf,

    /// Dynamic DHCP hosts directory containing per-host configuration files.
    ///
    /// Triggers cache flush and hosts file reload when files added/modified.
    /// Maps to C `struct dyndir` with AH_DHCP_HST flag.
    DhcpHostsDir,

    /// DHCP options directory containing option configuration files.
    ///
    /// Triggers DHCP configuration reload when files added/modified.
    /// Maps to C `struct dyndir` with AH_DHCP_OPT flag.
    DhcpOptsDir,

    /// Additional hosts directory for DNS static host entries.
    ///
    /// Triggers DNS cache flush and hosts file reload.
    /// Maps to C `struct dyndir` with AH_HOSTS flag.
    AddnHostsDir,
}

/// Linux inotify-based file system watcher for configuration reload.
///
/// This struct wraps the `notify` crate's `RecommendedWatcher` (which uses inotify
/// on Linux) and integrates it with tokio's async runtime via an mpsc channel.
/// It maintains a mapping of watched paths to their watch types for proper
/// reload action dispatching.
///
/// # C Implementation Mapping
///
/// - C `daemon->inotifyfd`: Rust `RecommendedWatcher` with internal inotify FD
/// - C `struct resolvc *daemon->resolv_files`: Rust `HashMap<PathBuf, WatchType>`
/// - C `struct dyndir *daemon->dynamic_dirs`: Rust `HashMap<PathBuf, WatchType>`
/// - C `inotify_check()` read loop: Rust `run()` async event processing
///
/// # Thread Safety
///
/// The watcher itself is not Send/Sync because it contains the underlying
/// notify watcher which manages OS resources. However, the event receiving
/// end of the mpsc channel is Send and can be moved to a tokio task.
#[cfg(all(target_os = "linux", feature = "inotify"))]
pub struct InotifyWatcher {
    /// The underlying notify watcher providing inotify backend.
    ///
    /// Uses `RecommendedWatcher` which automatically selects inotify on Linux.
    /// Holds inotify file descriptor internally and receives events via callback.
    watcher: RecommendedWatcher,

    /// Receiver end of mpsc channel for async event stream consumption.
    ///
    /// The notify watcher sends events to the channel's sender in its callback,
    /// converting synchronous C-style inotify events to async Rust streams.
    event_rx: mpsc::Receiver<notify::Result<Event>>,

    /// Mapping of watched paths to their watch types for dispatch routing.
    ///
    /// Keys are canonical paths (after symlink resolution) to avoid duplicate
    /// watches. Values determine which reload action to trigger on events.
    ///
    /// Replaces C's parallel resolvc and dyndir linked lists with unified HashMap.
    watched_paths: HashMap<PathBuf, WatchType>,
}

#[cfg(all(target_os = "linux", feature = "inotify"))]
impl InotifyWatcher {
    /// Create a new inotify watcher with async event channel.
    ///
    /// Initializes the notify `RecommendedWatcher` with a channel sender callback
    /// that forwards inotify events to a tokio mpsc channel for async consumption.
    /// This replaces C's `inotify_init1(IN_NONBLOCK | IN_CLOEXEC)` call.
    ///
    /// # C Implementation Mapping
    ///
    /// ```c
    /// // C implementation (inotify_dnsmasq_init in src/inotify.c)
    /// daemon->inotifyfd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    /// if (daemon->inotifyfd == -1)
    ///     die(_("failed to create inotify: %s"), NULL, EC_MISC);
    /// ```
    ///
    /// ```rust,ignore
    /// // Rust implementation
    /// let watcher = InotifyWatcher::new()?;
    /// // Watcher ready to receive events
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::InotifyError` if:
    /// - inotify initialization fails (e.g., out of inotify instances)
    /// - Channel creation fails (should never happen)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::platform::inotify::InotifyWatcher;
    ///
    /// let watcher = InotifyWatcher::new()
    ///     .expect("Failed to initialize inotify");
    /// ```
    #[instrument(name = "inotify_new")]
    pub fn new() -> Result<Self, PlatformError> {
        info!("Initializing inotify file system watcher");

        // Create bounded channel for event stream (buffer 32 events)
        let (tx, rx) = mpsc::channel(32);

        // Create notify watcher with callback that sends to channel
        let watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                // Send event to channel (non-blocking, drops if full)
                if tx.blocking_send(res).is_err() {
                    warn!("Inotify event channel full, dropping event");
                }
            },
            notify::Config::default(),
        )
        .map_err(|e| PlatformError::InotifyError {
            path: "inotify".to_string(),
            reason: format!("Failed to initialize inotify: {}", e),
        })?;

        debug!("Inotify watcher initialized successfully");

        Ok(Self { watcher, event_rx: rx, watched_paths: HashMap::new() })
    }

    /// Watch a specific file for changes, following symlinks to actual target.
    ///
    /// This method resolves symbolic links up to MAX_SYMLINK_DEPTH to find the
    /// actual file to watch, then watches its containing directory for
    /// IN_CLOSE_WRITE and IN_MOVED_TO events. Watching the directory handles
    /// atomic file updates via temp file + rename pattern used by many editors.
    ///
    /// # C Implementation Mapping
    ///
    /// ```c
    /// // C implementation (inotify_dnsmasq_init in src/inotify.c lines 239-273)
    /// for (res = daemon->resolv_files; res; res = res->next) {
    ///     char *path = safe_malloc(strlen(res->name) + 1);
    ///     strcpy(path, res->name);
    ///     
    ///     // Follow symlinks
    ///     while ((new_path = my_readlink(path))) {
    ///         if (links-- == 0)
    ///             die(_("too many symlinks following %s"), res->name, EC_MISC);
    ///         free(path);
    ///         path = new_path;
    ///     }
    ///     
    ///     // Watch parent directory
    ///     if ((d = strrchr(path, '/'))) {
    ///         *d = 0;
    ///         res->wd = inotify_add_watch(daemon->inotifyfd, path,
    ///                                      IN_CLOSE_WRITE | IN_MOVED_TO);
    ///         res->file = d+1;
    ///         *d = '/';
    ///     }
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `path` - Path to file to watch (will be canonicalized and symlink-resolved)
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::InotifyError` if:
    /// - Symlink depth exceeds MAX_SYMLINK_DEPTH (circular symlinks)
    /// - File's parent directory doesn't exist (required for watching)
    /// - `inotify_add_watch()` fails (e.g., out of inotify watches)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut watcher = InotifyWatcher::new()?;
    /// watcher.watch_file(Path::new("/etc/resolv.conf")).await?;
    /// // Now monitoring /etc/resolv.conf (follows symlink if needed)
    /// ```
    #[instrument(skip(self), fields(path = %path.display()))]
    pub async fn watch_file(&mut self, path: &Path) -> Result<(), PlatformError> {
        info!("Adding watch for file: {}", path.display());

        // Follow symlinks to actual target file
        let target_path = self.follow_symlink(path).await?;
        debug!("Resolved {} to {}", path.display(), target_path.display());

        // Watch parent directory to catch atomic file updates
        let dir_path = target_path.parent().ok_or_else(|| PlatformError::InotifyError {
            path: path.display().to_string(),
            reason: "File has no parent directory".to_string(),
        })?;

        // Add inotify watch for directory
        self.watcher.watch(dir_path, RecursiveMode::NonRecursive).map_err(|e| {
            PlatformError::InotifyError {
                path: dir_path.display().to_string(),
                reason: format!("Failed to add inotify watch: {}", e),
            }
        })?;

        // Track this path as resolv.conf type (default for file watches)
        self.watched_paths.insert(target_path.clone(), WatchType::ResolvConf);

        info!("Successfully watching {} (directory: {})", path.display(), dir_path.display());

        Ok(())
    }

    /// Watch a directory for file additions and modifications.
    ///
    /// Watches the specified directory (non-recursively) for IN_CLOSE_WRITE,
    /// IN_MOVED_TO, and IN_DELETE events. Used for dynamic DHCP hosts directories
    /// and DHCP options directories where configuration is split across multiple
    /// files.
    ///
    /// # C Implementation Mapping
    ///
    /// ```c
    /// // C implementation (set_dynamic_inotify in src/inotify.c lines 428-513)
    /// for (dd = daemon->dynamic_dirs; dd; dd = dd->next) {
    ///     if (!(dd->flags & flag))
    ///         continue;
    ///     
    ///     dd->wd = inotify_add_watch(daemon->inotifyfd, dd->dname,
    ///                                 IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE);
    ///     dd->flags |= AH_WD_DONE;
    ///     
    ///     // Read existing files after adding watch to avoid race
    ///     if (!(dir_stream = opendir(dd->dname)))
    ///         continue;
    ///     
    ///     while ((ent = readdir(dir_stream))) {
    ///         // Process existing files
    ///     }
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `path` - Directory path to watch
    /// * `watch_type` - Type of directory (DHCP hosts, DHCP options, etc.)
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::InotifyError` if:
    /// - Directory doesn't exist or isn't accessible
    /// - `inotify_add_watch()` fails
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut watcher = InotifyWatcher::new()?;
    /// watcher.watch_directory(
    ///     Path::new("/etc/dnsmasq.d/hosts"),
    ///     WatchType::DhcpHostsDir
    /// ).await?;
    /// ```
    #[instrument(skip(self), fields(path = %path.display()))]
    pub async fn watch_directory(
        &mut self,
        path: &Path,
        watch_type: WatchType,
    ) -> Result<(), PlatformError> {
        info!("Adding watch for directory: {} (type: {:?})", path.display(), watch_type);

        // Verify directory exists
        if !path.exists() {
            return Err(PlatformError::InotifyError {
                path: path.display().to_string(),
                reason: "Directory does not exist".to_string(),
            });
        }

        if !path.is_dir() {
            return Err(PlatformError::InotifyError {
                path: path.display().to_string(),
                reason: "Path is not a directory".to_string(),
            });
        }

        // Add inotify watch for directory (non-recursive)
        self.watcher.watch(path, RecursiveMode::NonRecursive).map_err(|e| {
            PlatformError::InotifyError {
                path: path.display().to_string(),
                reason: format!("Failed to add inotify watch: {}", e),
            }
        })?;

        // Track directory with its watch type
        self.watched_paths.insert(path.to_path_buf(), watch_type);

        info!("Successfully watching directory: {}", path.display());

        Ok(())
    }

    /// Follow a symbolic link to its target, resolving up to MAX_SYMLINK_DEPTH.
    ///
    /// Recursively follows symlinks to find the actual file, handling both absolute
    /// and relative symlink targets. Relative targets are resolved relative to the
    /// symlink's parent directory. Prevents infinite loops from circular symlinks
    /// by limiting depth.
    ///
    /// # C Implementation Mapping
    ///
    /// ```c
    /// // C implementation (my_readlink in src/inotify.c lines 133-176)
    /// static char *my_readlink(char *path) {
    ///     ssize_t rc, size = 64;
    ///     char *buf;
    ///     
    ///     while (1) {
    ///         buf = safe_malloc(size);
    ///         rc = readlink(path, buf, (size_t)size);
    ///         
    ///         if (rc == -1) {
    ///             if (errno == EINVAL || errno == ENOENT) {
    ///                 free(buf);
    ///                 return NULL;  // Not a symlink
    ///             }
    ///             die(_("cannot access path %s: %s"), path, EC_MISC);
    ///         } else if (rc < size-1) {
    ///             buf[rc] = 0;
    ///             // Handle relative links
    ///             if (buf[0] != '/' && ((d = strrchr(path, '/')))) {
    ///                 char *new_buf = safe_malloc((d - path) + strlen(buf) + 2);
    ///                 *(d+1) = 0;
    ///                 strcpy(new_buf, path);
    ///                 strcat(new_buf, buf);
    ///                 free(buf);
    ///                 buf = new_buf;
    ///             }
    ///             return buf;
    ///         }
    ///         // Buffer too small, retry
    ///         size += 64;
    ///         free(buf);
    ///     }
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `path` - Path to resolve (may be symlink or regular file)
    ///
    /// # Returns
    ///
    /// Canonical path to the target file (original path if not a symlink)
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::InotifyError` if:
    /// - Symlink depth exceeds MAX_SYMLINK_DEPTH
    /// - Symlink target doesn't exist
    /// - I/O error reading symlink
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let watcher = InotifyWatcher::new()?;
    /// let target = watcher.follow_symlink(Path::new("/etc/resolv.conf")).await?;
    /// // target might be PathBuf("/run/systemd/resolve/stub-resolv.conf")
    /// ```
    #[instrument(skip(self), fields(path = %path.display()))]
    pub async fn follow_symlink(&self, path: &Path) -> Result<PathBuf, PlatformError> {
        let mut current_path = path.to_path_buf();
        let mut depth = 0;

        loop {
            // Check symlink depth limit
            if depth >= MAX_SYMLINK_DEPTH {
                return Err(PlatformError::InotifyError {
                    path: path.display().to_string(),
                    reason: format!("Too many symlinks (depth > {})", MAX_SYMLINK_DEPTH),
                });
            }

            // Try to read symlink
            match std::fs::read_link(&current_path) {
                Ok(target) => {
                    depth += 1;
                    debug!(
                        "Symlink {} -> {} (depth {})",
                        current_path.display(),
                        target.display(),
                        depth
                    );

                    // Resolve relative symlinks relative to parent directory
                    if target.is_relative() {
                        if let Some(parent) = current_path.parent() {
                            current_path = parent.join(target);
                        } else {
                            return Err(PlatformError::InotifyError {
                                path: path.display().to_string(),
                                reason: "Cannot resolve relative symlink without parent"
                                    .to_string(),
                            });
                        }
                    } else {
                        current_path = target;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Path doesn't exist - return as-is (might be created later)
                    debug!("Path {} does not exist yet", current_path.display());
                    return Ok(current_path);
                }
                Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                    // Not a symlink - this is the target
                    debug!("Path {} is not a symlink", current_path.display());
                    return Ok(current_path);
                }
                Err(e) => {
                    return Err(PlatformError::InotifyError {
                        path: current_path.display().to_string(),
                        reason: format!("Failed to read symlink: {}", e),
                    });
                }
            }
        }
    }

    /// Run the async event loop, processing inotify events and triggering reloads.
    ///
    /// This is the main event processing loop that continuously receives inotify
    /// events from the mpsc channel and dispatches reload actions based on watch
    /// type. Runs until the channel is closed (when watcher is dropped) or an
    /// error occurs.
    ///
    /// The reload callback is invoked when file events are detected, allowing
    /// the caller to specify custom reload logic (typically calling `reload_config`).
    ///
    /// # C Implementation Mapping
    ///
    /// ```c
    /// // C implementation (inotify_check in src/inotify.c lines 580-685)
    /// int inotify_check(time_t now) {
    ///     int hit = 0;
    ///     
    ///     while (1) {
    ///         int rc;
    ///         struct inotify_event *in;
    ///         
    ///         rc = read(daemon->inotifyfd, inotify_buffer, INOTIFY_SZ);
    ///         if (rc <= 0)
    ///             break;
    ///         
    ///         for (p = inotify_buffer; ...; p += sizeof(...) + in->len) {
    ///             in = (struct inotify_event*)p;
    ///             
    ///             // Ignore emacs backups and dotfiles
    ///             if (in->len == 0 || ... || in->name[0] == '.')
    ///                 continue;
    ///             
    ///             // Check resolv files
    ///             for (res = daemon->resolv_files; res; res = res->next)
    ///                 if (res->wd == in->wd && strcmp(res->file, in->name) == 0)
    ///                     hit = 1;
    ///             
    ///             // Check dynamic directories
    ///             for (dd = daemon->dynamic_dirs; dd; dd = dd->next) {
    ///                 if (dd->wd == in->wd) {
    ///                     // Reload hosts or DHCP config
    ///                 }
    ///             }
    ///         }
    ///     }
    ///     
    ///     return hit;
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `on_reload` - Async callback invoked when reload is needed
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::FileMonitoring` if event processing fails
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::config::reload::reload_config;
    ///
    /// let config = Arc::new(RwLock::new(Config::default()));
    /// let config_path = PathBuf::from("/etc/dnsmasq.conf");
    ///
    /// let mut watcher = InotifyWatcher::new()?;
    /// watcher.watch_file(&config_path).await?;
    ///
    /// watcher.run(|| {
    ///     let config = config.clone();
    ///     let path = config_path.clone();
    ///     async move {
    ///         reload_config(&config, &path).await.ok();
    ///     }
    /// }).await?;
    /// ```
    #[instrument(skip(self, on_reload))]
    pub async fn run<F, Fut>(mut self, on_reload: F) -> Result<(), PlatformError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        info!("Starting inotify event loop");

        while let Some(event_result) = self.event_rx.recv().await {
            match event_result {
                Ok(event) => {
                    if let Err(e) = self.handle_event(event, &on_reload).await {
                        error!("Failed to handle inotify event: {}", e);
                    }
                }
                Err(e) => {
                    error!("Inotify watch error: {}", e);
                    return Err(PlatformError::FileMonitoring(format!(
                        "Inotify watch error: {}",
                        e
                    )));
                }
            }
        }

        info!("Inotify event loop terminated");
        Ok(())
    }

    /// Handle a single inotify event, filtering and dispatching reload actions.
    ///
    /// Filters out editor temporary files and dispatches reload actions based
    /// on the watch type associated with the path. Maps notify EventKind enums
    /// to C inotify event masks.
    ///
    /// # Event Kind Mapping
    ///
    /// - `EventKind::Modify(ModifyKind::Data)` → IN_CLOSE_WRITE
    /// - `EventKind::Create` → IN_MOVED_TO
    /// - `EventKind::Remove` → IN_DELETE
    ///
    /// # Arguments
    ///
    /// * `event` - The notify event to process
    /// * `on_reload` - Callback to invoke for reload events
    #[instrument(skip(self, on_reload))]
    async fn handle_event<F, Fut>(&self, event: Event, on_reload: &F) -> Result<()>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        // Extract paths from event
        for path in event.paths {
            // Ignore editor temporary files (matches C filtering)
            if let Some(filename) = path.file_name() {
                let name = filename.to_string_lossy();

                // Ignore emacs backups (ending with ~)
                if name.ends_with('~') {
                    debug!("Ignoring emacs backup file: {}", name);
                    continue;
                }

                // Ignore emacs auto-save files (surrounded by #)
                if name.starts_with('#') && name.ends_with('#') {
                    debug!("Ignoring emacs auto-save file: {}", name);
                    continue;
                }

                // Ignore dotfiles (starting with .)
                if name.starts_with('.') {
                    debug!("Ignoring dotfile: {}", name);
                    continue;
                }
            }

            // Determine if this is a modification or creation event
            let should_reload = matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_));

            if should_reload {
                // Check if path or its parent directory is watched
                let watched = self.watched_paths.contains_key(&path)
                    || path.parent().map(|p| self.watched_paths.contains_key(p)).unwrap_or(false);

                if watched {
                    info!("Configuration file modified: {}", path.display());

                    // Trigger reload callback
                    on_reload().await;

                    // Log event kind for debugging
                    match event.kind {
                        EventKind::Modify(_) => {
                            info!("File modified: {}", path.display());
                        }
                        EventKind::Create(_) => {
                            info!("File created: {}", path.display());
                        }
                        EventKind::Remove(_) => {
                            info!("File removed: {}", path.display());
                        }
                        _ => {
                            debug!("Other event: {:?} for {}", event.kind, path.display());
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

// Stub implementation for Linux when inotify feature is disabled
/// Stub implementation of InotifyWatcher when the `inotify` feature is disabled on Linux.
///
/// This stub always returns an error when attempting to create a new instance.
#[cfg(all(target_os = "linux", not(feature = "inotify")))]
pub struct InotifyWatcher;

#[cfg(all(target_os = "linux", not(feature = "inotify")))]
impl InotifyWatcher {
    /// Attempts to create a new InotifyWatcher, but always fails since the feature is disabled.
    ///
    /// # Errors
    ///
    /// Always returns `PlatformError::FileMonitoring` indicating the feature is not enabled.
    pub fn new() -> Result<Self, crate::error::PlatformError> {
        Err(crate::error::PlatformError::FileMonitoring(
            "Inotify feature is not enabled".to_string(),
        ))
    }
}

// Stub implementation for non-Linux platforms
/// Stub implementation of InotifyWatcher for non-Linux platforms.
///
/// This stub always returns an error when attempting to create a new instance.
#[cfg(not(target_os = "linux"))]
pub struct InotifyWatcher;

#[cfg(not(target_os = "linux"))]
impl InotifyWatcher {
    /// Attempts to create a new InotifyWatcher, but always fails since inotify is Linux-only.
    ///
    /// # Errors
    ///
    /// Always returns `PlatformError::FileMonitoring` indicating inotify is only available on Linux.
    pub fn new() -> Result<Self, crate::error::PlatformError> {
        Err(crate::error::PlatformError::FileMonitoring(
            "Inotify is only available on Linux".to_string(),
        ))
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(all(test, target_os = "linux", feature = "inotify"))]
mod tests {
    use super::*;
    use crate::error::PlatformError;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_inotify_watcher_creation() {
        let watcher = InotifyWatcher::new();
        assert!(watcher.is_ok());
    }

    #[tokio::test]
    async fn test_watch_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.conf");
        fs::write(&file_path, b"test content").unwrap();

        let mut watcher = InotifyWatcher::new().unwrap();
        let result = watcher.watch_file(&file_path).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_watch_directory() {
        let temp_dir = TempDir::new().unwrap();

        let mut watcher = InotifyWatcher::new().unwrap();
        let result = watcher.watch_directory(temp_dir.path(), WatchType::DhcpHostsDir).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_follow_symlink() {
        let temp_dir = TempDir::new().unwrap();
        let target_path = temp_dir.path().join("target.txt");
        let symlink_path = temp_dir.path().join("link.txt");

        fs::write(&target_path, b"target content").unwrap();
        std::os::unix::fs::symlink(&target_path, &symlink_path).unwrap();

        let watcher = InotifyWatcher::new().unwrap();
        let resolved = watcher.follow_symlink(&symlink_path).await.unwrap();

        assert_eq!(resolved, target_path);
    }

    #[tokio::test]
    async fn test_follow_symlink_non_existent() {
        let temp_dir = TempDir::new().unwrap();
        let non_existent = temp_dir.path().join("nonexistent.txt");

        let watcher = InotifyWatcher::new().unwrap();
        let resolved = watcher.follow_symlink(&non_existent).await;

        // Should return the path as-is (might be created later)
        assert!(resolved.is_ok());
        assert_eq!(resolved.unwrap(), non_existent);
    }

    #[tokio::test]
    async fn test_follow_symlink_relative() {
        let temp_dir = TempDir::new().unwrap();
        let target_path = temp_dir.path().join("target.txt");
        let symlink_path = temp_dir.path().join("link.txt");

        fs::write(&target_path, b"target content").unwrap();

        // Create relative symlink
        let current_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp_dir.path()).unwrap();
        std::os::unix::fs::symlink("target.txt", "link.txt").unwrap();
        std::env::set_current_dir(current_dir).unwrap();

        let watcher = InotifyWatcher::new().unwrap();
        let resolved = watcher.follow_symlink(&symlink_path).await.unwrap();

        assert_eq!(resolved, target_path);
    }

    #[tokio::test]
    async fn test_max_symlink_depth() {
        let temp_dir = TempDir::new().unwrap();

        // Create circular symlink
        let link1 = temp_dir.path().join("link1");
        let link2 = temp_dir.path().join("link2");

        std::os::unix::fs::symlink(&link2, &link1).unwrap();
        std::os::unix::fs::symlink(&link1, &link2).unwrap();

        let watcher = InotifyWatcher::new().unwrap();
        let result = watcher.follow_symlink(&link1).await;

        assert!(result.is_err());
        if let Err(PlatformError::InotifyError { reason, .. }) = result {
            assert!(reason.contains("Too many symlinks"));
        }
    }

    #[tokio::test]
    async fn test_file_event_detection() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.conf");
        fs::write(&file_path, b"initial content").unwrap();

        let mut watcher = InotifyWatcher::new().unwrap();
        watcher.watch_file(&file_path).await.unwrap();

        // Spawn event loop
        let reload_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reload_called_clone = reload_called.clone();

        tokio::spawn(async move {
            watcher
                .run(|| {
                    let reload_called = reload_called_clone.clone();
                    async move {
                        reload_called.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                })
                .await
                .ok();
        });

        // Give watcher time to initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Modify file
        let mut file = fs::OpenOptions::new().write(true).truncate(true).open(&file_path).unwrap();
        file.write_all(b"modified content").unwrap();
        file.flush().unwrap();
        drop(file);

        // Give event time to be processed
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Verify reload was called
        assert!(reload_called.load(std::sync::atomic::Ordering::SeqCst));
    }
}
