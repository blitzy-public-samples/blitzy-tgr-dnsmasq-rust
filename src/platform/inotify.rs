// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Linux inotify file monitoring
//!
//! This module provides file system monitoring using Linux inotify(7). It's used
//! to detect changes to configuration files and automatically reload them without
//! requiring manual SIGHUP signals.
//!
//! # Use Cases
//!
//! - Monitor `/etc/dnsmasq.conf` for changes
//! - Monitor `/etc/hosts` for host definition updates
//! - Monitor `/etc/dnsmasq.d/` directory for added/removed config files
//! - Monitor DHCP lease file for external modifications
//! - Monitor DNSSEC trust anchor file for updates
//!
//! # Example
//!
//! ```no_run
//! use dnsmasq::platform::inotify::{InotifyWatcher, FileEvent};
//! use tokio::sync::mpsc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let (tx, mut rx) = mpsc::channel(16);
//! let mut watcher = InotifyWatcher::new(tx)?;
//!
//! // Watch configuration file
//! watcher.watch_file("/etc/dnsmasq.conf").await?;
//!
//! // Watch hosts file
//! watcher.watch_file("/etc/hosts").await?;
//!
//! // Start monitoring
//! watcher.start().await?;
//!
//! while let Some(event) = rx.recv().await {
//!     match event {
//!         FileEvent::Modified(path) => {
//!             println!("File modified: {}", path.display());
//!             // Reload configuration
//!         }
//!         FileEvent::Deleted(path) => {
//!             println!("File deleted: {}", path.display());
//!         }
//!         FileEvent::Created(path) => {
//!             println!("File created: {}", path.display());
//!         }
//!         FileEvent::Moved(from, to) => {
//!             println!("File moved: {} -> {:?}", from.display(), to);
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Platform Support
//!
//! This module is only available on Linux. On other platforms, file monitoring
//! should use alternative mechanisms or be disabled.

use crate::error::{DnsmasqError, PlatformError, Result};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};
use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// File system events
///
/// These represent the different types of file changes we can detect.
#[derive(Debug, Clone)]
pub enum FileEvent {
    /// File was modified (written to)
    Modified(PathBuf),

    /// File was deleted
    Deleted(PathBuf),

    /// File was created
    Created(PathBuf),

    /// File was moved or renamed
    Moved(PathBuf, Option<PathBuf>),
}

/// inotify-based file watcher
///
/// This struct manages inotify watches on multiple files and directories.
/// It runs an async task that monitors the inotify file descriptor and
/// sends FileEvents when changes are detected.
pub struct InotifyWatcher {
    inotify: Inotify,
    watches: HashMap<WatchDescriptor, PathBuf>,
    event_sender: mpsc::Sender<FileEvent>,
}

impl InotifyWatcher {
    /// Create a new inotify watcher
    ///
    /// # Arguments
    ///
    /// * `event_sender` - Channel to send FileEvents to
    ///
    /// # Errors
    ///
    /// Returns an error if inotify initialization fails. This can happen if:
    /// - The kernel doesn't support inotify
    /// - The process has reached its inotify instance limit
    /// - Permission denied
    pub fn new(event_sender: mpsc::Sender<FileEvent>) -> Result<Self> {
        let inotify =
            Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).map_err(|e| {
                PlatformError::FileMonitoring(format!("Failed to initialize inotify: {}", e))
            })?;

        Ok(Self { inotify, watches: HashMap::new(), event_sender })
    }

    /// Watch a file for changes
    ///
    /// This adds an inotify watch on the specified file. We'll be notified when:
    /// - The file is modified (written to)
    /// - The file is deleted
    /// - The file is moved or renamed
    /// - The file attributes change (permissions, timestamps)
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to watch
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file doesn't exist
    /// - We don't have permission to read the file
    /// - The process has reached its inotify watch limit
    pub async fn watch_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();

        // Add inotify watch
        let flags = AddWatchFlags::IN_MODIFY
            | AddWatchFlags::IN_DELETE_SELF
            | AddWatchFlags::IN_MOVE_SELF
            | AddWatchFlags::IN_ATTRIB;

        let wd = self.inotify.add_watch(path, flags).map_err(|e| {
            PlatformError::FileMonitoring(format!(
                "Failed to add watch on {}: {}",
                path.display(),
                e
            ))
        })?;

        self.watches.insert(wd, path.to_path_buf());

        info!("Added inotify watch on {}", path.display());
        Ok(())
    }

    /// Watch a directory for changes
    ///
    /// This adds an inotify watch on a directory. We'll be notified when:
    /// - Files are created in the directory
    /// - Files are deleted from the directory
    /// - Files are modified in the directory
    /// - Files are moved into or out of the directory
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the directory to watch
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The directory doesn't exist
    /// - We don't have permission to read the directory
    /// - The process has reached its inotify watch limit
    pub async fn watch_directory<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();

        // Add inotify watch with directory-specific flags
        let flags = AddWatchFlags::IN_CREATE
            | AddWatchFlags::IN_DELETE
            | AddWatchFlags::IN_MODIFY
            | AddWatchFlags::IN_MOVED_FROM
            | AddWatchFlags::IN_MOVED_TO;

        let wd = self.inotify.add_watch(path, flags).map_err(|e| {
            PlatformError::FileMonitoring(format!(
                "Failed to add watch on directory {}: {}",
                path.display(),
                e
            ))
        })?;

        self.watches.insert(wd, path.to_path_buf());

        info!("Added inotify watch on directory {}", path.display());
        Ok(())
    }

    /// Remove a watch
    ///
    /// This removes an inotify watch that was previously added. This should be
    /// called when you no longer need to monitor a file or directory.
    ///
    /// # Arguments
    ///
    /// * `path` - Path that was being watched
    pub async fn remove_watch<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();

        // Find the watch descriptor for this path
        let wd = self.watches.iter().find(|(_, p)| p.as_path() == path).map(|(wd, _)| *wd);

        if let Some(wd) = wd {
            self.inotify.rm_watch(wd).map_err(|e| {
                PlatformError::FileMonitoring(format!(
                    "Failed to remove watch on {}: {}",
                    path.display(),
                    e
                ))
            })?;

            self.watches.remove(&wd);
            info!("Removed inotify watch on {}", path.display());
        }

        Ok(())
    }

    /// Start the inotify monitoring loop
    ///
    /// This spawns an async task that continuously monitors the inotify file
    /// descriptor and sends FileEvents when changes are detected. The task
    /// runs until an error occurs or the event channel is closed.
    pub async fn start(self) -> Result<()> {
        tokio::spawn(async move {
            if let Err(e) = self.monitor_loop().await {
                error!("Inotify monitoring loop failed: {}", e);
            }
        });

        Ok(())
    }

    /// Main monitoring loop
    ///
    /// This function continuously reads events from the inotify file descriptor
    /// and converts them to FileEvents. It uses tokio's async I/O to avoid
    /// blocking the runtime.
    async fn monitor_loop(self) -> Result<()> {
        use tokio::io::unix::AsyncFd;

        // Convert to async-capable fd
        let async_fd = AsyncFd::new(self.inotify.as_fd().as_raw_fd()).map_err(|e| {
            DnsmasqError::Platform(PlatformError::FileMonitoring(format!(
                "Failed to create async fd: {}",
                e
            )))
        })?;

        loop {
            // Wait for the fd to be readable
            let mut guard = async_fd.readable().await.map_err(|e| {
                DnsmasqError::Platform(PlatformError::FileMonitoring(format!(
                    "Failed to wait for readable: {}",
                    e
                )))
            })?;

            // Try to read events
            match guard.try_io(|_| {
                self.inotify.read_events().map_err(|e| std::io::Error::from_raw_os_error(e as i32))
            }) {
                Ok(Ok(events)) => {
                    // Process each event
                    for event in events {
                        if let Err(e) = self.handle_event(event).await {
                            warn!("Failed to handle inotify event: {}", e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Failed to read inotify events: {}", e);
                    return Err(DnsmasqError::Platform(PlatformError::FileMonitoring(format!(
                        "Failed to read events: {}",
                        e
                    ))));
                }
                Err(_would_block) => {
                    // Try again
                    continue;
                }
            }
        }
    }

    /// Handle a single inotify event
    ///
    /// This converts a raw inotify event into a FileEvent and sends it to
    /// the event channel.
    async fn handle_event(&self, event: nix::sys::inotify::InotifyEvent) -> Result<()> {
        // Look up the path for this watch descriptor
        let base_path = match self.watches.get(&event.wd) {
            Some(path) => path.clone(),
            None => {
                debug!("Received event for unknown watch descriptor");
                return Ok(());
            }
        };

        // Construct full path (for directory watches, append filename)
        let full_path = if let Some(name) = event.name {
            base_path.join(name.to_string_lossy().as_ref())
        } else {
            base_path
        };

        // Convert mask to FileEvent
        let file_event = if event.mask.contains(AddWatchFlags::IN_MODIFY)
            || event.mask.contains(AddWatchFlags::IN_ATTRIB)
        {
            FileEvent::Modified(full_path)
        } else if event.mask.contains(AddWatchFlags::IN_DELETE_SELF)
            || event.mask.contains(AddWatchFlags::IN_DELETE)
        {
            FileEvent::Deleted(full_path)
        } else if event.mask.contains(AddWatchFlags::IN_CREATE) {
            FileEvent::Created(full_path)
        } else if event.mask.contains(AddWatchFlags::IN_MOVE_SELF)
            || event.mask.contains(AddWatchFlags::IN_MOVED_FROM)
            || event.mask.contains(AddWatchFlags::IN_MOVED_TO)
        {
            FileEvent::Moved(full_path, None)
        } else {
            // Unknown event type
            return Ok(());
        };

        // Send the event
        if let Err(e) = self.event_sender.send(file_event).await {
            warn!("Failed to send file event: {}", e);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_inotify_watcher_creation() {
        let (tx, _rx) = mpsc::channel(16);
        let result = InotifyWatcher::new(tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_file_event_debug() {
        let event = FileEvent::Modified(PathBuf::from("/etc/dnsmasq.conf"));
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("Modified"));
        assert!(debug_str.contains("dnsmasq.conf"));
    }
}
