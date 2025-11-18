// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! systemd integration for socket activation and service notifications
//!
//! This module provides integration with systemd for socket activation and
//! service status notifications. It allows dnsmasq to be started on-demand
//! by systemd and to report its status during startup and runtime.
//!
//! # Socket Activation
//!
//! systemd can pre-create and bind sockets before starting dnsmasq, passing
//! them as file descriptors. This module retrieves these file descriptors
//! using the systemd socket activation protocol.
//!
//! # Service Notifications
//!
//! The module implements sd_notify() to send status updates to systemd:
//! - READY=1: Service has completed initialization
//! - STOPPING=1: Service is shutting down
//! - RELOADING=1: Service is reloading configuration
//! - STATUS=...: Human-readable status text
//!
//! # Example
//!
//! ```no_run
//! use dnsmasq::platform::systemd::{sd_listen_fds, sd_notify};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Get pre-activated sockets from systemd
//! let fds = sd_listen_fds(true)?;
//! println!("Received {} file descriptors from systemd", fds.len());
//!
//! // Notify systemd that we're ready
//! sd_notify(false, "READY=1")?;
//!
//! // Report status
//! sd_notify(false, "STATUS=Processing DNS queries")?;
//! # Ok(())
//! # }
//! ```

use crate::error::{DnsmasqError, PlatformError, Result};
use std::env;
use std::os::unix::io::RawFd;

/// SD_LISTEN_FDS_START is the first file descriptor number that systemd passes
/// File descriptors are numbered starting from 3 (after stdin=0, stdout=1, stderr=2)
const SD_LISTEN_FDS_START: RawFd = 3;

/// Retrieve file descriptors passed by systemd for socket activation
///
/// This function implements the systemd socket activation protocol. When systemd
/// starts a service with socket activation, it passes pre-created and bound sockets
/// as file descriptors starting from SD_LISTEN_FDS_START (fd 3).
///
/// # Arguments
///
/// * `unset_environment` - If true, unset the LISTEN_FDS and LISTEN_PID environment
///   variables after reading them. This prevents child processes from inheriting
///   these variables and mistakenly believing they have activated sockets.
///
/// # Returns
///
/// A vector of raw file descriptors passed by systemd. The vector is empty if:
/// - The service was not started by systemd with socket activation
/// - The LISTEN_PID doesn't match our process ID
/// - The LISTEN_FDS environment variable is not set or invalid
///
/// # Errors
///
/// Returns `PlatformError` if:
/// - The LISTEN_FDS environment variable contains invalid data
/// - The LISTEN_PID environment variable contains invalid data
///
/// # Example
///
/// ```no_run
/// use dnsmasq::platform::systemd::sd_listen_fds;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let fds = sd_listen_fds(true)?;
/// for (i, fd) in fds.iter().enumerate() {
///     println!("Socket {}: fd {}", i, fd);
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Protocol Details
///
/// The systemd socket activation protocol uses environment variables:
/// - `LISTEN_PID`: Process ID that should receive the file descriptors
/// - `LISTEN_FDS`: Number of file descriptors being passed
/// - `LISTEN_FDNAMES`: Optional semicolon-separated names for the sockets
///
/// File descriptors are passed starting at SD_LISTEN_FDS_START (3) and continuing
/// for LISTEN_FDS count. Example: if LISTEN_FDS=2, the fds are 3 and 4.
pub fn sd_listen_fds(unset_environment: bool) -> Result<Vec<RawFd>> {
    // Check if we were started by systemd by looking for LISTEN_PID
    let listen_pid = match env::var("LISTEN_PID") {
        Ok(pid_str) => pid_str
            .parse::<u32>()
            .map_err(|e| PlatformError::SystemdProtocol(format!("Invalid LISTEN_PID: {}", e)))?,
        Err(_) => {
            // Not started by systemd with socket activation
            return Ok(Vec::new());
        }
    };

    // Verify that LISTEN_PID matches our process ID
    let our_pid = std::process::id();
    if listen_pid != our_pid {
        // File descriptors are intended for a different process
        return Ok(Vec::new());
    }

    // Get the number of file descriptors passed
    let listen_fds = match env::var("LISTEN_FDS") {
        Ok(fds_str) => fds_str
            .parse::<u32>()
            .map_err(|e| PlatformError::SystemdProtocol(format!("Invalid LISTEN_FDS: {}", e)))?,
        Err(_) => {
            // LISTEN_PID was set but LISTEN_FDS wasn't - this is an error
            return Err(DnsmasqError::Platform(PlatformError::SystemdProtocol(
                "LISTEN_PID set but LISTEN_FDS not set".to_string(),
            )));
        }
    };

    // Unset environment variables if requested to prevent inheritance by children
    if unset_environment {
        env::remove_var("LISTEN_PID");
        env::remove_var("LISTEN_FDS");
        env::remove_var("LISTEN_FDNAMES");
    }

    // Build vector of file descriptors
    let fds: Vec<RawFd> = (0..listen_fds).map(|i| SD_LISTEN_FDS_START + i as RawFd).collect();

    Ok(fds)
}

/// Send a notification message to systemd
///
/// This function implements the sd_notify() protocol for sending service status
/// updates to systemd. The notification is sent via a UNIX domain socket whose
/// path is specified in the NOTIFY_SOCKET environment variable.
///
/// # Arguments
///
/// * `unset_environment` - If true, unset the NOTIFY_SOCKET environment variable
///   after sending the notification. This prevents child processes from sending
///   notifications and confusing systemd about the service state.
///
/// * `state` - The notification message to send. Common values:
///   - `"READY=1"`: Service startup is finished
///   - `"STOPPING=1"`: Service is stopping
///   - `"RELOADING=1"`: Service is reloading configuration
///   - `"STATUS=<text>"`: Human-readable status text
///   - `"ERRNO=<number>"`: Error number if service failed
///   - `"WATCHDOG=1"`: Watchdog keepalive ping
///
/// # Returns
///
/// Returns `Ok(())` if the notification was successfully sent, or if there was
/// no NOTIFY_SOCKET (meaning we're not running under systemd with notification
/// support). Returns an error if the socket path is invalid or the send fails.
///
/// # Errors
///
/// Returns `PlatformError` if:
/// - The NOTIFY_SOCKET path is invalid
/// - The UNIX socket cannot be created
/// - The notification cannot be sent
///
/// # Example
///
/// ```no_run
/// use dnsmasq::platform::systemd::sd_notify;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Notify systemd we're ready
/// sd_notify(false, "READY=1")?;
///
/// // Update status
/// sd_notify(false, "STATUS=Serving 1000 queries/sec")?;
///
/// // Send watchdog ping
/// sd_notify(false, "WATCHDOG=1")?;
/// # Ok(())
/// # }
/// ```
///
/// # Protocol Details
///
/// The sd_notify protocol uses a UNIX domain socket (either abstract or file-based)
/// specified in the NOTIFY_SOCKET environment variable. The message is sent as
/// a datagram with the status string as the payload.
pub fn sd_notify(unset_environment: bool, state: &str) -> Result<()> {
    use std::os::unix::net::UnixDatagram;

    // Get the notification socket path from environment
    let notify_socket = match env::var("NOTIFY_SOCKET") {
        Ok(socket) => socket,
        Err(_) => {
            // Not running under systemd with notification support - this is OK
            return Ok(());
        }
    };

    // Unset environment variable if requested
    if unset_environment {
        env::remove_var("NOTIFY_SOCKET");
    }

    // Handle abstract namespace sockets (starting with @)
    let socket_path = if let Some(stripped) = notify_socket.strip_prefix('@') {
        // Abstract socket - replace @ with null byte
        format!("\0{}", stripped)
    } else {
        notify_socket
    };

    // Create a UNIX datagram socket
    let socket = UnixDatagram::unbound().map_err(|e| {
        PlatformError::SystemdNotify(format!("Failed to create UNIX datagram socket: {}", e))
    })?;

    // Send the notification message
    socket.send_to(state.as_bytes(), &socket_path).map_err(|e| {
        PlatformError::SystemdNotify(format!(
            "Failed to send notification to {}: {}",
            socket_path, e
        ))
    })?;

    Ok(())
}

/// Send status text to systemd
///
/// This is a convenience wrapper around sd_notify() for sending human-readable
/// status text. The status is displayed in systemctl status output.
///
/// # Example
///
/// ```no_run
/// use dnsmasq::platform::systemd::sd_notify_status;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// sd_notify_status("Processing 1000 DNS queries/sec")?;
/// # Ok(())
/// # }
/// ```
pub fn sd_notify_status(status: &str) -> Result<()> {
    sd_notify(false, &format!("STATUS={}", status))
}

/// Notify systemd that the service is ready
///
/// This is a convenience wrapper around sd_notify() for sending the READY=1
/// notification. This should be called once after the service has completed
/// initialization and is ready to serve requests.
///
/// # Example
///
/// ```no_run
/// use dnsmasq::platform::systemd::sd_notify_ready;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Complete initialization...
///
/// // Tell systemd we're ready
/// sd_notify_ready()?;
/// # Ok(())
/// # }
/// ```
pub fn sd_notify_ready() -> Result<()> {
    sd_notify(false, "READY=1")
}

/// Notify systemd that the service is reloading
///
/// This is a convenience wrapper around sd_notify() for sending the RELOADING=1
/// notification. This should be called when handling SIGHUP or other configuration
/// reload triggers.
///
/// # Example
///
/// ```no_run
/// use dnsmasq::platform::systemd::{sd_notify_reloading, sd_notify_ready};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// sd_notify_reloading()?;
/// // Reload configuration...
/// sd_notify_ready()?; // Signal completion
/// # Ok(())
/// # }
/// ```
pub fn sd_notify_reloading() -> Result<()> {
    sd_notify(false, "RELOADING=1")
}

/// Notify systemd that the service is stopping
///
/// This is a convenience wrapper around sd_notify() for sending the STOPPING=1
/// notification. This should be called when beginning graceful shutdown.
///
/// # Example
///
/// ```no_run
/// use dnsmasq::platform::systemd::sd_notify_stopping;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// sd_notify_stopping()?;
/// // Perform graceful shutdown...
/// # Ok(())
/// # }
/// ```
pub fn sd_notify_stopping() -> Result<()> {
    sd_notify(false, "STOPPING=1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sd_listen_fds_no_environment() {
        // When LISTEN_PID is not set, should return empty vector
        env::remove_var("LISTEN_PID");
        env::remove_var("LISTEN_FDS");

        let result = sd_listen_fds(false);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_sd_notify_no_socket() {
        // When NOTIFY_SOCKET is not set, should succeed silently
        env::remove_var("NOTIFY_SOCKET");

        let result = sd_notify(false, "READY=1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_sd_notify_convenience_functions() {
        // These should not fail when NOTIFY_SOCKET is not set
        env::remove_var("NOTIFY_SOCKET");

        assert!(sd_notify_ready().is_ok());
        assert!(sd_notify_reloading().is_ok());
        assert!(sd_notify_stopping().is_ok());
        assert!(sd_notify_status("test status").is_ok());
    }
}
