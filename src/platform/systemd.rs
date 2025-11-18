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
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::net::{TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info};

/// SD_LISTEN_FDS_START is the first file descriptor number that systemd passes
/// File descriptors are numbered starting from 3 (after stdin=0, stdout=1, stderr=2)
const SD_LISTEN_FDS_START: RawFd = 3;

/// Type of systemd socket for type validation
///
/// This enum represents the different types of sockets that can be passed
/// through systemd socket activation. Used by validation functions to ensure
/// the socket type matches expectations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdSocket {
    /// TCP stream socket (SOCK_STREAM + AF_INET or AF_INET6)
    Tcp,
    /// UDP datagram socket (SOCK_DGRAM + AF_INET or AF_INET6)
    Udp,
}

/// Watchdog state information from systemd
///
/// Contains the watchdog configuration parsed from systemd environment variables.
/// The watchdog mechanism allows systemd to monitor service health and restart
/// it if watchdog pings are not received within the configured interval.
#[derive(Debug, Clone)]
pub struct WatchdogState {
    /// Whether watchdog is enabled for this service
    pub enabled: bool,
    /// Watchdog interval in microseconds (from WATCHDOG_USEC)
    pub interval_usec: u64,
    /// Process ID that watchdog applies to (from WATCHDOG_PID)
    pub pid: u32,
}

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
            .map_err(|e| {
                error!("Invalid LISTEN_PID environment variable: {}", e);
                PlatformError::SystemdProtocol(format!("Invalid LISTEN_PID: {}", e))
            })?,
        Err(_) => {
            // Not started by systemd with socket activation
            debug!("LISTEN_PID not set - not started with systemd socket activation");
            return Ok(Vec::new());
        }
    };

    // Verify that LISTEN_PID matches our process ID
    let our_pid = std::process::id();
    if listen_pid != our_pid {
        // File descriptors are intended for a different process
        debug!(
            "LISTEN_PID ({}) does not match our PID ({}) - ignoring file descriptors",
            listen_pid, our_pid
        );
        return Ok(Vec::new());
    }

    // Get the number of file descriptors passed
    let listen_fds = match env::var("LISTEN_FDS") {
        Ok(fds_str) => fds_str
            .parse::<u32>()
            .map_err(|e| {
                error!("Invalid LISTEN_FDS environment variable: {}", e);
                PlatformError::SystemdProtocol(format!("Invalid LISTEN_FDS: {}", e))
            })?,
        Err(_) => {
            // LISTEN_PID was set but LISTEN_FDS wasn't - this is an error
            error!("LISTEN_PID set but LISTEN_FDS not set");
            return Err(DnsmasqError::Platform(PlatformError::SystemdProtocol(
                "LISTEN_PID set but LISTEN_FDS not set".to_string(),
            )));
        }
    };

    info!(
        "Received {} file descriptors from systemd (FDs {}-{})",
        listen_fds,
        SD_LISTEN_FDS_START,
        SD_LISTEN_FDS_START + listen_fds as RawFd - 1
    );

    // Unset environment variables if requested to prevent inheritance by children
    if unset_environment {
        debug!("Unsetting systemd socket activation environment variables");
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
    // Get the notification socket path from environment
    let notify_socket = match env::var("NOTIFY_SOCKET") {
        Ok(socket) => socket,
        Err(_) => {
            // Not running under systemd with notification support - this is OK
            debug!("NOTIFY_SOCKET not set - not running under systemd with notification support");
            return Ok(());
        }
    };

    debug!("Sending systemd notification: {}", state);

    // Unset environment variable if requested
    if unset_environment {
        debug!("Unsetting NOTIFY_SOCKET environment variable");
        env::remove_var("NOTIFY_SOCKET");
    }

    // Handle abstract namespace sockets (starting with @)
    let socket_path = if let Some(stripped) = notify_socket.strip_prefix('@') {
        // Abstract socket - replace @ with null byte
        format!("\0{}", stripped)
    } else {
        notify_socket.clone()
    };

    // Create a UNIX datagram socket
    let socket = UnixDatagram::unbound().map_err(|e| {
        error!("Failed to create UNIX datagram socket for systemd notification: {}", e);
        PlatformError::SystemdNotify(format!("Failed to create UNIX datagram socket: {}", e))
    })?;

    // Send the notification message
    socket.send_to(state.as_bytes(), &socket_path).map_err(|e| {
        error!(
            "Failed to send systemd notification to {}: {}",
            notify_socket, e
        );
        PlatformError::SystemdNotify(format!(
            "Failed to send notification to {}: {}",
            socket_path, e
        ))
    })?;

    info!("Systemd notification sent: {}", state);
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

/// Check if a file descriptor is a socket of the specified type
///
/// This function validates that a given file descriptor is actually a socket
/// and optionally checks its type (TCP or UDP) and address family.
///
/// # Arguments
///
/// * `fd` - The raw file descriptor to check
/// * `socket_type` - Optional socket type to validate (TCP or UDP)
///
/// # Returns
///
/// Returns `Ok(true)` if the file descriptor is a valid socket matching the
/// specified type, `Ok(false)` if it's not a match, or an error if validation fails.
///
/// # Errors
///
/// Returns `PlatformError` if:
/// - The file descriptor is invalid
/// - Socket options cannot be queried
///
/// # Example
///
/// ```no_run
/// use dnsmasq::platform::systemd::{sd_listen_fds, sd_is_socket, SystemdSocket};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let fds = sd_listen_fds(true)?;
/// for fd in fds {
///     if sd_is_socket(fd, Some(SystemdSocket::Udp))? {
///         println!("FD {} is a UDP socket", fd);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn sd_is_socket(fd: RawFd, socket_type: Option<SystemdSocket>) -> Result<bool> {
    use nix::sys::socket::{getsockname, getsockopt, sockopt, AddressFamily, SockaddrLike, SockaddrStorage, SockType};
    use nix::sys::stat::{fstat, SFlag};
    use std::os::unix::io::BorrowedFd;

    // First check if the FD is a socket using fstat
    let stat = fstat(fd).map_err(|e| {
        error!("Failed to fstat fd {}: {}", fd, e);
        PlatformError::SystemdProtocol(format!("Failed to fstat fd {}: {}", fd, e))
    })?;

    // Check if it's a socket using S_IFSOCK
    if !SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFSOCK) {
        debug!("FD {} is not a socket", fd);
        return Ok(false);
    }

    // If no specific type requested, just confirm it's a socket
    let Some(expected_type) = socket_type else {
        debug!("FD {} is a socket (type not validated)", fd);
        return Ok(true);
    };

    // Get the socket type
    // SAFETY: We assume the file descriptor is valid as it was passed by systemd
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let sock_type = getsockopt(&borrowed_fd, sockopt::SockType).map_err(|e| {
        error!("Failed to get socket type for fd {}: {}", fd, e);
        PlatformError::SystemdProtocol(format!("Failed to get socket type for fd {}: {}", fd, e))
    })?;

    // Get the address family by querying the socket address
    let addr: SockaddrStorage = getsockname(fd).map_err(|e| {
        error!("Failed to get socket address for fd {}: {}", fd, e);
        PlatformError::SystemdProtocol(format!("Failed to get socket address for fd {}: {}", fd, e))
    })?;
    
    let domain = addr.family().ok_or_else(|| {
        error!("Failed to get address family for fd {}", fd);
        PlatformError::SystemdProtocol(format!("Failed to get address family for fd {}", fd))
    })?;

    // Check if the address family is IPv4 or IPv6
    let is_inet = matches!(domain, AddressFamily::Inet | AddressFamily::Inet6);
    if !is_inet {
        debug!("FD {} is not an Internet socket (domain: {:?})", fd, domain);
        return Ok(false);
    }

    // Validate socket type matches expectation
    let matches = match expected_type {
        SystemdSocket::Tcp => sock_type == SockType::Stream,
        SystemdSocket::Udp => sock_type == SockType::Datagram,
    };

    if matches {
        debug!(
            "FD {} is a valid {:?} socket (domain: {:?})",
            fd, expected_type, domain
        );
    } else {
        debug!(
            "FD {} socket type mismatch: expected {:?}, got {:?}",
            fd, expected_type, sock_type
        );
    }

    Ok(matches)
}

/// Check if a file descriptor is an Internet socket (IPv4 or IPv6)
///
/// This function validates that a given file descriptor is a TCP or UDP socket
/// with an IPv4 or IPv6 address family. This is a convenience wrapper around
/// `sd_is_socket()` that automatically checks for Internet socket types.
///
/// # Arguments
///
/// * `fd` - The raw file descriptor to check
/// * `socket_type` - The expected socket type (TCP or UDP)
///
/// # Returns
///
/// Returns `Ok(true)` if the file descriptor is an Internet socket of the
/// specified type, `Ok(false)` otherwise.
///
/// # Errors
///
/// Returns `PlatformError` if socket validation fails.
///
/// # Example
///
/// ```no_run
/// use dnsmasq::platform::systemd::{sd_listen_fds, sd_is_socket_inet, SystemdSocket};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let fds = sd_listen_fds(true)?;
/// for fd in fds {
///     if sd_is_socket_inet(fd, SystemdSocket::Tcp)? {
///         println!("FD {} is a TCP Internet socket", fd);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn sd_is_socket_inet(fd: RawFd, socket_type: SystemdSocket) -> Result<bool> {
    // sd_is_socket already validates it's an inet socket
    sd_is_socket(fd, Some(socket_type))
}

/// Check if systemd watchdog is enabled and get its configuration
///
/// This function checks if the systemd watchdog mechanism is enabled for this
/// service by reading the WATCHDOG_USEC and WATCHDOG_PID environment variables.
/// The watchdog requires periodic notifications via `sd_notify(false, "WATCHDOG=1")`
/// to prevent the service from being restarted by systemd.
///
/// # Returns
///
/// Returns a `WatchdogState` with:
/// - `enabled = true` if watchdog is configured for this process
/// - `enabled = false` if watchdog is not configured
/// - `interval_usec` - the watchdog interval in microseconds
/// - `pid` - the process ID that watchdog applies to
///
/// # Errors
///
/// Returns `PlatformError` if:
/// - WATCHDOG_USEC is set but invalid
/// - WATCHDOG_PID is set but invalid
///
/// # Example
///
/// ```no_run
/// use dnsmasq::platform::systemd::{sd_watchdog_enabled, sd_notify};
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let watchdog = sd_watchdog_enabled()?;
/// if watchdog.enabled {
///     println!("Watchdog enabled with {}µs interval", watchdog.interval_usec);
///     
///     // Send watchdog pings at half the interval
///     let interval = Duration::from_micros(watchdog.interval_usec / 2);
///     loop {
///         tokio::time::sleep(interval).await;
///         sd_notify(false, "WATCHDOG=1")?;
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn sd_watchdog_enabled() -> Result<WatchdogState> {
    // Check for WATCHDOG_USEC environment variable
    let watchdog_usec = match env::var("WATCHDOG_USEC") {
        Ok(usec_str) => usec_str.parse::<u64>().map_err(|e| {
            error!("Invalid WATCHDOG_USEC environment variable: {}", e);
            PlatformError::SystemdProtocol(format!("Invalid WATCHDOG_USEC: {}", e))
        })?,
        Err(_) => {
            // Watchdog not configured
            debug!("WATCHDOG_USEC not set - watchdog not enabled");
            return Ok(WatchdogState {
                enabled: false,
                interval_usec: 0,
                pid: 0,
            });
        }
    };

    // Check for WATCHDOG_PID - if set, verify it matches our PID
    let watchdog_pid = match env::var("WATCHDOG_PID") {
        Ok(pid_str) => {
            let pid = pid_str.parse::<u32>().map_err(|e| {
                error!("Invalid WATCHDOG_PID environment variable: {}", e);
                PlatformError::SystemdProtocol(format!("Invalid WATCHDOG_PID: {}", e))
            })?;

            // If WATCHDOG_PID is set, verify it matches our process ID
            let our_pid = std::process::id();
            if pid != our_pid {
                debug!(
                    "WATCHDOG_PID ({}) does not match our PID ({}) - watchdog not for us",
                    pid, our_pid
                );
                return Ok(WatchdogState {
                    enabled: false,
                    interval_usec: 0,
                    pid: our_pid,
                });
            }
            pid
        }
        Err(_) => {
            // WATCHDOG_PID not set - assume watchdog applies to us
            std::process::id()
        }
    };

    info!(
        "Systemd watchdog enabled: interval={}µs, pid={}",
        watchdog_usec, watchdog_pid
    );

    Ok(WatchdogState {
        enabled: true,
        interval_usec: watchdog_usec,
        pid: watchdog_pid,
    })
}

/// Convert a raw file descriptor to a tokio TcpListener
///
/// This function takes a raw file descriptor from systemd socket activation
/// and converts it to a tokio TcpListener for use in async code.
///
/// # Safety
///
/// This function uses `FromRawFd` which is unsafe. The caller must ensure:
/// - The file descriptor is valid and open
/// - The file descriptor is actually a TCP listening socket
/// - The file descriptor is not used elsewhere after this call
///
/// # Arguments
///
/// * `fd` - The raw file descriptor from systemd
///
/// # Returns
///
/// A tokio TcpListener or an error if conversion fails.
///
/// # Errors
///
/// Returns `PlatformError` if the file descriptor cannot be converted.
///
/// # Example
///
/// ```no_run
/// use dnsmasq::platform::systemd::{sd_listen_fds, sd_is_socket_inet, SystemdSocket, fd_to_tcp_listener};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let fds = sd_listen_fds(true)?;
/// for fd in fds {
///     if sd_is_socket_inet(fd, SystemdSocket::Tcp)? {
///         let listener = fd_to_tcp_listener(fd).await?;
///         // Use the listener...
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub async fn fd_to_tcp_listener(fd: RawFd) -> Result<TcpListener> {
    // SAFETY: We trust that systemd has given us a valid TCP listener FD
    // The caller should have validated this with sd_is_socket_inet()
    let std_listener = unsafe { StdTcpListener::from_raw_fd(fd) };
    
    // Set non-blocking mode for tokio
    std_listener.set_nonblocking(true).map_err(|e| {
        error!("Failed to set non-blocking mode on TCP listener: {}", e);
        PlatformError::SystemdError {
            operation: "set_nonblocking".to_string(),
            reason: e.to_string(),
        }
    })?;

    // Convert to tokio TcpListener
    TcpListener::from_std(std_listener).map_err(|e| {
        error!("Failed to convert std TcpListener to tokio: {}", e);
        DnsmasqError::Platform(PlatformError::SystemdError {
            operation: "from_std".to_string(),
            reason: e.to_string(),
        })
    })
}

/// Convert a raw file descriptor to a tokio UdpSocket
///
/// This function takes a raw file descriptor from systemd socket activation
/// and converts it to a tokio UdpSocket for use in async code.
///
/// # Safety
///
/// This function uses `FromRawFd` which is unsafe. The caller must ensure:
/// - The file descriptor is valid and open
/// - The file descriptor is actually a UDP socket
/// - The file descriptor is not used elsewhere after this call
///
/// # Arguments
///
/// * `fd` - The raw file descriptor from systemd
///
/// # Returns
///
/// A tokio UdpSocket or an error if conversion fails.
///
/// # Errors
///
/// Returns `PlatformError` if the file descriptor cannot be converted.
///
/// # Example
///
/// ```no_run
/// use dnsmasq::platform::systemd::{sd_listen_fds, sd_is_socket_inet, SystemdSocket, fd_to_udp_socket};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let fds = sd_listen_fds(true)?;
/// for fd in fds {
///     if sd_is_socket_inet(fd, SystemdSocket::Udp)? {
///         let socket = fd_to_udp_socket(fd).await?;
///         // Use the socket...
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub async fn fd_to_udp_socket(fd: RawFd) -> Result<UdpSocket> {
    // SAFETY: We trust that systemd has given us a valid UDP socket FD
    // The caller should have validated this with sd_is_socket_inet()
    let std_socket = unsafe { StdUdpSocket::from_raw_fd(fd) };
    
    // Set non-blocking mode for tokio
    std_socket.set_nonblocking(true).map_err(|e| {
        error!("Failed to set non-blocking mode on UDP socket: {}", e);
        PlatformError::SystemdError {
            operation: "set_nonblocking".to_string(),
            reason: e.to_string(),
        }
    })?;

    // Convert to tokio UdpSocket
    UdpSocket::from_std(std_socket).map_err(|e| {
        error!("Failed to convert std UdpSocket to tokio: {}", e);
        DnsmasqError::Platform(PlatformError::SystemdError {
            operation: "from_std".to_string(),
            reason: e.to_string(),
        })
    })
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
