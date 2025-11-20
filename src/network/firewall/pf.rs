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

//! BSD Packet Filter (PF) table integration for dynamic domain-based firewall rules.
//!
//! This module implements BSD-specific firewall integration by interfacing with the Packet Filter
//! (PF) system available on FreeBSD, OpenBSD, and NetBSD. It enables dnsmasq to automatically
//! populate PF tables with resolved IP addresses, allowing firewall rules to adapt dynamically
//! based on DNS resolution results.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      DNS Resolution Flow                        │
//! └─────────────────────────────────────────────────────────────────┘
//!                                 │
//!                                 ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │              Match domain against ipset patterns                │
//! │                  (from dnsmasq.conf)                            │
//! └─────────────────────────────────────────────────────────────────┘
//!                                 │
//!                                 ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   PfBackend::add_to_set()                       │
//! │                                                                 │
//! │  1. Open /dev/pf device (OwnedFd with RAII)                    │
//! │  2. Ensure table exists (DIOCRADDTABLES ioctl)                 │
//! │  3. Add IP address (DIOCRADDADDRS ioctl)                       │
//! └─────────────────────────────────────────────────────────────────┘
//!                                 │
//!                                 ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    PF Kernel Tables                             │
//! │                                                                 │
//! │  table <blocked_domains> persist                                │
//! │  block drop quick from any to <blocked_domains>                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # PF Table Operations
//!
//! ## Table Creation
//!
//! Tables are created automatically with the `PFR_TFLAG_PERSIST` flag, ensuring they survive
//! even if no rules currently reference them. This prevents table loss during ruleset reloads:
//!
//! ```c
//! // C equivalent
//! struct pfr_table table;
//! bzero(&table, sizeof(table));
//! table.pfrt_flags = PFR_TFLAG_PERSIST;
//! strlcpy(table.pfrt_name, "blocked_domains", sizeof(table.pfrt_name));
//! ioctl(dev, DIOCRADDTABLES, &io);
//! ```
//!
//! ```rust,ignore
//! // Rust implementation
//! let mut table = pfr_table::default();
//! table.pfrt_flags = PFR_TFLAG_PERSIST;
//! table.pfrt_name[..name.len()].copy_from_slice(name.as_bytes());
//! ```
//!
//! ## Address Addition
//!
//! IP addresses are added using the `DIOCRADDADDRS` ioctl with proper address family handling:
//!
//! - **IPv4**: `pfra_af = AF_INET`, `pfra_net = 0x20` (/32 prefix)
//! - **IPv6**: `pfra_af = AF_INET6`, `pfra_net = 0x80` (/128 prefix)
//!
//! # Configuration Integration
//!
//! BSD systems reuse the `--ipset` directive for PF table configuration:
//!
//! ```bash
//! # dnsmasq.conf
//! ipset=/doubleclick.net/blocked_ads
//! ipset=/facebook.com/social_media
//! ```
//!
//! Corresponding PF configuration in `/etc/pf.conf`:
//!
//! ```pf
//! # Create persistent tables
//! table <blocked_ads> persist
//! table <social_media> persist
//!
//! # Apply firewall rules
//! block drop quick from any to <blocked_ads>
//! pass out quick to <social_media> keep state queue social_queue
//! ```
//!
//! # Memory Safety Transformation
//!
//! The C implementation (src/tables.c) used manual memory management and pointer arithmetic:
//!
//! ```c
//! // C implementation: Manual buffer initialization
//! static int dev = -1;  // Global file descriptor
//! struct pfr_addr addr;
//! bzero(&addr, sizeof(addr));
//! addr.pfra_af = AF_INET;
//! memcpy(&(addr.pfra_ip4addr), ipaddr, sizeof(struct in_addr));
//! ```
//!
//! The Rust implementation provides memory safety through:
//!
//! ```rust,ignore
//! // Rust implementation: Automatic resource management
//! struct PfBackend {
//!     pf_fd: Arc<Mutex<Option<OwnedFd>>>,  // RAII file descriptor
//! }
//!
//! let mut addr = pfr_addr::default();  // Zero-initialized by Default trait
//! addr.pfra_af = libc::AF_INET as u8;
//! match ip {
//!     IpAddr::V4(ipv4) => {
//!         addr.pfra_u.pfra_ip4addr = unsafe { std::mem::transmute(ipv4.octets()) };
//!     }
//! }
//! ```
//!
//! Key safety improvements:
//! - `OwnedFd` automatically closes /dev/pf on Drop
//! - No manual bzero/memset - Default trait ensures zero-initialization
//! - Type-safe IpAddr enum prevents address family mismatches
//! - Bounds-checked array access for table names
//!
//! # Error Handling
//!
//! All operations return `Result<(), FirewallError>` with specific error variants:
//!
//! - [`FirewallError::DeviceNotFound`]: /dev/pf unavailable (PF not loaded)
//! - [`FirewallError::TableCreateFailed`]: DIOCRADDTABLES ioctl failed
//! - [`FirewallError::AddressFailed`]: DIOCRADDADDRS/DIOCRDELADDRS failed
//! - [`FirewallError::ProtocolError`]: General ioctl system call error
//!
//! # Async Operations
//!
//! BSD ioctl operations are inherently synchronous and may block. To prevent event loop stalls,
//! all ioctl calls are wrapped in `tokio::task::spawn_blocking`:
//!
//! ```rust,ignore
//! pub async fn add_to_set(&self, domain: &str, ip: IpAddr, set_name: &str) -> Result<()> {
//!     let set_name = set_name.to_string();
//!     let ip_copy = ip;
//!     
//!     tokio::task::spawn_blocking(move || {
//!         // Synchronous ioctl operations on blocking thread pool
//!         let fd = self.get_fd()?;
//!         self.ensure_table_exists_sync(fd, &set_name)?;
//!         self.add_address_sync(fd, &set_name, ip_copy)?;
//!         Ok(())
//!     }).await.unwrap()
//! }
//! ```
//!
//! # Use Cases
//!
//! ## Content Filtering
//!
//! Block advertising and tracking domains:
//!
//! ```bash
//! # dnsmasq.conf
//! ipset=/ads.example.com/blocked_ads
//! ipset=/tracker.example.com/blocked_ads
//!
//! # pf.conf
//! table <blocked_ads> persist
//! block drop quick from any to <blocked_ads>
//! ```
//!
//! ## Policy-Based Routing
//!
//! Route specific domains through alternative gateway:
//!
//! ```bash
//! # Route VPN domains through tun0
//! ipset=/vpn-provider.com/vpn_ips
//!
//! # pf.conf
//! table <vpn_ips> persist
//! pass out route-to (tun0 10.8.0.1) from any to <vpn_ips>
//! ```
//!
//! ## Parental Controls
//!
//! Block access to adult content domains:
//!
//! ```bash
//! ipset=/adult-site.com/parental_filter
//!
//! # pf.conf
//! table <parental_filter> persist
//! block drop log quick from $child_devices to <parental_filter>
//! ```
//!
//! # Platform Support
//!
//! This module is conditionally compiled only on BSD platforms:
//!
//! ```rust,ignore
//! #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
//! pub mod pf;
//! ```
//!
//! Supported platforms:
//! - FreeBSD 10.0+ (pfSense, OPNsense, FreeNAS/TrueNAS)
//! - OpenBSD 5.0+ (reference PF implementation)
//! - NetBSD 6.0+
//!
//! # References
//!
//! - OpenBSD PF User's Guide: <https://www.openbsd.org/faq/pf/>
//! - pf.conf(5): PF configuration file syntax
//! - pfctl(8): PF control utility
//! - ioctl(2): Device control system calls
//! - Original C implementation: src/tables.c

use async_trait::async_trait;
use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use tokio::task;
use tracing::{debug, error, info, instrument, warn};

use crate::network::firewall::{FirewallBackend, FirewallError, Result};
use crate::types::IpAddr;

/// Path to the BSD Packet Filter device file.
///
/// This character device provides the ioctl interface to the PF kernel subsystem.
/// Typically owned by root:wheel with mode 0600.
const PF_DEVICE_PATH: &str = "/dev/pf";

/// Maximum length for PF table names (from BSD sys/net/pfvar.h).
///
/// Table names exceeding this length are truncated or rejected with ENAMETOOLONG.
/// Standard BSD PF implementation defines PF_TABLE_NAME_SIZE as 32 bytes.
const PF_TABLE_NAME_SIZE: usize = 32;

/// PF table flag: Make table persistent across ruleset reloads.
///
/// From BSD pfvar.h: `#define PFR_TFLAG_PERSIST 0x00000001`
///
/// Tables with this flag survive even when no rules reference them, preventing
/// data loss during `pfctl -f /etc/pf.conf` reloads.
const PFR_TFLAG_PERSIST: u32 = 0x00000001;

/// ioctl request code for adding PF tables (from BSD sys/net/pfvar.h).
///
/// C definition: `#define DIOCRADDTABLES _IOWR('D', 65, struct pfioc_table)`
///
/// This is platform-specific and varies slightly between BSD variants. On most systems:
/// - FreeBSD: 0xc4504441
/// - OpenBSD: 0xc4504441  
/// - NetBSD: Similar but verify with `#include <net/pfvar.h>`
#[cfg(target_os = "freebsd")]
const DIOCRADDTABLES: libc::c_ulong = 0xc4504441;

#[cfg(target_os = "openbsd")]
const DIOCRADDTABLES: libc::c_ulong = 0xc4504441;

#[cfg(target_os = "netbsd")]
const DIOCRADDTABLES: libc::c_ulong = 0xc4504441;

// Dummy value for non-BSD platforms to allow compilation (will never be used at runtime)
#[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
const DIOCRADDTABLES: libc::c_ulong = 0xc4504441;

/// ioctl request code for adding addresses to PF tables.
///
/// C definition: `#define DIOCRADDADDRS _IOWR('D', 67, struct pfioc_table)`
#[cfg(target_os = "freebsd")]
const DIOCRADDADDRS: libc::c_ulong = 0xc4504443;

#[cfg(target_os = "openbsd")]
const DIOCRADDADDRS: libc::c_ulong = 0xc4504443;

#[cfg(target_os = "netbsd")]
const DIOCRADDADDRS: libc::c_ulong = 0xc4504443;

// Dummy value for non-BSD platforms to allow compilation (will never be used at runtime)
#[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
const DIOCRADDADDRS: libc::c_ulong = 0xc4504443;

/// ioctl request code for deleting addresses from PF tables.
///
/// C definition: `#define DIOCRDELADDRS _IOWR('D', 68, struct pfioc_table)`
#[cfg(target_os = "freebsd")]
const DIOCRDELADDRS: libc::c_ulong = 0xc4504444;

#[cfg(target_os = "openbsd")]
const DIOCRDELADDRS: libc::c_ulong = 0xc4504444;

#[cfg(target_os = "netbsd")]
const DIOCRDELADDRS: libc::c_ulong = 0xc4504444;

// Dummy value for non-BSD platforms to allow compilation (will never be used at runtime)
#[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
const DIOCRDELADDRS: libc::c_ulong = 0xc4504444;

/// PF table descriptor structure (from BSD sys/net/pfvar.h).
///
/// C definition:
/// ```c
/// struct pfr_table {
///     char pfrt_anchor[MAXPATHLEN];
///     char pfrt_name[PF_TABLE_NAME_SIZE];
///     u_int32_t pfrt_flags;
///     u_int8_t pfrt_fback;
/// };
/// ```
///
/// This structure identifies a PF table by name and optional anchor, with flags
/// controlling table behavior (e.g., persistence).
#[repr(C)]
#[derive(Clone, Copy)]
struct pfr_table {
    /// Anchor path (empty for global tables, e.g., "myanchor/nested")
    pfrt_anchor: [u8; 1024], // MAXPATHLEN on most BSD systems

    /// Table name (e.g., "blocked_domains", max 32 chars)
    pfrt_name: [u8; PF_TABLE_NAME_SIZE],

    /// Flags: PFR_TFLAG_PERSIST, PFR_TFLAG_CONST, etc.
    pfrt_flags: u32,

    /// Feedback byte (reserved for kernel use)
    pfrt_fback: u8,
}

impl Default for pfr_table {
    /// Create zero-initialized pfr_table structure.
    ///
    /// Replaces C's `bzero(&table, sizeof(table))` with safe Rust default initialization.
    fn default() -> Self {
        pfr_table {
            pfrt_anchor: [0; 1024],
            pfrt_name: [0; PF_TABLE_NAME_SIZE],
            pfrt_flags: 0,
            pfrt_fback: 0,
        }
    }
}

/// PF address structure with union for IPv4/IPv6 addresses (from BSD sys/net/pfvar.h).
///
/// C definition:
/// ```c
/// struct pfr_addr {
///     union {
///         struct in_addr  _pfra_ip4addr;
///         struct in6_addr _pfra_ip6addr;
///     } pfra_u;
///     u_int8_t pfra_af;       /* address family: AF_INET or AF_INET6 */
///     u_int8_t pfra_net;      /* network prefix length */
///     u_int8_t pfra_not;      /* negation flag */
///     u_int8_t pfra_fback;    /* feedback byte */
/// };
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
struct pfr_addr {
    /// Union containing either IPv4 or IPv6 address
    pfra_u: pfra_union,

    /// Address family: AF_INET (2) or AF_INET6 (10/28 depending on BSD)
    pfra_af: u8,

    /// Network prefix length: 0x20 (32) for IPv4 /32, 0x80 (128) for IPv6 /128
    pfra_net: u8,

    /// Negation flag (0 = normal, 1 = negated match)
    pfra_not: u8,

    /// Feedback byte (reserved for kernel)
    pfra_fback: u8,
}

/// Union for IPv4/IPv6 address storage in pfr_addr.
///
/// C definition:
/// ```c
/// union {
///     struct in_addr  _pfra_ip4addr;
///     struct in6_addr _pfra_ip6addr;
/// };
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
union pfra_union {
    /// IPv4 address (4 bytes)
    pfra_ip4addr: libc::in_addr,

    /// IPv6 address (16 bytes)
    pfra_ip6addr: libc::in6_addr,
}

impl Default for pfr_addr {
    /// Create zero-initialized pfr_addr structure.
    ///
    /// Replaces C's `bzero(&addr, sizeof(addr))`.
    fn default() -> Self {
        pfr_addr {
            pfra_u: pfra_union { pfra_ip6addr: libc::in6_addr { s6_addr: [0; 16] } },
            pfra_af: 0,
            pfra_net: 0,
            pfra_not: 0,
            pfra_fback: 0,
        }
    }
}

/// ioctl structure for PF table operations (from BSD sys/net/pfvar.h).
///
/// C definition:
/// ```c
/// struct pfioc_table {
///     struct pfr_table pfrio_table;
///     void            *pfrio_buffer;
///     int              pfrio_esize;
///     int              pfrio_size;
///     int              pfrio_nadd;
///     int              pfrio_ndel;
///     int              pfrio_nchange;
///     int              pfrio_flags;
/// };
/// ```
#[repr(C)]
struct pfioc_table {
    /// Target table descriptor
    pfrio_table: pfr_table,

    /// Pointer to data buffer (array of pfr_table or pfr_addr)
    pfrio_buffer: *mut libc::c_void,

    /// Size of each element in buffer (sizeof(pfr_table) or sizeof(pfr_addr))
    pfrio_esize: libc::c_int,

    /// Number of elements in buffer
    pfrio_size: libc::c_int,

    /// Output: Number of entries added (set by kernel)
    pfrio_nadd: libc::c_int,

    /// Output: Number of entries deleted (set by kernel)
    pfrio_ndel: libc::c_int,

    /// Output: Number of entries changed (set by kernel)
    pfrio_nchange: libc::c_int,

    /// Operation flags
    pfrio_flags: libc::c_int,
}

impl Default for pfioc_table {
    fn default() -> Self {
        pfioc_table {
            pfrio_table: pfr_table::default(),
            pfrio_buffer: std::ptr::null_mut(),
            pfrio_esize: 0,
            pfrio_size: 0,
            pfrio_nadd: 0,
            pfrio_ndel: 0,
            pfrio_nchange: 0,
            pfrio_flags: 0,
        }
    }
}

/// BSD Packet Filter (PF) firewall backend implementation.
///
/// This struct manages the connection to the BSD PF kernel subsystem via the `/dev/pf` device,
/// providing methods to dynamically populate PF tables with DNS-resolved IP addresses.
///
/// # Thread Safety
///
/// The `pf_fd` field is wrapped in `Arc<Mutex<>>` to allow safe concurrent access across
/// tokio tasks. While PF ioctl operations are synchronous, they execute on tokio's blocking
/// thread pool via `spawn_blocking`, so multiple tasks may attempt concurrent table updates.
///
/// # Memory Safety
///
/// - `OwnedFd` provides RAII management of /dev/pf file descriptor
/// - Automatic closure on Drop, preventing descriptor leaks
/// - No manual close() calls required
/// - Safe even during unwinding (panic-safe resource cleanup)
///
/// # C Comparison
///
/// ```c
/// // C implementation: Manual resource management
/// static int dev = -1;
///
/// void ipset_init(void) {
///     dev = open("/dev/pf", O_RDWR);
///     if (dev == -1) die(...);
/// }
///
/// // Risk: If die() doesn't close descriptor, resource leak
/// // Risk: Signal handler during operation may leave descriptor open
/// ```
///
/// ```rust,ignore
/// // Rust implementation: Automatic cleanup
/// struct PfBackend {
///     pf_fd: Arc<Mutex<Option<OwnedFd>>>,
/// }
///
/// impl Drop for OwnedFd {
///     fn drop(&mut self) {
///         // Automatically closes descriptor, even during panic
///     }
/// }
/// ```
pub struct PfBackend {
    /// File descriptor for /dev/pf device, protected by mutex for thread safety.
    ///
    /// Wrapped in `Option` to allow delayed initialization (None until `initialize()` called).
    /// `Arc` enables sharing across async tasks, `Mutex` provides exclusive access during ioctl.
    pf_fd: Arc<Mutex<Option<OwnedFd>>>,
}

impl Default for PfBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl PfBackend {
    /// Create a new PfBackend instance without opening /dev/pf.
    ///
    /// The file descriptor is not opened until `initialize()` is called. This two-phase
    /// construction allows error handling during initialization while keeping construction
    /// infallible.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let backend = PfBackend::new();
    /// backend.initialize().await?;
    /// backend.add_to_set("example.com", "192.0.2.1".parse()?, "blocked").await?;
    /// ```
    #[instrument(name = "pf_backend_new")]
    pub fn new() -> Self {
        debug!("Creating new PF backend instance");
        PfBackend { pf_fd: Arc::new(Mutex::new(None)) }
    }

    /// Initialize the PF backend by opening /dev/pf device.
    ///
    /// This method opens the `/dev/pf` character device with read-write access, storing
    /// the file descriptor for subsequent ioctl operations. Must be called before any
    /// table manipulation methods.
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError::DeviceNotFound`] if:
    /// - /dev/pf does not exist (PF kernel module not loaded)
    /// - Permission denied (insufficient privileges, need root or appropriate group)
    /// - Device busy or unavailable
    ///
    /// # Privileges
    ///
    /// Requires root privileges or membership in group with /dev/pf access (typically `wheel`
    /// on BSD systems). Should be called after port binding but before privilege drop in
    /// dnsmasq startup sequence.
    ///
    /// # Platform Notes
    ///
    /// - **FreeBSD**: `kldload pf` to load PF kernel module
    /// - **OpenBSD**: PF built into kernel, always available
    /// - **NetBSD**: `modload pf` to load PF module
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let backend = PfBackend::new();
    /// backend.initialize().await
    ///     .map_err(|e| eprintln!("Failed to initialize PF: {}", e))?;
    /// ```
    #[instrument(name = "pf_initialize", skip(self))]
    pub async fn initialize(&self) -> Result<()> {
        debug!(device = %PF_DEVICE_PATH, "Initializing PF device");

        // Spawn blocking task to open /dev/pf (may block on device access)
        let fd_result = task::spawn_blocking(|| open(PF_DEVICE_PATH, OFlag::O_RDWR, Mode::empty()))
            .await
            .map_err(|e| {
                error!(error = %e, "Tokio task join error during PF device open");
                FirewallError::DeviceNotFound(format!("Task join failed: {}", e))
            })?;

        match fd_result {
            Ok(fd) => {
                // SAFETY: open() returned a valid file descriptor
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

                let mut guard = self.pf_fd.lock().unwrap();
                *guard = Some(owned_fd);

                info!(device = %PF_DEVICE_PATH, "Successfully opened PF device");
                Ok(())
            }
            Err(errno) => {
                error!(
                    device = %PF_DEVICE_PATH,
                    errno = %errno,
                    "Failed to open PF device"
                );

                let error_msg = match errno {
                    Errno::EACCES => {
                        format!("Permission denied: {} (need root privileges)", PF_DEVICE_PATH)
                    }
                    Errno::ENOENT => {
                        format!("Device not found: {} (PF module not loaded?)", PF_DEVICE_PATH)
                    }
                    Errno::ENXIO => {
                        format!("Device not configured: {} (PF not enabled)", PF_DEVICE_PATH)
                    }
                    _ => format!("Failed to open {}: {}", PF_DEVICE_PATH, errno),
                };

                Err(FirewallError::DeviceNotFound(error_msg))
            }
        }
    }

    /// Get the raw file descriptor for PF ioctl operations.
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError::DeviceNotFound`] if `initialize()` has not been called.
    #[allow(dead_code)]
    fn get_fd(&self) -> Result<libc::c_int> {
        let guard = self.pf_fd.lock().unwrap();
        match guard.as_ref() {
            Some(fd) => Ok(fd.as_raw_fd()),
            None => {
                warn!("PF device not initialized, call initialize() first");
                Err(FirewallError::DeviceNotFound("PF device not initialized".to_string()))
            }
        }
    }

    /// Ensure a PF table exists, creating it if necessary with PERSIST flag.
    ///
    /// This internal method wraps the DIOCRADDTABLES ioctl operation. If the table already
    /// exists, the operation succeeds idempotently (EEXIST is not an error).
    ///
    /// # Arguments
    ///
    /// * `table_name` - Name of PF table to create (max 31 chars + null terminator)
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError::TableCreateFailed`] if:
    /// - Table name exceeds PF_TABLE_NAME_SIZE (32 bytes)
    /// - ioctl system call fails (except EEXIST)
    /// - Permission denied (CAP_NET_ADMIN or root required)
    ///
    /// # Synchronous Operation
    ///
    /// This method is synchronous and should only be called from within `spawn_blocking`.
    #[instrument(name = "pf_ensure_table", skip(self))]
    fn ensure_table_exists_sync(&self, fd: libc::c_int, table_name: &str) -> Result<()> {
        debug!(table = %table_name, "Ensuring PF table exists");

        // Validate table name length
        if table_name.len() >= PF_TABLE_NAME_SIZE {
            error!(
                table = %table_name,
                max_len = PF_TABLE_NAME_SIZE,
                "Table name too long"
            );
            return Err(FirewallError::TableCreateFailed(format!(
                "Table name '{}' exceeds maximum length of {} bytes",
                table_name,
                PF_TABLE_NAME_SIZE - 1
            )));
        }

        // Construct pfr_table structure
        let mut table = pfr_table { pfrt_flags: PFR_TFLAG_PERSIST, ..Default::default() };

        // Copy table name into pfrt_name field (safe: length validated above)
        let name_bytes = table_name.as_bytes();
        table.pfrt_name[..name_bytes.len()].copy_from_slice(name_bytes);

        // Construct pfioc_table structure for ioctl
        let mut io = pfioc_table {
            pfrio_buffer: &mut table as *mut pfr_table as *mut libc::c_void,
            pfrio_esize: std::mem::size_of::<pfr_table>() as libc::c_int,
            pfrio_size: 1,
            pfrio_flags: 0,
            ..Default::default()
        };

        // Execute DIOCRADDTABLES ioctl
        // SAFETY: fd is valid (checked by get_fd), io structure is properly initialized
        let result = unsafe {
            libc::ioctl(fd, DIOCRADDTABLES as libc::c_ulong, &mut io as *mut pfioc_table)
        };

        if result < 0 {
            let errno = Errno::last();

            // EEXIST means table already exists - this is success (idempotent operation)
            if errno == Errno::EEXIST {
                debug!(table = %table_name, "PF table already exists");
                return Ok(());
            }

            error!(
                table = %table_name,
                errno = %errno,
                "DIOCRADDTABLES ioctl failed"
            );

            let error_msg = pf_strerror(errno);
            return Err(FirewallError::TableCreateFailed(format!(
                "Failed to create table '{}': {}",
                table_name, error_msg
            )));
        }

        if io.pfrio_nadd > 0 {
            info!(table = %table_name, "Created new PF table");
        } else {
            debug!(table = %table_name, "PF table already existed");
        }

        Ok(())
    }

    /// Add an IP address to a PF table using DIOCRADDADDRS ioctl.
    ///
    /// This internal synchronous method performs the actual ioctl system call to add an
    /// IPv4 or IPv6 address to the specified PF table.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor for /dev/pf device
    /// * `table_name` - Name of PF table to modify
    /// * `ip` - IP address to add (IPv4 or IPv6)
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError::AddressFailed`] if ioctl fails or address format is invalid.
    #[instrument(name = "pf_add_address", skip(self, fd))]
    fn add_address_sync(&self, fd: libc::c_int, table_name: &str, ip: IpAddr) -> Result<()> {
        debug!(table = %table_name, ip = %ip, "Adding IP address to PF table");

        // Construct pfr_addr structure based on address family
        let mut addr = pfr_addr::default();

        match ip {
            IpAddr::V4(ipv4) => {
                addr.pfra_af = libc::AF_INET as u8;
                addr.pfra_net = 0x20; // /32 prefix for single IPv4 address

                // SAFETY: pfra_union discriminated by pfra_af = AF_INET
                unsafe {
                    addr.pfra_u.pfra_ip4addr =
                        std::mem::transmute::<[u8; 4], libc::in_addr>(ipv4.octets());
                }
            }
            IpAddr::V6(ipv6) => {
                addr.pfra_af = libc::AF_INET6 as u8;
                addr.pfra_net = 0x80; // /128 prefix for single IPv6 address

                // SAFETY: pfra_union discriminated by pfra_af = AF_INET6
                addr.pfra_u.pfra_ip6addr = libc::in6_addr { s6_addr: ipv6.octets() };
            }
        }

        // Construct table descriptor
        let mut table = pfr_table::default();
        let name_bytes = table_name.as_bytes();
        table.pfrt_name[..name_bytes.len()].copy_from_slice(name_bytes);

        // Construct pfioc_table structure for DIOCRADDADDRS
        let mut io = pfioc_table {
            pfrio_table: table,
            pfrio_buffer: &mut addr as *mut pfr_addr as *mut libc::c_void,
            pfrio_esize: std::mem::size_of::<pfr_addr>() as libc::c_int,
            pfrio_size: 1,
            pfrio_flags: 0,
            ..Default::default()
        };

        // Execute DIOCRADDADDRS ioctl
        // SAFETY: fd is valid, io structure is properly initialized
        let result =
            unsafe { libc::ioctl(fd, DIOCRADDADDRS as libc::c_ulong, &mut io as *mut pfioc_table) };

        if result < 0 {
            let errno = Errno::last();
            error!(
                table = %table_name,
                ip = %ip,
                errno = %errno,
                "DIOCRADDADDRS ioctl failed"
            );

            let error_msg = pf_strerror(errno);
            return Err(FirewallError::AddressFailed(format!(
                "Failed to add {} to table '{}': {}",
                ip, table_name, error_msg
            )));
        }

        info!(
            table = %table_name,
            ip = %ip,
            count = io.pfrio_nadd,
            "Successfully added address to PF table"
        );

        Ok(())
    }

    /// Remove an IP address from a PF table using DIOCRDELADDRS ioctl.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor for /dev/pf device
    /// * `table_name` - Name of PF table to modify
    /// * `ip` - IP address to remove
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError::AddressFailed`] if ioctl fails.
    #[instrument(name = "pf_remove_address", skip(self, fd))]
    fn remove_address_sync(&self, fd: libc::c_int, table_name: &str, ip: IpAddr) -> Result<()> {
        debug!(table = %table_name, ip = %ip, "Removing IP address from PF table");

        // Construct pfr_addr structure (same as add_address_sync)
        let mut addr = pfr_addr::default();

        match ip {
            IpAddr::V4(ipv4) => {
                addr.pfra_af = libc::AF_INET as u8;
                addr.pfra_net = 0x20;

                unsafe {
                    addr.pfra_u.pfra_ip4addr =
                        std::mem::transmute::<[u8; 4], libc::in_addr>(ipv4.octets());
                }
            }
            IpAddr::V6(ipv6) => {
                addr.pfra_af = libc::AF_INET6 as u8;
                addr.pfra_net = 0x80;

                // SAFETY: pfra_union discriminated by pfra_af = AF_INET6
                addr.pfra_u.pfra_ip6addr = libc::in6_addr { s6_addr: ipv6.octets() };
            }
        }

        // Construct table descriptor
        let mut table = pfr_table::default();
        let name_bytes = table_name.as_bytes();
        table.pfrt_name[..name_bytes.len()].copy_from_slice(name_bytes);

        // Construct pfioc_table structure for DIOCRDELADDRS
        let mut io = pfioc_table {
            pfrio_table: table,
            pfrio_buffer: &mut addr as *mut pfr_addr as *mut libc::c_void,
            pfrio_esize: std::mem::size_of::<pfr_addr>() as libc::c_int,
            pfrio_size: 1,
            pfrio_flags: 0,
            ..Default::default()
        };

        // Execute DIOCRDELADDRS ioctl
        // SAFETY: fd is valid, io structure is properly initialized
        let result =
            unsafe { libc::ioctl(fd, DIOCRDELADDRS as libc::c_ulong, &mut io as *mut pfioc_table) };

        if result < 0 {
            let errno = Errno::last();

            // ENOENT means address doesn't exist - this is success (idempotent)
            if errno == Errno::ENOENT {
                debug!(table = %table_name, ip = %ip, "Address not in table (already removed)");
                return Ok(());
            }

            error!(
                table = %table_name,
                ip = %ip,
                errno = %errno,
                "DIOCRDELADDRS ioctl failed"
            );

            let error_msg = pf_strerror(errno);
            return Err(FirewallError::AddressFailed(format!(
                "Failed to remove {} from table '{}': {}",
                ip, table_name, error_msg
            )));
        }

        info!(
            table = %table_name,
            ip = %ip,
            count = io.pfrio_ndel,
            "Successfully removed address from PF table"
        );

        Ok(())
    }

    /// Add an IP address to a PF table (public async wrapper).
    ///
    /// This is a convenience method that combines table creation and address addition.
    ///
    /// # Arguments
    ///
    /// * `table_name` - Name of PF table
    /// * `ip` - IP address to add
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// backend.add_to_table("blocked_ads", "192.0.2.100".parse()?).await?;
    /// ```
    #[instrument(name = "pf_add_to_table", skip(self))]
    pub async fn add_to_table(&self, table_name: &str, ip: IpAddr) -> Result<()> {
        let table_name = table_name.to_string();
        let pf_fd = self.pf_fd.clone();

        task::spawn_blocking(move || {
            let guard = pf_fd.lock().unwrap();
            let fd = match guard.as_ref() {
                Some(fd) => fd.as_raw_fd(),
                None => {
                    return Err(FirewallError::DeviceNotFound(
                        "PF device not initialized".to_string(),
                    ))
                }
            };

            // Ensure table exists
            let backend_temp = PfBackend { pf_fd: pf_fd.clone() };
            backend_temp.ensure_table_exists_sync(fd, &table_name)?;

            // Add address
            backend_temp.add_address_sync(fd, &table_name, ip)
        })
        .await
        .map_err(|e| {
            error!(error = %e, "Tokio task join error");
            FirewallError::ProtocolError(format!("Task join failed: {}", e))
        })?
    }

    /// Remove an IP address from a PF table (public async wrapper).
    ///
    /// # Arguments
    ///
    /// * `table_name` - Name of PF table
    /// * `ip` - IP address to remove
    #[instrument(name = "pf_remove_from_table", skip(self))]
    pub async fn remove_from_table(&self, table_name: &str, ip: IpAddr) -> Result<()> {
        let table_name = table_name.to_string();
        let pf_fd = self.pf_fd.clone();

        task::spawn_blocking(move || {
            let guard = pf_fd.lock().unwrap();
            let fd = match guard.as_ref() {
                Some(fd) => fd.as_raw_fd(),
                None => {
                    return Err(FirewallError::DeviceNotFound(
                        "PF device not initialized".to_string(),
                    ))
                }
            };

            let backend_temp = PfBackend { pf_fd: pf_fd.clone() };
            backend_temp.remove_address_sync(fd, &table_name, ip)
        })
        .await
        .map_err(|e| {
            error!(error = %e, "Tokio task join error");
            FirewallError::ProtocolError(format!("Task join failed: {}", e))
        })?
    }

    /// Ensure a PF table exists (public async wrapper).
    ///
    /// # Arguments
    ///
    /// * `table_name` - Name of PF table to create
    #[instrument(name = "pf_ensure_table_public", skip(self))]
    pub async fn ensure_table_exists(&self, table_name: &str) -> Result<()> {
        let table_name = table_name.to_string();
        let pf_fd = self.pf_fd.clone();

        task::spawn_blocking(move || {
            let guard = pf_fd.lock().unwrap();
            let fd = match guard.as_ref() {
                Some(fd) => fd.as_raw_fd(),
                None => {
                    return Err(FirewallError::DeviceNotFound(
                        "PF device not initialized".to_string(),
                    ))
                }
            };

            let backend_temp = PfBackend { pf_fd: pf_fd.clone() };
            backend_temp.ensure_table_exists_sync(fd, &table_name)
        })
        .await
        .map_err(|e| {
            error!(error = %e, "Tokio task join error");
            FirewallError::ProtocolError(format!("Task join failed: {}", e))
        })?
    }
}

#[async_trait]
impl FirewallBackend for PfBackend {
    /// Add resolved IP address to named PF table.
    ///
    /// This method implements the [`FirewallBackend`] trait for BSD PF integration. It:
    /// 1. Ensures the target table exists (creates with PERSIST flag if needed)
    /// 2. Adds the IP address to the table via DIOCRADDADDRS ioctl
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name that was resolved (used for logging)
    /// * `ip` - Resolved IP address (IPv4 or IPv6)
    /// * `set_name` - PF table name (max 31 characters)
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Address successfully added or already exists
    /// - `Err(FirewallError)` - Operation failed (device not initialized, ioctl error, etc.)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dnsmasq::network::firewall::{PfBackend, FirewallBackend};
    ///
    /// let backend = PfBackend::new();
    /// backend.initialize().await?;
    /// backend.add_to_set("ads.example.com", "192.0.2.100".parse()?, "blocked_ads").await?;
    /// ```
    #[instrument(name = "pf_add_to_set", skip(self))]
    async fn add_to_set(&self, domain: &str, ip: IpAddr, set_name: &str) -> Result<()> {
        debug!(
            domain = %domain,
            ip = %ip,
            table = %set_name,
            "Adding IP to PF table"
        );

        self.add_to_table(set_name, ip).await
    }

    /// Remove IP address from named PF table.
    ///
    /// This method removes an IP address from a PF table when DNS cache entries expire or
    /// change. The operation is idempotent - removing a non-existent address succeeds.
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name (used for logging)
    /// * `ip` - IP address to remove
    /// * `set_name` - PF table name
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Address successfully removed or doesn't exist
    /// - `Err(FirewallError)` - Operation failed
    #[instrument(name = "pf_remove_from_set", skip(self))]
    async fn remove_from_set(&self, domain: &str, ip: IpAddr, set_name: &str) -> Result<()> {
        debug!(
            domain = %domain,
            ip = %ip,
            table = %set_name,
            "Removing IP from PF table"
        );

        self.remove_from_table(set_name, ip).await
    }
}

/// Translate PF-specific error codes to human-readable error messages.
///
/// Converts errno values returned by PF ioctl operations to descriptive error strings.
/// PF operations can return standard POSIX error codes, but some have PF-specific meanings.
///
/// # Arguments
///
/// * `errno` - Error code from nix::errno::Errno after failed PF ioctl
///
/// # Returns
///
/// String describing the error condition
///
/// # Error Code Mappings
///
/// - `ESRCH`: Table does not exist (table name not found in PF)
/// - `ENOENT`: Anchor or ruleset does not exist (anchor reference invalid)
/// - Other: Standard errno description via nix
///
/// # Example
///
/// ```rust,ignore
/// if let Err(errno) = ioctl_result {
///     let msg = pf_strerror(errno);
///     error!("PF operation failed: {}", msg);
/// }
/// ```
fn pf_strerror(errno: Errno) -> String {
    match errno {
        Errno::ESRCH => "Table does not exist".to_string(),
        Errno::ENOENT => "Anchor or Ruleset does not exist".to_string(),
        _ => format!("{}", errno),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pfr_table_default() {
        let table = pfr_table::default();
        assert_eq!(table.pfrt_flags, 0);
        assert_eq!(table.pfrt_name[0], 0);
    }

    #[test]
    fn test_pfr_addr_default() {
        let addr = pfr_addr::default();
        assert_eq!(addr.pfra_af, 0);
        assert_eq!(addr.pfra_net, 0);
    }

    #[test]
    fn test_pf_strerror() {
        assert_eq!(pf_strerror(Errno::ESRCH), "Table does not exist");
        assert_eq!(pf_strerror(Errno::ENOENT), "Anchor or Ruleset does not exist");
    }

    #[test]
    fn test_table_name_size() {
        assert_eq!(PF_TABLE_NAME_SIZE, 32);

        let valid_name = "blocked_domains";
        assert!(valid_name.len() < PF_TABLE_NAME_SIZE);

        let too_long = "a".repeat(PF_TABLE_NAME_SIZE);
        assert!(too_long.len() >= PF_TABLE_NAME_SIZE);
    }
}
