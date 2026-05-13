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

//! Utilities Module Root
//!
//! This module provides cross-cutting utility functionality used throughout the dnsmasq
//! Rust implementation. It replaces C's flat header inclusion model (util.c, helper.c,
//! log.c as separate compilation units) with Rust's hierarchical module system providing
//! namespace organization, encapsulation, and type safety.
//!
//! # Module Organization
//!
//! The utilities module is organized into focused submodules, each providing specific
//! functionality:
//!
//! ## Random Number Generation (`random`)
//!
//! Implements the SURF (Speedy Unpredictable Random Function) cryptographic RNG
//! developed by Daniel J. Bernstein for djbdns. Provides cryptographic-quality
//! randomness essential for DNS query ID generation, source port randomization,
//! and cache key generation to prevent DNS cache poisoning attacks.
//!
//! **Key Types:**
//! - [`SurfRng`]: Main random number generator struct with interior mutability
//!
//! **Key Functions:**
//! - [`rand_init()`]: Initialize RNG from system entropy
//! - [`rand16()`]: Generate 16-bit random value (DNS query IDs, source ports)
//! - [`rand32()`]: Generate 32-bit random value (cache keys, delays)
//! - [`rand64()`]: Generate 64-bit random value (DHCPv6 transaction IDs)
//!
//! **Usage Example:**
//! ```rust
//! use dnsmasq::util::{rand_init, rand16, rand32, rand64};
//!
//! // Initialize RNG from system entropy (typically called once at startup)
//! let rng = rand_init().expect("Failed to initialize RNG");
//!
//! // Generate random values using instance methods
//! let query_id = rng.rand16();      // DNS query ID
//! let cache_key = rng.rand32();     // Cache key
//! let transaction_id = rng.rand64(); // DHCPv6 transaction ID
//!
//! // Or use global convenience functions (thread-local instance)
//! let port = rand16();              // Random source port
//! let delay = rand32() % 1000;      // Random delay in milliseconds
//! ```
//!
//! ## Logging (`logging`)
//!
//! Non-blocking asynchronous logging system using the `tracing` crate, replacing
//! C syslog integration. Implements bounded message queue (LOG_MAX depth) to
//! prevent blocking the main event loop when syslog is slow or making DNS lookups
//! back through dnsmasq (deadlock prevention).
//!
//! **Key Functions:**
//! - [`log_init()`]: Initialize tracing subscriber with configurable output targets
//! - [`flush_log()`]: Synchronous drain during shutdown ensuring all messages written
//!
//! **Usage Example:**
//! ```rust,ignore
//! use dnsmasq::util::log_init;
//! use tracing::{info, error, Level};
//!
//! // Initialize logging at startup with configuration
//! log_init(false, None, true, Level::INFO)
//!     .expect("Failed to initialize logging");
//!
//! // Use tracing macros throughout the codebase
//! info!(ip = "192.168.1.100", mac = "00:11:22:33:44:55", "DHCP lease allocated");
//! error!(domain = "example.com", "DNSSEC validation failed: BOGUS");
//! ```
//!
//! ## Metrics (`metrics`)
//!
//! Performance metrics collection and reporting for operational visibility into
//! DNS query processing, DHCP transactions, cache behavior, and DNSSEC validation.
//! Provides simple counter increments with atomic operations suitable for
//! single-threaded event loop architecture.
//!
//! **Key Types:**
//! - [`MetricType`]: Enum of all collectible metrics
//!
//! **Usage Example:**
//! ```rust,ignore
//! use dnsmasq::util::MetricType;
//! use dnsmasq::util::metrics::MetricsCollector;
//!
//! let metrics = MetricsCollector::new();
//! metrics.increment(MetricType::DnsQueriesForwarded);
//! metrics.increment(MetricType::DnsCacheInserted);
//!
//! // Export for D-Bus/monitoring systems
//! let json = metrics.to_json();
//! ```
//!
//! ## Pattern Matching (`patterns`)
//!
//! DNS hostname pattern validation and matching module for security policy
//! enforcement and conntrack filtering. Implements RFC 1123-compliant hostname
//! validation and wildcard pattern matching with security restrictions.
//!
//! **Key Functions:**
//! - [`is_valid_dns_name()`]: Validate DNS hostname per RFC 1123
//! - [`is_valid_dns_name_pattern()`]: Validate wildcard pattern with security checks
//! - [`is_dns_name_matching_pattern()`]: Case-insensitive pattern matching
//! - [`is_string_matching_glob_pattern()`]: General glob pattern matching
//!
//! **Usage Example:**
//! ```rust
//! use dnsmasq::util::patterns;
//!
//! // Validate hostname
//! assert!(patterns::is_valid_dns_name("example.com"));
//! assert!(!patterns::is_valid_dns_name("invalid_hostname"));
//!
//! // Validate and match patterns
//! assert!(patterns::is_valid_dns_name_pattern("*.example.com"));
//! assert!(!patterns::is_valid_dns_name_pattern("*.com")); // Too broad
//! assert!(patterns::is_dns_name_matching_pattern("sub.example.com", "*.example.com"));
//! ```
//!
//! ## Packet Capture (`pcap`)
//!
//! Implements libpcap file format writing for debugging and troubleshooting.
//! Captures DNS, DHCP, TFTP UDP packets and Router Advertisement ICMPv6 packets
//! compatible with Wireshark and tcpdump analysis tools.
//!
//! **Key Functions:**
//! - [`dump_init()`]: Create pcap file with global header
//! - [`dump_packet_udp()`]: Capture UDP packets (DNS/DHCP/TFTP)
//! - [`dump_packet_icmp()`]: Capture ICMPv6 packets (Router Advertisements)
//!
//! **Usage Example:**
//! ```rust,ignore
//! use dnsmasq::util::pcap::dump_init;
//! use std::path::Path;
//!
//! // Initialize packet capture with 65535 byte snaplen
//! let pcap = dump_init(Path::new("/var/log/dnsmasq.pcap"), 65535)
//!     .await
//!     .expect("Failed to create pcap file");
//!
//! // Capture packets using PcapWriter methods
//! // (see pcap module documentation for packet capture details)
//! ```
//!
//! ## Helper Scripts (`helpers`)
//!
//! Privilege-separated external script execution for DHCP lease events, TFTP
//! transfers, and ARP changes. Maintains environment variable contract
//! (DNSMASQ_DOMAIN, DNSMASQ_LEASE_EXPIRES, etc.) for backward compatibility
//! with existing user scripts.
//!
//! **Key Types:**
//! - [`ScriptEvent`]: Enum representing different event types
//!
//! **Key Functions:**
//! - [`queue_script()`]: Queue DHCP lease event for script execution
//! - [`queue_tftp()`]: Queue TFTP transfer event
//! - [`queue_arp()`]: Queue ARP table change event
//!
//! **Usage Example:**
//! ```rust,ignore
//! use dnsmasq::util::helpers::{queue_script, ScriptEvent, LeaseAction, ScriptExecutor};
//! use std::sync::Arc;
//! use std::net::IpAddr;
//!
//! // Queue DHCP lease event with executor
//! let executor = Arc::new(ScriptExecutor::new("/usr/local/bin/dhcp-script"));
//! queue_script(&executor, ScriptEvent::DhcpLease {
//!     action: LeaseAction::Add,
//!     mac: "00:11:22:33:44:55".to_string(),
//!     ip: IpAddr::from([192, 168, 1, 100]),
//!     hostname: Some("client-host".to_string()),
//!     // ... other required fields
//! }).await?;
//! ```
//!
//! # API Design Principles
//!
//! This module follows Rust idioms and best practices:
//!
//! - **Type Safety**: Strong typing replaces C's void* and union types
//! - **Memory Safety**: No manual memory management; RAII patterns throughout
//! - **Error Handling**: Result types instead of C error codes and errno
//! - **Async/Await**: Non-blocking operations with tokio integration
//! - **Interior Mutability**: RefCell/Mutex where needed for single-threaded event loop
//! - **Structured Logging**: Tracing crate with contextual fields instead of printf-style
//! - **Zero-Cost Abstractions**: Inline functions compiled to efficient machine code
//!
//! # Dependencies Between Utility Components
//!
//! Some utility modules depend on others:
//!
//! - **helpers** may use **logging** for script execution events
//! - **logging** may use **random** for unique log message IDs
//! - **metrics** may use **logging** for metric reporting
//! - **pcap** may use **logging** for error reporting
//!
//! These dependencies are managed through explicit module imports, ensuring
//! clear dependency graphs and preventing circular dependencies.
//!
//! # Feature Flags
//!
//! Some utility modules are conditionally compiled based on feature flags:
//!
//! - `pcap` module requires `dumpfile` feature for packet capture support
//! - `helpers` Lua integration requires `lua-scripts` feature
//!
//! # Thread Safety
//!
//! Most utility functions are designed for single-threaded event loop architecture
//! matching the C implementation. Where thread safety is required (e.g., metrics
//! export, global RNG), appropriate synchronization primitives (Arc, Mutex, RwLock)
//! are used.
//!
//! # Backward Compatibility
//!
//! The utilities maintain backward compatibility with C implementation:
//!
//! - Environment variables in helper scripts use same names
//! - Log message formats parseable by existing tools
//! - Metric names match C version for monitoring integration
//! - Random number sequences can be made deterministic for testing
//! - pcap files compatible with existing Wireshark dissectors

// ============================================================================
// Module Declarations
// ============================================================================

/// Helper script execution module for privilege-separated external script invocation.
///
/// Provides functions to queue DHCP lease events, TFTP transfers, and ARP changes
/// for asynchronous processing by a forked helper process. Maintains environment
/// variable contract for backward compatibility with existing user scripts.
///
/// # Public API
///
/// - `queue_script()`: Queue DHCP lease event
/// - `queue_tftp()`: Queue TFTP transfer event  
/// - `queue_arp()`: Queue ARP table change event
/// - `ScriptEvent`: Enum of event types
pub mod helpers;

/// Non-blocking asynchronous logging system using tracing crate.
///
/// Implements bounded message queue to prevent blocking main event loop when
/// syslog is slow. Provides structured logging with JSON formatting for SIEM
/// integration.
///
/// # Public API
///
/// - `log_init()`: Initialize tracing subscriber
/// - `flush_log()`: Synchronous drain during shutdown
pub mod logging;

/// Performance metrics collection and reporting module.
///
/// Provides operational visibility into DNS query processing, DHCP transactions,
/// cache behavior, and DNSSEC validation. Exports metrics via D-Bus/UBus control
/// interfaces for monitoring system integration.
///
/// # Public API
///
/// - `MetricType`: Enum of all collectible metrics
/// - `MetricsCollector`: Main metrics collection service
/// - `report_all()`: Export all metrics as JSON
pub mod metrics;

/// Packet capture module implementing libpcap file format writing.
///
/// Captures DNS, DHCP, TFTP UDP packets and Router Advertisement ICMPv6 packets
/// for debugging and troubleshooting. Output compatible with Wireshark and tcpdump.
///
/// # Public API
///
/// - `dump_init()`: Create pcap file with global header
/// - `dump_packet_udp()`: Capture UDP packets
/// - `dump_packet_icmp()`: Capture ICMPv6 packets
///
/// # Feature Requirements
///
/// This module is only available when the `dumpfile` feature is enabled.
/// Add `dumpfile` to your Cargo.toml features to enable packet capture support.
#[cfg(feature = "dumpfile")]
pub mod pcap;

/// DNS hostname pattern validation and matching module.
///
/// Implements RFC 1123-compliant hostname validation and wildcard pattern matching
/// with security restrictions preventing overly broad patterns like *.com or *.co.uk.
///
/// # Public API
///
/// - `is_valid_dns_name()`: Validate DNS hostname per RFC 1123
/// - `is_valid_dns_name_pattern()`: Validate wildcard pattern
/// - `is_dns_name_matching_pattern()`: Case-insensitive pattern matching
/// - `is_string_matching_glob_pattern()`: General glob pattern matching
pub mod patterns;

/// SURF cryptographic random number generator module.
///
/// Implements Daniel J. Bernstein's SURF algorithm for cryptographic-quality
/// randomness suitable for DNS query IDs, source port randomization, and cache
/// keys to prevent DNS cache poisoning attacks.
///
/// # Public API
///
/// - `SurfRng`: Main RNG struct
/// - `rand_init()`: Initialize RNG from system entropy
/// - `rand16()`: Generate 16-bit random value
/// - `rand32()`: Generate 32-bit random value
/// - `rand64()`: Generate 64-bit random value
pub mod random;

// ============================================================================
// Re-exports for Ergonomic API
// ============================================================================

// Re-export random number generation types and functions
pub use random::{rand16, rand32, rand64, rand_init, RandomError, SurfRng};

// Re-export metrics types
pub use metrics::MetricType;

// Re-export logging functions
pub use logging::{flush_log, log_init};

// Note: Other module exports are accessed via their module paths
// (e.g., util::helpers::queue_script, util::patterns::is_valid_dns_name)
// to maintain clear API boundaries and prevent namespace pollution.
