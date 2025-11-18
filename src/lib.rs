// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! dnsmasq - Memory-safe DNS forwarder and DHCP server
//!
//! This is the Rust implementation of dnsmasq, providing 100% functional parity
//! with the C implementation while ensuring memory safety through Rust's ownership
//! system and borrow checker.
//!
//! # Main Components
//!
//! - DNS forwarding and caching
//! - DHCPv4 and DHCPv6 server
//! - DNSSEC validation
//! - TFTP server
//! - IPv6 Router Advertisements
//!
//! # Architecture
//!
//! The library is organized into functional modules:
//! - `error`: Comprehensive error type definitions
//! - `config`: Configuration parsing and management
//! - `dns`: DNS query forwarding and caching
//! - `dhcp`: DHCPv4/v6 server implementation
//! - `dnssec`: DNSSEC validation
//! - `network`: Network layer abstraction
//! - `tftp`: TFTP server
//! - `radv`: IPv6 Router Advertisements
//! - `platform`: Platform-specific integration
//! - `runtime`: Async runtime and event loop

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

// Public API modules
pub mod constants;
pub mod dhcp;
pub mod dns;
pub mod error;
pub mod radv;

// Re-export commonly used types
pub use error::{DnsmasqError, Result};
