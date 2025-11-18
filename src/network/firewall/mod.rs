// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Firewall integration for address sets
//!
//! This module provides integration with platform-specific firewall systems
//! to populate address sets from DNS query results.

// Linux ipset integration
#[cfg(all(target_os = "linux", feature = "ipset"))]
pub mod ipset;

// Linux nftables integration
#[cfg(all(target_os = "linux", feature = "nftset"))]
pub mod nftables;

// BSD PF tables integration
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub mod pf;

// Re-export based on features
#[cfg(all(target_os = "linux", feature = "ipset"))]
pub use ipset::*;

#[cfg(all(target_os = "linux", feature = "nftset"))]
pub use nftables::*;

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub use pf::*;
