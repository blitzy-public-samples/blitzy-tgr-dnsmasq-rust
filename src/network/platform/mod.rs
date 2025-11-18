// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Platform-specific network operations
//!
//! This module provides platform-specific networking functionality,
//! with separate implementations for Linux, BSD, and macOS.

// Linux-specific networking (netlink)
#[cfg(target_os = "linux")]
pub mod linux;

// BSD-specific networking (BPF, routing sockets)
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub mod bsd;

// macOS-specific networking
#[cfg(target_os = "macos")]
pub mod macos;

// Common platform abstractions
pub mod common;

// Re-export platform-specific types
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub use bsd::*;

#[cfg(target_os = "macos")]
pub use macos::*;

pub use common::*;
