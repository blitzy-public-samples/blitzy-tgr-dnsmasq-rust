// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! DHCP (Dynamic Host Configuration Protocol) module
//!
//! This module provides DHCPv4 and DHCPv6 server implementations with full
//! protocol support for address assignment, lease management, and option handling.

/// Shared utilities and types for DHCPv4 and DHCPv6
pub mod common;

/// DHCPv4 (Dynamic Host Configuration Protocol for IPv4) implementation
pub mod v4;

/// DHCPv6 (Dynamic Host Configuration Protocol for IPv6) implementation
pub mod v6;

/// DHCP lease management and persistence
pub mod lease;
