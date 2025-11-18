// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! DHCPv4 (Dynamic Host Configuration Protocol for IPv4) implementation
//!
//! This module provides a complete DHCPv4 server implementation following RFC 2131
//! and related standards. It handles address allocation, lease management, and
//! all standard DHCPv4 options.

/// DHCPv4 protocol constants
pub mod constants;
