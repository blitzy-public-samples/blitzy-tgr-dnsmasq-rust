// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! DHCPv6 (Dynamic Host Configuration Protocol for IPv6) implementation module
//!
//! This module implements the DHCPv6 protocol per RFC 3315 and related extension RFCs,
//! providing stateful address assignment, stateless configuration, and prefix delegation.

/// DHCPv6 protocol constants (ports, message types, option codes, status codes, DUID types)
pub mod constants;
