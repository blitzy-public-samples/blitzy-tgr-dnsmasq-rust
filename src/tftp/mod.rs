// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! TFTP Server Implementation
//!
//! This module provides a memory-safe TFTP (Trivial File Transfer Protocol)
//! server implementation, ported from the C dnsmasq tftp.c source file.
//!
//! # Features
//!
//! - RFC 1350 TFTP protocol support
//! - RFC 2347 Option Extension support
//! - RFC 2348 Blocksize Option support
//! - RFC 7440 Windowsize Option support (multiple outstanding blocks)
//! - Netascii and octet transfer modes
//! - Async I/O using tokio
//! - Memory-safe file transfer state management
//!
//! # C Source Mapping
//!
//! C Source: src/tftp.c
//! - TFTP server socket handling → server.rs (to be implemented)
//! - TFTP protocol state machine → server.rs (to be implemented)
//! - Transfer state tracking → transfer.rs (implemented)
//!
//! # Architecture
//!
//! The TFTP module is organized into:
//! - `transfer`: Transfer state machine and file I/O logic
//! - `server`: TFTP protocol handler (to be implemented)
//!
//! # Memory Safety
//!
//! All TFTP packet parsing, file I/O, and state management use safe Rust:
//! - No manual buffer management (uses Vec<u8> and Bytes)
//! - No pointer arithmetic (uses safe slice operations)
//! - Automatic resource cleanup via RAII (Drop trait)
//! - Type-safe state transitions
//!
//! # Usage
//!
//! ```rust,ignore
//! use dnsmasq::tftp::transfer::TransferState;
//! use std::net::SocketAddr;
//! use std::path::PathBuf;
//!
//! let peer_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
//! let file_path = PathBuf::from("/srv/tftp/pxelinux.0");
//! let transfer = TransferState::new(
//!     peer_addr,
//!     file_path,
//!     512,  // blocksize
//!     1,    // windowsize
//!     5,    // timeout seconds
//!     false // netascii mode
//! ).await?;
//! ```

pub mod transfer;

// Re-export commonly used types
pub use transfer::TransferState;
