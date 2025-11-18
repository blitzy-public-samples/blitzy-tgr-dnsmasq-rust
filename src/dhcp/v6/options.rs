// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! DHCPv6 option serialization module implementing safe encoding of all RFC 3315 options.
//!
//! This module provides the [`OptionBuilder`] struct for constructing DHCPv6 options with
//! automatic buffer management, replacing C's manual pointer arithmetic and outpacket buffer
//! manipulation with memory-safe Rust patterns. All multi-byte integers are encoded in
//! big-endian (network byte order) format per DHCPv6 specification.
//!
//! # Purpose
//!
//! DHCPv6 options follow a TLV (Type-Length-Value) format:
//! - **Type**: 2-byte option code (u16)
//! - **Length**: 2-byte length of option data (u16), excluding the 4-byte header
//! - **Value**: Variable-length option data
//!
//! The [`OptionBuilder`] handles automatic length calculation, including complex nested
//! options like IA_NA containers that contain multiple IA_ADDR sub-options, each with
//! their own TLV structure.
//!
//! # Architecture
//!
//! ## Rust Implementation Pattern
//!
//! This module transforms the C implementation from `src/outpacket.c`:
//!
//! ```c
//! // C pattern: Global buffer with manual position tracking
//! static size_t outpacket_counter;
//! daemon->outpacket.iov_base = malloc(size);
//!
//! int new_opt6(int opt) {
//!     int ret = outpacket_counter;
//!     unsigned char *p = expand(4);
//!     PUTSHORT(opt, p);    // Manual byte packing
//!     PUTSHORT(0, p);      // Length placeholder
//!     return ret;
//! }
//!
//! void end_opt6(int container) {
//!     uint8_t *p = (uint8_t *)daemon->outpacket.iov_base + container + 2;
//!     u16 len = outpacket_counter - container - 4;
//!     PUTSHORT(len, p);    // Backpatch length
//! }
//! ```
//!
//! To safe Rust builder pattern:
//!
//! ```rust,ignore
//! // Rust pattern: Owned Vec<u8> with type-safe methods
//! let mut builder = OptionBuilder::new();
//!
//! builder.start_container(OPTION_IA_NA)?;
//! builder.put_u32(iaid)?;
//! builder.put_u32(t1)?;
//! builder.put_u32(t2)?;
//! builder.end_container()?;  // Automatic length calculation
//!
//! let packet = builder.build();
//! ```
//!
//! ## Memory Safety Improvements
//!
//! - **Automatic bounds checking**: Vec<u8> prevents buffer overflows
//! - **Ownership semantics**: No dangling pointers or use-after-free
//! - **Type-safe encoding**: to_be_bytes() replaces manual PUTSHORT/PUTLONG macros
//! - **Explicit error handling**: Result<T, DhcpError> replaces silent failures
//!
//! # Nested Option Support
//!
//! DHCPv6 options can be nested (e.g., IA_NA contains IA_ADDR sub-options). The builder
//! maintains a container stack to track nesting depth and automatically calculates lengths
//! for each container level when `end_container()` is called.
//!
//! ## Example: IA_NA with IA_ADDR
//!
//! ```rust,ignore
//! use std::net::Ipv6Addr;
//!
//! let mut builder = OptionBuilder::new();
//!
//! // Start IA_NA container
//! builder.start_container(constants::OPTION_IA_NA)?;
//! builder.put_u32(0x12345678)?;  // IAID
//! builder.put_u32(3600)?;         // T1
//! builder.put_u32(7200)?;         // T2
//!
//! // Add IA_ADDR sub-option within IA_NA
//! builder.start_container(constants::OPTION_IAADDR)?;
//! builder.put_ipv6_addr(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))?;
//! builder.put_u32(7200)?;   // Preferred lifetime
//! builder.put_u32(14400)?;  // Valid lifetime
//! builder.end_container()?;  // Finalize IA_ADDR
//!
//! builder.end_container()?;  // Finalize IA_NA with correct total length
//! ```
//!
//! # RFC Compliance
//!
//! - **RFC 3315**: DHCPv6 core specification (option format, message types)
//! - **RFC 3633**: IPv6 Prefix Options for DHCPv6 (IA_PD, IAPREFIX)
//! - **RFC 3646**: DNS Configuration options (DNS_SERVER, DOMAIN_SEARCH)
//! - **RFC 4704**: Client FQDN option
//! - **RFC 5908**: Network Time Protocol (NTP) Server Option
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::dhcp::v6::options::OptionBuilder;
//! use crate::dhcp::v6::constants;
//!
//! // Build a simple PREFERENCE option
//! let mut builder = OptionBuilder::new();
//! builder.put_preference(255)?;
//! let options_bytes = builder.build();
//!
//! // Build complex nested options
//! let mut builder = OptionBuilder::new();
//! builder.put_server_id(&[0x00, 0x01, 0x00, 0x01, ...])?;
//! builder.put_ia_na(0x12345678, 3600, 7200, |b| {
//!     b.put_ia_addr(&addr, 7200, 14400, |_| Ok(()))?;
//!     Ok(())
//! })?;
//! ```

use crate::dhcp::v6::constants;
use crate::error::DhcpError;
use std::net::Ipv6Addr;

/// DHCPv6 option builder providing safe construction of DHCPv6 options with TLV encoding.
///
/// This struct replaces the C implementation's global `daemon->outpacket` buffer and
/// `outpacket_counter` position tracking with an owned `Vec<u8>` buffer and a container
/// stack for nested option support. All methods return `Result<(), DhcpError>` for
/// explicit error propagation.
///
/// # Fields
///
/// - `buffer`: Growing byte buffer for option data with automatic capacity expansion
/// - `container_stack`: Stack tracking positions of nested option containers for length backpatching
///
/// # Thread Safety
///
/// Unlike the C implementation which uses global state, `OptionBuilder` is a self-contained
/// value type that can be used safely in concurrent contexts (though typically used sequentially
/// for constructing a single packet).
///
/// # Example
///
/// ```rust,ignore
/// let mut builder = OptionBuilder::new();
/// builder.put_client_id(&duid)?;
/// builder.put_preference(255)?;
/// let packet_options = builder.build();
/// ```
pub struct OptionBuilder {
    /// Buffer containing serialized DHCPv6 options in wire format
    buffer: Vec<u8>,

    /// Stack of container start positions for nested options (e.g., IA_NA containing IA_ADDR)
    /// Each entry stores the byte offset where the container option header begins
    container_stack: Vec<usize>,
}

impl OptionBuilder {
    /// Creates a new empty OptionBuilder with zero-capacity buffer.
    ///
    /// The buffer will grow automatically as options are added. This replaces the C
    /// implementation's `reset_counter()` function which cleared the global buffer.
    ///
    /// # Returns
    ///
    /// A new `OptionBuilder` ready for option construction
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut builder = OptionBuilder::new();
    /// assert_eq!(builder.buffer.len(), 0);
    /// ```
    pub fn new() -> Self {
        Self { buffer: Vec::new(), container_stack: Vec::new() }
    }

    /// Starts a new DHCPv6 option with the specified option code.
    ///
    /// Writes a 4-byte option header (2-byte option code + 2-byte length placeholder) to
    /// the buffer. This is the Rust equivalent of the C `new_opt6(int opt)` function.
    ///
    /// For simple options, follow this with `put_*` methods to add option data, then call
    /// `end_container()` to finalize. For container options, call `start_container()` instead
    /// which both creates the header and pushes the position onto the container stack.
    ///
    /// # Arguments
    ///
    /// * `option_code` - DHCPv6 option code (e.g., `constants::OPTION_PREFERENCE`)
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError::V6ProtocolError)` if encoding fails (should not occur with Vec)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.new_option(constants::OPTION_PREFERENCE)?;
    /// builder.put_u8(255)?;
    /// ```
    pub fn new_option(&mut self, option_code: u16) -> Result<(), DhcpError> {
        // Encode option code (2 bytes, big-endian)
        self.buffer.extend_from_slice(&option_code.to_be_bytes());

        // Encode length placeholder (2 bytes, big-endian) - will be backpatched
        self.buffer.extend_from_slice(&0u16.to_be_bytes());

        Ok(())
    }

    /// Appends arbitrary binary data to the buffer.
    ///
    /// This is the fundamental data addition method, equivalent to C's `put_opt6(void *data, size_t len)`.
    /// All other `put_*` methods are built on top of this.
    ///
    /// # Arguments
    ///
    /// * `data` - Slice of bytes to append
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError::V6ProtocolError)` if buffer operation fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let duid = vec![0x00, 0x01, 0x00, 0x01, 0x6a, 0x4e, 0x2c, 0x8a];
    /// builder.put_bytes(&duid)?;
    /// ```
    pub fn put_bytes(&mut self, data: &[u8]) -> Result<(), DhcpError> {
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    /// Appends a 32-bit unsigned integer in network byte order (big-endian).
    ///
    /// Equivalent to C's `put_opt6_long(unsigned int val)` which used the PUTLONG macro.
    /// Used for DHCPv6 fields like IAID, T1, T2, preferred/valid lifetimes.
    ///
    /// # Arguments
    ///
    /// * `value` - 32-bit unsigned integer to encode
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError::V6ProtocolError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.put_u32(0x12345678)?;  // IAID
    /// builder.put_u32(3600)?;         // T1: 1 hour
    /// ```
    pub fn put_u32(&mut self, value: u32) -> Result<(), DhcpError> {
        self.buffer.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Appends a 16-bit unsigned integer in network byte order (big-endian).
    ///
    /// Equivalent to C's `put_opt6_short(unsigned int val)` which used the PUTSHORT macro.
    /// Used for DHCPv6 fields like status codes, DUID types, hardware types.
    ///
    /// # Arguments
    ///
    /// * `value` - 16-bit unsigned integer to encode
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError::V6ProtocolError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.put_u16(0)?;  // Status code: Success
    /// builder.put_u16(1)?;  // DUID type: DUID-LLT
    /// ```
    pub fn put_u16(&mut self, value: u16) -> Result<(), DhcpError> {
        self.buffer.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Appends an 8-bit unsigned integer.
    ///
    /// Equivalent to C's `put_opt6_char(unsigned int val)`. Used for single-byte fields
    /// like preference values.
    ///
    /// # Arguments
    ///
    /// * `value` - 8-bit unsigned integer to encode
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError::V6ProtocolError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.put_u8(255)?;  // Highest preference
    /// ```
    pub fn put_u8(&mut self, value: u8) -> Result<(), DhcpError> {
        self.buffer.push(value);
        Ok(())
    }

    /// Appends a string as raw bytes (no length prefix, no null terminator).
    ///
    /// Equivalent to C's `put_opt6_string(char *s)` which used `put_opt6(s, strlen(s))`.
    /// Used for human-readable option data like status messages and domain names.
    ///
    /// # Arguments
    ///
    /// * `s` - String to append as UTF-8 bytes
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError::V6ProtocolError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.put_string("example.com")?;
    /// ```
    pub fn put_string(&mut self, s: &str) -> Result<(), DhcpError> {
        self.buffer.extend_from_slice(s.as_bytes());
        Ok(())
    }

    /// Appends an IPv6 address as 16 bytes in network byte order.
    ///
    /// Uses `Ipv6Addr::octets()` to get the 16-byte representation. This method provides
    /// type safety compared to C's `put_opt6(&addr, 16)` with raw struct in6_addr pointers.
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv6 address to encode
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError::V6ProtocolError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use std::net::Ipv6Addr;
    /// let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    /// builder.put_ipv6_addr(&addr)?;
    /// ```
    pub fn put_ipv6_addr(&mut self, addr: &Ipv6Addr) -> Result<(), DhcpError> {
        self.buffer.extend_from_slice(&addr.octets());
        Ok(())
    }

    /// Starts a new option container and pushes its position onto the stack.
    ///
    /// This combines `new_option()` with position tracking for nested options. The position
    /// is saved so that `end_container()` can later backpatch the correct length field.
    ///
    /// This replaces the C pattern:
    /// ```c
    /// int container = save_counter(-1);
    /// new_opt6(OPTION6_IA_NA);
    /// ```
    ///
    /// # Arguments
    ///
    /// * `option_code` - DHCPv6 option code for the container (e.g., `OPTION_IA_NA`)
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError::V6ProtocolError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.start_container(constants::OPTION_IA_NA)?;
    /// // Add container data...
    /// builder.end_container()?;
    /// ```
    pub fn start_container(&mut self, option_code: u16) -> Result<(), DhcpError> {
        // Save current buffer position (where this option header starts)
        let container_pos = self.buffer.len();
        self.container_stack.push(container_pos);

        // Create option header
        self.new_option(option_code)?;

        Ok(())
    }

    /// Finalizes the most recent container by backpatching its length field.
    ///
    /// Pops the container position from the stack, calculates the total length of data
    /// added since the container started (excluding the 4-byte header), and writes this
    /// length value into the option's length field (bytes 2-3 of the option header).
    ///
    /// This is the Rust equivalent of C's `end_opt6(int container)` function.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError::V6ProtocolError)` if no container is open or length calculation fails
    ///
    /// # Panics
    ///
    /// This method will not panic in normal operation. Invalid state (empty stack) returns an error.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.start_container(constants::OPTION_IA_NA)?;
    /// builder.put_u32(iaid)?;
    /// // ... more data ...
    /// builder.end_container()?;  // Backpatches length
    /// ```
    pub fn end_container(&mut self) -> Result<(), DhcpError> {
        // Pop container start position from stack
        let container_pos =
            self.container_stack.pop().ok_or_else(|| DhcpError::V6ProtocolError {
                reason: "end_container called without matching start_container".to_string(),
            })?;

        // Calculate option data length (total bytes - 4-byte header)
        let total_length = self.buffer.len() - container_pos;
        if total_length < 4 {
            return Err(DhcpError::V6ProtocolError {
                reason: format!("Invalid container length: {}", total_length),
            });
        }
        let option_data_len = (total_length - 4) as u16;

        // Backpatch the length field (bytes at container_pos+2 and container_pos+3)
        let length_bytes = option_data_len.to_be_bytes();
        self.buffer[container_pos + 2] = length_bytes[0];
        self.buffer[container_pos + 3] = length_bytes[1];

        Ok(())
    }

    /// Finalizes buffer construction and returns the complete option data.
    ///
    /// Consumes the builder and returns the serialized DHCPv6 options as a `Vec<u8>`.
    /// All containers must be properly closed with `end_container()` before calling this.
    ///
    /// # Returns
    ///
    /// Owned vector containing all serialized DHCPv6 options
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let options = builder.build();
    /// // options now contains wire-format DHCPv6 options ready for transmission
    /// ```
    pub fn build(self) -> Vec<u8> {
        self.buffer
    }

    // ========================================================================
    // High-Level Option Construction Methods
    // ========================================================================
    //
    // The methods below provide convenient APIs for constructing specific DHCPv6 options
    // according to RFC specifications. Each method creates the option header, adds the
    // required fields in the correct order, and finalizes the option.

    /// Adds a CLIENT_ID option (Option 1) containing client DUID.
    ///
    /// Per RFC 3315 Section 22.2, CLIENT_ID uniquely identifies the DHCP client.
    /// The DUID (DHCP Unique Identifier) format can be DUID-LLT, DUID-EN, or DUID-LL.
    ///
    /// # Arguments
    ///
    /// * `duid` - Client DUID bytes (variable length, typically 10-20 bytes)
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // DUID-LLT format: type(2) + hw_type(2) + time(4) + link_layer_addr(variable)
    /// let duid = vec![0x00, 0x01, 0x00, 0x01, 0x6a, 0x4e, 0x2c, 0x8a, 0xde, 0xad, 0xbe, 0xef];
    /// builder.put_client_id(&duid)?;
    /// ```
    pub fn put_client_id(&mut self, duid: &[u8]) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_CLIENT_ID)?;
        self.put_bytes(duid)?;
        self.end_container()
    }

    /// Adds a SERVER_ID option (Option 2) containing server DUID.
    ///
    /// Per RFC 3315 Section 22.3, SERVER_ID identifies the DHCP server. Required in
    /// ADVERTISE, REPLY, RECONFIGURE messages.
    ///
    /// # Arguments
    ///
    /// * `duid` - Server DUID bytes (variable length)
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let server_duid = vec![0x00, 0x02, 0x00, 0x00, 0x13, 0x37, ...];
    /// builder.put_server_id(&server_duid)?;
    /// ```
    pub fn put_server_id(&mut self, duid: &[u8]) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_SERVER_ID)?;
        self.put_bytes(duid)?;
        self.end_container()
    }

    /// Adds an IA_NA option (Option 3) for non-temporary address assignment.
    ///
    /// Per RFC 3315 Section 22.4, IA_NA (Identity Association for Non-temporary Addresses)
    /// contains IAID, T1, T2, and may contain IA_ADDR options for assigned addresses.
    ///
    /// # Arguments
    ///
    /// * `iaid` - Identity Association Identifier (arbitrary 32-bit value)
    /// * `t1` - Time when client contacts server to extend lifetimes (seconds)
    /// * `t2` - Time when client contacts any server to extend lifetimes (seconds)
    /// * `sub_options_fn` - Closure to add IA_ADDR sub-options and other nested options
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use std::net::Ipv6Addr;
    /// let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    ///
    /// builder.put_ia_na(0x12345678, 3600, 7200, |b| {
    ///     b.put_ia_addr(&addr, 7200, 14400, |_| Ok(()))?;
    ///     Ok(())
    /// })?;
    /// ```
    pub fn put_ia_na<F>(
        &mut self,
        iaid: u32,
        t1: u32,
        t2: u32,
        sub_options_fn: F,
    ) -> Result<(), DhcpError>
    where
        F: FnOnce(&mut Self) -> Result<(), DhcpError>,
    {
        self.start_container(constants::OPTION_IA_NA)?;
        self.put_u32(iaid)?;
        self.put_u32(t1)?;
        self.put_u32(t2)?;
        sub_options_fn(self)?;
        self.end_container()
    }

    /// Adds an IA_TA option (Option 4) for temporary address assignment.
    ///
    /// Per RFC 3315 Section 22.5, IA_TA (Identity Association for Temporary Addresses)
    /// contains IAID and may contain IA_ADDR options. No T1/T2 timers for temporary addresses.
    ///
    /// # Arguments
    ///
    /// * `iaid` - Identity Association Identifier (arbitrary 32-bit value)
    /// * `sub_options_fn` - Closure to add IA_ADDR sub-options
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.put_ia_ta(0x87654321, |b| {
    ///     b.put_ia_addr(&temp_addr, 3600, 7200, |_| Ok(()))?;
    ///     Ok(())
    /// })?;
    /// ```
    pub fn put_ia_ta<F>(&mut self, iaid: u32, sub_options_fn: F) -> Result<(), DhcpError>
    where
        F: FnOnce(&mut Self) -> Result<(), DhcpError>,
    {
        self.start_container(constants::OPTION_IA_TA)?;
        self.put_u32(iaid)?;
        sub_options_fn(self)?;
        self.end_container()
    }

    /// Adds an IA_PD option (Option 25) for prefix delegation.
    ///
    /// Per RFC 3633, IA_PD (Identity Association for Prefix Delegation) is used by
    /// requesting routers to obtain IPv6 prefixes. Contains IAID, T1, T2, and
    /// IA_PREFIX sub-options.
    ///
    /// # Arguments
    ///
    /// * `iaid` - Identity Association Identifier (arbitrary 32-bit value)
    /// * `t1` - Time when client contacts server to extend lifetimes (seconds)
    /// * `t2` - Time when client contacts any server to extend lifetimes (seconds)
    /// * `sub_options_fn` - Closure to add IA_PREFIX sub-options
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.put_ia_pd(0xaabbccdd, 1800, 3600, |b| {
    ///     b.put_ia_prefix(&prefix_addr, 56, 3600, 7200, |_| Ok(()))?;
    ///     Ok(())
    /// })?;
    /// ```
    pub fn put_ia_pd<F>(
        &mut self,
        iaid: u32,
        t1: u32,
        t2: u32,
        sub_options_fn: F,
    ) -> Result<(), DhcpError>
    where
        F: FnOnce(&mut Self) -> Result<(), DhcpError>,
    {
        self.start_container(constants::OPTION_IA_PD)?;
        self.put_u32(iaid)?;
        self.put_u32(t1)?;
        self.put_u32(t2)?;
        sub_options_fn(self)?;
        self.end_container()
    }

    /// Adds an IA_ADDR sub-option (Option 5) within IA_NA or IA_TA.
    ///
    /// Per RFC 3315 Section 22.6, IA_ADDR specifies an IPv6 address with preferred
    /// and valid lifetimes. Appears within IA_NA or IA_TA options.
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv6 address being assigned (16 bytes)
    /// * `preferred_lifetime` - Preferred lifetime in seconds (0xFFFFFFFF = infinity)
    /// * `valid_lifetime` - Valid lifetime in seconds (0xFFFFFFFF = infinity)
    /// * `sub_options_fn` - Closure to add optional STATUS_CODE or other sub-options
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    /// builder.put_ia_addr(&addr, 7200, 14400, |_| Ok(()))?;
    /// ```
    pub fn put_ia_addr<F>(
        &mut self,
        addr: &Ipv6Addr,
        preferred_lifetime: u32,
        valid_lifetime: u32,
        sub_options_fn: F,
    ) -> Result<(), DhcpError>
    where
        F: FnOnce(&mut Self) -> Result<(), DhcpError>,
    {
        self.start_container(constants::OPTION_IAADDR)?;
        self.put_ipv6_addr(addr)?;
        self.put_u32(preferred_lifetime)?;
        self.put_u32(valid_lifetime)?;
        sub_options_fn(self)?;
        self.end_container()
    }

    /// Adds an IA_PREFIX sub-option (Option 26) within IA_PD.
    ///
    /// Per RFC 3633 Section 10, IA_PREFIX specifies an IPv6 prefix for delegation,
    /// including prefix length, lifetimes, and prefix address.
    ///
    /// # Arguments
    ///
    /// * `prefix` - IPv6 prefix address
    /// * `prefix_len` - Prefix length in bits (typically 48, 56, or 64)
    /// * `preferred_lifetime` - Preferred lifetime in seconds
    /// * `valid_lifetime` - Valid lifetime in seconds
    /// * `sub_options_fn` - Closure to add optional sub-options
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails or prefix_len > 128
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0xaabb, 0, 0, 0, 0, 0);
    /// builder.put_ia_prefix(&prefix, 56, 3600, 7200, |_| Ok(()))?;
    /// ```
    pub fn put_ia_prefix<F>(
        &mut self,
        prefix: &Ipv6Addr,
        prefix_len: u8,
        preferred_lifetime: u32,
        valid_lifetime: u32,
        sub_options_fn: F,
    ) -> Result<(), DhcpError>
    where
        F: FnOnce(&mut Self) -> Result<(), DhcpError>,
    {
        if prefix_len > 128 {
            return Err(DhcpError::V6ProtocolError {
                reason: format!("Invalid prefix length: {} (must be <= 128)", prefix_len),
            });
        }

        self.start_container(constants::OPTION_IAPREFIX)?;
        self.put_u32(preferred_lifetime)?;
        self.put_u32(valid_lifetime)?;
        self.put_u8(prefix_len)?;
        self.put_ipv6_addr(prefix)?;
        sub_options_fn(self)?;
        self.end_container()
    }

    /// Adds an OPTION_REQUEST option (Option 6, ORO) listing requested options.
    ///
    /// Per RFC 3315 Section 22.7, ORO (Option Request Option) contains a list of
    /// option codes that the client is requesting from the server.
    ///
    /// # Arguments
    ///
    /// * `requested_options` - Slice of option codes being requested
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let oro = vec![
    ///     constants::OPTION_DNS_SERVER,
    ///     constants::OPTION_DOMAIN_SEARCH,
    ///     constants::OPTION_NTP_SERVER,
    /// ];
    /// builder.put_option_request(&oro)?;
    /// ```
    pub fn put_option_request(&mut self, requested_options: &[u16]) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_ORO)?;
        for &opt_code in requested_options {
            self.put_u16(opt_code)?;
        }
        self.end_container()
    }

    /// Adds a PREFERENCE option (Option 7) indicating server preference.
    ///
    /// Per RFC 3315 Section 22.8, PREFERENCE is a single-byte value (0-255) where
    /// higher values indicate higher server preference. Clients select servers with
    /// highest preference value.
    ///
    /// # Arguments
    ///
    /// * `preference` - Preference value (0-255, where 255 is highest)
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.put_preference(255)?;  // Highest priority server
    /// ```
    pub fn put_preference(&mut self, preference: u8) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_PREFERENCE)?;
        self.put_u8(preference)?;
        self.end_container()
    }

    /// Adds an ELAPSED_TIME option (Option 8) indicating time since client started.
    ///
    /// Per RFC 3315 Section 22.9, ELAPSED_TIME contains the time (in hundredths of a
    /// second) since the client began the current DHCP transaction.
    ///
    /// # Arguments
    ///
    /// * `elapsed_time_centiseconds` - Elapsed time in 1/100th second units
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.put_elapsed_time(125)?;  // 1.25 seconds elapsed
    /// ```
    pub fn put_elapsed_time(&mut self, elapsed_time_centiseconds: u16) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_ELAPSED_TIME)?;
        self.put_u16(elapsed_time_centiseconds)?;
        self.end_container()
    }

    /// Adds a STATUS_CODE option (Option 13) indicating operation status.
    ///
    /// Per RFC 3315 Section 22.13, STATUS_CODE contains a status code (2 bytes) and
    /// optional human-readable message explaining the status.
    ///
    /// # Arguments
    ///
    /// * `status_code` - Numeric status code (0=Success, 1=UnspecFail, 2=NoAddrsAvail, etc.)
    /// * `message` - Optional status message string (may be empty)
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Success status
    /// builder.put_status_code(0, "Success")?;
    ///
    /// // No addresses available
    /// builder.put_status_code(2, "No addresses available in pool")?;
    /// ```
    pub fn put_status_code(&mut self, status_code: u16, message: &str) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_STATUS_CODE)?;
        self.put_u16(status_code)?;
        self.put_string(message)?;
        self.end_container()
    }

    /// Adds a RAPID_COMMIT option (Option 14) for two-message exchange.
    ///
    /// Per RFC 3315 Section 22.14, RAPID_COMMIT (zero-length option) signals that
    /// the client/server supports rapid commit mode, allowing address assignment in
    /// two messages (SOLICIT+REPLY) instead of four (SOLICIT, ADVERTISE, REQUEST, REPLY).
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.put_rapid_commit()?;  // Enable rapid commit mode
    /// ```
    pub fn put_rapid_commit(&mut self) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_RAPID_COMMIT)?;
        // Rapid commit is a zero-length option (no data)
        self.end_container()
    }

    /// Adds a USER_CLASS option (Option 15) identifying user class.
    ///
    /// Per RFC 3315 Section 22.15, USER_CLASS contains one or more user class data
    /// items, each prefixed with a 2-byte length.
    ///
    /// # Arguments
    ///
    /// * `user_classes` - Slice of user class strings
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails or class too long
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.put_user_class(&["engineer", "developer"])?;
    /// ```
    pub fn put_user_class(&mut self, user_classes: &[&str]) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_USER_CLASS)?;
        for class in user_classes {
            let class_bytes = class.as_bytes();
            if class_bytes.len() > 65535 {
                return Err(DhcpError::V6ProtocolError {
                    reason: format!("User class too long: {} bytes", class_bytes.len()),
                });
            }
            self.put_u16(class_bytes.len() as u16)?;
            self.put_bytes(class_bytes)?;
        }
        self.end_container()
    }

    /// Adds a VENDOR_CLASS option (Option 16) identifying vendor class.
    ///
    /// Per RFC 3315 Section 22.16, VENDOR_CLASS contains enterprise number and
    /// one or more vendor class data items.
    ///
    /// # Arguments
    ///
    /// * `enterprise_number` - IANA enterprise number
    /// * `vendor_classes` - Slice of vendor class strings
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.put_vendor_class(9, &["MSFT 5.0"])?;
    /// ```
    pub fn put_vendor_class(
        &mut self,
        enterprise_number: u32,
        vendor_classes: &[&str],
    ) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_VENDOR_CLASS)?;
        self.put_u32(enterprise_number)?;
        for class in vendor_classes {
            let class_bytes = class.as_bytes();
            if class_bytes.len() > 65535 {
                return Err(DhcpError::V6ProtocolError {
                    reason: format!("Vendor class too long: {} bytes", class_bytes.len()),
                });
            }
            self.put_u16(class_bytes.len() as u16)?;
            self.put_bytes(class_bytes)?;
        }
        self.end_container()
    }

    /// Adds a DNS_SERVERS option (Option 23) listing recursive DNS server addresses.
    ///
    /// Per RFC 3646 Section 3, DNS_SERVERS contains one or more IPv6 addresses of
    /// recursive DNS servers available to the client.
    ///
    /// # Arguments
    ///
    /// * `dns_servers` - Slice of IPv6 DNS server addresses
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let dns = vec![
    ///     Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),  // Google DNS
    ///     Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
    /// ];
    /// builder.put_dns_servers(&dns)?;
    /// ```
    pub fn put_dns_servers(&mut self, dns_servers: &[Ipv6Addr]) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_DNS_SERVER)?;
        for addr in dns_servers {
            self.put_ipv6_addr(addr)?;
        }
        self.end_container()
    }

    /// Adds a DOMAIN_LIST option (Option 24) listing DNS search domains.
    ///
    /// Per RFC 3646 Section 4, DOMAIN_LIST contains a list of domain names for
    /// DNS search list configuration. Domains are encoded in DNS name format.
    ///
    /// # Arguments
    ///
    /// * `domains` - Slice of domain name strings
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails or domain invalid
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.put_domain_list(&["example.com", "example.org"])?;
    /// ```
    pub fn put_domain_list(&mut self, domains: &[&str]) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_DOMAIN_SEARCH)?;
        for domain in domains {
            // Encode domain in DNS wire format (length-prefixed labels)
            for label in domain.split('.') {
                if label.len() > 63 {
                    return Err(DhcpError::V6ProtocolError {
                        reason: format!("Domain label too long: {}", label),
                    });
                }
                self.put_u8(label.len() as u8)?;
                self.put_bytes(label.as_bytes())?;
            }
            self.put_u8(0)?; // Null terminator for domain name
        }
        self.end_container()
    }

    /// Adds an NTP_SERVER option (Option 56) listing NTP server addresses.
    ///
    /// Per RFC 5908, NTP_SERVER contains one or more IPv6 addresses of NTP servers
    /// available to the client for time synchronization.
    ///
    /// # Arguments
    ///
    /// * `ntp_servers` - Slice of IPv6 NTP server addresses
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let ntp = vec![
    ///     Ipv6Addr::new(0x2001, 0x67c, 0x1560, 0x8003, 0, 0, 0, 1),
    /// ];
    /// builder.put_ntp_server(&ntp)?;
    /// ```
    pub fn put_ntp_server(&mut self, ntp_servers: &[Ipv6Addr]) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_NTP_SERVER)?;
        for addr in ntp_servers {
            self.put_ipv6_addr(addr)?;
        }
        self.end_container()
    }

    /// Adds an FQDN option (Option 39) for client fully qualified domain name.
    ///
    /// Per RFC 4704, FQDN option allows client to exchange its FQDN with server.
    /// Contains flags byte and domain name in DNS wire format.
    ///
    /// # Arguments
    ///
    /// * `flags` - FQDN flags (S, O, N bits per RFC 4704)
    /// * `fqdn` - Fully qualified domain name
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(DhcpError)` if encoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Flags: S=1 (server should perform AAAA update), O=0, N=0
    /// builder.put_fqdn(0x01, "client.example.com")?;
    /// ```
    pub fn put_fqdn(&mut self, flags: u8, fqdn: &str) -> Result<(), DhcpError> {
        self.start_container(constants::OPTION_FQDN)?;
        self.put_u8(flags)?;

        // Encode FQDN in DNS wire format (length-prefixed labels)
        for label in fqdn.split('.') {
            if label.is_empty() {
                continue;
            }
            if label.len() > 63 {
                return Err(DhcpError::V6ProtocolError {
                    reason: format!("FQDN label too long: {}", label),
                });
            }
            self.put_u8(label.len() as u8)?;
            self.put_bytes(label.as_bytes())?;
        }
        self.put_u8(0)?; // Null terminator for domain name

        self.end_container()
    }
}

impl Default for OptionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_option_builder() {
        let builder = OptionBuilder::new();
        assert_eq!(builder.buffer.len(), 0);
        assert_eq!(builder.container_stack.len(), 0);
    }

    #[test]
    fn test_put_u8() {
        let mut builder = OptionBuilder::new();
        builder.put_u8(42).unwrap();
        assert_eq!(builder.buffer, vec![42]);
    }

    #[test]
    fn test_put_u16_big_endian() {
        let mut builder = OptionBuilder::new();
        builder.put_u16(0x1234).unwrap();
        assert_eq!(builder.buffer, vec![0x12, 0x34]);
    }

    #[test]
    fn test_put_u32_big_endian() {
        let mut builder = OptionBuilder::new();
        builder.put_u32(0x12345678).unwrap();
        assert_eq!(builder.buffer, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_put_ipv6_addr() {
        let mut builder = OptionBuilder::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        builder.put_ipv6_addr(&addr).unwrap();
        assert_eq!(builder.buffer.len(), 16);
        assert_eq!(&builder.buffer[0..2], &[0x20, 0x01]);
        assert_eq!(&builder.buffer[2..4], &[0x0d, 0xb8]);
    }

    #[test]
    fn test_simple_option() {
        let mut builder = OptionBuilder::new();
        builder.put_preference(255).unwrap();
        let result = builder.build();

        // Expected: option_code(2) + length(2) + value(1)
        assert_eq!(result.len(), 5);
        assert_eq!(&result[0..2], &constants::OPTION_PREFERENCE.to_be_bytes());
        assert_eq!(&result[2..4], &1u16.to_be_bytes()); // Length of 1 byte
        assert_eq!(result[4], 255);
    }

    #[test]
    fn test_nested_option() {
        let mut builder = OptionBuilder::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        builder
            .put_ia_na(0x12345678, 3600, 7200, |b| {
                b.put_ia_addr(&addr, 7200, 14400, |_| Ok(()))?;
                Ok(())
            })
            .unwrap();

        let result = builder.build();

        // Verify IA_NA option code
        assert_eq!(&result[0..2], &constants::OPTION_IA_NA.to_be_bytes());

        // Verify structure contains IA_NA fields + nested IA_ADDR
        assert!(result.len() > 20); // At minimum: header(4) + iaid(4) + t1(4) + t2(4) + nested option
    }

    #[test]
    fn test_container_stack_error() {
        let mut builder = OptionBuilder::new();
        // Calling end_container without start_container should error
        let result = builder.end_container();
        assert!(result.is_err());
    }
}
