// Copyright (C) 2024 Dnsmasq Contributors
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0

//! DHCPv4 Message Parsing and Serialization
//!
//! This module provides safe, memory-safe parsing and serialization of DHCPv4 messages
//! using nom parser combinators to replace C pointer arithmetic from dhcp.c and rfc2131.c.
//!
//! ## Wire Format
//!
//! DHCPv4 messages follow RFC 2131 Section 2 packet structure:
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
//! +---------------+---------------+---------------+---------------+
//! |                            xid (4)                            |
//! +-------------------------------+-------------------------------+
//! |           secs (2)            |           flags (2)           |
//! +-------------------------------+-------------------------------+
//! |                          ciaddr  (4)                          |
//! +---------------------------------------------------------------+
//! |                          yiaddr  (4)                          |
//! +---------------------------------------------------------------+
//! |                          siaddr  (4)                          |
//! +---------------------------------------------------------------+
//! |                          giaddr  (4)                          |
//! +---------------------------------------------------------------+
//! |                                                               |
//! |                          chaddr  (16)                         |
//! |                                                               |
//! |                                                               |
//! +---------------------------------------------------------------+
//! |                                                               |
//! |                          sname   (64)                         |
//! +---------------------------------------------------------------+
//! |                                                               |
//! |                          file    (128)                        |
//! +---------------------------------------------------------------+
//! |                          options (variable)                   |
//! +---------------------------------------------------------------+
//! ```
//!
//! Fixed header: 236 bytes
//! Options field: Variable length, starting with magic cookie 0x63825363
//!
//! ## Memory Safety
//!
//! This implementation replaces C's direct struct memory access with:
//! - nom parser combinators for bounds-checked parsing
//! - BytesMut for safe buffer construction during serialization
//! - Rust's type system to prevent buffer overflows
//!
//! ## OPTION_OVERLOAD Handling
//!
//! Per RFC 2132 Section 9.3, the sname and file fields can contain options
//! when the OPTION_OVERLOAD (52) option is present with values:
//! - 1: file field contains options
//! - 2: sname field contains options
//! - 3: both fields contain options

#[cfg(test)]
use crate::dhcp::v4::constants::BOOTREQUEST;
use crate::dhcp::v4::constants::{BOOTREPLY, DHCP_CHADDR_MAX, MAGIC_COOKIE, MIN_PACKETSZ};
use crate::dhcp::v4::options::{encode_options, parse_options, DhcpOption};
use crate::error::DhcpError;
use crate::types::MacAddress;
use bytes::{BufMut, Bytes, BytesMut};
use nom::{
    bytes::complete::take,
    combinator::verify,
    number::complete::{be_u16, be_u32, be_u8},
    sequence::tuple,
    IResult,
};
use std::net::Ipv4Addr;

/// `DHCPv4` Message
///
/// Represents a complete `DHCPv4` packet with fixed header fields and variable-length options.
/// This struct provides memory-safe access to all DHCP message fields, replacing C's
/// direct struct access patterns with Rust's ownership model.
///
/// # Fields
///
/// ## Fixed Header (236 bytes)
///
/// - `op`: Message op code / message type (1 = BOOTREQUEST, 2 = BOOTREPLY)
/// - `htype`: Hardware address type (1 = Ethernet)
/// - `hlen`: Hardware address length (6 for Ethernet MAC address)
/// - `hops`: Client sets to zero, incremented by relay agents
/// - `xid`: Transaction ID, random number chosen by client
/// - `secs`: Seconds elapsed since client began address acquisition
/// - `flags`: Flags (bit 0 = broadcast flag, others reserved)
/// - `ciaddr`: Client IP address (filled in by client in BOUND, RENEW, REBINDING states)
/// - `yiaddr`: 'your' (client) IP address (filled by server in OFFER, ACK)
/// - `siaddr`: IP address of next server to use in bootstrap (TFTP server)
/// - `giaddr`: Relay agent IP address, used in booting via relay agent
/// - `chaddr`: Client hardware address (16 bytes, padded with zeros)
/// - `sname`: Optional server host name, null terminated string (64 bytes)
/// - `file`: Boot file name, null terminated string (128 bytes)
///
/// ## Variable-Length Options
///
/// - `options`: Vector of parsed DHCP options following the magic cookie
#[derive(Debug, Clone, PartialEq)]
pub struct DhcpMessage {
    /// Operation code: BOOTREQUEST (1) or BOOTREPLY (2)
    pub(crate) op: u8,

    /// Hardware address type (1 = Ethernet, see ARP section in RFC 1700)
    pub(crate) htype: u8,

    /// Hardware address length (6 for Ethernet MAC addresses)
    pub(crate) hlen: u8,

    /// Hop count, incremented by relay agents (client sets to 0)
    pub(crate) hops: u8,

    /// Transaction ID, random number chosen by client for request/reply matching
    pub(crate) xid: u32,

    /// Seconds elapsed since client began address acquisition or renewal process
    pub(crate) secs: u16,

    /// Flags field (bit 0 = broadcast flag, 0x8000; remaining bits reserved)
    pub(crate) flags: u16,

    /// Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state
    pub(crate) ciaddr: Ipv4Addr,

    /// 'Your' (client) IP address; filled by server in OFFER and ACK messages
    pub(crate) yiaddr: Ipv4Addr,

    /// IP address of next server to use in bootstrap; returned in OFFER, ACK by server
    pub(crate) siaddr: Ipv4Addr,

    /// Relay agent IP address, used in booting via a relay agent
    pub(crate) giaddr: Ipv4Addr,

    /// Client hardware address (16 bytes, first hlen bytes valid, rest zero-padded)
    pub(crate) chaddr: [u8; DHCP_CHADDR_MAX],

    /// Optional server host name, null-terminated string (64 bytes)
    /// May contain options if `OPTION_OVERLOAD` indicates sname overload
    pub(crate) sname: [u8; 64],

    /// Boot file name, null-terminated string (128 bytes)
    /// May contain options if `OPTION_OVERLOAD` indicates file overload
    pub(crate) file: [u8; 128],

    /// Parsed DHCP options (after magic cookie validation)
    pub(crate) options: Vec<DhcpOption>,
}

impl DhcpMessage {
    /// Create a new `DHCPv4` message with default values
    ///
    /// Initializes a message with zeros for all fields. The caller must populate
    /// fields as appropriate for the message type (DISCOVER, OFFER, REQUEST, etc.).
    ///
    /// # Returns
    ///
    /// A new `DhcpMessage` with all fields initialized to zero/empty.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dhcp::v4::message::DhcpMessage;
    /// use dnsmasq::dhcp::v4::constants::BOOTREQUEST;
    ///
    /// let mut msg = DhcpMessage::new();
    /// msg.set_op(BOOTREQUEST);
    /// msg.set_xid(0x12345678);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            op: 0,
            htype: 1, // Ethernet by default
            hlen: 6,  // Ethernet MAC length
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; DHCP_CHADDR_MAX],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: Vec::new(),
        }
    }

    /// Create a reply message from a request
    ///
    /// Initializes a BOOTREPLY message copying relevant fields from the request:
    /// - xid: Transaction ID (must match for client to accept reply)
    /// - flags: Broadcast flag (server must honor client's broadcast flag)
    /// - giaddr: Gateway IP (for relay agent support)
    /// - chaddr: Client hardware address (for unicast replies)
    /// - htype, hlen: Hardware address type and length
    ///
    /// The caller must set yiaddr, siaddr, and add appropriate options.
    ///
    /// # Arguments
    ///
    /// * `request` - The client's request message (DISCOVER or REQUEST)
    ///
    /// # Returns
    ///
    /// A new reply message with fields copied from the request.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dhcp::v4::message::DhcpMessage;
    ///
    /// let request = DhcpMessage::new(); // Assume this was parsed from network
    /// let mut reply = DhcpMessage::new_reply(&request);
    /// reply.set_yiaddr("192.168.1.100".parse().unwrap());
    /// ```
    #[must_use]
    pub fn new_reply(request: &DhcpMessage) -> Self {
        let mut reply = Self::new();
        reply.op = BOOTREPLY;
        reply.htype = request.htype;
        reply.hlen = request.hlen;
        reply.xid = request.xid;
        reply.flags = request.flags;
        reply.giaddr = request.giaddr;
        reply.chaddr = request.chaddr;
        reply
    }

    /// Parse a `DHCPv4` message from wire format
    ///
    /// Uses nom parser combinators for safe, bounds-checked parsing. This replaces
    /// the C implementation's direct struct overlay and pointer arithmetic with
    /// memory-safe parsing that prevents buffer overflows.
    ///
    /// # Wire Format Parsing
    ///
    /// 1. Fixed header (236 bytes): Parses all standard DHCP fields
    /// 2. Magic cookie validation: Verifies 0x63825363 at start of options
    /// 3. Options parsing: Extracts variable-length options with TLV encoding
    /// 4. `OPTION_OVERLOAD` handling: If present, also parses options from sname/file
    ///
    /// # Arguments
    ///
    /// * `input` - Raw bytes from network (UDP payload)
    ///
    /// # Returns
    ///
    /// Returns `Ok(DhcpMessage)` on successful parse, or `Err(DhcpError)` if:
    /// - Packet is too short (< 236 bytes for fixed header)
    /// - Magic cookie is invalid (not 0x63825363)
    /// - Options parsing fails (malformed TLV encoding)
    /// - Buffer overrun detected during parsing
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dhcp::v4::message::DhcpMessage;
    ///
    /// let packet: &[u8] = &[/* UDP payload */];
    /// match DhcpMessage::parse_dhcp_message(packet) {
    ///     Ok(msg) => println!("Parsed message with xid: {:x}", msg.transaction_id()),
    ///     Err(e) => eprintln!("Parse error: {}", e),
    /// }
    /// ```
    #[allow(clippy::similar_names)] // RFC 2131 standard field names: ciaddr, yiaddr, siaddr, giaddr, chaddr
    pub fn parse_dhcp_message(input: &[u8]) -> Result<Self, DhcpError> {
        // Check minimum packet size (236 bytes fixed header + 4 bytes magic cookie)
        if input.len() < 240 {
            return Err(DhcpError::ParseFailed {
                reason: format!(
                    "Packet too short: {} bytes (minimum 240 bytes required)",
                    input.len()
                ),
            });
        }

        // Parse fixed header using nom combinators for safe, bounds-checked parsing
        let (remaining, (op, htype, hlen, hops, xid, secs, flags)) =
            parse_fixed_header_part1(input).map_err(|e| DhcpError::ParseFailed {
                reason: format!("Failed to parse header part 1: {e}"),
            })?;

        // Parse IPv4 addresses (ciaddr, yiaddr, siaddr, giaddr)
        let (remaining, (ciaddr, yiaddr, siaddr, giaddr)) = parse_ipv4_addresses(remaining)
            .map_err(|e| DhcpError::ParseFailed {
                reason: format!("Failed to parse IP addresses: {e}"),
            })?;

        // Parse chaddr (16 bytes), sname (64 bytes), file (128 bytes)
        let (remaining, chaddr_sname_file) = parse_variable_fields(remaining).map_err(|e| {
            DhcpError::ParseFailed { reason: format!("Failed to parse variable fields: {e}") }
        })?;
        let (chaddr, sname, file) = chaddr_sname_file;

        // Verify and consume magic cookie (0x63825363)
        let (remaining, _cookie) = verify(be_u32, |&cookie| cookie == MAGIC_COOKIE)(remaining)
            .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| DhcpError::ParseFailed {
                reason: format!(
                    "Invalid magic cookie: expected 0x{:08X}, found 0x{:08X}",
                    MAGIC_COOKIE,
                    if remaining.len() >= 4 {
                        u32::from_be_bytes([remaining[0], remaining[1], remaining[2], remaining[3]])
                    } else {
                        0
                    }
                ),
            })?;

        // Parse options from the options field
        let mut options = parse_options(remaining)?;

        // Handle OPTION_OVERLOAD (52) if present
        // This option indicates that sname and/or file fields contain options
        if let Some(overload_value) = find_overload_value(&options) {
            // Remove the overload option itself as it's metadata, not a real option
            options.retain(|opt| !matches!(opt, DhcpOption::Overload(_)));

            // Parse additional options from sname field if overload indicates it
            if overload_value == 2 || overload_value == 3 {
                let sname_options = parse_options(&sname)?;
                options.extend(sname_options);
            }

            // Parse additional options from file field if overload indicates it
            if overload_value == 1 || overload_value == 3 {
                let file_options = parse_options(&file)?;
                options.extend(file_options);
            }
        }

        Ok(Self {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            options,
        })
    }

    /// Serialize `DHCPv4` message to wire format
    ///
    /// Constructs a wire-format DHCP packet suitable for network transmission.
    /// Uses `BytesMut` for safe buffer management, replacing C's manual pointer
    /// manipulation with bounds-checked buffer operations.
    ///
    /// # Wire Format Construction
    ///
    /// 1. Fixed header (236 bytes): All fields in network byte order
    /// 2. Magic cookie (4 bytes): 0x63825363
    /// 3. Options (variable): TLV-encoded options with `OPTION_END`
    /// 4. Padding: Zeros to reach `MIN_PACKETSZ` (300 bytes) for Linux compatibility
    ///
    /// # Minimum Packet Size
    ///
    /// Linux kernel requires DHCP packets to be at least 300 bytes (`MIN_PACKETSZ`).
    /// Packets shorter than this are rejected. This function automatically pads
    /// with zeros to meet this requirement.
    ///
    /// # Returns
    ///
    /// Returns `Bytes` containing the complete wire-format packet ready for `sendto()`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dhcp::v4::message::DhcpMessage;
    ///
    /// let msg = DhcpMessage::new();
    /// let packet = msg.serialize_dhcp_message();
    /// // packet can now be sent via UDP socket
    /// ```
    #[must_use]
    pub fn serialize_dhcp_message(&self) -> Bytes {
        // Pre-allocate buffer with minimum packet size to avoid reallocations
        let mut buf = BytesMut::with_capacity(MIN_PACKETSZ);

        // Write fixed header (236 bytes) in network byte order
        buf.put_u8(self.op);
        buf.put_u8(self.htype);
        buf.put_u8(self.hlen);
        buf.put_u8(self.hops);
        buf.put_u32(self.xid);
        buf.put_u16(self.secs);
        buf.put_u16(self.flags);

        // Write IPv4 addresses (4 bytes each)
        buf.put_slice(&self.ciaddr.octets());
        buf.put_slice(&self.yiaddr.octets());
        buf.put_slice(&self.siaddr.octets());
        buf.put_slice(&self.giaddr.octets());

        // Write chaddr (16 bytes)
        buf.put_slice(&self.chaddr);

        // Write sname (64 bytes)
        buf.put_slice(&self.sname);

        // Write file (128 bytes)
        buf.put_slice(&self.file);

        // Write magic cookie (4 bytes)
        buf.put_u32(MAGIC_COOKIE);

        // Encode options to wire format
        let encoded_options = encode_options(&self.options);
        buf.put_slice(&encoded_options);

        // Pad to MIN_PACKETSZ if necessary for Linux kernel compatibility
        // The Linux DHCP client/server code expects at least 300 bytes
        if buf.len() < MIN_PACKETSZ {
            buf.resize(MIN_PACKETSZ, 0);
        }

        buf.freeze()
    }

    // ========================================================================
    // Getter Methods - Provide safe, immutable access to message fields
    // ========================================================================

    /// Get the operation code (BOOTREQUEST=1 or BOOTREPLY=2)
    #[inline]
    #[must_use]
    pub fn operation_code(&self) -> u8 {
        self.op
    }

    /// Get the transaction ID (xid)
    ///
    /// The transaction ID is a random number chosen by the client used to
    /// match requests with replies.
    #[inline]
    #[must_use]
    pub fn transaction_id(&self) -> u32 {
        self.xid
    }

    /// Get the hardware address type
    #[inline]
    #[must_use]
    pub fn htype(&self) -> u8 {
        self.htype
    }

    /// Get the hardware address length
    #[inline]
    #[must_use]
    pub fn hlen(&self) -> u8 {
        self.hlen
    }

    /// Get the hop count
    #[inline]
    #[must_use]
    pub fn hops(&self) -> u8 {
        self.hops
    }

    /// Get the seconds elapsed since client began acquisition
    #[inline]
    #[must_use]
    pub fn secs(&self) -> u16 {
        self.secs
    }

    /// Get the flags field (bit 0 = broadcast flag)
    #[inline]
    #[must_use]
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Get the client IP address (ciaddr)
    #[inline]
    #[must_use]
    pub fn ciaddr(&self) -> Ipv4Addr {
        self.ciaddr
    }

    /// Get the 'your' (client) IP address (yiaddr)
    ///
    /// This is the IP address offered or assigned by the server.
    #[inline]
    #[must_use]
    pub fn yiaddr(&self) -> Ipv4Addr {
        self.yiaddr
    }

    /// Get the server IP address (siaddr)
    ///
    /// This is typically the TFTP server address for network booting.
    #[inline]
    #[must_use]
    pub fn siaddr(&self) -> Ipv4Addr {
        self.siaddr
    }

    /// Get the relay agent IP address (giaddr)
    #[inline]
    #[must_use]
    pub fn giaddr(&self) -> Ipv4Addr {
        self.giaddr
    }

    /// Get the client hardware address as a slice
    ///
    /// Returns a slice of the first `hlen` bytes of the chaddr field.
    /// For Ethernet, this is typically 6 bytes (MAC address).
    #[must_use]
    pub fn chaddr(&self) -> &[u8] {
        #[allow(clippy::cast_possible_truncation)] // DHCP_CHADDR_MAX is 16, fits in u8
        let len = self.hlen.min(DHCP_CHADDR_MAX as u8) as usize;
        &self.chaddr[..len]
    }

    /// Get the client hardware address as a `MacAddress`
    ///
    /// Converts the chaddr field to a `MacAddress` type for type-safe handling.
    /// Only the first `hlen` bytes are considered valid.
    ///
    /// # Returns
    ///
    /// Returns `Ok(MacAddress)` if hlen is valid, or `Err(DhcpError)` if the
    /// hardware address length is invalid.
    pub fn client_hardware_addr(&self) -> Result<MacAddress, DhcpError> {
        if self.hlen != 6 {
            return Err(DhcpError::ParseFailed {
                reason: format!("Invalid hardware address length: expected 6, found {}", self.hlen),
            });
        }

        let mac_bytes: [u8; 6] =
            self.chaddr[..6].try_into().map_err(|_| DhcpError::ParseFailed {
                reason: "Failed to convert hardware address to MAC format".to_string(),
            })?;

        Ok(MacAddress::from_bytes(mac_bytes))
    }

    /// Get the server name field as a slice
    #[inline]
    #[must_use]
    pub fn sname(&self) -> &[u8] {
        &self.sname
    }

    /// Get the boot file name field as a slice
    #[inline]
    #[must_use]
    pub fn file(&self) -> &[u8] {
        &self.file
    }

    /// Get all options
    #[inline]
    #[must_use]
    pub fn options(&self) -> &[DhcpOption] {
        &self.options
    }

    /// Get a specific option by matching its type
    ///
    /// Searches the options list for an option matching the provided predicate.
    /// This replaces C's `option_find()` pointer walking with iterator-based searching.
    ///
    /// # Arguments
    ///
    /// * `predicate` - A function that returns true for the desired option
    ///
    /// # Returns
    ///
    /// Returns `Some(&DhcpOption)` if found, or `None` if not present.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dhcp::v4::message::DhcpMessage;
    /// use dnsmasq::dhcp::v4::options::DhcpOption;
    ///
    /// let msg = DhcpMessage::new();
    /// if let Some(DhcpOption::MessageType(msg_type)) = msg.get_option(|opt| {
    ///     matches!(opt, DhcpOption::MessageType(_))
    /// }) {
    ///     println!("Message type: {:?}", msg_type);
    /// }
    /// ```
    pub fn get_option<F>(&self, predicate: F) -> Option<&DhcpOption>
    where
        F: Fn(&DhcpOption) -> bool,
    {
        self.options.iter().find(|&opt| predicate(opt))
    }

    /// Get the requested IP address from options (option 50)
    ///
    /// Convenience method to extract the requested IP address option.
    ///
    /// # Returns
    ///
    /// Returns `Some(Ipv4Addr)` if the option is present, or `None` otherwise.
    #[must_use]
    pub fn requested_ip_address(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|opt| {
            if let DhcpOption::RequestedIpAddress(addr) = opt {
                Some(*addr)
            } else {
                None
            }
        })
    }

    /// Get the server identifier from options (option 54)
    ///
    /// Convenience method to extract the server identifier option.
    ///
    /// # Returns
    ///
    /// Returns `Some(Ipv4Addr)` if the option is present, or `None` otherwise.
    #[must_use]
    pub fn server_identifier(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|opt| {
            if let DhcpOption::ServerId(addr) = opt {
                Some(*addr)
            } else {
                None
            }
        })
    }

    // ========================================================================
    // Setter Methods - Provide safe, mutable access to modify message fields
    // ========================================================================

    /// Set the operation code
    #[inline]
    pub fn set_op(&mut self, op: u8) {
        self.op = op;
    }

    /// Set the transaction ID
    #[inline]
    pub fn set_xid(&mut self, xid: u32) {
        self.xid = xid;
    }

    /// Set the 'your' (client) IP address (yiaddr)
    ///
    /// This is the IP address being offered or assigned to the client.
    #[inline]
    pub fn set_yiaddr(&mut self, addr: Ipv4Addr) {
        self.yiaddr = addr;
    }

    /// Set the server IP address (siaddr)
    ///
    /// This is typically set to the TFTP server address for network booting.
    #[inline]
    pub fn set_siaddr(&mut self, addr: Ipv4Addr) {
        self.siaddr = addr;
    }

    /// Set the client IP address (ciaddr)
    #[inline]
    pub fn set_ciaddr(&mut self, addr: Ipv4Addr) {
        self.ciaddr = addr;
    }

    /// Set the gateway IP address (giaddr)
    #[inline]
    pub fn set_giaddr(&mut self, addr: Ipv4Addr) {
        self.giaddr = addr;
    }

    /// Set the flags field
    #[inline]
    pub fn set_flags(&mut self, flags: u16) {
        self.flags = flags;
    }

    /// Add an option to the message
    ///
    /// Appends an option to the options list. Options are serialized in the
    /// order they are added during message serialization.
    ///
    /// # Arguments
    ///
    /// * `option` - The option to add
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dhcp::v4::message::DhcpMessage;
    /// use dnsmasq::dhcp::v4::options::{DhcpOption, MessageType};
    ///
    /// let mut msg = DhcpMessage::new();
    /// msg.add_option(DhcpOption::MessageType(MessageType::Offer));
    /// msg.add_option(DhcpOption::ServerId("192.168.1.1".parse().unwrap()));
    /// ```
    pub fn add_option(&mut self, option: DhcpOption) {
        self.options.push(option);
    }

    /// Set the client hardware address
    ///
    /// Copies the provided MAC address into the chaddr field and updates hlen.
    ///
    /// # Arguments
    ///
    /// * `mac` - The MAC address to set
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dhcp::v4::message::DhcpMessage;
    /// use dnsmasq::types::MacAddress;
    ///
    /// let mut msg = DhcpMessage::new();
    /// let mac = MacAddress::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    /// msg.set_chaddr(&mac);
    /// ```
    pub fn set_chaddr(&mut self, mac: &MacAddress) {
        let bytes = mac.as_bytes();
        let len = bytes.len().min(DHCP_CHADDR_MAX);
        self.chaddr[..len].copy_from_slice(&bytes[..len]);
        #[allow(clippy::cast_possible_truncation)] // len is min(bytes.len(), 16), guaranteed ≤ 16
        {
            self.hlen = len as u8;
        }
    }
}

// ============================================================================
// Private Helper Functions for Parsing
// ============================================================================

/// Type alias for the first part of DHCP fixed header parsing result
type HeaderPart1 = (u8, u8, u8, u8, u32, u16, u16);

/// Type alias for variable fields parsing result (chaddr, sname, file)
type VariableFields = ([u8; DHCP_CHADDR_MAX], [u8; 64], [u8; 128]);

/// Parse the first part of the fixed header (16 bytes)
///
/// Parses: op, htype, hlen, hops, xid, secs, flags
fn parse_fixed_header_part1(input: &[u8]) -> IResult<&[u8], HeaderPart1> {
    tuple((be_u8, be_u8, be_u8, be_u8, be_u32, be_u16, be_u16))(input)
}

/// Parse the four IPv4 addresses (16 bytes total)
///
/// Parses: ciaddr, yiaddr, siaddr, giaddr
fn parse_ipv4_addresses(input: &[u8]) -> IResult<&[u8], (Ipv4Addr, Ipv4Addr, Ipv4Addr, Ipv4Addr)> {
    let (input, ciaddr_bytes) = take(4usize)(input)?;
    let (input, yiaddr_bytes) = take(4usize)(input)?;
    let (input, siaddr_bytes) = take(4usize)(input)?;
    let (input, giaddr_bytes) = take(4usize)(input)?;

    let ciaddr = Ipv4Addr::new(ciaddr_bytes[0], ciaddr_bytes[1], ciaddr_bytes[2], ciaddr_bytes[3]);
    let yiaddr = Ipv4Addr::new(yiaddr_bytes[0], yiaddr_bytes[1], yiaddr_bytes[2], yiaddr_bytes[3]);
    let siaddr = Ipv4Addr::new(siaddr_bytes[0], siaddr_bytes[1], siaddr_bytes[2], siaddr_bytes[3]);
    let giaddr = Ipv4Addr::new(giaddr_bytes[0], giaddr_bytes[1], giaddr_bytes[2], giaddr_bytes[3]);

    Ok((input, (ciaddr, yiaddr, siaddr, giaddr)))
}

/// Parse variable-length fields: chaddr, sname, file (208 bytes total)
///
/// Parses: chaddr (16 bytes), sname (64 bytes), file (128 bytes)
fn parse_variable_fields(input: &[u8]) -> IResult<&[u8], VariableFields> {
    let (input, chaddr_bytes) = take(DHCP_CHADDR_MAX)(input)?;
    let (input, sname_bytes) = take(64usize)(input)?;
    let (input, file_bytes) = take(128usize)(input)?;

    let mut chaddr = [0u8; DHCP_CHADDR_MAX];
    chaddr.copy_from_slice(chaddr_bytes);

    let mut sname = [0u8; 64];
    sname.copy_from_slice(sname_bytes);

    let mut file = [0u8; 128];
    file.copy_from_slice(file_bytes);

    Ok((input, (chaddr, sname, file)))
}

/// Find the overload option value if present
///
/// Searches the options list for `OPTION_OVERLOAD` (52) and returns its value.
///
/// # Returns
///
/// - `Some(1)`: file field contains options
/// - `Some(2)`: sname field contains options
/// - `Some(3)`: both fields contain options
/// - `None`: no overload option present
fn find_overload_value(options: &[DhcpOption]) -> Option<u8> {
    options.iter().find_map(
        |opt| {
            if let DhcpOption::Overload(value) = opt {
                Some(*value)
            } else {
                None
            }
        },
    )
}

impl Default for DhcpMessage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::v4::options::MessageType;

    #[test]
    fn test_new_message() {
        let msg = DhcpMessage::new();
        assert_eq!(msg.op, 0);
        assert_eq!(msg.htype, 1); // Ethernet
        assert_eq!(msg.hlen, 6); // MAC address length
        assert_eq!(msg.xid, 0);
        assert_eq!(msg.yiaddr, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_new_reply() {
        let mut request = DhcpMessage::new();
        request.op = BOOTREQUEST;
        request.xid = 0x12345678;
        request.flags = 0x8000; // Broadcast flag
        request.chaddr[0] = 0xAA;
        request.chaddr[1] = 0xBB;

        let reply = DhcpMessage::new_reply(&request);
        assert_eq!(reply.op, BOOTREPLY);
        assert_eq!(reply.xid, 0x12345678);
        assert_eq!(reply.flags, 0x8000);
        assert_eq!(reply.chaddr[0], 0xAA);
        assert_eq!(reply.chaddr[1], 0xBB);
    }

    #[test]
    fn test_serialize_minimum_size() {
        let msg = DhcpMessage::new();
        let serialized = msg.serialize_dhcp_message();

        // Must be at least MIN_PACKETSZ (300 bytes) for Linux compatibility
        assert!(serialized.len() >= MIN_PACKETSZ);
    }

    #[test]
    fn test_parse_and_serialize_roundtrip() {
        let mut original = DhcpMessage::new();
        original.op = BOOTREQUEST;
        original.xid = 0xABCD1234;
        original.secs = 10;
        original.flags = 0x8000;
        original.ciaddr = Ipv4Addr::new(192, 168, 1, 100);
        original.add_option(DhcpOption::MessageType(MessageType::Discover));

        let serialized = original.serialize_dhcp_message();
        let parsed = DhcpMessage::parse_dhcp_message(&serialized).unwrap();

        assert_eq!(parsed.op, original.op);
        assert_eq!(parsed.xid, original.xid);
        assert_eq!(parsed.secs, original.secs);
        assert_eq!(parsed.flags, original.flags);
        assert_eq!(parsed.ciaddr, original.ciaddr);
    }

    #[test]
    fn test_invalid_magic_cookie() {
        let mut packet = vec![0u8; 240];
        // Set op to BOOTREQUEST
        packet[0] = BOOTREQUEST;
        // Set invalid magic cookie at offset 236
        packet[236] = 0xFF;
        packet[237] = 0xFF;
        packet[238] = 0xFF;
        packet[239] = 0xFF;

        let result = DhcpMessage::parse_dhcp_message(&packet);
        assert!(result.is_err());
        // Should fail with ParseFailed containing "Invalid magic cookie" message
        match result {
            Err(DhcpError::ParseFailed { reason }) => {
                assert!(
                    reason.contains("Invalid magic cookie"),
                    "Expected magic cookie error, got: {}",
                    reason
                );
            }
            other => panic!("Expected ParseFailed with magic cookie error, got: {:?}", other),
        }
    }

    #[test]
    fn test_packet_too_short() {
        let packet = vec![0u8; 100]; // Too short
        let result = DhcpMessage::parse_dhcp_message(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_option() {
        let mut msg = DhcpMessage::new();
        msg.add_option(DhcpOption::MessageType(MessageType::Offer));
        msg.add_option(DhcpOption::LeaseTime(3600));

        assert_eq!(msg.options.len(), 2);
        assert!(matches!(msg.options[0], DhcpOption::MessageType(MessageType::Offer)));
        assert!(matches!(msg.options[1], DhcpOption::LeaseTime(3600)));
    }

    #[test]
    fn test_requested_ip_address() {
        let mut msg = DhcpMessage::new();
        let requested_ip = Ipv4Addr::new(192, 168, 1, 50);
        msg.add_option(DhcpOption::RequestedIpAddress(requested_ip));

        assert_eq!(msg.requested_ip_address(), Some(requested_ip));
    }

    #[test]
    fn test_server_identifier() {
        let mut msg = DhcpMessage::new();
        let server_id = Ipv4Addr::new(192, 168, 1, 1);
        msg.add_option(DhcpOption::ServerId(server_id));

        assert_eq!(msg.server_identifier(), Some(server_id));
    }

    #[test]
    fn test_getters() {
        let mut msg = DhcpMessage::new();
        msg.op = BOOTREQUEST;
        msg.xid = 0x11223344;
        msg.secs = 42;
        msg.flags = 0x8000;
        msg.htype = 1;
        msg.hlen = 6;
        msg.hops = 2;

        assert_eq!(msg.operation_code(), BOOTREQUEST);
        assert_eq!(msg.transaction_id(), 0x11223344);
        assert_eq!(msg.secs(), 42);
        assert_eq!(msg.flags(), 0x8000);
        assert_eq!(msg.htype(), 1);
        assert_eq!(msg.hlen(), 6);
        assert_eq!(msg.hops(), 2);
    }

    #[test]
    fn test_setters() {
        let mut msg = DhcpMessage::new();

        msg.set_op(BOOTREPLY);
        msg.set_xid(0xDEADBEEF);
        msg.set_yiaddr(Ipv4Addr::new(192, 168, 1, 100));
        msg.set_siaddr(Ipv4Addr::new(192, 168, 1, 1));
        msg.set_flags(0x8000);

        assert_eq!(msg.op, BOOTREPLY);
        assert_eq!(msg.xid, 0xDEADBEEF);
        assert_eq!(msg.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(msg.siaddr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(msg.flags, 0x8000);
    }
}
