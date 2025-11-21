// Copyright (c) 2000-2025 Simon Kelley
// Copyright (c) 2025 Dnsmasq Rust Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

//! DNS Message Structure and Parsing (RFC 1035)
//!
//! This module provides complete DNS packet representation, parsing, and serialization
//! per RFC 1035. It replaces C struct dns_header and packet parsing functions from
//! rfc1035.c with type-safe Rust structs and Result-based error handling.
//!
//! # Key Types
//!
//! - [`DnsFlags`]: DNS header flags with bitfield methods for QR, AA, TC, RD, RA, AD, CD, RCODE
//! - [`DnsHeader`]: DNS message header (12 bytes) with ID, flags, and section counts
//! - [`Question`]: DNS question section entry (QNAME, QTYPE, QCLASS)
//! - [`DnsMessage`]: Complete DNS packet with header and all sections
//! - [`DnsMessageBuilder`]: Fluent API for constructing DNS messages
//! - [`DnsQuery`]: Type alias for query extraction from messages
//! - [`DnsResponse`]: Wrapper for response message construction
//!
//! # Example: Parsing a DNS Message
//!
//! ```rust,ignore
//! use dnsmasq::dns::protocol::message::DnsMessage;
//!
//! let packet = receive_dns_packet();
//! let message = DnsMessage::from_bytes(&packet)?;
//!
//! println!("Query ID: {}", message.id());
//! println!("Is query: {}", message.is_query());
//! println!("Question count: {}", message.qdcount());
//! ```
//!
//! # Example: Building a DNS Response
//!
//! ```rust,ignore
//! use dnsmasq::dns::protocol::message::{DnsMessage, Question};
//! use dnsmasq::dns::protocol::name::DomainName;
//! use dnsmasq::types::RecordType;
//!
//! let response = DnsMessage::builder()
//!     .id(12345)
//!     .set_response()
//!     .set_authoritative()
//!     .add_question(Question::new(
//!         DomainName::from_str("example.com")?,
//!         RecordType::A,
//!         1,  // IN class
//!     ))
//!     .build();
//!
//! let packet_bytes = response.to_bytes()?;
//! ```

use bytes::{BufMut, BytesMut};

use super::compression::{compress_name, decompress_name, CompressionMap};
use super::constants::*;
use super::name::DomainName;
use super::record::ResourceRecord;
use crate::error::{DnsError, DnsmasqError, Result};
use crate::types::RecordType;

/// DNS header flags represented as a 16-bit field with bitfield access methods.
///
/// The flags field contains:
/// - Byte 3 (HB3): QR (1 bit), OPCODE (4 bits), AA, TC, RD (1 bit each)
/// - Byte 4 (HB4): RA, Z (must be 0), AD, CD (DNSSEC), RCODE (4 bits)
///
/// This replaces C manual bit manipulation with type-safe methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsFlags {
    raw: u16,
}

impl DnsFlags {
    /// Create new flags with all bits cleared.
    #[must_use]
    pub fn new() -> Self {
        Self { raw: 0 }
    }

    /// Create flags from raw 16-bit value.
    #[must_use]
    pub fn from_raw(raw: u16) -> Self {
        Self { raw }
    }

    /// Create flags from two header bytes (byte 3 and byte 4).
    #[must_use]
    pub fn from_bytes(hb3: u8, hb4: u8) -> Self {
        let raw = ((hb3 as u16) << 8) | (hb4 as u16);
        Self { raw }
    }

    /// Get raw 16-bit flags value.
    pub fn raw(&self) -> u16 {
        self.raw
    }

    /// Convert flags to two header bytes (hb3, hb4).
    pub fn to_bytes(&self) -> (u8, u8) {
        let hb3 = (self.raw >> 8) as u8;
        let hb4 = (self.raw & 0xFF) as u8;
        (hb3, hb4)
    }

    /// Get QR bit: false = query, true = response.
    pub fn qr(&self) -> bool {
        (self.raw & 0x8000) != 0
    }

    /// Set QR bit: false = query, true = response.
    pub fn set_qr(&mut self, value: bool) {
        if value {
            self.raw |= 0x8000;
        } else {
            self.raw &= !0x8000;
        }
    }

    /// Get OPCODE (4 bits): 0=QUERY, 1=IQUERY, 2=STATUS, 3=reserved, 4=NOTIFY, 5=UPDATE.
    pub fn opcode(&self) -> u8 {
        ((self.raw >> 11) & 0x0F) as u8
    }

    /// Set OPCODE (4 bits).
    pub fn set_opcode(&mut self, value: u8) {
        self.raw = (self.raw & !0x7800) | (((value & 0x0F) as u16) << 11);
    }

    /// Get AA bit: Authoritative Answer.
    pub fn aa(&self) -> bool {
        (self.raw & 0x0400) != 0
    }

    /// Set AA bit: Authoritative Answer.
    pub fn set_aa(&mut self, value: bool) {
        if value {
            self.raw |= 0x0400;
        } else {
            self.raw &= !0x0400;
        }
    }

    /// Get TC bit: Truncated (packet too large for UDP).
    pub fn tc(&self) -> bool {
        (self.raw & 0x0200) != 0
    }

    /// Set TC bit: Truncated.
    pub fn set_tc(&mut self, value: bool) {
        if value {
            self.raw |= 0x0200;
        } else {
            self.raw &= !0x0200;
        }
    }

    /// Get RD bit: Recursion Desired.
    pub fn rd(&self) -> bool {
        (self.raw & 0x0100) != 0
    }

    /// Set RD bit: Recursion Desired.
    pub fn set_rd(&mut self, value: bool) {
        if value {
            self.raw |= 0x0100;
        } else {
            self.raw &= !0x0100;
        }
    }

    /// Get RA bit: Recursion Available.
    pub fn ra(&self) -> bool {
        (self.raw & 0x0080) != 0
    }

    /// Set RA bit: Recursion Available.
    pub fn set_ra(&mut self, value: bool) {
        if value {
            self.raw |= 0x0080;
        } else {
            self.raw &= !0x0080;
        }
    }

    /// Get AD bit: Authenticated Data (DNSSEC).
    pub fn ad(&self) -> bool {
        (self.raw & 0x0020) != 0
    }

    /// Set AD bit: Authenticated Data (DNSSEC).
    pub fn set_ad(&mut self, value: bool) {
        if value {
            self.raw |= 0x0020;
        } else {
            self.raw &= !0x0020;
        }
    }

    /// Get CD bit: Checking Disabled (DNSSEC).
    pub fn cd(&self) -> bool {
        (self.raw & 0x0010) != 0
    }

    /// Set CD bit: Checking Disabled (DNSSEC).
    pub fn set_cd(&mut self, value: bool) {
        if value {
            self.raw |= 0x0010;
        } else {
            self.raw &= !0x0010;
        }
    }

    /// Get RCODE (4 bits): Response code (0=NOERROR, 1=FORMERR, 2=SERVFAIL, 3=NXDOMAIN, etc.).
    pub fn rcode(&self) -> u8 {
        (self.raw & 0x000F) as u8
    }

    /// Set RCODE (4 bits): Response code.
    pub fn set_rcode(&mut self, value: u8) {
        self.raw = (self.raw & !0x000F) | ((value & 0x0F) as u16);
    }
}

impl Default for DnsFlags {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS message header (12 bytes) per RFC 1035 Section 4.1.1.
///
/// Contains:
/// - ID: 16-bit identifier for matching queries/responses
/// - FLAGS: 16-bit flags field (QR, OPCODE, AA, TC, RD, RA, Z, AD, CD, RCODE)
/// - QDCOUNT: Number of entries in question section
/// - ANCOUNT: Number of resource records in answer section
/// - NSCOUNT: Number of name server records in authority section
/// - ARCOUNT: Number of resource records in additional section
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    /// Message ID for matching queries with responses (16 bits)
    pub id: u16,
    /// DNS flags including QR, opcode, AA, TC, RD, RA, AD, CD, and RCODE
    pub flags: DnsFlags,
    /// Number of entries in question section
    pub qdcount: u16,
    /// Number of resource records in answer section
    pub ancount: u16,
    /// Number of resource records in authority section
    pub nscount: u16,
    /// Number of resource records in additional section
    pub arcount: u16,
}

impl DnsHeader {
    /// Create new DNS header with given ID and all counts set to zero.
    #[must_use]
    pub fn new(id: u16) -> Self {
        Self { id, flags: DnsFlags::new(), qdcount: 0, ancount: 0, nscount: 0, arcount: 0 }
    }

    /// Parse DNS header from 12-byte slice.
    ///
    /// Returns the header or DnsError::ParseFailed if input is too short.
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        if input.len() < 12 {
            return Err(DnsmasqError::Dns(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: "DNS header too short (need 12 bytes)".to_string(),
            }));
        }

        let id = u16::from_be_bytes([input[0], input[1]]);
        let flags = DnsFlags::from_bytes(input[2], input[3]);
        let qdcount = u16::from_be_bytes([input[4], input[5]]);
        let ancount = u16::from_be_bytes([input[6], input[7]]);
        let nscount = u16::from_be_bytes([input[8], input[9]]);
        let arcount = u16::from_be_bytes([input[10], input[11]]);

        Ok(Self { id, flags, qdcount, ancount, nscount, arcount })
    }

    /// Serialize DNS header to 12 bytes.
    pub fn to_bytes(&self, buf: &mut BytesMut) {
        buf.put_u16(self.id);
        let (hb3, hb4) = self.flags.to_bytes();
        buf.put_u8(hb3);
        buf.put_u8(hb4);
        buf.put_u16(self.qdcount);
        buf.put_u16(self.ancount);
        buf.put_u16(self.nscount);
        buf.put_u16(self.arcount);
    }
}

/// DNS question section entry.
///
/// Contains:
/// - QNAME: Domain name being queried
/// - QTYPE: Query type (A, AAAA, CNAME, etc.)
/// - QCLASS: Query class (typically IN = 1 for Internet)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Domain name being queried (e.g., "example.com")
    pub qname: DomainName,
    /// Query type (A, AAAA, CNAME, MX, etc.)
    pub qtype: RecordType,
    /// Query class (1 = IN for Internet, typically always 1)
    pub qclass: u16,
}

impl Question {
    /// Create new question with given name, type, and class.
    #[must_use]
    pub fn new(qname: DomainName, qtype: RecordType, qclass: u16) -> Self {
        Self { qname, qtype, qclass }
    }

    /// Parse question from wire format.
    ///
    /// Returns (Question, bytes_consumed) or error.
    /// packet parameter is the full packet for decompression.
    pub fn from_bytes(input: &[u8], packet: &[u8], offset: usize) -> Result<(Self, usize)> {
        // Decompress domain name - returns (absolute_offset_after_name, domain_name_string)
        let (name_end_offset, name_string) =
            decompress_name(packet, offset).map_err(DnsmasqError::Dns)?;

        // Calculate bytes consumed by the name (relative to input)
        let name_bytes_consumed = name_end_offset - offset;
        let remaining = &input[name_bytes_consumed..];

        // Parse QTYPE and QCLASS (4 bytes total)
        if remaining.len() < 4 {
            return Err(DnsmasqError::Dns(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: "Question section truncated (need QTYPE and QCLASS)".to_string(),
            }));
        }

        let qtype_raw = u16::from_be_bytes([remaining[0], remaining[1]]);
        let qtype = RecordType::from(qtype_raw);
        let qclass = u16::from_be_bytes([remaining[2], remaining[3]]);

        // Create DomainName from the decompressed string
        let qname = DomainName::new(&name_string)?;

        let total_len = name_bytes_consumed + 4;
        Ok((Self::new(qname, qtype, qclass), total_len))
    }

    /// Serialize question to wire format with compression.
    pub fn to_bytes(&self, buf: &mut BytesMut, compression: &mut CompressionMap) -> Result<()> {
        // Compress and write QNAME
        compress_name(self.qname.as_str(), buf, Some(compression)).map_err(DnsmasqError::Dns)?;

        // Write QTYPE and QCLASS
        let qtype_val: u16 = self.qtype.into();
        buf.put_u16(qtype_val);
        buf.put_u16(self.qclass);

        Ok(())
    }
}

/// Complete DNS message with header and all sections.
///
/// Contains:
/// - Header: ID, flags, section counts
/// - Questions: Vec of question entries
/// - Answers: Vec of answer resource records
/// - Authority: Vec of authority resource records
/// - Additional: Vec of additional resource records
#[derive(Debug, Clone, PartialEq)]
pub struct DnsMessage {
    /// DNS message header with ID, flags, and section counts
    pub header: DnsHeader,
    /// Question section: domains being queried
    pub questions: Vec<Question>,
    /// Answer section: resource records answering the questions
    pub answers: Vec<ResourceRecord>,
    /// Authority section: authoritative nameserver records
    pub authority: Vec<ResourceRecord>,
    /// Additional section: additional helpful records (e.g., glue records)
    pub additional: Vec<ResourceRecord>,
}

impl DnsMessage {
    /// Create new DNS message with given ID.
    #[must_use]
    pub fn new(id: u16) -> Self {
        Self {
            header: DnsHeader::new(id),
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// Parse complete DNS message from wire format bytes.
    ///
    /// Performs complete RFC 1035 parsing:
    /// 1. Parse 12-byte header
    /// 2. Parse question section (QDCOUNT entries)
    /// 3. Parse answer section (ANCOUNT entries)
    /// 4. Parse authority section (NSCOUNT entries)
    /// 5. Parse additional section (ARCOUNT entries)
    ///
    /// Returns DnsMessage or DnsError::ParseFailed.
    pub fn from_bytes(packet: &[u8]) -> Result<Self> {
        // Parse header
        let header = DnsHeader::from_bytes(packet)?;
        let mut offset = 12; // Skip 12-byte header

        // Parse question section
        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            if offset >= packet.len() {
                return Err(DnsmasqError::Dns(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: "Packet truncated in question section".to_string(),
                }));
            }

            let (question, consumed) = Question::from_bytes(&packet[offset..], packet, offset)?;
            questions.push(question);
            offset += consumed;
        }

        // Parse answer section
        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            if offset >= packet.len() {
                return Err(DnsmasqError::Dns(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: "Packet truncated in answer section".to_string(),
                }));
            }

            let input_before = &packet[offset..];
            let (remaining, rr) = ResourceRecord::from_wire(input_before, packet).map_err(|e| {
                DnsmasqError::Dns(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: format!("Failed to parse answer RR: {:?}", e),
                })
            })?;
            let consumed = input_before.len() - remaining.len();
            answers.push(rr);
            offset += consumed;
        }

        // Parse authority section
        let mut authority = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            if offset >= packet.len() {
                return Err(DnsmasqError::Dns(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: "Packet truncated in authority section".to_string(),
                }));
            }

            let input_before = &packet[offset..];
            let (remaining, rr) =
                ResourceRecord::from_wire(input_before, packet).map_err(|_| {
                    DnsmasqError::Dns(DnsError::ParseFailed {
                        server: "local".to_string(),
                        reason: "Failed to parse authority RR".to_string(),
                    })
                })?;
            let consumed = input_before.len() - remaining.len();
            authority.push(rr);
            offset += consumed;
        }

        // Parse additional section
        let mut additional = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            if offset >= packet.len() {
                return Err(DnsmasqError::Dns(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: "Packet truncated in additional section".to_string(),
                }));
            }

            let input_before = &packet[offset..];
            let (remaining, rr) =
                ResourceRecord::from_wire(input_before, packet).map_err(|_| {
                    DnsmasqError::Dns(DnsError::ParseFailed {
                        server: "local".to_string(),
                        reason: "Failed to parse additional RR".to_string(),
                    })
                })?;
            let consumed = input_before.len() - remaining.len();
            additional.push(rr);
            offset += consumed;
        }

        Ok(Self { header, questions, answers, authority, additional })
    }

    /// Serialize complete DNS message to wire format with name compression.
    ///
    /// Builds packet with:
    /// 1. 12-byte header with section counts
    /// 2. Question section with compressed names
    /// 3. Answer section with compressed names and RDATA
    /// 4. Authority section with compressed names and RDATA
    /// 5. Additional section with compressed names and RDATA
    ///
    /// Returns packet bytes or DnsError::SerializeFailed.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(PACKETSZ);
        let mut compression = CompressionMap::new();

        // Update header counts
        let mut header = self.header.clone();
        header.qdcount = self.questions.len() as u16;
        header.ancount = self.answers.len() as u16;
        header.nscount = self.authority.len() as u16;
        header.arcount = self.additional.len() as u16;

        // Write header
        header.to_bytes(&mut buf);

        // Write question section
        for question in &self.questions {
            question.to_bytes(&mut buf, &mut compression)?;
        }

        // Write answer section
        for rr in &self.answers {
            Self::serialize_rr(rr, &mut buf, &mut compression)?;
        }

        // Write authority section
        for rr in &self.authority {
            Self::serialize_rr(rr, &mut buf, &mut compression)?;
        }

        // Write additional section
        for rr in &self.additional {
            Self::serialize_rr(rr, &mut buf, &mut compression)?;
        }

        Ok(buf.to_vec())
    }

    /// Serialize a single resource record to wire format with name compression.
    ///
    /// Wire format for RR:
    /// - NAME (variable, compressed)
    /// - TYPE (2 bytes)
    /// - CLASS (2 bytes)
    /// - TTL (4 bytes)
    /// - RDLENGTH (2 bytes)
    /// - RDATA (RDLENGTH bytes)
    fn serialize_rr(
        rr: &ResourceRecord,
        buf: &mut BytesMut,
        compression: &mut CompressionMap,
    ) -> Result<()> {
        // Serialize and write the name with compression
        compress_name(rr.name().as_str(), buf, Some(compression)).map_err(DnsmasqError::Dns)?;

        // Write TYPE (2 bytes)
        let rtype_val: u16 = u16::from(rr.rtype());
        buf.put_u16(rtype_val);

        // Write CLASS (2 bytes)
        buf.put_u16(rr.class());

        // Write TTL (4 bytes)
        buf.put_u32(rr.ttl());

        // Serialize RDATA to get its bytes
        let rdata_bytes = rr.serialize_rdata()?;

        // Write RDLENGTH (2 bytes)
        if rdata_bytes.len() > u16::MAX as usize {
            return Err(DnsmasqError::Dns(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: "RDATA length exceeds maximum (65535 bytes)".to_string(),
            }));
        }
        buf.put_u16(rdata_bytes.len() as u16);

        // Write RDATA bytes
        buf.put_slice(&rdata_bytes);

        Ok(())
    }

    /// Create builder for constructing DNS messages with fluent API.
    pub fn builder() -> DnsMessageBuilder {
        DnsMessageBuilder::new()
    }

    /// Get message ID.
    pub fn id(&self) -> u16 {
        self.header.id
    }

    /// Get immutable reference to flags.
    pub fn flags(&self) -> &DnsFlags {
        &self.header.flags
    }

    /// Get mutable reference to flags.
    pub fn flags_mut(&mut self) -> &mut DnsFlags {
        &mut self.header.flags
    }

    /// Check if message is a query (QR bit = 0).
    pub fn is_query(&self) -> bool {
        !self.header.flags.qr()
    }

    /// Check if message is a response (QR bit = 1).
    pub fn is_response(&self) -> bool {
        self.header.flags.qr()
    }

    /// Set QR bit to 1 (make this a response).
    pub fn set_response(&mut self) {
        self.header.flags.set_qr(true);
    }

    /// Set AA bit (authoritative answer).
    pub fn set_authoritative(&mut self, value: bool) {
        self.header.flags.set_aa(value);
    }

    /// Set TC bit (truncated).
    pub fn set_truncated(&mut self, value: bool) {
        self.header.flags.set_tc(value);
    }

    /// Get response code (RCODE).
    pub fn get_rcode(&self) -> u8 {
        self.header.flags.rcode()
    }

    /// Set response code (RCODE).
    pub fn set_rcode(&mut self, rcode: u8) {
        self.header.flags.set_rcode(rcode);
    }

    /// Get question count.
    pub fn qdcount(&self) -> u16 {
        self.questions.len() as u16
    }

    /// Get answer count.
    pub fn ancount(&self) -> u16 {
        self.answers.len() as u16
    }

    /// Get authority count.
    pub fn nscount(&self) -> u16 {
        self.authority.len() as u16
    }

    /// Get additional count.
    pub fn arcount(&self) -> u16 {
        self.additional.len() as u16
    }

    /// Add question to question section.
    pub fn add_question(&mut self, question: Question) {
        self.questions.push(question);
    }

    /// Add resource record to answer section.
    pub fn add_answer(&mut self, answer: ResourceRecord) {
        self.answers.push(answer);
    }

    /// Add resource record to authority section.
    pub fn add_authority(&mut self, authority: ResourceRecord) {
        self.authority.push(authority);
    }

    /// Add resource record to additional section.
    pub fn add_additional(&mut self, additional: ResourceRecord) {
        self.additional.push(additional);
    }
}

/// Fluent API builder for constructing DNS messages.
///
/// Provides chainable methods for setting message properties and adding sections.
///
/// # Example
///
/// ```rust,ignore
/// let message = DnsMessage::builder()
///     .id(12345)
///     .set_response()
///     .set_authoritative()
///     .add_question(question)
///     .add_answer(answer_rr)
///     .build();
/// ```
#[derive(Debug)]
pub struct DnsMessageBuilder {
    /// The DNS message being constructed
    message: DnsMessage,
}

impl DnsMessageBuilder {
    /// Create new builder with random ID.
    #[must_use]
    pub fn new() -> Self {
        Self { message: DnsMessage::new(0) }
    }

    /// Set message ID.
    #[must_use]
    pub fn id(mut self, id: u16) -> Self {
        self.message.header.id = id;
        self
    }

    /// Set QR bit to 0 (query).
    #[must_use]
    pub fn set_query(mut self) -> Self {
        self.message.header.flags.set_qr(false);
        self
    }

    /// Set QR bit to 1 (response).
    #[must_use]
    pub fn set_response(mut self) -> Self {
        self.message.header.flags.set_qr(true);
        self
    }

    /// Set AA bit (authoritative answer).
    #[must_use]
    pub fn set_authoritative(mut self) -> Self {
        self.message.header.flags.set_aa(true);
        self
    }

    /// Set RD bit (recursion desired).
    #[must_use]
    pub fn set_recursion_desired(mut self) -> Self {
        self.message.header.flags.set_rd(true);
        self
    }

    /// Set RA bit (recursion available).
    #[must_use]
    pub fn set_recursion_available(mut self) -> Self {
        self.message.header.flags.set_ra(true);
        self
    }

    /// Set RCODE (response code).
    #[must_use]
    pub fn rcode(mut self, rcode: u8) -> Self {
        self.message.header.flags.set_rcode(rcode);
        self
    }

    /// Add question to question section.
    #[must_use]
    pub fn add_question(mut self, question: Question) -> Self {
        self.message.questions.push(question);
        self
    }

    /// Add resource record to answer section.
    #[must_use]
    pub fn add_answer(mut self, answer: ResourceRecord) -> Self {
        self.message.answers.push(answer);
        self
    }

    /// Add resource record to authority section.
    #[must_use]
    pub fn add_authority(mut self, authority: ResourceRecord) -> Self {
        self.message.authority.push(authority);
        self
    }

    /// Add resource record to additional section.
    #[must_use]
    pub fn add_additional(mut self, additional: ResourceRecord) -> Self {
        self.message.additional.push(additional);
        self
    }

    /// Build and return the DNS message.
    pub fn build(self) -> DnsMessage {
        self.message
    }
}

impl Default for DnsMessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS query extracted from a message.
///
/// Contains the first question from the question section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// Domain name being queried
    pub name: DomainName,
    /// Query type (A, AAAA, CNAME, etc.)
    pub qtype: RecordType,
    /// Query class (1 = IN for Internet)
    pub qclass: u16,
}

impl DnsQuery {
    /// Extract query from first question in message.
    ///
    /// Returns None if message has no questions.
    pub fn from_message(message: &DnsMessage) -> Option<Self> {
        message.questions.first().map(|q| Self {
            name: q.qname.clone(),
            qtype: q.qtype,
            qclass: q.qclass,
        })
    }
}

/// DNS response wrapper for easier response construction.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsResponse {
    message: DnsMessage,
}

impl DnsResponse {
    /// Create response from query message (copies ID and question).
    #[must_use]
    pub fn from_query(query_message: &DnsMessage) -> Self {
        let mut message = DnsMessage::new(query_message.id());
        message.set_response();
        message.questions = query_message.questions.clone();
        Self { message }
    }

    /// Create response from an existing DNS message.
    #[must_use]
    pub fn from_message(message: DnsMessage) -> Self {
        Self { message }
    }

    /// Get underlying message.
    pub fn to_message(self) -> DnsMessage {
        self.message
    }

    /// Get mutable reference to underlying message.
    pub fn message_mut(&mut self) -> &mut DnsMessage {
        &mut self.message
    }

    /// Add answer resource record.
    pub fn add_answer(&mut self, answer: ResourceRecord) {
        self.message.add_answer(answer);
    }

    /// Set response code (RCODE).
    pub fn set_rcode(&mut self, rcode: u8) {
        self.message.set_rcode(rcode);
    }

    /// Set authoritative answer flag.
    pub fn set_authoritative(&mut self, value: bool) {
        self.message.set_authoritative(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_flags_qr() {
        let mut flags = DnsFlags::new();
        assert!(!flags.qr());
        flags.set_qr(true);
        assert!(flags.qr());
        flags.set_qr(false);
        assert!(!flags.qr());
    }

    #[test]
    fn test_dns_flags_opcode() {
        let mut flags = DnsFlags::new();
        assert_eq!(flags.opcode(), 0);
        flags.set_opcode(5); // UPDATE
        assert_eq!(flags.opcode(), 5);
        flags.set_opcode(0); // QUERY
        assert_eq!(flags.opcode(), 0);
    }

    #[test]
    fn test_dns_flags_aa_tc_rd() {
        let mut flags = DnsFlags::new();

        flags.set_aa(true);
        assert!(flags.aa());

        flags.set_tc(true);
        assert!(flags.tc());

        flags.set_rd(true);
        assert!(flags.rd());

        // Verify all stay set
        assert!(flags.aa());
        assert!(flags.tc());
        assert!(flags.rd());
    }

    #[test]
    fn test_dns_flags_ra_ad_cd() {
        let mut flags = DnsFlags::new();

        flags.set_ra(true);
        assert!(flags.ra());

        flags.set_ad(true);
        assert!(flags.ad());

        flags.set_cd(true);
        assert!(flags.cd());
    }

    #[test]
    fn test_dns_flags_rcode() {
        let mut flags = DnsFlags::new();
        assert_eq!(flags.rcode(), 0); // NOERROR

        flags.set_rcode(3); // NXDOMAIN
        assert_eq!(flags.rcode(), 3);

        flags.set_rcode(2); // SERVFAIL
        assert_eq!(flags.rcode(), 2);
    }

    #[test]
    fn test_dns_flags_to_from_bytes() {
        let mut flags = DnsFlags::new();
        flags.set_qr(true);
        flags.set_aa(true);
        flags.set_rd(true);
        flags.set_ra(true);
        flags.set_rcode(3);

        let (hb3, hb4) = flags.to_bytes();
        let restored = DnsFlags::from_bytes(hb3, hb4);

        assert!(restored.qr());
        assert!(restored.aa());
        assert!(restored.rd());
        assert!(restored.ra());
        assert_eq!(restored.rcode(), 3);
    }

    #[test]
    fn test_dns_header_new() {
        let header = DnsHeader::new(12345);
        assert_eq!(header.id, 12345);
        assert_eq!(header.qdcount, 0);
        assert_eq!(header.ancount, 0);
        assert_eq!(header.nscount, 0);
        assert_eq!(header.arcount, 0);
    }

    #[test]
    fn test_dns_header_from_bytes() {
        let data = vec![
            0x12, 0x34, // ID = 0x1234
            0x81, 0x80, // Flags: QR=1, RD=1, RA=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x02, // ANCOUNT = 2
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x01, // ARCOUNT = 1
        ];

        let header = DnsHeader::from_bytes(&data).unwrap();
        assert_eq!(header.id, 0x1234);
        assert!(header.flags.qr());
        assert!(header.flags.rd());
        assert!(header.flags.ra());
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 2);
        assert_eq!(header.nscount, 0);
        assert_eq!(header.arcount, 1);
    }

    #[test]
    fn test_dns_header_to_bytes() {
        let mut header = DnsHeader::new(0x1234);
        header.flags.set_qr(true);
        header.flags.set_rd(true);
        header.qdcount = 1;
        header.ancount = 2;
        header.arcount = 1;

        let mut buf = BytesMut::new();
        header.to_bytes(&mut buf);

        assert_eq!(buf.len(), 12);
        assert_eq!(&buf[0..2], &[0x12, 0x34]); // ID
        assert_eq!(&buf[4..6], &[0x00, 0x01]); // QDCOUNT
        assert_eq!(&buf[6..8], &[0x00, 0x02]); // ANCOUNT
        assert_eq!(&buf[8..10], &[0x00, 0x00]); // NSCOUNT
        assert_eq!(&buf[10..12], &[0x00, 0x01]); // ARCOUNT
    }

    #[test]
    fn test_dns_message_new() {
        let message = DnsMessage::new(999);
        assert_eq!(message.id(), 999);
        assert!(message.is_query());
        assert!(!message.is_response());
        assert_eq!(message.qdcount(), 0);
        assert_eq!(message.ancount(), 0);
    }

    #[test]
    fn test_dns_message_builder() {
        let message = DnsMessage::builder()
            .id(12345)
            .set_response()
            .set_authoritative()
            .set_recursion_available()
            .build();

        assert_eq!(message.id(), 12345);
        assert!(message.is_response());
        assert!(message.flags().aa());
        assert!(message.flags().ra());
    }

    #[test]
    fn test_question_new() {
        let name = DomainName::new("example.com").unwrap();
        let question = Question::new(name.clone(), RecordType::A, C_IN);

        assert_eq!(question.qname, name);
        assert_eq!(question.qtype, RecordType::A);
        assert_eq!(question.qclass, C_IN);
    }

    #[test]
    fn test_dns_message_add_sections() {
        let mut message = DnsMessage::new(1);

        let name = DomainName::new("test.com").unwrap();
        let question = Question::new(name.clone(), RecordType::A, C_IN);
        message.add_question(question);

        assert_eq!(message.qdcount(), 1);
        assert_eq!(message.questions[0].qname.as_str(), "test.com");
    }

    #[test]
    fn test_dns_query_from_message() {
        let name = DomainName::new("example.org").unwrap();
        let question = Question::new(name.clone(), RecordType::AAAA, C_IN);

        let mut message = DnsMessage::new(100);
        message.add_question(question);

        let query = DnsQuery::from_message(&message).unwrap();
        assert_eq!(query.name, name);
        assert_eq!(query.qtype, RecordType::AAAA);
        assert_eq!(query.qclass, C_IN);
    }

    #[test]
    fn test_dns_response_from_query() {
        let name = DomainName::new("test.net").unwrap();
        let question = Question::new(name.clone(), RecordType::A, C_IN);

        let mut query_msg = DnsMessage::new(555);
        query_msg.add_question(question);

        let mut response = DnsResponse::from_query(&query_msg);
        assert_eq!(response.message_mut().id(), 555);
        assert!(response.message_mut().is_response());
        assert_eq!(response.message_mut().qdcount(), 1);

        response.set_rcode(NOERROR);
        assert_eq!(response.message_mut().get_rcode(), NOERROR);
    }

    #[test]
    fn test_dns_flags_complete_roundtrip() {
        let mut flags = DnsFlags::new();
        flags.set_qr(true);
        flags.set_opcode(4); // NOTIFY
        flags.set_aa(true);
        flags.set_tc(false);
        flags.set_rd(true);
        flags.set_ra(true);
        flags.set_ad(true);
        flags.set_cd(false);
        flags.set_rcode(0);

        let raw = flags.raw();
        let restored = DnsFlags::from_raw(raw);

        assert!(restored.qr());
        assert_eq!(restored.opcode(), 4);
        assert!(restored.aa());
        assert!(!restored.tc());
        assert!(restored.rd());
        assert!(restored.ra());
        assert!(restored.ad());
        assert!(!restored.cd());
        assert_eq!(restored.rcode(), 0);
    }
}
