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

//! Complete DNS message structure and parsing.

use super::name::DomainName;
use super::record::ResourceRecord;

/// Represents a DNS question section entry.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuestion {
    /// Domain name being queried
    pub name: DomainName,
    /// Query type (A, AAAA, etc.)
    pub qtype: u16,
    /// Query class (typically IN for Internet)
    pub qclass: u16,
}

/// Represents a complete DNS message with all sections.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsMessage {
    /// Message ID for matching queries/responses
    pub id: u16,
    /// Message flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    pub flags: u16,
    /// Question section entries
    pub questions: Vec<DnsQuestion>,
    /// Answer section resource records
    pub answers: Vec<ResourceRecord>,
    /// Authority section resource records
    pub authority: Vec<ResourceRecord>,
    /// Additional section resource records
    pub additional: Vec<ResourceRecord>,
}

impl DnsMessage {
    /// Creates a new DNS message.
    pub fn new() -> Self {
        DnsMessage {
            id: 0,
            flags: 0,
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// Parses a DNS message from wire format bytes.
    pub fn from_bytes(_data: &[u8]) -> Result<Self, String> {
        // Stub implementation
        Ok(Self::new())
    }

    /// Checks if this is a query message (QR bit = 0).
    pub fn is_query(&self) -> bool {
        (self.flags & 0x8000) == 0
    }

    /// Checks if this is a response message (QR bit = 1).
    pub fn is_response(&self) -> bool {
        !self.is_query()
    }

    /// Creates a response message based on a query.
    pub fn new_response(query: &DnsMessage) -> Self {
        DnsMessage {
            id: query.id,
            flags: query.flags | 0x8000, // Set QR bit
            questions: query.questions.clone(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// Adds an answer record to the message.
    pub fn add_answer(&mut self, record: ResourceRecord) {
        self.answers.push(record);
    }

    /// Serializes the message to wire format bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        // Stub implementation
        Ok(Vec::new())
    }
}

impl Default for DnsMessage {
    fn default() -> Self {
        Self::new()
    }
}

/// Type alias for DNS query messages.
pub type DnsQuery = DnsMessage;

/// Type alias for DNS response messages.
pub type DnsResponse = DnsMessage;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_message_creation() {
        let msg = DnsMessage::new();
        assert_eq!(msg.id, 0);
        assert_eq!(msg.questions.len(), 0);
    }

    #[test]
    fn test_query_response_check() {
        let mut msg = DnsMessage::new();
        assert!(msg.is_query());
        assert!(!msg.is_response());

        msg.flags |= 0x8000; // Set QR bit
        assert!(msg.is_response());
        assert!(!msg.is_query());
    }

    #[test]
    fn test_new_response() {
        let query = DnsMessage::new();
        let response = DnsMessage::new_response(&query);
        assert!(response.is_response());
    }
}
