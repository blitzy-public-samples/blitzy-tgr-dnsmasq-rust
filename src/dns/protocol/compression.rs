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

//! DNS name compression implementation per RFC 1035 Section 4.1.4.
//!
//! This module provides safe compression pointer resolution and decompression with infinite
//! loop prevention. It replaces the C implementation's pointer arithmetic from rfc1035.c
//! with Rust bounds-checked slice operations and Result-based error propagation.
//!
//! # Key Features
//!
//! - Compression pointer validation with maximum 255 hop limit
//! - Bounds checking for all pointer dereferences
//! - Circular reference detection
//! - CompressionMap for building compression dictionaries during packet construction
//! - Safe label escaping for special characters (NUL, dot, escape byte)
//!
//! # RFC Compliance
//!
//! - RFC 1035 Section 4.1.4: Domain name compression using pointers
//! - RFC 1035 Section 2.3.1: Label format and length restrictions
//! - RFC 1035 Section 3.1: Name space definitions (MAXDNAME limit)
//!
//! # Memory Safety
//!
//! All functions use nom parser combinators and Rust slice operations to prevent buffer
//! overruns and invalid pointer dereferences that were possible in the C implementation.

use crate::dns::protocol::constants::{MAXDNAME, MAXLABEL, NAME_ESCAPE};
use crate::error::DnsError;
use bytes::{BufMut, Bytes, BytesMut};
use nom::{
    bytes::complete::take,
    combinator::map,
    error::{Error as NomError, ErrorKind, ParseError},
    number::complete::be_u8,
    IResult,
};
use std::collections::HashMap;

/// Maximum number of compression pointer hops allowed per RFC 1035 to prevent infinite loops.
///
/// This matches the C implementation's hop limit in extract_name() and prevents malicious
/// packets from causing infinite loops through circular compression pointer references.
const MAX_COMPRESSION_HOPS: usize = 255;

/// Compression pointer indicator (high 2 bits set to 11).
///
/// Per RFC 1035 Section 4.1.4, labels starting with 0xC0 (binary 11xxxxxx) are compression
/// pointers where the remaining 14 bits specify an offset from the packet start.
const COMPRESSION_POINTER_MASK: u8 = 0xC0;

/// CompressionMap tracks label offsets for compression pointer generation during packet construction.
///
/// Maps label sequences to their packet offsets, enabling optimal compression pointer insertion
/// when the same domain name or suffix appears multiple times in a packet. This replaces manual
/// compression tracking in the C implementation.
///
/// # Example
///
/// ```rust,ignore
/// let mut map = CompressionMap::new();
/// map.add_name(b"example.com", 12);  // Name starts at offset 12
/// if let Some(offset) = map.find_suffix(b"com") {
///     // Can use compression pointer to offset
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CompressionMap {
    /// Maps label sequences (as byte vectors) to packet offsets.
    /// Key: domain name suffix in wire format (labels without compression)
    /// Value: offset in packet where this suffix begins
    offsets: HashMap<Vec<u8>, usize>,
}

impl CompressionMap {
    /// Creates a new empty compression map.
    pub fn new() -> Self {
        Self {
            offsets: HashMap::new(),
        }
    }

    /// Adds a domain name and all its suffixes to the compression map.
    ///
    /// For a name like "www.example.com", this adds entries for:
    /// - "www.example.com" at given offset
    /// - "example.com" at offset + len("www.")
    /// - "com" at offset + len("www.example.")
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name in wire format (length-prefixed labels)
    /// * `offset` - Starting offset of the name in the packet
    pub fn add_name(&mut self, name: &[u8], offset: usize) {
        let mut current_offset = offset;
        let mut pos = 0;

        while pos < name.len() {
            // Record this suffix starting at current_offset
            self.offsets.insert(name[pos..].to_vec(), current_offset);

            // Read label length
            let label_len = name[pos] as usize;
            if label_len == 0 {
                // End of name
                break;
            }

            // Check for compression pointer (shouldn't be in input, but validate)
            if label_len & 0xC0 != 0 {
                break;
            }

            // Move past label length + label data
            pos += 1 + label_len;
            current_offset += 1 + label_len;
        }
    }

    /// Finds a compression pointer offset for the given name suffix.
    ///
    /// Returns the packet offset where this suffix (or a matching suffix) was previously
    /// recorded, allowing a compression pointer to be used instead of writing the full name.
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name suffix to search for
    ///
    /// # Returns
    ///
    /// The packet offset if found, or None if no matching suffix exists.
    pub fn find_suffix(&self, name: &[u8]) -> Option<usize> {
        // Try exact match first
        if let Some(&offset) = self.offsets.get(name) {
            return Some(offset);
        }

        // Try progressively shorter suffixes
        let mut pos = 0;
        while pos < name.len() {
            let label_len = name[pos] as usize;
            if label_len == 0 {
                break;
            }
            if label_len & 0xC0 != 0 {
                break;
            }

            pos += 1 + label_len;
            if pos < name.len() {
                if let Some(&offset) = self.offsets.get(&name[pos..]) {
                    return Some(offset);
                }
            }
        }

        None
    }

    /// Clears all recorded compression mappings.
    pub fn clear(&mut self) {
        self.offsets.clear();
    }

    /// Returns the number of recorded compression mappings.
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// Returns true if the map contains no compression mappings.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }
}

impl Default for CompressionMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Decompresses a DNS domain name from wire format, following compression pointers.
///
/// Extracts a domain name from a DNS packet in wire format (RFC 1035 Section 4.1.4),
/// following compression pointers to reconstruct the complete name. Implements safety
/// checks for infinite loops (max 255 hops), bounds validation, and length limits.
///
/// This replaces the C extract_name() function with safe Rust operations using nom parsers.
///
/// # Arguments
///
/// * `packet` - Complete DNS packet buffer (needed for compression pointer resolution)
/// * `offset` - Starting offset within packet where name begins
///
/// # Returns
///
/// Returns `Ok((remaining_offset, domain_name))` where:
/// - `remaining_offset` is the position after the name (accounting for compression jumps)
/// - `domain_name` is the extracted name as a String in dotted notation
///
/// Returns `Err(DnsError)` if:
/// - Compression pointer exceeds packet bounds
/// - More than 255 compression pointer hops detected (circular reference)
/// - Label length exceeds 63 bytes (MAXLABEL)
/// - Total name length exceeds 1025 bytes (MAXDNAME)
/// - Malformed label format detected
///
/// # Example
///
/// ```rust,ignore
/// let packet = Bytes::from_static(b"\x03www\x07example\x03com\x00");
/// let (next_offset, name) = decompress_name(&packet, 0)?;
/// assert_eq!(name, "www.example.com");
/// ```
pub fn decompress_name(packet: &[u8], offset: usize) -> Result<(usize, String), DnsError> {
    let mut result = String::with_capacity(256);
    let mut current_offset = offset;
    let mut hops = 0;
    let mut return_offset: Option<usize> = None;

    loop {
        // Bounds check for label length byte
        if current_offset >= packet.len() {
            return Err(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: "compression pointer beyond packet bounds".to_string(),
            });
        }

        let label_len = packet[current_offset];

        // Check for end of name (label length 0)
        if label_len == 0 {
            current_offset += 1;
            // Remove trailing dot if present
            if result.ends_with('.') {
                result.pop();
            }
            // Return the offset after the name (accounting for compression jump)
            let final_offset = return_offset.unwrap_or(current_offset);
            return Ok((final_offset, result));
        }

        // Check for compression pointer (top 2 bits = 11)
        if (label_len & COMPRESSION_POINTER_MASK) == COMPRESSION_POINTER_MASK {
            // Need next byte for 14-bit offset
            if current_offset + 1 >= packet.len() {
                return Err(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: "incomplete compression pointer".to_string(),
                });
            }

            // Calculate target offset (14-bit value)
            let pointer_offset =
                (((label_len & 0x3F) as usize) << 8) | (packet[current_offset + 1] as usize);

            // Save return position on first jump
            if return_offset.is_none() {
                return_offset = Some(current_offset + 2);
            }

            // Check for hop limit to prevent infinite loops
            hops += 1;
            if hops > MAX_COMPRESSION_HOPS {
                return Err(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: format!(
                        "compression hop limit exceeded (max {})",
                        MAX_COMPRESSION_HOPS
                    ),
                });
            }

            // Validate pointer offset is within packet
            if pointer_offset >= packet.len() {
                return Err(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: format!(
                        "compression pointer offset {} exceeds packet size {}",
                        pointer_offset,
                        packet.len()
                    ),
                });
            }

            // Follow the compression pointer
            current_offset = pointer_offset;
            continue;
        }

        // Check for unsupported label types (0x40 and 0x80)
        if (label_len & 0xC0) != 0 {
            return Err(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: format!("unsupported label type: 0x{:02X}", label_len),
            });
        }

        // Validate label length
        let len = label_len as usize;
        if len > MAXLABEL {
            return Err(DnsError::InvalidName {
                name: result.clone(),
                reason: format!("label length {} exceeds maximum {}", len, MAXLABEL),
            });
        }

        // Bounds check for label data
        if current_offset + 1 + len > packet.len() {
            return Err(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: "label extends beyond packet bounds".to_string(),
            });
        }

        // Extract label bytes
        current_offset += 1;
        let label_bytes = &packet[current_offset..current_offset + len];

        // Unescape and append label
        let label = unescape_label(label_bytes)?;
        result.push_str(&label);
        result.push('.');

        current_offset += len;

        // Check total name length
        if result.len() > MAXDNAME {
            return Err(DnsError::InvalidName {
                name: result.clone(),
                reason: format!("name length {} exceeds maximum {}", result.len(), MAXDNAME),
            });
        }
    }
}

/// Compresses a domain name into wire format with optional compression pointer insertion.
///
/// Converts a dotted domain name string into DNS wire format (length-prefixed labels),
/// using compression pointers when possible to reduce packet size. This implements the
/// compression algorithm from RFC 1035 Section 4.1.4.
///
/// # Arguments
///
/// * `name` - Domain name in dotted notation (e.g., "www.example.com")
/// * `buffer` - Mutable buffer to write wire format name into
/// * `compression_map` - Optional compression map for pointer generation. If provided and
///   a matching suffix is found, a compression pointer will be written instead of the full name.
///
/// # Returns
///
/// The number of bytes written to the buffer, or DnsError if compression fails.
///
/// # Example
///
/// ```rust,ignore
/// let mut buf = BytesMut::new();
/// let mut map = CompressionMap::new();
/// let written = compress_name("www.example.com", &mut buf, Some(&mut map))?;
/// ```
pub fn compress_name(
    name: &str,
    buffer: &mut BytesMut,
    compression_map: Option<&mut CompressionMap>,
) -> Result<usize, DnsError> {
    let initial_len = buffer.len();

    // Handle empty name (root)
    if name.is_empty() || name == "." {
        buffer.put_u8(0);
        return Ok(1);
    }

    // Split name into labels
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();

    let mut labels_written = 0;

    for i in 0..labels.len() {
        // Check if we can use a compression pointer for remaining labels
        if let Some(ref mut map) = compression_map {
            let remaining_name = labels[i..].join(".");
            let remaining_wire = encode_labels_to_wire(&labels[i..])?;

            if let Some(offset) = map.find_suffix(&remaining_wire) {
                // Write compression pointer (14-bit offset with top 2 bits set)
                if offset <= 0x3FFF {
                    // Maximum 14-bit value
                    let pointer = 0xC000 | (offset as u16);
                    buffer.put_u16(pointer);
                    return Ok(buffer.len() - initial_len);
                }
            }

            // Record this position for future compression
            let current_offset = buffer.len();
            if i < labels.len() {
                map.add_name(&remaining_wire, current_offset);
            }
        }

        // Write label
        let label = labels[i];
        if label.len() > MAXLABEL {
            return Err(DnsError::InvalidName {
                name: name.to_string(),
                reason: format!("label '{}' exceeds maximum length {}", label, MAXLABEL),
            });
        }

        // Escape and encode label
        let escaped = escape_label(label.as_bytes());
        buffer.put_u8(escaped.len() as u8);
        buffer.extend_from_slice(&escaped);

        labels_written += 1;
    }

    // Write terminating zero
    buffer.put_u8(0);

    Ok(buffer.len() - initial_len)
}

/// Helper function to encode labels into wire format without compression.
fn encode_labels_to_wire(labels: &[&str]) -> Result<Vec<u8>, DnsError> {
    let mut result = Vec::new();

    for label in labels {
        if label.len() > MAXLABEL {
            return Err(DnsError::InvalidName {
                name: labels.join("."),
                reason: format!("label '{}' exceeds maximum length {}", label, MAXLABEL),
            });
        }

        let escaped = escape_label(label.as_bytes());
        result.push(escaped.len() as u8);
        result.extend_from_slice(&escaped);
    }

    result.push(0); // Terminating zero
    Ok(result)
}

/// Escapes special characters in a DNS label per RFC 1035.
///
/// DNS labels can contain any byte value, but certain bytes need escaping:
/// - NUL byte (0x00): Escaped as [NAME_ESCAPE, 0x01]
/// - Dot (0x2E): Escaped as [NAME_ESCAPE, 0x2F]  
/// - Escape byte itself (NAME_ESCAPE): Escaped as [NAME_ESCAPE, NAME_ESCAPE+1]
///
/// This matches the C implementation's escaping logic in extract_name().
///
/// # Arguments
///
/// * `label` - Raw label bytes to escape
///
/// # Returns
///
/// Vector containing escaped label bytes
pub fn escape_label(label: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(label.len());

    for &byte in label {
        if byte == 0 || byte == b'.' || byte == NAME_ESCAPE {
            result.push(NAME_ESCAPE);
            result.push(byte + 1);
        } else {
            result.push(byte);
        }
    }

    result
}

/// Unescapes a DNS label, reversing the escape encoding.
///
/// Reverses the escaping applied by `escape_label()`, converting NAME_ESCAPE sequences
/// back to their original byte values.
///
/// # Arguments
///
/// * `label` - Escaped label bytes
///
/// # Returns
///
/// Unescaped label as a String, or DnsError if escape sequence is malformed.
pub fn unescape_label(label: &[u8]) -> Result<String, DnsError> {
    let mut result = Vec::with_capacity(label.len());
    let mut i = 0;

    while i < label.len() {
        if label[i] == NAME_ESCAPE {
            // Need next byte for escape sequence
            if i + 1 >= label.len() {
                return Err(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: "incomplete escape sequence in label".to_string(),
                });
            }
            // Unescape: subtract 1 from escaped byte
            let unescaped = label[i + 1].wrapping_sub(1);
            result.push(unescaped);
            i += 2;
        } else {
            result.push(label[i]);
            i += 1;
        }
    }

    // Convert to string, handling non-UTF8 labels gracefully
    String::from_utf8(result).or_else(|e| {
        // For non-UTF8 labels, represent as escaped hex
        let bytes = e.into_bytes();
        Ok(bytes
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() && *b != b'\\' {
                    (*b as char).to_string()
                } else {
                    format!("\\x{:02X}", b)
                }
            })
            .collect())
    })
}

/// Validates compression pointer integrity throughout a DNS packet.
///
/// Performs a full packet scan to detect malformed compression pointer chains before
/// processing. This provides an additional safety layer beyond per-name validation.
///
/// Checks for:
/// - Compression pointers that reference offsets beyond packet bounds
/// - Circular compression pointer references (loops)
/// - Compression pointers with excessive hop counts
/// - Invalid label types or lengths
///
/// # Arguments
///
/// * `packet` - Complete DNS packet to validate
///
/// # Returns
///
/// `Ok(())` if all compression pointers are valid, `Err(DnsError)` if any validation fails.
///
/// # Example
///
/// ```rust,ignore
/// validate_compression(&packet_bytes)?;
/// // Safe to parse packet, compression pointers are valid
/// ```
pub fn validate_compression(packet: &[u8]) -> Result<(), DnsError> {
    // DNS header is 12 bytes minimum
    if packet.len() < 12 {
        return Err(DnsError::ParseFailed {
            server: "local".to_string(),
            reason: format!("packet too short: {} bytes", packet.len()),
        });
    }

    // Parse header to get section counts
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let nscount = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let arcount = u16::from_be_bytes([packet[10], packet[11]]) as usize;

    let mut offset = 12; // Start after header

    // Validate questions section
    for _ in 0..qdcount {
        // Parse question name
        offset = validate_name_at_offset(packet, offset)?;
        // Skip QTYPE (2 bytes) and QCLASS (2 bytes)
        offset += 4;
        if offset > packet.len() {
            return Err(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: "question section extends beyond packet".to_string(),
            });
        }
    }

    // Validate answer, authority, and additional sections (all have same RR format)
    let total_rrs = ancount + nscount + arcount;
    for _ in 0..total_rrs {
        // Parse RR name
        offset = validate_name_at_offset(packet, offset)?;

        // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2) = 10 bytes
        if offset + 10 > packet.len() {
            return Err(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: "RR header extends beyond packet".to_string(),
            });
        }

        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;

        // Skip RDATA
        offset += rdlength;
        if offset > packet.len() {
            return Err(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: "RR RDATA extends beyond packet".to_string(),
            });
        }
    }

    Ok(())
}

/// Helper function to validate a name at a specific packet offset.
///
/// Returns the offset after the name (accounting for compression).
fn validate_name_at_offset(packet: &[u8], start_offset: usize) -> Result<usize, DnsError> {
    let mut offset = start_offset;
    let mut hops = 0;
    let mut return_offset: Option<usize> = None;

    loop {
        if offset >= packet.len() {
            return Err(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: "name offset beyond packet bounds".to_string(),
            });
        }

        let label_len = packet[offset];

        if label_len == 0 {
            // End of name
            offset += 1;
            return Ok(return_offset.unwrap_or(offset));
        }

        // Check for compression pointer
        if (label_len & COMPRESSION_POINTER_MASK) == COMPRESSION_POINTER_MASK {
            if offset + 1 >= packet.len() {
                return Err(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: "incomplete compression pointer".to_string(),
                });
            }

            let pointer_offset =
                (((label_len & 0x3F) as usize) << 8) | (packet[offset + 1] as usize);

            // Save return position on first jump
            if return_offset.is_none() {
                return_offset = Some(offset + 2);
            }

            // Check hop limit
            hops += 1;
            if hops > MAX_COMPRESSION_HOPS {
                return Err(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: "compression hop limit exceeded during validation".to_string(),
                });
            }

            // Validate pointer is within packet
            if pointer_offset >= packet.len() {
                return Err(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: format!(
                        "compression pointer {} exceeds packet size {}",
                        pointer_offset,
                        packet.len()
                    ),
                });
            }

            // Validate pointer doesn't point forward (potential loop)
            if pointer_offset >= offset {
                return Err(DnsError::ParseFailed {
                    server: "local".to_string(),
                    reason: "compression pointer references forward offset (potential loop)"
                        .to_string(),
                });
            }

            offset = pointer_offset;
            continue;
        }

        // Check for unsupported label types
        if (label_len & 0xC0) != 0 {
            return Err(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: format!("unsupported label type: 0x{:02X}", label_len),
            });
        }

        // Validate label length
        let len = label_len as usize;
        if len > MAXLABEL {
            return Err(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: format!("label length {} exceeds maximum {}", len, MAXLABEL),
            });
        }

        // Check bounds for label data
        if offset + 1 + len > packet.len() {
            return Err(DnsError::ParseFailed {
                server: "local".to_string(),
                reason: "label data extends beyond packet".to_string(),
            });
        }

        offset += 1 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_map_basic() {
        let mut map = CompressionMap::new();
        assert_eq!(map.len(), 0);

        // Add a name in wire format: \x03www\x07example\x03com\x00
        let name = b"\x03www\x07example\x03com\x00";
        map.add_name(name, 12);

        // Should be able to find suffixes
        assert!(map.len() > 0);

        // Clear and verify
        map.clear();
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_compression_map_find_suffix() {
        let mut map = CompressionMap::new();

        // Add "example.com" at offset 12
        let name = b"\x07example\x03com\x00";
        map.add_name(name, 12);

        // Should find exact match
        assert_eq!(map.find_suffix(b"\x07example\x03com\x00"), Some(12));

        // Should find suffix "com"
        let com_offset = 12 + 1 + 7; // Skip length byte + "example"
        assert_eq!(map.find_suffix(b"\x03com\x00"), Some(com_offset));
    }

    #[test]
    fn test_decompress_simple_name() {
        // Create packet with simple name: \x03www\x07example\x03com\x00
        let packet = b"\x03www\x07example\x03com\x00";

        let (offset, name) = decompress_name(packet, 0).expect("decompression failed");

        assert_eq!(name, "www.example.com");
        assert_eq!(offset, packet.len());
    }

    #[test]
    fn test_decompress_root_name() {
        // Root domain is just a zero byte
        let packet = b"\x00";

        let (offset, name) = decompress_name(packet, 0).expect("decompression failed");

        assert_eq!(name, "");
        assert_eq!(offset, 1);
    }

    #[test]
    fn test_decompress_with_compression_pointer() {
        // Create packet with compression:
        // Offset 0: \x03www\x07example\x03com\x00  (www.example.com)
        // Offset 17: \x03ftp\xc0\x04  (ftp.example.com with pointer to offset 4)
        let mut packet = Vec::new();
        packet.extend_from_slice(b"\x03www\x07example\x03com\x00"); // 0-16
        packet.extend_from_slice(b"\x03ftp");                        // 17-20
        packet.push(0xC0); // Compression pointer marker          // 21
        packet.push(0x04); // Points to offset 4 (\x07example...) // 22

        let (offset, name) = decompress_name(&packet, 17).expect("decompression failed");

        assert_eq!(name, "ftp.example.com");
        assert_eq!(offset, 23); // After the compression pointer
    }

    #[test]
    fn test_decompress_compression_loop_detected() {
        // Create malicious packet with circular pointer
        // Offset 0: \xc0\x00 (points to itself)
        let packet = b"\xc0\x00";

        let result = decompress_name(packet, 0);

        assert!(result.is_err());
        match result {
            Err(DnsError::ParseFailed { reason, .. }) => {
                assert!(reason.contains("hop limit"));
            }
            _ => panic!("expected hop limit error"),
        }
    }

    #[test]
    fn test_decompress_pointer_out_of_bounds() {
        // Compression pointer points beyond packet
        // \xc0\xff (points to offset 255, but packet is much smaller)
        let packet = b"\xc0\xff";

        let result = decompress_name(packet, 0);

        assert!(result.is_err());
        match result {
            Err(DnsError::ParseFailed { reason, .. }) => {
                assert!(reason.contains("exceeds packet size"));
            }
            _ => panic!("expected out of bounds error"),
        }
    }

    #[test]
    fn test_decompress_label_too_long() {
        // Label length of 64 (exceeds MAXLABEL of 63)
        let mut packet = Vec::new();
        packet.push(64); // Invalid length
        packet.extend_from_slice(&vec![b'a'; 64]);
        packet.push(0);

        let result = decompress_name(&packet, 0);

        assert!(result.is_err());
        match result {
            Err(DnsError::InvalidName { reason, .. }) => {
                assert!(reason.contains("exceeds maximum"));
            }
            _ => panic!("expected invalid name error"),
        }
    }

    #[test]
    fn test_decompress_incomplete_pointer() {
        // Compression pointer without second byte
        let packet = b"\xc0";

        let result = decompress_name(packet, 0);

        assert!(result.is_err());
    }

    #[test]
    fn test_compress_simple_name() {
        let mut buffer = BytesMut::new();
        let mut map = CompressionMap::new();

        let written = compress_name("www.example.com", &mut buffer, Some(&mut map))
            .expect("compression failed");

        assert!(written > 0);

        // Verify we can decompress it back
        let (_, name) = decompress_name(&buffer, 0).expect("decompression failed");
        assert_eq!(name, "www.example.com");
    }

    #[test]
    fn test_compress_root_name() {
        let mut buffer = BytesMut::new();

        let written = compress_name("", &mut buffer, None).expect("compression failed");

        assert_eq!(written, 1);
        assert_eq!(buffer[0], 0);
    }

    #[test]
    fn test_compress_with_compression_map() {
        let mut buffer = BytesMut::new();
        let mut map = CompressionMap::new();

        // Write first name
        let written1 =
            compress_name("www.example.com", &mut buffer, Some(&mut map)).expect("failed");

        // Write second name that shares suffix
        let offset2 = buffer.len();
        let written2 =
            compress_name("ftp.example.com", &mut buffer, Some(&mut map)).expect("failed");

        // Second name should be shorter due to compression
        // It should write "ftp" + compression pointer (2 bytes)
        assert!(written2 < written1);

        // Verify both names decompress correctly
        let (_, name1) = decompress_name(&buffer, 0).expect("decompression failed");
        assert_eq!(name1, "www.example.com");

        let (_, name2) = decompress_name(&buffer, offset2).expect("decompression failed");
        assert_eq!(name2, "ftp.example.com");
    }

    #[test]
    fn test_escape_label_special_chars() {
        // Test escaping of NUL byte
        let label = b"\x00test";
        let escaped = escape_label(label);
        assert_eq!(escaped[0], NAME_ESCAPE);
        assert_eq!(escaped[1], 1);

        // Test escaping of dot
        let label = b"test.com";
        let escaped = escape_label(label);
        // Should contain NAME_ESCAPE followed by ('.' + 1)
        let dot_pos = label.iter().position(|&b| b == b'.').unwrap();
        assert_eq!(escaped[dot_pos * 2], NAME_ESCAPE);
        assert_eq!(escaped[dot_pos * 2 + 1], b'.' + 1);

        // Test escaping of escape byte itself
        let label = &[NAME_ESCAPE];
        let escaped = escape_label(label);
        assert_eq!(escaped[0], NAME_ESCAPE);
        assert_eq!(escaped[1], NAME_ESCAPE + 1);
    }

    #[test]
    fn test_unescape_label_special_chars() {
        // Test unescaping NUL byte
        let escaped = vec![NAME_ESCAPE, 1, b't', b'e', b's', b't'];
        let unescaped = unescape_label(&escaped).expect("unescape failed");
        // NUL byte may not be valid UTF-8, so check representation
        assert!(unescaped.contains("test"));

        // Test unescaping regular characters
        let escaped = b"test";
        let unescaped = unescape_label(escaped).expect("unescape failed");
        assert_eq!(unescaped, "test");
    }

    #[test]
    fn test_unescape_label_incomplete_escape() {
        // Escape sequence without following byte
        let escaped = vec![NAME_ESCAPE];

        let result = unescape_label(&escaped);

        assert!(result.is_err());
        match result {
            Err(DnsError::ParseFailed { reason, .. }) => {
                assert!(reason.contains("incomplete escape"));
            }
            _ => panic!("expected parse failed error"),
        }
    }

    #[test]
    fn test_validate_compression_valid_packet() {
        // Create a valid DNS packet with header and simple question
        let mut packet = Vec::new();

        // Header: ID (2), flags (2), QDCOUNT=1 (2), ANCOUNT=0 (2), NSCOUNT=0 (2), ARCOUNT=0 (2)
        packet.extend_from_slice(&[0x12, 0x34]); // ID
        packet.extend_from_slice(&[0x01, 0x00]); // Flags
        packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Question: name + QTYPE + QCLASS
        packet.extend_from_slice(b"\x07example\x03com\x00"); // Name
        packet.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        let result = validate_compression(&packet);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_compression_forward_pointer() {
        // Create packet with forward-pointing compression pointer (invalid)
        let mut packet = Vec::new();

        // Header with QDCOUNT=1
        packet.extend_from_slice(&[0x12, 0x34]); // ID
        packet.extend_from_slice(&[0x01, 0x00]); // Flags
        packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Question with forward pointer
        packet.push(0xC0); // Compression pointer
        packet.push(0xFF); // Points to offset 255 (forward)

        let result = validate_compression(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_compression_packet_too_short() {
        // Packet smaller than DNS header (12 bytes)
        let packet = b"\x00\x00\x00\x00";

        let result = validate_compression(packet);

        assert!(result.is_err());
        match result {
            Err(DnsError::ParseFailed { reason, .. }) => {
                assert!(reason.contains("too short"));
            }
            _ => panic!("expected too short error"),
        }
    }

    #[test]
    fn test_compress_label_too_long() {
        let mut buffer = BytesMut::new();

        // Create label longer than MAXLABEL (63)
        let long_label = "a".repeat(64);
        let name = format!("{}.example.com", long_label);

        let result = compress_name(&name, &mut buffer, None);

        assert!(result.is_err());
        match result {
            Err(DnsError::InvalidName { reason, .. }) => {
                assert!(reason.contains("exceeds maximum"));
            }
            _ => panic!("expected invalid name error"),
        }
    }
}
