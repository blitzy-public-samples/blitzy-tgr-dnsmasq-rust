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

//! DNS domain name representation, validation, and wire format handling.
//!
//! This module provides the [`DomainName`] type implementing RFC 1035-compliant domain name
//! handling with memory-safe parsing, validation, and serialization. It replaces the C
//! implementation's manual pointer arithmetic from rfc1035.c and domain.c with Rust's
//! type-safe string operations and explicit bounds checking.
//!
//! # Key Features
//!
//! - RFC 1035 compliance: enforces 255-byte total length, 63-byte label length limits
//! - Case-insensitive comparison per DNS specification (RFC 1035 Section 3.1)
//! - Wire format serialization with compression pointer support
//! - Wire format parsing with decompression
//! - IDNA support for internationalized domain names (optional feature)
//! - Safe label validation and character set enforcement
//!
//! # RFC Compliance
//!
//! - RFC 1035 Section 2.3.1: Label format (63-byte limit, alphanumeric + hyphen)
//! - RFC 1035 Section 3.1: Name space definitions (255-byte limit, case-insensitive)
//! - RFC 1035 Section 4.1.4: Name compression in DNS messages
//! - RFC 3492: Punycode encoding for internationalized domain names (with "idn" feature)
//!
//! # Memory Safety
//!
//! All operations use Rust String and Vec types with automatic bounds checking, eliminating
//! buffer overflow vulnerabilities present in C's manual buffer management. The nom parser
//! combinator library provides safe wire format parsing without pointer arithmetic.
//!
//! # Examples
//!
//! ```rust,ignore
//! use std::str::FromStr;
//! use dnsmasq::dns::protocol::name::DomainName;
//!
//! // Parse from dotted notation
//! let name = DomainName::from_str("www.example.com")?;
//!
//! // Case-insensitive comparison
//! let name2 = DomainName::from_str("WWW.EXAMPLE.COM")?;
//! assert_eq!(name, name2);
//!
//! // Check subdomain relationship
//! let parent = DomainName::from_str("example.com")?;
//! assert!(name.is_subdomain_of(&parent));
//!
//! // Iterate over labels
//! for label in name.labels() {
//!     println!("Label: {}", label);
//! }
//! ```

use crate::dns::protocol::compression::CompressionMap;
use crate::dns::protocol::constants::MAXLABEL;
use crate::error::DnsError;
use bytes::{BufMut, Bytes, BytesMut};
use std::cmp::{Eq, PartialEq};
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "idn")]
use idna::domain_to_ascii;

/// Compression pointer mask (high 2 bits = 11).
const COMPRESSION_POINTER: u8 = 0xC0;

/// Maximum label length in DNS names (63 bytes) per RFC 1035 Section 2.3.1.
const MAX_LABEL_LEN: usize = MAXLABEL;

/// Maximum total domain name length (255 bytes) per RFC 1035 Section 3.1.
const MAX_NAME_LEN: usize = 255;

/// DomainName represents a DNS domain name with RFC 1035 compliance.
///
/// Internally stores the domain name in presentation format (dotted notation) as a String
/// for ease of use. Wire format serialization and parsing are provided through dedicated
/// methods. The type enforces RFC 1035 constraints on construction:
///
/// - Total length ≤ 255 bytes in wire format
/// - Individual label length ≤ 63 bytes
/// - Valid character set (alphanumeric, hyphen, period)
/// - No leading or trailing hyphens in labels
///
/// # Wire Format
///
/// DNS wire format uses length-prefixed labels terminated by a null byte:
/// - Each label: length_byte (1-63) + label_bytes
/// - Terminator: 0x00
/// - Example: "www.example.com" → 3www7example3com0
///
/// Compression pointers (0xC0 + 2-byte offset) reference earlier names in packets.
///
/// # Case Sensitivity
///
/// DNS names are case-insensitive per RFC 1035 Section 3.1. Comparison operations
/// (PartialEq, Eq) perform case-insensitive matching using ASCII lowercase conversion.
///
/// # IDNA Support
///
/// When the "idn" feature is enabled, non-ASCII domain names are automatically encoded
/// using Punycode (RFC 3492). For example, "münchen.de" becomes "xn--mnchen-3ya.de".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DomainName {
    /// Internal representation in presentation format (dotted notation).
    /// Stored as String for ease of manipulation and display.
    name: String,
}

impl DomainName {
    /// Creates a new DomainName from a string, applying validation.
    ///
    /// This is an alias for `FromStr::from_str()` that returns a DnsError
    /// instead of a string error message.
    ///
    /// # Arguments
    ///
    /// * `s` - Domain name in dotted notation (e.g., "www.example.com")
    ///
    /// # Returns
    ///
    /// A validated DomainName or a DnsError if validation fails.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let name = DomainName::new("example.com")?;
    /// assert_eq!(name.as_str(), "example.com");
    /// ```
    pub fn new(s: &str) -> Result<Self, DnsError> {
        Self::from_str(s).map_err(|e| DnsError::InvalidName { name: s.to_string(), reason: e })
    }

    /// Creates a new domain name pattern with wildcard support.
    ///
    /// This is a specialized constructor for creating domain patterns used in
    /// matching logic (e.g., `*.example.com`). Unlike `new()`, this allows
    /// wildcard characters (`*`) in labels for pattern matching purposes.
    ///
    /// # Arguments
    ///
    /// * `pattern` - Domain pattern string (may include wildcard labels like `*`)
    ///
    /// # Returns
    ///
    /// A DomainName that may contain wildcards, or a DnsError if basic validation fails.
    ///
    /// # Validation
    ///
    /// - Allows `*` as a complete label (e.g., `*.example.com` or `*.*.example.com`)
    /// - Non-wildcard labels follow normal RFC 1035 rules
    /// - Total length ≤ 255 bytes (including wildcards)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let wildcard = DomainName::new_pattern("*.example.com")?;
    /// let multi_wildcard = DomainName::new_pattern("*.*.example.com")?;
    /// let normal = DomainName::new_pattern("example.com")?;
    /// ```
    pub fn new_pattern(pattern: &str) -> Result<Self, DnsError> {
        // Basic length check
        if pattern.is_empty() {
            return Err(DnsError::InvalidName {
                name: pattern.to_string(),
                reason: "Domain pattern cannot be empty".to_string(),
            });
        }

        if pattern.len() > MAX_NAME_LEN {
            return Err(DnsError::InvalidName {
                name: pattern.to_string(),
                reason: format!(
                    "Domain pattern exceeds maximum length {}: {} bytes",
                    MAX_NAME_LEN,
                    pattern.len()
                ),
            });
        }

        // Create the domain name with the pattern string
        let name = DomainName {
            name: pattern.trim_end_matches('.').to_string(),
        };

        // Validate each label, allowing '*' as a complete label
        let labels: Vec<&str> = name.labels().collect();
        for label in labels {
            // Allow '*' as a complete label (wildcard)
            if label == "*" {
                continue;
            }

            // For non-wildcard labels, perform standard validation
            // Check label length
            if label.is_empty() {
                return Err(DnsError::InvalidName {
                    name: pattern.to_string(),
                    reason: "Empty label found".to_string(),
                });
            }

            if label.len() > MAX_LABEL_LEN {
                return Err(DnsError::InvalidName {
                    name: pattern.to_string(),
                    reason: format!("Label '{}' exceeds maximum length {}", label, MAX_LABEL_LEN),
                });
            }

            // Check for leading/trailing hyphens
            if label.starts_with('-') || label.ends_with('-') {
                return Err(DnsError::InvalidName {
                    name: pattern.to_string(),
                    reason: format!("Label '{}' has leading or trailing hyphen", label),
                });
            }

            // Check character set (alphanumeric and hyphen only)
            for ch in label.chars() {
                if !ch.is_ascii_alphanumeric() && ch != '-' {
                    return Err(DnsError::InvalidName {
                        name: pattern.to_string(),
                        reason: format!("Label '{}' contains invalid character '{}'", label, ch),
                    });
                }
            }
        }

        Ok(name)
    }

    /// Returns a string slice of the domain name in presentation format.
    ///
    /// Provides efficient access to the internal string without cloning.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let name = DomainName::from_str("example.com")?;
    /// assert_eq!(name.as_str(), "example.com");
    /// ```
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Returns an iterator over the individual labels of the domain name.
    ///
    /// Labels are returned from left to right (most specific to least specific).
    /// For "www.example.com", yields ["www", "example", "com"].
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let name = DomainName::from_str("www.example.com")?;
    /// let labels: Vec<&str> = name.labels().collect();
    /// assert_eq!(labels, vec!["www", "example", "com"]);
    /// ```
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.name.trim_end_matches('.').split('.')
    }

    /// Checks if this domain name is a subdomain of another domain.
    ///
    /// A domain is considered a subdomain if it has more labels than the parent
    /// and all the parent's labels match the rightmost labels of this domain
    /// (case-insensitive).
    ///
    /// # Arguments
    ///
    /// * `parent` - The potential parent domain to check against
    ///
    /// # Returns
    ///
    /// `true` if this is a subdomain of `parent`, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let subdomain = DomainName::from_str("www.example.com")?;
    /// let domain = DomainName::from_str("example.com")?;
    /// assert!(subdomain.is_subdomain_of(&domain));
    ///
    /// let unrelated = DomainName::from_str("example.org")?;
    /// assert!(!subdomain.is_subdomain_of(&unrelated));
    /// ```
    pub fn is_subdomain_of(&self, parent: &DomainName) -> bool {
        let self_labels: Vec<&str> = self.labels().collect();
        let parent_labels: Vec<&str> = parent.labels().collect();

        // Must have more labels to be a subdomain
        if self_labels.len() <= parent_labels.len() {
            return false;
        }

        // Check if parent labels match rightmost labels of self (case-insensitive)
        let self_suffix = &self_labels[self_labels.len() - parent_labels.len()..];
        self_suffix.iter().zip(parent_labels.iter()).all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// Returns the length of the domain name in presentation format.
    ///
    /// This is the byte length of the string representation (e.g., "example.com" = 11).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let name = DomainName::from_str("example.com")?;
    /// assert_eq!(name.len(), 11);
    /// ```
    pub fn len(&self) -> usize {
        self.name.len()
    }

    /// Checks if the domain name is empty (root domain only).
    ///
    /// Returns `true` only for the root domain ("." or "").
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let root = DomainName::from_str(".")?;
    /// assert!(root.is_empty());
    ///
    /// let name = DomainName::from_str("example.com")?;
    /// assert!(!name.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.name.is_empty() || self.name == "."
    }

    /// Serializes the domain name to DNS wire format.
    ///
    /// Converts the presentation format name to wire format with length-prefixed labels.
    /// Optionally uses compression pointers if a CompressionMap is provided and matching
    /// suffixes are found in the map.
    ///
    /// Wire format structure:
    /// - Each label: 1 byte length + N bytes data
    /// - Terminator: 0x00
    /// - Or compression pointer: 0xC0 + 2-byte offset
    ///
    /// # Arguments
    ///
    /// * `buffer` - The output buffer to write wire format bytes
    /// * `compression` - Optional compression map for generating compression pointers
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a DnsError if serialization fails.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let name = DomainName::from_str("example.com")?;
    /// let mut buffer = BytesMut::new();
    /// name.to_wire(&mut buffer, None)?;
    /// // buffer now contains: 07 65 78 61 6D 70 6C 65 03 63 6F 6D 00
    /// ```
    pub fn to_wire(
        &self,
        buffer: &mut BytesMut,
        compression: Option<&CompressionMap>,
    ) -> Result<(), DnsError> {
        // Convert to wire format (length-prefixed labels)
        let wire_name = self.to_wire_format()?;

        // If compression is available, try to find a matching suffix
        if let Some(map) = compression {
            if let Some(offset) = map.find_suffix(&wire_name) {
                // Use compression pointer if offset fits in 14 bits
                if offset < 0x3FFF {
                    let pointer = ((COMPRESSION_POINTER as u16) << 8) | (offset as u16);
                    buffer.put_u16(pointer);
                    return Ok(());
                }
            }
        }

        // Write the full name in wire format
        buffer.put_slice(&wire_name);
        Ok(())
    }

    /// Parses a domain name from DNS wire format.
    ///
    /// Extracts a domain name from a DNS packet buffer, handling compression pointers
    /// per RFC 1035 Section 4.1.4. The function validates label lengths, enforces the
    /// maximum hop count for compression pointers (255), and checks total name length.
    ///
    /// # Arguments
    ///
    /// * `packet` - The complete DNS packet (needed for resolving compression pointers)
    /// * `offset` - The starting offset within the packet where the name begins
    ///
    /// # Returns
    ///
    /// A tuple of (DomainName, next_offset) where next_offset points past the name.
    /// Returns a DnsError if parsing fails due to malformed data.
    ///
    /// # Compression Pointer Handling
    ///
    /// Compression pointers (0xC0 + offset) reference earlier positions in the packet.
    /// The parser follows pointers while maintaining the original position for returning
    /// the correct next offset after the name.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let packet = Bytes::from_static(&[/* DNS packet bytes */]);
    /// let (name, next_offset) = DomainName::from_wire(&packet, 12)?;
    /// println!("Parsed name: {}", name);
    /// // Continue parsing from next_offset
    /// ```
    pub fn from_wire(packet: &Bytes, mut offset: usize) -> Result<(Self, usize), DnsError> {
        let mut labels = Vec::new();
        let mut hops = 0;
        let mut first_pointer = None;
        let mut total_len = 0;

        loop {
            // Bounds check
            if offset >= packet.len() {
                return Err(DnsError::ParseFailed {
                    server: "packet".to_string(),
                    reason: "Offset out of bounds".to_string(),
                });
            }

            let len = packet[offset] as usize;

            // Check for null terminator (end of name)
            if len == 0 {
                offset += 1;
                break;
            }

            // Check for compression pointer (0xC0)
            if len & 0xC0 == 0xC0 {
                // Compression pointer: next byte forms 14-bit offset
                if offset + 1 >= packet.len() {
                    return Err(DnsError::ParseFailed {
                        server: "packet".to_string(),
                        reason: "Incomplete compression pointer".to_string(),
                    });
                }

                // Extract pointer offset
                let pointer_offset = ((len & 0x3F) << 8) | (packet[offset + 1] as usize);

                // Save first pointer position for returning correct next offset
                if first_pointer.is_none() {
                    first_pointer = Some(offset + 2);
                }

                // Jump to pointer location
                offset = pointer_offset;

                // Prevent infinite loops
                hops += 1;
                if hops > 255 {
                    return Err(DnsError::ParseFailed {
                        server: "packet".to_string(),
                        reason: "Too many compression pointer hops".to_string(),
                    });
                }

                continue;
            }

            // Regular label
            if len > MAX_LABEL_LEN {
                return Err(DnsError::InvalidName {
                    name: "parsed".to_string(),
                    reason: format!("Label length {} exceeds maximum {}", len, MAX_LABEL_LEN),
                });
            }

            // Check bounds for label data
            if offset + 1 + len > packet.len() {
                return Err(DnsError::ParseFailed {
                    server: "packet".to_string(),
                    reason: "Label data out of bounds".to_string(),
                });
            }

            // Extract label bytes
            let label_bytes = &packet[offset + 1..offset + 1 + len];
            let label =
                String::from_utf8(label_bytes.to_vec()).map_err(|_| DnsError::InvalidName {
                    name: "parsed".to_string(),
                    reason: "Invalid UTF-8 in label".to_string(),
                })?;

            labels.push(label);
            total_len += len + 1; // +1 for length byte

            offset += 1 + len;

            // Check total length
            if total_len > MAX_NAME_LEN {
                return Err(DnsError::InvalidName {
                    name: labels.join("."),
                    reason: format!(
                        "Total name length {} exceeds maximum {}",
                        total_len, MAX_NAME_LEN
                    ),
                });
            }
        }

        // Construct the domain name
        let name = if labels.is_empty() {
            ".".to_string() // Root domain
        } else {
            labels.join(".")
        };

        // Use first_pointer as next offset if we followed pointers, otherwise current offset
        let next_offset = first_pointer.unwrap_or(offset);

        Ok((DomainName { name }, next_offset))
    }

    /// Validates the domain name according to RFC 1035 rules.
    ///
    /// Checks:
    /// - Total name length ≤ 255 bytes in wire format
    /// - Each label length ≤ 63 bytes
    /// - Labels contain only alphanumeric characters and hyphens
    /// - Labels do not start or end with hyphens
    /// - Name is not empty (unless root)
    ///
    /// # Returns
    ///
    /// `Ok(())` if valid, or a DnsError describing the validation failure.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let name = DomainName::from_str("example.com")?;
    /// name.validate()?; // Returns Ok(())
    ///
    /// let invalid = DomainName { name: "invalid..name".to_string() };
    /// assert!(invalid.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<(), DnsError> {
        // Check for empty name (only root "." is allowed)
        if self.name.is_empty() || self.name == "." {
            return Ok(());
        }

        let labels: Vec<&str> = self.labels().collect();

        // Calculate wire format length (each label: 1 byte len + N bytes data + 1 null terminator)
        let wire_len: usize = labels.iter().map(|l| 1 + l.len()).sum::<usize>() + 1;
        if wire_len > MAX_NAME_LEN {
            return Err(DnsError::InvalidName {
                name: self.name.clone(),
                reason: format!(
                    "Total wire format length {} exceeds maximum {}",
                    wire_len, MAX_NAME_LEN
                ),
            });
        }

        // Validate each label
        for label in labels {
            // Check label length
            if label.is_empty() {
                return Err(DnsError::InvalidName {
                    name: self.name.clone(),
                    reason: "Empty label found".to_string(),
                });
            }

            if label.len() > MAX_LABEL_LEN {
                return Err(DnsError::InvalidName {
                    name: self.name.clone(),
                    reason: format!("Label '{}' exceeds maximum length {}", label, MAX_LABEL_LEN),
                });
            }

            // Check for leading/trailing hyphens
            if label.starts_with('-') || label.ends_with('-') {
                return Err(DnsError::InvalidName {
                    name: self.name.clone(),
                    reason: format!("Label '{}' has leading or trailing hyphen", label),
                });
            }

            // Check character set (alphanumeric, hyphen, and underscore)
            // Note: Underscores are allowed for service names (RFC 2782) like _http._tcp
            for ch in label.chars() {
                if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
                    return Err(DnsError::InvalidName {
                        name: self.name.clone(),
                        reason: format!("Invalid character '{}' in label '{}'", ch, label),
                    });
                }
            }
        }

        Ok(())
    }

    /// Converts the presentation format name to wire format (length-prefixed labels).
    ///
    /// Internal helper method for serialization. Produces a byte vector with:
    /// - Each label: 1 byte length + N bytes label data
    /// - Null terminator: 0x00
    ///
    /// # Returns
    ///
    /// A Vec<u8> containing the wire format representation, or a DnsError.
    fn to_wire_format(&self) -> Result<Vec<u8>, DnsError> {
        let mut result = Vec::new();

        // Handle root domain
        if self.name.is_empty() || self.name == "." {
            result.push(0);
            return Ok(result);
        }

        // Encode each label
        for label in self.labels() {
            let label_bytes = label.as_bytes();
            if label_bytes.len() > MAX_LABEL_LEN {
                return Err(DnsError::InvalidName {
                    name: self.name.clone(),
                    reason: format!("Label '{}' exceeds maximum length", label),
                });
            }

            result.push(label_bytes.len() as u8);
            result.extend_from_slice(label_bytes);
        }

        // Null terminator
        result.push(0);

        Ok(result)
    }
}

impl FromStr for DomainName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Handle IDNA encoding if feature is enabled
        #[cfg(feature = "idn")]
        let s = {
            // Check if domain contains non-ASCII characters
            if !s.is_ascii() {
                // Convert to ASCII using IDNA Punycode encoding
                match domain_to_ascii(s) {
                    Ok(ascii) => ascii,
                    Err(errors) => {
                        return Err(format!("IDNA encoding failed: {:?}", errors));
                    }
                }
            } else {
                s.to_string()
            }
        };

        #[cfg(not(feature = "idn"))]
        let s = s;

        // Create the domain name
        let name = DomainName { name: s.trim_end_matches('.').to_string() };

        // Validate
        name.validate().map_err(|e| match e {
            DnsError::InvalidName { reason, .. } => reason,
            _ => "Validation failed".to_string(),
        })?;

        Ok(name)
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl PartialEq for DomainName {
    fn eq(&self, other: &Self) -> bool {
        // Case-insensitive comparison per RFC 1035 Section 3.1
        self.name.eq_ignore_ascii_case(&other.name)
    }
}

impl Eq for DomainName {}

impl PartialOrd for DomainName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DomainName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Case-insensitive comparison per RFC 1035 Section 3.1
        // Convert both names to lowercase for consistent ordering
        self.name.to_ascii_lowercase().cmp(&other.name.to_ascii_lowercase())
    }
}

impl std::hash::Hash for DomainName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash lowercase version for case-insensitive equality
        self.name.to_ascii_lowercase().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_name_from_str() {
        let name = DomainName::from_str("www.example.com").unwrap();
        assert_eq!(name.as_str(), "www.example.com");
    }

    #[test]
    fn test_domain_name_case_insensitive() {
        let name1 = DomainName::from_str("Example.COM").unwrap();
        let name2 = DomainName::from_str("example.com").unwrap();
        assert_eq!(name1, name2);
    }

    #[test]
    fn test_label_too_long() {
        let long_label = "a".repeat(64);
        let result = DomainName::from_str(&long_label);
        assert!(result.is_err());
    }

    #[test]
    fn test_name_too_long() {
        // Create a name that exceeds 255 bytes in wire format
        let long_name =
            format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(63));
        let result = DomainName::from_str(&long_name);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_characters() {
        // Test various invalid characters (underscores are now allowed for service names)
        let result = DomainName::from_str("invalid name.com"); // space not allowed
        assert!(result.is_err());
        
        let result = DomainName::from_str("invalid@name.com"); // @ not allowed
        assert!(result.is_err());
        
        let result = DomainName::from_str("invalid!name.com"); // ! not allowed
        assert!(result.is_err());
    }

    #[test]
    fn test_leading_hyphen() {
        let result = DomainName::from_str("-invalid.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_trailing_hyphen() {
        let result = DomainName::from_str("invalid-.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_subdomain_of() {
        let subdomain = DomainName::from_str("www.example.com").unwrap();
        let domain = DomainName::from_str("example.com").unwrap();
        assert!(subdomain.is_subdomain_of(&domain));

        let unrelated = DomainName::from_str("example.org").unwrap();
        assert!(!subdomain.is_subdomain_of(&unrelated));

        // Domain is not a subdomain of itself
        assert!(!domain.is_subdomain_of(&domain));
    }

    #[test]
    fn test_labels_iterator() {
        let name = DomainName::from_str("www.example.com").unwrap();
        let labels: Vec<&str> = name.labels().collect();
        assert_eq!(labels, vec!["www", "example", "com"]);
    }

    #[test]
    fn test_root_domain() {
        let root = DomainName::from_str(".").unwrap();
        assert!(root.is_empty());
        assert_eq!(root.len(), 0);
    }

    #[test]
    fn test_to_wire_format() {
        let name = DomainName::from_str("example.com").unwrap();
        let wire = name.to_wire_format().unwrap();

        // Expected: 7 "example" 3 "com" 0
        assert_eq!(wire[0], 7); // Length of "example"
        assert_eq!(&wire[1..8], b"example");
        assert_eq!(wire[8], 3); // Length of "com"
        assert_eq!(&wire[9..12], b"com");
        assert_eq!(wire[12], 0); // Null terminator
    }

    #[test]
    fn test_to_wire_with_buffer() {
        let name = DomainName::from_str("example.com").unwrap();
        let mut buffer = BytesMut::new();
        name.to_wire(&mut buffer, None).unwrap();

        assert_eq!(buffer[0], 7);
        assert_eq!(&buffer[1..8], b"example");
        assert_eq!(buffer[8], 3);
        assert_eq!(&buffer[9..12], b"com");
        assert_eq!(buffer[12], 0);
    }

    #[test]
    fn test_from_wire_simple() {
        // Create wire format: 7 "example" 3 "com" 0
        let mut packet_vec = vec![7];
        packet_vec.extend_from_slice(b"example");
        packet_vec.push(3);
        packet_vec.extend_from_slice(b"com");
        packet_vec.push(0);

        let packet = Bytes::from(packet_vec);
        let (name, next_offset) = DomainName::from_wire(&packet, 0).unwrap();

        assert_eq!(name.as_str(), "example.com");
        assert_eq!(next_offset, 13); // Past the null terminator
    }

    #[test]
    fn test_from_wire_with_compression() {
        // Create a packet with compression pointer
        // First name: 3 "www" 7 "example" 3 "com" 0 (starts at offset 0)
        // Second name: 3 "ftp" C0 04 (compression pointer to offset 4 = "example.com")
        let mut packet_vec = vec![3];
        packet_vec.extend_from_slice(b"www");
        packet_vec.push(7);
        packet_vec.extend_from_slice(b"example");
        packet_vec.push(3);
        packet_vec.extend_from_slice(b"com");
        packet_vec.push(0); // Offset 16 (null terminator for first name)

        // Second name starts at offset 17
        packet_vec.push(3);
        packet_vec.extend_from_slice(b"ftp");
        packet_vec.push(0xC0); // Compression pointer
        packet_vec.push(4); // Offset 4 points to "example.com"

        let packet = Bytes::from(packet_vec);

        // Parse second name
        let (name, next_offset) = DomainName::from_wire(&packet, 17).unwrap();
        assert_eq!(name.as_str(), "ftp.example.com");
        assert_eq!(next_offset, 23); // Past the compression pointer
    }

    #[test]
    fn test_display() {
        let name = DomainName::from_str("example.com").unwrap();
        assert_eq!(format!("{}", name), "example.com");
    }

    #[test]
    fn test_hash_case_insensitive() {
        use std::collections::HashMap;

        let mut map = HashMap::new();
        let name1 = DomainName::from_str("Example.COM").unwrap();
        map.insert(name1, 42);

        let name2 = DomainName::from_str("example.com").unwrap();
        assert_eq!(map.get(&name2), Some(&42));
    }

    #[test]
    fn test_trailing_dot_removal() {
        let name1 = DomainName::from_str("example.com.").unwrap();
        let name2 = DomainName::from_str("example.com").unwrap();
        assert_eq!(name1, name2);
        assert_eq!(name1.as_str(), "example.com");
    }

    #[cfg(feature = "idn")]
    #[test]
    fn test_idna_encoding() {
        // Test Punycode encoding for internationalized domain
        let name = DomainName::from_str("münchen.de").unwrap();
        // Should be encoded as "xn--mnchen-3ya.de"
        assert!(name.as_str().starts_with("xn--"));
    }
}
