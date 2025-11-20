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

//! DNSSEC Trust Anchor Management
//!
//! This module implements trust anchor configuration parsing, storage, and RFC 5011
//! automated key rollover support for DNSSEC validation chain termination. Trust
//! anchors represent known-good DNSKEY records (in DS record format per RFC 4034)
//! that anchor the chain of trust from the DNS root down to specific zones.
//!
//! # Key Features
//!
//! - Trust anchor configuration parsing from trust-anchors.conf format
//! - DS record format support with hex digest decoding
//! - Longest-match zone lookup for trust anchor discovery
//! - RFC 5011 automated trust anchor rollover with revocation detection
//! - Efficient storage using BTreeMap for O(log n) zone lookups
//!
//! # RFC Compliance
//!
//! - RFC 4034: Resource Records for DNSSEC (DS record format)
//! - RFC 5011: Automated Updates of DNS Security (DNSSEC) Trust Anchors
//! - RFC 4034 Section 5.1.4: Whitespace tolerance in hex digests
//!
//! # trust-anchors.conf Format
//!
//! ```text
//! # Root zone trust anchor (DS record format)
//! trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
//!
//! # Zone-specific trust anchor with class
//! trust-anchor=example.com,IN,12345,8,1,1234567890ABCDEF
//!
//! # Multiple trust anchors per zone (key rollover)
//! trust-anchor=example.org,54321,8,2,FEDCBA0987654321
//! trust-anchor=example.org,54322,8,2,1234567890ABCDEF
//! ```
//!
//! # Memory Safety
//!
//! Replaces C daemon->ds_config linked list with manual malloc/free from option.c
//! with Rust BTreeMap providing automatic memory management and type-safe operations.
//! Eliminates buffer overflows in hex digest parsing through Vec<u8> bounds checking.

use crate::dns::protocol::name::DomainName;
use crate::error::Result;
use hex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use tokio::fs;
use tracing::{debug, error, info, warn};

/// DNS class constant for Internet (IN) class per RFC 1035.
const C_IN: u16 = 1;

/// DNS class constant for Chaos (CH) class per RFC 1035.
const C_CHAOS: u16 = 3;

/// DNS class constant for Hesiod (HS) class per RFC 1035.
const C_HESIOD: u16 = 4;

/// SHA-1 digest type per RFC 4034 Section 5.1.1.
const DIGEST_SHA1: u8 = 1;

/// SHA-256 digest type per RFC 4034 Section 5.1.1.
const DIGEST_SHA256: u8 = 2;

/// SHA-384 digest type per RFC 4034 Section 5.2.
const DIGEST_SHA384: u8 = 4;

/// SHA-1 digest length in bytes (160 bits).
const SHA1_DIGEST_LEN: usize = 20;

/// SHA-256 digest length in bytes (256 bits).
const SHA256_DIGEST_LEN: usize = 32;

/// SHA-384 digest length in bytes (384 bits).
const SHA384_DIGEST_LEN: usize = 48;

/// RFC 5011 automated trust anchor rollover state.
///
/// Tracks the lifecycle state of a trust anchor undergoing automated key rollover
/// per RFC 5011 Section 3. Trust anchors transition through states based on timer
/// expiration and DNSKEY flags (revoked bit) inspection.
///
/// # State Transitions
///
/// ```text
/// AddHold → Hold → Valid
///    ↓       ↓       ↓
///    └───────┴───→ Removed (on revocation)
/// ```
///
/// # RFC 5011 Timer Semantics
///
/// - **AddHold**: New key seen; waiting add-hold-down period (30 days default)
/// - **Hold**: Key confirmed valid; waiting hold-down period (30 days default)
/// - **Valid**: Key is active and trusted for validation
/// - **Removed**: Key revoked (DNSKEY flags bit 8 set); removed from trust set
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rfc5011State {
    /// New trust anchor in add-hold-down timer state.
    ///
    /// Trust anchor has been seen in DNSKEY RRset but is not yet trusted.
    /// Waiting for add-hold-down timer to expire before transitioning to Hold.
    AddHold,

    /// Trust anchor in hold-down timer state.
    ///
    /// Trust anchor has passed add-hold-down and is confirmed valid.
    /// Waiting for hold-down timer to expire before transitioning to Valid.
    Hold,

    /// Trust anchor is active and trusted for validation.
    ///
    /// This is the normal operational state for trust anchors actively used
    /// in DNSSEC validation chain termination.
    Valid,

    /// Trust anchor has been revoked and removed from trust set.
    ///
    /// DNSKEY flags indicate revocation (bit 8 set). This key must not be
    /// used for validation and will be removed from the trust anchor store.
    Removed,
}

/// DNSSEC trust anchor in DS record format per RFC 4034.
///
/// Represents a Delegation Signer (DS) resource record that serves as a trust
/// anchor for DNSSEC validation. Trust anchors are the root of the DNSSEC chain
/// of trust and are configured out-of-band (via trust-anchors.conf) rather than
/// discovered through DNS queries.
///
/// # DS Record Format (RFC 4034 Section 5)
///
/// ```text
/// DS RR = {
///     domain: owner name (zone apex)
///     class: DNS class (IN, CH, HS)
///     keytag: DNSKEY key identifier (u16)
///     algorithm: DNSSEC algorithm (u8)
///     digest_type: Hash algorithm (u8)
///     digest: Hash of DNSKEY (variable length)
/// }
/// ```
///
/// # Memory Layout
///
/// Replaces C struct ds_config:
///
/// ```c
/// struct ds_config {
///     char *name;           // domain name (malloc'd)
///     int class;            // DNS class
///     int keytag;           // key tag
///     int algo;             // algorithm
///     int digest_type;      // digest type
///     char *digest;         // hex digest (malloc'd)
///     int digestlen;        // digest length
///     struct ds_config *next; // linked list pointer
/// };
/// ```
///
/// Rust version uses owned types (String, Vec<u8>) for automatic memory management.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchor {
    /// Domain name (zone apex) this trust anchor applies to.
    ///
    /// Trust anchors are matched using longest-match zone lookup walking from
    /// query name to root (example.com → com → .) until a matching zone is found.
    pub domain: DomainName,

    /// DNS class code (default C_IN = 1 for Internet class).
    ///
    /// Supports IN (1), CH (3), and HS (4) per RFC 1035. Most deployments use IN.
    pub class: u16,

    /// DNSKEY key tag per RFC 4034 Section 5.1.1.
    ///
    /// 16-bit identifier computed from DNSKEY RDATA. Used to select which DNSKEY
    /// record this DS record references. Multiple DS records with different keytags
    /// may exist during key rollovers.
    pub keytag: u16,

    /// DNSSEC algorithm per RFC 4034 Appendix A.1.
    ///
    /// Common values:
    /// - 5: RSA/SHA-1
    /// - 7: RSASHA1-NSEC3-SHA1
    /// - 8: RSA/SHA-256
    /// - 10: RSA/SHA-512
    /// - 13: ECDSA Curve P-256 with SHA-256
    /// - 14: ECDSA Curve P-384 with SHA-384
    /// - 15: Ed25519
    pub algorithm: u8,

    /// Digest type per RFC 4034 Section 5.1.1.
    ///
    /// Specifies hash algorithm used to generate digest:
    /// - 1: SHA-1 (deprecated, 20 bytes)
    /// - 2: SHA-256 (recommended, 32 bytes)
    /// - 4: SHA-384 (optional, 48 bytes)
    pub digest_type: u8,

    /// Hash digest of DNSKEY RDATA.
    ///
    /// Variable-length byte vector containing digest of corresponding DNSKEY.
    /// Length depends on digest_type:
    /// - SHA-1: 20 bytes
    /// - SHA-256: 32 bytes
    /// - SHA-384: 48 bytes
    ///
    /// Parsed from hex string in trust-anchors.conf with whitespace tolerance
    /// per RFC 4034 Section 5.1.4: "Whitespace is allowed within digits".
    pub digest: Vec<u8>,

    /// RFC 5011 automated rollover state (optional).
    ///
    /// Tracks trust anchor lifecycle for automated updates. None indicates
    /// a static trust anchor that does not participate in RFC 5011 rollover.
    pub rfc5011_status: Option<Rfc5011State>,
}

impl TrustAnchor {
    /// Creates a new trust anchor with specified parameters.
    ///
    /// # Arguments
    ///
    /// * `domain` - Zone apex domain name
    /// * `class` - DNS class (typically C_IN for Internet)
    /// * `keytag` - DNSKEY key tag identifier
    /// * `algorithm` - DNSSEC algorithm number
    /// * `digest_type` - Hash algorithm identifier
    /// * `digest` - Hash digest bytes
    ///
    /// # Returns
    ///
    /// A Result containing the constructed TrustAnchor or an error if validation fails.
    pub fn new(
        domain: DomainName,
        class: u16,
        keytag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    ) -> Result<Self> {
        // Create the anchor first
        let anchor =
            Self { domain, class, keytag, algorithm, digest_type, digest, rfc5011_status: None };

        // Validate all parameters before returning
        anchor.validate()?;

        Ok(anchor)
    }

    /// Validates digest length matches expected length for digest type.
    fn validate_digest_length(digest_type: u8, digest_len: usize) -> Result<()> {
        let expected_len = match digest_type {
            DIGEST_SHA1 => SHA1_DIGEST_LEN,
            DIGEST_SHA256 => SHA256_DIGEST_LEN,
            DIGEST_SHA384 => SHA384_DIGEST_LEN,
            _ => {
                return Err(crate::error::DnsmasqError::Dnssec(
                    crate::error::DnssecError::TrustAnchorFailed {
                        reason: format!("Invalid digest type: {}", digest_type),
                    },
                ))
            }
        };

        if digest_len != expected_len {
            return Err(crate::error::DnsmasqError::Dnssec(
                crate::error::DnssecError::TrustAnchorFailed {
                    reason: format!(
                        "Invalid digest length for type {}: expected {}, got {}",
                        digest_type, expected_len, digest_len
                    ),
                },
            ));
        }

        Ok(())
    }

    /// Validates the trust anchor parameters.
    ///
    /// Performs comprehensive validation including:
    /// - Algorithm validity (must be known DNSSEC algorithm)
    /// - Digest type validity (1=SHA1, 2=SHA256, 4=SHA384)
    /// - Digest length consistency with digest type
    /// - Keytag range (0-65535, validated by type)
    ///
    /// # Returns
    ///
    /// Result indicating success or specific validation error.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Algorithm is not a recognized DNSSEC algorithm
    /// - Digest type is not supported (not 1, 2, or 4)
    /// - Digest length doesn't match digest type requirements
    pub fn validate(&self) -> Result<()> {
        // Validate algorithm (check against known DNSSEC algorithms)
        // Common algorithms: 1=RSAMD5, 3=DSA, 5=RSASHA1, 7=RSASHA1-NSEC3-SHA1,
        // 8=RSASHA256, 10=RSASHA512, 13=ECDSAP256SHA256, 14=ECDSAP384SHA384, 15=ED25519, 16=ED448
        const VALID_ALGORITHMS: &[u8] = &[1, 3, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16];

        if !VALID_ALGORITHMS.contains(&self.algorithm) {
            return Err(crate::error::DnsmasqError::Dnssec(
                crate::error::DnssecError::TrustAnchorFailed {
                    reason: format!("Invalid DNSSEC algorithm: {}", self.algorithm),
                },
            ));
        }

        // Validate digest type and length
        Self::validate_digest_length(self.digest_type, self.digest.len())?;

        Ok(())
    }

    /// Returns the domain name for this trust anchor.
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// Returns the DNS class for this trust anchor.
    pub fn class(&self) -> u16 {
        self.class
    }

    /// Returns the keytag for this trust anchor.
    pub fn keytag(&self) -> u16 {
        self.keytag
    }

    /// Returns the algorithm for this trust anchor.
    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Returns the digest type for this trust anchor.
    pub fn digest_type(&self) -> u8 {
        self.digest_type
    }

    /// Returns the digest bytes for this trust anchor.
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Returns the RFC 5011 state for this trust anchor, if any.
    pub fn rfc5011_state(&self) -> Option<&Rfc5011State> {
        self.rfc5011_status.as_ref()
    }

    /// Sets the RFC 5011 state for this trust anchor.
    ///
    /// Used during automated trust anchor rollover to track key lifecycle states.
    ///
    /// # Arguments
    ///
    /// * `state` - New RFC 5011 state
    pub fn set_rfc5011_state(&mut self, state: Option<Rfc5011State>) {
        self.rfc5011_status = state;
    }
}

/// Trust anchor storage and lookup.
///
/// Manages a collection of DNSSEC trust anchors with efficient longest-match zone
/// lookup for validation chain termination. Replaces C daemon->ds_config linked list
/// with Rust BTreeMap providing O(log n) lookup performance and automatic memory management.
///
/// # Storage Organization
///
/// Trust anchors are stored in a BTreeMap keyed by domain name, with each domain
/// potentially having multiple trust anchors (during key rollovers):
///
/// ```text
/// BTreeMap<DomainName, Vec<TrustAnchor>>
///   . → [TrustAnchor { keytag: 20326, ... }, ...]
///   com → [TrustAnchor { keytag: 12345, ... }]
///   example.com → [TrustAnchor { keytag: 54321, ... }, TrustAnchor { keytag: 54322, ... }]
/// ```
///
/// # Longest-Match Zone Lookup
///
/// When validating a query for "www.example.com", the store walks the DNS tree from
/// the query name to the root until a trust anchor is found:
///
/// ```text
/// www.example.com → (no match)
/// example.com → (match found!)
/// com → (not checked)
/// . → (fallback)
/// ```
///
/// This mimics DNS delegation and ensures the most specific trust anchor is used.
///
/// # RFC 5011 Rollover Support
///
/// The store supports automated trust anchor updates via RFC 5011 by tracking
/// rollover state (AddHold, Hold, Valid, Removed) and providing methods to add
/// new anchors and remove revoked anchors based on DNSKEY flags inspection.
#[derive(Debug, Clone)]
pub struct TrustAnchorStore {
    /// Trust anchors indexed by zone name for efficient lookup.
    ///
    /// BTreeMap provides ordered keys enabling efficient range queries for
    /// longest-match zone lookup. Vec<TrustAnchor> supports multiple trust
    /// anchors per zone during key rollover periods.
    anchors: BTreeMap<DomainName, Vec<TrustAnchor>>,
}

impl Default for TrustAnchorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustAnchorStore {
    /// Creates a new empty trust anchor store.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::dns::dnssec::trust_anchors::TrustAnchorStore;
    ///
    /// let store = TrustAnchorStore::new();
    /// assert_eq!(store.len(), 0);
    /// assert!(store.is_empty());
    /// ```
    pub fn new() -> Self {
        debug!("Creating new TrustAnchorStore");
        Self { anchors: BTreeMap::new() }
    }

    /// Loads trust anchors from a trust-anchors.conf file.
    ///
    /// Parses trust anchor configuration file using async I/O, maintaining compatibility
    /// with C dnsmasq trust-anchors.conf format. Handles comments (#), blank lines,
    /// and validates all trust anchor parameters.
    ///
    /// # trust-anchors.conf Format
    ///
    /// Each line follows DS record format:
    /// ```text
    /// trust-anchor=<domain>,<keytag>,<algorithm>,<digest_type>,<hex_digest>
    /// trust-anchor=<domain>,<class>,<keytag>,<algorithm>,<digest_type>,<hex_digest>
    /// ```
    ///
    /// Where:
    /// - `domain`: Zone apex (e.g., ".", "com", "example.com")
    /// - `class`: DNS class (optional, "IN", "CH", "HS"; defaults to IN)
    /// - `keytag`: DNSKEY key tag (0-65535)
    /// - `algorithm`: DNSSEC algorithm number (1-255)
    /// - `digest_type`: Hash algorithm (1=SHA1, 2=SHA256, 4=SHA384)
    /// - `hex_digest`: Hexadecimal digest with optional whitespace per RFC 4034
    ///
    /// # Arguments
    ///
    /// * `path` - Path to trust-anchors.conf file
    ///
    /// # Returns
    ///
    /// Result indicating success or detailed parse/validation error.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - File cannot be read (I/O error)
    /// - Line parsing fails (invalid syntax)
    /// - Domain name invalid
    /// - Numeric parameters out of range
    /// - Hex digest malformed
    /// - Digest length mismatches digest type
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::dns::dnssec::trust_anchors::TrustAnchorStore;
    ///
    /// let mut store = TrustAnchorStore::new();
    /// store.load_from_file("/etc/dnsmasq/trust-anchors.conf").await?;
    /// ```
    pub async fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        info!("Loading trust anchors from: {}", path.display());

        // Read entire file asynchronously
        let content = fs::read_to_string(path).await.map_err(|e| {
            error!("Failed to read trust anchor file {}: {}", path.display(), e);
            crate::error::DnsmasqError::Dnssec(crate::error::DnssecError::TrustAnchorFailed {
                reason: format!("Failed to read file {}: {}", path.display(), e),
            })
        })?;

        let mut line_num = 0;
        let mut loaded_count = 0;

        // Parse line by line
        for line in content.lines() {
            line_num += 1;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse trust anchor line
            match self.parse_trust_anchor_line(line, line_num, path.to_str().unwrap_or("unknown")) {
                Ok(anchor) => {
                    debug!(
                        "Parsed trust anchor: domain={}, keytag={}, algorithm={}, digest_type={}",
                        anchor.domain.as_str(),
                        anchor.keytag,
                        anchor.algorithm,
                        anchor.digest_type
                    );
                    self.add_anchor(anchor)?;
                    loaded_count += 1;
                }
                Err(e) => {
                    error!("Error parsing line {}: {}", line_num, e);
                    return Err(e);
                }
            }
        }

        info!("Successfully loaded {} trust anchors from {}", loaded_count, path.display());
        Ok(())
    }

    /// Parses a single trust-anchor line from configuration.
    ///
    /// Handles both 5-field and 6-field formats (with optional class parameter).
    /// Implements RFC 4034 Section 5.1.4 whitespace tolerance in hex digests.
    ///
    /// # Arguments
    ///
    /// * `line` - Configuration line to parse
    /// * `line_num` - Line number for error reporting
    ///
    /// # Returns
    ///
    /// Result containing parsed TrustAnchor or detailed error.
    fn parse_trust_anchor_line(
        &self,
        line: &str,
        line_num: usize,
        file_path: &str,
    ) -> Result<TrustAnchor> {
        // Strip "trust-anchor=" prefix if present
        let line = line.strip_prefix("trust-anchor=").unwrap_or(line);

        // Split by comma
        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();

        if parts.len() < 5 {
            return Err(crate::error::DnsmasqError::Config(
                crate::error::ConfigError::ParseError {
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    reason: "trust-anchor requires at least 5 fields: domain,keytag,algorithm,digest_type,digest".to_string(),
                },
            ));
        }

        let domain_str = parts[0];

        // Determine if class is specified (check if second field is a class name)
        let (class, keytag_idx) = if parts.len() >= 6 {
            let maybe_class = parts[1].to_uppercase();
            let class = match maybe_class.as_str() {
                "IN" => C_IN,
                "CH" | "CHAOS" => C_CHAOS,
                "HS" | "HESIOD" => C_HESIOD,
                _ => C_IN, // Not a class, assume default IN
            };

            if ["IN", "CH", "CHAOS", "HS", "HESIOD"].contains(&maybe_class.as_str()) {
                // Class was specified, keytag starts at index 2
                (class, 2)
            } else {
                // Class not specified, default to IN, keytag at index 1
                (C_IN, 1)
            }
        } else {
            // Only 5 fields, default to IN, keytag at index 1
            (C_IN, 1)
        };

        // Parse remaining fields
        let keytag_str: &&str = parts.get(keytag_idx).ok_or_else(|| {
            crate::error::DnsmasqError::Config(crate::error::ConfigError::ParseError {
                file_path: file_path.to_string(),
                line_number: line_num,
                reason: "missing keytag field".to_string(),
            })
        })?;

        let algo_str: &&str = parts.get(keytag_idx + 1).ok_or_else(|| {
            crate::error::DnsmasqError::Config(crate::error::ConfigError::ParseError {
                file_path: file_path.to_string(),
                line_number: line_num,
                reason: "missing algorithm field".to_string(),
            })
        })?;

        let digest_type_str: &&str = parts.get(keytag_idx + 2).ok_or_else(|| {
            crate::error::DnsmasqError::Config(crate::error::ConfigError::ParseError {
                file_path: file_path.to_string(),
                line_number: line_num,
                reason: "missing digest_type field".to_string(),
            })
        })?;

        let digest_hex = parts.get(keytag_idx + 3).ok_or_else(|| {
            crate::error::DnsmasqError::Config(crate::error::ConfigError::ParseError {
                file_path: file_path.to_string(),
                line_number: line_num,
                reason: "missing digest field".to_string(),
            })
        })?;

        // Parse domain name
        let domain = DomainName::new(domain_str).map_err(|e| {
            crate::error::DnsmasqError::Config(crate::error::ConfigError::ParseError {
                file_path: file_path.to_string(),
                line_number: line_num,
                reason: format!("invalid domain '{}': {}", domain_str, e),
            })
        })?;

        // Parse keytag (u16)
        let keytag: u16 = keytag_str.parse().map_err(|_| {
            crate::error::DnsmasqError::Config(crate::error::ConfigError::ParseError {
                file_path: file_path.to_string(),
                line_number: line_num,
                reason: format!("invalid keytag '{}' (must be 0-65535)", keytag_str),
            })
        })?;

        // Parse algorithm (u8)
        let algorithm: u8 = algo_str.parse().map_err(|_| {
            crate::error::DnsmasqError::Config(crate::error::ConfigError::ParseError {
                file_path: file_path.to_string(),
                line_number: line_num,
                reason: format!("invalid algorithm '{}' (must be 0-255)", algo_str),
            })
        })?;

        // Parse digest type (u8)
        let digest_type: u8 = digest_type_str.parse().map_err(|_| {
            crate::error::DnsmasqError::Config(crate::error::ConfigError::ParseError {
                file_path: file_path.to_string(),
                line_number: line_num,
                reason: format!("invalid digest_type '{}' (must be 0-255)", digest_type_str),
            })
        })?;

        // Parse hex digest with whitespace tolerance per RFC 4034 Section 5.1.4
        let digest = Self::parse_hex_digest(digest_hex, line_num, file_path)?;

        // Construct and validate trust anchor
        TrustAnchor::new(domain, class, keytag, algorithm, digest_type, digest)
    }

    /// Parses hex digest string with RFC 4034 whitespace tolerance.
    ///
    /// RFC 4034 Section 5.1.4: "Whitespace is allowed within digits" in DS record
    /// presentation format. This method strips all whitespace before hex decoding.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - Hex digest string potentially containing whitespace
    /// * `line_num` - Line number for error reporting
    ///
    /// # Returns
    ///
    /// Result containing decoded bytes or error.
    fn parse_hex_digest(hex_str: &str, line_num: usize, file_path: &str) -> Result<Vec<u8>> {
        // Remove all whitespace per RFC 4034 Section 5.1.4
        let hex_clean: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();

        // Decode hex string
        hex::decode(&hex_clean).map_err(|e| {
            crate::error::DnsmasqError::Config(crate::error::ConfigError::ParseError {
                file_path: file_path.to_string(),
                line_number: line_num,
                reason: format!("invalid hex digest: {}", e),
            })
        })
    }

    /// Finds trust anchors for a domain using longest-match zone lookup.
    ///
    /// Implements DNS tree traversal from specific domain up to root, finding the
    /// most specific trust anchor zone. For example, for query "www.example.com":
    /// 1. Check for "www.example.com" trust anchor
    /// 2. Check for "example.com" trust anchor
    /// 3. Check for "com" trust anchor
    /// 4. Check for "." (root) trust anchor
    ///
    /// Returns all trust anchors for the first matching zone (multiple anchors
    /// may exist for a single zone during key rollover).
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to find trust anchor for
    ///
    /// # Returns
    ///
    /// Option containing slice of trust anchors if found, None otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::dns::dnssec::trust_anchors::TrustAnchorStore;
    /// use dnsmasq::dns::protocol::name::DomainName;
    ///
    /// let store = TrustAnchorStore::new();
    /// // ... load trust anchors ...
    ///
    /// let domain = DomainName::new("www.example.com")?;
    /// if let Some(anchors) = store.find_anchor(&domain) {
    ///     println!("Found {} trust anchors", anchors.len());
    /// }
    /// ```
    pub fn find_anchor(&self, domain: &DomainName) -> Option<&[TrustAnchor]> {
        // Try exact match first
        if let Some(anchors) = self.anchors.get(domain) {
            debug!("Found trust anchor for exact domain: {}", domain.as_str());
            return Some(anchors.as_slice());
        }

        // Walk up DNS tree to find closest enclosing zone
        let domain_str = domain.as_str();
        let labels: Vec<&str> = domain_str.split('.').filter(|s| !s.is_empty()).collect();

        // Try each parent zone from most specific to least specific
        for i in 1..labels.len() {
            let parent_name = labels[i..].join(".");
            if let Ok(parent_domain) = DomainName::new(&parent_name) {
                if let Some(anchors) = self.anchors.get(&parent_domain) {
                    debug!(
                        "Found trust anchor for parent zone: {} (queried: {})",
                        parent_domain.as_str(),
                        domain.as_str()
                    );
                    return Some(anchors.as_slice());
                }
            }
        }

        // Try root zone "."
        if let Ok(root_domain) = DomainName::new(".") {
            if let Some(anchors) = self.anchors.get(&root_domain) {
                debug!("Found trust anchor for root zone (queried: {})", domain.as_str());
                return Some(anchors.as_slice());
            }
        }

        debug!("No trust anchor found for domain: {}", domain.as_str());
        None
    }

    /// Adds a trust anchor to the store.
    ///
    /// Adds trust anchor for domain, supporting multiple anchors per zone during
    /// RFC 5011 key rollover periods. Performs validation before adding.
    ///
    /// # Arguments
    ///
    /// * `anchor` - TrustAnchor to add
    ///
    /// # Returns
    ///
    /// Result indicating success or validation error.
    ///
    /// # Errors
    ///
    /// Returns error if anchor validation fails (invalid keytag, algorithm, etc.)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::dns::dnssec::trust_anchors::{TrustAnchorStore, TrustAnchor};
    /// use dnsmasq::dns::protocol::name::DomainName;
    ///
    /// let mut store = TrustAnchorStore::new();
    /// let domain = DomainName::new(".")?;
    /// let anchor = TrustAnchor::new(domain, 1, 20326, 8, 2, vec![/* digest */])?;
    /// store.add_anchor(anchor)?;
    /// ```
    pub fn add_anchor(&mut self, anchor: TrustAnchor) -> Result<()> {
        // Validate anchor before adding
        anchor.validate()?;

        let domain = anchor.domain.clone();
        info!(
            "Adding trust anchor: domain={}, keytag={}, algorithm={}",
            domain.as_str(),
            anchor.keytag,
            anchor.algorithm
        );

        // Add to appropriate zone in BTreeMap
        self.anchors.entry(domain).or_default().push(anchor);

        Ok(())
    }

    /// Removes a specific trust anchor from the store.
    ///
    /// Removes trust anchor matching domain and keytag. Used for RFC 5011 automated
    /// rollover when keys are revoked (REVOKE bit set in DNSKEY flags).
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name of trust anchor to remove
    /// * `keytag` - Key tag of trust anchor to remove
    ///
    /// # Returns
    ///
    /// Result indicating success or error if anchor not found.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::dns::dnssec::trust_anchors::TrustAnchorStore;
    /// use dnsmasq::dns::protocol::name::DomainName;
    ///
    /// let mut store = TrustAnchorStore::new();
    /// // ... load trust anchors ...
    ///
    /// let domain = DomainName::new(".")?;
    /// store.remove_anchor(&domain, 12345)?;
    /// ```
    pub fn remove_anchor(&mut self, domain: &DomainName, keytag: u16) -> Result<()> {
        if let Some(anchors) = self.anchors.get_mut(domain) {
            let original_len = anchors.len();
            anchors.retain(|a| a.keytag != keytag);

            if anchors.len() < original_len {
                info!("Removed trust anchor: domain={}, keytag={}", domain.as_str(), keytag);

                // Remove domain entry if no anchors remain
                if anchors.is_empty() {
                    self.anchors.remove(domain);
                }

                return Ok(());
            }
        }

        warn!("Trust anchor not found for removal: domain={}, keytag={}", domain.as_str(), keytag);

        Err(crate::error::DnsmasqError::Dnssec(crate::error::DnssecError::TrustAnchorFailed {
            reason: format!(
                "Trust anchor not found: domain={}, keytag={}",
                domain.as_str(),
                keytag
            ),
        }))
    }

    /// Validates all trust anchors in the store.
    ///
    /// Performs comprehensive validation of all stored trust anchors, checking:
    /// - Algorithm validity
    /// - Digest type validity
    /// - Digest length consistency
    /// - Keytag range
    ///
    /// # Returns
    ///
    /// Result indicating success or first validation error encountered.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::dns::dnssec::trust_anchors::TrustAnchorStore;
    ///
    /// let mut store = TrustAnchorStore::new();
    /// // ... load trust anchors ...
    ///
    /// store.validate()?; // Ensure all anchors are valid
    /// ```
    pub fn validate(&self) -> Result<()> {
        for (domain, anchors) in &self.anchors {
            for anchor in anchors {
                anchor.validate().map_err(|e| {
                    error!("Trust anchor validation failed for domain {}: {}", domain.as_str(), e);
                    e
                })?;
            }
        }

        info!("All {} trust anchors validated successfully", self.len());
        Ok(())
    }

    /// Returns an iterator over all trust anchors.
    ///
    /// Iterates over all domains and their associated trust anchors.
    ///
    /// # Returns
    ///
    /// Iterator yielding (DomainName, &[TrustAnchor]) pairs.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::dns::dnssec::trust_anchors::TrustAnchorStore;
    ///
    /// let store = TrustAnchorStore::new();
    /// for (domain, anchors) in store.iter() {
    ///     println!("Zone: {}, Anchors: {}", domain.as_str(), anchors.len());
    /// }
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (&DomainName, &[TrustAnchor])> {
        self.anchors.iter().map(|(domain, anchors)| (domain, anchors.as_slice()))
    }

    /// Returns the total number of trust anchors across all zones.
    ///
    /// # Returns
    ///
    /// Count of all trust anchors (not zone count).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::dns::dnssec::trust_anchors::TrustAnchorStore;
    ///
    /// let store = TrustAnchorStore::new();
    /// println!("Total trust anchors: {}", store.len());
    /// ```
    pub fn len(&self) -> usize {
        self.anchors.values().map(|v| v.len()).sum()
    }

    /// Returns true if the store contains no trust anchors.
    ///
    /// # Returns
    ///
    /// Boolean indicating if store is empty.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::dns::dnssec::trust_anchors::TrustAnchorStore;
    ///
    /// let store = TrustAnchorStore::new();
    /// assert!(store.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Clears all trust anchors from the store.
    ///
    /// Removes all trust anchors, leaving the store empty. This is useful for
    /// reloading trust anchors or resetting the store state.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::dns::dnssec::trust_anchors::TrustAnchorStore;
    ///
    /// let mut store = TrustAnchorStore::new();
    /// // ... add some anchors ...
    /// store.clear();
    /// assert!(store.is_empty());
    /// ```
    pub fn clear(&mut self) {
        debug!("Clearing all trust anchors from store");
        self.anchors.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic trust anchor creation with valid parameters
    #[tokio::test]
    async fn test_trust_anchor_creation_valid() {
        let domain = DomainName::new(".").unwrap();
        let digest = vec![
            0x49, 0xAA, 0xC1, 0x1D, 0x7B, 0x6F, 0x64, 0x46, 0x70, 0x2E, 0x54, 0xA1, 0x60, 0x73,
            0x71, 0x60, 0x7A, 0x1A, 0x41, 0x85, 0x52, 0x00, 0xFD, 0x2C, 0xE1, 0xCD, 0xDE, 0x32,
            0xF2, 0x4E, 0x8F, 0xB5,
        ];

        let anchor = TrustAnchor::new(
            domain, 1,     // class IN
            20326, // keytag
            8,     // algorithm RSASHA256
            2,     // digest_type SHA256
            digest,
        );

        assert!(anchor.is_ok());
        let anchor = anchor.unwrap();
        assert_eq!(anchor.keytag, 20326);
        assert_eq!(anchor.algorithm, 8);
        assert_eq!(anchor.digest_type, 2);
    }

    /// Test trust anchor creation with invalid algorithm
    #[tokio::test]
    async fn test_trust_anchor_invalid_algorithm() {
        let domain = DomainName::new(".").unwrap();
        let digest = vec![0u8; 32];

        let anchor = TrustAnchor::new(
            domain, 1, 20326, 99, // Invalid algorithm
            2, digest,
        );

        assert!(anchor.is_err());
    }

    /// Test trust anchor store creation
    #[test]
    fn test_trust_anchor_store_creation() {
        let store = TrustAnchorStore::new();
        assert_eq!(store.len(), 0);
    }

    /// Test adding trust anchor to store
    #[test]
    fn test_add_trust_anchor() {
        let mut store = TrustAnchorStore::new();
        let domain = DomainName::new("example.com").unwrap();
        let digest = vec![0u8; 32];

        let anchor = TrustAnchor::new(domain.clone(), 1, 12345, 8, 2, digest).unwrap();

        let result = store.add_anchor(anchor);
        assert!(result.is_ok());
        assert_eq!(store.len(), 1);
    }

    /// Test finding trust anchor with exact match
    #[test]
    fn test_find_anchor_exact_match() {
        let mut store = TrustAnchorStore::new();
        let domain = DomainName::new("example.com").unwrap();
        let digest = vec![0u8; 32];

        let anchor = TrustAnchor::new(domain.clone(), 1, 12345, 8, 2, digest).unwrap();
        store.add_anchor(anchor).unwrap();

        let query_name = DomainName::new("example.com").unwrap();
        let found = store.find_anchor(&query_name);

        assert!(found.is_some());
        let anchors = found.unwrap();
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].keytag, 12345);
    }

    /// Test finding no anchor when none exists
    #[test]
    fn test_find_anchor_none() {
        let store = TrustAnchorStore::new();

        let query_name = DomainName::new("example.com").unwrap();
        let found = store.find_anchor(&query_name);

        assert!(found.is_none());
    }

    /// Test removing trust anchor
    #[test]
    fn test_remove_anchor() {
        let mut store = TrustAnchorStore::new();
        let domain = DomainName::new("example.com").unwrap();
        let digest = vec![0u8; 32];

        let anchor = TrustAnchor::new(domain.clone(), 1, 12345, 8, 2, digest).unwrap();
        store.add_anchor(anchor).unwrap();
        assert_eq!(store.len(), 1);

        let result = store.remove_anchor(&domain, 12345);
        assert!(result.is_ok());
        assert_eq!(store.len(), 0);
    }

    /// Test clearing all anchors
    #[test]
    fn test_clear_anchors() {
        let mut store = TrustAnchorStore::new();
        let domain = DomainName::new(".").unwrap();
        let digest = vec![0u8; 32];

        let anchor = TrustAnchor::new(domain, 1, 20326, 8, 2, digest).unwrap();
        store.add_anchor(anchor).unwrap();
        assert_eq!(store.len(), 1);

        store.clear();
        assert_eq!(store.len(), 0);
    }

    /// Test case-insensitive domain matching
    #[test]
    fn test_case_insensitive_matching() {
        let mut store = TrustAnchorStore::new();

        // Add anchor with mixed case
        let domain = DomainName::new("Example.COM").unwrap();
        let digest = vec![0u8; 32];
        let anchor = TrustAnchor::new(domain, 1, 12345, 8, 2, digest).unwrap();
        store.add_anchor(anchor).unwrap();

        // Query with different case
        let query_name = DomainName::new("example.com").unwrap();
        let found = store.find_anchor(&query_name);

        assert!(found.is_some());
    }

    /// Test multiple anchors for same domain (key rollover)
    #[test]
    fn test_multiple_anchors_same_domain() {
        let mut store = TrustAnchorStore::new();
        let domain = DomainName::new(".").unwrap();

        // Add old key
        let digest1 = vec![1u8; 32];
        let anchor1 = TrustAnchor::new(domain.clone(), 1, 19036, 8, 2, digest1).unwrap();
        store.add_anchor(anchor1).unwrap();

        // Add new key
        let digest2 = vec![2u8; 32];
        let anchor2 = TrustAnchor::new(domain.clone(), 1, 20326, 8, 2, digest2).unwrap();
        store.add_anchor(anchor2).unwrap();

        // Should have both anchors
        assert_eq!(store.len(), 2);

        let query_name = DomainName::new(".").unwrap();
        let found = store.find_anchor(&query_name);
        assert!(found.is_some());
        assert_eq!(found.unwrap().len(), 2);
    }
}
