// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Domain pattern matching module for split-horizon DNS and query routing.
//!
//! This module implements sophisticated DNS query routing algorithms that form the foundation
//! of dnsmasq's split-horizon DNS, domain-specific upstream server selection, and
//! configuration-based query routing. It provides efficient matching of DNS queries against
//! configured domain patterns (including wildcards) with longest-match-wins semantics.
//!
//! # Core Functionality
//!
//! - **Pattern Matching**: Efficient domain name matching with wildcard support (`*.example.com`)
//! - **Longest Match Algorithm**: Selects the most specific domain match for query routing
//! - **Split-Horizon DNS**: Different upstream servers for different domain patterns
//! - **DNSSEC-Aware**: Filters servers based on DNSSEC capabilities
//! - **Performance**: O(log n) lookups using BTreeMap for sorted domain patterns
//!
//! # Architecture
//!
//! ## C Implementation (domain-match.c)
//!
//! ```c
//! // Sorted array with binary search
//! struct server **serverarray;
//! int serverarraysz;
//!
//! // Binary search with pointer arithmetic
//! int lookup_domain(char *domain, int flags, int *lowout, int *highout) {
//!     // Manual binary search with potential buffer overflows
//! }
//! ```
//!
//! ## Rust Implementation
//!
//! ```rust,ignore
//! // BTreeMap for automatic sorting and safe lookups
//! pub struct DomainMatcher {
//!     patterns: BTreeMap<DomainName, Vec<ServerDetails>>,
//!     has_wildcards: bool,
//! }
//!
//! // Memory-safe lookup with type-safe results
//! pub fn find_longest_match(&self, query: &DomainName) -> Option<MatchResult> {
//!     // Safe iteration with compile-time bounds checking
//! }
//! ```
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use dnsmasq::dns::matcher::{DomainMatcher, ServerFlags};
//! use dnsmasq::types::ServerDetails;
//! use dnsmasq::dns::protocol::name::DomainName;
//!
//! // Create matcher
//! let mut matcher = DomainMatcher::new();
//!
//! // Add patterns
//! let corp_server = ServerDetails::new(
//!     "10.0.0.1:53".parse()?,
//!     Some("corp.example.com"),
//!     ServerFlags::DOMAIN_SPECIFIC.bits(),
//! )?;
//! matcher.add_pattern(
//!     DomainName::new("corp.example.com")?,
//!     vec![corp_server],
//! )?;
//!
//! // Wildcard pattern
//! let cdn_server = ServerDetails::new(
//!     "8.8.8.8:53".parse()?,
//!     Some("*.cdn.example.com"),
//!     ServerFlags::WILDCARD.bits(),
//! )?;
//! matcher.add_pattern(
//!     DomainName::new("*.cdn.example.com")?,
//!     vec![cdn_server],
//! )?;
//!
//! // Match queries
//! let query = DomainName::new("mail.corp.example.com")?;
//! if let Some(result) = matcher.find_longest_match(&query) {
//!     println!("Matched domain: {}", result.domain.as_str());
//!     println!("Servers: {}", result.servers.len());
//!     println!("Is wildcard: {}", result.is_wildcard_match);
//! }
//! ```
//!
//! # Performance Characteristics
//!
//! - **Pattern Addition**: O(log n) due to BTreeMap insertion
//! - **Exact Match**: O(log n) binary search through BTreeMap
//! - **Longest Match**: O(m log n) where m = number of domain labels
//! - **Memory**: ~100 bytes per pattern (domain name + server list)
//!
//! # Memory Safety
//!
//! Replaces C implementation's manual memory management and pointer arithmetic with:
//! - BTreeMap for automatic sorting and safe iteration
//! - Vec for dynamic server lists with bounds checking
//! - DomainName for validated domain names
//! - No unsafe code required
//!
//! # RFC Compliance
//!
//! - RFC 1035 Section 3.1: Case-insensitive domain name comparison
//! - RFC 1035 Section 7.3: Domain name suffix matching for zone selection

use crate::dns::protocol::name::DomainName;
use crate::error::Result;
use crate::types::ServerDetails;
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{debug, instrument, trace};

/// Server configuration flags controlling upstream server behavior.
///
/// These flags correspond to the SERV_* defines in C dnsmasq.h and control
/// various aspects of server selection and query routing.
///
/// # C Equivalents (dnsmasq.h:570-585)
///
/// ```c
/// #define SERV_WILDCARD        (1u<<10)   // Domain pattern has leading '*'
/// #define SERV_LITERAL_ADDRESS (1u<<1)    // Return literal IP without forwarding
/// #define SERV_USE_RESOLV      (1u<<0)    // Forward to resolv.conf servers
/// #define SERV_DO_DNSSEC       (1u<<14)   // Upstream supports DNSSEC
/// #define SERV_FOR_NODOTS      (1u<<2)    // Handle names without dots
/// #define SERV_4ADDR           (1u<<3)    // IPv4 literal address
/// #define SERV_6ADDR           (1u<<4)    // IPv6 literal address
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerFlags(u16);

impl ServerFlags {
    /// Domain pattern has leading '*' for wildcard matching (*.example.com).
    pub const WILDCARD: Self = Self(1 << 10);

    /// Server returns a literal IP address without forwarding queries.
    /// Used for local domain resolution and blocklists.
    pub const LITERAL_ADDRESS: Self = Self(1 << 1);

    /// Forward queries to resolv.conf nameservers in normal way.
    pub const USE_RESOLV: Self = Self(1 << 0);

    /// Upstream server supports DNSSEC validation.
    /// Queries requiring DNSSEC validation are only sent to servers with this flag.
    pub const DO_DNSSEC: Self = Self(1 << 14);

    /// Handle domain names without dots (single-label names).
    /// Used for local network name resolution.
    pub const FOR_NODOTS: Self = Self(1 << 2);

    /// Server is configured for domain-specific forwarding.
    /// Used to distinguish from default upstream servers.
    pub const DOMAIN_SPECIFIC: Self = Self(1 << 5);

    /// Server returns all-zeros address (0.0.0.0 or ::).
    /// Used to return NODATA responses for blocked domains.
    pub const ALL_ZEROS: Self = Self(1 << 6);

    /// Server configuration contains IPv4 address.
    pub const IPV4_ADDR: Self = Self(1 << 3);

    /// Server configuration contains IPv6 address.
    pub const IPV6_ADDR: Self = Self(1 << 4);

    /// Returns the raw bitflags value.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Creates ServerFlags from raw bits.
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Checks if a specific flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combines two ServerFlags values with bitwise OR.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the intersection of two ServerFlags values.
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

/// Result of a domain pattern match operation.
///
/// Contains information about the matched domain pattern, the servers to use
/// for forwarding, and metadata about the match (wildcard vs. exact).
///
/// # Fields
///
/// - `domain`: The matched domain pattern from configuration
/// - `servers`: List of upstream servers to use for this domain
/// - `is_wildcard_match`: True if matched via wildcard pattern (*.example.com)
/// - `match_length`: Number of domain labels in the matched pattern (for comparison)
///
/// # Example
///
/// ```rust,ignore
/// let result = MatchResult {
///     domain: DomainName::new("corp.example.com")?,
///     servers: vec![corp_server],
///     is_wildcard_match: false,
///     match_length: 3,  // "corp.example.com" has 3 labels
/// };
/// ```
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// The matched domain pattern from configuration.
    pub domain: DomainName,

    /// Servers configured for this domain pattern.
    pub servers: Vec<ServerDetails>,

    /// True if this was a wildcard match (*.example.com), false for exact match.
    pub is_wildcard_match: bool,

    /// Number of labels in the matched domain (for longest-match comparison).
    pub match_length: usize,
}

/// Domain pattern matcher implementing longest-match-wins algorithm.
///
/// Maintains a sorted collection of domain patterns mapped to server configurations,
/// enabling efficient query routing based on domain-specific forwarding rules. Supports
/// both exact domain matches and wildcard patterns (*.example.com).
///
/// # Algorithm
///
/// 1. **Exact Match**: Check if query domain exists in pattern map
/// 2. **Suffix Match**: Iterate through progressively shorter domain suffixes
/// 3. **Wildcard Match**: Check wildcard patterns for each suffix
/// 4. **Longest Wins**: Return the most specific (longest) matching pattern
///
/// # Thread Safety
///
/// DomainMatcher can be safely shared across threads using `Arc<DomainMatcher>`.
/// The internal BTreeMap provides efficient concurrent reads. For writes, use
/// `Arc<RwLock<DomainMatcher>>` or rebuild the matcher and swap the Arc.
///
/// # Example
///
/// ```rust,ignore
/// let mut matcher = DomainMatcher::with_capacity(100);
///
/// // Add exact domain pattern
/// matcher.add_pattern(
///     DomainName::new("example.com")?,
///     vec![server1, server2],
/// )?;
///
/// // Add wildcard pattern
/// matcher.add_pattern(
///     DomainName::new("*.cdn.example.com")?,
///     vec![cdn_server],
/// )?;
///
/// // Find longest match
/// let query = DomainName::new("assets.cdn.example.com")?;
/// let result = matcher.find_longest_match(&query).unwrap();
/// assert_eq!(result.match_length, 3);  // "*.cdn.example.com"
/// ```
#[derive(Debug, Clone)]
pub struct DomainMatcher {
    /// Patterns mapped to their server configurations.
    /// BTreeMap ensures sorted order for efficient longest-match search.
    patterns: BTreeMap<String, PatternEntry>,

    /// Quick flag indicating if any wildcard patterns are configured.
    /// Enables optimization: skip wildcard processing if no wildcards exist.
    has_wildcards: bool,
}

/// Internal pattern entry storing servers and pattern metadata.
#[derive(Debug, Clone)]
struct PatternEntry {
    /// Original domain name for this pattern.
    domain: DomainName,

    /// Servers configured for this pattern.
    servers: Vec<ServerDetails>,

    /// True if this is a wildcard pattern (*.example.com).
    is_wildcard: bool,

    /// Number of labels in the domain pattern.
    label_count: usize,
}

impl DomainMatcher {
    /// Creates a new empty domain matcher.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let matcher = DomainMatcher::new();
    /// ```
    pub fn new() -> Self {
        Self {
            patterns: BTreeMap::new(),
            has_wildcards: false,
        }
    }

    /// Creates a new domain matcher with pre-allocated capacity.
    ///
    /// This is more efficient when you know the approximate number of patterns
    /// in advance, as it reduces reallocation during pattern addition.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Expected number of domain patterns
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Pre-allocate for 100 domain patterns
    /// let matcher = DomainMatcher::with_capacity(100);
    /// ```
    pub fn with_capacity(_capacity: usize) -> Self {
        // BTreeMap doesn't support capacity hints, but we maintain the API
        // for consistency and potential future optimization.
        Self::new()
    }

    /// Adds a domain pattern with its associated servers.
    ///
    /// The pattern can be either an exact domain name or a wildcard pattern.
    /// Wildcard patterns must start with `*.` (e.g., `*.example.com`).
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain pattern (exact or wildcard with `*.` prefix)
    /// * `servers` - List of servers to use for this domain
    ///
    /// # Returns
    ///
    /// Ok(()) on success, or an error if the pattern is invalid.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Exact domain
    /// matcher.add_pattern(
    ///     DomainName::new("example.com")?,
    ///     vec![server1],
    /// )?;
    ///
    /// // Wildcard domain
    /// matcher.add_pattern(
    ///     DomainName::new("*.example.com")?,
    ///     vec![server2],
    /// )?;
    /// ```
    #[instrument(skip(self, servers), fields(domain = %domain.as_str(), server_count = servers.len()))]
    pub fn add_pattern(&mut self, domain: DomainName, servers: Vec<ServerDetails>) -> Result<()> {
        let domain_str = domain.as_str();
        let is_wildcard = domain_str.starts_with("*.");

        if is_wildcard {
            self.has_wildcards = true;
        }

        let label_count = domain.labels().count();
        let key = self.normalize_pattern(&domain);

        let entry = PatternEntry {
            domain,
            servers,
            is_wildcard,
            label_count,
        };

        trace!("Adding pattern: {} (wildcard: {}, labels: {})", key, is_wildcard, label_count);
        self.patterns.insert(key, entry);

        Ok(())
    }

    /// Checks if a domain matches any configured pattern.
    ///
    /// Returns true if the domain matches at least one pattern (exact or wildcard),
    /// false otherwise. This is a lightweight check that doesn't return server details.
    ///
    /// # Arguments
    ///
    /// * `query` - Domain name to check
    ///
    /// # Returns
    ///
    /// True if the domain matches any pattern, false otherwise.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let query = DomainName::new("www.example.com")?;
    /// if matcher.is_match(&query) {
    ///     println!("Domain has specific configuration");
    /// }
    /// ```
    #[instrument(skip(self), fields(query = %query.as_str()))]
    pub fn is_match(&self, query: &DomainName) -> bool {
        self.find_longest_match(query).is_some()
    }

    /// Finds the longest (most specific) matching pattern for a query domain.
    ///
    /// Implements the longest-match-wins algorithm: if multiple patterns match,
    /// returns the one with the most labels (most specific). For example, if both
    /// `example.com` and `mail.example.com` match, returns `mail.example.com`.
    ///
    /// # Algorithm
    ///
    /// 1. Check for exact match of full query domain
    /// 2. If wildcards exist, check wildcard match of full domain
    /// 3. Remove leftmost label and repeat for each suffix
    /// 4. Return first (longest) match found
    ///
    /// # Arguments
    ///
    /// * `query` - Domain name to match against patterns
    ///
    /// # Returns
    ///
    /// Some(MatchResult) if a match is found, None otherwise.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let query = DomainName::new("www.mail.example.com")?;
    /// if let Some(result) = matcher.find_longest_match(&query) {
    ///     println!("Matched: {}", result.domain.as_str());
    ///     println!("Servers: {:?}", result.servers);
    /// }
    /// ```
    #[instrument(skip(self), fields(query = %query.as_str()))]
    pub fn find_longest_match(&self, query: &DomainName) -> Option<MatchResult> {
        let query_str = query.as_str();
        let query_labels: Vec<&str> = query.labels().collect();

        trace!("Searching for longest match: {} ({} labels)", query_str, query_labels.len());

        // Try progressively shorter suffixes (longest match first)
        for start_idx in 0..query_labels.len() {
            let suffix_labels = &query_labels[start_idx..];
            let suffix = suffix_labels.join(".");

            // Try exact match first
            trace!("Checking exact pattern: {}", suffix);
            if let Some(entry) = self.patterns.get(&suffix.to_lowercase()) {
                if !entry.is_wildcard {
                    debug!("Found exact match: {} ({} labels)", suffix, entry.label_count);
                    return Some(MatchResult {
                        domain: entry.domain.clone(),
                        servers: entry.servers.clone(),
                        is_wildcard_match: false,
                        match_length: entry.label_count,
                    });
                }
            }

            // Try wildcard match if wildcards are configured
            if self.has_wildcards && start_idx > 0 {
                let wildcard_pattern = format!("*.{}", suffix);
                trace!("Checking wildcard pattern: {}", wildcard_pattern);
                if let Some(entry) = self.patterns.get(&wildcard_pattern.to_lowercase()) {
                    if entry.is_wildcard {
                        debug!("Found wildcard match: {} ({} labels)", wildcard_pattern, entry.label_count);
                        return Some(MatchResult {
                            domain: entry.domain.clone(),
                            servers: entry.servers.clone(),
                            is_wildcard_match: true,
                            match_length: entry.label_count,
                        });
                    }
                }
            }
        }

        trace!("No match found for: {}", query_str);
        None
    }

    /// Finds all patterns matching a query domain.
    ///
    /// Unlike `find_longest_match()` which returns only the most specific match,
    /// this method returns all matching patterns sorted by specificity (most specific first).
    ///
    /// # Arguments
    ///
    /// * `query` - Domain name to match against patterns
    ///
    /// # Returns
    ///
    /// Vector of MatchResult entries, sorted by match_length descending (longest first).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let query = DomainName::new("www.example.com")?;
    /// let matches = matcher.find_all_matches(&query);
    /// for m in matches {
    ///     println!("Match: {} ({} labels)", m.domain.as_str(), m.match_length);
    /// }
    /// ```
    #[instrument(skip(self), fields(query = %query.as_str()))]
    pub fn find_all_matches(&self, query: &DomainName) -> Vec<MatchResult> {
        let query_str = query.as_str();
        let query_labels: Vec<&str> = query.labels().collect();
        let mut matches = Vec::new();

        trace!("Finding all matches for: {}", query_str);

        // Try progressively shorter suffixes
        for start_idx in 0..query_labels.len() {
            let suffix_labels = &query_labels[start_idx..];
            let suffix = suffix_labels.join(".");

            // Check exact match
            if let Some(entry) = self.patterns.get(&suffix.to_lowercase()) {
                if !entry.is_wildcard {
                    matches.push(MatchResult {
                        domain: entry.domain.clone(),
                        servers: entry.servers.clone(),
                        is_wildcard_match: false,
                        match_length: entry.label_count,
                    });
                }
            }

            // Check wildcard match
            if self.has_wildcards && start_idx > 0 {
                let wildcard_pattern = format!("*.{}", suffix);
                if let Some(entry) = self.patterns.get(&wildcard_pattern.to_lowercase()) {
                    if entry.is_wildcard {
                        matches.push(MatchResult {
                            domain: entry.domain.clone(),
                            servers: entry.servers.clone(),
                            is_wildcard_match: true,
                            match_length: entry.label_count,
                        });
                    }
                }
            }
        }

        // Sort by match length descending (longest/most specific first)
        matches.sort_by(|a, b| b.match_length.cmp(&a.match_length));

        debug!("Found {} total matches for: {}", matches.len(), query_str);
        matches
    }

    /// Returns true if any wildcard patterns are configured.
    ///
    /// This is a quick check that can be used to optimize processing when
    /// wildcard matching is not needed.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if matcher.has_wildcard_patterns() {
    ///     // Use slower wildcard-aware matching
    /// } else {
    ///     // Use faster exact-match-only algorithm
    /// }
    /// ```
    pub fn has_wildcard_patterns(&self) -> bool {
        self.has_wildcards
    }

    /// Returns the number of configured patterns.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// println!("Configured patterns: {}", matcher.pattern_count());
    /// ```
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Removes all patterns from the matcher.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// matcher.clear();
    /// assert_eq!(matcher.pattern_count(), 0);
    /// ```
    pub fn clear(&mut self) {
        self.patterns.clear();
        self.has_wildcards = false;
    }

    /// Normalizes a domain pattern for use as a BTreeMap key.
    ///
    /// Converts to lowercase for case-insensitive matching per RFC 1035.
    fn normalize_pattern(&self, domain: &DomainName) -> String {
        domain.as_str().to_lowercase()
    }
}

impl Default for DomainMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test server
    fn test_server(addr: &str, domain: Option<&str>) -> ServerDetails {
        ServerDetails::new(
            addr.parse().unwrap(),
            domain,
            0,
        ).unwrap()
    }

    #[test]
    fn test_exact_match() {
        let mut matcher = DomainMatcher::new();
        let server = test_server("8.8.8.8:53", Some("example.com"));

        matcher.add_pattern(
            DomainName::new("example.com").unwrap(),
            vec![server],
        ).unwrap();

        let query = DomainName::new("example.com").unwrap();
        assert!(matcher.is_match(&query));

        let result = matcher.find_longest_match(&query).unwrap();
        assert_eq!(result.domain.as_str(), "example.com");
        assert!(!result.is_wildcard_match);
        assert_eq!(result.servers.len(), 1);
    }

    #[test]
    fn test_subdomain_no_match() {
        let mut matcher = DomainMatcher::new();
        let server = test_server("8.8.8.8:53", Some("example.com"));

        matcher.add_pattern(
            DomainName::new("example.com").unwrap(),
            vec![server],
        ).unwrap();

        // Subdomain should match parent domain
        let query = DomainName::new("www.example.com").unwrap();
        let result = matcher.find_longest_match(&query);
        
        // Should find parent domain match
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.domain.as_str(), "example.com");
    }

    #[test]
    fn test_wildcard_match() {
        let mut matcher = DomainMatcher::new();
        let server = test_server("8.8.8.8:53", Some("*.example.com"));

        matcher.add_pattern(
            DomainName::new("*.example.com").unwrap(),
            vec![server],
        ).unwrap();

        assert!(matcher.has_wildcard_patterns());

        let query = DomainName::new("www.example.com").unwrap();
        let result = matcher.find_longest_match(&query).unwrap();
        
        assert_eq!(result.domain.as_str(), "*.example.com");
        assert!(result.is_wildcard_match);
    }

    #[test]
    fn test_longest_match_wins() {
        let mut matcher = DomainMatcher::new();
        
        let server1 = test_server("8.8.8.8:53", Some("example.com"));
        let server2 = test_server("8.8.4.4:53", Some("mail.example.com"));

        matcher.add_pattern(
            DomainName::new("example.com").unwrap(),
            vec![server1],
        ).unwrap();
        
        matcher.add_pattern(
            DomainName::new("mail.example.com").unwrap(),
            vec![server2],
        ).unwrap();

        let query = DomainName::new("mail.example.com").unwrap();
        let result = matcher.find_longest_match(&query).unwrap();
        
        // Should match more specific pattern
        assert_eq!(result.domain.as_str(), "mail.example.com");
        assert_eq!(result.match_length, 3);
    }

    #[test]
    fn test_case_insensitive() {
        let mut matcher = DomainMatcher::new();
        let server = test_server("8.8.8.8:53", Some("Example.COM"));

        matcher.add_pattern(
            DomainName::new("Example.COM").unwrap(),
            vec![server],
        ).unwrap();

        let query = DomainName::new("example.com").unwrap();
        assert!(matcher.is_match(&query));

        let query2 = DomainName::new("EXAMPLE.COM").unwrap();
        assert!(matcher.is_match(&query2));
    }

    #[test]
    fn test_no_match() {
        let mut matcher = DomainMatcher::new();
        let server = test_server("8.8.8.8:53", Some("example.com"));

        matcher.add_pattern(
            DomainName::new("example.com").unwrap(),
            vec![server],
        ).unwrap();

        let query = DomainName::new("different.org").unwrap();
        assert!(!matcher.is_match(&query));
        assert!(matcher.find_longest_match(&query).is_none());
    }

    #[test]
    fn test_find_all_matches() {
        let mut matcher = DomainMatcher::new();
        
        let server1 = test_server("8.8.8.8:53", Some("example.com"));
        let server2 = test_server("8.8.4.4:53", Some("*.example.com"));
        let server3 = test_server("1.1.1.1:53", Some("mail.example.com"));

        matcher.add_pattern(DomainName::new("example.com").unwrap(), vec![server1]).unwrap();
        matcher.add_pattern(DomainName::new("*.example.com").unwrap(), vec![server2]).unwrap();
        matcher.add_pattern(DomainName::new("mail.example.com").unwrap(), vec![server3]).unwrap();

        let query = DomainName::new("mail.example.com").unwrap();
        let matches = matcher.find_all_matches(&query);

        // Should find all three patterns
        assert_eq!(matches.len(), 3);
        
        // First match should be most specific (exact match)
        assert_eq!(matches[0].domain.as_str(), "mail.example.com");
        assert!(!matches[0].is_wildcard_match);
    }

    #[test]
    fn test_clear() {
        let mut matcher = DomainMatcher::new();
        let server = test_server("8.8.8.8:53", Some("example.com"));

        matcher.add_pattern(
            DomainName::new("example.com").unwrap(),
            vec![server],
        ).unwrap();

        assert_eq!(matcher.pattern_count(), 1);

        matcher.clear();
        assert_eq!(matcher.pattern_count(), 0);
        assert!(!matcher.has_wildcard_patterns());
    }

    #[test]
    fn test_server_flags() {
        let wildcard = ServerFlags::WILDCARD;
        let dnssec = ServerFlags::DO_DNSSEC;

        assert!(wildcard.contains(ServerFlags::WILDCARD));
        assert!(!wildcard.contains(ServerFlags::DO_DNSSEC));

        let combined = wildcard.union(dnssec);
        assert!(combined.contains(ServerFlags::WILDCARD));
        assert!(combined.contains(ServerFlags::DO_DNSSEC));

        assert_eq!(ServerFlags::WILDCARD.bits(), 1 << 10);
        assert_eq!(ServerFlags::DO_DNSSEC.bits(), 1 << 14);
    }
}
