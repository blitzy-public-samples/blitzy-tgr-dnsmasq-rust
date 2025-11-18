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

//! DNS hostname pattern validation and matching for security policy enforcement.
//!
//! # Overview
//!
//! This module provides DNS hostname pattern validation and matching functionality
//! used primarily for conntrack-based filtering and security policy enforcement.
//! It implements RFC 1123-compliant hostname validation with support for wildcard
//! patterns, enabling domain-based filtering rules that can match entire domain
//! hierarchies (e.g., `*.example.com`) while preventing malicious or malformed patterns.
//!
//! # Key Responsibilities
//!
//! - Validate DNS hostnames against RFC 1123 requirements ([`is_valid_dns_name`])
//! - Validate DNS hostname patterns with wildcard support ([`is_valid_dns_name_pattern`])
//! - Match DNS hostnames against validated patterns ([`is_dns_name_matching_pattern`])
//! - Implement case-insensitive glob pattern matching ([`is_string_matching_glob_pattern`])
//! - Enforce security restrictions on wildcard placement in patterns
//!
//! # Pattern Syntax
//!
//! Patterns support the wildcard character `*` which matches zero or more characters.
//!
//! Valid patterns include:
//! - Exact matches: `"www.example.com"`
//! - Subdomain wildcards: `"*.example.com"` (matches any subdomain)
//! - Multiple wildcards: `"*example*.com"` (matches any label containing "example")
//!
//! Invalid patterns include:
//! - Wildcards in TLD: `"*.com"` (too broad, security risk)
//! - Wildcards in second-level and TLD: `"*.co.uk"` (country-code TLD protection)
//!
//! # Security Considerations
//!
//! Pattern validation includes multiple security checks to prevent injection attacks
//! and overly broad matching:
//!
//! - Label length validation (max 63 characters per RFC 1123)
//! - Total hostname length validation (max 255 characters)
//! - Character validation (alphanumeric, hyphen, period, wildcard only)
//! - Wildcard placement restrictions (not in final two labels)
//! - Input sanitization against buffer overflows via length checks
//!
//! # Thread Safety
//!
//! All functions are pure (no side effects except logging) and thread-safe for
//! read-only operations on input strings. Functions do not modify shared state.
//!
//! # Example
//!
//! ```rust
//! use dnsmasq::util::patterns::{is_valid_dns_name, is_valid_dns_name_pattern, is_dns_name_matching_pattern};
//!
//! // Validate hostname
//! assert!(is_valid_dns_name("www.example.com"));
//! assert!(!is_valid_dns_name("ipcamera")); // Single label not allowed
//!
//! // Validate pattern
//! assert!(is_valid_dns_name_pattern("*.example.com"));
//! assert!(!is_valid_dns_name_pattern("*.com")); // Too broad
//!
//! // Match hostname against pattern
//! if is_valid_dns_name("api.example.com") && is_valid_dns_name_pattern("*.example.com") {
//!     assert!(is_dns_name_matching_pattern("api.example.com", "*.example.com"));
//! }
//! ```

use tracing::{debug, error};

/// Maximum length of a DNS label (single segment between dots) per RFC 1123.
const MAX_LABEL_LENGTH: usize = 63;

/// Maximum total length of a DNS hostname per RFC 1123.
const MAX_HOSTNAME_LENGTH: usize = 253;

/// Minimum number of labels required for a fully qualified domain name.
const MIN_LABELS: usize = 2;

/// Maximum number of wildcards allowed per label for security.
const MAX_WILDCARDS_PER_LABEL: usize = 2;

/// Match a string value against a glob pattern with wildcard support.
///
/// Implements case-insensitive glob pattern matching where `*` acts as a
/// zero-or-more-character wildcard. This function uses an efficient backtracking
/// algorithm based on Russ Cox's "Glob Matching Can Be Simple And Fast Too"
/// (<https://research.swtch.com/glob>). The algorithm avoids exponential complexity
/// by maintaining a single backtrack point rather than recursive backtracking.
///
/// # Arguments
///
/// * `value` - A string value to match against the pattern
/// * `pattern` - A glob pattern potentially containing `*` wildcards
///
/// # Returns
///
/// `true` if the value matches the pattern (case-insensitive), `false` otherwise.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::patterns::is_string_matching_glob_pattern;
///
/// // Match exact string
/// assert!(is_string_matching_glob_pattern("example", "example"));
///
/// // Match with wildcard
/// assert!(is_string_matching_glob_pattern("www.example.com", "*.example.com"));
///
/// // Case-insensitive match
/// assert!(is_string_matching_glob_pattern("Example", "EXAMPLE"));
///
/// // No match
/// assert!(!is_string_matching_glob_pattern("test", "example"));
/// ```
///
/// # Thread Safety
///
/// Thread-safe (read-only operations on input parameters).
pub fn is_string_matching_glob_pattern(value: &str, pattern: &str) -> bool {
    let value_bytes = value.as_bytes();
    let pattern_bytes = pattern.as_bytes();
    let num_value_bytes = value_bytes.len();
    let num_pattern_bytes = pattern_bytes.len();

    let mut value_index = 0;
    let mut next_value_index = 0;
    let mut pattern_index = 0;
    let mut next_pattern_index = 0;

    while value_index < num_value_bytes || pattern_index < num_pattern_bytes {
        if pattern_index < num_pattern_bytes {
            let mut pattern_character = pattern_bytes[pattern_index];
            
            // Convert lowercase ASCII to uppercase for case-insensitive comparison
            if (b'a'..=b'z').contains(&pattern_character) {
                pattern_character -= b'a' - b'A';
            }

            if pattern_character == b'*' {
                // Zero-or-more-character wildcard
                // Try to match at value_index, otherwise restart at value_index + 1 next
                next_pattern_index = pattern_index;
                pattern_index += 1;
                if value_index < num_value_bytes {
                    next_value_index = value_index + 1;
                } else {
                    next_value_index = 0;
                }
                continue;
            } else {
                // Ordinary character
                if value_index < num_value_bytes {
                    let mut value_character = value_bytes[value_index];
                    
                    // Convert lowercase ASCII to uppercase for case-insensitive comparison
                    if (b'a'..=b'z').contains(&value_character) {
                        value_character -= b'a' - b'A';
                    }

                    if value_character == pattern_character {
                        pattern_index += 1;
                        value_index += 1;
                        continue;
                    }
                }
            }
        }

        if next_value_index != 0 {
            pattern_index = next_pattern_index;
            value_index = next_value_index;
            continue;
        }

        return false;
    }

    true
}

/// Validate a DNS hostname against RFC 1123 requirements.
///
/// Validates DNS hostnames according to RFC 1123 Section 2.1 (host naming conventions)
/// with additional security restrictions for conntrack filtering. The validation ensures:
///
/// 1. Total length: 1-253 characters (DNS protocol limit)
/// 2. Label structure: Dot-separated labels, each 1-63 characters
/// 3. Character restrictions: ASCII letters (a-z, A-Z), digits (0-9), hyphens (-)
/// 4. Label boundaries: Labels must not start or end with hyphen
/// 5. Fully qualified: Minimum two labels (e.g., "host.domain")
/// 6. TLD restrictions: Final label must not be fully numeric (prevents IP addresses)
/// 7. Pseudo-TLD blocking: Rejects ".local" TLD (mDNS/Bonjour namespace)
///
/// # Arguments
///
/// * `value` - A string representing a hostname
///
/// # Returns
///
/// `true` if the hostname is valid per RFC 1123 and security restrictions, `false` otherwise.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::patterns::is_valid_dns_name;
///
/// // Valid fully-qualified domain names
/// assert!(is_valid_dns_name("example.com"));
/// assert!(is_valid_dns_name("www.example.com"));
///
/// // Invalid: single label (not fully qualified)
/// assert!(!is_valid_dns_name("ipcamera"));
///
/// // Invalid: .local pseudo-TLD (mDNS namespace)
/// assert!(!is_valid_dns_name("ipcamera.local"));
///
/// // Invalid: numeric TLD (looks like IP address)
/// assert!(!is_valid_dns_name("8.8.8.8"));
/// ```
///
/// # RFC Compliance
///
/// RFC 1123 Section 2.1 (Host Names and Numbers) - Enforces syntax rules for
/// Internet host names with additional security restrictions beyond the RFC specification.
///
/// # Thread Safety
///
/// Thread-safe (read-only operations on input string).
pub fn is_valid_dns_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut num_bytes = 0;
    let mut num_labels = 0;
    let mut label_start: Option<usize> = None;
    let mut is_label_numeric = true;

    for (index, &byte) in bytes.iter().enumerate() {
        // Check for valid characters: alphanumeric, hyphen, period
        if byte != b'-' && byte != b'.'
            && !(b'0'..=b'9').contains(&byte)
            && !(b'A'..=b'Z').contains(&byte)
            && !(b'a'..=b'z').contains(&byte)
        {
            debug!("Invalid DNS name: Invalid character {}", byte as char);
            return false;
        }

        if byte != b'.' {
            num_bytes += 1;
        }

        if label_start.is_none() {
            // Starting a new label
            if byte == b'.' {
                debug!("Invalid DNS name: Empty label");
                return false;
            }
            if byte == b'-' {
                debug!("Invalid DNS name: Label starts with hyphen");
                return false;
            }
            label_start = Some(index);
        }

        if byte != b'.' {
            // Within label
            if !(b'0'..=b'9').contains(&byte) {
                is_label_numeric = false;
            }
        } else {
            // End of label (at dot)
            if index > 0 && bytes[index - 1] == b'-' {
                debug!("Invalid DNS name: Label ends with hyphen");
                return false;
            }

            let label_start_idx = label_start.unwrap();
            let num_label_bytes = index - label_start_idx;

            if num_label_bytes > MAX_LABEL_LENGTH {
                debug!("Invalid DNS name: Label is too long ({})", num_label_bytes);
                return false;
            }

            num_labels += 1;
            label_start = None;
            is_label_numeric = true;
        }
    }

    // Handle the final label (no trailing dot)
    if let Some(label_start_idx) = label_start {
        if bytes.len() > 0 && bytes[bytes.len() - 1] == b'-' {
            debug!("Invalid DNS name: Label ends with hyphen");
            return false;
        }

        let num_label_bytes = bytes.len() - label_start_idx;

        if num_label_bytes > MAX_LABEL_LENGTH {
            debug!("Invalid DNS name: Label is too long ({})", num_label_bytes);
            return false;
        }

        num_labels += 1;

        // Validate minimum labels
        if num_labels < MIN_LABELS {
            debug!("Invalid DNS name: Not enough labels ({})", num_labels);
            return false;
        }

        // Check for fully numeric final label (prevents IP addresses)
        if is_label_numeric {
            debug!("Invalid DNS name: Final label is fully numeric");
            return false;
        }

        // Check for "local" pseudo-TLD (case-insensitive)
        if num_label_bytes == 5 {
            let label = &bytes[label_start_idx..];
            if label.eq_ignore_ascii_case(b"local") {
                debug!("Invalid DNS name: \"local\" pseudo-TLD");
                return false;
            }
        }

        // Validate total length
        if num_bytes < 1 || num_bytes > MAX_HOSTNAME_LENGTH {
            debug!("DNS name has invalid length ({})", num_bytes);
            return false;
        }

        return true;
    }

    // Should not reach here for valid input
    debug!("Invalid DNS name: Malformed input");
    false
}

/// Validate DNS hostname pattern with wildcard support and security restrictions.
///
/// Validates that a string represents a valid DNS hostname pattern conforming to
/// RFC 1123 naming requirements with wildcard extensions for pattern matching. This function
/// is primarily used for conntrack filtering rules to ensure that domain-based filters are
/// syntactically valid and do not pose security risks through overly broad matching.
///
/// The validation enforces multiple security and correctness constraints:
/// - RFC 1123 compliance: Total length 1-253 characters, labels 1-63 characters each
/// - Character restrictions: ASCII letters, digits, hyphens, periods, and wildcards only
/// - Label format: Labels cannot start or end with hyphens
/// - Wildcard restrictions: Up to two wildcards (`*`) per label, matching zero or more characters
/// - Security restriction: Final two labels must be literal (no wildcards) to prevent overly
///   broad matches like `"*.com"` or `"*.co.uk"` which would match unrelated domains
/// - Fully qualified requirement: Minimum two labels required
/// - TLD restrictions: Final label cannot be fully numeric or "local" pseudo-TLD
///
/// # Arguments
///
/// * `value` - String to validate as DNS hostname pattern
///
/// # Returns
///
/// `true` if the string is a valid DNS hostname pattern meeting all RFC and security requirements,
/// `false` otherwise.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::patterns::is_valid_dns_name_pattern;
///
/// // Valid patterns
/// assert!(is_valid_dns_name_pattern("example.com"));         // Exact hostname
/// assert!(is_valid_dns_name_pattern("*.example.com"));       // Subdomain wildcard
/// assert!(is_valid_dns_name_pattern("video*.example.com"));  // Partial label wildcard
///
/// // Invalid patterns
/// assert!(!is_valid_dns_name_pattern("ipcamera"));           // Not fully qualified (single label)
/// assert!(!is_valid_dns_name_pattern("*.com"));              // Wildcard in TLD (security risk)
/// assert!(!is_valid_dns_name_pattern("*.co.uk"));            // Wildcard in second-to-last label
/// assert!(!is_valid_dns_name_pattern("ipcamera.local"));     // "local" pseudo-TLD forbidden
/// ```
///
/// # Security
///
/// Wildcard restrictions are security-critical: patterns with wildcards in the final
/// two labels are explicitly rejected to prevent accidental or malicious overly broad
/// matching. For example, `"*.com"` would match millions of unrelated domains.
///
/// # RFC Compliance
///
/// RFC 1123 Section 2.1 (hostname syntax requirements).
///
/// # Thread Safety
///
/// Thread-safe for read-only operations; no shared state modified.
pub fn is_valid_dns_name_pattern(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut num_bytes = 0;
    let mut num_labels = 0;
    let mut label_start: Option<usize> = None;
    let mut is_label_numeric = true;
    let mut num_wildcards = 0;
    let mut previous_label_has_wildcard = true;

    for (index, &byte) in bytes.iter().enumerate() {
        // Check for valid characters: alphanumeric, hyphen, period, wildcard
        if byte != b'*' && byte != b'-' && byte != b'.'
            && !(b'0'..=b'9').contains(&byte)
            && !(b'A'..=b'Z').contains(&byte)
            && !(b'a'..=b'z').contains(&byte)
        {
            debug!("Invalid DNS name pattern: Invalid character {}", byte as char);
            return false;
        }

        if byte != b'*' && byte != b'.' {
            num_bytes += 1;
        }

        if label_start.is_none() {
            // Starting a new label
            if byte == b'.' {
                debug!("Invalid DNS name pattern: Empty label");
                return false;
            }
            if byte == b'-' {
                debug!("Invalid DNS name pattern: Label starts with hyphen");
                return false;
            }
            label_start = Some(index);
        }

        if byte != b'.' {
            // Within label
            if !(b'0'..=b'9').contains(&byte) {
                is_label_numeric = false;
            }
            if byte == b'*' {
                if num_wildcards >= MAX_WILDCARDS_PER_LABEL {
                    debug!("Invalid DNS name pattern: Wildcard character used more than twice per label");
                    return false;
                }
                num_wildcards += 1;
            }
        } else {
            // End of label (at dot)
            if index > 0 && bytes[index - 1] == b'-' {
                debug!("Invalid DNS name pattern: Label ends with hyphen");
                return false;
            }

            let label_start_idx = label_start.unwrap();
            let num_label_bytes = (index - label_start_idx) - num_wildcards;

            if num_label_bytes > MAX_LABEL_LENGTH {
                debug!("Invalid DNS name pattern: Label is too long ({})", num_label_bytes);
                return false;
            }

            num_labels += 1;
            label_start = None;
            is_label_numeric = true;
            previous_label_has_wildcard = num_wildcards != 0;
            num_wildcards = 0;
        }
    }

    // Handle the final label (no trailing dot)
    if let Some(label_start_idx) = label_start {
        if bytes.len() > 0 && bytes[bytes.len() - 1] == b'-' {
            debug!("Invalid DNS name pattern: Label ends with hyphen");
            return false;
        }

        let num_label_bytes = (bytes.len() - label_start_idx) - num_wildcards;

        if num_label_bytes > MAX_LABEL_LENGTH {
            debug!("Invalid DNS name pattern: Label is too long ({})", num_label_bytes);
            return false;
        }

        num_labels += 1;

        // Validate minimum labels
        if num_labels < MIN_LABELS {
            debug!("Invalid DNS name pattern: Not enough labels ({})", num_labels);
            return false;
        }

        // Security restriction: no wildcards in final two labels
        if num_wildcards != 0 || previous_label_has_wildcard {
            debug!("Invalid DNS name pattern: Wildcard within final two labels");
            return false;
        }

        // Check for fully numeric final label
        if is_label_numeric {
            debug!("Invalid DNS name pattern: Final label is fully numeric");
            return false;
        }

        // Check for "local" pseudo-TLD (case-insensitive)
        if num_label_bytes == 5 {
            let label = &bytes[label_start_idx..];
            if label.eq_ignore_ascii_case(b"local") {
                debug!("Invalid DNS name pattern: \"local\" pseudo-TLD");
                return false;
            }
        }

        // Validate total length (excluding wildcards)
        if num_bytes < 1 || num_bytes > MAX_HOSTNAME_LENGTH {
            debug!("DNS name pattern has invalid length after removing wildcards ({})", num_bytes);
            return false;
        }

        return true;
    }

    // Should not reach here for valid input
    debug!("Invalid DNS name pattern: Malformed input");
    false
}

/// Match DNS hostname against validated pattern with wildcard support.
///
/// Performs label-by-label matching of a DNS hostname against a validated DNS
/// hostname pattern, with support for wildcard matching within labels. This function
/// implements the pattern matching semantics used for conntrack filtering rules, where
/// domain-based filters need to match actual connection hostnames against configured patterns.
///
/// The matching algorithm processes both the name and pattern simultaneously, comparing
/// corresponding labels (segments separated by dots). Each label pair is matched using
/// case-insensitive glob pattern matching with wildcard support. The wildcard character (`*`)
/// within a pattern label matches zero or more characters within the corresponding name
/// label, but never crosses label boundaries.
///
/// # Matching Semantics
///
/// - **Case-insensitive**: "Example.COM" matches pattern "example.com"
/// - **Label-by-label**: Both name and pattern must have the same number of labels
/// - **Wildcard behavior**: `*` matches within a label but not across dots
/// - **Complete match required**: All labels must match and both strings must be fully consumed
///
/// # Arguments
///
/// * `name` - Valid DNS hostname to test against pattern
/// * `pattern` - Valid DNS hostname pattern with optional wildcards
///
/// # Returns
///
/// `true` if the hostname matches the pattern according to glob matching semantics,
/// `false` if at least one label fails to match or label counts differ.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::patterns::{is_valid_dns_name, is_valid_dns_name_pattern, is_dns_name_matching_pattern};
///
/// // Typical usage pattern: validate then match
/// let hostname = "api.example.com";
/// let filter_pattern = "*.example.com";
///
/// if is_valid_dns_name(hostname) && is_valid_dns_name_pattern(filter_pattern) {
///     assert!(is_dns_name_matching_pattern(hostname, filter_pattern));
/// }
///
/// // Example match scenarios
/// assert!(is_dns_name_matching_pattern("www.example.com", "*.example.com"));
/// assert!(!is_dns_name_matching_pattern("api.us.example.com", "*.example.com")); // Label count
/// assert!(is_dns_name_matching_pattern("video123.site.org", "video*.site.org"));
/// assert!(is_dns_name_matching_pattern("test.COM", "test.com")); // Case-insensitive
/// ```
///
/// # Panics
///
/// In debug builds, this function will panic (via `debug_assert!`) if inputs are invalid.
/// Callers should validate inputs using [`is_valid_dns_name`] and [`is_valid_dns_name_pattern`]
/// before calling this function.
///
/// # Thread Safety
///
/// Thread-safe for read-only operations on input strings; no shared state.
pub fn is_dns_name_matching_pattern(name: &str, pattern: &str) -> bool {
    debug_assert!(is_valid_dns_name(name), "Name must be valid DNS hostname");
    debug_assert!(is_valid_dns_name_pattern(pattern), "Pattern must be valid DNS hostname pattern");

    let name_bytes = name.as_bytes();
    let pattern_bytes = pattern.as_bytes();

    let mut n_pos = 0;
    let mut p_pos = 0;

    loop {
        // Extract name label
        let name_label_start = n_pos;
        while n_pos < name_bytes.len() && name_bytes[n_pos] != b'.' {
            n_pos += 1;
        }
        let name_label = &name[name_label_start..n_pos];

        // Extract pattern label
        let pattern_label_start = p_pos;
        while p_pos < pattern_bytes.len() && pattern_bytes[p_pos] != b'.' {
            p_pos += 1;
        }
        let pattern_label = &pattern[pattern_label_start..p_pos];

        // Match labels using glob pattern matching
        if !is_string_matching_glob_pattern(name_label, pattern_label) {
            return false;
        }

        // Advance past dot separator if present
        if n_pos < name_bytes.len() {
            n_pos += 1;
        }
        if p_pos < pattern_bytes.len() {
            p_pos += 1;
        }

        // Check if both strings are fully consumed
        if n_pos >= name_bytes.len() && p_pos >= pattern_bytes.len() {
            return true;
        }

        // If one is consumed but not the other, no match (label count mismatch)
        if n_pos >= name_bytes.len() || p_pos >= pattern_bytes.len() {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_pattern_exact_match() {
        assert!(is_string_matching_glob_pattern("example", "example"));
        assert!(is_string_matching_glob_pattern("www.example.com", "www.example.com"));
    }

    #[test]
    fn test_glob_pattern_case_insensitive() {
        assert!(is_string_matching_glob_pattern("Example", "EXAMPLE"));
        assert!(is_string_matching_glob_pattern("Test", "test"));
        assert!(is_string_matching_glob_pattern("API", "api"));
    }

    #[test]
    fn test_glob_pattern_wildcard() {
        assert!(is_string_matching_glob_pattern("www.example.com", "*.example.com"));
        assert!(is_string_matching_glob_pattern("api.example.com", "*.example.com"));
        assert!(is_string_matching_glob_pattern("video123", "video*"));
        assert!(is_string_matching_glob_pattern("test", "*"));
        assert!(is_string_matching_glob_pattern("", "*"));
    }

    #[test]
    fn test_glob_pattern_no_match() {
        assert!(!is_string_matching_glob_pattern("test", "example"));
        assert!(!is_string_matching_glob_pattern("api", "test*"));
    }

    #[test]
    fn test_valid_dns_name() {
        // Valid hostnames
        assert!(is_valid_dns_name("example.com"));
        assert!(is_valid_dns_name("www.example.com"));
        assert!(is_valid_dns_name("api.service.internal"));
        assert!(is_valid_dns_name("host-123.domain.org"));
    }

    #[test]
    fn test_invalid_dns_name_single_label() {
        assert!(!is_valid_dns_name("ipcamera"));
        assert!(!is_valid_dns_name("localhost"));
    }

    #[test]
    fn test_invalid_dns_name_local_tld() {
        assert!(!is_valid_dns_name("ipcamera.local"));
        assert!(!is_valid_dns_name("device.LOCAL"));
    }

    #[test]
    fn test_invalid_dns_name_numeric_tld() {
        assert!(!is_valid_dns_name("8.8.8.8"));
        assert!(!is_valid_dns_name("host.123"));
    }

    #[test]
    fn test_invalid_dns_name_hyphen_boundaries() {
        assert!(!is_valid_dns_name("-host.example.com"));
        assert!(!is_valid_dns_name("host-.example.com"));
    }

    #[test]
    fn test_invalid_dns_name_label_too_long() {
        let long_label = "a".repeat(64);
        let hostname = format!("{}.example.com", long_label);
        assert!(!is_valid_dns_name(&hostname));
    }

    #[test]
    fn test_valid_dns_name_pattern() {
        assert!(is_valid_dns_name_pattern("example.com"));
        assert!(is_valid_dns_name_pattern("*.example.com"));
        assert!(is_valid_dns_name_pattern("video*.example.com"));
        assert!(is_valid_dns_name_pattern("*api*.service.org"));
    }

    #[test]
    fn test_invalid_dns_name_pattern_wildcard_in_tld() {
        assert!(!is_valid_dns_name_pattern("*.com"));
        assert!(!is_valid_dns_name_pattern("example.*"));
    }

    #[test]
    fn test_invalid_dns_name_pattern_wildcard_in_second_to_last() {
        assert!(!is_valid_dns_name_pattern("*.co.uk"));
        assert!(!is_valid_dns_name_pattern("host.*.org"));
    }

    #[test]
    fn test_invalid_dns_name_pattern_too_many_wildcards() {
        assert!(!is_valid_dns_name_pattern("***example.com"));
        assert!(!is_valid_dns_name_pattern("a*b*c*.example.com"));
    }

    #[test]
    fn test_dns_name_matching_pattern() {
        // Exact matches
        assert!(is_dns_name_matching_pattern("www.example.com", "www.example.com"));
        
        // Wildcard matches
        assert!(is_dns_name_matching_pattern("api.example.com", "*.example.com"));
        assert!(is_dns_name_matching_pattern("video123.site.org", "video*.site.org"));
        
        // Case-insensitive
        assert!(is_dns_name_matching_pattern("API.EXAMPLE.COM", "api.example.com"));
        
        // No matches - label count mismatch
        assert!(!is_dns_name_matching_pattern("api.us.example.com", "*.example.com"));
        
        // No matches - pattern doesn't match
        assert!(!is_dns_name_matching_pattern("test.example.com", "api*.example.com"));
    }
}
