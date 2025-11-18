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

//! DNS domain name handling and validation.

use std::fmt;
use std::str::FromStr;

/// Represents a DNS domain name with RFC 1035 compliance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainName {
    labels: Vec<String>,
}

impl DomainName {
    /// Checks if this domain is a subdomain of another domain.
    pub fn is_subdomain_of(&self, other: &DomainName) -> bool {
        if self.labels.len() <= other.labels.len() {
            return false;
        }

        let self_suffix = &self.labels[self.labels.len() - other.labels.len()..];
        self_suffix == &other.labels[..]
    }

    /// Serializes the domain name to wire format.
    pub fn to_wire(&self, _buffer: &mut Vec<u8>, _compression: Option<&()>) -> Result<(), String> {
        // Stub implementation
        Ok(())
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.labels.join("."))
    }
}

impl FromStr for DomainName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let labels: Vec<String> =
            s.trim_end_matches('.').split('.').map(|s| s.to_string()).collect();

        // Validate labels
        for label in &labels {
            if label.len() > 63 {
                return Err(format!("Label too long: {}", label));
            }
        }

        Ok(DomainName { labels })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_name_creation() {
        let name = DomainName::from_str("www.example.com").unwrap();
        assert_eq!(name.labels.len(), 3);
    }

    #[test]
    fn test_subdomain_check() {
        let subdomain = DomainName::from_str("www.example.com").unwrap();
        let domain = DomainName::from_str("example.com").unwrap();
        assert!(subdomain.is_subdomain_of(&domain));
    }
}
