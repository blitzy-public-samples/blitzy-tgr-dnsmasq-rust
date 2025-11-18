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

//! DNS resource record representation and parsing.

use super::name::DomainName;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Represents a DNS resource record with type-specific data.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceRecord {
    /// IPv4 address record
    A {
        /// Domain name
        name: DomainName,
        /// Time to live in seconds
        ttl: u32,
        /// IPv4 address
        address: Ipv4Addr,
    },
    /// IPv6 address record
    AAAA {
        /// Domain name
        name: DomainName,
        /// Time to live in seconds
        ttl: u32,
        /// IPv6 address
        address: Ipv6Addr,
    },
    /// Canonical name record
    CNAME {
        /// Domain name
        name: DomainName,
        /// Time to live in seconds
        ttl: u32,
        /// Canonical name target
        cname: DomainName,
    },
    /// Pointer record
    PTR {
        /// Domain name
        name: DomainName,
        /// Time to live in seconds
        ttl: u32,
        /// Pointer target
        ptr: DomainName,
    },
    /// Mail exchange record
    MX {
        /// Domain name
        name: DomainName,
        /// Time to live in seconds
        ttl: u32,
        /// Preference value
        preference: u16,
        /// Mail exchange domain
        exchange: DomainName,
    },
    /// Text record
    TXT {
        /// Domain name
        name: DomainName,
        /// Time to live in seconds
        ttl: u32,
        /// Text data
        data: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_resource_record_a() {
        let name = DomainName::from_str("example.com").unwrap();
        let _record = ResourceRecord::A { name, ttl: 300, address: Ipv4Addr::new(192, 0, 2, 1) };
    }
}
