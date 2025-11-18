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

//! DNS protocol constants from RFC 1035 and related RFCs.

/// DNS standard port number
pub const NAMESERVER_PORT: u16 = 53;

/// DNS response code: No error
pub const NOERROR: u16 = 0;

/// DNS response code: Format error
pub const FORMERR: u16 = 1;

/// DNS response code: Server failure
pub const SERVFAIL: u16 = 2;

/// DNS response code: Name error (non-existent domain)
pub const NXDOMAIN: u16 = 3;

/// DNS response code: Not implemented
pub const NOTIMP: u16 = 4;

/// DNS response code: Query refused
pub const REFUSED: u16 = 5;

/// DNS resource record type: IPv4 address
pub const T_A: u16 = 1;

/// DNS resource record type: Name server
pub const T_NS: u16 = 2;

/// DNS resource record type: Canonical name
pub const T_CNAME: u16 = 5;

/// DNS resource record type: Start of authority
pub const T_SOA: u16 = 6;

/// DNS resource record type: Pointer record
pub const T_PTR: u16 = 12;

/// DNS resource record type: Mail exchange
pub const T_MX: u16 = 15;

/// DNS resource record type: Text record
pub const T_TXT: u16 = 16;

/// DNS resource record type: IPv6 address
pub const T_AAAA: u16 = 28;

/// DNS resource record type: Service locator
pub const T_SRV: u16 = 33;

/// DNS resource record type: DNSSEC signature
pub const T_RRSIG: u16 = 46;

/// DNS resource record type: Next secure record
pub const T_NSEC: u16 = 47;

/// DNS resource record type: DNSSEC key
pub const T_DNSKEY: u16 = 48;

/// DNS resource record type: Delegation signer
pub const T_DS: u16 = 43;

/// DNS resource record type: NSEC3 (hashed denial of existence)
pub const T_NSEC3: u16 = 50;

/// DNS resource record type: NSEC3PARAM
pub const T_NSEC3PARAM: u16 = 51;

/// DNS class: Internet
pub const C_IN: u16 = 1;

/// DNS class: Any
pub const C_ANY: u16 = 255;

/// Maximum domain name length in bytes
pub const MAXDNAME: usize = 255;

/// Maximum label length in bytes
pub const MAXLABEL: usize = 63;

/// Standard DNS packet size
pub const PACKETSZ: usize = 512;

/// Maximum DNS packet size
pub const MAXPACKET: usize = 65535;
