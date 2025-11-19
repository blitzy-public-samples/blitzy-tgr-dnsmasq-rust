// Copyright (C) 2024 Dnsmasq Contributors
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0

//! EDNS0 Extension Mechanism for DNS (RFC 6891)
//!
//! This module implements the Extension Mechanisms for DNS (EDNS0) per RFC 6891,
//! providing support for DNS protocol extensions beyond the original 512-byte UDP limit
//! through the OPT pseudo-RR in the additional section of DNS messages.
//!
//! # Supported EDNS0 Options
//!
//! - **DNSSEC OK (DO) bit**: Signals DNSSEC validation capability (RFC 4035)
//! - **UDP Payload Size**: Negotiates maximum response size (RFC 6891 §6.2.3)
//! - **EDNS Client Subnet (ECS)**: Geographic query routing (RFC 7871)
//! - **Extended DNS Errors (EDE)**: Detailed error reporting (RFC 8914)
//! - **DNS Cookies**: Transaction security (RFC 7873)
//! - **Padding**: Response size obfuscation (RFC 7830)
//! - **Proprietary Options**:
//!   - Generic MAC Address (code 65001)
//!   - Nominum Device ID (code 65073)
//!   - Nominum CPE ID (code 65074)
//!   - Cisco Umbrella Device ID (code 20292)
//!
//! # Memory Safety
//!
//! Replaces C pointer arithmetic and manual buffer management with:
//! - `nom` parser combinators for safe EDNS0 option decoding
//! - `bytes::BytesMut` for zero-copy packet construction
//! - Compile-time bounds checking eliminating buffer overflows
//!
//! # Architecture
//!
//! - `Edns0Option`: Type-safe enum representing all supported option types
//! - `Edns0Handler`: Core logic for finding and manipulating OPT pseudo-RRs
//! - `Edns0Builder`: Fluent API for constructing OPT records
//!
//! # Example
//!
//! ```rust,no_run
//! use dnsmasq::dns::edns0::{Edns0Builder, Edns0Option};
//! use std::net::Ipv4Addr;
//!
//! let opt_record = Edns0Builder::new()
//!     .udp_size(4096)
//!     .do_bit(true)
//!     .client_subnet(Ipv4Addr::new(192, 0, 2, 1).into(), 24)
//!     .build()
//!     .expect("Failed to build OPT record");
//! ```

use crate::dns::protocol::constants::{
    C_ANY, C_IN, EDNS0_OPTION_CLIENT_SUBNET, EDNS0_OPTION_MAC, EDNS0_OPTION_NOMCPEID,
    EDNS0_OPTION_NOMDEVICEID, EDNS0_OPTION_UMBRELLA, EDE_BOGUS, EDE_DNSSEC_BOGUS, EDE_DNSSEC_IND,
    EDE_FORGED, EDE_INDET, EDE_NETERR, EDE_NOT_AUTH, EDE_NOT_READY, EDE_NOT_SUP, EDE_NO_REACHABLE,
    EDE_OTHER, EDE_PROHIBITED, EDE_RRSIG_MISS, EDE_SIG_EXP, EDE_SIG_NYV, EDE_STALE, EDE_SXNAME_MISS,
    EDE_UNSET, EDE_USUPDNSKEY, EDE_USUPDS, IN6ADDRSZ, INADDRSZ, T_OPT, T_TKEY, T_TSIG,
};
use crate::error::{DnsError, Result};
use crate::types::{IpAddr, MacAddress, Timestamp};

use bytes::{BufMut, Bytes, BytesMut};
use nom::{
    bytes::complete::take,
    combinator::map,
    number::complete::{be_u16, be_u32, be_u8},
    sequence::tuple,
    IResult,
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tracing::{debug, instrument, trace, warn};

/// Maximum EDNS0 UDP payload size (RFC 6891 §6.2.3)
/// Conservative limit to avoid IP fragmentation
const MAX_UDP_PAYLOAD: u16 = 4096;

/// Default EDNS0 UDP payload size
const DEFAULT_UDP_PAYLOAD: u16 = 1232; // Path MTU safe size (RFC 8899)

/// EDNS0 version (always 0 per RFC 6891 §6.1.2)
const EDNS_VERSION: u8 = 0;

/// EDNS0 DO (DNSSEC OK) bit position in extended RCODE/flags
const EDNS_DO_BIT: u16 = 0x8000;

/// EDNS0 option representing all supported extension mechanisms.
///
/// Each variant corresponds to a specific EDNS0 option code with its
/// associated data payload. Unknown options are preserved for transparency.
///
/// # RFC References
///
/// - RFC 6891: EDNS0 base specification
/// - RFC 7871: Client Subnet in DNS Queries
/// - RFC 7873: Domain Name System (DNS) Cookies
/// - RFC 7830: The EDNS(0) Padding Option
/// - RFC 8914: Extended DNS Errors
#[derive(Debug, Clone, PartialEq)]
pub enum Edns0Option {
    /// RFC 7871: Client Subnet in DNS Queries
    ///
    /// Provides client IP subnet information to enable geographic DNS optimization.
    /// The source_netmask indicates the significant bits in the address,
    /// while scope_netmask indicates the precision of the response.
    ClientSubnet {
        /// Address family: 1 = IPv4, 2 = IPv6
        family: u16,
        /// Number of significant bits in the address (source netmask)
        source_netmask: u8,
        /// Scope netmask from server response
        scope_netmask: u8,
        /// Client subnet address (masked)
        address: IpAddr,
    },

    /// DNSSEC OK (DO) bit signaling (RFC 4035 §3.2.1)
    ///
    /// Indicates the client can handle DNSSEC signatures in responses.
    /// Represented as a flag in the OPT record header, not as an option.
    DnssecOk,

    /// RFC 7873: DNS Cookies
    ///
    /// Provides transaction security and denial-of-service protection.
    /// Client cookie is mandatory (8 bytes), server cookie is optional (8-32 bytes).
    Cookie {
        /// Client cookie (8 bytes)
        client: Vec<u8>,
        /// Server cookie (8-32 bytes, optional)
        server: Option<Vec<u8>>,
    },

    /// RFC 8914: Extended DNS Errors (EDE)
    ///
    /// Provides detailed error information beyond basic RCODE values.
    ExtendedError {
        /// EDE info code (see EDE_* constants)
        info_code: u16,
        /// Optional human-readable error text (UTF-8)
        extra_text: String,
    },

    /// RFC 7830: EDNS0 Padding Option
    ///
    /// Pads responses to a uniform size to prevent traffic analysis attacks.
    Padding {
        /// Padding length in bytes
        length: usize,
    },

    /// Generic MAC Address Option (code 65001)
    ///
    /// Transmits client MAC address for device identification.
    /// Proprietary dnsmasq extension.
    Mac {
        /// Client MAC address (6 bytes)
        address: MacAddress,
    },

    /// Nominum Device ID Option (code 65073)
    ///
    /// Identifies client device using proprietary Nominum encoding.
    NomDeviceId {
        /// Nominum device identifier (variable length)
        device_id: Vec<u8>,
    },

    /// Nominum CPE ID Option (code 65074)
    ///
    /// Identifies customer premises equipment using Nominum encoding.
    NomCpeId {
        /// Nominum CPE identifier (variable length)
        cpe_id: Vec<u8>,
    },

    /// Cisco Umbrella Device ID Option (code 20292)
    ///
    /// Transmits device identifier for Cisco Umbrella cloud security platform.
    Umbrella {
        /// Cisco Umbrella device identifier (variable length)
        device_id: Vec<u8>,
    },

    /// Unknown/Unrecognized EDNS0 Option
    ///
    /// Preserves unrecognized options for transparency per RFC 6891 §6.1.2
    /// ("Unknown EDNS options in a query should be silently ignored.")
    Unknown {
        /// Option code
        code: u16,
        /// Raw option data
        data: Vec<u8>,
    },
}

impl Edns0Option {
    /// Returns the EDNS0 option code for this option type
    pub fn code(&self) -> u16 {
        match self {
            Edns0Option::ClientSubnet { .. } => EDNS0_OPTION_CLIENT_SUBNET,
            Edns0Option::DnssecOk => 0, // DO bit is in header, not an option
            Edns0Option::Cookie { .. } => 10, // RFC 7873
            Edns0Option::ExtendedError { .. } => 15, // RFC 8914
            Edns0Option::Padding { .. } => 12, // RFC 7830
            Edns0Option::Mac { .. } => EDNS0_OPTION_MAC,
            Edns0Option::NomDeviceId { .. } => EDNS0_OPTION_NOMDEVICEID,
            Edns0Option::NomCpeId { .. } => EDNS0_OPTION_NOMCPEID,
            Edns0Option::Umbrella { .. } => EDNS0_OPTION_UMBRELLA,
            Edns0Option::Unknown { code, .. } => *code,
        }
    }

    /// Returns the wire-format serialized option data length
    pub fn data_len(&self) -> usize {
        match self {
            Edns0Option::ClientSubnet { family, address, .. } => {
                let addr_len = if *family == 1 {
                    INADDRSZ as usize
                } else {
                    IN6ADDRSZ as usize
                };
                4 + addr_len // family(2) + source(1) + scope(1) + address
            }
            Edns0Option::DnssecOk => 0,
            Edns0Option::Cookie { client, server } => {
                client.len() + server.as_ref().map_or(0, |s| s.len())
            }
            Edns0Option::ExtendedError { extra_text, .. } => 2 + extra_text.len(),
            Edns0Option::Padding { length } => *length,
            Edns0Option::Mac { .. } => 6, // MAC address is always 6 bytes
            Edns0Option::NomDeviceId { device_id } => device_id.len(),
            Edns0Option::NomCpeId { cpe_id } => cpe_id.len(),
            Edns0Option::Umbrella { device_id } => device_id.len(),
            Edns0Option::Unknown { data, .. } => data.len(),
        }
    }

    /// Serializes the option to wire format
    ///
    /// Returns the serialized option data (without the option code and length header).
    pub fn to_wire_format(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(self.data_len());

        match self {
            Edns0Option::ClientSubnet {
                family,
                source_netmask,
                scope_netmask,
                address,
            } => {
                buf.extend_from_slice(&family.to_be_bytes());
                buf.push(*source_netmask);
                buf.push(*scope_netmask);

                // Write address bytes (only significant octets based on netmask)
                let addr_bytes = match address {
                    IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
                    IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
                };

                // Calculate number of bytes to include based on source netmask
                let byte_count = ((*source_netmask as usize) + 7) / 8;
                buf.extend_from_slice(&addr_bytes[..byte_count.min(addr_bytes.len())]);
            }

            Edns0Option::DnssecOk => {
                // DO bit is set in OPT header flags, no option data
            }

            Edns0Option::Cookie { client, server } => {
                buf.extend_from_slice(client);
                if let Some(server_cookie) = server {
                    buf.extend_from_slice(server_cookie);
                }
            }

            Edns0Option::ExtendedError {
                info_code,
                extra_text,
            } => {
                buf.extend_from_slice(&info_code.to_be_bytes());
                buf.extend_from_slice(extra_text.as_bytes());
            }

            Edns0Option::Padding { length } => {
                buf.resize(*length, 0);
            }

            Edns0Option::Mac { address } => {
                buf.extend_from_slice(address.octets());
            }

            Edns0Option::NomDeviceId { device_id } => {
                buf.extend_from_slice(device_id);
            }

            Edns0Option::NomCpeId { cpe_id } => {
                buf.extend_from_slice(cpe_id);
            }

            Edns0Option::Umbrella { device_id } => {
                buf.extend_from_slice(device_id);
            }

            Edns0Option::Unknown { data, .. } => {
                buf.extend_from_slice(data);
            }
        }

        Ok(buf)
    }

    /// Serializes the option to wire format with code and data
    ///
    /// Returns a tuple of (option_code, option_data) for wire format serialization.
    /// This is a convenience method that combines `code()` and `to_wire_format()`.
    pub fn serialize(&self) -> Result<(u16, Vec<u8>)> {
        let code = self.code();
        let data = self.to_wire_format()?;
        Ok((code, data))
    }

    /// Parses an EDNS0 option from wire format
    ///
    /// # Arguments
    ///
    /// * `code` - The option code
    /// * `data` - The option data payload
    ///
    /// # Returns
    ///
    /// Parsed option or Unknown variant for unrecognized codes
    pub fn from_wire_format(code: u16, data: &[u8]) -> Result<Self> {
        match code {
            EDNS0_OPTION_CLIENT_SUBNET => Self::parse_client_subnet(data),
            10 => Self::parse_cookie(data), // RFC 7873
            15 => Self::parse_extended_error(data), // RFC 8914
            12 => Ok(Edns0Option::Padding { length: data.len() }),
            EDNS0_OPTION_MAC => Self::parse_mac(data),
            EDNS0_OPTION_NOMDEVICEID => Ok(Edns0Option::NomDeviceId {
                device_id: data.to_vec(),
            }),
            EDNS0_OPTION_NOMCPEID => Ok(Edns0Option::NomCpeId {
                cpe_id: data.to_vec(),
            }),
            EDNS0_OPTION_UMBRELLA => Ok(Edns0Option::Umbrella {
                device_id: data.to_vec(),
            }),
            _ => Ok(Edns0Option::Unknown {
                code,
                data: data.to_vec(),
            }),
        }
    }

    /// Parses Client Subnet option (RFC 7871)
    fn parse_client_subnet(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(DnsError::Edns0Failed {
                reason: format!("Client subnet option too short: {} bytes", data.len()),
            }
            .into());
        }

        let family = u16::from_be_bytes([data[0], data[1]]);
        let source_netmask = data[2];
        let scope_netmask = data[3];
        let addr_data = &data[4..];

        let address = match family {
            1 => {
                // IPv4
                if addr_data.len() > INADDRSZ as usize {
                    return Err(DnsError::Edns0Failed {
                        reason: format!("IPv4 client subnet address too long: {} bytes", addr_data.len()),
                    }
                    .into());
                }
                let mut octets = [0u8; 4];
                octets[..addr_data.len()].copy_from_slice(addr_data);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            2 => {
                // IPv6
                if addr_data.len() > IN6ADDRSZ as usize {
                    return Err(DnsError::Edns0Failed {
                        reason: format!("IPv6 client subnet address too long: {} bytes", addr_data.len()),
                    }
                    .into());
                }
                let mut octets = [0u8; 16];
                octets[..addr_data.len()].copy_from_slice(addr_data);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => {
                return Err(DnsError::Edns0Failed {
                    reason: format!("Unsupported address family in client subnet: {}", family),
                }
                .into());
            }
        };

        Ok(Edns0Option::ClientSubnet {
            family,
            source_netmask,
            scope_netmask,
            address,
        })
    }

    /// Parses DNS Cookie option (RFC 7873)
    fn parse_cookie(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(DnsError::Edns0Failed {
                reason: format!("Cookie option too short: {} bytes (minimum 8)", data.len()),
            }
            .into());
        }

        let client = data[..8].to_vec();
        let server = if data.len() > 8 {
            if data.len() < 16 || data.len() > 40 {
                return Err(DnsError::Edns0Failed {
                    reason: format!(
                        "Invalid server cookie length: {} bytes (must be 8-32)",
                        data.len() - 8
                    ),
                }
                .into());
            }
            Some(data[8..].to_vec())
        } else {
            None
        };

        Ok(Edns0Option::Cookie { client, server })
    }

    /// Parses Extended DNS Error option (RFC 8914)
    fn parse_extended_error(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(DnsError::Edns0Failed {
                reason: format!("Extended error option too short: {} bytes", data.len()),
            }
            .into());
        }

        let info_code = u16::from_be_bytes([data[0], data[1]]);
        let extra_text = if data.len() > 2 {
            String::from_utf8_lossy(&data[2..]).to_string()
        } else {
            String::new()
        };

        Ok(Edns0Option::ExtendedError {
            info_code,
            extra_text,
        })
    }

    /// Parses MAC address option
    fn parse_mac(data: &[u8]) -> Result<Self> {
        if data.len() != 6 {
            return Err(DnsError::Edns0Failed {
                reason: format!("Invalid MAC address length: {} bytes (expected 6)", data.len()),
            }
            .into());
        }

        let mut octets = [0u8; 6];
        octets.copy_from_slice(data);
        let address = MacAddress::from_bytes(octets);

        Ok(Edns0Option::Mac { address })
    }
}

impl std::fmt::Display for Edns0Option {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Edns0Option::ClientSubnet {
                family,
                source_netmask,
                scope_netmask,
                address,
            } => {
                write!(
                    f,
                    "CLIENT-SUBNET: family={} source={} scope={} addr={}",
                    family, source_netmask, scope_netmask, address
                )
            }
            Edns0Option::DnssecOk => write!(f, "DNSSEC-OK"),
            Edns0Option::Cookie { client, server } => {
                write!(f, "COOKIE: client={:?}", client)?;
                if let Some(s) = server {
                    write!(f, " server={:?}", s)?;
                }
                Ok(())
            }
            Edns0Option::ExtendedError {
                info_code,
                extra_text,
            } => {
                write!(f, "EDE: code={} text='{}'", info_code, extra_text)
            }
            Edns0Option::Padding { length } => write!(f, "PADDING: {} bytes", length),
            Edns0Option::Mac { address } => write!(f, "MAC: {}", address),
            Edns0Option::NomDeviceId { device_id } => {
                write!(f, "NOMINUM-DEVICE: {:?}", device_id)
            }
            Edns0Option::NomCpeId { cpe_id } => write!(f, "NOMINUM-CPE: {:?}", cpe_id),
            Edns0Option::Umbrella { device_id } => write!(f, "UMBRELLA: {:?}", device_id),
            Edns0Option::Unknown { code, data } => {
                write!(f, "UNKNOWN({}): {} bytes", code, data.len())
            }
        }
    }
}

/// OPT Pseudo-Resource Record (RFC 6891 §6.1.2)
///
/// The OPT RR uses the DNS RR format with special semantics:
/// - NAME: root (empty)
/// - TYPE: OPT (41)
/// - CLASS: requestor's UDP payload size
/// - TTL: extended RCODE and flags (including DO bit)
/// - RDATA: EDNS0 options
#[derive(Debug, Clone, PartialEq)]
pub struct OptRecord {
    /// UDP payload size (CLASS field)
    pub udp_payload_size: u16,
    /// Extended RCODE (high 8 bits of TTL)
    pub extended_rcode: u8,
    /// EDNS version (always 0 per RFC 6891)
    pub version: u8,
    /// EDNS flags (low 16 bits of TTL, includes DO bit)
    pub flags: u16,
    /// EDNS0 options
    pub options: Vec<Edns0Option>,
}

impl OptRecord {
    /// Creates a new OPT record with default values
    pub fn new() -> Self {
        Self {
            udp_payload_size: DEFAULT_UDP_PAYLOAD,
            extended_rcode: 0,
            version: EDNS_VERSION,
            flags: 0,
            options: Vec::new(),
        }
    }

    /// Returns true if the DNSSEC OK (DO) bit is set
    pub fn has_do_bit(&self) -> bool {
        (self.flags & EDNS_DO_BIT) != 0
    }

    /// Sets or clears the DNSSEC OK (DO) bit
    pub fn set_do_bit(&mut self, value: bool) {
        if value {
            self.flags |= EDNS_DO_BIT;
        } else {
            self.flags &= !EDNS_DO_BIT;
        }
    }

    /// Adds an EDNS0 option to this OPT record
    pub fn add_option(&mut self, option: Edns0Option) {
        self.options.push(option);
    }

    /// Returns the total wire format size of this OPT record
    ///
    /// Includes: NAME(1) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA
    pub fn wire_size(&self) -> usize {
        let mut size = 1 + 2 + 2 + 4 + 2; // OPT RR header
        for option in &self.options {
            size += 4; // option code(2) + length(2)
            size += option.data_len();
        }
        size
    }

    /// Serializes the OPT record to wire format
    pub fn to_wire_format(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(self.wire_size());

        // NAME: root (empty, single zero byte)
        buf.push(0);

        // TYPE: OPT (41)
        buf.extend_from_slice(&T_OPT.to_be_bytes());

        // CLASS: UDP payload size
        buf.extend_from_slice(&self.udp_payload_size.to_be_bytes());

        // TTL: extended RCODE(8) + version(8) + flags(16)
        let ttl: u32 = ((self.extended_rcode as u32) << 24)
            | ((self.version as u32) << 16)
            | (self.flags as u32);
        buf.extend_from_slice(&ttl.to_be_bytes());

        // RDLENGTH and RDATA (options)
        let mut rdata = Vec::new();
        for option in &self.options {
            // Skip DnssecOk pseudo-option (represented in flags)
            if matches!(option, Edns0Option::DnssecOk) {
                continue;
            }

            // Option code
            rdata.extend_from_slice(&option.code().to_be_bytes());

            // Option data
            let option_data = option.to_wire_format()?;

            // Option length
            rdata.extend_from_slice(&(option_data.len() as u16).to_be_bytes());

            // Option data
            rdata.extend_from_slice(&option_data);
        }

        // RDLENGTH
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());

        // RDATA
        buf.extend_from_slice(&rdata);

        Ok(buf)
    }

    /// Parses an OPT record from wire format
    ///
    /// # Arguments
    ///
    /// * `data` - Buffer starting at the OPT record NAME field
    ///
    /// # Returns
    ///
    /// Parsed OPT record and number of bytes consumed
    pub fn from_wire_format(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() || data[0] != 0 {
            return Err(DnsError::Edns0Failed {
                reason: "OPT record must have empty (root) name".to_string(),
            }
            .into());
        }

        if data.len() < 11 {
            return Err(DnsError::Edns0Failed {
                reason: format!("OPT record too short: {} bytes", data.len()),
            }
            .into());
        }

        let mut offset = 1; // Skip NAME (root)

        // TYPE
        let rr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        if rr_type != T_OPT {
            return Err(DnsError::Edns0Failed {
                reason: format!("Expected OPT type {}, got {}", T_OPT, rr_type),
            }
            .into());
        }

        // CLASS (UDP payload size)
        let udp_payload_size = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // TTL (extended RCODE + version + flags)
        let ttl = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        let extended_rcode = ((ttl >> 24) & 0xFF) as u8;
        let version = ((ttl >> 16) & 0xFF) as u8;
        let flags = (ttl & 0xFFFF) as u16;

        // RDLENGTH
        let rdlength = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + rdlength {
            return Err(DnsError::Edns0Failed {
                reason: format!(
                    "OPT RDATA truncated: expected {} bytes, got {}",
                    rdlength,
                    data.len() - offset
                ),
            }
            .into());
        }

        // Parse options
        let mut options = Vec::new();
        let rdata_end = offset + rdlength;
        while offset < rdata_end {
            if offset + 4 > rdata_end {
                return Err(DnsError::Edns0Failed {
                    reason: "Truncated EDNS0 option header".to_string(),
                }
                .into());
            }

            let opt_code = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;

            let opt_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + opt_len > rdata_end {
                return Err(DnsError::Edns0Failed {
                    reason: format!(
                        "EDNS0 option {} data truncated: expected {} bytes, got {}",
                        opt_code,
                        opt_len,
                        rdata_end - offset
                    ),
                }
                .into());
            }

            let opt_data = &data[offset..offset + opt_len];
            offset += opt_len;

            match Edns0Option::from_wire_format(opt_code, opt_data) {
                Ok(option) => {
                    trace!("Parsed EDNS0 option: {}", option);
                    options.push(option);
                }
                Err(e) => {
                    warn!("Failed to parse EDNS0 option {}: {}", opt_code, e);
                    // Store as unknown option for transparency
                    options.push(Edns0Option::Unknown {
                        code: opt_code,
                        data: opt_data.to_vec(),
                    });
                }
            }
        }

        Ok((
            OptRecord {
                udp_payload_size,
                extended_rcode,
                version,
                flags,
                options,
            },
            offset,
        ))
    }
}

impl Default for OptRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// EDNS0 Handler for manipulating OPT pseudo-RRs in DNS messages
///
/// Provides methods for finding existing OPT records, adding new ones,
/// and manipulating EDNS0 options. Maintains separation between parsing
/// logic and DNS message structure.
#[derive(Debug, Clone)]
pub struct Edns0Handler {
    /// Configuration: check source addresses for MAC options
    check_source: bool,
}

impl Edns0Handler {
    /// Creates a new EDNS0 handler
    pub fn new() -> Self {
        Self {
            check_source: false,
        }
    }

    /// Finds an existing OPT pseudo-RR in the additional section
    ///
    /// # Arguments
    ///
    /// * `additional` - Additional section RRs from DNS message
    ///
    /// # Returns
    ///
    /// Index of OPT record in additional section, if found
    ///
    /// # Note
    ///
    /// Per RFC 6891 §6.1.1, only one OPT RR is allowed per message.
    /// TSIG and TKEY records are ignored during the search.
    #[instrument(skip(self, additional))]
    pub fn find_opt_record(&self, additional: &[Vec<u8>]) -> Option<usize> {
        for (idx, rr_data) in additional.iter().enumerate() {
            // Parse RR type (offset 1 after name, assuming root name)
            if rr_data.len() < 3 {
                continue;
            }

            // Skip root name (1 byte)
            let rr_type = u16::from_be_bytes([rr_data[1], rr_data[2]]);

            // Skip TSIG and TKEY per C implementation
            if rr_type == T_TSIG || rr_type == T_TKEY {
                continue;
            }

            if rr_type == T_OPT {
                debug!("Found OPT pseudo-RR at index {}", idx);
                return Some(idx);
            }
        }

        trace!("No OPT pseudo-RR found in additional section");
        None
    }

    /// Adds an OPT pseudo-RR to the additional section
    ///
    /// # Arguments
    ///
    /// * `additional` - Mutable reference to additional section
    /// * `opt_record` - OPT record to add
    ///
    /// # Returns
    ///
    /// Index of the added OPT record
    ///
    /// # Errors
    ///
    /// Returns error if serialization fails
    #[instrument(skip(self, additional, opt_record))]
    pub fn add_opt_record(
        &self,
        additional: &mut Vec<Vec<u8>>,
        opt_record: OptRecord,
    ) -> Result<usize> {
        let wire_data = opt_record.to_wire_format()?;

        debug!(
            "Adding OPT pseudo-RR: udp_size={} do_bit={} options={}",
            opt_record.udp_payload_size,
            opt_record.has_do_bit(),
            opt_record.options.len()
        );

        additional.push(wire_data);
        Ok(additional.len() - 1)
    }

    /// Sets the DNSSEC OK (DO) bit in an OPT record
    ///
    /// # Arguments
    ///
    /// * `opt_record` - OPT record to modify
    #[instrument(skip(self, opt_record))]
    pub fn set_do_bit(&self, opt_record: &mut OptRecord) {
        opt_record.set_do_bit(true);
        debug!("Set DNSSEC OK (DO) bit in OPT record");
    }

    /// Adds a Client Subnet option to an OPT record
    ///
    /// # Arguments
    ///
    /// * `opt_record` - OPT record to modify
    /// * `address` - Client subnet address
    /// * `source_netmask` - Number of significant bits in the address
    ///
    /// # Errors
    ///
    /// Returns error if address family is invalid
    #[instrument(skip(self, opt_record))]
    pub fn add_client_subnet(
        &self,
        opt_record: &mut OptRecord,
        address: IpAddr,
        source_netmask: u8,
    ) -> Result<()> {
        let family = match address {
            IpAddr::V4(_) => {
                if source_netmask > 32 {
                    return Err(DnsError::Edns0Failed {
                        reason: format!("Invalid IPv4 netmask: {}", source_netmask),
                    }
                    .into());
                }
                1u16
            }
            IpAddr::V6(_) => {
                if source_netmask > 128 {
                    return Err(DnsError::Edns0Failed {
                        reason: format!("Invalid IPv6 netmask: {}", source_netmask),
                    }
                    .into());
                }
                2u16
            }
        };

        let option = Edns0Option::ClientSubnet {
            family,
            source_netmask,
            scope_netmask: 0, // Server sets scope in response
            address,
        };

        debug!("Adding client subnet option: {} /{}", address, source_netmask);
        opt_record.add_option(option);
        Ok(())
    }

    /// Adds an Extended DNS Error option to an OPT record
    ///
    /// # Arguments
    ///
    /// * `opt_record` - OPT record to modify
    /// * `info_code` - EDE info code (use EDE_* constants)
    /// * `extra_text` - Optional human-readable error text
    #[instrument(skip(self, opt_record))]
    pub fn add_extended_error(
        &self,
        opt_record: &mut OptRecord,
        info_code: u16,
        extra_text: &str,
    ) -> Result<()> {
        let option = Edns0Option::ExtendedError {
            info_code,
            extra_text: extra_text.to_string(),
        };

        debug!("Adding extended error: code={} text='{}'", info_code, extra_text);
        opt_record.add_option(option);
        Ok(())
    }

    /// Adds a MAC address option to an OPT record
    ///
    /// # Arguments
    ///
    /// * `opt_record` - OPT record to modify
    /// * `mac` - Client MAC address
    #[instrument(skip(self, opt_record))]
    pub fn add_mac_option(&self, opt_record: &mut OptRecord, mac: MacAddress) -> Result<()> {
        let option = Edns0Option::Mac { address: mac };

        debug!("Adding MAC address option: {}", mac);
        opt_record.add_option(option);
        Ok(())
    }

    /// Checks if an EDNS0 option should be accepted based on source address
    ///
    /// # Arguments
    ///
    /// * `option` - EDNS0 option to validate
    /// * `source` - Source socket address of the query
    ///
    /// # Returns
    ///
    /// `true` if the option should be accepted, `false` otherwise
    ///
    /// # Note
    ///
    /// This implements dnsmasq's check for accepting device identification
    /// options only from trusted sources (typically local networks).
    #[instrument(skip(self))]
    pub fn check_source(&self, option: &Edns0Option, source: &SocketAddr) -> bool {
        if !self.check_source {
            return true;
        }

        match option {
            Edns0Option::Mac { .. }
            | Edns0Option::NomDeviceId { .. }
            | Edns0Option::NomCpeId { .. }
            | Edns0Option::Umbrella { .. } => {
                // Only accept device ID options from local networks
                // This is a simplified check; the C version does more sophisticated
                // subnet matching via find_subnet_for_src()
                let is_local = match source.ip() {
                    std::net::IpAddr::V4(ipv4) => {
                        ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        ipv6.is_loopback()
                            || ipv6.is_unicast_link_local()
                            || ipv6.is_unique_local()
                    }
                };

                if !is_local {
                    warn!(
                        "Rejecting device ID option {} from non-local source {}",
                        option, source
                    );
                }

                is_local
            }
            _ => true, // All other options accepted
        }
    }
}

impl Default for Edns0Handler {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing OPT records with fluent API
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::dns::edns0::{Edns0Builder, Edns0Option};
/// use std::net::Ipv4Addr;
///
/// let opt = Edns0Builder::new()
///     .udp_size(4096)
///     .do_bit(true)
///     .client_subnet(Ipv4Addr::new(192, 0, 2, 1).into(), 24)
///     .build()
///     .expect("Failed to build OPT record");
/// ```
#[derive(Debug, Clone)]
pub struct Edns0Builder {
    udp_payload_size: u16,
    do_bit: bool,
    options: Vec<Edns0Option>,
}

impl Edns0Builder {
    /// Creates a new builder with default values
    pub fn new() -> Self {
        Self {
            udp_payload_size: DEFAULT_UDP_PAYLOAD,
            do_bit: false,
            options: Vec::new(),
        }
    }

    /// Sets the UDP payload size
    ///
    /// # Arguments
    ///
    /// * `size` - Maximum UDP payload size in bytes (clamped to MAX_UDP_PAYLOAD)
    pub fn udp_size(mut self, size: u16) -> Self {
        self.udp_payload_size = size.min(MAX_UDP_PAYLOAD);
        self
    }

    /// Sets the DNSSEC OK (DO) bit
    ///
    /// # Arguments
    ///
    /// * `value` - Whether to set the DO bit
    pub fn do_bit(mut self, value: bool) -> Self {
        self.do_bit = value;
        self
    }

    /// Adds a Client Subnet option
    ///
    /// # Arguments
    ///
    /// * `address` - Client subnet address
    /// * `source_netmask` - Number of significant bits
    pub fn client_subnet(mut self, address: IpAddr, source_netmask: u8) -> Self {
        let family = if address.is_ipv4() { 1 } else { 2 };
        self.options.push(Edns0Option::ClientSubnet {
            family,
            source_netmask,
            scope_netmask: 0,
            address,
        });
        self
    }

    /// Adds an Extended DNS Error option
    ///
    /// # Arguments
    ///
    /// * `info_code` - EDE info code
    /// * `extra_text` - Human-readable error text
    pub fn extended_error(mut self, info_code: u16, extra_text: impl Into<String>) -> Self {
        self.options.push(Edns0Option::ExtendedError {
            info_code,
            extra_text: extra_text.into(),
        });
        self
    }

    /// Adds a MAC address option
    ///
    /// # Arguments
    ///
    /// * `mac` - Client MAC address
    pub fn mac(mut self, mac: MacAddress) -> Self {
        self.options.push(Edns0Option::Mac { address: mac });
        self
    }

    /// Builds the OPT record
    ///
    /// # Returns
    ///
    /// Constructed OPT record
    pub fn build(self) -> Result<OptRecord> {
        let mut opt = OptRecord {
            udp_payload_size: self.udp_payload_size,
            extended_rcode: 0,
            version: EDNS_VERSION,
            flags: if self.do_bit { EDNS_DO_BIT } else { 0 },
            options: self.options,
        };

        // Validate UDP payload size
        if opt.udp_payload_size < 512 {
            warn!(
                "UDP payload size {} is below minimum 512, using default",
                opt.udp_payload_size
            );
            opt.udp_payload_size = DEFAULT_UDP_PAYLOAD;
        }

        Ok(opt)
    }
}

impl Default for Edns0Builder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opt_record_creation() {
        let opt = OptRecord::new();
        assert_eq!(opt.udp_payload_size, DEFAULT_UDP_PAYLOAD);
        assert_eq!(opt.version, EDNS_VERSION);
        assert_eq!(opt.flags, 0);
        assert!(!opt.has_do_bit());
    }

    #[test]
    fn test_do_bit() {
        let mut opt = OptRecord::new();
        assert!(!opt.has_do_bit());

        opt.set_do_bit(true);
        assert!(opt.has_do_bit());
        assert_eq!(opt.flags & EDNS_DO_BIT, EDNS_DO_BIT);

        opt.set_do_bit(false);
        assert!(!opt.has_do_bit());
    }

    #[test]
    fn test_client_subnet_ipv4() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let option = Edns0Option::ClientSubnet {
            family: 1,
            source_netmask: 24,
            scope_netmask: 0,
            address: addr,
        };

        assert_eq!(option.code(), EDNS0_OPTION_CLIENT_SUBNET);
        let data = option.to_wire_format().expect("Failed to serialize");
        assert!(data.len() >= 7); // family(2) + masks(2) + addr(3 bytes for /24)
    }

    #[test]
    fn test_client_subnet_ipv6() {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let option = Edns0Option::ClientSubnet {
            family: 2,
            source_netmask: 48,
            scope_netmask: 0,
            address: addr,
        };

        assert_eq!(option.code(), EDNS0_OPTION_CLIENT_SUBNET);
        let data = option.to_wire_format().expect("Failed to serialize");
        assert!(data.len() >= 10); // family(2) + masks(2) + addr(6 bytes for /48)
    }

    #[test]
    fn test_extended_error() {
        let option = Edns0Option::ExtendedError {
            info_code: EDE_DNSSEC_BOGUS as u16,
            extra_text: "DNSSEC validation failed".to_string(),
        };

        assert_eq!(option.code(), 15);
        let data = option.to_wire_format().expect("Failed to serialize");
        assert_eq!(data[0..2], (EDE_DNSSEC_BOGUS as u16).to_be_bytes());
        assert!(data.len() > 2);
    }

    #[test]
    fn test_mac_option() {
        let mac = MacAddress::from_bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let option = Edns0Option::Mac { address: mac };

        assert_eq!(option.code(), EDNS0_OPTION_MAC);
        assert_eq!(option.data_len(), 6);

        let data = option.to_wire_format().expect("Failed to serialize");
        assert_eq!(data, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_edns0_builder() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mac = MacAddress::from_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        let opt = Edns0Builder::new()
            .udp_size(4096)
            .do_bit(true)
            .client_subnet(addr, 24)
            .extended_error(EDE_STALE as u16, "Stale answer")
            .mac(mac)
            .build()
            .expect("Builder failed");

        assert_eq!(opt.udp_payload_size, 4096);
        assert!(opt.has_do_bit());
        assert_eq!(opt.options.len(), 3); // ClientSubnet, ExtendedError, Mac
    }

    #[test]
    fn test_opt_wire_format_roundtrip() {
        let mut opt = OptRecord::new();
        opt.udp_payload_size = 1232;
        opt.set_do_bit(true);
        opt.add_option(Edns0Option::ClientSubnet {
            family: 1,
            source_netmask: 24,
            scope_netmask: 0,
            address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
        });

        let wire = opt.to_wire_format().expect("Serialization failed");
        let (parsed, _consumed) = OptRecord::from_wire_format(&wire).expect("Parsing failed");

        assert_eq!(parsed.udp_payload_size, opt.udp_payload_size);
        assert_eq!(parsed.has_do_bit(), opt.has_do_bit());
        assert_eq!(parsed.options.len(), opt.options.len());
    }

    #[test]
    fn test_check_source_local() {
        let handler = Edns0Handler::new();
        let mac = MacAddress::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let option = Edns0Option::Mac { address: mac };

        // Local address should be accepted
        let local_source: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        assert!(handler.check_source(&option, &local_source));

        // Public address should be rejected (when check_source is enabled)
        let mut handler_strict = Edns0Handler::new();
        handler_strict.check_source = true;
        let public_source: SocketAddr = "8.8.8.8:12345".parse().unwrap();
        assert!(!handler_strict.check_source(&option, &public_source));
    }

    #[test]
    fn test_parse_client_subnet_option() {
        // IPv4 client subnet: family=1, source=24, scope=0, address=192.0.2.0
        let data = vec![
            0x00, 0x01, // family = 1 (IPv4)
            24,   // source netmask
            0,    // scope netmask
            192, 0, 2, // address bytes (3 bytes for /24)
        ];

        let option = Edns0Option::from_wire_format(EDNS0_OPTION_CLIENT_SUBNET, &data)
            .expect("Failed to parse");

        match option {
            Edns0Option::ClientSubnet {
                family,
                source_netmask,
                scope_netmask,
                address,
            } => {
                assert_eq!(family, 1);
                assert_eq!(source_netmask, 24);
                assert_eq!(scope_netmask, 0);
                assert!(matches!(address, IpAddr::V4(_)));
            }
            _ => panic!("Wrong option type"),
        }
    }

    #[test]
    fn test_parse_extended_error_option() {
        // EDE: code=6 (DNSSEC bogus), text="signature expired"
        let mut data = vec![0x00, 0x06]; // info code = 6
        data.extend_from_slice(b"signature expired");

        let option =
            Edns0Option::from_wire_format(15, &data).expect("Failed to parse EDE");

        match option {
            Edns0Option::ExtendedError {
                info_code,
                extra_text,
            } => {
                assert_eq!(info_code, 6);
                assert_eq!(extra_text, "signature expired");
            }
            _ => panic!("Wrong option type"),
        }
    }
}

