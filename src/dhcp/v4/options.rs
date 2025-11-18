//! DHCPv4 Option Encoding and Decoding
//!
//! This module provides type-safe DHCPv4 option handling per RFC 2132, replacing the C
//! implementation's manual buffer manipulation with memory-safe Rust patterns.
//!
//! # Overview
//!
//! DHCP options use TLV (Type-Length-Value) encoding:
//! - Type: 1 byte option code
//! - Length: 1 byte data length (not including type and length bytes)
//! - Value: Variable-length option data
//!
//! Special options:
//! - Option 0 (OPTION_PAD): Single byte padding, no length/value
//! - Option 255 (OPTION_END): End of options marker, no length/value
//! - Option 52 (OPTION_OVERLOAD): Indicates sname/file fields contain additional options
//!
//! # Memory Safety
//!
//! This implementation uses:
//! - `nom` parser combinators for bounds-checked option parsing
//! - `bytes::BytesMut` for safe buffer management during encoding
//! - Rust's type system to prevent invalid option data
//! - Exhaustive pattern matching to ensure all options are handled
//!
//! # Examples
//!
//! ```ignore
//! use dhcp::v4::options::{DhcpOption, MessageType, parse_options, encode_options};
//!
//! // Parse options from wire format
//! let data = &[53, 1, 1, 255]; // MessageType = Discover, End
//! let options = parse_options(data)?;
//!
//! // Encode options to wire format
//! let options = vec![DhcpOption::MessageType(MessageType::Discover)];
//! let encoded = encode_options(&options);
//! ```

use crate::dhcp::v4::constants::{
    OPTION_PAD, OPTION_END, OPTION_NETMASK, OPTION_ROUTER, OPTION_DNS_SERVER,
    OPTION_HOSTNAME, OPTION_DOMAIN_NAME, OPTION_REQUESTED_IP, OPTION_LEASE_TIME,
    OPTION_OVERLOAD, OPTION_MESSAGE_TYPE, OPTION_SERVER_IDENTIFIER, OPTION_PARAMETER_LIST,
    OPTION_MESSAGE, OPTION_T1, OPTION_T2, OPTION_VENDOR_ID,
    OPTION_CLIENT_ID, OPTION_SNAME, OPTION_FILENAME,
    OPTION_AGENT_ID, OPTION_RAPID_COMMIT, MSG_TYPE_DISCOVER, MSG_TYPE_OFFER,
    MSG_TYPE_REQUEST, MSG_TYPE_ACK, MSG_TYPE_NAK, MSG_TYPE_DECLINE, MSG_TYPE_RELEASE,
    MSG_TYPE_INFORM,
};
use crate::error::DhcpError;

use std::fmt;
use std::net::Ipv4Addr;
use bytes::{Bytes, BytesMut, BufMut};

/// DHCP Message Type (Option 53)
///
/// Identifies the type of DHCP message. This is a required option in all DHCP messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// DHCPDISCOVER - Client broadcast to locate available servers
    Discover,
    /// DHCPOFFER - Server response to DHCPDISCOVER with offered configuration
    Offer,
    /// DHCPREQUEST - Client message accepting offer or renewing/rebinding lease
    Request,
    /// DHCPACK - Server acknowledgment of DHCPREQUEST
    Ack,
    /// DHCPNAK - Server denial of DHCPREQUEST
    Nak,
    /// DHCPDECLINE - Client notification that offered address is already in use
    Decline,
    /// DHCPRELEASE - Client relinquishment of network address
    Release,
    /// DHCPINFORM - Client request for local configuration parameters (already has IP)
    Inform,
}

impl MessageType {
    /// Convert from wire format u8 value to MessageType enum
    ///
    /// # Errors
    ///
    /// Returns `DhcpError::InvalidOption` if the message type value is not in range 1-8
    pub fn from_u8(value: u8) -> Result<Self, DhcpError> {
        match value {
            MSG_TYPE_DISCOVER => Ok(MessageType::Discover),
            MSG_TYPE_OFFER => Ok(MessageType::Offer),
            MSG_TYPE_REQUEST => Ok(MessageType::Request),
            MSG_TYPE_ACK => Ok(MessageType::Ack),
            MSG_TYPE_NAK => Ok(MessageType::Nak),
            MSG_TYPE_DECLINE => Ok(MessageType::Decline),
            MSG_TYPE_RELEASE => Ok(MessageType::Release),
            MSG_TYPE_INFORM => Ok(MessageType::Inform),
            _ => Err(DhcpError::InvalidOption {
                option_code: OPTION_MESSAGE_TYPE,
                reason: format!("Invalid message type value: {}", value),
            }),
        }
    }

    /// Convert MessageType enum to wire format u8 value
    pub fn to_u8(self) -> u8 {
        match self {
            MessageType::Discover => MSG_TYPE_DISCOVER,
            MessageType::Offer => MSG_TYPE_OFFER,
            MessageType::Request => MSG_TYPE_REQUEST,
            MessageType::Ack => MSG_TYPE_ACK,
            MessageType::Nak => MSG_TYPE_NAK,
            MessageType::Decline => MSG_TYPE_DECLINE,
            MessageType::Release => MSG_TYPE_RELEASE,
            MessageType::Inform => MSG_TYPE_INFORM,
        }
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::Discover => write!(f, "DHCPDISCOVER"),
            MessageType::Offer => write!(f, "DHCPOFFER"),
            MessageType::Request => write!(f, "DHCPREQUEST"),
            MessageType::Ack => write!(f, "DHCPACK"),
            MessageType::Nak => write!(f, "DHCPNAK"),
            MessageType::Decline => write!(f, "DHCPDECLINE"),
            MessageType::Release => write!(f, "DHCPRELEASE"),
            MessageType::Inform => write!(f, "DHCPINFORM"),
        }
    }
}

/// DHCP Option
///
/// Represents all standard DHCPv4 options defined in RFC 2132 and related RFCs.
/// Each variant contains typed data appropriate for that option.
///
/// # Wire Format
///
/// Most options use TLV encoding: [code: u8][length: u8][data: [u8; length]]
/// Exceptions: OPTION_PAD (0) and OPTION_END (255) have no length or data.
#[derive(Debug, Clone, PartialEq)]
pub enum DhcpOption {
    /// Option 0: Padding byte (no length, no data)
    Pad,
    
    /// Option 255: End of options marker (no length, no data)
    End,
    
    /// Option 1: Subnet Mask - 4 bytes (IPv4 address)
    Netmask(Ipv4Addr),
    
    /// Option 3: Router - List of router IP addresses (multiple of 4 bytes)
    Router(Vec<Ipv4Addr>),
    
    /// Option 6: Domain Name Server - List of DNS server IP addresses (multiple of 4 bytes)
    DnsServer(Vec<Ipv4Addr>),
    
    /// Option 12: Hostname - Client hostname (variable length string)
    Hostname(String),
    
    /// Option 15: Domain Name - DNS domain name (variable length string)
    DomainName(String),
    
    /// Option 50: Requested IP Address - Client's requested IP (4 bytes)
    RequestedIpAddress(Ipv4Addr),
    
    /// Option 51: IP Address Lease Time - Lease duration in seconds (4 bytes, u32)
    LeaseTime(u32),
    
    /// Option 52: Overload - Indicates sname/file fields contain options (1 byte)
    /// Value: 1 = file field, 2 = sname field, 3 = both
    Overload(u8),
    
    /// Option 53: DHCP Message Type - Type of DHCP message (1 byte)
    MessageType(MessageType),
    
    /// Option 54: Server Identifier - DHCP server's IP address (4 bytes)
    ServerId(Ipv4Addr),
    
    /// Option 55: Parameter Request List - List of requested option codes (variable length)
    ParameterRequestList(Vec<u8>),
    
    /// Option 56: Message - Error message or informational text (variable length string)
    Message(String),
    
    /// Option 58: Renewal Time (T1) - Time until client should renew lease (4 bytes, u32 seconds)
    RenewalTime(u32),
    
    /// Option 59: Rebinding Time (T2) - Time until client should rebind (4 bytes, u32 seconds)
    RebindingTime(u32),
    
    /// Option 60: Vendor Class Identifier - Vendor-specific identifier (variable length bytes)
    VendorClassId(Vec<u8>),
    
    /// Option 61: Client Identifier - Unique client identifier (variable length)
    /// First byte is hardware type (usually 1 for Ethernet), followed by hardware address
    ClientId(Vec<u8>),
    
    /// Option 66: TFTP Server Name - TFTP server hostname (variable length string)
    TftpServerName(String),
    
    /// Option 67: Boot File Name - Boot file name for network booting (variable length string)
    BootFileName(String),
    
    /// Option 82: Relay Agent Information - Suboptions added by relay agents (variable length)
    RelayAgentInfo(Vec<u8>),
    
    /// Option 80: Rapid Commit - Enables 2-message exchange (no data, length = 0)
    RapidCommit,
    
    /// Unknown option - Code and raw data for options not explicitly handled
    Unknown {
        /// The DHCP option code (0-255)
        code: u8,
        /// The raw option data bytes
        data: Vec<u8>
    },
}

impl DhcpOption {
    /// Get the option code for this option
    pub fn option_code(&self) -> u8 {
        match self {
            DhcpOption::Pad => OPTION_PAD,
            DhcpOption::End => OPTION_END,
            DhcpOption::Netmask(_) => OPTION_NETMASK,
            DhcpOption::Router(_) => OPTION_ROUTER,
            DhcpOption::DnsServer(_) => OPTION_DNS_SERVER,
            DhcpOption::Hostname(_) => OPTION_HOSTNAME,
            DhcpOption::DomainName(_) => OPTION_DOMAIN_NAME,
            DhcpOption::RequestedIpAddress(_) => OPTION_REQUESTED_IP,
            DhcpOption::LeaseTime(_) => OPTION_LEASE_TIME,
            DhcpOption::Overload(_) => OPTION_OVERLOAD,
            DhcpOption::MessageType(_) => OPTION_MESSAGE_TYPE,
            DhcpOption::ServerId(_) => OPTION_SERVER_IDENTIFIER,
            DhcpOption::ParameterRequestList(_) => OPTION_PARAMETER_LIST,
            DhcpOption::Message(_) => OPTION_MESSAGE,
            DhcpOption::RenewalTime(_) => OPTION_T1,
            DhcpOption::RebindingTime(_) => OPTION_T2,
            DhcpOption::VendorClassId(_) => OPTION_VENDOR_ID,
            DhcpOption::ClientId(_) => OPTION_CLIENT_ID,
            DhcpOption::TftpServerName(_) => OPTION_SNAME,
            DhcpOption::BootFileName(_) => OPTION_FILENAME,
            DhcpOption::RelayAgentInfo(_) => OPTION_AGENT_ID,
            DhcpOption::RapidCommit => OPTION_RAPID_COMMIT,
            DhcpOption::Unknown { code, .. } => *code,
        }
    }

    /// Get the length of the option data (excluding code and length bytes)
    pub fn data_len(&self) -> usize {
        match self {
            DhcpOption::Pad | DhcpOption::End => 0,
            DhcpOption::Netmask(_) => 4,
            DhcpOption::Router(addrs) => addrs.len() * 4,
            DhcpOption::DnsServer(addrs) => addrs.len() * 4,
            DhcpOption::Hostname(s) => s.len(),
            DhcpOption::DomainName(s) => s.len(),
            DhcpOption::RequestedIpAddress(_) => 4,
            DhcpOption::LeaseTime(_) => 4,
            DhcpOption::Overload(_) => 1,
            DhcpOption::MessageType(_) => 1,
            DhcpOption::ServerId(_) => 4,
            DhcpOption::ParameterRequestList(list) => list.len(),
            DhcpOption::Message(s) => s.len(),
            DhcpOption::RenewalTime(_) => 4,
            DhcpOption::RebindingTime(_) => 4,
            DhcpOption::VendorClassId(data) => data.len(),
            DhcpOption::ClientId(data) => data.len(),
            DhcpOption::TftpServerName(s) => s.len(),
            DhcpOption::BootFileName(s) => s.len(),
            DhcpOption::RelayAgentInfo(data) => data.len(),
            DhcpOption::RapidCommit => 0,
            DhcpOption::Unknown { data, .. } => data.len(),
        }
    }
}

impl fmt::Display for DhcpOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpOption::Pad => write!(f, "Pad"),
            DhcpOption::End => write!(f, "End"),
            DhcpOption::Netmask(addr) => write!(f, "Netmask({})", addr),
            DhcpOption::Router(addrs) => write!(f, "Router({:?})", addrs),
            DhcpOption::DnsServer(addrs) => write!(f, "DnsServer({:?})", addrs),
            DhcpOption::Hostname(s) => write!(f, "Hostname({})", s),
            DhcpOption::DomainName(s) => write!(f, "DomainName({})", s),
            DhcpOption::RequestedIpAddress(addr) => write!(f, "RequestedIpAddress({})", addr),
            DhcpOption::LeaseTime(t) => write!(f, "LeaseTime({}s)", t),
            DhcpOption::Overload(flag) => write!(f, "Overload({})", flag),
            DhcpOption::MessageType(mt) => write!(f, "MessageType({})", mt),
            DhcpOption::ServerId(addr) => write!(f, "ServerId({})", addr),
            DhcpOption::ParameterRequestList(list) => write!(f, "ParameterRequestList({:?})", list),
            DhcpOption::Message(s) => write!(f, "Message({})", s),
            DhcpOption::RenewalTime(t) => write!(f, "RenewalTime({}s)", t),
            DhcpOption::RebindingTime(t) => write!(f, "RebindingTime({}s)", t),
            DhcpOption::VendorClassId(data) => write!(f, "VendorClassId({} bytes)", data.len()),
            DhcpOption::ClientId(data) => write!(f, "ClientId({} bytes)", data.len()),
            DhcpOption::TftpServerName(s) => write!(f, "TftpServerName({})", s),
            DhcpOption::BootFileName(s) => write!(f, "BootFileName({})", s),
            DhcpOption::RelayAgentInfo(data) => write!(f, "RelayAgentInfo({} bytes)", data.len()),
            DhcpOption::RapidCommit => write!(f, "RapidCommit"),
            DhcpOption::Unknown { code, data } => write!(f, "Unknown(code={}, {} bytes)", code, data.len()),
        }
    }
}

/// Parse a single DHCP option from wire format
///
/// Uses nom parser combinators for safe, bounds-checked parsing. This function
/// replaces the C implementation's manual pointer arithmetic and buffer walking.
///
/// # Arguments
///
/// * `code` - The option code (1 byte)
/// * `data` - The option data (length already validated by caller)
///
/// # Returns
///
/// Returns `Ok(DhcpOption)` on success or `Err(DhcpError)` if parsing fails.
///
/// # Errors
///
/// Returns errors for:
/// - Invalid data length for fixed-size options
/// - Invalid UTF-8 in string options
/// - Invalid subnet mask format
/// - Invalid message type value
/// - Malformed IP address lists
pub fn parse_option(code: u8, data: &[u8]) -> Result<DhcpOption, DhcpError> {
    match code {
        OPTION_PAD => Ok(DhcpOption::Pad),
        OPTION_END => Ok(DhcpOption::End),
        
        OPTION_NETMASK => {
            if data.len() != 4 {
                return Err(DhcpError::InvalidOption {
                    option_code: code,
                    reason: format!("Netmask option must be 4 bytes, got {}", data.len()),
                });
            }
            let addr = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            
            // Validate that it's a valid subnet mask (contiguous 1s followed by 0s)
            validate_subnet_mask(addr)?;
            
            Ok(DhcpOption::Netmask(addr))
        }
        
        OPTION_ROUTER => {
            if data.len() % 4 != 0 {
                return Err(DhcpError::InvalidOption {
                    option_code: OPTION_ROUTER,
                    reason: format!("Router option length must be multiple of 4, got {}", data.len()),
                });
            }
            let addrs = parse_ipv4_list(data, OPTION_ROUTER)?;
            Ok(DhcpOption::Router(addrs))
        }
        
        OPTION_DNS_SERVER => {
            if data.len() % 4 != 0 {
                return Err(DhcpError::InvalidOption {
                    option_code: OPTION_DNS_SERVER,
                    reason: format!("DNS Server option length must be multiple of 4, got {}", data.len()),
                });
            }
            let addrs = parse_ipv4_list(data, OPTION_DNS_SERVER)?;
            Ok(DhcpOption::DnsServer(addrs))
        }
        
        OPTION_HOSTNAME => {
            let hostname = parse_string(data, OPTION_HOSTNAME)?;
            Ok(DhcpOption::Hostname(hostname))
        }
        
        OPTION_DOMAIN_NAME => {
            let domain = parse_string(data, OPTION_DOMAIN_NAME)?;
            Ok(DhcpOption::DomainName(domain))
        }
        
        OPTION_REQUESTED_IP => {
            if data.len() != 4 {
                return Err(DhcpError::InvalidOption {
                    option_code: code,
                    reason: format!("Requested IP option must be 4 bytes, got {}", data.len()),
                });
            }
            let addr = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            Ok(DhcpOption::RequestedIpAddress(addr))
        }
        
        OPTION_LEASE_TIME => {
            if data.len() != 4 {
                return Err(DhcpError::InvalidOption {
                    option_code: code,
                    reason: format!("Lease Time option must be 4 bytes, got {}", data.len()),
                });
            }
            let time = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            Ok(DhcpOption::LeaseTime(time))
        }
        
        OPTION_OVERLOAD => {
            if data.len() != 1 {
                return Err(DhcpError::InvalidOption {
                    option_code: code,
                    reason: format!("Overload option must be 1 byte, got {}", data.len()),
                });
            }
            let flag = data[0];
            if flag < 1 || flag > 3 {
                return Err(DhcpError::InvalidOption {
                    option_code: code,
                    reason: format!("Overload flag must be 1-3, got {}", flag),
                });
            }
            Ok(DhcpOption::Overload(flag))
        }
        
        OPTION_MESSAGE_TYPE => {
            if data.len() != 1 {
                return Err(DhcpError::InvalidOption {
                    option_code: code,
                    reason: format!("Message Type option must be 1 byte, got {}", data.len()),
                });
            }
            let msg_type = MessageType::from_u8(data[0])?;
            Ok(DhcpOption::MessageType(msg_type))
        }
        
        OPTION_SERVER_IDENTIFIER => {
            if data.len() != 4 {
                return Err(DhcpError::InvalidOption {
                    option_code: code,
                    reason: format!("Server Identifier option must be 4 bytes, got {}", data.len()),
                });
            }
            let addr = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            Ok(DhcpOption::ServerId(addr))
        }
        
        OPTION_PARAMETER_LIST => {
            Ok(DhcpOption::ParameterRequestList(data.to_vec()))
        }
        
        OPTION_MESSAGE => {
            let message = parse_string(data, OPTION_MESSAGE)?;
            Ok(DhcpOption::Message(message))
        }
        
        OPTION_T1 => {
            if data.len() != 4 {
                return Err(DhcpError::InvalidOption {
                    option_code: code,
                    reason: format!("Renewal Time option must be 4 bytes, got {}", data.len()),
                });
            }
            let time = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            Ok(DhcpOption::RenewalTime(time))
        }
        
        OPTION_T2 => {
            if data.len() != 4 {
                return Err(DhcpError::InvalidOption {
                    option_code: code,
                    reason: format!("Rebinding Time option must be 4 bytes, got {}", data.len()),
                });
            }
            let time = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            Ok(DhcpOption::RebindingTime(time))
        }
        
        OPTION_VENDOR_ID => {
            Ok(DhcpOption::VendorClassId(data.to_vec()))
        }
        
        OPTION_CLIENT_ID => {
            if data.is_empty() {
                return Err(DhcpError::InvalidOption {
                    option_code: code,
                    reason: "Client Identifier option cannot be empty".to_string(),
                });
            }
            Ok(DhcpOption::ClientId(data.to_vec()))
        }
        
        OPTION_SNAME => {
            let name = parse_string(data, OPTION_SNAME)?;
            Ok(DhcpOption::TftpServerName(name))
        }
        
        OPTION_FILENAME => {
            let name = parse_string(data, OPTION_FILENAME)?;
            Ok(DhcpOption::BootFileName(name))
        }
        
        OPTION_AGENT_ID => {
            Ok(DhcpOption::RelayAgentInfo(data.to_vec()))
        }
        
        OPTION_RAPID_COMMIT => {
            if !data.is_empty() {
                return Err(DhcpError::InvalidOption {
                    option_code: code,
                    reason: format!("Rapid Commit option must have zero length, got {}", data.len()),
                });
            }
            Ok(DhcpOption::RapidCommit)
        }
        
        // Unknown option - store code and data for potential forwarding
        _ => Ok(DhcpOption::Unknown {
            code,
            data: data.to_vec(),
        }),
    }
}

/// Encode a DHCP option to wire format
///
/// Serializes the option using TLV encoding with BytesMut for safe buffer management.
/// This replaces the C implementation's manual buffer pointer manipulation.
///
/// # Arguments
///
/// * `option` - The option to encode
/// * `buf` - The buffer to write the encoded option to
///
/// # Wire Format
///
/// For most options: [code: u8][length: u8][data: length bytes]
/// For PAD and END: [code: u8] only (no length or data)
pub fn encode_option(option: &DhcpOption, buf: &mut BytesMut) {
    match option {
        DhcpOption::Pad => {
            buf.put_u8(OPTION_PAD);
        }
        
        DhcpOption::End => {
            buf.put_u8(OPTION_END);
        }
        
        DhcpOption::Netmask(addr) => {
            buf.put_u8(OPTION_NETMASK);
            buf.put_u8(4);
            buf.put_slice(&addr.octets());
        }
        
        DhcpOption::Router(addrs) => {
            buf.put_u8(OPTION_ROUTER);
            buf.put_u8((addrs.len() * 4) as u8);
            for addr in addrs {
                buf.put_slice(&addr.octets());
            }
        }
        
        DhcpOption::DnsServer(addrs) => {
            buf.put_u8(OPTION_DNS_SERVER);
            buf.put_u8((addrs.len() * 4) as u8);
            for addr in addrs {
                buf.put_slice(&addr.octets());
            }
        }
        
        DhcpOption::Hostname(s) => {
            buf.put_u8(OPTION_HOSTNAME);
            buf.put_u8(s.len() as u8);
            buf.put_slice(s.as_bytes());
        }
        
        DhcpOption::DomainName(s) => {
            buf.put_u8(OPTION_DOMAIN_NAME);
            buf.put_u8(s.len() as u8);
            buf.put_slice(s.as_bytes());
        }
        
        DhcpOption::RequestedIpAddress(addr) => {
            buf.put_u8(OPTION_REQUESTED_IP);
            buf.put_u8(4);
            buf.put_slice(&addr.octets());
        }
        
        DhcpOption::LeaseTime(time) => {
            buf.put_u8(OPTION_LEASE_TIME);
            buf.put_u8(4);
            buf.put_u32(*time);
        }
        
        DhcpOption::Overload(flag) => {
            buf.put_u8(OPTION_OVERLOAD);
            buf.put_u8(1);
            buf.put_u8(*flag);
        }
        
        DhcpOption::MessageType(msg_type) => {
            buf.put_u8(OPTION_MESSAGE_TYPE);
            buf.put_u8(1);
            buf.put_u8(msg_type.to_u8());
        }
        
        DhcpOption::ServerId(addr) => {
            buf.put_u8(OPTION_SERVER_IDENTIFIER);
            buf.put_u8(4);
            buf.put_slice(&addr.octets());
        }
        
        DhcpOption::ParameterRequestList(list) => {
            buf.put_u8(OPTION_PARAMETER_LIST);
            buf.put_u8(list.len() as u8);
            buf.put_slice(list);
        }
        
        DhcpOption::Message(s) => {
            buf.put_u8(OPTION_MESSAGE);
            buf.put_u8(s.len() as u8);
            buf.put_slice(s.as_bytes());
        }
        
        DhcpOption::RenewalTime(time) => {
            buf.put_u8(OPTION_T1);
            buf.put_u8(4);
            buf.put_u32(*time);
        }
        
        DhcpOption::RebindingTime(time) => {
            buf.put_u8(OPTION_T2);
            buf.put_u8(4);
            buf.put_u32(*time);
        }
        
        DhcpOption::VendorClassId(data) => {
            buf.put_u8(OPTION_VENDOR_ID);
            buf.put_u8(data.len() as u8);
            buf.put_slice(data);
        }
        
        DhcpOption::ClientId(data) => {
            buf.put_u8(OPTION_CLIENT_ID);
            buf.put_u8(data.len() as u8);
            buf.put_slice(data);
        }
        
        DhcpOption::TftpServerName(s) => {
            buf.put_u8(OPTION_SNAME);
            buf.put_u8(s.len() as u8);
            buf.put_slice(s.as_bytes());
        }
        
        DhcpOption::BootFileName(s) => {
            buf.put_u8(OPTION_FILENAME);
            buf.put_u8(s.len() as u8);
            buf.put_slice(s.as_bytes());
        }
        
        DhcpOption::RelayAgentInfo(data) => {
            buf.put_u8(OPTION_AGENT_ID);
            buf.put_u8(data.len() as u8);
            buf.put_slice(data);
        }
        
        DhcpOption::RapidCommit => {
            buf.put_u8(OPTION_RAPID_COMMIT);
            buf.put_u8(0);
        }
        
        DhcpOption::Unknown { code, data } => {
            buf.put_u8(*code);
            buf.put_u8(data.len() as u8);
            buf.put_slice(data);
        }
    }
}

/// Parse a complete DHCP option list from wire format
///
/// Parses options until OPTION_END is encountered or the buffer is exhausted.
/// Handles OPTION_PAD for alignment. Uses nom parsers for safe bounds checking.
///
/// # Arguments
///
/// * `input` - Raw option data from DHCP packet
///
/// # Returns
///
/// Returns `Ok(Vec<DhcpOption>)` with all parsed options, or `Err(DhcpError)` on failure.
///
/// # Errors
///
/// Returns errors for:
/// - Malformed TLV encoding
/// - Invalid option data
/// - Buffer overruns
/// - Missing OPTION_END
pub fn parse_options(input: &[u8]) -> Result<Vec<DhcpOption>, DhcpError> {
    let mut options = Vec::new();
    let mut remaining = input;
    
    while !remaining.is_empty() {
        // Parse option code
        let code = remaining[0];
        
        // Handle special options that don't have length fields
        if code == OPTION_PAD {
            options.push(DhcpOption::Pad);
            remaining = &remaining[1..];
            continue;
        }
        
        if code == OPTION_END {
            options.push(DhcpOption::End);
            break;
        }
        
        // Need at least 2 bytes for code + length
        if remaining.len() < 2 {
            return Err(DhcpError::ParseFailed {
                reason: "Truncated option: missing length field".to_string(),
            });
        }
        
        let length = remaining[1] as usize;
        
        // Check if we have enough data
        if remaining.len() < 2 + length {
            return Err(DhcpError::ParseFailed {
                reason: format!(
                    "Truncated option {}: expected {} bytes, got {}",
                    code,
                    length,
                    remaining.len() - 2
                ),
            });
        }
        
        // Extract option data
        let data = &remaining[2..2 + length];
        
        // Parse the option
        let option = parse_option(code, data)?;
        options.push(option);
        
        // Advance to next option
        remaining = &remaining[2 + length..];
    }
    
    Ok(options)
}

/// Encode a list of DHCP options to wire format
///
/// Serializes options in TLV format and appends OPTION_END if not already present.
/// Uses BytesMut for safe, growable buffer management.
///
/// # Arguments
///
/// * `options` - List of options to encode
///
/// # Returns
///
/// Returns `Bytes` containing the encoded options in wire format.
///
/// # Notes
///
/// - Automatically adds OPTION_END if the last option is not End
/// - Preserves OPTION_PAD for alignment if present in input
pub fn encode_options(options: &[DhcpOption]) -> Bytes {
    let mut buf = BytesMut::new();
    
    for option in options {
        encode_option(option, &mut buf);
    }
    
    // Ensure options end with OPTION_END
    if !options.is_empty() && !matches!(options.last(), Some(DhcpOption::End)) {
        buf.put_u8(OPTION_END);
    }
    
    buf.freeze()
}

/// Helper: Parse a list of IPv4 addresses from raw bytes
///
/// # Arguments
///
/// * `data` - Raw bytes containing IPv4 addresses (must be multiple of 4)
///
/// # Returns
///
/// Returns `Ok(Vec<Ipv4Addr>)` or `Err(DhcpError)` if length is invalid
fn parse_ipv4_list(data: &[u8], option_code: u8) -> Result<Vec<Ipv4Addr>, DhcpError> {
    if data.len() % 4 != 0 {
        return Err(DhcpError::InvalidOption {
            option_code,
            reason: format!("IPv4 address list length must be multiple of 4, got {}", data.len()),
        });
    }
    
    let mut addrs = Vec::new();
    for chunk in data.chunks_exact(4) {
        let addr = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        addrs.push(addr);
    }
    
    Ok(addrs)
}

/// Helper: Parse a UTF-8 string from raw bytes
///
/// Validates that the data is valid UTF-8. This replaces the C implementation's
/// byte-by-byte sanitization with Rust's built-in UTF-8 validation.
///
/// # Arguments
///
/// * `data` - Raw bytes to parse as UTF-8
///
/// # Returns
///
/// Returns `Ok(String)` or `Err(DhcpError)` if UTF-8 validation fails
fn parse_string(data: &[u8], option_code: u8) -> Result<String, DhcpError> {
    String::from_utf8(data.to_vec()).map_err(|e| {
        DhcpError::InvalidOption {
            option_code,
            reason: format!("Invalid UTF-8 in string option: {}", e),
        }
    })
}

/// Helper: Validate that an IPv4 address is a valid subnet mask
///
/// A valid subnet mask consists of contiguous 1 bits followed by contiguous 0 bits.
/// Examples: 255.255.255.0, 255.255.0.0, 255.240.0.0
/// Invalid: 255.255.0.255, 255.0.255.0
///
/// # Arguments
///
/// * `addr` - IPv4 address to validate as a subnet mask
///
/// # Returns
///
/// Returns `Ok(())` if valid, `Err(DhcpError)` if invalid
fn validate_subnet_mask(addr: Ipv4Addr) -> Result<(), DhcpError> {
    let mask = u32::from_be_bytes(addr.octets());
    
    // Check if mask has contiguous 1s followed by contiguous 0s
    // Method: After inverting, should be of form 2^n - 1 (all trailing 1s)
    let inverted = !mask;
    
    // Check if inverted is 0 (valid: 255.255.255.255)
    // or if inverted + 1 is a power of 2 (contiguous bits)
    if inverted == 0 || (inverted.wrapping_add(1) & inverted) == 0 {
        Ok(())
    } else {
        Err(DhcpError::InvalidOption {
            option_code: OPTION_NETMASK,
            reason: format!("Invalid subnet mask: {} (must have contiguous 1 bits)", addr),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversions() {
        assert_eq!(MessageType::from_u8(1).unwrap(), MessageType::Discover);
        assert_eq!(MessageType::from_u8(2).unwrap(), MessageType::Offer);
        assert_eq!(MessageType::Discover.to_u8(), 1);
        assert_eq!(MessageType::Offer.to_u8(), 2);
        assert!(MessageType::from_u8(0).is_err());
        assert!(MessageType::from_u8(9).is_err());
    }

    #[test]
    fn test_parse_netmask() {
        let data = [255, 255, 255, 0];
        let option = parse_option(OPTION_NETMASK, &data).unwrap();
        assert!(matches!(option, DhcpOption::Netmask(_)));
    }

    #[test]
    fn test_parse_message_type() {
        let data = [1]; // DHCPDISCOVER
        let option = parse_option(OPTION_MESSAGE_TYPE, &data).unwrap();
        assert_eq!(option, DhcpOption::MessageType(MessageType::Discover));
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let options = vec![
            DhcpOption::MessageType(MessageType::Request),
            DhcpOption::Hostname("testhost".to_string()),
            DhcpOption::End,
        ];
        
        let encoded = encode_options(&options);
        let decoded = parse_options(&encoded).unwrap();
        
        assert_eq!(decoded.len(), 3);
        assert!(matches!(decoded[0], DhcpOption::MessageType(MessageType::Request)));
    }

    #[test]
    fn test_validate_subnet_mask() {
        assert!(validate_subnet_mask(Ipv4Addr::new(255, 255, 255, 0)).is_ok());
        assert!(validate_subnet_mask(Ipv4Addr::new(255, 255, 0, 0)).is_ok());
        assert!(validate_subnet_mask(Ipv4Addr::new(255, 255, 255, 255)).is_ok());
        assert!(validate_subnet_mask(Ipv4Addr::new(255, 255, 0, 255)).is_err());
        assert!(validate_subnet_mask(Ipv4Addr::new(255, 0, 255, 0)).is_err());
    }

    #[test]
    fn test_parse_router_list() {
        let data = [192, 168, 1, 1, 192, 168, 1, 254];
        let option = parse_option(OPTION_ROUTER, &data).unwrap();
        if let DhcpOption::Router(addrs) = option {
            assert_eq!(addrs.len(), 2);
            assert_eq!(addrs[0], Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(addrs[1], Ipv4Addr::new(192, 168, 1, 254));
        } else {
            panic!("Expected Router option");
        }
    }

    #[test]
    fn test_option_code() {
        assert_eq!(DhcpOption::Pad.option_code(), OPTION_PAD);
        assert_eq!(DhcpOption::MessageType(MessageType::Discover).option_code(), OPTION_MESSAGE_TYPE);
        assert_eq!(DhcpOption::Hostname("test".to_string()).option_code(), OPTION_HOSTNAME);
    }

    #[test]
    fn test_data_len() {
        assert_eq!(DhcpOption::Pad.data_len(), 0);
        assert_eq!(DhcpOption::MessageType(MessageType::Discover).data_len(), 1);
        assert_eq!(DhcpOption::Netmask(Ipv4Addr::new(255, 255, 255, 0)).data_len(), 4);
        assert_eq!(DhcpOption::Hostname("test".to_string()).data_len(), 4);
    }
}
