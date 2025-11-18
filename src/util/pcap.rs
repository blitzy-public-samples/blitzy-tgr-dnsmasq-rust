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

//! Packet capture module implementing libpcap file format writing for debugging and troubleshooting.
//!
//! This module provides packet capture functionality for DNS, DHCP, DHCPv6, Router Advertisement,
//! and TFTP protocols. It writes packets in standard libpcap format compatible with Wireshark,
//! tcpdump, and other packet analysis tools.
//!
//! # Features
//!
//! - **Libpcap Format**: Standard pcap file format with DLT_RAW (raw IP packets)
//! - **UDP Capture**: DNS queries/responses (port 53), DHCP (ports 67/68, 547/546), TFTP
//! - **ICMPv6 Capture**: Router Advertisement and other ICMPv6 packets
//! - **Dual Stack**: Full IPv4 and IPv6 support with proper header construction
//! - **Checksum Calculation**: Automatic IPv4, UDP, and ICMPv6 checksum computation
//! - **Packet Filtering**: Selective capture via DumpMask flags
//! - **FIFO Support**: Real-time streaming to Wireshark via named pipes
//! - **Async I/O**: Non-blocking file operations using tokio::fs
//!
//! # Usage
//!
//! ```rust,ignore
//! use dnsmasq::util::pcap::{PcapWriter, DumpMask};
//! use std::path::Path;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize pcap file
//! let mut writer = PcapWriter::new(Path::new("/tmp/dnsmasq.pcap"), 4096).await?;
//!
//! // Capture DNS query packet
//! let dns_packet = vec![/* DNS packet data */];
//! let src_addr = "192.168.1.100:12345".parse()?;
//! let dst_addr = "192.168.1.1:53".parse()?;
//! writer.write_packet_udp(
//!     DumpMask::QUERY,
//!     &dns_packet,
//!     &src_addr,
//!     &dst_addr
//! ).await?;
//!
//! // Capture Router Advertisement
//! let ra_packet = vec![/* ICMPv6 RA data */];
//! writer.write_packet_icmp(
//!     DumpMask::RA,
//!     &ra_packet,
//!     &src_addr,
//!     &dst_addr
//! ).await?;
//!
//! writer.close().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Pcap File Format
//!
//! The implementation follows the libpcap file format specification:
//! <https://wiki.wireshark.org/Development/LibpcapFileFormat>
//!
//! File structure:
//! - Global header (24 bytes): Magic number, version, snaplen, data link type
//! - Packet records: Record header (16 bytes) + IP header + Protocol header + Payload
//!
//! # Memory Safety
//!
//! Replaces C manual buffer management and pointer arithmetic with:
//! - Safe byte buffer operations using `std::io::Cursor`
//! - Bounds-checked array access
//! - Automatic memory management via RAII
//! - Type-safe checksum calculation

use std::io::{self, Cursor, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::SystemTime;

use bitflags::bitflags;
use byteorder::{LittleEndian, NetworkEndian, WriteBytesExt};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};

use crate::constants::EDNS_PKTSZ;
use crate::error::PlatformError;
use crate::types::IpAddr as DnsmasqIpAddr;

/// Pcap magic number for native byte order libpcap files
const PCAP_MAGIC: u32 = 0xa1b2_c3d4;

/// Pcap file format version (major)
const PCAP_VERSION_MAJOR: u16 = 2;

/// Pcap file format version (minor)
const PCAP_VERSION_MINOR: u16 = 4;

/// Data link type: DLT_RAW (101) - raw IP packets without link layer
const DLT_RAW: u32 = 101;

/// IP protocol number for UDP
const IPPROTO_UDP: u8 = 17;

/// IP protocol number for ICMPv6
const IPPROTO_ICMPV6: u8 = 58;

/// IP protocol number for ICMP
const IPPROTO_ICMP: u8 = 1;

/// Default IP TTL value
const IP_DEFAULT_TTL: u8 = 64;

/// IPv4 version field value
const IPV4_VERSION: u8 = 4;

/// IPv6 version field value
const IPV6_VERSION: u8 = 6;

bitflags! {
    /// Packet dump filtering flags controlling which packet types to capture.
    ///
    /// These flags match the C implementation's DUMP_* constants from dnsmasq.h.
    /// Multiple flags can be combined to capture different packet types simultaneously.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::util::pcap::DumpMask;
    ///
    /// // Capture only DNS queries and replies from clients
    /// let mask = DumpMask::QUERY | DumpMask::REPLY;
    ///
    /// // Capture all DNS traffic including upstream
    /// let all_dns = DumpMask::QUERY | DumpMask::REPLY |
    ///               DumpMask::UP_QUERY | DumpMask::UP_REPLY;
    ///
    /// // Capture DHCP and DHCPv6 traffic
    /// let dhcp = DumpMask::DHCP | DumpMask::DHCPV6;
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DumpMask: u16 {
        /// DNS queries from clients to dnsmasq (0x0001)
        const QUERY = 0x0001;
        /// DNS replies from dnsmasq to clients (0x0002)
        const REPLY = 0x0002;
        /// DNS queries from dnsmasq to upstream servers (0x0004)
        const UP_QUERY = 0x0004;
        /// DNS replies from upstream servers to dnsmasq (0x0008)
        const UP_REPLY = 0x0008;
        /// DNSSEC validation queries (0x0010)
        const SEC_QUERY = 0x0010;
        /// DNSSEC validation replies (0x0020)
        const SEC_REPLY = 0x0020;
        /// DNS responses marked as bogus (0x0040)
        const BOGUS = 0x0040;
        /// DNSSEC bogus responses (0x0080)
        const SEC_BOGUS = 0x0080;
        /// DHCPv4 transactions (DISCOVER/OFFER/REQUEST/ACK) (0x1000)
        const DHCP = 0x1000;
        /// DHCPv6 messages (SOLICIT/ADVERTISE/REQUEST/REPLY) (0x2000)
        const DHCPV6 = 0x2000;
        /// IPv6 Router Advertisement packets (0x4000)
        const RA = 0x4000;
        /// TFTP file transfers (0x8000)
        const TFTP = 0x8000;
    }
}

/// Libpcap global file header (24 bytes).
///
/// Written once at the beginning of every pcap file to describe the file format
/// and packet structure. Conforms to libpcap specification.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct PcapGlobalHeader {
    /// Magic number (0xa1b2c3d4 for native byte order)
    magic_number: u32,
    /// Major version (2)
    version_major: u16,
    /// Minor version (4)
    version_minor: u16,
    /// GMT to local timezone correction (0 for UTC)
    thiszone: u32,
    /// Timestamp accuracy (0, unused)
    sigfigs: u32,
    /// Max packet capture length
    snaplen: u32,
    /// Data link type (101 = DLT_RAW)
    network: u32,
}

impl PcapGlobalHeader {
    /// Create new pcap global header with specified snapshot length.
    ///
    /// # Arguments
    /// * `snaplen` - Maximum bytes captured per packet (typically EDNS_PKTSZ + 200)
    fn new(snaplen: u32) -> Self {
        Self {
            magic_number: PCAP_MAGIC,
            version_major: PCAP_VERSION_MAJOR,
            version_minor: PCAP_VERSION_MINOR,
            thiszone: 0,
            sigfigs: 0,
            snaplen,
            network: DLT_RAW,
        }
    }

    /// Serialize header to bytes for file writing.
    fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(24);
        buf.write_u32::<LittleEndian>(self.magic_number)?;
        buf.write_u16::<LittleEndian>(self.version_major)?;
        buf.write_u16::<LittleEndian>(self.version_minor)?;
        buf.write_u32::<LittleEndian>(self.thiszone)?;
        buf.write_u32::<LittleEndian>(self.sigfigs)?;
        buf.write_u32::<LittleEndian>(self.snaplen)?;
        buf.write_u32::<LittleEndian>(self.network)?;
        Ok(buf)
    }
}

/// Libpcap packet record header (16 bytes).
///
/// Precedes each captured packet in the pcap file, providing timestamp
/// and length metadata.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct PcapRecordHeader {
    /// Timestamp seconds since Unix epoch
    ts_sec: u32,
    /// Timestamp microseconds component
    ts_usec: u32,
    /// Number of bytes saved in file
    incl_len: u32,
    /// Original packet length
    orig_len: u32,
}

impl PcapRecordHeader {
    /// Create new packet record header with current timestamp.
    fn new(packet_len: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();

        Self {
            ts_sec: now.as_secs() as u32,
            ts_usec: now.subsec_micros(),
            incl_len: packet_len,
            orig_len: packet_len,
        }
    }

    /// Serialize header to bytes for file writing.
    fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(16);
        buf.write_u32::<LittleEndian>(self.ts_sec)?;
        buf.write_u32::<LittleEndian>(self.ts_usec)?;
        buf.write_u32::<LittleEndian>(self.incl_len)?;
        buf.write_u32::<LittleEndian>(self.orig_len)?;
        Ok(buf)
    }
}

/// IPv4 header structure (20 bytes minimum).
#[derive(Debug, Clone)]
struct Ipv4Header {
    version_ihl: u8,      // Version (4 bits) + IHL (4 bits)
    tos: u8,              // Type of service
    total_length: u16,    // Total packet length
    identification: u16,  // Identification
    flags_fragment: u16,  // Flags (3 bits) + Fragment offset (13 bits)
    ttl: u8,              // Time to live
    protocol: u8,         // Protocol (UDP, ICMP, etc.)
    checksum: u16,        // Header checksum
    src_addr: Ipv4Addr,   // Source address
    dst_addr: Ipv4Addr,   // Destination address
}

impl Ipv4Header {
    /// Create new IPv4 header.
    fn new(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload_len: u16) -> Self {
        let total_length = 20 + payload_len;

        Self {
            version_ihl: (IPV4_VERSION << 4) | 5, // Version 4, IHL = 5 (20 bytes)
            tos: 0,
            total_length,
            identification: 0,
            flags_fragment: 0,
            ttl: IP_DEFAULT_TTL,
            protocol,
            checksum: 0, // Calculated later
            src_addr: src,
            dst_addr: dst,
        }
    }

    /// Calculate and set IPv4 header checksum.
    fn calculate_checksum(&mut self) {
        self.checksum = 0;

        let mut sum: u32 = 0;

        // Add all 16-bit words in header
        sum += u32::from(self.version_ihl) << 8;
        sum += u32::from(self.tos);
        sum += u32::from(self.total_length);
        sum += u32::from(self.identification);
        sum += u32::from(self.flags_fragment);
        sum += u32::from(self.ttl) << 8;
        sum += u32::from(self.protocol);
        // checksum field is zero
        
        let src_octets = self.src_addr.octets();
        sum += u32::from(u16::from_be_bytes([src_octets[0], src_octets[1]]));
        sum += u32::from(u16::from_be_bytes([src_octets[2], src_octets[3]]));
        
        let dst_octets = self.dst_addr.octets();
        sum += u32::from(u16::from_be_bytes([dst_octets[0], dst_octets[1]]));
        sum += u32::from(u16::from_be_bytes([dst_octets[2], dst_octets[3]]));

        // Fold 32-bit sum to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        // One's complement
        self.checksum = if sum == 0xffff {
            sum as u16
        } else {
            !sum as u16
        };
    }

    /// Serialize header to bytes.
    fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(20);
        buf.write_u8(self.version_ihl)?;
        buf.write_u8(self.tos)?;
        buf.write_u16::<NetworkEndian>(self.total_length)?;
        buf.write_u16::<NetworkEndian>(self.identification)?;
        buf.write_u16::<NetworkEndian>(self.flags_fragment)?;
        buf.write_u8(self.ttl)?;
        buf.write_u8(self.protocol)?;
        buf.write_u16::<NetworkEndian>(self.checksum)?;
        buf.write_all(&self.src_addr.octets())?;
        buf.write_all(&self.dst_addr.octets())?;
        Ok(buf)
    }
}

/// IPv6 header structure (40 bytes).
#[derive(Debug, Clone)]
struct Ipv6Header {
    version_class_flow: u32, // Version (4) + Traffic class (8) + Flow label (20)
    payload_length: u16,     // Payload length
    next_header: u8,         // Next header (protocol)
    hop_limit: u8,           // Hop limit
    src_addr: Ipv6Addr,      // Source address
    dst_addr: Ipv6Addr,      // Destination address
}

impl Ipv6Header {
    /// Create new IPv6 header.
    fn new(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload_len: u16) -> Self {
        Self {
            version_class_flow: (u32::from(IPV6_VERSION) << 28), // Version 6, rest zeros
            payload_length: payload_len,
            next_header,
            hop_limit: IP_DEFAULT_TTL,
            src_addr: src,
            dst_addr: dst,
        }
    }

    /// Serialize header to bytes.
    fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(40);
        buf.write_u32::<NetworkEndian>(self.version_class_flow)?;
        buf.write_u16::<NetworkEndian>(self.payload_length)?;
        buf.write_u8(self.next_header)?;
        buf.write_u8(self.hop_limit)?;
        buf.write_all(&self.src_addr.octets())?;
        buf.write_all(&self.dst_addr.octets())?;
        Ok(buf)
    }
}

/// UDP header structure (8 bytes).
#[derive(Debug, Clone)]
struct UdpHeader {
    src_port: u16,   // Source port
    dst_port: u16,   // Destination port
    length: u16,     // Length (header + data)
    checksum: u16,   // Checksum
}

impl UdpHeader {
    /// Create new UDP header.
    fn new(src_port: u16, dst_port: u16, data_len: u16) -> Self {
        Self {
            src_port,
            dst_port,
            length: 8 + data_len,
            checksum: 0, // Calculated later
        }
    }

    /// Serialize header to bytes.
    fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(8);
        buf.write_u16::<NetworkEndian>(self.src_port)?;
        buf.write_u16::<NetworkEndian>(self.dst_port)?;
        buf.write_u16::<NetworkEndian>(self.length)?;
        buf.write_u16::<NetworkEndian>(self.checksum)?;
        Ok(buf)
    }
}

/// Pcap file writer for capturing packets in libpcap format.
///
/// Provides async packet capture with automatic header construction,
/// checksum calculation, and support for both regular files and named pipes.
pub struct PcapWriter {
    /// Async file handle
    file: File,
    /// Packet counter for statistics
    packet_count: AtomicU32,
    /// Maximum snapshot length
    snaplen: u32,
    /// Whether file is a FIFO
    is_fifo: bool,
}

impl PcapWriter {
    /// Create new pcap writer and initialize file with global header.
    ///
    /// Opens or creates the specified file and writes the pcap global header.
    /// Supports regular files and named pipes (FIFOs) for real-time streaming.
    ///
    /// # Arguments
    /// * `path` - Path to pcap file or FIFO
    /// * `snaplen` - Maximum bytes captured per packet (typically EDNS_PKTSZ + 200)
    ///
    /// # Errors
    /// Returns error if file cannot be created or header write fails.
    pub async fn new(path: &Path, snaplen: usize) -> io::Result<Self> {
        let snaplen = snaplen as u32;

        // Check if path is FIFO using nix
        let is_fifo = if let Ok(metadata) = tokio::fs::metadata(path).await {
            // Use std::os::unix::fs::FileTypeExt to check for FIFO
            use std::os::unix::fs::FileTypeExt;
            metadata.file_type().is_fifo()
        } else {
            false
        };

        // Open file with appropriate flags
        let mut file = if is_fifo {
            // For FIFO, open with append and read-write
            tokio::fs::OpenOptions::new()
                .append(true)
                .read(true)
                .write(true)
                .open(path)
                .await?
        } else {
            // For regular file, create or open
            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .write(true)
                .open(path)
                .await?
        };

        // Write global header
        let header = PcapGlobalHeader::new(snaplen);
        let header_bytes = header.to_bytes()?;
        file.write_all(&header_bytes).await?;
        file.flush().await?;

        info!("Initialized pcap file: {} (FIFO: {})", path.display(), is_fifo);

        Ok(Self {
            file,
            packet_count: AtomicU32::new(0),
            snaplen,
            is_fifo,
        })
    }

    /// Write UDP packet to pcap file.
    ///
    /// Constructs complete IP and UDP headers, calculates checksums, and writes
    /// the packet with pcap record header. Supports both IPv4 and IPv6.
    ///
    /// # Arguments
    /// * `mask` - Dump mask for packet filtering and logging
    /// * `packet` - Packet payload data (without IP/UDP headers)
    /// * `src` - Source socket address (IP + port)
    /// * `dst` - Destination socket address (IP + port)
    ///
    /// # Errors
    /// Returns error if packet construction or file write fails.
    pub async fn write_packet_udp(
        &mut self,
        mask: DumpMask,
        packet: &[u8],
        src: &SocketAddr,
        dst: &SocketAddr,
    ) -> io::Result<()> {
        let packet_num = self.packet_count.fetch_add(1, Ordering::SeqCst) + 1;

        match (src.ip(), dst.ip()) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                self.write_udp_v4(packet, src_ip, src.port(), dst_ip, dst.port())
                    .await?;
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                self.write_udp_v6(packet, src_ip, src.port(), dst_ip, dst.port())
                    .await?;
            }
            _ => {
                error!("Mismatched IP address families in packet dump");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Mismatched IP families",
                ));
            }
        }

        debug!("Dumped packet {} mask 0x{:04x}", packet_num, mask.bits());
        Ok(())
    }

    /// Write ICMPv6 packet to pcap file.
    ///
    /// Constructs IPv6 header with ICMPv6 payload, calculates checksum, and writes
    /// the packet with pcap record header.
    ///
    /// # Arguments
    /// * `mask` - Dump mask for packet filtering and logging
    /// * `packet` - ICMPv6 packet data including ICMP header
    /// * `src` - Source socket address (IPv6 only)
    /// * `dst` - Destination socket address (IPv6 only)
    ///
    /// # Errors
    /// Returns error if packet construction or file write fails, or if addresses are not IPv6.
    pub async fn write_packet_icmp(
        &mut self,
        mask: DumpMask,
        packet: &[u8],
        src: &SocketAddr,
        dst: &SocketAddr,
    ) -> io::Result<()> {
        let packet_num = self.packet_count.fetch_add(1, Ordering::SeqCst) + 1;

        match (src.ip(), dst.ip()) {
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                self.write_icmpv6(packet, src_ip, dst_ip).await?;
            }
            _ => {
                error!("ICMPv6 dump requires IPv6 addresses");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ICMPv6 requires IPv6 addresses",
                ));
            }
        }

        debug!("Dumped ICMPv6 packet {} mask 0x{:04x}", packet_num, mask.bits());
        Ok(())
    }

    /// Get current packet count.
    pub fn packet_count(&self) -> u32 {
        self.packet_count.load(Ordering::SeqCst)
    }

    /// Close the pcap file, flushing any buffered data.
    pub async fn close(mut self) -> io::Result<()> {
        self.file.flush().await?;
        self.file.sync_all().await?;
        info!("Closed pcap file after {} packets", self.packet_count());
        Ok(())
    }

    /// Write UDP packet with IPv4 addresses.
    async fn write_udp_v4(
        &mut self,
        payload: &[u8],
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> io::Result<()> {
        let payload_len = payload.len() as u16;
        
        // Create UDP header
        let mut udp = UdpHeader::new(src_port, dst_port, payload_len);
        
        // Create IPv4 header
        let mut ip = Ipv4Header::new(src_ip, dst_ip, IPPROTO_UDP, 8 + payload_len);
        ip.calculate_checksum();
        
        // Calculate UDP checksum with IPv4 pseudo-header
        udp.checksum = self.calculate_udp_checksum_v4(&ip, &udp, payload);
        
        // Build complete packet
        let ip_bytes = ip.to_bytes()?;
        let udp_bytes = udp.to_bytes()?;
        
        let total_len = (ip_bytes.len() + udp_bytes.len() + payload.len()) as u32;
        let record_header = PcapRecordHeader::new(total_len);
        
        // Write to file
        self.file.write_all(&record_header.to_bytes()?).await?;
        self.file.write_all(&ip_bytes).await?;
        self.file.write_all(&udp_bytes).await?;
        self.file.write_all(payload).await?;
        self.file.flush().await?;
        
        Ok(())
    }

    /// Write UDP packet with IPv6 addresses.
    async fn write_udp_v6(
        &mut self,
        payload: &[u8],
        src_ip: Ipv6Addr,
        src_port: u16,
        dst_ip: Ipv6Addr,
        dst_port: u16,
    ) -> io::Result<()> {
        let payload_len = payload.len() as u16;
        
        // Create UDP header
        let mut udp = UdpHeader::new(src_port, dst_port, payload_len);
        
        // Create IPv6 header
        let ip = Ipv6Header::new(src_ip, dst_ip, IPPROTO_UDP, 8 + payload_len);
        
        // Calculate UDP checksum with IPv6 pseudo-header
        udp.checksum = self.calculate_udp_checksum_v6(&ip, &udp, payload);
        
        // Build complete packet
        let ip_bytes = ip.to_bytes()?;
        let udp_bytes = udp.to_bytes()?;
        
        let total_len = (ip_bytes.len() + udp_bytes.len() + payload.len()) as u32;
        let record_header = PcapRecordHeader::new(total_len);
        
        // Write to file
        self.file.write_all(&record_header.to_bytes()?).await?;
        self.file.write_all(&ip_bytes).await?;
        self.file.write_all(&udp_bytes).await?;
        self.file.write_all(payload).await?;
        self.file.flush().await?;
        
        Ok(())
    }

    /// Write ICMPv6 packet.
    async fn write_icmpv6(
        &mut self,
        packet: &[u8],
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
    ) -> io::Result<()> {
        let packet_len = packet.len() as u16;
        
        // Create IPv6 header
        let ip = Ipv6Header::new(src_ip, dst_ip, IPPROTO_ICMPV6, packet_len);
        
        // Calculate ICMPv6 checksum
        let mut packet_with_checksum = packet.to_vec();
        let checksum = self.calculate_icmpv6_checksum(&ip, &packet_with_checksum);
        
        // Set checksum in packet (bytes 2-3)
        if packet_with_checksum.len() >= 4 {
            packet_with_checksum[2] = (checksum >> 8) as u8;
            packet_with_checksum[3] = (checksum & 0xff) as u8;
        }
        
        // Build complete packet
        let ip_bytes = ip.to_bytes()?;
        
        let total_len = (ip_bytes.len() + packet_with_checksum.len()) as u32;
        let record_header = PcapRecordHeader::new(total_len);
        
        // Write to file
        self.file.write_all(&record_header.to_bytes()?).await?;
        self.file.write_all(&ip_bytes).await?;
        self.file.write_all(&packet_with_checksum).await?;
        self.file.flush().await?;
        
        Ok(())
    }

    /// Calculate UDP checksum with IPv4 pseudo-header.
    fn calculate_udp_checksum_v4(
        &self,
        ip: &Ipv4Header,
        udp: &UdpHeader,
        payload: &[u8],
    ) -> u16 {
        let mut sum: u32 = 0;
        
        // IPv4 pseudo-header
        let src_octets = ip.src_addr.octets();
        sum += u32::from(u16::from_be_bytes([src_octets[0], src_octets[1]]));
        sum += u32::from(u16::from_be_bytes([src_octets[2], src_octets[3]]));
        
        let dst_octets = ip.dst_addr.octets();
        sum += u32::from(u16::from_be_bytes([dst_octets[0], dst_octets[1]]));
        sum += u32::from(u16::from_be_bytes([dst_octets[2], dst_octets[3]]));
        
        sum += u32::from(IPPROTO_UDP);
        sum += u32::from(udp.length);
        
        // UDP header
        sum += u32::from(udp.src_port);
        sum += u32::from(udp.dst_port);
        sum += u32::from(udp.length);
        // checksum field is zero
        
        // Payload
        for chunk in payload.chunks(2) {
            if chunk.len() == 2 {
                sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            } else {
                sum += u32::from(chunk[0]) << 8;
            }
        }
        
        // Fold to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        
        if sum == 0xffff {
            sum as u16
        } else {
            !sum as u16
        }
    }

    /// Calculate UDP checksum with IPv6 pseudo-header.
    fn calculate_udp_checksum_v6(
        &self,
        ip: &Ipv6Header,
        udp: &UdpHeader,
        payload: &[u8],
    ) -> u16 {
        let mut sum: u32 = 0;
        
        // IPv6 pseudo-header - source address
        let src_octets = ip.src_addr.octets();
        for chunk in src_octets.chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        
        // IPv6 pseudo-header - destination address
        let dst_octets = ip.dst_addr.octets();
        for chunk in dst_octets.chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        
        // IPv6 pseudo-header - length and next header
        sum += u32::from(udp.length);
        sum += u32::from(IPPROTO_UDP);
        
        // UDP header
        sum += u32::from(udp.src_port);
        sum += u32::from(udp.dst_port);
        sum += u32::from(udp.length);
        // checksum field is zero
        
        // Payload
        for chunk in payload.chunks(2) {
            if chunk.len() == 2 {
                sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            } else {
                sum += u32::from(chunk[0]) << 8;
            }
        }
        
        // Fold to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        
        if sum == 0xffff {
            sum as u16
        } else {
            !sum as u16
        }
    }

    /// Calculate ICMPv6 checksum with IPv6 pseudo-header.
    fn calculate_icmpv6_checksum(&self, ip: &Ipv6Header, packet: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        
        // IPv6 pseudo-header - source address
        let src_octets = ip.src_addr.octets();
        for chunk in src_octets.chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        
        // IPv6 pseudo-header - destination address
        let dst_octets = ip.dst_addr.octets();
        for chunk in dst_octets.chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        
        // IPv6 pseudo-header - length and next header
        sum += u32::from(packet.len() as u16);
        sum += u32::from(IPPROTO_ICMPV6);
        
        // ICMPv6 packet (with checksum field zeroed)
        for (i, chunk) in packet.chunks(2).enumerate() {
            // Skip checksum field (bytes 2-3)
            if i == 1 {
                continue;
            }
            
            if chunk.len() == 2 {
                sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            } else {
                sum += u32::from(chunk[0]) << 8;
            }
        }
        
        // Fold to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        
        if sum == 0xffff {
            sum as u16
        } else {
            !sum as u16
        }
    }
}

/// Initialize packet capture dump file (wrapper function for C API compatibility).
///
/// Creates a pcap file at the specified path with the given snapshot length.
/// This function exists for compatibility with code expecting C-style initialization.
///
/// # Arguments
/// * `path` - Path to pcap file or FIFO
/// * `snaplen` - Maximum bytes per packet (typically EDNS_PKTSZ + 200)
///
/// # Returns
/// A new `PcapWriter` instance or error if initialization fails.
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::util::pcap::dump_init;
/// use std::path::Path;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let writer = dump_init(Path::new("/var/log/dnsmasq.pcap"), 4296).await?;
/// # Ok(())
/// # }
/// ```
pub async fn dump_init(path: &Path, snaplen: usize) -> io::Result<PcapWriter> {
    PcapWriter::new(path, snaplen).await
}

/// Dump UDP packet to capture file (wrapper function for C API compatibility).
///
/// Captures a UDP packet with specified source and destination addresses.
/// This function exists for compatibility with code expecting C-style packet dumping.
///
/// # Arguments
/// * `writer` - Mutable reference to PcapWriter
/// * `mask` - Packet type filter mask
/// * `packet` - Packet payload data
/// * `src` - Source socket address
/// * `dst` - Destination socket address
pub async fn dump_packet_udp(
    writer: &mut PcapWriter,
    mask: DumpMask,
    packet: &[u8],
    src: &SocketAddr,
    dst: &SocketAddr,
) -> io::Result<()> {
    writer.write_packet_udp(mask, packet, src, dst).await
}

/// Dump ICMPv6 packet to capture file (wrapper function for C API compatibility).
///
/// Captures an ICMPv6 packet with specified source and destination IPv6 addresses.
/// This function exists for compatibility with code expecting C-style packet dumping.
///
/// # Arguments
/// * `writer` - Mutable reference to PcapWriter
/// * `mask` - Packet type filter mask
/// * `packet` - ICMPv6 packet data
/// * `src` - Source socket address (IPv6)
/// * `dst` - Destination socket address (IPv6)
pub async fn dump_packet_icmp(
    writer: &mut PcapWriter,
    mask: DumpMask,
    packet: &[u8],
    src: &SocketAddr,
    dst: &SocketAddr,
) -> io::Result<()> {
    writer.write_packet_icmp(mask, packet, src, dst).await
}
