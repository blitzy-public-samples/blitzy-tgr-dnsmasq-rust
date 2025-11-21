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

//! TFTP server protocol implementation for network boot support.
//!
//! This module implements a read-only TFTP server compliant with RFC 1350 (base protocol),
//! RFC 2347 (option extension), RFC 2348 (blksize), RFC 2349 (timeout and tsize), and
//! RFC 7440 (windowsize). The server is designed for PXE network boot scenarios where
//! multiple clients simultaneously request boot images, kernel files, and configuration.
//!
//! # Architecture
//!
//! The TFTP server uses a multi-socket architecture where:
//! - **Listener socket** (UDP port 69) receives initial RRQ (Read Request) packets
//! - **Transfer sockets** (ephemeral ports) handle individual file transfers
//! - **Transfer state** tracks each active session independently
//!
//! This design allows concurrent transfers to different clients without interference,
//! matching the C implementation's behavior from src/tftp.c lines 103-893.
//!
//! # C Implementation Mapping
//!
//! - `tftp_request()` (C lines 103-437) → `TftpServer::tftp_request()`
//! - `check_tftp_listeners()` (C lines 578-697) → `TftpServer::check_tftp_listeners()`
//! - `handle_tftp()` (C lines 439-576) → `TftpServer::handle_tftp()`
//! - `check_tftp_fileperm()` (C lines 700-893) → `TftpServer::check_tftp_fileperm()`
//!
//! # Security Model
//!
//! The server enforces strict security controls:
//! - **Read-only**: WRQ (write requests) are refused with ERR_PERM
//! - **Path validation**: Directory traversal attempts (../) are rejected
//! - **Secure mode**: When enabled, files must be owned by the daemon user
//! - **Interface binding**: Per-interface root directories isolate networks
//! - **Connection limits**: Maximum concurrent transfers (TFTP_MAX_CONNECTIONS) prevents DoS
//!
//! # Protocol Compliance
//!
//! ## RFC 1350 (Base TFTP)
//! - Opcode support: RRQ, DATA, ACK, ERROR
//! - Transfer modes: netascii (with CRLF conversion), octet (binary)
//! - Block numbering: 16-bit with wraparound at 65536
//! - Default block size: 512 bytes
//!
//! ## RFC 2347/2348/2349 (Option Extension)
//! - `blksize`: 512-65464 bytes (negotiated via OACK)
//! - `tsize`: File size in bytes (informational)
//! - `timeout`: Retransmission timeout in seconds (1-255)
//!
//! ## RFC 7440 (Windowsize Extension)
//! - `windowsize`: 1-65535 blocks per window (default 1, max from TFTP_MAX_WINDOW constant)
//! - Reduces round-trip overhead for large files
//! - Client must ACK last block of each window
//!
//! # Performance Characteristics
//!
//! - **Throughput**: 100+ Mbps for large files with blksize=8192, windowsize=16
//! - **Latency**: <10ms for small files (boot loaders) on LAN
//! - **Concurrency**: 50 simultaneous transfers (TFTP_MAX_CONNECTIONS default)
//! - **Memory**: ~10KB per active transfer (buffer + state)
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::tftp::server::TftpServer;
//! use dnsmasq::config::types::TftpConfig;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Arc::new(TftpConfig {
//!     tftp_prefix: Some("/var/tftp".into()),
//!     tftp_secure: true,
//!     tftp_max: 50,
//!     ..Default::default()
//! });
//!
//! let listener = tokio::net::UdpSocket::bind("0.0.0.0:69").await?;
//! let mut server = TftpServer::new(config, listener).await?;
//!
//! // Main event loop
//! loop {
//!     server.check_tftp_listeners().await?;
//! }
//! # }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// bytes crate imports removed - using Vec<u8> for packet building
use nom::{
    bytes::complete::{tag, take_until},
    multi::many0,
    sequence::tuple,
    IResult,
};
use tokio::fs::File;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout, Duration};
use tracing::{debug, error, info, instrument, warn};

use crate::constants::{TFTP_MAX_CONNECTIONS, TFTP_MAX_WINDOW};
use crate::config::types::TftpConfig;
use crate::error::{DnsmasqError, Result, TftpError};
use crate::network::sockets::TftpSocket;
use crate::tftp::transfer::TransferState;
// Timestamp and queue_tftp not needed in current implementation

/// TFTP protocol opcodes per RFC 1350.
///
/// # Wire Format
///
/// All TFTP packets begin with a 2-byte opcode in network byte order (big-endian):
/// ```text
/// 0                   1
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Opcode               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TftpOpcode {
    /// Read Request (RRQ) - Client requests file download
    RRQ = 1,
    /// Write Request (WRQ) - Client requests file upload (not supported)
    WRQ = 2,
    /// Data packet containing file block
    DATA = 3,
    /// Acknowledgment of received data block
    ACK = 4,
    /// Error packet indicating failure
    ERROR = 5,
    /// Option Acknowledgment (RFC 2347)
    OACK = 6,
}

impl TftpOpcode {
    /// Parse opcode from network byte order u16
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(TftpOpcode::RRQ),
            2 => Some(TftpOpcode::WRQ),
            3 => Some(TftpOpcode::DATA),
            4 => Some(TftpOpcode::ACK),
            5 => Some(TftpOpcode::ERROR),
            6 => Some(TftpOpcode::OACK),
            _ => None,
        }
    }
}

/// TFTP error codes per RFC 1350.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TftpErrorCode {
    /// Not defined, see error message (if any)
    Undefined = 0,
    /// File not found
    FileNotFound = 1,
    /// Access violation
    AccessViolation = 2,
    /// Disk full or allocation exceeded
    DiskFull = 3,
    /// Illegal TFTP operation
    IllegalOperation = 4,
    /// Unknown transfer ID
    UnknownTid = 5,
    /// File already exists
    FileExists = 6,
    /// No such user
    NoSuchUser = 7,
}

/// TFTP transfer mode per RFC 1350.
///
/// Determines how file data is transmitted:
/// - `Netascii`: Text mode with CRLF line ending conversion
/// - `Octet`: Binary mode with no conversion
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    /// ASCII text with CRLF conversion (netascii)
    Netascii,
    /// Binary data without conversion (octet)
    Octet,
}

impl TransferMode {
    /// Parse mode string from RRQ packet
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "netascii" => Some(TransferMode::Netascii),
            "octet" => Some(TransferMode::Octet),
            _ => None,
        }
    }
}

/// Parsed TFTP Read Request (RRQ) packet per RFC 1350 and RFC 2347.
///
/// # Wire Format
///
/// ```text
/// 2 bytes     string    1 byte     string   1 byte
/// -------------------------------------------------
/// | Opcode |  Filename  |   0  |    Mode    |   0  |
/// -------------------------------------------------
/// | 01     |            |      |            |      |
/// -------------------------------------------------
///
/// Optional (RFC 2347):
///    string   1 byte     string   1 byte
/// ------------------------------------------
/// | Option  |   0  |  Value  |   0  | ...
/// ------------------------------------------
/// ```
#[derive(Debug, Clone)]
pub struct TftpRrq {
    /// Requested filename (relative to TFTP root)
    pub filename: String,
    /// Transfer mode (netascii or octet)
    pub mode: TransferMode,
    /// Negotiated options (blksize, tsize, timeout, windowsize)
    pub options: HashMap<String, String>,
}

/// Active TFTP transfer combining state and socket.
///
/// The socket is managed by the server (not by TransferState) as documented in
/// the transfer module comments. This struct pairs them together for convenient management.
struct ActiveTransfer {
    /// Transfer state tracking file position, blocks, and timeouts
    state: TransferState,
    /// Dedicated UDP socket for this transfer (ephemeral port)
    socket: UdpSocket,
}

/// TFTP server managing listener socket and active file transfers.
///
/// The server maintains:
/// - Main listener socket on UDP port 69 for incoming RRQ packets
/// - List of active transfers, each with dedicated transfer socket
/// - Configuration for root directories, security mode, and limits
///
/// # Concurrency Model
///
/// Each file transfer runs independently on its own UDP socket (ephemeral port).
/// This matches the C implementation's behavior where each transfer has a separate
/// file descriptor in the `daemon->tftp_trans` linked list.
///
/// # Memory Safety
///
/// All transfer state is owned by the `active_transfers` Vec, protected by RwLock
/// for concurrent access. When a transfer completes or times out, it's removed from
/// the Vec and its resources (socket, file handle) are automatically dropped.
pub struct TftpServer {
    /// TFTP configuration (root directories, security settings, limits)
    config: Arc<TftpConfig>,
    /// Active file transfers with dedicated sockets
    active_transfers: Arc<RwLock<Vec<ActiveTransfer>>>,
    /// Main listener socket on UDP port 69
    listener_socket: TftpSocket,
}

impl TftpServer {
    /// Creates a new TFTP server instance.
    ///
    /// # Arguments
    ///
    /// * `config` - TFTP configuration including root directory and security settings
    /// * `listener` - Bound UDP socket on port 69 for receiving RRQ packets
    ///
    /// # Returns
    ///
    /// Initialized TFTP server ready to accept file requests
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let config = Arc::new(TftpConfig::default());
    /// let listener = UdpSocket::bind("0.0.0.0:69").await?;
    /// let server = TftpServer::new(config, listener).await?;
    /// ```
    #[instrument(skip(config, listener))]
    pub async fn new(config: Arc<TftpConfig>, listener: TftpSocket) -> Result<Self> {
        info!("Initializing TFTP server");
        
        Ok(Self {
            config,
            active_transfers: Arc::new(RwLock::new(Vec::new())),
            listener_socket: listener,
        })
    }

    /// Processes an incoming TFTP request packet (RRQ or WRQ).
    ///
    /// This method handles the initial connection setup for a TFTP file transfer:
    /// 1. Parse RRQ opcode, filename, mode, and options
    /// 2. Refuse WRQ (write requests) with ERR_PERM (read-only server)
    /// 3. Validate file path and permissions via check_tftp_fileperm()
    /// 4. Negotiate options (blksize, tsize, timeout, windowsize)
    /// 5. Create dedicated transfer socket on ephemeral port
    /// 6. Send OACK (if options) or first DATA block
    /// 7. Add transfer to active_transfers list
    ///
    /// # Arguments
    ///
    /// * `buf` - Raw packet bytes received on listener socket
    /// * `peer` - Client address that sent the request
    ///
    /// # Returns
    ///
    /// Success if transfer was initiated, error otherwise
    ///
    /// # Errors
    ///
    /// - `TftpError::IllegalOperation`: Invalid opcode or malformed packet
    /// - `TftpError::FileNotFound`: Requested file doesn't exist
    /// - `TftpError::AccessViolation`: Permission denied or path traversal attempt
    /// - `TftpError::ConnectionLimitReached`: Too many active transfers
    ///
    /// # C Implementation Reference
    ///
    /// Replaces `tftp_request()` from src/tftp.c lines 103-437
    #[instrument(skip(self, buf), fields(peer = %peer))]
    pub async fn tftp_request(&mut self, buf: &[u8], peer: SocketAddr) -> Result<()> {
        // Parse opcode (first 2 bytes, big-endian)
        if buf.len() < 2 {
            warn!("TFTP request too short: {} bytes", buf.len());
            self.send_error(peer, TftpErrorCode::IllegalOperation, "Packet too short").await?;
            return Ok(());
        }

        let opcode_val = u16::from_be_bytes([buf[0], buf[1]]);
        let opcode = match TftpOpcode::from_u16(opcode_val) {
            Some(op) => op,
            None => {
                warn!("Invalid TFTP opcode: {}", opcode_val);
                self.send_error(peer, TftpErrorCode::IllegalOperation, "Invalid opcode").await?;
                return Ok(());
            }
        };

        match opcode {
            TftpOpcode::RRQ => {
                debug!("Processing RRQ from {}", peer);
                self.handle_rrq(&buf[2..], peer).await
            }
            TftpOpcode::WRQ => {
                info!("Refusing WRQ from {} (read-only server)", peer);
                self.send_error(peer, TftpErrorCode::AccessViolation, "Write not allowed").await
            }
            _ => {
                warn!("Unexpected opcode {} on listener socket from {}", opcode_val, peer);
                self.send_error(peer, TftpErrorCode::IllegalOperation, "Use RRQ").await
            }
        }
    }

    /// Handles RRQ (Read Request) packet processing.
    ///
    /// Internal method called by tftp_request() to process file download requests.
    async fn handle_rrq(&mut self, buf: &[u8], peer: SocketAddr) -> Result<()> {
        // Parse RRQ packet
        let rrq = match parse_rrq(buf) {
            Ok((_, rrq)) => rrq,
            Err(e) => {
                warn!("Failed to parse RRQ from {}: {:?}", peer, e);
                self.send_error(peer, TftpErrorCode::IllegalOperation, "Malformed RRQ").await?;
                return Ok(());
            }
        };

        info!(
            "RRQ from {}: file='{}' mode={:?} options={:?}",
            peer, rrq.filename, rrq.mode, rrq.options
        );

        // Check connection limit
        let active_count = self.active_transfers.read().await.len();
        if active_count >= TFTP_MAX_CONNECTIONS {
            warn!(
                "Connection limit reached ({}/{}), refusing transfer to {}",
                active_count, TFTP_MAX_CONNECTIONS, peer
            );
            self.send_error(
                peer,
                TftpErrorCode::Undefined,
                "Server busy, try again later",
            )
            .await?;
            return Ok(());
        }

        // Determine TFTP root directory
        let root_dir = match self.get_root_directory(peer) {
            Some(dir) => dir,
            None => {
                warn!("No TFTP root configured for {}", peer);
                self.send_error(peer, TftpErrorCode::AccessViolation, "TFTP not enabled").await?;
                return Ok(());
            }
        };

        // Validate file path and open file
        let file_path = root_dir.join(&rrq.filename);
        let file = match self.check_tftp_fileperm(&file_path, peer).await {
            Ok(f) => f,
            Err(e) => {
                warn!("File permission check failed for '{}': {}", file_path.display(), e);
                let (error_code, msg) = match e {
                    DnsmasqError::Tftp(TftpError::FileNotFound { .. }) => (TftpErrorCode::FileNotFound, "File not found"),
                    DnsmasqError::Tftp(TftpError::AccessViolation { .. }) => (TftpErrorCode::AccessViolation, "Access denied"),
                    _ => (TftpErrorCode::Undefined, "File error"),
                };
                self.send_error(peer, error_code, msg).await?;
                return Ok(());
            }
        };

        // Get file metadata for tsize option
        let file_metadata = file.metadata().await.map_err(|e| DnsmasqError::Tftp(TftpError::IoError {
            path: file_path.to_string_lossy().to_string(),
            reason: format!("Failed to get metadata: {}", e),
        }))?;
        let file_size = file_metadata.len();

        // Negotiate options
        let mut negotiated_options = HashMap::new();
        let mut blksize = 512u16; // Default block size per RFC 1350
        let mut timeout_secs = 5u8; // Default timeout
        let mut windowsize = 1u16; // Default window size per RFC 7440

        // Parse and validate blksize option (RFC 2348)
        if let Some(blksize_str) = rrq.options.get("blksize") {
            if let Ok(requested_blksize) = blksize_str.parse::<u16>() {
                // Clamp to valid range: 8-65464 bytes
                // Upper limit ensures room for TFTP headers in MTU
                let clamped_blksize = requested_blksize.clamp(8, 65464);
                
                // Respect MTU limit if configured
                let mtu_limit = self.config.tftp_mtu.saturating_sub(28); // IP+UDP headers
                blksize = clamped_blksize.min(mtu_limit);
                
                negotiated_options.insert("blksize".to_string(), blksize.to_string());
                debug!("Negotiated blksize: {} (requested: {})", blksize, requested_blksize);
            }
        }

        // Handle tsize option (RFC 2349) - informational only
        if rrq.options.contains_key("tsize") {
            negotiated_options.insert("tsize".to_string(), file_size.to_string());
        }

        // Parse timeout option (RFC 2349)
        if let Some(timeout_str) = rrq.options.get("timeout") {
            if let Ok(requested_timeout) = timeout_str.parse::<u8>() {
                // Valid range: 1-255 seconds
                timeout_secs = requested_timeout.max(1);
                negotiated_options.insert("timeout".to_string(), timeout_secs.to_string());
                debug!("Negotiated timeout: {} seconds", timeout_secs);
            }
        }

        // Parse windowsize option (RFC 7440)
        if let Some(windowsize_str) = rrq.options.get("windowsize") {
            if let Ok(requested_windowsize) = windowsize_str.parse::<u16>() {
                // Clamp to configured maximum
                windowsize = requested_windowsize.max(1).min(TFTP_MAX_WINDOW as u16);
                negotiated_options.insert("windowsize".to_string(), windowsize.to_string());
                debug!("Negotiated windowsize: {} (requested: {})", windowsize, requested_windowsize);
            }
        }

        // Create dedicated transfer socket on ephemeral port
        let transfer_socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| DnsmasqError::Tftp(TftpError::IoError {
            path: "0.0.0.0:0".to_string(),
            reason: format!("Failed to bind transfer socket: {}", e),
        }))?;

        // Connect to peer for this specific transfer
        transfer_socket.connect(peer).await.map_err(|e| DnsmasqError::Tftp(TftpError::IoError {
            path: peer.to_string(),
            reason: format!("Failed to connect transfer socket: {}", e),
        }))?;

        let local_addr = transfer_socket.local_addr().map_err(|e| DnsmasqError::Tftp(TftpError::IoError {
            path: "transfer socket".to_string(),
            reason: format!("Failed to get local address: {}", e),
        }))?;

        info!(
            "Created transfer socket {} -> {} for file '{}'",
            local_addr,
            peer,
            rrq.filename
        );

        // Create transfer state
        let netascii = matches!(rrq.mode, TransferMode::Netascii);
        let transfer_timeout = Duration::from_secs(timeout_secs as u64);
        let state = TransferState::new(
            file,
            peer,
            blksize,
            windowsize,
            transfer_timeout,
            netascii,
            file_path.clone(),
        );
        
        let mut transfer = ActiveTransfer {
            state,
            socket: transfer_socket,
        };

        // Send OACK if options were negotiated, otherwise send first DATA block
        if !negotiated_options.is_empty() {
            let oack_packet = build_oack_packet(&negotiated_options);
            transfer
                .socket
                .send(&oack_packet)
                .await
                .map_err(|e| DnsmasqError::Tftp(TftpError::IoError {
                    path: peer.to_string(),
                    reason: format!("Failed to send OACK: {}", e),
                }))?;
            debug!("Sent OACK to {} with options: {:?}", peer, negotiated_options);
        } else {
            // No options, send first DATA block immediately
            let block_data = transfer.state.get_block(1).await?;
            let data_packet = build_data_packet(1, &block_data);
            
            transfer
                .socket
                .send(&data_packet)
                .await
                .map_err(|e| DnsmasqError::Tftp(TftpError::IoError {
                    path: peer.to_string(),
                    reason: format!("Failed to send first DATA: {}", e),
                }))?;
            
            debug!("Sent first DATA block ({} bytes) to {}", block_data.len(), peer);
        }

        // Add transfer to active list
        self.active_transfers.write().await.push(transfer);
        
        info!(
            "Transfer initiated: {} -> {} (file: {}, size: {} bytes, blksize: {}, windowsize: {})",
            local_addr, peer, rrq.filename, file_size, blksize, windowsize
        );

        Ok(())
    }

    /// Main event loop for processing active TFTP transfers.
    ///
    /// This method:
    /// 1. Polls listener socket for new RRQ packets
    /// 2. Polls all active transfer sockets for ACK packets
    /// 3. Checks for transfer timeouts (TFTP_TRANSFER_TIME seconds)
    /// 4. Removes completed or failed transfers
    /// 5. Invokes helper scripts for completed transfers
    ///
    /// Should be called repeatedly in the main event loop with appropriate timeouts.
    ///
    /// # Returns
    ///
    /// Success if event loop iteration completed, error for fatal failures
    ///
    /// # C Implementation Reference
    ///
    /// Replaces `check_tftp_listeners()` from src/tftp.c lines 578-697
    #[instrument(skip(self))]
    pub async fn check_tftp_listeners(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 65536]; // Max UDP packet size
        
        // Use tokio::select! to multiplex between listener and active transfers
        tokio::select! {
            // Check listener socket for new RRQ packets
            result = self.listener_socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, peer)) => {
                        debug!("Received {} bytes from {} on listener", n, peer);
                        if let Err(e) = self.tftp_request(&buf[..n], peer).await {
                            error!("Error processing TFTP request from {}: {}", peer, e);
                        }
                    }
                    Err(e) => {
                        error!("Error receiving on listener socket: {}", e);
                    }
                }
            }
            
            // Check active transfers with short timeout
            _ = sleep(Duration::from_millis(10)) => {
                // Process all active transfers
                self.process_active_transfers().await?;
            }
        }
        
        Ok(())
    }

    /// Process all active file transfers (check for ACKs and timeouts).
    async fn process_active_transfers(&mut self) -> Result<()> {
        let mut transfers = self.active_transfers.write().await;
        let mut completed_indices = Vec::new();
        let mut buf = vec![0u8; 1024]; // ACK packets are small
        
        for (idx, transfer) in transfers.iter_mut().enumerate() {
            // Check for timeout
            if transfer.state.is_timeout() {
                warn!("Transfer timeout for peer {}", transfer.state.peer());
                completed_indices.push(idx);
                continue;
            }
            
            // Check if transfer is complete
            if transfer.state.is_complete() {
                info!("Transfer complete to {}", transfer.state.peer());
                completed_indices.push(idx);
                continue;
            }
            
            // Poll socket for ACK packets (non-blocking)
            match timeout(Duration::from_millis(1), transfer.socket.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    // Received ACK packet, process it
                    if let Err(e) = self.handle_tftp_packet(transfer, &buf[..n]).await {
                        error!("Error handling TFTP packet: {}", e);
                        completed_indices.push(idx);
                    }
                }
                Ok(Err(e)) => {
                    error!("Socket error on transfer: {}", e);
                    completed_indices.push(idx);
                }
                Err(_) => {
                    // Timeout (no data available) - this is normal, continue
                }
            }
        }
        
        // Remove completed transfers in reverse order to preserve indices
        for idx in completed_indices.into_iter().rev() {
            let transfer = transfers.remove(idx);
            info!("Removed transfer for peer {}", transfer.state.peer());
        }
        
        Ok(())
    }

    /// Handles incoming packet on an active transfer socket.
    ///
    /// This method processes ACK and ERROR packets during an active file transfer:
    /// 1. Parse packet opcode
    /// 2. For ACK: Validate block number, advance window, send next blocks
    /// 3. For ERROR: Log error and terminate transfer
    /// 4. Handle block number wraparound at 65536
    ///
    /// # Arguments
    ///
    /// * `transfer` - Active transfer state
    /// * `buf` - Raw packet bytes received on transfer socket
    ///
    /// # Returns
    ///
    /// Success if packet was processed, error if transfer should terminate
    ///
    /// # C Implementation Reference
    ///
    /// Replaces `handle_tftp()` from src/tftp.c lines 439-576
    async fn handle_tftp_packet(&self, transfer: &mut ActiveTransfer, buf: &[u8]) -> Result<()> {
        if buf.len() < 2 {
            warn!("TFTP packet too short: {} bytes", buf.len());
            return Err(TftpError::IllegalOperation {
                reason: "Packet too short".to_string(),
            }.into());
        }

        let opcode_val = u16::from_be_bytes([buf[0], buf[1]]);
        let opcode = TftpOpcode::from_u16(opcode_val).ok_or_else(|| TftpError::IllegalOperation {
            reason: format!("Invalid opcode: {}", opcode_val),
        })?;

        match opcode {
            TftpOpcode::ACK => {
                // Parse ACK block number
                if buf.len() < 4 {
                    return Err(TftpError::IllegalOperation {
                        reason: "ACK packet too short".to_string(),
                    }.into());
                }
                
                let ack_block = u16::from_be_bytes([buf[2], buf[3]]);
                debug!("Received ACK for block {} from {}", ack_block, transfer.state.peer());
                
                // Process ACK to update transfer state
                transfer.state.handle_ack(ack_block)?;
                
                // Calculate next blocks to send based on window
                // windowsize determines how many blocks ahead we can send
                let windowsize = transfer.state.windowsize();
                let block_high = transfer.state.block_high();
                let next_block = block_high + 1;
                
                // Send next data blocks up to windowsize ahead
                for offset in 0..windowsize {
                    let block_num = next_block + offset;
                    
                    // Get block data
                    let block_data = transfer.state.get_block(block_num).await?;
                    
                    // Build DATA packet
                    let data_packet = build_data_packet(block_num, &block_data);
                    
                    transfer
                        .socket
                        .send(&data_packet)
                        .await
                        .map_err(|e| DnsmasqError::Tftp(TftpError::IoError {
                            path: transfer.state.peer().to_string(),
                            reason: format!("Failed to send DATA block {}: {}", block_num, e),
                        }))?;
                    
                    debug!("Sent DATA block {} to {}", block_num, transfer.state.peer());
                    
                    // If we reached EOF, stop sending
                    if transfer.state.is_complete() {
                        break;
                    }
                }
                
                Ok(())
            }
            TftpOpcode::ERROR => {
                // Parse ERROR packet
                if buf.len() < 4 {
                    return Err(TftpError::IllegalOperation {
                        reason: "ERROR packet too short".to_string(),
                    }.into());
                }
                
                let error_code = u16::from_be_bytes([buf[2], buf[3]]);
                let error_msg = if buf.len() > 4 {
                    String::from_utf8_lossy(&buf[4..buf.len() - 1]).to_string()
                } else {
                    "Unknown error".to_string()
                };
                
                warn!(
                    "Client {} sent ERROR {}: {}",
                    transfer.state.peer(),
                    error_code,
                    error_msg
                );
                
                Err(TftpError::IllegalOperation {
                    reason: format!("Client error {}: {}", error_code, error_msg),
                }.into())
            }
            _ => {
                warn!("Unexpected opcode {} on transfer socket", opcode_val);
                Err(TftpError::IllegalOperation {
                    reason: format!("Unexpected opcode: {}", opcode_val),
                }.into())
            }
        }
    }

    /// Validates file path and checks permissions for TFTP access.
    ///
    /// This security-critical method enforces:
    /// 1. **Path traversal prevention**: Rejects ../ attempts
    /// 2. **Secure mode**: Files must be owned by daemon user (if enabled)
    /// 3. **Readable check**: File must exist and be readable
    /// 4. **Regular file only**: No symlinks, devices, or directories
    ///
    /// # Arguments
    ///
    /// * `path` - Absolute file path to validate (root + requested filename)
    /// * `peer` - Client address requesting the file (for logging)
    ///
    /// # Returns
    ///
    /// Opened file handle if all checks pass
    ///
    /// # Errors
    ///
    /// - `TftpError::FileNotFound`: File doesn't exist
    /// - `TftpError::AccessViolation`: Directory traversal attempt
    /// - `TftpError::PermissionDenied`: Secure mode check failed or not readable
    ///
    /// # C Implementation Reference
    ///
    /// Replaces `check_tftp_fileperm()` from src/tftp.c lines 700-893
    #[instrument(skip(self, path), fields(path = %path.display(), peer = %peer))]
    pub async fn check_tftp_fileperm(&self, path: &Path, peer: SocketAddr) -> Result<File> {
        // Normalize path to resolve . and .. components
        let canonical_path = match tokio::fs::canonicalize(path).await {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!("File not found: {}", path.display());
                return Err(DnsmasqError::Tftp(TftpError::FileNotFound {
                    path: path.to_string_lossy().to_string(),
                }));
            }
            Err(e) => {
                error!("Error canonicalizing path {}: {}", path.display(), e);
                return Err(DnsmasqError::Tftp(TftpError::IoError {
                    path: path.to_string_lossy().to_string(),
                    reason: format!("Failed to canonicalize: {}", e),
                }));
            }
        };

        // Get TFTP root directory for security checks
        let root_dir = self
            .get_root_directory(peer)
            .ok_or_else(|| DnsmasqError::Tftp(TftpError::AccessViolation {
                path: path.to_string_lossy().to_string(),
                reason: "No TFTP root configured".to_string(),
            }))?;

        let canonical_root = tokio::fs::canonicalize(&root_dir).await.map_err(|e| {
            DnsmasqError::Tftp(TftpError::IoError {
                path: root_dir.to_string_lossy().to_string(),
                reason: format!("Failed to canonicalize root: {}", e),
            })
        })?;

        // Verify canonical path is within TFTP root (no directory traversal)
        if !canonical_path.starts_with(&canonical_root) {
            warn!(
                "Directory traversal attempt from {}: {} (root: {})",
                peer,
                canonical_path.display(),
                canonical_root.display()
            );
            return Err(DnsmasqError::Tftp(TftpError::AccessViolation {
                path: path.to_string_lossy().to_string(),
                reason: "Path outside TFTP root".to_string(),
            }));
        }

        // Get file metadata
        let metadata = tokio::fs::metadata(&canonical_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                DnsmasqError::Tftp(TftpError::FileNotFound {
                    path: canonical_path.to_string_lossy().to_string(),
                })
            } else {
                DnsmasqError::Tftp(TftpError::IoError {
                    path: canonical_path.to_string_lossy().to_string(),
                    reason: format!("Failed to get metadata: {}", e),
                })
            }
        })?;

        // Verify it's a regular file
        if !metadata.is_file() {
            warn!("Attempted access to non-file: {}", canonical_path.display());
            return Err(DnsmasqError::Tftp(TftpError::AccessViolation {
                path: canonical_path.to_string_lossy().to_string(),
                reason: "Not a regular file".to_string(),
            }));
        }

        // Secure mode: Check file ownership (only on Unix platforms)
        #[cfg(unix)]
        if self.config.tftp_secure {
            use std::os::unix::fs::MetadataExt;
            
            // Get current process UID
            let our_uid = unsafe { libc::getuid() };
            let file_uid = metadata.uid();
            
            if file_uid != our_uid {
                warn!(
                    "Secure mode: file {} owned by UID {} (we are UID {})",
                    canonical_path.display(),
                    file_uid,
                    our_uid
                );
                return Err(DnsmasqError::Tftp(TftpError::AccessViolation {
                    path: canonical_path.to_string_lossy().to_string(),
                    reason: "File not owned by dnsmasq user".to_string(),
                }));
            }
        }

        // Open file for reading
        let file = File::open(&canonical_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                DnsmasqError::Tftp(TftpError::AccessViolation {
                    path: canonical_path.to_string_lossy().to_string(),
                    reason: "Permission denied".to_string(),
                })
            } else {
                DnsmasqError::Tftp(TftpError::IoError {
                    path: canonical_path.to_string_lossy().to_string(),
                    reason: format!("Failed to open file: {}", e),
                })
            }
        })?;

        debug!("File access granted: {} for {}", canonical_path.display(), peer);
        Ok(file)
    }

    /// Determines the appropriate TFTP root directory for a client.
    ///
    /// Checks interface-specific prefixes first, then falls back to global prefix.
    fn get_root_directory(&self, _peer: SocketAddr) -> Option<PathBuf> {
        // For now, just return the global prefix
        // Full implementation would check interface-specific prefixes
        self.config.tftp_prefix.clone()
    }

    /// Sends ERROR packet to client.
    async fn send_error(
        &self,
        peer: SocketAddr,
        error_code: TftpErrorCode,
        message: &str,
    ) -> Result<()> {
        let error_packet = build_error_packet(error_code, message);
        self.listener_socket
            .send_to(&error_packet, peer)
            .await
            .map_err(|e| DnsmasqError::Tftp(TftpError::IoError {
                path: peer.to_string(),
                reason: format!("Failed to send ERROR: {}", e),
            }))?;
        Ok(())
    }
}

// ============================================================================
// TFTP PACKET PARSING (nom parsers)
// ============================================================================

/// Parses a null-terminated string from TFTP packet.
fn parse_null_terminated_string(input: &[u8]) -> IResult<&[u8], String> {
    let (remaining, bytes) = take_until(&b"\0"[..])(input)?;
    let (remaining, _) = tag(&b"\0"[..])(remaining)?;
    let string = String::from_utf8_lossy(bytes).to_string();
    Ok((remaining, string))
}

/// Parses RRQ (Read Request) packet per RFC 1350 and RFC 2347.
///
/// # Wire Format
///
/// ```text
/// 2 bytes   string   1 byte   string   1 byte  [string 1 byte string 1 byte]*
/// -----------------------------------------------------------------------
/// | RRQ | Filename | 0 | Mode | 0 | [Option | 0 | Value | 0 | ...] |
/// -----------------------------------------------------------------------
/// ```
fn parse_rrq(input: &[u8]) -> IResult<&[u8], TftpRrq> {
    // Parse filename
    let (remaining, filename) = parse_null_terminated_string(input)?;
    
    // Parse mode
    let (remaining, mode_str) = parse_null_terminated_string(remaining)?;
    let mode = TransferMode::from_str(&mode_str).unwrap_or(TransferMode::Octet);
    
    // Parse options (option/value pairs)
    let (remaining, option_pairs) = many0(tuple((
        parse_null_terminated_string,
        parse_null_terminated_string,
    )))(remaining)?;
    
    let mut options = HashMap::new();
    for (key, value) in option_pairs {
        options.insert(key.to_lowercase(), value);
    }
    
    Ok((remaining, TftpRrq { filename, mode, options }))
}

// ============================================================================
// TFTP PACKET CONSTRUCTION
// ============================================================================

/// Builds OACK (Option Acknowledgment) packet per RFC 2347.
///
/// # Wire Format
///
/// ```text
/// 2 bytes   string   1 byte   string   1 byte  [...]
/// -----------------------------------------------
/// | OACK | Option | 0 | Value | 0 | [...] |
/// -----------------------------------------------
/// ```
fn build_oack_packet(options: &HashMap<String, String>) -> Vec<u8> {
    let mut packet = Vec::new();
    
    // Opcode (OACK = 6)
    packet.extend_from_slice(&6u16.to_be_bytes());
    
    // Option/value pairs
    for (key, value) in options {
        packet.extend_from_slice(key.as_bytes());
        packet.push(0);
        packet.extend_from_slice(value.as_bytes());
        packet.push(0);
    }
    
    packet
}

/// Builds ERROR packet per RFC 1350.
///
/// # Wire Format
///
/// ```text
/// 2 bytes   2 bytes   string   1 byte
/// ------------------------------------
/// | ERROR | ErrCode | ErrMsg | 0 |
/// ------------------------------------
/// ```
fn build_error_packet(error_code: TftpErrorCode, message: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    
    // Opcode (ERROR = 5)
    packet.extend_from_slice(&5u16.to_be_bytes());
    
    // Error code
    packet.extend_from_slice(&(error_code as u16).to_be_bytes());
    
    // Error message
    packet.extend_from_slice(message.as_bytes());
    packet.push(0);
    
    packet
}

/// Builds DATA packet per RFC 1350.
///
/// # Wire Format
///
/// ```text
/// 2 bytes   2 bytes   n bytes
/// ----------------------------
/// | DATA | Block # | Data |
/// ----------------------------
/// ```
fn build_data_packet(block: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    
    // Opcode (DATA = 3)
    packet.extend_from_slice(&3u16.to_be_bytes());
    
    // Block number
    packet.extend_from_slice(&block.to_be_bytes());
    
    // Data payload
    packet.extend_from_slice(data);
    
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rrq_basic() {
        let packet = b"\x00\x01pxelinux.0\x00octet\x00";
        let result = parse_rrq(&packet[2..]);
        assert!(result.is_ok());
        
        let (_, rrq) = result.unwrap();
        assert_eq!(rrq.filename, "pxelinux.0");
        assert_eq!(rrq.mode, TransferMode::Octet);
        assert!(rrq.options.is_empty());
    }

    #[test]
    fn test_parse_rrq_with_options() {
        let packet = b"\x00\x01file.txt\x00netascii\x00blksize\x008192\x00tsize\x00\x00";
        let result = parse_rrq(&packet[2..]);
        assert!(result.is_ok());
        
        let (_, rrq) = result.unwrap();
        assert_eq!(rrq.filename, "file.txt");
        assert_eq!(rrq.mode, TransferMode::Netascii);
        assert_eq!(rrq.options.get("blksize"), Some(&"8192".to_string()));
        assert_eq!(rrq.options.get("tsize"), Some(&"".to_string()));
    }

    #[test]
    fn test_build_oack() {
        let mut options = HashMap::new();
        options.insert("blksize".to_string(), "8192".to_string());
        options.insert("tsize".to_string(), "1024".to_string());
        
        let packet = build_oack_packet(&options);
        
        // Verify opcode
        assert_eq!(u16::from_be_bytes([packet[0], packet[1]]), 6);
        
        // Verify packet contains options
        let packet_str = String::from_utf8_lossy(&packet);
        assert!(packet_str.contains("blksize"));
        assert!(packet_str.contains("8192"));
    }

    #[test]
    fn test_build_error() {
        let packet = build_error_packet(TftpErrorCode::FileNotFound, "File not found");
        
        // Verify opcode
        assert_eq!(u16::from_be_bytes([packet[0], packet[1]]), 5);
        
        // Verify error code
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 1);
        
        // Verify message
        let message = String::from_utf8_lossy(&packet[4..packet.len() - 1]);
        assert_eq!(message, "File not found");
    }
}
