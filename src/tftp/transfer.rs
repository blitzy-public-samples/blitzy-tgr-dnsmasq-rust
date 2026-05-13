// Copyright (C) 2025 Dnsmasq Contributors
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! TFTP file transfer state machine implementation.
//!
//! This module provides the core transfer state management for TFTP (Trivial File Transfer Protocol)
//! sessions, handling block-level data transmission with support for:
//!
//! - **Windowed Transfer Flow Control**: RFC 7440 windowed transfer extension allowing multiple
//!   outstanding blocks (1-32 window size) before requiring acknowledgment, improving throughput
//!   over high-latency links.
//! - **Blocksize Negotiation**: RFC 2349 blocksize option supporting 512-65464 byte blocks
//!   (default 512) for efficient transfer of large files.
//! - **Netascii Mode Conversion**: Transparent LF → CR-LF line ending conversion for text files
//!   with stateful handling of line endings spanning block boundaries.
//! - **Timeout Management**: 120-second inactivity timeout for detecting stale transfers and
//!   automatic cleanup of abandoned sessions.
//! - **Retransmission Logic**: Block retransmission on timeout with window state preservation.
//!
//! # Transfer Lifecycle
//!
//! 1. **Initialization**: `TransferState::new()` creates a transfer session with negotiated
//!    parameters (blocksize, windowsize, netascii mode).
//! 2. **Block Transmission**: `get_block()` reads file data, applies netascii conversion if
//!    enabled, and prepares DATA packet payload.
//! 3. **ACK Processing**: `handle_ack()` validates acknowledgment block numbers and advances
//!    the transmission window via `advance_window()`.
//! 4. **Completion Detection**: `is_complete()` signals EOF when file is exhausted.
//! 5. **Timeout Enforcement**: `is_timeout()` detects inactive transfers exceeding 120 seconds.
//!
//! # Memory Safety
//!
//! This implementation replaces C's manual memory management (`malloc`/`free`, pointer arithmetic,
//! `memmove` for buffer manipulation) with Rust's ownership system:
//!
//! - File handles managed via `tokio::fs::File` with automatic cleanup on drop.
//! - Buffer allocation through `Vec<u8>` and `bytes::BytesMut` with bounds checking.
//! - Zero unsafe blocks - all operations are memory-safe by construction.
//!
//! # C Implementation Mapping
//!
//! Transforms C `struct tftp_transfer` (from `src/tftp.c`) to Rust `TransferState`:
//!
//! | C Field              | Rust Field       | Transformation                                    |
//! |----------------------|------------------|---------------------------------------------------|
//! | `int sockfd`         | N/A              | Socket managed externally by server               |
//! | `time_t start`       | `start: Instant` | C `time_t` → Rust `std::time::Instant`            |
//! | `time_t retransmit`  | `last_activity`  | Tracks last ACK for timeout detection             |
//! | `unsigned int timeout` | `timeout: Duration` | C seconds → Rust `Duration`                   |
//! | `off_t offset`       | `file_offset: u64` | C `off_t` → Rust `u64`                          |
//! | `int block`          | `block_current: u16` | Current block number                          |
//! | `int block_hi`       | `block_high: u16` | Highest ACK'd block (windowed transfer)          |
//! | `int blocksize`      | `blocksize: u16` | Negotiated block size (512-65464)                 |
//! | `int windowsize`     | `windowsize: u16` | RFC 7440 window size (1-32)                      |
//! | `int carrylf`        | `carrylf: bool`  | Netascii LF carryover flag                        |
//! | `int netascii`       | `netascii: bool` | Enable LF → CR-LF conversion                      |
//! | `FILE *file`         | `file: File`     | C `FILE*` → Rust `tokio::fs::File`                |
//! | `struct sockaddr*`   | `peer: SocketAddr` | C `sockaddr` → Rust `std::net::SocketAddr`     |
//!
//! # Example Usage
//!
//! ```no_run
//! use dnsmasq::tftp::TransferState;
//! use std::time::Duration;
//! use std::path::PathBuf;
//! use tokio::fs::File;
//! # use std::net::SocketAddr;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let peer: SocketAddr = "192.168.1.100:12345".parse()?;
//! # let file_path = PathBuf::from("/tftpboot/example.txt");
//!
//! // Open file for TFTP transfer
//! let file = File::open(&file_path).await?;
//!
//! // Create transfer state with RFC 7440 windowed transfer
//! let mut transfer = TransferState::new(
//!     file,
//!     peer,
//!     1468,           // blocksize (Ethernet MTU - headers)
//!     8,              // windowsize (8 outstanding blocks)
//!     Duration::from_secs(120),  // 120s timeout
//!     false,          // binary mode (not netascii)
//!     file_path,
//! );
//!
//! // Transfer loop (managed by server.rs)
//! let mut block_num = 1u16;
//! while !transfer.is_complete() {
//!     // Get next block data
//!     let data = transfer.get_block(block_num).await?;
//!     
//!     // Send DATA packet to client (server.rs responsibility)
//!     // ...
//!     
//!     // Wait for ACK (server.rs responsibility)
//!     // let ack_block = receive_ack().await?;
//!     // transfer.handle_ack(ack_block)?;
//!     
//!     block_num = block_num.wrapping_add(1);
//! }
//! # Ok(())
//! # }
//! ```

use crate::error::Result;
use bytes::{BufMut, Bytes, BytesMut};
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

/// TFTP transfer inactivity timeout (120 seconds).
///
/// Transfers with no ACK activity for this duration are considered stale and eligible for cleanup.
/// This matches the C implementation's `TFTP_TIMEOUT` constant from `src/tftp.c`.
///
/// RFC 1350 does not mandate a specific timeout, but 120 seconds is a common implementation choice
/// providing balance between patience for slow clients and resource cleanup.
pub const TFTP_TIMEOUT: Duration = Duration::from_secs(120);

/// TFTP file transfer state machine.
///
/// Tracks the complete state of a single TFTP read transfer session, including:
/// - File position and EOF status
/// - Block numbering (current and highest acknowledged)
/// - Windowed transfer state (RFC 7440)
/// - Timeout tracking for stale transfer detection
/// - Netascii conversion state (line ending handling)
///
/// # Thread Safety
///
/// `TransferState` is NOT thread-safe and should be used within a single async task.
/// The server manages multiple concurrent transfers via a collection of `TransferState` instances,
/// each associated with a unique (`client_addr`, TID) tuple.
///
/// # Memory Management
///
/// Replaces C's manual resource management:
/// - C: `FILE *file` with `fclose()` in `free_transfer()` → Rust: `tokio::fs::File` with automatic Drop
/// - C: Manual block number tracking with wraparound → Rust: `u16` with `.wrapping_add()`
/// - C: Pointer-based buffer manipulation (`memmove`) → Rust: `Vec<u8>` and `BytesMut` with safe operations
pub struct TransferState {
    /// Open file handle for reading TFTP data blocks.
    ///
    /// Managed asynchronously via `tokio::fs::File` for non-blocking I/O within the tokio runtime.
    /// Automatically closed when `TransferState` is dropped (RAII).
    file: File,

    /// Current block number being sent (1-based for DATA packets).
    ///
    /// - Block 0: Reserved for OACK packets (handled separately in server.rs)
    /// - Block 1+: DATA packet blocks containing file content
    /// - Wraps at `u16::MAX` (65535) per RFC 1350
    block_current: u16,

    /// Highest block number acknowledged by the client.
    ///
    /// Used for RFC 7440 windowed transfer flow control. The server can send blocks in the range
    /// `[block_high + 1, block_high + windowsize]` without waiting for ACKs.
    ///
    /// Updated via `advance_window()` when ACKs are received.
    block_high: u16,

    /// Client peer address (IP and port) for this transfer session.
    ///
    /// TFTP uses a unique (IP, port) pair per transfer session. The initial RRQ arrives on the
    /// server's well-known port (69), but the transfer continues on an ephemeral port.
    peer: SocketAddr,

    /// Negotiated block size in bytes (512-65464).
    ///
    /// RFC 2349 blocksize option. Default is 512 bytes per RFC 1350.
    /// Larger blocksizes improve throughput by reducing per-block overhead.
    /// Maximum 65464 bytes (65535 UDP payload - 4 byte TFTP header).
    blocksize: u16,

    /// Window size for RFC 7440 windowed transfers (1-32 blocks).
    ///
    /// Number of DATA blocks the server can send before requiring an ACK.
    /// - windowsize = 1: Traditional stop-and-wait (RFC 1350)
    /// - windowsize > 1: Pipelined transmission for improved throughput
    ///
    /// The client ACKs the highest block received within the window.
    windowsize: u16,

    /// Timeout duration for detecting stale transfers.
    ///
    /// Typically set to `TFTP_TIMEOUT` (120 seconds). Transfers with no ACK activity for this
    /// duration are considered abandoned and eligible for cleanup.
    timeout: Duration,

    /// Transfer start time for total session duration tracking.
    ///
    /// Used for metrics and logging. Not used for timeout detection (see `last_activity`).
    start: Instant,

    /// Last activity timestamp for timeout detection.
    ///
    /// Updated to `Instant::now()` whenever an ACK is received via `advance_window()`.
    /// If `Instant::now() - last_activity > timeout`, the transfer is considered stale.
    last_activity: Instant,

    /// Current file offset for reading the next block.
    ///
    /// Maintained for sequential reads. For retransmissions, we seek back to the appropriate
    /// offset based on the requested block number.
    file_offset: u64,

    /// Netascii mode enabled flag.
    ///
    /// When `true`, perform transparent LF → CR-LF line ending conversion for text files.
    /// RFC 1350 defines three modes: netascii, octet, and mail. Only netascii and octet are
    /// commonly implemented.
    netascii: bool,

    /// Carry-over LF flag for netascii conversion spanning block boundaries.
    ///
    /// If the last byte of a block is LF (`\n`) and converting to CR-LF would exceed the blocksize,
    /// we set `carrylf = true` and insert the CR at the start of the *next* block.
    ///
    /// This matches the C implementation's `transfer->carrylf` from `src/tftp.c:get_block()`.
    carrylf: bool,

    /// File path for error reporting and logging.
    ///
    /// Stored as `PathBuf` for owned path storage. Used in `TftpError::IoError` messages.
    file_path: PathBuf,

    /// End-of-file reached flag.
    ///
    /// Set to `true` when a read returns fewer bytes than `blocksize`, indicating the last block.
    /// Used by `is_complete()` to signal transfer completion.
    eof: bool,
}

impl TransferState {
    /// Create a new TFTP transfer state.
    ///
    /// Initializes a transfer session with the given parameters. The file must be opened by the
    /// caller (server.rs) with appropriate permissions before passing to this constructor.
    ///
    /// # Arguments
    ///
    /// - `file`: Opened file handle for reading. Will be automatically closed when `TransferState`
    ///   is dropped.
    /// - `peer`: Client socket address (IP and port) for this transfer session.
    /// - `blocksize`: Negotiated block size in bytes (512-65464). Must match the value sent in
    ///   the OACK packet to the client.
    /// - `windowsize`: RFC 7440 window size (1-32 blocks). Use 1 for traditional stop-and-wait.
    /// - `timeout`: Inactivity timeout duration. Typically `TFTP_TIMEOUT` (120 seconds).
    /// - `netascii`: Enable netascii mode (LF → CR-LF conversion) for text files.
    /// - `file_path`: Path to the file being transferred, used for error messages.
    ///
    /// # Returns
    ///
    /// A new `TransferState` ready to begin block transmission.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use dnsmasq::tftp::TransferState;
    /// use std::time::Duration;
    /// use std::path::PathBuf;
    /// use tokio::fs::File;
    /// # use std::net::SocketAddr;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let peer: SocketAddr = "192.168.1.100:12345".parse()?;
    /// # let file_path = PathBuf::from("/tftpboot/file.txt");
    ///
    /// let file = File::open(&file_path).await?;
    /// let transfer = TransferState::new(
    ///     file,
    ///     peer,
    ///     1468,                      // blocksize
    ///     8,                         // windowsize
    ///     Duration::from_secs(120),  // timeout
    ///     false,                     // binary mode
    ///     file_path,
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        file: File,
        peer: SocketAddr,
        blocksize: u16,
        windowsize: u16,
        timeout: Duration,
        netascii: bool,
        file_path: PathBuf,
    ) -> Self {
        let now = Instant::now();
        Self {
            file,
            block_current: 0,
            block_high: 0,
            peer,
            blocksize,
            windowsize,
            timeout,
            start: now,
            last_activity: now,
            file_offset: 0,
            netascii,
            carrylf: false,
            file_path,
            eof: false,
        }
    }

    /// Get the data for a specific block number.
    ///
    /// Reads `blocksize` bytes from the file at the position corresponding to the given block number,
    /// applies netascii conversion if enabled, and returns the block data ready for transmission
    /// in a TFTP DATA packet.
    ///
    /// # Block Number Semantics
    ///
    /// - Block 0: Reserved for OACK packets (not handled here; returns empty `Bytes`)
    /// - Block 1: First data block (file offset 0)
    /// - Block N: File offset = (N - 1) * blocksize
    ///
    /// # Netascii Conversion
    ///
    /// When `self.netascii` is true, transforms line endings from LF (`\n`) to CR-LF (`\r\n`).
    /// Handles the case where a LF at block boundary would cause overflow:
    ///
    /// - If inserting CR-LF would exceed `blocksize`, set `self.carrylf = true` and defer the CR
    ///   to the next block.
    /// - If `self.carrylf` is set from the previous block, insert CR at the start of this block.
    ///
    /// This stateful handling matches the C implementation in `src/tftp.c:get_block()` lines 1495-1533.
    ///
    /// # EOF Detection
    ///
    /// If the read returns fewer than `blocksize` bytes, sets `self.eof = true` to signal the
    /// last block. Subsequent calls to `is_complete()` will return `true`.
    ///
    /// # Arguments
    ///
    /// - `block`: Block number to retrieve (1-based for DATA blocks).
    ///
    /// # Returns
    ///
    /// - `Ok(Bytes)`: Block data ready for transmission.
    /// - `Err(TftpError::IoError)`: File I/O error during read or seek.
    ///
    /// # Errors
    ///
    /// Returns `TftpError::IoError` if:
    /// - File seek operation fails
    /// - File read operation fails
    /// - File was closed or deleted during transfer
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::tftp::TransferState;
    /// # use std::time::Duration;
    /// # use std::path::PathBuf;
    /// # use tokio::fs::File;
    /// # use std::net::SocketAddr;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let peer: SocketAddr = "192.168.1.100:12345".parse()?;
    /// # let file_path = PathBuf::from("/tftpboot/file.txt");
    /// # let file = File::open(&file_path).await?;
    /// # let mut transfer = TransferState::new(
    /// #     file, peer, 512, 1, Duration::from_secs(120), false, file_path
    /// # );
    ///
    /// // Get first block (file offset 0)
    /// let block1_data = transfer.get_block(1).await?;
    ///
    /// // Get second block (file offset 512)
    /// let block2_data = transfer.get_block(2).await?;
    ///
    /// // Check if transfer complete
    /// if transfer.is_complete() {
    ///     println!("Last block sent");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_block(&mut self, block: u16) -> Result<Bytes> {
        // Block 0 is reserved for OACK packets, not handled in transfer state
        // (OACK generation is server.rs responsibility)
        if block == 0 {
            return Ok(Bytes::new());
        }

        // Calculate file position for this block (1-based block numbering)
        // For netascii mode, we use the tracked file_offset instead of calculating
        // from block number, because netascii conversion can expand data (LF → CR-LF)
        // causing misalignment between input and output positions.
        let position = if self.netascii && self.block_current > 0 {
            // Use tracked position from previous block
            self.file_offset
        } else {
            // Binary mode or first block: calculate from block number
            (u64::from(block).wrapping_sub(1)).wrapping_mul(u64::from(self.blocksize))
        };

        // Seek to the appropriate file position
        // This allows retransmission of earlier blocks without maintaining a cache
        self.file.seek(SeekFrom::Start(position)).await.map_err(|e| {
            crate::error::TftpError::IoError {
                path: self.file_path.display().to_string(),
                reason: format!("Failed to seek to offset {position}: {e}"),
            }
        })?;

        // Allocate buffer for reading block data
        // In netascii mode, read extra bytes to account for potential expansion
        let read_size = if self.netascii {
            // Read more than blocksize to ensure we have enough input bytes
            // even if many are expanded (LF → CR-LF)
            self.blocksize as usize * 2
        } else {
            self.blocksize as usize
        };
        let mut buffer = vec![0u8; read_size];

        // Read up to read_size bytes from file
        let n =
            self.file.read(&mut buffer).await.map_err(|e| crate::error::TftpError::IoError {
                path: self.file_path.display().to_string(),
                reason: format!("Failed to read block {block}: {e}"),
            })?;

        // Truncate buffer to actual bytes read
        buffer.truncate(n);

        // Apply netascii conversion if enabled (LF → CR-LF)
        let (final_data, input_consumed) = if self.netascii {
            let (data, consumed) = self.netascii_convert(&buffer);
            // Set EOF if we consumed all available input and it was less than blocksize
            if consumed < self.blocksize as usize && n < read_size {
                self.eof = true;
            }
            (data, consumed)
        } else {
            // Binary mode: output size equals input size
            // Set EOF flag if we read fewer bytes than blocksize (last block)
            if n < self.blocksize as usize {
                self.eof = true;
            }
            (Bytes::from(buffer), n)
        };

        // Update transfer state
        self.block_current = block;
        // Track actual input file position for netascii mode
        self.file_offset = position.wrapping_add(input_consumed as u64);

        Ok(final_data)
    }

    /// Convert binary data to netascii format (LF → CR-LF).
    ///
    /// Implements RFC 1350 netascii mode line ending conversion. Scans the input buffer for
    /// LF (`\n`) characters and converts them to CR-LF (`\r\n`) sequences.
    ///
    /// # Stateful Conversion
    ///
    /// Handles line endings spanning block boundaries via the `carrylf` flag:
    ///
    /// 1. If `self.carrylf` is set (from previous block), insert CR at the start of this block
    ///    before processing the buffer.
    /// 2. Scan buffer and convert each LF to CR-LF.
    /// 3. If the conversion would exceed `blocksize`, truncate the output and set `self.carrylf`
    ///    for the next block.
    ///
    /// # RFC 1350 Netascii Specification
    ///
    /// Netascii is "ascii" with CR-LF line endings. The conversion is:
    /// - LF (`\n` / 0x0A) → CR-LF (`\r\n` / 0x0D 0x0A)
    /// - CR (`\r` / 0x0D) → CR-NUL (`\r\0` / 0x0D 0x00) [not commonly implemented]
    ///
    /// This implementation converts LF → CR-LF and leaves CR unchanged (common practice).
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces C pointer arithmetic and `memmove()` from `src/tftp.c:get_block()` lines 1495-1533:
    ///
    /// ```c
    /// // C code: in-place buffer expansion with memmove
    /// while ((p = memchr(p, '\n', len - (p - buffer))) != NULL) {
    ///     if (len++ == blocksize) {
    ///         len--;
    ///         transfer->carrylf = '\r';  // Defer CR to next block
    ///         break;
    ///     }
    ///     memmove(p+1, p, len - (p - buffer) - 1);  // Shift right
    ///     *p++ = '\r';  // Insert CR
    ///     p++;  // Skip over LF
    /// }
    /// ```
    ///
    /// Rust replacement uses `BytesMut` for safe buffer growth without manual pointer manipulation.
    ///
    /// # Arguments
    ///
    /// - `data`: Input buffer containing binary data.
    ///
    /// # Returns
    ///
    /// - `Ok((Bytes, usize))`: Tuple of (converted netascii data, number of input bytes consumed).
    ///
    /// # Performance
    ///
    /// Allocates a new `BytesMut` buffer and copies data with conversions. For binary transfers,
    /// set `netascii = false` to avoid this overhead.
    fn netascii_convert(&mut self, data: &[u8]) -> (Bytes, usize) {
        let mut output = BytesMut::new();
        let mut input_consumed = 0;

        // If we had a trailing LF from the previous block, insert the deferred CR now
        if self.carrylf {
            output.put_u8(b'\r');
            self.carrylf = false;
        }

        // Scan buffer and convert LF → CR-LF
        for &byte in data {
            if byte == b'\n' {
                // Check if inserting CR-LF would exceed blocksize
                if output.len() + 2 > self.blocksize as usize {
                    // Exceeded blocksize: defer LF's CR to next block
                    self.carrylf = true;
                    // Insert just the LF now; CR will be inserted at start of next block
                    output.put_u8(b'\n');
                    input_consumed += 1;
                    break;
                }
                // Convert LF → CR-LF
                output.put_u8(b'\r');
                output.put_u8(b'\n');
                input_consumed += 1;
            } else {
                // Check if adding this byte would exceed blocksize
                if output.len() >= self.blocksize as usize {
                    break;
                }
                // Copy other bytes as-is (including existing CR characters)
                output.put_u8(byte);
                input_consumed += 1;
            }
        }

        // Truncate to blocksize if we somehow exceeded it
        if output.len() > self.blocksize as usize {
            output.truncate(self.blocksize as usize);
        }

        (output.freeze(), input_consumed)
    }

    /// Check if the transfer has reached end-of-file.
    ///
    /// Returns `true` if the last `get_block()` call read fewer bytes than `blocksize`,
    /// indicating the last block of the file has been sent.
    ///
    /// # Returns
    ///
    /// - `true`: EOF reached, transfer complete after current block is acknowledged.
    /// - `false`: More blocks remain to be sent.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::tftp::TransferState;
    /// # use std::time::Duration;
    /// # use std::path::PathBuf;
    /// # use tokio::fs::File;
    /// # use std::net::SocketAddr;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let peer: SocketAddr = "192.168.1.100:12345".parse()?;
    /// # let file_path = PathBuf::from("/tftpboot/file.txt");
    /// # let file = File::open(&file_path).await?;
    /// # let mut transfer = TransferState::new(
    /// #     file, peer, 512, 1, Duration::from_secs(120), false, file_path
    /// # );
    ///
    /// let mut block = 1u16;
    /// while !transfer.is_complete() {
    ///     let data = transfer.get_block(block).await?;
    ///     // Send DATA packet...
    ///     block = block.wrapping_add(1);
    /// }
    /// println!("Transfer complete");
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_complete(&self) -> bool {
        self.eof
    }

    /// Check if the transfer has exceeded the inactivity timeout.
    ///
    /// Returns `true` if the time since the last ACK (`last_activity`) exceeds the configured
    /// `timeout` duration. Stale transfers should be cleaned up by the server.
    ///
    /// # Timeout Behavior
    ///
    /// - Timeout is reset on each ACK via `advance_window()`.
    /// - Default timeout is `TFTP_TIMEOUT` (120 seconds).
    /// - No automatic cleanup; the server must poll `is_timeout()` and remove stale transfers.
    ///
    /// # Returns
    ///
    /// - `true`: Transfer is stale (no ACK activity for `timeout` duration).
    /// - `false`: Transfer is active (recent ACK within timeout window).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::tftp::TransferState;
    /// # use std::time::Duration;
    /// # use std::path::PathBuf;
    /// # use tokio::fs::File;
    /// # use std::net::SocketAddr;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let peer: SocketAddr = "192.168.1.100:12345".parse()?;
    /// # let file_path = PathBuf::from("/tftpboot/file.txt");
    /// # let file = File::open(&file_path).await?;
    /// # let transfer = TransferState::new(
    /// #     file, peer, 512, 1, Duration::from_secs(120), false, file_path
    /// # );
    ///
    /// // Server cleanup loop
    /// if transfer.is_timeout() {
    ///     println!("Transfer timed out, cleaning up");
    ///     // Remove transfer from active sessions
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_timeout(&self) -> bool {
        Instant::now().duration_since(self.last_activity) > self.timeout
    }

    /// Advance the transmission window based on received ACK.
    ///
    /// Updates `block_high` to track the highest block acknowledged by the client, enabling
    /// RFC 7440 windowed transfer flow control. Resets the inactivity timeout (`last_activity`).
    ///
    /// # RFC 7440 Windowed Transfer
    ///
    /// The server can send blocks in the range `[block_high + 1, block_high + windowsize]`
    /// without waiting for ACKs. When an ACK is received:
    ///
    /// 1. Update `block_high = max(block_high, ack_block)`.
    /// 2. Reset `last_activity` to prevent timeout.
    /// 3. Continue sending blocks up to the new window limit.
    ///
    /// # Arguments
    ///
    /// - `ack_block`: Block number acknowledged by the client.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::tftp::TransferState;
    /// # use std::time::Duration;
    /// # use std::path::PathBuf;
    /// # use tokio::fs::File;
    /// # use std::net::SocketAddr;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let peer: SocketAddr = "192.168.1.100:12345".parse()?;
    /// # let file_path = PathBuf::from("/tftpboot/file.txt");
    /// # let file = File::open(&file_path).await?;
    /// # let mut transfer = TransferState::new(
    /// #     file, peer, 1468, 8, Duration::from_secs(120), false, file_path
    /// # );
    ///
    /// // Send blocks 1-8 (windowsize = 8)
    /// for block in 1..=8 {
    ///     let data = transfer.get_block(block).await?;
    ///     // Send DATA packet...
    /// }
    ///
    /// // Receive ACK for block 8
    /// transfer.advance_window(8);
    ///
    /// // Can now send blocks 9-16
    /// # Ok(())
    /// # }
    /// ```
    pub fn advance_window(&mut self, ack_block: u16) {
        // Update highest acknowledged block (monotonically increasing)
        if ack_block > self.block_high {
            self.block_high = ack_block;
        }

        // Reset inactivity timeout
        self.last_activity = Instant::now();
    }

    /// Handle received ACK and validate block number.
    ///
    /// Processes an ACK packet from the client, validating the block number and updating the
    /// transmission window. This is a convenience wrapper around `advance_window()` with
    /// validation logic.
    ///
    /// # Validation
    ///
    /// - ACK block number must be ≤ `block_current` (can't ACK blocks we haven't sent yet).
    /// - Out-of-range ACKs return `TftpError::IllegalOperation`.
    ///
    /// # Arguments
    ///
    /// - `ack_block`: Block number from the received ACK packet.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: ACK processed successfully, window advanced.
    /// - `Err(TftpError::IllegalOperation)`: Invalid ACK block number.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::tftp::TransferState;
    /// # use std::time::Duration;
    /// # use std::path::PathBuf;
    /// # use tokio::fs::File;
    /// # use std::net::SocketAddr;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let peer: SocketAddr = "192.168.1.100:12345".parse()?;
    /// # let file_path = PathBuf::from("/tftpboot/file.txt");
    /// # let file = File::open(&file_path).await?;
    /// # let mut transfer = TransferState::new(
    /// #     file, peer, 512, 1, Duration::from_secs(120), false, file_path
    /// # );
    ///
    /// // Send block 1
    /// let data = transfer.get_block(1).await?;
    /// // Send DATA packet...
    ///
    /// // Receive ACK
    /// let ack_block = 1u16;  // From ACK packet
    /// transfer.handle_ack(ack_block)?;
    ///
    /// // Invalid ACK example
    /// match transfer.handle_ack(999) {
    ///     Err(_) => println!("Invalid ACK ignored"),
    ///     Ok(_) => {}
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn handle_ack(&mut self, ack_block: u16) -> Result<()> {
        // Validate ACK block number (must not exceed blocks we've sent)
        if ack_block > self.block_current {
            return Err(crate::error::DnsmasqError::Tftp(
                crate::error::TftpError::IllegalOperation {
                    reason: format!(
                        "ACK block {} exceeds current block {}",
                        ack_block, self.block_current
                    ),
                },
            ));
        }

        // Advance window and reset timeout
        self.advance_window(ack_block);

        Ok(())
    }

    /// Get the client peer address for this transfer.
    ///
    /// Returns the socket address (IP and port) of the client for this transfer session.
    /// Used by the server for routing packets and associating transfers with client connections.
    ///
    /// # Returns
    ///
    /// Client socket address.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Get the current block number.
    ///
    /// Returns the block number of the most recently sent DATA packet via `get_block()`.
    ///
    /// # Returns
    ///
    /// Current block number (0 if no blocks sent yet, 1+ for DATA blocks).
    pub fn block_current(&self) -> u16 {
        self.block_current
    }

    /// Get the highest acknowledged block number.
    ///
    /// Returns the highest block number confirmed by the client via ACK packets.
    /// Used for RFC 7440 windowed transfer flow control.
    ///
    /// # Returns
    ///
    /// Highest ACK'd block number.
    pub fn block_high(&self) -> u16 {
        self.block_high
    }

    /// Get the configured window size.
    ///
    /// Returns the RFC 7440 window size negotiated for this transfer (1-32 blocks).
    ///
    /// # Returns
    ///
    /// Window size (1 = stop-and-wait, >1 = windowed transfer).
    pub fn windowsize(&self) -> u16 {
        self.windowsize
    }

    /// Get the transfer start time.
    ///
    /// Returns the `Instant` when this transfer was created. Used for metrics and logging.
    ///
    /// # Returns
    ///
    /// Transfer start time.
    pub fn start_time(&self) -> Instant {
        self.start
    }

    /// Get the last activity time.
    ///
    /// Returns the `Instant` of the most recent ACK received. Used for timeout detection.
    ///
    /// # Returns
    ///
    /// Last ACK timestamp.
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Test basic transfer state creation.
    #[tokio::test]
    async fn test_transfer_state_new() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "test data").unwrap();
        let path = temp_file.path().to_path_buf();

        let file = File::open(&path).await.unwrap();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let transfer =
            TransferState::new(file, peer, 512, 1, Duration::from_secs(120), false, path.clone());

        assert_eq!(transfer.block_current(), 0);
        assert_eq!(transfer.block_high(), 0);
        assert_eq!(transfer.peer(), peer);
        assert_eq!(transfer.windowsize(), 1);
        assert!(!transfer.is_complete());
        assert!(!transfer.is_timeout());
    }

    /// Test reading a single block.
    #[tokio::test]
    async fn test_get_block_single() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "Hello, TFTP!").unwrap();
        let path = temp_file.path().to_path_buf();

        let file = File::open(&path).await.unwrap();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let mut transfer =
            TransferState::new(file, peer, 512, 1, Duration::from_secs(120), false, path.clone());

        let data = transfer.get_block(1).await.unwrap();
        assert_eq!(&data[..], b"Hello, TFTP!");
        assert_eq!(transfer.block_current(), 1);
        assert!(transfer.is_complete()); // Less than blocksize → EOF
    }

    /// Test netascii conversion (LF → CR-LF).
    #[tokio::test]
    async fn test_netascii_conversion() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "Line1\nLine2\nLine3").unwrap();
        let path = temp_file.path().to_path_buf();

        let file = File::open(&path).await.unwrap();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let mut transfer = TransferState::new(
            file,
            peer,
            512,
            1,
            Duration::from_secs(120),
            true, // netascii mode
            path.clone(),
        );

        let data = transfer.get_block(1).await.unwrap();
        assert_eq!(&data[..], b"Line1\r\nLine2\r\nLine3");
    }

    /// Test ACK handling and window advancement.
    #[tokio::test]
    async fn test_handle_ack() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "test").unwrap();
        let path = temp_file.path().to_path_buf();

        let file = File::open(&path).await.unwrap();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let mut transfer =
            TransferState::new(file, peer, 512, 8, Duration::from_secs(120), false, path.clone());

        // Send block 1
        let _ = transfer.get_block(1).await.unwrap();
        assert_eq!(transfer.block_current(), 1);
        assert_eq!(transfer.block_high(), 0);

        // ACK block 1
        transfer.handle_ack(1).unwrap();
        assert_eq!(transfer.block_high(), 1);

        // Invalid ACK (block 999 not sent yet)
        let result = transfer.handle_ack(999);
        assert!(result.is_err());
    }

    /// Test timeout detection.
    #[tokio::test]
    async fn test_timeout() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "test").unwrap();
        let path = temp_file.path().to_path_buf();

        let file = File::open(&path).await.unwrap();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let mut transfer = TransferState::new(
            file,
            peer,
            512,
            1,
            Duration::from_millis(10), // Very short timeout for testing
            false,
            path.clone(),
        );

        assert!(!transfer.is_timeout());

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(transfer.is_timeout());

        // ACK resets timeout
        transfer.advance_window(0);
        assert!(!transfer.is_timeout());
    }
}
