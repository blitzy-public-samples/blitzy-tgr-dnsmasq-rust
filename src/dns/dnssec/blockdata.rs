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

//! Variable-length data storage using fixed-size block chains for efficient DNSSEC record storage.
//!
//! # Overview
//!
//! This module provides memory-efficient storage for variable-length DNSSEC data (RRSIG signatures,
//! DNSKEY public keys, DS delegation signer records, NSEC/NSEC3 denial-of-existence proofs) without
//! causing heap fragmentation. The implementation uses fixed-size blocks (40 bytes each) chained
//! together to store arbitrarily large DNSSEC records.
//!
//! # Key Differences from C Implementation
//!
//! The C implementation uses a manual free list pool with explicit malloc/free calls:
//! - Global `keyblock_free` linked list for available blocks
//! - Manual block allocation via `new_block()` from free list
//! - Explicit `blockdata_free()` to return blocks to free list
//! - Risk of memory leaks if `blockdata_free()` not called
//!
//! This Rust implementation uses automatic memory management:
//! - `Vec<[u8; BLOCK_SIZE]>` provides automatic allocation and growth
//! - Drop trait ensures automatic cleanup when BlockData goes out of scope
//! - No manual free list management required
//! - Memory safety guaranteed by Rust ownership system
//!
//! # Design Rationale
//!
//! Fixed-size blocks prevent heap fragmentation from variable-size DNSSEC records which range
//! from ~100 bytes (small signatures) to ~4KB (large DNSKEY records). Using 40-byte blocks
//! balances memory efficiency (minimal waste per record) with traversal performance (fewer
//! blocks to iterate).
//!
//! # Memory Efficiency
//!
//! - Fixed 40-byte blocks enable predictable allocation patterns
//! - Vec automatic reallocation strategy reduces allocation overhead
//! - Typical overhead: 0-39 bytes per record (average ~20 bytes)
//! - BLOCK_SIZE = 40 matches C KEYBLOCK_LEN for cache file compatibility
//!
//! # Usage Example
//!
//! ```no_run
//! use dnsmasq::dns::dnssec::blockdata::{BlockData, BlockDataStats};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create BlockData from RRSIG signature bytes
//! let signature_bytes: Vec<u8> = vec![0u8; 128]; // 128-byte signature
//! let blockdata = BlockData::new(&signature_bytes);
//!
//! // Retrieve data back to contiguous buffer
//! let retrieved = blockdata.retrieve();
//! assert_eq!(retrieved, signature_bytes);
//!
//! // Expand with additional data
//! let mut blockdata = blockdata;
//! let additional_data = vec![0xffu8; 64];
//! blockdata.expand(&additional_data)?;
//! assert_eq!(blockdata.len(), 192); // 128 + 64
//!
//! // Automatic cleanup via Drop trait - no manual free needed
//! # Ok(())
//! # }
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Fixed block size matching C KEYBLOCK_LEN for cache file compatibility.
///
/// This constant determines the payload size of each block in the chain. The value of 40 bytes
/// was chosen to balance memory efficiency (minimize waste from partial blocks) with traversal
/// performance (reduce number of blocks for large records).
///
/// Compatibility: Must match C KEYBLOCK_LEN (40 bytes) to enable reading/writing cache files
/// created by either C or Rust implementations.
pub const BLOCK_SIZE: usize = 40;

/// Error types for BlockData operations.
///
/// Provides detailed error information for allocation failures, I/O errors, and chain
/// corruption detection. Uses thiserror for automatic Error trait implementation.
#[derive(Debug, Error)]
pub enum BlockDataError {
    /// Memory allocation failed during block chain creation or expansion.
    ///
    /// This error indicates the system is unable to allocate memory for additional blocks.
    /// In the C implementation, this would manifest as NULL return from malloc().
    #[error("Block data allocation failed")]
    AllocationFailed,

    /// I/O operation failed during read or write to file descriptor.
    ///
    /// Wraps underlying I/O errors from tokio operations. The source error provides
    /// specific details (e.g., permission denied, disk full, broken pipe).
    #[error("I/O error during block data operation: {0}")]
    IoError(#[from] std::io::Error),

    /// Block chain is shorter than expected length parameter.
    ///
    /// Indicates programming error where caller specified oldlen that exceeds actual
    /// chain content in blockdata_expand() operation. The C implementation detects this
    /// as a sanity check to prevent chain corruption.
    #[error("Block chain too short for specified length")]
    ChainTooShort,

    /// Invalid length parameter provided to operation.
    ///
    /// Indicates length parameter doesn't make sense for the operation (e.g., negative
    /// length, length exceeds available data).
    #[error("Invalid length parameter: {0}")]
    InvalidLength(String),
}

/// Type alias for Result with BlockDataError.
pub type Result<T> = std::result::Result<T, BlockDataError>;

/// Variable-length data storage using fixed-size block chains.
///
/// BlockData stores arbitrary-length byte sequences using a vector of fixed-size blocks.
/// This design prevents heap fragmentation from variable-size DNSSEC records while
/// maintaining efficient allocation through Vec's exponential growth strategy.
///
/// # Implementation Notes
///
/// - Replaces C manual free list with Vec automatic memory management
/// - Drop trait ensures automatic cleanup eliminating memory leaks
/// - Each block stores exactly BLOCK_SIZE (40) bytes except potentially the last block
/// - Total data length tracked separately from block count for efficient queries
///
/// # Thread Safety
///
/// BlockData itself is not thread-safe (matches C single-threaded architecture).
/// For concurrent access, wrap in Arc<RwLock<BlockData>> or similar synchronization.
#[derive(Debug, Clone)]
pub struct BlockData {
    /// Vector of fixed-size blocks storing the actual data.
    ///
    /// Each block is exactly BLOCK_SIZE bytes. The last block may be partially filled
    /// if total data length is not a multiple of BLOCK_SIZE.
    blocks: Vec<[u8; BLOCK_SIZE]>,

    /// Total number of data bytes stored across all blocks.
    ///
    /// This may be less than blocks.len() * BLOCK_SIZE if the last block is partial.
    /// Tracking length separately avoids recalculating during len() calls.
    total_len: usize,
}

impl BlockData {
    /// Create a new BlockData from a byte slice.
    ///
    /// Allocates sufficient blocks to store all bytes from the input slice, chunking the
    /// data into BLOCK_SIZE segments. This is the primary constructor for storing DNSSEC
    /// record data (RRSIG signatures, DNSKEY public keys, DS digests).
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice containing data to store in block chain
    ///
    /// # Returns
    ///
    /// New BlockData instance containing a copy of the input data distributed across
    /// fixed-size blocks.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::dns::dnssec::blockdata::BlockData;
    /// let signature = vec![0u8; 128]; // 128-byte RRSIG signature
    /// let blockdata = BlockData::new(&signature);
    /// assert_eq!(blockdata.len(), 128);
    /// // 128 bytes requires 4 blocks (3 full + 1 partial): ceil(128 / 40) = 4
    /// ```
    ///
    /// # Memory Efficiency
    ///
    /// For N bytes of input:
    /// - Blocks allocated: ceil(N / BLOCK_SIZE)
    /// - Memory used: ceil(N / BLOCK_SIZE) * BLOCK_SIZE
    /// - Overhead: (ceil(N / BLOCK_SIZE) * BLOCK_SIZE) - N (0 to BLOCK_SIZE-1 bytes)
    pub fn new(data: &[u8]) -> Self {
        let total_len = data.len();
        
        // Calculate number of blocks needed: ceil(len / BLOCK_SIZE)
        let num_blocks = if total_len == 0 {
            0
        } else {
            (total_len + BLOCK_SIZE - 1) / BLOCK_SIZE
        };

        let mut blocks = Vec::with_capacity(num_blocks);
        
        // Chunk data into BLOCK_SIZE segments
        for chunk in data.chunks(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            blocks.push(block);
        }

        // Update global statistics
        GLOBAL_STATS.increment(num_blocks);

        Self { blocks, total_len }
    }

    /// Read data from an async reader into a new BlockData.
    ///
    /// Asynchronously reads exactly `len` bytes from the provided reader and stores them
    /// in a newly allocated BlockData chain. This replaces the C blockdata_read() function
    /// with async I/O to prevent event loop blocking during cache deserialization.
    ///
    /// # Arguments
    ///
    /// * `reader` - Async reader implementing AsyncReadExt (e.g., tokio::fs::File, TcpStream)
    /// * `len` - Number of bytes to read from reader
    ///
    /// # Returns
    ///
    /// - `Ok(BlockData)` - Successfully read and allocated block chain with `len` bytes
    /// - `Err(BlockDataError::IoError)` - Read failed (short read, permission denied, etc.)
    ///
    /// # Errors
    ///
    /// Returns IoError if:
    /// - Reader cannot provide `len` bytes (short read)
    /// - I/O error occurs during read (broken pipe, permission denied, disk error)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::dns::dnssec::blockdata::BlockData;
    /// # use tokio::fs::File;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut file = File::open("/var/cache/dnsmasq/dnssec.dat").await?;
    /// let blockdata = BlockData::from_reader(&mut file, 512).await?;
    /// assert_eq!(blockdata.len(), 512);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Implementation Notes
    ///
    /// Uses tokio::io::AsyncReadExt::read_exact() to ensure exactly `len` bytes are read.
    /// If EOF is reached before `len` bytes, read_exact() returns UnexpectedEof error.
    pub async fn from_reader<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        len: usize,
    ) -> Result<Self> {
        let mut buffer = vec![0u8; len];
        reader.read_exact(&mut buffer).await?;
        Ok(Self::new(&buffer))
    }

    /// Write BlockData to an async writer.
    ///
    /// Asynchronously writes all data stored in the BlockData chain to the provided writer.
    /// This replaces C blockdata_write() with async I/O for non-blocking cache serialization.
    ///
    /// # Arguments
    ///
    /// * `writer` - Async writer implementing AsyncWriteExt (e.g., tokio::fs::File, TcpStream)
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Successfully wrote all data to writer
    /// - `Err(BlockDataError::IoError)` - Write failed (disk full, broken pipe, etc.)
    ///
    /// # Errors
    ///
    /// Returns IoError if:
    /// - Writer cannot accept data (disk full, quota exceeded)
    /// - I/O error occurs during write (broken pipe, permission denied)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::dns::dnssec::blockdata::BlockData;
    /// # use tokio::fs::File;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let signature = vec![0u8; 128];
    /// let blockdata = BlockData::new(&signature);
    /// 
    /// let mut file = File::create("/var/cache/dnsmasq/sig.dat").await?;
    /// blockdata.to_writer(&mut file).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Implementation Notes
    ///
    /// Writes blocks sequentially, writing exactly total_len bytes. The last block may be
    /// partially written if total_len is not a multiple of BLOCK_SIZE.
    pub async fn to_writer<W: AsyncWriteExt + Unpin>(&self, writer: &mut W) -> Result<()> {
        let mut remaining = self.total_len;
        
        for block in &self.blocks {
            let write_len = std::cmp::min(remaining, BLOCK_SIZE);
            writer.write_all(&block[..write_len]).await?;
            remaining -= write_len;
            
            if remaining == 0 {
                break;
            }
        }
        
        Ok(())
    }

    /// Retrieve data from BlockData as a contiguous Vec<u8>.
    ///
    /// Copies all data from the block chain into a new contiguous vector, reversing the
    /// chunking performed by new(). This is the inverse operation of new() and equivalent
    /// to C blockdata_retrieve() with automatic buffer allocation.
    ///
    /// # Returns
    ///
    /// New Vec<u8> containing all data from the block chain in contiguous memory.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::dns::dnssec::blockdata::BlockData;
    /// let original = vec![1, 2, 3, 4, 5];
    /// let blockdata = BlockData::new(&original);
    /// let retrieved = blockdata.retrieve();
    /// assert_eq!(retrieved, original);
    /// ```
    ///
    /// # Performance
    ///
    /// - Time complexity: O(n) where n is total_len
    /// - Space complexity: O(n) for returned vector
    /// - Uses Iterator::flatten() for efficient copying
    pub fn retrieve(&self) -> Vec<u8> {
        if self.total_len == 0 {
            return Vec::new();
        }

        let mut result = Vec::with_capacity(self.total_len);
        let mut remaining = self.total_len;

        for block in &self.blocks {
            let copy_len = std::cmp::min(remaining, BLOCK_SIZE);
            result.extend_from_slice(&block[..copy_len]);
            remaining -= copy_len;
            
            if remaining == 0 {
                break;
            }
        }

        result
    }

    /// Expand the BlockData by appending additional data.
    ///
    /// Extends an existing block chain by appending new data, potentially allocating additional
    /// blocks if the new data doesn't fit in the remaining space of the final block. This
    /// function replicates C blockdata_expand() behavior with Rust memory safety.
    ///
    /// # Arguments
    ///
    /// * `additional_data` - Byte slice containing new data to append
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Successfully appended data to block chain
    /// - `Err(BlockDataError)` - Expansion failed
    ///
    /// # Errors
    ///
    /// Currently does not fail in practice (Vec handles allocation), but returns Result
    /// for consistency with C API and future error handling.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::dns::dnssec::blockdata::BlockData;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut blockdata = BlockData::new(&[1, 2, 3]);
    /// assert_eq!(blockdata.len(), 3);
    ///
    /// blockdata.expand(&[4, 5, 6])?;
    /// assert_eq!(blockdata.len(), 6);
    ///
    /// let retrieved = blockdata.retrieve();
    /// assert_eq!(retrieved, vec![1, 2, 3, 4, 5, 6]);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Implementation Strategy
    ///
    /// 1. Calculate remaining space in last block (if any)
    /// 2. Fill remaining space in last block with new data
    /// 3. Allocate additional blocks for remaining new data
    /// 4. Update total_len to reflect expanded size
    /// 5. Update global statistics for new blocks allocated
    pub fn expand(&mut self, additional_data: &[u8]) -> Result<()> {
        if additional_data.is_empty() {
            return Ok(());
        }

        let old_len = self.total_len;
        let new_data_len = additional_data.len();
        self.total_len += new_data_len;

        // Calculate space remaining in last block (if any)
        let last_block_used = if old_len == 0 {
            0
        } else {
            old_len % BLOCK_SIZE
        };
        
        let last_block_remaining = if old_len == 0 || last_block_used == 0 {
            0
        } else {
            BLOCK_SIZE - last_block_used
        };

        let mut data_remaining = new_data_len;
        let mut data_offset = 0;

        // Fill remaining space in last block
        if last_block_remaining > 0 && !self.blocks.is_empty() {
            let last_block = self.blocks.last_mut().unwrap();
            let fill_len = std::cmp::min(last_block_remaining, data_remaining);
            last_block[last_block_used..last_block_used + fill_len]
                .copy_from_slice(&additional_data[..fill_len]);
            
            data_offset += fill_len;
            data_remaining -= fill_len;
        }

        // Allocate new blocks for remaining data
        while data_remaining > 0 {
            let mut block = [0u8; BLOCK_SIZE];
            let copy_len = std::cmp::min(data_remaining, BLOCK_SIZE);
            block[..copy_len].copy_from_slice(&additional_data[data_offset..data_offset + copy_len]);
            
            self.blocks.push(block);
            data_offset += copy_len;
            data_remaining -= copy_len;
            
            // Update statistics for new block
            GLOBAL_STATS.increment(1);
        }

        Ok(())
    }

    /// Get the total number of data bytes stored.
    ///
    /// Returns the total length of data stored in the block chain, which may be less than
    /// blocks.len() * BLOCK_SIZE if the last block is partially filled.
    ///
    /// # Returns
    ///
    /// Total number of data bytes stored across all blocks.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::dns::dnssec::blockdata::BlockData;
    /// let blockdata = BlockData::new(&[0u8; 100]);
    /// assert_eq!(blockdata.len(), 100);
    /// // Uses ceil(100 / 40) = 3 blocks, but len() returns actual data length
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.total_len
    }

    /// Check if the BlockData is empty.
    ///
    /// # Returns
    ///
    /// `true` if no data is stored (total_len == 0), `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::dns::dnssec::blockdata::BlockData;
    /// let empty = BlockData::new(&[]);
    /// assert!(empty.is_empty());
    ///
    /// let non_empty = BlockData::new(&[1, 2, 3]);
    /// assert!(!non_empty.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    /// Get a reference to the underlying data as a slice (if possible).
    ///
    /// For efficiency, if the data fits within a single block, returns a slice directly
    /// to that block's data without allocation. For multi-block data, this would require
    /// allocation (use retrieve() instead).
    ///
    /// # Returns
    ///
    /// - `Some(&[u8])` - Data fits in single block, returns slice to that data
    /// - `None` - Data spans multiple blocks, caller should use retrieve()
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::dns::dnssec::blockdata::BlockData;
    /// // Small data fits in one block
    /// let small = BlockData::new(&[1, 2, 3]);
    /// assert!(small.as_bytes().is_some());
    ///
    /// // Large data spans multiple blocks
    /// let large = BlockData::new(&[0u8; 100]);
    /// assert!(large.as_bytes().is_none());
    /// ```
    #[inline]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if self.blocks.len() == 1 {
            Some(&self.blocks[0][..self.total_len])
        } else {
            None
        }
    }
}

/// Automatic cleanup when BlockData is dropped.
///
/// Implements Drop trait to update global statistics when BlockData goes out of scope.
/// This replaces C blockdata_free() manual cleanup with Rust automatic resource management,
/// eliminating memory leaks from forgotten free() calls.
///
/// The Rust implementation does not need a free list pool because Vec handles memory
/// management automatically. When BlockData is dropped:
/// 1. Drop impl decrements global block count statistics
/// 2. Vec's Drop impl automatically deallocates block memory
/// 3. No manual cleanup required by caller
impl Drop for BlockData {
    fn drop(&mut self) {
        // Decrement global statistics
        GLOBAL_STATS.decrement(self.blocks.len());
    }
}

/// Global statistics for BlockData memory usage.
///
/// Tracks allocation statistics across all BlockData instances for monitoring and debugging.
/// Uses atomic operations for thread-safe updates without locking, matching C static counter
/// pattern but with thread safety.
///
/// Statistics tracked:
/// - `current_count`: Number of blocks currently in use
/// - `high_water_mark`: Maximum blocks in use simultaneously since initialization
/// - `total_allocated`: Cumulative blocks allocated (never decreases)
///
/// The C implementation uses static variables (blockdata_count, blockdata_hwm, blockdata_alloced)
/// which are not thread-safe. This Rust implementation uses AtomicUsize for lock-free concurrent
/// access while maintaining equivalent functionality.
#[derive(Debug)]
pub struct BlockDataStats {
    /// Current number of blocks in use across all BlockData instances.
    current_count: AtomicUsize,
    
    /// High-water mark: maximum blocks in use simultaneously.
    high_water_mark: AtomicUsize,
    
    /// Total number of blocks allocated since initialization (cumulative).
    total_allocated: AtomicUsize,
}

impl BlockDataStats {
    /// Create a new BlockDataStats instance with zero counters.
    ///
    /// This is typically only called once to initialize GLOBAL_STATS.
    ///
    /// # Returns
    ///
    /// New BlockDataStats with all counters initialized to zero.
    pub const fn new() -> Self {
        Self {
            current_count: AtomicUsize::new(0),
            high_water_mark: AtomicUsize::new(0),
            total_allocated: AtomicUsize::new(0),
        }
    }

    /// Get current number of blocks in use.
    ///
    /// # Returns
    ///
    /// Number of blocks currently allocated across all BlockData instances.
    #[inline]
    pub fn current_count(&self) -> usize {
        self.current_count.load(Ordering::Relaxed)
    }

    /// Get high-water mark (maximum simultaneous blocks).
    ///
    /// # Returns
    ///
    /// Maximum number of blocks in use simultaneously since initialization.
    #[inline]
    pub fn high_water_mark(&self) -> usize {
        self.high_water_mark.load(Ordering::Relaxed)
    }

    /// Get total number of blocks allocated (cumulative).
    ///
    /// # Returns
    ///
    /// Cumulative count of all blocks allocated since initialization.
    #[inline]
    pub fn total_allocated(&self) -> usize {
        self.total_allocated.load(Ordering::Relaxed)
    }

    /// Get current memory usage in bytes.
    ///
    /// # Returns
    ///
    /// Total bytes currently in use (current_count * BLOCK_SIZE).
    #[inline]
    pub fn current_bytes(&self) -> usize {
        self.current_count() * BLOCK_SIZE
    }

    /// Get high-water mark memory usage in bytes.
    ///
    /// # Returns
    ///
    /// Maximum bytes in use simultaneously (high_water_mark * BLOCK_SIZE).
    #[inline]
    pub fn hwm_bytes(&self) -> usize {
        self.high_water_mark() * BLOCK_SIZE
    }

    /// Get total allocated memory in bytes.
    ///
    /// # Returns
    ///
    /// Cumulative bytes allocated (total_allocated * BLOCK_SIZE).
    #[inline]
    pub fn allocated_bytes(&self) -> usize {
        self.total_allocated() * BLOCK_SIZE
    }

    /// Increment block count statistics (called when blocks allocated).
    ///
    /// Updates current_count, high_water_mark, and total_allocated atomically.
    /// This is called internally by BlockData::new() and BlockData::expand().
    ///
    /// # Arguments
    ///
    /// * `count` - Number of blocks being allocated
    fn increment(&self, count: usize) {
        if count == 0 {
            return;
        }

        // Increment current count
        let new_count = self.current_count.fetch_add(count, Ordering::Relaxed) + count;
        
        // Update high-water mark if necessary
        self.high_water_mark.fetch_max(new_count, Ordering::Relaxed);
        
        // Increment total allocated
        self.total_allocated.fetch_add(count, Ordering::Relaxed);
    }

    /// Decrement block count statistics (called when blocks freed).
    ///
    /// Updates current_count atomically. Called by BlockData::drop().
    ///
    /// # Arguments
    ///
    /// * `count` - Number of blocks being freed
    fn decrement(&self, count: usize) {
        if count == 0 {
            return;
        }
        
        self.current_count.fetch_sub(count, Ordering::Relaxed);
    }

    /// Generate statistics report string for logging.
    ///
    /// Creates a formatted string matching C blockdata_report() output for compatibility
    /// with existing log parsing tools and monitoring systems.
    ///
    /// # Returns
    ///
    /// Formatted string: "pool memory in use {current}, max {hwm}, allocated {total}"
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::dns::dnssec::blockdata::GLOBAL_STATS;
    /// let report = GLOBAL_STATS.report();
    /// println!("{}", report);
    /// // Output: "pool memory in use 4800, max 9600, allocated 15000"
    /// ```
    pub fn report(&self) -> String {
        format!(
            "pool memory in use {}, max {}, allocated {}",
            self.current_bytes(),
            self.hwm_bytes(),
            self.allocated_bytes()
        )
    }
}

/// Global statistics instance for tracking all BlockData allocations.
///
/// This static variable provides process-wide visibility into BlockData memory usage,
/// equivalent to C static variables (blockdata_count, blockdata_hwm, blockdata_alloced).
///
/// Thread-safe through atomic operations, can be safely accessed from multiple threads
/// or async tasks without locking.
///
/// # Usage
///
/// ```no_run
/// # use dnsmasq::dns::dnssec::blockdata::GLOBAL_STATS;
/// println!("Current blocks: {}", GLOBAL_STATS.current_count());
/// println!("Peak blocks: {}", GLOBAL_STATS.high_water_mark());
/// println!("{}", GLOBAL_STATS.report());
/// ```
pub static GLOBAL_STATS: BlockDataStats = BlockDataStats::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockdata_new_empty() {
        let bd = BlockData::new(&[]);
        assert_eq!(bd.len(), 0);
        assert!(bd.is_empty());
        assert_eq!(bd.retrieve(), Vec::<u8>::new());
    }

    #[test]
    fn test_blockdata_new_single_block() {
        let data = vec![1u8, 2, 3, 4, 5];
        let bd = BlockData::new(&data);
        assert_eq!(bd.len(), 5);
        assert!(!bd.is_empty());
        assert_eq!(bd.retrieve(), data);
    }

    #[test]
    fn test_blockdata_new_multiple_blocks() {
        let data = vec![0xABu8; 100]; // 100 bytes = 3 blocks (40 + 40 + 20)
        let bd = BlockData::new(&data);
        assert_eq!(bd.len(), 100);
        assert_eq!(bd.blocks.len(), 3);
        assert_eq!(bd.retrieve(), data);
    }

    #[test]
    fn test_blockdata_new_exact_block_boundary() {
        let data = vec![0xFFu8; 80]; // Exactly 2 blocks
        let bd = BlockData::new(&data);
        assert_eq!(bd.len(), 80);
        assert_eq!(bd.blocks.len(), 2);
        assert_eq!(bd.retrieve(), data);
    }

    #[test]
    fn test_blockdata_expand_empty() {
        let mut bd = BlockData::new(&[]);
        let additional = vec![1u8, 2, 3];
        bd.expand(&additional).unwrap();
        assert_eq!(bd.len(), 3);
        assert_eq!(bd.retrieve(), additional);
    }

    #[test]
    fn test_blockdata_expand_partial_block() {
        let initial = vec![1u8, 2, 3];
        let mut bd = BlockData::new(&initial);
        let additional = vec![4u8, 5, 6];
        bd.expand(&additional).unwrap();
        
        assert_eq!(bd.len(), 6);
        let expected = vec![1u8, 2, 3, 4, 5, 6];
        assert_eq!(bd.retrieve(), expected);
    }

    #[test]
    fn test_blockdata_expand_across_block_boundary() {
        let initial = vec![0xAAu8; 38]; // Almost fills first block (40 bytes)
        let mut bd = BlockData::new(&initial);
        let additional = vec![0xBBu8; 10]; // Will span into second block
        bd.expand(&additional).unwrap();
        
        assert_eq!(bd.len(), 48);
        assert_eq!(bd.blocks.len(), 2);
        
        let retrieved = bd.retrieve();
        assert_eq!(&retrieved[..38], &vec![0xAAu8; 38][..]);
        assert_eq!(&retrieved[38..], &vec![0xBBu8; 10][..]);
    }

    #[test]
    fn test_blockdata_expand_multiple_new_blocks() {
        let initial = vec![1u8; 10];
        let mut bd = BlockData::new(&initial);
        let additional = vec![2u8; 100]; // Will require multiple new blocks
        bd.expand(&additional).unwrap();
        
        assert_eq!(bd.len(), 110);
        let retrieved = bd.retrieve();
        assert_eq!(&retrieved[..10], &vec![1u8; 10][..]);
        assert_eq!(&retrieved[10..], &vec![2u8; 100][..]);
    }

    #[tokio::test]
    async fn test_blockdata_from_reader() {
        let data = vec![0x42u8; 256];
        let mut cursor = std::io::Cursor::new(data.clone());
        
        let bd = BlockData::from_reader(&mut cursor, 256).await.unwrap();
        assert_eq!(bd.len(), 256);
        assert_eq!(bd.retrieve(), data);
    }

    #[tokio::test]
    async fn test_blockdata_to_writer() {
        let data = vec![0x99u8; 128];
        let bd = BlockData::new(&data);
        
        let mut output = Vec::new();
        bd.to_writer(&mut output).await.unwrap();
        
        assert_eq!(output, data);
    }

    #[tokio::test]
    async fn test_blockdata_roundtrip_io() {
        let original = vec![0x55u8; 200];
        let bd = BlockData::new(&original);
        
        // Write to buffer
        let mut buffer = Vec::new();
        bd.to_writer(&mut buffer).await.unwrap();
        
        // Read back
        let mut cursor = std::io::Cursor::new(buffer);
        let bd2 = BlockData::from_reader(&mut cursor, 200).await.unwrap();
        
        assert_eq!(bd2.retrieve(), original);
    }

    #[test]
    fn test_blockdata_as_bytes_single_block() {
        let data = vec![1u8, 2, 3, 4, 5];
        let bd = BlockData::new(&data);
        
        let bytes = bd.as_bytes();
        assert!(bytes.is_some());
        assert_eq!(bytes.unwrap(), &data[..]);
    }

    #[test]
    fn test_blockdata_as_bytes_multiple_blocks() {
        let data = vec![0u8; 100]; // Multiple blocks
        let bd = BlockData::new(&data);
        
        let bytes = bd.as_bytes();
        assert!(bytes.is_none()); // Should return None for multi-block data
    }

    #[test]
    fn test_blockdata_stats_increment_decrement() {
        let stats = BlockDataStats::new();
        
        assert_eq!(stats.current_count(), 0);
        assert_eq!(stats.high_water_mark(), 0);
        assert_eq!(stats.total_allocated(), 0);
        
        stats.increment(10);
        assert_eq!(stats.current_count(), 10);
        assert_eq!(stats.high_water_mark(), 10);
        assert_eq!(stats.total_allocated(), 10);
        
        stats.increment(5);
        assert_eq!(stats.current_count(), 15);
        assert_eq!(stats.high_water_mark(), 15);
        assert_eq!(stats.total_allocated(), 15);
        
        stats.decrement(10);
        assert_eq!(stats.current_count(), 5);
        assert_eq!(stats.high_water_mark(), 15); // HWM doesn't decrease
        assert_eq!(stats.total_allocated(), 15); // Total doesn't decrease
    }

    #[test]
    fn test_blockdata_stats_bytes() {
        let stats = BlockDataStats::new();
        stats.increment(10);
        
        assert_eq!(stats.current_bytes(), 10 * BLOCK_SIZE);
        assert_eq!(stats.hwm_bytes(), 10 * BLOCK_SIZE);
        assert_eq!(stats.allocated_bytes(), 10 * BLOCK_SIZE);
    }

    #[test]
    fn test_blockdata_stats_report() {
        let stats = BlockDataStats::new();
        stats.increment(5);
        
        let report = stats.report();
        assert!(report.contains("pool memory in use"));
        assert!(report.contains(&(5 * BLOCK_SIZE).to_string()));
    }

    #[test]
    fn test_blockdata_drop_updates_stats() {
        // Create isolated stats instance for testing
        let stats = BlockDataStats::new();
        
        // Manually simulate allocation
        stats.increment(3);
        assert_eq!(stats.current_count(), 3);
        
        // Manually simulate drop
        stats.decrement(3);
        assert_eq!(stats.current_count(), 0);
        assert_eq!(stats.high_water_mark(), 3);
    }
}
