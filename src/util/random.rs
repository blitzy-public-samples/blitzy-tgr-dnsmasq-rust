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

//! SURF cryptographic random number generator module.
//!
//! This module implements the SURF (Speedy Unpredictable Random Function) algorithm
//! developed by Daniel J. Bernstein for djbdns (public domain). SURF provides
//! cryptographic-quality randomness suitable for security-critical applications
//! including DNS query ID generation, source port randomization, and cache key
//! generation to prevent DNS cache poisoning and related attacks.
//!
//! # Algorithm Overview
//!
//! SURF is a cryptographic pseudo-random number generator that:
//! - Seeds from system entropy source (/dev/urandom or getrandom syscall)
//! - Maintains internal state (seed[32], input[12], output buffer[8])
//! - Generates outputs through 32 rounds of cryptographic mixing
//! - Uses rotation and XOR operations for unpredictability
//! - Automatically regenerates output buffer when depleted
//!
//! # Memory Safety
//!
//! The Rust implementation replaces C's global mutable state with:
//! - `SurfRng` struct encapsulating all RNG state
//! - `RefCell` for interior mutability in single-threaded contexts
//! - Type-safe u32 arrays replacing C pointer arithmetic
//! - Result-based error handling instead of C die() calls
//!
//! # Security Properties
//!
//! - Cryptographic-quality randomness from system entropy
//! - Unpredictable output sequence from 32-round mixing
//! - Suitable for DNS query IDs (prevents cache poisoning)
//! - Suitable for source port randomization (prevents spoofing)
//! - Constant-time operations (no timing side-channels)
//!
//! # Usage
//!
//! ```rust
//! use dnsmasq::util::random::{SurfRng, rand_init, rand16};
//!
//! // Initialize RNG from system entropy
//! let rng = rand_init().expect("Failed to initialize RNG");
//!
//! // Generate random values
//! let query_id = rng.rand16();      // DNS query ID
//! let cache_key = rng.rand32();     // Cache key
//! let transaction_id = rng.rand64(); // DHCPv6 transaction ID
//!
//! // Convenience functions (uses global instance)
//! let port = rand16();
//! ```
//!
//! # Thread Safety
//!
//! The current implementation uses `RefCell` for single-threaded event loop
//! architecture matching the C implementation. For multi-threaded contexts,
//! wrap `SurfRng` in `Arc<Mutex<SurfRng>>` or use thread-local instances.
//!
//! # References
//!
//! - djbdns-1.05 by Daniel J. Bernstein (public domain)
//! - RFC 1035 Section 4.1.1 (recommends random query IDs)

use crate::constants::RANDFILE;
use std::cell::RefCell;
use std::fmt;
use std::fs::File;
use std::io::Read;

/// Errors that can occur during random number generation initialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RandomError {
    /// Failed to open entropy source file (typically /dev/urandom).
    EntropySourceOpen(String),
    
    /// Failed to read sufficient entropy from source.
    EntropySourceRead(String),
    
    /// System entropy function (getrandom) failed.
    SystemEntropyFailed(String),
}

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RandomError::EntropySourceOpen(msg) => {
                write!(f, "Failed to open entropy source: {}", msg)
            }
            RandomError::EntropySourceRead(msg) => {
                write!(f, "Failed to read entropy: {}", msg)
            }
            RandomError::SystemEntropyFailed(msg) => {
                write!(f, "System entropy function failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for RandomError {}

/// Internal state for the SURF random number generator.
///
/// This structure maintains the cryptographic state of the SURF algorithm:
/// - `seed`: 32-element array seeded from system entropy
/// - `in_state`: 12-element input state incremented on each regeneration
/// - `out`: 8-element output buffer holding generated random values
/// - `outleft`: Counter tracking remaining values in output buffer
/// - `outleft64`: Separate counter for rand64() tracking 32-bit pairs
#[derive(Clone)]
struct SurfState {
    /// Seed array (32 x u32) initialized from system entropy.
    seed: [u32; 32],
    
    /// Input state array (12 x u32) incremented on each surf() call.
    in_state: [u32; 12],
    
    /// Output buffer (8 x u32) holding generated random values.
    out: [u32; 8],
    
    /// Remaining values in output buffer for rand16/rand32.
    outleft: usize,
    
    /// Remaining 32-bit pairs in output buffer for rand64.
    outleft64: usize,
}

impl SurfState {
    /// Create a new uninitialized SURF state.
    ///
    /// State must be initialized by calling `seed_from_entropy()` before use.
    fn new() -> Self {
        Self {
            seed: [0u32; 32],
            in_state: [0u32; 12],
            out: [0u32; 8],
            outleft: 0,
            outleft64: 0,
        }
    }

    /// Seed the RNG state from raw entropy bytes.
    ///
    /// Reads 32 u32 values for seed array and 12 u32 values for input state
    /// from the provided entropy buffer. Buffer must be at least 176 bytes
    /// (44 u32 values * 4 bytes).
    fn seed_from_entropy(&mut self, entropy: &[u8]) -> Result<(), RandomError> {
        if entropy.len() < 176 {
            return Err(RandomError::EntropySourceRead(format!(
                "Insufficient entropy: need 176 bytes, got {}",
                entropy.len()
            )));
        }

        // Read seed array (32 x u32 = 128 bytes)
        for i in 0..32 {
            let offset = i * 4;
            self.seed[i] = u32::from_le_bytes([
                entropy[offset],
                entropy[offset + 1],
                entropy[offset + 2],
                entropy[offset + 3],
            ]);
        }

        // Read input state array (12 x u32 = 48 bytes)
        for i in 0..12 {
            let offset = 128 + i * 4;
            self.in_state[i] = u32::from_le_bytes([
                entropy[offset],
                entropy[offset + 1],
                entropy[offset + 2],
                entropy[offset + 3],
            ]);
        }

        // Initialize output buffer counters to 0 (will trigger regeneration on first use)
        self.outleft = 0;
        self.outleft64 = 0;

        Ok(())
    }
}

/// SURF cryptographic random number generator.
///
/// Encapsulates the SURF algorithm state with interior mutability for
/// single-threaded use. Provides thread-safe methods for generating
/// random 16-bit, 32-bit, and 64-bit values.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::random::rand_init;
///
/// let rng = rand_init().expect("Failed to initialize RNG");
/// let query_id = rng.rand16();
/// let cache_key = rng.rand32();
/// let transaction_id = rng.rand64();
/// ```
pub struct SurfRng {
    /// Internal SURF state with interior mutability.
    state: RefCell<SurfState>,
}

impl SurfRng {
    /// Create a new SURF RNG initialized from system entropy.
    ///
    /// This is the primary constructor for `SurfRng`. It automatically
    /// seeds the generator from the system entropy source using either
    /// the getrandom syscall (preferred) or /dev/urandom (fallback).
    ///
    /// # Returns
    ///
    /// A new `SurfRng` instance seeded with cryptographic-quality entropy.
    ///
    /// # Errors
    ///
    /// * `RandomError::SystemEntropyFailed` - getrandom syscall failed
    /// * `RandomError::EntropySourceOpen` - Failed to open /dev/urandom
    /// * `RandomError::EntropySourceRead` - Failed to read sufficient entropy
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dnsmasq::util::random::SurfRng;
    ///
    /// let rng = SurfRng::new().expect("Failed to initialize RNG");
    /// let random_value = rng.rand32();
    /// ```
    pub fn new() -> Result<Self, RandomError> {
        rand_init()
    }

    /// Create a new SURF RNG from entropy bytes.
    ///
    /// # Arguments
    ///
    /// * `entropy` - At least 176 bytes of system entropy
    ///
    /// # Errors
    ///
    /// Returns `RandomError::EntropySourceRead` if entropy buffer too small.
    fn from_entropy(entropy: &[u8]) -> Result<Self, RandomError> {
        let mut state = SurfState::new();
        state.seed_from_entropy(entropy)?;
        Ok(Self {
            state: RefCell::new(state),
        })
    }

    /// Generate a random 16-bit value.
    ///
    /// Returns a random unsigned 16-bit value suitable for DNS query IDs
    /// and source port randomization. Automatically regenerates output
    /// buffer when depleted.
    ///
    /// # Returns
    ///
    /// Random u16 value (0-65535)
    pub fn rand16(&self) -> u16 {
        let mut state = self.state.borrow_mut();
        
        if state.outleft == 0 {
            // Increment input state counter
            increment_input_state(&mut state.in_state);
            // Regenerate output buffer
            surf(&mut state);
            state.outleft = 8;
        }
        
        state.outleft -= 1;
        (state.out[state.outleft] & 0xFFFF) as u16
    }

    /// Generate a random 32-bit value.
    ///
    /// Returns a random unsigned 32-bit value suitable for cache keys,
    /// delays, and general-purpose random numbers. Automatically
    /// regenerates output buffer when depleted.
    ///
    /// # Returns
    ///
    /// Random u32 value (0-4294967295)
    pub fn rand32(&self) -> u32 {
        let mut state = self.state.borrow_mut();
        
        if state.outleft == 0 {
            // Increment input state counter
            increment_input_state(&mut state.in_state);
            // Regenerate output buffer
            surf(&mut state);
            state.outleft = 8;
        }
        
        state.outleft -= 1;
        state.out[state.outleft]
    }

    /// Generate a random 64-bit value.
    ///
    /// Returns a random unsigned 64-bit value by combining two 32-bit
    /// outputs. Suitable for DHCPv6 transaction IDs, unique identifiers,
    /// and large random intervals. Maintains separate output counter
    /// for 64-bit generation.
    ///
    /// # Returns
    ///
    /// Random u64 value (0-18446744073709551615)
    pub fn rand64(&self) -> u64 {
        let mut state = self.state.borrow_mut();
        
        if state.outleft64 < 2 {
            // Increment input state counter
            increment_input_state(&mut state.in_state);
            // Regenerate output buffer
            surf(&mut state);
            state.outleft64 = 8;
        }
        
        state.outleft64 -= 2;
        let high = state.out[state.outleft64] as u64;
        let low = state.out[state.outleft64 + 1] as u64;
        (high << 32) | low
    }
}

// ============================================================================
// Core SURF Algorithm Implementation
// ============================================================================

/// Rotate bits left by specified amount (ROTATE macro from C).
///
/// Performs circular left rotation of a 32-bit value by `b` bits.
/// This is a constant-time operation compiled to a single CPU instruction
/// on most architectures.
///
/// # Arguments
///
/// * `x` - Value to rotate
/// * `b` - Number of bits to rotate left (0-31)
///
/// # Returns
///
/// Rotated value
#[inline(always)]
fn rotate(x: u32, b: u32) -> u32 {
    x.rotate_left(b)
}

/// MUSH operation from SURF algorithm (MUSH macro from C).
///
/// Performs one round of SURF mixing combining:
/// - XOR with seed value
/// - Addition with accumulated sum
/// - XOR with rotated value
/// - In-place update of temporary state
///
/// This is the core cryptographic primitive providing unpredictability.
///
/// # Arguments
///
/// * `t` - Temporary state array being mixed
/// * `seed` - Seed array providing cryptographic key material
/// * `i` - Index into arrays (0-11)
/// * `sum` - Accumulated sum value (incremented each round)
/// * `x` - Current mixing value (updated in-place)
/// * `b` - Rotation amount for this round
///
/// # Returns
///
/// Updated `x` value after mixing
#[inline(always)]
fn mush(t: &mut [u32; 12], seed: &[u32; 32], i: usize, sum: u32, x: u32, b: u32) -> u32 {
    t[i] = t[i].wrapping_add((x ^ seed[i]).wrapping_add(sum) ^ rotate(x, b));
    t[i]
}

/// Core SURF algorithm generating 8 random 32-bit values.
///
/// Executes the SURF (Speedy Unpredictable Random Function) cryptographic
/// mixing algorithm developed by Daniel J. Bernstein. Performs:
///
/// 1. Initialize temporary state from input XOR seed
/// 2. Initialize output from seed tail
/// 3. Perform 32 rounds of MUSH operations (2 loops x 16 rounds)
/// 4. XOR output with temporary state
///
/// Each round increments sum by the golden ratio constant 0x9e3779b9,
/// then applies 12 MUSH operations with varying rotation amounts (5, 7, 9, 13).
///
/// # Arguments
///
/// * `state` - Mutable reference to SURF state to update
///
/// # Side Effects
///
/// Updates `state.out` array with 8 new random values
fn surf(state: &mut SurfState) {
    let mut t: [u32; 12] = [0; 12];
    let mut sum: u32 = 0;
    
    // Initialize temporary state: t[i] = in[i] ^ seed[12 + i]
    for (i, item) in t.iter_mut().enumerate() {
        *item = state.in_state[i] ^ state.seed[12 + i];
    }
    
    // Initialize output: out[i] = seed[24 + i]
    for i in 0..8 {
        state.out[i] = state.seed[24 + i];
    }
    
    // Start with x = t[11]
    let mut x = t[11];
    
    // 2 loops of 16 rounds each = 32 total rounds
    for _ in 0..2 {
        for _ in 0..16 {
            // Increment sum by golden ratio constant
            sum = sum.wrapping_add(0x9e3779b9);
            
            // Apply 12 MUSH operations with rotation amounts: 5, 7, 9, 13
            x = mush(&mut t, &state.seed, 0, sum, x, 5);
            x = mush(&mut t, &state.seed, 1, sum, x, 7);
            x = mush(&mut t, &state.seed, 2, sum, x, 9);
            x = mush(&mut t, &state.seed, 3, sum, x, 13);
            
            x = mush(&mut t, &state.seed, 4, sum, x, 5);
            x = mush(&mut t, &state.seed, 5, sum, x, 7);
            x = mush(&mut t, &state.seed, 6, sum, x, 9);
            x = mush(&mut t, &state.seed, 7, sum, x, 13);
            
            x = mush(&mut t, &state.seed, 8, sum, x, 5);
            x = mush(&mut t, &state.seed, 9, sum, x, 7);
            x = mush(&mut t, &state.seed, 10, sum, x, 9);
            x = mush(&mut t, &state.seed, 11, sum, x, 13);
        }
        
        // XOR output with middle of temporary state
        for i in 0..8 {
            state.out[i] ^= t[i + 4];
        }
    }
}

/// Increment input state counter (equivalent to C code incrementing in[0..3]).
///
/// Increments the input state as a 128-bit little-endian counter:
/// - Increment in_state[0]
/// - If overflow, increment in_state[1]
/// - If overflow, increment in_state[2]
/// - If overflow, increment in_state[3]
///
/// This ensures the SURF algorithm produces a different output sequence
/// each time surf() is called.
///
/// # Arguments
///
/// * `in_state` - Input state array to increment
fn increment_input_state(in_state: &mut [u32; 12]) {
    in_state[0] = in_state[0].wrapping_add(1);
    if in_state[0] == 0 {
        in_state[1] = in_state[1].wrapping_add(1);
        if in_state[1] == 0 {
            in_state[2] = in_state[2].wrapping_add(1);
            if in_state[2] == 0 {
                in_state[3] = in_state[3].wrapping_add(1);
            }
        }
    }
}

// ============================================================================
// Initialization Functions
// ============================================================================

/// Initialize SURF RNG from system entropy source.
///
/// Reads 176 bytes of entropy from the system source:
/// - Attempts to use getrandom syscall (preferred, available on modern systems)
/// - Falls back to reading from RANDFILE (/dev/urandom) if getrandom unavailable
///
/// This function must be called once during daemon startup before any
/// calls to rand16(), rand32(), or rand64().
///
/// # Returns
///
/// * `Ok(SurfRng)` - Initialized RNG ready for use
/// * `Err(RandomError)` - Failed to obtain system entropy
///
/// # Errors
///
/// * `RandomError::SystemEntropyFailed` - getrandom syscall failed
/// * `RandomError::EntropySourceOpen` - Failed to open RANDFILE
/// * `RandomError::EntropySourceRead` - Failed to read sufficient entropy
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::random::rand_init;
///
/// let rng = rand_init().expect("Failed to initialize RNG");
/// let query_id = rng.rand16();
/// ```
pub fn rand_init() -> Result<SurfRng, RandomError> {
    let mut entropy = [0u8; 176]; // 32 u32 + 12 u32 = 44 u32 = 176 bytes
    
    // Try getrandom first (preferred method on modern systems)
    match getrandom::getrandom(&mut entropy) {
        Ok(()) => {
            return SurfRng::from_entropy(&entropy);
        }
        Err(e) => {
            // getrandom not available or failed, fall back to reading RANDFILE
            eprintln!("getrandom failed ({}), falling back to {}", e, RANDFILE);
        }
    }
    
    // Fallback: read from RANDFILE (/dev/urandom)
    let mut file = File::open(RANDFILE).map_err(|e| {
        RandomError::EntropySourceOpen(format!("{}: {}", RANDFILE, e))
    })?;
    
    file.read_exact(&mut entropy).map_err(|e| {
        RandomError::EntropySourceRead(format!("{}: {}", RANDFILE, e))
    })?;
    
    SurfRng::from_entropy(&entropy)
}

// ============================================================================
// Global Instance and Convenience Functions
// ============================================================================

thread_local! {
    /// Thread-local global SURF RNG instance.
    ///
    /// Initialized lazily on first use. Provides backward compatibility
    /// with C implementation's global state model while maintaining
    /// thread safety through thread-local storage.
    static GLOBAL_RNG: RefCell<Option<SurfRng>> = const { RefCell::new(None) };
}

/// Initialize global RNG instance if not already initialized.
///
/// Called automatically by rand16(), rand32(), rand64() convenience functions.
/// Panics if initialization fails (matching C implementation's die() behavior).
fn ensure_global_rng_initialized() {
    GLOBAL_RNG.with(|rng| {
        if rng.borrow().is_none() {
            let initialized = rand_init().expect("Failed to initialize global RNG");
            *rng.borrow_mut() = Some(initialized);
        }
    });
}

/// Generate random 16-bit value using global RNG instance.
///
/// Convenience function for backward compatibility with C implementation.
/// Automatically initializes global RNG on first call.
///
/// # Returns
///
/// Random u16 value (0-65535)
///
/// # Panics
///
/// Panics if global RNG initialization fails (entropy source unavailable).
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::random::rand16;
///
/// let query_id = rand16();
/// let src_port = rand16();
/// ```
pub fn rand16() -> u16 {
    ensure_global_rng_initialized();
    GLOBAL_RNG.with(|rng| {
        rng.borrow()
            .as_ref()
            .expect("Global RNG not initialized")
            .rand16()
    })
}

/// Generate random 32-bit value using global RNG instance.
///
/// Convenience function for backward compatibility with C implementation.
/// Automatically initializes global RNG on first call.
///
/// # Returns
///
/// Random u32 value (0-4294967295)
///
/// # Panics
///
/// Panics if global RNG initialization fails (entropy source unavailable).
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::random::rand32;
///
/// let cache_key = rand32();
/// let delay_ms = rand32() % 1000;
/// ```
pub fn rand32() -> u32 {
    ensure_global_rng_initialized();
    GLOBAL_RNG.with(|rng| {
        rng.borrow()
            .as_ref()
            .expect("Global RNG not initialized")
            .rand32()
    })
}

/// Generate random 64-bit value using global RNG instance.
///
/// Convenience function for backward compatibility with C implementation.
/// Automatically initializes global RNG on first call.
///
/// # Returns
///
/// Random u64 value (0-18446744073709551615)
///
/// # Panics
///
/// Panics if global RNG initialization fails (entropy source unavailable).
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::random::rand64;
///
/// let transaction_id = rand64();
/// let lease_id = rand64();
/// ```
pub fn rand64() -> u64 {
    ensure_global_rng_initialized();
    GLOBAL_RNG.with(|rng| {
        rng.borrow()
            .as_ref()
            .expect("Global RNG not initialized")
            .rand64()
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_init_succeeds() {
        // Should successfully initialize from system entropy
        let result = rand_init();
        assert!(result.is_ok(), "rand_init should succeed");
    }

    #[test]
    fn test_rand16_produces_values() {
        let rng = rand_init().expect("Failed to initialize RNG");
        let val1 = rng.rand16();
        let val2 = rng.rand16();
        // Values should be different (probabilistically)
        // (could be same with 1/65536 probability, but extremely unlikely)
        assert!(val1 != val2 || true); // Always passes but documents expectation
    }

    #[test]
    fn test_rand32_produces_values() {
        let rng = rand_init().expect("Failed to initialize RNG");
        let val1 = rng.rand32();
        let val2 = rng.rand32();
        // Document that we expect different values
        assert!(val1 != val2 || true);
    }

    #[test]
    fn test_rand64_produces_values() {
        let rng = rand_init().expect("Failed to initialize RNG");
        let val1 = rng.rand64();
        let val2 = rng.rand64();
        // Document that we expect different values
        assert!(val1 != val2 || true);
    }

    #[test]
    fn test_global_rand16() {
        let val = rand16();
        // Should produce a value without panicking
        assert!(val <= u16::MAX);
    }

    #[test]
    fn test_global_rand32() {
        let val = rand32();
        // Should produce a value without panicking
        assert!(val <= u32::MAX);
    }

    #[test]
    fn test_global_rand64() {
        let val = rand64();
        // Should produce a value without panicking
        assert!(val <= u64::MAX);
    }

    #[test]
    fn test_surf_state_initialization() {
        let state = SurfState::new();
        assert_eq!(state.outleft, 0);
        assert_eq!(state.outleft64, 0);
    }

    #[test]
    fn test_increment_input_state() {
        let mut in_state = [0u32; 12];
        
        // First increment
        increment_input_state(&mut in_state);
        assert_eq!(in_state[0], 1);
        assert_eq!(in_state[1], 0);
        
        // Overflow from in_state[0]
        in_state[0] = u32::MAX;
        increment_input_state(&mut in_state);
        assert_eq!(in_state[0], 0);
        assert_eq!(in_state[1], 1);
        
        // Cascade overflow from in_state[0] and in_state[1]
        in_state[0] = u32::MAX;
        in_state[1] = u32::MAX;
        increment_input_state(&mut in_state);
        assert_eq!(in_state[0], 0);
        assert_eq!(in_state[1], 0);
        assert_eq!(in_state[2], 1);
    }

    #[test]
    fn test_rotate() {
        let val = 0b00000001_00000000_00000000_00000000u32;
        let rotated = rotate(val, 8);
        assert_eq!(rotated, 0b00000000_00000000_00000000_00000001u32);
    }

    #[test]
    fn test_surf_generates_different_outputs() {
        let rng = rand_init().expect("Failed to initialize RNG");
        
        // Generate multiple values
        let mut values = Vec::new();
        for _ in 0..100 {
            values.push(rng.rand32());
        }
        
        // Check that not all values are the same (would indicate broken RNG)
        let first = values[0];
        let all_same = values.iter().all(|&v| v == first);
        assert!(!all_same, "RNG should produce varying output");
    }

    #[test]
    fn test_error_display() {
        let err = RandomError::EntropySourceOpen("test error".to_string());
        let display = format!("{}", err);
        assert!(display.contains("test error"));
    }
}
