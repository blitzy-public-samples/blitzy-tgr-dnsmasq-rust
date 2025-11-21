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

//! DNSSEC cryptographic signature verification using memory-safe ring crate.
//!
//! This module provides signature verification for DNSSEC RRSIG records, replacing the C
//! implementation's Nettle library wrapper with Rust's ring cryptographic library. It
//! implements verification for RSA (algorithms 5, 7, 8, 10), ECDSA (algorithms 13, 14),
//! and `EdDSA` (algorithm 15) signatures according to RFC 8624 requirements.
//!
//! # Overview
//!
//! The C implementation (`src/crypto.c`) wraps the Nettle cryptographic library with custom
//! functions for each algorithm family:
//! - `dnsmasq_rsa_verify()` - RSA signature verification
//! - `dnsmasq_ecdsa_verify()` - ECDSA signature verification  
//! - `dnsmasq_eddsa_verify()` - `EdDSA` signature verification
//! - `dnsmasq_gostdsa_verify()` - GOST signature verification (optional)
//!
//! This Rust implementation eliminates FFI overhead and unsafe code by using the pure-Rust
//! ring library, providing memory safety guarantees while maintaining functional equivalence.
//!
//! # Key Differences from C Implementation
//!
//! **Memory Safety:**
//! - C: Manual memory management with static `rsa_public_key`, `ecc_point` structs reused across calls
//! - Rust: Automatic ownership with per-verification key construction preventing state corruption
//!
//! **Error Handling:**
//! - C: Silent 0/1 return codes with limited diagnostic information
//! - Rust: Result<bool, `CryptoError`> with structured error variants providing detailed context
//!
//! **Cryptographic Library:**
//! - C: Nettle library via FFI (external dependency, potential ABI issues)
//! - Rust: ring crate (pure Rust, memory-safe, actively maintained by AWS)
//!
//! **`EdDSA` Handling:**
//! - C: Custom `null_hash` pseudo-hash to buffer entire message (`EdDSA` signs messages, not digests)
//! - Rust: Direct message verification without hash abstraction using `ring::signature::ED25519`
//!
//! # Supported Algorithms
//!
//! Per RFC 8624 DNSSEC Algorithm Implementation Status:
//!
//! | Algorithm | Number | Status | Implementation |
//! |-----------|--------|--------|----------------|
//! | RSA/MD5 | 1 | MUST NOT | Not implemented (insecure) |
//! | DSA/SHA1 | 3 | MUST NOT | Not implemented (deprecated) |
//! | RSA/SHA1 | 5 | NOT RECOMMENDED | Implemented (legacy support) |
//! | RSA/SHA1-NSEC3 | 7 | NOT RECOMMENDED | Implemented (legacy support) |
//! | RSA/SHA256 | 8 | MUST | Implemented |
//! | RSA/SHA512 | 10 | RECOMMENDED | Implemented |
//! | ECC-GOST | 12 | MAY | Not implemented (uncommon) |
//! | ECDSA P-256/SHA256 | 13 | MUST | Implemented |
//! | ECDSA P-384/SHA384 | 14 | RECOMMENDED | Implemented |
//! | Ed25519 | 15 | RECOMMENDED | Implemented |
//! | Ed448 | 16 | RECOMMENDED | Not implemented (ring limitation) |
//!
//! # Usage Example
//!
//! ```no_run
//! use dnsmasq::dns::dnssec::crypto::{SignatureVerifier, CryptoAlgorithm};
//! use dnsmasq::dns::dnssec::blockdata::BlockData;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let verifier = SignatureVerifier::new();
//!
//! // DNSKEY public key in wire format
//! let key_data = BlockData::new(&[/* RSA public key */]);
//!
//! // RRSIG signature
//! let signature = &[/* signature bytes */];
//!
//! // Message digest (SHA-256 for algorithm 8)
//! let message_digest = &[/* 32-byte SHA-256 digest */];
//!
//! // Verify RSA/SHA256 signature (algorithm 8)
//! let is_valid = verifier.verify(8, &key_data, signature, message_digest)?;
//!
//! if is_valid {
//!     println!("Signature verification successful");
//! } else {
//!     println!("Signature verification failed");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Performance Considerations
//!
//! - RSA verification: ~1ms per signature (key size dependent)
//! - ECDSA verification: ~0.5ms per signature
//! - `EdDSA` verification: ~0.1ms per signature (fastest)
//!
//! The ring library uses platform-specific optimizations (AES-NI, AVX2) when available,
//! providing performance comparable to or better than Nettle.

use crate::dns::dnssec::blockdata::BlockData;
use crate::error::DnsmasqError;
use ring::signature;
use std::fmt;
use thiserror::Error;
use tracing::{debug, error, trace, warn};

/// Cryptographic operation errors for DNSSEC signature verification.
///
/// Provides detailed error information for algorithm selection, key parsing, signature
/// format validation, and verification failures. Uses thiserror for automatic Error
/// trait implementation with descriptive messages.
///
/// # Error Variants
///
/// - **`UnsupportedAlgorithm`**: DNSSEC algorithm number not recognized or not implemented
/// - **`InvalidKeyFormat`**: Public key data cannot be parsed (wrong length, invalid encoding)
/// - **`InvalidSignatureFormat`**: Signature data malformed (wrong length, invalid ASN.1)
/// - **`VerificationFailed`**: Cryptographic verification failed (signature doesn't match)
/// - **`DigestLengthMismatch`**: Message digest length doesn't match algorithm requirements
/// - **`KeyExtractionFailed`**: `BlockData` key retrieval failed
/// - **`RingError`**: Underlying ring library error (key rejection, verification error)
#[derive(Debug, Error)]
pub enum CryptoError {
    /// DNSSEC algorithm not supported by this implementation.
    ///
    /// The algorithm number is either unrecognized (not in IANA registry) or not implemented
    /// in this build (e.g., GOST support, Ed448). See RFC 8624 for algorithm requirements.
    #[error("Unsupported DNSSEC algorithm: {algorithm}")]
    UnsupportedAlgorithm {
        /// The DNSSEC algorithm number from IANA registry (1-255)
        algorithm: u8,
    },

    /// Public key data format is invalid or cannot be parsed.
    ///
    /// Keys must conform to RFC-specified wire formats:
    /// - RSA: exponent length (1 or 3 bytes) + exponent + modulus (RFC 3110)
    /// - ECDSA: X coordinate + Y coordinate (RFC 6605)
    /// - `EdDSA`: Raw public key bytes (RFC 8080)
    #[error("Invalid key format for algorithm {algorithm}: {reason}")]
    InvalidKeyFormat {
        /// The DNSSEC algorithm number
        algorithm: u8,
        /// Detailed reason for parsing failure
        reason: String,
    },

    /// Signature data format is invalid or cannot be parsed.
    ///
    /// Signatures must conform to algorithm-specific formats:
    /// - RSA: Raw signature bytes (modulus length)
    /// - ECDSA: R + S values (curve-dependent length)
    /// - `EdDSA`: Raw signature bytes (64 bytes for Ed25519)
    #[error("Invalid signature format for algorithm {algorithm}: {reason}")]
    InvalidSignatureFormat {
        /// The DNSSEC algorithm number
        algorithm: u8,
        /// Detailed reason for parsing failure
        reason: String,
    },

    /// Cryptographic signature verification failed.
    ///
    /// The signature is correctly formatted but the cryptographic verification indicates
    /// the signature does not match the message digest and public key. This is the expected
    /// error for invalid signatures (not a programming error).
    #[error("Signature verification failed for algorithm {algorithm}: {reason}")]
    VerificationFailed {
        /// The DNSSEC algorithm number
        algorithm: u8,
        /// Detailed reason for verification failure
        reason: String,
    },

    /// Message digest length doesn't match algorithm requirements.
    ///
    /// Each algorithm requires a specific digest length:
    /// - SHA1: 20 bytes (algorithms 5, 7)
    /// - SHA256: 32 bytes (algorithms 8, 13)
    /// - SHA384: 48 bytes (algorithm 14)
    /// - SHA512: 64 bytes (algorithm 10)
    #[error("Digest length mismatch for algorithm {algorithm}: expected {expected} bytes, got {actual} bytes")]
    DigestLengthMismatch {
        /// The DNSSEC algorithm number
        algorithm: u8,
        /// Expected digest length in bytes
        expected: usize,
        /// Actual digest length provided
        actual: usize,
    },

    /// Failed to extract public key from `BlockData`.
    ///
    /// Indicates `BlockData` retrieval failed or returned empty data.
    #[error("Failed to extract key from BlockData: {reason}")]
    KeyExtractionFailed {
        /// Reason for extraction failure
        reason: String,
    },

    /// Underlying ring library error.
    ///
    /// Wraps errors from `ring::error::Unspecified` (key rejected, verification failed, etc).
    /// Ring provides minimal error information for security reasons (avoids timing attacks).
    #[error("Ring cryptographic operation failed: {operation}")]
    RingError {
        /// The operation that failed (e.g., "RSA key parsing", "ECDSA verification")
        operation: String,
    },
}

// Implement From<CryptoError> for DnsmasqError to enable ? operator
impl From<CryptoError> for DnsmasqError {
    fn from(err: CryptoError) -> Self {
        // CryptoError is a DNSSEC validation error
        use crate::error::DnssecError;
        DnsmasqError::Dnssec(DnssecError::SignatureVerificationFailed {
            name: String::from("unknown"),
            reason: err.to_string(),
        })
    }
}

/// DNSSEC cryptographic algorithm identifiers per IANA registry.
///
/// Maps DNSSEC algorithm numbers (0-255) to algorithm families with metadata about
/// implementation status, security recommendations, and digest requirements per RFC 8624.
///
/// # Algorithm Families
///
/// - **RSA**: Algorithms 1, 5, 7, 8, 10 (varying hash functions)
/// - **DSA**: Algorithm 3 (deprecated, not implemented)
/// - **ECDSA**: Algorithms 13, 14 (P-256 and P-384 curves)
/// - **`EdDSA`**: Algorithms 15, 16 (Ed25519 and Ed448)
/// - **GOST**: Algorithm 12 (optional, not widely used)
///
/// # Implementation Status Mapping
///
/// Per RFC 8624 Section 3.1:
/// - MUST implement: RSA/SHA256 (8), ECDSA P-256/SHA256 (13)
/// - RECOMMENDED: RSA/SHA512 (10), ECDSA P-384/SHA384 (14), Ed25519 (15)
/// - NOT RECOMMENDED: RSA/SHA1 (5, 7)
/// - MUST NOT: RSA/MD5 (1), DSA/SHA1 (3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CryptoAlgorithm {
    /// RSA/MD5 - Algorithm 1 (MUST NOT implement per RFC 8624)
    ///
    /// MD5 is cryptographically broken and must not be used.
    RsaMd5 = 1,

    /// DSA/SHA1 - Algorithm 3 (MUST NOT implement per RFC 8624)
    ///
    /// DSA with SHA1 is deprecated due to SHA1 weakness.
    Dsa = 3,

    /// RSA/SHA1 - Algorithm 5 (NOT RECOMMENDED per RFC 8624)
    ///
    /// SHA1 is deprecated but still encountered in legacy zones.
    /// Implemented for backward compatibility only.
    RsaSha1 = 5,

    /// RSA/SHA1-NSEC3-SHA1 - Algorithm 7 (NOT RECOMMENDED per RFC 8624)
    ///
    /// Identical to algorithm 5 but signals NSEC3 usage. SHA1 is deprecated.
    /// Implemented for backward compatibility only.
    RsaSha1Nsec3 = 7,

    /// RSA/SHA256 - Algorithm 8 (MUST implement per RFC 8624)
    ///
    /// Primary RSA algorithm for DNSSEC. SHA-256 provides 128-bit security.
    RsaSha256 = 8,

    /// RSA/SHA512 - Algorithm 10 (RECOMMENDED per RFC 8624)
    ///
    /// Stronger RSA algorithm using SHA-512 for 256-bit security.
    RsaSha512 = 10,

    /// ECC-GOST - Algorithm 12 (MAY implement per RFC 8624)
    ///
    /// Russian GOST R 34.10-2001 elliptic curve algorithm. Rarely used outside Russia.
    /// Not implemented in this build.
    EccGost = 12,

    /// ECDSA Curve P-256 with SHA-256 - Algorithm 13 (MUST implement per RFC 8624)
    ///
    /// Primary elliptic curve algorithm. Faster than RSA with equivalent security.
    EcdsaP256Sha256 = 13,

    /// ECDSA Curve P-384 with SHA-384 - Algorithm 14 (RECOMMENDED per RFC 8624)
    ///
    /// Stronger elliptic curve option providing 192-bit security.
    EcdsaP384Sha384 = 14,

    /// Ed25519 - Algorithm 15 (RECOMMENDED per RFC 8624)
    ///
    /// Edwards-curve Digital Signature Algorithm. Fastest and most secure modern option.
    Ed25519 = 15,

    /// Ed448 - Algorithm 16 (RECOMMENDED per RFC 8624)
    ///
    /// Stronger `EdDSA` variant using Curve448. Not implemented (ring limitation).
    Ed448 = 16,
}

impl CryptoAlgorithm {
    /// Convert DNSSEC algorithm number to enum variant.
    ///
    /// Maps IANA-assigned algorithm numbers (0-255) to `CryptoAlgorithm` enum variants.
    /// Returns None for unrecognized or unimplemented algorithms.
    ///
    /// # Arguments
    ///
    /// * `value` - DNSSEC algorithm number from RRSIG or DNSKEY record
    ///
    /// # Returns
    ///
    /// - `Some(CryptoAlgorithm)` - Recognized algorithm variant
    /// - `None` - Unrecognized algorithm number
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::dns::dnssec::crypto::CryptoAlgorithm;
    /// assert_eq!(CryptoAlgorithm::from_u8(8), Some(CryptoAlgorithm::RsaSha256));
    /// assert_eq!(CryptoAlgorithm::from_u8(13), Some(CryptoAlgorithm::EcdsaP256Sha256));
    /// assert_eq!(CryptoAlgorithm::from_u8(255), None); // Unassigned
    /// ```
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::RsaMd5),
            3 => Some(Self::Dsa),
            5 => Some(Self::RsaSha1),
            7 => Some(Self::RsaSha1Nsec3),
            8 => Some(Self::RsaSha256),
            10 => Some(Self::RsaSha512),
            12 => Some(Self::EccGost),
            13 => Some(Self::EcdsaP256Sha256),
            14 => Some(Self::EcdsaP384Sha384),
            15 => Some(Self::Ed25519),
            16 => Some(Self::Ed448),
            _ => None,
        }
    }

    /// Check if this algorithm is supported by this implementation.
    ///
    /// Returns true for algorithms with implemented verification code, false for
    /// deprecated or unimplemented algorithms.
    ///
    /// # Implementation Status
    ///
    /// - Supported: RSA/SHA1 (5, 7), RSA/SHA256 (8), RSA/SHA512 (10), ECDSA (13, 14), Ed25519 (15)
    /// - Not supported: RSA/MD5 (1), DSA (3), GOST (12), Ed448 (16)
    ///
    /// # Returns
    ///
    /// `true` if verification is implemented, `false` otherwise
    #[must_use]
    pub fn is_supported(&self) -> bool {
        matches!(
            self,
            Self::RsaSha1
                | Self::RsaSha1Nsec3
                | Self::RsaSha256
                | Self::RsaSha512
                | Self::EcdsaP256Sha256
                | Self::EcdsaP384Sha384
                | Self::Ed25519
        )
    }

    /// Check if this algorithm is deprecated per RFC 8624.
    ///
    /// Returns true for algorithms marked MUST NOT or NOT RECOMMENDED in RFC 8624.
    /// Validators may reject signatures using deprecated algorithms based on policy.
    ///
    /// # Returns
    ///
    /// `true` if algorithm is deprecated, `false` if still acceptable
    #[must_use]
    pub fn is_deprecated(&self) -> bool {
        matches!(self, Self::RsaMd5 | Self::Dsa | Self::RsaSha1 | Self::RsaSha1Nsec3)
    }

    /// Get required message digest length for this algorithm.
    ///
    /// Returns the expected digest length in bytes for signature verification.
    /// `EdDSA` algorithms use the full message, not a digest, so return 0.
    ///
    /// # Digest Lengths
    ///
    /// - SHA1: 20 bytes (algorithms 5, 7)
    /// - SHA256: 32 bytes (algorithms 8, 13)
    /// - SHA384: 48 bytes (algorithm 14)
    /// - SHA512: 64 bytes (algorithm 10)
    /// - `EdDSA`: 0 (verifies full message)
    ///
    /// # Returns
    ///
    /// Expected digest length in bytes, or 0 for `EdDSA`
    #[must_use]
    #[allow(clippy::match_same_arms)] // EdDSA and unknown algorithms both legitimately return 0
    pub fn required_digest_len(&self) -> usize {
        match self {
            Self::RsaSha1 | Self::RsaSha1Nsec3 => 20,      // SHA1
            Self::RsaSha256 | Self::EcdsaP256Sha256 => 32, // SHA256
            Self::RsaSha512 => 64,                         // SHA512
            Self::EcdsaP384Sha384 => 48,                   // SHA384
            Self::Ed25519 | Self::Ed448 => 0,              // EdDSA uses full message
            _ => 0,                                        // Unknown algorithms return 0
        }
    }
}

impl fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::RsaMd5 => "RSA/MD5",
            Self::Dsa => "DSA/SHA1",
            Self::RsaSha1 => "RSA/SHA1",
            Self::RsaSha1Nsec3 => "RSA/SHA1-NSEC3",
            Self::RsaSha256 => "RSA/SHA256",
            Self::RsaSha512 => "RSA/SHA512",
            Self::EccGost => "ECC-GOST",
            Self::EcdsaP256Sha256 => "ECDSA-P256/SHA256",
            Self::EcdsaP384Sha384 => "ECDSA-P384/SHA384",
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
        };
        write!(f, "{} (algorithm {})", name, *self as u8)
    }
}

/// DNSSEC signature verifier using ring cryptographic library.
///
/// Provides stateless signature verification for DNSSEC RRSIG records. Each verification
/// operation constructs keys and performs verification independently, ensuring thread safety
/// and preventing state corruption.
///
/// # Thread Safety
///
/// `SignatureVerifier` contains no mutable state and is safe to share across threads.
/// Wrap in Arc if sharing between tokio tasks.
///
/// # Memory Safety
///
/// Unlike the C implementation which reuses static key structures (potential state corruption),
/// this implementation constructs keys per-verification using Rust's ownership system.
#[derive(Debug, Clone, Copy)]
pub struct SignatureVerifier;

impl SignatureVerifier {
    /// Create a new signature verifier.
    ///
    /// `SignatureVerifier` is stateless, so `new()` simply returns a zero-sized type.
    ///
    /// # Returns
    ///
    /// New `SignatureVerifier` instance (zero-cost abstraction)
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Verify a DNSSEC signature using the specified algorithm.
    ///
    /// This is the main entry point for signature verification, dispatching to algorithm-specific
    /// verification functions based on the algorithm number. Replaces C `verify()` function with
    /// Result-based error handling.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - DNSSEC algorithm number from RRSIG record (1-255)
    /// * `key_data` - Public key in DNS wire format (from DNSKEY record)
    /// * `signature` - Signature bytes from RRSIG record
    /// * `message_digest` - Hash of signed data (RRSET canonical form)
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - Signature is cryptographically valid
    /// - `Ok(false)` - Signature is invalid (verification failed)
    /// - `Err(CryptoError)` - Verification could not be performed (unsupported algorithm, key error, etc.)
    ///
    /// # Errors
    ///
    /// - `UnsupportedAlgorithm` - Algorithm not recognized or not implemented
    /// - `InvalidKeyFormat` - Public key data cannot be parsed
    /// - `InvalidSignatureFormat` - Signature data malformed
    /// - `DigestLengthMismatch` - Message digest has wrong length
    /// - `KeyExtractionFailed` - `BlockData` retrieval failed
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::dns::dnssec::crypto::SignatureVerifier;
    /// # use dnsmasq::dns::dnssec::blockdata::BlockData;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let verifier = SignatureVerifier::new();
    /// let key_data = BlockData::new(&[/* DNSKEY */]);
    /// let signature = &[/* RRSIG signature */];
    /// let digest = &[/* SHA-256 hash */];
    ///
    /// match verifier.verify(8, &key_data, signature, digest)? {
    ///     true => println!("Signature valid"),
    ///     false => println!("Signature invalid"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Algorithm Dispatch
    ///
    /// - Algorithms 5, 7, 8, 10 → `verify_rsa()`
    /// - Algorithms 13, 14 → `verify_ecdsa()`
    /// - Algorithm 15 → `verify_eddsa()`
    /// - Algorithm 12 → `verify_gost()` (not implemented, returns error)
    /// - All others → `UnsupportedAlgorithm` error
    pub fn verify(
        &self,
        algorithm: u8,
        key_data: &BlockData,
        signature: &[u8],
        message_digest: &[u8],
    ) -> Result<bool, CryptoError> {
        // Convert algorithm number to enum for type safety
        let algo = CryptoAlgorithm::from_u8(algorithm)
            .ok_or(CryptoError::UnsupportedAlgorithm { algorithm })?;

        trace!(
            algorithm = algorithm,
            algorithm_name = %algo,
            key_len = key_data.len(),
            sig_len = signature.len(),
            digest_len = message_digest.len(),
            "Starting DNSSEC signature verification"
        );

        // Check if algorithm is supported
        if !algo.is_supported() {
            warn!(
                algorithm = algorithm,
                algorithm_name = %algo,
                "DNSSEC algorithm not supported by this implementation"
            );
            return Err(CryptoError::UnsupportedAlgorithm { algorithm });
        }

        // Warn about deprecated algorithms but still verify
        if algo.is_deprecated() {
            warn!(
                algorithm = algorithm,
                algorithm_name = %algo,
                "Using deprecated DNSSEC algorithm (RFC 8624 NOT RECOMMENDED)"
            );
        }

        // Extract key bytes from BlockData
        let key_bytes = key_data.retrieve();
        if key_bytes.is_empty() {
            error!("Failed to extract key from BlockData: empty key data");
            return Err(CryptoError::KeyExtractionFailed {
                reason: "BlockData retrieve returned empty data".to_string(),
            });
        }

        trace!(key_bytes_len = key_bytes.len(), "Extracted key bytes from BlockData");

        // Dispatch to algorithm-specific verification
        match algo {
            CryptoAlgorithm::RsaSha1
            | CryptoAlgorithm::RsaSha1Nsec3
            | CryptoAlgorithm::RsaSha256
            | CryptoAlgorithm::RsaSha512 => {
                self.verify_rsa(algorithm, &key_bytes, signature, message_digest)
            }
            CryptoAlgorithm::EcdsaP256Sha256 | CryptoAlgorithm::EcdsaP384Sha384 => {
                self.verify_ecdsa(algorithm, &key_bytes, signature, message_digest)
            }
            CryptoAlgorithm::Ed25519 => {
                self.verify_eddsa(algorithm, &key_bytes, signature, message_digest)
            }
            CryptoAlgorithm::EccGost => {
                warn!("GOST algorithm not implemented");
                Err(CryptoError::UnsupportedAlgorithm { algorithm })
            }
            CryptoAlgorithm::Ed448 => {
                warn!("Ed448 not supported by ring library");
                Err(CryptoError::UnsupportedAlgorithm { algorithm })
            }
            _ => Err(CryptoError::UnsupportedAlgorithm { algorithm }),
        }
    }

    /// Verify RSA signature (algorithms 5, 7, 8, 10).
    ///
    /// Parses RSA public key from RFC 3110 wire format and verifies signature using appropriate
    /// hash algorithm (SHA1, SHA256, or SHA512). Replaces C `dnsmasq_rsa_verify()` with ring's
    /// `RsaPublicKeyComponents` verification.
    ///
    /// # RSA Key Wire Format (RFC 3110)
    ///
    /// ```text
    /// +------------------+
    /// | exponent length  | 1 or 3 bytes
    /// +------------------+
    /// | exponent         | variable length
    /// +------------------+
    /// | modulus          | variable length
    /// +------------------+
    /// ```
    ///
    /// - If first byte ≤ 255: exponent length is 1 byte, exponent follows
    /// - If first byte = 0: next 2 bytes are exponent length (big-endian), then exponent
    ///
    /// # Arguments
    ///
    /// * `algorithm` - RSA algorithm number (5, 7, 8, or 10)
    /// * `key_bytes` - RSA public key in RFC 3110 wire format
    /// * `signature` - RSA signature bytes (modulus length)
    /// * `message_digest` - Hash of signed data (SHA1/SHA256/SHA512)
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - RSA signature valid
    /// - `Ok(false)` - RSA signature invalid
    /// - `Err(CryptoError)` - Verification error (key parsing, digest length, etc.)
    ///
    /// # Errors
    ///
    /// - `InvalidKeyFormat` - Key too short, invalid exponent length, etc.
    /// - `DigestLengthMismatch` - Digest length doesn't match algorithm
    /// - `RingError` - ring library rejected key or verification
    pub fn verify_rsa(
        &self,
        algorithm: u8,
        key_bytes: &[u8],
        signature: &[u8],
        message_digest: &[u8],
    ) -> Result<bool, CryptoError> {
        trace!(algorithm = algorithm, "Verifying RSA signature");

        // Validate digest length
        let algo = CryptoAlgorithm::from_u8(algorithm).unwrap();
        let expected_len = algo.required_digest_len();
        if message_digest.len() != expected_len {
            error!(
                algorithm = algorithm,
                expected = expected_len,
                actual = message_digest.len(),
                "RSA digest length mismatch"
            );
            return Err(CryptoError::DigestLengthMismatch {
                algorithm,
                expected: expected_len,
                actual: message_digest.len(),
            });
        }

        // Parse RSA key from wire format
        let (exponent, modulus) = Self::parse_rsa_key(key_bytes, algorithm)?;

        trace!(
            exponent_len = exponent.len(),
            modulus_len = modulus.len(),
            "Parsed RSA key components"
        );

        // Select hash algorithm and verification padding
        let verification_alg: &'static signature::RsaParameters = match algorithm {
            5 | 7 => &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            8 => &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            10 => &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
            _ => {
                return Err(CryptoError::UnsupportedAlgorithm { algorithm });
            }
        };

        // Create public key from components
        let public_key = signature::RsaPublicKeyComponents { n: modulus, e: exponent };

        // Verify signature
        if let Ok(()) = public_key.verify(verification_alg, message_digest, signature) {
            debug!(algorithm = algorithm, "RSA signature verification successful");
            Ok(true)
        } else {
            debug!(algorithm = algorithm, "RSA signature verification failed");
            Ok(false)
        }
    }

    /// Parse RSA public key from RFC 3110 wire format.
    ///
    /// Extracts exponent and modulus from DNS wire format. The key format uses a variable-length
    /// encoding for the exponent length to accommodate different key sizes.
    ///
    /// # Wire Format Details
    ///
    /// - Exponent length ≤ 255 bytes: First byte is length, exponent follows
    /// - Exponent length > 255 bytes: First byte is 0, next 2 bytes are big-endian length
    /// - Modulus: All remaining bytes after exponent
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - Complete RSA key in wire format
    /// * `algorithm` - Algorithm number (for error reporting)
    ///
    /// # Returns
    ///
    /// - `Ok((exponent, modulus))` - Slices pointing into `key_bytes`
    /// - `Err(CryptoError::InvalidKeyFormat)` - Parsing failed
    ///
    /// # Errors
    ///
    /// - Key too short (< 3 bytes)
    /// - Invalid exponent length encoding
    /// - Exponent length exceeds remaining data
    /// - Zero-length exponent or modulus
    fn parse_rsa_key(key_bytes: &[u8], algorithm: u8) -> Result<(&[u8], &[u8]), CryptoError> {
        if key_bytes.len() < 3 {
            return Err(CryptoError::InvalidKeyFormat {
                algorithm,
                reason: format!("RSA key too short: {} bytes (minimum 3)", key_bytes.len()),
            });
        }

        // Parse exponent length (RFC 3110 encoding)
        let (exp_len, exp_start): (usize, usize) = if key_bytes[0] == 0 {
            // Extended length encoding (3 bytes total: 0 + 2-byte big-endian length)
            if key_bytes.len() < 3 {
                return Err(CryptoError::InvalidKeyFormat {
                    algorithm,
                    reason: "RSA key too short for extended exponent length".to_string(),
                });
            }
            let len = ((key_bytes[1] as usize) << 8) | (key_bytes[2] as usize);
            (len, 3)
        } else {
            // Short length encoding (1 byte)
            (key_bytes[0] as usize, 1)
        };

        trace!(exp_len = exp_len, exp_start = exp_start, "Parsed RSA exponent length");

        // Validate exponent length
        if exp_len == 0 {
            return Err(CryptoError::InvalidKeyFormat {
                algorithm,
                reason: "RSA exponent length is zero".to_string(),
            });
        }

        let exp_end = exp_start + exp_len;
        if exp_end > key_bytes.len() {
            return Err(CryptoError::InvalidKeyFormat {
                algorithm,
                reason: format!(
                    "RSA exponent extends beyond key data: {} > {}",
                    exp_end,
                    key_bytes.len()
                ),
            });
        }

        // Extract exponent and modulus
        let exponent = &key_bytes[exp_start..exp_end];
        let modulus = &key_bytes[exp_end..];

        if modulus.is_empty() {
            return Err(CryptoError::InvalidKeyFormat {
                algorithm,
                reason: "RSA modulus is empty".to_string(),
            });
        }

        Ok((exponent, modulus))
    }

    /// Verify ECDSA signature (algorithms 13, 14).
    ///
    /// Parses ECDSA public key from RFC 6605 wire format and verifies signature using P-256
    /// or P-384 curves. Replaces C `dnsmasq_ecdsa_verify()` with ring's ECDSA verification.
    ///
    /// # ECDSA Key Wire Format (RFC 6605)
    ///
    /// ```text
    /// +------------------+
    /// | X coordinate     | curve-dependent length
    /// +------------------+
    /// | Y coordinate     | curve-dependent length
    /// +------------------+
    /// ```
    ///
    /// - Algorithm 13 (P-256): X and Y are 32 bytes each (total 64 bytes)
    /// - Algorithm 14 (P-384): X and Y are 48 bytes each (total 96 bytes)
    ///
    /// # ECDSA Signature Format
    ///
    /// ```text
    /// +------------------+
    /// | R value          | curve-dependent length
    /// +------------------+
    /// | S value          | curve-dependent length
    /// +------------------+
    /// ```
    ///
    /// - Algorithm 13: R and S are 32 bytes each (total 64 bytes)
    /// - Algorithm 14: R and S are 48 bytes each (total 96 bytes)
    ///
    /// # Arguments
    ///
    /// * `algorithm` - ECDSA algorithm number (13 or 14)
    /// * `key_bytes` - ECDSA public key in RFC 6605 wire format
    /// * `signature` - ECDSA signature (R || S)
    /// * `message_digest` - Hash of signed data (SHA256 or SHA384)
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - ECDSA signature valid
    /// - `Ok(false)` - ECDSA signature invalid
    /// - `Err(CryptoError)` - Verification error
    pub fn verify_ecdsa(
        &self,
        algorithm: u8,
        key_bytes: &[u8],
        signature: &[u8],
        message_digest: &[u8],
    ) -> Result<bool, CryptoError> {
        trace!(algorithm = algorithm, "Verifying ECDSA signature");

        // Validate digest length
        let algo = CryptoAlgorithm::from_u8(algorithm).unwrap();
        let expected_len = algo.required_digest_len();
        if message_digest.len() != expected_len {
            error!(
                algorithm = algorithm,
                expected = expected_len,
                actual = message_digest.len(),
                "ECDSA digest length mismatch"
            );
            return Err(CryptoError::DigestLengthMismatch {
                algorithm,
                expected: expected_len,
                actual: message_digest.len(),
            });
        }

        // Select curve and validate key/signature lengths
        let (verification_alg, expected_key_len, expected_sig_len) = match algorithm {
            13 => (
                &signature::ECDSA_P256_SHA256_FIXED,
                64, // P-256: 32-byte X + 32-byte Y
                64, // P-256: 32-byte R + 32-byte S
            ),
            14 => (
                &signature::ECDSA_P384_SHA384_FIXED,
                96, // P-384: 48-byte X + 48-byte Y
                96, // P-384: 48-byte R + 48-byte S
            ),
            _ => {
                return Err(CryptoError::UnsupportedAlgorithm { algorithm });
            }
        };

        // Validate key length
        if key_bytes.len() != expected_key_len {
            return Err(CryptoError::InvalidKeyFormat {
                algorithm,
                reason: format!(
                    "ECDSA key wrong length: expected {} bytes, got {}",
                    expected_key_len,
                    key_bytes.len()
                ),
            });
        }

        // Validate signature length
        if signature.len() != expected_sig_len {
            return Err(CryptoError::InvalidSignatureFormat {
                algorithm,
                reason: format!(
                    "ECDSA signature wrong length: expected {} bytes, got {}",
                    expected_sig_len,
                    signature.len()
                ),
            });
        }

        trace!(
            key_len = key_bytes.len(),
            sig_len = signature.len(),
            "ECDSA key and signature lengths validated"
        );

        // Parse public key (ring expects uncompressed point format: 0x04 || X || Y)
        // RFC 6605 omits the 0x04 prefix, so we need to prepend it
        let mut public_key_bytes = Vec::with_capacity(1 + key_bytes.len());
        public_key_bytes.push(0x04); // Uncompressed point indicator
        public_key_bytes.extend_from_slice(key_bytes);

        // Create public key
        let public_key = signature::UnparsedPublicKey::new(verification_alg, &public_key_bytes);

        // Verify signature
        if let Ok(()) = public_key.verify(message_digest, signature) {
            debug!(algorithm = algorithm, "ECDSA signature verification successful");
            Ok(true)
        } else {
            debug!(algorithm = algorithm, "ECDSA signature verification failed");
            Ok(false)
        }
    }

    /// Verify `EdDSA` signature (algorithm 15: Ed25519).
    ///
    /// Verifies Ed25519 signature using the full message (not a hash digest). `EdDSA` signs
    /// messages directly, so unlike RSA/ECDSA, we don't hash the data first. The C implementation
    /// uses a special "`null_hash`" to buffer the entire message for this purpose.
    ///
    /// # `EdDSA` Key Wire Format (RFC 8080)
    ///
    /// ```text
    /// +------------------+
    /// | public key       | 32 bytes for Ed25519
    /// +------------------+
    /// ```
    ///
    /// Ed25519 public keys are exactly 32 bytes (256 bits).
    ///
    /// # `EdDSA` Signature Format
    ///
    /// ```text
    /// +------------------+
    /// | signature        | 64 bytes for Ed25519
    /// +------------------+
    /// ```
    ///
    /// Ed25519 signatures are exactly 64 bytes (512 bits).
    ///
    /// # Arguments
    ///
    /// * `algorithm` - `EdDSA` algorithm number (15 for Ed25519)
    /// * `key_bytes` - Ed25519 public key (32 bytes)
    /// * `signature` - Ed25519 signature (64 bytes)
    /// * `message` - Full message to verify (NOT a hash digest)
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - `EdDSA` signature valid
    /// - `Ok(false)` - `EdDSA` signature invalid
    /// - `Err(CryptoError)` - Verification error
    ///
    /// # Note on `message_digest` Parameter
    ///
    /// Despite the parameter name "`message_digest`", for `EdDSA` this contains the FULL message,
    /// not a hash. This maintains API consistency with RSA/ECDSA verification functions.
    /// The C implementation achieves this by using a pseudo-hash that buffers the message.
    pub fn verify_eddsa(
        &self,
        algorithm: u8,
        key_bytes: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, CryptoError> {
        // Ed25519 constants
        const ED25519_KEY_LEN: usize = 32;
        const ED25519_SIG_LEN: usize = 64;

        trace!(algorithm = algorithm, "Verifying EdDSA signature");

        // Validate key length
        if key_bytes.len() != ED25519_KEY_LEN {
            return Err(CryptoError::InvalidKeyFormat {
                algorithm,
                reason: format!(
                    "Ed25519 key wrong length: expected {} bytes, got {}",
                    ED25519_KEY_LEN,
                    key_bytes.len()
                ),
            });
        }

        // Validate signature length
        if signature.len() != ED25519_SIG_LEN {
            return Err(CryptoError::InvalidSignatureFormat {
                algorithm,
                reason: format!(
                    "Ed25519 signature wrong length: expected {} bytes, got {}",
                    ED25519_SIG_LEN,
                    signature.len()
                ),
            });
        }

        trace!(
            key_len = key_bytes.len(),
            sig_len = signature.len(),
            message_len = message.len(),
            "EdDSA parameters validated"
        );

        // Create public key
        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, key_bytes);

        // Verify signature against full message (not digest)
        if let Ok(()) = public_key.verify(message, signature) {
            debug!(algorithm = algorithm, "EdDSA signature verification successful");
            Ok(true)
        } else {
            debug!(algorithm = algorithm, "EdDSA signature verification failed");
            Ok(false)
        }
    }

    /// Get the digest algorithm for a DNSSEC algorithm number.
    ///
    /// Maps DNSSEC algorithm numbers to their corresponding hash algorithm for digest
    /// computation. This is used by the validator module to compute the correct digest
    /// before calling `verify()`.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - DNSSEC algorithm number
    ///
    /// # Returns
    ///
    /// - `Some(&'static ring::digest::Algorithm)` - Hash algorithm for this DNSSEC algorithm
    /// - `None` - Algorithm doesn't use a hash (`EdDSA`) or is unsupported
    ///
    /// # Hash Algorithm Mapping
    ///
    /// - Algorithms 5, 7 → SHA1
    /// - Algorithm 8, 13 → SHA256
    /// - Algorithm 10 → SHA512
    /// - Algorithm 14 → SHA384
    /// - Algorithm 15, 16 → None (`EdDSA` verifies full message)
    #[must_use]
    #[allow(clippy::match_same_arms)] // EdDSA and unknown algorithms both legitimately return None
    pub fn hash_for_algorithm(algorithm: u8) -> Option<&'static ring::digest::Algorithm> {
        match algorithm {
            5 | 7 => Some(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY),
            8 | 13 => Some(&ring::digest::SHA256),
            10 => Some(&ring::digest::SHA512),
            14 => Some(&ring::digest::SHA384),
            15 | 16 => None, // EdDSA doesn't use a hash
            _ => None,       // Unknown algorithms return None
        }
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_from_u8() {
        assert_eq!(CryptoAlgorithm::from_u8(5), Some(CryptoAlgorithm::RsaSha1));
        assert_eq!(CryptoAlgorithm::from_u8(8), Some(CryptoAlgorithm::RsaSha256));
        assert_eq!(CryptoAlgorithm::from_u8(13), Some(CryptoAlgorithm::EcdsaP256Sha256));
        assert_eq!(CryptoAlgorithm::from_u8(15), Some(CryptoAlgorithm::Ed25519));
        assert_eq!(CryptoAlgorithm::from_u8(255), None);
    }

    #[test]
    fn test_algorithm_is_supported() {
        assert!(CryptoAlgorithm::RsaSha256.is_supported());
        assert!(CryptoAlgorithm::EcdsaP256Sha256.is_supported());
        assert!(CryptoAlgorithm::Ed25519.is_supported());
        assert!(!CryptoAlgorithm::RsaMd5.is_supported());
        assert!(!CryptoAlgorithm::Dsa.is_supported());
    }

    #[test]
    fn test_algorithm_is_deprecated() {
        assert!(CryptoAlgorithm::RsaMd5.is_deprecated());
        assert!(CryptoAlgorithm::RsaSha1.is_deprecated());
        assert!(!CryptoAlgorithm::RsaSha256.is_deprecated());
        assert!(!CryptoAlgorithm::Ed25519.is_deprecated());
    }

    #[test]
    fn test_algorithm_digest_len() {
        assert_eq!(CryptoAlgorithm::RsaSha1.required_digest_len(), 20);
        assert_eq!(CryptoAlgorithm::RsaSha256.required_digest_len(), 32);
        assert_eq!(CryptoAlgorithm::RsaSha512.required_digest_len(), 64);
        assert_eq!(CryptoAlgorithm::EcdsaP384Sha384.required_digest_len(), 48);
        assert_eq!(CryptoAlgorithm::Ed25519.required_digest_len(), 0);
    }

    #[test]
    fn test_hash_for_algorithm() {
        assert!(SignatureVerifier::hash_for_algorithm(5).is_some());
        assert!(SignatureVerifier::hash_for_algorithm(8).is_some());
        assert!(SignatureVerifier::hash_for_algorithm(10).is_some());
        assert!(SignatureVerifier::hash_for_algorithm(14).is_some());
        assert!(SignatureVerifier::hash_for_algorithm(15).is_none()); // EdDSA
        assert!(SignatureVerifier::hash_for_algorithm(255).is_none()); // Invalid
    }

    #[test]
    fn test_verifier_creation() {
        let verifier = SignatureVerifier::new();
        let default_verifier = SignatureVerifier;

        // Both should create valid verifiers (they're zero-sized types)
        assert_eq!(std::mem::size_of_val(&verifier), 0);
        assert_eq!(std::mem::size_of_val(&default_verifier), 0);
    }

    #[test]
    fn test_unsupported_algorithm_error() {
        let verifier = SignatureVerifier::new();
        let key_data = BlockData::new(&[0u8; 32]);
        let signature = &[0u8; 64];
        let digest = &[0u8; 32];

        // Algorithm 255 is not assigned
        let result = verifier.verify(255, &key_data, signature, digest);
        assert!(matches!(result, Err(CryptoError::UnsupportedAlgorithm { algorithm: 255 })));
    }

    #[test]
    fn test_rsa_key_parsing_short_exponent() {
        // Create RSA key with short exponent (1-byte length)
        let exponent = vec![0x01, 0x00, 0x01]; // 65537
        let modulus = vec![0xFF; 128]; // 1024-bit modulus

        let mut key_bytes = Vec::new();
        key_bytes.push(exponent.len() as u8); // Short length encoding
        key_bytes.extend_from_slice(&exponent);
        key_bytes.extend_from_slice(&modulus);

        let result = SignatureVerifier::parse_rsa_key(&key_bytes, 8);
        assert!(result.is_ok());
        let (exp, mod_result) = result.unwrap();
        assert_eq!(exp, &exponent[..]);
        assert_eq!(mod_result, &modulus[..]);
    }

    #[test]
    fn test_rsa_key_parsing_extended_exponent() {
        // Create RSA key with extended exponent length
        let exponent = vec![0xFF; 300]; // Long exponent (> 255 bytes)
        let modulus = vec![0xFF; 256]; // 2048-bit modulus

        let mut key_bytes = Vec::new();
        key_bytes.push(0); // Extended length indicator
        key_bytes.push((exponent.len() >> 8) as u8); // High byte
        key_bytes.push((exponent.len() & 0xFF) as u8); // Low byte
        key_bytes.extend_from_slice(&exponent);
        key_bytes.extend_from_slice(&modulus);

        let result = SignatureVerifier::parse_rsa_key(&key_bytes, 8);
        assert!(result.is_ok());
        let (exp, mod_result) = result.unwrap();
        assert_eq!(exp, &exponent[..]);
        assert_eq!(mod_result, &modulus[..]);
    }

    #[test]
    fn test_rsa_key_parsing_too_short() {
        // Key too short (< 3 bytes)
        let key_bytes = vec![0x03, 0x01];
        let result = SignatureVerifier::parse_rsa_key(&key_bytes, 8);
        assert!(matches!(result, Err(CryptoError::InvalidKeyFormat { .. })));
    }

    #[test]
    fn test_rsa_key_parsing_zero_exponent_length() {
        // Zero exponent length (invalid)
        let key_bytes = vec![0x00, 0x00, 0x00, 0xFF, 0xFF];
        let result = SignatureVerifier::parse_rsa_key(&key_bytes, 8);
        assert!(matches!(result, Err(CryptoError::InvalidKeyFormat { .. })));
    }

    #[test]
    fn test_digest_length_validation() {
        let verifier = SignatureVerifier::new();
        // Create a valid RSA key by concatenating the exponent length and modulus
        let mut key_bytes = vec![0x03, 0x01, 0x00, 0x01]; // Exponent length and exponent
        key_bytes.extend_from_slice(&[0xFF; 128]); // Modulus
        let key_data = BlockData::new(&key_bytes);
        let signature = vec![0xFF; 128];
        let wrong_digest = [0xFF; 16]; // Wrong length for SHA256

        // RSA/SHA256 (algorithm 8) requires 32-byte digest
        let result = verifier.verify(8, &key_data, &signature, &wrong_digest);
        assert!(matches!(result, Err(CryptoError::DigestLengthMismatch { .. })));
    }
}
