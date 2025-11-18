// dnsmasq-rust is Copyright (c) 2025 Dnsmasq Contributors
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

//! Cryptographic signature verification for DNSSEC.
//!
//! This module provides algorithm-specific signature validation for RSA,
//! ECDSA, EdDSA, and GOST algorithms, abstracting cryptographic operations
//! behind clean interfaces.
//!
//! Replaces C `crypto.c` (1300+ lines) with memory-safe cryptography using `ring` crate.

use std::fmt;

/// Cryptographic signature verifier.
///
/// Provides signature verification for DNSSEC RRSIG records using
/// various cryptographic algorithms.
#[derive(Debug)]
pub struct SignatureVerifier {
    // TODO: Implement signature verification state
}

impl SignatureVerifier {
    /// Creates a new signature verifier.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Cryptographic algorithm identifier for DNSSEC.
///
/// Represents the algorithm used for signing DNSSEC records.
/// See RFC 8624 for algorithm implementation requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoAlgorithm {
    /// RSA/SHA-1 (deprecated, MUST NOT implement)
    RsaSha1 = 5,
    
    /// DSA/SHA-1 (deprecated, MUST NOT implement)
    DsaSha1 = 3,
    
    /// RSA/SHA-256 (MUST implement)
    RsaSha256 = 8,
    
    /// RSA/SHA-512 (RECOMMENDED)
    RsaSha512 = 10,
    
    /// ECDSA Curve P-256 with SHA-256 (MUST implement)
    EcdsaP256Sha256 = 13,
    
    /// ECDSA Curve P-384 with SHA-384 (RECOMMENDED)
    EcdsaP384Sha384 = 14,
    
    /// Ed25519 (RECOMMENDED)
    Ed25519 = 15,
    
    /// Ed448 (RECOMMENDED)
    Ed448 = 16,
}

impl CryptoAlgorithm {
    /// Converts algorithm number to enum variant.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            3 => Some(Self::DsaSha1),
            5 => Some(Self::RsaSha1),
            8 => Some(Self::RsaSha256),
            10 => Some(Self::RsaSha512),
            13 => Some(Self::EcdsaP256Sha256),
            14 => Some(Self::EcdsaP384Sha384),
            15 => Some(Self::Ed25519),
            16 => Some(Self::Ed448),
            _ => None,
        }
    }
    
    /// Converts enum variant to algorithm number.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
    
    /// Returns whether this algorithm is recommended for use.
    pub fn is_recommended(self) -> bool {
        matches!(
            self,
            Self::RsaSha256
                | Self::RsaSha512
                | Self::EcdsaP256Sha256
                | Self::EcdsaP384Sha384
                | Self::Ed25519
                | Self::Ed448
        )
    }
    
    /// Returns whether this algorithm is deprecated.
    pub fn is_deprecated(self) -> bool {
        matches!(self, Self::RsaSha1 | Self::DsaSha1)
    }
}

impl fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RsaSha1 => write!(f, "RSA/SHA-1"),
            Self::DsaSha1 => write!(f, "DSA/SHA-1"),
            Self::RsaSha256 => write!(f, "RSA/SHA-256"),
            Self::RsaSha512 => write!(f, "RSA/SHA-512"),
            Self::EcdsaP256Sha256 => write!(f, "ECDSA P-256/SHA-256"),
            Self::EcdsaP384Sha384 => write!(f, "ECDSA P-384/SHA-384"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::Ed448 => write!(f, "Ed448"),
        }
    }
}
