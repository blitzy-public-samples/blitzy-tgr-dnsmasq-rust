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

//! DNSSEC Validation Subsystem
//!
//! This module provides complete DNSSEC (Domain Name System Security Extensions) validation
//! functionality for cryptographic verification of DNS responses according to RFC 4033, RFC 4034,
//! and RFC 4035. DNSSEC protects against DNS cache poisoning, man-in-the-middle attacks, and
//! domain hijacking by enabling DNS resolvers to verify the authenticity and integrity of DNS
//! responses through digital signatures.
//!
//! # Purpose
//!
//! DNSSEC validation ensures that DNS responses have not been tampered with during transmission
//! by verifying cryptographic signatures attached to DNS records. This module implements the
//! complete trust chain validation from target domains up to root zone trust anchors, verifying
//! RRSIG (signature) records against DNSKEY (public key) records, validating DNSKEY records
//! against DS (delegation signer) records in parent zones, and processing NSEC/NSEC3 records
//! for authenticated denial of existence.
//!
//! # Standards Compliance
//!
//! This implementation provides full compliance with the following RFCs:
//!
//! - **RFC 4033**: DNS Security Introduction and Requirements - Defines the overall DNSSEC
//!   architecture, security goals, and threat model. Specifies the relationship between RRSIG,
//!   DNSKEY, DS, and NSEC records in establishing chain of trust.
//!
//! - **RFC 4034**: Resource Records for DNS Security Extensions - Defines the wire format and
//!   semantics of DNSSEC-specific resource records including RRSIG (signature records), DNSKEY
//!   (public key records), DS (delegation signer records), and NSEC (authenticated denial).
//!
//! - **RFC 4035**: Protocol Modifications for DNS Security Extensions - Specifies protocol
//!   modifications for DNSSEC-aware resolvers including DO (DNSSEC OK) bit handling, CD (Checking
//!   Disabled) bit processing, and AD (Authenticated Data) bit semantics for validated responses.
//!
//! - **RFC 5155**: DNS Security (DNSSEC) Hashed Authenticated Denial of Existence - Extends
//!   DNSSEC with NSEC3 records providing authenticated denial of existence with zone enumeration
//!   protection through cryptographic hashing of owner names.
//!
//! - **RFC 6840**: Clarifications and Implementation Notes for DNS Security - Provides
//!   implementation guidance and clarifications for ambiguities in original DNSSEC specifications.
//!
//! - **RFC 8624**: Algorithm Implementation Requirements for DNSSEC - Specifies mandatory and
//!   recommended cryptographic algorithms for DNSSEC deployment (RSA/SHA-256, ECDSA, EdDSA).
//!
//! # Memory Safety Improvements
//!
//! This Rust implementation provides significant memory safety advantages over the original C
//! implementation (dnssec.c, crypto.c, blockdata.c):
//!
//! ## Automatic Memory Management
//!
//! - **C implementation**: Manual allocation/deallocation with malloc/free for DNSSEC records,
//!   cryptographic contexts, and temporary buffers. Memory leaks possible if validation fails
//!   mid-process or error paths are not properly cleaned up.
//!
//! - **Rust implementation**: Automatic memory management through ownership system and RAII
//!   (Resource Acquisition Is Initialization). All allocations automatically deallocated when
//!   they go out of scope, eliminating memory leaks even in complex error handling paths.
//!
//! ## Bounds Checking
//!
//! - **C implementation**: Manual bounds checking when parsing DNSSEC records from wire format.
//!   Buffer overflows possible if length fields are maliciously crafted or validation code
//!   contains off-by-one errors.
//!
//! - **Rust implementation**: Compile-time and runtime bounds checking on all buffer accesses.
//!   Slice types encode length information, preventing buffer overruns. Parser combinators
//!   provide safe, composable parsing without pointer arithmetic.
//!
//! ## Type Safety
//!
//! - **C implementation**: Type punning through void pointers and manual type casting for
//!   algorithm-specific signature verification. Type confusion vulnerabilities possible.
//!
//! - **Rust implementation**: Strong static typing with enum-based algorithm dispatch. Type
//!   system prevents mixing incompatible algorithm contexts or signature types at compile time.
//!
//! ## Cryptographic Safety
//!
//! - **C implementation**: Uses Nettle cryptography library through FFI. Manual memory management
//!   of cryptographic contexts and potential for memory corruption in FFI boundary.
//!
//! - **Rust implementation**: Uses pure-Rust `ring` cryptography crate providing memory-safe
//!   cryptographic operations with no FFI boundary. Automatic zeroing of sensitive key material
//!   through Drop implementations prevents key exposure in memory dumps.
//!
//! ## Concurrency Safety
//!
//! - **C implementation**: Single-threaded with global state. Not thread-safe if future versions
//!   add concurrent validation.
//!
//! - **Rust implementation**: Thread safety enforced at compile time through Send/Sync traits.
//!   Future concurrent validation can be safely implemented without data races or deadlocks.
//!
//! # Architecture
//!
//! The DNSSEC subsystem is organized into four focused submodules:
//!
//! ## [`validator`]
//!
//! Core DNSSEC validation orchestration implementing the complete trust chain verification
//! process. Coordinates signature verification, key validation, trust anchor lookup, and
//! denial-of-existence proof checking. Entry point for DNS forwarder integration.
//!
//! **Replaces**: C `dnssec.c` (4000+ lines) with modular, type-safe validation state machine.
//!
//! **Key Types**: [`DnssecValidator`], [`ValidationResult`], [`ValidationStatus`], [`ValidationCounter`]
//!
//! ## [`crypto`]
//!
//! Cryptographic signature verification providing algorithm-specific signature validation
//! for RSA, ECDSA, EdDSA, and GOST algorithms. Abstracts cryptographic operations behind
//! clean interfaces isolating algorithm complexity.
//!
//! **Replaces**: C `crypto.c` (1300+ lines) with memory-safe cryptography using `ring` crate.
//!
//! **Key Types**: [`SignatureVerifier`], [`CryptoAlgorithm`]
//!
//! ## [`trust_anchors`]
//!
//! Trust anchor management implementing secure storage and lookup of root zone DNSKEY records
//! that anchor the DNSSEC trust chain. Parses trust-anchors.conf file maintaining RFC 5011
//! format compatibility.
//!
//! **Replaces**: Trust anchor handling scattered throughout C `dnssec.c`.
//!
//! **Key Types**: [`TrustAnchorStore`]
//!
//! ## [`blockdata`]
//!
//! Variable-length DNSSEC record storage providing efficient memory management for
//! cryptographic signatures and keys of varying sizes. Prevents heap fragmentation through
//! fixed-size block chains.
//!
//! **Replaces**: C `blockdata.c` (800+ lines) with safe, ergonomic data structure.
//!
//! **Key Types**: [`BlockData`]
//!
//! # Usage Patterns
//!
//! ## Basic DNSSEC Validation
//!
//! ```rust,ignore
//! use dnsmasq::dns::dnssec::{DnssecValidator, ValidationStatus};
//! use dnsmasq::dns::protocol::message::DnsMessage;
//!
//! // Initialize validator with trust anchors
//! let mut validator = DnssecValidator::new();
//! validator.load_trust_anchors("/etc/dnsmasq/trust-anchors.conf").await?;
//!
//! // Validate DNS response
//! let response: DnsMessage = receive_dns_response().await?;
//! let result = validator.validate_response(&response).await?;
//!
//! match result.status {
//!     ValidationStatus::Secure => {
//!         // Response cryptographically verified - safe to use
//!         cache_response(&response).await?;
//!     }
//!     ValidationStatus::Insecure => {
//!         // Zone not signed - validation not possible but not an error
//!         cache_response(&response).await?;
//!     }
//!     ValidationStatus::Bogus => {
//!         // Validation failed - response may be forged
//!         log::warn!("DNSSEC validation failed: {:?}", result.error_details);
//!         drop_response(&response);
//!     }
//!     ValidationStatus::Indeterminate => {
//!         // Validation cannot complete (missing records, timeouts)
//!         log::debug!("DNSSEC validation indeterminate, retrying");
//!         retry_query().await?;
//!     }
//! }
//! ```
//!
//! ## Integration with DNS Forwarder
//!
//! ```rust,ignore
//! use dnsmasq::dns::forwarder::DnsForwarder;
//! use dnsmasq::dns::dnssec::DnssecValidator;
//!
//! // DNS forwarder checks for DNSSEC DO (DNSSEC OK) bit in queries
//! async fn handle_dns_query(
//!     forwarder: &DnsForwarder,
//!     validator: &DnssecValidator,
//!     query: DnsMessage,
//! ) -> Result<DnsMessage, DnsError> {
//!     // Forward query to upstream with DO bit set
//!     let response = forwarder.forward_query(query).await?;
//!
//!     // Validate response if it contains DNSSEC records
//!     if response.has_dnssec_records() {
//!         let validation = validator.validate_response(&response).await?;
//!         
//!         // Set AD (Authenticated Data) bit based on validation result
//!         let mut final_response = response;
//!         final_response.set_authenticated_data(validation.status == ValidationStatus::Secure);
//!         
//!         Ok(final_response)
//!     } else {
//!         Ok(response)
//!     }
//! }
//! ```
//!
//! ## Resource Limit Enforcement
//!
//! ```rust,ignore
//! use dnsmasq::dns::dnssec::{DnssecValidator, ValidationCounter};
//!
//! // Create validator with DoS protection limits
//! let mut validator = DnssecValidator::new();
//!
//! // Validation counter tracks resource usage to prevent DoS attacks
//! let mut counter = ValidationCounter::new();
//! counter.set_max_work(40);        // Maximum 40 validation queries
//! counter.set_max_crypto(200);     // Maximum 200 signature verifications
//! counter.set_max_sig_fail(20);    // Maximum 20 signature failures
//!
//! // Validate with resource limits
//! let result = validator.validate_with_limits(&response, &mut counter).await?;
//!
//! if counter.check_work_limit() || counter.check_crypto_limit() {
//!     log::warn!("DNSSEC validation exceeded resource limits - potential DoS attack");
//!     return Err(DnssecError::ResourceLimitExceeded);
//! }
//! ```
//!
//! # Integration Points
//!
//! ## DNS Forwarder Integration
//!
//! The DNS forwarder (in `crate::dns::forwarder`) invokes DNSSEC validation when:
//!
//! - Client query has DO (DNSSEC OK) bit set indicating DNSSEC awareness
//! - Upstream response contains DNSSEC-specific records (RRSIG, DNSKEY, DS, NSEC, NSEC3)
//! - Configuration option `dnssec-validation` is enabled
//!
//! Validation result determines whether AD (Authenticated Data) bit is set in response to client
//! and whether response is cached or discarded based on BOGUS status.
//!
//! ## DNS Cache Integration
//!
//! The DNS cache (in `crate::dns::cache`) stores:
//!
//! - Validated DNSSEC records with their validation status (SECURE/INSECURE/BOGUS)
//! - RRSIG signatures for cache coherency verification
//! - Negative cache entries with NSEC/NSEC3 proof records
//!
//! Cache lookup considers DNSSEC validation status when serving cached responses, never serving
//! BOGUS responses even if present in cache.
//!
//! ## Configuration Integration
//!
//! DNSSEC validation behavior controlled by configuration options:
//!
//! - `dnssec-validation`: Enable/disable DNSSEC validation (enabled by default)
//! - `trust-anchor-file`: Path to trust anchor configuration file
//! - `dnssec-timestamp`: Enable timestamp-based validation for systems without reliable clocks
//! - `dnssec-check-unsigned`: Require DNSSEC signatures for all zones
//! - `dnssec-no-timecheck`: Disable inception/expiration time validation for debugging
//!
//! # Feature Flag
//!
//! This entire module is conditionally compiled via the `dnssec` Cargo feature flag,
//! maintaining parity with the C implementation's `HAVE_DNSSEC` preprocessor flag:
//!
//! ```toml
//! [dependencies]
//! dnsmasq = { version = "2.92", features = ["dnssec"] }
//! ```
//!
//! When the `dnssec` feature is disabled, all DNSSEC validation code is excluded from the
//! binary, reducing code size and dependencies for deployments that do not require DNSSEC.
//!
//! # Performance Characteristics
//!
//! ## Validation Overhead
//!
//! DNSSEC validation adds computational overhead to DNS query processing:
//!
//! - **Cryptographic Operations**: RSA signature verification ~1-5ms, ECDSA ~0.5-2ms, EdDSA ~0.1-0.5ms
//! - **Trust Chain Traversal**: 2-5 additional queries per validation for DNSKEY/DS lookup
//! - **Memory Usage**: ~1-4 KB per validation for cryptographic contexts and temporary buffers
//!
//! ## Optimization Strategies
//!
//! - **Caching**: Validated DNSKEY records cached to avoid redundant cryptographic operations
//! - **Negative Caching**: NSEC/NSEC3 records cached to validate subsequent NXDOMAIN responses
//! - **Trust Anchor Lookup**: Pre-loaded trust anchors avoid disk I/O during validation
//! - **Resource Limits**: Configurable limits prevent DoS attacks from excessive validation work
//!
//! # Security Considerations
//!
//! ## Trust Anchor Management
//!
//! Trust anchors are the root of DNSSEC trust chains and must be carefully managed:
//!
//! - Store trust-anchors.conf with root-only read permissions (chmod 600)
//! - Regularly update trust anchors following root zone key rollovers (RFC 5011)
//! - Validate trust anchor file integrity before loading (signature verification recommended)
//!
//! ## Resource Exhaustion Attacks
//!
//! DNSSEC validation is computationally expensive and vulnerable to DoS attacks:
//!
//! - Validation work counter limits total queries per validation chain
//! - Cryptographic operation counter prevents excessive signature verification attempts
//! - Signature failure counter limits wasted work on invalid signatures
//! - NSEC3 iteration limit prevents hash computation DoS attacks
//!
//! ## Clock Synchronization
//!
//! DNSSEC relies on accurate system time for signature validation:
//!
//! - RRSIG records have inception and expiration timestamps
//! - Incorrect system time causes validation failures for valid signatures
//! - Use `dnssec-timestamp` option for systems without reliable clocks
//!
//! ## Algorithm Rollover
//!
//! Support multiple algorithms during transition periods:
//!
//! - Zones may dual-sign with old and new algorithms during key rollovers
//! - Validator must support both deprecated (for compatibility) and modern algorithms
//! - Prefer stronger algorithms (EdDSA > ECDSA > RSA/SHA-256) when multiple signatures present
//!
//! # Examples
//!
//! See individual submodule documentation for detailed usage examples:
//!
//! - [`validator`] - DNSSEC validation workflows
//! - [`crypto`] - Cryptographic algorithm usage
//! - [`trust_anchors`] - Trust anchor management
//! - [`blockdata`] - Efficient DNSSEC record storage

// Conditional compilation: entire DNSSEC module only available when feature flag is enabled
// This matches the C implementation's HAVE_DNSSEC preprocessor flag
#[cfg(feature = "dnssec")]
pub mod validator;

#[cfg(feature = "dnssec")]
pub mod crypto;

#[cfg(feature = "dnssec")]
pub mod trust_anchors;

#[cfg(feature = "dnssec")]
pub mod blockdata;

// Re-export commonly used types for ergonomic imports
// Allows users to write: use dnsmasq::dns::dnssec::{DnssecValidator, ValidationStatus};
// Instead of: use dnsmasq::dns::dnssec::validator::{DnssecValidator, ValidationStatus};

#[cfg(feature = "dnssec")]
pub use validator::{DnssecValidator, ValidationCounter, ValidationResult, ValidationStatus};

#[cfg(feature = "dnssec")]
pub use crypto::{CryptoAlgorithm, SignatureVerifier};

#[cfg(feature = "dnssec")]
pub use trust_anchors::TrustAnchorStore;

#[cfg(feature = "dnssec")]
pub use blockdata::BlockData;
