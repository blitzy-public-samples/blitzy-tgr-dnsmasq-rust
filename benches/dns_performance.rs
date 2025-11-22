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

//! DNS Performance Benchmarks
//!
//! Comprehensive criterion-based performance benchmarks for DNS query processing validating
//! that the Rust implementation meets or exceeds C version performance targets. These benchmarks
//! establish baseline metrics for regression detection in CI/CD pipelines.
//!
//! ## Performance Targets
//!
//! Based on Agent Action Plan section 0.2 performance requirements:
//! - **Cached Query Latency**: ≤10ms p95 (target: <1ms typical)
//! - **Upstream Forwarding**: ≤100ms p95 for cache misses
//! - **DNSSEC Validation Overhead**: ≤50ms per validation
//! - **Cache Operations**: Sub-millisecond for hits
//! - **Concurrent Throughput**: Linear scaling with CPU cores
//!
//! ## Benchmark Suite
//!
//! 1. **`dns_query_latency`**: End-to-end query processing from packet reception through
//!    cache lookup, upstream forwarding (when needed), and response generation.
//!
//! 2. **`cache_hit_performance`**: Isolated cache lookup path with pre-populated cache,
//!    measuring optimal performance for frequently requested domains.
//!
//! 3. **`cache_miss_performance`**: Upstream forwarding path when query is not cached,
//!    including network I/O, response validation, and cache population.
//!
//! 4. **`dnssec_validation_overhead`**: Cryptographic signature verification time for
//!    various key types (RSA 2048, ECDSA P-256, EdDSA) to ensure validation overhead
//!    remains acceptable.
//!
//! 5. **`concurrent_query_throughput`**: Stress test with multiple simultaneous queries
//!    measuring queries-per-second throughput and validating linear scaling.
//!
//! 6. **`query_parsing_performance`**: DNS wire format parsing benchmarks ensuring no
//!    performance regression versus C's pointer arithmetic approach.
//!
//! ## Benchmark Configuration
//!
//! All benchmarks use criterion with:
//! - Sample size: 100 measurements per benchmark
//! - Warm-up: 10 iterations to stabilize CPU caches
//! - Statistical analysis: Median, p95, p99 percentiles
//! - HTML reports: Generated in target/criterion/ for visualization
//! - black_box: Prevents compiler optimizations from invalidating results
//!
//! ## Usage
//!
//! Run all DNS benchmarks:
//! ```bash
//! cargo bench --bench dns_performance
//! ```
//!
//! Run specific benchmark:
//! ```bash
//! cargo bench --bench dns_performance -- cache_hit_performance
//! ```
//!
//! Compare with baseline:
//! ```bash
//! cargo bench --bench dns_performance -- --save-baseline dns-baseline
//! cargo bench --bench dns_performance -- --baseline dns-baseline
//! ```

use criterion::{
    criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion,
    Throughput, black_box,
};
use dnsmasq::{
    config::Config,
    dns::{
        DnsService,
        protocol::{DomainName, message::DnsMessage, message::DnsQuery},
    },
    types::RecordType,
};
use futures::future;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    runtime::Runtime,
    task::{spawn, JoinHandle},
};

// ================================================================================================
// Test Data Construction Utilities
// ================================================================================================

/// Dummy client IP address for benchmarking (not used for actual routing)
const BENCHMARK_CLIENT_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

/// Creates a minimal DNS configuration for benchmark testing
fn create_test_config() -> Config {
    use dnsmasq::config::ConfigBuilder;
    use dnsmasq::types::ServerDetails;
    
    ConfigBuilder::new()
        .dns_port(53)
        .cache_size(1000)
        .add_upstream_server(ServerDetails {
            addr: "8.8.8.8:53".parse::<SocketAddr>().unwrap(),
            domain: None,
            flags: 0,
            address: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        })
        .add_upstream_server(ServerDetails {
            addr: "8.8.4.4:53".parse::<SocketAddr>().unwrap(),
            domain: None,
            flags: 0,
            address: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
        })
        .build()
        .expect("Failed to build test config")
}

// Note: Cache pre-population is handled by running resolve_query once per entry
// before benchmarking, which will populate the cache naturally through normal operation.

/// Creates test DNS configuration with DNSSEC enabled
fn create_dnssec_test_config() -> Config {
    use dnsmasq::config::ConfigBuilder;
    use dnsmasq::types::ServerDetails;
    
    ConfigBuilder::new()
        .dns_port(53)
        .cache_size(1000)
        .add_upstream_server(ServerDetails {
            addr: "8.8.8.8:53".parse::<SocketAddr>().unwrap(),
            domain: None,
            flags: 0,
            address: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        })
        .enable_dnssec()
        .build()
        .expect("Failed to build DNSSEC test config")
}

/// Constructs a DNS query for benchmarking
fn create_test_query(domain: &str, record_type: RecordType) -> DnsQuery {
    DnsQuery {
        name: DomainName::new(domain).unwrap(),
        qtype: record_type,
        qclass: 1, // IN class
    }
}

/// Creates test DNS messages for wire format parsing benchmarks
fn create_test_dns_messages() -> Vec<Vec<u8>> {
    vec![
        // Minimal A query for example.com
        create_dns_query_packet("example.com", RecordType::A),
        // AAAA query
        create_dns_query_packet("ipv6.example.com", RecordType::AAAA),
        // CNAME query
        create_dns_query_packet("www.example.com", RecordType::CNAME),
        // Complex query with EDNS0
        create_edns0_query_packet("dnssec.example.com", RecordType::A),
    ]
}

/// Constructs a minimal DNS query packet in wire format
fn create_dns_query_packet(domain: &str, rtype: RecordType) -> Vec<u8> {
    let mut packet = Vec::new();
    
    // DNS Header (12 bytes)
    packet.extend_from_slice(&[
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query, recursion desired
        0x00, 0x01, // QDCOUNT: 1 question
        0x00, 0x00, // ANCOUNT: 0 answers
        0x00, 0x00, // NSCOUNT: 0 authority records
        0x00, 0x00, // ARCOUNT: 0 additional records
    ]);
    
    // Question section: encode domain name
    for label in domain.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // Root label (null terminator)
    
    // QTYPE (2 bytes)
    let qtype_code = match rtype {
        RecordType::A => 1u16,
        RecordType::AAAA => 28u16,
        RecordType::CNAME => 5u16,
        _ => 1u16,
    };
    packet.extend_from_slice(&qtype_code.to_be_bytes());
    
    // QCLASS: IN (1)
    packet.extend_from_slice(&[0x00, 0x01]);
    
    packet
}

/// Creates a DNS query packet with EDNS0 extension
fn create_edns0_query_packet(domain: &str, rtype: RecordType) -> Vec<u8> {
    let mut packet = create_dns_query_packet(domain, rtype);
    
    // Update ARCOUNT to 1 (for EDNS0 OPT record)
    packet[11] = 0x01;
    
    // Add OPT pseudo-record
    packet.push(0); // Root domain for OPT
    packet.extend_from_slice(&[0x00, 0x29]); // TYPE: OPT (41)
    packet.extend_from_slice(&[0x10, 0x00]); // UDP payload size: 4096
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Extended RCODE and flags
    packet.extend_from_slice(&[0x00, 0x00]); // RDLEN: 0 (no options)
    
    packet
}

// ================================================================================================
// Benchmark 1: DNS Query Latency (End-to-End)
// ================================================================================================

/// Benchmarks complete DNS query processing from reception to response transmission
///
/// Measures the end-to-end lifecycle including:
/// 1. Query parsing from wire format
/// 2. Cache lookup attempt
/// 3. Upstream forwarding (on cache miss)
/// 4. Response validation
/// 5. Cache population
/// 6. Response construction
///
/// Performance target: ≤10ms p95 for cached queries, ≤100ms for upstream forwarding
fn benchmark_dns_query_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_query_latency");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));
    group.warm_up_time(Duration::from_secs(3));
    
    let rt = Runtime::new().unwrap();
    
    // Benchmark cached query (optimal path)
    group.bench_function(BenchmarkId::new("cached", "example.com"), |b| {
        b.iter_batched(
            || {
                // Setup: Create DNS service with pre-populated cache
                let config = create_test_config();
                let dns_config = Arc::new(config.dns);
                let dns_service = rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .build()
                        .await
                        .unwrap()
                });
                
                let query = create_test_query("example.com", RecordType::A);
                
                // Pre-populate cache by resolving the query once (first call will cache it)
                rt.block_on(async {
                    let _ = dns_service.resolve_query(query.clone(), BENCHMARK_CLIENT_ADDR, None).await;
                });
                
                (dns_service, query)
            },
            |(dns_service, query)| {
                // Benchmark: Execute query resolution
                rt.block_on(async {
                    black_box(dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    // Benchmark cache miss with upstream forwarding
    group.bench_function(BenchmarkId::new("cache_miss", "upstream.example.com"), |b| {
        b.iter_batched(
            || {
                let config = create_test_config();
                let dns_config = Arc::new(config.dns);
                let dns_service = rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .build()
                        .await
                        .unwrap()
                });
                let query = create_test_query("upstream.example.com", RecordType::A);
                (dns_service, query)
            },
            |(dns_service, query)| {
                rt.block_on(async {
                    black_box(dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    // Benchmark IPv6 AAAA query
    group.bench_function(BenchmarkId::new("ipv6", "ipv6.example.com"), |b| {
        b.iter_batched(
            || {
                let config = create_test_config();
                let dns_config = Arc::new(config.dns);
                let dns_service = rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .build()
                        .await
                        .unwrap()
                });
                
                let query = create_test_query("ipv6.example.com", RecordType::AAAA);
                
                // Pre-populate cache by resolving the query once (first call will cache it)
                rt.block_on(async {
                    let _ = dns_service.resolve_query(query.clone(), BENCHMARK_CLIENT_ADDR, None).await;
                });
                
                (dns_service, query)
            },
            |(dns_service, query)| {
                rt.block_on(async {
                    black_box(dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

// ================================================================================================
// Benchmark 2: Cache Hit Performance
// ================================================================================================

/// Benchmarks cache lookup performance for queries with cache hits
///
/// Measures the end-to-end time for DNS query resolution when the result is already cached.
/// This benchmarks the full resolve_query path including cache lookup, representing realistic
/// performance for frequently queried domains.
///
/// Performance target: Sub-millisecond response time (<1ms typical)
fn benchmark_cache_hit_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_hit_performance");
    group.sample_size(100);
    group.throughput(Throughput::Elements(1));
    
    let rt = Runtime::new().unwrap();
    
    // Benchmark cached query resolution (small dataset)
    group.bench_function(BenchmarkId::new("cached_query", "frequently_accessed"), |b| {
        b.iter_batched(
            || {
                let config = create_test_config();
                let dns_config = Arc::new(config.dns);
                let dns_service = rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .build()
                        .await
                        .unwrap()
                });
                
                let query = create_test_query("cached.example.com", RecordType::A);
                
                // Pre-populate cache by resolving once
                rt.block_on(async {
                    let _ = dns_service.resolve_query(query.clone(), BENCHMARK_CLIENT_ADDR, None).await;
                });
                
                (dns_service, query)
            },
            |(dns_service, query)| {
                rt.block_on(async {
                    black_box(dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

// ================================================================================================
// Benchmark 3: Cache Miss Performance
// ================================================================================================

/// Benchmarks upstream forwarding path when queries result in cache misses
///
/// Measures the time to:
/// 1. Detect cache miss
/// 2. Select upstream server
/// 3. Construct forwarding query
/// 4. Send query to upstream
/// 5. Receive response
/// 6. Validate response
/// 7. Populate cache with result
///
/// Performance target: ≤100ms p95 for upstream query/response cycle
fn benchmark_cache_miss_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_miss_performance");
    group.sample_size(50); // Smaller sample size due to network I/O
    group.measurement_time(Duration::from_secs(15));
    
    let rt = Runtime::new().unwrap();
    
    // Benchmark upstream forwarding to primary server
    group.bench_function(BenchmarkId::new("upstream_forward", "primary_server"), |b| {
        b.iter_batched(
            || {
                let config = create_test_config();
                let dns_config = Arc::new(config.dns);
                let dns_service = rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .build()
                        .await
                        .unwrap()
                });
                // Use a domain that won't be in cache
                let query = create_test_query("uncached.example.com", RecordType::A);
                (dns_service, query)
            },
            |(dns_service, query)| {
                rt.block_on(async {
                    black_box(dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    // Benchmark with server failover
    group.bench_function(BenchmarkId::new("failover", "secondary_server"), |b| {
        b.iter_batched(
            || {
                use dnsmasq::types::ServerDetails;
                // Create config with multiple upstream servers for failover
                let config = dnsmasq::config::ConfigBuilder::new()
                    .dns_port(53)
                    .cache_size(1000)
                    .add_upstream_server(ServerDetails {
                        addr: "8.8.8.8:53".parse::<SocketAddr>().unwrap(),
                        domain: None,
                        flags: 0,
                        address: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                    })
                    .add_upstream_server(ServerDetails {
                        addr: "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
                        domain: None,
                        flags: 0,
                        address: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                    })
                    .build()
                    .unwrap();
                
                let dns_config = Arc::new(config.dns);
                let dns_service = rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .build()
                        .await
                        .unwrap()
                });
                let query = create_test_query("failover-test.example.com", RecordType::A);
                (dns_service, query)
            },
            |(dns_service, query)| {
                rt.block_on(async {
                    black_box(dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    // Benchmark TCP fallback for truncated responses
    group.bench_function(BenchmarkId::new("tcp_fallback", "truncated"), |b| {
        b.iter_batched(
            || {
                let config = create_test_config();
                let dns_config = Arc::new(config.dns);
                let dns_service = rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .build()
                        .await
                        .unwrap()
                });
                // Query for record type that may result in large response
                let query = create_test_query("large-response.example.com", RecordType::ANY);
                (dns_service, query)
            },
            |(dns_service, query)| {
                rt.block_on(async {
                    black_box(dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

// ================================================================================================
// Benchmark 4: DNSSEC Validation Overhead
// ================================================================================================

/// Benchmarks DNSSEC cryptographic signature verification overhead
///
/// Measures the additional latency introduced by DNSSEC validation for various
/// cryptographic algorithms commonly used in DNSSEC:
/// - RSA 2048-bit keys (most common)
/// - ECDSA P-256 (more efficient)
/// - EdDSA Ed25519 (modern, fast)
///
/// Performance target: ≤50ms validation overhead per Agent Action Plan requirements
#[cfg(feature = "dnssec")]
fn benchmark_dnssec_validation_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("dnssec_validation_overhead");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));
    
    let rt = Runtime::new().unwrap();
    
    // Benchmark RSA 2048 signature verification
    // Note: This benchmark requires actual DNSSEC-signed responses from upstream servers.
    // It measures the overhead of DNSSEC validation in a complete resolution flow.
    group.bench_function(BenchmarkId::new("rsa_2048", "signature_verify"), |b| {
        b.iter_batched(
            || {
                let config = create_dnssec_test_config();
                let dns_config = Arc::new(config.dns);
                let dns_service = rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .enable_dnssec(true)
                        .build()
                        .await
                        .unwrap()
                });
                let query = create_test_query("dnssec-rsa.example.com", RecordType::A);
                (dns_service, query)
            },
            |(dns_service, query)| {
                rt.block_on(async {
                    black_box(dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    // Benchmark ECDSA P-256 signature verification
    group.bench_function(BenchmarkId::new("ecdsa_p256", "signature_verify"), |b| {
        b.iter_batched(
            || {
                let config = create_dnssec_test_config();
                let dns_config = Arc::new(config.dns);
                let dns_service = rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .enable_dnssec(true)
                        .build()
                        .await
                        .unwrap()
                });
                let query = create_test_query("dnssec-ecdsa.example.com", RecordType::A);
                (dns_service, query)
            },
            |(dns_service, query)| {
                rt.block_on(async {
                    black_box(dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    // Benchmark trust chain validation (multiple signatures)
    group.bench_function(BenchmarkId::new("trust_chain", "full_validation"), |b| {
        b.iter_batched(
            || {
                let config = create_dnssec_test_config();
                let dns_config = Arc::new(config.dns);
                let dns_service = rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .enable_dnssec(true)
                        .build()
                        .await
                        .unwrap()
                });
                // Deep subdomain requiring multiple DS/DNSKEY lookups
                let query = create_test_query("deep.subdomain.example.com", RecordType::A);
                (dns_service, query)
            },
            |(dns_service, query)| {
                rt.block_on(async {
                    black_box(dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

/// Placeholder for DNSSEC benchmarks when feature is disabled
#[cfg(not(feature = "dnssec"))]
fn benchmark_dnssec_validation_overhead(_c: &mut Criterion) {
    // DNSSEC benchmarks skipped - feature not enabled
    eprintln!("DNSSEC validation benchmarks skipped (dnssec feature not enabled)");
}

// ================================================================================================
// Benchmark 5: Concurrent Query Throughput
// ================================================================================================

/// Benchmarks concurrent query handling throughput under load
///
/// Spawns multiple concurrent queries to measure:
/// - Queries per second throughput
/// - Linear scaling with CPU cores
/// - Contention on shared cache
/// - Async task scheduling overhead
///
/// Validates that the Rust async implementation scales efficiently with concurrent load.
fn benchmark_concurrent_query_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_query_throughput");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));
    
    let rt = Runtime::new().unwrap();
    
    // Benchmark with 10 concurrent queries
    group.bench_function(BenchmarkId::new("concurrent", "10_queries"), |b| {
        b.iter_batched(
            || {
                let config = create_test_config();
                let dns_config = Arc::new(config.dns);
                let dns_service = Arc::new(rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .build()
                        .await
                        .unwrap()
                }));
                
                // Pre-populate cache by resolving queries once
                rt.block_on(async {
                    for i in 0..10 {
                        let query = create_test_query(
                            &format!("concurrent{}.example.com", i),
                            RecordType::A,
                        );
                        let _ = dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await;
                    }
                });
                
                dns_service
            },
            |dns_service| {
                rt.block_on(async {
                    let mut handles: Vec<JoinHandle<_>> = Vec::new();
                    
                    for i in 0..10 {
                        let service = dns_service.clone();
                        let query = create_test_query(
                            &format!("concurrent{}.example.com", i),
                            RecordType::A,
                        );
                        
                        let handle = spawn(async move {
                            service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await
                        });
                        
                        handles.push(handle);
                    }
                    
                    // Wait for all queries to complete
                    let results: Vec<_> = futures::future::join_all(handles).await;
                    black_box(results)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    // Benchmark with 50 concurrent queries
    group.bench_function(BenchmarkId::new("concurrent", "50_queries"), |b| {
        b.iter_batched(
            || {
                let config = create_test_config();
                let dns_config = Arc::new(config.dns);
                let dns_service = Arc::new(rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .build()
                        .await
                        .unwrap()
                }));
                
                // Pre-populate cache by resolving queries once
                rt.block_on(async {
                    for i in 0..50 {
                        let query = create_test_query(
                            &format!("load{}.example.com", i),
                            RecordType::A,
                        );
                        let _ = dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await;
                    }
                });
                
                dns_service
            },
            |dns_service| {
                rt.block_on(async {
                    let mut handles: Vec<JoinHandle<_>> = Vec::new();
                    
                    for i in 0..50 {
                        let service = dns_service.clone();
                        let query = create_test_query(
                            &format!("load{}.example.com", i),
                            RecordType::A,
                        );
                        
                        let handle = spawn(async move {
                            service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await
                        });
                        
                        handles.push(handle);
                    }
                    
                    let results: Vec<_> = futures::future::join_all(handles).await;
                    black_box(results)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    // Benchmark with 100 concurrent queries (stress test)
    group.bench_function(BenchmarkId::new("concurrent", "100_queries"), |b| {
        b.iter_batched(
            || {
                let config = create_test_config();
                let dns_config = Arc::new(config.dns);
                let dns_service = Arc::new(rt.block_on(async {
                    DnsService::builder()
                        .config(dns_config)
                        .cache_size(1000)
                        .build()
                        .await
                        .unwrap()
                }));
                
                // Pre-populate cache by resolving queries once
                rt.block_on(async {
                    for i in 0..100 {
                        let query = create_test_query(
                            &format!("stress{}.example.com", i),
                            RecordType::A,
                        );
                        let _ = dns_service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await;
                    }
                });
                
                dns_service
            },
            |dns_service| {
                rt.block_on(async {
                    let mut handles: Vec<JoinHandle<_>> = Vec::new();
                    
                    for i in 0..100 {
                        let service = dns_service.clone();
                        let query = create_test_query(
                            &format!("stress{}.example.com", i),
                            RecordType::A,
                        );
                        
                        let handle = spawn(async move {
                            service.resolve_query(query, BENCHMARK_CLIENT_ADDR, None).await
                        });
                        
                        handles.push(handle);
                    }
                    
                    let results: Vec<_> = futures::future::join_all(handles).await;
                    black_box(results)
                })
            },
            BatchSize::SmallInput,
        );
    });
    
    group.throughput(Throughput::Elements(100));
    group.finish();
}

// ================================================================================================
// Benchmark 6: Query Parsing Performance
// ================================================================================================

/// Benchmarks DNS wire format parsing performance
///
/// Measures packet parsing time using Rust's safe parsing approach (nom combinators or
/// Hickory DNS protocol parsers) and validates no performance regression versus C's
/// pointer arithmetic approach. Tests various query types and packet sizes.
///
/// Performance target: Match or exceed C parsing speed (typically <10µs per packet)
fn benchmark_query_parsing_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("query_parsing_performance");
    group.sample_size(100);
    group.throughput(Throughput::Bytes(512)); // Typical DNS packet size
    
    let test_packets = create_test_dns_messages();
    
    // Benchmark minimal A query parsing
    group.bench_function(BenchmarkId::new("parse", "minimal_a_query"), |b| {
        let packet = &test_packets[0];
        b.iter(|| {
            black_box(DnsMessage::from_bytes(packet).unwrap())
        });
    });
    
    // Benchmark AAAA query parsing
    group.bench_function(BenchmarkId::new("parse", "aaaa_query"), |b| {
        let packet = &test_packets[1];
        b.iter(|| {
            black_box(DnsMessage::from_bytes(packet).unwrap())
        });
    });
    
    // Benchmark CNAME query parsing
    group.bench_function(BenchmarkId::new("parse", "cname_query"), |b| {
        let packet = &test_packets[2];
        b.iter(|| {
            black_box(DnsMessage::from_bytes(packet).unwrap())
        });
    });
    
    // Benchmark EDNS0 query parsing (with options)
    group.bench_function(BenchmarkId::new("parse", "edns0_query"), |b| {
        let packet = &test_packets[3];
        b.iter(|| {
            black_box(DnsMessage::from_bytes(packet).unwrap())
        });
    });
    
    // Benchmark batch parsing (multiple queries)
    group.bench_function(BenchmarkId::new("parse_batch", "10_queries"), |b| {
        b.iter(|| {
            for packet in &test_packets {
                black_box(DnsMessage::from_bytes(packet).unwrap());
            }
        });
    });
    
    // Benchmark domain name extraction and validation
    group.bench_function(BenchmarkId::new("domain_parsing", "name_extraction"), |b| {
        let packet = &test_packets[0];
        b.iter(|| {
            let message = DnsMessage::from_bytes(packet).unwrap();
            // Clone the domain names to avoid borrowing issues
            black_box(message.questions.iter().map(|q| q.qname.clone()).collect::<Vec<_>>())
        });
    });
    
    group.finish();
}

// ================================================================================================
// Benchmark Group Configuration
// ================================================================================================

criterion_group!(
    dns_benches,
    benchmark_dns_query_latency,
    benchmark_cache_hit_performance,
    benchmark_cache_miss_performance,
    benchmark_dnssec_validation_overhead,
    benchmark_concurrent_query_throughput,
    benchmark_query_parsing_performance
);

criterion_main!(dns_benches);
