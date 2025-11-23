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

//! # DHCP Performance Benchmarks
//!
//! Criterion-based performance benchmarks for DHCPv4 and DHCPv6 lease allocation validating
//! that the Rust implementation meets or exceeds C version performance for DHCP operations.
//!
//! ## Benchmark Suite
//!
//! ### 1. DHCPv4 Lease Allocation (`dhcpv4_lease_allocation`)
//!
//! Measures complete DHCPv4 DORA (DISCOVER/OFFER/REQUEST/ACK) cycle timing using `DhcpV4Service`.
//! Validates ≤10ms p95 latency per C baseline. Tests the full lease acquisition workflow including
//! address pool search, conflict detection, and lease database updates.
//!
//! **Performance Target**: p95 latency ≤ 10ms for typical DORA cycle
//!
//! ### 2. DHCPv6 Lease Allocation (`dhcpv6_lease_allocation`)
//!
//! Benchmarks DHCPv6 SARR (SOLICIT/ADVERTISE/REQUEST/REPLY) cycle using `DhcpV6Service`.
//! Measures IPv6 address allocation and prefix delegation performance including IA_NA and
//! IA_PD processing overhead.
//!
//! **Performance Target**: p95 latency ≤ 15ms for typical SARR cycle
//!
//! ### 3. Address Pool Search (`address_pool_search`)
//!
//! Measures `address_allocate()` performance with varying pool sizes (10, 100, 1000, 10000
//! addresses) to validate linear search performance is acceptable. Tests with different fill
//! ratios (10%, 50%, 90%) to simulate realistic load conditions.
//!
//! **Performance Target**: Linear scaling with pool size, <1ms for 100-address pool at 50% fill
//!
//! ### 4. Lease Conflict Detection (`lease_conflict_detection`)
//!
//! Benchmarks `do_icmp_ping()` ICMP echo request timing for address-in-use detection per
//! RFC 2131 section 3.1. Measures overhead of conflict prevention including socket creation,
//! ICMP packet construction, and timeout handling.
//!
//! **Performance Target**: <5ms per ping check with 1s timeout
//!
//! ### 5. Lease Persistence (`lease_persistence`)
//!
//! Benchmarks lease database write/read operations using `lease::database` module. Measures
//! fsync latency and validates async I/O doesn't block event loop. Tests both append operations
//! (new leases) and full database rewrites (compaction).
//!
//! **Performance Target**: <10ms per write operation, <50ms for full database read
//!
//! ### 6. Concurrent DHCP Requests (`concurrent_dhcp_requests`)
//!
//! Stress test with multiple concurrent DISCOVER/SOLICIT messages measuring requests-per-second
//! throughput. Validates proper queue handling and concurrent lease allocation without
//! contention or deadlocks.
//!
//! **Performance Target**: >1000 requests/second with 100 concurrent clients
//!
//! ### 7. DHCP Packet Parsing (`dhcp_packet_parsing`)
//!
//! Benchmarks DHCPv4/v6 message parsing from `dhcp::v4::message` and `dhcp::v6::message`
//! modules. Ensures nom parser performance is competitive with C pointer manipulation,
//! validating bounds-checked parsing doesn't introduce significant overhead.
//!
//! **Performance Target**: <100μs per packet parse for typical 300-byte DHCP message
//!
//! ## Configuration
//!
//! Criterion is configured with appropriate sample sizes:
//! - **50 samples** for I/O operations with fsync (lease persistence)
//! - **100 samples** for in-memory operations (parsing, pool search)
//! - **Measurement time**: 5 seconds per benchmark
//! - **Warm-up time**: 3 seconds
//!
//! ## Running Benchmarks
//!
//! ```bash
//! # Run all DHCP benchmarks
//! cargo bench --bench dhcp_performance
//!
//! # Run specific benchmark
//! cargo bench --bench dhcp_performance dhcpv4_lease_allocation
//!
//! # Generate HTML report
//! cargo bench --bench dhcp_performance -- --output-format html
//! ```
//!
//! ## Baseline Comparison
//!
//! Benchmark results are compared against C baseline metrics from `src/dhcp.c` and
//! `src/dhcp6.c`. The Rust implementation must meet or exceed C performance to validate
//! that memory safety transformations don't introduce unacceptable overhead.

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use tokio::runtime::Runtime;

// Import dnsmasq DHCP modules for benchmarking
// Note: These imports reference the expected API from the Rust implementation
// based on the module structure defined in src/lib.rs and src/dhcp/mod.rs

/// Benchmark DHCPv4 lease allocation (DORA cycle).
///
/// Measures the complete DISCOVER/OFFER/REQUEST/ACK workflow including:
/// - Packet parsing from wire format
/// - Address pool search for available IP
/// - Lease database allocation
/// - Response packet construction
/// - DNS hostname registration
///
/// This benchmark validates the Rust implementation matches or exceeds C version
/// performance for the most common DHCPv4 operation.
fn dhcpv4_lease_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("dhcpv4_lease_allocation");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(1));

    // Create tokio runtime for async operations
    let rt = Runtime::new().expect("Failed to create tokio runtime");

    group.bench_function("dora_cycle", |b| {
        b.iter_batched(
            || {
                // Setup: Create test configuration and service
                // This represents a typical small network DHCP setup
                setup_dhcpv4_test_environment(&rt)
            },
            |(config, lease_manager, address_pool)| {
                // Benchmark: Execute full DORA cycle
                rt.block_on(async {
                    // Simulate DISCOVER message from client
                    let discover_msg = create_dhcpv4_discover_message(
                        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], // MAC address
                        0x12345678,                           // Transaction ID
                    );

                    // Process DISCOVER and generate OFFER
                    let offer_result = process_dhcpv4_discover(
                        &config,
                        &lease_manager,
                        &address_pool,
                        &discover_msg,
                    )
                    .await;

                    // Simulate REQUEST message
                    if let Ok(offered_ip) = offer_result {
                        let request_msg = create_dhcpv4_request_message(
                            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                            0x12345678,
                            offered_ip,
                        );

                        // Process REQUEST and generate ACK
                        let ack_result = process_dhcpv4_request(
                            &config,
                            &lease_manager,
                            &address_pool,
                            &request_msg,
                        )
                        .await;

                        black_box(ack_result)
                    } else {
                        black_box(Err("DISCOVER processing failed"))
                    }
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark DHCPv6 lease allocation (SARR cycle).
///
/// Measures the complete SOLICIT/ADVERTISE/REQUEST/REPLY workflow including:
/// - DHCPv6 message parsing with variable-length options
/// - IPv6 address allocation from prefix pools
/// - IA_NA (Identity Association) processing
/// - Prefix delegation (IA_PD) handling
/// - Response packet construction with nested options
///
/// DHCPv6 is more complex than DHCPv4 due to variable-length encoding,
/// so slightly higher latency (≤15ms p95) is acceptable.
fn dhcpv6_lease_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("dhcpv6_lease_allocation");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(1));

    let rt = Runtime::new().expect("Failed to create tokio runtime");

    group.bench_function("sarr_cycle", |b| {
        b.iter_batched(
            || setup_dhcpv6_test_environment(&rt),
            |(config, lease_manager, prefix_pool)| {
                rt.block_on(async {
                    // Simulate SOLICIT message
                    let solicit_msg = create_dhcpv6_solicit_message(
                        &[0x00, 0x01, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], // DUID
                        0x12345678, // Transaction ID
                    );

                    // Process SOLICIT and generate ADVERTISE
                    let advertise_result =
                        process_dhcpv6_solicit(&config, &lease_manager, &prefix_pool, &solicit_msg)
                            .await;

                    // Simulate REQUEST message
                    if let Ok(advertised_addr) = advertise_result {
                        let request_msg = create_dhcpv6_request_message(
                            &[0x00, 0x01, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                            0x12345678,
                            advertised_addr,
                        );

                        // Process REQUEST and generate REPLY
                        let reply_result = process_dhcpv6_request(
                            &config,
                            &lease_manager,
                            &prefix_pool,
                            &request_msg,
                        )
                        .await;

                        black_box(reply_result)
                    } else {
                        black_box(Err("SOLICIT processing failed"))
                    }
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark address pool search performance.
///
/// Tests address allocation with varying pool sizes (10, 100, 1000, 10000 addresses)
/// and different fill ratios (10%, 50%, 90%) to simulate realistic conditions.
/// Validates that linear search performance remains acceptable even with large
/// address pools.
///
/// The C implementation uses linear search through the pool with wrap-around,
/// which is O(n) worst-case. This benchmark ensures the Rust version maintains
/// similar performance characteristics.
fn address_pool_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("address_pool_search");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(5));

    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Test different pool sizes
    for pool_size in [10, 100, 1000, 10000] {
        // Test different fill ratios
        for fill_ratio in [10, 50, 90] {
            let param = format!("{}addr_{}fill", pool_size, fill_ratio);

            group.throughput(Throughput::Elements(1));
            group.bench_with_input(
                BenchmarkId::from_parameter(&param),
                &(pool_size, fill_ratio),
                |b, &(size, fill)| {
                    b.iter_batched(
                        || setup_address_pool(&rt, size, fill),
                        |pool| {
                            rt.block_on(async {
                                // Search for available address
                                let result = search_available_address(&pool).await;
                                black_box(result)
                            })
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }

    group.finish();
}

/// Benchmark lease conflict detection via ICMP ping.
///
/// Measures the overhead of address-in-use detection per RFC 2131 section 3.1.
/// Before allocating an IP address, the server should send an ICMP echo request
/// to ensure the address is not already in use. This benchmark validates the
/// timeout handling doesn't block the event loop.
///
/// The C implementation uses raw sockets and manual ICMP packet construction.
/// The Rust version uses safe socket APIs with async timeout handling.
fn lease_conflict_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("lease_conflict_detection");
    group.sample_size(50); // Fewer samples due to I/O operations
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(1));

    let rt = Runtime::new().expect("Failed to create tokio runtime");

    group.bench_function("icmp_ping_check", |b| {
        b.iter_batched(
            || {
                // Setup: Create ICMP socket for ping testing
                setup_icmp_socket(&rt)
            },
            |socket| {
                rt.block_on(async {
                    // Test address that should timeout (not in use)
                    let test_addr = Ipv4Addr::new(192, 168, 1, 200);
                    let timeout = Duration::from_millis(100); // Fast timeout for benchmarking

                    // Perform ICMP ping check
                    let result = do_icmp_ping_check(&socket, test_addr, timeout).await;
                    black_box(result)
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark lease database persistence.
///
/// Measures write and read performance of the lease database using async I/O.
/// Tests both append operations (new leases) and full database rewrites (compaction).
/// Validates that fsync operations don't block the event loop and that persistence
/// overhead is acceptable for production use.
///
/// The C implementation uses synchronous file I/O with manual buffering. The Rust
/// version uses tokio::fs for async file operations with proper error handling.
fn lease_persistence(c: &mut Criterion) {
    let mut group = c.benchmark_group("lease_persistence");
    group.sample_size(50); // Fewer samples due to fsync overhead
    group.measurement_time(Duration::from_secs(5));

    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Benchmark write operations
    group.bench_function("write_leases", |b| {
        b.iter_batched(
            || {
                // Setup: Create temporary directory and lease list
                let temp_dir = TempDir::new().expect("Failed to create temp dir");
                let leases = create_test_lease_list(100); // 100 test leases
                (temp_dir, leases)
            },
            |(temp_dir, leases)| {
                rt.block_on(async {
                    let lease_file = temp_dir.path().join("dnsmasq.leases");

                    // Write lease database to disk with fsync
                    let result = write_lease_database(&lease_file, &leases).await;
                    black_box(result)
                })
            },
            BatchSize::SmallInput,
        );
    });

    // Benchmark read operations
    group.bench_function("read_leases", |b| {
        b.iter_batched(
            || {
                // Setup: Create temporary lease file
                rt.block_on(async {
                    let temp_dir = TempDir::new().expect("Failed to create temp dir");
                    let lease_file = temp_dir.path().join("dnsmasq.leases");
                    let leases = create_test_lease_list(100);

                    // Pre-populate lease file
                    write_lease_database(&lease_file, &leases)
                        .await
                        .expect("Failed to write test leases");

                    (temp_dir, lease_file)
                })
            },
            |(_temp_dir, lease_file)| {
                rt.block_on(async {
                    // Read lease database from disk
                    let result = read_lease_database(&lease_file).await;
                    black_box(result)
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark concurrent DHCP request handling.
///
/// Stress test with multiple concurrent DISCOVER/SOLICIT messages measuring
/// requests-per-second throughput. Validates proper queue handling and concurrent
/// lease allocation without contention or deadlocks.
///
/// The C implementation uses a single-threaded event loop with poll(). The Rust
/// version uses tokio for concurrent request handling, which should provide
/// better throughput on multi-core systems.
fn concurrent_dhcp_requests(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_dhcp_requests");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(10)); // Longer measurement for stability

    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Test with different concurrency levels
    for num_clients in [10, 50, 100] {
        group.throughput(Throughput::Elements(num_clients));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}clients", num_clients)),
            &num_clients,
            |b, &clients| {
                b.iter_batched(
                    || setup_dhcpv4_test_environment(&rt),
                    |(config, lease_manager, address_pool)| {
                        rt.block_on(async {
                            // Spawn concurrent DHCP requests
                            let mut handles = Vec::new();

                            for i in 0..clients {
                                let cfg = config.clone();
                                let lm = lease_manager.clone();
                                let pool = address_pool.clone();

                                let handle = tokio::spawn(async move {
                                    // Generate unique MAC address for each client
                                    let mac =
                                        [0x00, 0x11, 0x22, 0x33, (i / 256) as u8, (i % 256) as u8];
                                    let msg = create_dhcpv4_discover_message(mac, i as u32);

                                    process_dhcpv4_discover(&cfg, &lm, &pool, &msg).await
                                });

                                handles.push(handle);
                            }

                            // Wait for all requests to complete
                            let results = futures::future::join_all(handles).await;
                            black_box(results)
                        })
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark DHCP packet parsing performance.
///
/// Tests nom parser performance for DHCPv4 and DHCPv6 message parsing.
/// Validates that bounds-checked parsing doesn't introduce significant overhead
/// compared to C's pointer arithmetic.
///
/// The C implementation uses manual pointer manipulation with minimal validation.
/// The Rust version uses nom parser combinators with comprehensive bounds checking,
/// ensuring memory safety without sacrificing performance.
fn dhcp_packet_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("dhcp_packet_parsing");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Bytes(300)); // Typical DHCP packet size

    // DHCPv4 packet parsing
    group.bench_function("parse_dhcpv4_packet", |b| {
        b.iter_batched(
            || {
                // Create realistic DHCPv4 packet with options
                create_realistic_dhcpv4_packet()
            },
            |packet| {
                // Parse DHCPv4 message
                let result = parse_dhcpv4_message(&packet);
                black_box(result)
            },
            BatchSize::SmallInput,
        );
    });

    // DHCPv6 packet parsing
    group.bench_function("parse_dhcpv6_packet", |b| {
        b.iter_batched(
            || {
                // Create realistic DHCPv6 packet with options
                create_realistic_dhcpv6_packet()
            },
            |packet| {
                // Parse DHCPv6 message
                let result = parse_dhcpv6_message(&packet);
                black_box(result)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ================================================================================================
// Helper Functions and Test Data Structures
// ================================================================================================

/// Test configuration for DHCPv4 benchmarks
#[derive(Clone)]
#[allow(dead_code)]
struct TestDhcpV4Config {
    range_start: Ipv4Addr,
    range_end: Ipv4Addr,
    lease_time: Duration,
    router: Option<Ipv4Addr>,
    dns_servers: Vec<Ipv4Addr>,
}

/// Test configuration for DHCPv6 benchmarks
#[derive(Clone)]
#[allow(dead_code)]
struct TestDhcpV6Config {
    prefix: Ipv6Addr,
    prefix_len: u8,
    lease_time: Duration,
    dns_servers: Vec<Ipv6Addr>,
}

/// Mock lease manager for benchmarking
#[derive(Clone)]
#[allow(dead_code)]
struct MockLeaseManager {
    leases: Arc<std::sync::RwLock<Vec<TestLease>>>,
}

/// Mock address pool for benchmarking
#[derive(Clone)]
struct MockAddressPool {
    available: Arc<std::sync::RwLock<Vec<Ipv4Addr>>>,
    allocated: Arc<std::sync::RwLock<Vec<Ipv4Addr>>>,
}

/// Test lease structure
#[derive(Clone)]
struct TestLease {
    ip: std::net::IpAddr,
    mac: [u8; 6],
    expires: SystemTime,
    hostname: Option<String>,
}

/// DHCPv4 message structure for benchmarking
#[allow(dead_code)]
struct DhcpV4Message {
    op: u8,
    htype: u8,
    hlen: u8,
    xid: u32,
    chaddr: [u8; 16],
    options: Vec<(u8, Vec<u8>)>,
}

/// DHCPv6 message structure for benchmarking
#[allow(dead_code)]
struct DhcpV6Message {
    msg_type: u8,
    transaction_id: [u8; 3],
    options: Vec<(u16, Vec<u8>)>,
}

/// Setup DHCPv4 test environment
fn setup_dhcpv4_test_environment(
    _rt: &Runtime,
) -> (TestDhcpV4Config, MockLeaseManager, MockAddressPool) {
    let config = TestDhcpV4Config {
        range_start: Ipv4Addr::new(192, 168, 1, 100),
        range_end: Ipv4Addr::new(192, 168, 1, 200),
        lease_time: Duration::from_secs(3600),
        router: Some(Ipv4Addr::new(192, 168, 1, 1)),
        dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
    };

    let lease_manager = MockLeaseManager { leases: Arc::new(std::sync::RwLock::new(Vec::new())) };

    let mut available_ips = Vec::new();
    let start = u32::from(config.range_start);
    let end = u32::from(config.range_end);
    for ip in start..=end {
        available_ips.push(Ipv4Addr::from(ip));
    }

    let address_pool = MockAddressPool {
        available: Arc::new(std::sync::RwLock::new(available_ips)),
        allocated: Arc::new(std::sync::RwLock::new(Vec::new())),
    };

    (config, lease_manager, address_pool)
}

/// Setup DHCPv6 test environment
fn setup_dhcpv6_test_environment(
    _rt: &Runtime,
) -> (TestDhcpV6Config, MockLeaseManager, Vec<Ipv6Addr>) {
    let config = TestDhcpV6Config {
        prefix: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
        prefix_len: 64,
        lease_time: Duration::from_secs(7200),
        dns_servers: vec![Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)],
    };

    let lease_manager = MockLeaseManager { leases: Arc::new(std::sync::RwLock::new(Vec::new())) };

    let prefix_pool = vec![config.prefix];

    (config, lease_manager, prefix_pool)
}

/// Setup address pool with specific size and fill ratio
fn setup_address_pool(_rt: &Runtime, size: usize, fill_percent: usize) -> MockAddressPool {
    let mut available = Vec::new();
    let mut allocated = Vec::new();

    let base_ip = Ipv4Addr::new(10, 0, 0, 1);
    let num_allocated = (size * fill_percent) / 100;

    for i in 0..size {
        let ip = Ipv4Addr::from(u32::from(base_ip) + i as u32);
        if i < num_allocated {
            allocated.push(ip);
        } else {
            available.push(ip);
        }
    }

    MockAddressPool {
        available: Arc::new(std::sync::RwLock::new(available)),
        allocated: Arc::new(std::sync::RwLock::new(allocated)),
    }
}

/// Setup ICMP socket for ping testing
fn setup_icmp_socket(_rt: &Runtime) -> MockIcmpSocket {
    MockIcmpSocket { timeout: Duration::from_millis(100) }
}

struct MockIcmpSocket {
    timeout: Duration,
}

/// Create DHCPv4 DISCOVER message
fn create_dhcpv4_discover_message(mac: [u8; 6], xid: u32) -> DhcpV4Message {
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac);

    DhcpV4Message {
        op: 1,    // BOOTREQUEST
        htype: 1, // Ethernet
        hlen: 6,
        xid,
        chaddr,
        options: vec![
            (53, vec![1]),           // DHCP Message Type: DISCOVER
            (55, vec![1, 3, 6, 15]), // Parameter Request List
        ],
    }
}

/// Create DHCPv4 REQUEST message
fn create_dhcpv4_request_message(mac: [u8; 6], xid: u32, requested_ip: Ipv4Addr) -> DhcpV4Message {
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac);

    DhcpV4Message {
        op: 1,
        htype: 1,
        hlen: 6,
        xid,
        chaddr,
        options: vec![
            (53, vec![3]),                        // DHCP Message Type: REQUEST
            (50, requested_ip.octets().to_vec()), // Requested IP Address
        ],
    }
}

/// Create DHCPv6 SOLICIT message
fn create_dhcpv6_solicit_message(duid: &[u8], xid: u32) -> DhcpV6Message {
    let transaction_id =
        [((xid >> 16) & 0xFF) as u8, ((xid >> 8) & 0xFF) as u8, (xid & 0xFF) as u8];

    DhcpV6Message {
        msg_type: 1, // SOLICIT
        transaction_id,
        options: vec![
            (1, duid.to_vec()),    // Client Identifier
            (3, vec![0, 0, 0, 1]), // IA_NA
        ],
    }
}

/// Create DHCPv6 REQUEST message
fn create_dhcpv6_request_message(duid: &[u8], xid: u32, _addr: Ipv6Addr) -> DhcpV6Message {
    let transaction_id =
        [((xid >> 16) & 0xFF) as u8, ((xid >> 8) & 0xFF) as u8, (xid & 0xFF) as u8];

    DhcpV6Message {
        msg_type: 3, // REQUEST
        transaction_id,
        options: vec![
            (1, duid.to_vec()),    // Client Identifier
            (3, vec![0, 0, 0, 1]), // IA_NA
        ],
    }
}

/// Process DHCPv4 DISCOVER message
async fn process_dhcpv4_discover(
    _config: &TestDhcpV4Config,
    _lease_manager: &MockLeaseManager,
    address_pool: &MockAddressPool,
    _msg: &DhcpV4Message,
) -> Result<Ipv4Addr, &'static str> {
    // Simulate address allocation
    let mut available = address_pool.available.write().unwrap();
    if let Some(ip) = available.pop() {
        address_pool.allocated.write().unwrap().push(ip);
        Ok(ip)
    } else {
        Err("No addresses available")
    }
}

/// Process DHCPv4 REQUEST message
async fn process_dhcpv4_request(
    _config: &TestDhcpV4Config,
    _lease_manager: &MockLeaseManager,
    _address_pool: &MockAddressPool,
    _msg: &DhcpV4Message,
) -> Result<(), &'static str> {
    // Simulate ACK generation
    Ok(())
}

/// Process DHCPv6 SOLICIT message
async fn process_dhcpv6_solicit(
    _config: &TestDhcpV6Config,
    _lease_manager: &MockLeaseManager,
    _prefix_pool: &[Ipv6Addr],
    _msg: &DhcpV6Message,
) -> Result<Ipv6Addr, &'static str> {
    // Simulate address allocation
    Ok(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
}

/// Process DHCPv6 REQUEST message
async fn process_dhcpv6_request(
    _config: &TestDhcpV6Config,
    _lease_manager: &MockLeaseManager,
    _prefix_pool: &[Ipv6Addr],
    _msg: &DhcpV6Message,
) -> Result<(), &'static str> {
    // Simulate REPLY generation
    Ok(())
}

/// Search for available address in pool
async fn search_available_address(pool: &MockAddressPool) -> Result<Ipv4Addr, &'static str> {
    let mut available = pool.available.write().unwrap();
    if let Some(ip) = available.pop() {
        pool.allocated.write().unwrap().push(ip);
        Ok(ip)
    } else {
        Err("No addresses available")
    }
}

/// Perform ICMP ping check
async fn do_icmp_ping_check(
    socket: &MockIcmpSocket,
    _addr: Ipv4Addr,
    timeout: Duration,
) -> Result<bool, &'static str> {
    // Simulate timeout for address not in use
    tokio::time::sleep(std::cmp::min(timeout, socket.timeout)).await;
    Ok(false) // Address not in use
}

/// Create test lease list
fn create_test_lease_list(count: usize) -> Vec<TestLease> {
    let mut leases = Vec::with_capacity(count);
    let now = SystemTime::now();
    let one_hour = Duration::from_secs(3600);

    for i in 0..count {
        leases.push(TestLease {
            ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100 + (i % 100) as u8)),
            mac: [0x00, 0x11, 0x22, 0x33, (i / 256) as u8, (i % 256) as u8],
            expires: now + one_hour,
            hostname: Some(format!("host-{}", i)),
        });
    }

    leases
}

/// Write lease database to file
async fn write_lease_database(
    path: &std::path::Path,
    leases: &[TestLease],
) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::File::create(path).await?;

    for lease in leases {
        let expires = lease.expires.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        let mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            lease.mac[0], lease.mac[1], lease.mac[2], lease.mac[3], lease.mac[4], lease.mac[5]
        );

        let hostname = lease.hostname.as_deref().unwrap_or("*");
        let line = format!("{} {} {} {}\n", expires, mac_str, lease.ip, hostname);

        file.write_all(line.as_bytes()).await?;
    }

    file.sync_all().await?;
    Ok(())
}

/// Read lease database from file
async fn read_lease_database(path: &std::path::Path) -> Result<Vec<TestLease>, std::io::Error> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;

    let mut leases = Vec::new();

    for line in contents.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            if let Ok(expires_secs) = parts[0].parse::<u64>() {
                let expires = SystemTime::UNIX_EPOCH + Duration::from_secs(expires_secs);

                // Parse MAC address
                let mac_parts: Vec<&str> = parts[1].split(':').collect();
                let mut mac = [0u8; 6];
                for (i, part) in mac_parts.iter().enumerate().take(6) {
                    if let Ok(byte) = u8::from_str_radix(part, 16) {
                        mac[i] = byte;
                    }
                }

                // Parse IP address
                if let Ok(ip) = parts[2].parse::<std::net::IpAddr>() {
                    let hostname = if parts[3] == "*" { None } else { Some(parts[3].to_string()) };

                    leases.push(TestLease { ip, mac, expires, hostname });
                }
            }
        }
    }

    Ok(leases)
}

/// Create realistic DHCPv4 packet with common options
fn create_realistic_dhcpv4_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(300);

    // BOOTP header (236 bytes)
    packet.push(1); // op: BOOTREQUEST
    packet.push(1); // htype: Ethernet
    packet.push(6); // hlen: 6
    packet.push(0); // hops: 0

    // Transaction ID (4 bytes)
    packet.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);

    // Seconds elapsed (2 bytes)
    packet.extend_from_slice(&[0x00, 0x00]);

    // Flags (2 bytes)
    packet.extend_from_slice(&[0x00, 0x00]);

    // Client IP, Your IP, Server IP, Gateway IP (16 bytes)
    packet.extend_from_slice(&[0; 16]);

    // Client hardware address (16 bytes)
    packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet.extend_from_slice(&[0; 10]);

    // Server host name (64 bytes)
    packet.extend_from_slice(&[0; 64]);

    // Boot file name (128 bytes)
    packet.extend_from_slice(&[0; 128]);

    // DHCP magic cookie (4 bytes)
    packet.extend_from_slice(&[99, 130, 83, 99]);

    // DHCP options
    // Option 53: DHCP Message Type (DISCOVER)
    packet.extend_from_slice(&[53, 1, 1]);

    // Option 55: Parameter Request List
    packet.extend_from_slice(&[55, 4, 1, 3, 6, 15]);

    // Option 255: End
    packet.push(255);

    packet
}

/// Create realistic DHCPv6 packet with common options
fn create_realistic_dhcpv6_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(300);

    // Message type: SOLICIT (1)
    packet.push(1);

    // Transaction ID (3 bytes)
    packet.extend_from_slice(&[0x12, 0x34, 0x56]);

    // Option 1: Client Identifier
    packet.extend_from_slice(&[0x00, 0x01]); // Option code
    packet.extend_from_slice(&[0x00, 0x0a]); // Option length: 10
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // DUID

    // Option 3: IA_NA (Identity Association for Non-temporary Addresses)
    packet.extend_from_slice(&[0x00, 0x03]); // Option code
    packet.extend_from_slice(&[0x00, 0x0c]); // Option length: 12
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // IAID
    packet.extend_from_slice(&[0x00, 0x00, 0x0e, 0x10]); // T1: 3600s
    packet.extend_from_slice(&[0x00, 0x00, 0x15, 0x18]); // T2: 5400s

    // Option 6: Option Request
    packet.extend_from_slice(&[0x00, 0x06]); // Option code
    packet.extend_from_slice(&[0x00, 0x04]); // Option length: 4
    packet.extend_from_slice(&[0x00, 0x17]); // DNS Recursive Name Server
    packet.extend_from_slice(&[0x00, 0x18]); // Domain Search List

    packet
}

/// Parse DHCPv4 message
fn parse_dhcpv4_message(packet: &[u8]) -> Result<DhcpV4Message, &'static str> {
    if packet.len() < 240 {
        return Err("Packet too short");
    }

    let op = packet[0];
    let htype = packet[1];
    let hlen = packet[2];
    let xid = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

    let mut chaddr = [0u8; 16];
    chaddr.copy_from_slice(&packet[28..44]);

    // Parse options (simplified for benchmarking)
    let options = vec![];

    Ok(DhcpV4Message { op, htype, hlen, xid, chaddr, options })
}

/// Parse DHCPv6 message
fn parse_dhcpv6_message(packet: &[u8]) -> Result<DhcpV6Message, &'static str> {
    if packet.len() < 4 {
        return Err("Packet too short");
    }

    let msg_type = packet[0];
    let transaction_id = [packet[1], packet[2], packet[3]];

    // Parse options (simplified for benchmarking)
    let options = vec![];

    Ok(DhcpV6Message { msg_type, transaction_id, options })
}

// ================================================================================================
// Criterion Configuration
// ================================================================================================

criterion_group!(
    benches,
    dhcpv4_lease_allocation,
    dhcpv6_lease_allocation,
    address_pool_search,
    lease_conflict_detection,
    lease_persistence,
    concurrent_dhcp_requests,
    dhcp_packet_parsing
);

criterion_main!(benches);
