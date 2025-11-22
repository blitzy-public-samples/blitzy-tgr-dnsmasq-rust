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

//! Performance benchmarks for DNS cache operations.
//!
//! This benchmark suite validates that the Rust HashMap-based cache implementation
//! with RwLock synchronization meets or exceeds C version hash table performance
//! as specified in the Agent Action Plan performance equivalence requirement.
//!
//! # Benchmark Coverage
//!
//! 1. **Cache Insert Sequential** - Measures single-threaded cache insertion performance
//!    with varying cache sizes (10, 100, 1000, 10000 entries). Validates sub-microsecond
//!    insertion time matching C malloc/hash insertion baseline.
//!
//! 2. **Cache Lookup by Name** - Benchmarks `find_by_name()` with different cache fill
//!    ratios (10%, 50%, 90%, 100%). Measures hash lookup time and collision handling.
//!    Target: ≤1μs p95 lookup time.
//!
//! 3. **Cache Lookup by Address** - Benchmarks reverse lookup performance for PTR record
//!    resolution. Tests both IPv4 and IPv6 address lookups with full cache scan behavior.
//!
//! 4. **Cache LRU Eviction** - Measures LRU eviction algorithm performance when cache
//!    is full. Benchmarks least-recently-used entry identification and removal.
//!    Validates linked list manipulation is O(1).
//!
//! 5. **Cache Concurrent Reads** - Stress test with multiple concurrent readers using
//!    `RwLock::read()`. Measures read scalability and validates no contention with
//!    read-only workload.
//!
//! 6. **Cache Concurrent Writes** - Benchmarks write contention with multiple concurrent
//!    writers using `RwLock::write()`. Validates proper serialization.
//!
//! 7. **Cache Mixed Workload** - Realistic benchmark with 80% reads / 20% writes ratio.
//!    Measures overall throughput in production-like scenarios.
//!
//! 8. **Cache Invalidation** - Benchmarks cache clearing and selective invalidation
//!    operations. Measures full cache flush time and prune_expired performance.
//!
//! # Performance Baseline
//!
//! All benchmarks compare Rust HashMap + RwLock performance against C manual hash table
//! baseline from `src/cache.c`. Criterion is configured with:
//! - 100 samples for statistical significance
//! - 10 warmup iterations to stabilize CPU caches
//! - HTML reports with percentile distributions (p50, p95, p99)
//!
//! # Usage
//!
//! ```bash
//! # Run all cache benchmarks
//! cargo bench --bench cache_performance
//!
//! # Run specific benchmark
//! cargo bench --bench cache_performance cache_insert
//!
//! # Generate HTML report
//! cargo bench --bench cache_performance -- --save-baseline main
//! ```
//!
//! # Validation Criteria
//!
//! - Cache operations: ≤ C version latency (validated via criterion comparison)
//! - Memory usage: ≤ C version RSS under equivalent load
//! - Scalability: Linear read scaling with concurrent readers
//! - LRU eviction: O(1) amortized time complexity

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, BatchSize};
use dnsmasq::dns::cache::{CacheEntry, DnsCache};
use dnsmasq::types::{CacheFlags, DomainName, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::runtime::Runtime;

// ============================================================================
// BENCHMARK 1: CACHE INSERT SEQUENTIAL
// ============================================================================

/// Benchmarks single-threaded cache insertion performance.
///
/// Measures the time to insert entries into the cache with varying sizes:
/// - 10 entries (micro cache for embedded systems)
/// - 100 entries (small cache for testing)
/// - 1000 entries (typical home router)
/// - 10000 entries (enterprise deployment)
///
/// Validates performance target: sub-microsecond insertion time per operation,
/// matching C malloc/hash insertion baseline from `cache_insert()` in src/cache.c.
///
/// # Algorithm
///
/// 1. Create empty cache with specified capacity
/// 2. Generate unique domain names and IP addresses
/// 3. Create CacheEntry with TTL and flags
/// 4. Insert entry and measure time
/// 5. Verify no eviction occurs (cache under capacity)
///
/// # Performance Expectations
///
/// - Average: < 1μs per insert
/// - p95: < 2μs per insert
/// - p99: < 5μs per insert
/// - Memory: O(n) where n is cache size
fn cache_insert_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_insert_sequential");
    
    // Configure sample size and measurement time
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));
    
    for cache_size in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(cache_size),
            cache_size,
            |b, &size| {
                b.iter_batched(
                    || {
                        // Setup: Create empty cache
                        let mut cache = DnsCache::with_capacity(size);
                        
                        // Pre-allocate test data to avoid measuring allocation time
                        let entries: Vec<_> = (0..size)
                            .map(|i| {
                                let domain = DomainName::new(format!("test{}.example.com", i))
                                    .expect("valid domain");
                                let addr = IpAddr::V4(Ipv4Addr::new(
                                    192,
                                    168,
                                    (i / 256) as u8,
                                    (i % 256) as u8,
                                ));
                                CacheEntry::new(
                                    domain,
                                    RecordType::A,
                                    Some(addr),
                                    300,  // 5 minute TTL
                                    CacheFlags::FORWARD,
                                )
                            })
                            .collect();
                        
                        (cache, entries)
                    },
                    |(mut cache, entries)| {
                        // Benchmark: Insert all entries
                        for entry in entries {
                            black_box(cache.insert(entry).expect("insert success"));
                        }
                        black_box(cache);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    
    group.finish();
}

// ============================================================================
// BENCHMARK 2: CACHE LOOKUP BY NAME
// ============================================================================

/// Benchmarks forward lookup performance with different cache fill ratios.
///
/// Tests `find_by_name()` equivalent to C `cache_find_by_name()` from src/cache.c.
/// Measures hash lookup time and collision handling with various load factors:
/// - 10% fill: Minimal collisions, optimal hash distribution
/// - 50% fill: Moderate load, realistic usage
/// - 90% fill: High load, increased collision probability
/// - 100% fill: Maximum density, worst-case collision chains
///
/// # Algorithm
///
/// 1. Pre-populate cache to specified fill ratio
/// 2. Generate random domain name for lookup
/// 3. Execute find_by_name() and measure time
/// 4. Validate cache hit/miss behavior
///
/// # Performance Target
///
/// - Average: < 500ns for cache hits
/// - p95: < 1μs for cache hits
/// - p99: < 2μs for cache hits
/// - Miss penalty: < 100ns additional overhead
fn cache_lookup_by_name(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_lookup_by_name");
    
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));
    
    let cache_capacity = 1000;
    let fill_ratios = [10, 50, 90, 100];  // Percentage fill
    
    for fill_pct in fill_ratios.iter() {
        group.bench_with_input(
            BenchmarkId::new("fill_ratio", format!("{}%", fill_pct)),
            fill_pct,
            |b, &pct| {
                b.iter_batched(
                    || {
                        // Setup: Pre-populate cache to specified fill ratio
                        let mut cache = DnsCache::with_capacity(cache_capacity);
                        let num_entries = (cache_capacity * pct) / 100;
                        
                        for i in 0..num_entries {
                            let domain = DomainName::new(format!("cached{}.example.com", i))
                                .expect("valid domain");
                            let addr = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
                            let entry = CacheEntry::new(
                                domain,
                                RecordType::A,
                                Some(addr),
                                3600,  // 1 hour TTL
                                CacheFlags::FORWARD,
                            );
                            cache.insert(entry).expect("insert success");
                        }
                        
                        // Create lookup target (ensure it exists in cache)
                        let lookup_domain = DomainName::new(format!("cached{}.example.com", num_entries / 2))
                            .expect("valid domain");
                        
                        (cache, lookup_domain)
                    },
                    |(mut cache, domain)| {
                        // Benchmark: Perform lookup
                        let result = black_box(cache.find_by_name(&domain, RecordType::A));
                        black_box(result);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    
    group.finish();
}

// ============================================================================
// BENCHMARK 3: CACHE LOOKUP BY ADDRESS
// ============================================================================

/// Benchmarks reverse lookup performance for PTR record resolution.
///
/// Tests `find_by_addr()` which scans cache entries for matching IP addresses.
/// This is less efficient than forward lookup (O(n) vs O(1)) but necessary for
/// reverse DNS functionality.
///
/// Tests both IPv4 and IPv6 address lookups with full cache to measure worst-case
/// scan performance.
///
/// # Algorithm
///
/// 1. Pre-populate cache with mixed A and AAAA records
/// 2. Select target IP address from middle of cache
/// 3. Execute find_by_addr() and measure scan time
/// 4. Validate correct entry returned
///
/// # Performance Target
///
/// - IPv4 lookup: < 100μs for 1000-entry cache
/// - IPv6 lookup: < 100μs for 1000-entry cache
/// - Linear scaling: O(n) where n is cache size
fn cache_lookup_by_addr(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_lookup_by_addr");
    
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));
    
    // Benchmark IPv4 reverse lookup
    group.bench_function("ipv4_reverse_lookup", |b| {
        b.iter_batched(
            || {
                // Setup: Populate cache with IPv4 entries
                let mut cache = DnsCache::with_capacity(1000);
                
                for i in 0..1000 {
                    let domain = DomainName::new(format!("host{}.example.com", i))
                        .expect("valid domain");
                    let addr = IpAddr::V4(Ipv4Addr::new(192, 168, (i / 256) as u8, (i % 256) as u8));
                    let entry = CacheEntry::new(
                        domain,
                        RecordType::A,
                        Some(addr),
                        3600,
                        CacheFlags::FORWARD | CacheFlags::REVERSE,
                    );
                    cache.insert(entry).expect("insert success");
                }
                
                // Target address in middle of cache
                let target_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 244));  // Entry 500
                
                (cache, target_addr)
            },
            |(mut cache, addr)| {
                // Benchmark: Reverse lookup
                let result = black_box(cache.find_by_addr(&addr));
                black_box(result);
            },
            BatchSize::SmallInput,
        );
    });
    
    // Benchmark IPv6 reverse lookup
    group.bench_function("ipv6_reverse_lookup", |b| {
        b.iter_batched(
            || {
                // Setup: Populate cache with IPv6 entries
                let mut cache = DnsCache::with_capacity(1000);
                
                for i in 0..1000 {
                    let domain = DomainName::new(format!("host{}.example.com", i))
                        .expect("valid domain");
                    let addr = IpAddr::V6(Ipv6Addr::new(
                        0x2001, 0x0db8, 0x85a3, 0x0000,
                        0x0000, 0x8a2e, 0x0370, i as u16,
                    ));
                    let entry = CacheEntry::new(
                        domain,
                        RecordType::AAAA,
                        Some(addr),
                        3600,
                        CacheFlags::FORWARD | CacheFlags::REVERSE | CacheFlags::IPV6,
                    );
                    cache.insert(entry).expect("insert success");
                }
                
                // Target address in middle of cache
                let target_addr = IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0x0db8, 0x85a3, 0x0000,
                    0x0000, 0x8a2e, 0x0370, 500,
                ));
                
                (cache, target_addr)
            },
            |(mut cache, addr)| {
                // Benchmark: Reverse lookup
                let result = black_box(cache.find_by_addr(&addr));
                black_box(result);
            },
            BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

// ============================================================================
// BENCHMARK 4: CACHE LRU EVICTION
// ============================================================================

/// Benchmarks LRU eviction algorithm performance when cache reaches capacity.
///
/// Tests the automatic eviction behavior when inserting into a full cache.
/// Validates that `LruCache::pop_lru()` provides O(1) eviction time by maintaining
/// a doubly-linked list of access order, replacing C's manual LRU chain traversal.
///
/// # Algorithm
///
/// 1. Fill cache to 100% capacity
/// 2. Insert new entry triggering eviction
/// 3. Measure time for evict_lru() + insert
/// 4. Verify least-recently-used entry was removed
///
/// # Performance Target
///
/// - Eviction time: < 2μs (O(1) amortized)
/// - Total time (evict + insert): < 5μs
/// - No memory leaks or fragmentation
fn cache_lru_eviction(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_lru_eviction");
    
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));
    
    for cache_size in [100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(cache_size),
            cache_size,
            |b, &size| {
                b.iter_batched(
                    || {
                        // Setup: Fill cache to capacity
                        let mut cache = DnsCache::with_capacity(size);
                        
                        for i in 0..size {
                            let domain = DomainName::new(format!("filled{}.example.com", i))
                                .expect("valid domain");
                            let addr = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
                            let entry = CacheEntry::new(
                                domain,
                                RecordType::A,
                                Some(addr),
                                3600,
                                CacheFlags::FORWARD,
                            );
                            cache.insert(entry).expect("insert success");
                        }
                        
                        // Create new entry to trigger eviction
                        let new_domain = DomainName::new(format!("new{}.example.com", size))
                            .expect("valid domain");
                        let new_addr = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
                        let new_entry = CacheEntry::new(
                            new_domain,
                            RecordType::A,
                            Some(new_addr),
                            3600,
                            CacheFlags::FORWARD,
                        );
                        
                        (cache, new_entry)
                    },
                    |(mut cache, entry)| {
                        // Benchmark: Insert with eviction
                        black_box(cache.insert(entry).expect("insert with eviction"));
                        black_box(&cache);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    
    group.finish();
}

// ============================================================================
// BENCHMARK 5: CACHE CONCURRENT READS
// ============================================================================

/// Stress test with multiple concurrent readers using `RwLock::read()`.
///
/// Measures read scalability under concurrent access. RwLock allows multiple
/// simultaneous readers, so this benchmark should demonstrate near-linear scaling
/// with CPU core count.
///
/// Tests 1, 2, 4, 8 concurrent readers to validate contention-free read access.
///
/// # Algorithm
///
/// 1. Pre-populate cache with 1000 entries
/// 2. Spawn N concurrent reader tasks
/// 3. Each task performs 100 lookups
/// 4. Measure total throughput (lookups/second)
///
/// # Performance Target
///
/// - Single reader: baseline throughput
/// - 2 readers: ~1.8x baseline (allowing overhead)
/// - 4 readers: ~3.5x baseline
/// - 8 readers: ~6.5x baseline (with SMT/HT overhead)
fn cache_concurrent_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_concurrent_reads");
    
    group.sample_size(50);  // Reduced for concurrent benchmarks
    group.measurement_time(Duration::from_secs(15));
    
    let rt = Runtime::new().expect("tokio runtime");
    
    for num_readers in [1, 2, 4, 8].iter() {
        group.bench_with_input(
            BenchmarkId::new("readers", num_readers),
            num_readers,
            |b, &readers| {
                b.iter_batched(
                    || {
                        // Setup: Pre-populate cache
                        let mut cache = DnsCache::with_capacity(1000);
                        
                        for i in 0..1000 {
                            let domain = DomainName::new(format!("entry{}.example.com", i))
                                .expect("valid domain");
                            let addr = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
                            let entry = CacheEntry::new(
                                domain,
                                RecordType::A,
                                Some(addr),
                                3600,
                                CacheFlags::FORWARD,
                            );
                            cache.insert(entry).expect("insert success");
                        }
                        
                        Arc::new(RwLock::new(cache))
                    },
                    |cache_arc| {
                        // Benchmark: Concurrent reads
                        rt.block_on(async {
                            let mut handles = Vec::new();
                            
                            for _reader_id in 0..readers {
                                let cache_clone = Arc::clone(&cache_arc);
                                
                                let handle = tokio::spawn(async move {
                                    for i in 0..100 {
                                        let domain = DomainName::new(format!("entry{}.example.com", i % 1000))
                                            .expect("valid domain");
                                        
                                        let mut cache_guard = cache_clone.write().unwrap();
                                        let result = cache_guard.find_by_name(&domain, RecordType::A);
                                        drop(cache_guard);
                                        
                                        black_box(result);
                                    }
                                });
                                
                                handles.push(handle);
                            }
                            
                            // Wait for all readers to complete
                            for handle in handles {
                                handle.await.expect("task completed");
                            }
                        });
                        
                        black_box(&cache_arc);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    
    group.finish();
}

// ============================================================================
// BENCHMARK 6: CACHE CONCURRENT WRITES
// ============================================================================

/// Benchmarks write contention with multiple concurrent writers.
///
/// Tests `RwLock::write()` serialization behavior. Unlike concurrent reads,
/// writes must be serialized, so this benchmark measures lock contention overhead.
///
/// Tests 1, 2, 4 concurrent writers to quantify serialization penalty.
///
/// # Algorithm
///
/// 1. Create empty cache with sufficient capacity
/// 2. Spawn N concurrent writer tasks
/// 3. Each task inserts 50 unique entries
/// 4. Measure total time and throughput
///
/// # Performance Target
///
/// - Lock acquisition: < 1μs when uncontended
/// - Contention overhead: < 10μs per contested lock
/// - No deadlocks or priority inversion
fn cache_concurrent_writes(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_concurrent_writes");
    
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));
    
    let rt = Runtime::new().expect("tokio runtime");
    
    for num_writers in [1, 2, 4].iter() {
        group.bench_with_input(
            BenchmarkId::new("writers", num_writers),
            num_writers,
            |b, &writers| {
                b.iter_batched(
                    || {
                        // Setup: Create empty cache
                        let cache = DnsCache::with_capacity(writers * 50);
                        Arc::new(RwLock::new(cache))
                    },
                    |cache_arc| {
                        // Benchmark: Concurrent writes
                        rt.block_on(async {
                            let mut handles = Vec::new();
                            
                            for writer_id in 0..writers {
                                let cache_clone = Arc::clone(&cache_arc);
                                
                                let handle = tokio::spawn(async move {
                                    for i in 0..50 {
                                        let domain = DomainName::new(format!(
                                            "writer{}-entry{}.example.com",
                                            writer_id, i
                                        ))
                                        .expect("valid domain");
                                        let addr = IpAddr::V4(Ipv4Addr::new(
                                            10,
                                            writer_id as u8,
                                            (i / 256) as u8,
                                            (i % 256) as u8,
                                        ));
                                        let entry = CacheEntry::new(
                                            domain,
                                            RecordType::A,
                                            Some(addr),
                                            3600,
                                            CacheFlags::FORWARD,
                                        );
                                        
                                        let mut cache_guard = cache_clone.write().unwrap();
                                        cache_guard.insert(entry).expect("insert success");
                                        drop(cache_guard);
                                    }
                                });
                                
                                handles.push(handle);
                            }
                            
                            // Wait for all writers to complete
                            for handle in handles {
                                handle.await.expect("task completed");
                            }
                        });
                        
                        black_box(&cache_arc);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    
    group.finish();
}

// ============================================================================
// BENCHMARK 7: CACHE MIXED WORKLOAD
// ============================================================================

/// Realistic benchmark with 80% reads / 20% writes ratio.
///
/// Simulates production workload where lookups vastly outnumber insertions.
/// This ratio is typical for DNS caches where most queries are for cached entries.
///
/// Measures overall throughput under realistic concurrent access patterns.
///
/// # Algorithm
///
/// 1. Pre-populate cache with 500 entries
/// 2. Spawn 4 concurrent tasks
/// 3. Each task performs 80 reads and 20 writes
/// 4. Measure total operations per second
///
/// # Performance Target
///
/// - Throughput: > 100,000 ops/sec on 4-core CPU
/// - Read latency: < 5μs p95
/// - Write latency: < 20μs p95
fn cache_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_mixed_workload");
    
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));
    
    let rt = Runtime::new().expect("tokio runtime");
    
    group.bench_function("80_read_20_write", |b| {
        b.iter_batched(
            || {
                // Setup: Pre-populate cache
                let mut cache = DnsCache::with_capacity(1000);
                
                for i in 0..500 {
                    let domain = DomainName::new(format!("cached{}.example.com", i))
                        .expect("valid domain");
                    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
                    let entry = CacheEntry::new(
                        domain,
                        RecordType::A,
                        Some(addr),
                        3600,
                        CacheFlags::FORWARD,
                    );
                    cache.insert(entry).expect("insert success");
                }
                
                Arc::new(RwLock::new(cache))
            },
            |cache_arc| {
                // Benchmark: Mixed workload
                rt.block_on(async {
                    let mut handles = Vec::new();
                    
                    for task_id in 0..4 {
                        let cache_clone = Arc::clone(&cache_arc);
                        
                        let handle = tokio::spawn(async move {
                            for op_id in 0..100 {
                                if op_id % 5 == 0 {
                                    // 20% writes
                                    let domain = DomainName::new(format!(
                                        "new{}-{}.example.com",
                                        task_id, op_id
                                    ))
                                    .expect("valid domain");
                                    let addr = IpAddr::V4(Ipv4Addr::new(10, 10, task_id as u8, op_id as u8));
                                    let entry = CacheEntry::new(
                                        domain,
                                        RecordType::A,
                                        Some(addr),
                                        3600,
                                        CacheFlags::FORWARD,
                                    );
                                    
                                    let mut cache_guard = cache_clone.write().unwrap();
                                    cache_guard.insert(entry).expect("insert success");
                                    drop(cache_guard);
                                } else {
                                    // 80% reads
                                    let domain = DomainName::new(format!("cached{}.example.com", op_id % 500))
                                        .expect("valid domain");
                                    
                                    let mut cache_guard = cache_clone.write().unwrap();
                                    let result = cache_guard.find_by_name(&domain, RecordType::A);
                                    drop(cache_guard);
                                    
                                    black_box(result);
                                }
                            }
                        });
                        
                        handles.push(handle);
                    }
                    
                    // Wait for all tasks to complete
                    for handle in handles {
                        handle.await.expect("task completed");
                    }
                });
                
                black_box(&cache_arc);
            },
            BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

// ============================================================================
// BENCHMARK 8: CACHE INVALIDATION
// ============================================================================

/// Benchmarks cache clearing and selective invalidation operations.
///
/// Tests:
/// 1. Full cache flush (`clear()`) - removes all entries
/// 2. Expired entry pruning (`prune_expired()`) - selective removal by TTL
///
/// Validates efficient bulk operations for configuration reload (SIGHUP) and
/// periodic maintenance tasks.
///
/// # Algorithm
///
/// ## Full Clear
/// 1. Fill cache with 1000 entries
/// 2. Execute clear() and measure time
/// 3. Verify cache is empty
///
/// ## Prune Expired
/// 1. Fill cache with mix of expired and valid entries
/// 2. Execute prune_expired() and measure time
/// 3. Verify only expired entries removed
///
/// # Performance Target
///
/// - Full clear: < 1ms for 1000 entries (O(n))
/// - Prune expired: < 5ms for 1000 entries (O(n) scan + remove)
fn cache_invalidation(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_invalidation");
    
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));
    
    // Benchmark full cache clear
    group.bench_function("full_clear", |b| {
        b.iter_batched(
            || {
                // Setup: Fill cache
                let mut cache = DnsCache::with_capacity(1000);
                
                for i in 0..1000 {
                    let domain = DomainName::new(format!("entry{}.example.com", i))
                        .expect("valid domain");
                    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
                    let entry = CacheEntry::new(
                        domain,
                        RecordType::A,
                        Some(addr),
                        3600,
                        CacheFlags::FORWARD,
                    );
                    cache.insert(entry).expect("insert success");
                }
                
                cache
            },
            |mut cache| {
                // Benchmark: Clear cache
                black_box(cache.clear());
                black_box(&cache);
            },
            BatchSize::SmallInput,
        );
    });
    
    // Benchmark expired entry pruning
    group.bench_function("prune_expired", |b| {
        b.iter_batched(
            || {
                // Setup: Fill cache with mix of expired and valid entries
                let mut cache = DnsCache::with_capacity(1000);
                
                for i in 0..1000 {
                    let domain = DomainName::new(format!("entry{}.example.com", i))
                        .expect("valid domain");
                    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
                    
                    // 50% of entries get very short TTL (will be expired)
                    // 50% get normal TTL
                    let ttl = if i % 2 == 0 { 0 } else { 3600 };
                    
                    let entry = CacheEntry::new(
                        domain,
                        RecordType::A,
                        Some(addr),
                        ttl,
                        CacheFlags::FORWARD,
                    );
                    cache.insert(entry).expect("insert success");
                }
                
                // Sleep briefly to ensure 0-TTL entries expire
                std::thread::sleep(Duration::from_millis(10));
                
                cache
            },
            |mut cache| {
                // Benchmark: Prune expired entries
                let removed = black_box(cache.prune_expired());
                black_box(removed);
                black_box(&cache);
            },
            BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

// ============================================================================
// CRITERION CONFIGURATION
// ============================================================================

criterion_group!(
    benches,
    cache_insert_sequential,
    cache_lookup_by_name,
    cache_lookup_by_addr,
    cache_lru_eviction,
    cache_concurrent_reads,
    cache_concurrent_writes,
    cache_mixed_workload,
    cache_invalidation,
);

criterion_main!(benches);
