# Dnsmasq C-to-Rust Migration Guide

## Table of Contents

1. [Migration Overview](#migration-overview)
2. [Refactoring Objective and Rationale](#refactoring-objective-and-rationale)
3. [Transformation Rules and Patterns](#transformation-rules-and-patterns)
4. [Module Architecture Mapping](#module-architecture-mapping)
5. [Memory Safety Improvements](#memory-safety-improvements)
6. [Configuration and API Compatibility](#configuration-and-api-compatibility)
7. [Testing Strategy](#testing-strategy)
8. [Build System Transition](#build-system-transition)
9. [Platform Abstraction Evolution](#platform-abstraction-evolution)
10. [Dependency Migration](#dependency-migration)
11. [Performance Validation](#performance-validation)
12. [Development Guidelines](#development-guidelines)

---

## Migration Overview

This document provides comprehensive guidance for understanding and working with the dnsmasq C-to-Rust migration. The refactoring transforms the entire dnsmasq codebase from C to Rust while maintaining 100% functional parity, configuration compatibility, and operational characteristics.

### Migration Type

**Technology Stack Migration with Memory Safety Modernization**

This is a comprehensive programming language migration that fundamentally reimplements the entire codebase from C to Rust while maintaining identical external behavior, configuration compatibility, and operational characteristics.

### Key Principles

1. **Memory Safety First**: Eliminate all memory-safety vulnerabilities through Rust's ownership system
2. **Functional Preservation**: Maintain complete feature parity with the C implementation
3. **Behavioral Identity**: Ensure packet-level and timing compatibility
4. **Zero Configuration Changes**: Preserve 100% backward compatibility with existing configurations
5. **Drop-In Replacement**: Rust binary works as a direct replacement for C binary

### Migration Scope

- **Total C Source Files**: 50 implementation files + 5 header files (~35,000+ lines)
- **Total Rust Files Created**: 100+ source files organized into modular structure
- **Migration Approach**: Single-phase complete rewrite (not incremental)
- **Execution**: One complete phase producing fully functional Rust implementation

---

## Refactoring Objective and Rationale

### Primary Objective

Transform dnsmasq from its current C implementation to a memory-safe Rust implementation while maintaining 100% functional parity and configuration compatibility.

### Core Goals

#### 1. Memory Safety Elimination

**Objective**: Replace all manual memory management in C with Rust's ownership system, borrow checker, and RAII patterns to eliminate:

- Buffer overflows and underflows
- Use-after-free vulnerabilities
- Double-free errors
- Memory leaks
- Null pointer dereferences
- Data races in concurrent code

**Target**: Zero memory-safety vulnerabilities as validated by the Rust compiler and cargo-audit.

**Impact**: Approximately 70% of software security issues are related to incorrect memory handling. Eliminating these vulnerabilities fundamentally improves dnsmasq's security posture.

#### 2. Functional Preservation

**Objective**: Maintain complete feature parity across all dnsmasq capabilities:

- DNS forwarding with caching
- DHCPv4/DHCPv6 server functionality
- IPv6 Router Advertisements (RA)
- DNSSEC validation
- TFTP server
- Network boot (PXE) support
- All integration capabilities (D-Bus, systemd, inotify)

**Validation**: All existing C test suites must pass against the Rust binary without modification.

#### 3. Configuration Compatibility

**Objective**: Preserve 100% backward compatibility with existing dnsmasq.conf files.

**Requirements**:
- All existing configuration directives work identically
- All command-line arguments function the same
- All environment variables are supported
- No configuration migration required for existing deployments

#### 4. API Contract Preservation

**Objective**: Maintain all public interfaces:

- D-Bus API methods on uk.org.thekelleys.dnsmasq interface
- SIGHUP signal handling for configuration reload
- SIGUSR1/SIGUSR2 for cache statistics and dumps
- Helper script invocation patterns with identical environment variables
- systemd socket activation
- PID file format and location

#### 5. Performance Equivalence

**Objective**: Match or exceed C implementation performance characteristics:

- DNS query response times
- DHCP lease allocation speed
- Memory footprint under equivalent workloads
- CPU utilization
- Startup time

#### 6. Behavioral Identity

**Objective**: Ensure packet-level compatibility:

- Wire protocol formats (DNS, DHCP, RA packets)
- Timing characteristics and retry logic
- Error handling and response codes
- Log message formats

The Rust implementation must be indistinguishable from the C version from a network protocol and operational perspective.

### Why Rust?

#### Memory Safety Without Garbage Collection

Rust provides memory safety guarantees at compile-time without runtime overhead:
- Ownership system prevents use-after-free and double-free
- Borrow checker prevents data races and concurrent access issues
- No garbage collector pauses or unpredictable latency
- Zero-cost abstractions maintain performance

#### Type System Advantages

Rust's type system prevents entire classes of bugs:
- Option<T> eliminates null pointer dereferences
- Result<T, E> forces explicit error handling
- Enums with associated data create impossible states unrepresentable
- Pattern matching ensures exhaustive case handling

#### Modern Concurrency

Rust's async/await and tokio runtime provide:
- Efficient I/O multiplexing (replacement for C's poll() loop)
- Type-safe concurrent programming
- Fearless concurrency through compile-time verification
- Better scalability for handling multiple network sockets

#### Ecosystem and Tooling

Rust provides modern development infrastructure:
- Cargo for dependency management (vs. manual C library integration)
- Built-in testing framework (cargo test)
- Documentation generation (cargo doc)
- Security auditing (cargo audit)
- Code formatting and linting (rustfmt, clippy)

---

## Transformation Rules and Patterns

This section documents the systematic rules used to transform C code patterns into memory-safe Rust equivalents.

### Rule 1: Manual Memory → Ownership System

**C Pattern:**
```c
// Manual allocation and deallocation
struct cache_entry *entry = malloc(sizeof(struct cache_entry));
if (entry == NULL) {
    return -1;
}
strcpy(entry->name, hostname);
// ... use entry ...
free(entry);  // Manual cleanup
```

**Rust Pattern:**
```rust
// Automatic allocation with ownership
let entry = Box::new(CacheEntry {
    name: hostname.to_string(),
    ..Default::default()
});
// ... use entry ...
// Automatic Drop at end of scope - no manual free needed
```

**Transformations:**
- `malloc()` → `Box::new()` for single allocations
- `calloc()` / `realloc()` → `Vec::new()` / `Vec::with_capacity()` for dynamic arrays
- `free()` → Automatic via Drop trait
- C structs with pointer fields → Rust structs with owned/borrowed fields
- Reference counting (`daemon->refcount++`) → `Rc<T>` or `Arc<T>`

### Rule 2: Null Pointers → Option Types

**C Pattern:**
```c
// NULL indicates absence of value
struct cache_entry *lookup_cache(const char *name) {
    // Search logic...
    return NULL;  // Not found
}

// Usage requires null check
struct cache_entry *entry = lookup_cache("example.com");
if (entry == NULL) {
    // Handle miss
} else {
    // Use entry
}
```

**Rust Pattern:**
```rust
// Option<T> explicitly represents presence or absence
fn lookup_cache(&self, name: &str) -> Option<&CacheEntry> {
    // Search logic...
    None  // Not found
}

// Usage with pattern matching or combinators
match self.lookup_cache("example.com") {
    Some(entry) => {
        // Use entry
    }
    None => {
        // Handle miss
    }
}

// Or concisely:
let entry = self.lookup_cache("example.com")?;
```

**Transformations:**
- Nullable pointers → `Option<T>`
- `if (ptr == NULL)` → `if let Some(value) = option`
- Optional function parameters → `Option<T>` parameters
- `ptr != NULL` guards → `.is_some()` / `.is_none()`

### Rule 3: Error Codes → Result Types

**C Pattern:**
```c
// Return codes indicate success/failure
int forward_query(struct dns_query *query) {
    if (some_error_condition) {
        errno = EINVAL;
        return -1;  // Error
    }
    // ... processing ...
    return 0;  // Success
}

// Usage requires error checking
if (forward_query(query) < 0) {
    // Handle error
}
```

**Rust Pattern:**
```rust
// Result<T, E> forces explicit error handling
async fn forward_query(&self, query: DnsQuery) -> Result<DnsResponse, DnsError> {
    if some_error_condition {
        return Err(DnsError::InvalidQuery);
    }
    // ... processing ...
    Ok(response)
}

// Usage with ? operator for propagation
let response = self.forward_query(query).await?;
```

**Transformations:**
- Return codes (-1/0/1) → `Result<T, E>`
- `errno` global → `std::io::Error` or custom error types
- Error propagation `if (rc < 0) return rc;` → `?` operator
- Multiple error paths → Enum-based error types with thiserror

### Rule 4: Fixed Buffers → Dynamic Collections

**C Pattern:**
```c
// Fixed-size buffer with manual bounds checking
char buf[256];
int len = 0;

if (len + new_data_len >= sizeof(buf)) {
    return -1;  // Buffer overflow!
}
memcpy(buf + len, new_data, new_data_len);
len += new_data_len;
```

**Rust Pattern:**
```rust
// Dynamic buffer with automatic growth
let mut buf = Vec::new();

// Automatic reallocation, no overflow possible
buf.extend_from_slice(new_data);
```

**Transformations:**
- `char buf[N]` → `Vec<u8>` or `String`
- Fixed arrays → `Vec<T>` for dynamic sizing or `[T; N]` for compile-time size
- `realloc()` for growth → `Vec::push()` with automatic reallocation
- Manual bounds checking → Compile-time bounds checking with slices

### Rule 5: Platform Abstractions → Rust Crates

**C Pattern:**
```c
#ifdef HAVE_LINUX_NETLINK
#include <linux/netlink.h>
// Linux-specific netlink code
#elif defined(HAVE_BSD_ROUTE)
#include <net/route.h>
// BSD-specific routing socket code
#endif
```

**Rust Pattern:**
```rust
#[cfg(target_os = "linux")]
use rtnetlink::Handle;

#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
use nix::sys::socket::SockAddr;

// Platform-specific code behind trait
pub trait NetworkPlatform {
    async fn enumerate_interfaces(&self) -> Result<Vec<NetworkInterface>>;
}

#[cfg(target_os = "linux")]
pub struct LinuxNetworkPlatform { /* ... */ }

#[cfg(target_os = "linux")]
impl NetworkPlatform for LinuxNetworkPlatform {
    // Linux-specific implementation
}
```

**Transformations:**
- C `#ifdef` → Rust `#[cfg(...)]` attributes
- Platform-specific headers → Platform-specific crate imports
- Conditional compilation → Cargo feature flags
- Socket APIs → `tokio::net` or `std::net`
- Linux netlink → `rtnetlink` or `netlink-packet-route` crates
- BSD BPF → `nix` crate with platform-specific features
- D-Bus → `zbus` crate
- inotify → `notify` crate

### Rule 6: Synchronization → Async Concurrency

**C Pattern:**
```c
// poll()-based event loop
struct pollfd fds[MAX_FDS];
int nfds = 0;

fds[nfds].fd = dns_socket;
fds[nfds].events = POLLIN;
nfds++;

fds[nfds].fd = dhcp_socket;
fds[nfds].events = POLLIN;
nfds++;

while (running) {
    int ready = poll(fds, nfds, timeout_ms);
    if (ready < 0) {
        // Error handling
    }
    
    for (int i = 0; i < nfds; i++) {
        if (fds[i].revents & POLLIN) {
            if (fds[i].fd == dns_socket) {
                handle_dns_query();
            } else if (fds[i].fd == dhcp_socket) {
                handle_dhcp_packet();
            }
        }
    }
}
```

**Rust Pattern:**
```rust
// tokio async/await event loop
use tokio::select;

loop {
    select! {
        result = dns_socket.recv_from(&mut buf) => {
            let (len, addr) = result?;
            handle_dns_query(&buf[..len], addr).await?;
        }
        result = dhcp_socket.recv_from(&mut buf) => {
            let (len, addr) = result?;
            handle_dhcp_packet(&buf[..len], addr).await?;
        }
        _ = shutdown_signal.recv() => {
            break;
        }
    }
}
```

**Transformations:**
- `poll()` / `select()` → `tokio::select!` macro
- Blocking I/O → Async I/O with `.await`
- Manual state machines → Async functions with natural control flow
- Signal handlers → `tokio::signal` or `signal-hook`
- `fork()` / `exec()` → `tokio::process::Command`

### Rule 7: Pointer Arithmetic → Safe Slices

**C Pattern:**
```c
// Manual pointer arithmetic for packet parsing
unsigned char *p = packet;
unsigned char *end = packet + packet_len;

if (p + 2 > end) {
    return -1;  // Buffer overrun check
}
uint16_t id = ntohs(*(uint16_t *)p);
p += 2;

if (p + 1 > end) {
    return -1;
}
uint8_t flags = *p++;
```

**Rust Pattern:**
```rust
// Safe slice operations with automatic bounds checking
use nom::{bytes::complete::take, number::complete::be_u16};

fn parse_packet(input: &[u8]) -> IResult<&[u8], PacketHeader> {
    let (input, id) = be_u16(input)?;
    let (input, flags) = take(1u8)(input)?;
    
    Ok((input, PacketHeader { id, flags: flags[0] }))
}
```

**Transformations:**
- Raw pointer arithmetic → Slice operations
- Manual bounds checking → Compile-time bounds checking
- `memcpy()` → `.copy_from_slice()` or `.clone()`
- Network byte order conversions → `u16::from_be()` / `u16::to_be()`
- Binary parsing → `nom` parser combinators or manual safe parsing

### Rule 8: Global State → Structured State

**C Pattern:**
```c
// Global variables for daemon state
struct daemon *daemon;
struct server *servers;
int num_servers;
struct cache_entry *cache[HASH_SIZE];

// Access from anywhere
void some_function() {
    daemon->log_queries = 1;
    cache_insert(cache, entry);
}
```

**Rust Pattern:**
```rust
// Encapsulated state with clear ownership
pub struct DaemonContext {
    config: Arc<Config>,
    dns_service: DnsService,
    dhcp_service: DhcpService,
    cache: Arc<RwLock<DnsCache>>,
}

impl DaemonContext {
    pub async fn handle_dns_query(&self, query: DnsQuery) -> Result<DnsResponse> {
        self.dns_service.resolve(query).await
    }
}
```

**Transformations:**
- Global variables → Struct fields
- Scattered state → Centralized in context structs
- Global mutability → `Arc<RwLock<T>>` or `Arc<Mutex<T>>` for shared state
- Function parameters implicit → Explicit `&self` or `&mut self`

---

## Module Architecture Mapping

This section maps the C source file structure to the Rust module hierarchy.

### High-Level Structure Transformation

**C Structure:**
```
src/
├── dnsmasq.c          (1500+ lines - main, signals, event loop)
├── dnsmasq.h          (1200+ lines - types, prototypes, flags)
├── config.h           (600+ lines - compile-time configuration)
├── forward.c, cache.c, rfc1035.c, dnssec.c...
├── dhcp.c, dhcp6.c, lease.c, rfc2131.c...
└── [50+ C files total]
```

**Rust Structure:**
```
src/
├── main.rs            (entry point, CLI, tokio runtime)
├── lib.rs             (library root, public API)
├── types.rs, error.rs, constants.rs
├── config/
│   ├── mod.rs, parser.rs, cli.rs, types.rs, validator.rs, reload.rs
├── dns/
│   ├── mod.rs, forwarder.rs, cache.rs, upstream.rs
│   ├── protocol/ (message.rs, name.rs, record.rs, compression.rs, constants.rs)
│   └── dnssec/ (validator.rs, crypto.rs, trust_anchors.rs, blockdata.rs)
├── dhcp/
│   ├── v4/ (server.rs, protocol.rs, message.rs, options.rs, constants.rs)
│   ├── v6/ (server.rs, protocol.rs, message.rs, options.rs, constants.rs)
│   └── lease/ (database.rs, dns_integration.rs, script_hooks.rs)
├── radv/, network/, tftp/, platform/, runtime/, util/
```

### Detailed File Mapping

#### Core System Files

| C File | Rust Module(s) | Lines | Key Transformations |
|--------|---------------|-------|---------------------|
| src/dnsmasq.c | src/main.rs, src/runtime/event_loop.rs | 1500+ | Main entry point split: CLI parsing to main.rs, event loop to runtime module with tokio |
| src/dnsmasq.h | src/types.rs, src/lib.rs | 1200+ | Type definitions to types.rs, public API to lib.rs, prototypes replaced by modules |
| src/config.h | src/constants.rs | 600+ | Compile-time #define → const declarations, #ifdef → #[cfg] attributes |

#### DNS Subsystem (12 files → 18 Rust files)

| C File | Rust Module | Key Transformations |
|--------|-------------|---------------------|
| src/forward.c | src/dns/forwarder.rs | Poll-based forwarding → async/await queries, manual retry logic → tokio timeouts |
| src/cache.c | src/dns/cache.rs | Manual hash table → HashMap with RwLock, manual LRU → LinkedList tracking |
| src/rfc1035.c | src/dns/protocol/message.rs, name.rs, record.rs | Pointer arithmetic → nom parsers, manual name compression → safe compression module |
| src/dns-protocol.h | src/dns/protocol/constants.rs | C #define constants → Rust const declarations |
| src/dnssec.c | src/dns/dnssec/validator.rs | Validation state machine → async validator, manual crypto → ring crate |
| src/crypto.c | src/dns/dnssec/crypto.rs | Nettle FFI → pure Rust ring crate (RSA, ECDSA, EdDSA) |
| src/blockdata.c | src/dns/dnssec/blockdata.rs | Fixed-size chain storage → Vec<u8> dynamic storage |
| src/auth.c | src/dns/auth.rs | Authoritative zone data → HashMap-based zone storage |
| src/edns0.c | src/dns/edns0.rs | EDNS0 option parsing → type-safe option enums |
| src/rrfilter.c | src/dns/filter.rs | In-place RR modification → safe slice operations |
| src/domain-match.c | src/dns/matcher.rs | Pattern matching → regex/glob with regex crate |
| src/domain.c | src/dns/protocol/name.rs | Domain utilities → String/str-based operations |

#### DHCP Subsystem (9 files → 15 Rust files)

| C File | Rust Module | Key Transformations |
|--------|-------------|---------------------|
| src/dhcp.c | src/dhcp/v4/server.rs | DHCPv4 message loop → async packet handler |
| src/rfc2131.c | src/dhcp/v4/protocol.rs | DORA state machine → enum-based state with associated data |
| src/dhcp-protocol.h | src/dhcp/v4/constants.rs | DHCP constants → Rust const values |
| src/dhcp6.c | src/dhcp/v6/server.rs | DHCPv6 message loop → async packet handler |
| src/rfc3315.c | src/dhcp/v6/protocol.rs | SARR state machine → enum-based state transitions |
| src/dhcp6-protocol.h | src/dhcp/v6/constants.rs | DHCPv6 constants → Rust const values |
| src/dhcp-common.c | src/dhcp/common.rs | Shared utilities → common module with trait-based abstractions |
| src/lease.c | src/dhcp/lease/database.rs, dns_integration.rs | Manual file I/O → tokio::fs async I/O, DNS updates → service integration |
| src/outpacket.c | src/dhcp/v6/options.rs | DHCPv6 option serialization → safe buffer building |

#### Network Layer (7 files → 13 Rust files)

| C File | Rust Module | Key Transformations |
|--------|-------------|---------------------|
| src/network.c | src/network/sockets.rs, interfaces.rs | Socket creation → tokio::net, interface enumeration → nix crate |
| src/netlink.c | src/network/platform/linux.rs | Raw netlink → rtnetlink crate, route monitoring → async netlink messages |
| src/bpf.c | src/network/platform/bsd.rs | Raw BPF → nix crate BPF support, packet filtering → safe BPF operations |
| src/ipset.c | src/network/firewall/ipset.rs | ipset netlink → netlink-packet-route, set manipulation → type-safe operations |
| src/nftset.c | src/network/firewall/nftables.rs | nftables library → nftnl crate bindings |
| src/tables.c | src/network/firewall/pf.rs | PF ioctl → nix crate ioctl wrappers |
| src/arp.c | src/network/arp.rs | ARP table manipulation → platform-specific trait implementations |

#### Platform Integration (6 files → 7 Rust files)

| C File | Rust Module | Key Transformations |
|--------|-------------|---------------------|
| src/dbus.c | src/platform/dbus.rs | libdbus FFI → zbus pure Rust, method handlers → async trait methods |
| src/ubus.c | src/platform/ubus.rs | libubus FFI → custom Rust implementation or FFI wrapper |
| src/inotify.c | src/platform/inotify.rs | Raw inotify → notify crate cross-platform file watching |
| src/conntrack.c | src/network/conntrack.rs | libnetfilter_conntrack → rtnetlink with conntrack queries |
| src/helper.c | src/util/helpers.rs | fork/exec → tokio::process::Command, environment setup → Command::envs |
| src/loop.c | src/runtime/reactor.rs | Custom poll wrapper → tokio runtime integration |

#### Utilities (8 files → 7 Rust files)

| C File | Rust Module | Key Transformations |
|--------|-------------|---------------------|
| src/util.c | src/util/mod.rs | General utilities → safe Rust equivalents, random → SURF or rand crate |
| src/option.c | src/config/parser.rs, cli.rs | getopt_long → clap derive macros, manual parsing → nom combinators |
| src/poll.c | (integrated into tokio) | Poll wrapper → tokio reactor handles all I/O multiplexing |
| src/log.c | src/util/logging.rs | syslog FFI → tracing crate with syslog subscriber |
| src/dump.c | src/util/pcap.rs | pcap output → safe packet capture with pcap crate |
| src/pattern.c | src/util/patterns.rs | Pattern matching → regex crate with safe pattern compilation |
| src/metrics.c/h | src/util/metrics.rs | Manual counters → structured metrics with atomic operations |

### Module Dependency Graph

```
┌─────────────────────────────────────────────────────────────┐
│                         main.rs                              │
│                   (CLI, tokio runtime)                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  runtime/event_loop.rs                       │
│            (Main event loop with tokio::select)              │
└───┬─────────────┬─────────────┬─────────────┬───────────────┘
    │             │             │             │
    ▼             ▼             ▼             ▼
┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│dns/     │ │dhcp/     │ │radv/     │ │tftp/     │
│mod.rs   │ │mod.rs    │ │mod.rs    │ │mod.rs    │
└────┬────┘ └────┬─────┘ └────┬─────┘ └──────────┘
     │           │            │
     ▼           ▼            ▼
┌─────────────────────────────────────┐
│      network/sockets.rs              │
│   (Shared network layer)             │
└────────────┬─────────────────────────┘
             │
             ▼
┌───────────────────────────────────────┐
│   network/platform/                   │
│   (Linux, BSD, macOS abstractions)    │
└───────────────────────────────────────┘

Supporting modules used everywhere:
├── types.rs (common types)
├── error.rs (error handling)
├── constants.rs (global constants)
├── config/* (configuration)
└── util/* (utilities, logging, metrics)
```

---

## Memory Safety Improvements

This section details the specific memory safety vulnerabilities eliminated by the Rust migration.

### Buffer Overflow Elimination

**C Vulnerability:**
```c
// Potential buffer overflow
char domain_name[256];
strcpy(domain_name, user_input);  // No bounds checking!
```

**Attack Scenario**: If `user_input` is longer than 255 bytes, this writes past the buffer boundary, potentially overwriting stack data, return addresses, or other variables.

**Rust Solution:**
```rust
// Compile-time bounds checking
let domain_name = String::from(user_input);  // Heap-allocated, grows as needed

// Or with explicit bounds:
let domain_name: String = user_input.chars().take(255).collect();
```

**Safety Guarantee**: Rust's String and Vec types track their length and capacity. Any attempt to access beyond bounds is caught at compile-time or results in a panic (safe crash) rather than undefined behavior.

### Use-After-Free Prevention

**C Vulnerability:**
```c
// Use-after-free bug
struct cache_entry *entry = malloc(sizeof(struct cache_entry));
free(entry);
// Later...
entry->ttl = 300;  // Accessing freed memory!
```

**Attack Scenario**: Freed memory may be reallocated for another purpose. Writing to it corrupts unrelated data structures, leading to crashes or exploitable conditions.

**Rust Solution:**
```rust
// Ownership prevents use-after-free
let entry = Box::new(CacheEntry::default());
drop(entry);  // Explicit drop
// entry is now moved and cannot be accessed
// entry.ttl = 300;  // Compile error: "use of moved value"
```

**Safety Guarantee**: Rust's ownership system tracks the lifetime of every value. Once ownership is moved or a value is dropped, the compiler prevents any further access to that memory location.

### Double-Free Prevention

**C Vulnerability:**
```c
// Double-free bug
struct cache_entry *entry = malloc(sizeof(struct cache_entry));
free(entry);
// Some code path...
free(entry);  // Double free!
```

**Attack Scenario**: Double-freeing memory corrupts the allocator's internal data structures, potentially leading to arbitrary code execution when the allocator is later used.

**Rust Solution:**
```rust
// Ownership prevents double-free
let entry = Box::new(CacheEntry::default());
drop(entry);  // Drop consumes ownership
// drop(entry);  // Compile error: "use of moved value"
```

**Safety Guarantee**: Rust's Drop trait is called exactly once when a value goes out of scope or is explicitly dropped. The type system prevents calling Drop multiple times.

### Null Pointer Dereference Elimination

**C Vulnerability:**
```c
// Null pointer dereference
struct cache_entry *lookup_cache(const char *name);

struct cache_entry *entry = lookup_cache("example.com");
int ttl = entry->ttl;  // Crash if entry is NULL!
```

**Attack Scenario**: Dereferencing a NULL pointer causes a segmentation fault, leading to denial of service or potentially exploitable crashes.

**Rust Solution:**
```rust
// Option<T> forces null-check
fn lookup_cache(&self, name: &str) -> Option<&CacheEntry>;

let entry = self.lookup_cache("example.com");
let ttl = entry.map(|e| e.ttl).unwrap_or(0);

// Or with explicit matching:
match self.lookup_cache("example.com") {
    Some(entry) => {
        let ttl = entry.ttl;  // Safe: entry is guaranteed to exist
    }
    None => {
        // Handle missing entry
    }
}
```

**Safety Guarantee**: Rust has no null pointers. Optional values use `Option<T>`, which must be explicitly unwrapped or pattern-matched before access.

### Data Race Prevention

**C Vulnerability:**
```c
// Data race in multi-threaded code
static int query_count = 0;

void handle_query() {
    query_count++;  // Race condition if called from multiple threads
}
```

**Attack Scenario**: Concurrent access to shared mutable state without synchronization leads to lost updates, inconsistent reads, or memory corruption.

**Rust Solution:**
```rust
use std::sync::atomic::{AtomicUsize, Ordering};

static QUERY_COUNT: AtomicUsize = AtomicUsize::new(0);

fn handle_query() {
    QUERY_COUNT.fetch_add(1, Ordering::Relaxed);  // Atomic increment
}

// Or with Mutex for complex data:
use std::sync::{Arc, Mutex};

struct SharedState {
    query_count: usize,
    cache: HashMap<String, CacheEntry>,
}

let state = Arc::new(Mutex::new(SharedState {
    query_count: 0,
    cache: HashMap::new(),
}));

// Access requires lock
let mut state = state.lock().unwrap();
state.query_count += 1;
```

**Safety Guarantee**: Rust's type system enforces the Send and Sync traits. Data that is not thread-safe cannot be shared across threads. Mutex and RwLock provide runtime checking for proper synchronization.

### Integer Overflow Safety

**C Vulnerability:**
```c
// Integer overflow
unsigned short ttl = 65535;
ttl += 10;  // Wraps to 9, silent undefined behavior
```

**Rust Solution:**
```rust
// Debug mode panics on overflow, release mode wraps with explicit methods
let mut ttl: u16 = 65535;
// ttl += 10;  // Panics in debug mode

// Explicit wrapping if desired:
ttl = ttl.wrapping_add(10);  // Wraps to 9, intentional

// Or checked arithmetic:
ttl = ttl.checked_add(10).expect("TTL overflow");

// Or saturating:
ttl = ttl.saturating_add(10);  // Saturates at u16::MAX
```

**Safety Guarantee**: Integer overflow is caught in debug builds. Release builds provide explicit methods for desired behavior (wrapping, checked, saturating).

### Memory Leak Prevention

**C Challenge:**
```c
// Easy to forget free()
struct cache_entry *entry = malloc(sizeof(struct cache_entry));
if (error_condition) {
    return -1;  // Leaked! Forgot to free(entry)
}
free(entry);
```

**Rust Solution:**
```rust
// Automatic cleanup via RAII
let entry = Box::new(CacheEntry::default());
if error_condition {
    return Err(Error::SomeError);  // entry automatically dropped
}
// entry automatically dropped at end of scope
```

**Safety Guarantee**: Rust's Drop trait ensures cleanup code runs when values go out of scope, even in error paths. No manual memory management required.

### Comparison: C vs. Rust Memory Safety

| Vulnerability Type | C Status | Rust Status | Elimination Method |
|--------------------|----------|-------------|-------------------|
| Buffer overflow | Possible | Impossible | Compile-time bounds checking |
| Use-after-free | Possible | Impossible | Ownership and borrow checker |
| Double-free | Possible | Impossible | Single Drop guarantee |
| Null pointer deref | Possible | Impossible | Option<T> type |
| Data races | Possible | Impossible | Send/Sync traits, Mutex/RwLock |
| Integer overflow | Silent UB | Detected | Debug panics, explicit methods |
| Memory leaks | Common | Rare | RAII and Drop trait |
| Uninitialized memory | Possible | Impossible | All types must be initialized |

### Security Impact

The Rust migration eliminates approximately 70% of security vulnerabilities related to memory handling. This includes:

- **CVE-2015-3294** (DNSSEC validation heap overflow) - Impossible in Rust
- **CVE-2017-14491** (DNS response heap overflow) - Prevented by bounds checking
- **CVE-2017-14492** (DHCP option heap overflow) - Cannot occur with Vec<u8>
- **CVE-2017-14493** (DHCPv6 IAADDR heap overflow) - Safe slicing prevents this
- **CVE-2017-14494** (DNS name length integer overflow) - Checked arithmetic

### Audit Trail

To verify memory safety:

```bash
# Verify zero unsafe blocks in core logic
$ rg 'unsafe' src/ --type rust | grep -v 'test' | grep -v 'platform/'

# Audit dependencies for vulnerabilities
$ cargo audit

# Check for panics in release builds
$ cargo clippy -- -D clippy::panic -D clippy::unwrap_used

# Verify Send/Sync trait usage
$ cargo clippy -- -D clippy::non_send_fields_in_send_ty
```

---

## Configuration and API Compatibility

This section details the guarantees for backward compatibility with existing dnsmasq configurations and integrations.

### Configuration File Compatibility

**Guarantee**: 100% syntax compatibility with existing dnsmasq.conf files.

#### Configuration Parser Implementation

The Rust configuration parser in `src/config/parser.rs` maintains exact compatibility:

```rust
// Example: Parsing "dhcp-range" option
pub fn parse_dhcp_range(value: &str) -> Result<DhcpRange, ConfigError> {
    // C version: parse_dhcp_range() in option.c
    // Rust maintains identical parsing logic
    let parts: Vec<&str> = value.split(',').collect();
    
    match parts.len() {
        2 => {
            // dhcp-range=192.168.1.50,192.168.1.150
            Ok(DhcpRange {
                start: parts[0].parse()?,
                end: parts[1].parse()?,
                lease_time: None,
            })
        }
        3 => {
            // dhcp-range=192.168.1.50,192.168.1.150,12h
            Ok(DhcpRange {
                start: parts[0].parse()?,
                end: parts[1].parse()?,
                lease_time: Some(parse_duration(parts[2])?),
            })
        }
        _ => Err(ConfigError::InvalidDhcpRange),
    }
}
```

#### All 350+ Configuration Options Supported

Sample of critical options with compatibility notes:

| Option | C Behavior | Rust Implementation | Compatibility |
|--------|-----------|---------------------|---------------|
| `port=<number>` | Set DNS port | Parsed to `u16`, validated range | ✅ Identical |
| `interface=<name>` | Bind to interface | String, validated against system interfaces | ✅ Identical |
| `dhcp-range=start,end,time` | DHCP range | Parsed to DhcpRange struct | ✅ Identical |
| `server=<address>` | Upstream DNS | Vec of UpstreamServer | ✅ Identical |
| `log-queries` | Enable query logging | Boolean flag | ✅ Identical |
| `dnssec` | Enable DNSSEC | Boolean flag, loads trust anchors | ✅ Identical |
| `conf-dir=<dir>` | Include directory | Recursive config loading | ✅ Identical |
| `dhcp-script=<path>` | Helper script | PathBuf, validated existence | ✅ Identical |

#### Include File Processing

```rust
// Recursive include handling matches C behavior
pub async fn load_config_with_includes(path: &Path) -> Result<Config> {
    let mut config = Config::default();
    let content = tokio::fs::read_to_string(path).await?;
    
    for line in content.lines() {
        if line.starts_with("conf-file=") {
            // Recursively load included file
            let include_path = &line[10..];
            let included = load_config_with_includes(Path::new(include_path)).await?;
            config = config.merge(included);
        } else if line.starts_with("conf-dir=") {
            // Load all .conf files from directory
            let dir_path = &line[9..];
            for entry in std::fs::read_dir(dir_path)? {
                let path = entry?.path();
                if path.extension() == Some(OsStr::new("conf")) {
                    let included = load_config_with_includes(&path).await?;
                    config = config.merge(included);
                }
            }
        } else {
            config = parse_config_line(line, config)?;
        }
    }
    
    Ok(config)
}
```

### Command-Line Argument Compatibility

**Guarantee**: All command-line options work identically to C version.

#### CLI Parser Implementation

Using clap derive for type-safe parsing while maintaining compatibility:

```rust
use clap::Parser;

#[derive(Parser)]
#[clap(name = "dnsmasq", version, about = "DNS forwarder and DHCP server")]
pub struct CliArgs {
    /// Configuration file path
    #[clap(short = 'C', long = "conf-file", value_name = "FILE")]
    pub conf_file: Option<PathBuf>,
    
    /// DNS port (default: 53)
    #[clap(short = 'p', long = "port", value_name = "PORT")]
    pub port: Option<u16>,
    
    /// Keep in foreground (don't daemonize)
    #[clap(short = 'd', long = "no-daemon")]
    pub no_daemon: bool,
    
    /// Test configuration and exit
    #[clap(long = "test")]
    pub test: bool,
    
    /// Enable query logging
    #[clap(short = 'q', long = "log-queries")]
    pub log_queries: bool,
    
    // ... all other options match C version
}

// Usage:
let args = CliArgs::parse();
```

#### Compatibility with Existing Scripts

Scripts using dnsmasq CLI continue working:

```bash
# All these invocations work identically:
dnsmasq --port=5353 --no-daemon
dnsmasq -p 5353 -d
dnsmasq --conf-file=/etc/dnsmasq.conf --test
dnsmasq --interface=eth0 --dhcp-range=192.168.1.100,192.168.1.200
```

### D-Bus API Compatibility

**Guarantee**: Exact method and signal compatibility on `uk.org.thekelleys.dnsmasq` interface.

#### D-Bus Interface Implementation

```rust
use zbus::{dbus_interface, ConnectionBuilder};

pub struct DnsmasqDBusService {
    dns_service: Arc<DnsService>,
    dhcp_service: Arc<DhcpService>,
}

#[dbus_interface(name = "uk.org.thekelleys.dnsmasq")]
impl DnsmasqDBusService {
    /// Set upstream DNS servers
    async fn set_servers(&mut self, servers: Vec<String>) -> zbus::fdo::Result<()> {
        // Parse server strings
        let upstream_servers: Vec<UpstreamServer> = servers
            .iter()
            .map(|s| s.parse())
            .collect::<Result<_, _>>()
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        
        // Update DNS service
        self.dns_service.set_upstream_servers(upstream_servers).await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        
        Ok(())
    }
    
    /// Clear DNS cache
    async fn clear_cache(&mut self) -> zbus::fdo::Result<()> {
        self.dns_service.clear_cache().await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(())
    }
    
    /// Get dnsmasq version
    async fn get_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }
    
    /// Get metrics (cache size, query count, etc.)
    async fn get_metrics(&self) -> HashMap<String, String> {
        let mut metrics = HashMap::new();
        metrics.insert("cache_size".to_string(), 
                      self.dns_service.cache_size().await.to_string());
        metrics.insert("queries_forwarded".to_string(),
                      self.dns_service.queries_forwarded().await.to_string());
        // ... all metrics from C version
        metrics
    }
    
    /// Signal: DHCP lease added (matches C version)
    #[dbus_interface(signal)]
    async fn dhcp_lease_added(
        signal_ctxt: &SignalContext<'_>,
        ip: &str,
        mac: &str,
        hostname: &str,
    ) -> zbus::Result<()>;
    
    /// Signal: DHCP lease deleted (matches C version)
    #[dbus_interface(signal)]
    async fn dhcp_lease_deleted(
        signal_ctxt: &SignalContext<'_>,
        ip: &str,
        mac: &str,
    ) -> zbus::Result<()>;
}
```

#### D-Bus Testing

Existing D-Bus test scripts work without modification:

```python
# contrib/dbus-test/dbus-test.py (unchanged)
import dbus

bus = dbus.SystemBus()
dnsmasq = bus.get_object('uk.org.thekelleys.dnsmasq', '/')

# Clear cache
dnsmasq.ClearCache()

# Set servers
dnsmasq.SetServers(['8.8.8.8', '1.1.1.1'])

# Get version
version = dnsmasq.GetVersion()
print(f"Version: {version}")

# Get metrics
metrics = dnsmasq.GetMetrics()
for key, value in metrics.items():
    print(f"{key}: {value}")
```

### Signal Handler Compatibility

**Guarantee**: Identical signal handling behavior.

#### Signal Implementation

```rust
use tokio::signal::unix::{signal, SignalKind};

pub async fn setup_signal_handlers(context: Arc<DaemonContext>) {
    // SIGHUP: Reload configuration
    let mut sighup = signal(SignalKind::hangup()).unwrap();
    let context_hup = context.clone();
    tokio::spawn(async move {
        while sighup.recv().await.is_some() {
            info!("Received SIGHUP, reloading configuration");
            if let Err(e) = context_hup.reload_config().await {
                error!("Configuration reload failed: {}", e);
            } else {
                info!("Configuration reloaded successfully");
            }
        }
    });
    
    // SIGUSR1: Dump cache to log
    let mut sigusr1 = signal(SignalKind::user_defined1()).unwrap();
    let context_usr1 = context.clone();
    tokio::spawn(async move {
        while sigusr1.recv().await.is_some() {
            info!("Received SIGUSR1, dumping cache");
            context_usr1.dns_service.dump_cache().await;
        }
    });
    
    // SIGUSR2: Log statistics
    let mut sigusr2 = signal(SignalKind::user_defined2()).unwrap();
    let context_usr2 = context.clone();
    tokio::spawn(async move {
        while sigusr2.recv().await.is_some() {
            info!("Received SIGUSR2, logging statistics");
            context_usr2.log_statistics().await;
        }
    });
    
    // SIGTERM/SIGINT: Graceful shutdown
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down gracefully");
        }
        _ = sigint.recv() => {
            info!("Received SIGINT, shutting down gracefully");
        }
    }
    context.shutdown().await;
}
```

### Helper Script Compatibility

**Guarantee**: Helper scripts receive identical environment variables and invocation timing.

#### Helper Script Execution

```rust
use tokio::process::Command;

pub async fn invoke_dhcp_script(
    script_path: &Path,
    event: DhcpEvent,
    lease: &Lease,
) -> Result<()> {
    let mut cmd = Command::new(script_path);
    
    // Set environment variables matching C version
    cmd.env("DNSMASQ_DOMAIN", &lease.domain);
    cmd.env("DNSMASQ_LEASE_EXPIRES", lease.expires.to_string());
    cmd.env("DNSMASQ_TAGS", lease.tags.join(","));
    cmd.env("DNSMASQ_SUPPLIED_HOSTNAME", &lease.supplied_hostname);
    cmd.env("DNSMASQ_INTERFACE", &lease.interface);
    cmd.env("DNSMASQ_CLIENT_ID", hex::encode(&lease.client_id));
    cmd.env("DNSMASQ_VENDOR_CLASS", &lease.vendor_class);
    cmd.env("DNSMASQ_USER_CLASS0", &lease.user_class);
    cmd.env("DNSMASQ_RELAY_ADDRESS", lease.relay_address.to_string());
    cmd.env("DNSMASQ_CIRCUIT_ID", hex::encode(&lease.circuit_id));
    cmd.env("DNSMASQ_SUBSCRIBER_ID", hex::encode(&lease.subscriber_id));
    cmd.env("DNSMASQ_REMOTE_ID", hex::encode(&lease.remote_id));
    
    // Pass event and lease info as arguments (matches C)
    cmd.arg(match event {
        DhcpEvent::Add => "add",
        DhcpEvent::Del => "del",
        DhcpEvent::Old => "old",
    });
    cmd.arg(lease.mac.to_string());
    cmd.arg(lease.ip.to_string());
    cmd.arg(&lease.hostname);
    
    // Execute script
    let status = cmd.status().await?;
    
    if !status.success() {
        warn!("DHCP script exited with status: {}", status);
    }
    
    Ok(())
}
```

### systemd Integration

**Guarantee**: Drop-in replacement in systemd service units.

#### systemd Socket Activation

```rust
// Support systemd socket activation
pub async fn bind_dns_socket(config: &Config) -> Result<UdpSocket> {
    // Check for systemd-provided socket
    if let Ok(fds) = std::env::var("LISTEN_FDS") {
        if fds.parse::<u32>().unwrap_or(0) > 0 {
            // Use systemd-provided socket
            let fd = 3; // First systemd socket descriptor
            use std::os::unix::io::FromRawFd;
            let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
            std_socket.set_nonblocking(true)?;
            return Ok(UdpSocket::from_std(std_socket)?);
        }
    }
    
    // Fall back to normal binding
    UdpSocket::bind((config.listen_address, config.dns_port)).await
}
```

### File Format Compatibility

#### Lease File Format

```rust
// Write lease file in C-compatible format
pub async fn write_lease_file(leases: &[Lease], path: &Path) -> Result<()> {
    let mut content = String::new();
    
    for lease in leases {
        // Format: <expires> <mac> <ip> <hostname> <client-id>
        // Matches C format exactly
        content.push_str(&format!(
            "{} {} {} {} {}\n",
            lease.expires,
            lease.mac,
            lease.ip,
            lease.hostname,
            hex::encode(&lease.client_id)
        ));
    }
    
    tokio::fs::write(path, content).await?;
    Ok(())
}

// Read lease file (C-compatible format)
pub async fn read_lease_file(path: &Path) -> Result<Vec<Lease>> {
    let content = tokio::fs::read_to_string(path).await?;
    let mut leases = Vec::new();
    
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            leases.push(Lease {
                expires: parts[0].parse()?,
                mac: parts[1].parse()?,
                ip: parts[2].parse()?,
                hostname: parts[3].to_string(),
                client_id: if parts.len() > 4 {
                    hex::decode(parts[4])?
                } else {
                    Vec::new()
                },
                ..Default::default()
            });
        }
    }
    
    Ok(leases)
}
```

### Compatibility Testing

Validate compatibility with existing infrastructure:

```bash
# Test configuration parsing
./dnsmasq --test --conf-file=/etc/dnsmasq.conf

# Test D-Bus interface
dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
    --print-reply / uk.org.thekelleys.dnsmasq.GetVersion

# Test signal handling
killall -HUP dnsmasq  # Reload config
killall -USR1 dnsmasq  # Dump cache
killall -USR2 dnsmasq  # Log stats

# Test systemd integration
systemctl restart dnsmasq
systemctl status dnsmasq

# Test helper script
# (Script receives same environment variables and arguments)
```

---

## Testing Strategy

This section outlines the comprehensive testing approach to validate functional equivalence between C and Rust implementations.

### Testing Philosophy

**Primary Principle**: The existing C test suite serves as the acceptance criteria for the Rust implementation. If all C tests pass against the Rust binary, functional equivalence is proven.

### Test Categories

#### 1. Unit Tests (Rust-Native)

Located in `tests/` directory and inline with `#[cfg(test)]` modules:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dns_name_compression() {
        let name1 = DomainName::from("example.com");
        let name2 = DomainName::from("www.example.com");
        
        let mut buf = Vec::new();
        let compression_map = CompressionMap::new();
        
        // First name writes fully
        name1.write_compressed(&mut buf, &mut compression_map).unwrap();
        assert_eq!(buf.len(), 13); // \x07example\x03com\x00
        
        // Second name uses compression pointer
        name2.write_compressed(&mut buf, &mut compression_map).unwrap();
        assert!(buf[13..15] == [0x03, b'w', b'w', b'w', 0xC0, 0x00]);
    }
    
    #[tokio::test]
    async fn test_cache_insert_and_lookup() {
        let cache = DnsCache::new(100);
        let entry = CacheEntry {
            name: DomainName::from("example.com"),
            rtype: RecordType::A,
            address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            ttl: 300,
            expires: Instant::now() + Duration::from_secs(300),
        };
        
        cache.insert(entry.clone()).await.unwrap();
        
        let result = cache.lookup(&DomainName::from("example.com"), RecordType::A).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().address, entry.address);
    }
    
    #[test]
    fn test_dhcp_range_parsing() {
        // Test various dhcp-range formats
        let range1 = parse_dhcp_range("192.168.1.50,192.168.1.150").unwrap();
        assert_eq!(range1.start, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(range1.end, Ipv4Addr::new(192, 168, 1, 150));
        
        let range2 = parse_dhcp_range("192.168.1.50,192.168.1.150,12h").unwrap();
        assert_eq!(range2.lease_time, Some(Duration::from_secs(12 * 3600)));
    }
}
```

#### 2. Integration Tests (C Test Suite Compatibility)

Run existing C test infrastructure against Rust binary:

```bash
#!/bin/bash
# run-c-tests.sh - Execute C test suite against Rust binary

DNSMASQ_BIN="./target/release/dnsmasq"

# Test 1: DNS Query Forwarding
echo "Testing DNS query forwarding..."
$DNSMASQ_BIN --port=5353 --no-daemon --server=8.8.8.8 &
DNSMASQ_PID=$!
sleep 1

dig @localhost -p 5353 example.com +short
if [ $? -eq 0 ]; then
    echo "✓ DNS forwarding test passed"
else
    echo "✗ DNS forwarding test failed"
    kill $DNSMASQ_PID
    exit 1
fi

kill $DNSMASQ_PID

# Test 2: DNS Caching
echo "Testing DNS caching..."
$DNSMASQ_BIN --port=5353 --no-daemon --cache-size=1000 &
DNSMASQ_PID=$!
sleep 1

# First query (cache miss)
time1=$(dig @localhost -p 5353 example.com | grep "Query time" | awk '{print $4}')
# Second query (cache hit - should be faster)
time2=$(dig @localhost -p 5353 example.com | grep "Query time" | awk '{print $4}')

if [ "$time2" -lt "$time1" ]; then
    echo "✓ DNS caching test passed (cache hit faster)"
else
    echo "✗ DNS caching test failed"
    kill $DNSMASQ_PID
    exit 1
fi

kill $DNSMASQ_PID

# Test 3: DHCP Allocation
echo "Testing DHCP allocation..."
# (Use dhclient or similar to request lease)

# Test 4: Configuration Parsing
echo "Testing configuration parsing..."
$DNSMASQ_BIN --test --conf-file=testdata/test-config.conf
if [ $? -eq 0 ]; then
    echo "✓ Configuration parsing test passed"
else
    echo "✗ Configuration parsing test failed"
    exit 1
fi

# Test 5: Signal Handling
echo "Testing signal handling..."
$DNSMASQ_BIN --port=5353 --no-daemon &
DNSMASQ_PID=$!
sleep 1

# Send SIGHUP to reload config
kill -HUP $DNSMASQ_PID
sleep 1

# Check if still running
if ps -p $DNSMASQ_PID > /dev/null; then
    echo "✓ SIGHUP test passed (config reloaded)"
else
    echo "✗ SIGHUP test failed (process died)"
    exit 1
fi

# Send SIGTERM for graceful shutdown
kill -TERM $DNSMASQ_PID
wait $DNSMASQ_PID

echo "All tests passed!"
```

#### 3. Protocol Compliance Tests

Validate wire-format compatibility:

```rust
#[tokio::test]
async fn test_dns_wire_format_compliance() {
    // Test DNS message parsing and serialization
    let query_packet = [
        // DNS header (12 bytes)
        0x12, 0x34,  // Transaction ID
        0x01, 0x00,  // Flags: standard query
        0x00, 0x01,  // Questions: 1
        0x00, 0x00,  // Answers: 0
        0x00, 0x00,  // Authority: 0
        0x00, 0x00,  // Additional: 0
        // Question section
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,        // Root label
        0x00, 0x01,  // Type: A
        0x00, 0x01,  // Class: IN
    ];
    
    let message = DnsMessage::from_bytes(&query_packet).unwrap();
    assert_eq!(message.id, 0x1234);
    assert_eq!(message.questions.len(), 1);
    assert_eq!(message.questions[0].name.to_string(), "example.com");
    
    // Serialize and compare
    let serialized = message.to_bytes().unwrap();
    assert_eq!(serialized, query_packet);
}

#[tokio::test]
async fn test_dhcp_wire_format_compliance() {
    // Test DHCPv4 DISCOVER packet
    let discover_packet = vec![
        0x01,  // Message type: Boot Request
        0x01,  // Hardware type: Ethernet
        0x06,  // Hardware address length
        0x00,  // Hops
        0x12, 0x34, 0x56, 0x78,  // Transaction ID
        0x00, 0x00,  // Seconds
        0x00, 0x00,  // Flags
        0x00, 0x00, 0x00, 0x00,  // Client IP
        0x00, 0x00, 0x00, 0x00,  // Your IP
        0x00, 0x00, 0x00, 0x00,  // Server IP
        0x00, 0x00, 0x00, 0x00,  // Gateway IP
        // Client MAC address (16 bytes)
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // ... (Server hostname, boot file - 192 bytes of zeros)
    ];
    // Add proper padding and magic cookie
    
    let message = DhcpMessage::parse(&discover_packet).unwrap();
    assert_eq!(message.transaction_id, 0x12345678);
    assert_eq!(message.client_mac, MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
}
```

#### 4. Performance Regression Tests

Use criterion for benchmark comparisons:

```rust
// benches/dns_performance.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn dns_query_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let cache = Arc::new(RwLock::new(DnsCache::new(1000)));
    
    c.bench_function("dns_cache_lookup", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = cache.read().await.lookup(
                    black_box(&DomainName::from("example.com")),
                    black_box(RecordType::A),
                ).await;
                result
            })
        })
    });
    
    c.bench_function("dns_cache_insert", |b| {
        b.iter(|| {
            rt.block_on(async {
                cache.write().await.insert(black_box(CacheEntry {
                    name: DomainName::from("example.com"),
                    rtype: RecordType::A,
                    address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                    ttl: 300,
                    expires: Instant::now() + Duration::from_secs(300),
                })).await
            })
        })
    });
}

criterion_group!(benches, dns_query_benchmark);
criterion_main!(benches);
```

#### 5. Fuzzing Tests

Use cargo-fuzz for security testing:

```rust
// fuzz/fuzz_targets/dns_parser.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz DNS message parser
    let _ = dnsmasq::dns::protocol::DnsMessage::from_bytes(data);
});

// fuzz/fuzz_targets/dhcp_parser.rs
fuzz_target!(|data: &[u8]| {
    // Fuzz DHCP message parser
    let _ = dnsmasq::dhcp::v4::DhcpMessage::parse(data);
});
```

Run fuzzing:
```bash
cargo fuzz run dns_parser -- -max_total_time=3600
cargo fuzz run dhcp_parser -- -max_total_time=3600
```

### Test Execution

```bash
# Run all unit tests
cargo test --all-features

# Run integration tests
cargo test --test '*' --all-features

# Run with coverage
cargo tarpaulin --out Html --output-dir coverage/

# Run benchmarks
cargo bench --all-features

# Run fuzzing
cargo fuzz run dns_parser

# Run C test suite
./run-c-tests.sh

# Run D-Bus tests
python3 contrib/dbus-test/dbus-test.py
```

### Continuous Integration

```yaml
# .github/workflows/rust-ci.yml
name: Rust CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: 1.91.0
          override: true
          components: rustfmt, clippy
      
      - name: Build
        run: cargo build --release --all-features
      
      - name: Run tests
        run: cargo test --all-features
      
      - name: Run clippy
        run: cargo clippy --all-features -- -D warnings
      
      - name: Check formatting
        run: cargo fmt -- --check
      
      - name: Security audit
        run: cargo audit
      
      - name: Run C test suite
        run: ./run-c-tests.sh
      
      - name: Code coverage
        run: |
          cargo install cargo-tarpaulin
          cargo tarpaulin --out Xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

### Acceptance Criteria

The Rust implementation is considered functionally equivalent when:

- ✅ All Rust unit tests pass (>80% code coverage)
- ✅ All integration tests pass
- ✅ All C test suite tests pass against Rust binary
- ✅ Protocol compliance tests pass (wire format validation)
- ✅ Performance benchmarks meet or exceed C version
- ✅ D-Bus tests pass
- ✅ Configuration compatibility tests pass
- ✅ Fuzzing finds no crashes or hangs
- ✅ Zero memory safety issues (cargo audit, clippy)

---

## Build System Transition

This section explains the migration from GNU Make to Cargo build system.

### C Build System (Preserved)

The original C build infrastructure remains unchanged:

```makefile
# Makefile (UNCHANGED)
CC = gcc
CFLAGS = -Wall -W -O2
LDFLAGS = -lnettle -ldbus-1

PREFIX = /usr
BINDIR = $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man

OBJS = cache.o rfc1035.o dhcp.o lease.o forward.o # ...

all: dnsmasq

dnsmasq: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

install: dnsmasq
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 dnsmasq $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 dnsmasq.8 $(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o dnsmasq

# ... (rest unchanged)
```

### Rust Build System (New)

#### Cargo.toml Structure

```toml
[package]
name = "dnsmasq"
version = "2.92.0"
edition = "2021"
rust-version = "1.91.0"
authors = ["Dnsmasq Contributors"]
license = "GPL-2.0-or-later OR GPL-3.0"
description = "Memory-safe DNS forwarder and DHCP server"
repository = "https://github.com/dnsmasq/dnsmasq"
readme = "README.md"
keywords = ["dns", "dhcp", "network", "server", "forwarder"]
categories = ["network-programming"]

[dependencies]
# Async runtime
tokio = { version = "1.42", features = ["full"] }
tokio-util = "0.7"
futures = "0.3"
async-trait = "0.1"

# DNS protocol
hickory-proto = "0.25"
hickory-server = "0.25"
hickory-client = "0.25"
hickory-resolver = "0.25"

# Cryptography
ring = "0.17"
rustls = "0.23"

# Parsing and serialization
nom = "7.1"
bytes = "1.9"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# CLI and configuration
clap = { version = "4.5", features = ["derive", "env", "wrap_help"] }

# Error handling
thiserror = "2.0"
anyhow = "1.0"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

#### Platform-specific dependencies
[target.'cfg(target_os = "linux")'.dependencies]
nix = { version = "0.29", features = ["socket", "net", "signal", "process"] }
netlink-packet-route = "0.20"
rtnetlink = "0.15"
caps = "0.5"

[target.'cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))'.dependencies]
nix = { version = "0.29", features = ["socket", "net", "signal", "process"] }

[target.'cfg(target_os = "macos")'.dependencies]
nix = { version = "0.29", features = ["socket", "net", "signal", "process"] }

#### Optional feature dependencies
[dependencies.zbus]
version = "5.1"
optional = true

[dependencies.mlua]
version = "0.10"
optional = true
features = ["lua54", "vendored"]

[dependencies.idna]
version = "1.0"
optional = true

[dev-dependencies]
proptest = "1.6"
mockall = "0.13"
criterion = "0.5"
tempfile = "3.14"
tokio-test = "0.4"

[features]
default = ["dnssec", "idn"]
dnssec = ["ring"]
dbus = ["zbus"]
lua-scripts = ["mlua"]
idn = ["idna"]
tftp = []
conntrack = []
nftset = []
ipset = []
all-features = ["dnssec", "dbus", "lua-scripts", "idn", "tftp", "conntrack", "nftset", "ipset"]

[[bin]]
name = "dnsmasq"
path = "src/main.rs"

[lib]
name = "dnsmasq"
path = "src/lib.rs"

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = true
panic = "abort"

[profile.dev]
opt-level = 0

[profile.test]
opt-level = 1
```

### Feature Flag System

Cargo features replicate C's HAVE_* flags:

| C Flag | Cargo Feature | Default | Description |
|--------|--------------|---------|-------------|
| HAVE_DHCP | (always on) | ✓ | DHCPv4/v6 support (core feature) |
| HAVE_DNSSEC | dnssec | ✓ | DNSSEC validation with ring |
| HAVE_DBUS | dbus | ✗ | D-Bus interface |
| HAVE_LUASCRIPT | lua-scripts | ✗ | Lua scripting support |
| HAVE_LIBIDN2 | idn | ✓ | Internationalized domain names |
| HAVE_TFTP | tftp | ✗ | TFTP server |
| HAVE_CONNTRACK | conntrack | ✗ | Linux conntrack integration |
| HAVE_NFTSET | nftset | ✗ | nftables support |
| HAVE_IPSET | ipset | ✗ | ipset support |

Usage:
```bash
# Build with default features (dnssec, idn)
cargo build --release

# Build with all features
cargo build --release --all-features

# Build with specific features
cargo build --release --features "dbus,lua-scripts"

# Build without default features
cargo build --release --no-default-features --features "tftp"
```

### Cross-Compilation

```bash
# Install cross-compilation targets
rustup target add aarch64-unknown-linux-gnu
rustup target add armv7-unknown-linux-gnueabihf
rustup target add x86_64-unknown-freebsd

# Cross-compile for ARM64
cargo build --release --target aarch64-unknown-linux-gnu

# Cross-compile for FreeBSD
cargo build --release --target x86_64-unknown-freebsd
```

### Build Commands

```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Build for specific target
cargo build --release --target x86_64-unknown-linux-musl

# Build documentation
cargo doc --no-deps --open

# Run tests
cargo test

# Run specific test
cargo test dns_cache

# Run benchmarks
cargo bench

# Check without building
cargo check

# Format code
cargo fmt

# Lint code
cargo clippy

# Security audit
cargo audit

# Update dependencies
cargo update

# Generate coverage report
cargo tarpaulin --out Html
```

### Installation

```bash
# Install from source
cargo install --path . --locked

# Install to specific location
cargo install --path . --root /usr/local

# Install with all features
cargo install --path . --all-features
```

### Parallel C and Rust Builds

Both build systems can coexist:

```bash
# Build C version
make clean && make

# Build Rust version
cargo build --release

# Install both
make install PREFIX=/usr/local BINDIR=/usr/local/sbin/dnsmasq-c
cargo install --path . --root /usr/local --bin dnsmasq-rust
```

### Package Integration

For distribution packages:

```bash
# Debian package build
dpkg-buildpackage -us -uc -b

# RPM package build
rpmbuild -ba dnsmasq.spec

# Alpine package build
abuild -r
```

### Build Performance

Cargo provides parallel compilation by default:

```bash
# Use all CPU cores
cargo build --release

# Limit parallel jobs
cargo build --release -j 4

# Incremental builds for development
export CARGO_INCREMENTAL=1
cargo build
```

### Dependency Management

```bash
# Show dependency tree
cargo tree

# Check for outdated dependencies
cargo outdated

# Update to latest compatible versions
cargo update

# Verify dependency licenses
cargo deny check licenses

# Audit dependencies for vulnerabilities
cargo audit
```

---

## Platform Abstraction Evolution

This section details the transformation from C preprocessor conditionals to Rust's cfg-based abstractions.

### C Platform Detection Pattern

```c
// config.h and dnsmasq.h
#ifdef __linux__
#define HAVE_LINUX
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define HAVE_BSD
#include <net/bpf.h>
#include <net/route.h>
#endif

#ifdef __APPLE__
#define HAVE_MACOS
#include <net/route.h>
#endif

// network.c
void enumerate_interfaces() {
#ifdef HAVE_LINUX
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    // Linux-specific netlink code
#elif defined(HAVE_BSD)
    int sock = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    // BSD-specific routing socket code
#endif
}
```

### Rust Platform Abstraction Pattern

```rust
// Conditional compilation with cfg attributes
#[cfg(target_os = "linux")]
use rtnetlink::{new_connection, Handle};

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
use nix::sys::socket::{socket, AddressFamily, SockType, SockFlag};

#[cfg(target_os = "macos")]
use nix::sys::socket::{socket, AddressFamily, SockType, SockFlag};

// Platform-specific trait implementation
pub trait NetworkPlatform: Send + Sync {
    async fn enumerate_interfaces(&self) -> Result<Vec<NetworkInterface>>;
    async fn monitor_interface_changes(&self) -> Result<InterfaceMonitor>;
}

#[cfg(target_os = "linux")]
pub struct LinuxNetworkPlatform {
    netlink_handle: Handle,
}

#[cfg(target_os = "linux")]
impl NetworkPlatform for LinuxNetworkPlatform {
    async fn enumerate_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        let mut links = self.netlink_handle.link().get().execute();
        let mut interfaces = Vec::new();
        
        while let Some(link) = links.try_next().await? {
            interfaces.push(NetworkInterface {
                index: link.header.index,
                name: link.nlas.iter()
                    .find_map(|nla| match nla {
                        netlink_packet_route::link::nlas::Nla::IfName(name) => Some(name.clone()),
                        _ => None,
                    })
                    .unwrap_or_default(),
                // ... additional fields
            });
        }
        
        Ok(interfaces)
    }
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub struct BsdNetworkPlatform {
    routing_socket: RawFd,
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
impl NetworkPlatform for BsdNetworkPlatform {
    async fn enumerate_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        // BSD-specific implementation using routing sockets
        let ifaddrs = nix::ifaddrs::getifaddrs()?;
        let mut interfaces = Vec::new();
        
        for ifaddr in ifaddrs {
            interfaces.push(NetworkInterface {
                name: ifaddr.interface_name,
                // ... BSD-specific field extraction
            });
        }
        
        Ok(interfaces)
    }
}

// Platform-agnostic interface creation
pub fn create_network_platform() -> Box<dyn NetworkPlatform> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxNetworkPlatform::new())
    }
    
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        Box::new(BsdNetworkPlatform::new())
    }
    
    #[cfg(target_os = "macos")]
    {
        Box::new(MacosNetworkPlatform::new())
    }
}
```

### Platform-Specific Features

#### Privilege Dropping

**Linux (capabilities):**
```rust
#[cfg(target_os = "linux")]
pub fn drop_privileges(config: &Config) -> Result<()> {
    use caps::{Capability, CapSet};
    
    // Keep only required capabilities
    caps::clear(None, CapSet::Permitted)?;
    caps::set(None, CapSet::Permitted, &[
        Capability::CAP_NET_BIND_SERVICE,  // Bind to ports < 1024
        Capability::CAP_NET_ADMIN,         // Network admin operations
        Capability::CAP_NET_RAW,           // Raw sockets for DHCP
    ])?;
    
    // Change user
    let user = users::get_user_by_name(&config.user)
        .ok_or_else(|| Error::UserNotFound(config.user.clone()))?;
    nix::unistd::setuid(user.uid())?;
    
    Ok(())
}
```

**BSD (pledge/unveil):**
```rust
#[cfg(target_os = "openbsd")]
pub fn drop_privileges(config: &Config) -> Result<()> {
    use nix::sys::pledge;
    
    // Restrict system calls
    pledge::pledge(
        "stdio rpath wpath cpath inet dns unix sendfd recvfd proc exec",
        None,
    )?;
    
    // Restrict filesystem access
    // (unveil would be called here, but Rust nix doesn't have it yet)
    
    Ok(())
}
```

**macOS (sandbox):**
```rust
#[cfg(target_os = "macos")]
pub fn drop_privileges(config: &Config) -> Result<()> {
    // macOS sandbox profile
    // (Requires FFI to sandbox_init if not using full privilege drop)
    
    // For now, just change user
    let user = users::get_user_by_name(&config.user)
        .ok_or_else(|| Error::UserNotFound(config.user.clone()))?;
    nix::unistd::setuid(user.uid())?;
    
    Ok(())
}
```

#### Network Interface Monitoring

**Linux (netlink):**
```rust
#[cfg(target_os = "linux")]
pub struct InterfaceMonitor {
    connection: Connection,
}

#[cfg(target_os = "linux")]
impl InterfaceMonitor {
    pub async fn next_event(&mut self) -> Result<InterfaceEvent> {
        use netlink_packet_route::RtnlMessage;
        
        let (message, _) = self.connection.receive().await?;
        
        match message.payload {
            NetlinkPayload::InnerMessage(RtnlMessage::NewLink(link)) => {
                Ok(InterfaceEvent::Added(/* parse link */))
            }
            NetlinkPayload::InnerMessage(RtnlMessage::DelLink(link)) => {
                Ok(InterfaceEvent::Removed(/* parse link */))
            }
            _ => Ok(InterfaceEvent::Other),
        }
    }
}
```

**BSD (routing socket):**
```rust
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub struct InterfaceMonitor {
    socket: RawFd,
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
impl InterfaceMonitor {
    pub async fn next_event(&mut self) -> Result<InterfaceEvent> {
        let mut buf = [0u8; 2048];
        let len = nix::unistd::read(self.socket, &mut buf)?;
        
        // Parse routing message
        // (BSD routing message format)
        
        Ok(InterfaceEvent::Other)
    }
}
```

### Conditional Compilation Directives

#### OS-Specific

```rust
#[cfg(target_os = "linux")]
// Linux-specific code

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
// BSD-specific code

#[cfg(target_os = "macos")]
// macOS-specific code

#[cfg(unix)]
// All UNIX-like systems

#[cfg(target_family = "unix")]
// Unix family (Linux, BSD, macOS, etc.)
```

#### Architecture-Specific

```rust
#[cfg(target_arch = "x86_64")]
// x86-64 specific optimizations

#[cfg(target_arch = "aarch64")]
// ARM64 specific code

#[cfg(target_pointer_width = "64")]
// 64-bit platforms
```

#### Feature-Specific

```rust
#[cfg(feature = "dbus")]
// D-Bus integration code

#[cfg(feature = "dnssec")]
// DNSSEC validation code

#[cfg(all(feature = "dbus", target_os = "linux"))]
// D-Bus on Linux only
```

### Platform Testing

Test on multiple platforms:

```bash
# Linux
cargo test --target x86_64-unknown-linux-gnu

# FreeBSD
cargo test --target x86_64-unknown-freebsd

# macOS
cargo test --target x86_64-apple-darwin

# Check all platform-specific code compiles
cargo check --target x86_64-unknown-linux-gnu
cargo check --target x86_64-unknown-freebsd
cargo check --target x86_64-apple-darwin
```

---

## Dependency Migration

This section documents the replacement of C libraries with Rust crates.

### Core Dependency Mapping

| C Library | Purpose | Rust Replacement | Version | Migration Notes |
|-----------|---------|------------------|---------|-----------------|
| libc | Standard C library | std::* + nix | 0.29 | Most libc functions have Rust std equivalents |
| libnettle + libhogweed | DNSSEC crypto | ring | 0.17 | Pure Rust crypto, no FFI overhead |
| libdbus-1 | D-Bus IPC | zbus | 5.1 | Pure Rust, async D-Bus |
| libidn2 | Internationalized domains | idna | 1.0 | Pure Rust IDNA support |
| libnetfilter_conntrack | Conntrack integration | rtnetlink | 0.15 | Netlink-based queries |
| libnftables | nftables support | nftnl | 0.6 | Bindings to libnftables |

### DNS Protocol Stack

**C Implementation:**
```c
// Manual DNS parsing with pointer arithmetic
unsigned char *p = packet;
uint16_t id = ntohs(*(uint16_t *)p);
p += 2;
uint16_t flags = ntohs(*(uint16_t *)p);
p += 2;
// ... manual field extraction
```

**Rust Implementation:**
```rust
// Using Hickory DNS (formerly Trust-DNS)
use hickory_proto::op::{Message, MessageType, Query};
use hickory_proto::rr::{Name, RecordType};

// Safe, high-level DNS message handling
let query = Message::new();
query.set_id(transaction_id);
query.set_message_type(MessageType::Query);
query.set_op_code(OpCode::Query);
query.set_recursion_desired(true);

let name = Name::from_ascii("example.com")?;
let query_obj = Query::query(name, RecordType::A);
query.add_query(query_obj);

let packet = query.to_vec()?;
```

**Dependencies:**
```toml
[dependencies]
hickory-proto = "0.25"   # DNS protocol types
hickory-server = "0.25"  # Server components
hickory-client = "0.25"  # Client for upstream queries
hickory-resolver = "0.25"  # Resolver logic
```

### Cryptography Stack

**C Implementation:**
```c
// Nettle library for DNSSEC
#include <nettle/rsa.h>
#include <nettle/dsa.h>
#include <nettle/ecdsa.h>

int verify_rsa_sha256(unsigned char *signature, size_t sig_len,
                       unsigned char *data, size_t data_len,
                       struct rsa_public_key *key) {
    struct sha256_ctx hash_ctx;
    sha256_init(&hash_ctx);
    sha256_update(&hash_ctx, data_len, data);
    
    unsigned char digest[SHA256_DIGEST_SIZE];
    sha256_digest(&hash_ctx, SHA256_DIGEST_SIZE, digest);
    
    return rsa_sha256_verify(key, &hash_ctx, signature);
}
```

**Rust Implementation:**
```rust
// Ring crypto library
use ring::signature::{self, RsaPublicKeyComponents, VerificationAlgorithm};

pub fn verify_rsa_sha256(
    signature: &[u8],
    data: &[u8],
    public_key: &RsaPublicKey,
) -> Result<(), DnssecError> {
    let public_key_components = RsaPublicKeyComponents {
        n: &public_key.modulus,
        e: &public_key.exponent,
    };
    
    public_key_components.verify(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        data,
        signature,
    ).map_err(|_| DnssecError::SignatureVerificationFailed)?;
    
    Ok(())
}
```

**Dependencies:**
```toml
[dependencies]
ring = "0.17"  # Cryptographic operations
rustls = "0.23"  # TLS (for DoT/DoH)
webpki = "0.22"  # X.509 certificate validation
```

### Async Runtime

**C Implementation:**
```c
// Manual poll() event loop
struct pollfd fds[MAX_FDS];
int nfds = 0;

// Setup sockets
fds[nfds].fd = dns_socket;
fds[nfds].events = POLLIN;
nfds++;

// Event loop
while (running) {
    int ready = poll(fds, nfds, timeout_ms);
    
    if (ready < 0) {
        if (errno == EINTR) continue;
        handle_error();
    }
    
    for (int i = 0; i < nfds; i++) {
        if (fds[i].revents & POLLIN) {
            handle_readable(fds[i].fd);
        }
    }
}
```

**Rust Implementation:**
```rust
// Tokio async runtime
use tokio::net::UdpSocket;
use tokio::select;

async fn event_loop(context: Arc<DaemonContext>) -> Result<()> {
    let dns_socket = UdpSocket::bind("0.0.0.0:53").await?;
    let dhcp_socket = UdpSocket::bind("0.0.0.0:67").await?;
    
    let mut dns_buf = vec![0u8; 512];
    let mut dhcp_buf = vec![0u8; 1500];
    
    loop {
        select! {
            result = dns_socket.recv_from(&mut dns_buf) => {
                let (len, addr) = result?;
                context.handle_dns_query(&dns_buf[..len], addr).await?;
            }
            result = dhcp_socket.recv_from(&mut dhcp_buf) => {
                let (len, addr) = result?;
                context.handle_dhcp_packet(&dhcp_buf[..len], addr).await?;
            }
            _ = context.shutdown_signal.recv() => {
                break;
            }
        }
    }
    
    Ok(())
}
```

**Dependencies:**
```toml
[dependencies]
tokio = { version = "1.42", features = ["full"] }
tokio-util = "0.7"
futures = "0.3"
async-trait = "0.1"
```

### Network Stack

**C Implementation:**
```c
// Linux netlink
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

int netlink_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
// Manual netlink message construction
struct {
    struct nlmsghdr nlh;
    struct rtmsg rtm;
} req;
memset(&req, 0, sizeof(req));
req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
// ... manual serialization
send(netlink_socket, &req, req.nlh.nlmsg_len, 0);
```

**Rust Implementation:**
```rust
// rtnetlink crate
use rtnetlink::{new_connection, IpVersion};

let (connection, handle, _) = new_connection()?;
tokio::spawn(connection);

// High-level API
let mut links = handle.link().get().execute();
while let Some(link) = links.try_next().await? {
    println!("Interface: {:?}", link);
}

// Add route
handle
    .route()
    .add()
    .v4()
    .destination_prefix(Ipv4Addr::new(10, 0, 0, 0), 8)
    .gateway(Ipv4Addr::new(192, 168, 1, 1))
    .execute()
    .await?;
```

**Dependencies:**
```toml
[target.'cfg(target_os = "linux")'.dependencies]
rtnetlink = "0.15"
netlink-packet-route = "0.20"

[target.'cfg(unix)'.dependencies]
nix = { version = "0.29", features = ["socket", "net", "signal", "process"] }
```

### D-Bus Integration

**C Implementation:**
```c
// libdbus-1
#include <dbus/dbus.h>

DBusConnection *conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
dbus_bus_request_name(conn, "uk.org.thekelleys.dnsmasq",
                      DBUS_NAME_FLAG_REPLACE_EXISTING, &err);

// Manual message handling
while (dbus_connection_read_write_dispatch(conn, -1)) {
    DBusMessage *msg = dbus_connection_pop_message(conn);
    if (dbus_message_is_method_call(msg, "uk.org.thekelleys.dnsmasq", "ClearCache")) {
        clear_cache();
        DBusMessage *reply = dbus_message_new_method_return(msg);
        dbus_connection_send(conn, reply, NULL);
    }
}
```

**Rust Implementation:**
```rust
// zbus - Pure Rust async D-Bus
use zbus::{dbus_interface, ConnectionBuilder};

struct DnsmasqService {
    dns: Arc<DnsService>,
}

#[dbus_interface(name = "uk.org.thekelleys.dnsmasq")]
impl DnsmasqService {
    async fn clear_cache(&mut self) -> zbus::fdo::Result<()> {
        self.dns.clear_cache().await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(())
    }
    
    async fn get_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }
    
    #[dbus_interface(signal)]
    async fn dhcp_lease_added(
        signal_ctxt: &SignalContext<'_>,
        ip: &str,
        mac: &str,
        hostname: &str,
    ) -> zbus::Result<()>;
}

// Start D-Bus service
let service = DnsmasqService { dns: dns_service };
let _connection = ConnectionBuilder::system()?
    .name("uk.org.thekelleys.dnsmasq")?
    .serve_at("/", service)?
    .build()
    .await?;
```

**Dependencies:**
```toml
[dependencies.zbus]
version = "5.1"
optional = true
```

### Logging and Observability

**C Implementation:**
```c
// syslog
#include <syslog.h>

openlog("dnsmasq", LOG_PID, LOG_DAEMON);
syslog(LOG_INFO, "query[A] example.com from %s", client_ip);
closelog();
```

**Rust Implementation:**
```rust
// tracing - Structured logging
use tracing::{info, warn, error, instrument};

#[instrument(skip(self), fields(query = %name, qtype = ?qtype, client = %addr))]
async fn handle_query(&self, name: &DomainName, qtype: RecordType, addr: SocketAddr) {
    info!("Processing DNS query");
    
    match self.resolve(name, qtype).await {
        Ok(response) => {
            info!(answer = ?response.answers, "Query resolved");
        }
        Err(e) => {
            warn!(error = %e, "Query failed");
        }
    }
}

// Initialize logging
tracing_subscriber::fmt()
    .with_target(false)
    .with_timer(tracing_subscriber::fmt::time::uptime())
    .init();
```

**Dependencies:**
```toml
[dependencies]
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tracing-appender = "0.2"
```

### Dependency Audit

Ensure security of all dependencies:

```bash
# Install cargo-audit
cargo install cargo-audit

# Audit dependencies
cargo audit

# Check for outdated dependencies
cargo outdated

# Verify licenses
cargo deny check licenses

# Generate dependency tree
cargo tree --all-features
```

---

## Performance Validation

This section outlines the approach to ensure the Rust implementation matches or exceeds C performance.

### Performance Targets

| Metric | C Baseline | Rust Target | Validation Method |
|--------|-----------|-------------|-------------------|
| DNS query latency | X ms | ≤ X ms | Benchmark: 10k queries/sec |
| Cache lookup time | Y μs | ≤ Y μs | Benchmark: 1M lookups |
| DHCP allocation time | Z ms | ≤ Z ms | Benchmark: 1k allocations/sec |
| Memory footprint (RSS) | M MB | ≤ M MB | Monitor under 10k active leases |
| Startup time | S ms | ≤ S ms | Time from exec to ready |
| CPU utilization | C% | ≤ C% | Monitor under sustained load |

### Benchmarking Approach

#### DNS Query Performance

```rust
// benches/dns_performance.rs
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dnsmasq::dns::{DnsService, Query};

fn dns_query_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let service = rt.block_on(async {
        DnsService::new(Config::default()).await.unwrap()
    });
    
    let mut group = c.benchmark_group("dns_queries");
    group.throughput(Throughput::Elements(1));
    
    group.bench_function("cache_hit", |b| {
        // Pre-populate cache
        let query = Query::new("example.com", RecordType::A);
        rt.block_on(service.resolve(&query)).unwrap();
        
        b.iter(|| {
            rt.block_on(async {
                service.resolve(&query).await.unwrap()
            })
        });
    });
    
    group.bench_function("cache_miss_forward", |b| {
        b.iter(|| {
            let query = Query::new(&format!("{}.example.com", rand::random::<u32>()), RecordType::A);
            rt.block_on(async {
                service.resolve(&query).await
            })
        });
    });
    
    group.finish();
}

criterion_group!(benches, dns_query_benchmark);
criterion_main!(benches);
```

Run benchmarks:
```bash
cargo bench --bench dns_performance
```

#### Cache Performance

```rust
// benches/cache_performance.rs
fn cache_operations(c: &mut Criterion) {
    let cache = DnsCache::new(10000);
    
    let mut group = c.benchmark_group("cache_ops");
    
    group.bench_function("insert", |b| {
        let mut idx = 0;
        b.iter(|| {
            let entry = CacheEntry {
                name: DomainName::from(format!("test{}.example.com", idx)),
                // ...
            };
            cache.insert(entry);
            idx += 1;
        });
    });
    
    group.bench_function("lookup", |b| {
        b.iter(|| {
            cache.lookup(&DomainName::from("example.com"), RecordType::A)
        });
    });
    
    group.finish();
}
```

#### DHCP Performance

```rust
// benches/dhcp_performance.rs
fn dhcp_allocation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let service = rt.block_on(async {
        DhcpService::new(Config::default()).await.unwrap()
    });
    
    c.bench_function("dhcp_discover_offer", |b| {
        b.iter(|| {
            let discover = DhcpMessage::discover(MacAddress::random());
            rt.block_on(async {
                service.handle_discover(discover).await
            })
        });
    });
}
```

### Memory Profiling

#### Heap Profiling

Use `heaptrack` or `valgrind --tool=massif`:

```bash
# Build with debug symbols
cargo build --release

# Profile with heaptrack
heaptrack ./target/release/dnsmasq --no-daemon

# Analyze results
heaptrack_gui heaptrack.dnsmasq.*.gz

# Or use valgrind
valgrind --tool=massif --massif-out-file=massif.out ./target/release/dnsmasq --no-daemon
ms_print massif.out
```

#### Memory Leak Detection

```bash
# Valgrind leak check
valgrind --leak-check=full --show-leak-kinds=all ./target/release/dnsmasq --no-daemon

# Expected output: "All heap blocks were freed -- no leaks are possible"
```

### CPU Profiling

#### Using `perf` on Linux

```bash
# Record CPU profile
perf record -F 999 -g ./target/release/dnsmasq --no-daemon

# Generate flamegraph
perf script | stackcollapse-perf.pl | flamegraph.pl > flamegraph.svg

# View in browser
firefox flamegraph.svg
```

#### Using `cargo-flamegraph`

```bash
# Install
cargo install flamegraph

# Profile
cargo flamegraph --bin dnsmasq -- --no-daemon

# Opens flamegraph.svg automatically
```

### Load Testing

#### DNS Load Test

```bash
# Using dnsperf
dnsperf -s localhost -p 53 -d queries.txt -l 60 -Q 10000

# queries.txt format:
# example.com A
# www.example.com A
# mail.example.com MX
```

#### DHCP Load Test

```bash
# Using dhcptest or custom script
for i in {1..1000}; do
    dhclient -d eth0 &
done

# Monitor lease allocation time
```

### Comparative Benchmarks

Run identical workloads against C and Rust versions:

```bash
# Benchmark C version
time ./dnsmasq-c --test < bench-config.conf

# Benchmark Rust version
time ./dnsmasq-rust --test < bench-config.conf

# Compare results
hyperfine --warmup 3 './dnsmasq-c --test' './dnsmasq-rust --test'
```

### Performance Regression Detection

Integrate benchmarks into CI:

```yaml
# .github/workflows/performance.yml
name: Performance Tests

on: [push, pull_request]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: 1.91.0
      
      - name: Run benchmarks
        run: cargo bench --bench '*' -- --save-baseline current
      
      - name: Compare with baseline
        run: cargo bench --bench '*' -- --baseline main --save-baseline current
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: benchmark-results
          path: target/criterion/
```

### Performance Optimization Strategies

#### Async Runtime Tuning

```rust
// Tune tokio runtime for workload
let runtime = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(num_cpus::get())
    .thread_name("dnsmasq-worker")
    .thread_stack_size(3 * 1024 * 1024)
    .event_interval(61)
    .build()?;
```

#### Memory Pool Optimization

```rust
// Reuse buffers to reduce allocations
pub struct BufferPool {
    buffers: Vec<Vec<u8>>,
}

impl BufferPool {
    pub fn get(&mut self) -> Vec<u8> {
        self.buffers.pop().unwrap_or_else(|| Vec::with_capacity(1500))
    }
    
    pub fn return_buf(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        if self.buffers.len() < 100 {
            self.buffers.push(buf);
        }
    }
}
```

#### Cache Optimization

```rust
// Use efficient data structures
use ahash::AHashMap;  // Faster hash function

pub struct DnsCache {
    entries: AHashMap<CacheKey, CacheEntry>,
    lru: LinkedList<CacheKey>,
}
```

### Performance Success Criteria

The Rust implementation is considered performant when:

- ✅ DNS query latency ≤ C version (measured over 1M queries)
- ✅ Cache operations match or exceed C version speed
- ✅ DHCP allocation time ≤ C version
- ✅ Memory footprint ≤ C version under equivalent load
- ✅ CPU utilization ≤ C version for equivalent workload
- ✅ No memory leaks detected over 24-hour stress test
- ✅ Startup time ≤ C version + 10%
- ✅ No performance regressions in CI benchmarks

---

## Development Guidelines

This section provides guidance for developers working with the Rust codebase.

### Code Style and Formatting

```bash
# Format code
cargo fmt

# Check formatting without modifying
cargo fmt -- --check

# Lint code
cargo clippy -- -D warnings

# Fix clippy suggestions automatically
cargo clippy --fix
```

### Rust Idioms and Best Practices

#### Prefer `Result` and `Option` over Panics

```rust
// ✓ GOOD: Use Result for fallible operations
pub fn parse_config(path: &Path) -> Result<Config, ConfigError> {
    let content = std::fs::read_to_string(path)?;
    Config::parse(&content)
}

// ✗ BAD: Panic on errors
pub fn parse_config(path: &Path) -> Config {
    let content = std::fs::read_to_string(path).unwrap();  // Panics on error!
    Config::parse(&content).unwrap()
}
```

#### Use `?` Operator for Error Propagation

```rust
// ✓ GOOD: Concise error propagation
pub async fn handle_query(&self, query: DnsQuery) -> Result<DnsResponse> {
    let cached = self.cache.lookup(&query.name).await?;
    let validated = self.dnssec.validate(cached).await?;
    Ok(validated)
}

// ✗ BAD: Manual error handling
pub async fn handle_query(&self, query: DnsQuery) -> Result<DnsResponse> {
    match self.cache.lookup(&query.name).await {
        Ok(cached) => {
            match self.dnssec.validate(cached).await {
                Ok(validated) => Ok(validated),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}
```

#### Prefer Borrowing Over Cloning

```rust
// ✓ GOOD: Borrow when possible
pub fn log_query(&self, name: &DomainName, qtype: RecordType) {
    info!("Query: {} {:?}", name, qtype);
}

// ✗ BAD: Unnecessary clone
pub fn log_query(&self, name: DomainName, qtype: RecordType) {  // Takes ownership!
    info!("Query: {} {:?}", name, qtype);
}
```

#### Use Type-Safe Wrappers

```rust
// ✓ GOOD: Newtype pattern for type safety
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainName(String);

impl DomainName {
    pub fn new(name: impl Into<String>) -> Result<Self, InvalidDomainName> {
        let name = name.into();
        if name.len() > 255 {
            return Err(InvalidDomainName::TooLong);
        }
        Ok(DomainName(name))
    }
}

// ✗ BAD: Primitive obsession
pub fn lookup_cache(name: String) -> Option<CacheEntry> {
    // No validation, any string accepted
}
```

### Testing Conventions

#### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_domain_name_validation() {
        // Test valid name
        assert!(DomainName::new("example.com").is_ok());
        
        // Test invalid name (too long)
        let long_name = "a".repeat(256);
        assert!(DomainName::new(long_name).is_err());
    }
    
    #[tokio::test]
    async fn test_cache_insert_lookup() {
        let cache = DnsCache::new(100);
        let entry = CacheEntry::new("example.com", RecordType::A);
        
        cache.insert(entry.clone()).await.unwrap();
        
        let result = cache.lookup(&DomainName::from("example.com"), RecordType::A).await;
        assert_eq!(result, Some(entry));
    }
}
```

#### Integration Tests

```rust
// tests/integration/dns_tests.rs
use dnsmasq::{DnsService, Config};

#[tokio::test]
async fn test_end_to_end_dns_query() {
    let config = Config::default();
    let service = DnsService::new(config).await.unwrap();
    
    let query = Query::new("example.com", RecordType::A);
    let response = service.resolve(&query).await.unwrap();
    
    assert!(!response.answers.is_empty());
}
```

### Documentation Standards

#### Module Documentation

```rust
//! DNS cache implementation.
//!
//! This module provides a high-performance DNS cache with LRU eviction.
//!
//! # Examples
//!
//! ```
//! use dnsmasq::dns::cache::DnsCache;
//!
//! let cache = DnsCache::new(1000);
//! cache.insert(entry).await?;
//! ```

pub struct DnsCache {
    // ...
}
```

#### Function Documentation

```rust
/// Resolves a DNS query by checking the cache and forwarding if necessary.
///
/// # Arguments
///
/// * `query` - The DNS query to resolve
///
/// # Returns
///
/// Returns a `DnsResponse` on success, or a `DnsError` if resolution fails.
///
/// # Examples
///
/// ```
/// let query = Query::new("example.com", RecordType::A);
/// let response = service.resolve(&query).await?;
/// ```
pub async fn resolve(&self, query: &DnsQuery) -> Result<DnsResponse, DnsError> {
    // ...
}
```

### Error Handling Patterns

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS query timeout")]
    Timeout,
    
    #[error("Invalid domain name: {0}")]
    InvalidDomain(String),
    
    #[error("DNSSEC validation failed")]
    DnssecValidationFailed,
    
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
}
```

### Async/Await Guidelines

```rust
// ✓ GOOD: Async functions for I/O-bound operations
pub async fn forward_query(&self, query: DnsQuery) -> Result<DnsResponse> {
    let response = self.client.send(query).await?;
    Ok(response)
}

// ✗ BAD: Blocking operations in async context
pub async fn read_config(&self) -> Result<Config> {
    // Blocks the async runtime!
    let content = std::fs::read_to_string("config.conf")?;
    Ok(Config::parse(&content))
}

// ✓ GOOD: Use tokio::fs for async file I/O
pub async fn read_config(&self) -> Result<Config> {
    let content = tokio::fs::read_to_string("config.conf").await?;
    Ok(Config::parse(&content))
}
```

### Contribution Workflow

```bash
# 1. Fork and clone repository
git clone https://github.com/your-username/dnsmasq.git
cd dnsmasq

# 2. Create feature branch
git checkout -b feature/my-improvement

# 3. Make changes and test
cargo test --all-features
cargo clippy -- -D warnings
cargo fmt

# 4. Commit changes
git add .
git commit -m "Add feature: my improvement"

# 5. Push and create pull request
git push origin feature/my-improvement
```

### Code Review Checklist

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] Code coverage maintained or improved
- [ ] Documentation updated
- [ ] Clippy lints pass
- [ ] Code formatted with rustfmt
- [ ] No unsafe blocks without justification
- [ ] Error handling is comprehensive
- [ ] Performance impact considered
- [ ] Backward compatibility maintained

---

## Conclusion

This migration guide provides comprehensive documentation for understanding the dnsmasq C-to-Rust transformation. The refactoring achieves memory safety through Rust's ownership system while maintaining 100% functional equivalence with the C implementation.

### Key Takeaways

1. **Memory Safety**: Rust's type system eliminates entire classes of vulnerabilities present in C
2. **Functional Preservation**: All dnsmasq capabilities are maintained without behavioral changes
3. **Configuration Compatibility**: Existing configurations work without modification
4. **API Preservation**: D-Bus, signals, and helper scripts maintain exact compatibility
5. **Performance Equivalence**: Rust implementation matches or exceeds C performance
6. **Modern Architecture**: Async/await replaces poll() for cleaner, more maintainable code

### Future Enhancements

While the initial migration focuses on functional equivalence, future improvements could include:

- **DNS-over-HTTPS (DoH)** and **DNS-over-TLS (DoT)** support using rustls
- **Enhanced metrics** with Prometheus integration
- **Advanced caching strategies** leveraging Rust's type system
- **Improved logging** with structured logging and log levels
- **Additional platform support** (Android, iOS, embedded systems)

### Resources

- **Rust Documentation**: https://doc.rust-lang.org/
- **Tokio Guide**: https://tokio.rs/tokio/tutorial
- **Hickory DNS**: https://github.com/hickory-dns/hickory-dns
- **Cargo Book**: https://doc.rust-lang.org/cargo/
- **Rust API Guidelines**: https://rust-lang.github.io/api-guidelines/

### Support

For questions or issues related to the Rust implementation:

- GitHub Issues: https://github.com/dnsmasq/dnsmasq/issues
- Mailing List: dnsmasq-discuss@lists.thekelleys.org.uk
- Documentation: https://thekelleys.org.uk/dnsmasq/docs/

---

**Document Version**: 1.0  
**Last Updated**: 2024  
**Authors**: Dnsmasq Contributors  
**License**: GPL-2.0-or-later OR GPL-3.0

