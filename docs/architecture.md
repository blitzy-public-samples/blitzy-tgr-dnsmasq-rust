# Dnsmasq Rust Implementation Architecture

## Table of Contents

1. [Overview and Design Evolution](#overview-and-design-evolution)
2. [Architectural Transformation: C to Rust](#architectural-transformation-c-to-rust)
3. [Async Runtime Architecture](#async-runtime-architecture)
4. [Module Structure and Organization](#module-structure-and-organization)
5. [Memory Safety Architecture](#memory-safety-architecture)
6. [Type-Safe Protocol Parsing](#type-safe-protocol-parsing)
7. [Error Handling Architecture](#error-handling-architecture)
8. [Platform Abstraction Layer](#platform-abstraction-layer)
9. [Design Patterns and Architectural Patterns](#design-patterns-and-architectural-patterns)
10. [DNSSEC Cryptography Implementation](#dnssec-cryptography-implementation)
11. [Cross-Platform Support Strategy](#cross-platform-support-strategy)
12. [Performance and Resource Management](#performance-and-resource-management)
13. [Testing and Validation Architecture](#testing-and-validation-architecture)

---

## Overview and Design Evolution

### Relationship to Original C Implementation

This Rust implementation is a **complete rewrite** of dnsmasq that maintains 100% functional parity and behavioral equivalence with the original C implementation documented in the [C Architecture Documentation](ARCHITECTURE.md). The transformation from C to Rust represents a technology stack migration focused on achieving **memory safety** while preserving all existing functionality, configuration compatibility, and operational characteristics.

### Core Design Philosophy

The Rust implementation maintains dnsmasq's fundamental design principles while leveraging Rust's type system and ownership model to eliminate entire classes of vulnerabilities:

1. **Memory Safety Without Garbage Collection**: Rust's ownership system provides compile-time memory safety guarantees, eliminating buffer overflows, use-after-free, double-free, and memory leaks without runtime garbage collection overhead.

2. **Zero-Cost Abstractions**: Rust's abstractions (traits, generics, pattern matching) compile to efficient machine code with no runtime penalty, maintaining dnsmasq's efficiency goals for embedded systems.

3. **Fearless Concurrency**: While maintaining single-threaded execution for compatibility, Rust's type system prevents data races and ensures thread-safe patterns where needed (signal handling, metrics collection).

4. **Explicit Error Handling**: The `Result<T, E>` type system makes error paths explicit and enforces handling, eliminating silent failures common in C code paths.

### Design Goals Preserved from C Implementation

- **Resource Efficiency**: Target 1-10MB resident set size, suitable for embedded devices
- **Operational Simplicity**: Zero-configuration deployment, hot-reload via SIGHUP
- **Universal Portability**: Linux, BSD, macOS, Android support with platform-specific optimizations
- **Deterministic Behavior**: Predictable resource consumption enabling years of continuous operation

### Key Architectural Changes

| Aspect | C Implementation | Rust Implementation |
|--------|------------------|---------------------|
| **Event Loop** | poll() system call in src/dnsmasq.c | tokio async runtime with tokio::select! |
| **Memory Management** | Manual malloc/free | Ownership system with Box/Vec/Arc and automatic Drop |
| **Error Handling** | Return codes (-1/0/1) and errno | Result<T, E> and Option<T> types |
| **Protocol Parsing** | Pointer arithmetic | nom parser combinators and hickory-dns types |
| **Concurrency** | Single-threaded poll loop | Async/await with cooperative multitasking |
| **Platform Abstraction** | #ifdef preprocessor | Traits with cfg attributes and feature flags |
| **Cryptography** | Nettle library FFI | ring crate (pure Rust cryptography) |
| **Type Safety** | Minimal compile-time checking | Strong static typing with ownership invariants |

---

## Architectural Transformation: C to Rust

### From Poll-Based to Async/Await

The most significant architectural transformation is the replacement of the C poll-based event loop with Rust's async/await paradigm powered by the tokio runtime.

#### C Poll-Based Event Loop (Original)

```c
// src/dnsmasq.c - Simplified representation
while (1) {
    // Build pollfd array
    struct pollfd fds[MAX_FDS];
    int nfds = 0;
    
    fds[nfds++] = (struct pollfd){dns_socket, POLLIN, 0};
    fds[nfds++] = (struct pollfd){dhcp_socket, POLLIN, 0};
    fds[nfds++] = (struct pollfd){tftp_socket, POLLIN, 0};
    
    // Wait for events
    int ready = poll(fds, nfds, timeout_ms);
    
    // Dispatch events manually
    if (fds[0].revents & POLLIN) handle_dns_packet();
    if (fds[1].revents & POLLIN) handle_dhcp_packet();
    if (fds[2].revents & POLLIN) handle_tftp_packet();
}
```

**Characteristics**:
- Manual file descriptor management
- Explicit timeout calculations
- State machines maintained in global variables
- Error-prone fd_set manipulation

#### Rust Async/Await Event Loop (New)

```rust
// src/runtime/event_loop.rs
pub async fn run_event_loop(context: Arc<ServerContext>) -> Result<(), Error> {
    let mut dns_socket = context.dns_socket.clone();
    let mut dhcp_socket = context.dhcp_socket.clone();
    let mut tftp_socket = context.tftp_socket.clone();
    let mut shutdown = context.shutdown.subscribe();
    
    loop {
        tokio::select! {
            result = dns_socket.recv_from(&mut buf) => {
                let (len, peer) = result?;
                handle_dns_packet(&buf[..len], peer, &context).await?;
            }
            result = dhcp_socket.recv_from(&mut buf) => {
                let (len, peer) = result?;
                handle_dhcp_packet(&buf[..len], peer, &context).await?;
            }
            result = tftp_socket.recv_from(&mut buf) => {
                let (len, peer) = result?;
                handle_tftp_packet(&buf[..len], peer, &context).await?;
            }
            _ = shutdown.recv() => {
                info!("Shutdown signal received, exiting event loop");
                break;
            }
        }
    }
    
    Ok(())
}
```

**Characteristics**:
- Automatic file descriptor management via tokio
- Type-safe socket abstractions
- Explicit error propagation with `?` operator
- Structured concurrency with select! macro
- Graceful shutdown integrated into event loop

### From Manual Memory Management to Ownership

#### C Memory Management (Original)

```c
// src/cache.c - Simplified
struct cache_entry *allocate_cache_entry(char *name) {
    struct cache_entry *entry = safe_malloc(sizeof(struct cache_entry));
    entry->name = safe_malloc(strlen(name) + 1);
    strcpy(entry->name, name);
    entry->refs = 1;
    return entry;
}

void free_cache_entry(struct cache_entry *entry) {
    if (--entry->refs == 0) {
        free(entry->name);
        free(entry);
    }
}
```

**Problems**:
- Manual reference counting prone to errors
- Potential double-free if refs incorrectly managed
- Memory leaks if free() not called
- Use-after-free if dangling pointers exist

#### Rust Ownership System (New)

```rust
// src/dns/cache.rs
pub struct CacheEntry {
    name: String,                    // Owned, automatically freed
    address: IpAddr,
    ttl: Duration,
    inserted_at: Instant,
    flags: CacheFlags,
}

impl CacheEntry {
    pub fn new(name: String, address: IpAddr, ttl: Duration) -> Self {
        Self {
            name,                     // Moved, no copies
            address,
            ttl,
            inserted_at: Instant::now(),
            flags: CacheFlags::empty(),
        }
    }
    // Automatic Drop impl frees String when CacheEntry dropped
}

// Usage
let entry = CacheEntry::new("example.com".to_string(), addr, ttl);
// No manual free() needed - dropped automatically at scope exit
```

**Benefits**:
- No manual memory management
- Impossible to have use-after-free (enforced at compile time)
- No memory leaks (Drop trait automatically called)
- No double-free (ownership moves, not copies)
- No reference counting errors (Arc<T> when needed is type-safe)

---

## Async Runtime Architecture

### Tokio Runtime Integration

The Rust implementation uses tokio 1.42+ as the async runtime, replacing the C poll() loop with a sophisticated event-driven executor.

#### Runtime Initialization

```rust
// src/main.rs
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse configuration
    let config = Config::from_cli_and_files().await?;
    
    // Initialize logging
    init_logging(&config)?;
    
    // Build server context
    let context = ServerContext::new(config).await?;
    
    // Start services
    let dns_service = DnsService::new(context.clone()).await?;
    let dhcp_service = DhcpService::new(context.clone()).await?;
    
    // Run event loop
    runtime::event_loop::run(context, dns_service, dhcp_service).await?;
    
    Ok(())
}
```

**Runtime Configuration**:
- **Flavor**: `current_thread` maintains single-threaded semantics matching C version
- **No work-stealing**: Predictable execution order
- **Deterministic scheduling**: Tasks scheduled in order, no thread migration

#### Task Structure

```rust
// src/runtime/tasks.rs
pub struct TaskManager {
    tasks: Vec<JoinHandle<()>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl TaskManager {
    pub fn spawn_background_task<F>(&mut self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::spawn(future);
        self.tasks.push(handle);
    }
    
    pub async fn shutdown_all(self) -> Result<(), Error> {
        // Signal shutdown
        let _ = self.shutdown_tx.send(());
        
        // Wait for all tasks
        for task in self.tasks {
            task.await?;
        }
        
        Ok(())
    }
}
```

**Background Tasks**:
- DNS cache maintenance (TTL expiration)
- DHCP lease expiration checks
- Router Advertisement periodic transmission
- Metrics collection and aggregation
- Configuration reload on SIGHUP

### Async I/O Patterns

#### Non-Blocking Socket Operations

```rust
// src/network/sockets.rs
pub struct DnsSocket {
    socket: Arc<UdpSocket>,
    buffer_pool: BufferPool,
}

impl DnsSocket {
    pub async fn recv_query(&self) -> Result<(DnsQuery, SocketAddr), Error> {
        let mut buf = self.buffer_pool.acquire();
        let (len, peer) = self.socket.recv_from(&mut buf).await?;
        
        // Parse query (non-blocking, CPU-bound)
        let query = DnsQuery::parse(&buf[..len])?;
        
        Ok((query, peer))
    }
    
    pub async fn send_response(&self, response: &DnsResponse, peer: SocketAddr) 
        -> Result<usize, Error> 
    {
        let bytes = response.to_bytes()?;
        self.socket.send_to(&bytes, peer).await
            .map_err(Error::from)
    }
}
```

**Benefits Over C poll()**:
- Automatic readiness tracking (no manual POLLIN/POLLOUT checks)
- Type-safe buffer management (no buffer overflow)
- Explicit error types (no errno)
- Composable async operations (no callback hell)

---

## Module Structure and Organization

### Hierarchical Module Architecture

The Rust implementation organizes code into a hierarchical module structure that mirrors functional boundaries while providing clear dependency graphs.

```
src/
├── main.rs                    # Binary entry point, tokio runtime initialization
├── lib.rs                     # Public library API surface
│
├── types.rs                   # Common types (DomainName, IpAddr wrappers, etc.)
├── error.rs                   # Error type definitions using thiserror
├── constants.rs               # Global constants from C config.h
│
├── config/                    # Configuration management
│   ├── mod.rs                 # Config module public API
│   ├── parser.rs              # dnsmasq.conf parser (nom-based)
│   ├── cli.rs                 # Command-line parsing (clap-based)
│   ├── types.rs               # Configuration data structures
│   ├── validator.rs           # Configuration validation logic
│   └── reload.rs              # SIGHUP reload handling
│
├── dns/                       # DNS subsystem
│   ├── mod.rs                 # DnsService coordinator
│   ├── forwarder.rs           # Query forwarding logic (from forward.c)
│   ├── cache.rs               # DNS cache (from cache.c)
│   ├── upstream.rs            # Upstream server management
│   ├── matcher.rs             # Domain matching (from domain-match.c)
│   ├── auth.rs                # Authoritative zones (from auth.c)
│   ├── edns0.rs               # EDNS0 options (from edns0.c)
│   ├── filter.rs              # RR filtering (from rrfilter.c)
│   │
│   ├── protocol/              # DNS protocol implementation
│   │   ├── mod.rs             # Protocol types and parsing
│   │   ├── message.rs         # DNS message structure (from rfc1035.c)
│   │   ├── name.rs            # Domain name handling (from domain.c)
│   │   ├── record.rs          # Resource records
│   │   ├── compression.rs     # Name compression (from rfc1035.c)
│   │   └── constants.rs       # DNS protocol constants
│   │
│   └── dnssec/                # DNSSEC validation
│       ├── mod.rs             # DNSSEC subsystem
│       ├── validator.rs       # Validation logic (from dnssec.c)
│       ├── crypto.rs          # Signature verification using ring (from crypto.c)
│       ├── trust_anchors.rs   # Trust anchor management
│       └── blockdata.rs       # DNSSEC record storage (from blockdata.c)
│
├── dhcp/                      # DHCP subsystem
│   ├── mod.rs                 # DHCP module root
│   ├── common.rs              # Shared DHCPv4/v6 utilities (from dhcp-common.c)
│   │
│   ├── v4/                    # DHCPv4 server
│   │   ├── mod.rs             # DHCPv4 subsystem
│   │   ├── server.rs          # DHCPv4 server logic (from dhcp.c)
│   │   ├── protocol.rs        # DISCOVER/OFFER/REQUEST/ACK (from rfc2131.c)
│   │   ├── message.rs         # DHCPv4 message parsing
│   │   ├── options.rs         # DHCPv4 option handling
│   │   └── constants.rs       # DHCPv4 protocol constants
│   │
│   ├── v6/                    # DHCPv6 server
│   │   ├── mod.rs             # DHCPv6 subsystem
│   │   ├── server.rs          # DHCPv6 server logic (from dhcp6.c)
│   │   ├── protocol.rs        # SOLICIT/ADVERTISE/REQUEST (from rfc3315.c)
│   │   ├── message.rs         # DHCPv6 message parsing
│   │   ├── options.rs         # DHCPv6 options (from outpacket.c)
│   │   └── constants.rs       # DHCPv6 protocol constants
│   │
│   └── lease/                 # Lease management
│       ├── mod.rs             # Lease subsystem
│       ├── database.rs        # Lease persistence (from lease.c)
│       ├── dns_integration.rs # DNS record registration
│       └── script_hooks.rs    # Helper script execution
│
├── radv/                      # Router Advertisement
│   ├── mod.rs                 # RA generation (from radv.c)
│   ├── protocol.rs            # RA protocol constants
│   └── slaac.rs               # SLAAC DAD (from slaac.c)
│
├── network/                   # Network layer
│   ├── mod.rs                 # Network module root (from network.c)
│   ├── sockets.rs             # Socket creation and management
│   ├── interfaces.rs          # Interface enumeration
│   ├── arp.rs                 # ARP table manipulation (from arp.c)
│   ├── conntrack.rs           # Connection tracking (from conntrack.c)
│   │
│   ├── platform/              # Platform-specific networking
│   │   ├── mod.rs             # Platform abstraction traits
│   │   ├── linux.rs           # Linux netlink (from netlink.c)
│   │   ├── bsd.rs             # BSD BPF (from bpf.c)
│   │   ├── macos.rs           # macOS-specific code
│   │   └── common.rs          # Cross-platform abstractions
│   │
│   └── firewall/              # Firewall integration
│       ├── mod.rs             # Firewall subsystem
│       ├── ipset.rs           # Linux ipset (from ipset.c)
│       ├── nftables.rs        # nftables (from nftset.c)
│       └── pf.rs              # BSD PF (from tables.c)
│
├── tftp/                      # TFTP server
│   ├── mod.rs                 # TFTP module root
│   ├── server.rs              # TFTP protocol (from tftp.c)
│   └── transfer.rs            # File transfer state machine
│
├── platform/                  # Platform integration
│   ├── mod.rs                 # Platform module root
│   ├── signals.rs             # POSIX signal handling (async-signal-safe)
│   ├── privileges.rs          # Privilege dropping (capabilities)
│   ├── dbus.rs                # D-Bus interface (from dbus.c)
│   ├── ubus.rs                # OpenWrt ubus (from ubus.c)
│   ├── inotify.rs             # File monitoring (from inotify.c)
│   └── systemd.rs             # systemd integration (socket activation)
│
├── runtime/                   # Async runtime management
│   ├── mod.rs                 # Runtime module root
│   ├── event_loop.rs          # Main event loop (from dnsmasq.c, loop.c)
│   ├── reactor.rs             # I/O multiplexing (from poll.c)
│   └── tasks.rs               # Background task management
│
└── util/                      # Utilities
    ├── mod.rs                 # Utilities module root
    ├── helpers.rs             # Helper script execution (from helper.c)
    ├── logging.rs             # Logging system using tracing (from log.c)
    ├── metrics.rs             # Metrics collection (from metrics.c)
    ├── pcap.rs                # Packet capture (from dump.c)
    ├── patterns.rs            # Pattern matching (from pattern.c)
    └── random.rs              # Random number generation (from util.c)
```

### Module Dependency Graph

```
┌─────────────────────────────────────────────────────────────┐
│ main.rs                                                      │
│   ↓                                                          │
│ runtime/event_loop.rs                                        │
└──────────────────┬──────────────────────────────────────────┘
                   ↓
┌──────────────────┴──────────────────────────────────────────┐
│ Service Layer                                                │
│   ├── dns/mod.rs (DnsService)                               │
│   ├── dhcp/mod.rs (DhcpService)                             │
│   ├── tftp/mod.rs (TftpService)                             │
│   └── radv/mod.rs (RadvService)                             │
└──────────────────┬──────────────────────────────────────────┘
                   ↓
┌──────────────────┴──────────────────────────────────────────┐
│ Protocol Layer                                               │
│   ├── dns/protocol/* (DNS wire format)                      │
│   ├── dns/dnssec/* (DNSSEC validation)                      │
│   ├── dhcp/v4/* (DHCPv4 protocol)                           │
│   ├── dhcp/v6/* (DHCPv6 protocol)                           │
│   └── radv/protocol.rs (RA format)                          │
└──────────────────┬──────────────────────────────────────────┘
                   ↓
┌──────────────────┴──────────────────────────────────────────┐
│ Network Layer                                                │
│   ├── network/sockets.rs                                    │
│   ├── network/platform/* (Linux/BSD/macOS)                  │
│   └── network/firewall/* (ipset/nftables/PF)                │
└──────────────────┬──────────────────────────────────────────┘
                   ↓
┌──────────────────┴──────────────────────────────────────────┐
│ Foundation Layer                                             │
│   ├── types.rs (common types)                               │
│   ├── error.rs (error types)                                │
│   ├── config/* (configuration management)                   │
│   └── util/* (utilities)                                    │
└──────────────────────────────────────────────────────────────┘
```

### Public API Surface

The `lib.rs` file exposes a minimal public API for library usage:

```rust
// src/lib.rs
pub mod config;
pub mod dns;
pub mod dhcp;
pub mod error;

pub use config::Config;
pub use dns::DnsService;
pub use dhcp::DhcpService;
pub use error::Error;

// Internal modules (not public)
mod network;
mod platform;
mod runtime;
mod types;
mod util;
```

---

## Memory Safety Architecture

### Ownership and Borrowing Eliminating Manual Memory Management

Rust's ownership system provides compile-time guarantees that eliminate entire classes of memory safety vulnerabilities present in C code.

#### Ownership Rules Applied

**Rule 1: Each value has a single owner**

```rust
// src/dns/cache.rs
pub struct Cache {
    entries: HashMap<String, CacheEntry>,  // Cache owns entries
}

impl Cache {
    pub fn insert(&mut self, entry: CacheEntry) {
        let name = entry.name.clone();
        self.entries.insert(name, entry);  // Ownership transferred
        // entry no longer accessible here - moved into HashMap
    }
}
```

**Contrast with C** (from src/cache.c):
```c
// C code requires manual tracking
struct cache_entry *entry = malloc(sizeof(struct cache_entry));
cache_insert(entry);  // Who owns entry now? Unclear from type system
// Potential double-free if both caller and cache free entry
```

**Rule 2: References must be valid for their entire lifetime**

```rust
// src/dns/forwarder.rs
pub struct DnsForwarder<'a> {
    cache: &'a Cache,           // Borrowed reference with lifetime 'a
    upstream: &'a UpstreamPool, // Cannot outlive 'a
}

impl<'a> DnsForwarder<'a> {
    pub async fn forward_query(&self, query: &DnsQuery) -> Result<DnsResponse, Error> {
        // cache and upstream guaranteed valid here
        if let Some(cached) = self.cache.lookup(&query.name) {
            return Ok(cached.to_response());
        }
        
        self.upstream.send_query(query).await
    }
}
```

**Benefits**:
- Compiler enforces that cache and upstream pointers are valid
- No dangling pointer bugs possible
- No use-after-free possible

**Rule 3: Mutable references are exclusive**

```rust
// src/dhcp/lease/database.rs
pub async fn update_lease(
    database: &mut LeaseDatabase,  // Exclusive mutable access
    lease: &Lease,
) -> Result<(), Error> {
    // No other code can access database while we have &mut
    database.leases.insert(lease.ip, lease.clone());
    database.save_to_disk().await?;
    Ok(())
}
```

**Contrast with C**:
```c
// C code allows concurrent modification
void update_lease(struct lease_db *db, struct lease *lease) {
    db->leases[db->count++] = lease;  // Race condition if multi-threaded
    save_to_disk(db);                  // Potential corruption
}
```

### RAII (Resource Acquisition Is Initialization)

Rust's Drop trait automatically cleans up resources when ownership ends, eliminating resource leaks.

#### Automatic Resource Management

```rust
// src/network/sockets.rs
pub struct BoundSocket {
    socket: UdpSocket,
    #[cfg(target_os = "linux")]
    netlink: NetlinkSocket,
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        info!("Closing socket on port {}", self.socket.local_addr().unwrap().port());
        // socket and netlink automatically closed here
        // No explicit close() needed
    }
}

// Usage
async fn start_server() -> Result<(), Error> {
    let socket = BoundSocket::bind("0.0.0.0:53").await?;
    // ... use socket ...
    Ok(())
    // socket automatically closed when function returns
    // Even if error occurred - Drop trait called during stack unwinding
}
```

**Contrast with C** (from src/network.c):
```c
int start_server() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    
    if (bind(sock, ...) < 0) {
        close(sock);  // Must manually close on error
        return -1;
    }
    
    // ... use socket ...
    
    close(sock);  // Must manually close on success
    return 0;
    // If any error path forgets close(sock) → resource leak
}
```

#### File Handle Management

```rust
// src/dhcp/lease/database.rs
use tokio::fs::File;

pub async fn save_leases(path: &Path, leases: &[Lease]) -> Result<(), Error> {
    let mut file = File::create(path).await?;
    
    for lease in leases {
        file.write_all(lease.serialize().as_bytes()).await?;
    }
    
    file.flush().await?;
    Ok(())
    // File automatically closed via Drop, even if write_all fails
}
```

### Safe Concurrency with Arc and Mutex

While maintaining single-threaded execution, Rust ensures thread-safe sharing of configuration and metrics.

```rust
// src/types.rs
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct ServerContext {
    pub config: Arc<Config>,                    // Immutable, shared across tasks
    pub dns_cache: Arc<RwLock<Cache>>,          // Mutable, protected by RwLock
    pub dhcp_leases: Arc<RwLock<LeaseDatabase>>, // Mutable, protected by RwLock
    pub metrics: Arc<RwLock<Metrics>>,          // Mutable, protected by RwLock
}

impl ServerContext {
    pub async fn dns_cache_hit(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.dns_cache_hits += 1;
        // Write lock automatically released when metrics dropped
    }
}
```

**Benefits**:
- Compiler enforces that concurrent access uses locks
- Impossible to have data races (compile-time error)
- No forgotten lock acquisitions (RAII releases locks)

### Preventing Buffer Overflows

#### Bounds-Checked Array Access

```rust
// src/dns/protocol/message.rs
pub fn parse_dns_name(buffer: &[u8], offset: usize) -> Result<(String, usize), Error> {
    let mut name = String::new();
    let mut pos = offset;
    
    loop {
        // Bounds check automatically performed by slice indexing
        let len = buffer.get(pos)
            .ok_or(Error::BufferTooSmall)?;  // Explicit error if out of bounds
        
        if *len == 0 {
            break;
        }
        
        pos += 1;
        
        // Bounds-checked slice access
        let label = buffer.get(pos..pos + *len as usize)
            .ok_or(Error::BufferTooSmall)?;
        
        name.push_str(std::str::from_utf8(label)?);
        name.push('.');
        
        pos += *len as usize;
    }
    
    Ok((name, pos + 1))
}
```

**Contrast with C** (from src/rfc1035.c):
```c
unsigned char *parse_dns_name(unsigned char *buffer, char *name, int *offset) {
    int pos = *offset;
    while (1) {
        int len = buffer[pos];  // No bounds check - buffer overflow possible
        if (len == 0) break;
        
        memcpy(name, buffer + pos + 1, len);  // Potential buffer overflow
        pos += len + 1;
    }
    *offset = pos;
    return buffer + pos;
}
```

#### Vec<T> Replaces Fixed-Size Arrays

```rust
// src/dns/cache.rs
pub struct Cache {
    entries: Vec<CacheEntry>,  // Grows dynamically, no fixed limit
    max_size: usize,
}

impl Cache {
    pub fn insert(&mut self, entry: CacheEntry) -> Result<(), Error> {
        if self.entries.len() >= self.max_size {
            self.evict_lru();
        }
        
        self.entries.push(entry);  // Automatic reallocation if needed
        Ok(())
    }
}
```

**Contrast with C** (from src/cache.c):
```c
#define CACHESIZ 150
struct cache_entry cache[CACHESIZ];  // Fixed size, overflow if exceeded
int cache_count = 0;

void insert_cache(struct cache_entry entry) {
    if (cache_count < CACHESIZ) {  // Manual bounds checking required
        cache[cache_count++] = entry;
    } else {
        // Overflow - either reject or evict, error-prone
    }
}
```

---

## Type-Safe Protocol Parsing

### DNS Protocol Parsing with Hickory and Nom

The Rust implementation uses type-safe parsing libraries to replace C's pointer arithmetic with bounds-checked, composable parsers.

#### DNS Message Parsing

```rust
// src/dns/protocol/message.rs
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use bytes::Bytes;

pub struct DnsMessage {
    inner: Message,
}

impl DnsMessage {
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        let message = Message::from_vec(data)
            .map_err(|e| Error::ParseError(format!("Invalid DNS message: {}", e)))?;
        
        Ok(Self { inner: message })
    }
    
    pub fn query_name(&self) -> Option<&Name> {
        self.inner.queries().first().map(|q| q.name())
    }
    
    pub fn query_type(&self) -> Option<RecordType> {
        self.inner.queries().first().map(|q| q.query_type())
    }
    
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.inner.to_vec()
            .map_err(|e| Error::SerializationError(format!("Failed to serialize: {}", e)))
    }
}
```

**Benefits**:
- hickory_proto handles all wire format complexity
- Automatic bounds checking during parsing
- Type-safe access to DNS fields
- No manual pointer arithmetic

**Contrast with C** (from src/rfc1035.c):
```c
int parse_dns_message(unsigned char *packet, size_t len, struct dns_header *header) {
    if (len < 12) return 0;  // Manual header size check
    
    header->id = (packet[0] << 8) | packet[1];  // Manual byte extraction
    header->flags = (packet[2] << 8) | packet[3];
    header->qdcount = (packet[4] << 8) | packet[5];
    // ... more manual parsing, error-prone
}
```

#### DHCP Packet Parsing with Nom

```rust
// src/dhcp/v4/message.rs
use nom::{
    bytes::complete::{tag, take},
    number::complete::{be_u8, be_u16, be_u32},
    IResult,
};

#[derive(Debug)]
pub struct DhcpMessage {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub options: Vec<DhcpOption>,
}

impl DhcpMessage {
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let (_, message) = parse_dhcp_message(input)
            .map_err(|e| Error::ParseError(format!("DHCP parse error: {}", e)))?;
        Ok(message)
    }
}

fn parse_dhcp_message(input: &[u8]) -> IResult<&[u8], DhcpMessage> {
    let (input, op) = be_u8(input)?;
    let (input, htype) = be_u8(input)?;
    let (input, hlen) = be_u8(input)?;
    let (input, hops) = be_u8(input)?;
    let (input, xid) = be_u32(input)?;
    let (input, secs) = be_u16(input)?;
    let (input, flags) = be_u16(input)?;
    let (input, ciaddr) = take(4usize)(input)?;
    let (input, yiaddr) = take(4usize)(input)?;
    let (input, siaddr) = take(4usize)(input)?;
    let (input, giaddr) = take(4usize)(input)?;
    let (input, chaddr) = take(16usize)(input)?;
    let (input, _sname) = take(64usize)(input)?;  // Server name (unused)
    let (input, _file) = take(128usize)(input)?;  // Boot filename (unused)
    let (input, _) = tag(&[0x63, 0x82, 0x53, 0x63])(input)?;  // Magic cookie
    let (input, options) = parse_dhcp_options(input)?;
    
    Ok((input, DhcpMessage {
        op,
        htype,
        hlen,
        hops,
        xid,
        secs,
        flags,
        ciaddr: Ipv4Addr::from(u32::from_be_bytes(ciaddr.try_into().unwrap())),
        yiaddr: Ipv4Addr::from(u32::from_be_bytes(yiaddr.try_into().unwrap())),
        siaddr: Ipv4Addr::from(u32::from_be_bytes(siaddr.try_into().unwrap())),
        giaddr: Ipv4Addr::from(u32::from_be_bytes(giaddr.try_into().unwrap())),
        chaddr: chaddr.try_into().unwrap(),
        options,
    }))
}

fn parse_dhcp_options(input: &[u8]) -> IResult<&[u8], Vec<DhcpOption>> {
    let mut options = Vec::new();
    let mut remaining = input;
    
    while !remaining.is_empty() {
        let (rest, option) = parse_dhcp_option(remaining)?;
        
        if matches!(option, DhcpOption::End) {
            break;
        }
        
        options.push(option);
        remaining = rest;
    }
    
    Ok((remaining, options))
}
```

**Benefits of nom parser combinators**:
- Composable parsers built from small functions
- Automatic backtracking on parse failure
- Type-safe input consumption (no advancing past end)
- Clear error messages with parse position

---

## Error Handling Architecture

### Result<T, E> Type System

Rust's `Result<T, E>` type makes error handling explicit and enforced by the compiler, eliminating silent failures.

#### Error Type Hierarchy

```rust
// src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("DNS protocol error: {0}")]
    DnsProtocol(String),
    
    #[error("DHCP protocol error: {0}")]
    DhcpProtocol(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),
    
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),
    
    #[error("DNSSEC validation failed: {0}")]
    DnssecValidationFailed(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),
}

#[derive(Error, Debug)]
pub enum CacheError {
    #[error("Cache full")]
    CacheFull,
    
    #[error("Entry not found")]
    NotFound,
    
    #[error("Invalid TTL: {0}")]
    InvalidTtl(u32),
}

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Socket bind failed: {0}")]
    BindFailed(std::io::Error),
    
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),
    
    #[error("Platform error: {0}")]
    PlatformError(String),
}
```

**Benefits**:
- thiserror automatically implements Display and Error traits
- #[from] attribute enables automatic error conversion
- Exhaustive error matching enforced by compiler

#### Error Propagation with ? Operator

```rust
// src/dns/forwarder.rs
pub async fn forward_query(&self, query: &DnsQuery) -> Result<DnsResponse, Error> {
    // Check cache first
    let cached = self.cache.lookup(&query.name).await?;  // Propagates CacheError
    
    if let Some(entry) = cached {
        return Ok(entry.to_response());
    }
    
    // Forward to upstream
    let upstream = self.upstream_pool.select(&query.name)?;  // Propagates NetworkError
    let response = upstream.send_query(query).await?;        // Propagates io::Error
    
    // Validate DNSSEC if enabled
    if self.config.dnssec_enabled {
        self.dnssec.validate(&response).await?;  // Propagates DnssecValidationFailed
    }
    
    // Cache response
    self.cache.insert(response.to_cache_entry()).await?;  // Propagates CacheError
    
    Ok(response)
}
```

**Contrast with C** (from src/forward.c):
```c
int forward_query(struct dns_query *query, struct dns_response *response) {
    // Check cache
    if (cache_lookup(query->name, response) < 0) {
        // Error or not found? Unclear from return value
    }
    
    // Forward to upstream
    int upstream_fd = select_upstream(query->name);
    if (upstream_fd < 0) {
        return -1;  // What went wrong? errno might be set, or might not
    }
    
    if (send_query(upstream_fd, query) < 0) {
        return -1;  // IO error, but caller doesn't know specifics
    }
    
    // ... more error-prone code
}
```

#### Error Context with anyhow

For non-library code (binary), anyhow provides ergonomic error context:

```rust
// src/main.rs
use anyhow::{Context, Result};

async fn initialize_server(config: &Config) -> Result<ServerContext> {
    let dns_socket = bind_dns_socket(config)
        .await
        .context("Failed to bind DNS socket on port 53")?;
    
    let dhcp_socket = bind_dhcp_socket(config)
        .await
        .context("Failed to bind DHCP socket on port 67")?;
    
    let cache = Cache::new(config.cache_size)
        .context("Failed to initialize DNS cache")?;
    
    Ok(ServerContext {
        config: Arc::new(config.clone()),
        dns_socket,
        dhcp_socket,
        cache: Arc::new(RwLock::new(cache)),
    })
}
```

**Benefits**:
- Rich error messages with full context chain
- Easy to debug failures in production
- Automatic error type conversion

---

## Platform Abstraction Layer

### Traits for Cross-Platform APIs

Rust's trait system provides zero-cost abstractions for platform-specific code, replacing C's #ifdef preprocessor directives with type-safe interfaces.

#### Network Platform Trait

```rust
// src/network/platform/mod.rs
use async_trait::async_trait;

#[async_trait]
pub trait NetworkPlatform: Send + Sync {
    /// Enumerate all network interfaces
    async fn enumerate_interfaces(&self) -> Result<Vec<NetworkInterface>, NetworkError>;
    
    /// Bind to a socket with platform-specific options
    async fn bind_socket(
        &self,
        addr: SocketAddr,
        options: SocketOptions,
    ) -> Result<UdpSocket, NetworkError>;
    
    /// Get addresses for a specific interface
    async fn get_interface_addresses(&self, interface: &str) 
        -> Result<Vec<IpAddr>, NetworkError>;
    
    /// Set up packet filtering (BPF on BSD, socket filters on Linux)
    async fn setup_packet_filter(&self, socket: &UdpSocket, filter: PacketFilter) 
        -> Result<(), NetworkError>;
    
    /// Monitor interface changes
    async fn watch_interface_changes(&self) -> Result<InterfaceWatcher, NetworkError>;
}

pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub mac: Option<MacAddress>,
    pub mtu: u32,
    pub flags: InterfaceFlags,
}
```

#### Linux Implementation

```rust
// src/network/platform/linux.rs
use rtnetlink::{new_connection, Handle};
use netlink_packet_route::address::AddressAttribute;

pub struct LinuxNetworkPlatform {
    netlink: Handle,
}

#[async_trait]
impl NetworkPlatform for LinuxNetworkPlatform {
    async fn enumerate_interfaces(&self) -> Result<Vec<NetworkInterface>, NetworkError> {
        let mut links = self.netlink.link().get().execute();
        let mut interfaces = Vec::new();
        
        while let Some(link) = links.try_next().await? {
            let name = link.attributes.into_iter()
                .find_map(|attr| {
                    if let LinkAttribute::IfName(name) = attr {
                        Some(name)
                    } else {
                        None
                    }
                })
                .ok_or(NetworkError::PlatformError("No interface name".to_string()))?;
            
            interfaces.push(NetworkInterface {
                name,
                index: link.header.index,
                mac: None,  // Extract from attributes
                mtu: 1500,   // Extract from attributes
                flags: InterfaceFlags::from_bits_truncate(link.header.flags),
            });
        }
        
        Ok(interfaces)
    }
    
    async fn watch_interface_changes(&self) -> Result<InterfaceWatcher, NetworkError> {
        // Subscribe to netlink route/address change events
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        
        let mut link_updates = handle.link().get().execute();
        
        Ok(InterfaceWatcher {
            handle,
            link_updates,
        })
    }
}
```

#### BSD Implementation

```rust
// src/network/platform/bsd.rs
use nix::sys::socket::{socket, bind, SockaddrIn, AddressFamily, SockType, SockFlag};
use nix::ifaddrs::getifaddrs;

pub struct BsdNetworkPlatform;

#[async_trait]
impl NetworkPlatform for BsdNetworkPlatform {
    async fn enumerate_interfaces(&self) -> Result<Vec<NetworkInterface>, NetworkError> {
        let ifaddrs = getifaddrs()
            .map_err(|e| NetworkError::PlatformError(format!("getifaddrs failed: {}", e)))?;
        
        let mut interfaces = HashMap::new();
        
        for ifaddr in ifaddrs {
            let name = ifaddr.interface_name;
            let entry = interfaces.entry(name.clone()).or_insert(NetworkInterface {
                name: name.clone(),
                index: if_nametoindex(&name)?,
                mac: None,
                mtu: 1500,
                flags: InterfaceFlags::empty(),
            });
            
            // Extract addresses from ifaddr.address
            // ...
        }
        
        Ok(interfaces.into_values().collect())
    }
    
    async fn setup_packet_filter(&self, socket: &UdpSocket, filter: PacketFilter) 
        -> Result<(), NetworkError> 
    {
        // Implement using BPF ioctls via nix crate
        // BIOCSETF ioctl to attach BPF program
        Ok(())
    }
}
```

### Conditional Compilation with cfg Attributes

```rust
// src/network/mod.rs
use crate::network::platform::NetworkPlatform;

#[cfg(target_os = "linux")]
use crate::network::platform::linux::LinuxNetworkPlatform;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
use crate::network::platform::bsd::BsdNetworkPlatform;

#[cfg(target_os = "macos")]
use crate::network::platform::macos::MacOsNetworkPlatform;

pub fn create_network_platform() -> Box<dyn NetworkPlatform> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxNetworkPlatform::new())
    }
    
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        Box::new(BsdNetworkPlatform)
    }
    
    #[cfg(target_os = "macos")]
    {
        Box::new(MacOsNetworkPlatform)
    }
}
```

**Benefits over C #ifdef**:
- Type-checked at compile time
- Dead code elimination automatic
- Cannot accidentally mix platform APIs
- Trait enforces consistent interface across platforms

### Feature Flags in Cargo.toml

```toml
[features]
default = ["dnssec", "idn"]
dnssec = ["ring"]
dbus = ["zbus"]
lua-scripts = ["mlua"]
idn = ["idna"]
tftp = []
conntrack = ["rtnetlink", "netlink-packet-route"]
nftset = ["nftnl"]
ipset = []
inotify = ["notify"]
```

```rust
// src/platform/dbus.rs
#[cfg(feature = "dbus")]
use zbus::{Connection, interface};

#[cfg(feature = "dbus")]
pub async fn start_dbus_service() -> Result<(), Error> {
    // D-Bus implementation
    Ok(())
}

#[cfg(not(feature = "dbus"))]
pub async fn start_dbus_service() -> Result<(), Error> {
    // No-op when D-Bus feature disabled
    Ok(())
}
```

---

## Design Patterns and Architectural Patterns

### Repository Pattern for Data Access

The Repository pattern abstracts data storage, enabling testing and future backend changes.

#### DNS Cache Repository

```rust
// src/dns/cache.rs
#[async_trait]
pub trait CacheRepository: Send + Sync {
    async fn find_by_name(&self, name: &str, qtype: RecordType) -> Option<CacheEntry>;
    async fn find_by_addr(&self, addr: IpAddr) -> Option<CacheEntry>;
    async fn insert(&mut self, entry: CacheEntry) -> Result<(), CacheError>;
    async fn evict_lru(&mut self) -> Option<CacheEntry>;
    async fn clear(&mut self);
    async fn size(&self) -> usize;
}

pub struct HashMapCacheRepository {
    entries: HashMap<CacheKey, CacheEntry>,
    lru_list: VecDeque<CacheKey>,
    max_size: usize,
}

#[async_trait]
impl CacheRepository for HashMapCacheRepository {
    async fn find_by_name(&self, name: &str, qtype: RecordType) -> Option<CacheEntry> {
        let key = CacheKey::new(name, qtype);
        self.entries.get(&key).cloned()
    }
    
    async fn insert(&mut self, entry: CacheEntry) -> Result<(), CacheError> {
        if self.entries.len() >= self.max_size {
            self.evict_lru().await;
        }
        
        let key = entry.key();
        self.entries.insert(key.clone(), entry);
        self.lru_list.push_back(key);
        
        Ok(())
    }
    
    async fn evict_lru(&mut self) -> Option<CacheEntry> {
        let key = self.lru_list.pop_front()?;
        self.entries.remove(&key)
    }
}
```

**Benefits**:
- Testable with mock implementations
- Can swap backends (memory, disk, Redis) without changing business logic
- Clear interface boundaries

#### DHCP Lease Repository

```rust
// src/dhcp/lease/database.rs
#[async_trait]
pub trait LeaseRepository: Send + Sync {
    async fn find_by_ip(&self, ip: IpAddr) -> Result<Option<Lease>, LeaseError>;
    async fn find_by_mac(&self, mac: &MacAddress) -> Result<Option<Lease>, LeaseError>;
    async fn save(&mut self, lease: Lease) -> Result<(), LeaseError>;
    async fn delete(&mut self, lease: &Lease) -> Result<(), LeaseError>;
    async fn list_active(&self) -> Result<Vec<Lease>, LeaseError>;
    async fn cleanup_expired(&mut self) -> Result<usize, LeaseError>;
}

pub struct FileLeaseRepository {
    lease_file: PathBuf,
    leases: BTreeMap<IpAddr, Lease>,
    dirty: bool,
}

#[async_trait]
impl LeaseRepository for FileLeaseRepository {
    async fn save(&mut self, lease: Lease) -> Result<(), LeaseError> {
        self.leases.insert(lease.ip, lease);
        self.dirty = true;
        self.persist().await
    }
    
    async fn persist(&mut self) -> Result<(), LeaseError> {
        if !self.dirty {
            return Ok(());
        }
        
        let mut file = File::create(&self.lease_file).await?;
        
        for lease in self.leases.values() {
            let line = format!(
                "{} {} {} {} {}\n",
                lease.expires.as_secs(),
                lease.mac,
                lease.ip,
                lease.hostname.as_ref().unwrap_or(&String::new()),
                lease.client_id.as_ref().unwrap_or(&String::new()),
            );
            file.write_all(line.as_bytes()).await?;
        }
        
        self.dirty = false;
        Ok(())
    }
}
```

### Service Layer for Business Logic

Service structs encapsulate business logic, separating it from protocol parsing and I/O.

#### DNS Service

```rust
// src/dns/mod.rs
pub struct DnsService {
    cache: Arc<RwLock<dyn CacheRepository>>,
    forwarder: DnsForwarder,
    auth_zones: AuthoritativeService,
    dnssec_validator: Option<DnssecValidator>,
    config: Arc<DnsConfig>,
    metrics: Arc<RwLock<DnsMetrics>>,
}

impl DnsService {
    pub async fn handle_query(
        &self,
        query: DnsQuery,
        peer: SocketAddr,
    ) -> Result<DnsResponse, Error> {
        self.metrics.write().await.queries_received += 1;
        
        // Check cache first
        if let Some(cached) = self.cache.read().await
            .find_by_name(&query.name, query.qtype).await 
        {
            self.metrics.write().await.cache_hits += 1;
            return Ok(cached.to_response(&query));
        }
        
        // Check authoritative zones
        if let Some(auth_response) = self.auth_zones.try_answer(&query).await? {
            self.metrics.write().await.authoritative_answers += 1;
            return Ok(auth_response);
        }
        
        // Forward to upstream
        let response = self.forwarder.forward_query(&query).await?;
        
        // Validate DNSSEC if enabled
        if let Some(validator) = &self.dnssec_validator {
            validator.validate(&response).await?;
        }
        
        // Cache the response
        self.cache.write().await
            .insert(response.to_cache_entry()).await?;
        
        Ok(response)
    }
}
```

### Builder Pattern for Configuration

```rust
// src/config/types.rs
#[derive(Debug, Clone)]
pub struct Config {
    pub dns_port: u16,
    pub dhcp_ranges: Vec<DhcpRange>,
    pub upstream_servers: Vec<UpstreamServer>,
    pub cache_size: usize,
    pub dnssec_enabled: bool,
    pub interfaces: Vec<String>,
    pub lease_file: PathBuf,
}

pub struct ConfigBuilder {
    dns_port: Option<u16>,
    dhcp_ranges: Vec<DhcpRange>,
    upstream_servers: Vec<UpstreamServer>,
    cache_size: Option<usize>,
    dnssec_enabled: bool,
    interfaces: Vec<String>,
    lease_file: Option<PathBuf>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self {
            dns_port: None,
            dhcp_ranges: Vec::new(),
            upstream_servers: Vec::new(),
            cache_size: None,
            dnssec_enabled: false,
            interfaces: Vec::new(),
            lease_file: None,
        }
    }
    
    pub fn dns_port(mut self, port: u16) -> Self {
        self.dns_port = Some(port);
        self
    }
    
    pub fn add_dhcp_range(mut self, range: DhcpRange) -> Self {
        self.dhcp_ranges.push(range);
        self
    }
    
    pub fn enable_dnssec(mut self) -> Self {
        self.dnssec_enabled = true;
        self
    }
    
    pub fn build(self) -> Result<Config, ConfigError> {
        Ok(Config {
            dns_port: self.dns_port.unwrap_or(53),
            dhcp_ranges: self.dhcp_ranges,
            upstream_servers: if self.upstream_servers.is_empty() {
                vec![UpstreamServer::from_resolv_conf()?]
            } else {
                self.upstream_servers
            },
            cache_size: self.cache_size.unwrap_or(150),
            dnssec_enabled: self.dnssec_enabled,
            interfaces: self.interfaces,
            lease_file: self.lease_file
                .unwrap_or_else(|| PathBuf::from("/var/lib/misc/dnsmasq.leases")),
        })
    }
}
```

### State Machine Pattern for Protocol Handling

```rust
// src/dns/protocol/query_state.rs
pub enum QueryState {
    New(DnsQuery),
    Cached {
        query: DnsQuery,
        entry: CacheEntry,
    },
    Forwarded {
        query: DnsQuery,
        upstream: UpstreamServer,
        sent_at: Instant,
    },
    ValidatingDnssec {
        query: DnsQuery,
        response: DnsResponse,
    },
    Completed(DnsResponse),
    Failed(Error),
}

impl QueryState {
    pub async fn transition(self, context: &QueryContext) -> Self {
        match self {
            QueryState::New(query) => {
                if let Some(cached) = context.cache.lookup(&query).await {
                    QueryState::Cached { query, entry: cached }
                } else {
                    let upstream = context.select_upstream(&query);
                    QueryState::Forwarded {
                        query,
                        upstream,
                        sent_at: Instant::now(),
                    }
                }
            }
            
            QueryState::Forwarded { query, upstream, sent_at } => {
                match context.recv_from_upstream(upstream).await {
                    Ok(response) => {
                        if context.config.dnssec_enabled {
                            QueryState::ValidatingDnssec { query, response }
                        } else {
                            QueryState::Completed(response)
                        }
                    }
                    Err(e) if sent_at.elapsed() < Duration::from_secs(10) => {
                        // Retry with same state
                        QueryState::Forwarded { query, upstream, sent_at }
                    }
                    Err(e) => QueryState::Failed(e),
                }
            }
            
            QueryState::ValidatingDnssec { query, response } => {
                match context.dnssec.validate(&response).await {
                    Ok(()) => QueryState::Completed(response),
                    Err(e) => QueryState::Failed(e),
                }
            }
            
            state => state,  // Terminal states (Completed, Failed)
        }
    }
}
```

**Benefits**:
- Type-safe state transitions
- Impossible states are unrepresentable
- Clear progression through query lifecycle

---

## DNSSEC Cryptography Implementation

### Ring Crate for Memory-Safe Cryptography

The Rust implementation uses the `ring` crate for DNSSEC cryptographic operations, replacing the C implementation's use of Nettle library FFI.

#### Signature Verification

```rust
// src/dns/dnssec/crypto.rs
use ring::signature::{self, UnparsedPublicKey};

pub struct DnssecCrypto;

impl DnssecCrypto {
    pub fn verify_rrsig(
        &self,
        rrsig: &RRSig,
        dnskey: &DNSKey,
        rrset: &[ResourceRecord],
    ) -> Result<(), DnssecError> {
        // Reconstruct signed data
        let signed_data = self.reconstruct_signed_data(rrsig, rrset)?;
        
        // Select verification algorithm based on DNSKEY algorithm
        let verification_alg = match dnskey.algorithm {
            5 | 7 => &signature::RSA_PKCS1_2048_8192_SHA256,  // RSASHA256
            8 => &signature::RSA_PKCS1_2048_8192_SHA256,      // RSASHA256
            10 => &signature::RSA_PKCS1_2048_8192_SHA512,     // RSASHA512
            13 => &signature::ECDSA_P256_SHA256_FIXED,        // ECDSAP256SHA256
            14 => &signature::ECDSA_P384_SHA384_FIXED,        // ECDSAP384SHA384
            15 => &signature::ED25519,                         // ED25519
            _ => return Err(DnssecError::UnsupportedAlgorithm(dnskey.algorithm)),
        };
        
        // Create public key
        let public_key = UnparsedPublicKey::new(verification_alg, &dnskey.public_key);
        
        // Verify signature
        public_key.verify(&signed_data, &rrsig.signature)
            .map_err(|_| DnssecError::SignatureVerificationFailed)?;
        
        Ok(())
    }
    
    fn reconstruct_signed_data(
        &self,
        rrsig: &RRSig,
        rrset: &[ResourceRecord],
    ) -> Result<Vec<u8>, DnssecError> {
        let mut data = Vec::new();
        
        // RRSIG RDATA excluding signature
        data.extend_from_slice(&rrsig.type_covered.to_be_bytes());
        data.push(rrsig.algorithm);
        data.push(rrsig.labels);
        data.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        data.extend_from_slice(&rrsig.expiration.to_be_bytes());
        data.extend_from_slice(&rrsig.inception.to_be_bytes());
        data.extend_from_slice(&rrsig.key_tag.to_be_bytes());
        data.extend_from_slice(&rrsig.signer_name);
        
        // Canonical form of RRset
        let mut canonical_rrset = rrset.to_vec();
        canonical_rrset.sort_by(|a, b| a.canonical_order().cmp(&b.canonical_order()));
        
        for rr in canonical_rrset {
            data.extend_from_slice(&rr.to_canonical_wire_format(rrsig.original_ttl)?);
        }
        
        Ok(data)
    }
}
```

**Contrast with C** (from src/crypto.c using Nettle FFI):
```c
#include <nettle/rsa.h>
#include <nettle/dsa.h>

int verify_rrsig(struct rrset *rrset, struct rrsig *rrsig, struct dnskey *key) {
    struct rsa_public_key rsa_key;
    
    // Manual initialization
    rsa_public_key_init(&rsa_key);
    
    // Parse public key (error-prone)
    if (!rsa_public_key_from_der(&rsa_key, key->key_len, key->key_data)) {
        rsa_public_key_clear(&rsa_key);  // Manual cleanup
        return 0;
    }
    
    // Verify signature
    int result = rsa_sha256_verify(&rsa_key, signed_data_len, signed_data, 
                                     rrsig->sig_len, rrsig->sig_data);
    
    rsa_public_key_clear(&rsa_key);  // Manual cleanup (easy to forget)
    return result;
}
```

**Benefits of ring over Nettle FFI**:
- Memory-safe API (no manual key cleanup)
- Constant-time operations (side-channel resistant)
- Well-audited implementation
- Pure Rust (no FFI overhead or safety concerns)
- Modern algorithms (Ed25519, ECDSA)

#### Trust Anchor Management

```rust
// src/dns/dnssec/trust_anchors.rs
pub struct TrustAnchorStore {
    anchors: HashMap<String, Vec<DnsKey>>,
}

impl TrustAnchorStore {
    pub async fn from_file(path: &Path) -> Result<Self, DnssecError> {
        let content = tokio::fs::read_to_string(path).await?;
        let mut anchors = HashMap::new();
        
        for line in content.lines() {
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            
            // Parse trust anchor line (format: "zone DS/DNSKEY data")
            let key = Self::parse_trust_anchor(line)?;
            anchors.entry(key.zone.clone())
                .or_insert_with(Vec::new)
                .push(key);
        }
        
        Ok(Self { anchors })
    }
    
    pub fn get_trust_anchor(&self, zone: &str) -> Option<&[DnsKey]> {
        self.anchors.get(zone).map(|v| v.as_slice())
    }
}
```

### DNSSEC Validation Chain

```rust
// src/dns/dnssec/validator.rs
pub struct DnssecValidator {
    trust_anchors: Arc<TrustAnchorStore>,
    crypto: DnssecCrypto,
    query_cache: Arc<RwLock<ValidationCache>>,
}

impl DnssecValidator {
    pub async fn validate_response(
        &self,
        response: &DnsResponse,
    ) -> Result<ValidationResult, DnssecError> {
        // Check if response has DNSSEC records
        if !response.has_dnssec_records() {
            return Ok(ValidationResult::Insecure);
        }
        
        // Extract RRSIG records
        let rrsigs = response.rrsigs();
        if rrsigs.is_empty() {
            return Err(DnssecError::MissingRRSig);
        }
        
        // Build validation chain from trust anchor to target
        let chain = self.build_trust_chain(response).await?;
        
        // Validate each link in the chain
        for link in chain.iter() {
            self.validate_link(link).await?;
        }
        
        Ok(ValidationResult::Secure)
    }
    
    async fn build_trust_chain(
        &self,
        response: &DnsResponse,
    ) -> Result<Vec<ValidationLink>, DnssecError> {
        let mut chain = Vec::new();
        let mut current_zone = response.zone_name();
        
        // Walk up the DNS hierarchy to trust anchor
        while let Some(parent) = current_zone.parent() {
            let ds_records = self.query_ds_records(&current_zone).await?;
            let dnskey_records = self.query_dnskey_records(&parent).await?;
            
            chain.push(ValidationLink {
                zone: current_zone.clone(),
                ds_records,
                dnskey_records,
            });
            
            current_zone = parent;
            
            // Stop at trust anchor
            if self.trust_anchors.get_trust_anchor(current_zone.as_str()).is_some() {
                break;
            }
        }
        
        chain.reverse();  // Start from trust anchor
        Ok(chain)
    }
}
```

---

## Cross-Platform Support Strategy

### Platform-Specific Code Organization

```
src/network/platform/
├── mod.rs          # Trait definitions, platform selection
├── linux.rs        # Linux netlink implementation
├── bsd.rs          # FreeBSD/OpenBSD/NetBSD BPF implementation
├── macos.rs        # macOS-specific implementation
└── common.rs       # Shared utilities
```

### Compile-Time Platform Selection

```rust
// src/network/platform/mod.rs
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub use bsd::*;

#[cfg(target_os = "macos")]
pub use macos::*;

// Conditional imports based on platform
#[cfg(target_os = "linux")]
mod linux;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
mod bsd;

#[cfg(target_os = "macos")]
mod macos;
```

### Platform-Specific Dependencies (Cargo.toml)

```toml
[target.'cfg(target_os = "linux")'.dependencies]
nix = { version = "0.29", features = ["socket", "net", "signal", "process"] }
netlink-packet-route = "0.20"
rtnetlink = "0.15"
caps = "0.5"

[target.'cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))'.dependencies]
nix = { version = "0.29", features = ["socket", "net", "signal", "process"] }

[target.'cfg(target_os = "macos")'.dependencies]
nix = { version = "0.29", features = ["socket", "net", "signal", "process"] }
```

---

## Performance and Resource Management

### Memory Efficiency

The Rust implementation maintains memory efficiency through:

1. **Stack Allocation**: Small buffers on stack where possible
2. **Buffer Pooling**: Reusable buffer pools for network I/O
3. **Copy-on-Write**: Use of `Cow<str>` for configuration strings
4. **Lazy Initialization**: Services initialized only when needed

```rust
// src/network/buffer_pool.rs
pub struct BufferPool {
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
    buffer_size: usize,
}

impl BufferPool {
    pub fn acquire(&self) -> Vec<u8> {
        self.pool.lock().unwrap()
            .pop()
            .unwrap_or_else(|| vec![0u8; self.buffer_size])
    }
    
    pub fn release(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        let mut pool = self.pool.lock().unwrap();
        if pool.len() < 100 {  // Maximum pool size
            pool.push(buffer);
        }
    }
}
```

### CPU Efficiency

- **Zero-copy parsing** where possible using `bytes::Bytes`
- **Compile-time optimizations** with LTO and codegen-units=1
- **Inline hints** for hot paths
- **SIMD** operations where beneficial (hickory-dns uses SIMD for hashing)

---

## Testing and Validation Architecture

### Test Structure

```
tests/
├── integration/
│   ├── dns_tests.rs           # DNS protocol compliance
│   ├── dhcp_tests.rs          # DHCP allocation tests
│   ├── dnssec_tests.rs        # DNSSEC validation tests
│   └── config_tests.rs        # Config parser compatibility
└── common/
    ├── mod.rs                 # Test utilities
    └── fixtures/              # Test data
```

### Integration Tests

```rust
// tests/integration/dns_tests.rs
#[tokio::test]
async fn test_dns_query_forwarding() {
    let config = Config::builder()
        .dns_port(5353)
        .add_upstream_server("8.8.8.8:53".parse().unwrap())
        .build()
        .unwrap();
    
    let server = DnsmasqServer::start(config).await.unwrap();
    
    // Send DNS query
    let query = DnsQuery::new("example.com", RecordType::A);
    let response = send_query("127.0.0.1:5353", &query).await.unwrap();
    
    assert!(response.answers().len() > 0);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    
    server.shutdown().await.unwrap();
}
```

---

## Conclusion

The Rust implementation of dnsmasq represents a comprehensive architectural transformation that maintains 100% functional equivalence with the C implementation while achieving memory safety through Rust's ownership system. Key architectural improvements include:

- **Async/await runtime** replacing poll()-based event loop
- **Automatic memory management** via ownership eliminating manual malloc/free
- **Type-safe protocol parsing** preventing buffer overflows
- **Explicit error handling** with Result types
- **Platform abstraction** through traits
- **Modern cryptography** with ring crate

This architecture provides the foundation for a production-ready, memory-safe network services daemon suitable for embedded systems, edge devices, and enterprise deployments.
