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

//! Global constants module for dnsmasq Rust implementation.
//!
//! This module defines all compile-time configuration values, operational parameters,
//! and resource limits for the dnsmasq DNS forwarder and DHCP server. These constants
//! replace C preprocessor #define directives from config.h with type-safe Rust const
//! declarations, maintaining identical values for behavioral compatibility with the
//! C implementation.
//!
//! # Organization
//!
//! Constants are organized into logical groups:
//! - **Version**: Application version information
//! - **DNS Protocol**: RFC-compliant protocol limits and operational parameters
//! - **TCP/Network**: Connection limits and timeouts
//! - **EDNS0**: Extended DNS parameters
//! - **DNSSEC**: Security validation limits to prevent DoS attacks
//! - **DHCP**: Lease management and conflict detection parameters
//! - **TFTP**: Network boot server configuration
//! - **Authoritative DNS**: Zone configuration defaults
//! - **File Paths**: Platform-specific default file locations
//! - **Security**: Privilege separation and service naming
//! - **Operational Limits**: Resource management and caching behavior
//!
//! # Platform-Specific Configuration
//!
//! Some constants have platform-specific values determined at compile time using
//! `#[cfg(target_os)]` attributes. These maintain compatibility with existing
//! deployments across Linux, BSD, macOS, Solaris, and Android platforms.
//!
//! # Feature Flags
//!
//! Compile-time feature flags from the C implementation (HAVE_DHCP, HAVE_DNSSEC, etc.)
//! are handled through Cargo.toml feature declarations and conditional compilation
//! attributes rather than being defined as constants.
//!
//! # Rationale for Values
//!
//! Each constant includes documentation explaining:
//! - Purpose and usage within dnsmasq
//! - RFC compliance or security rationale
//! - Performance tuning considerations
//! - DoS prevention mechanisms
//! - Platform compatibility requirements

// ============================================================================
// VERSION INFORMATION
// ============================================================================

/// Dnsmasq version string.
///
/// This version identifies the Rust implementation and maintains compatibility
/// with the C version's configuration and behavior. Version format follows
/// semantic versioning: MAJOR.MINOR for the C compatibility baseline.
pub const VERSION: &str = "2.92";

// ============================================================================
// DNS PROTOCOL CONSTANTS
// ============================================================================

/// Maximum DNS domain name length in bytes (RFC 1035).
///
/// DNS names can be up to 255 octets including length bytes. This is the
/// maximum wire format representation of a fully-qualified domain name.
///
/// **RFC Compliance**: RFC 1035 Section 2.3.4  
/// **Usage**: Buffer allocation for DNS name parsing and validation  
/// **Security**: Prevents buffer overflows from oversized name claims
pub const MAXDNAME: usize = 255;

/// Typical maximum length for common domain names.
///
/// Most domain names fit within 50 bytes. Used as optimization hint for
/// buffer sizing and quick-path allocation strategies.
///
/// **Purpose**: Performance optimization for common case  
/// **Full limit**: MAXDNAME (255) applies for all names  
/// **Usage**: Fast path allocation before falling back to heap
pub const SMALLDNAME: usize = 50;

/// Maximum DNS label length in bytes (RFC 1035).
///
/// Individual labels (segments between dots) can be up to 63 octets.
/// Example: in "www.example.com", each of "www", "example", "com" ≤ 63 bytes.
///
/// **RFC Compliance**: RFC 1035 Section 2.3.4  
/// **Validation**: Label length checks during name parsing  
/// **Security**: Detects malformed DNS packets
pub const MAXLABEL: usize = 63;

/// Maximum number of concurrent outstanding DNS queries (forward table size).
///
/// Controls the size of the forward record table tracking active DNS queries from
/// clients to upstream servers. Each outstanding query consumes one forward record.
/// When limit reached, new queries are dropped until slots free.
///
/// **Default**: 150 concurrent queries  
/// **Tunable via**: --dns-forward-max command-line option  
/// **Memory impact**: ~200 bytes per forward record = ~30KB for default 150  
/// **Typical usage**: 150 sufficient for 100-250 clients in small network  
/// **Performance**: Increase for high-query-rate environments (>1000 qps)
pub const FTABSIZ: usize = 150;

/// Maximum CNAME chain length before loop detection triggers.
///
/// Prevents infinite loops from circular CNAME records. Chains longer than
/// this are truncated and flagged as potential loops.
///
/// **Default**: 10 CNAME redirections maximum  
/// **RFC Guidance**: RFC 1034 recommends limiting CNAME chains  
/// **Security**: Loop detection and DoS prevention  
/// **Typical**: Legitimate chains rarely exceed 3-4 CNAMEs
pub const CNAME_CHAIN: usize = 10;

/// Default DNS cache size (number of entries).
///
/// Number of DNS resource records cached in memory. Cache uses LRU eviction
/// when full. Entries consume ~100-200 bytes each depending on record type.
///
/// **Default**: 150 entries  
/// **Tunable via**: --cache-size command-line option  
/// **Memory impact**: ~20-30KB for 150 entries  
/// **Performance**: Larger cache improves hit rate, reduces upstream queries  
/// **Recommendation**: 1000+ for busy networks, 10000+ for ISP/enterprise
pub const CACHESIZ: usize = 150;

/// DNS query timeout in seconds.
///
/// Maximum time to wait for upstream DNS server response before retrying
/// or failing the query. Applies to each upstream query attempt.
///
/// **Default**: 10 seconds  
/// **RFC Guidance**: RFC 1035 suggests timeout, no specific value mandated  
/// **Rationale**: Balance between patience and responsiveness  
/// **Network**: 10s accommodates slow/congested networks without excessive delay
pub const TIMEOUT: usize = 10;

/// Server health check interval in queries.
///
/// After forwarding this many queries to an upstream server, send a test
/// query to verify the server is still responding. Detects dead servers
/// and triggers fallback to alternatives.
///
/// **Default**: Every 50 queries  
/// **Purpose**: Upstream server liveness detection  
/// **Behavior**: Failed test marks server temporarily unavailable  
/// **Recovery**: Periodic retries re-enable failed servers
pub const FORWARD_TEST: usize = 50;

/// Server health check timeout in seconds.
///
/// Maximum time to wait for server health check response before marking
/// server as failed and switching to alternative upstream servers.
///
/// **Default**: 20 seconds  
/// **Purpose**: Faster than TIMEOUT for responsiveness  
/// **Behavior**: Quicker failover for better user experience  
/// **Recovery**: Failed servers periodically retested
pub const FORWARD_TIME: usize = 20;

// ============================================================================
// TCP/NETWORK CONSTANTS
// ============================================================================

/// Maximum number of child processes for handling TCP DNS connections.
///
/// Limits concurrent TCP connections to prevent resource exhaustion from TCP
/// connection floods. Each TCP connection forks a child process to handle
/// query processing without blocking the main event loop.
///
/// **Default**: 20 concurrent TCP connections  
/// **Tunable via**: --max-tcp-connections command-line option  
/// **Resource impact**: Each child process ~2-5MB memory  
/// **DoS prevention**: Prevents fork bomb from TCP flood attacks  
/// **Typical usage**: 20 sufficient for normal loads; DNS primarily uses UDP
pub const MAX_PROCS: usize = 20;

/// Maximum DNS queries per single TCP connection.
///
/// Number of consecutive queries allowed on one TCP connection before
/// forcing connection close. Prevents resource hogging from persistent
/// TCP clients.
///
/// **Default**: 100 queries per connection  
/// **Purpose**: Prevent single client monopolizing server resources  
/// **Behavior**: Connection closed after limit, client must reconnect  
/// **Standards**: RFC 7766 recommends persistent TCP for DNS
pub const TCP_MAX_QUERIES: usize = 100;

/// TCP listen queue backlog size.
///
/// Maximum pending TCP connections in kernel queue before connection
/// refused errors. Low value prevents excessive connection storms.
///
/// **Default**: 5 pending connections  
/// **System**: Kernel listen() backlog parameter  
/// **Rationale**: DNS primarily UDP; TCP for large responses only  
/// **DoS mitigation**: Small backlog limits resource commitment
pub const TCP_BACKLOG: usize = 5;

/// TCP child process lifetime in seconds.
///
/// Maximum duration a TCP handler process can exist before forced termination.
/// Prevents hung connections from exhausting process slots.
///
/// **Default**: 150 seconds (2.5 minutes)  
/// **Purpose**: Stuck connection cleanup  
/// **Behavior**: Process killed after timeout regardless of activity  
/// **Typical**: Legitimate queries complete in <1 second
pub const CHILD_LIFETIME: usize = 150;

// ============================================================================
// EDNS0 CONSTANTS
// ============================================================================

/// EDNS0 maximum UDP packet size in bytes.
///
/// Maximum DNS packet size advertised via EDNS0 (Extension Mechanisms for DNS).
/// Allows larger responses without falling back to TCP. Must not exceed path MTU.
///
/// **Default**: 4096 bytes  
/// **RFC Compliance**: RFC 6891 EDNS(0) extensions  
/// **Network**: Safe for Ethernet MTU 1500 with fragmentation  
/// **DNSSEC**: Large RRSIG records benefit from increased size  
/// **Tunable via**: --edns-packet-max command-line option
pub const EDNS_PKTSZ: usize = 4096;

// ============================================================================
// DNSSEC SECURITY LIMITS
// ============================================================================

/// DNSSEC validation maximum work units to prevent DoS.
///
/// Total work units consumed during DNSSEC validation of a single query.
/// Each signature check, key fetch, and chain traversal consumes work units.
/// Exceeded limit terminates validation and returns SERVFAIL.
///
/// **Default**: 100 work units  
/// **Purpose**: Prevent algorithmic complexity DoS attacks  
/// **Attack vector**: Adversary creates deeply nested DNSSEC chains  
/// **Behavior**: Limit exceeded returns SERVFAIL (validation failed)  
/// **Typical**: Legitimate validations consume 5-20 work units
pub const DNSSEC_LIMIT_WORK: usize = 100;

/// DNSSEC maximum cryptographic operations per query.
///
/// Maximum number of signature verifications (RSA, ECDSA, EdDSA) performed
/// during validation of a single query. Exceeding limit terminates validation.
///
/// **Default**: 50 signature verifications  
/// **Purpose**: Prevent CPU exhaustion from crypto operations  
/// **Attack vector**: Many RRSIGs requiring signature checks  
/// **Behavior**: Limit exceeded returns SERVFAIL  
/// **Performance**: Each RSA verification ~1-10ms CPU time
pub const DNSSEC_LIMIT_CRYPTO: usize = 50;

/// DNSSEC maximum NSEC3 hash iterations.
///
/// Maximum iterations parameter in NSEC3 records during authenticated denial
/// of existence validation. High iteration counts cause CPU exhaustion.
///
/// **Default**: 500 iterations maximum  
/// **Purpose**: Prevent CPU DoS from expensive NSEC3 hash computations  
/// **Attack vector**: NSEC3 with iterations=10000+ causes second-scale delays  
/// **RFC Guidance**: RFC 5155 recommends <100 iterations for security  
/// **Behavior**: Records with iterations > limit treated as insecure
pub const DNSSEC_LIMIT_NSEC3_ITERS: usize = 500;

/// Minimum TTL in seconds for cached DNSSEC records (DNSKEY, DS).
///
/// DNSSEC validation records cached at least this long even if authoritative
/// TTL is shorter. Prevents excessive re-validation queries.
///
/// **Default**: 60 seconds minimum  
/// **Purpose**: Performance optimization - validation chain caching  
/// **Behavior**: Cache holds DNSSEC records for at least this duration  
/// **Typical**: DNSKEYs often have TTL 3600s (1 hour) anyway
pub const DNSSEC_MIN_TTL: usize = 60;

// ============================================================================
// DHCP CONSTANTS
// ============================================================================

/// Maximum number of DHCP leases.
///
/// Hard limit on total DHCP lease allocations across all interfaces and
/// address ranges. Prevents memory exhaustion from lease floods.
///
/// **Default**: 1000 leases  
/// **Tunable via**: --dhcp-lease-max command-line option  
/// **Memory impact**: ~100-200 bytes per lease structure  
/// **Typical usage**: 1000 sufficient for small/medium networks  
/// **Enterprise**: Increase to 10000+ for large deployments
pub const MAXLEASES: usize = 1000;

/// ICMP ping wait time in seconds for conflict detection.
///
/// Before allocating DHCP address, send ICMP echo request and wait this
/// duration for response. If reply received, address is in use (conflict).
///
/// **Default**: 3 seconds  
/// **RFC Compliance**: RFC 2131 recommends conflict detection  
/// **Security**: Prevents IP address conflicts  
/// **Performance**: 3s delay on each new lease allocation  
/// **Tunable via**: --dhcp-no-ping disables conflict detection
pub const PING_WAIT: usize = 3;

/// Ping cache duration in seconds.
///
/// After successful ping response (conflict detected), cache the result
/// for this duration to avoid repeated pings to the same address.
///
/// **Default**: 30 seconds  
/// **Purpose**: Performance optimization - reduce ICMP traffic  
/// **Behavior**: Cached conflicts mark address temporarily unavailable  
/// **Typical**: Host remains pingable for at least this long
pub const PING_CACHE_TIME: usize = 30;

/// Backoff time in seconds for DHCPDECLINE-d addresses.
///
/// When client sends DHCPDECLINE (address configuration failed on client),
/// mark address unavailable for this duration before reallocating.
///
/// **Default**: 600 seconds (10 minutes)  
/// **RFC Compliance**: RFC 2131 DHCPDECLINE handling  
/// **Purpose**: Give client time to resolve configuration issue  
/// **Security**: Prevents rapid reallocation of problematic addresses
pub const DECLINE_BACKOFF: usize = 600;

/// Hard maximum size for DHCP packets in bytes.
///
/// Absolute upper limit on DHCP packet buffer allocation. Prevents memory
/// exhaustion from malformed packets claiming huge option lengths.
///
/// **Default**: 16384 bytes (16KB)  
/// **Normal size**: 576 bytes typical, 1500 bytes for jumbo options  
/// **Security**: Buffer overflow prevention  
/// **Standards**: RFC 2131 minimum 576 bytes, no specified maximum
pub const DHCP_PACKET_MAX: usize = 16384;

/// Lease file write retry interval in seconds.
///
/// When lease file write fails (disk full, permissions), retry after this
/// interval. Prevents tight retry loops consuming CPU.
///
/// **Default**: 60 seconds  
/// **Purpose**: Graceful handling of transient disk errors  
/// **Behavior**: Leases held in memory; persistence retried periodically  
/// **Persistence**: Critical for lease survival across daemon restarts
pub const LEASE_RETRY: usize = 60;

/// Default DHCPv4 lease time in seconds.
///
/// Lease duration assigned when client doesn't request specific time and
/// dhcp-range configuration doesn't specify default.
///
/// **Default**: 3600 seconds (1 hour)  
/// **Tunable via**: dhcp-range option third parameter  
/// **Rationale**: 1 hour balances lease churn vs. address pool exhaustion  
/// **RFC Compliance**: RFC 2131 leaves default to administrator
pub const DEFLEASE: usize = 3600;

/// Default DHCPv6 lease time in seconds.
///
/// IPv6 lease duration for non-temporary addresses (IA_NA) when not
/// explicitly configured. Matches DHCPv4 default for consistency.
///
/// **Default**: 3600 seconds (1 hour)  
/// **Tunable via**: dhcp-range option for IPv6  
/// **Standards**: RFC 3315 leaves default to administrator  
/// **Rationale**: Same as DEFLEASE for operational consistency
pub const DEFLEASE6: usize = 3600;

/// Maximum hardware address (MAC) length in DHCP packets.
///
/// DHCP chaddr field maximum size. Standard Ethernet uses 6 bytes, but
/// other link layers may use longer addresses.
///
/// **Default**: 16 bytes  
/// **Standards**: RFC 2131 chaddr field is 16 octets  
/// **Common**: Ethernet MAC is 6 bytes, InfiniBand is 20 bytes (truncated)  
/// **Purpose**: Fixed-size buffer for hardware address storage
pub const DHCP_CHADDR_MAX: usize = 16;

// ============================================================================
// TFTP CONSTANTS
// ============================================================================

/// Maximum simultaneous TFTP connections.
///
/// Hard limit on simultaneous TFTP file transfers. Prevents resource
/// exhaustion from TFTP connection floods during network boot storms.
///
/// **Default**: 50 concurrent transfers  
/// **Typical usage**: 10-20 clients PXE booting simultaneously  
/// **Memory impact**: ~10KB per active transfer  
/// **Tunable via**: --tftp-max command-line option  
/// **Boot storm**: 50 sufficient for classroom/office boot scenarios
pub const TFTP_MAX_CONNECTIONS: usize = 50;

/// Maximum TFTP window size for RFC 7440 windowed transfers.
///
/// Window size for TFTP option negotiation. Larger windows improve throughput
/// for large files by reducing round-trip overhead.
///
/// **Default**: 32 blocks per window  
/// **Standards**: RFC 7440 (TFTP windowsize option)  
/// **Performance**: Significant speedup for large boot images  
/// **Network**: Higher windows require low-loss networks  
/// **Typical**: 8-16 for WAN, 32-64 for LAN
pub const TFTP_MAX_WINDOW: usize = 32;

/// Timeout in seconds for abandoned TFTP transfers.
///
/// Maximum duration for single TFTP transfer. Transfers exceeding this time
/// are terminated to free resources for other clients.
///
/// **Default**: 120 seconds (2 minutes)  
/// **Typical usage**: Boot images transfer in 10-30 seconds  
/// **Purpose**: Prevent hung transfers from exhausting connection slots  
/// **Behavior**: Transfer timeout returns error to client
pub const TFTP_TRANSFER_TIME: usize = 120;

// ============================================================================
// AUTHORITATIVE DNS CONSTANTS
// ============================================================================

/// Default TTL for authoritative zone records in seconds.
///
/// Time-to-live for DNS records served from authoritative zones when
/// not explicitly specified in zone configuration.
///
/// **Default**: 600 seconds (10 minutes)  
/// **Tunable via**: --auth-ttl command-line option  
/// **Rationale**: 10 minutes balances caching benefit vs. change propagation  
/// **Standards**: RFC 1035 leaves TTL to administrator discretion
pub const AUTH_TTL: usize = 600;

/// SOA record REFRESH interval in seconds.
///
/// Secondary nameserver polls primary this often to check for zone updates.
/// Part of SOA (Start of Authority) record for zone transfers.
///
/// **Default**: 1200 seconds (20 minutes)  
/// **Standards**: RFC 1035 SOA RDATA format  
/// **Purpose**: Secondary zone update checking frequency  
/// **Typical**: 1800-7200 seconds in production zones
pub const SOA_REFRESH: usize = 1200;

/// SOA record RETRY interval in seconds.
///
/// If secondary cannot reach primary during REFRESH, retry after this interval.
/// Shorter than REFRESH for quicker recovery from transient failures.
///
/// **Default**: 180 seconds (3 minutes)  
/// **Standards**: RFC 1035 SOA RDATA format  
/// **Purpose**: Failed transfer retry frequency  
/// **Typical**: 600-1800 seconds in production zones
pub const SOA_RETRY: usize = 180;

/// SOA record EXPIRY time in seconds.
///
/// If secondary cannot contact primary for this duration, stop serving zone
/// (zone data considered stale and unreliable).
///
/// **Default**: 1209600 seconds (2 weeks)  
/// **Standards**: RFC 1035 SOA RDATA format  
/// **Purpose**: Stale zone data expiration  
/// **Typical**: 604800-2419200 seconds (1-4 weeks) in production
pub const SOA_EXPIRY: usize = 1209600;

// ============================================================================
// FILE PATH CONSTANTS
// ============================================================================

/// Default path to system hosts file for local hostname resolution.
///
/// Static hostname-to-IP mappings read from this file and integrated into
/// DNS resolution. Entries override upstream DNS responses.
///
/// **Default**: /etc/hosts (standard Unix location)  
/// **Tunable via**: --hostsdir, --addn-hosts command-line options  
/// **Platform**: Standard across Linux, BSD, macOS, Solaris  
/// **Format**: Standard /etc/hosts format (IP address followed by hostnames)
pub const HOSTSFILE: &str = "/etc/hosts";

/// Default path to system ethers file for MAC-to-IP mappings.
///
/// Optional file mapping Ethernet MAC addresses to IP addresses for static
/// DHCP reservations. Format: MAC_address hostname
///
/// **Default**: /etc/ethers (traditional Unix location)  
/// **Tunable via**: --read-ethers command-line option  
/// **Platform**: Standard across Linux, BSD, macOS  
/// **Format**: Standard /etc/ethers format (MAC address followed by hostname)
pub const ETHERSFILE: &str = "/etc/ethers";

/// DHCP lease database file location (platform-specific).
///
/// Persistent storage for DHCP lease assignments. Contains lease records with
/// MAC address, assigned IP address, hostname, lease expiration, and client identifier.
///
/// **Platform-specific paths**:
/// - BSD (FreeBSD, OpenBSD, DragonFly, NetBSD): /var/db/dnsmasq.leases
/// - Solaris/OpenSolaris: /var/cache/dnsmasq.leases
/// - Android (AOSP): /data/misc/dhcp/dnsmasq.leases
/// - Linux/Default: /var/lib/misc/dnsmasq.leases
///
/// **Tunable via**: --leasefile-ro command-line option  
/// **Format**: Text file, one lease per line  
/// **Permissions**: Readable/writable by dnsmasq daemon user
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "netbsd"
))]
pub const LEASEFILE: &str = "/var/db/dnsmasq.leases";

/// DHCP/DHCPv6 lease database file (Solaris variant).
/// See platform-specific documentation above for full details.
#[cfg(target_os = "solaris")]
pub const LEASEFILE: &str = "/var/cache/dnsmasq.leases";

/// DHCP/DHCPv6 lease database file (Android variant).
/// See platform-specific documentation above for full details.
#[cfg(target_os = "android")]
pub const LEASEFILE: &str = "/data/misc/dhcp/dnsmasq.leases";

/// DHCP/DHCPv6 lease database file (Linux/Default variant).
/// See platform-specific documentation above for full details.
#[cfg(not(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "solaris",
    target_os = "android"
)))]
pub const LEASEFILE: &str = "/var/lib/misc/dnsmasq.leases";

/// Main configuration file location (platform-specific).
///
/// Primary configuration file containing all dnsmasq directives and options.
/// Parsed at daemon startup and on SIGHUP reload.
///
/// **Platform-specific paths**:
/// - FreeBSD: /usr/local/etc/dnsmasq.conf
/// - All other platforms: /etc/dnsmasq.conf
///
/// **Tunable via**: --conf-file command-line option  
/// **Format**: One directive per line, # comments  
/// **Permissions**: Readable by root (daemon starts as root)
#[cfg(target_os = "freebsd")]
pub const CONFFILE: &str = "/usr/local/etc/dnsmasq.conf";

/// Main configuration file location (Default variant).
/// See platform-specific documentation above for full details.
#[cfg(not(target_os = "freebsd"))]
pub const CONFFILE: &str = "/etc/dnsmasq.conf";

/// System resolver configuration file (platform-specific).
///
/// System's upstream DNS server configuration. Dnsmasq reads this file to
/// discover which recursive DNS servers to forward queries to.
///
/// **Platform-specific paths**:
/// - uClinux: /etc/config/resolv.conf
/// - All other platforms: /etc/resolv.conf
///
/// **Tunable via**: --resolv-file command-line option  
/// **Format**: Standard resolv.conf format (nameserver lines)  
/// **Monitoring**: Automatically reloaded on file change (with inotify on Linux)
#[cfg(target_env = "uclibc")]
pub const RESOLVFILE: &str = "/etc/config/resolv.conf";

/// System resolver configuration file (Default variant).
/// See platform-specific documentation above for full details.
#[cfg(not(target_env = "uclibc"))]
pub const RESOLVFILE: &str = "/etc/resolv.conf";

/// Process ID (PID) file location (platform-specific).
///
/// Stores daemon process ID for process management, signal delivery,
/// and preventing multiple daemon instances.
///
/// **Platform-specific paths**:
/// - Android (AOSP): /data/dnsmasq.pid
/// - All other platforms: /var/run/dnsmasq.pid
///
/// **Tunable via**: --pid-file command-line option  
/// **Format**: Single line containing ASCII decimal PID  
/// **Permissions**: 644 (world-readable, daemon-writable)
#[cfg(target_os = "android")]
pub const RUNFILE: &str = "/data/dnsmasq.pid";

/// Process ID (PID) file location (Default variant).
/// See platform-specific documentation above for full details.
#[cfg(not(target_os = "android"))]
pub const RUNFILE: &str = "/var/run/dnsmasq.pid";

/// Entropy source for random number generation.
///
/// Device file providing cryptographic random numbers for DNS query IDs,
/// source port randomization, and other security-critical random values.
///
/// **Default**: /dev/urandom (non-blocking random device)  
/// **Platform**: Standard on Linux, BSD, macOS, Solaris  
/// **Security**: Query ID randomization prevents cache poisoning attacks  
/// **Fallback**: SURF (Secure Universal Random Function) if unavailable
pub const RANDFILE: &str = "/dev/urandom";

// ============================================================================
// SERVICE/SECURITY CONSTANTS
// ============================================================================

/// Default user for privilege separation.
///
/// After binding to privileged ports, daemon drops to this unprivileged user
/// to limit damage from potential security vulnerabilities.
///
/// **Default**: "nobody" (standard unprivileged user)  
/// **Tunable via**: --user command-line option  
/// **Security**: Principle of least privilege  
/// **Platform**: "nobody" exists on most Unix systems
pub const CHUSER: &str = "nobody";

/// Default group for privilege separation.
///
/// Daemon switches to this group after initialization. On Linux, "dip"
/// (Dialup IP) group allows DHCP and network configuration access.
///
/// **Default**: "dip" (Dialup IP group on Debian/Ubuntu)  
/// **Tunable via**: --group command-line option  
/// **Linux**: "dip" allows dhcp and network device access  
/// **BSD**: May use "wheel" or "network" instead  
/// **Fallback**: Primary group of CHUSER if group doesn't exist
pub const CHGRP: &str = "dip";

/// D-Bus service name for control interface.
///
/// Service name registered on D-Bus system bus for programmatic control
/// and monitoring. Follows reverse-domain naming convention.
///
/// **Default**: "uk.org.thekelleys.dnsmasq"  
/// **Tunable via**: --dbus-service-name command-line option  
/// **Platform**: Linux, BSD, macOS with D-Bus daemon installed  
/// **API**: SetServers, ClearCache, GetVersion, GetMetrics methods
pub const DNSMASQ_SERVICE: &str = "uk.org.thekelleys.dnsmasq";

/// UBus service name for control interface (OpenWrt).
///
/// Service name registered on OpenWrt's ubus for control and monitoring.
/// Used in OpenWrt-based routers and embedded systems.
///
/// **Default**: "dnsmasq"  
/// **Platform**: OpenWrt Linux distribution only  
/// **Purpose**: Integration with OpenWrt management framework  
/// **API**: Similar functionality to D-Bus interface
pub const UBUS_SERVICE_NAME: &str = "dnsmasq";

// ============================================================================
// OPERATIONAL LIMITS
// ============================================================================

/// Non-blocking logging queue depth.
///
/// Maximum pending log messages before queue full condition. Non-blocking
/// queue prevents slow syslog from blocking packet processing.
///
/// **Default**: 5 messages  
/// **Behavior**: When full, new messages dropped with warning logged  
/// **Purpose**: Maintain packet processing performance during log storms  
/// **Performance**: Low value trades log completeness for packet latency
pub const LOG_MAX: usize = 5;

/// Maximum log message length in bytes.
///
/// Buffer size for individual log messages. Messages exceeding this length
/// are truncated.
///
/// **Default**: 512 bytes  
/// **Rationale**: Syslog traditionally limited to 1024 bytes total  
/// **Typical**: DNS queries and responses fit in 100-200 bytes  
/// **Truncation**: Long messages (DNSSEC chains) truncated with "..."
pub const MAX_MESSAGE: usize = 512;

/// ARP table refresh interval in seconds.
///
/// Frequency of ARP table polling for DHCP lease correlation. Associates
/// DHCP leases with ARP entries for network diagnostics.
///
/// **Default**: 30 seconds  
/// **Platform**: Linux only (uses /proc/net/arp)  
/// **Purpose**: DHCP-ARP binding for lease validation  
/// **Performance**: 30s balances freshness vs. overhead
pub const ARP_REFRESH_INTERVAL: usize = 30;

/// Stale cache expiry time in seconds.
///
/// When upstream servers unreachable, serve stale cache entries for up to
/// this duration past their original TTL expiry.
///
/// **Default**: 86400 seconds (24 hours)  
/// **Purpose**: Graceful degradation when upstream DNS fails  
/// **Behavior**: Stale entries served with reduced TTL  
/// **RFC Compliance**: RFC 8767 Serving Stale Data  
/// **Tunable via**: --use-stale-cache-timeout command-line option
pub const STALE_CACHE_EXPIRY: usize = 86400;

/// Minimum TTL floor limit in seconds.
///
/// Lower bound for TTL floor settings to prevent zero or very short TTLs
/// that cause excessive query storms.
///
/// **Default**: 3600 seconds (1 hour)  
/// **Purpose**: Prevent misconfiguration causing cache thrashing  
/// **Tunable via**: --min-cache-ttl command-line option  
/// **Security**: Protects against cache exhaustion attacks via 0 TTL
pub const TTL_FLOOR_LIMIT: usize = 3600;
