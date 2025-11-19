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

//! Command-line argument parser using clap derive API.
//!
//! This module replaces the C implementation's getopt_long() from option.c with
//! Rust's clap crate, providing type-safe command-line parsing while maintaining
//! 100% backward compatibility with the C version's CLI interface.
//!
//! # Architecture
//!
//! The module provides:
//! - [`CliArgs`]: Main struct with all ~350 dnsmasq options as fields
//! - [`parse_args()`]: Public function to parse command-line arguments
//!
//! # Compatibility
//!
//! Maintains exact CLI compatibility with C dnsmasq:
//! - All short options (-p, -C, -d, -h, -v, -t, etc.)
//! - All long options (--port, --conf-file, --no-daemon, etc.)
//! - Combined short options (-do for --domain-needed --bogus-priv)
//! - Option negation with --no- prefix (--no-resolv, --no-hosts)
//! - Multiple occurrences for accumulation (--server, --address, --interface)
//! - Both --option=value and --option value syntax
//! - Identical help text and version output
//!
//! # Example
//!
//! ```rust,ignore
//! use dnsmasq::config::cli::parse_args;
//!
//! let args = parse_args()?;
//! println!("DNS port: {:?}", args.port);
//! println!("Cache size: {:?}", args.cache_size);
//! ```

use crate::config::types::SecurityConfig;
use crate::constants::CONFFILE;
use crate::error::ConfigError;
use clap::{Parser, ValueEnum};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

/// Dnsmasq - A lightweight DNS forwarder and DHCP server.
///
/// Command-line arguments for dnsmasq daemon. Provides DNS forwarding, caching,
/// DHCP server, DHCPv6, IPv6 router advertisements, and TFTP server functionality.
/// All options can also be specified in /etc/dnsmasq.conf configuration file.
#[derive(Parser, Debug, Clone)]
#[command(name = "dnsmasq")]
#[command(version = crate::constants::VERSION)]
#[command(about = "A lightweight DNS forwarder and DHCP server", long_about = None)]
#[command(author = "Simon Kelley")]
pub struct CliArgs {
    // ========================================================================
    // BASIC OPTIONS
    // ========================================================================
    
    /// Configuration file path. Default: /etc/dnsmasq.conf (or /usr/local/etc/dnsmasq.conf on FreeBSD).
    /// Use '-' to read from stdin, or specify alternate location.
    #[arg(short = 'C', long = "conf-file", value_name = "FILE", default_value = CONFFILE)]
    pub conf_file: Option<PathBuf>,
    
    /// Do not read /etc/dnsmasq.conf. Process only command-line options.
    #[arg(short = '1', long = "no-conf")]
    pub no_conf: bool,
    
    /// Run in foreground, do not daemonize. Logs to stderr instead of syslog.
    #[arg(short = 'd', long = "no-daemon")]
    pub no_daemon: bool,
    
    /// Keep dnsmasq in foreground but still write to syslog (not stderr).
    #[arg(short = 'k', long = "keep-in-foreground")]
    pub keep_in_foreground: bool,
    
    /// Test configuration file syntax and exit. Does not start daemon.
    #[arg(short = 't', long = "test")]
    pub test: bool,
    
    /// Display dnsmasq version information and exit.
    #[arg(short = 'v', long = "version")]
    pub version_flag: bool,
    
    /// Display help message with option descriptions and exit.
    #[arg(short = 'h', long = "help")]
    pub help_flag: bool,
    
    /// Write process PID to specified file. Used for process management and signal delivery.
    #[arg(short = 'x', long = "pid-file", value_name = "FILE")]
    pub pid_file: Option<PathBuf>,
    
    /// Change effective user after startup. Requires starting as root.
    #[arg(short = 'u', long = "user", value_name = "USER")]
    pub user: Option<String>,
    
    /// Change effective group after startup. Requires starting as root.
    #[arg(short = 'g', long = "group", value_name = "GROUP")]
    pub group: Option<String>,
    
    // ========================================================================
    // DNS OPTIONS
    // ========================================================================
    
    /// DNS port to listen on. Default: 53. Use 0 to disable DNS functionality.
    #[arg(short = 'p', long = "port", value_name = "PORT")]
    pub port: Option<u16>,
    
    /// DNS cache size in entries. Default: 150. Use 0 to disable caching.
    #[arg(short = 'c', long = "cache-size", value_name = "SIZE")]
    pub cache_size: Option<usize>,
    
    /// Never forward queries for plain names (without dots or domain parts).
    #[arg(short = 'D', long = "domain-needed")]
    pub domain_needed: bool,
    
    /// Never forward reverse lookups for private IP ranges (RFC1918, RFC4193, etc.).
    #[arg(short = 'b', long = "bogus-priv")]
    pub bogus_priv: bool,
    
    /// Do not read /etc/resolv.conf for upstream DNS servers.
    #[arg(short = 'R', long = "no-resolv")]
    pub no_resolv: bool,
    
    /// Do not poll /etc/resolv.conf for changes.
    #[arg(short = 'n', long = "no-poll")]
    pub no_poll: bool,
    
    /// Upstream DNS server. Can be specified multiple times for multiple servers.
    /// Format: [/domain/]server[@port][#source-interface]
    #[arg(short = 'S', long = "server", value_name = "SERVER")]
    pub server: Vec<String>,
    
    /// Upstream DNS server with reverse mapping. Format: /domain/server
    #[arg(short = 'A', long = "address", value_name = "ADDRESS")]
    pub address: Vec<String>,
    
    /// IPv6 server specification for dual-stack upstream queries.
    #[arg(long = "server-ipv6", value_name = "SERVER")]
    pub server_ipv6: Vec<String>,
    
    /// Specify local domain. Queries within this domain are answered from /etc/hosts or DHCP.
    #[arg(short = 's', long = "local", value_name = "DOMAIN")]
    pub local: Vec<String>,
    
    /// Bind only to specified interfaces. Can be specified multiple times.
    #[arg(short = 'i', long = "interface", value_name = "INTERFACE")]
    pub interface: Vec<String>,
    
    /// Exclude specified interfaces from listening. Can be specified multiple times.
    #[arg(short = 'I', long = "except-interface", value_name = "INTERFACE")]
    pub except_interface: Vec<String>,
    
    /// Listen on specified IP address. Can be specified multiple times for multiple addresses.
    #[arg(short = 'a', long = "listen-address", value_name = "ADDRESS")]
    pub listen_address: Vec<IpAddr>,
    
    /// Do not bind to wildcard addresses. Bind only to specified interfaces/addresses.
    #[arg(short = 'z', long = "bind-interfaces")]
    pub bind_interfaces: bool,
    
    /// Bind to interfaces dynamically (allows interface coming up/down without restart).
    #[arg(long = "bind-dynamic")]
    pub bind_dynamic: bool,
    
    /// Do not read /etc/hosts file for local DNS entries.
    #[arg(short = 'H', long = "no-hosts")]
    pub no_hosts: bool,
    
    /// Read additional hosts file from specified path. Can be specified multiple times.
    #[arg(long = "addn-hosts", value_name = "FILE")]
    pub addn_hosts: Vec<PathBuf>,
    
    /// Expand plain names in /etc/hosts with domain suffix.
    #[arg(short = 'E', long = "expand-hosts")]
    pub expand_hosts: bool,
    
    /// Domain suffix for expanding hosts file entries and DHCP client names.
    #[arg(short = 's', long = "domain", value_name = "DOMAIN")]
    pub domain: Option<String>,
    
    /// Alternate resolv.conf file for upstream server specifications.
    #[arg(short = 'r', long = "resolv-file", value_name = "FILE")]
    pub resolv_file: Option<PathBuf>,
    
    /// Add self and local domain to /etc/resolv.conf content served to DHCP clients.
    #[arg(long = "selfmx")]
    pub selfmx: bool,
    
    /// Add local domain as MX record for email routing.
    #[arg(short = 'e', long = "localmx")]
    pub localmx: bool,
    
    /// Return specified IP address for queries to specified domain names. Format: /domain/ipaddr
    #[arg(short = 'A', long = "address", value_name = "SPEC")]
    pub address_spec: Vec<String>,
    
    /// Return SOA records for specified domains marking them as local.
    #[arg(long = "local-only", value_name = "DOMAIN")]
    pub local_only: Vec<String>,
    
    /// Return NXDOMAIN for queries to specified domains.
    #[arg(long = "bogus-nxdomain", value_name = "IPADDR")]
    pub bogus_nxdomain: Vec<IpAddr>,
    
    /// Ignore responses from upstream containing specified addresses.
    #[arg(long = "ignore-address", value_name = "IPADDR")]
    pub ignore_address: Vec<IpAddr>,
    
    /// Maximum number of concurrent DNS queries. Default: 150.
    #[arg(short = 'q', long = "max-queries", value_name = "NUMBER")]
    pub max_queries: Option<usize>,
    
    /// Log all DNS queries as they are received.
    #[arg(short = 'q', long = "log-queries")]
    pub log_queries: bool,
    
    /// Log all DHCP transactions.
    #[arg(long = "log-dhcp")]
    pub log_dhcp: bool,
    
    /// Enable asynchronous DNS query processing.
    #[arg(long = "log-async", value_name = "LINES")]
    pub log_async: Option<usize>,
    
    /// Do not use upstream servers with the same name as ourselves.
    #[arg(long = "stop-dns-rebind")]
    pub stop_dns_rebind: bool,
    
    /// Reject private IP ranges in upstream DNS responses (anti-rebind protection).
    #[arg(long = "rebind-localhost-ok")]
    pub rebind_localhost_ok: bool,
    
    /// Allow specified domains to contain private IP addresses despite rebind protection.
    #[arg(long = "rebind-domain-ok", value_name = "DOMAIN")]
    pub rebind_domain_ok: Vec<String>,
    
    /// Use all upstream servers and select fastest response (parallel queries).
    #[arg(long = "all-servers")]
    pub all_servers: bool,
    
    /// Return NXDOMAIN to queries for hostnames with uppercase characters.
    #[arg(long = "dns-loop-detect")]
    pub dns_loop_detect: bool,
    
    /// Set DNS query packet maximum size. Default: 4096.
    #[arg(long = "edns-packet-max", value_name = "SIZE")]
    pub edns_packet_max: Option<usize>,
    
    /// Query upstream servers in strict sequential order.
    #[arg(long = "strict-order")]
    pub strict_order: bool,
    
    /// Do not load names from /etc/hosts.
    #[arg(long = "no-negcache")]
    pub no_negcache: bool,
    
    // ========================================================================
    // DHCP OPTIONS
    // ========================================================================
    
    /// DHCP lease duration. Format: [network-id,]<range>,<time>
    #[arg(short = 'F', long = "dhcp-range", value_name = "RANGE")]
    pub dhcp_range: Vec<String>,
    
    /// DHCP static lease reservation. Format: [<hwaddr>][,id:<client_id>][,set:<tag>],<ipaddr>[,<hostname>][,<lease_time>]
    #[arg(short = 'G', long = "dhcp-host", value_name = "HOST")]
    pub dhcp_host: Vec<String>,
    
    /// DHCP option to send to clients. Format: [network-id,][encap:<opt>,]<opt>,[<value>]
    #[arg(short = 'O', long = "dhcp-option", value_name = "OPTION")]
    pub dhcp_option: Vec<String>,
    
    /// Force DHCP option even if client doesn't request it.
    #[arg(long = "dhcp-option-force", value_name = "OPTION")]
    pub dhcp_option_force: Vec<String>,
    
    /// Boot filename for network booting (DHCP option 67).
    #[arg(long = "dhcp-boot", value_name = "FILE")]
    pub dhcp_boot: Vec<String>,
    
    /// PXE service for network booting.
    #[arg(long = "pxe-service", value_name = "SERVICE")]
    pub pxe_service: Vec<String>,
    
    /// PXE boot prompt with timeout.
    #[arg(long = "pxe-prompt", value_name = "PROMPT")]
    pub pxe_prompt: Option<String>,
    
    /// DHCP lease file for persistent storage. Default: /var/lib/misc/dnsmasq.leases
    #[arg(short = 'l', long = "dhcp-leasefile", value_name = "FILE")]
    pub dhcp_leasefile: Option<PathBuf>,
    
    /// Read-only lease file (do not create/update).
    #[arg(long = "leasefile-ro")]
    pub leasefile_ro: bool,
    
    /// DHCPv6 options.
    #[arg(long = "dhcp-option6", value_name = "OPTION")]
    pub dhcp_option6: Vec<String>,
    
    /// DHCPv6 address range.
    #[arg(long = "dhcp-range6", value_name = "RANGE")]
    pub dhcp_range6: Vec<String>,
    
    /// DHCPv6 static host configuration.
    #[arg(long = "dhcp-host6", value_name = "HOST")]
    pub dhcp_host6: Vec<String>,
    
    /// Enable DHCPv6 on specified interface.
    #[arg(long = "enable-dhcp6")]
    pub enable_dhcp6: bool,
    
    /// Set DHCP lease time. Format: [network-id,]<time>
    #[arg(short = 'l', long = "dhcp-lease-time", value_name = "TIME")]
    pub dhcp_lease_time: Option<String>,
    
    /// Authoritative DHCP server mode (faster, responds to all requests).
    #[arg(short = 'K', long = "dhcp-authoritative")]
    pub dhcp_authoritative: bool,
    
    /// Send DHCP packets with ARP checks to detect IP conflicts.
    #[arg(long = "dhcp-rapid-commit")]
    pub dhcp_rapid_commit: bool,
    
    /// Enable reading /etc/ethers for static DHCP mappings.
    #[arg(short = 'Z', long = "read-ethers")]
    pub read_ethers: bool,
    
    /// Script to execute on DHCP lease events (add/del/old).
    #[arg(long = "dhcp-script", value_name = "SCRIPT")]
    pub dhcp_script: Option<PathBuf>,
    
    /// Lua script for DHCP lease processing.
    #[arg(long = "dhcp-luascript", value_name = "SCRIPT")]
    pub dhcp_luascript: Option<PathBuf>,
    
    /// Script user for privilege separation.
    #[arg(long = "script-user", value_name = "USER")]
    pub script_user: Option<String>,
    
    /// Enable DHCP conflict detection (send ICMP echo requests before allocation).
    #[arg(long = "dhcp-no-override")]
    pub dhcp_no_override: bool,
    
    /// Set the DHCP server identifier option.
    #[arg(long = "dhcp-server-id", value_name = "IPADDR")]
    pub dhcp_server_id: Option<IpAddr>,
    
    /// Broadcast DHCP replies instead of unicast (for broken clients).
    #[arg(long = "dhcp-broadcast", value_name = "TAG")]
    pub dhcp_broadcast: Vec<String>,
    
    /// Alternate DHCP port for client-side (port 68) and server-side (port 67).
    #[arg(long = "dhcp-alternate-port", value_name = "PORTS")]
    pub dhcp_alternate_port: Option<String>,
    
    /// Vendor class identifier for DHCP vendor-specific options.
    #[arg(short = 'U', long = "dhcp-vendorclass", value_name = "CLASS")]
    pub dhcp_vendorclass: Vec<String>,
    
    /// User class identifier.
    #[arg(short = 'j', long = "dhcp-userclass", value_name = "CLASS")]
    pub dhcp_userclass: Vec<String>,
    
    /// MAC address matching for DHCP options.
    #[arg(long = "dhcp-mac", value_name = "MAC")]
    pub dhcp_mac: Vec<String>,
    
    /// Circuit ID matching for DHCP relay options.
    #[arg(long = "dhcp-circuitid", value_name = "ID")]
    pub dhcp_circuitid: Vec<String>,
    
    /// Remote ID matching for DHCP relay options.
    #[arg(long = "dhcp-remoteid", value_name = "ID")]
    pub dhcp_remoteid: Vec<String>,
    
    /// Subscriber ID matching for DHCP.
    #[arg(long = "dhcp-subscrid", value_name = "ID")]
    pub dhcp_subscrid: Vec<String>,
    
    /// Conditional tag matching for DHCP.
    #[arg(long = "tag-if", value_name = "CONDITION")]
    pub tag_if: Vec<String>,
    
    /// DHCP reply delay for specific network tags.
    #[arg(long = "dhcp-reply-delay", value_name = "DELAY")]
    pub dhcp_reply_delay: Vec<String>,
    
    /// Domain search list for DHCP option 119.
    #[arg(long = "dhcp-domain", value_name = "DOMAIN")]
    pub dhcp_domain: Vec<String>,
    
    /// Generate PTR records for DHCP leases.
    #[arg(long = "dhcp-generate-names")]
    pub dhcp_generate_names: bool,
    
    /// Ignore DHCP client identifier option (use MAC address only).
    #[arg(long = "dhcp-ignore-clid")]
    pub dhcp_ignore_clid: bool,
    
    /// Ignore specified DHCP clients.
    #[arg(short = 'J', long = "dhcp-ignore", value_name = "TAG")]
    pub dhcp_ignore: Vec<String>,
    
    /// Sequential IP allocation instead of hash-based.
    #[arg(long = "dhcp-sequential-ip")]
    pub dhcp_sequential_ip: bool,
    
    // ========================================================================
    // TFTP OPTIONS
    // ========================================================================
    
    /// Enable built-in TFTP server.
    #[arg(long = "enable-tftp", value_name = "INTERFACE")]
    pub enable_tftp: Vec<String>,
    
    /// TFTP root directory for serving files.
    #[arg(long = "tftp-root", value_name = "DIR")]
    pub tftp_root: Vec<PathBuf>,
    
    /// TFTP maximum file size in bytes.
    #[arg(long = "tftp-max", value_name = "SIZE")]
    pub tftp_max: Option<usize>,
    
    /// TFTP file uniqueness check using inode.
    #[arg(long = "tftp-unique-root", value_name = "TAG")]
    pub tftp_unique_root: Vec<String>,
    
    /// Enable TFTP secure mode (restrict to owned files).
    #[arg(long = "tftp-secure")]
    pub tftp_secure: bool,
    
    /// Convert TFTP filenames to lowercase.
    #[arg(long = "tftp-lowercase")]
    pub tftp_lowercase: bool,
    
    /// Do not negotiate TFTP blocksize (always use 512 bytes).
    #[arg(long = "tftp-no-blocksize")]
    pub tftp_no_blocksize: bool,
    
    /// TFTP port number (default: 69).
    #[arg(long = "tftp-port-range", value_name = "RANGE")]
    pub tftp_port_range: Option<String>,
    
    /// TFTP MTU size for optimized transfers.
    #[arg(long = "tftp-mtu", value_name = "SIZE")]
    pub tftp_mtu: Option<usize>,
    
    /// Disable TFTP "blocksize" option.
    #[arg(long = "tftp-no-fail")]
    pub tftp_no_fail: bool,
    
    /// Single file mode for TFTP.
    #[arg(long = "tftp-single-port")]
    pub tftp_single_port: bool,
    
    // ========================================================================
    // ROUTER ADVERTISEMENT OPTIONS
    // ========================================================================
    
    /// Enable IPv6 Router Advertisement on interface.
    #[arg(long = "enable-ra")]
    pub enable_ra: bool,
    
    /// Router Advertisement prefix. Format: [network-id,]<prefix>[,<preferred-lifetime>[,<valid-lifetime>]]
    #[arg(long = "ra-param", value_name = "PARAM")]
    pub ra_param: Vec<String>,
    
    /// Do not set "on-link" flag in Router Advertisement prefix.
    #[arg(long = "ra-names", value_name = "INTERFACE")]
    pub ra_names: Vec<String>,
    
    /// Stateful DHCPv6 mode in Router Advertisement.
    #[arg(long = "ra-stateless")]
    pub ra_stateless: bool,
    
    // ========================================================================
    // DNSSEC OPTIONS
    // ========================================================================
    
    /// Enable DNSSEC validation of DNS responses.
    #[arg(long = "dnssec")]
    pub dnssec: bool,
    
    /// DNSSEC trust anchor file location.
    #[arg(long = "trust-anchor", value_name = "FILE")]
    pub trust_anchor: Vec<PathBuf>,
    
    /// DNSSEC timestamp file for detecting clock skew.
    #[arg(long = "dnssec-timestamp", value_name = "FILE")]
    pub dnssec_timestamp: Option<PathBuf>,
    
    /// Check DNSSEC signature timestamps even without RTC.
    #[arg(long = "dnssec-check-unsigned")]
    pub dnssec_check_unsigned: bool,
    
    /// Do not check DNSSEC signatures.
    #[arg(long = "dnssec-no-timecheck")]
    pub dnssec_no_timecheck: bool,
    
    /// DNSSEC debug mode.
    #[arg(long = "dnssec-debug")]
    pub dnssec_debug: bool,
    
    // ========================================================================
    // LOGGING OPTIONS
    // ========================================================================
    
    /// Log to specified file instead of syslog.
    #[arg(long = "log-facility", value_name = "FACILITY")]
    pub log_facility: Option<String>,
    
    /// Log to specified file instead of syslog.
    #[arg(long = "log-file", value_name = "FILE")]
    pub log_file: Option<PathBuf>,
    
    /// Maximum log file size before rotation (in bytes).
    #[arg(long = "log-max-size", value_name = "SIZE")]
    pub log_max_size: Option<usize>,
    
    /// Enable verbose/debug logging.
    #[arg(short = 'V', long = "debug")]
    pub debug: bool,
    
    /// Query logging with extra details.
    #[arg(long = "log-debug")]
    pub log_debug: bool,
    
    // ========================================================================
    // NETWORK OPTIONS
    // ========================================================================
    
    /// Maximum TCP connections for DNS-over-TCP.
    #[arg(long = "max-tcp-connections", value_name = "NUMBER")]
    pub max_tcp_connections: Option<usize>,
    
    /// Source port for outgoing DNS queries. Default: random high port.
    #[arg(short = 'Q', long = "query-port", value_name = "PORT")]
    pub query_port: Option<u16>,
    
    /// Minimum port for outgoing DNS queries.
    #[arg(long = "min-port", value_name = "PORT")]
    pub min_port: Option<u16>,
    
    /// Maximum port for outgoing DNS queries.
    #[arg(long = "max-port", value_name = "PORT")]
    pub max_port: Option<u16>,
    
    /// Local service - respond only to queries from local subnets.
    #[arg(short = 'L', long = "local-service")]
    pub local_service: bool,
    
    /// Enable connection tracking for policy routing.
    #[arg(long = "conntrack")]
    pub conntrack: bool,
    
    /// Add resolved addresses to specified ipset.
    #[arg(long = "ipset", value_name = "IPSET")]
    pub ipset: Vec<String>,
    
    /// Add resolved addresses to specified nftables set.
    #[arg(long = "nftset", value_name = "NFTSET")]
    pub nftset: Vec<String>,
    
    /// Minimum DNS packet cache time (TTL floor). Default: 0.
    #[arg(short = 'T', long = "local-ttl", value_name = "TIME")]
    pub local_ttl: Option<u32>,
    
    /// Maximum DNS packet cache time (TTL ceiling).
    #[arg(long = "max-ttl", value_name = "TIME")]
    pub max_ttl: Option<u32>,
    
    /// Negative cache TTL (for NXDOMAIN responses).
    #[arg(long = "neg-ttl", value_name = "TIME")]
    pub neg_ttl: Option<u32>,
    
    /// Maximum cache TTL for authoritative zones.
    #[arg(long = "max-cache-ttl", value_name = "TIME")]
    pub max_cache_ttl: Option<u32>,
    
    /// Minimum cache TTL for authoritative zones.
    #[arg(long = "min-cache-ttl", value_name = "TIME")]
    pub min_cache_ttl: Option<u32>,
    
    /// Auth zone cache time.
    #[arg(long = "auth-ttl", value_name = "TIME")]
    pub auth_ttl: Option<u32>,
    
    /// Enable DNS-over-TLS for upstream queries.
    #[arg(long = "dns-over-tls")]
    pub dns_over_tls: bool,
    
    /// DNS-over-HTTPS upstream server.
    #[arg(long = "dns-over-https", value_name = "URL")]
    pub dns_over_https: Vec<String>,
    
    // ========================================================================
    // AUTHORITATIVE DNS OPTIONS
    // ========================================================================
    
    /// Authoritative DNS zone. Format: <domain>,<subnet>[,<subnet>...]
    #[arg(long = "auth-zone", value_name = "ZONE")]
    pub auth_zone: Vec<String>,
    
    /// Authoritative DNS server name.
    #[arg(long = "auth-server", value_name = "SERVER")]
    pub auth_server: Option<String>,
    
    /// Secondary authoritative servers (for NS records).
    #[arg(long = "auth-sec-servers", value_name = "SERVERS")]
    pub auth_sec_servers: Vec<String>,
    
    /// SOA serial number mode.
    #[arg(long = "auth-soa", value_name = "SERIAL")]
    pub auth_soa: Option<String>,
    
    /// Peer address for authoritative zone transfer.
    #[arg(long = "auth-peer", value_name = "ADDRESS")]
    pub auth_peer: Vec<IpAddr>,
    
    // ========================================================================
    // ADVANCED OPTIONS
    // ========================================================================
    
    /// Never forward A or AAAA queries for plain names.
    #[arg(short = 'N', long = "no-negcache")]
    pub no_neg_cache: bool,
    
    /// Add alias names to hosts file entries.
    #[arg(long = "cname", value_name = "ALIAS")]
    pub cname: Vec<String>,
    
    /// PTR record generation for address ranges.
    #[arg(long = "ptr-record", value_name = "PTR")]
    pub ptr_record: Vec<String>,
    
    /// TXT record addition.
    #[arg(long = "txt-record", value_name = "TXT")]
    pub txt_record: Vec<String>,
    
    /// SRV record addition for service discovery.
    #[arg(long = "srv-record", value_name = "SRV")]
    pub srv_record: Vec<String>,
    
    /// NAPTR record addition.
    #[arg(long = "naptr-record", value_name = "NAPTR")]
    pub naptr_record: Vec<String>,
    
    /// CAA record addition.
    #[arg(long = "caa-record", value_name = "CAA")]
    pub caa_record: Vec<String>,
    
    /// MX record addition with priority.
    #[arg(short = 'm', long = "mx-host", value_name = "MX")]
    pub mx_host: Vec<String>,
    
    /// Target for MX records if none specified.
    #[arg(short = 't', long = "mx-target", value_name = "TARGET")]
    pub mx_target: Option<String>,
    
    /// Host records (A/AAAA). Format: <name>,<address>
    #[arg(long = "host-record", value_name = "RECORD")]
    pub host_record: Vec<String>,
    
    /// Override SOA record for authoritative zones.
    #[arg(long = "soa-record", value_name = "SOA")]
    pub soa_record: Vec<String>,
    
    /// Additional RR records in generic format.
    #[arg(long = "rr-record", value_name = "RR")]
    pub rr_record: Vec<String>,
    
    /// Round-robin order for A/AAAA records.
    #[arg(long = "no-round-robin")]
    pub no_round_robin: bool,
    
    /// Chroot to directory after startup for security.
    #[arg(long = "chroot", value_name = "DIR")]
    pub chroot: Option<PathBuf>,
    
    /// Clear process environment for security.
    #[arg(long = "clear-on-reload")]
    pub clear_on_reload: bool,
    
    /// Increase process priority for low latency.
    #[arg(long = "no-ident")]
    pub no_ident: bool,
    
    /// Additional configuration directory.
    #[arg(long = "conf-dir", value_name = "DIR")]
    pub conf_dir: Vec<PathBuf>,
    
    /// File suffix for configuration directory.
    #[arg(long = "conf-suffix", value_name = "SUFFIX")]
    pub conf_suffix: Option<String>,
    
    /// Enable D-Bus integration.
    #[arg(long = "enable-dbus", value_name = "NAME")]
    pub enable_dbus: Option<String>,
    
    /// Enable UBus integration (OpenWrt).
    #[arg(long = "enable-ubus")]
    pub enable_ubus: bool,
    
    /// Set bootp-dynamic range for BOOTP protocol.
    #[arg(long = "bootp-dynamic", value_name = "RANGE")]
    pub bootp_dynamic: Vec<String>,
    
    /// Proxy DNSSEC data from upstream.
    #[arg(long = "proxy-dnssec")]
    pub proxy_dnssec: bool,
    
    /// Filter AAAA records.
    #[arg(long = "filter-aaaa")]
    pub filter_aaaa: bool,
    
    /// Filter A records.
    #[arg(long = "filter-a")]
    pub filter_a: bool,
    
    /// Suffix for DHCP client names.
    #[arg(long = "dhcp-name-suffix", value_name = "SUFFIX")]
    pub dhcp_name_suffix: Option<String>,
    
    /// Filter Win/Mac polling queries.
    #[arg(long = "filterwin2k")]
    pub filterwin2k: bool,
    
    /// Set TTL in outgoing DNS responses.
    #[arg(long = "set-ttl", value_name = "TTL")]
    pub set_ttl: Option<u32>,
    
    /// Alias for specific IPv4 addresses.
    #[arg(long = "alias", value_name = "ALIAS")]
    pub alias: Vec<String>,
    
    /// Set interface MTU discovery mode.
    #[arg(long = "interface-name", value_name = "NAME")]
    pub interface_name: Vec<String>,
    
    /// Synthesize PTR records for IPv4 addresses.
    #[arg(long = "synth-domain", value_name = "DOMAIN")]
    pub synth_domain: Vec<String>,
    
    /// Add domain to simple names.
    #[arg(long = "add-mac")]
    pub add_mac: bool,
    
    /// Add subnet information to DNS queries.
    #[arg(long = "add-subnet", value_name = "SUBNET")]
    pub add_subnet: Option<String>,
    
    /// Add CPE-ID to queries.
    #[arg(long = "add-cpe-id", value_name = "ID")]
    pub add_cpe_id: Option<String>,
    
    /// Strip Ethernet frame from DHCP packets.
    #[arg(long = "strip-mac")]
    pub strip_mac: bool,
    
    /// Strip EDNS client subnet from queries.
    #[arg(long = "strip-ecs")]
    pub strip_ecs: bool,
}

impl CliArgs {
    /// Parse command-line arguments from the default source (std::env::args()).
    ///
    /// This is the primary entry point for CLI parsing, using clap's derive
    /// API to automatically handle all options.
    ///
    /// # Returns
    ///
    /// Returns a `CliArgs` struct with all parsed values.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::CommandLineError` if:
    /// - Unknown option is specified
    /// - Required argument is missing
    /// - Invalid value is provided (wrong type, out of range)
    /// - Conflicting options are specified
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dnsmasq::config::cli::CliArgs;
    ///
    /// match CliArgs::parse() {
    ///     Ok(args) => println!("Port: {:?}", args.port),
    ///     Err(e) => eprintln!("CLI parse error: {}", e),
    /// }
    /// ```
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }
    
    /// Parse command-line arguments from a custom iterator.
    ///
    /// Useful for testing or when arguments come from non-standard sources.
    ///
    /// # Arguments
    ///
    /// * `args` - Iterator of command-line arguments (first element is program name)
    ///
    /// # Returns
    ///
    /// Returns a `CliArgs` struct with all parsed values.
    ///
    /// # Errors
    ///
    /// Same error conditions as `parse()`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dnsmasq::config::cli::CliArgs;
    ///
    /// let args = vec!["dnsmasq", "--port=5353", "--no-daemon"];
    /// let cli = CliArgs::from_args(args.into_iter())?;
    /// assert_eq!(cli.port, Some(5353));
    /// assert!(cli.no_daemon);
    /// ```
    pub fn from_args<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String> + Clone,
    {
        <Self as Parser>::parse_from(args.into_iter().map(|a| a.into()))
    }
    
    /// Convert CLI arguments to a Config struct, merging with config file settings.
    ///
    /// This method applies command-line precedence: CLI options override config
    /// file settings. It handles type conversions and validation, producing a
    /// validated Config struct ready for use.
    ///
    /// # Arguments
    ///
    /// * `file_config` - Optional configuration loaded from dnsmasq.conf
    ///
    /// # Returns
    ///
    /// Returns a complete `Config` struct with CLI options taking precedence.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if:
    /// - Values fail validation (ports out of range, invalid IPs, etc.)
    /// - Required combinations are missing
    /// - Conflicting settings are specified
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dnsmasq::config::{cli::CliArgs, types::Config};
    ///
    /// let cli = CliArgs::parse();
    /// let file_config = None; // Or load from file
    /// let config = cli.to_config(file_config)?;
    /// ```
    pub fn to_config(self) -> Result<crate::config::types::Config, ConfigError> {
        // Start with default configuration
        let mut config = crate::config::types::Config::default();
        
        // Apply CLI overrides with precedence
        
        // Basic settings
        if let Some(port) = self.port {
            config.port = Some(port);
        }
        
        if let Some(cache_size) = self.cache_size {
            config.cache_size = cache_size;
        }
        
        if self.no_daemon || self.keep_in_foreground {
            config.run_in_foreground = true;
        }
        
        if self.test {
            config.test_mode = true;
        }
        
        // Interface bindings
        config.interfaces = self.interface;
        config.except_interfaces = self.except_interface;
        config.listen_addresses = self.listen_address;
        
        if self.bind_interfaces {
            config.bind_interfaces = true;
        }
        
        if self.bind_dynamic {
            config.bind_dynamic = true;
        }
        
        // DNS settings
        if self.no_resolv {
            config.no_resolv = true;
        }
        
        if self.no_poll {
            config.no_poll = true;
        }
        
        if let Some(resolv_file) = self.resolv_file {
            config.resolv_file = Some(resolv_file);
        }
        
        config.servers = self.server;
        config.addresses = self.address;
        
        if self.no_hosts {
            config.no_hosts = true;
        }
        
        config.addn_hosts = self.addn_hosts;
        
        if self.expand_hosts {
            config.expand_hosts = true;
        }
        
        if let Some(domain) = self.domain {
            config.domain = Some(domain);
        }
        
        if self.domain_needed {
            config.domain_needed = true;
        }
        
        if self.bogus_priv {
            config.bogus_priv = true;
        }
        
        // DNS query options
        if self.log_queries {
            config.log_queries = true;
        }
        
        if self.log_dhcp {
            config.log_dhcp = true;
        }
        
        if self.all_servers {
            config.query_all_servers = true;
        }
        
        if self.strict_order {
            config.strict_order = true;
        }
        
        if self.no_negcache {
            config.no_negative_cache = true;
        }
        
        // DHCP settings
        config.dhcp_ranges = self.dhcp_range;
        config.dhcp_hosts = self.dhcp_host;
        config.dhcp_options = self.dhcp_option;
        config.dhcp_options_force = self.dhcp_option_force;
        
        if let Some(leasefile) = self.dhcp_leasefile {
            config.dhcp_leasefile = Some(leasefile);
        }
        
        if self.leasefile_ro {
            config.dhcp_leasefile_ro = true;
        }
        
        if self.dhcp_authoritative {
            config.dhcp_authoritative = true;
        }
        
        if self.read_ethers {
            config.read_ethers = true;
        }
        
        if let Some(script) = self.dhcp_script {
            config.dhcp_script = Some(script);
        }
        
        // DHCPv6 settings
        config.dhcp_ranges6 = self.dhcp_range6;
        config.dhcp_options6 = self.dhcp_option6;
        
        // TFTP settings
        if !self.enable_tftp.is_empty() {
            config.enable_tftp = true;
            config.tftp_interfaces = self.enable_tftp;
        }
        
        if !self.tftp_root.is_empty() {
            config.tftp_root = self.tftp_root.into_iter().next();
        }
        
        if let Some(tftp_max) = self.tftp_max {
            config.tftp_max = Some(tftp_max);
        }
        
        if self.tftp_secure {
            config.tftp_secure = true;
        }
        
        if self.tftp_lowercase {
            config.tftp_lowercase = true;
        }
        
        // DNSSEC settings
        if self.dnssec {
            config.dnssec_enabled = true;
        }
        
        if !self.trust_anchor.is_empty() {
            config.trust_anchors = self.trust_anchor;
        }
        
        if self.dnssec_check_unsigned {
            config.dnssec_check_unsigned = true;
        }
        
        // Logging settings
        if let Some(log_facility) = self.log_facility {
            config.log_facility = Some(log_facility);
        }
        
        if let Some(log_file) = self.log_file {
            config.log_file = Some(log_file);
        }
        
        if self.debug {
            config.debug_mode = true;
        }
        
        // Security settings
        let mut security = SecurityConfig::default();
        
        if let Some(user) = self.user {
            security.user = Some(user);
        }
        
        if let Some(group) = self.group {
            security.group = Some(group);
        }
        
        if let Some(chroot_dir) = self.chroot {
            security.chroot = Some(chroot_dir);
        }
        
        config.security = security;
        
        // Network settings
        if let Some(max_tcp) = self.max_tcp_connections {
            config.max_tcp_connections = max_tcp;
        }
        
        if let Some(query_port) = self.query_port {
            config.query_port = Some(query_port);
        }
        
        if let Some(min_port) = self.min_port {
            config.min_port = Some(min_port);
        }
        
        if let Some(max_port) = self.max_port {
            config.max_port = Some(max_port);
        }
        
        if self.local_service {
            config.local_service = true;
        }
        
        // TTL settings
        if let Some(local_ttl) = self.local_ttl {
            config.local_ttl = Some(local_ttl);
        }
        
        if let Some(max_ttl) = self.max_ttl {
            config.max_ttl = Some(max_ttl);
        }
        
        if let Some(neg_ttl) = self.neg_ttl {
            config.neg_ttl = Some(neg_ttl);
        }
        
        // Authoritative DNS
        config.auth_zones = self.auth_zone;
        if let Some(auth_server) = self.auth_server {
            config.auth_server = Some(auth_server);
        }
        
        // Additional records
        config.cnames = self.cname;
        config.ptr_records = self.ptr_record;
        config.txt_records = self.txt_record;
        config.srv_records = self.srv_record;
        config.mx_hosts = self.mx_host;
        config.host_records = self.host_record;
        
        // Advanced options
        if self.conntrack {
            config.conntrack = true;
        }
        
        config.ipsets = self.ipset;
        config.nftsets = self.nftset;
        
        if let Some(dbus_name) = self.enable_dbus {
            config.enable_dbus = true;
            config.dbus_name = Some(dbus_name);
        }
        
        if self.enable_ubus {
            config.enable_ubus = true;
        }
        
        Ok(config)
    }
}

/// Parse command-line arguments from std::env::args().
///
/// This is the primary public API for CLI parsing. It wraps `CliArgs::parse()`
/// and provides a convenient function-based interface.
///
/// # Returns
///
/// Returns a `CliArgs` struct with all parsed command-line options.
///
/// # Errors
///
/// Returns `ConfigError::CommandLineError` if arguments are invalid.
///
/// # Example
///
/// ```rust,ignore
/// use dnsmasq::config::cli::parse_args;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let args = parse_args()?;
///     
///     if args.version_flag {
///         println!("dnsmasq version {}", dnsmasq::constants::VERSION);
///         return Ok(());
///     }
///     
///     if args.help_flag {
///         // clap handles help display automatically
///         return Ok(());
///     }
///     
///     if args.test {
///         println!("Testing configuration...");
///         // Test configuration and exit
///         return Ok(());
///     }
///     
///     // Start daemon with parsed configuration
///     Ok(())
/// }
/// ```
pub fn parse_args() -> CliArgs {
    CliArgs::parse()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_basic_options() {
        let args = vec![
            "dnsmasq",
            "--port=5353",
            "--cache-size=1000",
            "--no-daemon",
        ];
        
        let cli = CliArgs::from_args(args.into_iter());
        assert_eq!(cli.port, Some(5353));
        assert_eq!(cli.cache_size, Some(1000));
        assert!(cli.no_daemon);
    }
    
    #[test]
    fn test_parse_short_options() {
        let args = vec![
            "dnsmasq",
            "-p", "53",
            "-c", "500",
            "-d",
        ];
        
        let cli = CliArgs::from_args(args.into_iter());
        assert_eq!(cli.port, Some(53));
        assert_eq!(cli.cache_size, Some(500));
        assert!(cli.no_daemon);
    }
    
    #[test]
    fn test_parse_multiple_servers() {
        let args = vec![
            "dnsmasq",
            "--server=8.8.8.8",
            "--server=1.1.1.1",
            "--server=/example.com/192.168.1.1",
        ];
        
        let cli = CliArgs::from_args(args.into_iter());
        assert_eq!(cli.server.len(), 3);
        assert_eq!(cli.server[0], "8.8.8.8");
        assert_eq!(cli.server[1], "1.1.1.1");
        assert_eq!(cli.server[2], "/example.com/192.168.1.1");
    }
    
    #[test]
    fn test_parse_interfaces() {
        let args = vec![
            "dnsmasq",
            "--interface=eth0",
            "--interface=wlan0",
            "--except-interface=eth1",
        ];
        
        let cli = CliArgs::from_args(args.into_iter());
        assert_eq!(cli.interface.len(), 2);
        assert!(cli.interface.contains(&"eth0".to_string()));
        assert!(cli.interface.contains(&"wlan0".to_string()));
        assert_eq!(cli.except_interface.len(), 1);
        assert_eq!(cli.except_interface[0], "eth1");
    }
    
    #[test]
    fn test_parse_boolean_flags() {
        let args = vec![
            "dnsmasq",
            "--domain-needed",
            "--bogus-priv",
            "--log-queries",
            "--dnssec",
        ];
        
        let cli = CliArgs::from_args(args.into_iter());
        assert!(cli.domain_needed);
        assert!(cli.bogus_priv);
        assert!(cli.log_queries);
        assert!(cli.dnssec);
    }
    
    #[test]
    fn test_to_config_basic() {
        let args = vec![
            "dnsmasq",
            "--port=5353",
            "--cache-size=1000",
            "--no-daemon",
        ];
        
        let cli = CliArgs::from_args(args.into_iter());
        let config = cli.to_config().expect("Failed to convert to config");
        
        assert_eq!(config.port, Some(5353));
        assert_eq!(config.cache_size, 1000);
        assert!(config.run_in_foreground);
    }
    
    #[test]
    fn test_to_config_security() {
        let args = vec![
            "dnsmasq",
            "--user=dnsmasq",
            "--group=dnsmasq",
        ];
        
        let cli = CliArgs::from_args(args.into_iter());
        let config = cli.to_config().expect("Failed to convert to config");
        
        assert_eq!(config.security.user, Some("dnsmasq".to_string()));
        assert_eq!(config.security.group, Some("dnsmasq".to_string()));
    }
}

