// Copyright (c) 2000-2025 Simon Kelley
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

//! Performance metrics collection and reporting module
//!
//! This module provides operational visibility into DNS query processing, DHCP transactions,
//! cache behavior, and DNSSEC validation through comprehensive metrics collection.
//!
//! # Metric Categories
//!
//! - **DNS Cache Metrics**: Cache insertions, evictions, and memory management
//! - **DNS Query Metrics**: Forwarded queries, authoritative answers, local answers, stale responses
//! - **DNSSEC Validation Metrics**: Cryptographic operation high-water marks, signature failures
//! - **DHCPv4 Transaction Metrics**: DISCOVER, OFFER, REQUEST, ACK, NAK, DECLINE, RELEASE, INFORM
//! - **DHCPv6 Metrics**: Lease allocations and pruning for IPv6
//! - **Network Boot Metrics**: BOOTP and PXE transaction counts
//! - **Connection Metrics**: TCP connection establishment count
//!
//! # Design
//!
//! The metrics system uses simple counter increments for minimal performance overhead.
//! Atomic operations ensure thread-safe access while maintaining the single-threaded
//! architecture pattern. Metrics can be exported via D-Bus/UBus control interfaces or
//! cleared on demand for statistics collection periods.

use serde::Deserialize;
use serde_json::{to_string, to_value, Value};
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::sync::atomic::{AtomicU32, Ordering};

/// Metric type enumeration defining all collectible performance and operational metrics.
///
/// Each variant represents a specific operational event or state measurement tracked by dnsmasq.
/// The enum values maintain compatibility with the C implementation for potential FFI integration.
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::util::metrics::MetricType;
///
/// let metric = MetricType::DnsQueriesForwarded;
/// println!("Metric name: {}", metric);
/// // Output: dns_queries_forwarded
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[repr(u32)]
pub enum MetricType {
    /// DNS cache record successfully inserted into cache hash table.
    /// Tracks cache population rate and insertion throughput.
    DnsCacheInserted = 0,

    /// DNS cache record evicted from cache while still within TTL (live eviction).
    /// Indicates cache pressure when LRU eviction removes valid entries.
    DnsCacheLiveFreed = 1,

    /// DNS queries forwarded to upstream recursive DNS servers.
    /// Counts cache miss queries requiring upstream resolution.
    DnsQueriesForwarded = 2,

    /// DNS queries answered authoritatively from configured zones.
    /// Tracks authoritative DNS mode usage.
    DnsAuthAnswered = 3,

    /// DNS queries answered from local sources (/etc/hosts, static configuration).
    /// Includes responses from hosts file entries and manual address records.
    DnsLocalAnswered = 4,

    /// DNS queries answered with stale cache entries beyond original TTL.
    /// Indicates serve-stale functionality providing expired cached responses.
    DnsStaleAnswered = 5,

    /// DNS queries that could not be answered (NXDOMAIN or timeout).
    /// Tracks failed resolution attempts including upstream timeouts.
    DnsUnanswered = 6,

    /// DNSSEC cryptographic operations high-water mark (maximum observed).
    /// Tracks peak crypto operations during DNSSEC validation chains.
    CryptoHwm = 7,

    /// DNSSEC signature verification failures high-water mark.
    /// Maximum signature failures observed in single validation chain.
    SigFailHwm = 8,

    /// DNSSEC validation work operations high-water mark.
    /// Maximum queries required for single DNSSEC validation chain.
    WorkHwm = 9,

    /// BOOTP protocol requests processed.
    /// Counts legacy BOOTP (pre-DHCP) network boot requests.
    Bootp = 10,

    /// PXE (Preboot Execution Environment) boot requests processed.
    /// Tracks network boot via PXE protocol.
    Pxe = 11,

    /// `DHCPv4` ACK messages sent (address assignment confirmation).
    /// Successful DHCP lease grants completing the four-way handshake.
    DhcpAck = 12,

    /// `DHCPv4` DECLINE messages received from clients.
    /// Client detected IP address conflict via ARP and declined offered address.
    DhcpDecline = 13,

    /// `DHCPv4` DISCOVER messages received (initial address request).
    /// First phase of DHCP four-way handshake.
    DhcpDiscover = 14,

    /// `DHCPv4` INFORM messages received (configuration without address).
    /// Client has static IP but requests DHCP configuration options only.
    DhcpInform = 15,

    /// `DHCPv4` NAK messages sent (address assignment rejection).
    /// Server rejects client REQUEST (wrong network, expired lease, etc.).
    DhcpNak = 16,

    /// `DHCPv4` OFFER messages sent (address offer to client).
    /// Second phase of DHCP handshake offering available address.
    DhcpOffer = 17,

    /// `DHCPv4` RELEASE messages received (client relinquishes lease).
    /// Client explicitly releases IP address before lease expiration.
    DhcpRelease = 18,

    /// `DHCPv4` REQUEST messages received (address request/renewal).
    /// Third phase of DHCP handshake or lease renewal request.
    DhcpRequest = 19,

    /// Queries with no answer available (distinct from NXDOMAIN).
    /// Tracks queries that daemon cannot answer due to configuration or policy.
    Noanswer = 20,

    /// `DHCPv4` leases allocated from dynamic address pools.
    /// Counts successful IPv4 address assignments (dynamic leases only).
    LeasesAllocated4 = 21,

    /// `DHCPv4` leases expired and pruned from lease database.
    /// Lease expiration cleanup and memory reclamation for IPv4.
    LeasesPruned4 = 22,

    /// `DHCPv6` leases allocated from IPv6 address pools.
    /// Counts successful IPv6 address assignments (stateful `DHCPv6`).
    LeasesAllocated6 = 23,

    /// `DHCPv6` leases expired and pruned from lease database.
    /// Lease expiration cleanup and memory reclamation for IPv6.
    LeasesPruned6 = 24,

    /// TCP connections established for DNS-over-TCP queries.
    /// Tracks TCP query volume (large responses, zone transfers, DNSSEC).
    TcpConnections = 25,

    /// `DHCPv4` LEASEQUERY requests received (RFC 4388).
    /// External systems querying lease information by IP or MAC address.
    DhcpLeasequery = 26,

    /// `DHCPv4` LEASEQUERY responses: lease unassigned (IP not in pool).
    /// LEASEQUERY query for IP address not within configured DHCP ranges.
    DhcpLeaseUnassigned = 27,

    /// `DHCPv4` LEASEQUERY responses: lease active (IP currently leased).
    /// LEASEQUERY query returned active lease information.
    DhcpLeaseActive = 28,

    /// `DHCPv4` LEASEQUERY responses: lease unknown (no record found).
    /// LEASEQUERY query for IP/MAC with no matching lease database entry.
    DhcpLeaseUnknown = 29,
}

impl Display for MetricType {
    /// Formats the metric type as a human-readable string identifier.
    ///
    /// Returns lowercase identifiers with underscores, matching the C implementation's
    /// `metric_names` array format. These names are used for logging, export via control
    /// interfaces (D-Bus, `UBus`), and administrative display.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::util::metrics::MetricType;
    ///
    /// assert_eq!(format!("{}", MetricType::DnsQueriesForwarded), "dns_queries_forwarded");
    /// assert_eq!(format!("{}", MetricType::DhcpAck), "dhcp_ack");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            MetricType::DnsCacheInserted => "dns_cache_inserted",
            MetricType::DnsCacheLiveFreed => "dns_cache_live_freed",
            MetricType::DnsQueriesForwarded => "dns_queries_forwarded",
            MetricType::DnsAuthAnswered => "dns_auth_answered",
            MetricType::DnsLocalAnswered => "dns_local_answered",
            MetricType::DnsStaleAnswered => "dns_stale_answered",
            MetricType::DnsUnanswered => "dns_unanswered",
            MetricType::CryptoHwm => "dnssec_max_crypto_use",
            MetricType::SigFailHwm => "dnssec_max_sig_fail",
            MetricType::WorkHwm => "dnssec_max_work",
            MetricType::Bootp => "bootp",
            MetricType::Pxe => "pxe",
            MetricType::DhcpAck => "dhcp_ack",
            MetricType::DhcpDecline => "dhcp_decline",
            MetricType::DhcpDiscover => "dhcp_discover",
            MetricType::DhcpInform => "dhcp_inform",
            MetricType::DhcpNak => "dhcp_nak",
            MetricType::DhcpOffer => "dhcp_offer",
            MetricType::DhcpRelease => "dhcp_release",
            MetricType::DhcpRequest => "dhcp_request",
            MetricType::Noanswer => "noanswer",
            MetricType::LeasesAllocated4 => "leases_allocated_4",
            MetricType::LeasesPruned4 => "leases_pruned_4",
            MetricType::LeasesAllocated6 => "leases_allocated_6",
            MetricType::LeasesPruned6 => "leases_pruned_6",
            MetricType::TcpConnections => "tcp_connections",
            MetricType::DhcpLeasequery => "dhcp_leasequery",
            MetricType::DhcpLeaseUnassigned => "dhcp_lease_unassigned",
            MetricType::DhcpLeaseActive => "dhcp_lease_actve", // Note: typo preserved from C for compatibility
            MetricType::DhcpLeaseUnknown => "dhcp_lease_unknown",
        };
        write!(f, "{name}")
    }
}

impl MetricType {
    /// Returns an iterator over all metric types in order.
    ///
    /// This is useful for enumerating all metrics when exporting statistics
    /// or performing bulk operations.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::util::metrics::MetricType;
    ///
    /// for metric_type in MetricType::all() {
    ///     println!("{}: enabled", metric_type);
    /// }
    /// ```
    pub fn all() -> impl Iterator<Item = MetricType> {
        [
            MetricType::DnsCacheInserted,
            MetricType::DnsCacheLiveFreed,
            MetricType::DnsQueriesForwarded,
            MetricType::DnsAuthAnswered,
            MetricType::DnsLocalAnswered,
            MetricType::DnsStaleAnswered,
            MetricType::DnsUnanswered,
            MetricType::CryptoHwm,
            MetricType::SigFailHwm,
            MetricType::WorkHwm,
            MetricType::Bootp,
            MetricType::Pxe,
            MetricType::DhcpAck,
            MetricType::DhcpDecline,
            MetricType::DhcpDiscover,
            MetricType::DhcpInform,
            MetricType::DhcpNak,
            MetricType::DhcpOffer,
            MetricType::DhcpRelease,
            MetricType::DhcpRequest,
            MetricType::Noanswer,
            MetricType::LeasesAllocated4,
            MetricType::LeasesPruned4,
            MetricType::LeasesAllocated6,
            MetricType::LeasesPruned6,
            MetricType::TcpConnections,
            MetricType::DhcpLeasequery,
            MetricType::DhcpLeaseUnassigned,
            MetricType::DhcpLeaseActive,
            MetricType::DhcpLeaseUnknown,
        ]
        .into_iter()
    }
}

/// Metrics collector for tracking operational statistics.
///
/// Provides thread-safe counter management for all dnsmasq operational metrics.
/// Uses atomic operations for lock-free increments while maintaining compatibility
/// with single-threaded architecture assumptions.
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::util::metrics::{MetricsCollector, MetricType};
///
/// let collector = MetricsCollector::new();
/// collector.increment(MetricType::DnsQueriesForwarded);
///
/// let count = collector.get_metric(MetricType::DnsQueriesForwarded);
/// assert_eq!(count, 1);
///
/// let json = collector.to_json().expect("Failed to serialize metrics");
/// println!("Metrics: {}", json);
/// ```
pub struct MetricsCollector {
    /// Metric counters stored as atomic u32 values for thread-safe access.
    metrics: HashMap<MetricType, AtomicU32>,
}

impl MetricsCollector {
    /// Creates a new metrics collector with all counters initialized to zero.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::util::metrics::MetricsCollector;
    ///
    /// let collector = MetricsCollector::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        let mut metrics = HashMap::new();

        for metric_type in MetricType::all() {
            metrics.insert(metric_type, AtomicU32::new(0));
        }

        Self { metrics }
    }

    /// Increments the specified metric counter by one.
    ///
    /// Uses atomic relaxed ordering for minimal overhead. This is safe because
    /// dnsmasq operates in a single-threaded event loop, and the atomic operation
    /// only provides safety for potential future concurrent access scenarios.
    ///
    /// # Arguments
    ///
    /// * `metric_type` - The metric to increment
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::util::metrics::{MetricsCollector, MetricType};
    ///
    /// let collector = MetricsCollector::new();
    /// collector.increment(MetricType::DnsQueriesForwarded);
    /// collector.increment(MetricType::DnsQueriesForwarded);
    /// assert_eq!(collector.get_metric(MetricType::DnsQueriesForwarded), 2);
    /// ```
    pub fn increment(&self, metric_type: MetricType) {
        if let Some(counter) = self.metrics.get(&metric_type) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Retrieves the current value of the specified metric counter.
    ///
    /// # Arguments
    ///
    /// * `metric_type` - The metric to query
    ///
    /// # Returns
    ///
    /// The current counter value, or 0 if the metric type is not found
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::util::metrics::{MetricsCollector, MetricType};
    ///
    /// let collector = MetricsCollector::new();
    /// assert_eq!(collector.get_metric(MetricType::DnsQueriesForwarded), 0);
    /// ```
    #[must_use]
    pub fn get_metric(&self, metric_type: MetricType) -> u32 {
        self.metrics.get(&metric_type).map_or(0, |counter| counter.load(Ordering::Relaxed))
    }

    /// Resets all metric counters to zero.
    ///
    /// This operation is typically performed during daemon initialization,
    /// configuration reload, or when starting a new statistics collection period.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::util::metrics::{MetricsCollector, MetricType};
    ///
    /// let collector = MetricsCollector::new();
    /// collector.increment(MetricType::DnsQueriesForwarded);
    /// collector.clear_metrics();
    /// assert_eq!(collector.get_metric(MetricType::DnsQueriesForwarded), 0);
    /// ```
    pub fn clear_metrics(&self) {
        for counter in self.metrics.values() {
            counter.store(0, Ordering::Relaxed);
        }
    }

    /// Retrieves all metric values as a `HashMap`.
    ///
    /// Returns a snapshot of all metric counters at the time of the call.
    /// The returned `HashMap` maps metric types to their current counter values.
    ///
    /// # Returns
    ///
    /// `HashMap` containing all metric types and their current values
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::util::metrics::{MetricsCollector, MetricType};
    ///
    /// let collector = MetricsCollector::new();
    /// collector.increment(MetricType::DnsQueriesForwarded);
    ///
    /// let all_metrics = collector.get_all_metrics();
    /// assert_eq!(all_metrics.get(&MetricType::DnsQueriesForwarded), Some(&1));
    /// ```
    #[must_use]
    pub fn get_all_metrics(&self) -> HashMap<MetricType, u32> {
        self.metrics.iter().map(|(k, v)| (*k, v.load(Ordering::Relaxed))).collect()
    }

    /// Exports metrics as a JSON string.
    ///
    /// Converts all metric counters to a JSON object with metric names as keys
    /// and counter values as values. This format is suitable for D-Bus/UBus
    /// control interface responses and integration with monitoring systems.
    ///
    /// # Returns
    ///
    /// Result containing JSON string representation of all metrics, or error
    /// if serialization fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::util::metrics::{MetricsCollector, MetricType};
    ///
    /// let collector = MetricsCollector::new();
    /// collector.increment(MetricType::DnsQueriesForwarded);
    ///
    /// let json = collector.to_json().expect("Failed to serialize");
    /// assert!(json.contains("dns_queries_forwarded"));
    /// ```
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let mut json_map = serde_json::Map::new();

        for (metric_type, counter) in &self.metrics {
            let name = format!("{metric_type}");
            let value = counter.load(Ordering::Relaxed);
            json_map.insert(name, to_value(value)?);
        }

        to_string(&Value::Object(json_map))
    }

    /// Clears per-upstream-server statistics.
    ///
    /// In the C implementation, this function iterates through the upstream server list
    /// and resets query counters, failure counts, retry counts, NXDOMAIN replies, and
    /// query latency metrics for each server.
    ///
    /// In this Rust implementation, server-specific statistics are tracked separately
    /// in the upstream server management module. This method serves as a placeholder
    /// to maintain API compatibility and may invoke server statistics reset through
    /// the appropriate service layer when integrated with the full dnsmasq architecture.
    ///
    /// # Note
    ///
    /// This method currently has no effect as server-specific statistics are managed
    /// by the upstream server module. When integrating with the complete dnsmasq
    /// runtime, this should delegate to the appropriate server statistics manager.
    pub fn clear_server_stats(&self) {
        // Server-specific statistics (queries, failed_queries, retries, nxdomain_replies,
        // query_latency) are managed by the upstream server module (dns/upstream.rs).
        // This method is provided for API compatibility with the C implementation.
        //
        // In a complete integration, this would delegate to:
        // upstream_manager.clear_all_server_stats();
        //
        // Since we don't have access to the upstream manager here, this is a no-op.
        // The actual clearing happens when the upstream manager's clear_metrics is called.
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Retrieves the human-readable name for a specific metric type.
///
/// This function provides compatibility with the C implementation's `get_metric_name()`
/// function, returning string labels for metric identifiers.
///
/// # Arguments
///
/// * `metric_type` - The metric type to get the name for
///
/// # Returns
///
/// String slice containing the metric name
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::util::metrics::{get_metric_name, MetricType};
///
/// let name = get_metric_name(MetricType::DnsQueriesForwarded);
/// assert_eq!(name, "dns_queries_forwarded");
/// ```
#[must_use]
pub fn get_metric_name(metric_type: MetricType) -> &'static str {
    match metric_type {
        MetricType::DnsCacheInserted => "dns_cache_inserted",
        MetricType::DnsCacheLiveFreed => "dns_cache_live_freed",
        MetricType::DnsQueriesForwarded => "dns_queries_forwarded",
        MetricType::DnsAuthAnswered => "dns_auth_answered",
        MetricType::DnsLocalAnswered => "dns_local_answered",
        MetricType::DnsStaleAnswered => "dns_stale_answered",
        MetricType::DnsUnanswered => "dns_unanswered",
        MetricType::CryptoHwm => "dnssec_max_crypto_use",
        MetricType::SigFailHwm => "dnssec_max_sig_fail",
        MetricType::WorkHwm => "dnssec_max_work",
        MetricType::Bootp => "bootp",
        MetricType::Pxe => "pxe",
        MetricType::DhcpAck => "dhcp_ack",
        MetricType::DhcpDecline => "dhcp_decline",
        MetricType::DhcpDiscover => "dhcp_discover",
        MetricType::DhcpInform => "dhcp_inform",
        MetricType::DhcpNak => "dhcp_nak",
        MetricType::DhcpOffer => "dhcp_offer",
        MetricType::DhcpRelease => "dhcp_release",
        MetricType::DhcpRequest => "dhcp_request",
        MetricType::Noanswer => "noanswer",
        MetricType::LeasesAllocated4 => "leases_allocated_4",
        MetricType::LeasesPruned4 => "leases_pruned_4",
        MetricType::LeasesAllocated6 => "leases_allocated_6",
        MetricType::LeasesPruned6 => "leases_pruned_6",
        MetricType::TcpConnections => "tcp_connections",
        MetricType::DhcpLeasequery => "dhcp_leasequery",
        MetricType::DhcpLeaseUnassigned => "dhcp_lease_unassigned",
        MetricType::DhcpLeaseActive => "dhcp_lease_actve", // Note: typo preserved from C
        MetricType::DhcpLeaseUnknown => "dhcp_lease_unknown",
    }
}

/// Resets all performance metrics to zero.
///
/// This function provides a standalone way to clear all metric counters, typically
/// invoked during daemon initialization, configuration reload, or administrative reset
/// via control interfaces (D-Bus, `UBus`).
///
/// # Arguments
///
/// * `collector` - Reference to the metrics collector to clear
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::util::metrics::{clear_metrics, MetricsCollector, MetricType};
///
/// let collector = MetricsCollector::new();
/// collector.increment(MetricType::DnsQueriesForwarded);
/// clear_metrics(&collector);
/// assert_eq!(collector.get_metric(MetricType::DnsQueriesForwarded), 0);
/// ```
pub fn clear_metrics(collector: &MetricsCollector) {
    collector.clear_metrics();
    collector.clear_server_stats();
}

/// Reports all metrics to standard output in human-readable format.
///
/// This function iterates through all metrics and prints their names and values.
/// It's useful for diagnostic output, logging, and administrative inspection of
/// system statistics.
///
/// # Arguments
///
/// * `collector` - Reference to the metrics collector to report
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::util::metrics::{report_all, MetricsCollector, MetricType};
///
/// let collector = MetricsCollector::new();
/// collector.increment(MetricType::DnsQueriesForwarded);
/// report_all(&collector);
/// // Output:
/// // dns_queries_forwarded: 1
/// // dns_cache_inserted: 0
/// // ...
/// ```
pub fn report_all(collector: &MetricsCollector) {
    for metric_type in MetricType::all() {
        let value = collector.get_metric(metric_type);
        println!("{metric_type}: {value}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_type_display() {
        assert_eq!(format!("{}", MetricType::DnsQueriesForwarded), "dns_queries_forwarded");
        assert_eq!(format!("{}", MetricType::DhcpAck), "dhcp_ack");
        assert_eq!(format!("{}", MetricType::LeasesAllocated4), "leases_allocated_4");
    }

    #[test]
    fn test_get_metric_name() {
        assert_eq!(get_metric_name(MetricType::DnsQueriesForwarded), "dns_queries_forwarded");
        assert_eq!(get_metric_name(MetricType::DhcpAck), "dhcp_ack");
    }

    #[test]
    fn test_metrics_collector_new() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.get_metric(MetricType::DnsQueriesForwarded), 0);
        assert_eq!(collector.get_metric(MetricType::DhcpAck), 0);
    }

    #[test]
    fn test_metrics_collector_increment() {
        let collector = MetricsCollector::new();

        collector.increment(MetricType::DnsQueriesForwarded);
        assert_eq!(collector.get_metric(MetricType::DnsQueriesForwarded), 1);

        collector.increment(MetricType::DnsQueriesForwarded);
        assert_eq!(collector.get_metric(MetricType::DnsQueriesForwarded), 2);

        collector.increment(MetricType::DhcpAck);
        assert_eq!(collector.get_metric(MetricType::DhcpAck), 1);
    }

    #[test]
    fn test_metrics_collector_clear() {
        let collector = MetricsCollector::new();

        collector.increment(MetricType::DnsQueriesForwarded);
        collector.increment(MetricType::DhcpAck);

        collector.clear_metrics();

        assert_eq!(collector.get_metric(MetricType::DnsQueriesForwarded), 0);
        assert_eq!(collector.get_metric(MetricType::DhcpAck), 0);
    }

    #[test]
    fn test_metrics_collector_get_all() {
        let collector = MetricsCollector::new();

        collector.increment(MetricType::DnsQueriesForwarded);
        collector.increment(MetricType::DhcpAck);

        let all_metrics = collector.get_all_metrics();
        assert_eq!(all_metrics.get(&MetricType::DnsQueriesForwarded), Some(&1));
        assert_eq!(all_metrics.get(&MetricType::DhcpAck), Some(&1));
        assert_eq!(all_metrics.get(&MetricType::DnsCacheInserted), Some(&0));
    }

    #[test]
    fn test_metrics_collector_to_json() {
        let collector = MetricsCollector::new();

        collector.increment(MetricType::DnsQueriesForwarded);
        collector.increment(MetricType::DhcpAck);

        let json = collector.to_json().expect("Failed to serialize to JSON");

        assert!(json.contains("dns_queries_forwarded"));
        assert!(json.contains("dhcp_ack"));
    }

    #[test]
    fn test_clear_metrics_function() {
        let collector = MetricsCollector::new();

        collector.increment(MetricType::DnsQueriesForwarded);
        clear_metrics(&collector);

        assert_eq!(collector.get_metric(MetricType::DnsQueriesForwarded), 0);
    }

    #[test]
    fn test_metric_type_all() {
        let all_types: Vec<MetricType> = MetricType::all().collect();
        assert_eq!(all_types.len(), 30);
        assert_eq!(all_types[0], MetricType::DnsCacheInserted);
        assert_eq!(all_types[29], MetricType::DhcpLeaseUnknown);
    }
}
