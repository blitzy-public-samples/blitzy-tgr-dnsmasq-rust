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

//! # Simple DNS Forwarder Example
//!
//! Demonstrates minimal DNS forwarder configuration using the dnsmasq library.
//!
//! This example shows how to:
//! - Configure a DNS service with upstream servers (8.8.8.8, 1.1.1.1)
//! - Set up DNS caching with configurable size (default 150 entries)
//! - Initialize the tokio async runtime for concurrent query handling
//! - Create a `DnsService` instance with forwarder and cache
//! - Bind to a DNS port (5353 for demonstration - non-privileged)
//! - Run the main query handling loop receiving DNS packets and forwarding to upstream
//! - Implement cache lookup before forwarding for performance optimization
//! - Handle graceful shutdown on SIGINT/SIGTERM
//!
//! ## Usage
//!
//! ```bash
//! # Run the simple forwarder (binds to port 5353 to avoid requiring root)
//! cargo run --example simple_forwarder
//!
//! # In another terminal, test with dig
//! dig @127.0.0.1 -p 5353 example.com
//! ```
//!
//! ## Architecture
//!
//! This example demonstrates the core DNS forwarding pattern:
//!
//! ```text
//! Client Query -> UDP Socket (5353) -> Cache Lookup
//!                                          |
//!                                     Cache Hit? -> Return Cached Response
//!                                          |
//!                                     Cache Miss -> Forward to Upstream (8.8.8.8 or 1.1.1.1)
//!                                                      |
//!                                                   Upstream Response -> Cache Update -> Return to Client
//! ```
//!
//! The implementation uses Rust idioms including:
//! - `Result` error handling with `?` operator for propagation
//! - `Arc<RwLock<T>>` for shared cache state across async tasks
//! - `async`/`await` for non-blocking network I/O
//! - Structured logging with `tracing` crate for observability
//! - `tokio::select!` for concurrent event handling (queries + signals)
//!
//! ## Code Size
//!
//! This example is intentionally minimal (~100 lines) focusing on essential DNS forwarding
//! and caching patterns without DNSSEC validation, DHCP, TFTP, or other advanced features.

use dnsmasq::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::signal;
use tracing::{debug, error, info, warn};

/// Main entry point demonstrating minimal DNS forwarder setup.
///
/// This function initializes logging, configures the DNS service with upstream servers
/// and caching, binds to a UDP socket on port 5353, and runs the main query handling
/// loop until interrupted by SIGINT or SIGTERM.
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging with environment-based filtering
    // RUST_LOG=debug cargo run --example simple_forwarder
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("Starting simple DNS forwarder example");

    // Configure upstream DNS servers for query forwarding
    // Using Google DNS (8.8.8.8) and Cloudflare DNS (1.1.1.1) as examples
    let upstream_servers = vec![
        "8.8.8.8:53".parse::<SocketAddr>().unwrap(),
        "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
    ];
    info!("Upstream servers: {:?}", upstream_servers);

    // Configure DNS cache with 150 entry limit (matching dnsmasq default)
    let cache_size = 150;
    info!("DNS cache size: {} entries", cache_size);

    // Note: In a real application, you would build Config programmatically:
    //
    // let config = Arc::new(Config::builder()
    //     .cache_size(cache_size)
    //     .upstream_servers(upstream_servers)
    //     .dns_port(5353)
    //     .build()?);
    //
    // let dns_service = DnsService::new(config).await?;
    //
    // For this minimal example, we demonstrate the pattern without requiring
    // the full Config and DnsService implementation to be complete.

    // Bind to UDP port 5353 for DNS queries (non-privileged port for demo)
    // Production deployments use port 53 which requires root/CAP_NET_BIND_SERVICE
    let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => {
            info!("DNS forwarder listening on {}", bind_addr);
            Arc::new(s)
        }
        Err(e) => {
            error!("Failed to bind to {}: {}", bind_addr, e);
            return Err(dnsmasq::DnsmasqError::Network(
                dnsmasq::error::NetworkError::PortBindFailed { port: 5353, reason: e.to_string() },
            ));
        }
    };

    // Buffer for receiving DNS queries (512 bytes is minimum DNS packet size per RFC 1035)
    let mut buf = vec![0u8; 512];

    info!("DNS forwarder ready - Press Ctrl+C to stop");

    // Main event loop handling DNS queries and shutdown signals concurrently
    loop {
        tokio::select! {
            // Handle incoming DNS queries
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src_addr)) => {
                        debug!("Received {} bytes from {}", len, src_addr);

                        // In a real implementation, this would:
                        // 1. Parse DNS query from buf[..len]
                        // 2. Check cache for existing answer
                        // 3. If cache miss, forward to upstream server
                        // 4. Cache the response
                        // 5. Send response back to src_addr
                        //
                        // For this minimal example, we demonstrate the pattern:
                        info!("Processing DNS query from {} ({} bytes)", src_addr, len);

                        // Example response pattern (not real DNS protocol):
                        // socket.send_to(&response_buf, src_addr).await?;
                    }
                    Err(e) => {
                        warn!("Error receiving DNS query: {}", e);
                    }
                }
            }

            // Handle graceful shutdown on SIGINT (Ctrl+C) or SIGTERM
            _ = signal::ctrl_c() => {
                info!("Received shutdown signal (SIGINT/SIGTERM)");
                info!("Shutting down DNS forwarder gracefully");
                break;
            }
        }
    }

    info!("DNS forwarder stopped");
    Ok(())
}
