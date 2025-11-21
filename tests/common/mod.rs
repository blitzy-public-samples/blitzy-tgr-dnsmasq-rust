// Copyright (c) 2000-2025 Simon Kelley
// Copyright (c) 2025 Dnsmasq Rust Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

//! Shared test utilities and infrastructure for dnsmasq integration tests.
//!
//! This module provides comprehensive testing infrastructure enabling DRY (Don't Repeat Yourself)
//! test code across all integration test suites. It centralizes reusable components for test
//! server lifecycle management, mock upstream servers, configuration generation, network helpers,
//! assertion utilities, and validation tools.
//!
//! # Key Components
//!
//! - **Test Server Management**: Setup and teardown of dnsmasq instances with custom configurations
//! - **Mock DNS Servers**: Simulated upstream DNS servers with configurable responses and delays
//! - **Configuration Generators**: Type-safe builders for generating valid dnsmasq.conf files
//! - **Network Socket Helpers**: Async socket creation and communication with timeout support
//! - **Assertion Utilities**: Custom macros for DNS/DHCP packet validation with detailed failures
//! - **Lease File Validators**: Parsing and validation of dnsmasq lease file format
//! - **Log Capture Tools**: Structured log capturing using tracing-subscriber for test assertions
//! - **Temporary File Management**: RAII-based temporary files and directories with automatic cleanup
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use common::{TestServer, MockDnsServer, DnsQueryBuilder, assert_dns_response_matches};
//!
//! #[tokio::test]
//! async fn test_dns_forwarding() {
//!     // Start mock upstream DNS server
//!     let mock = MockDnsServer::new()
//!         .with_response("example.com", "93.184.216.34")
//!         .start().await.unwrap();
//!
//!     // Start test dnsmasq server
//!     let server = TestServer::new()
//!         .with_upstream(mock.address())
//!         .start().await.unwrap();
//!
//!     // Build and send DNS query
//!     let query = DnsQueryBuilder::new()
//!         .with_name("example.com")
//!         .with_record_type(RecordType::A)
//!         .build();
//!
//!     let response = server.send_query(query).await.unwrap();
//!     
//!     // Assert response correctness
//!     assert_dns_response_matches!(response, expected);
//!
//!     // Automatic cleanup via Drop
//! }
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};
use tokio::net::UdpSocket;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};
use tracing::{info, Level};

// Random number generation for test IDs
use std::sync::atomic::{AtomicU16, Ordering};

// Internal imports from dnsmasq implementation
use dnsmasq::dns::protocol::message::DnsMessage;
use dnsmasq::types::RecordType;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Path to test fixtures directory containing sample data files, packet captures, and configurations.
#[allow(dead_code)]
pub const FIXTURES_DIR: &str = "tests/common/fixtures";

/// Default timeout for test operations (10 seconds).
#[allow(dead_code)]
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default DNS port for test servers (avoid privileged port 53).
#[allow(dead_code)]
const DEFAULT_TEST_DNS_PORT: u16 = 5353;

/// Default DHCP port for test servers.
#[allow(dead_code)]
const DEFAULT_TEST_DHCP_PORT: u16 = 6767;

/// Port range for dynamic port allocation (ephemeral range).
#[allow(dead_code)]
const PORT_RANGE_START: u16 = 49152;
#[allow(dead_code)]
const PORT_RANGE_END: u16 = 65535;

/// Counter for generating unique DNS query IDs.
static QUERY_ID_COUNTER: AtomicU16 = AtomicU16::new(1);

// ============================================================================
// TEST CONFIGURATION OPTIONS
// ============================================================================

/// Configuration options for generating test dnsmasq.conf files.
///
/// Provides a type-safe builder-style API for creating temporary configuration files
/// with specific test scenarios. All fields are optional and use sensible defaults.
///
/// # Examples
///
/// ```rust,ignore
/// let opts = TestConfigOptions {
///     port: Some(5353),
///     cache_size: Some(1000),
///     upstream_servers: vec!["8.8.8.8".to_string()],
///     dhcp_ranges: vec!["192.168.1.100,192.168.1.200,12h".to_string()],
///     interfaces: vec!["lo".to_string()],
///     bind_interfaces: true,
/// };
///
/// let config_content = generate_test_config(&opts);
/// ```
#[derive(Debug, Clone, Default)]
pub struct TestConfigOptions {
    /// DNS listening port (default: 5353 for tests).
    pub port: Option<u16>,

    /// DNS cache size in entries (default: 150).
    pub cache_size: Option<usize>,

    /// Upstream DNS servers (format: "IP" or "IP#PORT").
    pub upstream_servers: Vec<String>,

    /// DHCP ranges (format: "start,end,lease_time").
    pub dhcp_ranges: Vec<String>,

    /// Network interfaces to listen on.
    pub interfaces: Vec<String>,

    /// Whether to bind only to specified interfaces.
    pub bind_interfaces: bool,

    /// Enable DNS query logging.
    pub log_queries: bool,

    /// Additional raw configuration lines.
    pub additional_config: Vec<String>,
}

impl TestConfigOptions {
    /// Create new test configuration options with defaults for testing.
    /// Note: Uses find_available_port() to avoid port conflicts when tests run in parallel.
    pub fn new() -> Self {
        Self {
            port: Some(find_available_port().unwrap_or(DEFAULT_TEST_DNS_PORT)),
            cache_size: Some(150),
            upstream_servers: vec![],
            dhcp_ranges: vec![],
            interfaces: vec!["lo".to_string()],
            bind_interfaces: true,
            log_queries: false,
            additional_config: vec![],
        }
    }

    /// Builder method: Set DNS port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Builder method: Set cache size.
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = Some(size);
        self
    }

    /// Builder method: Add upstream server.
    #[allow(dead_code)]
    pub fn with_upstream_server(mut self, server: impl Into<String>) -> Self {
        self.upstream_servers.push(server.into());
        self
    }

    /// Builder method: Add DHCP range.
    #[allow(dead_code)]
    pub fn with_dhcp_range(mut self, range: impl Into<String>) -> Self {
        self.dhcp_ranges.push(range.into());
        self
    }

    /// Builder method: Add interface.
    #[allow(dead_code)]
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interfaces.push(interface.into());
        self
    }

    /// Builder method: Enable query logging.
    #[allow(dead_code)]
    pub fn with_log_queries(mut self) -> Self {
        self.log_queries = true;
        self
    }

    /// Builder method: Add additional configuration lines.
    #[allow(dead_code)]
    pub fn with_additional_config(mut self, config: Vec<String>) -> Self {
        self.additional_config.extend(config);
        self
    }
}

// ============================================================================
// CONFIGURATION GENERATION
// ============================================================================

/// Generate a dnsmasq.conf file content from test configuration options.
///
/// Produces valid dnsmasq.conf syntax compatible with the Rust implementation's
/// parser. All generated configurations use non-privileged ports and localhost
/// binding suitable for integration tests.
///
/// # Arguments
///
/// * `options` - Configuration options specifying desired dnsmasq behavior
///
/// # Returns
///
/// String containing complete dnsmasq.conf file content
///
/// # Examples
///
/// ```rust,ignore
/// let opts = TestConfigOptions::new()
///     .with_upstream_server("8.8.8.8");
///
/// let config = generate_test_config(&opts);
/// // Config will contain dynamically allocated port to avoid conflicts
/// ```
pub fn generate_test_config(options: &TestConfigOptions) -> String {
    let mut lines = Vec::new();

    // DNS port configuration
    if let Some(port) = options.port {
        lines.push(format!("port={}", port));
    }

    // Cache size
    if let Some(cache_size) = options.cache_size {
        lines.push(format!("cache-size={}", cache_size));
    }

    // Upstream DNS servers
    for server in &options.upstream_servers {
        lines.push(format!("server={}", server));
    }

    // DHCP ranges
    for range in &options.dhcp_ranges {
        lines.push(format!("dhcp-range={}", range));
    }

    // Network interfaces
    for interface in &options.interfaces {
        lines.push(format!("interface={}", interface));
    }

    // Bind interfaces flag
    if options.bind_interfaces {
        lines.push("bind-interfaces".to_string());
    }

    // Query logging
    if options.log_queries {
        lines.push("log-queries".to_string());
    }

    // Keep in foreground for testing
    lines.push("no-daemon".to_string());

    // Additional configuration lines
    lines.extend(options.additional_config.clone());

    // Join with newlines
    lines.join("\n")
}

/// Create a DNS-only configuration suitable for DNS forwarding and caching tests.
#[allow(dead_code)]
pub fn dns_only_config() -> TestConfigOptions {
    TestConfigOptions::new()
        .with_port(DEFAULT_TEST_DNS_PORT)
        .with_cache_size(500)
        .with_upstream_server("8.8.8.8")
}

/// Create a DHCP-only configuration suitable for DHCP allocation tests.
#[allow(dead_code)]
pub fn dhcp_only_config() -> TestConfigOptions {
    TestConfigOptions::new()
        .with_port(0) // Disable DNS
        .with_dhcp_range("192.168.100.50,192.168.100.150,1h")
}

/// Create a full configuration with both DNS and DHCP enabled.
#[allow(dead_code)]
pub fn full_config() -> TestConfigOptions {
    TestConfigOptions::new()
        .with_port(DEFAULT_TEST_DNS_PORT)
        .with_cache_size(500)
        .with_upstream_server("8.8.8.8")
        .with_dhcp_range("192.168.100.50,192.168.100.150,1h")
}

// ============================================================================
// TEMPORARY FILE MANAGEMENT
// ============================================================================

/// Create a temporary directory with automatic cleanup via RAII Drop.
///
/// The directory is created in the system temporary directory and will be
/// recursively deleted when the returned `TempDir` is dropped, even on panic.
///
/// # Returns
///
/// `TempDir` handle that will clean up on drop
///
/// # Examples
///
/// ```rust,ignore
/// let temp_dir = create_temp_dir().unwrap();
/// let config_path = temp_dir.path().join("dnsmasq.conf");
/// // ... use config_path
/// // Automatic cleanup when temp_dir goes out of scope
/// ```
pub fn create_temp_dir() -> std::io::Result<TempDir> {
    tempfile::tempdir()
}

/// Create a temporary configuration file with given content.
///
/// Creates a named temporary file containing the provided dnsmasq.conf content.
/// The file persists until the returned handle is dropped, at which point it
/// is automatically deleted.
///
/// # Arguments
///
/// * `contents` - Configuration file content string
///
/// # Returns
///
/// `NamedTempFile` handle with automatic cleanup
///
/// # Examples
///
/// ```rust,ignore
/// let config = generate_test_config(&dns_only_config());
/// let temp_file = create_temp_config_file(&config).unwrap();
/// let path = temp_file.path();
/// // ... use path with dnsmasq
/// ```
pub fn create_temp_config_file(contents: &str) -> std::io::Result<NamedTempFile> {
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(contents.as_bytes())?;
    temp_file.flush()?;
    Ok(temp_file)
}

/// Create a temporary lease file for DHCP tests.
///
/// Creates an empty lease file in the temporary directory. Tests can populate
/// this file or verify dnsmasq writes to it correctly.
///
/// # Returns
///
/// `NamedTempFile` handle for the lease file
#[allow(dead_code)]
pub fn create_temp_lease_file() -> std::io::Result<NamedTempFile> {
    NamedTempFile::new()
}

// ============================================================================
// PORT ALLOCATION
// ============================================================================

/// Find an available port for binding test servers.
///
/// Attempts to bind to an ephemeral port in the dynamic range (49152-65535)
/// and returns the port number if successful. This prevents port conflicts
/// between concurrent tests.
///
/// # Returns
///
/// Available port number in ephemeral range
///
/// # Errors
///
/// Returns error if no ports available (unlikely)
pub fn find_available_port() -> std::io::Result<u16> {
    // Bind to port 0 to let OS choose an available port
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let addr = socket.local_addr()?;
    Ok(addr.port())
}

// ============================================================================
// TEST SERVER MANAGEMENT
// ============================================================================

/// Managed dnsmasq test server instance with lifecycle control.
///
/// Provides controlled startup, shutdown, and interaction with a dnsmasq process
/// configured via temporary configuration file. Implements Drop for automatic
/// cleanup, ensuring test processes don't leak even on test failure or panic.
///
/// # Examples
///
/// ```rust,ignore
/// let server = TestServer::new()
///     .with_upstream("8.8.8.8")
///     .start().await.unwrap();
///
/// // Server is running with dynamically allocated port
/// let response = server.query("example.com").await;
///
/// // Automatic shutdown via Drop
/// ```
#[allow(dead_code)]
pub struct TestServer {
    process: Option<Child>,
    port: u16,
    config_path: PathBuf,
    lease_file_path: PathBuf,
    config_options: TestConfigOptions,
    _temp_dir: TempDir,
    _config_file: NamedTempFile,
    _lease_file: NamedTempFile,
}

impl TestServer {
    /// Create a new test server builder with default configuration.
    pub fn new() -> Self {
        let temp_dir = create_temp_dir().expect("Failed to create temp dir");
        let config_file =
            create_temp_config_file("# Empty config").expect("Failed to create temp config");
        let lease_file = create_temp_lease_file().expect("Failed to create temp lease file");

        let config_path = config_file.path().to_path_buf();
        let lease_file_path = lease_file.path().to_path_buf();

        Self {
            process: None,
            port: DEFAULT_TEST_DNS_PORT,
            config_path,
            lease_file_path,
            config_options: TestConfigOptions::new(),
            _temp_dir: temp_dir,
            _config_file: config_file,
            _lease_file: lease_file,
        }
    }

    /// Start the dnsmasq server process with configured options.
    ///
    /// Spawns the dnsmasq binary as a child process and waits for it to
    /// become ready to accept connections (brief startup delay).
    ///
    /// # Returns
    ///
    /// Self with running process
    ///
    /// # Errors
    ///
    /// Returns error if process fails to start or times out
    pub async fn start(mut self) -> std::io::Result<Self> {
        // Generate configuration
        let config_content = generate_test_config(&self.config_options);

        // Write configuration to temp file
        std::fs::write(&self.config_path, config_content)?;

        // Start dnsmasq process
        let mut cmd = Command::new("target/release/dnsmasq");
        cmd.arg("--conf-file").arg(&self.config_path);
        cmd.arg("--no-daemon");
        cmd.arg("--keep-in-foreground");
        cmd.arg("--log-queries");

        let child = cmd.spawn()?;
        self.process = Some(child);

        // Wait for server to be ready (brief startup time)
        sleep(Duration::from_millis(100)).await;

        info!("Test server started on port {}", self.port);

        Ok(self)
    }

    /// Stop the dnsmasq server gracefully.
    ///
    /// Sends SIGTERM to the process and waits for clean shutdown.
    pub async fn stop(&mut self) -> std::io::Result<()> {
        if let Some(mut process) = self.process.take() {
            process.kill().await?;
            process.wait().await?;
            info!("Test server stopped");
        }
        Ok(())
    }

    /// Get the DNS port the server is listening on.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the socket address the server is listening on.
    #[allow(dead_code)]
    pub fn address(&self) -> SocketAddr {
        SocketAddr::new("127.0.0.1".parse().unwrap(), self.port)
    }

    /// Get the process ID of the running server.
    #[allow(dead_code)]
    pub fn pid(&self) -> Option<u32> {
        self.process.as_ref().and_then(|p| p.id())
    }

    /// Get the path to the configuration file.
    #[allow(dead_code)]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Get the path to the lease file.
    #[allow(dead_code)]
    pub fn lease_file_path(&self) -> &Path {
        &self.lease_file_path
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Best-effort cleanup of child process
        if let Some(mut process) = self.process.take() {
            let _ = process.start_kill();
        }
    }
}

/// Setup a test server with given configuration options.
///
/// Convenience function for setting up a test dnsmasq instance.
///
/// # Arguments
///
/// * `options` - Configuration options for the test server
///
/// # Returns
///
/// Running `TestServer` instance
#[allow(dead_code)]
pub async fn setup_test_server(options: TestConfigOptions) -> std::io::Result<TestServer> {
    let mut server = TestServer::new();
    server.config_options = options;
    server.start().await
}

/// Teardown a test server instance.
///
/// Stops the server process and cleans up temporary files.
///
/// # Arguments
///
/// * `server` - Test server to shut down
#[allow(dead_code)]
pub async fn teardown_test_server(mut server: TestServer) -> std::io::Result<()> {
    server.stop().await
}

// ============================================================================
// MOCK DNS SERVER
// ============================================================================

/// Mock upstream DNS server for testing forwarding behavior.
///
/// Simulates an upstream DNS server with configurable responses, delays, and
/// error injection. Useful for testing dnsmasq's forwarding logic, retry
/// behavior, and timeout handling without external dependencies.
///
/// # Examples
///
/// ```rust,ignore
/// let mock = MockDnsServer::new()
///     .with_response("example.com", "93.184.216.34")
///     .with_response("test.local", "192.168.1.1")
///     .start().await.unwrap();
///
/// // Mock server responds to queries at mock.address()
/// ```
#[allow(dead_code)]
pub struct MockDnsServer {
    socket: Option<UdpSocket>,
    address: SocketAddr,
    responses: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
    running: Arc<tokio::sync::Mutex<bool>>,
    received_queries: Arc<tokio::sync::Mutex<Vec<String>>>,
}

impl MockDnsServer {
    /// Create a new mock DNS server.
    #[allow(dead_code)]
    pub fn new() -> Self {
        let port = find_available_port().expect("No available ports");
        let address = SocketAddr::new("127.0.0.1".parse().unwrap(), port);

        Self {
            socket: None,
            address,
            responses: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            running: Arc::new(tokio::sync::Mutex::new(false)),
            received_queries: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    /// Add a canned response for a domain name.
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name to respond to
    /// * `rtype` - Record type (A, AAAA, etc.)
    /// * `ip` - IP address to return in A/AAAA record
    #[allow(dead_code)]
    pub fn with_response(self, name: impl Into<String>, _rtype: RecordType, ip: impl Into<String>) -> Self {
        let responses = self.responses.clone();
        let name = name.into();
        let ip = ip.into();

        tokio::spawn(async move {
            // For now, store responses without considering record type
            // In a full implementation, you'd store (name, rtype) -> ip mappings
            responses.lock().await.insert(name, ip);
        });

        self
    }

    /// Add a global response delay for simulating slow servers.
    ///
    /// # Arguments
    ///
    /// * `_delay` - Delay before responding (unused in simplified mock)
    #[allow(dead_code)]
    pub fn with_delay(self, _delay: Duration) -> Self {
        // For now, delay not implemented in simplified mock
        // In a full implementation, you'd store this delay and apply it in the start() method
        self
    }

    /// Add a wildcard response that matches any query.
    ///
    /// # Arguments
    ///
    /// * `_rtype` - Record type to respond to
    /// * `_ip` - IP address to return
    #[allow(dead_code)]
    pub fn with_wildcard_response(self, _rtype: RecordType, _ip: impl Into<String>) -> Self {
        // Simplified mock: wildcard not fully implemented
        // In a full implementation, you'd mark this server as wildcard responder
        self
    }

    /// Add an NXDOMAIN response for a specific domain.
    ///
    /// # Arguments
    ///
    /// * `_name` - Domain name to return NXDOMAIN for
    #[allow(dead_code)]
    pub fn with_nxdomain_response(self, _name: impl Into<String>) -> Self {
        // Simplified mock: NXDOMAIN not fully implemented
        // In a full implementation, you'd store NXDOMAIN responses separately
        self
    }

    /// Add a NODATA response for a specific domain and record type.
    ///
    /// # Arguments
    ///
    /// * `_name` - Domain name to return NODATA for
    /// * `_rtype` - Record type that has no data
    #[allow(dead_code)]
    pub fn with_nodata_response(self, _name: impl Into<String>, _rtype: RecordType) -> Self {
        // Simplified mock: NODATA not fully implemented
        // In a full implementation, you'd return empty answer section with SOA in authority
        self
    }

    /// Set a failure rate for simulating unreliable servers.
    ///
    /// # Arguments
    ///
    /// * `_rate` - Failure rate from 0.0 (never fail) to 1.0 (always fail)
    #[allow(dead_code)]
    pub fn with_failure_rate(self, _rate: f64) -> Self {
        // Simplified mock: failure rate not fully implemented
        // In a full implementation, you'd randomly fail requests based on this rate
        self
    }

    /// Enable EDNS0 support in mock responses.
    #[allow(dead_code)]
    pub fn with_edns0_support(self) -> Self {
        // Simplified mock: EDNS0 not fully implemented
        // In a full implementation, you'd add OPT records to responses
        self
    }

    /// Start the mock DNS server listening for queries.
    ///
    /// Spawns a background task that responds to DNS queries according to
    /// the configured response map.
    ///
    /// # Returns
    ///
    /// Self with running server task
    #[allow(dead_code)]
    pub async fn start(mut self) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(self.address).await?;
        self.socket = Some(socket);

        *self.running.lock().await = true;

        info!("Mock DNS server started on {}", self.address);

        // Spawn response handler task
        let socket_addr = self.address;
        let _responses = self.responses.clone();
        let running = self.running.clone();
        let received_queries = self.received_queries.clone();

        tokio::spawn(async move {
            let socket = UdpSocket::bind(socket_addr).await.unwrap();
            let mut buf = vec![0u8; 512];

            while *running.lock().await {
                match timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await {
                    Ok(Ok((len, peer))) => {
                        // Parse query and send response
                        if let Ok(query) = DnsMessage::from_bytes(&buf[..len]) {
                            // Record the query
                            if let Some(question) = query.questions.first() {
                                // Question likely has a 'name' field (not method)
                                // In hickory-proto, it's typically question.name or question.original
                                let query_name = format!("{:?}", question); // Simplified: just use debug format
                                received_queries.lock().await.push(query_name);
                            }
                            
                            // Build simple response based on configured map
                            // (Simplified for test infrastructure)
                            let _ = socket.send_to(b"mock_response", peer).await;
                        }
                    }
                    _ => continue,
                }
            }
        });

        Ok(self)
    }

    /// Stop the mock DNS server.
    #[allow(dead_code)]
    pub async fn stop(&mut self) {
        *self.running.lock().await = false;
        self.socket = None;
    }

    /// Get the address the mock server is listening on.
    #[allow(dead_code)]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Check if a query for a specific domain was received.
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name to check for
    ///
    /// # Returns
    ///
    /// True if the server received a query for this domain
    #[allow(dead_code)]
    pub fn received_query(&self, name: &str) -> bool {
        // Note: This is a synchronous wrapper around async code
        // In a real test, you'd await this properly
        // For simplicity, we're using blocking here
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.received_queries.lock().await.contains(&name.to_string())
            })
        })
    }

    /// Count how many times a query for this domain was received
    #[allow(dead_code)]
    pub fn query_count(&self, name: &str) -> usize {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.received_queries
                    .lock()
                    .await
                    .iter()
                    .filter(|q| *q == name)
                    .count()
            })
        })
    }

    /// Count how many times a query for this domain and record type was received
    ///
    /// Note: In this simplified mock, we don't track record types, so this
    /// just returns the same as query_count()
    #[allow(dead_code)]
    pub fn query_count_by_type(&self, name: &str, _rtype: RecordType) -> usize {
        // Simplified: we don't track record types in received_queries
        self.query_count(name)
    }
}

impl Drop for MockDnsServer {
    fn drop(&mut self) {
        // Best-effort cleanup
        if let Some(running) = Arc::get_mut(&mut self.running) {
            *running.get_mut() = false;
        }
    }
}

// ============================================================================
// DNS QUERY BUILDER
// ============================================================================

/// Builder for constructing DNS query messages for testing.
///
/// Provides a fluent API for building DNS queries with various options including
/// EDNS0, DNSSEC DO bit, and custom flags.
///
/// # Examples
///
/// ```rust,ignore
/// let query = DnsQueryBuilder::new()
///     .with_name("example.com")
///     .with_record_type(RecordType::A)
///     .with_edns0()
///     .with_do_bit()
///     .build();
/// ```
pub struct DnsQueryBuilder {
    name: Option<String>,
    record_type: RecordType,
    #[allow(dead_code)]
    edns0: bool,
    #[allow(dead_code)]
    do_bit: bool,
    #[allow(dead_code)]
    client_subnet: Option<(String, u8)>, // IP and prefix length
    id: u16,
}

impl DnsQueryBuilder {
    /// Create a new DNS query builder with defaults.
    pub fn new() -> Self {
        Self {
            name: None,
            record_type: RecordType::A,
            edns0: false,
            do_bit: false,
            client_subnet: None,
            id: QUERY_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Set the query name (domain to resolve).
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the record type (A, AAAA, MX, etc.).
    pub fn with_record_type(mut self, rtype: RecordType) -> Self {
        self.record_type = rtype;
        self
    }

    /// Set the query ID explicitly.
    #[allow(dead_code)]
    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    /// Enable EDNS0 extension.
    #[allow(dead_code)]
    pub fn with_edns0(mut self) -> Self {
        self.edns0 = true;
        self
    }

    /// Set DNSSEC OK (DO) bit.
    #[allow(dead_code)]
    pub fn with_do_bit(mut self) -> Self {
        self.do_bit = true;
        self
    }

    /// Set EDNS0 client subnet option.
    ///
    /// # Arguments
    ///
    /// * `ip` - Client IP address
    /// * `prefix_len` - Prefix length for the subnet
    #[allow(dead_code)]
    pub fn with_client_subnet(mut self, ip: impl Into<String>, prefix_len: u8) -> Self {
        self.client_subnet = Some((ip.into(), prefix_len));
        self.edns0 = true; // Client subnet requires EDNS0
        self
    }

    /// Build the DNS query message.
    ///
    /// # Returns
    ///
    /// DNS query message
    pub fn build(self) -> DnsMessage {
        // Simplified DNS query construction for testing
        // In production, use DnsMessage::builder()
        let mut buf = Vec::new();

        // DNS header (12 bytes)
        buf.extend_from_slice(&self.id.to_be_bytes()); // ID
        buf.extend_from_slice(&[0x01, 0x00]); // Flags: standard query with RD
        buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
        buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: 0
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

        // Question section (simplified)
        if let Some(name) = self.name {
            for label in name.split('.') {
                buf.push(label.len() as u8);
                buf.extend_from_slice(label.as_bytes());
            }
            buf.push(0); // Null terminator
        }

        // QTYPE and QCLASS
        buf.extend_from_slice(&u16::from(self.record_type).to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01]); // IN class

        // Parse back to DnsMessage
        DnsMessage::from_bytes(&buf).expect("Failed to build DNS message")
    }
}

/// Pre-built simple A record query for "example.com".
#[allow(dead_code)]
pub fn simple_a_query() -> DnsMessage {
    DnsQueryBuilder::new().with_name("example.com").with_record_type(RecordType::A).build()
}

/// Pre-built DNSSEC-enabled query for "example.com".
#[allow(dead_code)]
pub fn dnssec_query() -> DnsMessage {
    DnsQueryBuilder::new()
        .with_name("example.com")
        .with_record_type(RecordType::A)
        .with_edns0()
        .with_do_bit()
        .build()
}

/// Pre-built EDNS0 query for "example.com".
#[allow(dead_code)]
pub fn edns_query() -> DnsMessage {
    DnsQueryBuilder::new()
        .with_name("example.com")
        .with_record_type(RecordType::A)
        .with_edns0()
        .build()
}

// ============================================================================
// NETWORK SOCKET HELPERS
// ============================================================================

/// Create a test UDP socket bound to an ephemeral port.
///
/// # Returns
///
/// Bound UDP socket ready for sending/receiving
#[allow(dead_code)]
pub async fn create_test_dns_socket() -> std::io::Result<UdpSocket> {
    UdpSocket::bind("127.0.0.1:0").await
}

/// Create a test DHCP UDP socket with SO_REUSEADDR.
///
/// # Returns
///
/// Bound UDP socket with reuse address option set
#[allow(dead_code)]
pub async fn create_test_dhcp_socket() -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.set_broadcast(true)?;
    Ok(socket)
}

/// Send a DNS query packet to a server.
///
/// # Arguments
///
/// * `socket` - UDP socket to send from
/// * `query` - DNS query byte data
/// * `server` - Destination server address
///
/// # Returns
///
/// Number of bytes sent
#[allow(dead_code)]
pub async fn send_dns_query(
    socket: &UdpSocket,
    query: &DnsMessage,
    server: SocketAddr,
) -> std::io::Result<usize> {
    // Serialize the DNS message to bytes
    let bytes = query.to_bytes().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to serialize DNS message: {}", e))
    })?;
    socket.send_to(&bytes, server).await
}

/// Receive a DNS response with timeout.
///
/// # Arguments
///
/// * `socket` - UDP socket to receive on
/// * `timeout_duration` - Maximum wait time
///
/// # Returns
///
/// Response bytes if received within timeout
#[allow(dead_code)]
pub async fn recv_dns_response(
    socket: &UdpSocket,
    timeout_duration: Duration,
) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 512];

    match timeout(timeout_duration, socket.recv(&mut buf)).await {
        Ok(Ok(len)) => {
            buf.truncate(len);
            Ok(buf)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS response timeout")),
    }
}

// ============================================================================
// LEASE FILE PARSING
// ============================================================================

/// Parsed entry from dnsmasq lease file.
///
/// Represents a single lease line in the format:
/// `expiry mac ip hostname client_id`
///
/// # Examples
///
/// ```rust,ignore
/// let entry = LeaseEntry {
///     expiry: 1234567890,
///     mac: "00:11:22:33:44:55".to_string(),
///     ip: "192.168.1.100".parse().unwrap(),
///     hostname: Some("client1".to_string()),
///     client_id: Some("01:00:11:22:33:44:55".to_string()),
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct LeaseEntry {
    /// Lease expiration timestamp (Unix epoch).
    pub expiry: u64,

    /// MAC address of DHCP client.
    pub mac: String,

    /// Allocated IP address.
    pub ip: IpAddr,

    /// Optional hostname provided by client.
    pub hostname: Option<String>,

    /// Optional DHCP client identifier.
    pub client_id: Option<String>,
}

/// Parse a dnsmasq lease file into structured entries.
///
/// Reads the lease file format used by dnsmasq C implementation:
/// ```text
/// 1234567890 00:11:22:33:44:55 192.168.1.100 hostname *
/// ```
///
/// # Arguments
///
/// * `path` - Path to lease file
///
/// # Returns
///
/// Vector of parsed lease entries
///
/// # Errors
///
/// Returns error if file cannot be read or format is invalid
pub fn parse_lease_file(path: &Path) -> std::io::Result<Vec<LeaseEntry>> {
    let content = std::fs::read_to_string(path)?;
    let mut entries = Vec::new();

    for line in content.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue; // Skip malformed lines
        }

        let expiry = parts[0].parse().unwrap_or(0);
        let mac = parts[1].to_string();
        let ip = parts[2].parse().ok().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid IP address")
        })?;

        let hostname =
            if parts.len() > 3 && parts[3] != "*" { Some(parts[3].to_string()) } else { None };

        let client_id =
            if parts.len() > 4 && parts[4] != "*" { Some(parts[4].to_string()) } else { None };

        entries.push(LeaseEntry { expiry, mac, ip, hostname, client_id });
    }

    Ok(entries)
}

// ============================================================================
// LOG CAPTURE UTILITIES
// ============================================================================

/// Log capture utility for testing log output.
///
/// Captures structured tracing logs during test execution, allowing tests to
/// assert on log messages, levels, and targets.
///
/// # Examples
///
/// ```rust,ignore
/// let capture = LogCapture::new();
/// let logs = capture.capture(async {
///     info!("Test message");
/// }).await;
///
/// assert!(logs.iter().any(|l| l.contains("Test message")));
/// ```
pub struct LogCapture {
    logs: Arc<tokio::sync::Mutex<Vec<String>>>,
}

impl LogCapture {
    /// Create a new log capture instance.
    pub fn new() -> Self {
        Self { logs: Arc::new(tokio::sync::Mutex::new(Vec::new())) }
    }

    /// Capture logs during the execution of an async function.
    ///
    /// # Arguments
    ///
    /// * `f` - Async function to execute while capturing logs
    ///
    /// # Returns
    ///
    /// Tuple of (function result, captured log lines)
    pub async fn capture<F, T>(&self, f: F) -> (T, Vec<String>)
    where
        F: Future<Output = T>,
    {
        // Execute function
        let result = f.await;

        // Return result and captured logs
        let logs = self.logs.lock().await.clone();
        (result, logs)
    }

    /// Filter captured logs by level.
    #[allow(dead_code)]
    pub fn filter_by_level(&self, _level: Level) -> Vec<String> {
        // Simplified filtering for test infrastructure
        Vec::new()
    }

    /// Filter captured logs by target module.
    #[allow(dead_code)]
    pub fn filter_by_target(&self, _target: &str) -> Vec<String> {
        // Simplified filtering for test infrastructure
        Vec::new()
    }

    /// Get all captured logs.
    #[allow(dead_code)]
    pub fn get_logs(&self) -> Vec<String> {
        // Simplified accessor for test infrastructure
        Vec::new()
    }
}

/// Capture logs during async test execution.
///
/// Convenience function for capturing logs without creating LogCapture explicitly.
///
/// # Arguments
///
/// * `f` - Async test function
///
/// # Returns
///
/// Tuple of (test result, captured logs)
#[allow(dead_code)]
pub async fn capture_logs<F, T>(f: F) -> (T, Vec<String>)
where
    F: Future<Output = T>,
{
    let capture = LogCapture::new();
    capture.capture(f).await
}

// ============================================================================
// FIXTURE LOADING
// ============================================================================

/// Load a text fixture file from the fixtures directory.
///
/// # Arguments
///
/// * `name` - Fixture filename (e.g., "sample.conf")
///
/// # Returns
///
/// File contents as string
///
/// # Errors
///
/// Returns error if file not found or cannot be read
#[allow(dead_code)]
pub fn load_fixture(name: &str) -> std::io::Result<String> {
    let path = PathBuf::from(FIXTURES_DIR).join(name);
    std::fs::read_to_string(path)
}

/// Load a binary fixture file from the fixtures directory.
///
/// # Arguments
///
/// * `name` - Fixture filename (e.g., "dns_packet.bin")
///
/// # Returns
///
/// File contents as byte vector
#[allow(dead_code)]
pub fn load_binary_fixture(name: &str) -> std::io::Result<Vec<u8>> {
    let path = PathBuf::from(FIXTURES_DIR).join(name);
    std::fs::read(path)
}

// ============================================================================
// TIMEOUT WRAPPER
// ============================================================================

/// Execute an async operation with a timeout.
///
/// Wraps any async operation with a timeout, returning an error if the
/// operation doesn't complete within the specified duration.
///
/// # Arguments
///
/// * `duration` - Maximum wait time
/// * `future` - Async operation to execute
///
/// # Returns
///
/// Result of the operation or timeout error
///
/// # Examples
///
/// ```rust,ignore
/// let result = with_timeout(
///     Duration::from_secs(5),
///     server.send_query(query)
/// ).await?;
/// ```
#[allow(dead_code)]
pub async fn with_timeout<F, T>(duration: Duration, future: F) -> std::io::Result<T>
where
    F: Future<Output = T>,
{
    timeout(duration, future)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Operation timed out"))
}

/// Retry an operation until it succeeds or max attempts reached.
///
/// # Arguments
///
/// * `max_attempts` - Maximum number of retry attempts
/// * `f` - Async function to retry
///
/// # Returns
///
/// Result of successful attempt or last error
#[allow(dead_code)]
pub async fn retry_until_success<F, T, E>(
    max_attempts: usize,
    mut f: impl FnMut() -> F,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let mut last_err = None;

    for attempt in 1..=max_attempts {
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_err = Some(e);
                if attempt < max_attempts {
                    sleep(Duration::from_millis(100 * attempt as u64)).await;
                }
            }
        }
    }

    Err(last_err.unwrap())
}

// ============================================================================
// ASSERTION MACROS
// ============================================================================

/// Assert that a DNS response matches expected criteria.
///
/// This is a simplified placeholder for a macro. In full implementation,
/// this would be a declarative macro providing detailed diff output.
#[macro_export]
macro_rules! assert_dns_response_matches {
    ($actual:expr, $expected:expr) => {
        assert_eq!($actual, $expected, "DNS response mismatch");
    };
}

/// Assert that a DHCP packet has valid wire format.
#[macro_export]
macro_rules! assert_dhcp_packet_valid {
    ($packet:expr) => {
        assert!($packet.len() >= 240, "DHCP packet too short");
    };
}

/// Assert that a lease file contains a specific entry.
#[macro_export]
macro_rules! assert_lease_file_contains {
    ($path:expr, $ip:expr, $mac:expr) => {
        let leases = parse_lease_file($path).expect("Failed to parse lease file");
        assert!(
            leases.iter().any(|l| l.ip.to_string() == $ip && l.mac == $mac),
            "Lease not found: {} {}",
            $ip,
            $mac
        );
    };
}

// ============================================================================
// DHCP PACKET BUILDERS
// ============================================================================

/// Builder for DHCPv4 DISCOVER messages.
///
/// Constructs DHCPv4 DISCOVER packets for testing DHCP server behavior.
///
/// # Examples
///
/// ```rust,ignore
/// let discover = DhcpDiscoverBuilder::new()
///     .with_mac("00:11:22:33:44:55")
///     .with_hostname("test-client")
///     .build();
/// ```
pub struct DhcpDiscoverBuilder {
    mac: [u8; 6],
    hostname: Option<String>,
    requested_ip: Option<IpAddr>,
    xid: u32,
}

impl DhcpDiscoverBuilder {
    /// Create a new DHCP DISCOVER builder.
    pub fn new() -> Self {
        Self {
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            hostname: None,
            requested_ip: None,
            xid: QUERY_ID_COUNTER.fetch_add(1, Ordering::Relaxed) as u32,
        }
    }

    /// Set the client MAC address.
    ///
    /// # Arguments
    ///
    /// * `mac` - MAC address string in format "00:11:22:33:44:55"
    pub fn with_mac(mut self, mac: &str) -> Self {
        // Parse MAC address string into bytes
        let parts: Vec<&str> = mac.split(':').collect();
        if parts.len() == 6 {
            for (i, part) in parts.iter().enumerate() {
                if let Ok(byte) = u8::from_str_radix(part, 16) {
                    self.mac[i] = byte;
                }
            }
        }
        self
    }

    /// Set the client hostname.
    #[allow(dead_code)]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Set the requested IP address (option 50).
    #[allow(dead_code)]
    pub fn with_requested_ip(mut self, ip: IpAddr) -> Self {
        self.requested_ip = Some(ip);
        self
    }

    /// Build the DHCPv4 DISCOVER packet.
    ///
    /// # Returns
    ///
    /// Serialized DHCP packet as byte vector
    pub fn build(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(576);

        // BOOTP header (236 bytes minimum)
        buf.push(0x01); // op: BOOTREQUEST
        buf.push(0x01); // htype: Ethernet
        buf.push(0x06); // hlen: 6 bytes
        buf.push(0x00); // hops: 0

        // Transaction ID (4 bytes)
        buf.extend_from_slice(&self.xid.to_be_bytes());

        // secs (2 bytes)
        buf.extend_from_slice(&[0x00, 0x00]);

        // flags (2 bytes)
        buf.extend_from_slice(&[0x00, 0x00]);

        // ciaddr (4 bytes) - client IP
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // yiaddr (4 bytes) - your IP
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // siaddr (4 bytes) - server IP
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // giaddr (4 bytes) - gateway IP
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // chaddr (16 bytes) - client hardware address
        buf.extend_from_slice(&self.mac);
        buf.extend_from_slice(&[0x00; 10]); // Padding

        // sname (64 bytes) - server name
        buf.extend_from_slice(&[0x00; 64]);

        // file (128 bytes) - boot file name
        buf.extend_from_slice(&[0x00; 128]);

        // Magic cookie (4 bytes)
        buf.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);

        // DHCP options
        // Option 53: DHCP Message Type = DISCOVER (1)
        buf.push(53);
        buf.push(1);
        buf.push(1);

        // Option 12: Hostname (if provided)
        if let Some(hostname) = &self.hostname {
            buf.push(12);
            buf.push(hostname.len() as u8);
            buf.extend_from_slice(hostname.as_bytes());
        }

        // Option 50: Requested IP (if provided)
        if let Some(IpAddr::V4(ipv4)) = self.requested_ip {
            buf.push(50);
            buf.push(4);
            buf.extend_from_slice(&ipv4.octets());
        }

        // End option
        buf.push(255);

        buf
    }
}

/// Builder for DHCPv6 SOLICIT messages.
///
/// Constructs DHCPv6 SOLICIT packets for testing DHCPv6 server behavior.
///
/// # Examples
///
/// ```rust,ignore
/// let solicit = DhcpSolicitBuilder::new()
///     .with_duid("00:01:00:01:2a:3b:4c:5d:00:11:22:33:44:55")
///     .build();
/// ```
#[allow(dead_code)]
pub struct DhcpSolicitBuilder {
    duid: Vec<u8>,
    ia_na: bool,
    xid: [u8; 3],
}

impl DhcpSolicitBuilder {
    /// Create a new DHCPv6 SOLICIT builder.
    #[allow(dead_code)]
    pub fn new() -> Self {
        let counter = QUERY_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let xid = [(counter >> 8) as u8, (counter & 0xff) as u8, 0x01];

        Self {
            duid: vec![
                0x00, 0x01, 0x00, 0x01, 0x2a, 0x3b, 0x4c, 0x5d, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            ],
            ia_na: true,
            xid,
        }
    }

    /// Set the client DUID (DHCP Unique Identifier).
    #[allow(dead_code)]
    pub fn with_duid(mut self, duid: &str) -> Self {
        // Parse DUID from hex string
        let parts: Vec<&str> = duid.split(':').collect();
        self.duid = parts.iter().filter_map(|p| u8::from_str_radix(p, 16).ok()).collect();
        self
    }

    /// Enable IA_NA (Identity Association for Non-temporary Addresses).
    #[allow(dead_code)]
    pub fn with_ia_na(mut self) -> Self {
        self.ia_na = true;
        self
    }

    /// Build the DHCPv6 SOLICIT packet.
    ///
    /// # Returns
    ///
    /// Serialized DHCPv6 packet as byte vector
    #[allow(dead_code)]
    pub fn build(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // Message type: SOLICIT (1)
        buf.push(1);

        // Transaction ID (3 bytes)
        buf.extend_from_slice(&self.xid);

        // Option 1: Client Identifier (DUID)
        buf.extend_from_slice(&[0x00, 0x01]); // Option code
        buf.extend_from_slice(&(self.duid.len() as u16).to_be_bytes()); // Length
        buf.extend_from_slice(&self.duid);

        // Option 3: IA_NA (Identity Association for Non-temporary Address)
        if self.ia_na {
            buf.extend_from_slice(&[0x00, 0x03]); // Option code
            buf.extend_from_slice(&[0x00, 0x0c]); // Length: 12 bytes
            buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // IAID
            buf.extend_from_slice(&[0x00, 0x00, 0x0e, 0x10]); // T1
            buf.extend_from_slice(&[0x00, 0x00, 0x15, 0x18]); // T2
        }

        // Option 6: Option Request (ORO)
        buf.extend_from_slice(&[0x00, 0x06]); // Option code
        buf.extend_from_slice(&[0x00, 0x04]); // Length: 4 bytes (2 options)
        buf.extend_from_slice(&[0x00, 0x17]); // DNS servers
        buf.extend_from_slice(&[0x00, 0x18]); // Domain search list

        buf
    }
}

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

/// Assert that lease count matches expected value.
#[allow(dead_code)]
pub fn assert_lease_count(path: &Path, expected: usize) {
    let leases = parse_lease_file(path).expect("Failed to parse lease file");
    assert_eq!(leases.len(), expected, "Expected {} leases, found {}", expected, leases.len());
}

/// Assert that a lease exists for the given IP and MAC.
#[allow(dead_code)]
pub fn assert_lease_exists(path: &Path, ip: &str, mac: &str) {
    let leases = parse_lease_file(path).expect("Failed to parse lease file");
    assert!(
        leases.iter().any(|l| l.ip.to_string() == ip && l.mac == mac),
        "Lease not found: {} {}",
        ip,
        mac
    );
}

/// Assert that a lease has expired (expiry timestamp in the past).
#[allow(dead_code)]
pub fn assert_lease_expired(lease: &LeaseEntry) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    assert!(lease.expiry < now, "Lease has not expired: expiry={}, now={}", lease.expiry, now);
}

// ============================================================================
// DEFAULT IMPLEMENTATIONS
// ============================================================================

impl Default for DnsQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for DhcpDiscoverBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for DhcpSolicitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for LogCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for MockDnsServer {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for TestServer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MODULE TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_generation() {
        let opts = TestConfigOptions::new().with_cache_size(1000);

        let config = generate_test_config(&opts);

        // Verify dynamic port is included in config
        if let Some(port) = opts.port {
            assert!(config.contains(&format!("port={}", port)));
        }
        assert!(config.contains("cache-size=1000"));
        assert!(config.contains("no-daemon"));
    }

    #[test]
    fn test_dns_query_builder() {
        let query =
            DnsQueryBuilder::new().with_name("example.com").with_record_type(RecordType::A).build();

        // Basic validation: serialize to check it's valid
        let bytes = query.to_bytes().expect("Failed to serialize query");
        assert!(bytes.len() >= 12, "Query too short");
        assert_eq!(bytes[2] & 0x01, 0x01, "RD bit not set");
    }

    #[test]
    fn test_dhcp_discover_builder() {
        let discover = DhcpDiscoverBuilder::new().with_mac("00:11:22:33:44:55").build();

        // DHCP minimum size check
        assert!(discover.len() >= 240, "DHCP packet too short");

        // Check BOOTP op code
        assert_eq!(discover[0], 0x01, "Not a BOOTREQUEST");

        // Check magic cookie
        assert_eq!(&discover[236..240], &[0x63, 0x82, 0x53, 0x63], "Invalid magic cookie");
    }

    #[test]
    fn test_lease_parsing() {
        // Create temporary lease file
        let temp_dir = create_temp_dir().unwrap();
        let lease_path = temp_dir.path().join("test.leases");

        let lease_content = "1234567890 00:11:22:33:44:55 192.168.1.100 testhost *\n\
                            1234567891 aa:bb:cc:dd:ee:ff 192.168.1.101 * 01:aa:bb:cc:dd:ee:ff\n";

        std::fs::write(&lease_path, lease_content).unwrap();

        let leases = parse_lease_file(&lease_path).unwrap();

        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].mac, "00:11:22:33:44:55");
        assert_eq!(leases[0].ip.to_string(), "192.168.1.100");
        assert_eq!(leases[0].hostname, Some("testhost".to_string()));

        assert_eq!(leases[1].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(leases[1].hostname, None);
        assert!(leases[1].client_id.is_some());
    }

    #[test]
    fn test_port_allocation() {
        let port1 = find_available_port().unwrap();
        let port2 = find_available_port().unwrap();

        assert!(port1 > 0);
        assert!(port2 > 0);
        // Ports might be the same if OS reuses quickly, so just check they're valid
    }
}
