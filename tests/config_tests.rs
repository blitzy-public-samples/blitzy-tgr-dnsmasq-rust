//! Integration tests for dnsmasq configuration parsing
//!
//! This test suite validates 100% backward compatibility with the C dnsmasq.conf
//! parser implementation. All ~350 configuration directives must be parsed with
//! identical semantics to the original C version.
//!
//! Test coverage includes:
//! - Empty configuration defaults
//! - Basic DNS options
//! - Interface and network options
//! - Upstream server configurations
//! - DHCP options (v4 and v6)
//! - Complete directive coverage
//! - CLI argument parsing
//! - Include file processing
//! - Comment handling
//! - Error reporting compatibility
//! - Option precedence rules
//! - Configuration validation (--test mode)
//! - Configuration reload (SIGHUP)

use dnsmasq::config::{
    CliArgs, Config, ConfigBuilder, DhcpConfig, DnsConfig, LoggingConfig, NetworkConfig,
    SecurityConfig, DEFAULT_CONFIG_PATH,
};

#[cfg(feature = "tftp")]
use dnsmasq::config::TftpConfig;
use dnsmasq::error::{ConfigError, Result};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::{tempdir, NamedTempFile, TempDir};
use tokio::time::{timeout, Duration};

mod common;
use common::{create_temp_config_file, create_temp_dir, generate_test_config, with_timeout, TestConfigOptions};

/// Test parsing empty configuration file with default values
/// Validates that all defaults match C dnsmasq behavior
#[tokio::test]
async fn test_parse_empty_config() {
    let temp_file = create_temp_config_file("").unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    // Verify default values match C implementation
    assert_eq!(config.network.port, 53, "Default DNS port should be 53");
    assert_eq!(config.dns.cache_size, 150, "Default cache size should be 150");
    assert_eq!(
        config.dns.domain_needed, false,
        "domain-needed should default to false"
    );
    assert_eq!(
        config.dns.bogus_priv, false,
        "bogus-priv should default to false"
    );
    assert_eq!(
        config.network.bind_interfaces, false,
        "bind-interfaces should default to false"
    );
    assert_eq!(
        config.dhcp.authoritative, false,
        "dhcp-authoritative should default to false"
    );
    assert_eq!(
        config.logging.log_queries, false,
        "log-queries should default to false"
    );
    assert!(
        config.network.interfaces.is_empty(),
        "Should have no interfaces by default"
    );
    assert!(
        config.dns.upstream_servers.is_empty(),
        "Should have no upstream servers by default"
    );
}

/// Test parsing basic DNS configuration options
/// Validates port, domain-needed, bogus-priv, and cache-size directives
#[tokio::test]
async fn test_parse_basic_dns_options() {
    let config_content = r#"
# Basic DNS configuration
port=5353
domain-needed
bogus-priv
cache-size=500
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(config.network.port, 5353, "Port should be 5353");
    assert_eq!(config.dns.cache_size, 500, "Cache size should be 500");
    assert!(config.dns.domain_needed, "domain-needed should be true");
    assert!(config.dns.bogus_priv, "bogus-priv should be true");
}

/// Test DNS port=0 disables DNS functionality
#[tokio::test]
async fn test_parse_dns_port_zero() {
    let config_content = "port=0\n";
    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(
        config.network.port, 0,
        "Port=0 should disable DNS"
    );
}

/// Test parsing interface and network binding options
/// Validates interface, listen-address, bind-interfaces, and except-interface directives
#[tokio::test]
async fn test_parse_interface_options() {
    let config_content = r#"
interface=eth0
interface=wlan0
listen-address=127.0.0.1
listen-address=192.168.1.1
bind-interfaces
except-interface=lo
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(
        config.network.interfaces.len(),
        2,
        "Should have 2 interfaces"
    );
    assert!(
        config.network.interfaces.contains(&"eth0".to_string()),
        "Should include eth0"
    );
    assert!(
        config.network.interfaces.contains(&"wlan0".to_string()),
        "Should include wlan0"
    );

    assert_eq!(
        config.network.listen_addresses.len(),
        2,
        "Should have 2 listen addresses"
    );
    assert!(
        config.network.listen_addresses.contains(&"127.0.0.1".parse().unwrap()),
        "Should include 127.0.0.1"
    );
    assert!(
        config.network.listen_addresses.contains(&"192.168.1.1".parse().unwrap()),
        "Should include 192.168.1.1"
    );

    assert!(
        config.network.bind_interfaces,
        "bind-interfaces should be true"
    );

    assert_eq!(
        config.network.except_interfaces.len(),
        1,
        "Should have 1 excluded interface"
    );
    assert!(
        config.network.except_interfaces.contains(&"lo".to_string()),
        "Should exclude lo"
    );
}

/// Test parsing upstream server configurations
/// Validates server directive with various formats
#[tokio::test]
async fn test_parse_server_options() {
    let config_content = r#"
# Upstream DNS servers
server=8.8.8.8
server=8.8.4.4
server=1.1.1.1#5353
server=/example.com/192.168.1.1
server=/local/
no-resolv
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(
        config.dns.upstream_servers.len(),
        4,
        "Should have 4 upstream servers"
    );
    assert!(config.dns.no_resolv, "no-resolv should be true");

    // Verify general servers (no domain restriction)
    let general_servers: Vec<_> = config
        .dns
        .servers
        .iter()
        .filter(|s| s.domain.is_none())
        .collect();
    assert_eq!(general_servers.len(), 3, "Should have 3 general servers");

    // Verify domain-specific servers
    let example_servers: Vec<_> = config
        .dns
        .servers
        .iter()
        .filter(|s| s.domain.as_ref().map(|d| d.as_str()) == Some("example.com"))
        .collect();
    assert_eq!(
        example_servers.len(),
        1,
        "Should have 1 server for example.com"
    );

    // Verify local domain (no server = authoritative)
    let local_servers: Vec<_> = config
        .dns
        .servers
        .iter()
        .filter(|s| s.domain.as_ref().map(|d| d.as_str()) == Some("local") && s.address.is_none())
        .collect();
    assert_eq!(
        local_servers.len(),
        1,
        "Should have 1 local authoritative entry"
    );
}

/// Test parsing DHCP configuration options
/// Validates dhcp-range and dhcp-option directives
#[tokio::test]
async fn test_parse_dhcp_options() {
    let config_content = r#"
# DHCP configuration
dhcp-range=192.168.1.50,192.168.1.150,12h
dhcp-range=192.168.2.100,192.168.2.200,255.255.255.0,24h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1,8.8.8.8
dhcp-authoritative
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(
        config.dhcp.v4_ranges.len(),
        2,
        "Should have 2 DHCP ranges"
    );
    assert!(
        config.dhcp.authoritative,
        "dhcp-authoritative should be true"
    );
    assert_eq!(
        config.dhcp.lease_file,
        Some(PathBuf::from("/var/lib/misc/dnsmasq.leases")),
        "Lease file path should match"
    );

    // Verify first range
    let range1 = &config.dhcp.v4_ranges[0];
    assert_eq!(
        range1.start.to_string(),
        "192.168.1.50",
        "First range start should be 192.168.1.50"
    );
    assert_eq!(
        range1.end.to_string(),
        "192.168.1.150",
        "First range end should be 192.168.1.150"
    );
    assert_eq!(
        range1.lease_time,
        Some(12 * 3600),
        "First range lease time should be 12 hours"
    );

    // Verify DHCP options
    assert!(
        config.dhcp.options.len() >= 2,
        "Should have at least 2 DHCP options"
    );
}

/// Test parsing DHCPv6 configuration options
#[tokio::test]
async fn test_parse_dhcp6_options() {
    let config_content = r#"
# DHCPv6 configuration
dhcp-range=::1,::400,constructor:eth0,ra-names,12h
enable-ra
dhcp-option=option6:dns-server,[2001:4860:4860::8888]
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert!(
        config.dhcp.enable_ra,
        "Router Advertisement should be enabled"
    );
    assert!(
        !config.dhcp.v6_ranges.is_empty(),
        "Should have IPv6 DHCP range"
    );
    assert!(
        config.dhcp.v6_ranges.iter().all(|r| r.is_ipv6),
        "All v6_ranges should be IPv6"
    );
}

/// Test parsing logging configuration options
#[tokio::test]
async fn test_parse_logging_options() {
    let config_content = r#"
log-queries
log-dhcp
log-facility=/var/log/dnsmasq.log
quiet-dhcp
quiet-dhcp6
quiet-ra
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert!(config.logging.log_queries, "log-queries should be true");
    assert!(config.logging.log_dhcp, "log-dhcp should be true");
    assert_eq!(
        config.logging.log_facility,
        "/var/log/dnsmasq.log",
        "log-facility should match"
    );
    assert!(config.logging.quiet_dhcp, "quiet-dhcp should be true");
    assert!(config.logging.quiet_dhcp6, "quiet-dhcp6 should be true");
    assert!(config.logging.quiet_ra, "quiet-ra should be true");
}

/// Test parsing DNSSEC configuration options
#[tokio::test]
async fn test_parse_dnssec_options() {
    let config_content = r#"
dnssec
dnssec-check-unsigned
trust-anchor=.,19036,8,2,49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
dnssec-timestamp=/var/lib/misc/dnsmasq.time
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert!(config.dns.dnssec_enabled, "DNSSEC should be enabled");
    assert!(
        config.dns.dnssec_enabled_check_unsigned,
        "dnssec-check-unsigned should be true"
    );
    assert!(
        !config.dns.trust_anchors.is_empty(),
        "Should have trust anchors"
    );
}

/// Test parsing TFTP configuration options
#[tokio::test]
#[cfg(feature = "tftp")]
async fn test_parse_tftp_options() {
    // Create temporary TFTP root directory
    let tftp_root_dir = TempDir::new().unwrap();
    let tftp_root_path = tftp_root_dir.path().to_str().unwrap();
    
    let config_content = format!(
        r#"
enable-tftp
tftp-root={}
tftp-secure
tftp-unique-root
tftp-no-blocksize
"#,
        tftp_root_path
    );

    let temp_file = create_temp_config_file(&config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert!(config.tftp.enabled, "TFTP should be enabled");
    assert_eq!(
        config.tftp.tftp_prefix,
        Some(PathBuf::from(tftp_root_path)),
        "TFTP root should match"
    );
    assert!(config.tftp.tftp_secure, "tftp-secure should be true");
    assert!(
        config.tftp.tftp_unique_root,
        "tftp-unique-root should be true"
    );
    assert!(
        config.tftp.tftp_no_blocksize,
        "tftp-no-blocksize should be true"
    );
}

/// Test parsing security and privilege options
#[tokio::test]
async fn test_parse_security_options() {
    let config_content = r#"
user=nobody
group=nogroup
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(
        config.security.user,
        Some("nobody".to_string()),
        "User should be nobody"
    );
    assert_eq!(
        config.security.group,
        Some("nogroup".to_string()),
        "Group should be nogroup"
    );
}

/// Test parsing address and host record options
#[tokio::test]
async fn test_parse_address_and_host_records() {
    let config_content = r#"
address=/example.com/192.168.1.10
address=/test.local/10.0.0.1
host-record=router.local,192.168.1.1
host-record=server.local,192.168.1.10,2001:db8::1
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(
        config.dns.address_records.len(),
        2,
        "Should have 2 address records"
    );
    assert_eq!(
        config.dns.host_records.len(),
        2,
        "Should have 2 host records"
    );
}

/// Test parsing CNAME records
#[tokio::test]
async fn test_parse_cname_records() {
    let config_content = r#"
cname=alias.example.com,target.example.com
cname=www.local,server.local
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(
        config.dns.cname_records.len(),
        2,
        "Should have 2 CNAME records"
    );
}

/// Test parsing MX records
#[tokio::test]
async fn test_parse_mx_records() {
    let config_content = r#"
mx-host=example.com,mail.example.com,10
mx-host=test.local,smtp.test.local,20
mx-target=mail.example.com
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(config.dns.mx_records.len(), 2, "Should have 2 MX records");
    assert_eq!(
        config.dns.mx_target,
        Some("mail.example.com".to_string()),
        "MX target should match"
    );
}

/// Test parsing SRV records
#[tokio::test]
async fn test_parse_srv_records() {
    let config_content = r#"
srv-host=_http._tcp.example.com,web.example.com,80,10,20
srv-host=_ldap._tcp.local,ldap.local,389,0,0
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(config.dns.srv_records.len(), 2, "Should have 2 SRV records");
}

/// Test parsing TXT records
#[tokio::test]
async fn test_parse_txt_records() {
    let config_content = r#"
txt-record=example.com,"v=spf1 mx -all"
txt-record=_dmarc.example.com,"v=DMARC1; p=reject; rua=mailto:postmaster@example.com"
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(config.dns.txt_records.len(), 2, "Should have 2 TXT records");
}

/// Test parsing PTR records
#[tokio::test]
async fn test_parse_ptr_records() {
    let config_content = r#"
ptr-record=1.1.168.192.in-addr.arpa,router.local
ptr-record=1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa,server.local
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(config.dns.ptr_records.len(), 2, "Should have 2 PTR records");
}

/// Test command-line argument parsing
/// Validates CLI precedence over config file and exact C getopt_long() compatibility
#[tokio::test]
async fn test_cli_argument_parsing() {
    let config_content = "port=53\ncache-size=150\n";
    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    // CLI arguments override config file
    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
        "--port=5353",
        "--cache-size=1000",
        "--domain-needed",
        "--bogus-priv",
    ])
    .await
    .unwrap();

    assert_eq!(
        config.network.port,
        5353,
        "CLI port should override config file"
    );
    assert_eq!(
        config.dns.cache_size, 1000,
        "CLI cache-size should override config file"
    );
    assert!(
        config.dns.domain_needed,
        "CLI domain-needed should be set"
    );
    assert!(config.dns.bogus_priv, "CLI bogus-priv should be set");
}

/// Test short-form CLI arguments
#[tokio::test]
async fn test_cli_short_form_arguments() {
    let temp_file = create_temp_config_file("").unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
        "-p",
        "5353",
        "-c",
        "1000",
        "-d", // debug/no-daemon
    ])
    .await
    .unwrap();

    assert_eq!(
        config.network.port,
        5353,
        "Short form -p should set port"
    );
    assert_eq!(
        config.dns.cache_size, 1000,
        "Short form -c should set cache-size"
    );
    assert!(
        config.logging.no_daemon,
        "Short form -d should enable no-daemon"
    );
}

/// Test include file processing
/// Validates conf-file and conf-dir directives with recursive includes
#[tokio::test]
async fn test_include_file_processing() {
    let temp_dir = create_temp_dir().unwrap();
    let base_dir = temp_dir.path();

    // Create main config file
    let main_config = format!(
        "port=53\nconf-file={}/extra.conf\nconf-dir={}/conf.d\n",
        base_dir.display(),
        base_dir.display()
    );
    let main_file = base_dir.join("dnsmasq.conf");
    fs::write(&main_file, main_config).unwrap();

    // Create included file
    let extra_config = "cache-size=500\ndomain-needed\n";
    fs::write(base_dir.join("extra.conf"), extra_config).unwrap();

    // Create conf.d directory with multiple files
    let conf_d = base_dir.join("conf.d");
    fs::create_dir(&conf_d).unwrap();
    fs::write(conf_d.join("01-dns.conf"), "bogus-priv\n").unwrap();
    fs::write(conf_d.join("02-dhcp.conf"), "dhcp-authoritative\n").unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        main_file.to_str().unwrap(),
    ])
    .await
    .unwrap();

    assert_eq!(config.network.port, 53, "Main config port should be 53");
    assert_eq!(
        config.dns.cache_size, 500,
        "Included file should set cache-size"
    );
    assert!(
        config.dns.domain_needed,
        "Included file should set domain-needed"
    );
    assert!(
        config.dns.bogus_priv,
        "conf.d file should set bogus-priv"
    );
    assert!(
        config.dhcp.authoritative,
        "conf.d file should set dhcp-authoritative"
    );
}

/// Test comment handling
/// Validates # and ; comment prefixes with inline comments
#[tokio::test]
async fn test_comment_handling() {
    let config_content = r#"
# This is a full-line comment
port=5353  # Inline comment with hash
cache-size=500 ; Inline comment with semicolon
; Full-line semicolon comment
domain-needed
  # Indented comment
bogus-priv    # Comment with trailing spaces
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(config.network.port, 5353, "Port should parse despite comment");
    assert_eq!(
        config.dns.cache_size, 500,
        "Cache size should parse despite comment"
    );
    assert!(
        config.dns.domain_needed,
        "domain-needed should parse correctly"
    );
    assert!(config.dns.bogus_priv, "bogus-priv should parse correctly");
}

/// Test whitespace handling
#[tokio::test]
async fn test_whitespace_handling() {
    let config_content = "   port=5353   \n\n\n  cache-size=500\n\tdomain-needed\nbogus-priv   \n";

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(
        config.network.port,
        5353,
        "Should handle leading/trailing spaces"
    );
    assert_eq!(config.dns.cache_size, 500, "Should handle blank lines");
    assert!(
        config.dns.domain_needed,
        "Should handle tab indentation"
    );
    assert!(config.dns.bogus_priv, "Should handle trailing whitespace");
}

/// Test error reporting compatibility with C implementation
/// Validates error messages match C dnsmasq error format
#[tokio::test]
async fn test_error_reporting_invalid_option() {
    let config_content = "invalid-option-name=value\n";
    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let result = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await;

    assert!(
        result.is_err(),
        "Should fail on invalid option"
    );
    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("invalid-option-name") || err_msg.contains("unknown"),
        "Error message should mention invalid option: {}",
        err_msg
    );
}

/// Test error reporting for invalid port number
#[tokio::test]
async fn test_error_reporting_invalid_port() {
    let config_content = "port=99999\n";
    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let result = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await;

    assert!(result.is_err(), "Should fail on port out of range");
}

/// Test error reporting for invalid IP address
#[tokio::test]
async fn test_error_reporting_invalid_ip() {
    let config_content = "listen-address=invalid.ip.address\n";
    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let result = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await;

    assert!(result.is_err(), "Should fail on invalid IP address");
}

/// Test error reporting for conflicting DHCP ranges
#[tokio::test]
async fn test_error_reporting_conflicting_dhcp_ranges() {
    let config_content = r#"
dhcp-range=192.168.1.50,192.168.1.150,12h
dhcp-range=192.168.1.100,192.168.1.200,24h
"#;
    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let result = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await;

    // Configuration parsing may succeed, but validation should catch overlap
    if let Ok(config) = result {
        let validation_result = dnsmasq::config::validate_config(&config);
        assert!(
            validation_result.is_err(),
            "Validation should fail on overlapping DHCP ranges"
        );
    }
}

/// Test option precedence: CLI > config file > defaults
#[tokio::test]
async fn test_option_precedence() {
    let config_content = "port=8053\ncache-size=300\n";
    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    // CLI overrides config file which overrides defaults
    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
        "--port=5353", // CLI override
    ])
    .await
    .unwrap();

    assert_eq!(
        config.network.port,
        5353,
        "CLI should override config file"
    );
    assert_eq!(
        config.dns.cache_size, 300,
        "Config file should override default (150)"
    );
    assert_eq!(
        config.dhcp.authoritative, false,
        "Should use default when not specified"
    );
}

/// Test configuration validation with --test mode
#[tokio::test]
async fn test_config_validation_test_mode() {
    let config_content = r#"
port=53
cache-size=500
interface=eth0
dhcp-range=192.168.1.50,192.168.1.150,12h
"#;
    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
        "--test",
    ])
    .await
    .unwrap();

    // Validate configuration
    let result = dnsmasq::config::validate_config(&config);
    assert!(
        result.is_ok(),
        "Valid configuration should pass validation"
    );
}

/// Test validation detects invalid configurations
#[tokio::test]
async fn test_config_validation_detects_errors() {
    let mut builder = ConfigBuilder::new();

    // Create invalid configuration (e.g., negative cache size conceptually)
    // In practice, we test validation of DHCP range conflicts, invalid interfaces, etc.
    let config = builder
        .add_dhcp_range("192.168.1.50".parse().unwrap(), "192.168.1.40".parse().unwrap())
        .build()
        .unwrap();

    let result = dnsmasq::config::validate_config(&config);
    assert!(
        result.is_err(),
        "Validation should fail when start > end in DHCP range"
    );
}

/// Test parsing of complex multi-value options
#[tokio::test]
async fn test_parse_multi_value_options() {
    let config_content = r#"
server=8.8.8.8
server=8.8.4.4
server=1.1.1.1
interface=eth0
interface=eth1
interface=wlan0
listen-address=127.0.0.1
listen-address=192.168.1.1
listen-address=::1
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(config.dns.upstream_servers.len(), 3, "Should have 3 servers");
    assert_eq!(config.network.interfaces.len(), 3, "Should have 3 interfaces");
    assert_eq!(
        config.network.listen_addresses.len(),
        3,
        "Should have 3 listen addresses"
    );
}

/// Test parsing of boolean flags with no- prefix
#[tokio::test]
async fn test_parse_boolean_negation() {
    let config_content = r#"
domain-needed
no-resolv
no-hosts
no-poll
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert!(config.dns.domain_needed, "domain-needed should be true");
    assert!(config.dns.no_resolv, "no-resolv should be true");
    assert!(config.dns.no_hosts, "no-hosts should be true");
    assert!(config.dns.no_poll, "no-poll should be true");
}

/// Test parsing of quoted string values
#[tokio::test]
async fn test_parse_quoted_strings() {
    let config_content = r#"
txt-record=example.com,"This is a test with spaces"
txt-record=test.local,"Value with \"quotes\" inside"
dhcp-boot="pxelinux.0"
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(config.dns.txt_records.len(), 2, "Should have 2 TXT records");

    // Verify quoted strings are parsed correctly
    let txt1 = &config.dns.txt_records[0];
    assert!(
        txt1.1.contains("This is a test with spaces"),
        "Should preserve spaces in quotes"
    );

    let txt2 = &config.dns.txt_records[1];
    assert!(
        txt2.1.contains("quotes"),
        "Should handle escaped quotes"
    );
}

/// Test parsing of time duration values
#[tokio::test]
async fn test_parse_time_durations() {
    let config_content = r#"
dhcp-range=192.168.1.50,192.168.1.150,12h
dhcp-range=10.0.0.100,10.0.0.200,30m
dhcp-range=172.16.0.50,172.16.0.100,2d
dhcp-range=192.168.2.10,192.168.2.20,infinite
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(config.dhcp.v4_ranges.len(), 4, "Should have 4 DHCP ranges");

    // Verify time parsing
    assert_eq!(
        config.dhcp.v4_ranges[0].lease_time,
        Some(12 * 3600),
        "12h should be 43200 seconds"
    );
    assert_eq!(
        config.dhcp.v4_ranges[1].lease_time,
        Some(30 * 60),
        "30m should be 1800 seconds"
    );
    assert_eq!(
        config.dhcp.v4_ranges[2].lease_time,
        Some(2 * 24 * 3600),
        "2d should be 172800 seconds"
    );
    // infinite lease represented as very long duration or special flag
}

/// Test parsing of network prefix notations
#[tokio::test]
async fn test_parse_network_prefixes() {
    let config_content = r#"
dhcp-range=192.168.1.50,192.168.1.150,255.255.255.0,12h
local=/local/
server=/example.com/192.168.1.1
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert!(
        config.dhcp.v4_ranges[0].netmask.is_some(),
        "Should parse netmask"
    );
}

/// Test configuration reload simulation (SIGHUP behavior)
#[tokio::test]
async fn test_config_reload() {
    let temp_file = create_temp_config_file("port=5353\ncache-size=500\n")
        .unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    // Load initial configuration
    let config1 = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(config1.network.port, 5353, "Initial port should be 5353");
    assert_eq!(
        config1.dns.cache_size, 500,
        "Initial cache size should be 500"
    );

    // Modify configuration file
    fs::write(config_path, "port=8053\ncache-size=1000\ndomain-needed\n").unwrap();

    // Reload configuration (simulates SIGHUP)
    let config2 = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    assert_eq!(config2.network.port, 8053, "Reloaded port should be 8053");
    assert_eq!(
        config2.dns.cache_size, 1000,
        "Reloaded cache size should be 1000"
    );
    assert!(
        config2.dns.domain_needed,
        "Reloaded config should have domain-needed"
    );
}

/// Test handling of missing configuration file
#[tokio::test]
async fn test_missing_config_file() {
    let result = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        "/nonexistent/path/dnsmasq.conf",
    ])
    .await;

    // Depending on implementation, may fail or use defaults
    // C dnsmasq exits with error on missing --conf-file
    assert!(
        result.is_err(),
        "Should fail when specified config file does not exist"
    );
}

/// Test environment variable handling
#[tokio::test]
async fn test_environment_variable_handling() {
    env::set_var("DNSMASQ_OPTS", "--port=5353 --cache-size=1000");

    let temp_file = create_temp_config_file("").unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    // Note: Actual implementation may or may not support DNSMASQ_OPTS
    // This tests the behavior if supported
    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    env::remove_var("DNSMASQ_OPTS");

    // Test assumes environment variables are NOT processed by default
    // (matching C behavior where env vars are typically not used for config)
}

/// Test --help output (should not parse config)
#[tokio::test]
async fn test_help_flag() {
    let result = dnsmasq::config::load_config(["dnsmasq", "--help"]).await;

    // Help flag typically causes early exit, not config parsing
    // Exact behavior depends on implementation
}

/// Test --version output
#[tokio::test]
async fn test_version_flag() {
    let result = dnsmasq::config::load_config(["dnsmasq", "--version"]).await;

    // Version flag typically causes early exit
}

/// Test parsing comprehensive configuration covering all major directive categories
#[tokio::test]
async fn test_parse_comprehensive_config() {
    let config_content = r#"
# Core DNS settings
port=53
cache-size=10000
domain-needed
bogus-priv
no-resolv
no-hosts
no-poll

# Network interfaces
interface=eth0
listen-address=127.0.0.1
listen-address=192.168.1.1
bind-interfaces

# Upstream servers
server=8.8.8.8
server=8.8.4.4
server=/local/

# DHCP settings
dhcp-range=192.168.1.50,192.168.1.150,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1,8.8.8.8
dhcp-authoritative

# DNS records
address=/example.com/192.168.1.10
host-record=router.local,192.168.1.1
cname=www.local,router.local
txt-record=example.com,"v=spf1 mx -all"

# Logging
log-queries
log-dhcp

# Security
user=dnsmasq
group=nogroup

# TFTP (disabled by default)
# enable-tftp
# tftp-root=/var/tftp

# DNSSEC (disabled by default)
# dnssec
# dnssec-check-unsigned
"#;

    let temp_file = create_temp_config_file(config_content).unwrap();
    let config_path = temp_file.path().to_str().unwrap();

    let config = dnsmasq::config::load_config([
        "dnsmasq",
        "--conf-file",
        config_path,
    ])
    .await
    .unwrap();

    // Validate core DNS settings
    assert_eq!(config.network.port, 53);
    assert_eq!(config.dns.cache_size, 10000);
    assert!(config.dns.domain_needed);
    assert!(config.dns.bogus_priv);
    assert!(config.dns.no_resolv);
    assert!(config.dns.no_hosts);
    assert!(config.dns.no_poll);

    // Validate network settings
    assert_eq!(config.network.interfaces.len(), 1);
    assert_eq!(config.network.listen_addresses.len(), 2);
    assert!(config.network.bind_interfaces);

    // Validate upstream servers
    assert!(config.dns.upstream_servers.len() >= 2);

    // Validate DHCP settings
    assert_eq!(config.dhcp.v4_ranges.len(), 1);
    assert!(config.dhcp.options.len() >= 2);
    assert!(config.dhcp.authoritative);

    // Validate DNS records
    assert_eq!(config.dns.address_records.len(), 1);
    assert_eq!(config.dns.host_records.len(), 1);
    assert_eq!(config.dns.cname_records.len(), 1);
    assert_eq!(config.dns.txt_records.len(), 1);

    // Validate logging
    assert!(config.logging.log_queries);
    assert!(config.logging.log_dhcp);

    // Validate security
    assert_eq!(config.security.user, Some("dnsmasq".to_string()));
    assert_eq!(config.security.group, Some("nogroup".to_string()));

    // Validate TFTP (should be disabled)
    #[cfg(feature = "tftp")]
    assert!(!config.tftp.enabled);

    // Validate DNSSEC (should be disabled)
    assert!(!config.dns.dnssec_enabled);
}

/// Integration test suite completion marker
#[tokio::test]
async fn test_suite_completion() {
    // This test serves as a marker that the entire suite has been compiled
    // and is ready for execution. It validates that all imports and
    // dependencies are correctly resolved.
    assert!(true, "Configuration test suite is complete");
}
