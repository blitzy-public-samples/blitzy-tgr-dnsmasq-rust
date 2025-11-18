// Ad-hoc integration tests for DHCPv6 OptionBuilder
// Tests comprehensive scenarios for src/dhcp/v6/options.rs

use dnsmasq::dhcp::v6::options::OptionBuilder;
use dnsmasq::dhcp::v6::constants;
use std::net::Ipv6Addr;

#[test]
fn test_basic_option_encoding_integration() {
    let mut builder = OptionBuilder::new();
    builder.put_preference(255).unwrap();
    let result = builder.build();
    
    // Verify structure: option_code (2 bytes) + length (2 bytes) + value (1 byte)
    assert_eq!(result.len(), 5);
    
    // Option code should be OPTION_PREFERENCE
    let option_code = u16::from_be_bytes([result[0], result[1]]);
    assert_eq!(option_code, constants::OPTION_PREFERENCE);
    
    // Length should be 1
    let length = u16::from_be_bytes([result[2], result[3]]);
    assert_eq!(length, 1);
    
    // Value should be 255
    assert_eq!(result[4], 255);
}

#[test]
fn test_nested_ia_na_with_single_ia_addr() {
    let mut builder = OptionBuilder::new();
    let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let iaid = 0x12345678u32;
    let t1 = 3600u32;
    let t2 = 7200u32;
    let preferred = 7200u32;
    let valid = 14400u32;
    
    builder.put_ia_na(iaid, t1, t2, |b| {
        b.put_ia_addr(&addr, preferred, valid, |_| Ok(()))?;
        Ok(())
    }).unwrap();
    
    let result = builder.build();
    
    // Parse the result to verify correctness
    let mut offset = 0;
    
    // IA_NA option header
    let ia_na_code = u16::from_be_bytes([result[offset], result[offset + 1]]);
    assert_eq!(ia_na_code, constants::OPTION_IA_NA);
    offset += 2;
    
    let ia_na_length = u16::from_be_bytes([result[offset], result[offset + 1]]);
    offset += 2;
    
    // IA_NA fields: IAID (4 bytes), T1 (4 bytes), T2 (4 bytes)
    let parsed_iaid = u32::from_be_bytes([
        result[offset], result[offset + 1], result[offset + 2], result[offset + 3]
    ]);
    assert_eq!(parsed_iaid, iaid);
    offset += 4;
    
    let parsed_t1 = u32::from_be_bytes([
        result[offset], result[offset + 1], result[offset + 2], result[offset + 3]
    ]);
    assert_eq!(parsed_t1, t1);
    offset += 4;
    
    let parsed_t2 = u32::from_be_bytes([
        result[offset], result[offset + 1], result[offset + 2], result[offset + 3]
    ]);
    assert_eq!(parsed_t2, t2);
    offset += 4;
    
    // Nested IA_ADDR option
    let ia_addr_code = u16::from_be_bytes([result[offset], result[offset + 1]]);
    assert_eq!(ia_addr_code, constants::OPTION_IAADDR);
    offset += 2;
    
    let ia_addr_length = u16::from_be_bytes([result[offset], result[offset + 1]]);
    assert_eq!(ia_addr_length, 24); // 16 (IPv6) + 4 (preferred) + 4 (valid)
    offset += 2;
    
    // Verify IPv6 address
    let parsed_addr_bytes = &result[offset..offset + 16];
    assert_eq!(parsed_addr_bytes, addr.octets());
    offset += 16;
    
    let parsed_preferred = u32::from_be_bytes([
        result[offset], result[offset + 1], result[offset + 2], result[offset + 3]
    ]);
    assert_eq!(parsed_preferred, preferred);
    offset += 4;
    
    let parsed_valid = u32::from_be_bytes([
        result[offset], result[offset + 1], result[offset + 2], result[offset + 3]
    ]);
    assert_eq!(parsed_valid, valid);
    offset += 4;
    
    // Verify we parsed everything
    assert_eq!(offset, result.len());
    
    // Verify IA_NA length includes nested option (12 bytes IAID+T1+T2 + 4 bytes IAADDR header + 24 bytes IAADDR data)
    assert_eq!(ia_na_length as usize, 12 + 4 + 24);
}

#[test]
fn test_multiple_nested_ia_addr_in_ia_na() {
    let mut builder = OptionBuilder::new();
    let addr1 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let addr2 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let addr3 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3);
    
    builder.put_ia_na(0x11111111, 1800, 3600, |b| {
        b.put_ia_addr(&addr1, 3600, 7200, |_| Ok(()))?;
        b.put_ia_addr(&addr2, 3600, 7200, |_| Ok(()))?;
        b.put_ia_addr(&addr3, 3600, 7200, |_| Ok(()))?;
        Ok(())
    }).unwrap();
    
    let result = builder.build();
    
    // Verify structure: IA_NA header (4) + IAID+T1+T2 (12) + 3 * (IA_ADDR header (4) + data (24))
    // = 4 + 12 + 3 * 28 = 100 bytes
    assert_eq!(result.len(), 100);
    
    // Verify IA_NA length field
    let ia_na_length = u16::from_be_bytes([result[2], result[3]]);
    assert_eq!(ia_na_length as usize, 12 + 3 * 28); // 96 bytes of data
}

#[test]
fn test_status_code_with_message() {
    let mut builder = OptionBuilder::new();
    let message = "Address successfully allocated";
    builder.put_status_code(0, message).unwrap();
    let result = builder.build();
    
    // Parse the result
    let option_code = u16::from_be_bytes([result[0], result[1]]);
    assert_eq!(option_code, constants::OPTION_STATUS_CODE);
    
    let length = u16::from_be_bytes([result[2], result[3]]);
    assert_eq!(length as usize, 2 + message.len()); // status code (2) + message
    
    let status = u16::from_be_bytes([result[4], result[5]]);
    assert_eq!(status, 0);
    
    let parsed_message = &result[6..];
    assert_eq!(parsed_message, message.as_bytes());
}

#[test]
fn test_dns_servers_multiple() {
    let mut builder = OptionBuilder::new();
    let dns1 = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
    let dns2 = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844);
    let dns3 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    
    builder.put_dns_servers(&[dns1, dns2, dns3]).unwrap();
    let result = builder.build();
    
    // Verify: header (4) + 3 IPv6 addresses (48)
    assert_eq!(result.len(), 52);
    
    let option_code = u16::from_be_bytes([result[0], result[1]]);
    assert_eq!(option_code, constants::OPTION_DNS_SERVER);
    
    let length = u16::from_be_bytes([result[2], result[3]]);
    assert_eq!(length, 48); // 3 * 16 bytes
    
    // Verify first DNS server bytes
    let dns1_bytes = &result[4..20];
    assert_eq!(dns1_bytes, &dns1.octets());
}

#[test]
fn test_domain_list_multiple_domains() {
    let mut builder = OptionBuilder::new();
    builder.put_domain_list(&["example.com", "test.local"]).unwrap();
    let result = builder.build();
    
    let option_code = u16::from_be_bytes([result[0], result[1]]);
    assert_eq!(option_code, constants::OPTION_DOMAIN_SEARCH);
    
    // Verify first domain "example.com" in DNS wire format
    let mut offset = 4;
    assert_eq!(result[offset], 7); // Length of "example"
    offset += 1;
    assert_eq!(&result[offset..offset + 7], b"example");
    offset += 7;
    assert_eq!(result[offset], 3); // Length of "com"
    offset += 1;
    assert_eq!(&result[offset..offset + 3], b"com");
    offset += 3;
    assert_eq!(result[offset], 0); // Null terminator
    offset += 1;
    
    // Verify second domain "test.local"
    assert_eq!(result[offset], 4); // Length of "test"
    offset += 1;
    assert_eq!(&result[offset..offset + 4], b"test");
    offset += 4;
    assert_eq!(result[offset], 5); // Length of "local"
    offset += 1;
    assert_eq!(&result[offset..offset + 5], b"local");
    offset += 5;
    assert_eq!(result[offset], 0); // Null terminator
}

#[test]
fn test_fqdn_with_s_bit() {
    let mut builder = OptionBuilder::new();
    let flags = 0x01; // S bit set (Server should perform AAAA RR updates)
    builder.put_fqdn(flags, "client.example.com").unwrap();
    let result = builder.build();
    
    let option_code = u16::from_be_bytes([result[0], result[1]]);
    assert_eq!(option_code, constants::OPTION_FQDN);
    
    // Check flags byte
    assert_eq!(result[4], flags);
    
    // Verify DNS wire format encoding
    let mut offset = 5;
    assert_eq!(result[offset], 6); // "client"
    offset += 1;
    assert_eq!(&result[offset..offset + 6], b"client");
    offset += 6;
    assert_eq!(result[offset], 7); // "example"
    offset += 1;
    assert_eq!(&result[offset..offset + 7], b"example");
    offset += 7;
    assert_eq!(result[offset], 3); // "com"
    offset += 1;
    assert_eq!(&result[offset..offset + 3], b"com");
    offset += 3;
    assert_eq!(result[offset], 0); // Null terminator
}

#[test]
fn test_complex_message_with_multiple_options() {
    let mut builder = OptionBuilder::new();
    let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dns1 = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
    let dns2 = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844);
    
    // Build a complete DHCPv6 reply with multiple options
    builder.put_client_id(&[0x00, 0x01, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78]).unwrap();
    builder.put_server_id(&[0x00, 0x02, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
    builder.put_preference(255).unwrap();
    
    builder.put_ia_na(0xAAAAAAAA, 1800, 3600, |b| {
        b.put_ia_addr(&addr, 3600, 7200, |inner| {
            inner.put_status_code(0, "Success")?;
            Ok(())
        })?;
        Ok(())
    }).unwrap();
    
    builder.put_dns_servers(&[dns1, dns2]).unwrap();
    builder.put_domain_list(&["example.com"]).unwrap();
    
    let result = builder.build();
    
    // Verify the message is substantial and well-formed
    assert!(result.len() > 100);
    
    // Verify first option is CLIENT_ID
    let first_option = u16::from_be_bytes([result[0], result[1]]);
    assert_eq!(first_option, constants::OPTION_CLIENT_ID);
}

#[test]
fn test_ia_na_with_status_code_only() {
    let mut builder = OptionBuilder::new();
    
    // IA_NA with only a status code (e.g., NoAddrsAvail)
    builder.put_ia_na(0x99999999, 0, 0, |b| {
        b.put_status_code(2, "No addresses available")?;
        Ok(())
    }).unwrap();
    
    let result = builder.build();
    
    // Verify structure
    let ia_na_code = u16::from_be_bytes([result[0], result[1]]);
    assert_eq!(ia_na_code, constants::OPTION_IA_NA);
    
    // The nested status code should be present
    let nested_offset = 16; // After IA_NA header (4) + IAID+T1+T2 (12)
    let status_code = u16::from_be_bytes([result[nested_offset], result[nested_offset + 1]]);
    assert_eq!(status_code, constants::OPTION_STATUS_CODE);
}

#[test]
fn test_length_backpatching_accuracy() {
    let mut builder = OptionBuilder::new();
    
    // Create a known-size nested structure
    builder.put_ia_na(0x12345678, 100, 200, |b| {
        // Add exactly 40 bytes of nested data (nested IAADDR with no sub-options)
        b.put_ia_addr(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 300, 400, |_| Ok(()))?;
        Ok(())
    }).unwrap();
    
    let result = builder.build();
    
    // IA_NA length should be: 12 (IAID+T1+T2) + 4 (IAADDR header) + 24 (IAADDR data) = 40
    let ia_na_length = u16::from_be_bytes([result[2], result[3]]);
    assert_eq!(ia_na_length, 40);
}

#[test]
fn test_empty_builder_produces_empty_output() {
    let builder = OptionBuilder::new();
    let result = builder.build();
    assert_eq!(result.len(), 0);
}

#[test]
fn test_builder_with_single_simple_option() {
    let mut builder = OptionBuilder::new();
    builder.put_client_id(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    let result = builder.build();
    
    // Header (4 bytes) + data (4 bytes) = 8 bytes
    assert_eq!(result.len(), 8);
    
    let option_code = u16::from_be_bytes([result[0], result[1]]);
    assert_eq!(option_code, constants::OPTION_CLIENT_ID);
    
    let length = u16::from_be_bytes([result[2], result[3]]);
    assert_eq!(length, 4);
    
    assert_eq!(&result[4..8], &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn test_rapid_commit_flag() {
    let mut builder = OptionBuilder::new();
    builder.put_rapid_commit().unwrap();
    let result = builder.build();
    
    // Rapid commit is a zero-length option
    assert_eq!(result.len(), 4);
    
    let option_code = u16::from_be_bytes([result[0], result[1]]);
    assert_eq!(option_code, constants::OPTION_RAPID_COMMIT);
    
    let length = u16::from_be_bytes([result[2], result[3]]);
    assert_eq!(length, 0);
}
