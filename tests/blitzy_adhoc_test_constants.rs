// Ad-hoc test for src/dns/protocol/constants.rs
// This test validates all constants defined in the constants module

use dnsmasq::dns::protocol::constants::*;

#[test]
fn test_port_constants() {
    // Verify port constants exist and have correct values
    assert_eq!(NAMESERVER_PORT, 53, "DNS port should be 53");
    assert_eq!(TFTP_PORT, 69, "TFTP port should be 69");
    assert_eq!(MIN_PORT, 1024, "Min port should be 1024");
    assert_eq!(MAX_PORT, 65535, "Max port should be 65535");
    
    // Verify types
    let _: u16 = NAMESERVER_PORT;
    let _: u16 = TFTP_PORT;
    let _: u16 = MIN_PORT;
    let _: u16 = MAX_PORT;
}

#[test]
fn test_size_constants() {
    // Verify size constants exist and have correct values
    assert_eq!(IN6ADDRSZ, 16, "IPv6 address size should be 16");
    assert_eq!(INADDRSZ, 4, "IPv4 address size should be 4");
    assert_eq!(PACKETSZ, 512, "Standard DNS packet size should be 512");
    assert_eq!(MAXDNAME, 1025, "Max domain name size should be 1025");
    assert_eq!(RRFIXEDSZ, 10, "RR fixed size should be 10");
    assert_eq!(MAXLABEL, 63, "Max label size should be 63");
    
    // Verify types
    let _: usize = IN6ADDRSZ;
    let _: usize = INADDRSZ;
    let _: usize = PACKETSZ;
    let _: usize = MAXDNAME;
    let _: usize = RRFIXEDSZ;
    let _: usize = MAXLABEL;
}

#[test]
fn test_response_codes() {
    // Verify DNS response codes exist and have correct values
    assert_eq!(NOERROR, 0, "NOERROR should be 0");
    assert_eq!(FORMERR, 1, "FORMERR should be 1");
    assert_eq!(SERVFAIL, 2, "SERVFAIL should be 2");
    assert_eq!(NXDOMAIN, 3, "NXDOMAIN should be 3");
    assert_eq!(NOTIMP, 4, "NOTIMP should be 4");
    assert_eq!(REFUSED, 5, "REFUSED should be 5");
    
    // Verify types
    let _: u8 = NOERROR;
    let _: u8 = FORMERR;
    let _: u8 = SERVFAIL;
    let _: u8 = NXDOMAIN;
    let _: u8 = NOTIMP;
    let _: u8 = REFUSED;
}

#[test]
fn test_opcode() {
    // Verify OPCODE exists and has correct value
    assert_eq!(QUERY, 0, "QUERY opcode should be 0");
    let _: u8 = QUERY;
}

#[test]
fn test_class_codes() {
    // Verify DNS class codes exist and have correct values
    assert_eq!(C_IN, 1, "C_IN should be 1");
    assert_eq!(C_CHAOS, 3, "C_CHAOS should be 3");
    assert_eq!(C_HESIOD, 4, "C_HESIOD should be 4");
    assert_eq!(C_ANY, 255, "C_ANY should be 255");
    
    // Verify types
    let _: u16 = C_IN;
    let _: u16 = C_CHAOS;
    let _: u16 = C_HESIOD;
    let _: u16 = C_ANY;
}

#[test]
fn test_resource_record_types() {
    // Verify common RR types exist and have correct values
    assert_eq!(T_A, 1, "A record type should be 1");
    assert_eq!(T_NS, 2, "NS record type should be 2");
    assert_eq!(T_CNAME, 5, "CNAME record type should be 5");
    assert_eq!(T_SOA, 6, "SOA record type should be 6");
    assert_eq!(T_PTR, 12, "PTR record type should be 12");
    assert_eq!(T_MX, 15, "MX record type should be 15");
    assert_eq!(T_TXT, 16, "TXT record type should be 16");
    assert_eq!(T_AAAA, 28, "AAAA record type should be 28");
    assert_eq!(T_SRV, 33, "SRV record type should be 33");
    assert_eq!(T_NAPTR, 35, "NAPTR record type should be 35");
    assert_eq!(T_OPT, 41, "OPT pseudo-record type should be 41");
    assert_eq!(T_DS, 43, "DS record type should be 43");
    assert_eq!(T_RRSIG, 46, "RRSIG record type should be 46");
    assert_eq!(T_NSEC, 47, "NSEC record type should be 47");
    assert_eq!(T_DNSKEY, 48, "DNSKEY record type should be 48");
    assert_eq!(T_NSEC3, 50, "NSEC3 record type should be 50");
    
    // Verify types
    let _: u16 = T_A;
    let _: u16 = T_AAAA;
    let _: u16 = T_CNAME;
    let _: u16 = T_MX;
    let _: u16 = T_TXT;
    let _: u16 = T_SRV;
}

#[test]
fn test_dnssec_types() {
    // Verify DNSSEC-specific record types
    assert_eq!(T_DNSKEY, 48, "DNSKEY type should be 48");
    assert_eq!(T_RRSIG, 46, "RRSIG type should be 46");
    assert_eq!(T_NSEC, 47, "NSEC type should be 47");
    assert_eq!(T_DS, 43, "DS type should be 43");
    assert_eq!(T_NSEC3, 50, "NSEC3 type should be 50");
}

#[test]
fn test_edns0_options() {
    // Verify EDNS0 option codes exist
    let _: u16 = EDNS0_OPTION_MAC;
    let _: u16 = EDNS0_OPTION_CLIENT_SUBNET;
    let _: u16 = EDNS0_OPTION_NOMDEVICEID;
    let _: u16 = EDNS0_OPTION_NOMCPEID;
}

#[test]
fn test_extended_dns_errors() {
    // Verify EDE codes exist and are i32 type
    let _: i32 = EDE_UNSET;
    let _: i32 = EDE_OTHER;
    let _: i32 = EDE_USUPDNSKEY;
    let _: i32 = EDE_USUPDS;
    let _: i32 = EDE_STALE;
    let _: i32 = EDE_FORGED;
    let _: i32 = EDE_DNSSEC_IND;
    let _: i32 = EDE_DNSSEC_BOGUS;
    let _: i32 = EDE_SIG_EXP;
    let _: i32 = EDE_SIG_NYV;
    let _: i32 = EDE_NO_DNSKEY;
    let _: i32 = EDE_NO_RRSIG;
    let _: i32 = EDE_NO_ZONEKEY;
    let _: i32 = EDE_NO_NSEC;
    let _: i32 = EDE_CACHED_ERR;
    let _: i32 = EDE_NOT_READY;
    let _: i32 = EDE_BLOCKED;
    let _: i32 = EDE_CENSORED;
    let _: i32 = EDE_FILTERED;
    let _: i32 = EDE_PROHIBITED;
    let _: i32 = EDE_STALE_NXD;
    let _: i32 = EDE_NOT_AUTH;
    let _: i32 = EDE_NOT_SUP;
    let _: i32 = EDE_NO_AUTH;
    let _: i32 = EDE_NETERR;
    let _: i32 = EDE_INVALID_DATA;
    let _: i32 = EDE_SIG_E_B_V;
    let _: i32 = EDE_TOO_EARLY;
    let _: i32 = EDE_UNS_NS3_ITER;
    let _: i32 = EDE_UNABLE_POLICY;
    let _: i32 = EDE_SYNTHESIZED;
    
    // Verify EDE_UNSET is negative
    assert_eq!(EDE_UNSET, -1, "EDE_UNSET should be -1");
    // Note: EDE_UNSET is -1, confirming it's negative as per specification
}

#[test]
fn test_dns_header_flags() {
    // Verify DNS header flag bit masks exist
    let _: u8 = HB3_QR;
    let _: u8 = HB3_OPCODE;
    let _: u8 = HB3_AA;
    let _: u8 = HB3_TC;
    let _: u8 = HB3_RD;
    let _: u8 = HB4_RA;
    let _: u8 = HB4_AD;
    let _: u8 = HB4_CD;
    let _: u8 = HB4_RCODE;
    
    // Verify specific flag values
    assert_eq!(HB3_QR, 0x80, "QR flag should be 0x80");
    assert_eq!(HB3_AA, 0x04, "AA flag should be 0x04");
    assert_eq!(HB3_RD, 0x01, "RD flag should be 0x01");
}

#[test]
fn test_name_escape() {
    assert_eq!(NAME_ESCAPE, 1, "NAME_ESCAPE should be 1");
    let _: u8 = NAME_ESCAPE;
}

#[test]
fn test_constant_types_comprehensive() {
    // Comprehensive type checking for all major constant categories
    
    // Port numbers are u16
    let _port: u16 = NAMESERVER_PORT;
    let _port: u16 = TFTP_PORT;
    let _port: u16 = MIN_PORT;
    let _port: u16 = MAX_PORT;
    
    // Sizes are usize
    let _size: usize = IN6ADDRSZ;
    let _size: usize = INADDRSZ;
    let _size: usize = PACKETSZ;
    let _size: usize = MAXDNAME;
    let _size: usize = RRFIXEDSZ;
    let _size: usize = MAXLABEL;
    
    // Response codes and opcodes are u8
    let _code: u8 = NOERROR;
    let _code: u8 = QUERY;
    
    // Class codes are u16
    let _class: u16 = C_IN;
    
    // Record types are u16
    let _type: u16 = T_A;
    
    // EDE codes are i32
    let _ede: i32 = EDE_UNSET;
    
    // Header flags are u8
    let _flag: u8 = HB3_QR;
    
    // NAME_ESCAPE is u8
    let _escape: u8 = NAME_ESCAPE;
}

#[test]
fn test_constant_values_match_rfcs() {
    // Verify values match RFC specifications
    
    // RFC 1035 - Basic DNS
    assert_eq!(NAMESERVER_PORT, 53, "RFC 1035: DNS port");
    assert_eq!(PACKETSZ, 512, "RFC 1035: Default UDP packet size");
    assert_eq!(MAXLABEL, 63, "RFC 1035: Maximum label length");
    
    // RFC 1035 - Response codes
    assert_eq!(NOERROR, 0, "RFC 1035: No error");
    assert_eq!(FORMERR, 1, "RFC 1035: Format error");
    assert_eq!(SERVFAIL, 2, "RFC 1035: Server failure");
    assert_eq!(NXDOMAIN, 3, "RFC 1035: Non-existent domain");
    assert_eq!(NOTIMP, 4, "RFC 1035: Not implemented");
    assert_eq!(REFUSED, 5, "RFC 1035: Query refused");
    
    // RFC 1035 - Classes
    assert_eq!(C_IN, 1, "RFC 1035: Internet class");
    assert_eq!(C_CHAOS, 3, "RFC 1035: CHAOS class");
    assert_eq!(C_HESIOD, 4, "RFC 1035: Hesiod class");
    assert_eq!(C_ANY, 255, "RFC 1035: ANY class");
    
    // RFC 4034 - DNSSEC Resource Records
    assert_eq!(T_DNSKEY, 48, "RFC 4034: DNSKEY");
    assert_eq!(T_RRSIG, 46, "RFC 4034: RRSIG");
    assert_eq!(T_NSEC, 47, "RFC 4034: NSEC");
    assert_eq!(T_DS, 43, "RFC 4034: DS");
    assert_eq!(T_NSEC3, 50, "RFC 5155: NSEC3");
}
