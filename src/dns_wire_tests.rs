use super::*;
use crate::blocklist::Blocklist;

const QUERY: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

#[test]
fn literal_opt_wire_uses_low_flags_bit_and_preserves_options() {
    let mut wire = QUERY.to_vec();
    wire[11] = 1;
    wire.extend_from_slice(b"\0\0\x29\x10\0\0\0\x80\0\0\x08\0\x0a\0\x04abcd");
    let (msg, offset) = DnsMessage::parse_wire(&wire).unwrap();
    assert!(msg.edns_do);
    assert_eq!(msg.additionals[0].ttl, 0x0000_8000);
    let patched = query_with_udp_size(&wire, offset, 1232);
    let mut expected = wire.clone();
    expected[QUERY.len() + 3..QUERY.len() + 5].copy_from_slice(&[0x04, 0xd0]);
    assert_eq!(patched, expected);
}

#[test]
fn legacy_query_is_forwarded_without_an_opt() {
    let (_, offset) = DnsMessage::parse_wire(QUERY).unwrap();
    assert_eq!(query_with_udp_size(QUERY, offset, 1232).as_ref(), QUERY);
}

#[test]
fn extended_rcode_high_bit_is_not_do() {
    let mut wire = QUERY.to_vec();
    wire[11] = 1;
    wire.extend_from_slice(b"\0\0\x29\x04\xd0\x80\0\0\0\0\0");
    assert!(!DnsMessage::parse(&wire).unwrap().edns_do);
}

#[test]
fn raw_rewrite_keeps_packet_relative_rdata_pointers() {
    let mut wire = QUERY.to_vec();
    wire[11] = 3;
    // Place OPT before the other records so relocating it would break their pointers.
    wire.extend_from_slice(b"\0\0\x29\x10\0\0\0\0\0\0\0");
    // An NS record's RDATA introduces an uncompressed target name.
    wire.extend_from_slice(b"\xc0\x0c\0\x02\0\x01\0\0\0\x3c\0\x10");
    let target_offset = wire.len();
    wire.extend_from_slice(b"\x06target\x07example\0");
    wire.extend_from_slice(b"\xc0\x0c\0\x05\0\x01\0\0\0\x3c\0\x02");
    wire.extend_from_slice(&(0xc000 | target_offset as u16).to_be_bytes());
    let (before, offset) = DnsMessage::parse_wire(&wire).unwrap();
    assert_eq!(
        before.additionals[2].cname_target.as_deref(),
        Some("target.example")
    );
    let patched = query_with_udp_size(&wire, offset, 1232);
    let mut expected = wire.clone();
    expected[QUERY.len() + 3..QUERY.len() + 5].copy_from_slice(&1232u16.to_be_bytes());
    assert_eq!(patched, expected);
    let after = DnsMessage::parse(&patched).unwrap();
    assert_eq!(
        after.additionals[2].cname_target,
        before.additionals[2].cname_target
    );
    assert_eq!(after.additionals[1].rdata, before.additionals[1].rdata);
}

#[test]
fn binary_label_octets_round_trip_without_changing_boundaries() {
    let wire = b"\x07foo.bar\x04\xff\0\\\n\x04test\0";
    let name = parse_name(&mut Cursor::new(wire.as_slice())).unwrap();
    assert_eq!(name, r"foo\046bar.\255\000\092\010.test");
    assert_eq!(serialize_name(&name).unwrap(), wire);
    let mut rules = Blocklist::new();
    rules.block_suffixes.insert("bar.test".into());
    assert!(!rules.matches(&name));
    let dotted = parse_name(&mut Cursor::new(b"\x07foo.bar\x04test\0".as_slice())).unwrap();
    assert!(!rules.matches(&dotted));
    rules.block_suffixes.insert("test".into());
    assert!(rules.matches(&dotted));
}

#[test]
fn every_label_octet_can_be_represented_reversibly() {
    for start in [0u8, 63, 126, 189, 252] {
        let label: Vec<_> = (u16::from(start)..(u16::from(start) + 63).min(256))
            .map(|b| b as u8)
            .collect();
        let mut wire = vec![label.len() as u8];
        wire.extend(label);
        wire.push(0);
        let parsed = parse_name(&mut Cursor::new(wire.as_slice())).unwrap();
        assert_eq!(serialize_name(&parsed).unwrap(), wire);
    }
}

#[test]
fn compressed_binary_name_restores_cursor_after_pointer() {
    let wire = b"\x03a.b\0\xc0\0TAIL";
    let mut reader = Cursor::new(wire.as_slice());
    reader.set_position(5);
    let name = parse_name(&mut reader).unwrap();
    assert_eq!(name, r"a\046b");
    assert_eq!(reader.position(), 7);
    assert_eq!(serialize_name(&name).unwrap(), &wire[..5]);
}

#[test]
fn root_and_maximum_length_names_are_valid() {
    assert_eq!(serialize_name("").unwrap(), [0]);
    assert_eq!(serialize_name(".").unwrap(), [0]);
    assert_eq!(parse_name(&mut Cursor::new(b"\0".as_slice())).unwrap(), "");
    let longest = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    let wire = serialize_name(&longest).unwrap();
    assert_eq!(wire.len(), 255);
    assert_eq!(
        parse_name(&mut Cursor::new(wire.as_slice())).unwrap(),
        longest
    );
    assert_eq!(
        serialize_name("example.com.").unwrap(),
        serialize_name("example.com").unwrap()
    );
}

#[test]
fn invalid_name_encodings_are_rejected() {
    for name in ["a..b", ".a", r"a\", r"a\2", r"a\999"] {
        assert!(serialize_name(name).is_err(), "{name:?}");
    }
    assert!(serialize_name(&"a".repeat(64)).is_err());
    let oversized = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62),
    ]
    .join(".");
    assert!(serialize_name(&oversized).is_err());
    let mut wire = Vec::new();
    for _ in 0..4 {
        wire.push(63);
        wire.extend([b'a'; 63]);
    }
    wire.push(0);
    assert!(parse_name(&mut Cursor::new(wire.as_slice())).is_err());
    for prefix in [0x40, 0x80] {
        let mut wire = vec![prefix];
        wire.extend([b'a'; 128]);
        wire.push(0);
        assert!(parse_name(&mut Cursor::new(wire.as_slice())).is_err());
    }
}

#[test]
fn expanded_name_limit_also_applies_through_compression() {
    let mut wire = Vec::new();
    for _ in 0..3 {
        wire.push(63);
        wire.extend([b'a'; 63]);
    }
    wire.push(0);
    let start = wire.len();
    wire.push(63);
    wire.extend([b'b'; 63]);
    wire.extend([0xc0, 0]);
    let mut reader = Cursor::new(wire.as_slice());
    reader.set_position(start as u64);
    assert!(parse_name(&mut reader).is_err());
}

#[test]
fn invalid_cname_lengths_and_compression_are_rejected() {
    for (len, rdata) in [
        (1, vec![0xc0, 0x0c]),
        (3, vec![0xc0, 0x0c, 0]),
        (2, vec![0xc0, 0xff]),
    ] {
        let mut wire = QUERY.to_vec();
        wire[2] = 0x81;
        wire[3] = 0x80;
        wire[7] = 1;
        wire.extend_from_slice(b"\xc0\x0c\0\x05\0\x01\0\0\0\x3c");
        wire.extend_from_slice(&(len as u16).to_be_bytes());
        wire.extend(rdata);
        assert!(DnsMessage::parse(&wire).is_err());
    }
}

#[test]
fn section_counts_follow_vectors_and_oversized_rdata_is_rejected() {
    let mut msg = DnsMessage::new_query(1, "example.com", 1);
    msg.header.qdcount = 10;
    msg.header.ancount = 12;
    let parsed = DnsMessage::parse(&msg.serialize().unwrap()).unwrap();
    assert_eq!(parsed.header.qdcount, 1);
    assert_eq!(parsed.header.ancount, 0);
    let rr = DnsResourceRecord {
        name: "".into(),
        rtype: 16,
        rclass: 1,
        ttl: 0,
        rdata: vec![0; 65536],
        cname_target: None,
    };
    assert!(rr.serialize().is_err());
}

#[test]
fn extra_bytes_and_invalid_opt_layout_are_rejected() {
    let mut trailing = QUERY.to_vec();
    trailing.push(0);
    assert!(DnsMessage::parse(&trailing).is_err());
    let opt = b"\0\0\x29\x04\xd0\0\0\x80\0\0\0";
    let mut duplicated = QUERY.to_vec();
    duplicated[11] = 2;
    duplicated.extend_from_slice(opt);
    duplicated.extend_from_slice(opt);
    assert!(DnsMessage::parse(&duplicated).is_err());
    let mut wrong_section = QUERY.to_vec();
    wrong_section[7] = 1;
    wrong_section.extend_from_slice(opt);
    assert!(DnsMessage::parse(&wrong_section).is_err());
}

#[test]
fn truncated_input_prefixes_never_panic() {
    let mut packet = QUERY.to_vec();
    packet[11] = 1;
    packet.extend_from_slice(b"\0\0\x29\x04\xd0\0\0\x80\0\0\0");
    for len in 0..packet.len() {
        let result = std::panic::catch_unwind(|| DnsMessage::parse(&packet[..len]));
        assert!(result.is_ok(), "prefix {len} panicked");
        assert!(result.unwrap().is_err());
    }
}
