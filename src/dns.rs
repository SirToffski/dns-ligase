use std::borrow::Cow;
use std::convert::TryInto;
use std::io::{self, Cursor, Read};
use std::net::Ipv4Addr;

/// OPT TTL: the high bit of its low 16-bit flags field (RFC 6891).
pub const EDNS_DO: u32 = 0x0000_8000;
pub const MAX_DNS_MESSAGE: usize = u16::MAX as usize;

#[cfg(test)]
#[path = "dns_wire_tests.rs"]
mod wire_tests;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    #[allow(dead_code)]
    pub fn new(
        id: u16,
        flags: u16,
        qdcount: u16,
        ancount: u16,
        nscount: u16,
        arcount: u16,
    ) -> Self {
        Self {
            id,
            flags,
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }

    pub fn parse(reader: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let mut buf = [0u8; 12];
        reader.read_exact(&mut buf)?;
        Ok(Self {
            id: u16::from_be_bytes(buf[0..2].try_into().unwrap()),
            flags: u16::from_be_bytes(buf[2..4].try_into().unwrap()),
            qdcount: u16::from_be_bytes(buf[4..6].try_into().unwrap()),
            ancount: u16::from_be_bytes(buf[6..8].try_into().unwrap()),
            nscount: u16::from_be_bytes(buf[8..10].try_into().unwrap()),
            arcount: u16::from_be_bytes(buf[10..12].try_into().unwrap()),
        })
    }

    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());
        Ok(buf)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn parse(reader: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let name = parse_name(reader)?;
        let mut type_buf = [0u8; 4];
        reader.read_exact(&mut type_buf)?;
        let qtype = u16::from_be_bytes(type_buf[0..2].try_into().unwrap());
        let qclass = u16::from_be_bytes(type_buf[2..4].try_into().unwrap());
        Ok(Self {
            name,
            qtype,
            qclass,
        })
    }

    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut buf = serialize_name(&self.name)?;
        buf.extend_from_slice(&self.qtype.to_be_bytes());
        buf.extend_from_slice(&self.qclass.to_be_bytes());
        Ok(buf)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DnsResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    /// For CNAME records (rtype == 5), the resolved target domain name. CNAME
    /// rdata is a domain name that may use compression pointers into the full
    /// packet, so it must be parsed from the cursor (not the rdata slice).
    /// None for all other record types.
    pub cname_target: Option<String>,
}

impl DnsResourceRecord {
    pub fn parse(reader: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let name = parse_name(reader)?;
        let mut meta_buf = [0u8; 10];
        reader.read_exact(&mut meta_buf)?;
        let rtype = u16::from_be_bytes(meta_buf[0..2].try_into().unwrap());
        let rclass = u16::from_be_bytes(meta_buf[2..4].try_into().unwrap());
        let ttl = u32::from_be_bytes(meta_buf[4..8].try_into().unwrap());
        let rdlength = u16::from_be_bytes(meta_buf[8..10].try_into().unwrap());
        if reader.position() as usize + rdlength as usize > reader.get_ref().len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Truncated RDATA",
            ));
        }

        // For CNAME records, parse the target domain name from the rdata
        // position (which may contain compression pointers into the full
        // packet), then restore the cursor so the normal rdata read still
        // happens. This is the only type whose rdata we need to interpret.
        let cname_target = if rtype == 5 {
            let saved = reader.position();
            let target = parse_name(reader)?;
            if reader.position() != saved + u64::from(rdlength) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CNAME length mismatch",
                ));
            }
            reader.set_position(saved);
            Some(target)
        } else {
            None
        };

        let mut rdata = vec![0u8; rdlength as usize];
        reader.read_exact(&mut rdata)?;

        Ok(Self {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
            cname_target,
        })
    }

    /// Serialize a locally constructed RR. Opaque RDATA must be independent
    /// of packet offsets; parsed packets should be relayed in their wire form.
    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut buf = serialize_name(&self.name)?;
        buf.extend_from_slice(&self.rtype.to_be_bytes());
        buf.extend_from_slice(&self.rclass.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        // CNAME is the one name-bearing RDATA type we decode. Expand it when
        // constructing a new packet instead of copying its old pointers.
        let cname;
        let rdata = if let Some(target) = self.cname_target.as_ref().filter(|_| self.rtype == 5) {
            cname = serialize_name(target)?;
            &cname
        } else {
            &self.rdata
        };
        let len = u16::try_from(rdata.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "RDATA too long"))?;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(rdata);
        Ok(buf)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub authorities: Vec<DnsResourceRecord>,
    pub additionals: Vec<DnsResourceRecord>,
    pub edns_do: bool,
}

impl DnsMessage {
    /// Build a standard query: RD set, one question, qclass IN.
    pub fn new_query(id: u16, name: &str, qtype: u16) -> Self {
        Self {
            header: DnsHeader {
                id,
                flags: 0x0100,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                name: name.to_string(),
                qtype,
                qclass: 1,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns_do: false,
        }
    }

    /// Extract IPv4 addresses from the answer section (rtype == 1,
    /// rdata.len() == 4). CNAME records (rtype == 5) and malformed A records
    /// are ignored — a CNAME ahead of the A records is normal and needs no
    /// special handling since we only want the final addresses.
    pub fn a_records(&self) -> Vec<Ipv4Addr> {
        self.answers
            .iter()
            .filter(|rr| rr.rtype == 1 && rr.rdata.len() == 4)
            .map(|rr| Ipv4Addr::new(rr.rdata[0], rr.rdata[1], rr.rdata[2], rr.rdata[3]))
            .collect()
    }

    pub fn parse(data: &[u8]) -> io::Result<Self> {
        Self::parse_wire(data).map(|(message, _)| message)
    }

    /// Also retain the OPT metadata offset for an in-place forwarding edit.
    pub(crate) fn parse_wire(data: &[u8]) -> io::Result<(Self, Option<usize>)> {
        if data.len() > MAX_DNS_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS message too long",
            ));
        }
        let mut reader = Cursor::new(data);
        let header = DnsHeader::parse(&mut reader)?;

        let mut questions = Vec::new();
        for _ in 0..header.qdcount {
            questions.push(DnsQuestion::parse(&mut reader)?);
        }

        let mut answers = Vec::new();
        for _ in 0..header.ancount {
            answers.push(DnsResourceRecord::parse(&mut reader)?);
        }

        let mut authorities = Vec::new();
        for _ in 0..header.nscount {
            authorities.push(DnsResourceRecord::parse(&mut reader)?);
        }

        let mut additionals = Vec::new();
        let mut opt_offset = None;
        for _ in 0..header.arcount {
            let rr = DnsResourceRecord::parse(&mut reader)?;
            if rr.rtype == 41 {
                opt_offset = Some(reader.position() as usize - rr.rdata.len() - 10);
            }
            additionals.push(rr);
        }

        if reader.position() as usize != data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Trailing DNS data",
            ));
        }
        if answers.iter().chain(&authorities).any(|rr| rr.rtype == 41) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OPT outside additional section",
            ));
        }
        let mut opts = additionals.iter().filter(|rr| rr.rtype == 41);
        let opt = opts.next();
        if opts.next().is_some() || opt.is_some_and(|rr| !rr.name.is_empty()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid OPT record",
            ));
        }
        let edns_do = opt.is_some_and(|opt| opt.ttl & EDNS_DO != 0);

        Ok((
            Self {
                header,
                questions,
                answers,
                authorities,
                additionals,
                edns_do,
            },
            opt_offset,
        ))
    }

    /// Construct a packet. Use `query_with_udp_size` to modify existing wire data:
    /// opaque RDATA in parsed records can contain packet-relative pointers.
    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut header = self.header.clone();
        let count = |len| {
            u16::try_from(len)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Too many DNS records"))
        };
        header.qdcount = count(self.questions.len())?;
        header.ancount = count(self.answers.len())?;
        header.nscount = count(self.authorities.len())?;
        header.arcount = count(self.additionals.len())?;
        let mut buf = header.serialize()?;
        for q in &self.questions {
            buf.extend(q.serialize()?);
        }
        for a in &self.answers {
            buf.extend(a.serialize()?);
        }
        for au in &self.authorities {
            buf.extend(au.serialize()?);
        }
        for ad in &self.additionals {
            buf.extend(ad.serialize()?);
        }
        if buf.len() > MAX_DNS_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS message too long",
            ));
        }
        Ok(buf)
    }

    #[allow(dead_code)] // Also useful for locally constructed library packets.
    pub fn add_opt_record(&mut self, buffer_size: u16) -> io::Result<()> {
        if let Some(opt) = self.additionals.iter_mut().find(|r| r.rtype == 41) {
            opt.rclass = buffer_size;
            opt.ttl |= EDNS_DO;
        } else {
            let opt = DnsResourceRecord {
                name: "".to_string(),
                rtype: 41,
                rclass: buffer_size,
                ttl: EDNS_DO,
                rdata: vec![],
                cname_target: None,
            };
            self.additionals.push(opt);
        }
        self.header.arcount = u16::try_from(self.additionals.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Too many DNS records"))?;
        self.edns_do = true;
        Ok(())
    }
}

/// Adjust an existing OPT's payload size without changing DO, options, or packet offsets.
pub(crate) fn query_with_udp_size(
    data: &[u8],
    opt_offset: Option<usize>,
    buffer_size: u16,
) -> Cow<'_, [u8]> {
    let mut wire = Cow::Borrowed(data);
    if let Some(offset) = opt_offset {
        let size = offset + 2..offset + 4;
        if data[size.clone()] != buffer_size.to_be_bytes() {
            wire.to_mut()[size].copy_from_slice(&buffer_size.to_be_bytes());
        }
    }
    wire
}

/// A reversible presentation name: separators are dots; dots, backslashes
/// and non-printable/non-ASCII label octets are decimal escapes. This keeps
/// suffix matching from treating an embedded dot as a new DNS label.
pub fn parse_name(reader: &mut Cursor<&[u8]>) -> io::Result<String> {
    use std::fmt::Write;
    let mut name = String::new();
    let mut jumps = 0;
    let mut resume = None;
    let mut expanded_len = 1;
    loop {
        let pos = reader.position() as usize;
        let len = *reader
            .get_ref()
            .get(pos)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "End of data"))?;
        match len {
            0 => {
                reader.set_position(resume.unwrap_or(pos + 1) as u64);
                return Ok(name);
            }
            0xc0..=0xff => {
                let next = *reader.get_ref().get(pos + 1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Truncated compression pointer",
                    )
                })?;
                let offset = (usize::from(len & 0x3f) << 8) | usize::from(next);
                if offset >= reader.get_ref().len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Pointer out of bounds",
                    ));
                }
                resume.get_or_insert(pos + 2);
                jumps += 1;
                if jumps > 64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Too many DNS name compression jumps",
                    ));
                }
                reader.set_position(offset as u64);
            }
            1..=63 => {
                expanded_len += usize::from(len) + 1;
                if expanded_len > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNS name exceeds 255 octets",
                    ));
                }
                let end = pos + 1 + usize::from(len);
                let label = reader.get_ref().get(pos + 1..end).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "Truncated label")
                })?;
                if !name.is_empty() {
                    name.push('.');
                }
                for &byte in label {
                    if (b'!'..=b'~').contains(&byte) && byte != b'.' && byte != b'\\' {
                        name.push(char::from(byte));
                    } else {
                        let _ = write!(name, "\\{byte:03}");
                    }
                }
                reader.set_position(end as u64);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unsupported DNS label type",
                ))
            }
        }
    }
}

/// Encode a presentation name, checking both label and expanded name limits.
pub fn serialize_name(name: &str) -> io::Result<Vec<u8>> {
    if name.is_empty() || name == "." {
        return Ok(vec![0]);
    }
    let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
    let mut wire = Vec::new();
    let mut label = Vec::new();
    let bytes = name.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        match bytes[pos] {
            b'.' => {
                if label.is_empty() {
                    return Err(invalid("Empty DNS label"));
                }
                wire.push(label.len() as u8);
                wire.extend_from_slice(&label);
                label.clear();
                pos += 1;
            }
            b'\\' => {
                pos += 1;
                let first = *bytes
                    .get(pos)
                    .ok_or_else(|| invalid("Incomplete DNS name escape"))?;
                if first.is_ascii_digit() {
                    let digits = bytes
                        .get(pos..pos + 3)
                        .filter(|s| s.iter().all(u8::is_ascii_digit))
                        .ok_or_else(|| invalid("Expected three decimal escape digits"))?;
                    let value = (u16::from(digits[0] - b'0') * 100)
                        + (u16::from(digits[1] - b'0') * 10)
                        + u16::from(digits[2] - b'0');
                    label.push(u8::try_from(value).map_err(|_| invalid("DNS escape exceeds 255"))?);
                    pos += 3;
                } else {
                    label.push(first);
                    pos += 1;
                }
            }
            byte => {
                label.push(byte);
                pos += 1;
            }
        }
        if label.len() > 63 {
            return Err(invalid("DNS label exceeds 63 octets"));
        }
    }
    if !label.is_empty() {
        wire.push(label.len() as u8);
        wire.extend_from_slice(&label);
    }
    wire.push(0);
    if wire.len() > 255 {
        return Err(invalid("DNS name exceeds 255 octets"));
    }
    Ok(wire)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_dns_message_serialize_parse() {
        let header = DnsHeader::new(0x1234, 0x0100, 1, 0, 0, 0);
        let question = DnsQuestion {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
        };
        let msg = DnsMessage {
            header,
            questions: vec![question],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns_do: false,
        };

        let serialized = msg.serialize().unwrap();
        let parsed = DnsMessage::parse(&serialized).unwrap();

        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_parse_real_packet() {
        // A hardcoded UDP DNS query for 'google.com' (Type A, Class IN)
        // Header: ID=0x1234, Flags=0x0100, QD=1, AN=0, NS=0, AR=0
        // Question: google.com (0x06 + google + 0x03 + com + 0x00), Type A (0x0001), Class IN (0x0001)
        let raw_packet: [u8; 28] = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];

        let parsed = DnsMessage::parse(&raw_packet).expect("Failed to parse real packet");

        assert_eq!(parsed.header.id, 0x1234);
        assert_eq!(parsed.header.qdcount, 1);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "google.com");
        assert_eq!(parsed.questions[0].qtype, 1);
        assert_eq!(parsed.questions[0].qclass, 1);
    }

    #[test]
    fn test_malicious_pointer_lone_c0() {
        // Packet ends with a lone 0xC0 pointer
        let raw_packet: [u8; 13] = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0
        ];
        let mut reader = Cursor::new(&raw_packet[..]);
        let result = parse_name(&mut reader);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[test]
    fn test_malicious_pointer_out_of_bounds() {
        // Packet has a pointer (0xC0 0x05) pointing to offset 5, but only 4 bytes exist.
        let raw_packet: [u8; 4] = [0xC0, 0x05, 0x00, 0x00];
        let mut reader = Cursor::new(&raw_packet[..]);
        let result = parse_name(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_malicious_pointer_infinite_loop() {
        // Create a packet where a pointer leads to an infinite loop
        // byte 0: 0xC0 0x02 (pointer to offset 2)
        // byte 2: 0xC0 0x02 (pointer to offset 2)
        let raw_packet: [u8; 4] = [0xC0, 0x02, 0xC0, 0x02];
        let mut reader = Cursor::new(&raw_packet[..]);
        let result = parse_name(&mut reader);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.to_string(), "Too many DNS name compression jumps");
        }
    }

    #[test]
    fn test_edns_opt_record() {
        let header = DnsHeader::new(0x1234, 0x0100, 0, 0, 0, 1);
        let mut msg = DnsMessage {
            header,
            questions: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns_do: false,
        };

        msg.add_opt_record(1232).unwrap();
        assert!(msg.edns_do);
        let serialized = msg.serialize().unwrap();
        let parsed = DnsMessage::parse(&serialized).unwrap();
        assert!(parsed.edns_do);
        assert_eq!(parsed.additionals.len(), 1);
        assert_eq!(parsed.additionals[0].rtype, 41);
        assert_eq!(parsed.additionals[0].rclass, 1232);
    }

    #[test]
    fn test_new_query_round_trip() {
        let msg = DnsMessage::new_query(0xABCD, "example.com", 1);
        assert_eq!(msg.header.flags, 0x0100);
        assert_eq!(msg.header.qdcount, 1);
        let serialized = msg.serialize().unwrap();
        let parsed = DnsMessage::parse(&serialized).unwrap();
        assert_eq!(parsed.header.id, 0xABCD);
        assert_eq!(parsed.header.flags & 0x0100, 0x0100);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "example.com");
        assert_eq!(parsed.questions[0].qtype, 1);
        assert_eq!(parsed.questions[0].qclass, 1);
    }

    fn a_rr(name: &str, octets: [u8; 4]) -> crate::dns::DnsResourceRecord {
        crate::dns::DnsResourceRecord {
            name: name.to_string(),
            rtype: 1,
            rclass: 1,
            ttl: 300,
            rdata: octets.to_vec(),
            cname_target: None,
        }
    }

    fn cname_rr(name: &str, target: &str) -> crate::dns::DnsResourceRecord {
        crate::dns::DnsResourceRecord {
            name: name.to_string(),
            rtype: 5,
            rclass: 1,
            ttl: 300,
            rdata: crate::dns::serialize_name(target).unwrap(),
            cname_target: Some(target.to_string()),
        }
    }

    #[test]
    fn test_a_records_with_cname_then_two_a() {
        let mut msg = DnsMessage::new_query(1, "example.com", 1);
        msg.answers = vec![
            cname_rr("example.com", "alias.example.net"),
            a_rr("alias.example.net", [93, 184, 216, 34]),
            a_rr("alias.example.net", [93, 184, 216, 35]),
        ];
        let addrs = msg.a_records();
        assert_eq!(
            addrs,
            vec![
                Ipv4Addr::new(93, 184, 216, 34),
                Ipv4Addr::new(93, 184, 216, 35),
            ]
        );
    }

    #[test]
    fn test_a_records_only_cname_is_empty() {
        let mut msg = DnsMessage::new_query(1, "example.com", 1);
        msg.answers = vec![cname_rr("example.com", "alias.example.net")];
        assert!(msg.a_records().is_empty());
    }

    #[test]
    fn test_a_records_ignores_malformed() {
        let mut msg = DnsMessage::new_query(1, "example.com", 1);
        msg.answers = vec![
            crate::dns::DnsResourceRecord {
                name: "example.com".to_string(),
                rtype: 1,
                rclass: 1,
                ttl: 300,
                rdata: vec![1, 2, 3], // too short
                cname_target: None,
            },
            crate::dns::DnsResourceRecord {
                name: "example.com".to_string(),
                rtype: 1,
                rclass: 1,
                ttl: 300,
                rdata: vec![1, 2, 3, 4, 5], // too long
                cname_target: None,
            },
            a_rr("example.com", [9, 9, 9, 9]),
        ];
        assert_eq!(msg.a_records(), vec![Ipv4Addr::new(9, 9, 9, 9)]);
    }
}
