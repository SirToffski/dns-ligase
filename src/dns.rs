use std::convert::TryInto;
use std::io::{self, Cursor, Read};

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
    pub fn new(id: u16, flags: u16, qdcount: u16, ancount: u16, nscount: u16, arcount: u16) -> Self {
        Self { id, flags, qdcount, ancount, nscount, arcount }
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
        Ok(Self { name, qtype, qclass })
    }

    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut buf = serialize_name(&self.name);
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

        let mut rdata = vec![0u8; rdlength as usize];
        reader.read_exact(&mut rdata)?;

        Ok(Self { name, rtype, rclass, ttl, rdata })
    }

    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut buf = serialize_name(&self.name);
        buf.extend_from_slice(&self.rtype.to_be_bytes());
        buf.extend_from_slice(&self.rclass.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        buf.extend_from_slice(&(self.rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.rdata);
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
    pub fn parse(data: &[u8]) -> io::Result<Self> {
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
        for _ in 0..header.arcount {
            additionals.push(DnsResourceRecord::parse(&mut reader)?);
        }

        let mut edns_do = false;
        for opt in &additionals {
            if opt.rtype == 41 { // OPT record type
                if (opt.ttl & 0x80000000) != 0 {
                    edns_do = true;
                }
            }
        }

        Ok(Self { header, questions, answers, authorities, additionals, edns_do })
    }

    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut header = self.header.clone();
        header.arcount = self.additionals.len() as u16;
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
        Ok(buf)
    }

    pub fn add_opt_record(&mut self, buffer_size: u16) {
        if let Some(opt) = self.additionals.iter_mut().find(|r| r.rtype == 41) {
            opt.rclass = buffer_size;
            opt.ttl |= 0x80000000; // Set DO bit in TTL
        } else {
            let mut ttl = 0u32;
            ttl |= 0x80000000; // Set DO bit in TTL

            let opt = DnsResourceRecord {
                name: "".to_string(),
                rtype: 41,
                rclass: buffer_size,
                ttl,
                rdata: vec![],
            };
            self.additionals.push(opt);
            self.header.arcount += 1;
        }
    }
}

pub fn parse_name(reader: &mut Cursor<&[u8]>) -> io::Result<String> {
    let mut labels = Vec::new();
    let mut jumps = 0;
    let max_jumps = 64;
    let mut jumped = false;
    let mut jump_pos = 0;

    loop {
        let pos = reader.position() as usize;
        if pos >= reader.get_ref().len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "End of data"));
        }
        let len = reader.get_ref()[pos];
        if len == 0 {
            if !jumped {
                reader.set_position((pos + 1) as u64);
            }
            break;
        } else if (len & 0xC0) == 0xC0 {
            if pos + 1 >= reader.get_ref().len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Truncated compression pointer"));
            }
            let offset = (((len & 0x3F) as usize) << 8) | (reader.get_ref()[pos + 1] as usize);
            if offset >= reader.get_ref().len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Pointer out of bounds"));
            }
            if !jumped {
                jump_pos = pos + 2;
                jumped = true;
            }
            reader.set_position(offset as u64);
            jumps += 1;
            if jumps > max_jumps {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Too many DNS name compression jumps"));
            }
        } else {
            let label_start = pos + 1;
            let label_end = label_start + len as usize;
            if label_end > reader.get_ref().len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Truncated label"));
            }
            let label = std::str::from_utf8(&reader.get_ref()[label_start..label_end])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in label"))?;
            labels.push(label.to_string());
            reader.set_position(label_end as u64);
        }
    }

    if jumped {
        reader.set_position(jump_pos as u64);
    }

    Ok(labels.join("."))
}

pub fn serialize_name(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for label in name.split('.') {
        if label.is_empty() { continue; }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf
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
        let mut msg = DnsMessage {
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

        msg.add_opt_record(1232);
        assert!(msg.edns_do == false); // add_opt_record doesn't set edns_do on the msg itself, but adds the record

        // Wait, add_opt_record sets ttl bit.
        // DnsMessage::parse should detect it.
        let serialized = msg.serialize().unwrap();
        let parsed = DnsMessage::parse(&serialized).unwrap();
        assert!(parsed.edns_do);
        assert_eq!(parsed.additionals.len(), 1);
        assert_eq!(parsed.additionals[0].rtype, 41);
        assert_eq!(parsed.additionals[0].rclass, 1232);
    }
}
