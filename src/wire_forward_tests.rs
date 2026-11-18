use super::*;
use crate::dns::{DnsHeader, DnsResourceRecord, EDNS_DO};
use std::sync::atomic::AtomicUsize;

#[test]
fn client_udp_limits_cover_small_and_large_advertisements() {
    let mut query = DnsMessage::new_query(1, "example.com", 1);
    assert_eq!(client_udp_limit(&query), 512);
    query.add_opt_record(1232).unwrap();
    for (advertised, expected) in [
        (0, 512),
        (128, 512),
        (512, 512),
        (1232, 1232),
        (8192, 8192),
        (65535, MAX_UDP_PAYLOAD),
    ] {
        query.additionals[0].rclass = advertised;
        assert_eq!(client_udp_limit(&query), expected);
    }
}

#[test]
fn truncated_response_drops_oversized_options_and_preserves_extended_rcode() {
    let mut msg = DnsMessage::new_query(1, "example.com", 1);
    msg.header.flags = 0x81a0;
    msg.add_opt_record(1232).unwrap();
    msg.additionals[0].ttl = 0x0100_8000;
    msg.additionals[0].rdata = vec![0; 1000];
    let wire = truncate_response(&msg.serialize().unwrap(), 512).unwrap();
    assert!(wire.len() <= 512);
    let parsed = DnsMessage::parse(&wire).unwrap();
    assert_ne!(parsed.header.flags & 0x0200, 0);
    assert_eq!(parsed.header.flags & 0x0020, 0);
    assert_eq!(parsed.additionals[0].ttl, 0x0100_8000);
    assert!(parsed.additionals[0].rdata.is_empty());
}

#[test]
fn blocked_response_preserves_question_bytes_and_request_flags() {
    let mut query = DnsMessage::new_query(1234, r"a\046b.\255.test", 28);
    query.header.flags = 0x0010; // CD, no RD
    let parsed = DnsMessage::parse(&build_nxdomain(&query).unwrap()).unwrap();
    assert_eq!(parsed.header.flags, 0x8093);
    assert_eq!(parsed.questions, query.questions);
    assert_eq!(parsed.header.qdcount, 1);
}

fn answer(query: &[u8], truncated: bool) -> Vec<u8> {
    let mut msg = DnsMessage::parse(query).unwrap();
    assert!(msg.edns_do);
    assert_eq!(msg.additionals[0].ttl & 0xff00_0000, 0);
    assert_eq!(msg.additionals[0].rclass, 1232);
    msg.header.flags = if truncated { 0x8380 } else { 0x8180 };
    if !truncated {
        // Three well-formed TXT character strings, making the reply >512 B.
        let mut rdata = Vec::new();
        for _ in 0..3 {
            rdata.push(200);
            rdata.extend([b'x'; 200]);
        }
        msg.answers.push(DnsResourceRecord {
            name: msg.questions[0].name.clone(),
            rtype: 16,
            rclass: 1,
            ttl: 60,
            rdata,
            cname_target: None,
        });
    }
    msg.serialize().unwrap()
}

#[tokio::test]
async fn udp_size_normalization_and_tcp_fallback_work_end_to_end() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();
    let udp_task = tokio::spawn(async move {
        let mut buf = [0; 65535];
        loop {
            let (n, client) = udp.recv_from(&mut buf).await.unwrap();
            let name = DnsMessage::parse(&buf[..n]).unwrap().questions[0]
                .name
                .clone();
            let reply = answer(&buf[..n], name == "fallback.test");
            udp.send_to(&reply, client).await.unwrap();
        }
    });
    let tcp_queries = Arc::new(AtomicUsize::new(0));
    let seen = tcp_queries.clone();
    let tcp_task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let seen = seen.clone();
            tasks.spawn(async move {
                while let Ok(len) = stream.read_u16().await {
                    let mut query = vec![0; len as usize];
                    if stream.read_exact(&mut query).await.is_err() {
                        break;
                    }
                    seen.fetch_add(1, Ordering::SeqCst);
                    let reply = answer(&query, false);
                    let mut frame = (reply.len() as u16).to_be_bytes().to_vec();
                    frame.extend(reply);
                    if stream.write_all(&frame).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let state = Arc::new(RwLock::new(Arc::new(QueryState {
        upstream: Arc::new(Upstream::new(addr)),
        blocklist: Arc::new(Blocklist::new()),
        clients: Arc::default(),
        log_queries: false,
    })));
    let forwarder = UdpForwarder::new("127.0.0.1:0", state).await.unwrap();
    let listen = forwarder.udp_socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        forwarder.run().await.unwrap();
    });
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (size, should_truncate) in [(0, true), (128, true), (8192, false)] {
        let mut query = DnsMessage::new_query(0x1234, "large.test", 16);
        query.add_opt_record(size).unwrap();
        client
            .send_to(&query.serialize().unwrap(), listen)
            .await
            .unwrap();
        let mut buf = [0; 8192];
        let n = timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tc_bit_set(&buf[..n]), should_truncate);
        if should_truncate {
            assert!(n <= 512);
        } else {
            assert_eq!(DnsMessage::parse(&buf[..n]).unwrap().answers.len(), 1);
        }
    }
    let query = DnsMessage::new_query(0x4321, "fallback.test", 16)
        .serialize()
        .unwrap();
    client.send_to(&query, listen).await.unwrap();
    let mut buf = [0; 4096];
    let n = timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(tc_bit_set(&buf[..n]));
    assert!(n <= 512);
    let mut stream = TcpStream::connect(listen).await.unwrap();
    let mut frame = (query.len() as u16).to_be_bytes().to_vec();
    frame.extend(query);
    stream.write_all(&frame).await.unwrap();
    let n = timeout(Duration::from_secs(2), stream.read_u16())
        .await
        .unwrap()
        .unwrap();
    let mut reply = vec![0; n as usize];
    stream.read_exact(&mut reply).await.unwrap();
    assert!(!tc_bit_set(&reply));
    assert_eq!(DnsMessage::parse(&reply).unwrap().answers.len(), 1);
    assert_eq!(tcp_queries.load(Ordering::SeqCst), 2);
    server.abort();
    udp_task.abort();
    tcp_task.abort();
}

#[test]
fn serialization_rejects_a_message_that_exceeds_tcp_length() {
    let mut msg = DnsMessage::new_query(1, "", 16);
    msg.answers.push(DnsResourceRecord {
        name: "".into(),
        rtype: 16,
        rclass: 1,
        ttl: 0,
        rdata: vec![0; 65535],
        cname_target: None,
    });
    assert!(msg.serialize().is_err());
    // Counts also cannot silently wrap, even if a stale header says zero.
    msg.answers.clear();
    msg.questions = vec![msg.questions[0].clone(); 65536];
    msg.header = DnsHeader::new(1, 0, 0, 0, 0, 0);
    assert!(msg.serialize().is_err());
    assert_eq!(EDNS_DO.to_be_bytes(), [0, 0, 0x80, 0]);
}
