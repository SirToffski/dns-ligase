use super::*;

fn query(id: u16, name: &str) -> Vec<u8> {
    DnsMessage::new_query(id, name, 1).serialize().unwrap()
}
fn reply(query: &[u8]) -> DnsMessage {
    let mut msg = DnsMessage::parse(query).unwrap();
    msg.header.flags = 0x8180;
    msg
}

#[tokio::test]
async fn udp_and_tcp_share_the_upstream_limit_and_checkout_deadline() {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let socket = UdpSocket::bind(addr).await.unwrap();
    let upstream = Upstream::new(addr);
    let reserved = upstream
        .exchanges
        .acquire_many(MAX_ACTIVE_EXCHANGES as u32)
        .await
        .unwrap();
    let wire = query(7, "waiting.test");
    let (udp, tcp) = tokio::join!(upstream.udp_query(&wire), upstream.tcp_query(&wire));
    assert_eq!(udp.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(tcp.unwrap_err().kind(), io::ErrorKind::TimedOut);
    let mut buf = [0; 512];
    assert_eq!(
        socket.try_recv(&mut buf).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(timeout(Duration::from_millis(50), server.accept())
        .await
        .is_err());
    drop(reserved);
    let respond = async {
        let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
        socket
            .send_to(&reply(&buf[..len]).serialize().unwrap(), peer)
            .await
            .unwrap();
    };
    let (response, ()) = tokio::join!(upstream.udp_query(&wire), respond);
    assert_eq!(DnsMessage::parse(&response.unwrap()).unwrap().header.id, 7);
    assert_eq!(upstream.exchanges.available_permits(), MAX_ACTIVE_EXCHANGES);
}
async fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let len = stream.read_u16().await.unwrap() as usize;
    let mut query = vec![0; len];
    stream.read_exact(&mut query).await.unwrap();
    query
}
async fn send_frame(stream: &mut TcpStream, wire: &[u8]) -> io::Result<()> {
    let mut frame = (wire.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(wire);
    stream.write_all(&frame).await
}

#[tokio::test]
async fn duplicate_udp_reply_cannot_answer_a_different_same_id_question() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = Upstream::new(server.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        let (n, peer) = server.recv_from(&mut buf).await.unwrap();
        let response = reply(&buf[..n]).serialize().unwrap();
        server.send_to(&response, peer).await.unwrap();
        server.send_to(&response, peer).await.unwrap();
        let (n, peer) = server.recv_from(&mut buf).await.unwrap();
        server
            .send_to(&reply(&buf[..n]).serialize().unwrap(), peer)
            .await
            .unwrap();
    });
    upstream
        .udp_query(&query(1234, "first.test"))
        .await
        .unwrap();
    let second = upstream
        .udp_query(&query(1234, "second.test"))
        .await
        .unwrap();
    assert_eq!(
        DnsMessage::parse(&second).unwrap().questions[0].name,
        "second.test"
    );
    assert!(
        upstream.udp_pool.lock().await.is_empty(),
        "retire a socket with stale replies"
    );
    task.await.unwrap();
}

#[tokio::test]
async fn udp_checks_response_bit_opcode_type_class_and_all_questions() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = Upstream::new(server.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        let (n, peer) = server.recv_from(&mut buf).await.unwrap();
        let valid = reply(&buf[..n]);
        let mut variants = Vec::new();
        let mut wrong = valid.clone();
        wrong.header.id += 1;
        variants.push(wrong);
        let mut wrong = valid.clone();
        wrong.header.flags &= !0x8000;
        variants.push(wrong);
        let mut wrong = valid.clone();
        wrong.header.flags |= 0x0800;
        variants.push(wrong);
        let mut wrong = valid.clone();
        wrong.questions[0].qtype = 28;
        variants.push(wrong);
        let mut wrong = valid.clone();
        wrong.questions[0].qclass = 3;
        variants.push(wrong);
        let mut wrong = valid.clone();
        wrong.questions[0].name = "other.test".into();
        variants.push(wrong);
        let mut wrong = valid.clone();
        wrong.questions.push(wrong.questions[0].clone());
        variants.push(wrong);
        for wrong in variants {
            server
                .send_to(&wrong.serialize().unwrap(), peer)
                .await
                .unwrap();
        }
        let mut valid = valid;
        valid.questions[0].name = "EXAMPLE.TEST".into();
        server
            .send_to(&valid.serialize().unwrap(), peer)
            .await
            .unwrap();
    });
    let result = upstream.udp_query(&query(1, "example.test")).await.unwrap();
    assert_eq!(
        DnsMessage::parse(&result).unwrap().questions[0].name,
        "EXAMPLE.TEST"
    );
    task.await.unwrap();
}

#[tokio::test]
async fn malformed_and_oversized_udp_replies_are_not_pooled() {
    for oversized in [false, true] {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = Upstream::new(server.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut buf = [0; 4096];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let mut wire = reply(&buf[..n]).serialize().unwrap();
            if oversized {
                wire.extend(vec![0; 2000]);
            } else {
                wire.truncate(12);
            }
            server.send_to(&wire, peer).await.unwrap();
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            server
                .send_to(&reply(&buf[..n]).serialize().unwrap(), peer)
                .await
                .unwrap();
        });
        assert!(upstream.udp_query(&query(1, "example.test")).await.is_err());
        assert!(upstream.udp_pool.lock().await.is_empty());
        assert!(upstream.udp_query(&query(2, "example.test")).await.is_ok());
        task.await.unwrap();
    }
}

#[tokio::test]
async fn stale_udp_traffic_does_not_reset_the_deadline() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = Upstream::new(server.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        let (n, peer) = server.recv_from(&mut buf).await.unwrap();
        let mut stale = reply(&buf[..n]);
        stale.header.id += 1;
        let stale = stale.serialize().unwrap();
        for _ in 0..120 {
            server.send_to(&stale, peer).await.unwrap();
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
    let error = timeout(
        Duration::from_secs(4),
        upstream.udp_query(&query(1, "example.test")),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(upstream.udp_pool.lock().await.is_empty());
    task.abort();
}

#[tokio::test]
async fn tcp_skips_wrong_frames_but_discards_the_connection_afterward() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = Upstream::new(listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let query = read_frame(&mut stream).await;
            let valid = reply(&query);
            let mut wrong = valid.clone();
            wrong.header.id += 1;
            send_frame(&mut stream, &wrong.serialize().unwrap())
                .await
                .unwrap();
            let mut wrong = valid.clone();
            wrong.questions[0].name = "different.test".into();
            send_frame(&mut stream, &wrong.serialize().unwrap())
                .await
                .unwrap();
            let mut wrong = valid.clone();
            wrong.questions[0].qclass = 3;
            send_frame(&mut stream, &wrong.serialize().unwrap())
                .await
                .unwrap();
            send_frame(&mut stream, &valid.serialize().unwrap())
                .await
                .unwrap();
        }
    });
    for id in [1, 2] {
        let result = upstream
            .tcp_query(&query(id, "example.test"))
            .await
            .unwrap();
        assert_eq!(DnsMessage::parse(&result).unwrap().header.id, id);
        assert!(upstream.tcp_pool.lock().await.is_empty());
    }
    task.await.unwrap();
}

#[tokio::test]
async fn malformed_tcp_reply_is_discarded_and_next_query_uses_a_fresh_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = Upstream::new(listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let wire = read_frame(&mut stream).await;
        let mut malformed = reply(&wire).serialize().unwrap();
        malformed.truncate(12);
        send_frame(&mut stream, &malformed).await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let wire = read_frame(&mut stream).await;
        send_frame(&mut stream, &reply(&wire).serialize().unwrap())
            .await
            .unwrap();
    });
    assert!(upstream.tcp_query(&query(1, "example.test")).await.is_err());
    assert!(upstream.tcp_pool.lock().await.is_empty());
    assert!(upstream.tcp_query(&query(2, "example.test")).await.is_ok());
    task.await.unwrap();
}

#[tokio::test]
async fn stale_tcp_frames_do_not_reset_the_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = Upstream::new(listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let wire = read_frame(&mut stream).await;
        let mut stale = reply(&wire);
        stale.header.id += 1;
        let stale = stale.serialize().unwrap();
        for _ in 0..120 {
            if send_frame(&mut stream, &stale).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
    let error = timeout(
        Duration::from_secs(4),
        upstream.tcp_query(&query(1, "example.test")),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(upstream.tcp_pool.lock().await.is_empty());
    task.abort();
}

#[tokio::test]
async fn tcp_length_and_body_reads_share_one_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = Upstream::new(listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let wire = read_frame(&mut stream).await;
        let response = reply(&wire).serialize().unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let _ = stream.write_all(&response).await;
    });
    let error = timeout(
        Duration::from_secs(4),
        upstream.tcp_query(&query(1, "example.test")),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(upstream.tcp_pool.lock().await.is_empty());
    task.abort();
}

#[test]
fn partial_tc_requires_matching_header_and_complete_question() {
    let request = query(1, "example.test");
    let key = QueryKey::parse(&request).unwrap();
    let mut partial = reply(&request).serialize().unwrap();
    partial[2] |= 0x02;
    partial[7] = 1; // claims an answer but ends after the complete question
    assert!(key.matches_response(&partial, true).unwrap());
    assert!(key.matches_response(&partial, false).is_err());
    partial.truncate(12);
    assert!(key.matches_response(&partial, true).is_err());
    let mut wrong = reply(&query(1, "different.test")).serialize().unwrap();
    wrong[2] |= 0x02;
    assert!(!key.matches_response(&wrong, true).unwrap());
}

#[test]
fn missing_or_extra_questions_cannot_match() {
    let request = query(1, "example.test");
    let key = QueryKey::parse(&request).unwrap();
    let mut response = reply(&request);
    response.questions.clear();
    assert!(!key
        .matches_response(&response.serialize().unwrap(), false)
        .unwrap());
    assert!(QueryKey::parse(&response.serialize().unwrap()).is_err());
    let mut request = DnsMessage::parse(&request).unwrap();
    request.questions.push(DnsQuestion {
        name: "second.test".into(),
        qtype: 28,
        qclass: 1,
    });
    let key = QueryKey::parse(&request.serialize().unwrap()).unwrap();
    let mut response = request.clone();
    response.header.flags = 0x8180;
    assert!(key
        .matches_response(&response.serialize().unwrap(), false)
        .unwrap());
    response.questions[1].qtype = 1;
    assert!(!key
        .matches_response(&response.serialize().unwrap(), false)
        .unwrap());
}
