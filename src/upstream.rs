use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{timeout, Duration};

use crate::blocklist::{Blocklist, MatchOutcome};
use crate::dns::DnsMessage;
use crate::journald;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// EDNS0 UDP payload size we advertise to upstream and the size of our
/// upstream UDP recv buffer. 1232 is the DNS flag day value: large enough to
/// carry typical responses while staying under the common path MTU to avoid
/// IP fragmentation. We advertise this fixed size regardless of what the client
/// asked for; the client's own limit is honored separately via truncation.
const EDNS_BUFFER_SIZE: usize = 1232;
/// How long to wait for a client to send the next query on an idle TCP
/// connection (RFC 7766 idle timeout). A clean EOF or expiry here closes the
/// connection normally — not an error.
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Max idle sockets kept per transport. On exhaustion a fresh connection is
/// created rather than blocking, so a burst never stalls.
const UDP_POOL_CAP: usize = 16;
const TCP_POOL_CAP: usize = 8;

/// A pool of connected sockets to a single upstream resolver.
///
/// Each query checks out a connected socket, uses it for one request/response,
/// and returns it. A socket that times out or errors is dropped instead of
/// returned, so a late stray response can never be read by a later query.
///
/// This is a connection pool, not an ID-multiplexed reader: each checkout is
/// exclusive to one task, so there is no query-ID rewriting, no demux task,
/// and no collision handling. That is deliberate — a home server does not need
/// the throughput of a single-shared-socket demux, and the pool gets the same
/// reuse benefit within a burst (a page load fires many queries) with far
/// less machinery.
pub struct Upstream {
    addr: SocketAddr,
    udp_pool: Mutex<VecDeque<UdpSocket>>,
    tcp_pool: Mutex<VecDeque<TcpStream>>,
}

impl Upstream {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            udp_pool: Mutex::new(VecDeque::new()),
            tcp_pool: Mutex::new(VecDeque::new()),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Forward a query over UDP and return the full response.
    /// On timeout or I/O error the socket is discarded (never returned).
    pub async fn udp_query(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let socket = match self.udp_pool.lock().await.pop_back() {
            Some(s) => s,
            None => {
                let s = UdpSocket::bind("0.0.0.0:0").await?;
                s.connect(self.addr).await?;
                s
            }
        };
        socket.send(query).await?;

        // The query ID is the first 2 bytes. Validate the response ID matches
        // before accepting — a stale datagram from a previous query on a pooled
        // socket would otherwise be returned as the answer to this query.
        let query_id = if query.len() >= 2 {
            u16::from_be_bytes([query[0], query[1]])
        } else {
            0
        };

        let mut buf = vec![0u8; EDNS_BUFFER_SIZE];
        let len = match timeout(UPSTREAM_TIMEOUT, socket.recv(&mut buf)).await {
            Ok(Ok(len)) => len,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Upstream UDP timeout",
                ))
            }
        };

        // ID mismatch: a stale datagram was queued on this socket. Discard the
        // socket (don't pool it) and return an error so the client retries.
        let resp_id = if len >= 2 {
            u16::from_be_bytes([buf[0], buf[1]])
        } else {
            0
        };
        if resp_id != query_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Upstream UDP response ID mismatch — stale datagram discarded",
            ));
        }

        // Success: return the socket if there is room, else let it drop.
        let mut pool = self.udp_pool.lock().await;
        if pool.len() < UDP_POOL_CAP {
            pool.push_back(socket);
        }
        buf.truncate(len);
        Ok(buf)
    }

    /// Forward a query over TCP and return the full response.
    /// On timeout or I/O error the connection is discarded (never returned).
    pub async fn tcp_query(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let stream = match self.tcp_pool.lock().await.pop_back() {
            Some(s) => s,
            None => timeout(UPSTREAM_TIMEOUT, TcpStream::connect(self.addr))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Upstream TCP connect timeout",
                    )
                })??,
        };
        match Self::tcp_query_on(stream, query).await {
            Ok((stream, bytes)) => {
                let mut pool = self.tcp_pool.lock().await;
                if pool.len() < TCP_POOL_CAP {
                    pool.push_back(stream);
                }
                Ok(bytes)
            }
            Err(e) => Err(e),
        }
    }

    /// Drive a single query over an owned TCP stream, returning the stream
    /// (so the caller can pool it) and the response bytes.
    async fn tcp_query_on(
        mut stream: TcpStream,
        query: &[u8],
    ) -> io::Result<(TcpStream, Vec<u8>)> {
        let len_buf = (query.len() as u16).to_be_bytes();
        timeout(UPSTREAM_TIMEOUT, stream.write_all(&len_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Upstream TCP write timeout"))??;
        timeout(UPSTREAM_TIMEOUT, stream.write_all(query))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Upstream TCP write timeout"))??;
        stream.flush().await?;

        let mut resp_len_buf = [0u8; 2];
        timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut resp_len_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Upstream TCP read timeout"))??;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut resp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Upstream TCP read timeout"))??;
        Ok((stream, resp))
    }
}

/// Shared, swappable handle to the current upstream pool.
///
/// Query handlers take a brief read lock only to clone the inner `Arc<Upstream>`,
/// then drop the lock and do I/O against their clone — so a SIGHUP swap never
/// blocks in-flight queries. On swap, in-flight queries holding the old `Arc`
/// finish against the old address; new queries use the new one.
pub type UpstreamHandle = Arc<RwLock<Arc<Upstream>>>;

pub struct UdpForwarder {
    udp_socket: Arc<UdpSocket>,
    listen_addr: String,
    upstream: UpstreamHandle,
    blocklist: Arc<RwLock<Blocklist>>,
    log_queries: Arc<RwLock<bool>>,
}

impl UdpForwarder {
    pub async fn new(
        listen_addr: &str,
        upstream: UpstreamHandle,
        blocklist: Arc<RwLock<Blocklist>>,
        log_queries: Arc<RwLock<bool>>,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        Ok(Self {
            udp_socket: Arc::new(socket),
            listen_addr: listen_addr.to_string(),
            upstream,
            blocklist,
            log_queries,
        })
    }

    pub async fn run(&self) -> io::Result<()> {
        let mut tasks = Vec::new();

        // UDP Task
        let udp_socket = Arc::clone(&self.udp_socket);
        let upstream_udp = Arc::clone(&self.upstream);
        let blocklist_udp = Arc::clone(&self.blocklist);
        let log_udp = Arc::clone(&self.log_queries);

        tasks.push(tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match udp_socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        let packet = buf[..len].to_vec();
                        let upstream_ref = Arc::clone(&upstream_udp);
                        let blocklist_ref = Arc::clone(&blocklist_udp);
                        let socket_ref = Arc::clone(&udp_socket);
                        let log_ref = Arc::clone(&log_udp);
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_udp_query(
                                socket_ref,
                                upstream_ref,
                                addr,
                                packet,
                                blocklist_ref,
                                log_ref,
                            )
                            .await
                            {
                                log::error!("UDP query error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("UDP recv error: {}", e);
                        break;
                    }
                }
            }
        }));

        // TCP Task
        let listen_addr_tcp = self.listen_addr.clone();
        let upstream_tcp = Arc::clone(&self.upstream);
        let blocklist_tcp = Arc::clone(&self.blocklist);
        let log_tcp = Arc::clone(&self.log_queries);
        tasks.push(tokio::spawn(async move {
            let listener = TcpListener::bind(&listen_addr_tcp).await.unwrap();
            loop {
                if let Ok((mut stream, addr)) = listener.accept().await {
                    let upstream_ref = Arc::clone(&upstream_tcp);
                    let blocklist_ref = Arc::clone(&blocklist_tcp);
                    let log_ref = Arc::clone(&log_tcp);
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_tcp_query(&mut stream, upstream_ref, addr, blocklist_ref, log_ref)
                                .await
                        {
                            log::error!("TCP query error: {}", e);
                        }
                    });
                }
            }
        }));

        for task in tasks {
            let _ = task.await;
        }

        Ok(())
    }

    async fn handle_udp_query(
        socket: Arc<UdpSocket>,
        upstream: UpstreamHandle,
        client: std::net::SocketAddr,
        packet: Vec<u8>,
        blocklist: Arc<RwLock<Blocklist>>,
        log_queries: Arc<RwLock<bool>>,
    ) -> io::Result<()> {
        let msg = match DnsMessage::parse(&packet[..]) {
            Ok(m) => m,
            Err(e) => {
                log::error!("Failed to parse incoming UDP packet: {}", e);
                return Err(e);
            }
        };

        if let Some(q) = msg.questions.first() {
            let outcome = blocklist.read().await.check(&q.name);
            match outcome {
                MatchOutcome::Blocked(rule) => {
                    log::info!("Blocking domain: {}", q.name);
                    if *log_queries.read().await {
                        journald::log_query(
                            &client.ip().to_string(),
                            &q.name,
                            qtype_str(q.qtype),
                            "blocked",
                            &rule,
                        );
                    }
                    let response = build_nxdomain(&msg)?;
                    socket.send_to(&response, client).await?;
                    return Ok(());
                }
                MatchOutcome::Allowed(rule) => {
                    if *log_queries.read().await {
                        journald::log_query(
                            &client.ip().to_string(),
                            &q.name,
                            qtype_str(q.qtype),
                            "allowed",
                            &rule,
                        );
                    }
                }
                MatchOutcome::Forwarded => {}
            }
        }

        // Client's UDP payload size: from its OPT record if present, else the
        // RFC 1035 default of 512. Used to decide client-side truncation.
        let mut client_udp_size: usize = 512;
        for opt in &msg.additionals {
            if opt.rtype == 41 {
                let size = opt.rclass as usize;
                if size > 0 && size <= 4096 {
                    client_udp_size = size;
                }
                break;
            }
        }

        // Always advertise a fixed 1232-byte EDNS0 buffer to upstream and
        // ensure the DO bit is set. add_opt_record rewrites an existing OPT
        // record in place (preserving any client EDNS options in its rdata) or
        // adds one if absent.
        let packet_to_send = {
            let mut msg_to_send = msg.clone();
            msg_to_send.edns_do = true;
            msg_to_send.add_opt_record(EDNS_BUFFER_SIZE as u16);
            msg_to_send.serialize()?
        };

        // Clone the current upstream Arc without holding the lock across I/O.
        let upstream = upstream.read().await.clone();

        let mut resp = upstream.udp_query(&packet_to_send).await?;

        // Upstream truncated even within our advertised buffer: fall back to TCP
        // to retrieve the full response.
        if tc_bit_set(&resp) {
            log::debug!("Upstream set TC; retrying over TCP");
            resp = upstream.tcp_query(&packet_to_send).await?;
        }

        // CNAME cloaking check: parse the response and walk the answer section
        // for CNAME records. If any target is blocked, return NXDOMAIN for the
        // original question. A malformed response is relayed as-is (parse
        // failure does not break forwarding).
        if let Some(q) = msg.questions.first() {
            if let Ok(resp_msg) = DnsMessage::parse(&resp) {
                for rr in &resp_msg.answers {
                    if rr.rtype != 5 {
                        continue;
                    }
                    let Some(target) = &rr.cname_target else { continue };
                    if let MatchOutcome::Blocked(rule) = blocklist.read().await.check(target) {
                        log::info!("Blocking CNAME target {target} for {}", q.name);
                        if *log_queries.read().await {
                            journald::log_query(
                                &client.ip().to_string(),
                                &q.name,
                                qtype_str(q.qtype),
                                "blocked",
                                &format!("cname:{target} {rule}"),
                            );
                        }
                        let nx = build_nxdomain(&msg)?;
                        socket.send_to(&nx, client).await?;
                        return Ok(());
                    }
                }
            }
        }

        // The full response may still be too large for the client's UDP path.
        // Signal truncation so the client retries over TCP.
        if resp.len() > client_udp_size {
            log::debug!(
                "Response {}B exceeds client UDP limit {}B; setting TC",
                resp.len(),
                client_udp_size
            );
            resp = truncate_response(&resp)?;
        }

        socket.send_to(&resp, client).await?;

        if *log_queries.read().await {
            if let Some(q) = msg.questions.first() {
                journald::log_query(
                    &client.ip().to_string(),
                    &q.name,
                    qtype_str(q.qtype),
                    "forwarded",
                    "",
                );
            }
        }
        Ok(())
    }

    async fn handle_tcp_query(
        client_stream: &mut TcpStream,
        upstream: UpstreamHandle,
        client_addr: std::net::SocketAddr,
        blocklist: Arc<RwLock<Blocklist>>,
        log_queries: Arc<RwLock<bool>>,
    ) -> io::Result<()> {
        // RFC 7766: a client may send multiple queries on one TCP connection.
        // Loop until the client closes the connection (clean EOF), goes idle
        // (CLIENT_IDLE_TIMEOUT), or hits an error.
        'next_query: loop {
            let mut len_buf = [0u8; 2];
            // Idle wait for the next query — long timeout, and a clean EOF or
            // expiry closes the connection normally (not an error).
            match timeout(CLIENT_IDLE_TIMEOUT, client_stream.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(()), // idle timeout: close quietly
            }
            let len = u16::from_be_bytes(len_buf) as usize;

            // Once the length prefix arrives, the body must follow promptly.
            let mut packet = vec![0u8; len];
            timeout(UPSTREAM_TIMEOUT, client_stream.read_exact(&mut packet))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Client read timeout"))??;

            let msg = match DnsMessage::parse(&packet[..]) {
                Ok(m) => m,
                Err(e) => return Err(e),
            };

            if let Some(q) = msg.questions.first() {
                let outcome = blocklist.read().await.check(&q.name);
                match outcome {
                    MatchOutcome::Blocked(rule) => {
                        let response = build_nxdomain(&msg)?;
                        write_tcp_message(client_stream, &response).await?;
                        if *log_queries.read().await {
                            journald::log_query(
                                &client_addr.ip().to_string(),
                                &q.name,
                                qtype_str(q.qtype),
                                "blocked",
                                &rule,
                            );
                        }
                        continue 'next_query;
                    }
                    MatchOutcome::Allowed(rule) => {
                        if *log_queries.read().await {
                            journald::log_query(
                                &client_addr.ip().to_string(),
                                &q.name,
                                qtype_str(q.qtype),
                                "allowed",
                                &rule,
                            );
                        }
                    }
                    MatchOutcome::Forwarded => {}
                }
            }

            let packet_to_send = {
                let mut msg_to_send = msg.clone();
                msg_to_send.edns_do = true;
                msg_to_send.add_opt_record(EDNS_BUFFER_SIZE as u16);
                msg_to_send.serialize()?
            };

            let upstream = upstream.read().await.clone();
            let resp = upstream.tcp_query(&packet_to_send).await?;

            // CNAME cloaking check: same as the UDP path. If a CNAME target in
            // the answer section is blocked, return NXDOMAIN for the original
            // question. A malformed response is relayed as-is.
            if let Some(q) = msg.questions.first() {
                if let Ok(resp_msg) = DnsMessage::parse(&resp) {
                    for rr in &resp_msg.answers {
                        if rr.rtype != 5 {
                            continue;
                        }
                        let Some(target) = &rr.cname_target else { continue };
                        if let MatchOutcome::Blocked(rule) = blocklist.read().await.check(target) {
                            log::info!("Blocking CNAME target {target} for {}", q.name);
                            if *log_queries.read().await {
                                journald::log_query(
                                    &client_addr.ip().to_string(),
                                    &q.name,
                                    qtype_str(q.qtype),
                                    "blocked",
                                    &format!("cname:{target} {rule}"),
                                );
                            }
                            let nx = build_nxdomain(&msg)?;
                            write_tcp_message(client_stream, &nx).await?;
                            continue 'next_query;
                        }
                    }
                }
            }

            write_tcp_message(client_stream, &resp).await?;

            if *log_queries.read().await {
                if let Some(q) = msg.questions.first() {
                    journald::log_query(
                        &client_addr.ip().to_string(),
                        &q.name,
                        qtype_str(q.qtype),
                        "forwarded",
                        "",
                    );
                }
            }
        }
    }
}

/// Convert a DNS qtype number to a short string for logging.
fn qtype_str(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        52 => "TLSA",
        255 => "ANY",
        _ => "OTHER",
    }
}

/// Build an NXDOMAIN response for a blocked query, preserving the question.
fn build_nxdomain(msg: &DnsMessage) -> io::Result<Vec<u8>> {
    let mut response_msg = msg.clone();
    response_msg.header.flags = 0x8183; // QR|RD|RA|NXDOMAIN
    response_msg.header.qdcount = 1;
    response_msg.header.ancount = 0;
    response_msg.header.nscount = 0;
    // arcount is set by serialize() from additionals.len(), not the header field.
    response_msg.answers.clear();
    response_msg.authorities.clear();
    response_msg.additionals.clear();
    response_msg.serialize()
}

/// Write a DNS message to a TCP stream with the 2-byte length prefix.
async fn write_tcp_message(stream: &mut TcpStream, msg: &[u8]) -> io::Result<()> {
    let len_buf = (msg.len() as u16).to_be_bytes();
    stream.write_all(&len_buf).await?;
    stream.write_all(msg).await?;
    stream.flush().await?;
    Ok(())
}

/// True if the TC (truncation) bit is set in a DNS message's flags.
fn tc_bit_set(msg: &[u8]) -> bool {
    if msg.len() < 4 {
        return false;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    (flags & 0x0200) != 0
}

/// Build a truncated response for a UDP client: keep the question (and the OPT
/// record if present), drop the answer/authority sections, and set the TC bit
/// so the client retries over TCP.
fn truncate_response(resp: &[u8]) -> io::Result<Vec<u8>> {
    let mut msg = DnsMessage::parse(resp)?;
    msg.answers.clear();
    msg.authorities.clear();
    // Keep only the OPT record (if any) in additionals; drop everything else.
    msg.additionals.retain(|r| r.rtype == 41);
    msg.header.flags |= 0x0200; // TC
    msg.header.ancount = 0;
    msg.header.nscount = 0;
    msg.serialize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsHeader, DnsQuestion, DnsResourceRecord};

    fn query_msg(name: &str) -> DnsMessage {
        DnsMessage {
            header: DnsHeader::new(0x1234, 0x0100, 1, 0, 0, 0),
            questions: vec![DnsQuestion {
                name: name.to_string(),
                qtype: 1,
                qclass: 1,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns_do: false,
        }
    }

    #[test]
    fn test_tc_bit_set() {
        // QR|RD|RA|TC = 0x8180 | 0x0200 = 0x8380
        let flags = 0x8380u16.to_be_bytes();
        let msg = [0x12, 0x34, flags[0], flags[1]];
        assert!(tc_bit_set(&msg));

        let flags = 0x8180u16.to_be_bytes();
        let msg = [0x12, 0x34, flags[0], flags[1]];
        assert!(!tc_bit_set(&msg));

        assert!(!tc_bit_set(&[0x12, 0x34]));
    }

    #[test]
    fn test_truncate_response_sets_tc_and_strips_answers() {
        // A response large enough to exceed any UDP limit: a TXT record with
        // a big RDATA field.
        let answer = DnsResourceRecord {
            name: "example.com".to_string(),
            rtype: 1,
            rclass: 1,
            ttl: 300,
            rdata: vec![0u8; 600],
            cname_target: None,
        };
        let opt = DnsResourceRecord {
            name: "".to_string(),
            rtype: 41,
            rclass: 1232,
            ttl: 0x80000000,
            rdata: vec![],
            cname_target: None,
        };
        let mut msg = query_msg("example.com");
        msg.header.flags = 0x8180; // QR|RD|RA
        msg.header.ancount = 1;
        msg.answers = vec![answer];
        msg.additionals = vec![opt];

        let serialized = msg.serialize().unwrap();
        assert!(serialized.len() > 512);

        let truncated = truncate_response(&serialized).unwrap();
        let parsed = DnsMessage::parse(&truncated).unwrap();

        assert_ne!(parsed.header.flags & 0x0200, 0, "TC bit must be set");
        assert_eq!(parsed.answers.len(), 0);
        assert_eq!(parsed.authorities.len(), 0);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "example.com");
        // OPT record retained so the client still sees EDNS0.
        assert_eq!(parsed.additionals.len(), 1);
        assert_eq!(parsed.additionals[0].rtype, 41);
        // Truncated response must fit under the 512-byte default UDP limit.
        assert!(truncated.len() <= 512);
    }

    #[tokio::test]
    async fn test_tcp_pool_reuses_connection() {
        // Local TCP echo server speaking DNS-over-TCP (2-byte length prefix).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();

        let accepted = Arc::new(Mutex::new(0u32));
        let accepted_clone = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    *accepted_clone.lock().await += 1;
                    // Handle every query on this connection in a loop so the
                    // pooled connection can be reused.
                    tokio::spawn(async move {
                        loop {
                            let mut len_buf = [0u8; 2];
                            if stream.read_exact(&mut len_buf).await.is_err() {
                                return;
                            }
                            let len = u16::from_be_bytes(len_buf) as usize;
                            let mut req = vec![0u8; len];
                            if stream.read_exact(&mut req).await.is_err() {
                                return;
                            }
                            let mut resp = req;
                            resp[2] = 0x81;
                            resp[3] = 0x80; // QR|RD|RA, NOERROR
                            let l = (resp.len() as u16).to_be_bytes();
                            if stream.write_all(&l).await.is_err() {
                                return;
                            }
                            if stream.write_all(&resp).await.is_err() {
                                return;
                            }
                            let _ = stream.flush().await;
                        }
                    });
                }
            }
        });

        let upstream = Upstream::new(upstream_addr);

        let query = query_msg("example.com").serialize().unwrap();
        let r1 = upstream.tcp_query(&query).await.unwrap();
        let r2 = upstream.tcp_query(&query).await.unwrap();

        // Both responses carry the echoed id and a set QR bit.
        assert_eq!(&r1[..2], &query[..2]);
        assert_eq!(r1[2], 0x81);
        assert_eq!(&r2[..2], &query[..2]);

        // The pool should have reused the same connection: exactly one accept.
        let n = *accepted.lock().await;
        assert_eq!(n, 1, "second query must reuse the pooled connection");
    }

    // --- CNAME filtering tests ---

    /// Build a raw DNS response for "metrics.site.com" with a CNAME answer.
    /// If `compressed` is true, the CNAME target uses a compression pointer
    /// back into the question section (pointing to "site.com" at offset 20).
    fn build_cname_response(compressed: bool) -> Vec<u8> {
        // Header: ID=0x1234, flags=0x8180 (QR|RD|RA, NOERROR), QD=1, AN=1, NS=0, AR=0
        let mut buf = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        // Question: metrics.site.com, type A, class IN
        // Offset 12: \x07metrics\x04site\x03com\x00
        buf.extend_from_slice(b"\x07metrics\x04site\x03com\x00");
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
        // Question ends at offset 34. "site.com" starts at offset 20 (0x14).

        // Answer: CNAME for metrics.site.com -> target
        buf.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to offset 12
        buf.extend_from_slice(&[0x00, 0x05]); // type CNAME
        buf.extend_from_slice(&[0x00, 0x01]); // class IN
        buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL 300

        if compressed {
            // CNAME target: tracker.site.com — "tracker" + pointer to offset 20
            let rdata: &[u8] = b"\x07tracker\xC0\x14";
            buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            buf.extend_from_slice(rdata);
        } else {
            // CNAME target: tracker.evil.net — fully uncompressed
            let rdata: &[u8] = b"\x07tracker\x04evil\x03net\x00";
            buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            buf.extend_from_slice(rdata);
        }
        buf
    }

    #[test]
    fn test_cname_target_with_compression_pointer() {
        let resp = build_cname_response(true);
        let msg = DnsMessage::parse(&resp).unwrap();
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].rtype, 5);
        assert_eq!(
            msg.answers[0].cname_target.as_deref(),
            Some("tracker.site.com"),
            "CNAME target must resolve through compression pointer"
        );
    }

    #[test]
    fn test_cname_target_uncompressed() {
        let resp = build_cname_response(false);
        let msg = DnsMessage::parse(&resp).unwrap();
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].rtype, 5);
        assert_eq!(
            msg.answers[0].cname_target.as_deref(),
            Some("tracker.evil.net"),
            "uncompressed CNAME target must resolve"
        );
    }

    #[test]
    fn test_no_cname_in_a_only_response() {
        // A response with only an A record — no CNAME target should be found.
        let mut msg = query_msg("example.com");
        msg.header.flags = 0x8180;
        msg.header.ancount = 1;
        msg.answers = vec![DnsResourceRecord {
            name: "example.com".to_string(),
            rtype: 1,
            rclass: 1,
            ttl: 300,
            rdata: vec![192, 0, 2, 1],
            cname_target: None,
        }];
        let resp = msg.serialize().unwrap();
        let parsed = DnsMessage::parse(&resp).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].rtype, 1);
        assert!(parsed.answers[0].cname_target.is_none());
    }

    #[test]
    fn test_garbage_response_does_not_panic() {
        // Valid header claiming 1 answer but no answer data follows — parsing
        // must fail cleanly when trying to read the answer RR, not panic.
        let garbage = [
            0x12, 0x34, 0x81, 0x80, // ID, flags
            0x00, 0x01, 0x00, 0x01, // QD=1, AN=1
            0x00, 0x00, 0x00, 0x00, // NS=0, AR=0
            // Question: "x" type A class IN
            0x01, b'x', 0x00, 0x00, 0x01, 0x00, 0x01,
            // No answer data — header claims 1 answer but packet ends here.
        ];
        let result = DnsMessage::parse(&garbage);
        assert!(result.is_err());
    }
}
