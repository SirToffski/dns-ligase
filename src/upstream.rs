use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::time::{timeout, timeout_at, Duration, Instant};

use crate::blocklist::{Blocklist, MatchOutcome};
use crate::clients::ClientPolicy;
use crate::dns::{
    qtype_str, query_with_udp_size, DnsHeader, DnsMessage, DnsQuestion, EDNS_DO, MAX_DNS_MESSAGE,
};
use crate::journald;

#[cfg(test)]
#[path = "wire_forward_tests.rs"]
mod wire_forward_tests;

#[cfg(test)]
#[path = "pool_tests.rs"]
mod pool_tests;

#[cfg(test)]
#[path = "policy_tests.rs"]
mod policy_tests;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// EDNS0 UDP payload size we advertise to upstream. 1232 is the DNS flag day
/// value: large enough to carry typical responses while staying under the common path MTU to avoid
/// IP fragmentation. Only EDNS queries advertise this size. The client's
/// receive limit is honored separately via truncation.
const EDNS_BUFFER_SIZE: usize = 1232;
const SERVFAIL: u16 = 2;
const NXDOMAIN: u16 = 3;
const BADVERS: u16 = 16;
const MAX_UDP_PAYLOAD: usize = 65_507;
/// How long to wait for a client to send the next query on an idle TCP
/// connection (RFC 7766 idle timeout). A clean EOF or expiry here closes the
/// connection normally — not an error.
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// Idle pool sizes are separate from the number of simultaneous exchanges.
const UDP_POOL_CAP: usize = 16;
const TCP_POOL_CAP: usize = 8;
const MAX_ACTIVE_EXCHANGES: usize = 128;
const MAX_UDP_HANDLERS: usize = 128;
const MAX_TCP_CLIENTS: usize = 64;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Monotonic counter for internally-generated query IDs (e.g. resolve_a).
/// A counter is sufficient here — the IDs only need to be unique per
/// in-flight query on our pooled sockets, not unpredictable.
static INTERNAL_QUERY_ID: AtomicU16 = AtomicU16::new(1);

#[derive(Debug)]
struct QueryKey {
    id: u16,
    opcode: u16,
    questions: Vec<DnsQuestion>,
}

impl QueryKey {
    fn parse(query: &[u8]) -> io::Result<Self> {
        if query.len() > MAX_DNS_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS query too long",
            ));
        }
        let mut reader = std::io::Cursor::new(query);
        let header = DnsHeader::parse(&mut reader)?;
        if header.flags & 0x8000 != 0 || header.qdcount == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Expected a DNS query with a question",
            ));
        }
        let mut questions = Vec::new();
        for _ in 0..header.qdcount {
            questions.push(DnsQuestion::parse(&mut reader)?);
        }
        Ok(Self {
            id: header.id,
            opcode: header.flags & 0x7800,
            questions,
        })
    }

    fn matches_questions(&self, questions: &[DnsQuestion]) -> bool {
        self.questions.len() == questions.len()
            && self.questions.iter().zip(questions).all(|(query, reply)| {
                query.qtype == reply.qtype
                    && query.qclass == reply.qclass
                    && query.name.eq_ignore_ascii_case(&reply.name)
            })
    }

    /// A UDP TC reply may stop inside an answer. Its header and complete
    /// question must still match before it can trigger a TCP retry.
    fn matches_response(&self, wire: &[u8], allow_partial_tc: bool) -> io::Result<bool> {
        let mut reader = std::io::Cursor::new(wire);
        let header = DnsHeader::parse(&mut reader)?;
        if header.id != self.id
            || header.flags & 0x8000 == 0
            || header.flags & 0x7800 != self.opcode
        {
            return Ok(false);
        }
        if allow_partial_tc && header.flags & 0x0200 != 0 {
            let mut questions = Vec::new();
            for _ in 0..header.qdcount {
                questions.push(DnsQuestion::parse(&mut reader)?);
            }
            return Ok(self.matches_questions(&questions));
        }
        // Fully validate ordinary replies before reusing a socket. Opaque
        // record data remains in its original packet for downstream delivery.
        Ok(self.matches_questions(&DnsMessage::parse(wire)?.questions))
    }
}

fn upstream_timeout(transport: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("Upstream {transport} deadline exceeded"),
    )
}

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
    exchanges: Semaphore,
    udp_pool: Mutex<VecDeque<UdpSocket>>,
    tcp_pool: Mutex<VecDeque<TcpStream>>,
}

impl Upstream {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            exchanges: Semaphore::new(MAX_ACTIVE_EXCHANGES),
            udp_pool: Mutex::new(VecDeque::new()),
            tcp_pool: Mutex::new(VecDeque::new()),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Resolve `host` to IPv4 addresses via the configured upstream.
    ///
    /// Builds an A query, sends it through the existing pooled UDP path
    /// (reusing connection pooling, timeouts, and response-ID validation),
    /// and returns the answer-section A records. An empty Vec means the
    /// response carried no A records — the caller decides what to do.
    pub async fn resolve_a(&self, host: &str) -> io::Result<Vec<Ipv4Addr>> {
        let id = INTERNAL_QUERY_ID.fetch_add(1, Ordering::Relaxed);
        let query = DnsMessage::new_query(id, host, 1);
        let wire = query.serialize()?;
        let resp_bytes = self.udp_query_with_fallback(&wire).await?;
        if tc_bit_set(&resp_bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Truncated bootstrap DNS response",
            ));
        }
        let resp = DnsMessage::parse(&resp_bytes)?;
        Ok(resp.a_records())
    }

    async fn udp_query_with_fallback(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let response = self.udp_query(query).await?;
        if tc_bit_set(&response) {
            self.tcp_query(query).await
        } else {
            Ok(response)
        }
    }

    /// One overall deadline covers checkout, send, stale replies and return.
    /// Any failed or contaminated socket is discarded.
    pub async fn udp_query(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let key = QueryKey::parse(query)?;
        let deadline = Instant::now() + UPSTREAM_TIMEOUT;
        timeout_at(deadline, self.udp_exchange(query, &key, deadline))
            .await
            .map_err(|_| upstream_timeout("UDP"))?
    }

    async fn udp_exchange(
        &self,
        query: &[u8],
        key: &QueryKey,
        deadline: Instant,
    ) -> io::Result<Vec<u8>> {
        // The caller's deadline includes waiting for an exchange slot.
        let _exchange = self
            .exchanges
            .acquire()
            .await
            .expect("semaphore stays open");
        // Drop the pool guard before binding or connecting a fresh socket.
        let pooled = self.udp_pool.lock().await.pop_back();
        let socket = match pooled {
            Some(socket) => socket,
            None => {
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                socket.connect(self.addr).await?;
                socket
            }
        };
        socket.send(query).await?;
        // One sentinel byte detects oversized datagrams without allocating a
        // 64 KiB buffer on every query or silently relaying a clipped packet.
        let mut buf = vec![0; EDNS_BUFFER_SIZE + 1];
        let mut reusable = true;
        loop {
            if Instant::now() >= deadline {
                return Err(upstream_timeout("UDP"));
            }
            let len = socket.recv(&mut buf).await?;
            if len > EDNS_BUFFER_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Upstream UDP reply exceeds advertised buffer",
                ));
            }
            if !key.matches_response(&buf[..len], true)? {
                reusable = false;
                log::debug!("Discarding stale upstream UDP reply");
                continue;
            }
            if reusable {
                let mut pool = self.udp_pool.lock().await;
                if pool.len() < UDP_POOL_CAP {
                    pool.push_back(socket);
                }
            }
            buf.truncate(len);
            return Ok(buf);
        }
    }

    /// Match complete replies and retry a dead pooled connection once. Both
    /// attempts share a single deadline, rather than extending it per I/O.
    pub async fn tcp_query(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let key = QueryKey::parse(query)?;
        let deadline = Instant::now() + UPSTREAM_TIMEOUT;
        timeout_at(deadline, self.tcp_exchange(query, &key, deadline))
            .await
            .map_err(|_| upstream_timeout("TCP"))?
    }

    async fn tcp_exchange(
        &self,
        query: &[u8],
        key: &QueryKey,
        deadline: Instant,
    ) -> io::Result<Vec<u8>> {
        let _exchange = self
            .exchanges
            .acquire()
            .await
            .expect("semaphore stays open");
        let pooled = self.tcp_pool.lock().await.pop_back();
        if let Some(stream) = pooled {
            match Self::tcp_query_on(stream, query, key, deadline).await {
                Ok((stream, bytes, reusable)) => {
                    if reusable {
                        self.return_tcp(stream).await;
                    }
                    return Ok(bytes);
                }
                Err(e) => log::debug!(
                    "Pooled upstream TCP connection failed ({e}); retrying on a fresh one"
                ),
            }
        }
        let stream = TcpStream::connect(self.addr).await?;
        stream.set_nodelay(true)?;
        let (stream, bytes, reusable) = Self::tcp_query_on(stream, query, key, deadline).await?;
        if reusable {
            self.return_tcp(stream).await;
        }
        Ok(bytes)
    }

    async fn return_tcp(&self, stream: TcpStream) {
        let mut pool = self.tcp_pool.lock().await;
        if pool.len() < TCP_POOL_CAP {
            pool.push_back(stream);
        }
    }

    async fn tcp_query_on(
        mut stream: TcpStream,
        query: &[u8],
        key: &QueryKey,
        deadline: Instant,
    ) -> io::Result<(TcpStream, Vec<u8>, bool)> {
        write_tcp_frame(&mut stream, query, deadline).await?;
        let mut reusable = true;
        loop {
            if Instant::now() >= deadline {
                return Err(upstream_timeout("TCP"));
            }
            let len = stream.read_u16().await? as usize;
            let mut reply = vec![0; len];
            stream.read_exact(&mut reply).await?;
            if key.matches_response(&reply, false)? {
                return Ok((stream, reply, reusable));
            }
            reusable = false;
            log::debug!("Discarding stale upstream TCP reply");
        }
    }
}

/// One immutable serving generation. Each query keeps its snapshot across I/O.
pub struct QueryState {
    pub upstream: Arc<Upstream>,
    pub blocklist: Arc<Blocklist>,
    pub clients: Arc<ClientPolicy>,
    pub log_queries: bool,
}

impl QueryState {
    fn check(&self, client: IpAddr, name: &str, rtype: u16) -> MatchOutcome {
        self.clients
            .check(client, name)
            .unwrap_or_else(|| self.blocklist.check_query(name, rtype))
    }
}

#[derive(Clone, Copy)]
enum ClientTransport {
    Udp,
    Tcp,
}

struct QueryResult {
    wire: Vec<u8>,
    question: DnsQuestion,
    outcome: MatchOutcome,
}

/// Filtering and forwarding policy shared by both client transports.
async fn process_query(
    packet: &[u8],
    state: &QueryState,
    transport: ClientTransport,
    client: IpAddr,
) -> io::Result<QueryResult> {
    let (msg, opt_offset) = DnsMessage::parse_wire(packet)?;
    if msg.header.flags & 0xf800 != 0 || msg.questions.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Expected a standard single-question DNS query",
        ));
    }
    let question = msg.questions[0].clone();
    // Client-specific bypass/allow overrides global rules; it never blocks.
    let outcome = state.check(client, &question.name, question.qtype);
    if let Some((rcode, _)) = block_decision(&outcome) {
        log::info!("Blocking domain: {}", question.name);
        return Ok(QueryResult {
            wire: build_error_response(msg, rcode)?,
            question,
            outcome,
        });
    }
    let outgoing = query_with_udp_size(packet, opt_offset, EDNS_BUFFER_SIZE as u16);
    let response = match transport {
        ClientTransport::Udp => state.upstream.udp_query_with_fallback(&outgoing).await,
        ClientTransport::Tcp => state.upstream.tcp_query(&outgoing).await,
    };
    let mut wire = match response {
        Ok(wire) => wire,
        Err(error) => {
            log::error!(
                "DNS exchange with {} failed: {error}",
                state.upstream.addr()
            );
            return Ok(QueryResult {
                wire: build_error_response(msg, SERVFAIL)?,
                question,
                outcome,
            });
        }
    };
    // An actual allow rule for the requested name (or a bypassed client)
    // exempts this entire query from filtering. It does not allow the target
    // for any other query.
    if matches!(outcome, MatchOutcome::Forwarded) {
        let response = DnsMessage::parse(&wire)?;
        for target in response
            .answers
            .iter()
            .filter_map(|rr| rr.cname_target.as_ref())
        {
            let target_outcome = state.check(client, target, 5); // CNAME response record
            if let Some((rcode, rule)) = block_decision(&target_outcome) {
                log::info!("Blocking CNAME target {target} for {}", question.name);
                let detail = format!("cname:{target} {rule}");
                return Ok(QueryResult {
                    wire: build_error_response(msg, rcode)?,
                    question,
                    outcome: if rcode == NXDOMAIN {
                        MatchOutcome::Blocked(detail)
                    } else {
                        MatchOutcome::BlockedType(detail)
                    },
                });
            }
        }
    }
    if matches!(transport, ClientTransport::Udp) && wire.len() > client_udp_limit(&msg) {
        wire = truncate_response(&wire, client_udp_limit(&msg))?;
    }
    Ok(QueryResult {
        wire,
        question,
        outcome,
    })
}

/// A single completion point prevents allowed/forwarded double counting.
/// The sink is FnOnce: a completed request has at most one query-log entry.
async fn handle_request<Send, Sent, Log>(
    packet: &[u8],
    state: &QueryState,
    transport: ClientTransport,
    client: SocketAddr,
    send: Send,
    log: Log,
) -> io::Result<()>
where
    Send: FnOnce(Vec<u8>) -> Sent,
    Sent: std::future::Future<Output = io::Result<()>>,
    Log: FnOnce(&str, &str, &str, &str, &str),
{
    let QueryResult {
        wire,
        question,
        outcome,
    } = process_query(packet, state, transport, client.ip()).await?;
    send(wire).await?;
    if state.log_queries {
        let (action, rule) = match &outcome {
            MatchOutcome::Allowed(rule) => ("allowed", rule.as_str()),
            MatchOutcome::Blocked(rule) | MatchOutcome::BlockedType(rule) => {
                ("blocked", rule.as_str())
            }
            MatchOutcome::Forwarded => ("forwarded", ""),
            MatchOutcome::Bypassed(rule) => ("bypassed", rule.as_str()),
        };
        log(
            &client.ip().to_string(),
            &question.name,
            qtype_str(question.qtype),
            action,
            rule,
        );
    }
    Ok(())
}

pub type QueryStateHandle = Arc<RwLock<Arc<QueryState>>>;

pub struct UdpForwarder {
    udp_handlers: Arc<Semaphore>,
    tcp_clients: Arc<Semaphore>,
    udp_socket: Arc<UdpSocket>,
    tcp_listener: Arc<TcpListener>,
    state: QueryStateHandle,
}

impl UdpForwarder {
    pub async fn new(listen_addr: &str, state: QueryStateHandle) -> io::Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        // Bind both transports before reporting readiness, using the actual
        // UDP address so port 0 also selects the same port for TCP.
        let listener = TcpListener::bind(socket.local_addr()?).await?;
        Ok(Self {
            udp_handlers: Arc::new(Semaphore::new(MAX_UDP_HANDLERS)),
            tcp_clients: Arc::new(Semaphore::new(MAX_TCP_CLIENTS)),
            udp_socket: Arc::new(socket),
            tcp_listener: Arc::new(listener),
            state,
        })
    }

    pub async fn run(&self) -> io::Result<()> {
        let mut tasks = Vec::new();

        // UDP Task
        let udp_socket = Arc::clone(&self.udp_socket);
        let state_udp = Arc::clone(&self.state);
        let udp_handlers = self.udp_handlers.clone();

        tasks.push(tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                let slot = udp_handlers
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("semaphore stays open");
                match udp_socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        let packet = buf[..len].to_vec();
                        let state_ref = Arc::clone(&state_udp);
                        let socket_ref = Arc::clone(&udp_socket);
                        tokio::spawn(async move {
                            let _slot = slot;
                            if let Err(e) =
                                Self::handle_udp_query(socket_ref, state_ref, addr, packet).await
                            {
                                log::error!("UDP query error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("UDP recv error: {}", e);
                        // Transient (e.g. resource pressure) — stay alive. A
                        // short nap avoids a hot spin if the error persists.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }));

        // TCP Task
        let listener = Arc::clone(&self.tcp_listener);
        let state_tcp = Arc::clone(&self.state);
        let tcp_clients = self.tcp_clients.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let slot = tcp_clients
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("semaphore stays open");
                let (mut stream, addr) = match listener.accept().await {
                    Ok(client) => client,
                    Err(e) => {
                        log::error!("TCP accept error: {e}");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                        continue;
                    }
                };
                if let Err(e) = stream.set_nodelay(true) {
                    log::warn!("Could not configure TCP client {addr}: {e}");
                    continue;
                }
                let state_ref = Arc::clone(&state_tcp);
                tokio::spawn(async move {
                    let _slot = slot;
                    if let Err(e) = Self::handle_tcp_query(&mut stream, state_ref, addr).await {
                        log::error!("TCP query error: {e}");
                    }
                });
            }
        }));

        for task in tasks {
            let _ = task.await;
        }

        Ok(())
    }

    async fn handle_udp_query(
        socket: Arc<UdpSocket>,
        state_handle: QueryStateHandle,
        client: std::net::SocketAddr,
        packet: Vec<u8>,
    ) -> io::Result<()> {
        let state = state_handle.read().await.clone();
        handle_request(
            &packet,
            &state,
            ClientTransport::Udp,
            client,
            |wire| async move { socket.send_to(&wire, client).await.map(|_| ()) },
            journald::log_query,
        )
        .await
    }

    async fn handle_tcp_query(
        client_stream: &mut TcpStream,
        state_handle: QueryStateHandle,
        client_addr: std::net::SocketAddr,
    ) -> io::Result<()> {
        // RFC 7766: a client may send multiple queries on one TCP connection.
        // Loop until the client closes the connection (clean EOF), goes idle
        // (CLIENT_IDLE_TIMEOUT), or hits an error.
        loop {
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

            let state = state_handle.read().await.clone();
            let writer = &mut *client_stream;
            handle_request(
                &packet,
                &state,
                ClientTransport::Tcp,
                client_addr,
                |wire| async move { write_tcp_message(writer, &wire).await },
                journald::log_query,
            )
            .await?;
        }
    }
}

fn block_decision(outcome: &MatchOutcome) -> Option<(u16, &str)> {
    match outcome {
        MatchOutcome::Blocked(rule) => Some((NXDOMAIN, rule)),
        MatchOutcome::BlockedType(rule) => Some((0, rule)),
        _ => None,
    }
}

/// Answer a validated question locally. An EDNS client gets a minimal OPT
/// advertising our own size and version, with its DO bit and no echoed options.
fn build_error_response(mut msg: DnsMessage, mut rcode: u16) -> io::Result<Vec<u8>> {
    msg.answers.clear();
    msg.authorities.clear();
    msg.additionals.retain(|rr| rr.rtype == 41);
    if let Some(opt) = msg.additionals.first_mut() {
        if opt.ttl & 0x00ff_0000 != 0 {
            rcode = BADVERS;
        }
        opt.rclass = EDNS_BUFFER_SIZE as u16;
        opt.ttl = (u32::from(rcode >> 4) << 24) | (opt.ttl & EDNS_DO);
        opt.rdata.clear();
    }
    msg.header.flags = (msg.header.flags & 0x7910) | 0x8080 | (rcode & 0xf); // opcode/RD/CD, QR|RA
    msg.serialize()
}

/// Write a DNS message to a TCP stream with the 2-byte length prefix.
/// Bounded by a timeout so a stalled client can't park its handler task forever.
async fn write_tcp_message(stream: &mut TcpStream, msg: &[u8]) -> io::Result<()> {
    write_tcp_frame(stream, msg, Instant::now() + UPSTREAM_TIMEOUT).await
}

/// Pass the prefix and body to TCP together. NODELAY on both hops also avoids
/// delayed-ACK stalls when a peer splits its own reads or writes.
async fn write_tcp_frame(stream: &mut TcpStream, msg: &[u8], deadline: Instant) -> io::Result<()> {
    let len = u16::try_from(msg.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS TCP message too long"))?;
    let mut frame = Vec::with_capacity(msg.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(msg);
    timeout_at(deadline, stream.write_all(&frame))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS TCP write deadline exceeded"))?
}

/// True if the TC (truncation) bit is set in a DNS message's flags.
fn tc_bit_set(msg: &[u8]) -> bool {
    if msg.len() < 4 {
        return false;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    (flags & 0x0200) != 0
}

/// EDNS advertisements below 512 have the same meaning as 512. Larger sizes
/// are limited only by the IPv4 UDP payload ceiling, rather than reverting to
/// the legacy limit and causing unnecessary TCP retries.
fn client_udp_limit(msg: &DnsMessage) -> usize {
    msg.additionals
        .iter()
        .find(|rr| rr.rtype == 41)
        .map(|opt| usize::from(opt.rclass))
        .unwrap_or(512)
        .clamp(512, MAX_UDP_PAYLOAD)
}

/// Keep the question and OPT when they fit, setting TC so the client retries
/// over TCP. Oversized OPT options cannot inflate the truncated reply.
fn truncate_response(resp: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    let mut msg = DnsMessage::parse(resp)?;
    msg.answers.clear();
    msg.authorities.clear();
    // Keep only the OPT record (if any) in additionals; drop everything else.
    msg.additionals.retain(|r| r.rtype == 41);
    msg.header.flags = (msg.header.flags | 0x0200) & !0x0020; // TC, clear AD
    msg.header.ancount = 0;
    msg.header.nscount = 0;
    let mut wire = msg.serialize()?;
    if wire.len() > limit {
        // Large OPT options (e.g. padding) must not make the TC reply exceed
        // the client's path. Preserve its extended RCODE and flags.
        for opt in &mut msg.additionals {
            opt.rdata.clear();
        }
        wire = msg.serialize()?;
    }
    if wire.len() > limit {
        msg.questions.clear();
        wire = msg.serialize()?;
    }
    if wire.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP limit too small for DNS header",
        ));
    }
    Ok(wire)
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
            ttl: crate::dns::EDNS_DO,
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

        let truncated = truncate_response(&serialized, 512).unwrap();
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

    #[tokio::test]
    async fn test_tcp_pool_dead_connection_retries_once() {
        // The first connection serves exactly one query and is then dropped,
        // simulating an upstream that closed an idle pooled connection. The
        // next checkout must transparently retry on a fresh connection.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();

        let accepted = Arc::new(Mutex::new(0u32));
        let accepted_clone = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut n = accepted_clone.lock().await;
                    *n += 1;
                    let which = *n;
                    drop(n);
                    if which == 1 {
                        // Serve one query, then close: the pooled connection
                        // is dead by the time it is checked out again.
                        tokio::spawn(async move {
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
                            resp[3] = 0x80;
                            let l = (resp.len() as u16).to_be_bytes();
                            let _ = stream.write_all(&l).await;
                            let _ = stream.write_all(&resp).await;
                            let _ = stream.flush().await;
                            // Fall off the end: connection closed while pooled.
                        });
                        continue;
                    }
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
                            resp[3] = 0x80;
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

        // Seeds the pool with a connection the server is about to close.
        let r1 = upstream.tcp_query(&query).await.unwrap();
        assert_eq!(r1[2], 0x81);

        // Checks out the dead pooled connection; must retry on a fresh one.
        let r2 = upstream.tcp_query(&query).await.unwrap();
        assert_eq!(&r2[..2], &query[..2]);
        assert_eq!(r2[2], 0x81);

        let n = *accepted.lock().await;
        assert_eq!(n, 2, "dead pooled connection must be retried once on fresh");
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
