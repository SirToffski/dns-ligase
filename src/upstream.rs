use std::io;
use std::sync::Arc;
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::blocklist::Blocklist;
use crate::config::Config;
use crate::dns::DnsMessage;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};

pub struct UdpForwarder {
    udp_socket: Arc<UdpSocket>,
    listen_addr: String,
    config: Arc<RwLock<Config>>,
    blocklist: Arc<RwLock<Blocklist>>,
}

impl UdpForwarder {
    pub async fn new(listen_addr: &str, config: Arc<RwLock<Config>>, blocklist: Arc<RwLock<Blocklist>>) -> io::Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        Ok(Self {
            udp_socket: Arc::new(socket),
            listen_addr: listen_addr.to_string(),
            config,
            blocklist,
        })
    }

    pub async fn run(&self) -> io::Result<()> {
        let mut tasks = Vec::new();

        // UDP Task
        let udp_socket = Arc::clone(&self.udp_socket);
        let config_udp = Arc::clone(&self.config);
        let blocklist_udp = Arc::clone(&self.blocklist);

        tasks.push(tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match udp_socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        let packet = buf[..len].to_vec();
                        let config_ref = Arc::clone(&config_udp);
                        let blocklist_ref = Arc::clone(&blocklist_udp);
                        let socket_ref = Arc::clone(&udp_socket);
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_udp_query(socket_ref, config_ref, addr, packet, blocklist_ref).await {
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
        let config_tcp = Arc::clone(&self.config);
        let blocklist_tcp = Arc::clone(&self.blocklist);
        tasks.push(tokio::spawn(async move {
            let listener = TcpListener::bind(&listen_addr_tcp).await.unwrap();
            loop {
                if let Ok((mut stream, addr)) = listener.accept().await {
                    let config_ref = Arc::clone(&config_tcp);
                    let blocklist_ref = Arc::clone(&blocklist_tcp);
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_tcp_query(&mut stream, config_ref, addr, blocklist_ref).await {
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
        config: Arc<RwLock<Config>>,
        client: std::net::SocketAddr,
        packet: Vec<u8>,
        blocklist: Arc<RwLock<Blocklist>>
    ) -> io::Result<()> {
        let msg = match DnsMessage::parse(&packet[..]) {
            Ok(m) => m,
            Err(e) => {
                log::error!("Failed to parse incoming UDP packet: {}", e);
                return Err(e);
            }
        };

        if let Some(q) = msg.questions.first() {
            if blocklist.read().await.matches(&q.name) {
                log::info!("Blocking domain: {}", q.name);
                let mut response_msg = msg.clone();
                response_msg.header.flags = 0x8183;
                response_msg.header.qdcount = 1;
                response_msg.header.ancount = 0;
                response_msg.header.nscount = 0;
                response_msg.header.arcount = 0;
                response_msg.answers.clear();
                response_msg.authorities.clear();
                response_msg.additionals.clear();

                let response = response_msg.serialize()?;
                socket.send_to(&response, client).await?;
                return Ok(());
            }
        }

        let mut advertised_size = 1232;
        for opt in &msg.additionals {
            if opt.rtype == 41 {
                let size = opt.rclass as usize;
                if size > 0 && size <= 4096 {
                    advertised_size = size;
                }
                break;
            }
        }

        let packet_to_send = if msg.edns_do {
            packet
        } else {
            let mut msg_to_send = msg.clone();
            msg_to_send.edns_do = true;
            msg_to_send.additionals.clear();
            msg_to_send.add_opt_record(advertised_size as u16);
            msg_to_send.serialize()?
        };

        // Read upstream address from config (dynamic — picks up SIGHUP changes)
        let upstream: std::net::SocketAddr = {
            let cfg = config.read().await;
            format!("{}:{}", cfg.upstream.address, cfg.upstream.port)
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad upstream: {e}")))?
        };

        let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;
        upstream_socket.send_to(&packet_to_send, upstream).await?;

        let mut resp_buf = vec![0u8; 4096];
        let (resp_len, _) = timeout(Duration::from_secs(2), upstream_socket.recv_from(&mut resp_buf)).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Upstream UDP timeout"))??;
        let resp_packet = &resp_buf[..resp_len];

        socket.send_to(resp_packet, client).await?;
        Ok(())
    }

    async fn handle_tcp_query(
        client_stream: &mut TcpStream,
        config: Arc<RwLock<Config>>,
        _client_addr: std::net::SocketAddr,
        blocklist: Arc<RwLock<Blocklist>>
    ) -> io::Result<()> {
        let mut len_buf = [0u8; 2];
        timeout(Duration::from_secs(2), client_stream.read_exact(&mut len_buf)).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Client read timeout"))??;
        let len = u16::from_be_bytes(len_buf) as usize;

        let mut packet = vec![0u8; len];
        timeout(Duration::from_secs(2), client_stream.read_exact(&mut packet)).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Client read timeout"))??;

        let msg = match DnsMessage::parse(&packet[..]) {
            Ok(m) => m,
            Err(e) => return Err(e),
        };

        if let Some(q) = msg.questions.first() {
            if blocklist.read().await.matches(&q.name) {
                let mut response_msg = msg.clone();
                response_msg.header.flags = 0x8183;
                response_msg.header.qdcount = 1;
                response_msg.header.ancount = 0;
                response_msg.header.nscount = 0;
                response_msg.header.arcount = 0;
                response_msg.answers.clear();
                response_msg.authorities.clear();
                response_msg.additionals.clear();

                let response = response_msg.serialize()?;
                let resp_len = (response.len() as u16).to_be_bytes();
                client_stream.write_all(&resp_len).await?;
                client_stream.write_all(&response).await?;
                return Ok(());
            }
        }

        let mut advertised_size = 1232;
        for opt in &msg.additionals {
            if opt.rtype == 41 {
                let size = opt.rclass as usize;
                if size > 0 && size <= 4096 {
                    advertised_size = size;
                }
                break;
            }
        }

        let packet_to_send = if msg.edns_do {
            packet
        } else {
            let mut msg_to_send = msg.clone();
            msg_to_send.edns_do = true;
            msg_to_send.additionals.clear();
            msg_to_send.add_opt_record(advertised_size as u16);
            msg_to_send.serialize()?
        };

        // Read upstream address from config (dynamic — picks up SIGHUP changes)
        let upstream: std::net::SocketAddr = {
            let cfg = config.read().await;
            format!("{}:{}", cfg.upstream.address, cfg.upstream.port)
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad upstream: {e}")))?
        };

        let mut upstream_stream = timeout(Duration::from_secs(2), TcpStream::connect(upstream)).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Upstream TCP connect timeout"))??;

        let len_buf = (packet_to_send.len() as u16).to_be_bytes();
        upstream_stream.write_all(&len_buf).await?;
        upstream_stream.write_all(&packet_to_send).await?;
        upstream_stream.flush().await?;

        let mut resp_len_buf = [0u8; 2];
        timeout(Duration::from_secs(2), upstream_stream.read_exact(&mut resp_len_buf)).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Upstream TCP read timeout"))??;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        let mut resp_packet = vec![0u8; resp_len];
        timeout(Duration::from_secs(2), upstream_stream.read_exact(&mut resp_packet)).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Upstream TCP read timeout"))??;

        client_stream.write_all(&resp_len_buf).await?;
        client_stream.write_all(&resp_packet).await?;
        client_stream.flush().await?;

        Ok(())
    }
}
