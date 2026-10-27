use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use rust_dns::blocklist::{CachedLists, DownloadResult};
use rust_dns::dns::{DnsMessage, DnsResourceRecord};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};

static ID: AtomicUsize = AtomicUsize::new(0);
struct App {
    dir: PathBuf,
    port: u16,
    upstream_port: u16,
    urls: Vec<String>,
    blocked: Vec<String>,
    interval: u64,
    cache_path: PathBuf,
    child: Option<Child>,
}
impl App {
    fn new(upstream_port: u16) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "dns-ligase-lifecycle-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        Self {
            cache_path: dir.join("cache.json"),
            dir,
            port,
            upstream_port,
            urls: vec![],
            blocked: vec![],
            interval: 3600,
            child: None,
        }
    }
    fn write_config(&self) {
        let text = format!(
            r#"
[server]
listen_addr="127.0.0.1"
listen_port={}
[upstream]
address="127.0.0.1"
port={}
use_tcp=false
[blocklists]
urls={}
refresh_interval_secs={}
cache_ttl_secs=0
[matching]
manual_block={}
manual_allow=[]
regex_block=[]
regex_allow=[]
[cache]
path={}
[logging]
queries=false
"#,
            self.port,
            self.upstream_port,
            serde_json::to_string(&self.urls).unwrap(),
            self.interval,
            serde_json::to_string(&self.blocked).unwrap(),
            serde_json::to_string(self.cache_path.to_str().unwrap()).unwrap()
        );
        fs::write(self.dir.join("config.toml"), text).unwrap();
    }
    fn start(&mut self) {
        self.write_config();
        let log = fs::File::create(self.dir.join("log")).unwrap();
        self.child = Some(
            Command::new(env!("CARGO_BIN_EXE_dns-ligase"))
                .arg("--config")
                .arg(self.dir.join("config.toml"))
                .env("RUST_LOG", "info")
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        );
    }
    fn log(&self) -> String {
        fs::read_to_string(self.dir.join("log")).unwrap()
    }
    async fn wait_log(&mut self, marker: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if self.log().contains(marker) {
                    return;
                }
                assert!(
                    self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                    "{}",
                    self.log()
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("missing {marker}: {}", self.log()));
    }
    fn signal(&self, signal: &str) {
        assert!(Command::new("kill")
            .arg(signal)
            .arg(self.child.as_ref().unwrap().id().to_string())
            .status()
            .unwrap()
            .success());
    }
    async fn udp(&self, name: &str) -> io::Result<DnsMessage> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket
            .send_to(
                &DnsMessage::new_query(1234, name, 1).serialize()?,
                ("127.0.0.1", self.port),
            )
            .await?;
        let mut buf = [0; 4096];
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await??;
        DnsMessage::parse(&buf[..n])
    }
    async fn tcp(&self, name: &str) -> DnsMessage {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
            let query = DnsMessage::new_query(1234, name, 1).serialize().unwrap();
            let mut frame = (query.len() as u16).to_be_bytes().to_vec();
            frame.extend(query);
            stream.write_all(&frame).await.unwrap();
            let n = stream.read_u16().await.unwrap() as usize;
            let mut buf = vec![0; n];
            stream.read_exact(&mut buf).await.unwrap();
            DnsMessage::parse(&buf).unwrap()
        })
        .await
        .unwrap()
    }
    async fn stop(&mut self) {
        self.signal("-TERM");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                    assert!(status.success(), "{}", self.log());
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}
impl Drop for App {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn rcode(msg: &DnsMessage) -> u16 {
    msg.header.flags & 15
}

struct Dns {
    port: u16,
    count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
    site_seen: Arc<Semaphore>,
    release_site: Arc<Semaphore>,
}
impl Drop for Dns {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn dns(hold_site: bool) -> Dns {
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let port = udp.local_addr().unwrap().port();
    let site_seen = Arc::new(Semaphore::new(0));
    let release_site = Arc::new(Semaphore::new(0));
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    let seen = site_seen.clone();
    let release = release_site.clone();
    let task = tokio::spawn(async move {
        let mut handlers = JoinSet::new();
        let mut buf = [0; 4096];
        loop {
            tokio::select! {
                received = udp.recv_from(&mut buf) => {
                    let (n, peer) = received.unwrap();
                    counter.fetch_add(1, Ordering::SeqCst);
                    let mut msg = DnsMessage::parse(&buf[..n]).unwrap();
                    msg.header.flags = 0x8180;
                    msg.additionals.clear();
                    let site = msg.questions[0].name == "site.test";
                    if site {
                        msg.answers.push(DnsResourceRecord {
                            name: "site.test".into(), rtype: 5, rclass: 1, ttl: 60,
                            rdata: rust_dns::dns::serialize_name("tracker.test").unwrap(), cname_target: None,
                        });
                        msg.header.ancount = 1;
                    }
                    let wire = msg.serialize().unwrap();
                    let (socket, seen, release) = (udp.clone(), seen.clone(), release.clone());
                    handlers.spawn(async move {
                        if site && hold_site {
                            seen.add_permits(1);
                            release.acquire().await.unwrap().forget();
                        }
                        socket.send_to(&wire, peer).await.unwrap();
                    });
                },
                Some(result) = handlers.join_next() => { result.unwrap(); },
            }
        }
    });
    Dns {
        port,
        count,
        task,
        site_seen,
        release_site,
    }
}

struct Http {
    url: String,
    count: Arc<AtomicUsize>,
    release: Arc<Semaphore>,
    task: JoinHandle<()>,
}
impl Drop for Http {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Http {
    async fn wait_count(&self, n: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.count.load(Ordering::SeqCst) < n {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}
async fn http(hold: Option<usize>) -> Http {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://127.0.0.1:{}/list",
        listener.local_addr().unwrap().port()
    );
    let count = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Semaphore::new(0));
    let (counter, gate) = (count.clone(), release.clone());
    let task = tokio::spawn(async move {
        let mut handlers = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted.unwrap();
                    let (counter, gate) = (counter.clone(), gate.clone());
                    handlers.spawn(async move {
                        let mut request = Vec::new();
                        let mut buf = [0; 1024];
                        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                            let n = stream.read(&mut buf).await.unwrap();
                            if n == 0 { return; }
                            request.extend_from_slice(&buf[..n]);
                        }
                        let number = counter.fetch_add(1, Ordering::SeqCst) + 1;
                        if hold == Some(number) { gate.acquire().await.unwrap().forget(); }
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nold.list\n").await;
                    });
                },
                Some(result) = handlers.join_next() => { result.unwrap(); },
            }
        }
    });
    Http {
        url,
        count,
        release,
        task,
    }
}

#[tokio::test]
async fn cold_start_serves_udp_and_tcp_while_first_list_is_stalled_and_stops_promptly() {
    let upstream = dns(false).await;
    let list = http(Some(1)).await;
    let mut app = App::new(upstream.port);
    app.urls.push(list.url.clone());
    app.blocked.push("manual.test".into());
    app.start();
    app.wait_log("Listening on").await;
    list.wait_count(1).await;
    assert_eq!(rcode(&app.udp("manual.test").await.unwrap()), 3);
    assert_eq!(rcode(&app.tcp("manual.test").await), 3);
    assert_eq!(rcode(&app.udp("public.test").await.unwrap()), 0);
    assert!(!app.log().contains("Initial remote refresh completed."));
    app.stop().await;
}

#[tokio::test]
async fn stale_cached_rules_apply_before_remote_refresh_finishes() {
    let upstream = dns(false).await;
    let list = http(Some(1)).await;
    let mut app = App::new(upstream.port);
    app.urls.push(list.url.clone());
    let path = app.cache_path.to_str().unwrap();
    let mut cache = CachedLists::new();
    cache.merge_downloads(
        vec![(
            list.url.clone(),
            DownloadResult::Fresh {
                body: "cached.test\n".into(),
                etag: None,
            },
        )],
        path,
    );
    cache.save_to_disk(path).unwrap();
    app.start();
    app.wait_log("Listening on").await;
    list.wait_count(1).await;
    assert_eq!(rcode(&app.udp("cached.test").await.unwrap()), 3);
    list.release.add_permits(1);
    app.wait_log("Initial remote refresh completed.").await;
    assert_eq!(rcode(&app.udp("old.list").await.unwrap()), 3);
    app.stop().await;
}

#[tokio::test]
async fn hup_queued_during_old_refresh_cannot_be_overwritten_by_it() {
    let upstream = dns(false).await;
    let list = http(Some(2)).await;
    let mut app = App::new(upstream.port);
    app.urls.push(list.url.clone());
    app.blocked.push("old.manual".into());
    app.interval = 1;
    app.start();
    app.wait_log("Initial remote refresh completed.").await;
    list.wait_count(2).await;
    app.urls.clear();
    app.blocked = vec!["new.manual".into()];
    app.interval = 3600;
    app.write_config();
    app.signal("-HUP");
    // Give the previous independent HUP path time to publish out of order.
    tokio::time::sleep(Duration::from_millis(200)).await;
    list.release.add_permits(1);
    app.wait_log("Configuration reloaded successfully.").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rcode(&app.udp("new.manual").await.unwrap()), 3);
    assert_eq!(rcode(&app.udp("old.manual").await.unwrap()), 0);
    assert_eq!(rcode(&app.udp("old.list").await.unwrap()), 0);
    assert!(
        CachedLists::load_from_disk(app.cache_path.to_str().unwrap())
            .unwrap()
            .map
            .is_empty()
    );
    app.stop().await;
}

#[tokio::test]
async fn interval_change_wakes_previously_long_timer() {
    let upstream = dns(false).await;
    let list = http(None).await;
    let mut app = App::new(upstream.port);
    app.urls.push(list.url.clone());
    app.start();
    app.wait_log("Initial remote refresh completed.").await;
    app.interval = 1;
    app.write_config();
    app.signal("-HUP");
    app.wait_log("Configuration reloaded successfully.").await;
    list.wait_count(3).await; // initial, HUP, then new one-second timer
    app.stop().await;
}

#[tokio::test]
async fn cache_path_migration_is_used_after_reload_and_restart() {
    let upstream = dns(false).await;
    let list = http(Some(2)).await;
    let mut app = App::new(upstream.port);
    app.urls.push(list.url.clone());
    app.start();
    app.wait_log("Initial remote refresh completed.").await;
    let old_path = app.cache_path.clone();
    app.cache_path = app.dir.join("new").join("cache.json");
    app.write_config();
    app.signal("-HUP");
    list.wait_count(2).await;
    // Migration is complete before the remote update; cached filtering remains.
    assert!(app.cache_path.exists());
    assert!(old_path.exists());
    assert_eq!(rcode(&app.udp("old.list").await.unwrap()), 3);
    list.release.add_permits(1);
    app.wait_log("Configuration reloaded successfully.").await;
    assert_eq!(
        CachedLists::load_from_disk(app.cache_path.to_str().unwrap())
            .unwrap()
            .map
            .len(),
        1
    );
    app.stop().await;
    // Restart from the new cache with the list server offline.
    drop(list);
    app.start();
    app.wait_log("Listening on").await;
    assert_eq!(rcode(&app.udp("old.list").await.unwrap()), 3);
    app.stop().await;
}

#[tokio::test]
async fn failed_cache_path_change_keeps_previous_config_and_rules() {
    let upstream = dns(false).await;
    let mut app = App::new(upstream.port);
    app.blocked.push("old.manual".into());
    app.start();
    app.wait_log("Initial remote refresh completed.").await;
    let old_path = app.cache_path.clone();
    let blocker = app.dir.join("file");
    fs::write(&blocker, "not a directory").unwrap();
    app.cache_path = blocker.join("cache.json");
    app.upstream_port = 9;
    app.blocked = vec!["new.manual".into()];
    app.write_config();
    app.signal("-HUP");
    app.wait_log("Failed to prepare update; keeping previous state")
        .await;
    assert_eq!(rcode(&app.udp("old.manual").await.unwrap()), 3);
    assert_eq!(rcode(&app.udp("new.manual").await.unwrap()), 0);
    app.cache_path = old_path;
    app.upstream_port = upstream.port;
    app.write_config();
    app.signal("-HUP");
    app.wait_log("Configuration reloaded successfully.").await;
    assert_eq!(rcode(&app.udp("new.manual").await.unwrap()), 3);
    app.stop().await;
}

#[tokio::test]
async fn invalid_reload_retains_working_rules() {
    let upstream = dns(false).await;
    let mut app = App::new(upstream.port);
    app.blocked.push("old.manual".into());
    app.start();
    app.wait_log("Initial remote refresh completed.").await;
    app.write_config();
    let path = app.dir.join("config.toml");
    fs::write(
        &path,
        fs::read_to_string(&path)
            .unwrap()
            .replace("regex_block=[]", "regex_block=[\"[\"]"),
    )
    .unwrap();
    app.signal("-HUP");
    app.wait_log("Failed to prepare update; keeping previous state")
        .await;
    assert_eq!(rcode(&app.udp("old.manual").await.unwrap()), 3);
    for (interval, marker) in [
        (0, "refresh_interval_secs must be greater than zero"),
        (i64::MAX as u64, "refresh_interval_secs exceeds the timer range"),
    ] {
        app.interval = interval;
        app.write_config();
        app.signal("-HUP");
        app.wait_log(marker).await;
        assert_eq!(rcode(&app.udp("old.manual").await.unwrap()), 3);
    }
    app.stop().await;
}

#[tokio::test]
async fn in_flight_query_keeps_its_original_filtering_generation() {
    let upstream = dns(true).await;
    let mut app = App::new(upstream.port);
    app.start();
    app.wait_log("Initial remote refresh completed.").await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(
            &DnsMessage::new_query(1234, "site.test", 1)
                .serialize()
                .unwrap(),
            ("127.0.0.1", app.port),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), upstream.site_seen.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    app.blocked.push("tracker.test".into());
    app.write_config();
    app.signal("-HUP");
    app.wait_log("Configuration reloaded successfully.").await;
    upstream.release_site.add_permits(1);
    let mut buf = [0; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rcode(&DnsMessage::parse(&buf[..n]).unwrap()), 0);
    assert_eq!(rcode(&app.udp("tracker.test").await.unwrap()), 3);
    app.stop().await;
}

#[tokio::test]
async fn tcp_bind_failure_exits_without_a_half_running_service() {
    let upstream = dns(false).await;
    let mut app = App::new(upstream.port);
    let _occupied = std::net::TcpListener::bind(("127.0.0.1", app.port)).unwrap();
    app.start();
    let status = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(status) = app.child.as_mut().unwrap().try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(!status.success());
    assert!(!app.log().contains("Listening on"));
}

#[tokio::test]
async fn upstream_changes_only_for_queries_after_successful_reload() {
    let old = dns(false).await;
    let new = dns(false).await;
    let mut app = App::new(old.port);
    app.start();
    app.wait_log("Initial remote refresh completed.").await;
    assert_eq!(rcode(&app.udp("public.test").await.unwrap()), 0);
    assert_eq!(old.count.load(Ordering::SeqCst), 1);
    assert_eq!(new.count.load(Ordering::SeqCst), 0);
    app.upstream_port = new.port;
    app.write_config();
    app.signal("-HUP");
    app.wait_log("Configuration reloaded successfully.").await;
    assert_eq!(rcode(&app.udp("public.test").await.unwrap()), 0);
    assert_eq!(old.count.load(Ordering::SeqCst), 1);
    assert_eq!(new.count.load(Ordering::SeqCst), 1);
    app.stop().await;
}

#[tokio::test]
async fn existing_body_is_usable_at_boot_with_corrupt_metadata() {
    let upstream = dns(false).await;
    let list = http(Some(1)).await;
    let mut app = App::new(upstream.port);
    app.urls.push(list.url.clone());
    let mut cache = CachedLists::new();
    cache.merge_downloads(
        vec![(
            list.url.clone(),
            DownloadResult::Fresh {
                body: "cached.test\n".into(),
                etag: None,
            },
        )],
        app.cache_path.to_str().unwrap(),
    );
    fs::write(&app.cache_path, "{unfinished").unwrap();
    app.start();
    app.wait_log("Listening on").await;
    list.wait_count(1).await;
    assert_eq!(rcode(&app.udp("cached.test").await.unwrap()), 3);
    app.stop().await;
}
