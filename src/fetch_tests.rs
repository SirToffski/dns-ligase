use super::*;
use crate::dns::{DnsMessage, DnsResourceRecord};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let id = TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("dns-ligase-fetch-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn cache(&self) -> String {
        self.0.join("cache.json").to_str().unwrap().into()
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct DnsStub {
    upstream: Arc<Upstream>,
    queries: Arc<tokio::sync::Mutex<Vec<String>>>,
    tasks: Vec<JoinHandle<()>>,
}
impl Drop for DnsStub {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
fn dns_reply(bytes: &[u8], truncated: bool, has_address: bool) -> Vec<u8> {
    let mut msg = DnsMessage::parse(bytes).unwrap();
    msg.header.flags = if truncated { 0x8380 } else { 0x8180 };
    msg.additionals.clear();
    if has_address && !truncated {
        msg.answers = vec![DnsResourceRecord {
            name: msg.questions[0].name.clone(),
            rtype: 1,
            rclass: 1,
            ttl: 60,
            rdata: vec![127, 0, 0, 1],
            cname_target: None,
        }];
        msg.header.ancount = 1;
    }
    msg.serialize().unwrap()
}
async fn dns_stub(truncated: bool, has_address: bool) -> DnsStub {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();
    let queries = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let seen = Arc::clone(&queries);
    let udp_task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            let name = DnsMessage::parse(&buf[..n]).unwrap().questions[0]
                .name
                .clone();
            seen.lock().await.push(name);
            udp.send_to(&dns_reply(&buf[..n], truncated, has_address), peer)
                .await
                .unwrap();
        }
    });
    let seen = Arc::clone(&queries);
    let tcp_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let n = stream.read_u16().await.unwrap() as usize;
            let mut query = vec![0; n];
            stream.read_exact(&mut query).await.unwrap();
            seen.lock().await.push(format!(
                "tcp:{}",
                DnsMessage::parse(&query).unwrap().questions[0].name
            ));
            let resp = dns_reply(&query, false, has_address);
            let mut frame = (resp.len() as u16).to_be_bytes().to_vec();
            frame.extend(resp);
            stream.write_all(&frame).await.unwrap();
        }
    });
    DnsStub {
        upstream: Arc::new(Upstream::new(addr)),
        queries,
        tasks: vec![udp_task, tcp_task],
    }
}
async fn http_stub(responses: Vec<String>) -> (u16, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buf[..n]);
            }
            requests.push(String::from_utf8(request).unwrap());
            stream.write_all(response.as_bytes()).await.unwrap();
        }
        requests
    });
    (port, task)
}

#[tokio::test]
async fn redirects_resolve_both_hosts_through_upstream() {
    let dns = dns_stub(false, true).await;
    let (dest, final_task) = http_stub(vec![
        "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nads.example\n".into(),
    ])
    .await;
    let (origin, first_task) = http_stub(vec![format!("HTTP/1.1 302 Found\r\nLocation: http://redirect.invalid:{dest}/list\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")]).await;
    let dir = TestDir::new();
    let url = format!("http://origin.invalid:{origin}/list");
    let result = CachedLists::download_jobs(
        vec![FetchJob { url, etag: None }],
        &dir.cache(),
        Arc::clone(&dns.upstream),
    )
    .await;
    assert!(matches!(&result[0].1, DownloadResult::Fresh { body, .. } if body == "ads.example\n"));
    assert_eq!(
        *dns.queries.lock().await,
        ["origin.invalid", "redirect.invalid"]
    );
    first_task.await.unwrap();
    final_task.await.unwrap();
}

#[tokio::test]
async fn dns_failure_does_not_fall_back_to_system_localhost() {
    let dns = dns_stub(false, false).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = TestDir::new();
    // System DNS can resolve localhost; our upstream deliberately returns no A.
    let url = format!(
        "http://localhost:{}/list",
        listener.local_addr().unwrap().port()
    );
    let client = list_client_builder(Arc::clone(&dns.upstream))
        .build()
        .unwrap();
    let result = download_one(&url, None, &client, &dir.cache()).await;
    assert!(matches!(result, DownloadResult::Failed(_)));
    assert_eq!(*dns.queries.lock().await, ["localhost"]);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn bootstrap_dns_retries_truncation_over_tcp() {
    let dns = dns_stub(true, true).await;
    assert_eq!(
        dns.upstream.resolve_a("list.invalid").await.unwrap(),
        [std::net::Ipv4Addr::LOCALHOST]
    );
    assert_eq!(
        *dns.queries.lock().await,
        ["list.invalid", "tcp:list.invalid"]
    );
}

#[tokio::test]
async fn incomplete_http_200_uses_old_body() {
    let (port, task) = http_stub(vec![
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial\n".into(),
    ])
    .await;
    let dns = dns_stub(false, true).await;
    let dir = TestDir::new();
    let url = format!("http://127.0.0.1:{port}/list");
    CachedLists::new()
        .write_body(&dir.cache(), &url_to_filename(&url), "old.example\n")
        .unwrap();
    let client = list_client_builder(Arc::clone(&dns.upstream))
        .build()
        .unwrap();
    assert!(
        matches!(download_one(&url, None, &client, &dir.cache()).await,
        DownloadResult::StaleFallback { body, error } if body == "old.example\n" && error.contains("read body"))
    );
    task.await.unwrap();
}

#[tokio::test]
async fn missing_body_304_rejects_error_page_and_drops_etag_on_retry() {
    let (port, task) = http_stub(vec![
        "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".into(),
        "HTTP/1.1 503 Unavailable\r\nContent-Length: 5\r\nConnection: close\r\n\r\nerror".into(),
    ])
    .await;
    let dns = dns_stub(false, true).await;
    let dir = TestDir::new();
    let client = list_client_builder(Arc::clone(&dns.upstream))
        .build()
        .unwrap();
    let result = download_one(
        &format!("http://127.0.0.1:{port}/list"),
        Some("\"v1\""),
        &client,
        &dir.cache(),
    )
    .await;
    assert!(matches!(result, DownloadResult::Failed(error) if error.contains("503")));
    let requests = task.await.unwrap();
    assert!(requests[0].to_lowercase().contains("if-none-match: \"v1\""));
    assert!(!requests[1].to_lowercase().contains("if-none-match"));
}

#[tokio::test]
async fn stalled_headers_and_body_are_bounded_and_keep_cache() {
    let dns = dns_stub(false, true).await;
    for send_headers in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://127.0.0.1:{}/list",
            listener.local_addr().unwrap().port()
        );
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0; 1];
            stream.read_exact(&mut buf).await.unwrap();
            if send_headers {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
                    .await
                    .unwrap();
            }
            std::future::pending::<()>().await;
        });
        let dir = TestDir::new();
        CachedLists::new()
            .write_body(&dir.cache(), &url_to_filename(&url), "old.example\n")
            .unwrap();
        let client = list_client_builder(Arc::clone(&dns.upstream))
            .timeout(Duration::from_millis(75))
            .build()
            .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            download_one(&url, None, &client, &dir.cache()),
        )
        .await
        .unwrap();
        assert!(
            matches!(result, DownloadResult::StaleFallback { body, .. } if body == "old.example\n")
        );
        task.abort();
    }
}

#[test]
fn persistence_failure_keeps_download_and_old_metadata() {
    let dir = TestDir::new();
    let blocker = dir.0.join("file");
    fs::write(&blocker, "not a directory").unwrap();
    let path = blocker.join("cache.json");
    let mut cache = CachedLists::new();
    let url = "https://list.invalid/a";
    cache.map.insert(
        url.into(),
        CachedList {
            fetched_at: 1,
            etag: Some("old".into()),
            filename: url_to_filename(url),
        },
    );
    let bodies = cache.merge_downloads(
        vec![(
            url.into(),
            DownloadResult::Fresh {
                body: "new.example\n".into(),
                etag: Some("new".into()),
            },
        )],
        path.to_str().unwrap(),
    );
    assert_eq!(bodies, [(url.into(), "new.example\n".into())]);
    assert_eq!(cache.map[url].etag.as_deref(), Some("old"));
    let rejected = cache.merge_downloads(
        vec![(
            url.into(),
            DownloadResult::Fresh {
                body: String::new(),
                etag: Some("empty".into()),
            },
        )],
        path.to_str().unwrap(),
    );
    assert_eq!(rejected, bodies);
    assert_eq!(cache.map[url].etag.as_deref(), Some("old"));
}

#[test]
fn validate_candidates_in_each_configured_list_format() {
    for body in ["", " \n", "! comment\n", "<!DOCTYPE html>\n<p>error</p>"] {
        assert!(validate_list(body, true, false).is_err());
        assert!(validate_list(body, false, true).is_err());
    }
    assert!(validate_list("||host.test^$client=phone", true, false).is_err());
    assert!(validate_list("unsupported rule text\n", true, false).is_err());
    assert!(validate_list("[invalid\n(?=unsupported)", false, true).is_err());
    assert!(validate_list("[invalid\n^ads[.]", false, true).is_ok());
    assert!(validate_list("||host.test^$badfilter", true, false).is_ok());
    assert!(validate_list("bad rule text\n127.0.0.1 real.test", true, false).is_ok());
}

#[test]
fn failed_metadata_save_is_retried() {
    let dir = TestDir::new();
    let mut cache = CachedLists::new();
    cache.merge_downloads(
        vec![(
            "https://list.invalid/a".into(),
            DownloadResult::Fresh {
                body: "ads.example\n".into(),
                etag: None,
            },
        )],
        &dir.cache(),
    );
    let blocker = dir.0.join("file");
    fs::write(&blocker, "not a directory").unwrap();
    assert!(cache
        .save_to_disk(blocker.join("cache.json").to_str().unwrap())
        .is_err());
    cache.save_to_disk(&dir.cache()).unwrap();
    assert_eq!(
        CachedLists::load_from_disk(&dir.cache()).unwrap().map.len(),
        1
    );
}

#[test]
fn failed_atomic_replacement_preserves_target_and_cleans_temporary_file() {
    let dir = TestDir::new();
    let target = dir.0.join("existing");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), "old").unwrap();
    assert!(atomic_write(&target, b"new").is_err());
    assert_eq!(fs::read_to_string(target.join("sentinel")).unwrap(), "old");
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
}
