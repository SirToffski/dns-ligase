//! Minimal journald native protocol sender.
//!
//! The journald native protocol is a single UNIX datagram to
//! `/run/systemd/journal/socket`. Each field is `KEY=VALUE\n`. Journald adds
//! the timestamp, unit name (from the sender's cgroup), and handles storage.
//! If the socket doesn't exist (not under systemd), the send silently fails.
//!
//! No external crates. Query logs go through here; operational logs stay on
//! `log::info!`/`env_logger`. Both end up in journald, but query entries carry
//! `QUERY_*` structured fields for precise filtering:
//!
//! ```sh
//! journalctl -u dns-ligase QUERY_ACTION=blocked
//! journalctl -u dns-ligase QUERY_DOMAIN=ads.example.com
//! ```

use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::OnceLock;

const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// Lazily-initialized, reused journald socket. Created once on first query
/// log; if the socket can't be created (no journald), stores `None` and never
/// retries, so the hot path is a single `send()` per log line.
static JOURNAL_SOCK: OnceLock<Option<UnixDatagram>> = OnceLock::new();

/// Log a DNS query decision to journald with structured fields.
///
/// Silently does nothing if the journald socket is unavailable (e.g. running
/// outside systemd), so this is safe to call unconditionally.
pub fn log_query(source: &str, domain: &str, qtype: &str, action: &str, rule: &str) {
    // The native protocol frames fields with newlines, but DNS labels may
    // legally contain 0x0A/0x0D bytes — a crafted QNAME could otherwise inject
    // forged journal fields. ('=' inside a value is harmless: only the first
    // '=' separates key from value.)
    let source = sanitize_field(source);
    let domain = sanitize_field(domain);
    let qtype = sanitize_field(qtype);
    let action = sanitize_field(action);
    let rule = sanitize_field(rule);

    let priority = match action.as_str() {
        "blocked" => 6, // LOG_INFO
        "allowed" => 7, // LOG_DEBUG
        _ => 6,
    };

    let message = if rule.is_empty() {
        format!("query {action} {domain} ({qtype}) from {source}")
    } else {
        format!("query {action} {domain} ({qtype}) from {source} [{rule}]")
    };

    let entry = format!(
        "PRIORITY={priority}\n\
         SYSLOG_IDENTIFIER=dns-ligase\n\
         MESSAGE={message}\n\
         QUERY_SOURCE={source}\n\
         QUERY_DOMAIN={domain}\n\
         QUERY_QTYPE={qtype}\n\
         QUERY_ACTION={action}\n\
         QUERY_RULE={rule}\n"
    );

    if let Err(e) = send(&entry) {
        // Only log at debug to avoid spamming stderr when journald is absent.
        log::debug!("journald send failed: {e}");
    }
}

fn send(entry: &str) -> io::Result<()> {
    let socket = JOURNAL_SOCK.get_or_init(|| connect_socket(Path::new(JOURNAL_SOCKET)).ok());
    match socket {
        Some(s) => send_entry(s, entry),
        None => Ok(()),
    }
}

fn connect_socket(path: &Path) -> io::Result<UnixDatagram> {
    let socket = UnixDatagram::unbound()?;
    socket.set_nonblocking(true)?;
    socket.connect(path)?;
    Ok(socket)
}

fn send_entry(socket: &UnixDatagram, entry: &str) -> io::Result<()> {
    match socket.send(entry.as_bytes()) {
        // Query logging is best-effort; congestion must not block DNS or
        // recursively flood journald through operational error logs.
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
        result => result.map(|_| ()),
    }
}

/// Strip newline bytes from a journal field value so untrusted input (e.g. a
/// QNAME containing 0x0A) cannot forge journal protocol framing.
fn sanitize_field(s: &str) -> String {
    if s.bytes().any(|b| b == b'\n' || b == b'\r') {
        s.replace(['\n', '\r'], "_")
    } else {
        s.to_string()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_journal_queue_is_best_effort_and_never_blocks() {
        use std::sync::{atomic::{AtomicUsize, Ordering}, mpsc};
        use std::time::Duration;
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!("dns-journal-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("socket");
        let receiver = UnixDatagram::bind(&path).unwrap();
        let socket = connect_socket(&path).unwrap();
        let (tx,rx) = mpsc::channel();
        let task = std::thread::spawn(move || {
            for _ in 0..1024 {
                match socket.send(&[b'x';8192]) {
                    Ok(_) => {},
                    Err(e) if e.kind()==io::ErrorKind::WouldBlock => {
                        let _ = tx.send(send_entry(&socket,"QUERY_ACTION=blocked\n").is_ok());
                        return;
                    },
                    Err(_) => break,
                }
            }
            let _ = tx.send(false);
        });
        let result = rx.recv_timeout(Duration::from_secs(2));
        drop(receiver); // also releases a buggy blocking sender before joining
        task.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(result.unwrap());
    }

    #[test]
    fn unavailable_journal_socket_returns_an_error() {
        let path = std::env::temp_dir().join(format!("missing-dns-journal-{}",std::process::id()));
        assert!(connect_socket(&path).is_err());
    }

    #[test]
    fn test_log_query_does_not_panic_without_journald() {
        // On a system without journald (or in a test environment), this should
        // silently fail rather than panic.
        log_query("192.168.1.5", "ads.example.com", "A", "blocked", "||ads.example.com^");
        log_query("10.0.0.1", "example.com", "AAAA", "allowed", "");
        // A QNAME carrying newline bytes must not panic either.
        log_query("10.0.0.2", "evil\nQUERY_ACTION=allowed", "A", "blocked", "x\ny");
    }

    #[test]
    fn test_sanitize_field() {
        assert_eq!(sanitize_field("ads.example.com"), "ads.example.com");
        assert_eq!(sanitize_field("a\nb"), "a_b");
        assert_eq!(sanitize_field("a\rb"), "a_b");
        assert_eq!(sanitize_field("a\nQUERY_ACTION=x\nb"), "a_QUERY_ACTION=x_b");
        // '=' is harmless to the protocol and must survive (rules contain it).
        assert_eq!(sanitize_field("a=b"), "a=b");
    }
}
