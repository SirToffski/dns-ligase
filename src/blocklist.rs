use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::upstream::Upstream;
mod adguard;
pub(crate) use adguard::DisabledRules;
use adguard::{split_options, TypedRule};

#[derive(Debug, Default)]
pub struct Blocklist {
    pub allow_domains: HashSet<String>,
    pub block_domains: HashSet<String>,
    pub allow_suffixes: HashSet<String>,
    pub block_suffixes: HashSet<String>,
    pub allow_regex: Vec<Regex>,
    pub block_regex: Vec<Regex>,
    typed_suffixes: HashMap<String, Vec<TypedRule>>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn rule_count(&self) -> usize {
        self.block_domains.len()
            + self.allow_domains.len()
            + self.block_suffixes.len()
            + self.allow_suffixes.len()
            + self.block_regex.len()
            + self.allow_regex.len()
            + self.typed_suffixes.values().map(Vec::len).sum::<usize>()
    }

    pub fn parse_line(&mut self, line: &str, format: ListFormat) -> Result<(), Box<dyn Error>> {
        self.parse_line_mode(line, format, false)
    }

    /// Parse a single line. When `as_allow` is true, every rule is routed to
    /// the allow sets regardless of `@@` prefix — used for allowlist URL files
    /// where bare domains and `||domain^` patterns should all be allow rules.
    pub fn parse_line_mode(
        &mut self,
        line: &str,
        format: ListFormat,
        as_allow: bool,
    ) -> Result<(), Box<dyn Error>> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            return Ok(());
        }

        match format {
            ListFormat::Hosts | ListFormat::PiHole => {
                self.parse_host_line(line, as_allow);
            }
            ListFormat::AdBlock | ListFormat::AdGuard => {
                let has_at = line.starts_with("@@");
                let is_allow = as_allow || has_at;
                let pattern_part = if has_at {
                    line.trim_start_matches("@@")
                } else {
                    line
                };

                let (pattern_part, options) = split_options(pattern_part);
                if let Some(suffix) = pattern_part.strip_prefix("||") {
                    let domain = suffix
                        .strip_suffix('^')
                        .unwrap_or(suffix)
                        .trim_end_matches('.');
                    if !valid_domain(domain) {
                        return Err("unsupported AdGuard domain pattern".into());
                    }
                    let domain = domain.to_ascii_lowercase();
                    if let Some(options) = options {
                        let rule = TypedRule::parse(line, is_allow, options)?;
                        self.typed_suffixes.entry(domain).or_default().push(rule);
                    } else if is_allow {
                        self.allow_suffixes.insert(domain);
                    } else {
                        self.block_suffixes.insert(domain);
                    }
                } else if let Some(options) = options {
                    return Err(
                        format!("unsupported AdGuard modifier or pattern: {options}").into(),
                    );
                } else if pattern_part.starts_with('/') && pattern_part.ends_with('/') {
                    let pattern = pattern_part
                        .strip_prefix('/')
                        .and_then(|s| s.strip_suffix('/'))
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "Empty regex delimiter")
                        })?;
                    let re = Regex::new(pattern)?;
                    if is_allow {
                        self.allow_regex.push(re);
                    } else {
                        self.block_regex.push(re);
                    }
                } else {
                    self.parse_host_line(pattern_part, is_allow);
                }
            }
        }
        Ok(())
    }

    pub fn parse_auto(&mut self, line: &str) -> Result<(), Box<dyn Error>> {
        self.parse_auto_mode(line, false)
    }

    /// Auto-detect format and parse. When `as_allow` is true, every rule is
    /// routed to the allow sets.
    pub fn parse_auto_mode(&mut self, line: &str, as_allow: bool) -> Result<(), Box<dyn Error>> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            return Ok(());
        }

        if line.starts_with("||")
            || line.starts_with("@@")
            || line.starts_with('/')
            || (line.contains('$') && !line.contains('#') && !line.contains(char::is_whitespace))
        {
            self.parse_line_mode(line, ListFormat::AdBlock, as_allow)
        } else {
            self.parse_line_mode(line, ListFormat::Hosts, as_allow)
        }
    }

    #[allow(dead_code)]
    pub async fn fetch_and_parse(
        &mut self,
        url: &str,
        format: Option<ListFormat>,
        upstream: Arc<Upstream>,
    ) -> Result<(), Box<dyn Error>> {
        let content = list_client_builder(upstream)
            .build()?
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        validate_content(&content)?;
        let mut disabled = DisabledRules::default();
        disabled.collect(content.lines(), false);
        for line in content.lines().filter(|line| !disabled.skips(line, false)) {
            match format {
                Some(f) => self.parse_line(line, f)?,
                None => self.parse_auto(line)?,
            }
        }
        Ok(())
    }

    /// Suffix lookup returning the matched rule, so logs show which suffix
    /// fired (e.g. `block_suffix:ads.com`) rather than the queried name.
    fn suffix_match<'s>(set: &'s HashSet<String>, domain: &str) -> Option<&'s str> {
        if let Some(hit) = set.get(domain) {
            return Some(hit);
        }
        let mut rest = domain;
        while let Some(pos) = rest.find('.') {
            rest = &rest[pos + 1..];
            if let Some(hit) = set.get(rest) {
                return Some(hit);
            }
        }
        None
    }

    fn parse_host_line(&mut self, line: &str, as_allow: bool) {
        // AdBlock/uBO cosmetic and scriptlet rules (##, #$#, #@#, #?#) are not
        // DNS rules. Without this guard a line like `example.com##.ad` would be
        // truncated at '#' below and misparsed as a bare-domain block for the
        // whole domain. A hosts file never legitimately contains these markers.
        if line.contains("##")
            || line.contains("#$#")
            || line.contains("#@#")
            || line.contains("#?#")
        {
            return;
        }
        let mut parts = line.split('#').next().unwrap_or("").split_whitespace();
        let Some(first) = parts.next() else {
            return;
        };
        let set = if as_allow {
            &mut self.allow_domains
        } else {
            &mut self.block_domains
        };
        if first.parse::<IpAddr>().is_ok() {
            for domain in parts {
                if let Some(domain) = Self::clean_domain_static(domain) {
                    set.insert(domain.to_lowercase());
                }
            }
        } else if parts.next().is_none() {
            // Bare-domain entries contain one token. Arbitrary trailing prose
            // must not become a hostname rule.
            if let Some(domain) = Self::clean_domain_static(first) {
                set.insert(domain.to_lowercase());
            }
        }
    }

    fn clean_domain_static(domain: &str) -> Option<&str> {
        let cleaned = domain.trim_end_matches('.');
        if !valid_domain(cleaned) {
            return None;
        }
        // Never block local names commonly present in hosts files (e.g. the
        // `127.0.0.1 localhost` lines in StevenBlack). Blocking them would
        // NXDOMAIN local resolution for the whole LAN.
        if cleaned.eq_ignore_ascii_case("localhost")
            || cleaned.eq_ignore_ascii_case("localhost.localdomain")
            || cleaned.eq_ignore_ascii_case("broadcasthost")
            || cleaned.eq_ignore_ascii_case("local")
        {
            return None;
        }
        Some(cleaned)
    }

    #[allow(dead_code)]
    pub fn matches(&self, domain: &str) -> bool {
        matches!(self.check(domain), MatchOutcome::Blocked(_))
    }

    /// Check a domain and return the outcome with the matched rule, if any.
    /// Only allocates the rule description string when a rule actually matches.
    pub fn check(&self, domain: &str) -> MatchOutcome {
        self.check_name(domain, None)
    }

    /// Evaluate a DNS question or CNAME target using its wire record type.
    pub fn check_query(&self, domain: &str, qtype: u16) -> MatchOutcome {
        self.check_name(domain, Some(qtype))
    }

    fn check_name(&self, domain: &str, qtype: Option<u16>) -> MatchOutcome {
        // Fast path: query names are almost always already lowercase — borrow
        // the input as-is and only allocate when an uppercase byte is present.
        let lowered;
        let domain_lower: &str = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            lowered = domain.to_lowercase();
            &lowered
        } else {
            domain
        };
        // Allow takes precedence over block
        if self.allow_domains.contains(domain_lower) {
            return MatchOutcome::Allowed(format!("allow:{}", domain_lower));
        }
        for re in &self.allow_regex {
            if re.is_match(domain_lower) {
                return MatchOutcome::Allowed(format!("allow_regex:{}", re.as_str()));
            }
        }
        if let Some(hit) = Self::suffix_match(&self.allow_suffixes, domain_lower) {
            return MatchOutcome::Allowed(format!("allow_suffix:{hit}"));
        }
        let mut typed_block = None;
        let mut has_typed_allow = false;
        if let Some(qtype) = qtype.filter(|_| !self.typed_suffixes.is_empty()) {
            let suffixes = std::iter::successors(Some(domain_lower), |name| {
                name.split_once('.').map(|(_, rest)| rest)
            });
            for rules in suffixes.filter_map(|suffix| self.typed_suffixes.get(suffix)) {
                for rule in rules {
                    has_typed_allow |= rule.allow;
                    if !rule.matches(qtype) {
                        continue;
                    }
                    if rule.allow {
                        return MatchOutcome::Allowed(format!("allow:{}", rule.text));
                    }
                    typed_block.get_or_insert(rule);
                }
            }
        }
        // A name with an exception for another type cannot be reported as nonexistent.
        let blocked = if has_typed_allow {
            MatchOutcome::BlockedType
        } else {
            MatchOutcome::Blocked
        };
        if self.block_domains.contains(domain_lower) {
            return blocked(format!("block:{}", domain_lower));
        }
        if let Some(hit) = Self::suffix_match(&self.block_suffixes, domain_lower) {
            return blocked(format!("block_suffix:{hit}"));
        }
        for re in &self.block_regex {
            if re.is_match(domain_lower) {
                return blocked(format!("block_regex:{}", re.as_str()));
            }
        }
        match typed_block {
            Some(rule) => MatchOutcome::BlockedType(format!("block:{}", rule.text)),
            None => MatchOutcome::Forwarded,
        }
    }
}

fn valid_domain(name: &str) -> bool {
    if name.contains('\\') {
        // Wire names can contain decimal escapes, including literal dots inside a label.
        return name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'\\'))
            && crate::dns::serialize_name(name).is_ok();
    }
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
}

fn validate_content(body: &str) -> Result<(), &'static str> {
    let first = body.trim_start_matches('\u{feff}').trim_start();
    if first.is_empty() {
        return Err("empty list body");
    }
    if first.starts_with('<') {
        return Err("received markup instead of a filter list");
    }
    Ok(())
}

/// Probe only until the first usable rule in each configured format. The
/// regular full parse still reports malformed lines with source locations.
pub(crate) fn validate_list(body: &str, domains: bool, regex: bool) -> Result<(), String> {
    validate_content(body)?;
    if domains {
        let mut probe = Blocklist::new();
        let mut reason = None;
        let usable = body.lines().enumerate().any(|(i, line)| {
            let target = adguard::disabled_target(line);
            match probe.parse_auto(target.as_deref().unwrap_or(line)) {
                Ok(()) => probe.rule_count() > 0,
                Err(error) => {
                    reason.get_or_insert_with(|| format!("line {}: {error}", i + 1));
                    false
                }
            }
        });
        if !usable {
            return Err(reason.map_or_else(
                || "no usable domain rules".into(),
                |r| format!("no usable domain rules ({r})"),
            ));
        }
    }
    if regex
        && !body
            .lines()
            .filter_map(regex_pattern)
            .any(|pattern| !pattern.is_empty() && Regex::new(pattern).is_ok())
    {
        return Err("no usable regex rules".into());
    }
    Ok(())
}

/// Outcome of checking a domain against the blocklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchOutcome {
    /// Blocked by a block rule.
    Blocked(String),
    /// A type-specific block returns NODATA, since other types may exist.
    BlockedType(String),
    /// Allowed by an allow rule (overrides any block).
    Allowed(String),
    /// Not matched by any rule; forward to upstream.
    Forwarded,
    /// The client is configured to skip filtering entirely.
    Bypassed(String),
}

/// Parse ordinary list bodies, preserving source/line context for bad rules.
#[allow(dead_code)] // Public single-feed API. The daemon compiles all feeds together.
pub fn parse_lines_into(bl: &mut Blocklist, body: &str, source: &str) {
    parse_domain_feed(bl, body, false, source);
}

#[allow(dead_code)]
pub fn parse_lines_into_allow(bl: &mut Blocklist, body: &str, source: &str) {
    parse_domain_feed(bl, body, true, source);
}

fn parse_domain_feed(bl: &mut Blocklist, body: &str, allow: bool, source: &str) {
    let mut disabled = DisabledRules::default();
    disabled.collect(body.lines(), allow);
    parse_domain_lines(bl, body, allow, source, &disabled);
}

const MAX_RULE_WARNINGS: usize = 10;

pub(crate) fn parse_domain_lines(
    bl: &mut Blocklist,
    body: &str,
    as_allow: bool,
    source: &str,
    disabled: &DisabledRules,
) {
    let mut skipped = 0;
    for (line_number, line) in body.lines().enumerate() {
        if disabled.skips(line, as_allow) {
            continue;
        }
        if let Err(error) = bl.parse_auto_mode(line, as_allow) {
            skipped += 1;
            if skipped <= MAX_RULE_WARNINGS {
                log::warn!(
                    "{source}:{}: skipping invalid rule {line:?}: {error}",
                    line_number + 1
                );
            }
        }
    }
    if skipped != 0 {
        log::warn!("{source}: skipped {skipped} invalid rules");
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RegexParseCounts {
    pub compiled: usize,
    pub skipped: usize,
}

fn regex_pattern(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with(['#', '!']) || line.starts_with("--") {
        return None;
    }
    let pattern = line.split(" -- ").next()?.trim();
    if pattern.starts_with('/') && pattern.ends_with('/') {
        Some(pattern.strip_prefix('/')?.strip_suffix('/').unwrap_or(""))
    } else {
        Some(pattern)
    }
}

/// Compile one pattern per line, accepting Pi-hole comment trailers and /.../
/// wrapping. Unsupported regexes are counted and reported, never broadened.
pub fn parse_lines_into_regex(
    bl: &mut Blocklist,
    body: &str,
    as_allow: bool,
    source: &str,
) -> RegexParseCounts {
    let mut counts = RegexParseCounts::default();
    for (line_number, line) in body.lines().enumerate() {
        let Some(pattern) = regex_pattern(line) else {
            continue;
        };
        let compiled = if pattern.is_empty() {
            Err("empty regex delimiter".to_string())
        } else {
            Regex::new(pattern).map_err(|e| e.to_string())
        };
        match compiled {
            Ok(re) => {
                counts.compiled += 1;
                if as_allow {
                    bl.allow_regex.push(re);
                } else {
                    bl.block_regex.push(re);
                }
            }
            Err(error) => {
                counts.skipped += 1;
                if counts.skipped <= MAX_RULE_WARNINGS {
                    log::warn!(
                        "{source}:{}: skipping invalid regex {line:?}: {error}",
                        line_number + 1
                    );
                }
            }
        }
    }
    if counts.skipped != 0 {
        log::warn!(
            "{source}: compiled {} regexes, skipped {} invalid patterns",
            counts.compiled,
            counts.skipped
        );
    } else {
        log::info!("{source}: compiled {} regexes", counts.compiled);
    }
    counts
}

/// Merge source blocklist into target.
#[allow(dead_code)]
pub fn merge_blocklist(target: &mut Blocklist, source: Blocklist) {
    target.allow_domains.extend(source.allow_domains);
    target.block_domains.extend(source.block_domains);
    target.allow_suffixes.extend(source.allow_suffixes);
    target.block_suffixes.extend(source.block_suffixes);
    target.allow_regex.extend(source.allow_regex);
    target.block_regex.extend(source.block_regex);
    for (domain, rules) in source.typed_suffixes {
        target
            .typed_suffixes
            .entry(domain)
            .or_default()
            .extend(rules);
    }
}

// ---------------------------------------------------------------------------
// CachedLists: metadata in memory, bodies on disk
// ---------------------------------------------------------------------------

/// Metadata for one cached list. The body is stored in a separate file on
/// disk (under the bodies_dir derived from cache path), read on demand, and
/// never held in RAM after parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedList {
    pub fetched_at: u64, // Unix timestamp (seconds)
    pub etag: Option<String>,
    /// Body file name, relative to the bodies directory. Derived from the URL.
    pub filename: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CachedLists {
    pub map: HashMap<String, CachedList>,
    /// A valid download whose disk write failed remains available to later refreshes.
    #[serde(skip)]
    unsaved: HashMap<String, Arc<String>>,
    #[serde(skip)]
    dirty: bool,
}

/// Derive a deterministic, human-readable filename from a URL.
///
/// Strips the scheme, replaces every character outside [A-Za-z0-9._-] with
/// '_', truncates the readable prefix to 100 chars, then appends a short
/// FNV-1a hash of the *full* URL to avoid collisions when two URLs share a
/// long common prefix. FNV-1a is used instead of `DefaultHasher` because its
/// algorithm is specified and stable across Rust versions — a toolchain
/// upgrade must not orphan the cache.
///
/// All output characters are ASCII by construction (every non-ASCII char is
/// mapped to `_`), so byte-slicing at 100 is safe.
fn url_to_filename(url: &str) -> String {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let sanitized: String = stripped
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let truncated = if sanitized.len() > 100 {
        &sanitized[..100]
    } else {
        &sanitized
    };
    // FNV-1a hash of the full URL for collision resistance.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in url.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{truncated}_{h:016x}.txt")
}

/// Derive the bodies directory from the cache metadata path.
/// E.g. "/var/lib/dns-ligase/cache.json" -> "/var/lib/dns-ligase/cache.d"
fn bodies_dir(cache_path: &str) -> PathBuf {
    Path::new(cache_path)
        .parent()
        .unwrap_or(Path::new("."))
        .join("cache.d")
}

const LIST_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const LIST_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolves every hostname, including redirect destinations, through unbound.
/// Never fall back to system DNS: it may point back at this process.
struct ListResolver(Arc<Upstream>);

impl reqwest::dns::Resolve for ListResolver {
    fn resolve(&self, name: hyper::client::connect::dns::Name) -> reqwest::dns::Resolving {
        let upstream = Arc::clone(&self.0);
        Box::pin(async move {
            let ips = upstream.resolve_a(name.as_str()).await?;
            if ips.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("No upstream A records for {name}"),
                )
                .into());
            }
            // reqwest substitutes the URL's port for zero.
            let addrs: reqwest::dns::Addrs =
                Box::new(ips.into_iter().map(|ip| SocketAddr::new(IpAddr::V4(ip), 0)));
            Ok(addrs)
        })
    }
}

fn list_client_builder(upstream: Arc<Upstream>) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(ListResolver(upstream)))
        // Proxy-side DNS would bypass the configured resolver.
        .no_proxy()
        .connect_timeout(LIST_CONNECT_TIMEOUT)
        .timeout(LIST_REQUEST_TIMEOUT)
}

/// Read a cached body file from disk. Free function so the download phase can
/// use it without holding the cache lock.
fn read_body_file(cache_path: &str, filename: &str) -> Option<String> {
    fs::read_to_string(bodies_dir(cache_path).join(filename)).ok()
}

/// One URL needing a download, with its stored etag for a conditional GET.
pub struct FetchJob {
    pub url: String,
    pub etag: Option<String>,
}

/// Outcome of downloading one URL. Carries everything phase 3 needs without
/// further I/O.
#[derive(Debug)]
pub enum DownloadResult {
    /// New content: persist the body file and metadata.
    Fresh { body: String, etag: Option<String> },
    /// 304 Not Modified: body file already on disk; refresh `fetched_at` to
    /// restart the freshness window.
    NotModified,
    /// Failure but a stale body file was present: serve it WITHOUT refreshing
    /// `fetched_at`, so a dead list is retried (not silenced for a full TTL).
    StaleFallback { body: String, error: String },
    /// No body available (error message for the warning log).
    Failed(String),
}

fn resp_etag(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get(reqwest::header::ETAG)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

/// Download one list body with a conditional GET. Disk reads only (body-file
/// fallback); never touches cache metadata, so it runs without the cache lock.
/// Semantics match the old sequential fetcher: 304 keeps the existing entry,
/// any failure falls back to the on-disk copy when present.
async fn download_one(
    url: &str,
    etag: Option<&str>,
    client: &reqwest::Client,
    cache_path: &str,
) -> DownloadResult {
    // The deadline includes a possible second GET after a missing-body 304.
    match tokio::time::timeout(
        LIST_REQUEST_TIMEOUT,
        download_response(url, etag, client, cache_path),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => stale_or_failed(url, cache_path, error),
        Err(_) => stale_or_failed(url, cache_path, "List download deadline exceeded".into()),
    }
}

fn stale_or_failed(url: &str, cache_path: &str, error: String) -> DownloadResult {
    match read_body_file(cache_path, &url_to_filename(url)) {
        Some(body) => DownloadResult::StaleFallback { body, error },
        None => DownloadResult::Failed(error),
    }
}

async fn download_response(
    url: &str,
    etag: Option<&str>,
    client: &reqwest::Client,
    cache_path: &str,
) -> Result<DownloadResult, String> {
    let mut request = client.get(url);
    if let Some(etag) = etag {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    let mut resp = request
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        if read_body_file(cache_path, &url_to_filename(url)).is_some() {
            return Ok(DownloadResult::NotModified);
        }
        log::warn!("304 for {url} but body file missing; refetching");
        resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("refetch failed: {e}"))?;
    }
    if resp.status() != reqwest::StatusCode::OK {
        return Err(format!("HTTP {}", resp.status()));
    }
    if resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| {
            v.trim().eq_ignore_ascii_case("text/html")
                || v.trim().eq_ignore_ascii_case("application/xhtml+xml")
        })
    {
        return Err("received an HTML response for a filter list".into());
    }
    let etag = resp_etag(&resp);
    let body = resp.text().await.map_err(|e| format!("read body: {e}"))?;
    validate_content(&body)?;
    Ok(DownloadResult::Fresh { body, etag })
}

static TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

/// Replace a cache file only after its complete contents reach disk.
fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let filename = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing cache filename"))?;
    let (temp_path, mut file) = loop {
        let id = TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            ".{}.{}.{id}.tmp",
            filename.to_string_lossy(),
            std::process::id()
        );
        let temp_path = parent.join(name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => break (temp_path, file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    let result = (|| {
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temp_path, path)?;
        fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp_path);
    }
    result
}

impl CachedLists {
    /// Usable cached bodies, regardless of age, for serving during startup.
    pub fn cached_bodies(&self, urls: &[String], cache_path: &str) -> HashMap<String, String> {
        urls.iter()
            .filter_map(|url| {
                if let Some(body) = self.unsaved.get(url) {
                    return Some((url.clone(), body.as_ref().clone()));
                }
                let filename = self
                    .map
                    .get(url)
                    .map(|entry| entry.filename.clone())
                    .unwrap_or_else(|| url_to_filename(url));
                read_body_file(cache_path, &filename).map(|body| (url.clone(), body))
            })
            .collect()
    }

    /// Prepare a new cache location without changing the active cache. Failed
    /// migration leaves the old location available to serving queries/reloads.
    pub fn migrate_to(&self, old_path: &str, new_path: &str, urls: &[String]) -> io::Result<Self> {
        let mut migrated = Self::default();
        for (url, body) in self.cached_bodies(urls, old_path) {
            let filename = url_to_filename(&url);
            migrated.write_body(new_path, &filename, &body)?;
            let mut entry = self
                .map
                .get(&url)
                .filter(|_| !self.unsaved.contains_key(&url))
                .cloned()
                .unwrap_or(CachedList {
                    fetched_at: 0,
                    etag: None,
                    filename: filename.clone(),
                });
            entry.filename = filename;
            migrated.map.insert(url, entry);
        }
        // Also verifies a writable destination when no body files exist.
        migrated.dirty = true;
        migrated.save_to_disk(new_path)?;
        Ok(migrated)
    }

    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a cached body from disk. Returns None if the file is missing or
    /// unreadable — caller should treat the entry as stale.
    fn read_body(&self, cache_path: &str, filename: &str) -> Option<String> {
        read_body_file(cache_path, filename)
    }

    /// Write a body to disk. Creates the bodies directory if needed.
    fn write_body(&self, cache_path: &str, filename: &str, body: &str) -> io::Result<()> {
        let dir = bodies_dir(cache_path);
        atomic_write(&dir.join(filename), body.as_bytes())
    }

    /// Get cached body if it was fetched within the interval and the body
    /// file exists on disk.
    #[allow(dead_code)]
    pub fn get_if_fresh(&self, url: &str, interval_secs: u64, cache_path: &str) -> Option<String> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.map.get(url).and_then(|c| {
            if now.saturating_sub(c.fetched_at) < interval_secs {
                self.read_body(cache_path, &c.filename)
            } else {
                None
            }
        })
    }

    /// Phase 1 (sync — call under a brief lock): split URLs into fresh cached
    /// bodies vs. jobs needing a download. No network, only small disk reads.
    pub fn plan_fetches(
        &self,
        urls: &[String],
        interval_secs: u64,
        cache_path: &str,
    ) -> (Vec<(String, String)>, Vec<FetchJob>) {
        let mut fresh = Vec::new();
        let mut jobs = Vec::new();
        for url in urls {
            if self.unsaved.contains_key(url) {
                jobs.push(FetchJob {
                    url: url.clone(),
                    etag: None,
                });
            } else if let Some(body) = self.get_if_fresh(url, interval_secs, cache_path) {
                fresh.push((url.clone(), body));
            } else {
                jobs.push(FetchJob {
                    url: url.clone(),
                    etag: self.map.get(url).and_then(|c| c.etag.clone()),
                });
            }
        }
        (fresh, jobs)
    }

    /// Phase 2: download concurrently with one pooled client. Every connection
    /// resolves through unbound, including redirects to other hostnames.
    pub async fn download_jobs(
        jobs: Vec<FetchJob>,
        cache_path: &str,
        upstream: Arc<Upstream>,
    ) -> Vec<(String, DownloadResult)> {
        if jobs.is_empty() {
            return Vec::new();
        }
        let client = match list_client_builder(upstream).build() {
            Ok(client) => client,
            Err(e) => {
                return jobs
                    .into_iter()
                    .map(|job| {
                        let result =
                            stale_or_failed(&job.url, cache_path, format!("HTTP client: {e}"));
                        (job.url, result)
                    })
                    .collect()
            }
        };
        let cache_path = cache_path.to_string();
        let mut set = tokio::task::JoinSet::new();
        for job in jobs {
            let client = client.clone();
            let cp = cache_path.clone();
            set.spawn(async move {
                let FetchJob { url, etag } = job;
                let res = download_one(&url, etag.as_deref(), &client, &cp).await;
                (url, res)
            });
        }
        let mut out = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(pair) => out.push(pair),
                Err(e) => log::error!("List download task failed: {e}"),
            }
        }
        out
    }

    /// Phase 3 (sync — call under a brief lock): persist fresh downloads,
    /// refresh `fetched_at` on 304s, and return every usable (url, body),
    /// from disk or network. Logs failures.
    #[allow(dead_code)] // Library callers can merge without the daemon's per-URL format config.
    pub fn merge_downloads(
        &mut self,
        results: Vec<(String, DownloadResult)>,
        cache_path: &str,
    ) -> Vec<(String, String)> {
        self.merge_validated(results, cache_path, |_, body| validate_content(body))
    }

    pub(crate) fn merge_validated<E: std::fmt::Display>(
        &mut self,
        results: Vec<(String, DownloadResult)>,
        cache_path: &str,
        validate: impl Fn(&str, &str) -> Result<(), E>,
    ) -> Vec<(String, String)> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut bodies = Vec::new();
        for (url, mut res) in results {
            if let DownloadResult::Fresh { body, .. } = &res {
                if let Err(reason) = validate(&url, body) {
                    res = DownloadResult::Failed(reason.to_string());
                }
            }
            if !matches!(res, DownloadResult::Fresh { .. }) {
                if let Some(body) = self.unsaved.get(&url) {
                    log::warn!(
                        "No valid replacement for {url}; retaining last usable in-memory copy"
                    );
                    bodies.push((url, body.as_ref().clone()));
                    continue;
                }
            }
            match res {
                DownloadResult::Fresh { body, etag } => {
                    let filename = url_to_filename(&url);
                    if let Err(e) = self.write_body(cache_path, &filename, &body) {
                        log::error!("Failed to write cached body for {url}: {e}");
                        // Serve the valid download now; keep the metadata/ETag
                        // paired with the old disk body for the next retry.
                        self.unsaved.insert(url.clone(), Arc::new(body.clone()));
                        bodies.push((url, body));
                        continue;
                    }
                    self.unsaved.remove(&url);
                    self.map.insert(
                        url.clone(),
                        CachedList {
                            fetched_at: now,
                            etag,
                            filename,
                        },
                    );
                    self.dirty = true;
                    bodies.push((url, body));
                }
                DownloadResult::NotModified => {
                    // Refresh the freshness window; the body file is authoritative.
                    if let Some(entry) = self.map.get_mut(url.as_str()) {
                        entry.fetched_at = now;
                        self.dirty = true;
                        let filename = entry.filename.clone();
                        if let Some(body) = read_body_file(cache_path, &filename) {
                            bodies.push((url, body));
                        } else {
                            log::warn!(
                                "304 for {url} but body file missing; will refetch next cycle"
                            );
                        }
                    } else {
                        // Entry vanished between plan and merge (e.g. URL removed
                        // by a SIGHUP reload racing this refresh). Serve the file
                        // if it is still there; there is no metadata to refresh.
                        log::debug!("304 for {url} with no cache entry; serving file if present");
                        let filename = url_to_filename(&url);
                        if let Some(body) = read_body_file(cache_path, &filename) {
                            bodies.push((url, body));
                        }
                    }
                }
                DownloadResult::StaleFallback { body, error } => {
                    log::warn!("Fetch failed for {url}; using cached copy: {error}");
                    bodies.push((url, body));
                }
                DownloadResult::Failed(err) => {
                    let filename = self
                        .map
                        .get(&url)
                        .map(|entry| entry.filename.clone())
                        .unwrap_or_else(|| url_to_filename(&url));
                    if let Some(body) = read_body_file(cache_path, &filename) {
                        log::warn!("Fetch failed for {url}; using cached copy: {err}");
                        bodies.push((url, body));
                    } else {
                        log::warn!("Fetch failed for {url}, no cached copy: {err}");
                    }
                }
            }
        }
        bodies
    }

    /// Remove cache entries whose URLs are no longer in the config.
    /// Also deletes the corresponding body files from disk.
    pub fn prune(&mut self, keep_urls: &[String], cache_path: &str) {
        let keep: HashSet<&str> = keep_urls.iter().map(|s| s.as_str()).collect();
        self.unsaved.retain(|url, _| keep.contains(url.as_str()));
        let dir = bodies_dir(cache_path);
        let before = self.map.len();
        self.map.retain(|url, entry| {
            if keep.contains(url.as_str()) {
                true
            } else {
                // Delete the body file
                let _ = fs::remove_file(dir.join(&entry.filename));
                false
            }
        });
        if self.map.len() < before {
            self.dirty = true;
        }
    }

    /// Persist cache metadata to disk only if modified since last save.
    pub fn save_to_disk(&mut self, path: &str) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let data = serde_json::to_string(self)?;
        atomic_write(Path::new(path), data.as_bytes())?;
        self.dirty = false;
        Ok(())
    }

    /// Load cache metadata from disk. Returns Err if the file doesn't exist
    /// or if the format is incompatible (e.g. old cache.json with body fields).
    /// Callers use unwrap_or_default() to start fresh on failure.
    pub fn load_from_disk(path: &str) -> io::Result<Self> {
        let data = fs::read_to_string(path)?;
        let cache: CachedLists = serde_json::from_str(&data)?;
        Ok(cache)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ListFormat {
    Hosts,
    AdBlock,
    PiHole,
    AdGuard,
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hosts_format() {
        let mut bl = Blocklist::new();
        bl.parse_line("example.com", ListFormat::Hosts).unwrap();
        bl.parse_line("  sub.example.org  ", ListFormat::Hosts).unwrap();
        bl.parse_line("! comment", ListFormat::Hosts).unwrap();
        bl.parse_line("# comment", ListFormat::Hosts).unwrap();
        assert!(bl.matches("example.com"));
        assert!(bl.matches("sub.example.org"));
        assert!(!bl.matches("google.com"));
    }

    #[test]
    fn test_adblock_format() {
        let mut bl = Blocklist::new();
        bl.parse_line("||ads.com^", ListFormat::AdBlock).unwrap();
        bl.parse_line("/track\\.me/", ListFormat::AdBlock).unwrap();
        assert!(bl.matches("ads.com"));
        assert!(bl.matches("sub.ads.com"));
        assert!(bl.matches("track.me"));
        assert!(!bl.matches("google.com"));
    }

    #[test]
    fn test_allow_precedence() {
        let mut bl = Blocklist::new();
        bl.parse_line("||ads.com^", ListFormat::AdBlock).unwrap();
        bl.parse_line("@@||sub.ads.com^", ListFormat::AdBlock).unwrap();
        assert!(bl.matches("ads.com"));
        assert!(!bl.matches("sub.ads.com"));
        assert!(bl.matches("other.ads.com"));
    }

    #[test]
    fn test_regex_allow() {
        let mut bl = Blocklist::new();
        bl.parse_line("||ads.com^", ListFormat::AdBlock).unwrap();
        bl.parse_line("/^safe\\.com$/", ListFormat::AdBlock).unwrap();
        bl.parse_line("@@/^safe\\.com$/", ListFormat::AdBlock).unwrap();
        assert!(bl.matches("ads.com"));
        assert!(!bl.matches("safe.com"));
    }

    #[test]
    fn test_ip_prefix_format() {
        let mut bl = Blocklist::new();
        bl.parse_line("0.0.0.0 ads.example.com", ListFormat::Hosts).unwrap();
        assert!(bl.matches("ads.example.com"));
    }

    #[test]
    fn test_direct_match() {
        let mut bl = Blocklist::new();
        bl.parse_line("direct.com", ListFormat::AdBlock).unwrap();
        assert!(bl.matches("direct.com"));
        assert!(!bl.matches("sub.direct.com"));
    }

    #[test]
    fn test_auto_detect() {
        let mut bl = Blocklist::new();
        bl.parse_auto("||ads.com^").unwrap();
        assert!(bl.matches("sub.ads.com"));

        let mut bl2 = Blocklist::new();
        bl2.parse_auto("example.com").unwrap();
        assert!(bl2.matches("example.com"));
    }

    #[test]
    fn test_all_formats() {
        let formats = [
            ListFormat::Hosts,
            ListFormat::AdBlock,
            ListFormat::PiHole,
            ListFormat::AdGuard,
        ];
        for format in formats {
            let mut bl = Blocklist::new();
            bl.parse_line("example.com", format).unwrap();
            assert!(bl.matches("example.com"), "Failed for {:?}", format);
        }
    }

    #[test]
    fn test_adguard_format() {
        let mut bl = Blocklist::new();
        bl.parse_line("||ads.example.com^", ListFormat::AdGuard).unwrap();
        bl.parse_line("/track\\.me/", ListFormat::AdGuard).unwrap();
        assert!(bl.matches("ads.example.com"));
        assert!(bl.matches("sub.ads.example.com"));
        assert!(bl.matches("track.me"));
        assert!(!bl.matches("google.com"));
    }

    #[test]
    fn test_suffix_match_blocks_subdomains() {
        let mut bl = Blocklist::new();
        bl.parse_line("||ads.com^", ListFormat::AdBlock).unwrap();
        assert!(bl.matches("ads.com"));
        assert!(bl.matches("sub.ads.com"));
        assert!(bl.matches("a.b.ads.com"));
        assert!(!bl.matches("google.com"));
    }

    #[test]
    fn test_suffix_match_no_anchor() {
        let mut bl = Blocklist::new();
        bl.parse_line("||ads.com^", ListFormat::AdBlock).unwrap();
        // ads.com.evil.net should NOT be blocked (no implicit $ anchor)
        assert!(!bl.matches("ads.com.evil.net"));
        assert!(!bl.matches("notads.com"));
    }

    #[test]
    fn test_allow_suffix_beats_block_suffix() {
        let mut bl = Blocklist::new();
        bl.parse_line("||ads.com^", ListFormat::AdBlock).unwrap();
        bl.parse_line("@@||safe.ads.com^", ListFormat::AdBlock).unwrap();
        assert!(bl.matches("ads.com"));
        assert!(bl.matches("evil.ads.com"));
        assert!(!bl.matches("safe.ads.com"));
    }

    #[test]
    fn test_parse_lines_into_allow_hosts_format() {
        let mut bl = Blocklist::new();
        // Block everything under ads.com
        bl.parse_line("||ads.com^", ListFormat::AdBlock).unwrap();

        // Allowlist body in hosts format: bare domains become allow rules
        let body = "# allowlist\nexample.com\n0.0.0.0 safe.ads.com\n";
        parse_lines_into_allow(&mut bl, body, "test-list");

        assert!(!bl.matches("example.com"), "allowlist entry should override");
        assert!(!bl.matches("safe.ads.com"), "allowlist should override block suffix");
        assert!(bl.matches("evil.ads.com"), "block suffix still applies elsewhere");
    }

    #[test]
    fn test_parse_lines_into_allow_adblock_format() {
        let mut bl = Blocklist::new();
        bl.parse_line("||ads.com^", ListFormat::AdBlock).unwrap();

        // Allowlist body in AdBlock format: ||domain^ and /regex/ become allow rules
        let body = "||safe.ads.com^\n/^allow\\.me$/\n@@||redundant.ads.com^\n";
        parse_lines_into_allow(&mut bl, body, "test-list");

        assert!(!bl.matches("safe.ads.com"), "|| suffix in allowlist should allow");
        assert!(!bl.matches("sub.safe.ads.com"), "subdomain of allow suffix");
        assert!(!bl.matches("allow.me"), "regex in allowlist should allow");
        assert!(!bl.matches("redundant.ads.com"), "@@ in allowlist is still allow");
        assert!(bl.matches("evil.ads.com"), "block still applies");
    }

    #[test]
    fn test_localhost_names_never_blocked() {
        let mut bl = Blocklist::new();
        // As found in StevenBlack/hosts headers.
        bl.parse_auto("127.0.0.1 localhost").unwrap();
        bl.parse_auto("127.0.0.1 localhost.localdomain").unwrap();
        bl.parse_auto("255.255.255.255 broadcasthost").unwrap();
        bl.parse_auto("::1 localhost").unwrap();
        bl.parse_auto("local").unwrap();
        assert!(!bl.matches("localhost"));
        assert!(!bl.matches("localhost.localdomain"));
        assert!(!bl.matches("broadcasthost"));
        assert!(!bl.matches("local"));
        // ...while real entries from the same file still block.
        bl.parse_auto("0.0.0.0 ads.example.com").unwrap();
        assert!(bl.matches("ads.example.com"));
    }

    #[test]
    fn adguard_modifiers_never_broaden_a_rule() {
        let mut bl = Blocklist::new();
        for line in [
            "||ads.test^$third-party",
            "||ads.test^$important",
            "@@||ads.test^$client=pc",
            "||ads.test^$dnstype=A,client=pc",
            "||ads.test^$dnstype=AAAA|typo",
        ] {
            assert!(bl.parse_auto(line).is_err(), "{line}");
        }
        assert_eq!(bl.check_query("ads.test", 28), MatchOutcome::Forwarded);
        bl.parse_auto("||ads.test^$dnstype=~A|~cname").unwrap();
        bl.parse_auto("@@||sub.ads.test^$dnstype=aaaa|HTTPS")
            .unwrap();
        assert_eq!(bl.check_query("sub.ads.test", 1), MatchOutcome::Forwarded);
        assert!(matches!(
            bl.check_query("ads.test", 28),
            MatchOutcome::BlockedType(_)
        ));
        assert!(matches!(
            bl.check_query("sub.ads.test", 28),
            MatchOutcome::Allowed(_)
        ));
        assert!(matches!(
            bl.check_query("sub.ads.test", 65),
            MatchOutcome::Allowed(_)
        ));
        assert!(matches!(
            bl.check_query("sub.ads.test", 16),
            MatchOutcome::BlockedType(_)
        ));
    }

    #[test]
    fn badfilter_disables_only_its_matching_rule_in_any_order() {
        let body = "||one.test^$badfilter\n||one.test^\n||two.test^$dnstype=A\n||two.test^$badfilter,dnstype=A\n||two.test^$dnstype=AAAA\n@@||other.test^\n@@||other.test^$badfilter\n||other.test^\n/^regex[.]test$/\n/^regex[.]test$/$badfilter";
        let mut rules = Blocklist::new();
        parse_lines_into(&mut rules, body, "list");
        for name in ["one.test", "two.test", "regex.test"] {
            assert_eq!(rules.check_query(name, 1), MatchOutcome::Forwarded);
        }
        assert!(matches!(
            rules.check_query("two.test", 28),
            MatchOutcome::BlockedType(_)
        ));
        assert!(rules.matches("other.test"));
    }

    #[test]
    fn unconditional_block_with_typed_exception_returns_nodata_for_other_types() {
        let mut rules = Blocklist::new();
        rules.parse_auto("||example.test^").unwrap();
        rules.parse_auto("@@||example.test^$dnstype=A").unwrap();
        assert!(matches!(
            rules.check_query("example.test", 1),
            MatchOutcome::Allowed(_)
        ));
        assert!(matches!(
            rules.check_query("example.test", 28),
            MatchOutcome::BlockedType(_)
        ));
    }

    #[test]
    fn test_cosmetic_rules_ignored() {
        let mut bl = Blocklist::new();
        bl.parse_auto("example.com##.ad-banner").unwrap();
        bl.parse_auto("##.global-ad").unwrap();
        bl.parse_auto("example.com#$#abort-on-property-read.js").unwrap();
        assert!(
            !bl.matches("example.com"),
            "cosmetic rules must not block the page domain"
        );
    }

    #[test]
    fn test_check_uppercase_query_matches() {
        // Exercises both branches of the lowercase fast-path in check().
        let mut bl = Blocklist::new();
        bl.parse_auto("||ads.com^").unwrap();
        assert!(bl.matches("ADS.COM"));
        assert!(bl.matches("Sub.Ads.Com"));
        assert!(!bl.matches("GOOGLE.COM"));
    }

    #[test]
    fn test_suffix_hit_logs_matched_rule() {
        let mut bl = Blocklist::new();
        bl.parse_auto("||ads.com^").unwrap();
        bl.parse_auto("@@||safe.ads.com^").unwrap();
        // Logs name the rule that fired, not the queried name.
        assert_eq!(
            bl.check("sub.ads.com"),
            MatchOutcome::Blocked("block_suffix:ads.com".to_string())
        );
        assert_eq!(
            bl.check("ads.com"),
            MatchOutcome::Blocked("block_suffix:ads.com".to_string())
        );
        assert_eq!(
            bl.check("deep.safe.ads.com"),
            MatchOutcome::Allowed("allow_suffix:safe.ads.com".to_string())
        );
    }

    #[test]
    fn test_parse_lines_into_regex_block() {
        let mut bl = Blocklist::new();
        // Pi-hole regex list shape: bare pattern + ` -- comment` trailer.
        let body = "## placeholder comment\n\
                    (\\.|^)ad-score\\.com$ -- Overwolf Desktop App\n\
                    ^(.+[_.-])?adse?rv(er?|ice)?s?[0-9]*[_.-] -- mmotti RegEx\n\
                    \n\
                    # hash comment\n\
                    ! bang comment\n\
                    [invalid(regex -- skipped, must not poison the rest\n";
        parse_lines_into_regex(&mut bl, body, false, "test-list");
        assert_eq!(bl.block_regex.len(), 2);
        assert!(bl.matches("ad-score.com"));
        assert!(bl.matches("eu.ad-score.com"));
        assert!(bl.matches("adserver-1.example.com"));
        assert!(!bl.matches("google.com"));
    }

    #[test]
    fn test_parse_lines_into_regex_unwraps_slashes() {
        let mut bl = Blocklist::new();
        parse_lines_into_regex(&mut bl, "/^allow\\.me$/\n", true, "test-list");
        assert_eq!(bl.allow_regex.len(), 1);
        // Allow-via-URL beats an exact block, like any other allow rule.
        bl.parse_auto("allow.me").unwrap();
        assert!(!bl.matches("allow.me"));
    }

    #[test]
    fn test_parse_lines_into_regex_allow_only() {
        let mut bl = Blocklist::new();
        bl.parse_auto("||ads.com^").unwrap();
        parse_lines_into_regex(&mut bl, "(\\.|^)safe\\.ads\\.com$ -- exception\n", true, "test-list");
        assert!(!bl.matches("safe.ads.com"));
        assert!(bl.matches("evil.ads.com"));
    }

    #[test]
    fn test_plan_and_merge_round_trip() {
        let dir = std::env::temp_dir().join("dns-ligase-test-plan-merge");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cache_path = dir.join("cache.json");
        let path_str = cache_path.to_str().unwrap();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut cache = CachedLists::default();
        // Fresh entry with body on disk.
        let fresh_url = "https://example.com/fresh.txt";
        let fresh_fn = url_to_filename(fresh_url);
        cache.write_body(path_str, &fresh_fn, "fresh-body\n").unwrap();
        cache.map.insert(fresh_url.to_string(), CachedList {
            fetched_at: now,
            etag: Some("\"f\"".to_string()),
            filename: fresh_fn,
        });
        // Stale entry with body on disk and an etag for conditional GET.
        let stale_url = "https://example.com/stale.txt";
        let stale_fn = url_to_filename(stale_url);
        cache.write_body(path_str, &stale_fn, "stale-body\n").unwrap();
        let stale_at = now.saturating_sub(7200);
        cache.map.insert(stale_url.to_string(), CachedList {
            fetched_at: stale_at,
            etag: Some("\"s\"".to_string()),
            filename: stale_fn,
        });
        // Second stale entry, for the error-fallback path.
        let deadish_url = "https://example.com/deadish.txt";
        let deadish_fn = url_to_filename(deadish_url);
        cache.write_body(path_str, &deadish_fn, "deadish-body\n").unwrap();
        let deadish_at = now.saturating_sub(7200);
        cache.map.insert(deadish_url.to_string(), CachedList {
            fetched_at: deadish_at,
            etag: None,
            filename: deadish_fn,
        });

        let new_url = "https://new.example/x.txt";
        let (fresh, jobs) = cache.plan_fetches(
            &[fresh_url.to_string(), stale_url.to_string(), new_url.to_string()],
            3600,
            path_str,
        );
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].0, fresh_url);
        assert_eq!(fresh[0].1, "fresh-body\n");
        assert_eq!(jobs.len(), 2);
        let stale_job = jobs.iter().find(|j| j.url == stale_url).unwrap();
        assert_eq!(stale_job.etag.as_deref(), Some("\"s\""));
        let new_job = jobs.iter().find(|j| j.url == new_url).unwrap();
        assert_eq!(new_job.etag, None);

        // Merge: one fresh download, one 304, one error fallback, one failure.
        let merged = cache.merge_downloads(
            vec![
                (new_url.to_string(), DownloadResult::Fresh {
                    body: "new-body\n".to_string(),
                    etag: None,
                }),
                (stale_url.to_string(), DownloadResult::NotModified),
                (deadish_url.to_string(), DownloadResult::StaleFallback { body: "deadish-body\n".to_string(), error: "offline".to_string() }),
                ("https://dead.example/y.txt".to_string(), DownloadResult::Failed("boom".to_string())),
            ],
            path_str,
        );
        assert_eq!(merged.len(), 3);
        // Fresh download persisted to disk and metadata.
        let entry = cache.map.get(new_url).unwrap();
        assert_eq!(
            cache.read_body(path_str, &entry.filename).as_deref(),
            Some("new-body\n")
        );
        // 304 refreshes the freshness window; the body still comes from disk.
        let stale_entry = cache.map.get(stale_url).unwrap();
        assert!(stale_entry.fetched_at > stale_at);
        assert_eq!(stale_entry.etag.as_deref(), Some("\"s\""));
        assert!(merged.iter().any(|(u, b)| u == stale_url && b == "stale-body\n"));
        // Error fallback serves the stale copy WITHOUT refreshing the
        // timestamp, so a dead list keeps retrying instead of going quiet.
        assert_eq!(cache.map.get(deadish_url).unwrap().fetched_at, deadish_at);
        assert!(merged.iter().any(|(u, b)| u == deadish_url && b == "deadish-body\n"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Cache body-on-disk tests ---

    #[test]
    fn test_url_to_filename_stable_and_safe() {
        // Stable for the same URL
        let f1 = url_to_filename("https://v.firebog.net/hosts/Prigent-Crypto.txt");
        let f2 = url_to_filename("https://v.firebog.net/hosts/Prigent-Crypto.txt");
        assert_eq!(f1, f2);
        // Readable prefix + FNV-1a hash suffix
        assert!(
            f1.starts_with("v.firebog.net_hosts_Prigent-Crypto.txt_"),
            "filename should start with readable prefix: {f1}"
        );
        assert!(f1.ends_with(".txt"), "filename should end with .txt: {f1}");

        // Different URLs with same prefix produce different filenames
        let a = url_to_filename("https://example.com/list-A.txt");
        let b = url_to_filename("https://example.com/list-B.txt");
        assert_ne!(a, b, "different URLs must not collide");

        // Path traversal blocked — no / or \ in the filename
        let evil = url_to_filename("https://evil.com/../../../etc/passwd");
        assert!(!evil.contains('/'));
        assert!(!evil.contains('\\'));
    }

    #[test]
    fn test_url_to_filename_collision_resistance() {
        // Two URLs that share a long common prefix (identical past 100 chars
        // when sanitized) must produce different filenames thanks to the hash.
        let prefix = format!("https://example.com/{}", "x".repeat(120));
        let url_a = format!("{prefix}/a");
        let url_b = format!("{prefix}/b");
        let fa = url_to_filename(&url_a);
        let fb = url_to_filename(&url_b);
        assert_ne!(fa, fb, "URLs differing only past 100 chars must not collide");
        // Both should share the readable prefix
        assert_eq!(&fa[..100], &fb[..100]);
    }

    #[test]
    fn test_url_to_filename_truncation() {
        let long_url = format!("https://example.com/{}", "a".repeat(200));
        let fname = url_to_filename(&long_url);
        // 100 chars readable prefix + 1 underscore + 16 hex hash + ".txt" = 121
        assert!(fname.len() <= 121, "filename too long: {} ({})", fname, fname.len());
        assert!(fname.ends_with(".txt"));
    }

    #[test]
    fn test_cache_round_trip() {
        let dir = std::env::temp_dir().join("dns-ligase-test-round-trip");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cache_path = dir.join("cache.json");
        let path_str = cache_path.to_str().unwrap();

        let mut cache = CachedLists::default();
        // Simulate a fetch: write body file + metadata
        let url = "https://example.com/list.txt";
        let filename = url_to_filename(url);
        cache.write_body(path_str, &filename, "example.com\nads.com\n").unwrap();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        cache.map.insert(url.to_string(), CachedList {
            fetched_at: now,
            etag: Some("\"abc\"".to_string()),
            filename: filename.clone(),
        });
        cache.dirty = true;
        cache.save_to_disk(path_str).unwrap();

        // Load metadata from disk
        let loaded = CachedLists::load_from_disk(path_str).unwrap();
        assert_eq!(loaded.map.len(), 1);
        let entry = loaded.map.get(url).unwrap();
        assert_eq!(entry.filename, filename);
        assert_eq!(entry.etag.as_deref(), Some("\"abc\""));

        // Body is retrievable from disk
        let body = loaded.read_body(path_str, &entry.filename).unwrap();
        assert_eq!(body, "example.com\nads.com\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cache_missing_body_file_falls_back() {
        let dir = std::env::temp_dir().join("dns-ligase-test-missing-body");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cache_path = dir.join("cache.json");
        let path_str = cache_path.to_str().unwrap();

        let mut cache = CachedLists::default();
        let url = "https://example.com/list.txt";
        let filename = url_to_filename(url);

        // Fresh metadata but no body file on disk
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        cache.map.insert(url.to_string(), CachedList {
            fetched_at: now,
            etag: None,
            filename,
        });

        // get_if_fresh should return None because body file is missing
        let result = cache.get_if_fresh(url, 3600, path_str);
        assert!(result.is_none(), "missing body file must not return a body");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_prune_deletes_body_file() {
        let dir = std::env::temp_dir().join("dns-ligase-test-prune");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cache_path = dir.join("cache.json");
        let path_str = cache_path.to_str().unwrap();

        let mut cache = CachedLists::default();
        let url = "https://example.com/removed.txt";
        let keep_url = "https://example.com/kept.txt";
        let fn_removed = url_to_filename(url);
        let fn_kept = url_to_filename(keep_url);

        // Write both body files
        cache.write_body(path_str, &fn_removed, "removed\n").unwrap();
        cache.write_body(path_str, &fn_kept, "kept\n").unwrap();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        cache.map.insert(url.to_string(), CachedList {
            fetched_at: now,
            etag: None,
            filename: fn_removed.clone(),
        });
        cache.map.insert(keep_url.to_string(), CachedList {
            fetched_at: now,
            etag: None,
            filename: fn_kept.clone(),
        });

        // Prune: keep only keep_url
        cache.prune(&[keep_url.to_string()], path_str);

        assert_eq!(cache.map.len(), 1);
        assert!(cache.map.contains_key(keep_url));

        // The removed body file must be gone
        let bodies = bodies_dir(path_str);
        assert!(!bodies.join(&fn_removed).exists(), "pruned body file must be deleted");
        assert!(bodies.join(&fn_kept).exists(), "kept body file must survive");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
#[cfg(test)]
#[path = "fetch_tests.rs"]
mod fetch_tests;
