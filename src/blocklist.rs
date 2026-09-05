use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::upstream::Upstream;

#[derive(Debug, Default)]
pub struct Blocklist {
    pub allow_domains: HashSet<String>,
    pub block_domains: HashSet<String>,
    pub allow_suffixes: HashSet<String>,
    pub block_suffixes: HashSet<String>,
    pub allow_regex: Vec<Regex>,
    pub block_regex: Vec<Regex>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.allow_domains.clear();
        self.block_domains.clear();
        self.allow_suffixes.clear();
        self.block_suffixes.clear();
        self.allow_regex.clear();
        self.block_regex.clear();
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
                if let Some(domain) = Self::clean_domain_static(line) {
                    let domain = domain.to_lowercase();
                    if as_allow {
                        self.allow_domains.insert(domain);
                    } else {
                        self.block_domains.insert(domain);
                    }
                }
            }
            ListFormat::AdBlock | ListFormat::AdGuard => {
                let has_at = line.starts_with("@@");
                let is_allow = as_allow || has_at;
                let pattern_part = if has_at {
                    line.trim_start_matches("@@")
                } else {
                    line
                };

                if pattern_part.starts_with("||") {
                    let domain = pattern_part
                        .trim_start_matches("||")
                        .trim_end_matches('^')
                        .trim_end_matches('.')
                        .to_lowercase();
                    if domain.is_empty() {
                        return Ok(());
                    }
                    if is_allow {
                        self.allow_suffixes.insert(domain);
                    } else {
                        self.block_suffixes.insert(domain);
                    }
                } else if pattern_part.starts_with('/') && pattern_part.ends_with('/') {
                    let pattern = &pattern_part[1..pattern_part.len() - 1];
                    let re = Regex::new(pattern)?;
                    if is_allow {
                        self.allow_regex.push(re);
                    } else {
                        self.block_regex.push(re);
                    }
                } else {
                    if let Some(domain) = Self::clean_domain_static(pattern_part) {
                        let domain_lower = domain.to_lowercase();
                        if is_allow {
                            self.allow_domains.insert(domain_lower);
                        } else {
                            self.block_domains.insert(domain_lower);
                        }
                    }
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

        if line.starts_with("||") || line.starts_with("@@") || (line.starts_with('/') && line.ends_with('/')) {
            self.parse_line_mode(line, ListFormat::AdBlock, as_allow)
        } else {
            self.parse_line_mode(line, ListFormat::Hosts, as_allow)
        }
    }

    #[allow(dead_code)]
    pub async fn fetch_and_parse(&mut self, url: &str, format: Option<ListFormat>) -> Result<(), Box<dyn Error>> {
        let content = reqwest::get(url).await?.text().await?;
        for line in content.lines() {
            match format {
                Some(f) => self.parse_line(line, f)?,
                None => self.parse_auto(line)?,
            }
        }
        Ok(())
    }

    fn suffix_match(set: &HashSet<String>, domain: &str) -> bool {
        if set.contains(domain) {
            return true;
        }
        let mut rest = domain;
        while let Some(pos) = rest.find('.') {
            rest = &rest[pos + 1..];
            if set.contains(rest) {
                return true;
            }
        }
        false
    }

    fn clean_domain_static(domain: &str) -> Option<String> {
        let domain = domain.split('#').next()?.trim();
        if domain.is_empty() {
            return None;
        }

        let parts: Vec<&str> = domain.split_whitespace().collect();
        let target = if parts.len() > 1 {
            parts.last().unwrap()
        } else {
            parts[0]
        };

        let cleaned = target.trim_end_matches('.');
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned.to_string())
        }
    }

    #[allow(dead_code)]
    pub fn matches(&self, domain: &str) -> bool {
        matches!(self.check(domain), MatchOutcome::Blocked(_))
    }

    /// Check a domain and return the outcome with the matched rule, if any.
    /// Only allocates the rule description string when a rule actually matches.
    pub fn check(&self, domain: &str) -> MatchOutcome {
        let domain_lower = domain.to_lowercase();
        // Allow takes precedence over block
        if self.allow_domains.contains(&domain_lower) {
            return MatchOutcome::Allowed(format!("allow:{}", domain_lower));
        }
        for re in &self.allow_regex {
            if re.is_match(&domain_lower) {
                return MatchOutcome::Allowed(format!("allow_regex:{}", re.as_str()));
            }
        }
        if Self::suffix_match(&self.allow_suffixes, &domain_lower) {
            return MatchOutcome::Allowed(format!("allow_suffix:{}", domain_lower));
        }
        if self.block_domains.contains(&domain_lower) {
            return MatchOutcome::Blocked(format!("block:{}", domain_lower));
        }
        if Self::suffix_match(&self.block_suffixes, &domain_lower) {
            return MatchOutcome::Blocked(format!("block_suffix:{}", domain_lower));
        }
        for re in &self.block_regex {
            if re.is_match(&domain_lower) {
                return MatchOutcome::Blocked(format!("block_regex:{}", re.as_str()));
            }
        }
        MatchOutcome::Forwarded
    }
}

/// Outcome of checking a domain against the blocklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchOutcome {
    /// Blocked by a block rule.
    Blocked(String),
    /// Allowed by an allow rule (overrides any block).
    Allowed(String),
    /// Not matched by any rule; forward to upstream.
    Forwarded,
}

/// Parse lines from a blocklist body into an existing Blocklist.
/// This is used by the cache reload path to merge a single URL's content.
pub fn parse_lines_into(bl: &mut Blocklist, body: &str) {
    for line in body.lines() {
        let _ = bl.parse_auto(line);
    }
}

/// Parse lines from an allowlist body, routing every entry to the allow sets.
pub fn parse_lines_into_allow(bl: &mut Blocklist, body: &str) {
    for line in body.lines() {
        let _ = bl.parse_auto_mode(line, true);
    }
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
}

// ---------------------------------------------------------------------------
// CachedLists: metadata in memory, bodies on disk
// ---------------------------------------------------------------------------

/// Metadata for one cached list. The body is stored in a separate file on
/// disk (under the bodies_dir derived from cache path), read on demand, and
/// never held in RAM after parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedList {
    pub fetched_at: u64,  // Unix timestamp (seconds)
    pub etag: Option<String>,
    /// Body file name, relative to the bodies directory. Derived from the URL.
    pub filename: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CachedLists {
    pub map: HashMap<String, CachedList>,
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

/// Build an HTTP client for fetching `url_str`, pinning the URL's hostname to
/// addresses resolved through our own upstream.
///
/// TLS still uses the hostname for SNI and certificate validation — only the
/// address lookup is overridden. On any resolution failure (parse error, IP
/// literal, upstream unreachable, no A records) returns a plain client so the
/// system resolver gets a chance as a backstop.
async fn client_for_url(url_str: &str, upstream: &Upstream) -> reqwest::Client {
    let parsed = match url::Url::parse(url_str) {
        Ok(u) => u,
        Err(e) => {
            log::warn!("Could not parse list URL {url_str} ({e}); using system resolver");
            return reqwest::Client::new();
        }
    };
    let host = match parsed.host_str() {
        Some(h) => h.to_string(),
        None => {
            log::warn!("List URL {url_str} has no hostname; using system resolver");
            return reqwest::Client::new();
        }
    };
    // IP literals need no resolution.
    if host.parse::<IpAddr>().is_ok() {
        return reqwest::Client::new();
    }
    let ips = match upstream.resolve_a(&host).await {
        Ok(ips) if !ips.is_empty() => ips,
        Ok(_) => {
            log::warn!("Upstream returned no A records for {host}; using system resolver");
            return reqwest::Client::new();
        }
        Err(e) => {
            log::warn!("Upstream resolution failed for {host} ({e}); using system resolver");
            return reqwest::Client::new();
        }
    };
    // The port in the override addr is ignored by reqwest (it uses the URL's
    // own port / scheme default); pass the URL's effective port anyway.
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = ips
        .into_iter()
        .map(|ip| SocketAddr::new(IpAddr::V4(ip), port))
        .collect();
    reqwest::Client::builder()
        .resolve_to_addrs(&host, &addrs)
        .build()
        .unwrap_or_else(|e| {
            log::warn!("Failed to build resolving client for {host} ({e}); using system resolver");
            reqwest::Client::new()
        })
}

impl CachedLists {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a cached body from disk. Returns None if the file is missing or
    /// unreadable — caller should treat the entry as stale.
    fn read_body(&self, cache_path: &str, filename: &str) -> Option<String> {
        let path = bodies_dir(cache_path).join(filename);
        fs::read_to_string(&path).ok()
    }

    /// Write a body to disk. Creates the bodies directory if needed.
    fn write_body(&self, cache_path: &str, filename: &str, body: &str) -> io::Result<()> {
        let dir = bodies_dir(cache_path);
        fs::create_dir_all(&dir)?;
        let path = dir.join(filename);
        fs::write(path, body)?;
        Ok(())
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

    /// Fetch a URL. If cached and fresh, read the body from disk and return it.
    /// Otherwise fetch fresh; on failure, read the body from disk if available.
    ///
    /// The list hostname is resolved through our own `upstream` first so the
    /// service doesn't depend on the system resolver (which may itself point
    /// at dns-ligase). If our resolution fails or yields nothing, falls back
    /// to a plain client and lets the system resolver try — never fail the
    /// fetch just because our own resolution failed.
    pub async fn fetch_or_cached(
        &mut self,
        url: &str,
        interval_secs: u64,
        cache_path: &str,
        upstream: &Upstream,
    ) -> Result<String, Box<dyn Error>> {
        // Check cache freshness — body must exist on disk
        if let Some(body) = self.get_if_fresh(url, interval_secs, cache_path) {
            return Ok(body);
        }

        // Try to fetch fresh.
        //
        // NOTE: one client per URL is intentional, not a missed optimization.
        // The resolve() override is per-client and per-host, so sharing a
        // single client across lists would silently drop the per-host pinning.
        let client = client_for_url(url, upstream).await;
        let mut request = client.get(url);

        // Conditional GET: send If-None-Match if we have an etag
        if let Some(ref etag) = self.map.get(url).and_then(|c| c.etag.clone()) {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }

        let resp = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                // Network failure — fall back to cached body file if available
                if let Some(cached) = self.map.get(url) {
                    if let Some(body) = self.read_body(cache_path, &cached.filename) {
                        log::warn!("Fetch failed for {url} ({e}); using cached copy");
                        return Ok(body);
                    }
                }
                return Err(e.into());
            }
        };

        match resp.status() {
            reqwest::StatusCode::NOT_MODIFIED => {
                // Not modified — keep existing cache entry, read body from disk
                if let Some(cached) = self.map.get(url) {
                    if let Some(body) = self.read_body(cache_path, &cached.filename) {
                        return Ok(body);
                    }
                }
                // Body file missing despite a 304 — fall through to a full GET
                log::warn!("304 for {url} but body file missing; refetching");
                let resp2 = client.get(url).send().await?;
                let new_etag = resp2
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string());
                let body = resp2.text().await?;
                let filename = url_to_filename(url);
                self.write_body(cache_path, &filename, &body)?;
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                self.map.insert(url.to_string(), CachedList {
                    fetched_at: now,
                    etag: new_etag,
                    filename,
                });
                self.dirty = true;
                Ok(body)
            }
            reqwest::StatusCode::OK => {
                let new_etag = resp
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string());
                let body = resp.text().await?;

                let filename = url_to_filename(url);
                self.write_body(cache_path, &filename, &body)?;

                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                self.map.insert(url.to_string(), CachedList {
                    fetched_at: now,
                    etag: new_etag,
                    filename,
                });
                self.dirty = true;
                Ok(body)
            }
            _ => {
                // HTTP error (4xx/5xx) — fall back to cached body file if available
                if let Some(cached) = self.map.get(url) {
                    if let Some(body) = self.read_body(cache_path, &cached.filename) {
                        log::warn!("Fetch returned {} for {}; using cached copy", resp.status(), url);
                        return Ok(body);
                    }
                }
                Err(io::Error::other(format!("HTTP {}", resp.status())).into())
            }
        }
    }

    /// Remove cache entries whose URLs are no longer in the config.
    /// Also deletes the corresponding body files from disk.
    pub fn prune(&mut self, keep_urls: &[String], cache_path: &str) {
        let keep: HashSet<&str> = keep_urls.iter().map(|s| s.as_str()).collect();
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
        self.dirty = false;
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string(self)?;
        fs::write(path, data)?;
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
        parse_lines_into_allow(&mut bl, body);

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
        parse_lines_into_allow(&mut bl, body);

        assert!(!bl.matches("safe.ads.com"), "|| suffix in allowlist should allow");
        assert!(!bl.matches("sub.safe.ads.com"), "subdomain of allow suffix");
        assert!(!bl.matches("allow.me"), "regex in allowlist should allow");
        assert!(!bl.matches("redundant.ads.com"), "@@ in allowlist is still allow");
        assert!(bl.matches("evil.ads.com"), "block still applies");
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
