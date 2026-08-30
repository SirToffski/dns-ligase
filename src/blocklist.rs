use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;
use std::time::SystemTime;

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default)]
pub struct Blocklist {
    pub allow_domains: HashSet<String>,
    pub block_domains: HashSet<String>,
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
        self.allow_regex.clear();
        self.block_regex.clear();
    }

    pub fn parse_line(&mut self, line: &str, format: ListFormat) -> Result<(), Box<dyn Error>> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            return Ok(());
        }

        match format {
            ListFormat::Hosts | ListFormat::PiHole => {
                if let Some(domain) = Self::clean_domain_static(line) {
                    self.block_domains.insert(domain.to_lowercase());
                }
            }
            ListFormat::AdBlock | ListFormat::AdGuard => {
                let is_allow = line.starts_with("@@");
                let pattern_part = if is_allow {
                    line.trim_start_matches("@@")
                } else {
                    line
                };

                if pattern_part.starts_with("||") {
                    let pattern = pattern_part.trim_start_matches("||").trim_end_matches('^');
                    let escaped = regex::escape(pattern);
                    let re_str = format!(r"^(?:.*\.)?{}", escaped);
                    let re = Regex::new(&re_str)?;
                    if is_allow {
                        self.allow_regex.push(re);
                    } else {
                        self.block_regex.push(re);
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
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            return Ok(());
        }

        if line.starts_with("||") || line.starts_with("@@") || (line.starts_with('/') && line.ends_with('/')) {
            self.parse_line(line, ListFormat::AdBlock)
        } else {
            self.parse_line(line, ListFormat::Hosts)
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

    pub fn matches(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        if self.allow_domains.contains(&domain_lower) {
            return false;
        }
        for re in &self.allow_regex {
            if re.is_match(&domain_lower) {
                return false;
            }
        }
        if self.block_domains.contains(&domain_lower) {
            return true;
        }
        for re in &self.block_regex {
            if re.is_match(&domain_lower) {
                return true;
            }
        }
        false
    }
}

/// Parse lines from a blocklist body into an existing Blocklist.
/// This is used by the cache reload path to merge a single URL's content.
pub fn parse_lines_into(bl: &mut Blocklist, body: &str) {
    for line in body.lines() {
        let _ = bl.parse_auto(line);
    }
}

/// Merge source blocklist into target.
#[allow(dead_code)]
pub fn merge_blocklist(target: &mut Blocklist, source: Blocklist) {
    target.allow_domains.extend(source.allow_domains);
    target.block_domains.extend(source.block_domains);
    target.allow_regex.extend(source.allow_regex);
    target.block_regex.extend(source.block_regex);
}

// ---------------------------------------------------------------------------
// CachedLists: raw-body cache with freshness and disk persistence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedList {
    pub body: String,
    pub fetched_at: u64,  // Unix timestamp (seconds)
    pub etag: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CachedLists {
    pub map: HashMap<String, CachedList>,
    #[serde(skip)]
    dirty: bool,
}

impl CachedLists {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get cached body if it was fetched within the interval.
    #[allow(dead_code)]
    pub fn get_if_fresh(&self, url: &str, interval_secs: u64) -> Option<String> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.map.get(url).and_then(|c| {
            // saturating_sub prevents panic on clock skew (NTP steps, copied cache)
            if now.saturating_sub(c.fetched_at) < interval_secs {
                Some(c.body.clone())
            } else {
                None
            }
        })
    }

    /// Fetch a URL. If cached and fresh, return cached body.
    /// Otherwise fetch fresh; on failure, return cached body if available.
    pub async fn fetch_or_cached(
        &mut self,
        url: &str,
        interval_secs: u64,
    ) -> Result<String, Box<dyn Error>> {
        // Check cache freshness
        if let Some(body) = self.get_if_fresh(url, interval_secs) {
            return Ok(body);
        }

        // Try to fetch fresh
        let client = reqwest::Client::new();
        let mut request = client.get(url);

        // Conditional GET: send If-None-Match if we have an etag
        if let Some(ref etag) = self.map.get(url).and_then(|c| c.etag.clone()) {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }

        let resp = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                // Network failure — fall back to cached body if available
                if let Some(cached) = self.map.get(url) {
                    log::warn!("Fetch failed for {url} ({e}); using cached copy");
                    return Ok(cached.body.clone());
                }
                return Err(e.into());
            }
        };

        match resp.status() {
            reqwest::StatusCode::NOT_MODIFIED => {
                // Not modified — keep existing cache entry, return cached body
                if let Some(cached) = self.map.get(url) {
                    return Ok(cached.body.clone());
                }
                return Err(io::Error::new(io::ErrorKind::Other, "304 but no cached body").into());
            }
            reqwest::StatusCode::OK => {
                let new_etag = resp
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string());
                let body = resp.text().await?;

                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                self.map.insert(url.to_string(), CachedList {
                    body: body.clone(),
                    fetched_at: now,
                    etag: new_etag,
                });
                self.dirty = true;
                Ok(body)
            }
            _ => {
                // HTTP error (4xx/5xx) — fall back to cached body if available
                if let Some(cached) = self.map.get(url) {
                    log::warn!("Fetch returned {} for {}; using cached copy", resp.status(), url);
                    return Ok(cached.body.clone());
                }
                Err(io::Error::new(io::ErrorKind::Other, format!("HTTP {}", resp.status())).into())
            }
        }
    }

    /// Remove cache entries whose URLs are no longer in the config.
    pub fn prune(&mut self, keep_urls: &[String]) {
        let keep: std::collections::HashSet<&str> = keep_urls.iter().map(|s| s.as_str()).collect();
        let before = self.map.len();
        self.map.retain(|url, _| keep.contains(url.as_str()));
        if self.map.len() < before {
            self.dirty = true;
        }
    }

    /// Persist cache to disk only if it has been modified since last save.
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

    /// Load cache from disk. Returns default if file doesn't exist or is invalid.
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
}
