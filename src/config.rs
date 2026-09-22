use serde::Deserialize;
use std::net::Ipv4Addr;

fn default_cache_path() -> String {
    std::env::var("HOME")
        .ok()
        .map(|h| format!("{}/.cache/dns-ligase/cache.json", h))
        .unwrap_or_else(|| "cache.json".to_string())
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub blocklists: BlocklistConfig,
    pub matching: MatchingConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub listen_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_cache_path")]
    pub path: String,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self { path: default_cache_path() }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LoggingConfig {
    /// Enable per-query logging to journald with structured fields.
    /// When false, no query logs are emitted (operational logs still go to
    /// stderr via env_logger). Defaults to false.
    #[serde(default)]
    pub queries: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    pub address: Ipv4Addr,
    pub port: u16,
    #[allow(dead_code)]
    pub use_tcp: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlocklistConfig {
    pub urls: Vec<String>,
    /// URLs fetched and parsed as allow rules. Shares the same refresh
    /// interval, cache, and cache_ttl as blocklists.
    #[serde(default)]
    pub allowlist_urls: Vec<String>,
    /// URLs fetched and parsed as regex rules (one pattern per line, with
    /// optional ` -- comment` trailers as in Pi-hole regex lists). Shares the
    /// same refresh interval, cache, and cache_ttl as blocklists.
    #[serde(default)]
    pub regex_block_urls: Vec<String>,
    /// Same as regex_block_urls, but every pattern becomes an allow rule.
    #[serde(default)]
    pub regex_allow_urls: Vec<String>,
    pub refresh_interval_secs: u64,
    /// How long to use a cached blocklist body before refetching.
    /// Defaults to refresh_interval_secs if not set.
    #[serde(default)]
    pub cache_ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatchingConfig {
    pub manual_block: Vec<String>,
    pub manual_allow: Vec<String>,
    pub regex_block: Vec<String>,
    pub regex_allow: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_toml() -> &'static str {
        r#"
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
address = "127.0.0.1"
port = 5335
use_tcp = false

[blocklists]
urls = ["https://example.com/list.txt"]
refresh_interval_secs = 3600

[matching]
manual_block = []
manual_allow = []
regex_block = []
regex_allow = []
"#
    }

    #[test]
    fn test_regex_urls_default_to_empty() {
        // Configs written before regex_*_urls existed must still parse.
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        assert!(cfg.blocklists.regex_block_urls.is_empty());
        assert!(cfg.blocklists.regex_allow_urls.is_empty());
        assert!(cfg.blocklists.allowlist_urls.is_empty());
    }

    #[test]
    fn test_regex_urls_parse() {
        let toml = minimal_toml().replace(
            "refresh_interval_secs = 3600",
            "refresh_interval_secs = 3600\n\
             regex_block_urls = [\"https://example.com/regex-block.txt\"]\n\
             regex_allow_urls = [\"https://example.com/regex-allow.txt\"]",
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        assert_eq!(
            cfg.blocklists.regex_block_urls,
            vec!["https://example.com/regex-block.txt".to_string()]
        );
        assert_eq!(
            cfg.blocklists.regex_allow_urls,
            vec!["https://example.com/regex-allow.txt".to_string()]
        );
    }
}
