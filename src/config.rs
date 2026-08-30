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
