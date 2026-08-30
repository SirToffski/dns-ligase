use serde::Deserialize;
use std::net::Ipv4Addr;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub blocklists: BlocklistConfig,
    pub matching: MatchingConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub listen_port: u16,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamConfig {
    pub address: Ipv4Addr,
    pub port: u16,
    #[allow(dead_code)]
    pub use_tcp: bool,
}

#[derive(Debug, Deserialize)]
pub struct BlocklistConfig {
    pub urls: Vec<String>,
    pub refresh_interval_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct MatchingConfig {
    pub manual_block: Vec<String>,
    pub manual_allow: Vec<String>,
    pub regex_block: Vec<String>,
    pub regex_allow: Vec<String>,
}
