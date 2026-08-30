mod config;
mod dns;
mod blocklist;
mod upstream;

use crate::blocklist::Blocklist;
use crate::upstream::UdpForwarder;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    log::info!("Starting DNS filter forwarder...");

    // Load configuration
    let config_str = std::fs::read_to_string("config.toml")?;
    let config: crate::config::Config = toml::from_str(&config_str)?;

    // Initialize Blocklist with RwLock for concurrency
    let mut blocklist = Blocklist::new();

    // Add manual rules
    for domain in &config.matching.manual_block {
        blocklist.parse_line(domain, crate::blocklist::ListFormat::AdBlock)?;
    }
    for domain in &config.matching.manual_allow {
        blocklist.allow_domains.insert(domain.to_lowercase().trim_end_matches('.').to_string());
    }
    for pattern in &config.matching.regex_block {
        let re = regex::Regex::new(pattern)?;
        blocklist.block_regex.push(re);
    }
    for pattern in &config.matching.regex_allow {
        let re = regex::Regex::new(pattern)?;
        blocklist.allow_regex.push(re);
    }

    // Initial load of remote blocklists
    for url in &config.blocklists.urls {
        log::info!("Initial fetch: {}", url);
        blocklist.fetch_and_parse(url, None).await?;
    }

    let blocklist = Arc::new(RwLock::new(blocklist));

    // Spawn refresh timer task
    let blocklist_clone = Arc::clone(&blocklist);
    let urls = config.blocklists.urls.clone();
    let manual_block = config.matching.manual_block.clone();
    let manual_allow = config.matching.manual_allow.clone();
    let regex_block = config.matching.regex_block.clone();
    let regex_allow = config.matching.regex_allow.clone();
    let interval = config.blocklists.refresh_interval_secs;

    tokio::spawn(async move {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(interval));
        loop {
            timer.tick().await;
            log::info!("Refreshing blocklists...");
            
            // 1. Build a fresh Blocklist
            let mut new_blocklist = Blocklist::new();

            // 2. Re-apply manual rules
            for domain in &manual_block {
                let _ = new_blocklist.parse_line(domain, crate::blocklist::ListFormat::AdBlock);
            }
            for domain in &manual_allow {
                new_blocklist.allow_domains.insert(domain.to_lowercase().trim_end_matches('.').to_string());
            }
            for pattern in &regex_block {
                if let Ok(re) = regex::Regex::new(pattern) {
                    new_blocklist.block_regex.push(re);
                }
            }
            for pattern in &regex_allow {
                if let Ok(re) = regex::Regex::new(pattern) {
                    new_blocklist.allow_regex.push(re);
                }
            }

            // 3. Fetch remote blocklists
            for url in &urls {
                if let Err(e) = new_blocklist.fetch_and_parse(url, None).await {
                    log::error!("Failed to fetch blocklist {}: {}", url, e);
                }
            }

            // 4. Swap the blocklist under write lock
            {
                let mut lock = blocklist_clone.write().await;
                *lock = new_blocklist;
                log::info!("Blocklist refreshed successfully.");
            }
        }
    });

    let listen_addr = format!("{}:{}", config.server.listen_addr, config.server.listen_port);
    let upstream_addr = format!("{}:{}", config.upstream.address, config.upstream.port).parse()?;

    log::info!("Listening on {} and forwarding to {}", listen_addr, upstream_addr);

    let forwarder = UdpForwarder::new(&listen_addr, upstream_addr, blocklist).await?;
    forwarder.run().await?;

    Ok(())
}
