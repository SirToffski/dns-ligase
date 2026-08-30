mod config;
mod dns;
mod blocklist;
mod upstream;

use crate::blocklist::{
    parse_lines_into, Blocklist, CachedLists,
};
use crate::config::Config;
use crate::upstream::UdpForwarder;
use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tokio::signal::unix::{signal, SignalKind};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    log::info!("Starting DNS filter forwarder...");

    // Load configuration
    let config = Arc::new(RwLock::new(load_config().await?));

    // Load or initialize cache
    let cache_path = config.read().await.cache.path.clone();
    let cache = Arc::new(Mutex::new(
        CachedLists::load_from_disk(&cache_path).unwrap_or_default(),
    ));

    // Initialize Blocklist
    let cfg_init = config.read().await.clone();
    let blocklist = Arc::new(RwLock::new(create_blocklist(&cfg_init, &cache, &cache_path).await));

    // Spawn refresh timer task
    spawn_refresh_task(Arc::clone(&config), Arc::clone(&blocklist), Arc::clone(&cache), cache_path.clone());

    // Spawn SIGHUP reload task
    spawn_sighup_handler(Arc::clone(&config), Arc::clone(&blocklist), Arc::clone(&cache), cache_path.clone());

    // Spawn disk-persist task (save cache on graceful shutdown)
    let cache_shutdown = Arc::clone(&cache);
    let cache_path_shutdown = cache_path.clone();
    tokio::spawn(async move {
        if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
            sigterm.recv().await;
            log::info!("SIGTERM received, saving cache and shutting down...");
            let mut c = cache_shutdown.lock().await;
            if let Err(e) = c.save_to_disk(&cache_path_shutdown) {
                log::error!("Failed to save cache: {}", e);
            }
        }
    });

    let listen_addr = {
        let cfg = config.read().await;
        format!("{}:{}", cfg.server.listen_addr, cfg.server.listen_port)
    };
    let upstream_addr: std::net::SocketAddr = {
        let cfg = config.read().await;
        format!("{}:{}", cfg.upstream.address, cfg.upstream.port)
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad upstream: {e}")))?
    };

    log::info!("Listening on {} and forwarding to {}", listen_addr, upstream_addr);

    let forwarder = UdpForwarder::new(&listen_addr, Arc::clone(&config), Arc::clone(&blocklist)).await?;
    forwarder.run().await?;

    Ok(())
}

async fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let config_str = std::fs::read_to_string("config.toml")?;
    let config: Config = toml::from_str(&config_str)?;
    Ok(config)
}

/// Create a Blocklist from config: manual rules + all blocklist URLs (cached or fresh).
async fn create_blocklist(config: &Config, cache: &Mutex<CachedLists>, cache_path: &str) -> Blocklist {
    let mut bl = Blocklist::new();

    // 1. Apply manual rules
    for domain in &config.matching.manual_block {
        let _ = bl.parse_line(domain, crate::blocklist::ListFormat::AdBlock);
    }
    for domain in &config.matching.manual_allow {
        bl.allow_domains.insert(domain.to_lowercase().trim_end_matches('.').to_string());
    }
    for pattern in &config.matching.regex_block {
        if let Ok(re) = regex::Regex::new(pattern) {
            bl.block_regex.push(re);
        }
    }
    for pattern in &config.matching.regex_allow {
        if let Ok(re) = regex::Regex::new(pattern) {
            bl.allow_regex.push(re);
        }
    }

    // 2. Fetch each blocklist URL (cached or fresh), merge into final
    let cache_ttl = config.blocklists.cache_ttl_secs.unwrap_or(config.blocklists.refresh_interval_secs);
    let urls = config.blocklists.urls.clone();
    for url in &urls {
        log::info!("Fetching blocklist: {}", url);
        let mut c = cache.lock().await;
        match c.fetch_or_cached(url, cache_ttl).await {
            Ok(body) => {
                log::info!("Blocklist fetched: {}", url);
                parse_lines_into(&mut bl, &body);
            }
            Err(e) => {
                log::warn!("Fetch failed for {}, using cached: {}", url, e);
            }
        }
    }

    // 3. Prune stale entries and persist cache to disk
    let urls = config.blocklists.urls.clone();
    {
        let mut c = cache.lock().await;
        c.prune(&urls);
        let save_result = c.save_to_disk(cache_path);
        if let Err(e) = save_result {
            log::error!("Failed to save cache: {}", e);
        }
    }

    bl
}

fn spawn_refresh_task(
    config: Arc<RwLock<Config>>,
    blocklist: Arc<RwLock<Blocklist>>,
    cache: Arc<Mutex<CachedLists>>,
    cache_path: String,
) {
    tokio::spawn(async move {
        loop {
            let interval = {
                let cfg = config.read().await;
                cfg.blocklists.refresh_interval_secs
            };

            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            log::info!("Refreshing blocklists...");

            let cfg = {
                let cfg = config.read().await;
                cfg.clone()
            };

            let new_blocklist = create_blocklist(&cfg, &cache, &cache_path).await;

            {
                let mut lock = blocklist.write().await;
                *lock = new_blocklist;
                log::info!("Blocklist refreshed successfully.");
            }
        }
    });
}

fn spawn_sighup_handler(
    config: Arc<RwLock<Config>>,
    blocklist: Arc<RwLock<Blocklist>>,
    cache: Arc<Mutex<CachedLists>>,
    cache_path: String,
) {
    tokio::spawn(async move {
        match signal(SignalKind::hangup()) {
            Ok(mut sigup) => {
                log::info!("SIGHUP signal handler registered.");
                loop {
                    sigup.recv().await;
                    log::info!("SIGHUP received, reloading configuration...");

                    let new_config = match load_config().await {
                        Ok(c) => c,
                        Err(e) => {
                            log::error!("Failed to reload configuration: {}", e);
                            continue;
                        }
                    };

                    // Log every config change by comparing old vs new
                    {
                        let old_config = config.read().await;

                        // Upstream
                        if old_config.upstream.address != new_config.upstream.address
                            || old_config.upstream.port != new_config.upstream.port
                        {
                            log::info!(
                                "Upstream: {}:{} -> {}:{} (use_tcp: {} -> {})",
                                old_config.upstream.address, old_config.upstream.port,
                                new_config.upstream.address, new_config.upstream.port,
                                old_config.upstream.use_tcp, new_config.upstream.use_tcp
                            );
                        }

                        // Listen address
                        if old_config.server.listen_addr != new_config.server.listen_addr
                            || old_config.server.listen_port != new_config.server.listen_port
                        {
                            log::warn!(
                                "Listen address changed: {}:{} -> {}:{} (requires restart to take effect)",
                                old_config.server.listen_addr, old_config.server.listen_port,
                                new_config.server.listen_addr, new_config.server.listen_port
                            );
                        }

                        // Blocklist URLs
                        let old_urls: HashSet<_> = old_config.blocklists.urls.iter().collect();
                        let new_urls: HashSet<_> = new_config.blocklists.urls.iter().collect();
                        for url in &new_urls - &old_urls {
                            log::info!("Blocklist added: {}", url);
                        }
                        for url in &old_urls - &new_urls {
                            log::info!("Blocklist removed: {}", url);
                        }

                        // Refresh interval
                        if old_config.blocklists.refresh_interval_secs != new_config.blocklists.refresh_interval_secs {
                            log::info!(
                                "Blocklist refresh interval: {}s -> {}s",
                                old_config.blocklists.refresh_interval_secs,
                                new_config.blocklists.refresh_interval_secs
                            );
                        }

                        // Cache path
                        if old_config.cache.path != new_config.cache.path {
                            log::info!("Cache path: {} -> {}", old_config.cache.path, new_config.cache.path);
                        }

                        // Manual block domains
                        let old_block: HashSet<_> = old_config.matching.manual_block.iter().collect();
                        let new_block: HashSet<_> = new_config.matching.manual_block.iter().collect();
                        for domain in &new_block - &old_block {
                            log::info!("Manual block added: {}", domain);
                        }
                        for domain in &old_block - &new_block {
                            log::info!("Manual block removed: {}", domain);
                        }

                        // Manual allow domains
                        let old_allow: HashSet<_> = old_config.matching.manual_allow.iter().collect();
                        let new_allow: HashSet<_> = new_config.matching.manual_allow.iter().collect();
                        for domain in &new_allow - &old_allow {
                            log::info!("Manual allow added: {}", domain);
                        }
                        for domain in &old_allow - &new_allow {
                            log::info!("Manual allow removed: {}", domain);
                        }

                        // Regex block patterns
                        let old_regex_block: HashSet<_> = old_config.matching.regex_block.iter().collect();
                        let new_regex_block: HashSet<_> = new_config.matching.regex_block.iter().collect();
                        for pattern in &new_regex_block - &old_regex_block {
                            log::info!("Regex block added: {}", pattern);
                        }
                        for pattern in &old_regex_block - &new_regex_block {
                            log::info!("Regex block removed: {}", pattern);
                        }

                        // Regex allow patterns
                        let old_regex_allow: HashSet<_> = old_config.matching.regex_allow.iter().collect();
                        let new_regex_allow: HashSet<_> = new_config.matching.regex_allow.iter().collect();
                        for pattern in &new_regex_allow - &old_regex_allow {
                            log::info!("Regex allow added: {}", pattern);
                        }
                        for pattern in &old_regex_allow - &new_regex_allow {
                            log::info!("Regex allow removed: {}", pattern);
                        }
                    }

                    // Update config atomically
                    *config.write().await = new_config;

                    // Rebuild blocklist with new matching rules + remote fetches
                    // Clone config inside read block so guard drops before any work
                    let cfg_reload = {
                        let cfg = config.read().await;
                        cfg.clone()
                    };
                    let new_blocklist = create_blocklist(&cfg_reload, &cache, &cache_path).await;
                    *blocklist.write().await = new_blocklist;
                    log::info!("Configuration reloaded successfully.");
                }
            }
            Err(e) => {
                log::error!("Failed to register SIGHUP handler: {}", e);
            }
        }
    });
}
