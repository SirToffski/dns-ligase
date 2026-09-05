mod config;
mod dns;
mod blocklist;
mod upstream;
mod journald;
mod stats;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use crate::blocklist::{
    parse_lines_into, parse_lines_into_allow, Blocklist, CachedLists,
};
use crate::config::Config;
use crate::upstream::{Upstream, UdpForwarder, UpstreamHandle};
use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tokio::signal::unix::{signal, SignalKind};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Subcommand: `dns-ligase stats [flags]` — read and filter query logs.
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "stats" {
        return run_stats_cmd(&args[2..]);
    }

    env_logger::init();
    log::info!("Starting DNS filter forwarder...");

    // Load configuration
    let config = Arc::new(RwLock::new(load_config().await?));

    // Load or initialize cache
    let cache_path = config.read().await.cache.path.clone();
    let cache = Arc::new(Mutex::new(
        CachedLists::load_from_disk(&cache_path).unwrap_or_else(|e| {
            log::warn!("Cache format changed or unreadable; starting fresh: {e}");
            CachedLists::default()
        }),
    ));

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
    // The upstream pool must exist before the first fetch so list hostnames
    // can be resolved through it instead of the system resolver.
    let upstream_handle: UpstreamHandle =
        Arc::new(RwLock::new(Arc::new(Upstream::new(upstream_addr))));

    // Initialize Blocklist
    let cfg_init = config.read().await.clone();
    let upstream_init = upstream_handle.read().await.clone();
    let blocklist = Arc::new(RwLock::new(create_blocklist(&cfg_init, &cache, &cache_path, &upstream_init).await));

    // Spawn refresh timer task
    spawn_refresh_task(Arc::clone(&config), Arc::clone(&blocklist), Arc::clone(&cache), cache_path.clone(), Arc::clone(&upstream_handle));

    let log_queries = {
        let cfg = config.read().await;
        cfg.logging.queries
    };
    log::info!("Listening on {} and forwarding to {}", listen_addr, upstream_addr);
    if log_queries {
        log::info!("Query logging to journald enabled");
    }

    // Shared flag so SIGHUP can toggle logging without restart.
    let log_queries_handle: Arc<RwLock<bool>> = Arc::new(RwLock::new(log_queries));

    // Spawn SIGHUP reload task (shares the upstream handle so it can swap pools
    // when the upstream address changes).
    spawn_sighup_handler(
        Arc::clone(&config),
        Arc::clone(&blocklist),
        Arc::clone(&cache),
        cache_path.clone(),
        Arc::clone(&upstream_handle),
        Arc::clone(&log_queries_handle),
    );

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
            log::info!("Cache saved, exiting.");
            std::process::exit(0);
        }
    });

    let forwarder = UdpForwarder::new(&listen_addr, Arc::clone(&upstream_handle), Arc::clone(&blocklist), Arc::clone(&log_queries_handle)).await?;
    forwarder.run().await?;

    Ok(())
}

/// Parse `stats` subcommand flags and run the stats query.
fn run_stats_cmd(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut filter = stats::StatsFilter::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--blocked" => filter.blocked = true,
            "--allowed" => filter.allowed = true,
            "--forwarded" => filter.forwarded = true,
            "--summary" => filter.summary = true,
            "--domain" | "-d" => {
                i += 1;
                filter.domain = args.get(i).cloned();
            }
            "--src" | "-s" => {
                i += 1;
                filter.src = args.get(i).cloned();
            }
            "--since" => {
                i += 1;
                filter.since = args.get(i).cloned();
            }
            "--help" | "-h" => {
                println!("Usage: dns-ligase stats [OPTIONS]");
                println!();
                println!("Options:");
                println!("  --blocked       Show only blocked queries");
                println!("  --allowed       Show only allowed queries");
                println!("  --forwarded     Show only forwarded queries");
                println!("  --domain <str>  Filter by domain substring");
                println!("  --src <ip>      Filter by source IP substring");
                println!("  --since <time>  journalctl time spec (e.g. \"1 hour ago\")");
                println!("  --summary       Print aggregate summary instead of list");
                println!();
                println!("Pipe to fzf or grep for ad-hoc search:");
                println!("  dns-ligase stats | fzf");
                println!("  dns-ligase stats --blocked | grep doubleclick");
                return Ok(());
            }
            other => {
                return Err(format!("unknown stats flag: {other}").into());
            }
        }
        i += 1;
    }
    stats::run_stats(filter)
}

async fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let path = std::env::args()
        .skip_while(|a| a != "--config")
        .nth(1)
        .or_else(|| std::env::var("DNS_LIGASE_CONFIG").ok())
        .unwrap_or_else(|| "config.toml".to_string());
    let config_str = std::fs::read_to_string(&path)?;
    let config: Config = toml::from_str(&config_str)?;
    Ok(config)
}

/// Create a Blocklist from config: manual rules + all blocklist URLs (cached or fresh).
/// List hostnames are resolved through `upstream` (not the system resolver).
async fn create_blocklist(config: &Config, cache: &Mutex<CachedLists>, cache_path: &str, upstream: &Upstream) -> Blocklist {
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

    // 2. Fetch all list URLs concurrently (block + allow), then merge.
    // Lock discipline: the cache lock is held only for the sync plan and
    // merge phases, never across network I/O.
    let cache_ttl = config.blocklists.cache_ttl_secs.unwrap_or(config.blocklists.refresh_interval_secs);
    let urls = config.blocklists.urls.clone();
    let allow_urls = config.blocklists.allowlist_urls.clone();
    let mut all_urls = urls.clone();
    all_urls.extend(allow_urls.iter().cloned());
    for url in &all_urls {
        log::info!("Fetching list: {}", url);
    }
    let (fresh, jobs) = {
        cache.lock().await.plan_fetches(&all_urls, cache_ttl, cache_path)
    };
    let downloaded = CachedLists::download_jobs(jobs, cache_path, upstream).await;
    let merged = {
        cache.lock().await.merge_downloads(downloaded, cache_path)
    };
    let mut bodies: std::collections::HashMap<String, String> =
        fresh.into_iter().collect();
    bodies.extend(merged);

    for url in &urls {
        match bodies.get(url) {
            Some(body) => {
                log::info!("Blocklist fetched: {}", url);
                parse_lines_into(&mut bl, body);
            }
            None => log::warn!("Blocklist {url} has no usable copy; skipping"),
        }
    }
    for url in &allow_urls {
        match bodies.get(url) {
            Some(body) => {
                log::info!("Allowlist fetched: {}", url);
                parse_lines_into_allow(&mut bl, body);
            }
            None => log::warn!("Allowlist {url} has no usable copy; skipping"),
        }
    }

    log::info!(
        "Blocklist: {} block exact, {} block suffix, {} block regex, {} allow exact, {} allow suffix, {} allow regex",
        bl.block_domains.len(), bl.block_suffixes.len(), bl.block_regex.len(),
        bl.allow_domains.len(), bl.allow_suffixes.len(), bl.allow_regex.len()
    );

    // 3. Prune stale entries and persist cache to disk
    let mut keep_urls = config.blocklists.urls.clone();
    keep_urls.extend(config.blocklists.allowlist_urls.iter().cloned());
    {
        let mut c = cache.lock().await;
        c.prune(&keep_urls, cache_path);
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
    upstream: UpstreamHandle,
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

            // Clone the current pool without holding the lock across I/O.
            let up = upstream.read().await.clone();
            let new_blocklist = create_blocklist(&cfg, &cache, &cache_path, &up).await;

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
    upstream: UpstreamHandle,
    log_queries: Arc<RwLock<bool>>,
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

                        // Allowlist URLs
                        let old_allow: HashSet<_> = old_config.blocklists.allowlist_urls.iter().collect();
                        let new_allow: HashSet<_> = new_config.blocklists.allowlist_urls.iter().collect();
                        for url in &new_allow - &old_allow {
                            log::info!("Allowlist added: {}", url);
                        }
                        for url in &old_allow - &new_allow {
                            log::info!("Allowlist removed: {}", url);
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

                        // Query logging
                        if old_config.logging.queries != new_config.logging.queries {
                            log::info!(
                                "Query logging: {} -> {}",
                                old_config.logging.queries, new_config.logging.queries
                            );
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

                    // Validate the new upstream address BEFORE swapping anything
                    // in: a bad value rejects the whole reload, leaving the old
                    // config, pool, and blocklist untouched.
                    let new_upstream_addr: std::net::SocketAddr = match format!(
                        "{}:{}",
                        new_config.upstream.address,
                        new_config.upstream.port
                    )
                    .parse()
                    {
                        Ok(a) => a,
                        Err(e) => {
                            log::error!("Reloaded config has bad upstream, ignoring reload: {e}");
                            continue;
                        }
                    };

                    // Update config atomically
                    *config.write().await = new_config;

                    // Apply the logging toggle without restart
                    {
                        let cfg = config.read().await;
                        *log_queries.write().await = cfg.logging.queries;
                    }

                    // If the upstream address/port changed, swap in a fresh
                    // connection pool. In-flight queries holding the old Arc
                    // finish against the old address; new queries use the new.
                    {
                        let current = upstream.read().await.clone();
                        if current.addr() != new_upstream_addr {
                            log::info!(
                                "Upstream pool: {} -> {}",
                                current.addr(),
                                new_upstream_addr
                            );
                            *upstream.write().await = Arc::new(Upstream::new(new_upstream_addr));
                        }
                    }

                    // Rebuild blocklist with new matching rules + remote fetches
                    // Clone config inside read block so guard drops before any work
                    let cfg_reload = {
                        let cfg = config.read().await;
                        cfg.clone()
                    };
                    // Resolve list hostnames through the (possibly just-swapped)
                    // upstream pool.
                    let up = upstream.read().await.clone();
                    let new_blocklist = create_blocklist(&cfg_reload, &cache, &cache_path, &up).await;
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
