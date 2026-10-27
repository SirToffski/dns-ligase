//! Startup cache loading and the single owner of refresh/reload state.
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::signal::unix::Signal;
use tokio::sync::RwLock;

use crate::blocklist::{
    parse_lines_into, parse_lines_into_allow, parse_lines_into_regex, Blocklist, CachedLists,
    DownloadResult, FetchJob, ListFormat,
};
use crate::config::Config;
use crate::upstream::{QueryState, QueryStateHandle, Upstream};

pub struct ReloadManager {
    config: Config,
    cache: CachedLists,
    pub state: QueryStateHandle,
}

struct PreparedUpdate {
    config: Config,
    cache: CachedLists,
    manual: Blocklist,
    fresh: HashMap<String, String>,
    jobs: Vec<FetchJob>,
    upstream: Arc<Upstream>,
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(io::Error::other)?
}

pub async fn read_config(path: String) -> io::Result<Config> {
    blocking(move || {
        let text = std::fs::read_to_string(path)?;
        toml::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    })
    .await
}

fn all_urls(config: &Config) -> Vec<String> {
    let lists = &config.blocklists;
    let mut seen = HashSet::new();
    lists
        .urls
        .iter()
        .chain(&lists.allowlist_urls)
        .chain(&lists.regex_block_urls)
        .chain(&lists.regex_allow_urls)
        .filter(|url| seen.insert((*url).clone()))
        .cloned()
        .collect()
}

fn manual_rules(config: &Config) -> io::Result<Blocklist> {
    if config.blocklists.refresh_interval_secs == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refresh_interval_secs must be greater than zero",
        ));
    }
    if std::time::Instant::now()
        .checked_add(Duration::from_secs(config.blocklists.refresh_interval_secs))
        .is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refresh_interval_secs exceeds the timer range",
        ));
    }
    if config.upstream.port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "upstream port must be greater than zero",
        ));
    }
    let invalid = |field: &str, pattern: &str, error: String| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {field} entry {pattern:?}: {error}"),
        )
    };
    let mut bl = Blocklist::new();
    for entry in &config.matching.manual_block {
        // Reject this malformed delimiter before the list parser's slice.
        if entry.trim().trim_start_matches("@@") == "/" {
            return Err(invalid(
                "manual_block",
                entry,
                "empty regex delimiter".into(),
            ));
        }
        bl.parse_line(entry, ListFormat::AdBlock)
            .map_err(|e| invalid("manual_block", entry, e.to_string()))?;
    }
    for entry in &config.matching.manual_allow {
        bl.allow_domains
            .insert(entry.to_lowercase().trim_end_matches('.').to_string());
    }
    for pattern in &config.matching.regex_block {
        bl.block_regex.push(
            regex::Regex::new(pattern)
                .map_err(|e| invalid("regex_block", pattern, e.to_string()))?,
        );
    }
    for pattern in &config.matching.regex_allow {
        bl.allow_regex.push(
            regex::Regex::new(pattern)
                .map_err(|e| invalid("regex_allow", pattern, e.to_string()))?,
        );
    }
    Ok(bl)
}

fn assemble(config: &Config, mut bl: Blocklist, bodies: &HashMap<String, String>) -> Blocklist {
    for url in &config.blocklists.urls {
        if let Some(body) = bodies.get(url) {
            parse_lines_into(&mut bl, body);
        } else {
            log::warn!("Blocklist {url} has no usable copy; skipping");
        }
    }
    for url in &config.blocklists.allowlist_urls {
        if let Some(body) = bodies.get(url) {
            parse_lines_into_allow(&mut bl, body);
        } else {
            log::warn!("Allowlist {url} has no usable copy; skipping");
        }
    }
    for (urls, allow) in [
        (&config.blocklists.regex_block_urls, false),
        (&config.blocklists.regex_allow_urls, true),
    ] {
        for url in urls {
            if let Some(body) = bodies.get(url) {
                parse_lines_into_regex(&mut bl, body, allow);
            } else {
                log::warn!("Regex list {url} has no usable copy; skipping");
            }
        }
    }
    log::info!(
        "Blocklist: {} block exact, {} block suffix, {} block regex, {} allow exact, {} allow suffix, {} allow regex",
        bl.block_domains.len(), bl.block_suffixes.len(), bl.block_regex.len(),
        bl.allow_domains.len(), bl.allow_suffixes.len(), bl.allow_regex.len()
    );
    bl
}

impl ReloadManager {
    pub async fn new(config: Config) -> io::Result<Self> {
        let (cache, bl, config) = blocking(move || {
            let manual = manual_rules(&config)?;
            let cache = match CachedLists::load_from_disk(&config.cache.path) {
                Ok(cache) => cache,
                Err(e) => {
                    if e.kind() != io::ErrorKind::NotFound {
                        log::warn!("Cache metadata unreadable; trying existing bodies: {e}");
                    }
                    CachedLists::default()
                }
            };
            let bodies = cache.cached_bodies(&all_urls(&config), &config.cache.path);
            let bl = assemble(&config, manual, &bodies);
            Ok((cache, bl, config))
        })
        .await?;
        let upstream = Arc::new(Upstream::new(
            (config.upstream.address, config.upstream.port).into(),
        ));
        let state = Arc::new(RwLock::new(Arc::new(QueryState {
            upstream,
            blocklist: Arc::new(bl),
            log_queries: config.logging.queries,
        })));
        Ok(Self {
            config,
            cache,
            state,
        })
    }

    async fn prepare(&self, mut config: Config) -> io::Result<PreparedUpdate> {
        // Listener changes remain restart-only and are not recorded as active.
        if config.server.listen_addr != self.config.server.listen_addr
            || config.server.listen_port != self.config.server.listen_port
        {
            log::warn!("Listen address changed; requires restart to take effect");
            config.server = self.config.server.clone();
        }
        let cache = self.cache.clone();
        let old_path = self.config.cache.path.clone();
        let upstream = self.state.read().await.upstream.clone();
        blocking(move || {
            let manual = manual_rules(&config)?;
            let cache = if old_path != config.cache.path {
                cache.migrate_to(&old_path, &config.cache.path, &all_urls(&config))?
            } else {
                cache
            };
            let ttl = config
                .blocklists
                .cache_ttl_secs
                .unwrap_or(config.blocklists.refresh_interval_secs);
            let (fresh, jobs) = cache.plan_fetches(&all_urls(&config), ttl, &config.cache.path);
            let address = (config.upstream.address, config.upstream.port).into();
            let upstream = if upstream.addr() == address {
                upstream
            } else {
                Arc::new(Upstream::new(address))
            };
            Ok(PreparedUpdate {
                config,
                cache,
                manual,
                fresh: fresh.into_iter().collect(),
                jobs,
                upstream,
            })
        })
        .await
    }

    async fn finish(
        &mut self,
        mut update: PreparedUpdate,
        downloaded: Vec<(String, DownloadResult)>,
    ) -> io::Result<()> {
        let (config, cache, state) = blocking(move || {
            update.fresh.extend(
                update
                    .cache
                    .merge_downloads(downloaded, &update.config.cache.path),
            );
            let bl = assemble(&update.config, update.manual, &update.fresh);
            update
                .cache
                .prune(&all_urls(&update.config), &update.config.cache.path);
            if let Err(e) = update.cache.save_to_disk(&update.config.cache.path) {
                log::error!("Failed to save cache; will retry: {e}");
            }
            let state = Arc::new(QueryState {
                upstream: update.upstream,
                blocklist: Arc::new(bl),
                log_queries: update.config.logging.queries,
            });
            Ok((update.config, update.cache, state))
        })
        .await?;
        log_config_changes(&self.config, &config);
        let previous = {
            let mut active = self.state.write().await;
            std::mem::replace(&mut *active, state)
        };
        self.config = config;
        self.cache = cache;
        // Large old tables are never freed while holding the serving lock.
        tokio::task::spawn_blocking(move || drop(previous));
        Ok(())
    }

    async fn save(&mut self) -> io::Result<()> {
        let mut cache = self.cache.clone();
        let path = self.config.cache.path.clone();
        let (cache, result) = tokio::task::spawn_blocking(move || {
            let result = cache.save_to_disk(&path);
            (cache, result)
        })
        .await
        .map_err(io::Error::other)?;
        self.cache = cache;
        result
    }

    /// Single coordinator: a HUP arriving during a refresh waits for that
    /// bounded fetch to complete, then rebuilds from the newly read config.
    pub async fn run(
        mut self,
        config_path: String,
        mut hup: Signal,
        mut term: Signal,
    ) -> io::Result<()> {
        let timer = tokio::time::sleep(Duration::ZERO);
        tokio::pin!(timer);
        let mut initial = true;
        loop {
            let reload = tokio::select! {
                biased;
                _ = term.recv() => break,
                _ = hup.recv() => true,
                _ = &mut timer => false,
            };
            let config = if reload {
                log::info!("SIGHUP received, reloading configuration...");
                match read_config(config_path.clone()).await {
                    Ok(config) => config,
                    Err(e) => {
                        log::error!("Failed to reload configuration: {e}");
                        continue;
                    }
                }
            } else {
                log::info!("Refreshing blocklists...");
                self.config.clone()
            };
            match self.prepare(config).await {
                Ok(mut update) => {
                    let jobs = std::mem::take(&mut update.jobs);
                    let downloaded = tokio::select! {
                        biased;
                        _ = term.recv() => break,
                        downloaded = CachedLists::download_jobs(jobs, &update.config.cache.path, Arc::clone(&update.upstream)) => downloaded,
                    };
                    // Finish persistence/publication before handling the next
                    // signal. No detached writer can race the shutdown save.
                    if let Err(e) = self.finish(update, downloaded).await {
                        log::error!("Failed to rebuild blocklists; keeping previous state: {e}");
                    } else if reload {
                        log::info!("Configuration reloaded successfully.");
                    } else if initial {
                        log::info!("Initial remote refresh completed.");
                    } else {
                        log::info!("Blocklist refreshed successfully.");
                    }
                }
                Err(e) => log::error!("Failed to prepare update; keeping previous state: {e}"),
            }
            initial = false;
            timer.as_mut().reset(
                tokio::time::Instant::now()
                    + Duration::from_secs(self.config.blocklists.refresh_interval_secs),
            );
        }
        log::info!("SIGTERM received, saving cache and shutting down...");
        self.save().await?;
        log::info!("Cache saved, exiting.");
        Ok(())
    }
}

fn log_config_changes(old_config: &Config, new_config: &Config) {
    // Upstream
    if old_config.upstream.address != new_config.upstream.address
        || old_config.upstream.port != new_config.upstream.port
    {
        log::info!(
            "Upstream: {}:{} -> {}:{} (use_tcp: {} -> {})",
            old_config.upstream.address,
            old_config.upstream.port,
            new_config.upstream.address,
            new_config.upstream.port,
            old_config.upstream.use_tcp,
            new_config.upstream.use_tcp
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

    // Regex blocklist URLs
    let old_rb: HashSet<_> = old_config.blocklists.regex_block_urls.iter().collect();
    let new_rb: HashSet<_> = new_config.blocklists.regex_block_urls.iter().collect();
    for url in &new_rb - &old_rb {
        log::info!("Regex blocklist added: {}", url);
    }
    for url in &old_rb - &new_rb {
        log::info!("Regex blocklist removed: {}", url);
    }

    // Regex allowlist URLs
    let old_ra: HashSet<_> = old_config.blocklists.regex_allow_urls.iter().collect();
    let new_ra: HashSet<_> = new_config.blocklists.regex_allow_urls.iter().collect();
    for url in &new_ra - &old_ra {
        log::info!("Regex allowlist added: {}", url);
    }
    for url in &old_ra - &new_ra {
        log::info!("Regex allowlist removed: {}", url);
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
        log::info!(
            "Cache path: {} -> {}",
            old_config.cache.path,
            new_config.cache.path
        );
    }

    // Query logging
    if old_config.logging.queries != new_config.logging.queries {
        log::info!(
            "Query logging: {} -> {}",
            old_config.logging.queries,
            new_config.logging.queries
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
