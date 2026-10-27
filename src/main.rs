mod blocklist;
mod config;
mod dns;
mod journald;
mod reload;
mod stats;
mod upstream;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use crate::upstream::UdpForwarder;
use tokio::signal::unix::{signal, SignalKind};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "stats" {
        return run_stats_cmd(&args[2..]);
    }
    env_logger::init();
    let config_path = args
        .iter()
        .skip_while(|a| a.as_str() != "--config")
        .nth(1)
        .cloned()
        .or_else(|| std::env::var("DNS_LIGASE_CONFIG").ok())
        .unwrap_or_else(|| "config.toml".into());
    let config = reload::read_config(config_path.clone()).await?;
    let listen_addr = format!(
        "{}:{}",
        config.server.listen_addr, config.server.listen_port
    );
    let manager = reload::ReloadManager::new(config).await?;
    // Register signals and bind both transports before any remote work begins.
    let hup = signal(SignalKind::hangup())?;
    let term = signal(SignalKind::terminate())?;
    let forwarder = UdpForwarder::new(&listen_addr, manager.state.clone()).await?;
    let upstream_addr = manager.state.read().await.upstream.addr();
    log::info!("Listening on {listen_addr} and forwarding to {upstream_addr}; manual and cached rules active, remote refresh pending.");
    tokio::select! {
        result = forwarder.run() => result?,
        result = manager.run(config_path, hup, term) => result?,
    }
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
                filter.domain = Some(stats_value(args, i, "--domain")?);
            }
            "--src" | "-s" => {
                i += 1;
                filter.src = Some(stats_value(args, i, "--src")?);
            }
            "--since" => {
                i += 1;
                filter.since = Some(stats_value(args, i, "--since")?);
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

fn stats_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.get(index)
        .filter(|value| !value.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value").into())
}
