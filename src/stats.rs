//! `dns-ligase stats` subcommand: reads query logs from journald and prints
//! them in a human-readable format with optional filtering.
//!
//! Query logs are written by `journald.rs` with structured fields:
//! `QUERY_SOURCE`, `QUERY_DOMAIN`, `QUERY_QTYPE`, `QUERY_ACTION`, `QUERY_RULE`.
//! This subcommand shells out to `journalctl --output=json`, parses the JSON
//! with `serde_json` (already a dependency), and filters in-process.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::process::Command;

use serde::Deserialize;

/// One parsed journal entry with query fields extracted.
#[derive(Debug, Clone)]
pub struct QueryEntry {
    pub timestamp: String,
    pub source: String,
    pub domain: String,
    pub qtype: String,
    pub action: String,
    pub rule: String,
}

/// Raw journald JSON entry — only the fields we care about.
#[derive(Debug, Deserialize)]
struct JournalEntry {
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    timestamp: Option<String>,
    #[serde(rename = "QUERY_SOURCE")]
    source: Option<String>,
    #[serde(rename = "QUERY_DOMAIN")]
    domain: Option<String>,
    #[serde(rename = "QUERY_QTYPE")]
    qtype: Option<String>,
    #[serde(rename = "QUERY_ACTION")]
    action: Option<String>,
    #[serde(rename = "QUERY_RULE")]
    rule: Option<String>,
}

/// Filter flags for `run_stats`.
#[derive(Debug, Default)]
pub struct StatsFilter {
    pub blocked: bool,
    pub allowed: bool,
    pub forwarded: bool,
    pub domain: Option<String>,
    pub src: Option<String>,
    pub since: Option<String>,
    pub summary: bool,
}

/// Parse a stream of JSON objects (one per line, as journalctl --output=json
/// produces) into `QueryEntry` records.
pub fn parse_entries(json_lines: &str) -> Vec<QueryEntry> {
    let mut entries = Vec::new();
    for line in json_lines.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(raw) = serde_json::from_str::<JournalEntry>(line) {
            // Skip entries that don't have query fields (operational logs).
            if raw.action.is_none() && raw.domain.is_none() {
                continue;
            }
            entries.push(QueryEntry {
                timestamp: format_timestamp(raw.timestamp.as_deref()),
                source: raw.source.unwrap_or_default(),
                domain: raw.domain.unwrap_or_default(),
                qtype: raw.qtype.unwrap_or_default(),
                action: raw.action.unwrap_or_default(),
                rule: raw.rule.unwrap_or_default(),
            });
        }
    }
    entries
}

/// Convert journald's microsecond timestamp to a readable `YYYY-MM-DD HH:MM:SS`.
fn format_timestamp(us: Option<&str>) -> String {
    let us: u64 = match us {
        Some(s) => s.parse().unwrap_or(0),
        None => return String::new(),
    };
    if us == 0 {
        return String::new();
    }
    let secs = us / 1_000_000;
    // Simple UTC formatting — good enough for a home server stats view.
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days_since_epoch);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch (1970-01-01) to (year, month, day).
/// Uses the algorithm from Howard Hinnant's date library (proleptic Gregorian).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as u64, m, d)
}

/// Filter entries according to the given flags.
pub fn filter_entries(entries: Vec<QueryEntry>, f: &StatsFilter) -> Vec<QueryEntry> {
    entries
        .into_iter()
        .filter(|e| {
            if f.blocked && e.action != "blocked" {
                return false;
            }
            if f.allowed && e.action != "allowed" {
                return false;
            }
            if f.forwarded && e.action != "forwarded" {
                return false;
            }
            if !f.blocked && !f.allowed && !f.forwarded {
                // No action filter: show all.
            }
            if let Some(ref d) = f.domain {
                if !e.domain.contains(d) {
                    return false;
                }
            }
            if let Some(ref s) = f.src {
                if !e.source.contains(s) {
                    return false;
                }
            }
            true
        })
        .collect()
}

/// Print entries as a formatted table, one per line.
pub fn print_entries(entries: &[QueryEntry]) {
    if entries.is_empty() {
        println!("No matching entries.");
        return;
    }
    println!("TIMESTAMP             SOURCE          TYPE   ACTION     DOMAIN                              RULE");
    println!("{}", "-".repeat(100));
    for e in entries {
        println!(
            "{:<20} {:<15} {:<6} {:<10} {:<32} {}",
            e.timestamp, e.source, e.qtype, e.action, e.domain, e.rule
        );
    }
}

/// Print a summary: totals by action, top blocked domains, top sources.
pub fn print_summary(entries: &[QueryEntry]) {
    if entries.is_empty() {
        println!("No matching entries.");
        return;
    }

    let mut by_action: HashMap<&str, usize> = HashMap::new();
    let mut blocked_domains: HashMap<&str, usize> = HashMap::new();
    let mut by_source: HashMap<&str, usize> = HashMap::new();

    for e in entries {
        *by_action.entry(e.action.as_str()).or_default() += 1;
        if e.action == "blocked" {
            *blocked_domains.entry(e.domain.as_str()).or_default() += 1;
        }
        *by_source.entry(e.source.as_str()).or_default() += 1;
    }

    println!("Total queries: {}", entries.len());
    println!();
    println!("By action:");
    for (action, count) in by_action {
        println!("  {:<12} {}", action, count);
    }

    println!();
    println!("Top 10 blocked domains:");
    let mut top_blocked: Vec<_> = blocked_domains.into_iter().collect();
    top_blocked.sort_by_key(|(_, c)| Reverse(*c));
    for (i, (domain, count)) in top_blocked.iter().take(10).enumerate() {
        println!("  {:<2}. {:<40} {}", i + 1, domain, count);
    }

    println!();
    println!("Top 10 sources:");
    let mut top_sources: Vec<_> = by_source.into_iter().collect();
    top_sources.sort_by_key(|(_, c)| Reverse(*c));
    for (i, (source, count)) in top_sources.iter().take(10).enumerate() {
        println!("  {:<2}. {:<40} {}", i + 1, source, count);
    }
}

/// Run the stats subcommand: invoke journalctl, parse, filter, print.
pub fn run_stats(filter: StatsFilter) -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new("journalctl");
    cmd.arg("-u").arg("dns-ligase");
    cmd.arg("--output=json");
    if let Some(ref since) = filter.since {
        cmd.arg("--since").arg(since);
    }
    // Only query log entries have QUERY_ACTION; journalctl can't filter on
    // arbitrary fields, so we pull everything and filter in-process.

    let output = cmd.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("journalctl failed: {stderr}").into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let entries = parse_entries(&stdout);
    let filtered = filter_entries(entries, &filter);

    if filter.summary {
        print_summary(&filtered);
    } else {
        print_entries(&filtered);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(action: &str, domain: &str, source: &str) -> QueryEntry {
        QueryEntry {
            timestamp: "2025-01-01 12:00:00".to_string(),
            source: source.to_string(),
            domain: domain.to_string(),
            qtype: "A".to_string(),
            action: action.to_string(),
            rule: String::new(),
        }
    }

    #[test]
    fn test_parse_entries_skips_non_query_logs() {
        let json = r#"{"__REALTIME_TIMESTAMP":"123","MESSAGE":"Starting up"}
{"__REALTIME_TIMESTAMP":"456","QUERY_SOURCE":"10.0.0.1","QUERY_DOMAIN":"ads.com","QUERY_QTYPE":"A","QUERY_ACTION":"blocked","QUERY_RULE":"block:ads.com"}"#;
        let entries = parse_entries(json);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "ads.com");
        assert_eq!(entries[0].action, "blocked");
    }

    #[test]
    fn test_filter_by_action() {
        let entries = vec![
            make_entry("blocked", "ads.com", "10.0.0.1"),
            make_entry("forwarded", "example.com", "10.0.0.2"),
            make_entry("allowed", "safe.com", "10.0.0.1"),
        ];
        let f = StatsFilter { blocked: true, ..Default::default() };
        assert_eq!(filter_entries(entries, &f).len(), 1);

        let entries = vec![
            make_entry("blocked", "ads.com", "10.0.0.1"),
            make_entry("forwarded", "example.com", "10.0.0.2"),
            make_entry("allowed", "safe.com", "10.0.0.1"),
        ];
        let f = StatsFilter { allowed: true, ..Default::default() };
        assert_eq!(filter_entries(entries, &f).len(), 1);
    }

    #[test]
    fn test_filter_by_domain() {
        let entries = vec![
            make_entry("blocked", "ads.example.com", "10.0.0.1"),
            make_entry("blocked", "tracker.net", "10.0.0.2"),
        ];
        let f = StatsFilter { blocked: true, domain: Some("example".to_string()), ..Default::default() };
        let filtered = filter_entries(entries, &f);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].domain, "ads.example.com");
    }

    #[test]
    fn test_filter_by_source() {
        let entries = vec![
            make_entry("blocked", "ads.com", "10.0.0.1"),
            make_entry("blocked", "tracker.net", "10.0.0.2"),
        ];
        let f = StatsFilter { blocked: true, src: Some("10.0.0.2".to_string()), ..Default::default() };
        let filtered = filter_entries(entries, &f);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].source, "10.0.0.2");
    }

    #[test]
    fn test_filter_no_action_shows_all() {
        let entries = vec![
            make_entry("blocked", "ads.com", "10.0.0.1"),
            make_entry("forwarded", "example.com", "10.0.0.2"),
            make_entry("allowed", "safe.com", "10.0.0.1"),
        ];
        let f = StatsFilter::default();
        assert_eq!(filter_entries(entries, &f).len(), 3);
    }

    #[test]
    fn test_format_timestamp() {
        // 2025-01-01 00:00:00 UTC = 1735689600 epoch seconds = 1735689600000000 us
        assert_eq!(format_timestamp(Some("1735689600000000")), "2025-01-01 00:00:00");
        assert_eq!(format_timestamp(None), "");
        assert_eq!(format_timestamp(Some("0")), "");
    }

    #[test]
    fn test_days_to_ymd() {
        // 1970-01-01 is day 0
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        // 2025-01-01
        let jan1_2025 = 1735689600u64 / 86400;
        assert_eq!(days_to_ymd(jan1_2025), (2025, 1, 1));
    }
}
