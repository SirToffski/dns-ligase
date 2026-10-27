//! Journal query output is read incrementally; summaries retain only counts.
use std::cmp::Reverse;
use std::collections::{BTreeSet, HashMap};
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde::Deserialize;

#[cfg(test)]
#[path = "stats_stream_tests.rs"]
mod stream_tests;

#[derive(Debug, Clone)]
pub struct QueryEntry {
    pub timestamp: String,
    pub source: String,
    pub domain: String,
    pub qtype: String,
    pub action: String,
    pub rule: String,
}

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

impl StatsFilter {
    fn matches(&self, entry: &QueryEntry) -> bool {
        let any_action = self.blocked || self.allowed || self.forwarded;
        (!any_action
            || (self.blocked && entry.action == "blocked")
            || (self.allowed && entry.action == "allowed")
            || (self.forwarded && entry.action == "forwarded"))
            && self
                .domain
                .as_ref()
                .is_none_or(|domain| entry.domain.contains(domain))
            && self
                .src
                .as_ref()
                .is_none_or(|source| entry.source.contains(source))
    }
}

fn parse_entry(line: &str) -> Option<QueryEntry> {
    let raw: JournalEntry = serde_json::from_str(line).ok()?;
    if raw.action.is_none() && raw.domain.is_none() {
        return None;
    }
    Some(QueryEntry {
        timestamp: format_timestamp(raw.timestamp.as_deref()),
        source: raw.source.unwrap_or_default(),
        domain: raw.domain.unwrap_or_default(),
        qtype: raw.qtype.unwrap_or_default(),
        action: raw.action.unwrap_or_default(),
        rule: raw.rule.unwrap_or_default(),
    })
}

/// Collection helpers retained for library callers. The CLI reads one line at
/// a time and does not build an in-memory list of journal entries.
#[allow(dead_code)]
pub fn parse_entries(json_lines: &str) -> Vec<QueryEntry> {
    json_lines.lines().filter_map(parse_entry).collect()
}

#[allow(dead_code)]
pub fn filter_entries(entries: Vec<QueryEntry>, filter: &StatsFilter) -> Vec<QueryEntry> {
    entries
        .into_iter()
        .filter(|entry| filter.matches(entry))
        .collect()
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

#[derive(Default)]
struct Summary {
    total: usize,
    by_action: HashMap<String, usize>,
    blocked_domains: HashMap<String, usize>,
    by_source: HashMap<String, usize>,
}

impl Summary {
    fn add(&mut self, entry: QueryEntry) {
        self.total += 1;
        if entry.action == "blocked" {
            *self.blocked_domains.entry(entry.domain).or_default() += 1;
        }
        *self.by_action.entry(entry.action).or_default() += 1;
        *self.by_source.entry(entry.source).or_default() += 1;
    }

    fn write(self, output: &mut impl Write) -> io::Result<()> {
        if self.total == 0 {
            return writeln!(output, "No matching entries.");
        }
        writeln!(output, "Total queries: {}\n\nBy action:", self.total)?;
        let mut actions: Vec<_> = self.by_action.into_iter().collect();
        actions.sort_by(|a, b| a.0.cmp(&b.0));
        for (action, count) in actions {
            writeln!(output, "  {action:<12} {count}")?;
        }
        write_top(output, "Top 10 blocked domains:", self.blocked_domains)?;
        write_top(output, "Top 10 sources:", self.by_source)
    }
}

fn write_top(
    output: &mut impl Write,
    title: &str,
    counts: HashMap<String, usize>,
) -> io::Result<()> {
    // Keep only ten candidates rather than allocating/sorting another complete
    // copy of the distinct-domain/source maps. Ties use the name for stability.
    let mut top = BTreeSet::new();
    for (name, count) in counts {
        top.insert((Reverse(count), name));
        if top.len() > 10 {
            top.pop_last();
        }
    }
    writeln!(output, "\n{title}")?;
    for (i, (Reverse(count), name)) in top.into_iter().enumerate() {
        writeln!(output, "  {:<2}. {:<40} {}", i + 1, name, count)?;
    }
    Ok(())
}

fn write_header(output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "TIMESTAMP             SOURCE          TYPE   ACTION     DOMAIN                              RULE")?;
    writeln!(output, "{}", "-".repeat(100))
}
fn write_entry(output: &mut impl Write, entry: &QueryEntry) -> io::Result<()> {
    writeln!(
        output,
        "{:<20} {:<15} {:<6} {:<10} {:<32} {}",
        entry.timestamp, entry.source, entry.qtype, entry.action, entry.domain, entry.rule
    )
}

#[allow(dead_code)]
pub fn print_entries(entries: &[QueryEntry]) {
    let mut output = io::stdout().lock();
    if entries.is_empty() {
        let _ = writeln!(output, "No matching entries.");
        return;
    }
    if write_header(&mut output).is_err() {
        return;
    }
    for entry in entries {
        if write_entry(&mut output, entry).is_err() {
            return;
        }
    }
}

#[allow(dead_code)]
pub fn print_summary(entries: &[QueryEntry]) {
    let mut summary = Summary::default();
    for entry in entries.iter().cloned() {
        summary.add(entry);
    }
    let _ = summary.write(&mut io::stdout().lock());
}

fn read_entries(
    mut reader: impl BufRead,
    filter: &StatsFilter,
    output: &mut impl Write,
) -> io::Result<Summary> {
    let mut summary = Summary::default();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let Some(entry) = parse_entry(&line).filter(|entry| filter.matches(entry)) else {
            continue;
        };
        if filter.summary {
            summary.add(entry);
        } else {
            if summary.total == 0 {
                write_header(output)?;
            }
            write_entry(output, &entry)?;
            summary.total += 1;
        }
    }
    Ok(summary)
}

fn journal_command(filter: &StatsFilter) -> Command {
    let mut command = Command::new("journalctl");
    command.args(["-u", "dns-ligase", "--output=json", "--no-pager"]);
    if let Some(since) = &filter.since {
        command.arg("--since").arg(since);
    }
    // Multiple matches for the same journal field are alternatives (OR).
    for (selected, action) in [
        (filter.blocked, "blocked"),
        (filter.allowed, "allowed"),
        (filter.forwarded, "forwarded"),
    ] {
        if selected {
            command.arg(format!("QUERY_ACTION={action}"));
        }
    }
    // Domain/source retain their existing substring semantics in-process.
    command
}

fn run_command(
    mut command: Command,
    filter: &StatsFilter,
    output: &mut impl Write,
) -> io::Result<()> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let reader = BufReader::new(child.stdout.take().expect("piped journal stdout"));
    let result = read_entries(reader, filter, output);
    let summary = match result {
        Ok(summary) => summary,
        Err(error) => {
            // A closed output pipe or read error must not leave journalctl
            // running. stderr is inherited so it cannot fill an unread pipe.
            let _ = child.kill();
            let _ = child.wait();
            return if error.kind() == io::ErrorKind::BrokenPipe {
                Ok(())
            } else {
                Err(error)
            };
        }
    };
    let status = child.wait()?;
    if !status.success() {
        return Err(io::Error::other(format!("journalctl failed: {status}")));
    }
    if filter.summary {
        summary.write(output)
    } else if summary.total == 0 {
        writeln!(output, "No matching entries.")
    } else {
        Ok(())
    }
}

pub fn run_stats(filter: StatsFilter) -> Result<(), Box<dyn std::error::Error>> {
    run_command(journal_command(&filter), &filter, &mut io::stdout().lock())?;
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
