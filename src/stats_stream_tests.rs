use super::*;

fn row(action: &str, domain: &str, source: &str) -> String {
    serde_json::json!({"__REALTIME_TIMESTAMP":"1735689600000000","QUERY_SOURCE":source,
        "QUERY_DOMAIN":domain,"QUERY_QTYPE":"A","QUERY_ACTION":action,"QUERY_RULE":"rule"})
    .to_string()
        + "\n"
}

#[test]
fn streamed_rows_keep_substring_filters_and_combined_actions() {
    let input = row("blocked", "ads.example", "192.168.2.10")
        + &row("allowed", "safe.example", "192.168.2.11")
        + &row("forwarded", "ads.example", "10.0.0.1")
        + "&bad json\n{\"MESSAGE\":\"operational\"}\n";
    let filter = StatsFilter {
        blocked: true,
        allowed: true,
        domain: Some(".example".into()),
        src: Some("192.168.2.".into()),
        ..Default::default()
    };
    let mut output = Vec::new();
    let totals = read_entries(io::Cursor::new(input), &filter, &mut output).unwrap();
    assert_eq!(totals.total, 2);
    assert!(totals.by_source.is_empty());
    let output = String::from_utf8(output).unwrap();
    assert_eq!(output.matches("TIMESTAMP").count(), 1);
    assert!(output.contains("ads.example") && output.contains("safe.example"));
    assert!(!output.contains("10.0.0.1"));
}

struct RepeatedRows {
    line: Vec<u8>,
    remaining: usize,
    offset: usize,
}
impl io::Read for RepeatedRows {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let input = self.fill_buf()?;
        let count = input.len().min(out.len());
        out[..count].copy_from_slice(&input[..count]);
        self.consume(count);
        Ok(count)
    }
}
impl BufRead for RepeatedRows {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.remaining == 0 {
            Ok(&[])
        } else {
            Ok(&self.line[self.offset..])
        }
    }
    fn consume(&mut self, amount: usize) {
        self.offset += amount;
        if self.offset == self.line.len() {
            self.remaining -= 1;
            self.offset = 0;
        }
    }
}

#[test]
fn summary_counts_a_large_stream_without_retaining_entries() {
    let reader = RepeatedRows {
        line: row("blocked", "ads.example", "192.168.2.10").into_bytes(),
        remaining: 10000,
        offset: 0,
    };
    let filter = StatsFilter {
        summary: true,
        ..Default::default()
    };
    let mut output = Vec::new();
    let summary = read_entries(reader, &filter, &mut output).unwrap();
    assert!(output.is_empty());
    assert_eq!(summary.total, 10000);
    assert_eq!(summary.by_source.len(), 1);
    assert_eq!(summary.blocked_domains.len(), 1);
    summary.write(&mut output).unwrap();
    assert!(String::from_utf8(output)
        .unwrap()
        .contains("Total queries: 10000"));
}

#[test]
fn summary_top_ten_is_stable_and_ranked() {
    let mut counts: HashMap<_, _> = (0..20).map(|i| (format!("domain{i:02}"), 1)).collect();
    counts.insert("winner".into(), 50);
    let mut output = Vec::new();
    write_top(&mut output, "Top 10:", counts).unwrap();
    let output = String::from_utf8(output).unwrap();
    let rows: Vec<_> = output
        .lines()
        .filter(|line| line.starts_with("  "))
        .collect();
    assert_eq!(rows.len(), 10);
    assert!(rows[0].contains("winner"));
    assert!(rows[1].contains("domain00"));
    assert!(rows[9].contains("domain08"));
    assert!(!output.contains("domain09"));
}

#[test]
fn journalctl_receives_only_exact_action_filters() {
    let filter = StatsFilter {
        blocked: true,
        allowed: true,
        domain: Some("ads".into()),
        src: Some("192.".into()),
        since: Some("1 hour ago".into()),
        ..Default::default()
    };
    let command = journal_command(&filter);
    let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
    assert_eq!(
        args,
        [
            "-u",
            "dns-ligase",
            "--output=json",
            "--no-pager",
            "--since",
            "1 hour ago",
            "QUERY_ACTION=blocked",
            "QUERY_ACTION=allowed"
        ]
    );
}

fn fake_journal(text: &str, exit: u8) -> Command {
    let mut command = Command::new("sh");
    command.args([
        "-c",
        "printf '%s' \"$1\"; exit \"$2\"",
        "stats-test",
        text,
        &exit.to_string(),
    ]);
    command
}

#[test]
fn journal_failure_does_not_print_a_misleading_empty_or_summary_result() {
    let filter = StatsFilter {
        summary: true,
        ..Default::default()
    };
    let mut output = Vec::new();
    let error = run_command(
        fake_journal(&row("blocked", "ads.example", "10.0.0.1"), 7),
        &filter,
        &mut output,
    )
    .unwrap_err();
    assert!(error.to_string().contains("journalctl failed"));
    assert!(output.is_empty());
    run_command(fake_journal("", 0), &filter, &mut output).unwrap();
    assert_eq!(String::from_utf8(output).unwrap(), "No matching entries.\n");
}

struct ClosedOutput;
impl Write for ClosedOutput {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn closed_output_pipe_stops_and_reaps_the_child() {
    let mut command = Command::new("sh");
    command.args([
        "-c",
        "printf '%s' \"$1\"; exec sleep 30",
        "stats-test",
        &row("blocked", "ads.example", "10.0.0.1"),
    ]);
    let start = std::time::Instant::now();
    run_command(command, &StatsFilter::default(), &mut ClosedOutput).unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}
