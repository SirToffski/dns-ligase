# dns-ligase

A small DNS filtering forwarder written in Rust. It listens for DNS queries on UDP and TCP, checks the requested domain against blocklists and allowlists, returns `NXDOMAIN` for anything blocked, and forwards everything else to an upstream resolver.

It is intended to sit in front of a local validating resolver (unbound) as a lightweight replacement for AdGuard Home — no web UI, no admin API, no auto-updater, no third-party binary in the DNS path for the whole LAN.

> **Status: work in progress.** The core pipeline works end to end and has been verified with real blocklists and `dig`, but there are known bugs and missing pieces listed below. Don't put this in front of anything you care about yet.

## Why

The goal was a resolver path made of parts I've actually read. AdGuard Home works fine, but it's a large third-party binary serving DNS for every device in the house, with a web server and update machinery attached. This does the one thing I need — filter, then forward — in a few hundred lines.

The DNS wire protocol is parsed by hand rather than pulled from a crate. That was the point of the exercise. Crates are used for the genuinely solved problems (TLS, regex, async runtime).

## How it works

```
client → UDP/TCP listener → parse DNS wire format → extract QNAME
                                                        ↓
                                              check allow/block rules
                                                   ↙          ↘
                                          NXDOMAIN         forward to unbound
                                                                  ↓
                                                          relay response back
```

| Module | Responsibility |
| --- | --- |
| `dns.rs` | Hand-rolled DNS wire format: header, question, resource record, message. Name parsing with compression-pointer support, EDNS0/OPT handling. |
| `blocklist.rs` | Rule storage and matching. Exact domains in `HashSet`, patterns in `Vec<Regex>`, separate allow and block sets. List fetching and format parsing. |
| `upstream.rs` | UDP and TCP listeners, blocklist check, NXDOMAIN construction, forwarding, timeouts. |
| `config.rs` | TOML config structs. |
| `main.rs` | Wiring, initial list load, periodic refresh task. |

Blocklists live behind `Arc<RwLock<Blocklist>>`. Query handlers take a read lock; the refresh task builds an entirely new `Blocklist` and swaps it in under a write lock, so refreshes never leave a partially-populated list visible to queries.

## Features

**Filtering**

- Blocklists and allowlists fetched from URLs over HTTPS
- Formats: hosts files, AdBlock/uBO syntax (`||domain^`, `@@` exceptions, `/regex/`), Pi-hole, AdGuard
- Format auto-detection per line
- Manual block/allow entries from config
- Regex block/allow rules from config
- Allow rules take precedence over block rules
- Periodic background refresh with atomic swap

**DNS**

- UDP and TCP listeners (TCP with correct 2-byte length prefix)
- Hand-written wire format parser and serializer
- Name compression pointer support with a jump limit
- EDNS0: advertises a 1232-byte buffer, sets the DO bit on outgoing queries even when the client didn't, passes RRSIG/NSEC and the AD flag through untouched
- 2-second timeouts on all upstream I/O

## Requirements

- Linux (x86_64). Windows and macOS are explicitly out of scope.
- A local validating resolver to forward to — unbound is what this is built around.
- Rust stable.

## Build and run

```bash
cargo build --release
cp config.example.toml config.toml   # then edit it
RUST_LOG=info ./target/release/rust_dns
```

Develop on a high port (5354 below) — binding 53 needs privileges. For a real deployment, prefer capabilities over running as root:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/rust_dns
```

## Configuration

```toml
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
address = "192.168.2.53"   # your unbound instance
port = 5354
use_tcp = false            # currently unused

[blocklists]
urls = ["https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"]
refresh_interval_secs = 3600

[matching]
manual_block = ["ads.example.com"]
manual_allow = []
regex_block = ["^(.+[_.-])?telemetry[_.-]"]
regex_allow = []
```

If you point `upstream` at a public resolver instead of a local validating one, you lose the DNSSEC validation this is designed around.

## Testing

Unit tests:

```bash
cargo test
```

End-to-end, with the server running:

```bash
# blocked by a manual rule → NXDOMAIN
dig @127.0.0.1 -p 5354 ads.example.com

# blocked by a regex rule → NXDOMAIN
dig @127.0.0.1 -p 5354 telemetry-in.battle.net

# subdomain of a ||domain^ blocklist rule → NXDOMAIN
dig @127.0.0.1 -p 5354 sub.d2pf0ys5xus6n.cloudfront.net

# not blocked → NOERROR with answers
dig @127.0.0.1 -p 5354 google.com

# DNSSEC pass-through: expect the ad flag and RRSIG records
dig @127.0.0.1 -p 5354 cloudflare.com +dnssec

# DO bit injection: no +dnssec from the client, but RRSIGs should still appear
dig @127.0.0.1 -p 5354 cloudflare.com

# unsigned zone control: no ad flag and no RRSIG is the CORRECT result here
dig @127.0.0.1 -p 5354 cbc.ca +dnssec
```

Compare any of these against querying your unbound directly — the outputs should match.

## Known issues

Things that are actually broken right now:

- **`parse_name` is missing a bounds check** on compression pointers. A packet ending in a lone `0xC0` byte will index past the end and panic. Tokio isolates the panic per task so the server survives, but this is remotely triggerable and needs fixing.
- **Test coverage regressed.** Several `dns.rs` tests were lost in a rewrite, including the malicious-pointer test that would have caught the above.
- **Debug logging on the hot path.** Full packet hex is logged at info level and appended to `/tmp/dns_packet.hex`. That's blocking I/O in an async task, unbounded disk growth, and it records every query. Remove before using this for real.
- **`ListFormat::AdGuard` routes to the hosts parser**, but AdGuard DNS lists use AdBlock syntax. Currently unreached because auto-detection handles it, but wrong if selected explicitly.

Not yet implemented:

- SIGHUP config reload
- systemd unit file
- Truncation handling — no TC flag or TCP fallback for oversized UDP responses
- Upstream connection reuse; a fresh socket is created per query
- `use_tcp` config field is parsed but ignored

## License

TBD.

---

*Built as a learning project, largely by pair-programming with a local LLM (Gemma 4 26B running on llama.cpp) inside an agentic harness. The bugs above are a fair sample of what that process produces — the architecture is sound, and the details need a careful human read.*
