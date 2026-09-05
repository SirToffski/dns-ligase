# dns-ligase

A small DNS filtering forwarder written in Rust. It listens for DNS queries on UDP and TCP, checks the requested domain against blocklists and allowlists, returns `NXDOMAIN` for anything blocked, and forwards everything else to an upstream resolver.

It is intended to sit in front of a local validating resolver (unbound) as a lightweight replacement for AdGuard Home — no web UI, no admin API, no auto-updater, no third-party binary in the DNS path for the whole LAN.

> **Status: work in progress.** The core pipeline works end to end and has been verified against real blocklists and a real unbound instance with `dig`. It runs under systemd in tens of MB. Still young — read the known issues before putting it in front of anything you care about.

## Why

The goal was a resolver path made of parts I've actually read. AdGuard Home works fine, but it's a large third-party binary serving DNS for every device in the house, with a web server and update machinery attached. This does the one thing I need — filter, then forward — in a few thousand lines.

The DNS wire protocol is parsed by hand rather than pulled from a crate. That was the point of the exercise. Crates are used for the genuinely solved problems (TLS, regex, async runtime, allocation).

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
| `dns.rs` | Hand-rolled DNS wire format: header, question, resource record, message. Name parsing with compression-pointer support and jump limits, EDNS0/OPT handling. |
| `blocklist.rs` | Rule storage and matching. List fetching with an on-disk cache, conditional GETs, and format parsing. |
| `upstream.rs` | Upstream connection pool (UDP + TCP, shared across queries), UDP and TCP listeners, blocklist check, NXDOMAIN construction, DO-bit injection, forwarding, truncation/TCP fallback, timeouts, query logging. |
| `journald.rs` | Minimal journald native protocol sender for structured query logs (no external crate). |
| `stats.rs` | `stats` subcommand: reads journald JSON, filters by action/domain/source/time, prints table or summary. |
| `config.rs` | TOML config structs. |
| `main.rs` | Wiring, initial list load, periodic refresh, SIGHUP reload, SIGTERM shutdown, `stats` subcommand dispatch. |

### Matching

Rules are stored in three shapes, checked with allow always beating block:

| Shape | Source | Storage | Cost per query |
| --- | --- | --- | --- |
| Exact domain | hosts files, bare domains | `HashSet<String>` | one hash lookup |
| Domain + subdomains | `\|\|domain^` AdBlock rules | `HashSet<String>` | one lookup per label |
| Pattern | `/regex/` rules, config regexes | `Vec<Regex>` | linear scan |

`||domain^` rules are the overwhelming bulk of any real blocklist, and they mean exactly "this domain or any subdomain" — so they go into a suffix set matched by walking labels off the query name, not into compiled regexes. Compiling ~100k rules into individual `Regex` objects previously cost 1.5 GB of RAM and a linear scan on every query; the suffix set does the same job in tens of MB with a handful of hash lookups.

### Concurrency

Blocklists live behind `Arc<RwLock<Blocklist>>`. Query handlers take a read lock; refreshes build an entirely new `Blocklist` and swap it in under a write lock, so a reload never leaves a partially-populated list visible to queries. Config lives behind its own `Arc<RwLock<Config>>` and is read per-query, so upstream changes take effect without a restart.

List refreshes fetch all URLs concurrently and never hold the cache lock across network I/O — only the quick plan and merge steps take it.

## Features

**Filtering**

- Blocklists and allowlists fetched from URLs over HTTPS
- Formats: hosts files, AdBlock/uBO syntax (`||domain^` with `$options`, `@@` exceptions, `/regex/`), Pi-hole, AdGuard
- Format auto-detection per line; cosmetic/scriptlet rules (`##`, `#$#`, …) ignored rather than misparsed
- Local names (`localhost`, `broadcasthost`, …) from hosts-file headers are never blocked
- Manual block/allow entries and regex rules from config
- Allow rules take precedence over block rules
- Responses are also scanned for CNAME-cloaked trackers: a blocked CNAME target means NXDOMAIN
- Periodic background refresh with atomic swap

**Fetching**

- Raw list bodies cached on disk as JSON, surviving restarts
- Conditional GETs with `If-None-Match`; a `304` skips the download entirely
- Configurable freshness window (`cache_ttl_secs`) — lists within it aren't refetched
- On fetch failure (network error or HTTP 4xx/5xx), the last good copy is used rather than silently dropping thousands of rules
- List hostnames resolve through the configured `[upstream]`, not the system resolver — so dns-ligase can itself be the system resolver without deadlocking at boot
- Entries for URLs removed from config are pruned automatically

**DNS**

- UDP and TCP listeners (TCP with correct 2-byte length prefix)
- Hand-written wire format parser and serializer
- Name compression pointers with bounds checks and a jump limit
- EDNS0: advertises a 1232-byte buffer, sets the DO bit on outgoing queries even when the client didn't, passes RRSIG/NSEC and the AD flag through untouched
- Truncation handling: if an upstream UDP response comes back with the TC bit set, the query is retried over TCP to retrieve the full response; if the final response is still too large for the client's UDP path (its OPT buffer size, or 512 bytes with no OPT), a header-only response with the TC bit set is returned so the client retries over TCP
- Upstream connection reuse: a bounded pool of connected UDP and TCP sockets to the upstream, shared across queries; timed-out or errored sockets are discarded rather than returned, so a late stray response can never leak into a later query; a dead pooled TCP connection is retried once on a fresh one
- Timeouts on all upstream and client I/O; a dead listener exits loudly so systemd restarts the unit instead of serving half-protocol

**Operations**

- `SIGHUP` reloads config and rebuilds the blocklist, logging every individual change (lists added/removed, rules added/removed, upstream changed, query logging toggled). A bad upstream address rejects the whole reload rather than half-applying it.
- `SIGTERM` saves the cache and exits cleanly
- Config path via `--config`, `DNS_LIGASE_CONFIG`, or `./config.toml` in that order
- systemd unit with `DynamicUser`, `ProtectSystem=strict`, and `ExecReload`
- Arch `PKGBUILD` included

**Query logging**

- Optional per-query logging to journald with structured fields, enabled via `[logging] queries = true`
- Each log entry carries: source IP, domain, query type, action (blocked/allowed/forwarded), and the matched rule
- `dns-ligase stats` subcommand reads and filters the logs:
  ```
  dns-ligase stats                        # all recent queries
  dns-ligase stats --blocked              # blocked only
  dns-ligase stats --src 192.168.1.5      # from a specific client
  dns-ligase stats --domain ads --blocked # blocked queries with "ads" in the domain
  dns-ligase stats --since "1 hour ago"   # time window (journalctl syntax)
  dns-ligase stats --summary              # aggregate: totals, top blocked, top sources
  dns-ligase stats | fzf                  # fuzzy search interactively
  ```
- Log retention is controlled by journald globally; add a drop-in for 3 days:
  ```
  # /etc/systemd/journald.conf.d/retention.conf
  [Journal]
  MaxRetentionSec=3day
  ```

## Requirements

- Linux (x86_64). Windows and macOS are explicitly out of scope.
- A local validating resolver to forward to — unbound is what this is built around.
- Rust stable.

## Install

**Arch (PKGBUILD):**

```bash
cd PKGBUILD
makepkg -si
sudo systemctl enable --now dns-ligase
```

Installs the binary to `/usr/bin/dns-ligase`, config to `/etc/dns-ligase/config.toml` (marked `backup=`, so pacman won't clobber your edits), and the unit to `/usr/lib/systemd/system/`.

**From source:**

```bash
cargo build --release
cp config.toml my-config.toml   # then edit it: upstream address, lists, rules
RUST_LOG=info ./target/release/dns-ligase --config my-config.toml
```

Develop on a high port — binding 53 needs privileges. Under systemd, add `AmbientCapabilities=CAP_NET_BIND_SERVICE` rather than running as root; standalone, use `setcap`:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/bin/dns-ligase
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
urls = [
  "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  "https://v.firebog.net/hosts/Prigent-Crypto.txt",
]
# Optional: URLs fetched and parsed as allow rules. Same formats as blocklists
# (hosts, AdBlock/uBO, Pi-hole, AdGuard). Every entry is treated as an allow
# rule, overriding block rules. Shares the same refresh interval and cache.
# allowlist_urls = [
#   "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
# ]
refresh_interval_secs = 3600
# cache_ttl_secs = 3600    # optional; defaults to refresh_interval_secs

[matching]
manual_block = ["ads.example.com"]
manual_allow = []
regex_block = ["^(.+[_.-])?telemetry[_.-]"]
regex_allow = []

[cache]
# path = "/var/lib/dns-ligase/cache.json"   # defaults to $HOME/.cache/dns-ligase/cache.json

[logging]
# Enable per-query logging to journald with structured fields.
# View with: dns-ligase stats [--blocked|--allowed|--src|--domain|--summary]
queries = false
```

If you point `upstream` at a public resolver instead of a local validating one, you lose the DNSSEC validation this is designed around.

Blocklist hostnames resolve through `[upstream]`, so dns-ligase can be the machine's only resolver: point DNS at it directly. If you previously worked around the old boot deadlock with a second unbound listener plus a NetworkManager DNS override, that workaround is no longer needed — removing it is a deliberate manual step, nothing in code touches your network config.

Everything except `listen_addr` and `listen_port` is reloadable with `SIGHUP`:

```bash
sudo systemctl reload dns-ligase
# or
kill -HUP $(pidof dns-ligase)
```

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

Health check:

```bash
systemctl show dns-ligase -p MemoryCurrent   # expect well under 100 MB
journalctl -u dns-ligase -f
```

## Known issues

- **`use_tcp` config field** is parsed but ignored; upstream transport follows the client's transport, not config.
- **A `304 Not Modified` doesn't refresh `fetched_at`**, so once a list's TTL expires you get a conditional GET on every reload rather than restarting the freshness window. Cheap, but not ideal.
- **The startup log line doesn't report suffix-set sizes**, which are now where most rules live.
- **Cold boot with an unreachable upstream and an empty cache yields empty lists** (fail-open). It recovers on the next refresh once the upstream is reachable.

Not yet implemented:

- IPv6 upstreams (`UpstreamConfig.address` is `Ipv4Addr`)
