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
| `dns.rs` | Hand-rolled DNS wire format: header, question, resource record, message. Reversible byte escapes for names, compression-pointer and length checks, EDNS0/OPT handling. |
| `blocklist.rs` | Rule storage and matching. List fetching with an on-disk cache, conditional GETs, and format parsing. |
| `upstream.rs` | Upstream connection pool (UDP + TCP, shared across queries), UDP and TCP listeners, blocklist check, NXDOMAIN construction, DO-bit injection, forwarding, truncation/TCP fallback, timeouts, query logging. |
| `journald.rs` | Minimal journald native protocol sender for structured query logs (no external crate). |
| `stats.rs` | `stats` subcommand: reads journald JSON, filters by action/domain/source/time, prints table or summary. |
| `clients.rs` | Per-client policy: unfiltered sources and source-scoped allow rules, with IP/CIDR matching. |
| `config.rs` | TOML config structs. |
| `main.rs` | Startup, listener wiring, signal registration, `stats` subcommand dispatch. |
| `reload.rs` | Cached startup rules, coordinated periodic refresh and SIGHUP reload, config validation, cache migration, SIGTERM persistence. |

### Matching

Rules are stored in three shapes, checked with allow always beating block:

| Shape | Source | Storage | Cost per query |
| --- | --- | --- | --- |
| Exact domain | hosts files, bare domains | `HashSet<String>` | one hash lookup |
| Domain + subdomains | `\|\|domain^` AdBlock rules | `HashSet<String>` | one lookup per label |
| Pattern | `/regex/` rules, config regexes | `Vec<Regex>` | linear scan |

`||domain^` rules are the overwhelming bulk of any real blocklist, and they mean exactly "this domain or any subdomain" — so they go into a suffix set matched by walking labels off the query name, not into compiled regexes. Compiling ~100k rules into individual `Regex` objects previously cost 1.5 GB of RAM and a linear scan on every query; the suffix set does the same job in tens of MB with a handful of hash lookups.

### Concurrency

Each query takes a brief read lock to clone one immutable serving snapshot: rules, upstream pool, and query-logging setting. It keeps that snapshot across upstream I/O and CNAME checks. Rebuilds publish a complete replacement under the same lock; in-flight queries finish with their original snapshot.

One coordinator owns periodic refreshes and SIGHUP reloads, so an older build cannot overwrite a completed reload or prune its cache. A SIGHUP arriving during a fetch waits for that bounded fetch to finish. Fetches run concurrently; parsing and filesystem work run on blocking workers, outside the serving lock.

Startup loads manual rules and all readable cached bodies, including stale ones, then binds both UDP and TCP before the first remote refresh. Missing lists are temporarily absent (fail-open); logs distinguish listener readiness from completion of the initial refresh. List-server outages do not prevent DNS from starting. SIGTERM cancels active downloads and saves the currently active cache.

## Features

**Filtering**

- Blocklists and allowlists fetched from URLs over HTTPS
- Formats: hosts files, AdBlock/uBO syntax (`||domain^` with `$options`, `@@` exceptions, `/regex/`), Pi-hole, AdGuard
- Format auto-detection per line; cosmetic/scriptlet rules (`##`, `#$#`, …) ignored rather than misparsed
- Local names (`localhost`, `broadcasthost`, …) from hosts-file headers are never blocked
- Manual block/allow entries and regex rules from config
- Regex block/allow lists fetched from URLs (one pattern per line, Pi-hole style)
- Allow rules take precedence over block rules
- Per-client policy (`[clients]`): listed sources can skip filtering entirely, or get extra allow rules that apply only to them. See [Per-client rules](#per-client-rules).
- An allow-rule match on the requested name exempts that query from CNAME filtering, including exact, suffix and regex allow rules from config or lists. It does not allow the target for unrelated queries, and upstream NXDOMAIN/SERVFAIL still pass through.
- Other responses are scanned for CNAME-cloaked trackers: a blocked CNAME target means NXDOMAIN
- Hosts-file aliases are all parsed. Malformed rules are skipped safely; invalid remote regexes report their URL, line and skipped count (details limited to the first 10 per list).
- Periodic background refresh with atomic swap

**Fetching**

- List bodies cached on disk, surviving restarts: `cache.json` holds per-URL metadata (fetch time, ETag, filename) and a `cache.d/` directory next to it holds the raw list text files (e.g. with `path = "/var/lib/dns-ligase/cache.json"`, bodies live in `/var/lib/dns-ligase/cache.d/`)
- Conditional GETs with `If-None-Match`; a `304` skips the download entirely
- Configurable freshness window (`cache_ttl_secs`) — lists within it aren't refetched
- On fetch failure (including an incomplete response body), the last good copy is used. A valid download remains usable even if saving its cache file fails; cache files are replaced atomically and failed metadata saves are retried.
- List requests have a 5-second connection timeout and a 30-second overall deadline, including any missing-body conditional-GET retry.
- All list hostnames, including redirect destinations, resolve through the configured `[upstream]`, with TCP fallback for truncated DNS replies. Fetches connect directly without environment proxies or system-resolver fallback, so dns-ligase can itself be the system resolver without a circular dependency.
- Entries for URLs removed from config are pruned automatically

**DNS**

- UDP and TCP listeners (TCP with correct 2-byte length prefix)
- Standard single-question DNS queries; ambiguous multi-question requests and non-query messages are rejected before filtering
- Hand-written wire format parser and serializer
- Name compression pointers with bounds checks and a jump limit
- Names retain literal dots, backslashes and arbitrary label bytes using decimal escapes internally; only actual label boundaries become dots. Reserved label types and overlong names are rejected. Forwarded queries retain their original wire layout, so adding/updating OPT does not relocate compression pointers in opaque RDATA.
- EDNS0: advertises a 1232-byte buffer, sets the DO bit on outgoing queries even when the client didn't, passes RRSIG/NSEC and the AD flag through untouched
- Truncation handling: if an upstream UDP response comes back with TC set, the query is retried over TCP. A response exceeding the client's UDP path is reduced to a TC reply with the question and OPT when they fit. Oversized OPT options are dropped. The client limit is its advertised size, with a 512-byte minimum and the IPv4 UDP payload ceiling; without OPT it is 512 bytes.
- Upstream connection reuse: a bounded pool of connected UDP and TCP sockets to the upstream, shared across queries; timed-out or errored sockets are discarded rather than returned, so a late stray response can never leak into a later query; a dead pooled TCP connection is retried once on a fresh one
- Replies on both transports must match ID, response bit, opcode and all question names/types/classes. Stale replies are skipped within the deadline; sockets that see stale or malformed replies are discarded. UDP TC replies may have partial answer sections, but must carry the complete matching question before TCP fallback.
- Each upstream exchange has one 2-second deadline covering checkout, connection, writes, reads, stale replies and the pooled TCP retry. Client TCP I/O is bounded separately, with a 30-second idle timeout. TCP frames send their prefix and body together with NODELAY enabled on both hops.
- Both listeners bind before readiness. Transient TCP accept errors are logged with a 100 ms backoff so resource pressure cannot cause a busy loop.

**Operations**

- `SIGHUP` validates config, rebuilds the blocklist, and publishes rules, upstream and logging together, logging individual changes. Invalid manual regexes, a zero/unsupported refresh interval, a zero upstream port, or a failed cache-path migration reject the reload while preserving the active state. Invalid startup config exits with an error.
- Refresh-interval changes reset the timer after reload. Cache-path changes prepare the destination and copy usable configured list bodies before publication; the old cache location is retained.
- `SIGTERM` saves the cache and exits cleanly
- Config path via `--config`, `DNS_LIGASE_CONFIG`, or `./config.toml` in that order
- systemd unit with `DynamicUser`, `ProtectSystem=strict`, and `ExecReload`
- Arch `PKGBUILD` included

**Query logging**

- Optional per-query logging to journald with structured fields, enabled via `[logging] queries = true`
- Each log entry carries: source IP, domain, query type, action (blocked/allowed/forwarded/bypassed), and the matched rule
- One filtering decision is logged per completed response. Failed delivery produces an operational error rather than a misleading success entry. Journal writes are nonblocking and best-effort; entries may be dropped if journald is unavailable or congested.
- `dns-ligase stats` streams journal entries and prints rows as they arrive. Summaries retain counts per action/domain/source rather than every query. Exact action filters are sent to journalctl; domain and source filters remain case-sensitive substrings. Times are printed in UTC.
- Filter options requiring a value (`--domain`, `--src`, `--since`) reject missing arguments. Closing a downstream pipe stops and reaps journalctl cleanly.
- Examples:
  ```
  dns-ligase stats                        # all recent queries
  dns-ligase stats --blocked              # blocked only
  dns-ligase stats --src 192.168.1.5      # from a specific client
  dns-ligase stats --bypassed             # queries from [clients] unfiltered sources
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

The Git package normally builds upstream HEAD. To package a local committed revision, copy the recipe to a separate build directory (makepkg updates `pkgver` and creates build files):

```bash
repo=$(git rev-parse --show-toplevel)
revision=$(git rev-parse HEAD)
build_dir=$(mktemp -d)
cp "$repo/PKGBUILD/PKGBUILD" "$build_dir/PKGBUILD"
cd "$build_dir"
DNS_LIGASE_SOURCE="git+file://${repo}#commit=${revision}" makepkg --check
```

The package's `check()` runs `cargo test --locked`. The recipe disables makepkg's C/C++ LTO because mimalloc includes C code, while retaining Rust's ThinLTO from `Cargo.toml`. The manual GitHub workflow pins its selected checkout commit through this same override and checks that the packaged source revision matches. Nothing publishes or installs the resulting package automatically.

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
# Optional: URLs fetched and parsed as regex rules, one pattern per line
# (Pi-hole style, e.g. `(\.|^)ads\.example\.com$ -- comment`). Same formats
# for trailers (` -- comment` suffixes and `/.../ ` wrapping are tolerated).
# regex_block_urls = [
#   "https://raw.githubusercontent.com/slyfox1186/pihole-regex/main/domains/regex-blacklist.sql",
# ]
# regex_allow_urls = [
#   "https://raw.githubusercontent.com/slyfox1186/pihole-regex/main/domains/regex-whitelist.sql",
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
# View with: dns-ligase stats [--blocked|--allowed|--bypassed|--src|--domain|--summary]
queries = false

[clients]
# Optional. See "Per-client rules" below.
# unfiltered = ["192.168.2.54", "192.168.2.53"]
#
# [[clients.allow]]
# sources = ["192.168.2.60"]
# domains = ["ads.example.com", "||tracking.example.net^"]
# regex   = ['(^|\.)metrics\.example\.org$']
```

### Per-client rules

Sources are IP addresses or CIDR ranges (`192.168.2.54`, `192.168.2.0/24`, `fd00::/8`). IPv4 clients reaching an IPv6 listener as `::ffff:a.b.c.d` match their IPv4 entries.

- **`unfiltered`** — every query from these sources is forwarded to `[upstream]` with no filtering at all: no block rules, no CNAME check. Logged with action `bypassed` and rule `client_bypass:<entry>`.
- **`[[clients.allow]]`** — allow rules that apply only to the group's `sources`; every other client is filtered normally, and these sources stay filtered for anything the group doesn't match. A match beats global block rules and exempts the query from CNAME filtering, exactly like a global allow. `domains` entries are exact (`example.com`) or domain-plus-subdomains (`||example.com^`); `regex` entries use the same syntax as `regex_allow`. Logged as `allowed` with a `client_` rule prefix, e.g. `client_allow:ads.example.com`. Repeat the table for more groups; a source in several groups gets the union of their rules.

Precedence for a query: client `unfiltered` → that client's `allow` groups → global allow → global block → forward. Client rules never block anything.

Unknown keys under `[clients]` (e.g. a typo like `unfilterd`) are an error rather than silently ignored, as are invalid addresses, empty groups, and invalid regexes — startup fails or the reload is rejected with the active state kept. Client rules reload with `SIGHUP`.

TOML single-quoted strings preserve backslashes. For example, `'^ads\.example\.com$'` and `"^ads\\.example\\.com$"` are equivalent regexes. A glob such as `"*.example.com"` is not a valid regex; use `'(^|\.)example\.com$'` for that domain and its subdomains. Invalid manual regexes reject startup/reload; unsupported remote patterns (including lookaround) are skipped with diagnostics rather than silently rewritten.

If you point `upstream` at a public resolver instead of a local validating one, you lose the DNSSEC validation this is designed around.

Blocklist hostnames resolve through `[upstream]`, so dns-ligase can be the machine's only resolver: point DNS at it directly. If you previously worked around the old boot deadlock with a second unbound listener plus a NetworkManager DNS override, that workaround is no longer needed — removing it is a deliberate manual step, nothing in code touches your network config.

Everything except `listen_addr` and `listen_port` is reloadable with `SIGHUP`:

```bash
sudo systemctl reload dns-ligase
# or
kill -HUP $(pidof dns-ligase)
```

## Testing

Unit and lifecycle integration tests, lint, and release build:

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
```

The tests use local mock resolvers/list servers to cover DNS wire edge cases, response matching and deadlines, CNAME allow precedence, one query-log decision, congested/unavailable journald, list/cache failures, startup readiness, reload races and rollback, timer/cache-path changes, descriptor exhaustion, streamed stats and child cleanup. They do not change the host's DNS settings or require the live LAN resolver.

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

# DNSSEC validation failure: expect SERVFAIL through proxy and unbound
dig @127.0.0.1 -p 5354 dnssec-failed.org
```

Compare any of these against querying your unbound directly — the outputs should match.

Health check:

```bash
systemctl show dns-ligase -p MemoryCurrent
journalctl -u dns-ligase -f
```

Measure memory with your configured lists. A refresh temporarily holds both the active and replacement rules; in-flight queries can briefly retain the old snapshot after publication.

## Known issues

- **`use_tcp` config field** is parsed but ignored; upstream transport follows the client's transport, not config.
- **Cold boot with an empty cache serves manual rules immediately while remote lists load** (fail-open for missing lists). If the fetch fails, it retries on the next configured refresh or SIGHUP once the upstream/list servers are reachable.

Not yet implemented:

- IPv6 upstreams (`UpstreamConfig.address` is `Ipv4Addr`)
