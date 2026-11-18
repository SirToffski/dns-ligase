//! Per-client policy: sources that bypass filtering entirely, and allow rules
//! that apply only to specific sources.
use std::io;
use std::net::IpAddr;

use crate::blocklist::{Blocklist, MatchOutcome};
use crate::config::ClientsConfig;

/// A single address or CIDR range, e.g. `192.168.2.54` or `192.168.2.0/24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    pub fn parse(text: &str) -> Result<Self, String> {
        let (addr_text, prefix_text) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr_text.trim().parse().map_err(|e| format!("{e}"))?;
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            None => max,
            Some(p) => p
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("prefix length must be 0-{max}"))?,
        };
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

#[derive(Debug)]
struct AllowGroup {
    sources: Vec<IpNet>,
    rules: Blocklist,
}

/// Immutable per-client rules, published with each serving snapshot.
#[derive(Debug, Default)]
pub struct ClientPolicy {
    unfiltered: Vec<(IpNet, String)>,
    allow: Vec<AllowGroup>,
}

fn invalid(field: &str, entry: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid clients.{field} entry {entry:?}: {error}"),
    )
}

fn parse_sources(field: &str, entries: &[String]) -> io::Result<Vec<IpNet>> {
    entries
        .iter()
        .map(|entry| IpNet::parse(entry).map_err(|e| invalid(field, entry, e)))
        .collect()
}

/// `example.com` matches exactly; `||example.com^` also matches subdomains.
fn add_domain(rules: &mut Blocklist, entry: &str) -> io::Result<()> {
    let (name, suffix) = match entry
        .strip_prefix("||")
        .and_then(|rest| rest.strip_suffix('^'))
    {
        Some(name) => (name, true),
        None => (entry, false),
    };
    let name = name.trim().trim_end_matches('.').to_lowercase();
    if name.is_empty() || name.contains(|c: char| c.is_whitespace() || "|^/*".contains(c)) {
        return Err(invalid(
            "allow.domains",
            entry,
            "expected `example.com` or `||example.com^` (use `regex` for patterns)",
        ));
    }
    if suffix {
        rules.allow_suffixes.insert(name);
    } else {
        rules.allow_domains.insert(name);
    }
    Ok(())
}

impl ClientPolicy {
    pub fn from_config(config: &ClientsConfig) -> io::Result<Self> {
        let unfiltered = config
            .unfiltered
            .iter()
            .map(|entry| {
                IpNet::parse(entry)
                    .map(|net| (net, entry.trim().to_string()))
                    .map_err(|e| invalid("unfiltered", entry, e))
            })
            .collect::<io::Result<_>>()?;
        let mut allow = Vec::with_capacity(config.allow.len());
        for group in &config.allow {
            if group.sources.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "clients.allow group has no sources",
                ));
            }
            if group.domains.is_empty() && group.regex.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "clients.allow group for {:?} has no domains or regex",
                        group.sources
                    ),
                ));
            }
            let sources = parse_sources("allow.sources", &group.sources)?;
            let mut rules = Blocklist::new();
            for entry in &group.domains {
                add_domain(&mut rules, entry)?;
            }
            for pattern in &group.regex {
                rules.allow_regex.push(
                    regex::Regex::new(pattern).map_err(|e| invalid("allow.regex", pattern, e))?,
                );
            }
            allow.push(AllowGroup { sources, rules });
        }
        Ok(Self { unfiltered, allow })
    }

    pub fn is_empty(&self) -> bool {
        self.unfiltered.is_empty() && self.allow.is_empty()
    }

    /// A client-specific decision that overrides global rules, if any.
    /// Bypass beats per-client allow; neither ever blocks.
    pub fn check(&self, client: IpAddr, domain: &str) -> Option<MatchOutcome> {
        if self.is_empty() {
            return None;
        }
        let client = client.to_canonical();
        if let Some((_, entry)) = self.unfiltered.iter().find(|(net, _)| net.contains(client)) {
            return Some(MatchOutcome::Bypassed(format!("client_bypass:{entry}")));
        }
        self.allow
            .iter()
            .filter(|group| group.sources.iter().any(|net| net.contains(client)))
            .find_map(|group| match group.rules.check(domain) {
                MatchOutcome::Allowed(rule) => {
                    Some(MatchOutcome::Allowed(format!("client_{rule}")))
                }
                _ => None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientAllowConfig;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn ipnet_matches_addresses_and_ranges() {
        let single = IpNet::parse("192.168.2.54").unwrap();
        assert!(single.contains(ip("192.168.2.54")));
        assert!(!single.contains(ip("192.168.2.55")));
        let range = IpNet::parse("192.168.2.0/24").unwrap();
        assert!(range.contains(ip("192.168.2.200")));
        assert!(!range.contains(ip("192.168.3.1")));
        assert!(IpNet::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        let v6 = IpNet::parse("fd00::/8").unwrap();
        assert!(v6.contains(ip("fd12::1")));
        assert!(!v6.contains(ip("fe80::1")));
        assert!(!v6.contains(ip("192.168.2.54")));
        for bad in [
            "192.168.2.300",
            "192.168.2.0/33",
            "fd00::/129",
            "host",
            "1.2.3.4/x",
        ] {
            assert!(IpNet::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ipv4_mapped_clients_match_ipv4_entries() {
        let cfg = ClientsConfig {
            unfiltered: strings(&["192.168.2.54"]),
            allow: vec![],
        };
        let policy = ClientPolicy::from_config(&cfg).unwrap();
        assert!(policy.check(ip("::ffff:192.168.2.54"), "x.test").is_some());
    }

    #[test]
    fn bypass_then_per_client_allow_then_none() {
        let cfg = ClientsConfig {
            unfiltered: strings(&["192.168.2.53", "192.168.2.54"]),
            allow: vec![
                ClientAllowConfig {
                    sources: strings(&["192.168.2.60", "10.0.0.0/8"]),
                    domains: strings(&["exact.test", "||suffix.test^"]),
                    regex: strings(&[r"^re\.test$"]),
                },
                ClientAllowConfig {
                    sources: strings(&["192.168.2.61"]),
                    domains: strings(&["other.test"]),
                    regex: vec![],
                },
            ],
        };
        let policy = ClientPolicy::from_config(&cfg).unwrap();
        assert_eq!(
            policy.check(ip("192.168.2.54"), "ads.test"),
            Some(MatchOutcome::Bypassed("client_bypass:192.168.2.54".into()))
        );
        let kid = ip("192.168.2.60");
        assert_eq!(
            policy.check(kid, "EXACT.test"),
            Some(MatchOutcome::Allowed("client_allow:exact.test".into()))
        );
        assert_eq!(policy.check(kid, "sub.exact.test"), None);
        assert_eq!(
            policy.check(kid, "a.suffix.test"),
            Some(MatchOutcome::Allowed(
                "client_allow_suffix:suffix.test".into()
            ))
        );
        assert_eq!(
            policy.check(ip("10.1.2.3"), "re.test"),
            Some(MatchOutcome::Allowed(
                r"client_allow_regex:^re\.test$".into()
            ))
        );
        assert_eq!(policy.check(kid, "other.test"), None);
        assert!(policy.check(ip("192.168.2.61"), "other.test").is_some());
        assert_eq!(policy.check(ip("192.168.2.99"), "exact.test"), None);
    }

    #[test]
    fn invalid_entries_are_rejected() {
        let group = |sources: &[&str], domains: &[&str], regex: &[&str]| ClientsConfig {
            unfiltered: vec![],
            allow: vec![ClientAllowConfig {
                sources: strings(sources),
                domains: strings(domains),
                regex: strings(regex),
            }],
        };
        let bad = [
            ClientsConfig {
                unfiltered: strings(&["not-an-ip"]),
                allow: vec![],
            },
            group(&[], &["a.test"], &[]),
            group(&["10.0.0.1"], &[], &[]),
            group(&["10.0.0.300"], &["a.test"], &[]),
            group(&["10.0.0.1"], &["*.a.test"], &[]),
            group(&["10.0.0.1"], &["||"], &[]),
            group(&["10.0.0.1"], &[], &["[unclosed"]),
        ];
        for cfg in bad {
            assert!(ClientPolicy::from_config(&cfg).is_err(), "{cfg:?}");
        }
        assert!(ClientPolicy::from_config(&ClientsConfig::default())
            .unwrap()
            .is_empty());
    }
}
