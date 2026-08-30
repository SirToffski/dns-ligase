use std::collections::HashSet;
use std::error::Error;
use regex::Regex;

#[derive(Debug, Default)]
pub struct Blocklist {
    pub allow_domains: HashSet<String>,
    pub block_domains: HashSet<String>,
    pub allow_regex: Vec<Regex>,
    pub block_regex: Vec<Regex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ListFormat {
    Hosts,
    AdBlock,
    PiHole,
    AdGuard,
}

impl Blocklist {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.allow_domains.clear();
        self.block_domains.clear();
        self.allow_regex.clear();
        self.block_regex.clear();
    }

    pub fn parse_line(&mut self, line: &str, format: ListFormat) -> Result<(), Box<dyn Error>> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            return Ok(());
        }

        match format {
            ListFormat::Hosts | ListFormat::PiHole => {
                if let Some(domain) = Self::clean_domain_static(line) {
                    self.block_domains.insert(domain.to_lowercase());
                }
            }
            ListFormat::AdBlock | ListFormat::AdGuard => {
                let is_allow = line.starts_with("@@");
                let pattern_part = if is_allow {
                    line.trim_start_matches("@@")
                } else {
                    line
                };

                if pattern_part.starts_with("||") {
                    let pattern = pattern_part.trim_start_matches("||").trim_end_matches('^');
                    let escaped = regex::escape(pattern);
                    let re_str = format!(r"^(?:.*\.)?{}", escaped);
                    let re = Regex::new(&re_str)?;
                    if is_allow {
                        self.allow_regex.push(re);
                    } else {
                        self.block_regex.push(re);
                    }
                } else if pattern_part.starts_with('/') && pattern_part.ends_with('/') {
                    let pattern = &pattern_part[1..pattern_part.len() - 1];
                    let re = Regex::new(pattern)?;
                    if is_allow {
                        self.allow_regex.push(re);
                    } else {
                        self.block_regex.push(re);
                    }
                } else {
                    if let Some(domain) = Self::clean_domain_static(pattern_part) {
                        let domain_lower = domain.to_lowercase();
                        if is_allow {
                            self.allow_domains.insert(domain_lower);
                        } else {
                            self.block_domains.insert(domain_lower);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn parse_auto(&mut self, line: &str) -> Result<(), Box<dyn Error>> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            return Ok(());
        }

        if line.starts_with("||") || line.starts_with("@@") || (line.starts_with('/') && line.ends_with('/')) {
            self.parse_line(line, ListFormat::AdBlock)
        } else {
            self.parse_line(line, ListFormat::Hosts)
        }
    }

    pub async fn fetch_and_parse(&mut self, url: &str, format: Option<ListFormat>) -> Result<(), Box<dyn Error>> {
        let content = reqwest::get(url).await?.text().await?;
        for line in content.lines() {
            match format {
                Some(f) => self.parse_line(line, f)?,
                None => self.parse_auto(line)?,
            }
        }
        Ok(())
    }

    fn clean_domain_static(domain: &str) -> Option<String> {
        let domain = domain.split('#').next()?.trim();
        if domain.is_empty() {
            return None;
        }

        let parts: Vec<&str> = domain.split_whitespace().collect();
        let target = if parts.len() > 1 {
            parts.last().unwrap()
        } else {
            parts[0]
        };

        let cleaned = target.trim_end_matches('.');
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned.to_string())
        }
    }

    pub fn matches(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        if self.allow_domains.contains(&domain_lower) {
            return false; 
        }
        for re in &self.allow_regex {
            if re.is_match(&domain_lower) {
                return false; 
            }
        }
        if self.block_domains.contains(&domain_lower) {
            return true;
        }
        for re in &self.block_regex {
            if re.is_match(&domain_lower) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hosts_format() {
        let mut bl = Blocklist::new();
        bl.parse_line("example.com", ListFormat::Hosts).unwrap();
        bl.parse_line("  sub.example.org  ", ListFormat::Hosts).unwrap();
        bl.parse_line("! comment", ListFormat::Hosts).unwrap();
        bl.parse_line("# comment", ListFormat::Hosts).unwrap();
        assert!(bl.matches("example.com"));
        assert!(bl.matches("sub.example.org"));
        assert!(!bl.matches("google.com"));
    }

    #[test]
    fn test_adblock_format() {
        let mut bl = Blocklist::new();
        bl.parse_line("||ads.com^", ListFormat::AdBlock).unwrap();
        bl.parse_line("/track\\.me/", ListFormat::AdBlock).unwrap(); 
        assert!(bl.matches("ads.com"));
        assert!(bl.matches("sub.ads.com"));
        assert!(bl.matches("track.me"));
        assert!(!bl.matches("google.com"));
    }

    #[test]
    fn test_allow_precedence() {
        let mut bl = Blocklist::new();
        bl.parse_line("||ads.com^", ListFormat::AdBlock).unwrap();
        bl.parse_line("@@||sub.ads.com^", ListFormat::AdBlock).unwrap();
        assert!(bl.matches("ads.com"));
        assert!(!bl.matches("sub.ads.com"));
        assert!(bl.matches("other.ads.com"));
    }

    #[test]
    fn test_regex_allow() {
        let mut bl = Blocklist::new();
        bl.parse_line("||ads.com^", ListFormat::AdBlock).unwrap();
        bl.parse_line("/^safe\\.com$/", ListFormat::AdBlock).unwrap(); 
        bl.parse_line("@@/^safe\\.com$/", ListFormat::AdBlock).unwrap();
        assert!(bl.matches("ads.com"));
        assert!(!bl.matches("safe.com"));
    }

    #[test]
    fn test_ip_prefix_format() {
        let mut bl = Blocklist::new();
        bl.parse_line("0.0.0.0 ads.example.com", ListFormat::Hosts).unwrap();
        assert!(bl.matches("ads.example.com"));
    }

    #[test]
    fn test_direct_match() {
        let mut bl = Blocklist::new();
        bl.parse_line("direct.com", ListFormat::AdBlock).unwrap();
        assert!(bl.matches("direct.com"));
        assert!(!bl.matches("sub.direct.com"));
    }

    #[test]
    fn test_auto_detect() {
        let mut bl = Blocklist::new();
        bl.parse_auto("||ads.com^").unwrap();
        assert!(bl.matches("sub.ads.com"));
        
        let mut bl2 = Blocklist::new();
        bl2.parse_auto("example.com").unwrap();
        assert!(bl2.matches("example.com"));
    }

    #[test]
    fn test_all_formats() {
        let formats = [
            ListFormat::Hosts,
            ListFormat::AdBlock,
            ListFormat::PiHole,
            ListFormat::AdGuard,
        ];
        for format in formats {
            let mut bl = Blocklist::new();
            bl.parse_line("example.com", format).unwrap();
            assert!(bl.matches("example.com"), "Failed for {:?}", format);
        }
    }
}
