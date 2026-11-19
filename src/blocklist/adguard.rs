use std::collections::HashSet;

use crate::dns::qtype_from_name;

/// A dollar sign inside /regex/ is part of the expression.
pub(super) fn split_options(pattern: &str) -> (&str, Option<&str>) {
    if pattern.starts_with('/') {
        for (end, _) in pattern.match_indices("/$") {
            let escapes = pattern[..end]
                .bytes()
                .rev()
                .take_while(|&b| b == b'\\')
                .count();
            if end > 0 && escapes % 2 == 0 {
                return (&pattern[..=end], Some(&pattern[end + 2..]));
            }
        }
        return (pattern, None);
    }
    pattern
        .split_once('$')
        .map_or((pattern, None), |(p, o)| (p, Some(o)))
}

fn badfilter_target(pattern: &str) -> Option<String> {
    let (base, options) = split_options(pattern);
    if base.is_empty() || (!base.starts_with('/') && base.contains(char::is_whitespace)) {
        return None;
    }
    let mut remaining = Vec::new();
    let mut disables = false;
    for option in options?.split(',') {
        match option {
            "" => return None,
            "badfilter" if disables => return None,
            "badfilter" => disables = true,
            other => remaining.push(other),
        }
    }
    disables.then(|| {
        if remaining.is_empty() {
            base.to_owned()
        } else {
            format!("{base}${}", remaining.join(","))
        }
    })
}

pub(super) fn disabled_target(line: &str) -> Option<String> {
    let line = line.trim();
    if line.starts_with(['!', '#']) || !line.contains("badfilter") {
        return None;
    }
    if let Some(pattern) = line.strip_prefix("@@") {
        badfilter_target(pattern).map(|target| format!("@@{target}"))
    } else {
        badfilter_target(line)
    }
}

/// Collect exact rule text before compiling any domain feed. This avoids
/// storing a second copy of every rule just to support a few cancellations.
#[derive(Default)]
pub(crate) struct DisabledRules {
    allowed: HashSet<String>,
    blocked: HashSet<String>,
}

impl DisabledRules {
    pub(crate) fn collect<'a>(&mut self, lines: impl Iterator<Item = &'a str>, as_allow: bool) {
        for line in lines {
            let Some(target) = disabled_target(line) else {
                continue;
            };
            let line = line.trim();
            let disabled = if as_allow || line.starts_with("@@") {
                &mut self.allowed
            } else {
                &mut self.blocked
            };
            disabled.insert(target);
            disabled.insert(line.to_owned());
        }
    }

    pub(crate) fn skips(&self, line: &str, as_allow: bool) -> bool {
        let line = line.trim();
        if as_allow || line.starts_with("@@") {
            self.allowed.contains(line)
        } else {
            self.blocked.contains(line)
        }
    }
}

#[derive(Debug)]
pub(super) struct TypedRule {
    pub(super) text: String,
    pub(super) allow: bool,
    types: Vec<u16>,
    exclude: bool,
}

impl TypedRule {
    pub(super) fn parse(text: &str, allow: bool, options: &str) -> Result<Self, String> {
        let values = options
            .strip_prefix("dnstype=")
            .ok_or_else(|| format!("unsupported AdGuard modifier {options:?}"))?;
        let mut included = Vec::new();
        let mut excluded = Vec::new();
        for value in values.split('|') {
            let (name, types) = match value.strip_prefix('~') {
                Some(name) => (name, &mut excluded),
                None => (value, &mut included),
            };
            types.push(
                qtype_from_name(name).ok_or_else(|| format!("unsupported dnstype {name:?}"))?,
            );
        }
        let exclude = included.is_empty();
        Ok(Self {
            text: text.to_owned(),
            allow,
            types: if exclude { excluded } else { included },
            exclude,
        })
    }

    pub(super) fn matches(&self, qtype: u16) -> bool {
        self.types.contains(&qtype) != self.exclude
    }
}
