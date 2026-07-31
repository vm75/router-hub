use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};

use regex::Regex as CaptureRegex;
use regex_automata::{
    Input, MatchError,
    hybrid::dfa::{Cache as HybridCache, Config as HybridConfig, DFA as HybridDfa},
};

use crate::ban_attack::{Error, RuleConfig};

pub(crate) struct CompiledRule {
    pub name: String,
    pub weight: u64,
    fast: HybridDfa,
    cache: HybridCache,
    captures: CaptureRegex,
    ip_group_index: usize,
    filters: Vec<(usize, HashSet<String>)>,
    named_groups: Vec<(String, usize)>,
}

#[derive(Debug)]
pub(crate) struct RuleHit {
    pub ip: IpAddr,
    pub groups: BTreeMap<String, String>,
}

impl CompiledRule {
    pub fn compile(
        config: &RuleConfig,
        dfa_cache_bytes: usize,
        regex_size_limit_bytes: usize,
    ) -> Result<Self, Error> {
        if config.name.trim().is_empty() {
            return Err(Error::Config("rule names cannot be empty".to_owned()));
        }
        if config.weight == 0 {
            return Err(Error::Config(format!(
                "rule `{}` has a zero weight",
                config.name
            )));
        }

        let fast = HybridDfa::builder()
            .configure(HybridConfig::new().cache_capacity(dfa_cache_bytes))
            .build(&config.regex)
            .map_err(|error| Error::Rule {
                rule: config.name.clone(),
                message: error.to_string(),
            })?;
        let cache = fast.create_cache();

        let captures = regex::RegexBuilder::new(&config.regex)
            .size_limit(regex_size_limit_bytes)
            .dfa_size_limit(dfa_cache_bytes)
            .build()
            .map_err(|error| Error::Rule {
                rule: config.name.clone(),
                message: error.to_string(),
            })?;

        let named_groups: Vec<(String, usize)> = captures
            .capture_names()
            .enumerate()
            .filter_map(|(index, name)| name.map(|name| (name.to_owned(), index)))
            .collect();

        let ip_group_index = named_groups
            .iter()
            .find_map(|(name, index)| (name == &config.ip_group).then_some(*index))
            .ok_or_else(|| {
                Error::Config(format!(
                    "rule `{}` does not define named IP group `{}`",
                    config.name, config.ip_group
                ))
            })?;

        let mut filters = Vec::with_capacity(config.group_values.len());
        for (group, values) in &config.group_values {
            if values.is_empty() {
                return Err(Error::Config(format!(
                    "rule `{}` has an empty value list for group `{group}`",
                    config.name
                )));
            }
            let index = named_groups
                .iter()
                .find_map(|(name, index)| (name == group).then_some(*index))
                .ok_or_else(|| {
                    Error::Config(format!(
                        "rule `{}` filters unknown group `{group}`",
                        config.name
                    ))
                })?;
            filters.push((index, values.iter().cloned().collect()));
        }

        Ok(Self {
            name: config.name.clone(),
            weight: config.weight,
            fast,
            cache,
            captures,
            ip_group_index,
            filters,
            named_groups,
        })
    }

    pub fn match_line(&mut self, line: &str) -> Result<Option<RuleHit>, MatchError> {
        if self
            .fast
            .try_search_fwd(&mut self.cache, &Input::new(line))?
            .is_none()
        {
            return Ok(None);
        }

        let Some(captures) = self.captures.captures(line) else {
            return Ok(None);
        };
        for (index, allowed) in &self.filters {
            let Some(value) = captures.get(*index) else {
                return Ok(None);
            };
            if !allowed.contains(value.as_str()) {
                return Ok(None);
            }
        }

        let Some(ip_capture) = captures.get(self.ip_group_index) else {
            return Ok(None);
        };
        let Ok(ip) = ip_capture.as_str().parse::<IpAddr>() else {
            return Ok(None);
        };
        let groups = self
            .named_groups
            .iter()
            .filter_map(|(name, index)| {
                captures
                    .get(*index)
                    .map(|value| (name.clone(), value.as_str().to_owned()))
            })
            .collect();

        Ok(Some(RuleHit { ip, groups }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn hybrid_prefilter_then_captures_and_filters() {
        let mut group_values = BTreeMap::new();
        group_values.insert("result".to_owned(), vec!["failed".to_owned()]);
        let config = RuleConfig {
            name: "login".to_owned(),
            regex: r"result=(?P<result>\w+) ip=(?P<ip>[0-9.]+)".to_owned(),
            ip_group: "ip".to_owned(),
            group_values,
            weight: 2,
        };
        let mut rule = CompiledRule::compile(&config, 1024 * 1024, 1024 * 1024).unwrap();

        assert!(
            rule.match_line("result=failed ip=192.0.2.10")
                .unwrap()
                .is_some()
        );
        assert!(
            rule.match_line("result=success ip=192.0.2.10")
                .unwrap()
                .is_none()
        );
    }
}
