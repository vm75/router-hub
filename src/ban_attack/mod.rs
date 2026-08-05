//! `ban-attack` module for Router Hub.
//!
//! It tails configured files, screens rules with `regex-automata`'s hybrid
//! lazy DFA, extracts named captures only after a match, aggregates failures by
//! IP and subnet, and manages bans in `ipset` `hash:net` sets and `iptables`/`ip6tables` rules.

mod aggregate;
mod backend;
mod compiled;
mod config;
mod engine;
mod error;
mod rule;
mod tailer;

#[allow(unused_imports)]
pub use aggregate::{ActiveBan, Aggregator, PersistentState, RuleStats, RuleStatsEntry, Snapshot};
#[allow(unused_imports)]
pub use backend::{BanBackend, BanTarget, CommandIpSet, MemoryBanBackend};
#[allow(unused_imports)]
pub use config::{
    AggregationConfig, Config, FileConfig, FirewallConfig, IpSetConfig, RuleConfig, StartAt,
};
#[allow(unused_imports)]
pub use engine::{BanEngine, EngineEvent, EngineHandle, EngineHealth, EngineState, EngineStatus};
#[allow(unused_imports)]
pub use error::{BackendError, Error};

pub(crate) fn validate_config(config: Config) -> Result<(), Error> {
    compiled::CompiledConfig::compile(config).map(|_| ())
}
