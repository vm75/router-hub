#!/usr/bin/env python3
from pathlib import Path


def replace(path: str, old: str, new: str, count: int = 1) -> None:
    file = Path(path)
    text = file.read_text()
    actual = text.count(old)
    if actual != count:
        raise SystemExit(
            f"{path}: expected {count} occurrence(s), found {actual}: {old[:80]!r}"
        )
    file.write_text(text.replace(old, new, count))


replace(
    "src/analytics/mod.rs",
    "use tracing::{info, warn};",
    "use tracing::warn;",
)
replace(
    "src/analytics/mod.rs",
    """                    self.overhead.lock().samples_dropped =
                        self.overhead.lock().samples_dropped.saturating_add(1);""",
    """                    let mut overhead = self.overhead.lock();
                    overhead.samples_dropped = overhead.samples_dropped.saturating_add(1);""",
)
replace(
    "src/analytics/mod.rs",
    """                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {},
                    _ = self.notify.notified() => {},
                }
                continue;""",
    """                self.notify.notified().await;
                continue;""",
)
replace(
    "src/analytics/mod.rs",
    """            for (name, (matches, bans)) in &status.snapshot.rule_stats {
                let (previous_matches, previous_bans) = previous
                    .rule_stats
                    .get(name)
                    .copied()
                    .unwrap_or((matches.match_count, matches.ban_count));
                let match_delta = counter_delta(matches.match_count, previous_matches);
                let ban_delta = counter_delta(matches.ban_count, previous_bans);""",
    """            for (name, stats) in &status.snapshot.rule_stats {
                let (previous_matches, previous_bans) = previous
                    .rule_stats
                    .get(name)
                    .copied()
                    .unwrap_or((stats.match_count, stats.ban_count));
                let match_delta = counter_delta(stats.match_count, previous_matches);
                let ban_delta = counter_delta(stats.ban_count, previous_bans);""",
)
replace(
    "src/analytics/mod.rs",
    """        self.overhead.lock().external_commands =
            self.overhead.lock().external_commands.saturating_add(1);""",
    """        {
            let mut overhead = self.overhead.lock();
            overhead.external_commands = overhead.external_commands.saturating_add(1);
        }""",
    count=2,
)
replace(
    "src/analytics/mod.rs",
    """        self.overhead.lock().ai_requests_attempted =
            self.overhead.lock().ai_requests_attempted.saturating_add(1);""",
    """        {
            let mut overhead = self.overhead.lock();
            overhead.ai_requests_attempted = overhead.ai_requests_attempted.saturating_add(1);
        }""",
)
replace(
    "src/analytics/mod.rs",
    """                self.overhead.lock().ai_requests_failed =
                    self.overhead.lock().ai_requests_failed.saturating_add(1);""",
    """                let mut overhead = self.overhead.lock();
                overhead.ai_requests_failed = overhead.ai_requests_failed.saturating_add(1);""",
)
replace(
    "src/analytics/mod.rs",
    """        EngineEvent::Match {
            rule, ip, groups, ..
        } => {
            let (request_method, request_path) = parse_request_line(""",
    """        EngineEvent::Match {
            rule, ip, groups, ..
        } => {
            if !ingress.collect_samples.load(Ordering::Relaxed) {
                return;
            }
            let (request_method, request_path) = parse_request_line(""",
)
replace(
    "src/analytics/mod.rs",
    """                method: ingress
                    .collect_samples
                    .load(Ordering::Relaxed)
                    .then_some(method)
                    .flatten(),
                path: ingress
                    .collect_samples
                    .load(Ordering::Relaxed)
                    .then_some(path)
                    .flatten(),""",
    """                method,
                path,""",
)
replace(
    "src/ban_attack/engine.rs",
    """    fn emit(&mut self, event: EngineEvent) {
        match event {""",
    """    fn emit(&mut self, event: EngineEvent) {
        crate::analytics::record_engine_event(&event);
        match event {""",
)
replace(
    "src/asus_ui.rs",
    """    let initial_refresh = "    refreshCurrent();";
    let analytics_script = format!("{ANALYTICS_JS}\\n{initial_refresh}");

    source
        .replace(desktop_anchor, &desktop_tabs)
        .replace(sidebar_anchor, &sidebar_tabs)
        .replace(title_anchor, titles)
        .replace(refresh_anchor, refresh)
        .replace(pane_anchor, &pane)
        .replacen(initial_refresh, &analytics_script, 1)""",
    """    let script_anchor = "    setInterval(pollSystemUsage, 1000);\\n\\n    refreshCurrent();";
    let analytics_script = format!(
        "    setInterval(pollSystemUsage, 1000);\\n\\n{ANALYTICS_JS}\\n    refreshCurrent();"
    );

    source
        .replace(desktop_anchor, &desktop_tabs)
        .replace(sidebar_anchor, &sidebar_tabs)
        .replace(title_anchor, titles)
        .replace(refresh_anchor, refresh)
        .replace(pane_anchor, &pane)
        .replace(script_anchor, &analytics_script)""",
)
