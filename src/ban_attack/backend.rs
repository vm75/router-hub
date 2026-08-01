use std::{
    collections::HashSet,
    ffi::OsStr,
    io::{Read, Write},
    net::IpAddr,
    path::Path,
    process::{Command, Output, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use ipnet::IpNet;

use crate::ban_attack::{BackendError, FirewallConfig, IpSetConfig};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BanTarget {
    Ip(IpAddr),
    Subnet(IpNet),
}

impl BanTarget {
    fn entry(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Subnet(net) => net.to_string(),
        }
    }

    fn is_ipv4(&self) -> bool {
        match self {
            Self::Ip(ip) => ip.is_ipv4(),
            Self::Subnet(net) => net.addr().is_ipv4(),
        }
    }
}

pub trait BanBackend: Send + Sync + 'static {
    fn ensure(&self) -> Result<(), BackendError>;
    fn add(&self, target: &BanTarget) -> Result<(), BackendError>;
    fn remove(&self, target: &BanTarget) -> Result<(), BackendError>;

    fn set_exceptions(&self, _exceptions: &[IpNet]) -> Result<(), BackendError> {
        Ok(())
    }

    fn reconcile(
        &self,
        active: &[BanTarget],
        exceptions: &[IpNet],
    ) -> Result<ReconcileReport, BackendError> {
        self.ensure()?;
        self.set_exceptions(exceptions)?;
        for target in active {
            self.add(target)?;
        }
        Ok(ReconcileReport {
            restored_entries: active.len(),
            repaired: true,
        })
    }

    fn disable(&self) -> Result<(), BackendError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub restored_entries: usize,
    pub repaired: bool,
}

const INPUT_CHAIN: &str = "ROUTER_HUB_INPUT";
const FORWARD_CHAIN: &str = "ROUTER_HUB_FORWARD";
const RULE_COMMENT: &str = "router-hub:ban-attack";
const MAX_RESTORE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug)]
pub struct CommandIpSet {
    config: IpSetConfig,
    firewall: FirewallConfig,
    test_mode: bool,
    exceptions: Mutex<HashSet<IpNet>>,
}

impl CommandIpSet {
    #[allow(dead_code)]
    pub fn new(config: IpSetConfig) -> Self {
        Self {
            config,
            firewall: FirewallConfig::default(),
            test_mode: false,
            exceptions: Mutex::new(HashSet::new()),
        }
    }

    pub fn new_with_options(
        config: IpSetConfig,
        firewall: FirewallConfig,
        test_mode: bool,
    ) -> Self {
        Self {
            config,
            firewall,
            test_mode,
            exceptions: Mutex::new(HashSet::new()),
        }
    }

    fn set_for(&self, target: &BanTarget) -> &str {
        if target.is_ipv4() {
            &self.config.v4_set
        } else {
            &self.config.v6_set
        }
    }

    fn run_cmd<I, S>(&self, program: &Path, args: I) -> Result<(), BackendError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        if self.test_mode {
            return Ok(());
        }

        let output = self.run_output(program, args, None)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err(BackendError(format!(
            "{} exited with {}{}",
            program.display(),
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        )))
    }

    fn run_output<I, S>(
        &self,
        program: &Path,
        args: I,
        stdin: Option<&[u8]>,
    ) -> Result<Output, BackendError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        if self.test_mode {
            return Ok(simulated_output());
        }
        if stdin.is_some_and(|bytes| bytes.len() > MAX_RESTORE_BYTES) {
            return Err(BackendError("bounded command stdin exceeded".to_owned()));
        }
        let mut command = Command::new(program);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().map_err(|error| {
            BackendError(format!("failed to execute {}: {error}", program.display()))
        })?;
        let stdin_writer = if let Some(bytes) = stdin {
            let mut pipe = child
                .stdin
                .take()
                .ok_or_else(|| BackendError("command stdin unavailable".to_owned()))?;
            let bytes = bytes.to_vec();
            Some(thread::spawn(move || pipe.write_all(&bytes)))
        } else {
            None
        };
        let stdout_reader = child.stdout.take().map(|mut pipe| {
            thread::spawn(move || {
                let mut bytes = Vec::new();
                let result = pipe.read_to_end(&mut bytes);
                (result, bytes)
            })
        });
        let stderr_reader = child.stderr.take().map(|mut pipe| {
            thread::spawn(move || {
                let mut bytes = Vec::new();
                let result = pipe.read_to_end(&mut bytes);
                (result, bytes)
            })
        });
        let deadline =
            Instant::now() + Duration::from_secs(self.firewall.command_timeout_seconds.max(1));
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(reader) = stdout_reader {
                        let _ = reader.join();
                    }
                    if let Some(reader) = stderr_reader {
                        let _ = reader.join();
                    }
                    if let Some(writer) = stdin_writer {
                        let _ = writer.join();
                    }
                    return Err(BackendError(format!(
                        "{} timed out after {} seconds",
                        program.display(),
                        self.firewall.command_timeout_seconds.max(1)
                    )));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(BackendError(format!(
                        "failed while waiting for {}: {error}",
                        program.display()
                    )));
                }
            }
        };
        if let Some(writer) = stdin_writer {
            writer
                .join()
                .map_err(|_| BackendError("command stdin writer panicked".to_owned()))?
                .map_err(|error| BackendError(format!("failed to write command stdin: {error}")))?;
        }
        let stdout = join_reader(stdout_reader, "stdout")?;
        let stderr = join_reader(stderr_reader, "stderr")?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    fn command_succeeds<I, S>(&self, program: &Path, args: I) -> Result<bool, BackendError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Ok(self.run_output(program, args, None)?.status.success())
    }

    fn run_ipset<I, S>(&self, args: I) -> Result<(), BackendError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.run_cmd(&self.config.command, args)
    }

    fn ensure_set(&self, name: &str, family: &str) -> Result<(), BackendError> {
        let max_entries = self.config.max_entries.to_string();
        self.run_ipset([
            "-exist",
            "create",
            name,
            "hash:net",
            "family",
            family,
            "maxelem",
            &max_entries,
        ])?;
        if !self.test_mode {
            let output = self.run_output(&self.config.command, ["list", name], None)?;
            let description = String::from_utf8_lossy(&output.stdout);
            if !output.status.success()
                || !description.contains("Type: hash:net")
                || !description.contains(&format!("family {family}"))
                || !description.contains(&format!("maxelem {}", self.config.max_entries))
            {
                return Err(BackendError(format!(
                    "ipset `{name}` has an incompatible type, family, or capacity"
                )));
            }
        }
        Ok(())
    }

    fn ensure_owned_chain(
        &self,
        command: &Path,
        parent: &str,
        owned: &str,
        set_name: &str,
    ) -> Result<(), BackendError> {
        if self.test_mode {
            return Ok(());
        }

        if !self.command_succeeds(command, ["-nL", owned])? {
            self.run_cmd(command, ["-N", owned])?;
        }
        if !self.command_succeeds(
            command,
            [
                "-C",
                owned,
                "-m",
                "set",
                "--match-set",
                set_name,
                "src",
                "-m",
                "comment",
                "--comment",
                RULE_COMMENT,
                "-j",
                "DROP",
            ],
        )? {
            self.run_cmd(
                command,
                [
                    "-I",
                    owned,
                    "1",
                    "-m",
                    "set",
                    "--match-set",
                    set_name,
                    "src",
                    "-m",
                    "comment",
                    "--comment",
                    RULE_COMMENT,
                    "-j",
                    "DROP",
                ],
            )?;
        }
        let hook = [
            "-C",
            parent,
            "-m",
            "comment",
            "--comment",
            RULE_COMMENT,
            "-j",
            owned,
        ];
        if self.command_succeeds(command, hook)? {
            self.run_cmd(
                command,
                [
                    "-D",
                    parent,
                    "-m",
                    "comment",
                    "--comment",
                    RULE_COMMENT,
                    "-j",
                    owned,
                ],
            )?;
        }
        self.run_cmd(
            command,
            [
                "-I",
                parent,
                "1",
                "-m",
                "comment",
                "--comment",
                RULE_COMMENT,
                "-j",
                owned,
            ],
        )?;
        Ok(())
    }

    fn remove_hook(&self, command: &Path, parent: &str, owned: &str) -> Result<(), BackendError> {
        if self.test_mode {
            return Ok(());
        }
        let args = [
            "-C",
            parent,
            "-m",
            "comment",
            "--comment",
            RULE_COMMENT,
            "-j",
            owned,
        ];
        if self.command_succeeds(command, args)? {
            self.run_cmd(
                command,
                [
                    "-D",
                    parent,
                    "-m",
                    "comment",
                    "--comment",
                    RULE_COMMENT,
                    "-j",
                    owned,
                ],
            )?;
        }
        Ok(())
    }

    fn set_exception(&self, network: IpNet) -> Result<(), BackendError> {
        let target = BanTarget::Subnet(network);
        let entry = network.to_string();
        self.run_ipset(["-exist", "add", self.set_for(&target), &entry, "nomatch"])?;

        if self.test_mode {
            return Ok(());
        }

        let output = self.run_output(
            &self.config.command,
            ["test", self.set_for(&target), &entry, "nomatch"],
            None,
        )?;
        if output.status.success() {
            Ok(())
        } else {
            Err(BackendError(format!(
                "exception `{network}` conflicts with an existing exact ban; unban it first"
            )))
        }
    }

    fn remove_exception(&self, network: IpNet) -> Result<(), BackendError> {
        let target = BanTarget::Subnet(network);
        let entry = network.to_string();

        if self.test_mode {
            return Ok(());
        }

        let test = self.run_output(
            &self.config.command,
            ["test", self.set_for(&target), &entry, "nomatch"],
            None,
        )?;
        if test.status.success() {
            self.run_ipset(["-exist", "del", self.set_for(&target), &entry])?;
        }
        Ok(())
    }

    fn restore_family(
        &self,
        live: &str,
        stage: &str,
        family: &str,
        active: &[BanTarget],
        exceptions: &[IpNet],
    ) -> Result<usize, BackendError> {
        if self.test_mode {
            return Ok(active
                .iter()
                .filter(|target| target.is_ipv4() == (family == "inet"))
                .count());
        }
        let _ = self.run_output(&self.config.command, ["destroy", stage], None)?;
        let max_entries = self.config.max_entries.to_string();
        self.run_ipset([
            "create",
            stage,
            "hash:net",
            "family",
            family,
            "maxelem",
            &max_entries,
        ])?;
        let family_is_v4 = family == "inet";
        let mut restore = String::new();
        let mut count = 0usize;
        for target in active
            .iter()
            .filter(|target| target.is_ipv4() == family_is_v4)
        {
            restore.push_str("add ");
            restore.push_str(stage);
            restore.push(' ');
            restore.push_str(&target.entry());
            restore.push('\n');
            count += 1;
        }
        for network in exceptions
            .iter()
            .filter(|network| network.addr().is_ipv4() == family_is_v4)
        {
            restore.push_str("add ");
            restore.push_str(stage);
            restore.push(' ');
            restore.push_str(&network.to_string());
            restore.push_str(" nomatch\n");
        }
        let output = self.run_output(
            &self.config.command,
            ["restore", "-exist"],
            Some(restore.as_bytes()),
        )?;
        if !output.status.success() {
            let _ = self.run_output(&self.config.command, ["destroy", stage], None);
            return Err(BackendError(format!(
                "ipset restore for `{live}` failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        self.run_ipset(["swap", stage, live])?;
        self.run_ipset(["destroy", stage])?;
        Ok(count)
    }
}

fn join_reader(
    reader: Option<thread::JoinHandle<(std::io::Result<usize>, Vec<u8>)>>,
    name: &str,
) -> Result<Vec<u8>, BackendError> {
    let Some(reader) = reader else {
        return Ok(Vec::new());
    };
    let (result, bytes) = reader
        .join()
        .map_err(|_| BackendError(format!("command {name} reader panicked")))?;
    result.map_err(|error| BackendError(format!("failed to read command {name}: {error}")))?;
    Ok(bytes)
}

#[cfg(unix)]
fn simulated_output() -> Output {
    use std::os::unix::process::ExitStatusExt;
    Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

impl BanBackend for CommandIpSet {
    fn ensure(&self) -> Result<(), BackendError> {
        if self.firewall.observe_only {
            return Ok(());
        }
        self.ensure_set(&self.config.v4_set, "inet")?;
        self.ensure_set(&self.config.v6_set, "inet6")?;

        if self.firewall.enabled {
            if self.firewall.protect_input {
                self.ensure_owned_chain(
                    &self.firewall.iptables_command,
                    "INPUT",
                    INPUT_CHAIN,
                    &self.config.v4_set,
                )?;
                self.ensure_owned_chain(
                    &self.firewall.ip6tables_command,
                    "INPUT",
                    INPUT_CHAIN,
                    &self.config.v6_set,
                )?;
            } else {
                self.remove_hook(&self.firewall.iptables_command, "INPUT", INPUT_CHAIN)?;
                self.remove_hook(&self.firewall.ip6tables_command, "INPUT", INPUT_CHAIN)?;
            }
            if self.firewall.protect_forward {
                self.ensure_owned_chain(
                    &self.firewall.iptables_command,
                    "FORWARD",
                    FORWARD_CHAIN,
                    &self.config.v4_set,
                )?;
                self.ensure_owned_chain(
                    &self.firewall.ip6tables_command,
                    "FORWARD",
                    FORWARD_CHAIN,
                    &self.config.v6_set,
                )?;
            } else {
                self.remove_hook(&self.firewall.iptables_command, "FORWARD", FORWARD_CHAIN)?;
                self.remove_hook(&self.firewall.ip6tables_command, "FORWARD", FORWARD_CHAIN)?;
            }
        }
        Ok(())
    }

    fn add(&self, target: &BanTarget) -> Result<(), BackendError> {
        if self.firewall.observe_only {
            return Ok(());
        }
        let entry = target.entry();
        self.run_ipset(["-exist", "add", self.set_for(target), &entry])
    }

    fn remove(&self, target: &BanTarget) -> Result<(), BackendError> {
        if self.firewall.observe_only {
            return Ok(());
        }
        let entry = target.entry();
        self.run_ipset(["-exist", "del", self.set_for(target), &entry])
    }

    fn set_exceptions(&self, exceptions: &[IpNet]) -> Result<(), BackendError> {
        if self.firewall.observe_only {
            *self
                .exceptions
                .lock()
                .map_err(|_| BackendError("ipset exception mutex poisoned".to_owned()))? =
                exceptions.iter().copied().collect();
            return Ok(());
        }
        let desired: HashSet<IpNet> = exceptions.iter().copied().collect();
        let mut current = self
            .exceptions
            .lock()
            .map_err(|_| BackendError("ipset exception mutex poisoned".to_owned()))?;

        let additions: Vec<IpNet> = desired.difference(&current).copied().collect();
        let removals: Vec<IpNet> = current.difference(&desired).copied().collect();

        for network in additions {
            self.set_exception(network)?;
            current.insert(network);
        }
        for network in removals {
            self.remove_exception(network)?;
            current.remove(&network);
        }
        Ok(())
    }

    fn reconcile(
        &self,
        active: &[BanTarget],
        exceptions: &[IpNet],
    ) -> Result<ReconcileReport, BackendError> {
        if self.firewall.observe_only {
            self.disable()?;
            return Ok(ReconcileReport {
                restored_entries: active.len(),
                repaired: false,
            });
        }
        self.ensure()?;
        let v4 = self.restore_family(
            &self.config.v4_set,
            "router_hub_stage4",
            "inet",
            active,
            exceptions,
        )?;
        let v6 = self.restore_family(
            &self.config.v6_set,
            "router_hub_stage6",
            "inet6",
            active,
            exceptions,
        )?;
        *self
            .exceptions
            .lock()
            .map_err(|_| BackendError("ipset exception mutex poisoned".to_owned()))? =
            exceptions.iter().copied().collect();
        Ok(ReconcileReport {
            restored_entries: v4 + v6,
            repaired: true,
        })
    }

    fn disable(&self) -> Result<(), BackendError> {
        self.remove_hook(&self.firewall.iptables_command, "INPUT", INPUT_CHAIN)?;
        self.remove_hook(&self.firewall.ip6tables_command, "INPUT", INPUT_CHAIN)?;
        self.remove_hook(&self.firewall.iptables_command, "FORWARD", FORWARD_CHAIN)?;
        self.remove_hook(&self.firewall.ip6tables_command, "FORWARD", FORWARD_CHAIN)?;
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct MemoryBanBackend {
    entries: Mutex<HashSet<BanTarget>>,
}

impl MemoryBanBackend {
    #[allow(dead_code)]
    pub fn entries(&self) -> HashSet<BanTarget> {
        self.entries
            .lock()
            .expect("memory backend mutex poisoned")
            .clone()
    }
}

impl BanBackend for MemoryBanBackend {
    fn ensure(&self) -> Result<(), BackendError> {
        Ok(())
    }

    fn add(&self, target: &BanTarget) -> Result<(), BackendError> {
        self.entries
            .lock()
            .map_err(|_| BackendError("memory backend mutex poisoned".to_owned()))?
            .insert(target.clone());
        Ok(())
    }

    fn remove(&self, target: &BanTarget) -> Result<(), BackendError> {
        self.entries
            .lock()
            .map_err(|_| BackendError("memory backend mutex poisoned".to_owned()))?
            .remove(target);
        Ok(())
    }

    fn reconcile(
        &self,
        active: &[BanTarget],
        _exceptions: &[IpNet],
    ) -> Result<ReconcileReport, BackendError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BackendError("memory backend mutex poisoned".to_owned()))?;
        entries.clear();
        entries.extend(active.iter().cloned());
        Ok(ReconcileReport {
            restored_entries: active.len(),
            repaired: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_reconciliation_replaces_stale_entries() {
        let backend = MemoryBanBackend::default();
        let stale = BanTarget::Ip("192.0.2.1".parse().unwrap());
        let desired = BanTarget::Subnet("198.51.100.0/24".parse().unwrap());
        backend.add(&stale).unwrap();

        let report = backend
            .reconcile(std::slice::from_ref(&desired), &[])
            .unwrap();

        assert_eq!(report.restored_entries, 1);
        assert_eq!(backend.entries(), HashSet::from([desired]));
    }

    // ---------------------------------------------------------------------------
    // Spy-script helpers for hook-placement tests.
    //
    // Each test creates a tiny shell script that appends its own name and
    // arguments to a log file.  CommandIpSet is built with test_mode=false and
    // all three tool paths pointing at this script, so every branch in ensure()
    // and disable() leaves a textual record that can be asserted on without
    // root or real iptables/ipset binaries.
    //
    // The script exits 0 for every invocation (simulating success).  For
    // ensure_owned_chain this means the -C parent hook check "succeeds" (rule
    // present), so the function issues -D then unconditionally -I.  For
    // remove_hook the -C success causes -D to be issued.  Assertions target
    // -I (install) and -D (remove) on the parent chain as the key signals.
    //
    // SERIALIZATION: WSL2 triggers ETXTBSY when multiple threads concurrently
    // execve() freshly-written shell scripts, even from distinct tempdirs.
    // Spy tests acquire SPY_LOCK before running to prevent the race.
    // ---------------------------------------------------------------------------

    static SPY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Writes the spy script to `dir` and returns its path.
    fn write_spy_script(dir: &std::path::Path, log: &std::path::Path) -> std::path::PathBuf {
        use std::io::Write;
        let script = dir.join("spy.sh");
        let log_str = log.to_str().unwrap();
        let content = format!(
            r#"#!/bin/sh
LOG="{log_str}"
printf '%s\n' "$0 $*" >> "$LOG"
# ipset list <name>: emit just enough for ensure_set verification
if [ "$1" = "list" ]; then
    printf 'Type: hash:net\nfamily inet\nfamily inet6\nmaxelem 65536\n'
fi
exit 0
"#
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o755)
                .open(&script)
                .unwrap();
            file.write_all(content.as_bytes()).unwrap();
            // sync_all() ensures the write handle is fully closed in the
            // kernel before any execve call, preventing ETXTBSY under
            // parallel test execution on Linux.
            file.sync_all().unwrap();
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&script, content).unwrap();
        }
        script
    }

    /// Reads recorded invocation lines from the spy log.
    fn spy_lines(log: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Returns true if any recorded line's arguments contain all of `needles`.
    fn any_line_contains(lines: &[String], needles: &[&str]) -> bool {
        lines
            .iter()
            .any(|line| needles.iter().all(|n| line.contains(n)))
    }

    fn make_ipset(spy: &std::path::Path, firewall: FirewallConfig) -> CommandIpSet {
        CommandIpSet::new_with_options(
            IpSetConfig {
                command: spy.to_path_buf(),
                v4_set: "rh_ban_v4".to_owned(),
                v6_set: "rh_ban_v6".to_owned(),
                max_entries: 65536,
            },
            firewall,
            false, // real mode — not test_mode
        )
    }

    // -------------------------------------------------------------------------
    // protect_forward = true (default)
    // -------------------------------------------------------------------------

    /// When protect_forward is true, ensure() must install the FORWARD chain
    /// hook for BOTH iptables (IPv4) and ip6tables (IPv6).
    #[test]
    fn protect_forward_true_installs_both_ipv4_and_ipv6_forward_hooks() {
        let _guard = SPY_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("spy.log");
        let spy = write_spy_script(dir.path(), &log);

        let backend = make_ipset(
            &spy,
            FirewallConfig {
                enabled: true,
                protect_input: false,
                protect_forward: true,
                iptables_command: spy.clone(),
                ip6tables_command: spy.clone(),
                ..FirewallConfig::default()
            },
        );
        backend.ensure().unwrap();

        let lines = spy_lines(&log);
        assert!(
            any_line_contains(&lines, &["FORWARD", FORWARD_CHAIN, "rh_ban_v4"]),
            "IPv4 FORWARD hook not installed;\nrecorded calls:\n{}",
            lines.join("\n")
        );
        assert!(
            any_line_contains(&lines, &["FORWARD", FORWARD_CHAIN, "rh_ban_v6"]),
            "IPv6 FORWARD hook not installed (Bug 1 regression);\nrecorded calls:\n{}",
            lines.join("\n")
        );
    }

    /// With protect_forward false, ensure() must issue remove_hook calls (-D)
    /// for FORWARD but must NOT install any FORWARD rules (-I).
    #[test]
    fn protect_forward_false_issues_remove_not_install() {
        let _guard = SPY_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("spy.log");
        let spy = write_spy_script(dir.path(), &log);

        let backend = make_ipset(
            &spy,
            FirewallConfig {
                enabled: true,
                protect_input: false,
                protect_forward: false,
                iptables_command: spy.clone(),
                ip6tables_command: spy.clone(),
                ..FirewallConfig::default()
            },
        );
        backend.ensure().unwrap();

        let lines = spy_lines(&log);
        // remove_hook checks for the parent hook with -C then issues -D;
        // the spy exits 0 for -C so -D must appear.
        assert!(
            any_line_contains(&lines, &["-D", "FORWARD", FORWARD_CHAIN]),
            "ensure() with protect_forward=false must call remove_hook (-D);\nrecorded calls:\n{}",
            lines.join("\n")
        );
        // No -I on the parent FORWARD chain (ensure_owned_chain not called).
        assert!(
            !any_line_contains(&lines, &["-I", "FORWARD"]),
            "ensure() with protect_forward=false must not insert any FORWARD rule;\nrecorded calls:\n{}",
            lines.join("\n")
        );
    }

    // -------------------------------------------------------------------------
    // protect_forward = false
    // -------------------------------------------------------------------------

    /// When protect_forward is false, ensure() must not install any FORWARD
    /// hook for either address family (Bug 2 regression guard).
    #[test]
    fn protect_forward_false_does_not_install_any_forward_hooks() {
        let _guard = SPY_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("spy.log");
        let spy = write_spy_script(dir.path(), &log);

        let backend = make_ipset(
            &spy,
            FirewallConfig {
                enabled: true,
                protect_input: false,
                protect_forward: false,
                iptables_command: spy.clone(),
                ip6tables_command: spy.clone(),
                ..FirewallConfig::default()
            },
        );
        backend.ensure().unwrap();

        let lines = spy_lines(&log);
        // -I inserts a rule; there must be no FORWARD insertion at all.
        assert!(
            !any_line_contains(&lines, &["-I", "FORWARD"]),
            "ensure() with protect_forward=false must not insert any FORWARD rule (Bug 2 regression);\nrecorded calls:\n{}",
            lines.join("\n")
        );
        // ip6tables FORWARD hook must specifically not be installed.
        assert!(
            !any_line_contains(&lines, &["FORWARD", FORWARD_CHAIN, "rh_ban_v6"]),
            "ensure() with protect_forward=false must not install the IPv6 FORWARD hook;\nrecorded calls:\n{}",
            lines.join("\n")
        );
    }

    // -------------------------------------------------------------------------
    // protect_input = true (symmetric correctness check)
    // -------------------------------------------------------------------------

    /// Both IPv4 and IPv6 INPUT hooks must be installed when protect_input=true.
    #[test]
    fn protect_input_true_installs_both_ipv4_and_ipv6_input_hooks() {
        let _guard = SPY_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("spy.log");
        let spy = write_spy_script(dir.path(), &log);

        let backend = make_ipset(
            &spy,
            FirewallConfig {
                enabled: true,
                protect_input: true,
                protect_forward: false,
                iptables_command: spy.clone(),
                ip6tables_command: spy.clone(),
                ..FirewallConfig::default()
            },
        );
        backend.ensure().unwrap();

        let lines = spy_lines(&log);
        assert!(
            any_line_contains(&lines, &["INPUT", INPUT_CHAIN, "rh_ban_v4"]),
            "IPv4 INPUT hook not installed;\nrecorded calls:\n{}",
            lines.join("\n")
        );
        assert!(
            any_line_contains(&lines, &["INPUT", INPUT_CHAIN, "rh_ban_v6"]),
            "IPv6 INPUT hook not installed;\nrecorded calls:\n{}",
            lines.join("\n")
        );
    }

    // -------------------------------------------------------------------------
    // disable()
    // -------------------------------------------------------------------------

    /// disable() must remove both IPv4 and IPv6 hooks for both INPUT and
    /// FORWARD chains, regardless of the protect_* settings.
    #[test]
    fn disable_removes_all_four_chain_hooks() {
        let _guard = SPY_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("spy.log");
        let spy = write_spy_script(dir.path(), &log);

        let backend = make_ipset(
            &spy,
            FirewallConfig {
                enabled: true,
                iptables_command: spy.clone(),
                ip6tables_command: spy.clone(),
                ..FirewallConfig::default()
            },
        );
        // The spy exits 0 for every command including -C, so remove_hook finds
        // each hook "present" and issues -D.  Call disable() directly so the log
        // only contains its commands, not any ensure() calls.
        backend.disable().unwrap();

        let lines = spy_lines(&log);
        // Four remove_hook calls: {iptables,ip6tables} × {INPUT,FORWARD}.
        let removals = [
            (&["-D", "INPUT", INPUT_CHAIN][..]),
            &["-D", "FORWARD", FORWARD_CHAIN],
        ];
        for needle_set in &removals {
            // Both iptables and ip6tables variants must appear.
            let count = lines
                .iter()
                .filter(|line| needle_set.iter().all(|n| line.contains(n)))
                .count();
            assert!(
                count >= 2,
                "expected at least 2 -D calls for {:?} (one per address family); got {};\nrecorded calls:\n{}",
                needle_set,
                count,
                lines.join("\n")
            );
        }
    }
}
