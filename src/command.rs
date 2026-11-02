use std::{ffi::OsString, path::Path, process::Stdio, time::Duration};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use anyhow::{Context, Result, bail};
use tokio::{process::Command, time::timeout};
use tracing::info;

use crate::models::CommandResult;

#[derive(Clone)]
pub struct CommandRunner {
    test_mode: bool,
}

impl CommandRunner {
    pub fn new(test_mode: bool) -> Self {
        Self { test_mode }
    }

    pub async fn run<I, S>(
        &self,
        program: &Path,
        args: I,
        timeout_duration: Duration,
    ) -> Result<CommandResult>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
        if self.test_mode {
            let rendered = args
                .iter()
                .map(|arg| arg.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            info!(program = %program.display(), args = %rendered, "simulated command");
            return Ok(CommandResult {
                success: true,
                code: Some(0),
                stdout: format!("SIMULATED: {} {}", program.display(), rendered),
                stderr: String::new(),
                simulated: true,
            });
        }

        if !program.exists() {
            bail!("command not found: {}", program.display());
        }

        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let output = timeout(timeout_duration, command.output())
            .await
            .with_context(|| format!("command timed out: {}", program.display()))??;

        Ok(CommandResult {
            success: output.status.success(),
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            simulated: false,
        })
    }
    /// Run a command and all its hook subprocesses in a dedicated Unix process
    /// group. On timeout, kill the group rather than only the parent shell.
    pub async fn run_process_group<I, S>(
        &self,
        program: &Path,
        args: I,
        timeout_duration: Duration,
    ) -> Result<CommandResult>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
        if self.test_mode {
            return self.run(program, args, timeout_duration).await;
        }
        if !program.exists() {
            bail!("command not found: {}", program.display());
        }

        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.as_std_mut().process_group(0);

        let child = command.spawn().with_context(|| format!("failed to start {}", program.display()))?;
        #[cfg(unix)]
        let child_pid = child.id();
        let output = match timeout(timeout_duration, child.wait_with_output()).await {
            Ok(result) => result?,
            Err(_) => {
                #[cfg(unix)]
                if let Some(pid) = child_pid {
                    // Negative PID addresses the process group established above.
                    // This includes a DNS hook's shell, curl, and propagation sleep.
                    let signal_result = unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
                    if signal_result != 0 {
                        tracing::warn!(%pid, error = %std::io::Error::last_os_error(), "unable to kill dehydrated process group");
                    }
                }
                bail!("command timed out: {}", program.display());
            }
        };

        Ok(CommandResult {
            success: output.status.success(),
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            simulated: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_command_runner_simulation() {
        let runner = CommandRunner::new(true);
        let res = runner
            .run(
                Path::new("/bin/nonexistent"),
                vec!["arg1", "arg2"],
                Duration::from_secs(1),
            )
            .await
            .unwrap();

        assert!(res.simulated);
        assert!(res.success);
        assert_eq!(res.code, Some(0));
        assert!(res.stdout.contains("SIMULATED: /bin/nonexistent arg1 arg2"));
    }

    #[tokio::test]
    async fn test_command_runner_non_existent() {
        let runner = CommandRunner::new(false);
        let res = runner
            .run(
                Path::new("/nonexistent/path/cmd"),
                vec!["arg"],
                Duration::from_secs(1),
            )
            .await;

        assert!(res.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_process_group_timeout_kills_hook_descendants() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("child-survived");
        let command = format!("sleep 1; touch '{}'", marker.display());
        let result = CommandRunner::new(false)
            .run_process_group(
                Path::new("/bin/sh"),
                vec!["-c".to_string(), command],
                Duration::from_millis(100),
            )
            .await;
        assert!(result.unwrap_err().to_string().contains("timed out"));
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!marker.exists(), "a timed-out command left a subprocess running");
    }

    #[tokio::test]
    async fn test_command_runner_real_echo() {
        let runner = CommandRunner::new(false);
        let res = runner
            .run(
                Path::new("/bin/echo"),
                vec!["hello"],
                Duration::from_secs(1),
            )
            .await
            .unwrap();

        assert!(!res.simulated);
        assert!(res.success);
        assert_eq!(res.stdout, "hello");
    }
}
