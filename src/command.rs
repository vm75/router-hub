use std::{ffi::OsString, path::Path, process::Stdio, time::Duration};

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
