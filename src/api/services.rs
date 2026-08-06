use std::{
    fs,
    os::unix::fs::PermissionsExt,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Result as AnyResult};
use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    api::ApiError,
    models::{ApiMessage, CommandResult, ServiceInfo},
    state::AppState,
    util::{tail_lines, validate_simple_name},
};

pub async fn list(State(state): State<AppState>) -> Result<Json<Vec<ServiceInfo>>, ApiError> {
    Ok(Json(collect_services(&state).await?))
}

async fn check_service_status(
    runner: &crate::command::CommandRunner,
    path: &std::path::Path,
    timeout: Duration,
) -> (bool, Option<i32>, String) {
    if let Ok(result) = runner.run(path, ["check"], timeout).await {
        let output = if result.stdout.is_empty() {
            &result.stderr
        } else {
            &result.stdout
        };
        if !output.contains("Usage:") && !output.contains("usage:") {
            let is_alive =
                result.success || output.contains("alive.") || output.contains("running");
            return (is_alive, result.code, output.clone());
        }
    }

    if let Ok(result) = runner.run(path, ["status"], timeout).await {
        let output = if result.stdout.is_empty() {
            &result.stderr
        } else {
            &result.stdout
        };
        let is_alive = result.success || output.contains("alive.") || output.contains("running");
        return (is_alive, result.code, output.clone());
    }

    (false, None, "Failed to execute status check".to_string())
}

pub async fn collect_services(state: &AppState) -> AnyResult<Vec<ServiceInfo>> {
    let mut paths = Vec::new();
    if state.config.services.init_dir.exists() {
        for entry in fs::read_dir(&state.config.services.init_dir)? {
            let entry = entry?;
            let path = entry.path();
            let filename = entry.file_name().to_string_lossy().to_string();
            let (name, enabled) = if let Some(name) = filename.strip_prefix(".disabled.") {
                (name.to_string(), false)
            } else {
                (filename, true)
            };
            if !entry.file_type()?.is_file()
                || entry.metadata()?.permissions().mode() & 0o111 == 0
                || name.starts_with("rc.")
                || validate_simple_name(&name, "service name").is_err()
            {
                continue;
            }
            paths.push((name, path, enabled));
        }
    }
    paths.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| right.2.cmp(&left.2)));
    paths.dedup_by(|left, right| left.0 == right.0);
    let mut services = Vec::with_capacity(paths.len());
    for (name, path, enabled) in paths {
        let (running, status_code, status) = if enabled {
            check_service_status(
                &state.runner,
                &path,
                Duration::from_secs(state.config.services.status_timeout_seconds),
            )
            .await
        } else {
            (false, None, "disabled".to_string())
        };

        services.push(ServiceInfo {
            name,
            enabled,
            path,
            running,
            status_code,
            status,
        });
    }
    Ok(services)
}

pub async fn action(
    State(state): State<AppState>,
    Path((name, action)): Path<(String, String)>,
) -> Result<Json<CommandResult>, ApiError> {
    validate_simple_name(&name, "service name").map_err(ApiError::bad_request)?;
    let action_str = match action.as_str() {
        "start" => "start",
        "stop" => "stop",
        "restart" => "restart",
        "reconfigure" | "refresh" => "reconfigure",
        "enable" => "enable",
        "disable" => "disable",
        "status" | "check" => "check",
        _ => return Err(ApiError::bad_request("unsupported service action")),
    };
    if action == "disable" && is_router_hub_service(&name) {
        return Err(ApiError::bad_request("Router Hub cannot be disabled"));
    }
    if action == "enable" && state.config.test_mode {
        return Ok(Json(CommandResult {
            success: true,
            code: Some(0),
            stdout: "SIMULATED: enable".to_string(),
            stderr: String::new(),
            simulated: true,
        }));
    }
    let path = service_path(&state, &name, action_str == "enable")?;

    if action == "enable" {
        return Ok(Json(rename_service(&state, &path, &name, true)?));
    }

    // Router Hub cannot synchronously restart its own init script: rc.func's
    // `killall router-hub` terminates this API process. Run the init script in a
    // new session so it survives the server shutdown and can complete the restart.
    if action == "restart" && is_router_hub_service(&name) && !state.config.test_mode {
        let mut command = Command::new(&path);

        command
            .arg(action_str)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        // SAFETY: pre_exec runs after fork and before exec. The closure performs
        // only the async-signal-safe setsid syscall and constructs an OS error if
        // that syscall fails.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            });
        }

        command.spawn().with_context(|| {
            format!(
                "failed to schedule detached service action using {}",
                path.display()
            )
        })?;

        return Ok(Json(CommandResult {
            success: true,
            code: None,
            stdout: format!("{action} scheduled"),
            stderr: String::new(),
            simulated: false,
        }));
    }

    if action == "disable" {
        if state.config.test_mode {
            return Ok(Json(
                state
                    .runner
                    .run(
                        &path,
                        ["disable"],
                        Duration::from_secs(state.config.services.action_timeout_seconds),
                    )
                    .await?,
            ));
        }

        let (running, _, _) = check_service_status(
            &state.runner,
            &path,
            Duration::from_secs(state.config.services.status_timeout_seconds),
        )
        .await;
        if running {
            let result = state
                .runner
                .run(
                    &path,
                    ["stop"],
                    Duration::from_secs(state.config.services.action_timeout_seconds),
                )
                .await?;
            if !result.success {
                return Ok(Json(result));
            }
        }
        return Ok(Json(rename_service(&state, &path, &name, false)?));
    }

    let mut args = vec![action_str.to_string()];
    if is_adguard_home_service(&name) {
        args.push("x".to_string());
    }

    let mut result = state
        .runner
        .run(
            &path,
            args,
            Duration::from_secs(state.config.services.action_timeout_seconds),
        )
        .await?;

    if (action.as_str() == "status" || action.as_str() == "check")
        && (result.stdout.contains("Usage:") || result.stderr.contains("Usage:"))
    {
        let mut status_args = vec!["status".to_string()];
        if is_adguard_home_service(&name) {
            status_args.push("x".to_string());
        }
        if let Ok(res) = state
            .runner
            .run(
                &path,
                status_args,
                Duration::from_secs(state.config.services.action_timeout_seconds),
            )
            .await
        {
            result = res;
        }
    }

    Ok(Json(result))
}

pub async fn logs(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<ApiMessage>, ApiError> {
    validate_simple_name(&name, "service name").map_err(ApiError::bad_request)?;
    service_path(&state, &name, false).or_else(|_| service_path(&state, &name, true))?;
    let candidates = log_candidates(&state, &name);
    for path in candidates {
        if path.is_file() {
            let raw = tokio::fs::read_to_string(&path)
                .await
                .unwrap_or_else(|error| error.to_string());
            return Ok(Json(ApiMessage::new(tail_lines(
                &raw,
                state.config.services.log_tail_lines,
            ))));
        }
    }

    let result = state
        .runner
        .run(
            &state.config.commands.logread,
            std::iter::empty::<&str>(),
            Duration::from_secs(10),
        )
        .await?;
    let filtered = result
        .stdout
        .lines()
        .filter(|line| {
            line.to_ascii_lowercase()
                .contains(&name.to_ascii_lowercase())
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Json(ApiMessage::new(if filtered.is_empty() {
        "No matching log file or syslog entries found.".into()
    } else {
        tail_lines(&filtered, state.config.services.log_tail_lines)
    })))
}

fn service_path(
    state: &AppState,
    name: &str,
    disabled: bool,
) -> std::result::Result<PathBuf, ApiError> {
    let filename = if disabled {
        format!(".disabled.{name}")
    } else {
        name.to_string()
    };
    let path = state.config.services.init_dir.join(filename);
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| ApiError::not_found("service script not found"))?;
    if !metadata.file_type().is_file() {
        return Err(ApiError::not_found("service script not found"));
    }
    let canonical_parent = state
        .config
        .services
        .init_dir
        .canonicalize()
        .unwrap_or_else(|_| state.config.services.init_dir.clone());
    let canonical = path
        .canonicalize()
        .context("failed to resolve service path")?;
    if canonical.parent() != Some(canonical_parent.as_path()) {
        return Err(ApiError::bad_request(
            "service path escaped configured init directory",
        ));
    }
    Ok(canonical)
}

fn rename_service(
    state: &AppState,
    source: &std::path::Path,
    name: &str,
    enable: bool,
) -> Result<CommandResult, ApiError> {
    let target_name = if enable {
        name.to_string()
    } else {
        format!(".disabled.{name}")
    };
    let target = state.config.services.init_dir.join(target_name);
    if target.exists() {
        return Err(ApiError::bad_request("service target path already exists"));
    }
    fs::rename(source, &target).map_err(|error| {
        ApiError::internal(format!(
            "failed to rename service {}: {error}",
            source.display()
        ))
    })?;
    Ok(CommandResult {
        success: true,
        code: Some(0),
        stdout: if enable {
            "service enabled; start it explicitly when ready".to_string()
        } else {
            "service disabled".to_string()
        },
        stderr: String::new(),
        simulated: false,
    })
}

fn is_router_hub_service(name: &str) -> bool {
    name.ends_with("router-hub")
}

fn is_adguard_home_service(name: &str) -> bool {
    name.ends_with("AdGuardHome")
}

fn is_nginx_service(name: &str) -> bool {
    name.ends_with("nginx")
}

fn log_candidates(state: &AppState, name: &str) -> Vec<PathBuf> {
    let stripped =
        name.trim_start_matches(|character: char| character == 'S' || character.is_ascii_digit());
    let mut candidates: Vec<PathBuf> = state
        .config
        .services
        .log_dirs
        .iter()
        .flat_map(|directory| {
            [
                directory.join(format!("{name}.log")),
                directory.join(format!("{stripped}.log")),
                directory.join(name),
                directory.join(stripped),
            ]
        })
        .collect();
    if is_nginx_service(name) {
        candidates.extend(
            ["error.log", "access.log", "traps.log"]
                .into_iter()
                .map(|file| state.config.nginx.log_dir.join(file)),
        );
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::{is_adguard_home_service, is_nginx_service, is_router_hub_service};

    #[test]
    fn recognizes_router_hub_service_by_suffix() {
        assert!(is_router_hub_service("S99router-hub"));
        assert!(is_router_hub_service("S10router-hub"));
        assert!(is_router_hub_service("K42router-hub"));
        assert!(!is_router_hub_service("S99other-service"));
    }

    #[test]
    fn recognizes_adguard_home_service_by_suffix() {
        assert!(is_adguard_home_service("S99AdGuardHome"));
        assert!(is_adguard_home_service("K42AdGuardHome"));
        assert!(is_adguard_home_service("AdGuardHome"));
        assert!(!is_adguard_home_service("S99other-service"));
    }

    #[test]
    fn recognizes_nginx_service_by_suffix() {
        assert!(is_nginx_service("S80nginx"));
        assert!(is_nginx_service("K80nginx"));
        assert!(!is_nginx_service("S80other-service"));
    }
}
