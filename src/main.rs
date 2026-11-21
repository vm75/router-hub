mod api;
#[path = "platforms/asus_ui.rs"]
mod asus_ui;
mod auth;
mod backup;
mod ban_attack;
mod certificate_http;
mod command;
mod config;
mod core;
mod models;
mod modules;
mod nginx_ingress;
mod nginx_mutation;
mod nginx_render;
#[path = "platforms/nginx_upgrade.rs"]
mod nginx_upgrade;
mod platforms;
mod restore;
mod state;
mod storage;
mod system;
#[path = "platforms/upgrade.rs"]
mod upgrade;
mod util;

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

// Stable crate-root aliases while domain sources move beneath modules/.
use modules::{adguard, firewall, nginx, nginx_sites};

use crate::{
    asus_ui::{install_menu_entry, render_ui_file},
    config::{AppConfig, Platform},
    firewall::FirewallManager,
    state::AppState,
    storage::Stores,
};

#[derive(Debug, Parser)]
#[command(name = "maestro", version, about)]
struct Cli {
    #[arg(long, default_value = "/opt/etc/maestro/maestro.toml")]
    config: PathBuf,

    #[arg(long, global = true)]
    test_mode: bool,

    /// Run native Linux services without Asuswrt integration or command simulation.
    #[arg(long, global = true, conflicts_with = "test_mode")]
    linux_mode: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve,
    CheckConfig,
    /// Install the bundled nginx configuration, backing up a different nginx.conf.
    InitNginx,
    /// Download or update the official dehydrated executable.
    #[command(alias = "init-dehydrated")]
    UpdateDehydrated,
    /// Move current-format nginx inputs into inputs_dir; run while the service is stopped.
    MigrateNginxInputs,
    RenderUi,
    MountUi,
    UnmountUi,
    /// Back up the installed binary, configuration, state, nginx and certificates.
    Backup {
        /// Override /tmp on routers or the configuration directory on Linux.
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
    /// Restore a backup archive; stop services before restoring original locations.
    Restore {
        archive: PathBuf,
        /// Restore beneath this existing directory instead of /.
        #[arg(long, default_value = "/")]
        root: PathBuf,
    },
    /// Download the newest stable Entware IPK and optionally install it (router only).
    Upgrade {
        /// Verify and stage the IPK in /tmp without invoking opkg.
        #[arg(long)]
        download_only: bool,
        /// Skip creating the pre-upgrade backup.
        #[arg(long)]
        no_backup: bool,
    },
    /// Download the newest custom NGINX Entware IPK bundle and optionally install it (router only).
    #[command(alias = "update-nginx")]
    UpgradeNginx {
        /// NGINX release channel: stable (default) or mainline.
        #[arg(long, value_enum, default_value_t = nginx_upgrade::NginxChannel::Stable)]
        channel: nginx_upgrade::NginxChannel,
        /// Target a specific release tag (e.g. nginx-v1.30.7-run44684227015-a1).
        #[arg(long, conflicts_with = "version")]
        tag: Option<String>,
        /// Target a specific NGINX version (e.g. 1.30.7).
        #[arg(long, conflicts_with = "tag")]
        version: Option<String>,
        /// Verify and stage the IPK bundle in /tmp without invoking opkg.
        #[arg(long)]
        download_only: bool,
        /// Skip creating the pre-upgrade backup.
        #[arg(long)]
        no_backup: bool,
        /// Force installation even if already up to date.
        #[arg(long)]
        force: bool,
        /// Check for available updates without downloading or installing.
        #[arg(long)]
        check: bool,
        /// Permit switching from a newer version to an older stable/mainline release.
        #[arg(long)]
        allow_downgrade: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "maestro=info,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    // Recovery must remain available when the installed configuration is corrupt.
    if let Some(Command::Restore { archive, root }) = &cli.command {
        return restore::run(archive, root, cli.test_mode);
    }
    let mut config = AppConfig::load(&cli.config)?;
    if cli.linux_mode {
        config.platform = Platform::Linux;
    }
    if cli.test_mode {
        config.apply_test_mode(&cli.config)?;
    }
    config.validate()?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Restore { .. } => unreachable!("restore is handled before configuration loading"),
        Command::Backup { output_dir } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(backup::run(&config, &cli.config, output_dir.as_deref())),
        Command::Upgrade {
            download_only,
            no_backup,
        } => {
            upgrade::require_router(config.platform, config.test_mode)?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(upgrade::run(&config, &cli.config, download_only, no_backup))
        }
        Command::UpgradeNginx {
            channel,
            tag,
            version,
            download_only,
            no_backup,
            force,
            check,
            allow_downgrade,
        } => {
            nginx_upgrade::require_router(config.platform, config.test_mode)?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(nginx_upgrade::run(
                    &config,
                    &cli.config,
                    nginx_upgrade::UpgradeNginxOptions {
                        channel,
                        tag,
                        version,
                        download_only,
                        no_backup,
                        force,
                        check,
                        allow_downgrade,
                    },
                ))
        }
        Command::CheckConfig => {
            println!("configuration is valid: {}", cli.config.display());
            Ok(())
        }
        Command::MigrateNginxInputs => {
            let count = nginx_render::migrate_inputs(&config)?;
            println!("migrated {count} nginx input files; runtime configuration preserved");
            Ok(())
        }
        Command::InitNginx => {
            let created = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(nginx_render::bootstrap(&config))?;
            println!(
                "{}",
                if created {
                    "installed Maestro nginx configuration"
                } else {
                    "Maestro nginx configuration is already current"
                }
            );
            Ok(())
        }
        Command::UpdateDehydrated => {
            let update = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(state::download_latest_dehydrated(&config))?;
            println!(
                "{}",
                if update.simulated {
                    format!(
                        "simulated download of dehydrated to {}",
                        update.path.display()
                    )
                } else {
                    format!(
                        "downloaded dehydrated ({} bytes) to {}",
                        update.bytes,
                        update.path.display()
                    )
                }
            );
            Ok(())
        }
        Command::RenderUi => {
            let path = render_ui_file(&config)?;
            println!("rendered {}", path.display());
            Ok(())
        }
        Command::MountUi => {
            if config.platform == Platform::Linux {
                anyhow::bail!("mount-ui requires Asuswrt; use the standalone UI on Linux");
            }
            if !config.test_mode && config.asus_ui.enabled {
                install_menu_entry(&config)?;
            }
            render_ui_file(&config)?;
            Ok(())
        }
        Command::UnmountUi => Ok(()),
        Command::Serve => {
            if config.server.daemonize && !config.test_mode {
                if let Some(parent) = config.paths.log_file.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let log_file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&config.paths.log_file)
                    .with_context(|| {
                        format!(
                            "failed to open log file {}",
                            config.paths.log_file.display()
                        )
                    })?;

                daemonize::Daemonize::new()
                    .stdout(log_file.try_clone()?)
                    .stderr(log_file)
                    .working_directory("/")
                    .start()
                    .context("failed to daemonize")?;
            }

            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(serve(config))
        }
    }
}

async fn serve(config: AppConfig) -> Result<()> {
    nginx_render::require_migrated_input(&config, "nginx.toml")?;
    nginx_render::require_migrated_input(&config, "sites.toml")?;
    config.ensure_directories()?;
    let stores = Stores::load(&config).await?;
    let firewall = FirewallManager::new(config.clone(), stores.clone()).await?;
    let state = AppState::new(config.clone(), stores, firewall.clone());

    if config.asus_ui.enabled && !config.test_mode && config.platform == Platform::Asuswrt {
        if let Err(error) = install_menu_entry(&config) {
            warn!(%error, "unable to update ASUS menu tree; continuing with rendered UI");
        }
        if let Err(error) = render_ui_file(&config) {
            warn!(%error, "unable to render ASUS UI page; continuing with standalone listener");
        }
    } else if config.test_mode || config.platform == Platform::Asuswrt {
        // Preserve standalone ASUS rendering in simulated and router modes.
        render_ui_file(&config)?;
    }

    firewall.start().await;
    spawn_firewall_reconcile_signal(state.clone());
    spawn_reconfigure_signal();
    if let Err(error) = crate::certificate_http::recover_startup(&state).await {
        warn!(%error, "nginx ingress startup reconciliation failed; inspect certificate HTTP access status");
    }
    state.start_certificate_renewal_loop();
    crate::certificate_http::start_reconciliation(state.clone());

    let adguard_cfg = crate::api::adguard::get_effective_config(&state).await;
    if adguard_cfg.enabled {
        let config_clone = state.config.clone();
        tokio::spawn(async move {
            if let Ok(client) = crate::adguard::AdGuardClient::new(&adguard_cfg) {
                if let Err(error) = client.deduplicate_rewrites().await {
                    warn!(%error, "unable to deduplicate AdGuard rewrites");
                }
                if let Ok(objects) = crate::nginx::list_objects(&config_clone, true) {
                    for obj in objects {
                        if obj.enabled {
                            let full_domain = match obj.kind {
                                crate::models::NginxObjectKind::Domain => obj.domain.clone(),
                                crate::models::NginxObjectKind::Subdomain => {
                                    format!("{}.{}", obj.name, obj.domain)
                                }
                                crate::models::NginxObjectKind::Subfolder => String::new(),
                            };
                            if !full_domain.is_empty() {
                                if let Err(error) = client
                                    .ensure_rewrite(&full_domain, &adguard_cfg.lan_ip)
                                    .await
                                {
                                    warn!(domain = %full_domain, %error, "unable to reconcile AdGuard rewrite");
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    let app = api::app(state.clone())?.layer(TraceLayer::new_for_http());

    let bind_ip: IpAddr = config
        .server
        .bind
        .parse()
        .context("invalid server bind address")?;
    let address = SocketAddr::new(bind_ip, config.server.port);
    let listener = TcpListener::bind(address).await?;
    info!(%address, version = env!("CARGO_PKG_VERSION"), test_mode = config.test_mode, "maestro listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(state))
        .await?;

    Ok(())
}

#[cfg(unix)]
fn spawn_firewall_reconcile_signal(state: AppState) {
    tokio::spawn(async move {
        let mut signal =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()) {
                Ok(signal) => signal,
                Err(error) => {
                    warn!(%error, "unable to install firewall reconciliation signal");
                    return;
                }
            };
        while signal.recv().await.is_some() {
            if let Err(error) = state.firewall.reconcile().await {
                warn!(%error, "signal-triggered firewall reconciliation failed");
            }
            if let Err(error) = crate::certificate_http::reconcile(&state).await {
                warn!(%error, "signal-triggered HTTP WAN reconciliation failed");
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_firewall_reconcile_signal(_state: AppState) {}

#[cfg(unix)]
fn spawn_reconfigure_signal() {
    tokio::spawn(async move {
        let mut signal = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(signal) => signal,
            Err(error) => {
                warn!(%error, "unable to install reconfigure signal");
                return;
            }
        };

        while signal.recv().await.is_some() {
            // rc.func's reconfigure action uses SIGHUP for a reload. Keep the
            // process alive so service refresh does not become an accidental
            // restart; runtime configuration remains owned by the process.
            info!("reconfigure signal received; keeping service running");
        }
    });
}

#[cfg(not(unix))]
fn spawn_reconfigure_signal() {}

async fn shutdown_signal(state: AppState) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    if let Err(error) = state.stop_certificates().await {
        warn!(%error, "certificate HTTP cleanup failed during shutdown");
    }
}

#[cfg(test)]
mod cli_tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn backup_and_upgrade_flags() {
        let cli = Cli::try_parse_from(["maestro", "upgrade"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Upgrade {
                no_backup: false,
                ..
            })
        ));
        let cli =
            Cli::try_parse_from(["maestro", "upgrade", "--no-backup", "--download-only"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Upgrade {
                no_backup: true,
                download_only: true
            })
        ));
        let cli = Cli::try_parse_from([
            "maestro",
            "--config",
            "/lab/maestro.toml",
            "--linux-mode",
            "backup",
            "--output-dir",
            "/lab/backups",
        ])
        .unwrap();
        assert!(cli.linux_mode);
        assert!(
            matches!(cli.command, Some(Command::Backup { output_dir: Some(path) }) if path == Path::new("/lab/backups"))
        );
        let cli = Cli::try_parse_from([
            "maestro",
            "restore",
            "/tmp/backup.tar.gz",
            "--root",
            "/tmp/recovery",
        ])
        .unwrap();
        assert!(
            matches!(cli.command, Some(Command::Restore { archive, root }) if archive == Path::new("/tmp/backup.tar.gz") && root == Path::new("/tmp/recovery"))
        );

        // upgrade-nginx default flags
        let cli = Cli::try_parse_from(["maestro", "upgrade-nginx"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::UpgradeNginx {
                channel: nginx_upgrade::NginxChannel::Stable,
                tag: None,
                version: None,
                download_only: false,
                no_backup: false,
                force: false,
                check: false,
                allow_downgrade: false,
            })
        ));

        // upgrade-nginx with alias update-nginx and mainline channel
        let cli = Cli::try_parse_from([
            "maestro",
            "update-nginx",
            "--channel",
            "mainline",
            "--download-only",
            "--no-backup",
            "--force",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::UpgradeNginx {
                channel: nginx_upgrade::NginxChannel::Mainline,
                tag: None,
                version: None,
                download_only: true,
                no_backup: true,
                force: true,
                check: false,
                allow_downgrade: false,
            })
        ));

        // upgrade-nginx with explicit tag and check
        let cli = Cli::try_parse_from([
            "maestro",
            "upgrade-nginx",
            "--tag",
            "nginx-v1.30.7-run44684227015-a1",
            "--check",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::UpgradeNginx {
                channel: nginx_upgrade::NginxChannel::Stable,
                tag: Some(ref t),
                version: None,
                download_only: false,
                no_backup: false,
                force: false,
                check: true,
                allow_downgrade: false,
            }) if t == "nginx-v1.30.7-run44684227015-a1"
        ));

        // upgrade-nginx with explicit version
        let cli = Cli::try_parse_from(["maestro", "upgrade-nginx", "--version", "1.30.7"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::UpgradeNginx {
                channel: nginx_upgrade::NginxChannel::Stable,
                tag: None,
                version: Some(ref v),
                download_only: false,
                no_backup: false,
                force: false,
                check: false,
                allow_downgrade: false,
            }) if v == "1.30.7"
        ));
        assert!(
            Cli::try_parse_from([
                "maestro",
                "upgrade-nginx",
                "--tag",
                "nginx-v1.30.7",
                "--version",
                "1.30.7"
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "maestro",
            "upgrade-nginx",
            "--channel",
            "stable",
            "--allow-downgrade",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::UpgradeNginx {
                allow_downgrade: true,
                ..
            })
        ));
    }
}
