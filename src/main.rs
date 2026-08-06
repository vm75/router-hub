mod adguard;
mod api;
mod asus_ui;
mod auth;
mod ban_attack;
mod command;
mod config;
mod firewall;
mod models;
mod nginx;
mod state;
mod storage;
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

use crate::{
    asus_ui::{install_menu_entry, render_ui_file},
    config::AppConfig,
    firewall::FirewallManager,
    state::AppState,
    storage::Stores,
};

#[derive(Debug, Parser)]
#[command(name = "router-hub", version, about)]
struct Cli {
    #[arg(long, default_value = "/opt/etc/router-hub/router-hub.toml")]
    config: PathBuf,

    #[arg(long, global = true)]
    test_mode: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve,
    CheckConfig,
    RenderUi,
    MountUi,
    UnmountUi,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "router_hub=info,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let mut config = AppConfig::load(&cli.config)?;
    if cli.test_mode {
        config.apply_test_mode(&cli.config)?;
    }
    config.validate()?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::CheckConfig => {
            println!("configuration is valid: {}", cli.config.display());
            Ok(())
        }
        Command::RenderUi => {
            let path = render_ui_file(&config)?;
            println!("rendered {}", path.display());
            Ok(())
        }
        Command::MountUi => {
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
    config.ensure_directories()?;
    let stores = Stores::load(&config).await?;
    let firewall = FirewallManager::new(config.clone(), stores.clone()).await?;
    let state = AppState::new(config.clone(), stores, firewall.clone());

    if let Err(error) = crate::nginx::reconcile_auxiliary_config(&config) {
        warn!(%error, "unable to reconcile nginx auxiliary configuration");
    }

    if config.asus_ui.enabled && !config.test_mode {
        if let Err(error) = install_menu_entry(&config) {
            warn!(%error, "unable to update ASUS menu tree; continuing with rendered UI");
        }
        if let Err(error) = render_ui_file(&config) {
            warn!(%error, "unable to render ASUS UI page; continuing with standalone listener");
        }
    } else {
        render_ui_file(&config)?;
    }

    firewall.start().await;
    spawn_firewall_reconcile_signal(firewall.clone());
    spawn_reconfigure_signal();
    state.start_certificate_renewal_loop();

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

    let app = api::app(state)?.layer(TraceLayer::new_for_http());

    let bind_ip: IpAddr = config
        .server
        .bind
        .parse()
        .context("invalid server bind address")?;
    let address = SocketAddr::new(bind_ip, config.server.port);
    let listener = TcpListener::bind(address).await?;
    info!(%address, version = env!("CARGO_PKG_VERSION"), test_mode = config.test_mode, "router-hub listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

#[cfg(unix)]
fn spawn_firewall_reconcile_signal(firewall: FirewallManager) {
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
            if let Err(error) = firewall.reconcile().await {
                warn!(%error, "signal-triggered firewall reconciliation failed");
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_firewall_reconcile_signal(_firewall: FirewallManager) {}

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

async fn shutdown_signal() {
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
}
