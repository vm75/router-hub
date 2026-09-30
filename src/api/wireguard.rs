use std::time::Duration;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::{api::ApiError, models::ApiMessage, state::AppState};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct WireGuardConfig {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct InterfaceConfig {
    pub private_key: String,
    pub address: String,
    pub listen_port: Option<u16>,
    pub post_up: Option<String>,
    pub post_down: Option<String>,
    pub dns: Option<String>,
    pub mtu: Option<u16>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct PeerConfig {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub allowed_ips: String,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Deserialize)]
pub struct ToggleRequest {
    pub enable: bool,
}

#[derive(Serialize)]
pub struct WireGuardStatus {
    pub is_running: bool,
    pub raw_status: String,
}

fn parse_wg_conf(content: &str) -> WireGuardConfig {
    let mut config = WireGuardConfig::default();
    let mut current_section = "";
    let mut current_peer = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if let Some(peer) = current_peer.take() {
                config.peers.push(peer);
            }
            current_section = &trimmed[1..trimmed.len() - 1];
            if current_section.eq_ignore_ascii_case("Peer") {
                current_peer = Some(PeerConfig::default());
            }
            continue;
        }

        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            let value = value.trim();

            if current_section.eq_ignore_ascii_case("Interface") {
                match key.to_ascii_lowercase().as_str() {
                    "privatekey" => config.interface.private_key = value.to_string(),
                    "address" => config.interface.address = value.to_string(),
                    "listenport" => config.interface.listen_port = value.parse().ok(),
                    "postup" => config.interface.post_up = Some(value.to_string()),
                    "postdown" => config.interface.post_down = Some(value.to_string()),
                    "dns" => config.interface.dns = Some(value.to_string()),
                    "mtu" => config.interface.mtu = value.parse().ok(),
                    _ => {}
                }
            } else if current_section.eq_ignore_ascii_case("Peer") {
                if let Some(ref mut peer) = current_peer {
                    match key.to_ascii_lowercase().as_str() {
                        "publickey" => peer.public_key = value.to_string(),
                        "presharedkey" => peer.preshared_key = Some(value.to_string()),
                        "allowedips" => peer.allowed_ips = value.to_string(),
                        "endpoint" => peer.endpoint = Some(value.to_string()),
                        "persistentkeepalive" => peer.persistent_keepalive = value.parse().ok(),
                        _ => {}
                    }
                }
            }
        }
    }

    if let Some(peer) = current_peer {
        config.peers.push(peer);
    }

    config
}

fn write_wg_conf(config: &WireGuardConfig) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    if !config.interface.private_key.is_empty() {
        out.push_str(&format!("PrivateKey = {}\n", config.interface.private_key));
    }
    if !config.interface.address.is_empty() {
        out.push_str(&format!("Address = {}\n", config.interface.address));
    }
    if let Some(port) = config.interface.listen_port {
        out.push_str(&format!("ListenPort = {}\n", port));
    }
    if let Some(ref dns) = config.interface.dns {
        out.push_str(&format!("DNS = {}\n", dns));
    }
    if let Some(mtu) = config.interface.mtu {
        out.push_str(&format!("MTU = {}\n", mtu));
    }
    if let Some(ref post_up) = config.interface.post_up {
        out.push_str(&format!("PostUp = {}\n", post_up));
    }
    if let Some(ref post_down) = config.interface.post_down {
        out.push_str(&format!("PostDown = {}\n", post_down));
    }

    for peer in &config.peers {
        out.push_str("\n[Peer]\n");
        if !peer.public_key.is_empty() {
            out.push_str(&format!("PublicKey = {}\n", peer.public_key));
        }
        if let Some(ref psk) = peer.preshared_key {
            out.push_str(&format!("PresharedKey = {}\n", psk));
        }
        if !peer.allowed_ips.is_empty() {
            out.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips));
        }
        if let Some(ref ep) = peer.endpoint {
            out.push_str(&format!("Endpoint = {}\n", ep));
        }
        if let Some(keepalive) = peer.persistent_keepalive {
            out.push_str(&format!("PersistentKeepalive = {}\n", keepalive));
        }
    }
    out
}

pub async fn get_config(State(state): State<AppState>) -> Result<Json<WireGuardConfig>, ApiError> {
    let iface = state
        .config
        .paths
        .wireguard_conf
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let result = state
        .runner
        .run(
            &state.config.commands.wg,
            ["showconf", &iface],
            Duration::from_secs(5),
        )
        .await;

    if let Ok(res) = result {
        if res.success || res.simulated {
            return Ok(Json(parse_wg_conf(&res.stdout)));
        }
    }

    let path = &state.config.paths.wireguard_conf;
    let content = match tokio::fs::read_to_string(path).await {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(ApiError::internal(error)),
    };
    Ok(Json(parse_wg_conf(&content)))
}

pub async fn update_config(
    State(state): State<AppState>,
    Json(config): Json<WireGuardConfig>,
) -> Result<Json<WireGuardConfig>, ApiError> {
    let content = write_wg_conf(&config);
    let path = &state.config.paths.wireguard_conf;
    let iface = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let _ = crate::nginx::atomic_write(path, content.as_bytes());

    let temp_path = std::env::temp_dir().join(format!("wg-sync-{}.conf", iface));
    tokio::fs::write(&temp_path, content.as_bytes())
        .await
        .map_err(ApiError::internal)?;

    let result = state
        .runner
        .run(
            &state.config.commands.wg,
            ["syncconf", &iface, &temp_path.to_string_lossy()],
            Duration::from_secs(5),
        )
        .await
        .map_err(ApiError::internal)?;

    let _ = tokio::fs::remove_file(&temp_path).await;

    if !result.success && !result.simulated {
        return Err(ApiError::conflict(format!(
            "wg syncconf failed: {}",
            result.stderr
        )));
    }

    Ok(Json(config))
}

pub async fn get_status(State(state): State<AppState>) -> Result<Json<WireGuardStatus>, ApiError> {
    let iface = state
        .config
        .paths
        .wireguard_conf
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let result = state
        .runner
        .run(
            &state.config.commands.wg,
            ["show", &iface],
            Duration::from_secs(5),
        )
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(WireGuardStatus {
        is_running: result.success,
        raw_status: if result.success {
            result.stdout
        } else {
            result.stderr
        },
    }))
}

pub async fn toggle(
    State(state): State<AppState>,
    Json(req): Json<ToggleRequest>,
) -> Result<Json<ApiMessage>, ApiError> {
    let iface = state
        .config
        .paths
        .wireguard_conf
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let action = if req.enable { "up" } else { "down" };

    let path_str = state
        .config
        .paths
        .wireguard_conf
        .to_string_lossy()
        .to_string();
    let arg = if req.enable { &path_str } else { &iface };

    let result = state
        .runner
        .run(
            &state.config.commands.wg_quick,
            [action, arg],
            Duration::from_secs(10),
        )
        .await
        .map_err(ApiError::internal)?;

    if !result.success && !result.simulated {
        return Err(ApiError::conflict(format!(
            "wg-quick {} failed: {}",
            action, result.stderr
        )));
    }

    Ok(Json(ApiMessage::new(format!(
        "WireGuard interface {}",
        if req.enable {
            "brought up"
        } else {
            "brought down"
        }
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_write_wg_conf() {
        let conf = r#"
[Interface]
PrivateKey = myprivatekey
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT

[Peer]
PublicKey = peerpublickey
PresharedKey = peerpresharedkey
AllowedIPs = 10.0.0.2/32
Endpoint = 192.168.1.100:51820
PersistentKeepalive = 25
"#;
        let parsed = parse_wg_conf(conf);
        assert_eq!(parsed.interface.private_key, "myprivatekey");
        assert_eq!(parsed.interface.address, "10.0.0.1/24");
        assert_eq!(parsed.interface.listen_port, Some(51820));
        assert_eq!(
            parsed.interface.post_up.as_deref(),
            Some("iptables -A FORWARD -i wg0 -j ACCEPT")
        );

        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].public_key, "peerpublickey");
        assert_eq!(
            parsed.peers[0].preshared_key.as_deref(),
            Some("peerpresharedkey")
        );
        assert_eq!(parsed.peers[0].allowed_ips, "10.0.0.2/32");
        assert_eq!(
            parsed.peers[0].endpoint.as_deref(),
            Some("192.168.1.100:51820")
        );
        assert_eq!(parsed.peers[0].persistent_keepalive, Some(25));

        // Also test case-insensitivity
        let conf_lower = r#"
[interface]
privatekey = myprivatekey
address = 10.0.0.1/24

[peer]
publickey = peerpublickey
allowedips = 10.0.0.2/32
"#;
        let parsed_lower = parse_wg_conf(conf_lower);
        assert_eq!(parsed_lower.interface.private_key, "myprivatekey");
        assert_eq!(parsed_lower.peers.len(), 1);
        assert_eq!(parsed_lower.peers[0].public_key, "peerpublickey");

        let generated = write_wg_conf(&parsed);
        assert!(generated.contains("PrivateKey = myprivatekey"));
        assert!(generated.contains("Endpoint = 192.168.1.100:51820"));
    }
}
