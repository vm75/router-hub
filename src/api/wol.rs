use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use axum::{
    Json,
    extract::{Path, State},
};
use chrono::Utc;
use serde::Serialize;
use tokio::net::UdpSocket;
use uuid::Uuid;

use crate::{
    api::ApiError,
    models::{ApiMessage, WolMachine},
    state::AppState,
    util::parse_mac,
};

pub async fn list(State(state): State<AppState>) -> Json<Vec<WolMachine>> {
    Json(state.stores.wol_machines.read().await.clone())
}

#[derive(Debug, Serialize)]
pub struct WolMachineStatus {
    pub id: Uuid,
    pub ip: Option<IpAddr>,
    pub status: &'static str,
}

pub async fn status(
    State(state): State<AppState>,
) -> Result<Json<Vec<WolMachineStatus>>, ApiError> {
    let machines = state.stores.wol_machines.read().await.clone();
    let neighbors = state
        .runner
        .run(
            &state.config.commands.ip,
            ["neigh", "show"],
            Duration::from_secs(2),
        )
        .await?;
    let mut result = Vec::with_capacity(machines.len());
    for machine in machines {
        let ip = find_neighbor_ip(&neighbors.stdout, &machine.mac);
        let reachable = if let Some(ip) = ip {
            state
                .runner
                .run(
                    &state.config.commands.ping,
                    ["-c", "1", "-W", "1", &ip.to_string()],
                    Duration::from_secs(2),
                )
                .await
                .map(|result| result.success)
                .unwrap_or(false)
        } else {
            false
        };
        result.push(WolMachineStatus {
            id: machine.id,
            ip,
            status: if ip.is_some() && reachable {
                "up"
            } else if ip.is_some() {
                "down"
            } else {
                "unknown"
            },
        });
    }
    Ok(Json(result))
}

fn find_neighbor_ip(output: &str, mac: &str) -> Option<IpAddr> {
    let wanted = mac.replace([':', '-'], "").to_ascii_lowercase();
    output.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        let ip = fields.first()?.parse().ok()?;
        let lladdr = fields
            .windows(2)
            .find(|pair| pair[0] == "lladdr")
            .map(|pair| pair[1])?;
        (lladdr.replace([':', '-'], "").eq_ignore_ascii_case(&wanted)).then_some(ip)
    })
}

pub async fn create(
    State(state): State<AppState>,
    Json(mut machine): Json<WolMachine>,
) -> Result<Json<WolMachine>, ApiError> {
    validate(&machine)?;
    machine.id = Uuid::new_v4();
    machine.updated_at = Utc::now();
    state
        .stores
        .wol_machines
        .write()
        .await
        .push(machine.clone());
    state.stores.save_wol_machines().await?;
    Ok(Json(machine))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(mut machine): Json<WolMachine>,
) -> Result<Json<WolMachine>, ApiError> {
    validate(&machine)?;
    machine.id = id;
    machine.updated_at = Utc::now();
    let mut machines = state.stores.wol_machines.write().await;
    let existing = machines
        .iter_mut()
        .find(|machine| machine.id == id)
        .ok_or_else(|| ApiError::not_found("machine not found"))?;
    *existing = machine.clone();
    drop(machines);
    state.stores.save_wol_machines().await?;
    Ok(Json(machine))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiMessage>, ApiError> {
    let mut machines = state.stores.wol_machines.write().await;
    let before = machines.len();
    machines.retain(|machine| machine.id != id);
    if machines.len() == before {
        return Err(ApiError::not_found("machine not found"));
    }
    drop(machines);
    state.stores.save_wol_machines().await?;
    Ok(Json(ApiMessage::new("machine deleted")))
}

#[derive(Serialize)]
pub struct WakeResult {
    machine: String,
    destination: SocketAddr,
    packets_sent: usize,
    simulated: bool,
}

pub async fn wake(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<WakeResult>, ApiError> {
    let machine = state
        .stores
        .wol_machines
        .read()
        .await
        .iter()
        .find(|machine| machine.id == id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("machine not found"))?;
    let mac = parse_mac(&machine.mac).map_err(ApiError::bad_request)?;
    let mut packet = [0_u8; 102];
    packet[..6].fill(0xff);
    for index in 0..16 {
        packet[6 + index * 6..12 + index * 6].copy_from_slice(&mac);
    }

    let destination = SocketAddr::new(machine.broadcast, machine.port);
    if state.config.test_mode {
        return Ok(Json(WakeResult {
            machine: machine.name,
            destination,
            packets_sent: 3,
            simulated: true,
        }));
    }

    let destinations = packet_destinations(machine.broadcast, machine.port);
    let mut packets_sent = 0;
    for (bind, destination) in destinations {
        let socket = UdpSocket::bind(bind).await?;
        socket.set_broadcast(true)?;
        for _ in 0..3 {
            socket.send_to(&packet, destination).await?;
            packets_sent += 1;
        }
    }
    Ok(Json(WakeResult {
        machine: machine.name,
        destination,
        packets_sent,
        simulated: false,
    }))
}

fn packet_destinations(broadcast: IpAddr, port: u16) -> Vec<(SocketAddr, SocketAddr)> {
    match broadcast {
        IpAddr::V4(broadcast) if broadcast == Ipv4Addr::BROADCAST => {
            let interfaces = interface_broadcasts().unwrap_or_default();
            if interfaces.is_empty() {
                return vec![(
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                    SocketAddr::V4(SocketAddrV4::new(broadcast, port)),
                )];
            }
            interfaces
                .into_iter()
                .map(|(local, broadcast)| {
                    (
                        SocketAddr::V4(SocketAddrV4::new(local, 0)),
                        SocketAddr::V4(SocketAddrV4::new(broadcast, port)),
                    )
                })
                .collect()
        }
        IpAddr::V4(broadcast) => {
            let interfaces = interface_broadcasts().unwrap_or_default();
            if let Some((local, _)) = interfaces
                .into_iter()
                .find(|(_, interface_broadcast)| *interface_broadcast == broadcast)
            {
                return vec![(
                    SocketAddr::V4(SocketAddrV4::new(local, 0)),
                    SocketAddr::V4(SocketAddrV4::new(broadcast, port)),
                )];
            }
            vec![(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                SocketAddr::V4(SocketAddrV4::new(broadcast, port)),
            )]
        }
        IpAddr::V6(broadcast) => vec![(
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
            SocketAddr::new(IpAddr::V6(broadcast), port),
        )],
    }
}

#[cfg(target_os = "linux")]
fn interface_broadcasts() -> io::Result<Vec<(Ipv4Addr, Ipv4Addr)>> {
    use std::ptr;

    let mut addresses = ptr::null_mut();
    let result = unsafe { libc::getifaddrs(&mut addresses) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut interfaces = Vec::new();
    let mut current = addresses;
    while !current.is_null() {
        let address = unsafe { &*current };
        if !address.ifa_addr.is_null()
            && !address.ifa_netmask.is_null()
            && unsafe { (*address.ifa_addr).sa_family } == libc::AF_INET as libc::sa_family_t
            && address.ifa_flags & libc::IFF_LOOPBACK as libc::c_uint == 0
        {
            let local = unsafe { *(address.ifa_addr as *const libc::sockaddr_in) };
            let netmask = unsafe { *(address.ifa_netmask as *const libc::sockaddr_in) };
            let local = u32::from_be(local.sin_addr.s_addr);
            let netmask = u32::from_be(netmask.sin_addr.s_addr);
            if netmask != 0 {
                let broadcast = Ipv4Addr::from(local | !netmask);
                let local = Ipv4Addr::from(local);
                if !interfaces.iter().any(|(existing, existing_broadcast)| {
                    *existing == local && *existing_broadcast == broadcast
                }) {
                    interfaces.push((local, broadcast));
                }
            }
        }
        current = address.ifa_next;
    }
    unsafe { libc::freeifaddrs(addresses) };
    Ok(interfaces)
}

#[cfg(not(target_os = "linux"))]
fn interface_broadcasts() -> io::Result<Vec<(Ipv4Addr, Ipv4Addr)>> {
    Ok(Vec::new())
}

fn validate(machine: &WolMachine) -> Result<(), ApiError> {
    if machine.name.trim().is_empty() {
        return Err(ApiError::bad_request("machine name is required"));
    }
    parse_mac(&machine.mac).map_err(ApiError::bad_request)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::find_neighbor_ip;
    use std::net::IpAddr;

    #[test]
    fn finds_ipv4_neighbor_by_mac() {
        let output = "192.168.1.20 dev br0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n";
        assert_eq!(
            find_neighbor_ip(output, "AA-BB-CC-DD-EE-FF"),
            Some("192.168.1.20".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn ignores_neighbors_without_matching_mac() {
        let output = "192.168.1.20 dev br0 lladdr aa:bb:cc:dd:ee:00 STALE\n";
        assert_eq!(find_neighbor_ip(output, "aa:bb:cc:dd:ee:ff"), None);
    }
}
