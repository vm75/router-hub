use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Serialize)]
pub struct SystemUsage {
    pub cpu: Vec<CpuStat>,
    pub memory: MemoryStat,
    pub network: NetworkStat,
    pub uptime_seconds: u64,
    pub load_average: [f64; 3],
}

#[derive(Debug, Default, Serialize)]
pub struct CpuStat {
    pub name: String,
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct MemoryStat {
    pub total_kb: u64,
    pub free_kb: u64,
    pub available_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct NetworkStat {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub fn get_system_usage(
    stat_path: &Path,
    meminfo_path: &Path,
    net_dev_path: &Path,
    uptime_path: &Path,
    loadavg_path: &Path,
    wan_interface: &str,
) -> Result<SystemUsage> {
    let cpu = parse_proc_stat(stat_path).unwrap_or_default();
    let memory = parse_proc_meminfo(meminfo_path).unwrap_or_default();
    let network = parse_proc_net_dev(net_dev_path, wan_interface).unwrap_or_default();
    let uptime_seconds = parse_proc_uptime(uptime_path).unwrap_or_default();
    let load_average = parse_proc_loadavg(loadavg_path).unwrap_or([0.0, 0.0, 0.0]);

    Ok(SystemUsage {
        cpu,
        memory,
        network,
        uptime_seconds,
        load_average,
    })
}

fn parse_proc_stat(path: &Path) -> Result<Vec<CpuStat>> {
    let content = fs::read_to_string(path).context("failed to read /proc/stat")?;
    let mut cpus = Vec::new();
    for line in content.lines() {
        if line.starts_with("cpu") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 8 {
                let name = parts[0].to_string();
                // skip the overall 'cpu' line if we only want per-core, but let's send all and let frontend decide.
                let user = parts.get(1).unwrap_or(&"0").parse().unwrap_or(0);
                let nice = parts.get(2).unwrap_or(&"0").parse().unwrap_or(0);
                let system = parts.get(3).unwrap_or(&"0").parse().unwrap_or(0);
                let idle = parts.get(4).unwrap_or(&"0").parse().unwrap_or(0);
                let iowait = parts.get(5).unwrap_or(&"0").parse().unwrap_or(0);
                let irq = parts.get(6).unwrap_or(&"0").parse().unwrap_or(0);
                let softirq = parts.get(7).unwrap_or(&"0").parse().unwrap_or(0);
                let steal = parts.get(8).unwrap_or(&"0").parse().unwrap_or(0);

                cpus.push(CpuStat {
                    name,
                    user,
                    nice,
                    system,
                    idle,
                    iowait,
                    irq,
                    softirq,
                    steal,
                });
            }
        }
    }
    Ok(cpus)
}

fn parse_proc_meminfo(path: &Path) -> Result<MemoryStat> {
    let content = fs::read_to_string(path).context("failed to read /proc/meminfo")?;
    let mut stat = MemoryStat::default();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let key = parts[0];
            let val_kb = parts[1].parse().unwrap_or(0);
            match key {
                "MemTotal:" => stat.total_kb = val_kb,
                "MemFree:" => stat.free_kb = val_kb,
                "MemAvailable:" => stat.available_kb = val_kb,
                "SwapTotal:" => stat.swap_total_kb = val_kb,
                "SwapFree:" => stat.swap_free_kb = val_kb,
                _ => {}
            }
        }
    }
    // Fallback if MemAvailable is missing (older kernels)
    if stat.available_kb == 0 {
        stat.available_kb = stat.free_kb;
    }
    Ok(stat)
}

fn parse_proc_net_dev(path: &Path, wan_interface: &str) -> Result<NetworkStat> {
    let content = fs::read_to_string(path).context("failed to read /proc/net/dev")?;
    for line in content.lines().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let iface = parts[0].trim_end_matches(':');
        if iface == wan_interface && parts.len() >= 10 {
            return Ok(NetworkStat {
                rx_bytes: parts.get(1).unwrap_or(&"0").parse().unwrap_or(0),
                tx_bytes: parts.get(9).unwrap_or(&"0").parse().unwrap_or(0),
            });
        }
    }
    Ok(NetworkStat::default())
}

fn parse_proc_uptime(path: &Path) -> Result<u64> {
    let content = fs::read_to_string(path).context("failed to read /proc/uptime")?;
    if let Some(uptime_str) = content.split_whitespace().next() {
        if let Ok(uptime_f64) = uptime_str.parse::<f64>() {
            return Ok(uptime_f64 as u64);
        }
    }
    Ok(0)
}

fn parse_proc_loadavg(path: &Path) -> Result<[f64; 3]> {
    let content = fs::read_to_string(path).context("failed to read /proc/loadavg")?;
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() >= 3 {
        let one = parts[0].parse().unwrap_or(0.0);
        let five = parts[1].parse().unwrap_or(0.0);
        let fifteen = parts[2].parse().unwrap_or(0.0);
        return Ok([one, five, fifteen]);
    }
    Ok([0.0, 0.0, 0.0])
}
