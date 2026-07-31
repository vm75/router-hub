use std::{
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
};

use anyhow::{Result, bail};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

pub fn safe_relative_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if value.is_empty() || path.is_absolute() {
        bail!("path must be a non-empty relative path");
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            _ => bail!("path traversal is not allowed"),
        }
    }
    Ok(path.to_path_buf())
}

pub fn validate_simple_name(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
    {
        bail!("{field} contains invalid characters");
    }
    Ok(())
}

pub fn tail_lines(input: &str, count: usize) -> String {
    let lines: Vec<&str> = input.lines().collect();
    lines[lines.len().saturating_sub(count)..].join("\n")
}

pub fn parse_mac(value: &str) -> Result<[u8; 6]> {
    let normalized = value.replace('-', ":");
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() != 6 {
        bail!("MAC address must contain six octets");
    }
    let mut mac = [0_u8; 6];
    for (index, part) in parts.iter().enumerate() {
        mac[index] =
            u8::from_str_radix(part, 16).map_err(|_| anyhow::anyhow!("invalid MAC address"))?;
    }
    Ok(mac)
}

#[allow(dead_code)]
pub fn extract_ip(line: &str) -> Option<IpAddr> {
    line.split(|character: char| {
        character.is_whitespace()
            || matches!(
                character,
                ',' | ';' | '=' | '(' | ')' | '[' | ']' | '<' | '>' | '"' | '\''
            )
    })
    .filter_map(|token| {
        let token = token.trim_matches(|character: char| matches!(character, '{' | '}'));
        if let Ok(ip) = token.parse::<IpAddr>() {
            return Some(ip);
        }
        if let Ok(address) = token.parse::<SocketAddr>() {
            return Some(address.ip());
        }
        let token = token.trim_end_matches([',', ';', ')', ']']);
        if let Ok(ip) = token.parse::<IpAddr>() {
            return Some(ip);
        }
        if let Ok(address) = token.parse::<SocketAddr>() {
            return Some(address.ip());
        }
        if let Some((host, port)) = token.rsplit_once(':') {
            if port.chars().all(|character| character.is_ascii_digit()) {
                if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                    return Some(IpAddr::V4(ip));
                }
            }
        }
        if token.matches(':').count() <= 1 {
            let token = token.trim_end_matches([':', '.']);
            return token.parse::<IpAddr>().ok();
        }
        None
    })
    .next()
}

#[allow(dead_code)]
pub fn subnet_for(ip: IpAddr, prefix_v4: u8, prefix_v6: u8) -> Result<IpNet> {
    Ok(match ip {
        IpAddr::V4(value) => IpNet::V4(Ipv4Net::new(value, prefix_v4)?),
        IpAddr::V6(value) => IpNet::V6(Ipv6Net::new(value, prefix_v6)?),
    })
}

#[allow(dead_code)]
pub fn ip_as_host_network(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(value) => IpNet::V4(Ipv4Net::new(value, 32).expect("valid prefix")),
        IpAddr::V6(value) => IpNet::V6(Ipv6Net::new(value, 128).expect("valid prefix")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_paths() {
        assert!(safe_relative_path("../secret").is_err());
        assert!(safe_relative_path("conf/site.conf").is_ok());
    }

    #[test]
    fn parses_mac_addresses() {
        assert_eq!(
            parse_mac("00:11:22:aa:bb:cc").unwrap(),
            [0, 17, 34, 170, 187, 204]
        );
    }

    #[test]
    fn extracts_ipv4_from_log_line() {
        assert_eq!(
            extract_ip("failed login from 192.168.1.42 port 22"),
            Some("192.168.1.42".parse().unwrap())
        );
        assert_eq!(
            extract_ip("upstream client 192.168.1.43:53122"),
            Some("192.168.1.43".parse().unwrap())
        );
        assert_eq!(
            extract_ip("peer [2001:db8::44]:443"),
            Some("2001:db8::44".parse().unwrap())
        );
    }
}
