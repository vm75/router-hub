use std::path::{Component, Path, PathBuf};

use anyhow::{Result, bail};

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
}
