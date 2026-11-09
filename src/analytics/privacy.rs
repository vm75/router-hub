use std::net::IpAddr;

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

pub fn pseudonymize_ip(key: &[u8; 32], ip: IpAddr) -> String {
    let digest = hmac_sha256(key, ip.to_string().as_bytes());
    let prefix = if is_private_ip(ip) { "LAN" } else { "SRC" };
    format!(
        "{prefix}_{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
}

pub fn sanitize_rule_name(key: &[u8; 32], name: &str) -> String {
    let trimmed = name.trim();
    let safe = !trimmed.is_empty()
        && trimmed.len() <= 64
        && !trimmed.contains(['.', '/', '\\', '@', ':'])
        && trimmed
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_ ".contains(character));
    if safe {
        return trimmed.to_owned();
    }
    let digest = hmac_sha256(key, trimmed.as_bytes());
    format!(
        "RULE_{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
}

pub fn sanitize_method(method: Option<&str>) -> Option<String> {
    method.and_then(|value| {
        let method = value.trim().to_ascii_uppercase();
        (!method.is_empty()
            && method.len() <= 16
            && method
                .chars()
                .all(|character| character.is_ascii_alphabetic() || character == '-'))
        .then_some(method)
    })
}

pub fn sanitize_status(status: Option<&str>) -> Option<u16> {
    status
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|value| (100..=599).contains(value))
}

pub fn sanitize_path(path: Option<&str>, max_bytes: usize) -> Option<String> {
    let raw = path?.trim();
    if raw.is_empty() {
        return None;
    }
    let path_only = raw.split(['?', '#']).next().unwrap_or("/");
    let mut sanitized = String::with_capacity(path_only.len().min(max_bytes));
    for (index, segment) in path_only.split('/').enumerate() {
        if index > 0 {
            sanitized.push('/');
        }
        if segment.is_empty() {
            continue;
        }
        if segment.chars().all(|character| character.is_ascii_digit()) {
            sanitized.push_str(":id");
        } else if looks_like_uuid(segment) {
            sanitized.push_str(":uuid");
        } else if segment.parse::<IpAddr>().is_ok() {
            sanitized.push_str(":ip");
        } else if segment.contains('@') {
            sanitized.push_str(":id");
        } else if looks_like_secret_segment(segment) {
            sanitized.push_str(":token");
        } else {
            for character in segment.chars() {
                if character.is_ascii_alphanumeric()
                    || matches!(character, '.' | '-' | '_' | '~' | '%' | ':')
                {
                    sanitized.push(character);
                } else {
                    sanitized.push('_');
                }
            }
        }
        if sanitized.len() >= max_bytes {
            break;
        }
    }
    if !sanitized.starts_with('/') {
        sanitized.insert(0, '/');
    }
    truncate_utf8(&mut sanitized, max_bytes.max(1));
    Some(sanitized)
}

pub fn parse_request_line(value: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(value) = value else {
        return (None, None);
    };
    let mut parts = value.split_whitespace();
    let method = parts.next().map(str::to_owned);
    let path = parts.next().map(str::to_owned);
    (method, path)
}

pub fn scan_outbound_payload(payload: &[u8], secrets: &[&str]) -> Result<()> {
    let text =
        std::str::from_utf8(payload).map_err(|_| anyhow::anyhow!("AI payload is not UTF-8"))?;
    let lower = text.to_ascii_lowercase();
    for marker in [
        "authorization:",
        "\"authorization\":",
        "proxy-authorization:",
        "\"proxy-authorization\":",
        "cookie:",
        "\"cookie\":",
        "set-cookie:",
        "\"set-cookie\":",
        "bearer ",
        "basic ",
        "-----begin private key",
        "-----begin rsa private key",
        "-----begin openssh private key",
        "password=",
        "password\":",
        "secret=",
        "secret\":",
        "token=",
        "sessionid=",
        "\"session\":",
    ] {
        if lower.contains(marker) {
            bail!("AI payload failed the strict privacy secret scan");
        }
    }
    for secret in secrets {
        let secret = secret.trim();
        if secret.len() >= 6 && text.contains(secret) {
            bail!("AI payload contains a configured secret and will not be sent");
        }
    }
    Ok(())
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        normalized[..digest.len()].copy_from_slice(&digest);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

pub fn hex_decode_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(&value[start..start + 2], 16).ok()?;
    }
    Some(output)
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_unspecified() || (ip.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn looks_like_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn looks_like_secret_segment(value: &str) -> bool {
    value.len() >= 20
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_=.".contains(character))
        && value.chars().any(|character| character.is_ascii_digit())
        && value
            .chars()
            .any(|character| character.is_ascii_alphabetic())
}

fn truncate_utf8(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut boundary = max_bytes.min(value.len());
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudonyms_are_stable_and_hide_addresses() {
        let key = [7u8; 32];
        let ip: IpAddr = "203.0.113.44".parse().unwrap();
        let first = pseudonymize_ip(&key, ip);
        let second = pseudonymize_ip(&key, ip);
        assert_eq!(first, second);
        assert!(first.starts_with("SRC_"));
        assert!(!first.contains("203.0.113.44"));
    }

    #[test]
    fn paths_drop_queries_and_identifiers() {
        assert_eq!(
            sanitize_path(Some("/api/users/12345?token=secret"), 256).as_deref(),
            Some("/api/users/:id")
        );
        assert_eq!(sanitize_path(Some("/.env"), 256).as_deref(), Some("/.env"));
    }

    #[test]
    fn paths_remove_email_ip_uuid_and_token_identifiers() {
        assert_eq!(
            sanitize_path(Some("/user/alice@example.com"), 256).as_deref(),
            Some("/user/:id")
        );
        assert_eq!(
            sanitize_path(Some("/host/192.168.1.25"), 256).as_deref(),
            Some("/host/:ip")
        );
        assert_eq!(
            sanitize_path(Some("/item/550e8400-e29b-41d4-a716-446655440000"), 256).as_deref(),
            Some("/item/:uuid")
        );
        assert_eq!(
            sanitize_path(Some("/reset/AbCdEfGhIjKlMnOpQrSt1234"), 256).as_deref(),
            Some("/reset/:token")
        );
    }

    #[test]
    fn scanner_rejects_configured_secrets() {
        let payload = br#"{"value":"super-secret-value"}"#;
        assert!(scan_outbound_payload(payload, &["super-secret-value"]).is_err());
        assert!(scan_outbound_payload(br#"{"path":"/.env"}"#, &["different-secret"]).is_ok());
    }

    #[test]
    fn scanner_rejects_adversarial_secret_shapes() {
        for payload in [
            br#"{"Authorization":"Bearer abcdefgh"}"#.as_slice(),
            br#"{"cookie":"sessionid=abcdefgh"}"#.as_slice(),
            br#"{"password":"abcdefgh"}"#.as_slice(),
            b"-----BEGIN OPENSSH PRIVATE KEY-----".as_slice(),
        ] {
            assert!(scan_outbound_payload(payload, &[]).is_err());
        }
    }

    #[test]
    fn manual_hmac_is_deterministic() {
        let digest = hmac_sha256(b"key", b"data");
        assert_eq!(hex_encode(&digest).len(), 64);
        assert_eq!(hex_decode_32(&hex_encode(&digest)), Some(digest));
    }
}
