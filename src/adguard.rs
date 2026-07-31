use std::time::Duration;

use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};

use std::path::Path;

use crate::{command::CommandRunner, config::AdGuardConfig};

pub async fn get_lan_ip(runner: &CommandRunner, nvram_cmd: &Path) -> String {
    if let Ok(res) = runner
        .run(nvram_cmd, ["get", "lan_ipaddr"], Duration::from_secs(3))
        .await
    {
        let ip = res.stdout.trim();
        if !ip.is_empty() && !res.simulated {
            return ip.to_string();
        }
    }
    "192.168.1.1".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewriteEntry {
    pub domain: String,
    pub answer: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionState {
    pub protection_enabled: bool,
}

#[derive(Clone)]
pub struct AdGuardClient {
    client: Client,
    endpoint: String,
}

impl AdGuardClient {
    pub fn new(config: &AdGuardConfig) -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        if !config.username.is_empty() {
            let auth = format!("{}:{}", config.username, config.password);
            let encoded = BASE64.encode(auth.as_bytes());
            headers.insert(
                header::AUTHORIZATION,
                header::HeaderValue::from_str(&format!("Basic {}", encoded))?,
            );
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .default_headers(headers)
            .build()?;

        let endpoint = config.api_endpoint.trim_end_matches('/').to_string();

        Ok(Self { client, endpoint })
    }

    pub async fn get_rewrites(&self) -> Result<Vec<RewriteEntry>> {
        let url = format!("{}/control/rewrite/list", self.endpoint);
        let res = self.client.get(&url).send().await?.error_for_status()?;
        let rewrites: Vec<RewriteEntry> = res.json().await?;
        Ok(rewrites)
    }

    async fn add_rewrite(&self, domain: &str, answer: &str) -> Result<()> {
        let url = format!("{}/control/rewrite/add", self.endpoint);
        let payload = RewriteEntry {
            domain: domain.to_string(),
            answer: answer.to_string(),
        };
        self.client
            .post(&url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Make sure AdGuard Home contains exactly one copy of this rewrite.
    ///
    /// AdGuard Home accepts duplicate calls to `/control/rewrite/add`, so an
    /// unconditional add is not idempotent. Read the current list first and
    /// only add when the rewrite is absent; if old duplicates exist, remove
    /// the extras while retaining one entry.
    pub async fn ensure_rewrite(&self, domain: &str, answer: &str) -> Result<()> {
        let existing = self.get_rewrites().await?;
        let matching = existing
            .iter()
            .filter(|rewrite| rewrite.domain == domain && rewrite.answer == answer)
            .count();

        match matching {
            0 => self.add_rewrite(domain, answer).await,
            1 => Ok(()),
            extras => {
                self.remove_excess_rewrites(domain, answer, extras).await?;
                let remaining = self
                    .get_rewrites()
                    .await?
                    .iter()
                    .filter(|rewrite| rewrite.domain == domain && rewrite.answer == answer)
                    .count();
                if remaining == 0 {
                    self.add_rewrite(domain, answer).await
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Remove duplicate entries from the whole AdGuard rewrite list.
    pub async fn deduplicate_rewrites(&self) -> Result<()> {
        let existing = self.get_rewrites().await?;
        let mut duplicate_keys = Vec::new();
        for rewrite in &existing {
            if existing.iter().filter(|item| *item == rewrite).count() > 1
                && !duplicate_keys.contains(rewrite)
            {
                duplicate_keys.push(rewrite.clone());
            }
        }

        for rewrite in duplicate_keys {
            self.ensure_rewrite(&rewrite.domain, &rewrite.answer)
                .await?;
        }
        Ok(())
    }

    pub async fn delete_rewrite(&self, domain: &str, answer: &str) -> Result<()> {
        let url = format!("{}/control/rewrite/delete", self.endpoint);
        let payload = RewriteEntry {
            domain: domain.to_string(),
            answer: answer.to_string(),
        };
        self.client
            .post(&url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn remove_all_rewrites(&self, domain: &str, answer: &str) -> Result<()> {
        let count = self
            .get_rewrites()
            .await?
            .iter()
            .filter(|rewrite| rewrite.domain == domain && rewrite.answer == answer)
            .count();

        self.remove_excess_rewrites(domain, answer, count + 1).await
    }

    async fn remove_excess_rewrites(
        &self,
        domain: &str,
        answer: &str,
        initial_count: usize,
    ) -> Result<()> {
        let max_deletes = initial_count.saturating_sub(1);
        for _ in 0..max_deletes {
            self.delete_rewrite(domain, answer).await?;
            let remaining = self
                .get_rewrites()
                .await?
                .iter()
                .filter(|rewrite| rewrite.domain == domain && rewrite.answer == answer)
                .count();
            if remaining <= 1 {
                return Ok(());
            }
        }

        let remaining = self
            .get_rewrites()
            .await?
            .iter()
            .filter(|rewrite| rewrite.domain == domain && rewrite.answer == answer)
            .count();
        if remaining > 1 {
            bail!("AdGuard rewrite cleanup did not converge for {domain}");
        }
        Ok(())
    }

    pub async fn toggle_protection(&self, enabled: bool, duration_ms: Option<u64>) -> Result<()> {
        let url = format!("{}/control/protection", self.endpoint);
        let payload = serde_json::json!({
            "protection_enabled": enabled,
            "duration": duration_ms.unwrap_or(0),
        });
        self.client
            .post(&url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_state_serde() {
        let state = ProtectionState {
            protection_enabled: true,
        };
        let json = serde_json::to_string(&state).unwrap();
        let decoded: ProtectionState = serde_json::from_str(&json).unwrap();
        assert!(decoded.protection_enabled);
    }

    #[test]
    fn test_adguard_client_new() {
        let config = AdGuardConfig {
            enabled: true,
            api_endpoint: "http://127.0.0.1:80/".to_string(),
            username: "admin".to_string(),
            password: "password".to_string(),
            lan_ip: "192.168.50.1".to_string(),
        };
        let client = AdGuardClient::new(&config);
        assert!(client.is_ok());
        assert_eq!(client.unwrap().endpoint, "http://127.0.0.1:80");
    }

    #[tokio::test]
    async fn test_get_lan_ip_fallback() {
        let runner = CommandRunner::new(true);
        let ip = get_lan_ip(&runner, Path::new("/usr/sbin/nvram")).await;
        assert_eq!(ip, "192.168.1.1");
    }
}
