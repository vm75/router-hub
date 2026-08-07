use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::{Serialize, de::DeserializeOwned};
use tokio::{fs, sync::RwLock};
use tracing::warn;
use uuid::Uuid;

use crate::{
    command::CommandRunner,
    config::{AdGuardConfig, AppConfig},
    models::{CertificateMethod, CertificateSpec, FirewallPolicy, WolMachine},
    util::validate_simple_name,
};

#[derive(Clone)]
pub struct Stores {
    pub certificates: Arc<RwLock<Vec<CertificateSpec>>>,
    pub wol_machines: Arc<RwLock<Vec<WolMachine>>>,
    pub firewall_policy: Arc<RwLock<FirewallPolicy>>,
    pub adguard: Arc<RwLock<Option<AdGuardConfig>>>,
    data_dir: Arc<std::path::PathBuf>,
}

impl Stores {
    pub async fn load(config: &AppConfig) -> Result<Self> {
        let data_dir = Arc::new(config.paths.data_dir.clone());
        let certificates_path = data_dir.join("certificates.json");
        let mut certificates: Vec<CertificateSpec> = load_json(&certificates_path).await?;
        let mut discovered =
            discover_dehydrated_certificates(&config.certificates.certs_dir).await?;
        discovered.extend(discover_deployed_certificates(config).await?);
        let mut imported = 0;
        for spec in discovered {
            if certificates
                .iter()
                .any(|existing| existing.name == spec.name)
            {
                continue;
            }
            certificates.push(spec);
            imported += 1;
        }
        if imported > 0 {
            save_json(&certificates_path, &certificates).await?;
        }
        Ok(Self {
            certificates: Arc::new(RwLock::new(certificates)),
            wol_machines: Arc::new(RwLock::new(
                load_json(&data_dir.join("wol-machines.json")).await?,
            )),
            firewall_policy: Arc::new(RwLock::new(
                load_json_with_fallback(
                    &data_dir.join("firewall-policy.json"),
                    Path::new("/opt/etc/router-hub/firewall-policy.json"),
                )
                .await?,
            )),
            adguard: Arc::new(RwLock::new(
                load_json_optional(&data_dir.join("adguard.json")).await?,
            )),
            data_dir,
        })
    }

    pub async fn save_certificates(&self) -> Result<()> {
        save_json(
            &self.data_dir.join("certificates.json"),
            &*self.certificates.read().await,
        )
        .await
    }

    pub async fn save_wol_machines(&self) -> Result<()> {
        save_json(
            &self.data_dir.join("wol-machines.json"),
            &*self.wol_machines.read().await,
        )
        .await
    }

    pub async fn save_firewall_policy(&self) -> Result<()> {
        let policy_data = &*self.firewall_policy.read().await;
        save_json(&self.data_dir.join("firewall-policy.json"), policy_data).await?;
        let config_dir_policy = Path::new("/opt/etc/router-hub/firewall-policy.json");
        if config_dir_policy.exists()
            && config_dir_policy != self.data_dir.join("firewall-policy.json").as_path()
        {
            let _ = save_json(config_dir_policy, policy_data).await;
        }
        Ok(())
    }

    pub async fn save_adguard(&self) -> Result<()> {
        save_json(
            &self.data_dir.join("adguard.json"),
            &*self.adguard.read().await,
        )
        .await
    }
}

#[derive(Default)]
struct ParsedDehydratedConfig {
    ca: Option<String>,
    challenge_type: Option<String>,
    hook: Option<String>,
    hook_env: BTreeMap<String, String>,
    domains_path: Option<PathBuf>,
}

async fn discover_dehydrated_certificates(certificates_dir: &Path) -> Result<Vec<CertificateSpec>> {
    let mut entries = match fs::read_dir(certificates_dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read dehydrated certificate directory {}",
                    certificates_dir.display()
                )
            });
        }
    };
    let mut specs = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("cfg") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
            warn!(path = %path.display(), "skipping dehydrated config with a non-UTF-8 name");
            continue;
        };
        if !valid_certificate_name(name) {
            warn!(path = %path.display(), "skipping dehydrated config with an invalid certificate name");
            continue;
        }
        let domains_path = certificates_dir.join(format!("{name}.txt"));
        match load_dehydrated_certificate(&path, &domains_path, name).await {
            Ok(spec) => specs.push(spec),
            Err(error) => {
                warn!(path = %path.display(), %error, "skipping dehydrated certificate definition")
            }
        }
    }
    Ok(specs)
}

async fn discover_deployed_certificates(config: &AppConfig) -> Result<Vec<CertificateSpec>> {
    let certificates_dir = config.nginx.root_dir.join("certs");
    let mut entries = match fs::read_dir(&certificates_dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read deployed certificate directory {}",
                    certificates_dir.display()
                )
            });
        }
    };
    let runner = CommandRunner::new(config.test_mode);
    let mut specs = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if !entry.file_type().await?.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            warn!(path = %path.display(), "skipping deployed certificate with a non-UTF-8 name");
            continue;
        };
        if !valid_certificate_name(name) {
            warn!(path = %path.display(), "skipping deployed certificate with an invalid name");
            continue;
        }
        let cert_path = path.join("cert.pem");
        let fullchain_path = path.join("fullchain.pem");
        let inspect_path = if cert_path.exists() {
            cert_path
        } else if fullchain_path.exists() {
            fullchain_path
        } else {
            continue;
        };
        let result = match runner
            .run(
                &config.commands.openssl,
                vec![
                    "x509".to_string(),
                    "-in".to_string(),
                    inspect_path.to_string_lossy().to_string(),
                    "-noout".to_string(),
                    "-text".to_string(),
                ],
                Duration::from_secs(10),
            )
            .await
        {
            Ok(result) if result.success && !result.simulated => result,
            Ok(result) => {
                warn!(
                    path = %inspect_path.display(),
                    stderr = %result.stderr,
                    "unable to inspect deployed certificate"
                );
                continue;
            }
            Err(error) => {
                warn!(path = %inspect_path.display(), %error, "unable to inspect deployed certificate");
                continue;
            }
        };
        let domains = parse_certificate_domains(&result.stdout);
        if domains.is_empty() {
            warn!(path = %inspect_path.display(), "deployed certificate has no DNS subject names");
            continue;
        }
        let method = if domains.iter().any(|domain| domain.starts_with("*.")) {
            CertificateMethod::Dns
        } else {
            CertificateMethod::Http
        };
        specs.push(CertificateSpec {
            id: Uuid::new_v4(),
            name: name.into(),
            domains,
            method,
            hook: None,
            hook_env: BTreeMap::new(),
            staging: false,
            auto_renew: false,
            updated_at: Utc::now(),
        });
    }
    Ok(specs)
}

fn parse_certificate_domains(output: &str) -> Vec<String> {
    let mut domains = BTreeSet::new();
    for suffix in output.split("DNS:").skip(1) {
        let domain = suffix
            .split(|character: char| character == ',' || character.is_whitespace())
            .next()
            .unwrap_or_default()
            .trim();
        if !domain.is_empty() {
            domains.insert(domain.to_string());
        }
    }
    domains.into_iter().collect()
}

async fn load_dehydrated_certificate(
    config_path: &Path,
    domains_path: &Path,
    name: &str,
) -> Result<CertificateSpec> {
    let config = parse_dehydrated_config(&fs::read_to_string(config_path).await?)?;
    let challenge_type = config
        .challenge_type
        .as_deref()
        .context("missing CHALLENGETYPE")?;
    let method = match challenge_type {
        "http-01" => CertificateMethod::Http,
        "dns-01" => CertificateMethod::Dns,
        other => bail!("unsupported CHALLENGETYPE {other:?}"),
    };
    let domains_contents = match fs::read_to_string(domains_path).await {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let configured_path = config
                .domains_path
                .as_deref()
                .filter(|path| *path != domains_path)
                .context("missing dehydrated domain file and DOMAINS_TXT")?;
            fs::read_to_string(configured_path).await.with_context(|| {
                format!(
                    "failed to read dehydrated domain file {}",
                    configured_path.display()
                )
            })?
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read dehydrated domain file {}",
                    domains_path.display()
                )
            });
        }
    };
    let domains = parse_dehydrated_domains(&domains_contents)?;
    Ok(CertificateSpec {
        id: Uuid::new_v4(),
        name: name.into(),
        domains,
        method,
        hook: config.hook.map(Into::into),
        hook_env: config.hook_env,
        staging: config.ca.as_deref() == Some("letsencrypt-test"),
        auto_renew: true,
        updated_at: Utc::now(),
    })
}

fn parse_dehydrated_config(contents: &str) -> Result<ParsedDehydratedConfig> {
    let mut config = ParsedDehydratedConfig::default();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(assignment) = line.strip_prefix("export ") {
            let Some((name, value)) = assignment.split_once('=') else {
                continue;
            };
            if valid_hook_env_name(name.trim()) {
                if let Some(value) = parse_shell_value(value) {
                    config.hook_env.insert(name.trim().into(), value);
                }
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some(value) = parse_shell_value(value) else {
            continue;
        };
        match key.trim() {
            "CA" => config.ca = Some(value),
            "CHALLENGETYPE" => config.challenge_type = Some(value),
            "DOMAINS_TXT" if !value.is_empty() => config.domains_path = Some(value.into()),
            "HOOK" if !value.is_empty() => config.hook = Some(value),
            _ => {}
        }
    }
    Ok(config)
}

fn parse_shell_value(raw: &str) -> Option<String> {
    let value = raw.trim();
    if let Some(value) = value.strip_prefix('\'') {
        let mut chars = value.chars().peekable();
        let mut output = String::new();
        while let Some(character) = chars.next() {
            if character != '\'' {
                output.push(character);
                continue;
            }
            if chars.peek() == Some(&'\\') {
                chars.next();
                if chars.next() != Some('\'') || chars.next() != Some('\'') {
                    return None;
                }
                output.push('\'');
                continue;
            }
            return chars.next().is_none().then_some(output);
        }
        return None;
    }
    if value.starts_with('"') {
        return value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .map(ToOwned::to_owned);
    }
    if value.chars().any(char::is_whitespace) {
        None
    } else {
        Some(value.into())
    }
}

fn parse_dehydrated_domains(contents: &str) -> Result<Vec<String>> {
    let mut domains = Vec::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let domain_list = line
            .split_once('>')
            .map_or(line, |(domains, _)| domains.trim());
        for domain in domain_list.split_whitespace() {
            if !valid_domain(domain) {
                bail!("invalid domain {domain:?}");
            }
            if !domains.iter().any(|existing| existing == domain) {
                domains.push(domain.to_string());
            }
        }
    }
    if domains.is_empty() {
        bail!("domain file contains no domains");
    }
    Ok(domains)
}

fn valid_certificate_name(name: &str) -> bool {
    validate_simple_name(name, "certificate name").is_ok()
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && !name.ends_with('.')
}

fn valid_domain(domain: &str) -> bool {
    let hostname = domain.strip_prefix("*.").unwrap_or(domain);
    let wildcard_count = domain.matches('*').count();
    let wildcard_allowed = if domain.starts_with("*.") { 1 } else { 0 };
    !hostname.is_empty()
        && hostname.len() <= 253
        && wildcard_count <= wildcard_allowed
        && !domain.chars().any(|character| {
            character.is_whitespace()
                || matches!(character, '#' | '>' | '\\' | '\'' | '"' | '/' | ':')
        })
        && hostname
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
}

fn valid_hook_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().enumerate().all(|(index, character)| {
            if index == 0 {
                character.is_ascii_alphabetic() || character == '_'
            } else {
                character.is_ascii_alphanumeric() || character == '_'
            }
        })
}

async fn load_json<T>(path: &Path) -> Result<T>
where
    T: DeserializeOwned + Default,
{
    match fs::read(path).await {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

async fn load_json_optional<T>(path: &Path) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    match fs::read(path).await {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("failed to parse {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

async fn load_json_with_fallback<T>(primary: &Path, fallback: &Path) -> Result<T>
where
    T: DeserializeOwned + Default,
{
    if primary.exists() {
        load_json(primary).await
    } else if fallback.exists() {
        load_json(fallback).await
    } else {
        load_json(primary).await
    }
}

async fn save_json<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let temp = path.with_extension(format!("json.tmp-{}", Uuid::new_v4().simple()));
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(&temp, bytes)
        .await
        .with_context(|| format!("failed to write {}", temp.display()))?;
    fs::rename(&temp, path)
        .await
        .with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_load_defaults_when_missing() {
        let temp = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.paths.data_dir = temp.path().to_path_buf();

        let stores = Stores::load(&config).await.unwrap();
        assert!(stores.certificates.read().await.is_empty());
        assert!(stores.wol_machines.read().await.is_empty());
        assert!(!stores.firewall_policy.read().await.enabled);
    }

    #[tokio::test]
    async fn test_discovers_reference_style_dehydrated_certificate() {
        let temp = tempdir().unwrap();
        let certs_dir = temp.path().join("dehydrated/certs");
        fs::create_dir_all(&certs_dir).await.unwrap();
        fs::write(
            certs_dir.join("example_duckdns_org.cfg"),
            "CA='letsencrypt'\nAUTO_CLEANUP='yes'\nDOMAINS_TXT='/old/path/example_duckdns_org.txt'\nCHALLENGETYPE='dns-01'\nHOOK='/opt/hooks/dehydrated-duckdns-hook.sh'\nexport DUCKDNS_TOKEN='token-value'\n",
        )
        .await
        .unwrap();
        fs::write(
            certs_dir.join("example_duckdns_org.txt"),
            "\n# example.duckdns.org-start\n*.example.duckdns.org > example_duckdns_org\n# example.duckdns.org-end\n",
        )
        .await
        .unwrap();

        let mut config = AppConfig::default();
        config.paths.data_dir = temp.path().join("data");
        config.certificates.certs_dir = certs_dir;
        let stores = Stores::load(&config).await.unwrap();
        let certificates = stores.certificates.read().await;
        assert_eq!(certificates.len(), 1);
        assert_eq!(certificates[0].name, "example_duckdns_org");
        assert_eq!(
            certificates[0].domains,
            vec!["*.example.duckdns.org".to_string()]
        );
        assert!(matches!(certificates[0].method, CertificateMethod::Dns));
        assert_eq!(
            certificates[0].hook.as_deref(),
            Some(Path::new("/opt/hooks/dehydrated-duckdns-hook.sh"))
        );
        assert_eq!(
            certificates[0].hook_env.get("DUCKDNS_TOKEN"),
            Some(&"token-value".to_string())
        );
        assert!(temp.path().join("data/certificates.json").exists());
    }

    #[tokio::test]
    async fn test_discovers_wildcard_certificate_from_configured_domains_path() {
        let temp = tempdir().unwrap();
        let certs_dir = temp.path().join("router-config/dehydrated/certs");
        let domains_path = temp.path().join("home/.certs/example_dev.txt");
        fs::create_dir_all(&certs_dir).await.unwrap();
        fs::create_dir_all(domains_path.parent().unwrap())
            .await
            .unwrap();
        fs::write(
            certs_dir.join("example_dev.cfg"),
            format!(
                "OPENSSL_CNF='/opt/etc/openssl.cnf'\nCA='letsencrypt'\nAUTO_CLEANUP='yes'\nDOMAINS_TXT='{}'\nCHALLENGETYPE='dns-01'\nHOOK='/opt/hooks/dehydrated-namesilo-hook.sh'\nexport NAMESILO_API_KEY='api-key'\n",
                domains_path.display()
            ),
        )
        .await
        .unwrap();
        fs::write(
            &domains_path,
            "\n# example.xyz-start\n*.example.xyz > example_dev\n# example.xyz-end\n",
        )
        .await
        .unwrap();

        let mut config = AppConfig::default();
        config.paths.data_dir = temp.path().join("data");
        config.certificates.certs_dir = certs_dir;
        let stores = Stores::load(&config).await.unwrap();
        let certificates = stores.certificates.read().await;
        assert_eq!(certificates.len(), 1);
        assert_eq!(certificates[0].name, "example_dev");
        assert_eq!(certificates[0].domains, vec!["*.example.xyz"]);
        assert!(matches!(certificates[0].method, CertificateMethod::Dns));
        assert_eq!(
            certificates[0].hook.as_deref(),
            Some(Path::new("/opt/hooks/dehydrated-namesilo-hook.sh"))
        );
        assert_eq!(
            certificates[0].hook_env.get("NAMESILO_API_KEY"),
            Some(&"api-key".to_string())
        );
    }

    #[tokio::test]
    async fn test_discovers_deployed_wildcard_certificate_without_dehydrated_definition() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap();
        let certificate_dir = temp.path().join("nginx/certs/example_dev");
        fs::create_dir_all(&certificate_dir).await.unwrap();
        fs::write(certificate_dir.join("cert.pem"), "certificate fixture")
            .await
            .unwrap();
        fs::write(certificate_dir.join("fullchain.pem"), "fullchain fixture")
            .await
            .unwrap();

        let openssl = temp.path().join("mock-openssl");
        fs::write(
            &openssl,
            "#!/bin/sh\nprintf '%s\\n' 'X509v3 Subject Alternative Name:' '    DNS:example.xyz, DNS:*.example.xyz'\n",
        )
        .await
        .unwrap();
        fs::set_permissions(&openssl, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();

        let mut config = AppConfig::default();
        config.paths.data_dir = temp.path().join("data");
        config.certificates.certs_dir = temp.path().join("dehydrated/certs");
        config.nginx.root_dir = temp.path().join("nginx");
        config.commands.openssl = openssl;

        let stores = Stores::load(&config).await.unwrap();
        let certificates = stores.certificates.read().await;
        assert_eq!(certificates.len(), 1);
        assert_eq!(certificates[0].name, "example_dev");
        assert_eq!(
            certificates[0].domains,
            vec!["*.example.xyz".to_string(), "example.xyz".to_string()]
        );
        assert!(matches!(certificates[0].method, CertificateMethod::Dns));
        assert!(!certificates[0].auto_renew);
        assert!(certificates[0].hook.is_none());
        assert!(temp.path().join("data/certificates.json").exists());
    }

    #[tokio::test]
    async fn test_atomic_save_and_reload() {
        let temp = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.paths.data_dir = temp.path().to_path_buf();

        let stores = Stores::load(&config).await.unwrap();

        // Add a WolMachine
        let machine = WolMachine {
            id: Uuid::new_v4(),
            name: "Server".into(),
            mac: "00:11:22:33:44:55".into(),
            broadcast: "192.168.1.255".parse().unwrap(),
            port: 9,
            notes: "Home server".into(),
            updated_at: chrono::Utc::now(),
        };

        stores.wol_machines.write().await.push(machine.clone());
        stores.save_wol_machines().await.unwrap();

        // Reload stores from same directory
        let reloaded = Stores::load(&config).await.unwrap();
        let machines = reloaded.wol_machines.read().await;
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0].id, machine.id);
        assert_eq!(machines[0].name, "Server");
    }

    #[tokio::test]
    async fn test_corrupted_json_error() {
        let temp = tempdir().unwrap();
        let json_path = temp.path().join("wol-machines.json");
        tokio::fs::write(&json_path, "{ malformed json")
            .await
            .unwrap();

        let res: Result<Vec<WolMachine>> = load_json(&json_path).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_firewall_policy_fallback_load() {
        let primary_temp = tempdir().unwrap();
        let fallback_temp = tempdir().unwrap();

        let primary_path = primary_temp.path().join("firewall-policy.json");
        let fallback_path = fallback_temp.path().join("firewall-policy.json");

        let policy = FirewallPolicy {
            enabled: true,
            observe_only: false,
            rules: vec![],
            allowlist: vec![],
            tuning: None,
        };
        save_json(&fallback_path, &policy).await.unwrap();

        let loaded: FirewallPolicy = load_json_with_fallback(&primary_path, &fallback_path)
            .await
            .unwrap();
        assert!(loaded.enabled);
    }
}
