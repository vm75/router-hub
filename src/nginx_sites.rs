//! Persistent inputs for code-generated nginx sites.
use std::{collections::BTreeMap, fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    config::AppConfig,
    models::NginxObjectKind,
    nginx,
    nginx_render::{self, Settings},
};

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sites {
    pub sites: BTreeMap<String, Site>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Site {
    pub kind: NginxObjectKind,
    pub domain: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub subfolder: Option<String>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(flatten)]
    pub settings: Settings,
}

impl Site {
    pub fn object_name(&self, key: &str) -> Result<String> {
        let name = match self.kind {
            NginxObjectKind::Domain => self.domain.clone(),
            NginxObjectKind::Subfolder => self
                .subfolder
                .clone()
                .or_else(|| {
                    key.strip_prefix(&format!("subfolder/{}/", self.domain))
                        .map(str::to_string)
                })
                .or_else(|| {
                    key.strip_prefix(&format!("{}/", self.domain))
                        .map(str::to_string)
                })
                .or_else(|| key.split_once('/').map(|(_, name)| name.to_string()))
                .context("subfolder name is missing")?,
            NginxObjectKind::Subdomain => self
                .name
                .clone()
                .or_else(|| {
                    key.strip_suffix(&format!(".{}", self.domain))
                        .map(str::to_string)
                })
                .or_else(|| {
                    key.strip_prefix(&format!("subdomain/{}/", self.domain))
                        .map(str::to_string)
                })
                .or_else(|| {
                    key.strip_prefix(&format!("{}/", self.domain))
                        .map(str::to_string)
                })
                .or_else(|| key.rsplit_once('/').map(|(_, name)| name.to_string()))
                .context("subdomain name is missing")?,
        };
        nginx::validate_name(&self.domain, "domain")?;
        nginx::validate_name(&name, "site name")?;
        nginx_render::validate_site(&self.settings)?;
        nginx::validate_site_upstream(self.upstream.as_deref())?;
        Ok(name)
    }
}

pub fn path(config: &AppConfig) -> PathBuf {
    config.nginx.inputs_dir.join("sites.toml")
}

pub fn load(config: &AppConfig) -> Result<Sites> {
    let path = path(config);
    nginx_render::require_migrated_input(config, "sites.toml")?;
    let mut sites: Sites = match fs::read_to_string(&path) {
        Ok(content) => toml::from_str(&content).context("invalid managed nginx sites.toml")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Sites::default(),
        Err(error) => return Err(error.into()),
    };
    let mut identities = std::collections::BTreeSet::new();
    for (key, site) in &mut sites.sites {
        let name = site.object_name(key)?;
        if site.name.is_none() && site.kind == NginxObjectKind::Subdomain {
            site.name = Some(name.clone());
        }
        if site.subfolder.is_none() && site.kind == NginxObjectKind::Subfolder {
            site.subfolder = Some(name.clone());
        }
        if !identities.insert((site.kind.as_str(), &site.domain, name)) {
            bail!("duplicate managed site identity");
        }
    }
    Ok(sites)
}

pub fn find(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
) -> Result<Option<Site>> {
    for (key, site) in load(config)?.sites {
        if site.kind == kind && site.domain == domain && site.object_name(&key)? == name {
            return Ok(Some(site));
        }
    }
    Ok(None)
}

/// Hold this guard through nginx validation and reload; dropping it restores the inputs.
pub fn save(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
    site: Option<Site>,
) -> Result<nginx_render::FileTransaction> {
    let mut sites = load(config)?;
    let mut remove = Vec::new();
    let mut existing_key = None;
    for (key, existing) in &sites.sites {
        if existing.domain == domain
            && ((kind == NginxObjectKind::Domain && site.is_none())
                || (existing.kind == kind && existing.object_name(key)? == name))
        {
            remove.push(key.clone());
            if existing_key.is_none() {
                existing_key = Some(key.clone());
            }
        }
    }
    for key in remove {
        sites.sites.remove(&key);
    }
    if let Some(mut site) = site {
        if site.name.is_none() && kind == NginxObjectKind::Subdomain {
            site.name = Some(name.to_string());
        }
        if site.subfolder.is_none() && kind == NginxObjectKind::Subfolder {
            site.subfolder = Some(name.to_string());
        }
        let key = existing_key.unwrap_or_else(|| format!("{}/{}/{}", kind.as_str(), domain, name));
        if sites.sites.contains_key(&key) {
            bail!("managed site key {key:?} belongs to another site");
        }
        sites.sites.insert(key, site);
    }
    nginx_render::FileTransaction::apply(
        config,
        [(path(config), toml::to_string_pretty(&sites)?)].into(),
    )
}

pub fn settings(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
) -> Result<Option<Settings>> {
    Ok(find(config, kind, domain, name)?.map(|site| site.settings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_name_resolves_various_subdomain_and_subfolder_keys() {
        let subdomain_site = Site {
            kind: NginxObjectKind::Subdomain,
            domain: "example.test".into(),
            name: None,
            server_name: "media.example.test".into(),
            subfolder: None,
            upstream: Some("http://127.0.0.1:8081".into()),
            enabled: true,
            settings: Settings::default(),
        };

        // Key as media.example.test (standard examples/hand-written)
        assert_eq!(
            subdomain_site.object_name("media.example.test").unwrap(),
            "media"
        );
        // Key as subdomain/example.test/media (legacy save path)
        assert_eq!(
            subdomain_site
                .object_name("subdomain/example.test/media")
                .unwrap(),
            "media"
        );
        // Key as example.test/media
        assert_eq!(
            subdomain_site.object_name("example.test/media").unwrap(),
            "media"
        );

        let subfolder_site = Site {
            kind: NginxObjectKind::Subfolder,
            domain: "example.test".into(),
            name: None,
            server_name: "".into(),
            subfolder: None,
            upstream: Some("http://127.0.0.1:8082".into()),
            enabled: true,
            settings: Settings::default(),
        };

        assert_eq!(
            subfolder_site.object_name("example.test/app").unwrap(),
            "app"
        );
        assert_eq!(
            subfolder_site
                .object_name("subfolder/example.test/app")
                .unwrap(),
            "app"
        );
    }

    #[test]
    fn save_and_reload_subdomain_without_explicit_name_field() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.nginx.root_dir = temp.path().to_path_buf();
        config.nginx.inputs_dir = temp.path().join("router-hub/nginx");
        std::fs::create_dir_all(&config.nginx.inputs_dir).unwrap();

        // Write a sites.toml where subdomain does NOT have `name` field
        let initial_toml = r#"
[sites."media.example.test"]
kind = "subdomain"
domain = "example.test"
server_name = "media.example.test"
upstream = "http://127.0.0.1:8081"
enabled = true
"#;
        std::fs::write(path(&config), initial_toml).unwrap();

        let mut site = find(&config, NginxObjectKind::Subdomain, "example.test", "media")
            .unwrap()
            .expect("subdomain should be found");
        assert!(site.enabled);
        assert_eq!(site.name.as_deref(), Some("media"));

        // Disable the subdomain and save
        site.enabled = false;
        let tx = save(
            &config,
            NginxObjectKind::Subdomain,
            "example.test",
            "media",
            Some(site),
        )
        .unwrap();
        tx.commit();

        // Reload should succeed without "subdomain name is missing" error
        let reloaded = find(&config, NginxObjectKind::Subdomain, "example.test", "media")
            .unwrap()
            .expect("subdomain should still be found");
        assert!(!reloaded.enabled);
        assert_eq!(reloaded.name.as_deref(), Some("media"));
        assert!(
            load(&config)
                .unwrap()
                .sites
                .contains_key("media.example.test")
        );
    }

    #[test]
    fn saving_overlapping_hostname_preserves_both_site_identities() {
        for existing_kind in [NginxObjectKind::Domain, NginxObjectKind::Subdomain] {
            let temp = tempfile::tempdir().unwrap();
            let mut config = AppConfig::default();
            config.nginx.root_dir = temp.path().into();
            config.nginx.inputs_dir = temp.path().join("router-hub/nginx");
            std::fs::create_dir_all(&config.nginx.inputs_dir).unwrap();
            let domain = Site {
                kind: NginxObjectKind::Domain,
                domain: "api.example.test".into(),
                name: None,
                server_name: "api.example.test".into(),
                subfolder: None,
                upstream: Some("http://127.0.0.1:8080".into()),
                enabled: true,
                settings: Settings::new(),
            };
            let subdomain = Site {
                kind: NginxObjectKind::Subdomain,
                domain: "example.test".into(),
                name: Some("api".into()),
                upstream: Some("http://127.0.0.1:8081".into()),
                enabled: false,
                ..domain.clone()
            };
            let (existing, new_site, new_name) = if existing_kind == NginxObjectKind::Domain {
                (domain, subdomain, "api")
            } else {
                (subdomain, domain, "api.example.test")
            };
            let initial = Sites {
                sites: [("api.example.test".into(), existing.clone())].into(),
            };
            std::fs::write(path(&config), toml::to_string_pretty(&initial).unwrap()).unwrap();
            save(
                &config,
                new_site.kind,
                &new_site.domain,
                new_name,
                Some(new_site.clone()),
            )
            .unwrap()
            .commit();

            let reloaded = load(&config).unwrap();
            assert_eq!(reloaded.sites.len(), 2);
            assert_eq!(reloaded.sites["api.example.test"].kind, existing_kind);
            for (site, name) in [
                (
                    &existing,
                    if existing_kind == NginxObjectKind::Domain {
                        "api.example.test"
                    } else {
                        "api"
                    },
                ),
                (&new_site, new_name),
            ] {
                let saved = find(&config, site.kind, &site.domain, name)
                    .unwrap()
                    .unwrap();
                assert_eq!(saved.enabled, site.enabled);
                assert_eq!(saved.upstream, site.upstream);
            }
        }
    }

    #[test]
    fn conflicting_handwritten_key_is_rejected_without_changing_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.nginx.root_dir = temp.path().into();
        config.nginx.inputs_dir = temp.path().join("router-hub/nginx");
        std::fs::create_dir_all(&config.nginx.inputs_dir).unwrap();
        let original = r#"
[sites."subdomain/example.test/api"]
kind = "domain"
domain = "other.test"
enabled = true
"#;
        std::fs::write(path(&config), original).unwrap();
        let site = Site {
            kind: NginxObjectKind::Subdomain,
            domain: "example.test".into(),
            name: Some("api".into()),
            server_name: "api.example.test".into(),
            subfolder: None,
            upstream: None,
            enabled: false,
            settings: Settings::new(),
        };
        let error = match save(&config, site.kind, &site.domain, "api", Some(site.clone())) {
            Ok(_) => panic!("conflicting key must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("belongs to another site"));
        assert_eq!(std::fs::read_to_string(path(&config)).unwrap(), original);
    }
}
