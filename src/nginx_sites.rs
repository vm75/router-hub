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
                .or_else(|| key.split_once('/').map(|(_, name)| name.to_string()))
                .context("subfolder name is missing")?,
            NginxObjectKind::Subdomain => self
                .name
                .clone()
                .or_else(|| {
                    key.strip_suffix(&format!(".{}", self.domain))
                        .map(str::to_string)
                })
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
    config.nginx.root_dir.join("settings/sites.toml")
}

pub fn load(config: &AppConfig) -> Result<Sites> {
    let path = path(config);
    nginx::ensure_no_symlink_ancestors(&config.nginx.root_dir, &path)?;
    let sites: Sites = match fs::read_to_string(&path) {
        Ok(content) => toml::from_str(&content).context("invalid nginx settings/sites.toml")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Sites::default(),
        Err(error) => return Err(error.into()),
    };
    let mut identities = std::collections::BTreeSet::new();
    for (key, site) in &sites.sites {
        let name = site.object_name(key)?;
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
    for (key, existing) in &sites.sites {
        if existing.domain == domain
            && ((kind == NginxObjectKind::Domain && site.is_none())
                || (existing.kind == kind && existing.object_name(key)? == name))
        {
            remove.push(key.clone());
        }
    }
    for key in remove {
        sites.sites.remove(&key);
    }
    if let Some(site) = site {
        sites
            .sites
            .insert(format!("{}/{}/{}", kind.as_str(), domain, name), site);
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
