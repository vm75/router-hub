//! Declarative, version-controlled nginx sites. Existing .conf sites remain authoritative
//! unless an adjacent .toml file explicitly opts into composition.
use std::{fs, path::PathBuf, process::Command};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    config::AppConfig,
    models::NginxObjectKind,
    nginx,
};

fn version() -> u8 { 1 }

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    #[default]
    Public,
    Lan,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootMode {
    #[default]
    Subfolders,
    Proxy,
    ProxyAndSubfolders,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubfolderMode {
    #[default]
    Standard,
    Pwa,
}

/// Only capabilities that are represented by the currently shipped/deployed templates.
/// Add new capabilities here deliberately, with validation and rendering tests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SiteOptions {
    pub access: Access,
    pub root: RootMode,
    pub subfolder: SubfolderMode,
    pub large_upload: bool,
    pub long_lived: bool,
    pub streaming: bool,
    pub websocket: bool,
    pub pwa: bool,
    pub sessions_lan_only: bool,
    pub strip_origin: bool,
    pub body_size: Option<String>,
    pub read_timeout: Option<String>,
    pub send_timeout: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteDefinition {
    #[serde(default = "version")]
    pub schema_version: u8,
    pub kind: NginxObjectKind,
    pub domain: String,
    pub name: String,
    #[serde(default)]
    pub server_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    #[serde(default)]
    pub options: SiteOptions,
}

impl SiteDefinition {
    pub fn new(kind: NginxObjectKind, domain: &str, name: &str,
        server_names: &[String], upstream: Option<&str>, options: SiteOptions) -> Self {
        Self {
            schema_version: version(),
            kind,
            domain: domain.into(),
            name: name.into(),
            server_names: server_names.to_vec(),
            upstream: upstream.map(str::to_string),
            options,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 { bail!("unsupported nginx site schema_version"); }
        nginx::validate_name(&self.domain, "domain")?;
        nginx::validate_name(&self.name, "name")?;
        if self.kind == NginxObjectKind::Domain && self.domain != self.name {
            bail!("domain name must equal its domain");
        }
        let names = nginx::normalize_server_names(
            self.kind, &self.domain, &self.name, &self.server_names)?;
        if self.kind == NginxObjectKind::Subfolder && names != vec![self.domain.clone()] {
            bail!("subfolder server_names must be the parent domain");
        }
        nginx::validate_site_upstream(self.kind, self.upstream.as_deref())?;
        let o = &self.options;
        if let Some(size) = &o.body_size { validate_size(size)?; }
        if let Some(value) = &o.read_timeout { validate_duration(value)?; }
        if let Some(value) = &o.send_timeout { validate_duration(value)?; }
        if self.kind != NginxObjectKind::Domain && o.root != RootMode::Subfolders {
            bail!("root routing applies only to domain sites");
        }
        if self.kind != NginxObjectKind::Subfolder && o.subfolder != SubfolderMode::Standard {
            bail!("subfolder mode applies only to subfolder sites");
        }
        if self.kind == NginxObjectKind::Subfolder {
            if o.large_upload || o.long_lived || o.streaming || o.websocket
                || o.pwa || o.sessions_lan_only || o.strip_origin
                || o.body_size.is_some() || o.read_timeout.is_some()
                || o.send_timeout.is_some() {
                bail!("subfolder currently supports only access and standard/pwa mode; use custom nginx for other behavior");
            }
        } else if self.kind == NginxObjectKind::Domain {
            if o.streaming || o.websocket || o.pwa || o.sessions_lan_only || o.strip_origin {
                bail!("these proxy capabilities are supported only on subdomains");
            }
            if o.root == RootMode::Subfolders
                && (o.large_upload || o.long_lived || o.read_timeout.is_some()
                    || o.send_timeout.is_some())
            {
                bail!("proxy capabilities require a domain proxy root");
            }
        }
        if o.sessions_lan_only && !o.streaming {
            bail!("sessions_lan_only requires streaming");
        }
        if o.pwa && o.access != Access::Lan {
            bail!("the deployed subdomain PWA profile requires LAN access");
        }
        if (self.kind == NginxObjectKind::Subdomain
            || self.kind == NginxObjectKind::Subfolder
            || (self.kind == NginxObjectKind::Domain && o.root != RootMode::Subfolders))
            && self.upstream.as_deref().is_none_or(str::is_empty)
        {
            bail!("a proxied composed site requires an upstream URL");
        }
        Ok(())
    }

    pub fn render(&self) -> Result<String> {
        self.validate()?;
        let o = &self.options;
        let names = nginx::normalize_server_names(
            self.kind, &self.domain, &self.name, &self.server_names)?.join(" ");
        let mut out = String::from("# router-hub-composed: 1\n# Source: adjacent .toml (do not edit this file)\n");
        if self.kind == NginxObjectKind::Subfolder {
            emit(&mut out, 0, &format!("location ^~ /{}/ {{", self.name));
            if o.access == Access::Lan { emit(&mut out, 1, "include snippets/restrict.conf;"); }
            emit(&mut out, 1, &format!("rewrite ^/{}/(.*)$ /$1 break;", regex::escape(&self.name)));
            emit(&mut out, 1, "include snippets/subfolder-proxy-pass.conf;");
            match o.subfolder {
                SubfolderMode::Standard => emit(&mut out, 1, "include snippets/proxy-params.conf;"),
                SubfolderMode::Pwa => {
                    emit(&mut out, 1, "include snippets/proxy-pwa.conf;");
                    emit(&mut out, 1, "include snippets/proxy-websocket.conf;");
                    emit(&mut out, 1, "include snippets/proxy-byte-ranges.conf;");
                    emit(&mut out, 1, "include snippets/pwa-no-cache.conf;");
                }
            }
            emit(&mut out, 0, "}");
            return Ok(out);
        }

        emit(&mut out, 0, "server {");
        emit(&mut out, 1, &format!("server_name {names};"));
        if o.access == Access::Lan { emit(&mut out, 1, "include snippets/restrict.conf;"); }
        emit(&mut out, 1, "include snippets/ssl.conf;");
        if self.kind == NginxObjectKind::Domain {
            emit(&mut out, 1, "include snippets/acme-challenge.conf;");
        }
        emit(&mut out, 1, "include snippets/security-headers.conf;");
        if o.pwa { emit(&mut out, 1, "include snippets/pwa.conf;"); }
        if self.kind == NginxObjectKind::Domain && o.root != RootMode::Proxy {
            if o.body_size.is_none() { emit(&mut out, 1, "client_max_body_size 100M;"); }
            emit(&mut out, 1, &format!(
                "include domains-enabled/{}/subfolders-enabled/*.conf;", self.domain));
        }
        if self.kind == NginxObjectKind::Domain && o.root == RootMode::Subfolders {
            if let Some(size) = &o.body_size { emit(&mut out, 1, &format!("client_max_body_size {size};")); }
            emit(&mut out, 1, "location / { return 404; }");
            emit(&mut out, 0, "}");
            return Ok(out);
        }
        emit(&mut out, 1, "location / {");
        if o.strip_origin { emit(&mut out, 2, "proxy_set_header Origin \"\";"); }
        emit(&mut out, 2, "include snippets/proxy-common.conf;");
        if let Some(size) = o.body_size.as_deref().or(if o.large_upload { Some("5G") } else { None }) {
            emit(&mut out, 2, &format!("client_max_body_size {size};"));
        }
        if o.large_upload { emit(&mut out, 2, "proxy_request_buffering off;"); }
        if o.streaming { emit(&mut out, 2, "proxy_buffering off;"); }
        let timeouts = o.long_lived || o.large_upload;
        let default_timeout = if timeouts { Some("3600s") }
            else if o.websocket { Some("60s") } else { None };
        if let Some(timeout) = o.read_timeout.as_deref().or(default_timeout) {
            emit(&mut out, 2, &format!("proxy_read_timeout {timeout};"));
        }
        if let Some(timeout) = o.send_timeout.as_deref().or(default_timeout) {
            emit(&mut out, 2, &format!("proxy_send_timeout {timeout};"));
        }
        if self.kind == NginxObjectKind::Domain {
            emit(&mut out, 2, "proxy_pass $domain_upstream;");
        } else {
            emit(&mut out, 2, "include snippets/subdomain-proxy-pass.conf;");
        }
        emit(&mut out, 1, "}");
        if o.sessions_lan_only {
            emit(&mut out, 1, "location /Sessions {");
            emit(&mut out, 2, "access_log off;");
            emit(&mut out, 2, "include snippets/restrict.conf;");
            emit(&mut out, 2, "include snippets/proxy-common.conf;");
            emit(&mut out, 2, "include snippets/subdomain-proxy-pass.conf;");
            emit(&mut out, 1, "}");
        }
        emit(&mut out, 0, "}");
        Ok(out)
    }
}

fn emit(out: &mut String, indent: usize, line: &str) {
    out.push_str(&"    ".repeat(indent));
    out.push_str(line);
    out.push('\n');
}

fn validate_number_unit(input: &str, units: &[char]) -> Result<()> {
    let digits = input.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let unit = &input[digits.len()..];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit())
        || digits.parse::<u64>().unwrap_or(0) == 0
        || (unit.len() != 1 || !unit.chars().all(|c| units.contains(&c))) {
        bail!("invalid nginx numeric parameter: {input}");
    }
    Ok(())
}
fn validate_size(value: &str) -> Result<()> {
    validate_number_unit(value, &['k', 'K', 'm', 'M', 'g', 'G'])
}
fn validate_duration(value: &str) -> Result<()> {
    validate_number_unit(value, &['s', 'm', 'h', 'd'])
}

pub fn definition_path(config: &AppConfig, kind: NginxObjectKind,
    domain: &str, name: &str) -> Result<PathBuf> {
    Ok(nginx::available_path(config, kind, domain, name)?.with_extension("toml"))
}

pub fn read(config: &AppConfig, kind: NginxObjectKind, domain: &str,
    name: &str) -> Result<Option<SiteDefinition>> {
    let path = definition_path(config, kind, domain, name)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() { bail!("site definition must be a regular file"); }
    let value = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let spec: SiteDefinition = toml::from_str(&value)
        .with_context(|| format!("invalid site definition {}", path.display()))?;
    if spec.kind != kind || spec.domain != domain || spec.name != name {
        bail!("site definition identity does not match its file path: {}", path.display());
    }
    spec.validate()?;
    Ok(Some(spec))
}

pub fn write(config: &AppConfig, spec: &SiteDefinition) -> Result<()> {
    spec.validate()?;
    let path = definition_path(config, spec.kind, &spec.domain, &spec.name)?;
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata.file_type().is_file() { bail!("refusing non-regular site definition"); }
    }
    let content = toml::to_string_pretty(spec)?;
    nginx::atomic_write(&path, content.as_bytes())
}

pub fn remove(config: &AppConfig, kind: NginxObjectKind,
    domain: &str, name: &str) -> Result<()> {
    let path = definition_path(config, kind, domain, name)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Explicit apply operation for Git-managed TOML edits. Syntax tests the whole
/// generated tree before accepting it, and restores every changed .conf on failure.
/// Does not reload a running nginx; callers control the deployment window.
pub fn apply_all(config: &AppConfig) -> Result<usize> {
    let mut specs = Vec::new();
    for object in nginx::list_objects(config, false)? {
        if let Some(spec) = read(config, object.kind, &object.domain, &object.name)? {
            let path = nginx::available_path(config, object.kind, &object.domain, &object.name)?;
            let old = fs::read_to_string(&path)?;
            let new = spec.render()?;
            specs.push((spec, path, old, new));
        }
    }
    if specs.is_empty() { return Ok(0); }

    // All generated config and auxiliary maps form one transaction. A Git edit
    // can change server aliases or an upstream even if the proxy body is unchanged.
    let auxiliary_paths = [
        &config.nginx.domain_upstream_map_path,
        &config.nginx.subdomain_upstream_map_path,
        &config.nginx.subfolder_upstream_map_path,
        &config.nginx.http_forwarder_path,
    ];
    let backups = auxiliary_paths.iter().map(|path| {
        match fs::read(path) {
            Ok(content) => Ok(Some(content)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }).collect::<std::io::Result<Vec<_>>>()?;

    let apply = (|| -> Result<()> {
        for (_, path, old, new) in &specs {
            if old != new { nginx::atomic_write(path, new.as_bytes())?; }
        }
        for (spec, _, old, new) in &specs {
            let old_names = nginx::normalize_server_names(
                spec.kind, &spec.domain, &spec.name, &nginx::extract_server_names(old))?;
            let new_names = nginx::normalize_server_names(
                spec.kind, &spec.domain, &spec.name, &spec.server_names)?;
            let old_key = if spec.kind == NginxObjectKind::Subfolder {
                Some(nginx::subfolder_map_key(old, &spec.name)?)
            } else { None };
            let new_key = if spec.kind == NginxObjectKind::Subfolder {
                Some(nginx::subfolder_map_key(new, &spec.name)?)
            } else { None };
            nginx::sync_site_upstream(
                config, spec.kind, &spec.domain, &spec.name,
                old_key.as_deref(), new_key.as_deref(),
                &old_names, &new_names, spec.upstream.as_deref())?;
        }
        nginx::reconcile_http_forwarder(config)?;
        let mut command = Command::new(&config.commands.nginx);
        if let Some(prefix) = &config.nginx.prefix_path {
            command.arg("-p").arg(prefix);
        }
        let output = command.arg("-t").arg("-c").arg(&config.nginx.config_path).output()
            .context("unable to run nginx -t")?;
        if !output.status.success() {
            bail!("nginx -t rejected composed sites: {}", String::from_utf8_lossy(&output.stderr));
        }
        Ok(())
    })();

    if let Err(error) = apply {
        let mut failed_restore = Vec::new();
        for (_, path, old, new) in specs.iter().rev() {
            if old != new {
                if let Err(restore_error) = nginx::atomic_write(path, old.as_bytes()) {
                    failed_restore.push(format!("{}: {restore_error}", path.display()));
                }
            }
        }
        for (path, old) in auxiliary_paths.iter().zip(backups.iter()) {
            let restored = match old {
                Some(content) => nginx::atomic_write(path, content),
                None => match fs::remove_file(path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(e.into()),
                },
            };
            if let Err(restore_error) = restored {
                failed_restore.push(format!("{}: {restore_error}", path.display()));
            }
        }
        if failed_restore.is_empty() {
            bail!("composed site apply failed; previous configuration restored: {error}");
        }
        bail!("composed site apply failed: {error}; incomplete rollback: {}", failed_restore.join(", "));
    }
    Ok(specs.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(kind: NginxObjectKind) -> SiteDefinition {
        SiteDefinition::new(kind, "example.test",
            if kind == NginxObjectKind::Domain { "example.test" } else { "media" },
            &[], Some("http://127.0.0.1:8096"), SiteOptions::default())
    }

    #[test]
    fn composable_features_emit_single_directives() {
        let mut site = sample(NginxObjectKind::Subdomain);
        site.options.access = Access::Lan;
        site.options.streaming = true;
        site.options.large_upload = true;
        site.options.long_lived = true;
        site.options.websocket = true;
        let rendered = site.render().unwrap();
        for directive in ["proxy_read_timeout", "proxy_send_timeout", "proxy_buffering", "client_max_body_size"] {
            assert_eq!(rendered.matches(directive).count(), 1, "{directive}");
        }
        assert!(rendered.contains("include snippets/restrict.conf;"));
        assert!(rendered.contains("client_max_body_size 5G;"));
    }

    #[test]
    fn domain_route_choice_and_subfolder_pwa() {
        let mut domain = sample(NginxObjectKind::Domain);
        domain.options.root = RootMode::ProxyAndSubfolders;
        let root = domain.render().unwrap();
        assert!(root.contains("$domain_upstream"));
        assert!(root.contains("subfolders-enabled/*.conf"));
        let mut folder = sample(NginxObjectKind::Subfolder);
        folder.options.subfolder = SubfolderMode::Pwa;
        let content = folder.render().unwrap();
        assert!(content.contains("proxy-pwa.conf"));
        assert!(content.contains("location ^~ /media/"));
    }

    #[test]
    fn rejects_incompatible_scope_and_injection() {
        let mut folder = sample(NginxObjectKind::Subfolder);
        folder.options.streaming = true;
        assert!(folder.render().is_err());
        let mut subdomain = sample(NginxObjectKind::Subdomain);
        subdomain.options.body_size = Some("1G; deny all".into());
        assert!(subdomain.render().is_err());
        subdomain.options.body_size = None;
        subdomain.options.sessions_lan_only = true;
        assert!(subdomain.render().is_err());
    }

    #[test]
    fn definition_round_trips_through_toml() {
        let site = sample(NginxObjectKind::Subdomain);
        let saved = toml::to_string_pretty(&site).unwrap();
        let parsed: SiteDefinition = toml::from_str(&saved).unwrap();
        assert_eq!(parsed.render().unwrap(), site.render().unwrap());
        assert!(toml::from_str::<SiteOptions>("unknown = true").is_err());
    }
}
