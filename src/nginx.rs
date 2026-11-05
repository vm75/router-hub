use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs as unix_fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use walkdir::WalkDir;

use crate::{
    config::AppConfig,
    models::{NginxLogEntry, NginxObject, NginxObjectKind},
    util::safe_relative_path,
};

pub fn parse_kind(value: &str) -> Result<NginxObjectKind> {
    match value {
        "domain" => Ok(NginxObjectKind::Domain),
        "subdomain" => Ok(NginxObjectKind::Subdomain),
        "subfolder" => Ok(NginxObjectKind::Subfolder),
        _ => bail!("kind must be domain, subdomain, or subfolder"),
    }
}

pub fn site_state(enabled: bool, nginx_running: bool, upstream_reachable: bool) -> &'static str {
    if !enabled {
        "disabled"
    } else if nginx_running && upstream_reachable {
        "live"
    } else {
        "down"
    }
}

pub fn validate_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.starts_with('.')
        || value.ends_with('.')
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
    {
        bail!("{label} may contain only letters, digits, dot, dash, and underscore");
    }
    Ok(())
}

pub fn config_file_name(name: &str) -> Result<String> {
    validate_name(name, "name")?;
    if name.ends_with(".conf") {
        Ok(name.to_string())
    } else {
        Ok(format!("{name}.conf"))
    }
}

pub fn available_path(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
) -> Result<PathBuf> {
    validate_name(domain, "domain")?;
    let domain_dir = config.nginx.domains_available_dir.join(domain);
    match kind {
        NginxObjectKind::Domain => Ok(domain_dir.join("root.conf")),
        NginxObjectKind::Subdomain => Ok(domain_dir
            .join("subdomains-available")
            .join(config_file_name(name)?)),
        NginxObjectKind::Subfolder => Ok(domain_dir
            .join("subfolders-available")
            .join(config_file_name(name)?)),
    }
}

pub fn enabled_path(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
) -> Result<PathBuf> {
    validate_name(domain, "domain")?;
    match kind {
        NginxObjectKind::Domain => Ok(config.nginx.domains_enabled_dir.join(domain)),
        NginxObjectKind::Subdomain => Ok(config
            .nginx
            .domains_available_dir
            .join(domain)
            .join("subdomains-enabled")
            .join(config_file_name(name)?)),
        NginxObjectKind::Subfolder => Ok(config
            .nginx
            .domains_available_dir
            .join(domain)
            .join("subfolders-enabled")
            .join(config_file_name(name)?)),
    }
}

pub fn list_objects(config: &AppConfig, nginx_running: bool) -> Result<Vec<NginxObject>> {
    let mut objects = Vec::new();
    let domains = match fs::read_dir(&config.nginx.domains_available_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(objects),
        Err(error) => return Err(error.into()),
    };

    for entry in domains {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let domain = entry.file_name().to_string_lossy().to_string();
        if validate_name(&domain, "domain").is_err() {
            continue;
        }
        let root = entry.path().join("root.conf");
        if fs::symlink_metadata(&root).is_ok_and(|metadata| metadata.file_type().is_file()) {
            objects.push(object_entry(
                config,
                NginxObjectKind::Domain,
                &domain,
                &domain,
                &root,
                nginx_running,
            )?);
        }
        collect_children(
            config,
            &mut objects,
            NginxObjectKind::Subdomain,
            &domain,
            &entry.path().join("subdomains-available"),
            nginx_running,
        )?;
        collect_children(
            config,
            &mut objects,
            NginxObjectKind::Subfolder,
            &domain,
            &entry.path().join("subfolders-available"),
            nginx_running,
        )?;
    }
    objects.sort_by(|left, right| {
        left.domain
            .cmp(&right.domain)
            .then(left.kind.as_str().cmp(right.kind.as_str()))
            .then(left.name.cmp(&right.name))
    });
    Ok(objects)
}

fn collect_children(
    config: &AppConfig,
    objects: &mut Vec<NginxObject>,
    kind: NginxObjectKind,
    domain: &str,
    directory: &Path,
    nginx_running: bool,
) -> Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("conf")
        {
            continue;
        }
        let name = entry
            .path()
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_string();
        if validate_name(&name, "name").is_err() {
            continue;
        }
        objects.push(object_entry(
            config,
            kind,
            domain,
            &name,
            &entry.path(),
            nginx_running,
        )?);
    }
    Ok(())
}

fn object_entry(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
    path: &Path,
    nginx_running: bool,
) -> Result<NginxObject> {
    let enabled = symlink_exists(&enabled_path(config, kind, domain, name)?);
    let parent_enabled = kind == NginxObjectKind::Domain
        || symlink_exists(&config.nginx.domains_enabled_dir.join(domain));
    let metadata = path.metadata()?;
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let display_name = match kind {
        NginxObjectKind::Domain => domain.to_string(),
        NginxObjectKind::Subdomain => extract_server_names(&content)
            .into_iter()
            .next()
            .unwrap_or_else(|| {
                if name.contains('_') {
                    name.replace('_', ".")
                } else {
                    format!("{name}.{domain}")
                }
            }),
        NginxObjectKind::Subfolder => format!("{domain}/{name}"),
    };
    Ok(NginxObject {
        kind,
        domain: domain.to_string(),
        name: name.to_string(),
        display_name,
        path: path
            .strip_prefix(&config.nginx.root_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string(),
        managed: crate::nginx_sites::settings(config, kind, domain, name)?.is_some(),
        port: site_upstream_with_key(
            config,
            kind,
            domain,
            name,
            &extract_server_names(&content),
            (kind == NginxObjectKind::Subfolder)
                .then(|| subfolder_map_key(name))
                .transpose()?
                .as_deref(),
        )?
        .and_then(|upstream| url::Url::parse(&upstream).ok()?.port()),
        enabled,
        running: enabled && parent_enabled && nginx_running,
        state: site_state(enabled && parent_enabled, nginx_running, true).to_string(),
        modified: metadata.modified().ok().map(DateTime::<Utc>::from),
    })
}

pub fn object_upstream(config: &AppConfig, object: &NginxObject) -> Result<Option<String>> {
    let content = read_object(config, object.kind, &object.domain, &object.name)?;
    let server_names = extract_server_names(&content);
    let map_key = (object.kind == NginxObjectKind::Subfolder)
        .then(|| subfolder_map_key(&object.name))
        .transpose()?;
    site_upstream_with_key(
        config,
        object.kind,
        &object.domain,
        &object.name,
        &server_names,
        map_key.as_deref(),
    )
}

pub fn read_object(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
) -> Result<String> {
    let path = available_path(config, kind, domain, name)?;
    ensure_no_symlink_ancestors(&config.nginx.domains_available_dir, &path)?;
    ensure_regular_file(&path, "nginx object")?;
    fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))
}

pub fn write_object(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
    content: &str,
    create_only: bool,
) -> Result<PathBuf> {
    let path = available_path(config, kind, domain, name)?;
    ensure_no_symlink_ancestors(&config.nginx.domains_available_dir, &path)?;
    if create_only && path.exists() {
        bail!("nginx object already exists");
    }
    if kind != NginxObjectKind::Domain
        && !config
            .nginx
            .domains_available_dir
            .join(domain)
            .join("root.conf")
            .is_file()
    {
        bail!("parent domain does not exist");
    }
    if kind == NginxObjectKind::Domain {
        let domain_dir = config.nginx.domains_available_dir.join(domain);
        for child in [
            "subdomains-available",
            "subdomains-enabled",
            "subfolders-available",
            "subfolders-enabled",
        ] {
            fs::create_dir_all(domain_dir.join(child))?;
        }
    }
    atomic_write(&path, content.as_bytes())?;
    Ok(path)
}

pub fn delete_object(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
) -> Result<()> {
    set_enabled(config, kind, domain, name, false)?;
    let path = available_path(config, kind, domain, name)?;
    if kind == NginxObjectKind::Domain {
        let domain_dir = path
            .parent()
            .context("domain root configuration has no parent")?;
        if domain_dir.is_dir() {
            fs::remove_dir_all(domain_dir)?;
        }
    } else if path.is_file() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn set_enabled(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
    enabled: bool,
) -> Result<()> {
    let available = available_path(config, kind, domain, name)?;
    if enabled {
        ensure_no_symlink_ancestors(&config.nginx.domains_available_dir, &available)?;
        ensure_regular_file(&available, "nginx object")?;
    }
    let link = enabled_path(config, kind, domain, name)?;
    if enabled {
        if symlink_exists(&link) {
            let metadata = fs::symlink_metadata(&link)?;
            if metadata.file_type().is_symlink() {
                return Ok(());
            }
            bail!("enabled path exists and is not a symlink");
        }
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent)?;
        }
        let target = match kind {
            NginxObjectKind::Domain => PathBuf::from("../domains-available").join(domain),
            NginxObjectKind::Subdomain => {
                PathBuf::from("../subdomains-available").join(config_file_name(name)?)
            }
            NginxObjectKind::Subfolder => {
                PathBuf::from("../subfolders-available").join(config_file_name(name)?)
            }
        };
        unix_fs::symlink(target, link)?;
    } else if symlink_exists(&link) {
        let metadata = fs::symlink_metadata(&link)?;
        if !metadata.file_type().is_symlink() {
            bail!("refusing to remove enabled path because it is not a symlink");
        }
        fs::remove_file(link)?;
    }
    Ok(())
}

pub fn normalize_server_names(
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
    server_names: &[String],
) -> Result<Vec<String>> {
    let names = if server_names.is_empty() {
        vec![match kind {
            NginxObjectKind::Domain | NginxObjectKind::Subfolder => domain.to_string(),
            NginxObjectKind::Subdomain => format!("{name}.{domain}"),
        }]
    } else {
        server_names.to_vec()
    };
    for server_name in &names {
        if server_name.is_empty()
            || server_name
                .chars()
                .any(|character| character.is_whitespace() || ";{}#".contains(character))
        {
            bail!("server names may not contain whitespace, semicolons, braces, or comments");
        }
    }
    Ok(names)
}

pub fn validate_site_upstream(upstream: Option<&str>) -> Result<()> {
    let Some(upstream) = upstream.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if !(upstream.starts_with("http://") || upstream.starts_with("https://"))
        || upstream
            .chars()
            .any(|character| character.is_whitespace() || ";{}#".contains(character))
    {
        bail!("upstream must be an http:// or https:// URL without whitespace or nginx syntax");
    }
    Ok(())
}

fn upstream_data_path(config: &AppConfig, kind: NginxObjectKind) -> PathBuf {
    config.nginx.root_dir.join(match kind {
        NginxObjectKind::Domain => "settings/domains.conf",
        NginxObjectKind::Subdomain => "settings/subdomains.conf",
        NginxObjectKind::Subfolder => "settings/subfolders.conf",
    })
}

pub fn site_upstream_with_key(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
    server_names: &[String],
    map_key: Option<&str>,
) -> Result<Option<String>> {
    let path = upstream_data_path(config, kind);
    let content = read_managed_config_file(config, &path)?.unwrap_or_default();
    let keys = if kind == NginxObjectKind::Subfolder {
        vec![map_key.unwrap_or(name).to_string()]
    } else {
        normalize_server_names(kind, domain, name, server_names)?
    };
    for line in content.lines() {
        let mut words = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace();
        if words
            .next()
            .is_some_and(|key| keys.iter().any(|name| name == key))
        {
            if let Some(value) = words.next() {
                return Ok(Some(value.trim_end_matches(';').to_string()));
            }
        }
    }
    Ok(None)
}

pub fn subfolder_map_key(name: &str) -> Result<String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        bail!("subfolder must be a literal path segment");
    }
    Ok(name.into())
}

#[allow(clippy::too_many_arguments)]
pub fn sync_site_upstream(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
    old_map_key: Option<&str>,
    new_map_key: Option<&str>,
    old_server_names: &[String],
    new_server_names: &[String],
    upstream: Option<&str>,
) -> Result<()> {
    validate_site_upstream(upstream)?;
    let path = upstream_data_path(config, kind);
    let previous = read_managed_config_file(config, &path)?;
    let (old_keys, new_keys) = if kind == NginxObjectKind::Subfolder {
        (
            vec![subfolder_map_key(old_map_key.unwrap_or(name))?],
            if new_server_names.is_empty() {
                Vec::new()
            } else {
                vec![subfolder_map_key(new_map_key.unwrap_or(name))?]
            },
        )
    } else {
        let new_keys = if new_server_names.is_empty() {
            Vec::new()
        } else {
            normalize_server_names(kind, domain, name, new_server_names)?
        };
        (old_server_names.to_vec(), new_keys)
    };
    let keys: BTreeSet<_> = old_keys.iter().chain(&new_keys).collect();
    let mut content = String::new();
    for line in previous.as_deref().unwrap_or_default().lines() {
        let key = line.split_whitespace().next().unwrap_or_default();
        if !keys.iter().any(|name| name.as_str() == key) {
            content.push_str(line);
            content.push('\n');
        }
    }
    if let Some(upstream) = upstream.filter(|value| !value.trim().is_empty()) {
        for key in new_keys {
            content.push_str(&format!("{key} {upstream};\n"));
        }
    }
    let mut data = std::collections::BTreeMap::new();
    let data_name = path
        .strip_prefix(&config.nginx.root_dir)?
        .to_string_lossy()
        .into_owned();
    data.insert(data_name, content.clone());
    let global = crate::nginx_render::load_global(config)?;
    data.insert(
        "settings/free_subdomains.txt".into(),
        global.free_subdomains.join("\n"),
    );
    let env = crate::nginx_render::environment(&data)?;
    let (source, output) = match kind {
        NginxObjectKind::Domain => (
            "conf.d/02_domain_upstream_map.conf",
            &config.nginx.domain_upstream_map_path,
        ),
        NginxObjectKind::Subdomain => (
            "conf.d/03_subdomain_upstream_map.conf.jinja",
            &config.nginx.subdomain_upstream_map_path,
        ),
        NginxObjectKind::Subfolder => (
            "conf.d/04_subfolder_upstream_map.conf.jinja",
            &config.nginx.subfolder_upstream_map_path,
        ),
    };
    let rendered = env.get_template(source)?.render(())?;
    let files = [(path, content), (output.clone(), rendered)]
        .into_iter()
        .collect();
    crate::nginx_render::FileTransaction::apply(config, files)?.commit();
    Ok(())
}

pub fn reconcile_http_forwarder(config: &AppConfig) -> Result<()> {
    let mut names = BTreeSet::new();
    for object in list_objects(config, false)? {
        if !object.enabled {
            continue;
        }
        if object.kind != NginxObjectKind::Domain && object.kind != NginxObjectKind::Subdomain {
            continue;
        }
        if object.kind == NginxObjectKind::Subdomain
            && !symlink_exists(&config.nginx.domains_enabled_dir.join(&object.domain))
        {
            continue;
        }
        let content = read_object(config, object.kind, &object.domain, &object.name)?;
        names.extend(normalize_server_names(
            object.kind,
            &object.domain,
            &object.name,
            &extract_server_names(&content),
        )?);
    }

    // HTTP-01 certificates need a hostname-matching HTTP server even before a
    // reverse-proxy site exists. Read persisted definitions so startup and site
    // reconciliation keep those challenge hosts routed to the shared ACME alias.
    let certificates_path = config.paths.data_dir.join("certificates.json");
    if let Ok(bytes) = fs::read(&certificates_path) {
        let certificates: Vec<serde_json::Value> =
            serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "invalid certificate definitions: {}",
                    certificates_path.display()
                )
            })?;
        for certificate in certificates {
            if certificate
                .get("method")
                .and_then(serde_json::Value::as_str)
                != Some("http")
            {
                continue;
            }
            if let Some(domains) = certificate
                .get("domains")
                .and_then(serde_json::Value::as_array)
            {
                for domain in domains.iter().filter_map(serde_json::Value::as_str) {
                    if !domain.starts_with("*.") {
                        names.insert(domain.to_string());
                    }
                }
            }
        }
    }

    let global = crate::nginx_render::load_global(config)?;
    let servers = if names.is_empty() {
        "\"\";".into()
    } else {
        format!("{};", names.into_iter().collect::<Vec<_>>().join(" "))
    };
    let data = [("settings/servers.conf".into(), servers.clone())]
        .into_iter()
        .collect();
    let env = crate::nginx_render::environment(&data)?;
    let mut context = global.shared;
    context.entry("acme_challenge_dir").or_insert_with(|| {
        config
            .certificates
            .certs_dir
            .join("acme-challenge")
            .to_string_lossy()
            .into_owned()
            .into()
    });
    let rendered = env
        .get_template("conf.d/05-http-to-https.conf.jinja")?
        .render(minijinja::value::Serde(context))?;
    let files = [
        (config.nginx.root_dir.join("settings/servers.conf"), servers),
        (config.nginx.http_forwarder_path.clone(), rendered),
    ]
    .into_iter()
    .collect();
    crate::nginx_render::FileTransaction::apply(config, files)?.commit();
    Ok(())
}

fn read_managed_config_file(config: &AppConfig, path: &Path) -> Result<Option<String>> {
    ensure_no_symlink_ancestors(&config.nginx.root_dir, path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            Ok(Some(fs::read_to_string(path).with_context(|| {
                format!("failed to read managed nginx file {}", path.display())
            })?))
        }
        Ok(_) => bail!(
            "managed nginx path is not a regular file: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn extract_server_names(content: &str) -> Vec<String> {
    let mut directive = String::new();
    let mut collecting = false;
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if !collecting {
            let Some(index) = line.find("server_name") else {
                continue;
            };
            if index > 0
                && line[..index]
                    .chars()
                    .next_back()
                    .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
            {
                continue;
            }
            let rest = &line[index + "server_name".len()..];
            if !rest.starts_with(char::is_whitespace) {
                continue;
            }
            directive.push_str(rest.trim());
            collecting = true;
        } else {
            directive.push(' ');
            directive.push_str(line);
        }
        if directive.contains(';') {
            break;
        }
    }
    directive
        .split_once(';')
        .map(|(names, _)| names)
        .unwrap_or(&directive)
        .split_whitespace()
        .map(ToString::to_string)
        .collect()
}

pub fn list_logs(config: &AppConfig) -> Result<Vec<NginxLogEntry>> {
    let mut logs = Vec::new();
    if !config.nginx.log_dir.exists() {
        return Ok(logs);
    }
    for entry in WalkDir::new(&config.nginx.log_dir).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let metadata = entry.metadata()?;
        logs.push(NginxLogEntry {
            path: entry
                .path()
                .strip_prefix(&config.nginx.log_dir)?
                .to_string_lossy()
                .to_string(),
            size: metadata.len(),
            modified: metadata.modified().ok().map(DateTime::<Utc>::from),
        });
    }
    logs.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(logs)
}

pub fn read_log(config: &AppConfig, path: &str) -> Result<String> {
    let relative = safe_relative_path(path)?;
    validate_relative_characters(&relative)?;
    let target = config.nginx.log_dir.join(relative);
    ensure_no_symlink_ancestors(&config.nginx.log_dir, &target)?;
    let metadata = fs::symlink_metadata(&target)
        .with_context(|| format!("failed to inspect {}", target.display()))?;
    if !metadata.file_type().is_file() {
        bail!("log path is not a regular file");
    }
    let mut file = fs::File::open(&target)?;
    let limit = config.nginx.log_read_bytes as u64;
    let start = metadata.len().saturating_sub(limit);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::with_capacity((metadata.len() - start) as usize);
    file.read_to_end(&mut bytes)?;
    let mut content = String::from_utf8_lossy(&bytes).to_string();
    if start > 0 {
        if let Some(newline) = content.find('\n') {
            content.drain(..=newline);
        }
        content.insert_str(0, "[older log content omitted]\n");
    }
    Ok(content)
}

pub fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("router-hub.tmp-{}", Uuid::new_v4().simple()));
    fs::write(&temp, content).with_context(|| format!("failed to write {}", temp.display()))?;
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error).with_context(|| format!("failed to replace {}", path.display()));
    }
    Ok(())
}

pub fn symlink_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn validate_relative_characters(path: &Path) -> Result<()> {
    if path
        .to_string_lossy()
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || "/-_.".contains(character)))
    {
        bail!("paths may contain only letters, digits, slash, dash, underscore, and dot");
    }
    Ok(())
}

pub(crate) fn ensure_no_symlink_ancestors(base: &Path, target: &Path) -> Result<()> {
    let relative = target.strip_prefix(base)?;
    let mut current = base.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("path traverses a symlink")
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn ensure_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("{label} does not exist"))?;
    if !metadata.file_type().is_file() {
        bail!("{label} is not a regular file");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config(root: &Path) -> AppConfig {
        let mut config = AppConfig::default();
        config.nginx.root_dir = root.to_path_buf();
        config.nginx.config_path = root.join("nginx.conf");
        config.nginx.domains_available_dir = root.join("domains-available");
        config.nginx.domains_enabled_dir = root.join("domains-enabled");
        config.nginx.subdomain_upstream_map_path =
            root.join("conf.d/03_subdomain_upstream_map.conf");
        config.nginx.domain_upstream_map_path = root.join("conf.d/02_domain_upstream_map.conf");
        config.nginx.subfolder_upstream_map_path =
            root.join("conf.d/04_subfolder_upstream_map.conf");
        config.nginx.http_forwarder_path = root.join("conf.d/05-http-to-https.conf");
        config.nginx.log_dir = root.join("logs");
        config
    }

    #[test]
    fn site_state_distinguishes_disabled_down_and_live() {
        assert_eq!(site_state(false, true, true), "disabled");
        assert_eq!(site_state(true, true, false), "down");
        assert_eq!(site_state(true, true, true), "live");
        assert_eq!(site_state(true, false, true), "down");
    }

    #[test]
    fn creates_lists_and_enables_hierarchical_objects() {
        let temp = tempdir().unwrap();
        let config = test_config(temp.path());
        write_object(
            &config,
            NginxObjectKind::Domain,
            "example.test",
            "example.test",
            "server {}",
            true,
        )
        .unwrap();
        write_object(
            &config,
            NginxObjectKind::Subdomain,
            "example.test",
            "media",
            "server {}",
            true,
        )
        .unwrap();
        set_enabled(
            &config,
            NginxObjectKind::Domain,
            "example.test",
            "example.test",
            true,
        )
        .unwrap();
        set_enabled(
            &config,
            NginxObjectKind::Subdomain,
            "example.test",
            "media",
            true,
        )
        .unwrap();

        let objects = list_objects(&config, true).unwrap();
        assert_eq!(objects.len(), 2);
        assert!(
            objects
                .iter()
                .all(|object| object.enabled && object.running)
        );
        assert_eq!(
            fs::read_link(config.nginx.domains_enabled_dir.join("example.test")).unwrap(),
            PathBuf::from("../domains-available/example.test")
        );
    }

    #[test]
    fn lists_human_readable_site_names() {
        let temp = tempdir().unwrap();
        let config = test_config(temp.path());
        write_object(
            &config,
            NginxObjectKind::Domain,
            "example.xyz",
            "example.xyz",
            "server {}",
            true,
        )
        .unwrap();
        write_object(
            &config,
            NginxObjectKind::Subdomain,
            "example.xyz",
            "calibre_example_xyz",
            "server { server_name calibre.example.xyz; }",
            true,
        )
        .unwrap();
        write_object(
            &config,
            NginxObjectKind::Subfolder,
            "example.xyz",
            "remote",
            "location /remote/ {}",
            true,
        )
        .unwrap();

        let objects = list_objects(&config, false).unwrap();
        assert_eq!(
            objects
                .iter()
                .find(|object| object.kind == NginxObjectKind::Subdomain)
                .unwrap()
                .display_name
                .as_str(),
            "calibre.example.xyz"
        );
        assert_eq!(
            objects
                .iter()
                .find(|object| object.kind == NginxObjectKind::Subfolder)
                .unwrap()
                .display_name
                .as_str(),
            "example.xyz/remote"
        );
    }

    #[test]
    fn manages_current_upstream_data_and_renders_maps() {
        let temp = tempdir().unwrap();
        let config = test_config(temp.path());
        let kind = NginxObjectKind::Subfolder;
        sync_site_upstream(
            &config,
            kind,
            "example.test",
            "media",
            None,
            None,
            &[],
            &["example.test".into()],
            Some("http://127.0.0.1:8080"),
        )
        .unwrap();
        assert_eq!(
            site_upstream_with_key(&config, kind, "example.test", "media", &[], None)
                .unwrap()
                .as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert!(
            fs::read_to_string(&config.nginx.subfolder_upstream_map_path)
                .unwrap()
                .contains("(?:media)(?:-dev)?")
        );
        sync_site_upstream(
            &config,
            kind,
            "example.test",
            "media",
            None,
            None,
            &["example.test".into()],
            &[],
            None,
        )
        .unwrap();
        assert_eq!(
            site_upstream_with_key(&config, kind, "example.test", "media", &[], None).unwrap(),
            None
        );
        assert!(
            !fs::read_to_string(&config.nginx.subfolder_upstream_map_path)
                .unwrap()
                .contains("(?:media)")
        );
    }

    #[test]
    fn reads_only_the_log_tail() {
        let temp = tempdir().unwrap();
        let mut config = test_config(temp.path());
        config.nginx.log_read_bytes = 12;
        fs::create_dir_all(&config.nginx.log_dir).unwrap();
        fs::write(
            config.nginx.log_dir.join("access.log"),
            "one\ntwo\nthree\nfour\n",
        )
        .unwrap();
        let content = read_log(&config, "access.log").unwrap();
        assert!(content.starts_with("[older log content omitted]"));
        assert!(content.ends_with("three\nfour\n"));
    }
}
