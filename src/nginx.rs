use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs as unix_fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use walkdir::WalkDir;

use crate::{
    config::AppConfig,
    models::{NginxFileEntry, NginxLogEntry, NginxObject, NginxObjectKind, NginxTemplateEntry},
    util::safe_relative_path,
};

const ROOT_FILE_EXCLUSIONS: &[&str] =
    &["certs", "domains-available", "domains-enabled", "templates"];
const TEMPLATE_COMMENT_PREFIX: &str = "# router-hub-template:";

pub fn parse_kind(value: &str) -> Result<NginxObjectKind> {
    match value {
        "domain" => Ok(NginxObjectKind::Domain),
        "subdomain" => Ok(NginxObjectKind::Subdomain),
        "subfolder" => Ok(NginxObjectKind::Subfolder),
        _ => bail!("kind must be domain, subdomain, or subfolder"),
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
        template: template_name(&content),
        port: site_upstream_with_key(
            config,
            kind,
            domain,
            name,
            &extract_server_names(&content),
            (kind == NginxObjectKind::Subfolder)
                .then(|| subfolder_map_key(&content, name))
                .transpose()?
                .as_deref(),
        )?
        .and_then(|upstream| url::Url::parse(&upstream).ok()?.port()),
        enabled,
        running: enabled && parent_enabled && nginx_running,
        modified: metadata.modified().ok().map(DateTime::<Utc>::from),
    })
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

pub fn render_template(
    template: &str,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
    server_names: &[String],
) -> Result<String> {
    let server_name = normalize_server_names(kind, domain, name, server_names)?.join(" ");
    Ok(template
        .replace("{{kind}}", kind.as_str())
        .replace("{{domain}}", domain)
        .replace("{{name}}", name)
        .replace("{{subdomain}}", name)
        .replace("{{subfolder}}", name)
        .replace("{{server_name}}", &server_name))
}

pub fn validate_site_upstream(_kind: NginxObjectKind, upstream: Option<&str>) -> Result<()> {
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

pub fn site_upstream_with_key(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
    server_names: &[String],
    map_key: Option<&str>,
) -> Result<Option<String>> {
    match kind {
        NginxObjectKind::Domain => {
            let names = normalize_server_names(kind, domain, name, server_names)?;
            for server_name in names {
                if let Some(value) = read_map_value(
                    config,
                    &config.nginx.domain_upstream_map_path,
                    "map $host $domain_upstream",
                    &server_name,
                )? {
                    return Ok(Some(value));
                }
            }
            Ok(None)
        }
        NginxObjectKind::Subdomain => {
            let names = normalize_server_names(kind, domain, name, server_names)?;
            for server_name in names {
                if let Some(value) = read_map_value(
                    config,
                    &config.nginx.subdomain_upstream_map_path,
                    "map $host $subdomain_upstream",
                    &server_name,
                )? {
                    return Ok(Some(value));
                }
            }
            Ok(None)
        }
        NginxObjectKind::Subfolder => read_map_value(
            config,
            &config.nginx.subfolder_upstream_map_path,
            "map $subfolder_app $subfolder_upstream",
            map_key.unwrap_or(name),
        ),
    }
}

pub fn subfolder_map_key(content: &str, name: &str) -> Result<String> {
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let Some(location) = line.find("location") else {
            continue;
        };
        if location > 0
            && line[..location]
                .chars()
                .next_back()
                .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            continue;
        }
        let rest = &line[location + "location".len()..];
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let Some(slash) = rest.find('/') else {
            continue;
        };
        let key = rest[slash + 1..]
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric() || ".-_".contains(*character))
            .collect::<String>();
        if !key.is_empty() {
            return validate_map_key(&key, "subfolder map key");
        }
    }
    validate_map_key(name, "subfolder map key")
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
    let upstream = upstream.map(str::trim).filter(|value| !value.is_empty());
    validate_site_upstream(kind, upstream)?;

    match kind {
        NginxObjectKind::Domain | NginxObjectKind::Subdomain => {
            let old_names = old_server_names.to_vec();
            let new_names = if new_server_names.is_empty() {
                Vec::new()
            } else {
                normalize_server_names(kind, domain, name, new_server_names)?
            };
            let mut remove = BTreeSet::new();
            remove.extend(old_names.iter().cloned());
            remove.extend(new_names.iter().cloned());
            for name in &remove {
                validate_map_key(name, "server name")?;
            }

            let (map_path, map_header) = if kind == NginxObjectKind::Domain {
                (
                    &config.nginx.domain_upstream_map_path,
                    "map $host $domain_upstream",
                )
            } else {
                (
                    &config.nginx.subdomain_upstream_map_path,
                    "map $host $subdomain_upstream",
                )
            };
            let has_existing = remove.iter().try_fold(false, |found, name| {
                Ok::<_, anyhow::Error>(
                    found || read_map_value(config, map_path, map_header, name)?.is_some(),
                )
            })?;
            if upstream.is_none() && !has_existing {
                return Ok(());
            }

            let additions = upstream.map(|value| {
                new_names
                    .iter()
                    .map(|name| (name.clone(), format!("{name} {value};")))
                    .collect::<Vec<_>>()
            });
            update_map_file(
                config,
                map_path,
                map_header,
                additions.as_deref().unwrap_or(&[]),
                |line| map_entry_key(line).is_some_and(|key| remove.contains(key)),
            )
        }
        NginxObjectKind::Subfolder => {
            let old_key = validate_map_key(old_map_key.unwrap_or(name), "subfolder map key")?;
            let new_key = validate_map_key(new_map_key.unwrap_or(name), "subfolder map key")?;
            let mut remove = BTreeSet::new();
            remove.insert(old_key.clone());
            remove.insert(new_key.clone());
            let has_existing = remove.iter().try_fold(false, |found, key| {
                Ok::<_, anyhow::Error>(
                    found
                        || read_map_value(
                            config,
                            &config.nginx.subfolder_upstream_map_path,
                            "map $subfolder_app $subfolder_upstream",
                            key,
                        )?
                        .is_some(),
                )
            })?;
            let has_existing_selector = remove.iter().try_fold(false, |found, key| {
                Ok::<_, anyhow::Error>(
                    found
                        || request_selector_exists(
                            config,
                            &config.nginx.subfolder_upstream_map_path,
                            key,
                            true,
                        )?,
                )
            })?;
            if upstream.is_none() && !has_existing && !has_existing_selector {
                return Ok(());
            }
            let additions =
                upstream.map(|value| vec![(new_key.clone(), format!("{new_key} {value};"))]);
            update_map_file(
                config,
                &config.nginx.subfolder_upstream_map_path,
                "map $subfolder_app $subfolder_upstream",
                additions.as_deref().unwrap_or(&[]),
                |line| {
                    map_entry_key(line).is_some_and(|key| remove.contains(key))
                        || remove
                            .iter()
                            .any(|key| line.contains(&format!("# router-hub-managed: {key}")))
                },
            )?;
            let has_unmanaged_selector = request_selector_exists(
                config,
                &config.nginx.subfolder_upstream_map_path,
                &new_key,
                false,
            )?;
            let additions = upstream.filter(|_| !has_unmanaged_selector).map(|_| {
                let escaped = regex::escape(&new_key);
                vec![(
                    new_key.clone(),
                    format!(r#"~^/{escaped}(?:/|\?|$) {new_key};"#),
                )]
            });
            update_map_file(
                config,
                &config.nginx.subfolder_upstream_map_path,
                "map $request_uri $subfolder_app",
                additions.as_deref().unwrap_or(&[]),
                |line| {
                    remove
                        .iter()
                        .any(|key| line.contains(&format!("# router-hub-managed: {key}")))
                },
            )
        }
    }
}

pub fn reconcile_auxiliary_config(config: &AppConfig) -> Result<()> {
    for object in list_objects(config, false)? {
        if object.kind == NginxObjectKind::Domain {
            continue;
        }
        let content = read_object(config, object.kind, &object.domain, &object.name)?;
        let map_key = (object.kind == NginxObjectKind::Subfolder)
            .then(|| subfolder_map_key(&content, &object.name))
            .transpose()?;
        let names = normalize_server_names(
            object.kind,
            &object.domain,
            &object.name,
            &extract_server_names(&content),
        )?;
        let upstream = site_upstream_with_key(
            config,
            object.kind,
            &object.domain,
            &object.name,
            &names,
            map_key.as_deref(),
        )?;
        if upstream.is_some() {
            sync_site_upstream(
                config,
                object.kind,
                &object.domain,
                &object.name,
                map_key.as_deref(),
                map_key.as_deref(),
                &names,
                &names,
                upstream.as_deref(),
            )?;
        }
    }
    reconcile_http_forwarder(config)
}

pub fn reconcile_http_forwarder(config: &AppConfig) -> Result<()> {
    migrate_legacy_http_forwarder(config)?;
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

    let mut content = String::from(
        "# Managed by Router Hub. HTTP requests for enabled sites are redirected to HTTPS.\n",
    );
    if !names.is_empty() {
        let names = names.into_iter().collect::<Vec<_>>();
        content.push_str("server {\n    server_name\n");
        for (index, name) in names.iter().enumerate() {
            content.push_str("        ");
            content.push_str(name);
            if index + 1 == names.len() {
                content.push(';');
            }
            content.push('\n');
        }
        content.push_str(
            "\n    include snippets/listen-http.conf;\n\n    include snippets/server-guard.conf;\n    include snippets/acme-challenge.conf;\n    return 301 https://$host$request_uri;\n}\n",
        );
    }
    write_managed_config_file(config, &config.nginx.http_forwarder_path, &content)
}

fn migrate_legacy_http_forwarder(config: &AppConfig) -> Result<()> {
    let legacy = config
        .nginx
        .root_dir
        .join("conf.d/05-known-subdomains-http.conf");
    if legacy == config.nginx.http_forwarder_path {
        return Ok(());
    }
    let Ok(legacy_metadata) = fs::symlink_metadata(&legacy) else {
        return Ok(());
    };
    if !legacy_metadata.file_type().is_file() {
        bail!(
            "legacy nginx HTTP forwarder is not a regular file: {}",
            legacy.display()
        );
    }
    ensure_no_symlink_ancestors(&config.nginx.root_dir, &legacy)?;
    match fs::symlink_metadata(&config.nginx.http_forwarder_path) {
        Ok(metadata) if !metadata.file_type().is_file() => bail!(
            "managed nginx path is not a regular file: {}",
            config.nginx.http_forwarder_path.display()
        ),
        Ok(_) => fs::remove_file(&legacy)
            .with_context(|| format!("failed to remove legacy nginx file {}", legacy.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure_no_symlink_ancestors(&config.nginx.root_dir, &config.nginx.http_forwarder_path)?;
            fs::rename(&legacy, &config.nginx.http_forwarder_path).with_context(|| {
                format!(
                    "failed to rename legacy nginx file {} to {}",
                    legacy.display(),
                    config.nginx.http_forwarder_path.display()
                )
            })
        }
        Err(error) => Err(error.into()),
    }
}

fn read_map_value(
    config: &AppConfig,
    path: &Path,
    header: &str,
    key: &str,
) -> Result<Option<String>> {
    let Some(content) = read_managed_config_file(config, path)? else {
        return Ok(None);
    };
    let lines = content.lines().map(ToString::to_string).collect::<Vec<_>>();
    let Some((start, end)) = map_block_bounds(&lines, header)? else {
        return Ok(None);
    };
    Ok(lines[start + 1..end].iter().find_map(|line| {
        (map_entry_key(line) == Some(key)).then(|| {
            line.split('#')
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .trim_end_matches(';')
                .to_string()
        })
    }))
}

fn request_selector_exists(
    config: &AppConfig,
    path: &Path,
    key: &str,
    include_managed: bool,
) -> Result<bool> {
    let Some(content) = read_managed_config_file(config, path)? else {
        return Ok(false);
    };
    let lines = content.lines().map(ToString::to_string).collect::<Vec<_>>();
    let Some((start, end)) = map_block_bounds(&lines, "map $request_uri $subfolder_app")? else {
        return Ok(false);
    };
    Ok(lines[start + 1..end].iter().any(|line| {
        (include_managed || !line.contains("# router-hub-managed:"))
            && request_selector_matches_key(line, key)
    }))
}

fn request_selector_matches_key(line: &str, key: &str) -> bool {
    let code = line.split('#').next().unwrap_or_default().trim();
    let Some(selector) = code.split_whitespace().next() else {
        return false;
    };
    if let Some(pattern) = selector
        .strip_prefix("~*")
        .or_else(|| selector.strip_prefix('~'))
    {
        let pattern = pattern.replace("(?<", "(?P<");
        return regex::Regex::new(&pattern)
            .ok()
            .is_some_and(|pattern| pattern.is_match(&format!("/{key}/")));
    }
    selector == format!("/{key}") || selector.starts_with(&format!("/{key}/"))
}

fn update_map_file<F>(
    config: &AppConfig,
    path: &Path,
    header: &str,
    additions: &[(String, String)],
    should_remove: F,
) -> Result<()>
where
    F: Fn(&str) -> bool,
{
    let mut lines = read_managed_config_file(config, path)?
        .unwrap_or_default()
        .lines()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if let Some((start, end)) = map_block_bounds(&lines, header)? {
        let mut body = lines[start + 1..end]
            .iter()
            .filter(|line| !should_remove(line))
            .cloned()
            .collect::<Vec<_>>();
        for (key, entry) in additions {
            let marker = format!("# router-hub-managed: {key}");
            if !body
                .iter()
                .any(|line| map_entry_key(line) == Some(key.as_str()) || line.contains(&marker))
            {
                body.push(format!("    {entry} {marker}"));
            }
        }
        let mut replacement = vec![lines[start].clone()];
        replacement.extend(body);
        replacement.push(lines[end].clone());
        lines.splice(start..=end, replacement);
    } else if !additions.is_empty() {
        if !lines.is_empty() && !lines.last().is_some_and(String::is_empty) {
            lines.push(String::new());
        }
        lines.push(format!("{header} {{"));
        lines.push("    default \"\";".to_string());
        for (key, entry) in additions {
            lines.push(format!("    {entry} # router-hub-managed: {key}"));
        }
        lines.push("}".to_string());
    } else {
        return Ok(());
    }
    let mut content = lines.join("\n");
    content.push('\n');
    write_managed_config_file(config, path, &content)
}

fn map_block_bounds(lines: &[String], header: &str) -> Result<Option<(usize, usize)>> {
    let Some(start) = lines.iter().position(|line| {
        let trimmed = line.trim();
        trimmed.starts_with(header) && trimmed[header.len()..].trim_start().starts_with('{')
    }) else {
        return Ok(None);
    };
    let mut depth = 0i32;
    for (index, line) in lines.iter().enumerate().skip(start) {
        let code = line.split('#').next().unwrap_or_default();
        depth += code.chars().filter(|character| *character == '{').count() as i32;
        depth -= code.chars().filter(|character| *character == '}').count() as i32;
        if depth == 0 {
            return Ok(Some((start, index)));
        }
    }
    bail!("unterminated nginx map block: {header}")
}

fn map_entry_key(line: &str) -> Option<&str> {
    let code = line.split('#').next()?.trim();
    let key = code.split_whitespace().next()?;
    (!code.is_empty() && key != "default" && key != "hostnames" && key != "}").then_some(key)
}

fn validate_map_key(value: &str, label: &str) -> Result<String> {
    if value.is_empty()
        || value == "default"
        || value
            .chars()
            .any(|character| character.is_whitespace() || ";{}#".contains(character))
    {
        bail!("{label} contains invalid nginx map characters");
    }
    Ok(value.to_string())
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

fn write_managed_config_file(config: &AppConfig, path: &Path, content: &str) -> Result<()> {
    ensure_no_symlink_ancestors(&config.nginx.root_dir, path)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_file() {
            bail!(
                "managed nginx path is not a regular file: {}",
                path.display()
            );
        }
    }
    atomic_write(path, content.as_bytes())
}

pub fn template_name(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let name = line.trim().strip_prefix(TEMPLATE_COMMENT_PREFIX)?.trim();
        validate_name(name, "template name")
            .is_ok()
            .then(|| name.to_string())
    })
}

pub fn with_template_comment(template: &str, content: &str) -> Result<String> {
    validate_name(template, "template name")?;
    let content = strip_template_comment(content);
    Ok(format!(
        "{TEMPLATE_COMMENT_PREFIX} {template}\n{}",
        content.trim_start()
    ))
}

pub fn strip_template_comment(content: &str) -> String {
    let mut stripped = content
        .lines()
        .filter(|line| !line.trim().starts_with(TEMPLATE_COMMENT_PREFIX))
        .collect::<Vec<_>>()
        .join("\n");
    if content.ends_with('\n') {
        stripped.push('\n');
    }
    stripped
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

pub fn list_templates(
    config: &AppConfig,
    kind: NginxObjectKind,
) -> Result<Vec<NginxTemplateEntry>> {
    let base = config.nginx.templates_dir.join(kind.as_str());
    let mut templates = Vec::new();
    for entry in read_dir_if_exists(&base)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("conf")
        {
            continue;
        }
        let metadata = entry.metadata()?;
        templates.push(NginxTemplateEntry {
            kind,
            name: entry
                .path()
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_string(),
            size: metadata.len(),
            modified: metadata.modified().ok().map(DateTime::<Utc>::from),
        });
    }
    templates.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(templates)
}

pub fn template_path(config: &AppConfig, kind: NginxObjectKind, name: &str) -> Result<PathBuf> {
    validate_name(name, "template name")?;
    let path = config
        .nginx
        .templates_dir
        .join(kind.as_str())
        .join(config_file_name(name)?);
    ensure_no_symlink_ancestors(&config.nginx.templates_dir, &path)?;
    Ok(path)
}

pub fn read_template(config: &AppConfig, kind: NginxObjectKind, name: &str) -> Result<String> {
    let path = template_path(config, kind, name)?;
    ensure_regular_file(&path, "nginx template")?;
    fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))
}

pub fn write_template(
    config: &AppConfig,
    kind: NginxObjectKind,
    name: &str,
    content: &str,
) -> Result<()> {
    atomic_write(&template_path(config, kind, name)?, content.as_bytes())
}

pub fn rename_template(
    config: &AppConfig,
    kind: NginxObjectKind,
    old_name: &str,
    new_name: &str,
    content: &str,
) -> Result<()> {
    let old_path = template_path(config, kind, old_name)?;
    let new_path = template_path(config, kind, new_name)?;
    ensure_regular_file(&old_path, "nginx template")?;
    if new_path.exists() {
        bail!("nginx template already exists");
    }
    fs::rename(&old_path, &new_path)?;
    if let Err(error) = atomic_write(&new_path, content.as_bytes()) {
        let _ = fs::rename(&new_path, &old_path);
        return Err(error);
    }
    Ok(())
}

pub fn delete_template(config: &AppConfig, kind: NginxObjectKind, name: &str) -> Result<()> {
    let path = template_path(config, kind, name)?;
    if path.is_file() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn list_root_files(config: &AppConfig) -> Result<Vec<NginxFileEntry>> {
    let mut files = Vec::new();
    if !config.nginx.root_dir.exists() {
        return Ok(files);
    }
    for entry in WalkDir::new(&config.nginx.root_dir).follow_links(false) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(&config.nginx.root_dir)?;
        if root_file_excluded(relative) {
            continue;
        }
        if entry.file_type().is_file() {
            let metadata = entry.metadata()?;
            files.push(NginxFileEntry {
                path: relative.to_string_lossy().to_string(),
                size: metadata.len(),
                modified: metadata.modified().ok().map(DateTime::<Utc>::from),
            });
        }
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

pub fn root_file_path(config: &AppConfig, path: &str) -> Result<PathBuf> {
    let relative = safe_relative_path(path)?;
    if relative.as_os_str().is_empty() || root_file_excluded(&relative) {
        bail!("that nginx path is managed by a dedicated API or is not editable");
    }
    validate_relative_characters(&relative)?;
    let target = config.nginx.root_dir.join(&relative);
    ensure_no_symlink_ancestors(&config.nginx.root_dir, &target)?;
    if symlink_exists(&target) && fs::symlink_metadata(&target)?.file_type().is_symlink() {
        bail!("nginx root files may not be symlinks");
    }
    Ok(target)
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

fn root_file_excluded(relative: &Path) -> bool {
    relative
        .components()
        .next()
        .and_then(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .is_some_and(|value| ROOT_FILE_EXCLUSIONS.contains(&value))
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

fn ensure_no_symlink_ancestors(base: &Path, target: &Path) -> Result<()> {
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

fn read_dir_if_exists(path: &Path) -> Result<fs::ReadDir> {
    fs::create_dir_all(path)?;
    Ok(fs::read_dir(path)?)
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
        config.nginx.templates_dir = root.join("templates");
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
    fn renders_named_template_values() {
        let rendered = render_template(
            "server_name {{server_name}}; location /{{subfolder}}/ {}",
            NginxObjectKind::Subfolder,
            "example.test",
            "media",
            &[],
        );
        assert_eq!(
            rendered.unwrap(),
            "server_name example.test; location /media/ {}"
        );
    }

    #[test]
    fn template_metadata_and_aliases_round_trip() {
        let rendered = render_template(
            "server { server_name {{server_name}}; }",
            NginxObjectKind::Subdomain,
            "example.test",
            "app",
            &["app.example.test".into(), "media.example.test".into()],
        )
        .unwrap();
        let content = with_template_comment("proxy", &rendered).unwrap();

        assert_eq!(template_name(&content).as_deref(), Some("proxy"));
        assert_eq!(
            extract_server_names(&content),
            ["app.example.test", "media.example.test"]
        );
        assert_eq!(
            strip_template_comment(&content),
            "server { server_name app.example.test media.example.test; }"
        );
        assert!(
            render_template(
                "server_name {{server_name}};",
                NginxObjectKind::Domain,
                "example.test",
                "example.test",
                &["example.test; return 204".into()],
            )
            .is_err()
        );
    }

    #[test]
    fn manages_site_upstream_maps_and_http_forwarder() {
        let temp = tempdir().unwrap();
        let config = test_config(temp.path());
        assert_eq!(
            subfolder_map_key("location ^~ /librarydev/admin {", "library_dev").unwrap(),
            "librarydev"
        );
        write_object(
            &config,
            NginxObjectKind::Domain,
            "example.test",
            "example.test",
            "server { server_name example.test; }",
            true,
        )
        .unwrap();
        write_object(
            &config,
            NginxObjectKind::Subdomain,
            "example.test",
            "app",
            "server { server_name app.example.test alias.example.test; }",
            true,
        )
        .unwrap();
        write_object(
            &config,
            NginxObjectKind::Subfolder,
            "example.test",
            "media",
            "location /media/ {}",
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
            "app",
            true,
        )
        .unwrap();

        let names = [
            "app.example.test".to_string(),
            "alias.example.test".to_string(),
        ];
        sync_site_upstream(
            &config,
            NginxObjectKind::Subdomain,
            "example.test",
            "app",
            None,
            None,
            &[],
            &names,
            Some("http://127.0.0.1:8080"),
        )
        .unwrap();
        sync_site_upstream(
            &config,
            NginxObjectKind::Domain,
            "example.test",
            "example.test",
            None,
            None,
            &[],
            &["example.test".to_string()],
            Some("http://127.0.0.1:8083"),
        )
        .unwrap();
        sync_site_upstream(
            &config,
            NginxObjectKind::Subfolder,
            "example.test",
            "media",
            None,
            None,
            &[],
            &[],
            Some("http://127.0.0.1:8081"),
        )
        .unwrap();
        reconcile_http_forwarder(&config).unwrap();

        let subdomain_map = fs::read_to_string(&config.nginx.subdomain_upstream_map_path).unwrap();
        assert!(subdomain_map.contains("app.example.test http://127.0.0.1:8080;"));
        assert!(subdomain_map.contains("alias.example.test http://127.0.0.1:8080;"));
        assert_eq!(
            site_upstream_with_key(
                &config,
                NginxObjectKind::Subdomain,
                "example.test",
                "app",
                &names,
                None,
            )
            .unwrap()
            .as_deref(),
            Some("http://127.0.0.1:8080")
        );
        let domain_map = fs::read_to_string(&config.nginx.domain_upstream_map_path).unwrap();
        assert!(domain_map.contains("example.test http://127.0.0.1:8083;"));
        assert_eq!(
            site_upstream_with_key(
                &config,
                NginxObjectKind::Domain,
                "example.test",
                "example.test",
                &["example.test".to_string()],
                None,
            )
            .unwrap()
            .as_deref(),
            Some("http://127.0.0.1:8083")
        );
        let subfolder_map = fs::read_to_string(&config.nginx.subfolder_upstream_map_path).unwrap();
        assert!(subfolder_map.contains("media http://127.0.0.1:8081;"));
        assert!(subfolder_map.contains("~^/media(?:/|\\?|$) media;"));

        let forwarder = fs::read_to_string(&config.nginx.http_forwarder_path).unwrap();
        assert!(forwarder.contains("example.test"));
        assert!(forwarder.contains("app.example.test"));
        assert!(forwarder.contains("alias.example.test"));

        sync_site_upstream(
            &config,
            NginxObjectKind::Subdomain,
            "example.test",
            "app",
            None,
            None,
            &names,
            &["new.example.test".to_string()],
            Some("https://127.0.0.1:8443"),
        )
        .unwrap();
        let subdomain_map = fs::read_to_string(&config.nginx.subdomain_upstream_map_path).unwrap();
        assert!(!subdomain_map.contains("app.example.test http://127.0.0.1:8080;"));
        assert!(subdomain_map.contains("new.example.test https://127.0.0.1:8443;"));

        fs::write(
            &config.nginx.subfolder_upstream_map_path,
            "map $request_uri $subfolder_app {\n    default \"\";\n    ~^/(?<subfolder_from_uri>library(?:dev)?)(?:/|\\?|$) $subfolder_from_uri;\n}\n",
        )
        .unwrap();
        sync_site_upstream(
            &config,
            NginxObjectKind::Subfolder,
            "example.test",
            "library_dev",
            Some("librarydev"),
            Some("librarydev"),
            &[],
            &[],
            Some("http://127.0.0.1:8082"),
        )
        .unwrap();
        let subfolder_map = fs::read_to_string(&config.nginx.subfolder_upstream_map_path).unwrap();
        assert!(subfolder_map.contains("librarydev http://127.0.0.1:8082;"));
        assert!(!subfolder_map.contains("~^/librarydev(?:/|\\?|$)"));
    }

    #[test]
    fn migrates_legacy_known_subdomains_forwarder() {
        let temp = tempdir().unwrap();
        let config = test_config(temp.path());
        let legacy = config
            .nginx
            .root_dir
            .join("conf.d/05-known-subdomains-http.conf");
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(&legacy, "server { server_name old.example.test; }").unwrap();

        reconcile_http_forwarder(&config).unwrap();

        assert!(!legacy.exists());
        assert_eq!(
            fs::read_to_string(&config.nginx.http_forwarder_path).unwrap(),
            "# Managed by Router Hub. HTTP requests for enabled sites are redirected to HTTPS.\n"
        );
    }

    #[test]
    fn root_files_reject_managed_trees_and_symlinks() {
        let temp = tempdir().unwrap();
        let config = test_config(temp.path());
        fs::create_dir_all(temp.path().join("conf.d")).unwrap();
        unix_fs::symlink("/tmp", temp.path().join("conf.d/link")).unwrap();
        assert!(root_file_path(&config, "../outside.conf").is_err());
        assert!(root_file_path(&config, "domains-available/x/root.conf").is_err());
        assert!(root_file_path(&config, "conf.d/link/escape.conf").is_err());
        assert!(root_file_path(&config, "conf.d/global.conf").is_ok());
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
