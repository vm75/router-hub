//! Rendering and validated inputs for the bundled nginx configuration.
//! Policy templates are compiled into the binary; deployment data cannot shadow them.
use std::collections::BTreeMap;

use anyhow::{Result, bail};
use minijinja::{Environment, UndefinedBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{models::NginxObjectKind, nginx};

pub type Settings = Map<String, Value>;
pub const SETTINGS_PREFIX: &str = "# router-hub-settings: ";

/// Named budgets are shared per client IP across every assignment of that name.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitPolicy {
    pub rate: String,
    pub burst: u32,
    pub nodelay: bool,
    pub connections: u32,
}

fn policy_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn validate_limit_references(
    settings: &Settings,
    profiles: &BTreeMap<String, LimitPolicy>,
) -> Result<()> {
    if let Some(name) = settings.get("limit_policy").and_then(Value::as_str) {
        if name != "default" && !profiles.contains_key(name) {
            bail!("unknown limit_policy: {name}");
        }
    }
    for key in ["routes", "children"] {
        if let Some(routes) = settings.get(key).and_then(Value::as_array) {
            for route in routes {
                validate_limit_references(route.as_object().unwrap(), profiles)?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GlobalSettings {
    pub shared: Settings,
    pub site_defaults: Settings,
    pub limit_policies: BTreeMap<String, LimitPolicy>,
    pub allowed_ips: Vec<String>,
    pub free_subdomains: Vec<String>,
}

/// On-disk TOML schema; the HTTP API retains its `shared` field name.
#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NginxSettings {
    allowed_ips: Option<Vec<String>>,
    free_subdomains: Option<Vec<String>>,
    global: Settings,
    site_defaults: Settings,
    limit_policies: BTreeMap<String, LimitPolicy>,
}

fn encode_global(settings: &GlobalSettings) -> Result<String> {
    Ok(toml::to_string_pretty(&NginxSettings {
        allowed_ips: Some(settings.allowed_ips.clone()),
        free_subdomains: Some(settings.free_subdomains.clone()),
        global: settings.shared.clone(),
        site_defaults: settings.site_defaults.clone(),
        limit_policies: settings.limit_policies.clone(),
    })?)
}

const BOOL_SETTINGS: &[&str] = &[
    "enable_lanonly",
    "enable_subfolders",
    "disable_root",
    "enable_large_upload",
    "enable_longlived",
    "enable_streaming",
    "enable_byte_ranges",
    "enable_restricted_sessions",
    "clear_origin",
    "access_log",
    "backend_auth",
    "hide_etag",
    "disable_proxy_redirect",
];
const SIZE_SETTINGS: &[&str] = &["client_max_body_size", "large_upload_max_body_size"];
const TIME_SETTINGS: &[&str] = &[
    "proxy_connect_timeout",
    "proxy_session_timeout",
    "client_upload_timeout",
];

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/._-:,= ".contains(&c))
}

fn quantity(value: &Value, suffixes: &str) -> bool {
    let Some(s) = value.as_str() else {
        return false;
    };
    let digits = s.trim_end_matches(|c: char| suffixes.contains(c));
    !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit()) && s.len() - digits.len() <= 1
}

pub fn validate_site(settings: &Settings) -> Result<()> {
    validate_policy(settings, false, 0)
}

fn validate_policy(settings: &Settings, route: bool, depth: usize) -> Result<()> {
    if depth > 8 {
        bail!("route nesting exceeds 8 levels");
    }
    for (key, value) in settings {
        let valid = if BOOL_SETTINGS.contains(&key.as_str()) {
            value.is_boolean()
        } else if SIZE_SETTINGS.contains(&key.as_str()) {
            quantity(value, "kKmMgG")
        } else if TIME_SETTINGS.contains(&key.as_str()) {
            quantity(value, "smhdw")
        } else {
            match key.as_str() {
                "limit_policy" => value.as_str().is_some_and(policy_name),
                "proxy_transport" => matches!(value.as_str(), Some("websocket" | "http" | "sse")),
                "cache_policy" => matches!(
                    value.as_str(),
                    Some("inherit" | "no_cache" | "immutable" | "pwa")
                ),
                "forwarded_for" => matches!(value.as_str(), Some("replace" | "append")),
                "spa_fallback" | "rewrite_to" => value.as_str().is_some_and(|s| {
                    s.is_empty() || (s.starts_with('/') && token(s) && !s.contains(' '))
                }),
                "cors_origin" => value.as_str().is_some_and(|s| {
                    s.is_empty()
                        || s == "*"
                        || ((s.starts_with("http://") || s.starts_with("https://"))
                            && token(s)
                            && !s.contains(' '))
                }),
                "routes" if !route => {
                    validate_routes(value, depth + 1)?;
                    true
                }
                "children" if route => {
                    validate_routes(value, depth + 1)?;
                    true
                }
                "path" if route => value.as_str().is_some_and(|s| {
                    s.starts_with('/')
                        && s.len() <= 1024
                        && s.bytes()
                            .all(|c| c.is_ascii_graphic() && !b";{}#\"'".contains(&c))
                }),
                "match" if route => matches!(
                    value.as_str(),
                    Some("prefix" | "exact" | "regex" | "regex_i")
                ),
                "rate_limit" if route => {
                    let obj = value
                        .as_object()
                        .ok_or_else(|| anyhow::anyhow!("rate_limit must be an object"))?;
                    obj.keys().all(|k| k == "zone" || k == "burst")
                        && obj.get("zone").and_then(Value::as_str).is_some_and(|s| {
                            !s.is_empty()
                                && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                        })
                        && obj
                            .get("burst")
                            .is_none_or(|v| v.as_u64().is_some_and(|n| n <= 100000))
                }
                _ => false,
            }
        };
        if !valid {
            bail!("invalid nginx setting: {key}");
        }
    }
    Ok(())
}

fn validate_routes(value: &Value, depth: usize) -> Result<()> {
    let routes = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("routes must be an array"))?;
    if routes.len() > 128 {
        bail!("too many routes");
    }
    for route in routes {
        let route = route
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("route must be an object"))?;
        if !route.contains_key("path") {
            bail!("route path is required");
        }
        validate_policy(route, true, depth)?;
    }
    Ok(())
}

impl GlobalSettings {
    pub fn validate(&self) -> Result<()> {
        validate_site(&self.site_defaults)?;
        if self.limit_policies.len() > 16 {
            bail!("at most 16 limit policies are allowed");
        }
        for (name, policy) in &self.limit_policies {
            let rate = policy
                .rate
                .strip_suffix("r/s")
                .or_else(|| policy.rate.strip_suffix("r/m"));
            if name == "default"
                || !policy_name(name)
                || !rate.is_some_and(|s| {
                    !s.is_empty()
                        && s.bytes().all(|c| c.is_ascii_digit())
                        && s.parse::<u32>().is_ok_and(|n| (1..=100000).contains(&n))
                })
                || policy.burst > 100000
                || !(1..=65535).contains(&policy.connections)
            {
                bail!("invalid limit policy: {name}");
            }
        }
        validate_limit_references(&self.site_defaults, &self.limit_policies)?;
        for (key, value) in &self.shared {
            let valid = match key.as_str() {
                "http_port" | "https_port" => {
                    value.as_u64().is_some_and(|n| (1..=65535).contains(&n))
                }
                "worker_processes" => {
                    value == "auto" || value.as_u64().is_some_and(|n| (1..=1024).contains(&n))
                }
                "worker_connections" => value.as_u64().is_some_and(|n| (1..=1048576).contains(&n)),
                "router_ip" | "resolver_addr" => value
                    .as_str()
                    .is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok()),
                "resolver_validity" => quantity(value, "smhdw"),
                "nginx_daemon" => value.is_boolean(),
                "nginx_user" => value.as_str().is_some_and(|s| {
                    s.is_empty()
                        || s.bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                }),
                "var_dir" | "acme_challenge_dir" | "default_certificate_dir" | "temp_dir" => value
                    .as_str()
                    .is_some_and(|s| s.starts_with('/') && token(s) && !s.contains(' ')),
                "pwa_shell_cache_control" | "pwa_asset_cache_control" => {
                    value.as_str().is_some_and(token)
                }
                _ => false,
            };
            if !valid {
                bail!("invalid shared nginx setting: {key}");
            }
        }
        for ip in &self.allowed_ips {
            ip.parse::<ipnet::IpNet>()
                .or_else(|_| ip.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))?;
        }
        for suffix in &self.free_subdomains {
            nginx::validate_name(suffix, "free subdomain suffix")?;
            if !suffix.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            }) {
                bail!("invalid free subdomain suffix");
            }
        }
        Ok(())
    }
}

// Only the four Python string methods used by the shipped templates are needed.
// Keeping this callback small avoids the full Python compatibility extension.
fn string_method(
    _state: &mut minijinja::State,
    value: &minijinja::Value,
    method: &str,
    args: &[minijinja::Value],
) -> std::result::Result<minijinja::Value, minijinja::Error> {
    use minijinja::{Error, ErrorKind, value::from_args};
    let s = value
        .as_str()
        .ok_or_else(|| Error::from(ErrorKind::UnknownMethod))?;
    match method {
        "splitlines" => {
            let () = from_args(args)?;
            Ok(s.lines().map(str::to_string).collect::<Vec<_>>().into())
        }
        "split" => {
            let (separator, maxsplit): (Option<String>, Option<usize>) = from_args(args)?;
            let pieces: Vec<String> = match separator {
                Some(separator) if separator.is_empty() => {
                    return Err(Error::new(ErrorKind::InvalidOperation, "empty separator"));
                }
                Some(separator) => s
                    .splitn(
                        maxsplit.map_or(usize::MAX, |n| n.saturating_add(1)),
                        &separator,
                    )
                    .map(str::to_string)
                    .collect(),
                None => s.split_whitespace().map(str::to_string).collect(),
            };
            Ok(pieces.into())
        }
        "endswith" => {
            let (suffix,): (String,) = from_args(args)?;
            Ok(s.ends_with(&suffix).into())
        }
        "rstrip" => {
            let (characters,): (String,) = from_args(args)?;
            Ok(s.trim_end_matches(|c| characters.contains(c))
                .to_string()
                .into())
        }
        _ => Err(Error::from(ErrorKind::UnknownMethod)),
    }
}

pub fn environment(data: &BTreeMap<String, String>) -> Result<Environment<'static>> {
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    env.set_syntax(
        minijinja::syntax::SyntaxConfig::builder()
            .trim_blocks(true)
            .lstrip_blocks(true)
            .build()?,
    );
    env.set_unknown_method_callback(string_method);
    for &(name, source) in BUNDLE {
        // Only data fragments may override the embedded defaults, never policy code.
        let source = if name.starts_with("settings/") && !name.ends_with(".jinja") {
            data.get(name).map(String::as_str).unwrap_or(source)
        } else {
            source
        };
        env.add_template_owned(name.to_string(), source.to_string())?;
    }
    Ok(env)
}

pub fn site_settings(content: &str) -> Result<Option<Settings>> {
    content
        .lines()
        .next()
        .and_then(|line| line.strip_prefix(SETTINGS_PREFIX))
        .map(serde_json::from_str)
        .transpose()
        .map_err(Into::into)
}

pub fn render_site(
    global: &GlobalSettings,
    settings: &Settings,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
    server_names: &[String],
) -> Result<String> {
    global.validate()?;
    validate_site(settings)?;
    nginx::validate_name(domain, "domain")?;
    nginx::validate_name(name, "name")?;
    if kind == NginxObjectKind::Subfolder
        && !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        bail!("subfolder must be a literal path segment");
    }
    let mut context = global.shared.clone();
    context.extend(global.site_defaults.clone());
    context.extend(settings.clone());
    validate_limit_references(&context, &global.limit_policies)?;
    context.insert(
        "limit_policies".into(),
        serde_json::to_value(&global.limit_policies)?,
    );
    context.insert("domain".into(), domain.into());
    context.insert("subfolder".into(), name.into());
    context.insert(
        "server_name".into(),
        nginx::normalize_server_names(kind, domain, name, server_names)?
            .join(" ")
            .into(),
    );
    let env = environment(&BTreeMap::new())?;
    let rendered = env
        .get_template(&format!("templates/{}.conf.jinja", kind.as_str()))?
        .render(minijinja::value::Serde(context))?;
    Ok(format!(
        "{SETTINGS_PREFIX}{}\n{rendered}",
        serde_json::to_string(settings)?
    ))
}

// Generated list of versioned inputs. Deployment folders and examples are excluded.
const BUNDLE: &[(&str, &str)] = &[
    (
        "conf.d/00-limit-policies.conf.jinja",
        include_str!("../config/nginx/conf.d/00-limit-policies.conf.jinja"),
    ),
    (
        "ban-shield/access-logging.conf.jinja",
        include_str!("../config/nginx/ban-shield/access-logging.conf.jinja"),
    ),
    (
        "ban-shield/default-drop.conf.jinja",
        include_str!("../config/nginx/ban-shield/default-drop.conf.jinja"),
    ),
    (
        "ban-shield/http.conf",
        include_str!("../config/nginx/ban-shield/http.conf"),
    ),
    (
        "ban-shield/log-conditions.conf",
        include_str!("../config/nginx/ban-shield/log-conditions.conf"),
    ),
    (
        "ban-shield/log-formats.conf",
        include_str!("../config/nginx/ban-shield/log-formats.conf"),
    ),
    (
        "ban-shield/maps.conf",
        include_str!("../config/nginx/ban-shield/maps.conf"),
    ),
    (
        "ban-shield/security-trap-gate.conf",
        include_str!("../config/nginx/ban-shield/security-trap-gate.conf"),
    ),
    (
        "ban-shield/server-guard.conf",
        include_str!("../config/nginx/ban-shield/server-guard.conf"),
    ),
    (
        "ban-shield/zones.conf",
        include_str!("../config/nginx/ban-shield/zones.conf"),
    ),
    (
        "conf.d/00-access-log-map.conf",
        include_str!("../config/nginx/conf.d/00-access-log-map.conf"),
    ),
    (
        "conf.d/00-ban-shield.conf",
        include_str!("../config/nginx/conf.d/00-ban-shield.conf"),
    ),
    (
        "conf.d/00-pwa-cache-map.conf.jinja",
        include_str!("../config/nginx/conf.d/00-pwa-cache-map.conf.jinja"),
    ),
    (
        "conf.d/00-websocket-map.conf",
        include_str!("../config/nginx/conf.d/00-websocket-map.conf"),
    ),
    (
        "conf.d/01-global.conf.jinja",
        include_str!("../config/nginx/conf.d/01-global.conf.jinja"),
    ),
    (
        "conf.d/02-default-drop.conf",
        include_str!("../config/nginx/conf.d/02-default-drop.conf"),
    ),
    (
        "conf.d/02_domain_upstream_map.conf",
        include_str!("../config/nginx/conf.d/02_domain_upstream_map.conf"),
    ),
    (
        "conf.d/03_subdomain_upstream_map.conf.jinja",
        include_str!("../config/nginx/conf.d/03_subdomain_upstream_map.conf.jinja"),
    ),
    (
        "conf.d/04_subfolder_upstream_map.conf.jinja",
        include_str!("../config/nginx/conf.d/04_subfolder_upstream_map.conf.jinja"),
    ),
    (
        "conf.d/05-http-to-https.conf.jinja",
        include_str!("../config/nginx/conf.d/05-http-to-https.conf.jinja"),
    ),
    (
        "nginx.conf.jinja",
        include_str!("../config/nginx/nginx.conf.jinja"),
    ),
    (
        "resolver.conf.jinja",
        include_str!("../config/nginx/resolver.conf.jinja"),
    ),
    (
        "settings/access_log_suppress.conf",
        include_str!("../config/nginx/settings/access_log_suppress.conf"),
    ),
    (
        "settings/allowed_ips.txt",
        include_str!("../config/nginx/settings/allowed_ips.txt"),
    ),
    (
        "settings/domains.conf",
        include_str!("../config/nginx/settings/domains.conf"),
    ),
    (
        "settings/free_subdomains.txt",
        include_str!("../config/nginx/settings/free_subdomains.txt"),
    ),
    (
        "settings/location.jinja",
        include_str!("../config/nginx/settings/location.jinja"),
    ),
    (
        "settings/proxy.jinja",
        include_str!("../config/nginx/settings/proxy.jinja"),
    ),
    (
        "settings/pwa.jinja",
        include_str!("../config/nginx/settings/pwa.jinja"),
    ),
    (
        "settings/security_trap_allow.conf",
        include_str!("../config/nginx/settings/security_trap_allow.conf"),
    ),
    (
        "settings/servers.conf",
        include_str!("../config/nginx/settings/servers.conf"),
    ),
    (
        "settings/subdomains.conf",
        include_str!("../config/nginx/settings/subdomains.conf"),
    ),
    (
        "settings/subfolders.conf",
        include_str!("../config/nginx/settings/subfolders.conf"),
    ),
    (
        "settings/tls.jinja",
        include_str!("../config/nginx/settings/tls.jinja"),
    ),
    (
        "snippets/acme-challenge.conf.jinja",
        include_str!("../config/nginx/snippets/acme-challenge.conf.jinja"),
    ),
    (
        "snippets/proxy-backend-auth.conf",
        include_str!("../config/nginx/snippets/proxy-backend-auth.conf"),
    ),
    (
        "snippets/proxy-byte-ranges.conf",
        include_str!("../config/nginx/snippets/proxy-byte-ranges.conf"),
    ),
    (
        "snippets/proxy-events.conf",
        include_str!("../config/nginx/snippets/proxy-events.conf"),
    ),
    (
        "snippets/proxy-location.conf.jinja",
        include_str!("../config/nginx/snippets/proxy-location.conf.jinja"),
    ),
    (
        "snippets/proxy-origin.conf",
        include_str!("../config/nginx/snippets/proxy-origin.conf"),
    ),
    (
        "snippets/proxy-request.conf.jinja",
        include_str!("../config/nginx/snippets/proxy-request.conf.jinja"),
    ),
    (
        "snippets/proxy-routes.conf.jinja",
        include_str!("../config/nginx/snippets/proxy-routes.conf.jinja"),
    ),
    (
        "snippets/proxy-site.conf.jinja",
        include_str!("../config/nginx/snippets/proxy-site.conf.jinja"),
    ),
    (
        "snippets/proxy-streaming.conf",
        include_str!("../config/nginx/snippets/proxy-streaming.conf"),
    ),
    (
        "snippets/proxy-timeouts.conf.jinja",
        include_str!("../config/nginx/snippets/proxy-timeouts.conf.jinja"),
    ),
    (
        "snippets/proxy-upgrade.conf",
        include_str!("../config/nginx/snippets/proxy-upgrade.conf"),
    ),
    (
        "snippets/proxy-upload.conf.jinja",
        include_str!("../config/nginx/snippets/proxy-upload.conf.jinja"),
    ),
    (
        "snippets/pwa-no-cache.conf",
        include_str!("../config/nginx/snippets/pwa-no-cache.conf"),
    ),
    (
        "snippets/restrict.conf.jinja",
        include_str!("../config/nginx/snippets/restrict.conf.jinja"),
    ),
    (
        "snippets/security-headers.conf",
        include_str!("../config/nginx/snippets/security-headers.conf"),
    ),
    (
        "snippets/ssl.conf.jinja",
        include_str!("../config/nginx/snippets/ssl.conf.jinja"),
    ),
    (
        "templates/domain.conf.jinja",
        include_str!("../config/nginx/templates/domain.conf.jinja"),
    ),
    (
        "templates/subdomain.conf.jinja",
        include_str!("../config/nginx/templates/subdomain.conf.jinja"),
    ),
    (
        "templates/subfolder.conf.jinja",
        include_str!("../config/nginx/templates/subfolder.conf.jinja"),
    ),
];

pub fn global_path(config: &crate::config::AppConfig) -> std::path::PathBuf {
    config.nginx.inputs_dir.join("nginx.toml")
}

/// Limit managed writes to the configured input and runtime trees.
pub(crate) fn ensure_managed_path(
    config: &crate::config::AppConfig,
    path: &std::path::Path,
) -> Result<()> {
    use std::path::Component;
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        bail!("managed nginx path must be normalized");
    }
    let base = if path.starts_with(&config.nginx.inputs_dir) {
        &config.nginx.inputs_dir
    } else {
        &config.nginx.root_dir
    };
    if std::fs::symlink_metadata(base).is_ok_and(|m| m.file_type().is_symlink()) {
        bail!("managed nginx root is a symlink");
    }
    nginx::ensure_no_symlink_ancestors(base, path)
}

/// Refuse to silently replace legacy persisted inputs with empty defaults.
pub(crate) fn require_migrated_input(config: &crate::config::AppConfig, name: &str) -> Result<()> {
    let path = config.nginx.inputs_dir.join(name);
    ensure_managed_path(config, &path)?;
    if !path.try_exists()? {
        let legacy = config.nginx.root_dir.join("settings").join(name);
        ensure_managed_path(config, &legacy)?;
        if legacy.try_exists()? {
            bail!(
                "legacy nginx inputs found; stop Router Hub and run migrate-nginx-inputs before starting this version"
            );
        }
    }
    Ok(())
}

/// Keep render-time filesystem defaults tied to configurable application paths,
/// including fixture paths in test mode.
pub fn with_path_defaults(
    mut settings: GlobalSettings,
    config: &crate::config::AppConfig,
) -> GlobalSettings {
    if let Some(var_dir) = config.nginx.log_dir.parent().and_then(|path| path.parent()) {
        settings
            .shared
            .entry("var_dir")
            .or_insert_with(|| var_dir.to_string_lossy().into_owned().into());
    }
    settings
        .shared
        .entry("acme_challenge_dir")
        .or_insert_with(|| {
            config
                .certificates
                .certs_dir
                .join("acme-challenge")
                .to_string_lossy()
                .into_owned()
                .into()
        });
    if let Some(relative) = settings
        .shared
        .get("default_certificate_dir")
        .and_then(Value::as_str)
        .filter(|path| !path.starts_with('/'))
    {
        if let Ok(relative) = crate::util::safe_relative_path(relative) {
            settings.shared.insert(
                "default_certificate_dir".into(),
                config
                    .nginx
                    .root_dir
                    .join(relative)
                    .to_string_lossy()
                    .into_owned()
                    .into(),
            );
        }
    }
    if config.platform == crate::config::Platform::Linux {
        settings.shared.entry("temp_dir").or_insert_with(|| {
            config
                .nginx
                .root_dir
                .parent()
                .unwrap_or(&config.nginx.root_dir)
                .join("tmp")
                .to_string_lossy()
                .into_owned()
                .into()
        });
    }
    settings
}

pub fn load_global(config: &crate::config::AppConfig) -> Result<GlobalSettings> {
    let path = global_path(config);
    require_migrated_input(config, "nginx.toml")?;
    let stored: NginxSettings = match std::fs::read_to_string(&path) {
        Ok(content) => toml::from_str(&content)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => NginxSettings::default(),
        Err(error) => return Err(error.into()),
    };
    let settings = with_path_defaults(
        GlobalSettings {
            shared: stored.global,
            site_defaults: stored.site_defaults,
            limit_policies: stored.limit_policies,
            allowed_ips: stored.allowed_ips.unwrap_or_default(),
            free_subdomains: stored.free_subdomains.unwrap_or_default(),
        },
        config,
    );
    settings.validate()?;
    Ok(settings)
}

fn runtime_context(settings: &GlobalSettings, is_root: bool) -> Settings {
    let mut context = settings.shared.clone();
    context.insert("nginx_is_root".into(), is_root.into());
    context.entry("nginx_daemon").or_insert(true.into());
    context
}

/// Assemble all shared runtime output before mutating the active configuration.
/// Only versioned policy inputs are used; deployment overrides are data fragments.
pub fn shared_files(
    config: &crate::config::AppConfig,
    settings: &GlobalSettings,
) -> Result<BTreeMap<std::path::PathBuf, String>> {
    let settings = with_path_defaults(settings.clone(), config);
    settings.validate()?;
    let mut data = BTreeMap::new();
    for &(name, source) in BUNDLE {
        if name.starts_with("settings/") && !name.ends_with(".jinja") {
            let path = config
                .nginx
                .inputs_dir
                .join(name.strip_prefix("settings/").unwrap());
            ensure_managed_path(config, &path)?;
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    data.insert(name.into(), content);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    data.insert(name.into(), source.into());
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    // Saved managed targets override generated map fragments; retain custom rows.
    for (key, site) in crate::nginx_sites::load(config)?.sites {
        let name = site.object_name(&key)?;
        validate_limit_references(&site.settings, &settings.limit_policies)?;
        let names = site
            .server_name
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let keys = if site.kind == NginxObjectKind::Subfolder {
            vec![nginx::subfolder_map_key(&name)?]
        } else {
            nginx::normalize_server_names(site.kind, &site.domain, &name, &names)?
        };
        let fragment = match site.kind {
            NginxObjectKind::Domain => "settings/domains.conf",
            NginxObjectKind::Subdomain => "settings/subdomains.conf",
            NginxObjectKind::Subfolder => "settings/subfolders.conf",
        };
        let previous = data.entry(fragment.into()).or_default();
        let mut content = previous
            .lines()
            .filter(|line| {
                !keys
                    .iter()
                    .any(|key| line.split_whitespace().next() == Some(key.as_str()))
            })
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        if let Some(upstream) = site.upstream.filter(|value| !value.trim().is_empty()) {
            for key in keys {
                content.push_str(&format!("{key} {upstream};\n"));
            }
        }
        *previous = content;
    }
    data.insert(
        "settings/allowed_ips.txt".into(),
        settings.allowed_ips.join("\n"),
    );
    data.insert(
        "settings/free_subdomains.txt".into(),
        settings.free_subdomains.join("\n"),
    );
    let env = environment(&data)?;
    // SAFETY: geteuid has no arguments or memory safety requirements.
    let mut context = runtime_context(&settings, unsafe { libc::geteuid() == 0 });
    context.insert(
        "limit_policies".into(),
        serde_json::to_value(&settings.limit_policies)?,
    );
    context.insert(
        "pid_path".into(),
        config.nginx.pid_path.to_string_lossy().into_owned().into(),
    );
    context.insert(
        "error_log_path".into(),
        config
            .nginx
            .log_dir
            .join("error.log")
            .to_string_lossy()
            .into_owned()
            .into(),
    );
    context.entry("acme_challenge_dir").or_insert_with(|| {
        config
            .certificates
            .certs_dir
            .join("acme-challenge")
            .to_string_lossy()
            .into_owned()
            .into()
    });
    let mut files = BTreeMap::new();
    for &(name, source) in BUNDLE {
        let runtime = name == "nginx.conf.jinja"
            || name == "resolver.conf.jinja"
            || name.starts_with("conf.d/")
            || name.starts_with("ban-shield/")
            || [
                "snippets/ssl.conf.jinja",
                "snippets/acme-challenge.conf.jinja",
                "snippets/restrict.conf.jinja",
                "snippets/security-headers.conf",
            ]
            .contains(&name);
        if !runtime {
            continue;
        }
        let output = name.strip_suffix(".jinja").unwrap_or(name);
        let path = match name {
            "nginx.conf.jinja" => config.nginx.config_path.clone(),
            "conf.d/02_domain_upstream_map.conf" => config.nginx.domain_upstream_map_path.clone(),
            "conf.d/03_subdomain_upstream_map.conf.jinja" => {
                config.nginx.subdomain_upstream_map_path.clone()
            }
            "conf.d/04_subfolder_upstream_map.conf.jinja" => {
                config.nginx.subfolder_upstream_map_path.clone()
            }
            "conf.d/05-http-to-https.conf.jinja" => config.nginx.http_forwarder_path.clone(),
            _ => config.nginx.root_dir.join(output),
        };
        let content = if name.ends_with(".jinja") {
            env.get_template(name)?
                .render(minijinja::value::Serde(&context))?
        } else {
            source.into()
        };
        files.insert(path, content);
    }
    for (name, content) in data {
        files.insert(
            config
                .nginx
                .inputs_dir
                .join(name.strip_prefix("settings/").unwrap()),
            content.clone(),
        );
        // These are concrete nginx includes; text lists and TOML stay in inputs_dir.
        if name.ends_with(".conf") {
            files.insert(config.nginx.root_dir.join(name), content);
        }
    }
    files.insert(global_path(config), encode_global(&settings)?);
    Ok(files)
}

/// Rolls back every file if a write, nginx test, or reload fails.
/// Callers serialize mutations with AppState::nginx_lock.
pub struct FileTransaction {
    previous: Vec<(std::path::PathBuf, Option<Vec<u8>>)>,
    committed: bool,
}

impl FileTransaction {
    pub fn apply(
        config: &crate::config::AppConfig,
        files: BTreeMap<std::path::PathBuf, String>,
    ) -> Result<Self> {
        Self::apply_with_removals(config, files, &[])
    }

    fn apply_with_removals(
        config: &crate::config::AppConfig,
        files: BTreeMap<std::path::PathBuf, String>,
        removals: &[std::path::PathBuf],
    ) -> Result<Self> {
        let mut transaction = Self {
            previous: Vec::new(),
            committed: false,
        };
        // Preflight every path before writing any file.
        for path in files.keys().chain(removals) {
            ensure_managed_path(config, path)?;
            let previous = match std::fs::read(path) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
            transaction.previous.push((path.clone(), previous));
        }
        if let Some(content) = files.get(&global_path(config)) {
            let settings: NginxSettings = toml::from_str(content)?;
            GlobalSettings {
                shared: settings.global.clone(),
                site_defaults: settings.site_defaults,
                limit_policies: settings.limit_policies,
                allowed_ips: settings.allowed_ips.unwrap_or_default(),
                free_subdomains: settings.free_subdomains.unwrap_or_default(),
            }
            .validate()?;
            if let Some(path) = settings.global.get("temp_dir").and_then(Value::as_str) {
                let path = std::path::Path::new(path);
                nginx::ensure_no_symlink_ancestors(std::path::Path::new("/"), path)?;
                std::fs::create_dir_all(path)?;
            }
        }
        for (path, content) in files {
            nginx::atomic_write(&path, content.as_bytes())?;
        }
        for path in removals {
            std::fs::remove_file(path)?;
        }
        Ok(transaction)
    }

    pub fn commit(mut self) {
        self.committed = true;
    }

    pub fn rollback(&mut self) -> Result<()> {
        for (path, content) in self.previous.iter().rev() {
            match content {
                Some(bytes) => nginx::atomic_write(path, bytes)?,
                None => match std::fs::remove_file(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                },
            }
        }
        self.committed = true;
        Ok(())
    }
}

impl Drop for FileTransaction {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = self.rollback() {
                tracing::error!(%error, "failed to roll back nginx files");
            }
        }
    }
}

/// Move current-format legacy inputs without altering active nginx configuration.
/// Run while Router Hub is stopped. Conflicting destinations are never overwritten.
pub fn migrate_inputs(config: &crate::config::AppConfig) -> Result<usize> {
    use std::fs;
    let mut names = BUNDLE
        .iter()
        .filter_map(|(name, _)| {
            name.strip_prefix("settings/")
                .filter(|name| !name.ends_with(".jinja"))
        })
        .collect::<Vec<_>>();
    names.extend(["nginx.toml", "sites.toml"]);
    let mut files = BTreeMap::new();
    let mut removals = Vec::new();
    for name in names {
        let source = config.nginx.root_dir.join("settings").join(name);
        let target = config.nginx.inputs_dir.join(name);
        if source == target {
            bail!("inputs_dir must be separate from legacy nginx settings");
        }
        ensure_managed_path(config, &source)?;
        ensure_managed_path(config, &target)?;
        let content = match fs::read_to_string(&source) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        match fs::read_to_string(&target) {
            Ok(existing) if existing != content => {
                bail!("conflicting nginx input: {}", target.display())
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        files.insert(target, content);
        // Keep .conf files as live runtime includes, but retire non-runtime inputs.
        if !name.ends_with(".conf") {
            removals.push(source);
        }
    }
    let count = files.len();
    let transaction = FileTransaction::apply_with_removals(config, files, &removals)?;
    let global = load_global(config)?;
    for (key, site) in crate::nginx_sites::load(config)?.sites {
        let name = site.object_name(&key)?;
        let names = site
            .server_name
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        render_site(
            &global,
            &site.settings,
            site.kind,
            &site.domain,
            &name,
            &names,
        )?;
    }
    transaction.commit();
    Ok(count)
}

/// Initialize only a missing nginx configuration using the current bundle.
/// Existing installations are never converted or overwritten.
pub async fn bootstrap(config: &crate::config::AppConfig) -> Result<bool> {
    use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
    let root = &config.nginx.root_dir;
    nginx::ensure_no_symlink_ancestors(root, &config.nginx.config_path)?;
    if fs::symlink_metadata(&config.nginx.config_path).is_ok() {
        return Ok(false);
    }
    if config.test_mode {
        bail!(
            "init-nginx requires a real openssl invocation; use an isolated Linux config for testing"
        );
    }
    let mut global = load_global(config)?;
    let var_dir = config
        .nginx
        .log_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("nginx log path requires a runtime directory"))?;
    global
        .shared
        .entry("var_dir")
        .or_insert_with(|| var_dir.to_string_lossy().into_owned().into());
    let mut files = shared_files(config, &global)?;
    for (name, content) in [
        ("mime.types", include_str!("../config/nginx/mime.types")),
        ("dhparams.pem", include_str!("../config/nginx/dhparams.pem")),
    ] {
        files.insert(root.join(name), content.into());
    }
    // Keep every pre-existing shared file, including administrator settings.
    files.retain(|path, _| fs::symlink_metadata(path).is_err());
    for directory in [
        &config.nginx.domains_available_dir,
        &config.nginx.domains_enabled_dir,
        &root.join("module.d"),
    ] {
        nginx::ensure_no_symlink_ancestors(root, directory)?;
        fs::create_dir_all(directory)?;
    }
    for directory in [
        &config.nginx.log_dir,
        config.nginx.pid_path.parent().unwrap_or(root),
        &var_dir.join("log/nginx"),
    ] {
        fs::create_dir_all(directory)?;
    }
    let certificate_dir = root.join(
        global
            .shared
            .get("default_certificate_dir")
            .and_then(Value::as_str)
            .unwrap_or("certs/default"),
    );
    let key = certificate_dir.join("privkey.pem");
    let certificate = certificate_dir.join("fullchain.pem");
    nginx::ensure_no_symlink_ancestors(root, &key)?;
    nginx::ensure_no_symlink_ancestors(root, &certificate)?;
    if !key.exists() || !certificate.exists() {
        if key.exists() || certificate.exists() {
            bail!("fallback certificate is incomplete; supply both fullchain.pem and privkey.pem");
        }
        fs::create_dir_all(&certificate_dir)?;
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let temporary_key = certificate_dir.join(format!(".{nonce}.key"));
        let temporary_certificate = certificate_dir.join(format!(".{nonce}.crt"));
        let result = crate::command::CommandRunner::new(false)
            .run(
                &config.commands.openssl,
                [
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "3650",
                    "-subj",
                    "/CN=router-hub-default.invalid",
                    "-keyout",
                    temporary_key
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("invalid certificate path"))?,
                    "-out",
                    temporary_certificate
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("invalid certificate path"))?,
                ],
                Duration::from_secs(60),
            )
            .await;
        let material = (|| -> Result<(String, String)> {
            let result = result?;
            if !result.success {
                bail!("fallback certificate generation failed: {}", result.stderr);
            }
            Ok((
                fs::read_to_string(&temporary_key)?,
                fs::read_to_string(&temporary_certificate)?,
            ))
        })();
        let _ = fs::remove_file(temporary_key);
        let _ = fs::remove_file(temporary_certificate);
        let (key_content, certificate_content) = material?;
        files.insert(key.clone(), key_content);
        files.insert(certificate, certificate_content);
    }
    let transaction = FileTransaction::apply(config, files)?;
    if key.exists() {
        fs::set_permissions(key, fs::Permissions::from_mode(0o600))?;
    }
    transaction.commit();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn migration_config(root: &std::path::Path) -> crate::config::AppConfig {
        let mut config = crate::config::AppConfig::default();
        config.nginx.root_dir = root.join("nginx");
        config.nginx.inputs_dir = root.join("router-hub/nginx");
        std::fs::create_dir_all(config.nginx.root_dir.join("settings")).unwrap();
        config
    }

    #[test]
    fn migration_preserves_policies_and_active_runtime_files() {
        use std::fs;
        let temp = tempfile::tempdir().unwrap();
        let config = migration_config(temp.path());
        let legacy = config.nginx.root_dir.join("settings");
        let globals = encode_global(&limits()).unwrap();
        let sites = r#"[sites.app]
kind = "subdomain"
domain = "example.test"
name = "app"
enabled = true
upstream = "http://127.0.0.1:8080"
limit_policy = "api"
routes = [{path = "/static/", limit_policy = "assets"}]
"#;
        for (name, content) in [
            ("nginx.toml", globals.as_str()),
            ("sites.toml", sites),
            ("allowed_ips.txt", "192.0.2.0/24"),
            ("domains.conf", "custom.test http://127.0.0.1:8000;"),
            ("security_trap_allow.conf", "# custom guard exceptions"),
            ("proxy.jinja", "ignored template"),
        ] {
            fs::write(legacy.join(name), content).unwrap();
        }
        fs::write(
            config.nginx.root_dir.join("custom.conf"),
            "administrator config",
        )
        .unwrap();
        assert!(load_global(&config).is_err());
        assert!(crate::nginx_sites::load(&config).is_err());
        assert_eq!(migrate_inputs(&config).unwrap(), 5);
        assert_eq!(fs::read_to_string(global_path(&config)).unwrap(), globals);
        assert_eq!(
            fs::read_to_string(crate::nginx_sites::path(&config)).unwrap(),
            sites
        );
        assert!(!legacy.join("nginx.toml").exists());
        assert!(!legacy.join("sites.toml").exists());
        assert!(!legacy.join("allowed_ips.txt").exists());
        assert!(legacy.join("domains.conf").exists());
        assert!(!config.nginx.inputs_dir.join("proxy.jinja").exists());
        assert_eq!(
            fs::read_to_string(config.nginx.root_dir.join("custom.conf")).unwrap(),
            "administrator config"
        );
        let global = load_global(&config).unwrap();
        let sites = crate::nginx_sites::load(&config).unwrap();
        let site = &sites.sites["app"];
        let output =
            render_site(&global, &site.settings, site.kind, &site.domain, "app", &[]).unwrap();
        assert!(output.contains("limit_req zone=rh_req_assets burst=500 nodelay;"));
        assert!(output.contains("limit_req zone=rh_req_api;"));
        let before = fs::read(global_path(&config)).unwrap();
        migrate_inputs(&config).unwrap();
        assert_eq!(fs::read(global_path(&config)).unwrap(), before);
    }

    #[test]
    fn migration_rejects_conflicts_before_changing_any_files() {
        use std::fs;
        let temp = tempfile::tempdir().unwrap();
        let config = migration_config(temp.path());
        let legacy = config.nginx.root_dir.join("settings");
        fs::write(legacy.join("nginx.toml"), "[global]\nhttp_port = 8080").unwrap();
        fs::write(legacy.join("allowed_ips.txt"), "192.0.2.0/24").unwrap();
        fs::create_dir_all(&config.nginx.inputs_dir).unwrap();
        fs::write(global_path(&config), "[global]\nhttp_port = 9090").unwrap();
        assert!(migrate_inputs(&config).is_err());
        assert!(!config.nginx.inputs_dir.join("allowed_ips.txt").exists());
        assert!(legacy.join("allowed_ips.txt").exists());
        assert_eq!(
            fs::read_to_string(global_path(&config)).unwrap(),
            "[global]\nhttp_port = 9090"
        );
    }

    #[test]
    fn migration_validation_failure_restores_both_directories() {
        use std::fs;
        for invalid in [
            "invalid TOML [",
            "[sites.bad]\nkind = 'subdomain'\ndomain = 'example.test'\nname = 'bad'\nlimit_policy = 'missing'",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let config = migration_config(temp.path());
            let legacy = config.nginx.root_dir.join("settings");
            fs::write(legacy.join("nginx.toml"), "[global]\nhttp_port = 8080").unwrap();
            fs::write(legacy.join("sites.toml"), invalid).unwrap();
            fs::write(legacy.join("allowed_ips.txt"), "192.0.2.0/24").unwrap();
            assert!(migrate_inputs(&config).is_err());
            assert_eq!(
                fs::read_to_string(legacy.join("sites.toml")).unwrap(),
                invalid
            );
            assert!(legacy.join("nginx.toml").exists());
            assert!(legacy.join("allowed_ips.txt").exists());
            assert!(!global_path(&config).exists());
            assert!(!crate::nginx_sites::path(&config).exists());
            assert!(!config.nginx.inputs_dir.join("allowed_ips.txt").exists());
        }
    }

    #[test]
    fn transaction_spans_inputs_and_runtime_and_rejects_symlinks() {
        use std::{fs, os::unix::fs::symlink};
        let temp = tempfile::tempdir().unwrap();
        let config = migration_config(temp.path());
        fs::create_dir_all(&config.nginx.inputs_dir).unwrap();
        let input = config.nginx.inputs_dir.join("domains.conf");
        let runtime = config.nginx.root_dir.join("settings/domains.conf");
        fs::write(&input, "old input").unwrap();
        fs::write(&runtime, "old runtime").unwrap();
        let transaction = FileTransaction::apply(
            &config,
            [
                (input.clone(), "new input".into()),
                (runtime.clone(), "new runtime".into()),
            ]
            .into(),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&input).unwrap(), "new input");
        assert_eq!(fs::read_to_string(&runtime).unwrap(), "new runtime");
        drop(transaction);
        assert_eq!(fs::read_to_string(&input).unwrap(), "old input");
        assert_eq!(fs::read_to_string(&runtime).unwrap(), "old runtime");
        let outside = temp.path().join("outside");
        fs::write(&outside, "outside").unwrap();
        let link = config.nginx.inputs_dir.join("nginx.toml");
        symlink(&outside, &link).unwrap();
        assert!(load_global(&config).is_err());
        assert!(migrate_inputs(&config).is_err());
        assert_eq!(fs::read_to_string(&outside).unwrap(), "outside");
        assert!(
            FileTransaction::apply(
                &config,
                [(temp.path().join("outside.conf"), "bad".into())].into()
            )
            .is_err()
        );
    }

    fn limits() -> GlobalSettings {
        serde_json::from_value(json!({"limit_policies": {
            "assets": {"rate":"100r/s", "burst":500, "nodelay":true, "connections":50},
            "api": {"rate":"5r/m", "burst":0, "nodelay":false, "connections":3}
        }}))
        .unwrap()
    }

    #[test]
    fn named_limits_resolve_nested_policies_and_supplements() {
        let global = limits();
        let settings = json!({"limit_policy":"assets", "routes":[
            {"path":"/api", "limit_policy":"api", "rate_limit":{"zone":"wplogin","burst":3}, "children":[
                {"path":"/api/nested"}, {"path":"/api/default", "limit_policy":"default"}
            ]}
        ]}).as_object().unwrap().clone();
        let rendered = render_site(
            &global,
            &settings,
            NginxObjectKind::Subdomain,
            "example.test",
            "app",
            &[],
        )
        .unwrap();
        assert_eq!(
            rendered
                .matches("limit_req zone=rh_req_assets burst=500 nodelay;")
                .count(),
            1
        );
        assert_eq!(rendered.matches("limit_req zone=rh_req_api;").count(), 2);
        assert_eq!(rendered.matches("limit_conn rh_conn_api 3;").count(), 2);
        assert_eq!(
            rendered
                .matches("limit_req zone=wplogin burst=3 nodelay;")
                .count(),
            3
        );
        assert_eq!(
            rendered
                .matches("limit_req zone=global_rate burst=60 nodelay;")
                .count(),
            1
        );
        let defaults = render_site(
            &GlobalSettings::default(),
            &Settings::new(),
            NginxObjectKind::Subdomain,
            "example.test",
            "app",
            &[],
        )
        .unwrap();
        assert!(defaults.contains("limit_conn per_client_conn 30;"));
        assert!(defaults.contains("limit_req zone=global_rate burst=60 nodelay;"));
        let mut inherited = global.clone();
        inherited.site_defaults = json!({"limit_policy":"api"}).as_object().unwrap().clone();
        let output = render_site(
            &inherited,
            &Settings::new(),
            NginxObjectKind::Subfolder,
            "example.test",
            "app",
            &[],
        )
        .unwrap();
        assert!(output.contains("limit_req zone=rh_req_api;"));
    }

    #[test]
    fn invalid_limit_policies_and_references_are_rejected() {
        for policy in [
            json!({"rate":"0r/s","burst":1,"nodelay":true,"connections":1}),
            json!({"rate":"1r/s;bad","burst":1,"nodelay":true,"connections":1}),
            json!({"rate":"1r/s","burst":100001,"nodelay":true,"connections":1}),
            json!({"rate":"1r/s","burst":1,"nodelay":true,"connections":0}),
        ] {
            let global: GlobalSettings =
                serde_json::from_value(json!({"limit_policies":{"test":policy}})).unwrap();
            assert!(global.validate().is_err());
        }
        for name in ["default", "bad;", ""] {
            let mut global = limits();
            global
                .limit_policies
                .insert(name.into(), global.limit_policies["api"].clone());
            assert!(global.validate().is_err());
        }
        for value in [
            json!({"limit_policy":null}),
            json!({"limit_policy":{}}),
            json!({"limit_policy":"bad;"}),
        ] {
            assert!(validate_site(value.as_object().unwrap()).is_err());
        }
        let settings = json!({"routes":[{"path":"/parent","children":[{"path":"/parent/child","limit_policy":"missing"}]}]}).as_object().unwrap().clone();
        assert!(
            render_site(
                &limits(),
                &settings,
                NginxObjectKind::Subfolder,
                "example.test",
                "app",
                &[]
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<GlobalSettings>(
                json!({"limit_policies":{"test":{"rate":"1r/s","burst":1,"connections":1}}})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<GlobalSettings>(json!({"limit_policies":{"test":{"rate":"1r/s","burst":1,"nodelay":true,"connections":1,"unknown":true}}})).is_err());
    }

    #[test]
    fn named_limit_persistence_and_zone_accounting() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = crate::config::AppConfig::default();
        config.nginx.root_dir = temp.path().into();
        config.nginx.inputs_dir = temp.path().join("router-hub/nginx");
        let mut global = limits();
        global.site_defaults = json!({"limit_policy":"api"}).as_object().unwrap().clone();
        let files = shared_files(&config, &global).unwrap();
        let zones = &files[&temp.path().join("conf.d/00-limit-policies.conf")];
        for name in ["assets", "api"] {
            assert!(zones.contains(&format!("$binary_remote_addr zone=rh_req_{name}:1m")));
            assert!(zones.contains(&format!("$binary_remote_addr zone=rh_conn_{name}:1m")));
        }
        std::fs::create_dir_all(&config.nginx.inputs_dir).unwrap();
        std::fs::write(global_path(&config), encode_global(&global).unwrap()).unwrap();
        let restored = load_global(&config).unwrap();
        assert_eq!(
            serde_json::to_value(&restored.limit_policies).unwrap(),
            serde_json::to_value(&global.limit_policies).unwrap()
        );
        assert_eq!(
            shared_files(&config, &restored).unwrap()
                [&temp.path().join("conf.d/00-limit-policies.conf")],
            *zones
        );
        let site = crate::nginx_sites::Site {
            kind: NginxObjectKind::Subdomain,
            domain: "example.test".into(),
            name: Some("app".into()),
            server_name: "app.example.test".into(),
            subfolder: None,
            upstream: Some("http://127.0.0.1:8080".into()),
            enabled: false,
            settings: json!({"limit_policy":"assets"})
                .as_object()
                .unwrap()
                .clone(),
        };
        crate::nginx_sites::save(&config, site.kind, &site.domain, "app", Some(site.clone()))
            .unwrap()
            .commit();
        let saved = crate::nginx_sites::find(&config, site.kind, &site.domain, "app")
            .unwrap()
            .unwrap();
        assert_eq!(saved.settings["limit_policy"], "assets");
        assert!(!saved.enabled);
        let mut removed = restored.clone();
        removed.limit_policies.remove("assets");
        removed.validate().unwrap();
        assert!(shared_files(&config, &removed).is_err());
    }

    #[test]
    fn renders_every_base_combination_and_preserves_false_and_zero() {
        let global = GlobalSettings::default();
        for kind in [
            NginxObjectKind::Domain,
            NginxObjectKind::Subdomain,
            NginxObjectKind::Subfolder,
        ] {
            for bits in 0..64 {
                let mut settings = Settings::new();
                for (i, key) in [
                    "enable_lanonly",
                    "enable_large_upload",
                    "enable_longlived",
                    "enable_streaming",
                    "enable_byte_ranges",
                ]
                .iter()
                .enumerate()
                {
                    settings.insert((*key).into(), ((bits & (1 << i)) != 0).into());
                }
                settings.insert(
                    "cache_policy".into(),
                    (if bits & 32 != 0 { "pwa" } else { "inherit" }).into(),
                );
                settings.insert("disable_root".into(), false.into());
                settings.insert("large_upload_max_body_size".into(), "0".into());
                let content =
                    render_site(&global, &settings, kind, "example.test", "app", &[]).unwrap();
                assert!(!content.contains("{%"));
                assert!(!content.contains("{{"));
                assert_eq!(site_settings(&content).unwrap(), Some(settings));
                if bits & 2 != 0 {
                    assert!(content.contains("client_max_body_size 0;"));
                }
            }
        }
    }

    #[test]
    fn rejects_removed_cache_switches_in_sites_and_nested_routes() {
        for key in ["enable_pwa", "enable_no_cache", "output"] {
            let settings = [(key.to_string(), json!(true))].into_iter().collect();
            assert!(validate_site(&settings).is_err());
            let settings = json!({"routes": [{"path": "/parent", "children": [{"path": "/parent/child", key: true}]}]}).as_object().unwrap().clone();
            assert!(validate_site(&settings).is_err());
        }
    }

    #[test]
    fn lists_are_read_only_from_current_toml() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = crate::config::AppConfig::default();
        config.nginx.root_dir = temp.path().into();
        config.nginx.inputs_dir = temp.path().join("router-hub/nginx");
        std::fs::create_dir(temp.path().join("settings")).unwrap();
        std::fs::write(temp.path().join("settings/allowed_ips.txt"), "192.0.2.0/24").unwrap();
        std::fs::write(
            temp.path().join("settings/free_subdomains.txt"),
            "example.test",
        )
        .unwrap();
        let settings = load_global(&config).unwrap();
        assert!(settings.allowed_ips.is_empty());
        assert!(settings.free_subdomains.is_empty());
    }

    #[test]
    fn renders_route_inheritance_and_spa_macros() {
        let settings = json!({"enable_lanonly": false, "disable_root": false, "cache_policy": "pwa", "spa_fallback": "/index.html", "routes": [{"path": "/admin", "enable_lanonly": true, "spa_fallback": "", "children": [{"path": "/admin/quiet", "access_log": false}]}, {"path": "/events", "proxy_transport": "sse"}]}).as_object().unwrap().clone();
        let content = render_site(
            &GlobalSettings::default(),
            &settings,
            NginxObjectKind::Subfolder,
            "example.test",
            "app",
            &[],
        )
        .unwrap();
        assert!(content.contains("/app/admin"));
        assert!(content.contains("proxy_buffering off;"));
        assert!(content.contains("if=$log_traps_only;"));
        assert!(content.contains("@rh_"));
    }

    #[test]
    fn rejects_injection_and_unknown_options() {
        for value in [
            json!({"client_max_body_size": "0; include evil;"}),
            json!({"enable_lanonly": "false"}),
            json!({"routes": [{"path": "/admin;"}]}),
            json!({"template": "old"}),
            json!({"proxy_transport": "ftp"}),
        ] {
            assert!(validate_site(value.as_object().unwrap()).is_err());
        }
        let global = GlobalSettings {
            shared: json!({"router_ip": "127.0.0.1;"})
                .as_object()
                .unwrap()
                .clone(),
            ..Default::default()
        };
        assert!(global.validate().is_err());
    }

    #[test]
    fn deployment_data_cannot_replace_policy() {
        let mut data = BTreeMap::new();
        data.insert("settings/proxy.jinja".into(), "invalid policy".into());
        data.insert("settings/allowed_ips.txt".into(), "192.0.2.0/24\n".into());
        let env = environment(&data).unwrap();
        let rendered = env
            .get_template("snippets/restrict.conf.jinja")
            .unwrap()
            .render(())
            .unwrap();
        assert!(rendered.contains("allow 192.0.2.0/24;"));
        assert!(
            !env.get_template("settings/proxy.jinja")
                .unwrap()
                .render(())
                .unwrap()
                .contains("invalid policy")
        );
    }
    #[test]
    fn file_transaction_restores_bytes_and_rejects_symlinks() {
        use std::fs;
        let temp = tempfile::tempdir().unwrap();
        let mut config = crate::config::AppConfig::default();
        config.nginx.root_dir = temp.path().join("nginx");
        config.nginx.inputs_dir = temp.path().join("router-hub/nginx");
        fs::create_dir_all(&config.nginx.root_dir).unwrap();
        let original = config.nginx.root_dir.join("original.conf");
        let added = config.nginx.root_dir.join("added.conf");
        fs::write(&original, "original bytes").unwrap();
        let files = [
            (original.clone(), "replacement".into()),
            (added.clone(), "new file".into()),
        ]
        .into_iter()
        .collect();
        let transaction = FileTransaction::apply(&config, files).unwrap();
        assert_eq!(fs::read_to_string(&original).unwrap(), "replacement");
        drop(transaction);
        assert_eq!(fs::read_to_string(&original).unwrap(), "original bytes");
        assert!(!added.exists());
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        std::fs::create_dir_all(config.nginx.inputs_dir.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside, &config.nginx.inputs_dir).unwrap();
        assert!(load_global(&config).is_err());
        let files = [(global_path(&config), "bad write".into())]
            .into_iter()
            .collect();
        assert!(FileTransaction::apply(&config, files).is_err());
        assert!(!outside.join("nginx.toml").exists());
    }
    #[test]
    fn deployment_globals_preserve_linux_runtime_options_and_normalize_certificates() {
        use std::fs;
        let temp = tempfile::tempdir().unwrap();
        let nginx_root = temp.path().join("nginx");
        std::fs::create_dir(&nginx_root).unwrap();
        let root = nginx_root.as_path();
        let mut config = crate::config::AppConfig {
            platform: crate::config::Platform::Linux,
            ..Default::default()
        };
        config.nginx.root_dir = root.into();
        config.nginx.inputs_dir = temp.path().join("router-hub/nginx");
        config.nginx.config_path = root.join("nginx.conf");
        config.nginx.domain_upstream_map_path = root.join("conf.d/02_domain_upstream_map.conf");
        config.nginx.subdomain_upstream_map_path =
            root.join("conf.d/03_subdomain_upstream_map.conf");
        config.nginx.subfolder_upstream_map_path =
            root.join("conf.d/04_subfolder_upstream_map.conf");
        config.nginx.http_forwarder_path = root.join("conf.d/05-http-to-https.conf");
        fs::create_dir_all(&config.nginx.inputs_dir).unwrap();
        let input = global_path(&config);
        fs::write(&input, "[global]\nhttp_port = 19080\nhttps_port = 19443\nnginx_daemon = false\nnginx_user = ''\ndefault_certificate_dir = 'certs/example_test'\n").unwrap();
        let mut global = load_global(&config).unwrap();
        global.site_defaults = json!({"enable_streaming": false, "large_upload_max_body_size": "0", "routes": [{"path": "/events", "proxy_transport": "sse"}]}).as_object().unwrap().clone();
        global.allowed_ips = vec!["192.0.2.0/24".into()];
        global.free_subdomains = vec!["shared.example.test".into()];
        assert_eq!(global.shared["http_port"], 19080);
        assert_eq!(global.shared["nginx_daemon"], false);
        assert_eq!(
            global.shared["default_certificate_dir"],
            root.join("certs/example_test").to_string_lossy().as_ref()
        );
        assert_eq!(global_path(&config), input);
        let files = shared_files(&config, &global).unwrap();
        let main = &files[&config.nginx.config_path];
        assert!(main.contains("daemon off;"));
        assert_eq!(main.contains("user nobody;"), unsafe {
            libc::geteuid() == 0
        });
        for (directive, folder) in [
            ("client_body", "client-body"),
            ("proxy", "proxy"),
            ("fastcgi", "fastcgi"),
            ("uwsgi", "uwsgi"),
            ("scgi", "scgi"),
        ] {
            let temp_dir = global.shared["temp_dir"].as_str().unwrap();
            assert!(main.contains(&format!("{directive}_temp_path {temp_dir}/{folder};")));
        }
        FileTransaction::apply(&config, files).unwrap().commit();
        let saved: toml::Value = toml::from_str(&fs::read_to_string(&input).unwrap()).unwrap();
        assert_eq!(saved["global"]["http_port"].as_integer(), Some(19080));
        let restored = load_global(&config).unwrap();
        assert_eq!(restored.shared, global.shared);
        assert_eq!(restored.site_defaults, global.site_defaults);
        assert_eq!(restored.allowed_ips, global.allowed_ips);
        assert_eq!(restored.free_subdomains, global.free_subdomains);
        // An explicit empty list in TOML overrides an older generated fragment.
        let mut saved: toml::Value = saved;
        saved["allowed_ips"] = toml::Value::Array(Vec::new());
        saved["global"]["http_port"] = toml::Value::Integer(19081);
        fs::write(&input, toml::to_string_pretty(&saved).unwrap()).unwrap();
        let edited = load_global(&config).unwrap();
        assert!(edited.allowed_ips.is_empty());
        assert_eq!(edited.shared["http_port"], 19081);
        assert!(
            shared_files(&config, &restored).unwrap()[&config.nginx.config_path]
                .contains("daemon off;")
        );
        fs::remove_file(global_path(&config)).unwrap();
        fs::write(&input, "[global]\ndefault_certificate_dir = '../outside'\n").unwrap();
        assert!(load_global(&config).is_err());
        fs::remove_file(&input).unwrap();
        std::os::unix::fs::symlink(root.join("outside"), &input).unwrap();
        assert!(load_global(&config).is_err());
    }
    #[test]
    fn worker_user_depends_on_effective_root_privileges() {
        let env = environment(&BTreeMap::new()).unwrap();
        let template = env.get_template("nginx.conf.jinja").unwrap();
        for (user, expected) in [
            (None, "nobody"),
            (Some(""), "nobody"),
            (Some("www-data"), "www-data"),
        ] {
            let mut settings = GlobalSettings::default();
            if let Some(user) = user {
                settings.shared.insert("nginx_user".into(), user.into());
            }
            settings.validate().unwrap();
            for is_root in [false, true] {
                let output = template
                    .render(minijinja::value::Serde(runtime_context(&settings, is_root)))
                    .unwrap();
                let user_lines = output
                    .lines()
                    .filter(|line| line.starts_with("user "))
                    .collect::<Vec<_>>();
                if is_root {
                    assert_eq!(user_lines, vec![format!("user {expected};")]);
                } else {
                    assert!(user_lines.is_empty());
                }
            }
        }
    }
}
