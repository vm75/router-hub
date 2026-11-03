//! Nginx composition is defined by a versioned TOML catalog, not Rust feature enums.
//! A site's adjacent .toml file opts in; existing custom and template sites stay intact.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    process::Command,
};

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{config::AppConfig, models::NginxObjectKind, nginx};

const SITE_SCHEMA: u8 = 1;
const CATALOG_SCHEMA: u8 = 1;

/// Site values are keyed by catalog option ID. New options need no Rust changes.
pub type SiteOptions = BTreeMap<String, serde_json::Value>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionCatalog {
    pub schema_version: u8,
    pub base: Vec<BaseDefinition>,
    pub options: Vec<OptionDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseDefinition {
    pub kind: NginxObjectKind,
    #[serde(default)]
    pub effects: Vec<Effect>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionType {
    Optional,
    Choice,
    Parameterized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionDefinition {
    pub id: String,
    #[serde(rename = "type")]
    pub option_type: OptionType,
    pub label: String,
    #[serde(default)]
    pub description: String,
    pub kinds: Vec<NginxObjectKind>,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub requirements: Vec<ScopedRequirement>,
    #[serde(default)]
    pub effects: Vec<Effect>,
    #[serde(default)]
    pub choices: Vec<ChoiceDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedRequirement {
    pub kind: NginxObjectKind,
    pub condition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChoiceDefinition {
    pub value: String,
    pub label: String,
    #[serde(default)]
    pub effects: Vec<Effect>,
}

/// Directive arguments are data; slots are the only structural operation supported.
/// "site" means server for domain/subdomain and location for subfolder.
/// "location:/path" adds a named location under a domain or subdomain server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Effect {
    pub slot: String,
    pub directive: String,
    pub value: String,
    #[serde(default)]
    pub kinds: Vec<NginxObjectKind>,
}

impl OptionCatalog {
    pub fn parse(content: &str) -> Result<Self> {
        let catalog: Self =
            toml::from_str(content).context("invalid nginx composer catalog TOML")?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CATALOG_SCHEMA {
            bail!(
                "unsupported nginx composer catalog schema_version {}",
                self.schema_version
            );
        }
        for kind in [
            NginxObjectKind::Domain,
            NginxObjectKind::Subdomain,
            NginxObjectKind::Subfolder,
        ] {
            if self.base.iter().filter(|base| base.kind == kind).count() != 1 {
                bail!(
                    "nginx composer catalog requires exactly one base for {}",
                    kind.as_str()
                );
            }
        }
        for base in &self.base {
            for effect in &base.effects {
                validate_effect(effect)?;
            }
        }
        let mut names = BTreeSet::new();
        for option in &self.options {
            if !valid_identifier(&option.id) || !names.insert(option.id.as_str()) {
                bail!(
                    "invalid or duplicate nginx composer option ID: {}",
                    option.id
                );
            }
            if option.label.trim().is_empty() || option.kinds.is_empty() {
                bail!(
                    "option {} must have a label and at least one kind",
                    option.id
                );
            }
            for effect in &option.effects {
                validate_effect(effect)?;
            }
            match option.option_type {
                OptionType::Optional => {
                    if !option.choices.is_empty()
                        || option.pattern.is_some()
                        || option
                            .default
                            .as_deref()
                            .is_some_and(|v| v != "true" && v != "false")
                    {
                        bail!("invalid optional option definition: {}", option.id);
                    }
                }
                OptionType::Choice => {
                    if option.choices.is_empty()
                        || option.pattern.is_some()
                        || option.default.is_none()
                    {
                        bail!("choice {} needs choices and a default", option.id);
                    }
                    let mut values = BTreeSet::new();
                    for choice in &option.choices {
                        if !valid_identifier(&choice.value) || !values.insert(choice.value.as_str())
                        {
                            bail!(
                                "invalid or duplicate choice {}: {}",
                                option.id,
                                choice.value
                            );
                        }
                        for effect in &choice.effects {
                            validate_effect(effect)?;
                        }
                    }
                    if !values.contains(option.default.as_deref().unwrap_or_default()) {
                        bail!("default for choice {} must match a choice", option.id);
                    }
                }
                OptionType::Parameterized => {
                    if !option.choices.is_empty() || option.pattern.is_none() {
                        bail!("parameterized option {} needs a regex pattern", option.id);
                    }
                    validate_pattern(option.pattern.as_deref().unwrap_or_default())?;
                    if let Some(default) = &option.default {
                        validate_parameter(option, default)?;
                    }
                }
            }
        }
        // Validate dependencies at catalog load time: typoed references must not
        // silently disable a required feature.
        for option in &self.options {
            for condition in option
                .requires
                .iter()
                .chain(option.requirements.iter().map(|r| &r.condition))
            {
                let (id, _, _) = parse_condition(condition)?;
                if !names.contains(id) {
                    bail!("option {} requires missing catalog option {id}", option.id);
                }
            }
            for requirement in &option.requirements {
                if !option.kinds.contains(&requirement.kind) {
                    bail!(
                        "condition for {} applies to an unsupported site kind",
                        option.id
                    );
                }
            }
        }
        Ok(())
    }

    fn option(&self, id: &str) -> Option<&OptionDefinition> {
        self.options.iter().find(|o| o.id == id)
    }
}

pub fn load_catalog(config: &AppConfig) -> Result<OptionCatalog> {
    let path = &config.nginx.composer_path;
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("nginx composer catalog missing: {}", path.display()))?;
    if !meta.file_type().is_file() {
        bail!(
            "nginx composer catalog must be a regular file: {}",
            path.display()
        );
    }
    let content = fs::read_to_string(path)?;
    OptionCatalog::parse(&content).with_context(|| format!("catalog: {}", path.display()))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn validate_pattern(pattern: &str) -> Result<()> {
    if pattern.len() > 512 {
        bail!("parameter pattern is too long");
    }
    Regex::new(&format!(r"\A(?:{pattern})\z"))?;
    Ok(())
}

fn validate_parameter(option: &OptionDefinition, input: &str) -> Result<()> {
    if input.len() > 256 || input.is_empty() || input.contains(['\r', '\n', ';', '{', '}', '#']) {
        bail!("invalid value for nginx option {}", option.id);
    }
    let pattern = option
        .pattern
        .as_deref()
        .context("parameter pattern missing")?;
    if !Regex::new(&format!(r"\A(?:{pattern})\z"))?.is_match(input) {
        bail!("invalid value for nginx option {}: {input}", option.id);
    }
    Ok(())
}

fn validate_effect(effect: &Effect) -> Result<()> {
    if !valid_identifier(&effect.directive)
        || effect.value.len() > 4096
        || effect.value.contains(['\r', '\n', ';', '#'])
    {
        bail!("invalid nginx directive or value: {}", effect.directive);
    }
    match effect.slot.as_str() {
        "site" | "server" | "location" => {}
        slot if slot.starts_with("location:/")
            && slot[9..].len() <= 128
            && slot[9..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.')) => {}
        _ => bail!("invalid nginx composer slot: {}", effect.slot),
    }
    // Only well-defined substitutions are accepted, avoiding unresolved braces.
    let mut rest = effect.value.as_str();
    while let Some(start) = rest.find("{{") {
        let remaining = &rest[start + 2..];
        let end = remaining
            .find("}}")
            .context("unterminated composer placeholder")?;
        if !matches!(
            &remaining[..end],
            "domain" | "name" | "regex_name" | "server_name" | "value"
        ) {
            bail!("unknown nginx composer placeholder: {}", &remaining[..end]);
        }
        rest = &remaining[end + 2..];
    }
    Ok(())
}

fn parse_condition(input: &str) -> Result<(&str, &'static str, &str)> {
    if let Some((id, value)) = input.split_once("!=") {
        if valid_identifier(id) && valid_identifier(value) {
            return Ok((id, "!=", value));
        }
    }
    if let Some((id, value)) = input.split_once('=') {
        if valid_identifier(id) && valid_identifier(value) {
            return Ok((id, "=", value));
        }
    }
    if valid_identifier(input) {
        return Ok((input, "enabled", ""));
    }
    bail!("invalid catalog condition: {input}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteDefinition {
    #[serde(default = "site_schema")]
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

fn site_schema() -> u8 {
    SITE_SCHEMA
}

impl SiteDefinition {
    pub fn new(
        kind: NginxObjectKind,
        domain: &str,
        name: &str,
        server_names: &[String],
        upstream: Option<&str>,
        options: SiteOptions,
    ) -> Self {
        Self {
            schema_version: SITE_SCHEMA,
            kind,
            domain: domain.into(),
            name: name.into(),
            server_names: server_names.to_vec(),
            upstream: upstream.map(str::to_string),
            options: options
                .into_iter()
                .filter(|(_, value)| !value.is_null())
                .collect(),
        }
    }

    fn selected_value(&self, option: &OptionDefinition) -> Result<Option<String>> {
        let input = self.options.get(&option.id);
        match option.option_type {
            OptionType::Optional => {
                let on = match input {
                    None => option.default.as_deref() == Some("true"),
                    Some(value) => value
                        .as_bool()
                        .with_context(|| format!("option {} must be a boolean", option.id))?,
                };
                Ok(on.then(|| "true".to_string()))
            }
            OptionType::Choice => {
                let value = match input {
                    None => option
                        .default
                        .as_deref()
                        .context("choice default missing")?,
                    Some(value) => value
                        .as_str()
                        .with_context(|| format!("option {} must be a choice string", option.id))?,
                };
                if !option.choices.iter().any(|choice| choice.value == value) {
                    bail!("invalid choice for {}: {value}", option.id);
                }
                Ok(Some(value.to_string()))
            }
            OptionType::Parameterized => {
                let value = match input {
                    None => option.default.as_deref(),
                    Some(value) => Some(
                        value
                            .as_str()
                            .with_context(|| format!("option {} must be a string", option.id))?,
                    ),
                };
                if let Some(value) = value {
                    validate_parameter(option, value)?;
                }
                Ok(value.map(str::to_string))
            }
        }
    }

    fn condition_met(&self, catalog: &OptionCatalog, condition: &str) -> Result<bool> {
        let (id, operation, required) = parse_condition(condition)?;
        let option = catalog.option(id).context("unknown dependency")?;
        let value = self.selected_value(option)?;
        Ok(match operation {
            "enabled" => value.as_deref().is_some_and(|v| v != "false"),
            "=" => value.as_deref() == Some(required),
            "!=" => value.as_deref() != Some(required),
            _ => unreachable!(),
        })
    }

    /// Earlier branch versions serialized defaults for every kind into sidecars.
    /// Drop only inapplicable default-valued fields; non-default out-of-scope
    /// fields still fail validation to prevent silent behavior loss.
    pub fn remove_legacy_defaults(&mut self, catalog: &OptionCatalog) {
        self.options.retain(|id, value| {
            let Some(option) = catalog.option(id) else {
                return true;
            };
            if option.kinds.contains(&self.kind) {
                return true;
            }
            match option.option_type {
                OptionType::Optional => value
                    .as_bool()
                    .is_some_and(|v| v != (option.default.as_deref() == Some("true"))),
                OptionType::Choice => value.as_str() != option.default.as_deref(),
                OptionType::Parameterized => value.as_str() != option.default.as_deref(),
            }
        });
    }

    pub fn validate(&self, catalog: &OptionCatalog) -> Result<()> {
        if self.schema_version != SITE_SCHEMA {
            bail!(
                "unsupported nginx site schema_version {}",
                self.schema_version
            );
        }
        nginx::validate_name(&self.domain, "domain")?;
        nginx::validate_name(&self.name, "name")?;
        if self.kind == NginxObjectKind::Domain && self.domain != self.name {
            bail!("domain name must equal its domain");
        }
        let names =
            nginx::normalize_server_names(self.kind, &self.domain, &self.name, &self.server_names)?;
        if self.kind == NginxObjectKind::Subfolder && names != vec![self.domain.clone()] {
            bail!("subfolder server_names must be the parent domain");
        }
        nginx::validate_site_upstream(self.kind, self.upstream.as_deref())?;
        for (id, input) in &self.options {
            let option = catalog
                .option(id)
                .with_context(|| format!("unknown nginx option: {id}"))?;
            if !option.kinds.contains(&self.kind) {
                bail!("nginx option {id} cannot be used on {}", self.kind.as_str());
            }
            if input.is_null() {
                bail!("nginx option {id} cannot be null");
            }
            self.selected_value(option)?;
        }
        for option in &catalog.options {
            if !option.kinds.contains(&self.kind) {
                continue;
            }
            let selected = self.selected_value(option)?;
            if selected.is_none() {
                continue;
            }
            for condition in option.requires.iter().chain(
                option
                    .requirements
                    .iter()
                    .filter(|r| r.kind == self.kind)
                    .map(|r| &r.condition),
            ) {
                if !self.condition_met(catalog, condition)? {
                    bail!("nginx option {} requires {condition}", option.id);
                }
            }
        }
        // The structural renderer always relies on the corresponding upstream for
        // subdomain/subfolder; domain proxy roots are identified by catalog rules.
        let needs_upstream = self.kind != NginxObjectKind::Domain
            || self
                .resolved(catalog)?
                .get("location")
                .is_some_and(|rules| rules.iter().any(|r| r.directive == "proxy_pass"));
        if needs_upstream && self.upstream.as_deref().is_none_or(str::is_empty) {
            bail!("a proxied composed site requires an upstream URL");
        }
        Ok(())
    }

    fn expand(&self, value: &str, parameter: Option<&str>) -> Result<String> {
        let server_names =
            nginx::normalize_server_names(self.kind, &self.domain, &self.name, &self.server_names)?
                .join(" ");
        let out = value
            .replace("{{domain}}", &self.domain)
            .replace("{{regex_name}}", &regex::escape(&self.name))
            .replace("{{name}}", &self.name)
            .replace("{{server_name}}", &server_names)
            .replace("{{value}}", parameter.unwrap_or(""));
        if out.contains("{{") || out.contains('\n') || out.contains(';') {
            bail!("unsafe nginx composer directive value");
        }
        Ok(out)
    }

    fn resolved(&self, catalog: &OptionCatalog) -> Result<BTreeMap<String, Vec<Directive>>> {
        let mut rules: BTreeMap<String, Vec<Directive>> = BTreeMap::new();
        let base = catalog
            .base
            .iter()
            .find(|base| base.kind == self.kind)
            .context("nginx composer base missing")?;
        for effect in &base.effects {
            self.add_effect(&mut rules, effect, 0, None)?;
        }
        for option in &catalog.options {
            if !option.kinds.contains(&self.kind) {
                continue;
            }
            let Some(value) = self.selected_value(option)? else {
                continue;
            };
            for effect in &option.effects {
                self.add_effect(&mut rules, effect, option.priority, Some(&value))?;
            }
            if option.option_type == OptionType::Choice {
                let choice = option
                    .choices
                    .iter()
                    .find(|c| c.value == value)
                    .context("catalog choice missing")?;
                for effect in &choice.effects {
                    self.add_effect(&mut rules, effect, option.priority, Some(&value))?;
                }
            }
        }
        Ok(rules)
    }

    fn add_effect(
        &self,
        rules: &mut BTreeMap<String, Vec<Directive>>,
        effect: &Effect,
        priority: i32,
        parameter: Option<&str>,
    ) -> Result<()> {
        if !effect.kinds.is_empty() && !effect.kinds.contains(&self.kind) {
            return Ok(());
        }
        let slot = if effect.slot == "site" {
            if self.kind == NginxObjectKind::Subfolder {
                "location"
            } else {
                "server"
            }
        } else {
            &effect.slot
        };
        if self.kind == NginxObjectKind::Subfolder && slot != "location" {
            bail!("subfolder directives must belong to its location");
        }
        let value = self.expand(&effect.value, parameter)?;
        let key = match effect.directive.as_str() {
            "include" => format!("include:{value}"),
            "proxy_set_header" | "add_header" => format!(
                "{}:{}",
                effect.directive,
                value.split_whitespace().next().unwrap_or_default()
            ),
            _ => effect.directive.clone(),
        };
        let directives = rules.entry(slot.to_owned()).or_default();
        if let Some(existing) = directives.iter_mut().find(|rule| rule.key == key) {
            if priority > existing.priority {
                existing.value = value;
                existing.priority = priority;
            } else if priority == existing.priority && existing.value != value {
                bail!(
                    "conflicting nginx composer directives at {slot}: {}",
                    effect.directive
                );
            }
        } else {
            directives.push(Directive {
                key,
                directive: effect.directive.clone(),
                value,
                priority,
            });
        }
        Ok(())
    }

    pub fn render(&self, catalog: &OptionCatalog) -> Result<String> {
        self.validate(catalog)?;
        let mut groups = self.resolved(catalog)?;
        let mut output = String::from(
            "# router-hub-composed: 1\n# Source: adjacent .toml (do not edit this file)\n",
        );
        if self.kind == NginxObjectKind::Subfolder {
            line(&mut output, 0, &format!("location ^~ /{}/ {{", self.name));
            write_rules(&mut output, 1, groups.remove("location"));
            line(&mut output, 0, "}");
            return Ok(output);
        }

        let names =
            nginx::normalize_server_names(self.kind, &self.domain, &self.name, &self.server_names)?
                .join(" ");
        line(&mut output, 0, "server {");
        line(&mut output, 1, &format!("server_name {names};"));
        write_rules(&mut output, 1, groups.remove("server"));
        line(&mut output, 1, "location / {");
        write_rules(&mut output, 2, groups.remove("location"));
        line(&mut output, 1, "}");
        for (slot, rules) in groups {
            let path = slot
                .strip_prefix("location:")
                .context("unsupported composer slot")?;
            line(&mut output, 1, &format!("location {path} {{"));
            write_rules(&mut output, 2, Some(rules));
            line(&mut output, 1, "}");
        }
        line(&mut output, 0, "}");
        Ok(output)
    }
}

#[derive(Debug, Clone)]
struct Directive {
    key: String,
    directive: String,
    value: String,
    priority: i32,
}

fn line(output: &mut String, indent: usize, value: &str) {
    output.push_str(&"    ".repeat(indent));
    output.push_str(value);
    output.push('\n');
}

fn write_rules(output: &mut String, indent: usize, rules: Option<Vec<Directive>>) {
    for rule in rules.unwrap_or_default() {
        line(
            output,
            indent,
            &format!("{} {};", rule.directive, rule.value),
        );
    }
}

pub fn definition_path(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
) -> Result<PathBuf> {
    Ok(nginx::available_path(config, kind, domain, name)?.with_extension("toml"))
}

pub fn read(
    config: &AppConfig,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
) -> Result<Option<SiteDefinition>> {
    let path = definition_path(config, kind, domain, name)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() {
        bail!("site definition must be a regular file");
    }
    let value =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let spec: SiteDefinition = toml::from_str(&value)
        .with_context(|| format!("invalid site definition {}", path.display()))?;
    if spec.kind != kind || spec.domain != domain || spec.name != name {
        bail!(
            "site definition identity does not match its file path: {}",
            path.display()
        );
    }
    let catalog = load_catalog(config)?;
    let mut spec = spec;
    spec.remove_legacy_defaults(&catalog);
    spec.validate(&catalog)?;
    Ok(Some(spec))
}

pub fn write(config: &AppConfig, spec: &SiteDefinition) -> Result<()> {
    let catalog = load_catalog(config)?;
    let mut spec = spec.clone();
    spec.remove_legacy_defaults(&catalog);
    spec.validate(&catalog)?;
    let path = definition_path(config, spec.kind, &spec.domain, &spec.name)?;
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata.file_type().is_file() {
            bail!("refusing non-regular site definition");
        }
    }
    let content = toml::to_string_pretty(&spec)?;
    nginx::atomic_write(&path, content.as_bytes())
}

pub fn remove(config: &AppConfig, kind: NginxObjectKind, domain: &str, name: &str) -> Result<()> {
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
    let catalog = load_catalog(config)?;
    let mut specs = Vec::new();
    for object in nginx::list_objects(config, false)? {
        if let Some(spec) = read(config, object.kind, &object.domain, &object.name)? {
            let path = nginx::available_path(config, object.kind, &object.domain, &object.name)?;
            let old = fs::read_to_string(&path)?;
            let new = spec.render(&catalog)?;
            specs.push((spec, path, old, new));
        }
    }
    if specs.is_empty() {
        return Ok(0);
    }

    // All generated config and auxiliary maps form one transaction. A Git edit
    // can change server aliases or an upstream even if the proxy body is unchanged.
    let auxiliary_paths = [
        &config.nginx.domain_upstream_map_path,
        &config.nginx.subdomain_upstream_map_path,
        &config.nginx.subfolder_upstream_map_path,
        &config.nginx.http_forwarder_path,
    ];
    let backups = auxiliary_paths
        .iter()
        .map(|path| match fs::read(path) {
            Ok(content) => Ok(Some(content)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        })
        .collect::<std::io::Result<Vec<_>>>()?;

    let apply = (|| -> Result<()> {
        for (_, path, old, new) in &specs {
            if old != new {
                nginx::atomic_write(path, new.as_bytes())?;
            }
        }
        for (spec, _, old, new) in &specs {
            let old_names = nginx::normalize_server_names(
                spec.kind,
                &spec.domain,
                &spec.name,
                &nginx::extract_server_names(old),
            )?;
            let new_names = nginx::normalize_server_names(
                spec.kind,
                &spec.domain,
                &spec.name,
                &spec.server_names,
            )?;
            let old_key = if spec.kind == NginxObjectKind::Subfolder {
                Some(nginx::subfolder_map_key(old, &spec.name)?)
            } else {
                None
            };
            let new_key = if spec.kind == NginxObjectKind::Subfolder {
                Some(nginx::subfolder_map_key(new, &spec.name)?)
            } else {
                None
            };
            nginx::sync_site_upstream(
                config,
                spec.kind,
                &spec.domain,
                &spec.name,
                old_key.as_deref(),
                new_key.as_deref(),
                &old_names,
                &new_names,
                spec.upstream.as_deref(),
            )?;
        }
        nginx::reconcile_http_forwarder(config)?;
        let mut command = Command::new(&config.commands.nginx);
        if let Some(prefix) = &config.nginx.prefix_path {
            command.arg("-p").arg(prefix);
        }
        let output = command
            .arg("-t")
            .arg("-c")
            .arg(&config.nginx.config_path)
            .output()
            .context("unable to run nginx -t")?;
        if !output.status.success() {
            bail!(
                "nginx -t rejected composed sites: {}",
                String::from_utf8_lossy(&output.stderr)
            );
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
        bail!(
            "composed site apply failed: {error}; incomplete rollback: {}",
            failed_restore.join(", ")
        );
    }
    Ok(specs.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> OptionCatalog {
        OptionCatalog::parse(include_str!("../config/nginx/composer.toml")).unwrap()
    }

    fn sample(kind: NginxObjectKind) -> SiteDefinition {
        SiteDefinition::new(
            kind,
            "example.test",
            if kind == NginxObjectKind::Domain {
                "example.test"
            } else {
                "media"
            },
            &[],
            Some("http://127.0.0.1:8096"),
            SiteOptions::new(),
        )
    }

    #[test]
    fn catalog_has_all_three_types_and_is_versioned() {
        let cat = catalog();
        assert!(
            cat.options
                .iter()
                .any(|o| o.option_type == OptionType::Optional)
        );
        assert!(
            cat.options
                .iter()
                .any(|o| o.option_type == OptionType::Choice)
        );
        assert!(
            cat.options
                .iter()
                .any(|o| o.option_type == OptionType::Parameterized)
        );
        let mut invalid = cat.clone();
        invalid.schema_version = 2;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn combined_features_resolve_without_duplicate_directives() {
        let mut site = sample(NginxObjectKind::Subdomain);
        for id in ["streaming", "large_upload", "long_lived", "websocket"] {
            site.options.insert(id.into(), serde_json::json!(true));
        }
        site.options
            .insert("access".into(), serde_json::json!("lan"));
        site.options
            .insert("read_timeout".into(), serde_json::json!("1200s"));
        let rendered = site.render(&catalog()).unwrap();
        for directive in [
            "proxy_read_timeout",
            "proxy_send_timeout",
            "proxy_buffering",
            "client_max_body_size",
        ] {
            assert_eq!(rendered.matches(directive).count(), 1, "{directive}");
        }
        assert!(rendered.contains("proxy_read_timeout 1200s;"));
        assert!(rendered.contains("proxy_send_timeout 3600s;"));
        assert!(rendered.contains("include snippets/restrict.conf;"));
    }

    #[test]
    fn all_routing_choices_come_from_catalog() {
        let cat = catalog();
        let mut domain = sample(NginxObjectKind::Domain);
        let fallback = domain.render(&cat).unwrap();
        assert!(fallback.contains("return 404;"));
        domain
            .options
            .insert("root".into(), serde_json::json!("proxy_and_subfolders"));
        let rendered = domain.render(&cat).unwrap();
        assert!(rendered.contains("proxy_pass $domain_upstream;"));
        assert!(rendered.contains("subfolders-enabled/*.conf"));
        let mut folder = sample(NginxObjectKind::Subfolder);
        folder
            .options
            .insert("subfolder".into(), serde_json::json!("pwa"));
        let mounted = folder.render(&cat).unwrap();
        assert!(mounted.contains("include snippets/proxy-pwa.conf;"));
        assert!(mounted.contains("location ^~ /media/"));
    }

    #[test]
    fn new_catalog_option_needs_no_rust_changes() {
        let mut cat = catalog();
        cat.options.push(OptionDefinition {
            id: "my_header".into(),
            option_type: OptionType::Optional,
            label: "My header".into(),
            description: String::new(),
            kinds: vec![NginxObjectKind::Subdomain],
            default: None,
            pattern: None,
            priority: 30,
            requires: vec![],
            requirements: vec![],
            effects: vec![Effect {
                slot: "location".into(),
                directive: "proxy_set_header".into(),
                value: "X-Test enabled".into(),
                kinds: vec![],
            }],
            choices: vec![],
        });
        cat.validate().unwrap();
        let mut site = sample(NginxObjectKind::Subdomain);
        site.options
            .insert("my_header".into(), serde_json::json!(true));
        assert!(
            site.render(&cat)
                .unwrap()
                .contains("proxy_set_header X-Test enabled;")
        );
    }

    #[test]
    fn invalid_options_parameters_and_dependencies_fail_closed() {
        let cat = catalog();
        let mut site = sample(NginxObjectKind::Subdomain);
        site.options
            .insert("unknown".into(), serde_json::json!(true));
        assert!(site.render(&cat).is_err());
        site.options.remove("unknown");
        site.options
            .insert("body_size".into(), serde_json::json!("5G; deny all"));
        assert!(site.render(&cat).is_err());
        site.options.remove("body_size");
        site.options.insert("pwa".into(), serde_json::json!(true));
        assert!(site.render(&cat).is_err());
        site.options.clear();
        site.options
            .insert("sessions_lan_only".into(), serde_json::json!(true));
        assert!(site.render(&cat).is_err());
        let mut folder = sample(NginxObjectKind::Subfolder);
        folder
            .options
            .insert("large_upload".into(), serde_json::json!(true));
        assert!(folder.render(&cat).is_err());
    }

    #[test]
    fn site_definition_round_trips() {
        let cat = catalog();
        let mut site = sample(NginxObjectKind::Subdomain);
        site.options
            .insert("access".into(), serde_json::json!("lan"));
        site.options
            .insert("large_upload".into(), serde_json::json!(true));
        let saved = toml::to_string_pretty(&site).unwrap();
        let parsed: SiteDefinition = toml::from_str(&saved).unwrap();
        assert_eq!(site.render(&cat).unwrap(), parsed.render(&cat).unwrap());
    }
}
