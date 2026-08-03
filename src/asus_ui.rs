use std::fs;

use anyhow::{Context, Result, bail};

use crate::config::AppConfig;

const UI: &str = include_str!("../web/index.html");
const ASP_TEMPLATE: &str = include_str!("../config/asus-wrt.asp.template");

pub fn render_ui(config: &AppConfig) -> String {
    render_ui_with_token(config, None)
}

fn render_ui_with_token(config: &AppConfig, token: Option<&str>) -> String {
    let api_base = if config.asus_ui.api_base_url.trim().is_empty() {
        format!("{{PROTOCOL}}//{{HOST}}:{}", config.server.port)
    } else {
        config.asus_ui.api_base_url.clone()
    };
    let version_json =
        serde_json::to_string(env!("CARGO_PKG_VERSION")).expect("version is JSON safe");
    let api_base_json = serde_json::to_string(&api_base).expect("API base is JSON safe");
    let token_json = serde_json::to_string(&token).expect("token is JSON safe");
    UI.replace("__ROUTER_HUB_VERSION__", env!("CARGO_PKG_VERSION"))
        .replace("__ROUTER_HUB_VERSION_JSON__", &version_json)
        .replace("__ROUTER_HUB_API_BASE_JSON__", &api_base_json)
        .replace("__ROUTER_HUB_TOKEN_JSON__", &token_json)
}

pub fn render_asus_ui(config: &AppConfig) -> String {
    let rendered_ui = render_ui_with_token(config, Some(&config.server.auth_token));
    let styles = fragment_between(&rendered_ui, "<style>", "</style>");
    let contents = fragment_between(&rendered_ui, "<body class=\"rh-page\">", "</body>");

    ASP_TEMPLATE
        .replace(
            "<!-- router-hub-head -->",
            &format!("<style>{styles}</style>"),
        )
        .replace("<!-- contents -->", contents)
}

fn fragment_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source
        .find(start)
        .unwrap_or_else(|| panic!("embedded UI is missing {start}"))
        + start.len();
    let end = source[start..]
        .find(end)
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("embedded UI is missing {end}"));
    &source[start..end]
}

pub fn render_ui_file(config: &AppConfig) -> Result<std::path::PathBuf> {
    if let Some(parent) = config.asus_ui.rendered_page.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&config.asus_ui.rendered_page, render_asus_ui(config)).with_context(|| {
        format!(
            "failed to render {}",
            config.asus_ui.rendered_page.display()
        )
    })?;
    Ok(config.asus_ui.rendered_page.clone())
}

pub fn install_menu_entry(config: &AppConfig) -> Result<()> {
    let page = config
        .asus_ui
        .rendered_page
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("asus_ui.rendered_page must end in a UTF-8 filename"))?;
    if !page.ends_with(".asp") || page.chars().any(|c| matches!(c, '"' | '\n' | '\r')) {
        bail!("asus_ui.rendered_page must end in an .asp filename without quotes or newlines");
    }
    let menu_index = config.asus_ui.menu_index.trim();
    if !menu_index.starts_with("menu_")
        || menu_index == "menu_RouterHub"
        || menu_index == "menu_Router_Hub"
        || !menu_index
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        bail!("asus_ui.menu_index must name an existing menu_* index");
    }

    let mut menu_tree = fs::read_to_string(&config.asus_ui.menu_tree).with_context(|| {
        format!(
            "failed to read ASUS menu tree {}",
            config.asus_ui.menu_tree.display()
        )
    })?;
    for index in ["menu_RouterHub", "menu_Router_Hub"] {
        let marker = format!("{{\nmenuName: \"Router Hub\",\nindex: \"{index}\",");
        if let Some(start) = menu_tree.find(&marker) {
            if let Some(end) = menu_tree[start..].find("\n},\n") {
                menu_tree.replace_range(start..start + end + 4, "");
            }
        }
    }
    let settings_child = format!("{{url: \"{page}\", tabName: \"Router Hub\"}},\n");
    menu_tree = menu_tree.replacen(&settings_child, "", 1);

    let index_marker = format!("index: \"{menu_index}\"");
    let index = menu_tree.find(&index_marker).ok_or_else(|| {
        anyhow::anyhow!(
            "ASUS menu tree {} has no {} entry",
            config.asus_ui.menu_tree.display(),
            menu_index
        )
    })?;
    let start = menu_tree[..index]
        .rfind("{\n")
        .ok_or_else(|| anyhow::anyhow!("malformed {} menu", menu_index))?;
    let end = menu_tree[index..]
        .find("\n},\n")
        .map(|offset| index + offset + 4)
        .ok_or_else(|| anyhow::anyhow!("malformed {} menu", menu_index))?;
    let entry = format!(
        "{{\nmenuName: \"Router Hub\",\nindex: \"{menu_index}\",\ntab: [\n{{url: \"{page}\", tabName: \"__INHERIT__\"}},\n{{url: \"NULL\", tabName: \"__INHERIT__\"}}\n]\n}},\n"
    );
    menu_tree.replace_range(start..end, &entry);
    fs::write(&config.asus_ui.menu_tree, menu_tree).with_context(|| {
        format!(
            "failed to update ASUS menu tree {}",
            config.asus_ui.menu_tree.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_ui_placeholders() {
        let mut config = AppConfig::default();
        config.server.auth_token = "my-secret-token".into();

        let standalone = render_ui(&config);
        assert!(!standalone.contains("__ROUTER_HUB_VERSION__"));
        assert!(!standalone.contains("__ROUTER_HUB_VERSION_JSON__"));
        assert!(!standalone.contains("__ROUTER_HUB_API_BASE_JSON__"));
        assert!(!standalone.contains("__ROUTER_HUB_TOKEN_JSON__"));
        assert!(!standalone.contains("my-secret-token"));
        assert_eq!(standalone.matches("<html").count(), 1);
        assert_eq!(standalone.matches("<body").count(), 1);
        assert!(standalone.contains("rel=\"icon\" href=\"/favicon.png\""));
        assert!(standalone.contains("<details class=\"card nginx-root\">"));
        assert_eq!(
            standalone
                .matches("class=\"card nginx-card nginx-accordion\"")
                .count(),
            3
        );
        assert!(!standalone.contains("nginx-card nginx-accordion\" open"));
        assert!(standalone.contains("data-custom-config"));
        assert!(!standalone.contains(">Start nginx<"));
        assert!(!standalone.contains(">Stop nginx<"));

        let rendered = render_asus_ui(&config);
        assert!(rendered.contains("my-secret-token"));
        assert!(!rendered.contains("<!-- contents -->"));
        assert!(!rendered.contains("<!-- router-hub-head -->"));
        assert!(rendered.contains("rel=\"icon\" href=\"images/favicon.png\""));
        assert!(rendered.contains("<div id=\"TopBanner\"></div>"));
        assert_eq!(rendered.matches("<html").count(), 1);
        assert_eq!(rendered.matches("<body").count(), 1);
        assert!(
            rendered.find("id=\"tabMenu\"").unwrap() < rendered.find("id=\"FormTitle\"").unwrap()
        );
        assert!(
            rendered.find("class=\"splitLine\"").unwrap()
                < rendered.find("class=\"rh-tab-pane\"").unwrap()
        );
        assert!(rendered.contains("new MutationObserver"));
        assert!(rendered.contains("rhInstallAsusTabs(asusTabs)"));
    }

    #[test]
    fn test_menu_entry_replaces_configured_menu_index() {
        let temp = tempfile::tempdir().unwrap();
        let menu_tree = temp.path().join("menuTree.js");
        fs::write(
            &menu_tree,
            "define(function(){\nlist: [\n{\nindex: \"menu_WAN\",\ntab: [\n{url: \"Advanced_WAN_Content.asp\", tabName: \"WAN\"},\n{url: \"NULL\", tabName: \"__INHERIT__\"}\n]\n},\n{\nmenuName: \"Alexa & IFTTT\",\nindex: \"menu_Alexa_IFTTT\",\ntab: [\n{url: \"Advanced_Smart_Home_Alexa.asp\", tabName: \"__INHERIT__\"},\n{url: \"NULL\", tabName: \"__INHERIT__\"}\n]\n},\n{\nindex: \"menu_Setting\",\ntab: [\n{url: \"user20.asp\", tabName: \"Router Hub\"},\n{url: \"Advanced_System_Content.asp\", tabName: \"System\"}\n]\n}\n]\n});\n",
        )
        .unwrap();
        let mut config = AppConfig::default();
        config.asus_ui.rendered_page = "/tmp/var/wwwext/user20.asp".into();
        config.asus_ui.menu_tree = menu_tree.clone();
        config.asus_ui.menu_index = "menu_Alexa_IFTTT".into();

        install_menu_entry(&config).unwrap();
        install_menu_entry(&config).unwrap();

        let updated = fs::read_to_string(menu_tree).unwrap();
        assert!(updated.contains(
            "menuName: \"Router Hub\",\nindex: \"menu_Alexa_IFTTT\",\ntab: [\n{url: \"user20.asp\", tabName: \"__INHERIT__\"},\n{url: \"NULL\", tabName: \"__INHERIT__\"}"
        ));
        assert!(!updated.contains("tabName: \"Router Hub\""));
        assert_eq!(updated.matches("index: \"menu_Alexa_IFTTT\"").count(), 1);
    }
}
