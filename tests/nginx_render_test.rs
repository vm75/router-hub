//! Validate the Rust renderer's complete output with an actual, isolated nginx.
use router_hub::{
    command::CommandRunner,
    config::AppConfig,
    models::NginxObjectKind,
    nginx,
    nginx_render::{self, GlobalSettings},
};
use serde_json::json;
use std::{fs, path::PathBuf, time::Duration};

fn program(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
}

#[tokio::test]
async fn native_jinja_output_passes_real_nginx_validation() {
    let (Some(nginx_bin), Some(openssl)) = (program("nginx"), program("openssl")) else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let mut config = AppConfig::default();
    config.nginx.root_dir = root.into();
    config.nginx.config_path = root.join("nginx.conf");
    config.nginx.pid_path = root.join("var/run/nginx.pid");
    config.nginx.log_dir = root.join("var/log/nginx");
    config.nginx.domains_available_dir = root.join("domains-available");
    config.nginx.domains_enabled_dir = root.join("domains-enabled");
    config.nginx.domain_upstream_map_path = root.join("conf.d/02_domain_upstream_map.conf");
    config.nginx.subdomain_upstream_map_path = root.join("conf.d/03_subdomain_upstream_map.conf");
    config.nginx.subfolder_upstream_map_path = root.join("conf.d/04_subfolder_upstream_map.conf");
    config.nginx.http_forwarder_path = root.join("conf.d/05-http-to-https.conf");
    config.certificates.certs_dir = root.join("certificates");
    for dir in [
        "var/log/nginx",
        "var/run",
        "certs/default",
        "certs/example_test",
        "module.d",
    ] {
        fs::create_dir_all(root.join(dir)).unwrap();
    }
    let runner = CommandRunner::new(false);
    let result = runner
        .run(
            &openssl,
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=example.test",
                "-keyout",
                root.join("certs/default/privkey.pem").to_str().unwrap(),
                "-out",
                root.join("certs/default/fullchain.pem").to_str().unwrap(),
            ],
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert!(result.success, "{}", result.stderr);
    for file in ["privkey.pem", "fullchain.pem"] {
        fs::copy(
            root.join("certs/default").join(file),
            root.join("certs/example_test").join(file),
        )
        .unwrap();
    }
    let bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/nginx");
    for file in ["mime.types", "dhparams.pem"] {
        fs::copy(bundle.join(file), root.join(file)).unwrap();
    }
    let global = GlobalSettings {
        shared: json!({"var_dir":root.join("var"),"http_port":18080,"https_port":18443,"nginx_daemon":false,"nginx_user":"","temp_dir":root.join("tmp")})
            .as_object()
            .unwrap()
            .clone(),
        allowed_ips: vec!["127.0.0.1".into()],
        ..Default::default()
    };
    nginx_render::FileTransaction::apply(
        &config,
        nginx_render::shared_files(&config, &global).unwrap(),
    )
    .unwrap()
    .commit();
    let main = fs::read_to_string(&config.nginx.config_path).unwrap();
    assert!(main.contains("daemon off;"));
    assert!(main.contains(&format!(
        "client_body_temp_path {}/tmp/client-body;",
        root.display()
    )));
    let domain = nginx_render::render_site(
        &global,
        json!({"disable_root":true,"enable_lanonly":false})
            .as_object()
            .unwrap(),
        NginxObjectKind::Domain,
        "example.test",
        "example.test",
        &[],
    )
    .unwrap();
    nginx::write_object(
        &config,
        NginxObjectKind::Domain,
        "example.test",
        "example.test",
        &domain,
        true,
    )
    .unwrap();
    nginx::set_enabled(
        &config,
        NginxObjectKind::Domain,
        "example.test",
        "example.test",
        true,
    )
    .unwrap();
    for kind in [
        NginxObjectKind::Domain,
        NginxObjectKind::Subdomain,
        NginxObjectKind::Subfolder,
    ] {
        let name = if kind == NginxObjectKind::Domain {
            "example.test"
        } else {
            "app"
        };
        for bits in 0..64 {
            let mut settings = json!({"disable_root":false}).as_object().unwrap().clone();
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
            if bits == 63 {
                settings.insert("routes".into(), json!([{"path":"/admin","enable_lanonly":true,"spa_fallback":"","children":[{"path":"/admin/quiet","access_log":false}]},{"path":"/events","proxy_transport":"sse"}]));
                settings.insert("spa_fallback".into(), json!("/index.html"));
            }
            let content =
                nginx_render::render_site(&global, &settings, kind, "example.test", name, &[])
                    .unwrap();
            nginx::write_object(&config, kind, "example.test", name, &content, false).unwrap();
            nginx::set_enabled(&config, kind, "example.test", name, true).unwrap();
            let result = runner
                .run(
                    &nginx_bin,
                    [
                        "-t",
                        "-p",
                        root.to_str().unwrap(),
                        "-c",
                        config.nginx.config_path.to_str().unwrap(),
                    ],
                    Duration::from_secs(5),
                )
                .await
                .unwrap();
            assert!(result.success, "{kind:?}, bits={bits}: {}", result.stderr);
        }
        if kind != NginxObjectKind::Domain {
            nginx::set_enabled(&config, kind, "example.test", name, false).unwrap();
        }
    }
    if let Some(fixture) = std::env::var_os("ROUTER_HUB_NGINX_FIXTURE") {
        fs::create_dir_all(root.join("settings")).unwrap();
        fs::copy(
            PathBuf::from(fixture).join("settings/sites.toml"),
            root.join("settings/sites.toml"),
        )
        .unwrap();
        let sites = router_hub::nginx_sites::load(&config).unwrap();
        let mut entries: Vec<_> = sites.sites.iter().collect();
        entries.sort_by_key(|(_, site)| site.kind != NginxObjectKind::Domain);
        for (key, site) in entries {
            let name = site.object_name(key).unwrap();
            let names = site
                .server_name
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();
            let content = nginx_render::render_site(
                &global,
                &site.settings,
                site.kind,
                &site.domain,
                &name,
                &names,
            )
            .unwrap();
            nginx::write_object(&config, site.kind, &site.domain, &name, &content, false).unwrap();
            let map_key = (site.kind == NginxObjectKind::Subfolder)
                .then(|| nginx::subfolder_map_key(&name).unwrap());
            nginx::sync_site_upstream(
                &config,
                site.kind,
                &site.domain,
                &name,
                None,
                map_key.as_deref(),
                &[],
                &names,
                site.upstream.as_deref(),
            )
            .unwrap();
            nginx::set_enabled(&config, site.kind, &site.domain, &name, site.enabled).unwrap();
        }
        let result = runner
            .run(
                &nginx_bin,
                [
                    "-t",
                    "-p",
                    root.to_str().unwrap(),
                    "-c",
                    config.nginx.config_path.to_str().unwrap(),
                ],
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert!(result.success, "fixture: {}", result.stderr);
        eprintln!(
            "Validated {} managed sites from the Linux fixture with real nginx",
            sites.sites.len()
        );
    }
}

#[tokio::test]
async fn bootstrap_is_empty_current_format_and_preserves_existing_configuration() {
    let (Some(nginx_bin), Some(openssl)) = (program("nginx"), program("openssl")) else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let mut config = AppConfig::default();
    config.nginx.root_dir = root.into();
    config.nginx.config_path = root.join("nginx.conf");
    config.nginx.pid_path = root.join("var/run/nginx.pid");
    config.nginx.log_dir = root.join("var/log/nginx");
    config.nginx.domains_available_dir = root.join("domains-available");
    config.nginx.domains_enabled_dir = root.join("domains-enabled");
    config.nginx.domain_upstream_map_path = root.join("conf.d/02_domain_upstream_map.conf");
    config.nginx.subdomain_upstream_map_path = root.join("conf.d/03_subdomain_upstream_map.conf");
    config.nginx.subfolder_upstream_map_path = root.join("conf.d/04_subfolder_upstream_map.conf");
    config.nginx.http_forwarder_path = root.join("conf.d/05-http-to-https.conf");
    config.certificates.certs_dir = root.join("certificates");
    config.commands.openssl = openssl;
    fs::create_dir_all(root.join("settings")).unwrap();
    fs::write(
        nginx_render::global_path(&config),
        "[global]\nhttp_port = 18081\nhttps_port = 18444\n",
    )
    .unwrap();
    assert!(nginx_render::bootstrap(&config).await.unwrap());
    assert!(nginx::list_objects(&config, false).unwrap().is_empty());
    let main = fs::read_to_string(&config.nginx.config_path).unwrap();
    assert!(main.contains("daemon on;"));
    assert!(!main.contains("{{"));
    assert!(root.join("certs/default/fullchain.pem").is_file());
    assert!(root.join("mime.types").is_file());
    assert!(!root.join("templates").exists());
    let paths = ["client_body", "proxy", "fastcgi", "uwsgi", "scgi"]
        .iter()
        .map(|name| format!("{name}_temp_path {}/{}-temp;", root.display(), name))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        &config.nginx.config_path,
        main.replace("http {", &format!("http {{\n{paths}")),
    )
    .unwrap();
    let result = CommandRunner::new(false)
        .run(
            &nginx_bin,
            [
                "-t",
                "-p",
                root.to_str().unwrap(),
                "-c",
                config.nginx.config_path.to_str().unwrap(),
            ],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(result.success, "{}", result.stderr);
    fs::write(&config.nginx.config_path, "administrator configuration").unwrap();
    fs::write(root.join("snippets/restrict.conf"), "administrator rules").unwrap();
    assert!(!nginx_render::bootstrap(&config).await.unwrap());
    assert_eq!(
        fs::read_to_string(&config.nginx.config_path).unwrap(),
        "administrator configuration"
    );
    assert_eq!(
        fs::read_to_string(root.join("snippets/restrict.conf")).unwrap(),
        "administrator rules"
    );
}

#[test]
fn synthetic_current_policies_validate_and_render_natively() {
    let examples: toml::Value =
        toml::from_str(include_str!("../config/nginx/examples/sites.toml")).unwrap();
    for (name, site) in examples["sites"].as_table().unwrap() {
        let mut site = serde_json::to_value(site)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        let kind = nginx::parse_kind(site.remove("kind").unwrap().as_str().unwrap()).unwrap();
        site.remove("domain");
        site.remove("upstream");
        let names = site
            .remove("server_name")
            .map(|v| {
                v.as_str()
                    .unwrap()
                    .split_whitespace()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let folder = site
            .remove("subfolder")
            .map(|v| v.as_str().unwrap().to_string())
            .unwrap_or_else(|| "app".into());
        nginx_render::render_site(
            &GlobalSettings::default(),
            &site,
            kind,
            "example.test",
            &folder,
            &names,
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}
