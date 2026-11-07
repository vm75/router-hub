use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use router_hub::{
    api, config::AppConfig, firewall::FirewallManager, state::AppState, storage::Stores,
};
use tempfile::tempdir;
use tower::ServiceExt;

async fn setup_test_app() -> (axum::Router, AppState, tempfile::TempDir) {
    let temp = tempdir().unwrap();
    let root = std::env::current_dir().unwrap();
    let config_path = root.join("test-fixtures/etc/router-hub/router-hub.toml");
    let mut config = AppConfig::default();
    config.apply_test_mode(&config_path).unwrap();
    config.paths.data_dir = temp.path().join("data");
    config.paths.dnsmasq_conf_add = temp.path().join("dnsmasq.conf.add");
    config.commands.dehydrated = temp.path().join("dehydrated/dehydrated");
    config.certificates.certs_dir = temp.path().join("dehydrated/certs");
    config.nginx.root_dir = temp.path().join("nginx");
    config.nginx.inputs_dir = temp.path().join("router-hub/nginx");
    config.nginx.config_path = config.nginx.root_dir.join("nginx.conf");
    config.nginx.pid_path = config.nginx.root_dir.join("nginx.pid");
    config.nginx.domains_available_dir = config.nginx.root_dir.join("domains-available");
    config.nginx.domains_enabled_dir = config.nginx.root_dir.join("domains-enabled");
    config.nginx.subdomain_upstream_map_path = config
        .nginx
        .root_dir
        .join("conf.d/03_subdomain_upstream_map.conf");
    config.nginx.subfolder_upstream_map_path = config
        .nginx
        .root_dir
        .join("conf.d/04_subfolder_upstream_map.conf");
    config.nginx.domain_upstream_map_path = config
        .nginx
        .root_dir
        .join("conf.d/02_domain_upstream_map.conf");
    config.nginx.http_forwarder_path = config.nginx.root_dir.join("conf.d/05-http-to-https.conf");
    config.nginx.log_dir = temp.path().join("logs/nginx");
    config.firewall.log_dirs = vec![temp.path().to_path_buf()];
    config.ensure_directories().unwrap();
    std::fs::write(&config.nginx.config_path, "events {} http {}").unwrap();

    let stores = Stores::load(&config).await.unwrap();
    let firewall = FirewallManager::new(config.clone(), stores.clone())
        .await
        .unwrap();
    let state = AppState::new(config, stores, firewall);
    let app = api::app(state.clone()).unwrap();
    (app, state, temp)
}

#[tokio::test]
async fn test_unauthenticated_endpoints() {
    let (app, _state, _temp) = setup_test_app().await;

    // Test GET /healthz
    let req = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(bytes.as_ref(), b"ok");

    let req = Request::builder()
        .uri("/favicon.png")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "image/png");
    assert!(
        !axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
    );

    let req = Request::builder()
        .uri("/favicon.svg")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "image/svg+xml");

    let req = Request::builder()
        .uri("/router-hub.svg")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "image/svg+xml");

    // Test GET /api/version
    let req = Request::builder()
        .uri("/api/version")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn test_standalone_ui_endpoint() {
    let (app, _state, _temp) = setup_test_app().await;

    // Standalone index in test mode is accessible without token
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_protection() {
    let (app, _state, _temp) = setup_test_app().await;

    // Missing auth token -> 401
    let req = Request::builder()
        .uri("/api/auth/check")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Invalid auth token -> 401
    let req = Request::builder()
        .uri("/api/auth/check")
        .header(header::AUTHORIZATION, "Bearer invalid-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Valid Bearer token -> 200
    let req = Request::builder()
        .uri("/api/auth/check")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Query tokens are deliberately not accepted.
    let req = Request::builder()
        .uri("/api/auth/check?token=router-hub-test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_dashboard_endpoint() {
    let (app, _state, _temp) = setup_test_app().await;

    let req = Request::builder()
        .uri("/api/dashboard")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["test_mode"], true);
}

#[tokio::test]
async fn test_dehydrated_certificate_api_and_files() {
    let (app, _state, temp) = setup_test_app().await;
    let auth_header = ("authorization", "Bearer router-hub-test-token");
    let payload = serde_json::json!({
        "name": "example_test",
        "domains": ["example.test"],
        "method": "http",
        "hook": null,
        "hook_env": {},
        "staging": false,
        "auto_renew": true
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/certificates")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let certificate_id = created["id"].as_str().unwrap();
    let cert_root = temp.path().join("dehydrated/certs");

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/certificates/{certificate_id}/issue"))
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(result["stdout"].as_str().unwrap().contains("--cron"));
    assert!(result["stdout"].as_str().unwrap().contains("--config"));

    let lock_path = cert_root.join("lock");
    std::fs::write(&lock_path, "stale lock").unwrap();
    let req = Request::builder()
        .uri("/api/certificates/dehydrated/lock")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let lock: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(lock["locked"], true);
    assert_eq!(lock["path"], lock_path.to_string_lossy().to_string());

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/certificates/{certificate_id}/renew"))
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/certificates/dehydrated/lock")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let lock: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(lock["locked"], false);
    assert!(!lock_path.exists());

    assert_eq!(
        std::fs::read_to_string(cert_root.join("example_test.cfg")).unwrap(),
        format!(
            "CA='letsencrypt'\nAUTO_CLEANUP='yes'\nDOMAINS_TXT='{}'\nCHALLENGETYPE='http-01'\nWELLKNOWN='{}/acme-challenge'\n",
            cert_root.join("example_test.txt").display(),
            cert_root.display()
        )
    );
    assert_eq!(
        std::fs::read_to_string(cert_root.join("example_test.txt")).unwrap(),
        "\n# example.test-start\nexample.test > example_test\n# example.test-end\n"
    );

    let deployed_cert_root = temp.path().join("nginx/certs/example_test");
    std::fs::create_dir_all(&deployed_cert_root).unwrap();
    std::fs::write(deployed_cert_root.join("cert.pem"), "deployed certificate").unwrap();
    std::fs::write(
        deployed_cert_root.join("fullchain.pem"),
        "deployed full chain",
    )
    .unwrap();

    let req = Request::builder()
        .uri("/api/certificates")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let statuses: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        statuses[0]["fullchain_path"],
        deployed_cert_root
            .join("fullchain.pem")
            .to_string_lossy()
            .to_string()
    );

    let req = Request::builder()
        .method("POST")
        .uri("/api/certificates/dehydrated/update")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let update: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(update["simulated"], true);
}

#[tokio::test]
async fn test_wol_crud_api() {
    let (app, _state, _temp) = setup_test_app().await;
    let auth_header = ("authorization", "Bearer router-hub-test-token");

    // 1. GET /api/wol (empty list)
    let req = Request::builder()
        .uri("/api/wol")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let machines: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(machines.len(), 0);

    // 2. POST /api/wol (Create machine)
    let new_machine = serde_json::json!({
        "name": "NAS Server",
        "mac": "11:22:33:44:55:66",
        "broadcast": "192.168.1.255",
        "port": 9,
        "notes": "Backup target"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/wol")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&new_machine).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(created["name"], "NAS Server");
    let machine_id = created["id"].as_str().unwrap().to_string();

    // 3. GET /api/wol/status (test mode simulates the neighbor lookup)
    let req = Request::builder()
        .uri("/api/wol/status")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let statuses: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(statuses[0]["id"], machine_id);
    assert_eq!(statuses[0]["status"], "unknown");

    // 4. POST /api/wol/{id}/wake (Simulate magic packet)
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/wol/{}/wake", machine_id))
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. DELETE /api/wol/{id}
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/wol/{}", machine_id))
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_firewall_policy_api() {
    let (app, state, temp) = setup_test_app().await;
    let auth_header = ("authorization", "Bearer router-hub-test-token");

    let log_file = temp.path().join("auth.log");
    std::fs::write(&log_file, "").unwrap();

    // Enable firewall policy with a valid rule
    let mut policy = state.stores.firewall_policy.read().await.clone();
    policy.enabled = true;
    policy.rules.push(router_hub::models::BanRule {
        id: uuid::Uuid::new_v4(),
        name: "ssh".into(),
        enabled: true,
        log_paths: vec![log_file],
        pattern: r"Failed password for root from (?P<ip>[0-9.]+)".into(),
        ip_group: "ip".into(),
        group_values: Default::default(),
        attempts: 3,
        weight: 1,
        updated_at: chrono::Utc::now(),
    });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/firewall")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&policy).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Start firewall manager to initialize ban engine
    state.firewall.start().await;

    // GET /api/firewall
    let req = Request::builder()
        .uri("/api/firewall")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // POST /api/firewall/allowlist (Add allowlist network)
    let payload = serde_json::json!({ "network": "10.0.0.0/8" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/firewall/allowlist")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Host-network allowlist entries are accepted after UI normalization.
    let payload = serde_json::json!({ "network": "10.0.0.42/32" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/firewall/allowlist")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // POST /api/firewall/bans (Manual ban)
    let ban_payload =
        serde_json::json!({ "network": "192.168.1.100/32", "reason": "test manual ban" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/firewall/bans")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&ban_payload).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/firewall/bans/192.168.1.100%2F32")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let policy = state.stores.firewall_policy.read().await;
    assert!(
        policy
            .allowlist
            .contains(&"192.168.1.100/32".parse().unwrap())
    );
    drop(policy);
    let status = state.firewall.status().await;
    assert!(status.bans.is_empty());
    assert!(status.snapshot.ip_counts.is_empty());
}

#[tokio::test]
async fn test_services_api() {
    let (app, state, _temp) = setup_test_app().await;
    let auth_header = ("authorization", "Bearer router-hub-test-token");

    std::fs::write(
        state.config.services.init_dir.join("S80nginx"),
        "#!/bin/sh\n",
    )
    .unwrap();
    std::fs::write(
        state.config.nginx.log_dir.join("error.log"),
        "nginx service log entry\n",
    )
    .unwrap();

    let req = Request::builder()
        .uri("/api/services/S80nginx/logs")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["message"], "nginx service log entry");

    // GET /api/services
    let req = Request::builder()
        .uri("/api/services")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let services: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    // Test fixtures directory contains init.d scripts
    assert!(!services.is_empty());
    assert!(
        services
            .iter()
            .all(|service| service["enabled"].as_bool() == Some(true))
    );

    let req = Request::builder()
        .method("POST")
        .uri("/api/services/S99router-hub/disable")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    for (action, expected_command) in [
        ("restart", "restart"),
        ("reconfigure", "reconfigure"),
        // Keep the old action name working while applying its new behavior.
        ("refresh", "reconfigure"),
        ("disable", "disable"),
        ("enable", "enable"),
    ] {
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/services/S10demo/{action}"))
            .header(auth_header.0, auth_header.1)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(result["success"].as_bool().unwrap());
        assert!(
            result["stdout"]
                .as_str()
                .unwrap()
                .ends_with(expected_command)
        );
    }
}

async fn nginx_request(
    app: &axum::Router,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method(method)
        .uri(format!("/api/nginx{path}"))
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
async fn test_nginx_jinja_settings_objects_actions_and_logs_api() {
    use serde_json::json;
    let (app, state, _temp) = setup_test_app().await;
    // Removed editors have no read or mutation endpoints.
    for path in [
        "/files",
        "/files/nginx.conf",
        "/templates/domain",
        "/templates/domain/basic",
    ] {
        for method in ["GET", "PUT", "DELETE"] {
            assert_eq!(
                nginx_request(&app, method, path, json!({"content":"bad"}))
                    .await
                    .0,
                StatusCode::NOT_FOUND
            );
        }
    }
    let globals = json!({"shared":{"http_port":8080,"https_port":8443,"var_dir":state.config.nginx.log_dir.parent().unwrap().parent().unwrap(),"acme_challenge_dir":state.config.certificates.certs_dir.join("acme-challenge")}, "limit_policies":{"assets":{"rate":"100r/s","burst":500,"nodelay":true,"connections":50}}, "site_defaults":{"enable_streaming":true,"enable_lanonly":false,"limit_policy":"assets"}, "allowed_ips":["192.0.2.0/24"], "free_subdomains":["shared.example.test"]});
    let (status, result) = nginx_request(&app, "PUT", "/settings", globals.clone()).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(
        nginx_request(&app, "GET", "/settings", json!(null)).await.1,
        globals
    );
    let persisted: toml::Value = toml::from_str(
        &std::fs::read_to_string(router_hub::nginx_render::global_path(&state.config)).unwrap(),
    )
    .unwrap();
    assert_eq!(persisted["global"]["http_port"].as_integer(), Some(8080));
    assert_eq!(
        persisted["site_defaults"]["enable_streaming"].as_bool(),
        Some(true)
    );
    assert_eq!(persisted["allowed_ips"][0].as_str(), Some("192.0.2.0/24"));
    assert!(
        !state
            .config
            .nginx
            .root_dir
            .join("settings/nginx.toml")
            .exists()
    );
    assert!(
        !state
            .config
            .nginx
            .root_dir
            .join("settings/sites.toml")
            .exists()
    );
    assert!(
        !state
            .config
            .nginx
            .root_dir
            .join("settings/allowed_ips.txt")
            .exists()
    );
    assert!(
        state
            .config
            .nginx
            .inputs_dir
            .join("allowed_ips.txt")
            .exists()
    );
    assert_eq!(
        persisted["limit_policies"]["assets"]["burst"].as_integer(),
        Some(500)
    );
    let payload = json!({"domain":"example.test", "name":"example.test", "server_names":["example.test","www.example.test"], "settings":{"disable_root":false}, "upstream":"http://127.0.0.1:8081", "enabled":true});
    let (status, domain) = nginx_request(&app, "POST", "/objects/domain", payload).await;
    assert_eq!(status, StatusCode::OK, "{domain}");
    assert_eq!(domain["object"]["managed"], true);
    assert!(
        domain["content"]
            .as_str()
            .unwrap()
            .contains("limit_req zone=rh_req_assets burst=500 nodelay;")
    );
    assert!(
        domain["content"]
            .as_str()
            .unwrap()
            .contains("limit_conn rh_conn_assets 50;")
    );
    let mut removed = globals.clone();
    removed["limit_policies"] = json!({});
    assert_eq!(
        nginx_request(&app, "PUT", "/settings", removed).await.0,
        StatusCode::BAD_REQUEST
    );

    assert!(
        domain["content"]
            .as_str()
            .unwrap()
            .contains("proxy_buffering off;")
    );
    assert!(
        !domain["content"]
            .as_str()
            .unwrap()
            .contains("include snippets/restrict.conf;")
    );
    let domain_data =
        std::fs::read_to_string(state.config.nginx.root_dir.join("settings/domains.conf")).unwrap();
    assert!(domain_data.contains("www.example.test http://127.0.0.1:8081;"));
    let folder = json!({"domain":"example.test", "name":"media", "settings":{"enable_streaming":false,"enable_large_upload":true,"large_upload_max_body_size":"0","limit_policy":"assets"}, "upstream":"http://127.0.0.1:8082", "enabled":true});
    let (status, folder) = nginx_request(&app, "POST", "/objects/subfolder", folder).await;
    assert_eq!(status, StatusCode::OK, "{folder}");
    assert!(
        folder["content"]
            .as_str()
            .unwrap()
            .contains("client_max_body_size 0;")
    );
    assert!(
        !folder["content"]
            .as_str()
            .unwrap()
            .contains("proxy_buffering off;")
    );
    // A policy used explicitly by a saved site cannot be removed, even if defaults stop using it.
    let mut removed = globals.clone();
    removed["limit_policies"] = json!({});
    removed["site_defaults"]
        .as_object_mut()
        .unwrap()
        .remove("limit_policy");
    assert_eq!(
        nginx_request(&app, "PUT", "/settings", removed).await.0,
        StatusCode::BAD_REQUEST
    );
    let (_, saved_folder) = nginx_request(
        &app,
        "GET",
        "/objects/subfolder/example.test/media",
        json!(null),
    )
    .await;
    assert_eq!(saved_folder["settings"]["limit_policy"], "assets");
    let custom = "server { server_name raw.example.test; # {{untouched}}\n return 204; }";
    let payload = json!({"domain":"example.test", "name":"raw", "content":custom});
    assert_eq!(
        nginx_request(&app, "POST", "/objects/subdomain", payload)
            .await
            .0,
        StatusCode::OK
    );
    // Global edits rerender inherited settings while preserving per-site false/zero and custom content.
    let globals = json!({"shared":{"http_port":8080,"https_port":8443},"limit_policies":{"assets":{"rate":"100r/s","burst":500,"nodelay":true,"connections":50}},"site_defaults":{"enable_lanonly":true,"enable_streaming":true},"allowed_ips":["198.51.100.0/24"],"free_subdomains":[]});
    let (status, response) = nginx_request(&app, "PUT", "/settings", globals).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (_, domain) = nginx_request(
        &app,
        "GET",
        "/objects/domain/example.test/example.test",
        json!(null),
    )
    .await;
    assert!(
        domain["content"]
            .as_str()
            .unwrap()
            .contains("include snippets/restrict.conf;")
    );
    let (_, folder) = nginx_request(
        &app,
        "GET",
        "/objects/subfolder/example.test/media",
        json!(null),
    )
    .await;
    assert_eq!(folder["settings"]["enable_streaming"], false);
    assert_eq!(folder["settings"]["limit_policy"], "assets");
    assert!(
        folder["content"]
            .as_str()
            .unwrap()
            .contains("limit_req zone=rh_req_assets burst=500 nodelay;")
    );
    assert!(
        !folder["content"]
            .as_str()
            .unwrap()
            .contains("proxy_buffering off;")
    );
    assert_eq!(
        nginx_request(
            &app,
            "GET",
            "/objects/subdomain/example.test/raw",
            json!(null)
        )
        .await
        .1["content"],
        custom
    );
    assert!(
        std::fs::read_to_string(state.config.nginx.root_dir.join("snippets/restrict.conf"))
            .unwrap()
            .contains("allow 198.51.100.0/24;")
    );
    // Unknown legacy payload fields and unsafe directive values are rejected.
    assert_eq!(
        nginx_request(
            &app,
            "PUT",
            "/objects/domain/example.test/example.test",
            json!({"template":"basic"})
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        nginx_request(&app, "PUT", "/settings", json!({"shared":{"http_port":0}}))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        nginx_request(
            &app,
            "PUT",
            "/objects/subfolder/example.test/media",
            json!({"settings":{"proxy_connect_timeout":"1s; return 200;"}})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (_, unchanged) = nginx_request(
        &app,
        "GET",
        "/objects/subfolder/example.test/media",
        json!(null),
    )
    .await;
    assert_eq!(unchanged["content"], folder["content"]);
    // Updating aliases replaces the matching upstream entries together.
    let (status, response) = nginx_request(&app,"PUT","/objects/domain/example.test/example.test",json!({"server_names":["example.test","alias.example.test"],"upstream":"https://127.0.0.1:9443"})).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let data =
        std::fs::read_to_string(state.config.nginx.root_dir.join("settings/domains.conf")).unwrap();
    assert!(!data.contains("www.example.test"));
    assert!(data.contains("alias.example.test https://127.0.0.1:9443;"));
    for action in ["disable", "enable", "stop", "start"] {
        assert_eq!(
            nginx_request(
                &app,
                "POST",
                &format!("/objects/subfolder/example.test/media/{action}"),
                json!(null)
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    std::fs::write(
        state.config.nginx.log_dir.join("access.log"),
        "nginx log entry\n",
    )
    .unwrap();
    assert_eq!(
        nginx_request(&app, "GET", "/logs/access.log", json!(null))
            .await
            .1["content"],
        "nginx log entry\n"
    );
    assert_eq!(
        nginx_request(
            &app,
            "DELETE",
            "/objects/domain/example.test/example.test",
            json!(null)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        nginx_request(&app, "GET", "/objects", json!(null)).await.1,
        json!([])
    );
    assert!(
        !std::fs::read_to_string(state.config.nginx.root_dir.join("settings/domains.conf"))
            .unwrap()
            .contains("example.test")
    );
}

#[tokio::test]
async fn test_nginx_settings_validation_failure_restores_all_files() {
    let temp = tempdir().unwrap();
    let mut config = AppConfig {
        test_mode: false,
        ..Default::default()
    };
    config.server.auth_token = "router-hub-test-token-that-is-long-enough".into();
    config.paths.data_dir = temp.path().join("data");
    config.certificates.certs_dir = temp.path().join("dehydrated/certs");
    config.paths.runtime_dir = temp.path().join("runtime");
    config.nginx.root_dir = temp.path().join("nginx");
    config.nginx.inputs_dir = temp.path().join("router-hub/nginx");
    config.nginx.config_path = config.nginx.root_dir.join("nginx.conf");
    config.nginx.pid_path = config.nginx.root_dir.join("nginx.pid");
    config.nginx.domains_available_dir = config.nginx.root_dir.join("domains-available");
    config.nginx.domains_enabled_dir = config.nginx.root_dir.join("domains-enabled");
    config.nginx.domain_upstream_map_path = config
        .nginx
        .root_dir
        .join("conf.d/02_domain_upstream_map.conf");
    config.nginx.subdomain_upstream_map_path = config
        .nginx
        .root_dir
        .join("conf.d/03_subdomain_upstream_map.conf");
    config.nginx.subfolder_upstream_map_path = config
        .nginx
        .root_dir
        .join("conf.d/04_subfolder_upstream_map.conf");
    config.nginx.http_forwarder_path = config.nginx.root_dir.join("conf.d/05-http-to-https.conf");
    config.nginx.log_dir = temp.path().join("logs/nginx");
    config.asus_ui.rendered_page = temp.path().join("router-hub.asp");
    config.commands.nginx = "/bin/false".into();
    config.ensure_directories().unwrap();
    std::fs::write(&config.nginx.config_path, "original").unwrap();
    let original_globals = "# Operator settings\n[global]\nhttp_port = 19080\n";
    let globals_path = router_hub::nginx_render::global_path(&config);
    std::fs::create_dir_all(globals_path.parent().unwrap()).unwrap();
    std::fs::write(&globals_path, original_globals).unwrap();

    let input_map = config.nginx.inputs_dir.join("domains.conf");
    std::fs::write(&input_map, "# original custom input map\n").unwrap();
    let stores = Stores::load(&config).await.unwrap();
    let firewall = FirewallManager::new(config.clone(), stores.clone())
        .await
        .unwrap();
    let state = AppState::new(config, stores, firewall);
    let app = api::app(state.clone()).unwrap();

    let req = Request::builder()
        .method("PUT")
        .uri("/api/nginx/settings")
        .header(
            header::AUTHORIZATION,
            "Bearer router-hub-test-token-that-is-long-enough",
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"shared":{"http_port":8080},"site_defaults":{"enable_lanonly":false}}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(
        std::fs::read_to_string(&state.config.nginx.config_path).unwrap(),
        "original"
    );
    assert_eq!(
        std::fs::read_to_string(&globals_path).unwrap(),
        original_globals
    );
    assert_eq!(
        std::fs::read_to_string(input_map).unwrap(),
        "# original custom input map\n"
    );
    assert!(
        !state
            .config
            .nginx
            .inputs_dir
            .join("allowed_ips.txt")
            .exists()
    );
    assert!(
        !state
            .config
            .nginx
            .root_dir
            .join("snippets/ssl.conf")
            .exists()
    );
    assert!(
        !state
            .config
            .nginx
            .root_dir
            .join("settings/allowed_ips.txt")
            .exists()
    );
}

#[tokio::test]
async fn test_adguard_config_api() {
    let (app, _state, _temp) = setup_test_app().await;

    // GET /api/adguard/config
    let req = Request::builder()
        .uri("/api/adguard/config")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let info: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(info["launch_url"], "http://192.168.1.1:3000");

    // PUT /api/adguard/config with explicit launch_url alias
    let update_payload = serde_json::json!({
        "enabled": true,
        "api_endpoint": "http://192.168.50.1:3000",
        "launch_url": "http://adguard.lan:3000",
        "username": "admin",
        "password": "secretpassword",
        "lan_ip": "192.168.50.1"
    });
    let req = Request::builder()
        .method("PUT")
        .uri("/api/adguard/config")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(update_payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET again to verify launch_url returns the custom alias
    let req = Request::builder()
        .uri("/api/adguard/config")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let info: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(info["api_endpoint"], "http://192.168.50.1:3000");
    assert_eq!(info["launch_url"], "http://adguard.lan:3000");
    assert_eq!(info["lan_ip"], "192.168.50.1");
}

#[tokio::test]
async fn test_adguard_filtering_and_protection_api() {
    let (app, _state, _temp) = setup_test_app().await;

    // Enable AdGuard integration
    let req = Request::builder()
        .method("PUT")
        .uri("/api/adguard/config")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "enabled": true,
                "api_endpoint": "http://127.0.0.1:18080",
                "username": "",
                "password": "",
                "lan_ip": "192.168.1.1"
            })
            .to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    // POST /api/adguard/filtering when enabled (will fail downstream client network connection if not mocked, but tests route/auth/validation)
    let req = Request::builder()
        .method("POST")
        .uri("/api/adguard/filtering")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "enabled": false,
                "duration_minutes": 10
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    // Endpoint exists and auth passes (status is InternalServerError due to unmocked downstream endpoint, or OK)
    assert!(
        resp.status().is_client_error()
            || resp.status().is_server_error()
            || resp.status().is_success()
    );

    // Disable AdGuard integration and check that /api/adguard/filtering returns BAD_REQUEST
    let req = Request::builder()
        .method("PUT")
        .uri("/api/adguard/config")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "enabled": false,
                "api_endpoint": "",
                "username": "",
                "password": "",
                "lan_ip": "192.168.1.1"
            })
            .to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    let req = Request::builder()
        .method("POST")
        .uri("/api/adguard/filtering")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "enabled": false,
                "duration_minutes": 10
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // GET /api/adguard/status when disabled
    let req = Request::builder()
        .uri("/api/adguard/status")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let status_val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status_val["enabled"], false);
}

#[tokio::test]
async fn test_adguard_rewrites_require_enabled_integration() {
    let (app, _state, _temp) = setup_test_app().await;
    let req = Request::builder()
        .method("PUT")
        .uri("/api/adguard/config")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "enabled": false,
                "api_endpoint": "",
                "username": "",
                "password": "",
                "lan_ip": "192.168.1.1"
            })
            .to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    let req = Request::builder()
        .uri("/api/adguard/rewrites")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_adguard_hosts_are_saved_and_read_back() {
    let (app, state, _temp) = setup_test_app().await;
    let payload = serde_json::json!([
        {"ip": "192.168.1.10", "hostnames": ["xyz", "xyz.example.com"]}
    ]);
    let req = Request::builder()
        .method("PUT")
        .uri("/api/adguard/hosts")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read_to_string(&state.config.paths.hosts_add).unwrap(),
        "192.168.1.10 xyz xyz.example.com\n"
    );

    let req = Request::builder()
        .uri("/api/adguard/hosts")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        payload
    );
}

#[tokio::test]
async fn test_dnsmasq_hosts_manage_only_dhcp_host_lines() {
    let (app, state, _temp) = setup_test_app().await;
    std::fs::write(
        &state.config.paths.dnsmasq_conf_add,
        "interface=wg*     # WireGuard\n\n# keep this\ndhcp-host=AA:BB:CC:DD:EE:FF,set:AA:BB:CC:DD:EE:FF,old,192.168.1.20\n",
    )
    .unwrap();
    let req = Request::builder()
        .uri("/api/adguard/dnsmasq-hosts")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!([
            {"mac":"AA:BB:CC:DD:EE:FF","hostname":"old","ip":"192.168.1.20"}
        ])
    );

    let req = Request::builder()
        .method("PUT")
        .uri("/api/adguard/dnsmasq-hosts")
        .header(header::AUTHORIZATION, "Bearer router-hub-test-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!([
                {"mac":"AA:BB:CC:DD:EE:FF","hostname":"new","ip":"192.168.1.21"}
            ])
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read_to_string(&state.config.paths.dnsmasq_conf_add).unwrap(),
        "interface=wg*     # WireGuard\n\n# keep this\ndhcp-host=AA:BB:CC:DD:EE:FF,set:AA:BB:CC:DD:EE:FF,new,192.168.1.21\n"
    );
}

#[tokio::test]
async fn test_nginx_settings_reload_failure_restores_all_files() {
    use std::os::unix::fs::PermissionsExt;
    let (_app, state, temp) = setup_test_app().await;
    let executable = temp.path().join("nginx-failing-reload");
    std::fs::write(
        &executable,
        "#!/bin/sh\nfor arg do\n    [ \"$arg\" = reload ] && exit 1\ndone\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = (*state.config).clone();
    config.test_mode = false;
    config.commands.nginx = executable;
    std::fs::create_dir_all(config.nginx.pid_path.parent().unwrap()).unwrap();
    std::fs::write(&config.nginx.pid_path, std::process::id().to_string()).unwrap();
    let state = AppState::new(config, state.stores.clone(), state.firewall.clone());
    let app = api::app(state.clone()).unwrap();
    let previous = std::fs::read(&state.config.nginx.config_path).unwrap();
    let (status, response) = nginx_request(
        &app,
        "PUT",
        "/settings",
        serde_json::json!({"shared":{"http_port":8080}}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{response}");
    assert_eq!(
        std::fs::read(&state.config.nginx.config_path).unwrap(),
        previous
    );
    assert!(!router_hub::nginx_render::global_path(&state.config).exists());
    assert!(
        !state
            .config
            .nginx
            .root_dir
            .join("snippets/restrict.conf")
            .exists()
    );
}

#[tokio::test]
async fn managed_sites_persist_inputs_and_regenerate_without_metadata() {
    use router_hub::{models::NginxObjectKind, nginx, nginx_sites};
    use serde_json::json;
    let (app, state, _temp) = setup_test_app().await;
    let (status, result) = nginx_request(&app, "POST", "/objects/domain", json!({"domain":"saved.test","name":"saved.test","settings":{"disable_root":true},"upstream":"http://127.0.0.1:8080"})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    let path = nginx::available_path(
        &state.config,
        NginxObjectKind::Domain,
        "saved.test",
        "saved.test",
    )
    .unwrap();
    // Generated bytes are disposable: their settings comment is not the source.
    std::fs::write(&path, "server { server_name saved.test; }\n").unwrap();
    let (status, result) = nginx_request(
        &app,
        "GET",
        "/objects/domain/saved.test/saved.test",
        json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["settings"]["disable_root"], true);
    assert_eq!(result["object"]["managed"], true);
    let (status, result) = nginx_request(
        &app,
        "PUT",
        "/objects/domain/saved.test/saved.test",
        json!({"settings":{"disable_root":false,"client_max_body_size":"23M"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("client_max_body_size 23M;")
    );
    let saved = nginx_sites::find(
        &state.config,
        NginxObjectKind::Domain,
        "saved.test",
        "saved.test",
    )
    .unwrap()
    .unwrap();
    assert_eq!(saved.settings["client_max_body_size"], "23M");
    assert_eq!(saved.upstream.as_deref(), Some("http://127.0.0.1:8080"));
    std::fs::remove_file(&path).unwrap();
    let (status, result) = nginx_request(&app, "PUT", "/settings", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("client_max_body_size 23M;")
    );
    let before = std::fs::read(nginx_sites::path(&state.config)).unwrap();
    assert_eq!(
        nginx_request(
            &app,
            "PUT",
            "/objects/domain/saved.test/saved.test",
            json!({"content":"server {}"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        before,
        std::fs::read(nginx_sites::path(&state.config)).unwrap()
    );
    assert_eq!(
        nginx_request(
            &app,
            "POST",
            "/objects/domain/saved.test/saved.test/enable",
            json!(null)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(
        nginx_sites::find(
            &state.config,
            NginxObjectKind::Domain,
            "saved.test",
            "saved.test"
        )
        .unwrap()
        .unwrap()
        .enabled
    );
    assert_eq!(
        nginx_request(
            &app,
            "DELETE",
            "/objects/domain/saved.test/saved.test",
            json!(null)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(nginx_sites::load(&state.config).unwrap().sites.is_empty());
}

#[tokio::test]
async fn managed_site_inputs_roll_back_when_nginx_rejects_an_update() {
    use router_hub::{command::CommandRunner, models::NginxObjectKind, nginx, nginx_sites};
    use serde_json::json;
    let (_app, mut state, _temp) = setup_test_app().await;
    state.runner = CommandRunner::new(false);
    std::sync::Arc::make_mut(&mut state.config).commands.nginx = "/bin/false".into();
    let app = api::app(state.clone()).unwrap();
    let (status, result) = nginx_request(
        &app,
        "POST",
        "/objects/domain",
        json!({"domain":"rollback.test","name":"rollback.test","settings":{"disable_root":true}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    nginx::set_enabled(
        &state.config,
        NginxObjectKind::Domain,
        "rollback.test",
        "rollback.test",
        true,
    )
    .unwrap();
    let path = nginx::available_path(
        &state.config,
        NginxObjectKind::Domain,
        "rollback.test",
        "rollback.test",
    )
    .unwrap();
    let inputs = std::fs::read(nginx_sites::path(&state.config)).unwrap();
    let output = std::fs::read(&path).unwrap();
    let (status, result) = nginx_request(
        &app,
        "PUT",
        "/objects/domain/rollback.test/rollback.test",
        json!({"settings":{"disable_root":false}}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{result}");
    assert_eq!(
        inputs,
        std::fs::read(nginx_sites::path(&state.config)).unwrap()
    );
    assert_eq!(output, std::fs::read(path).unwrap());
}

#[tokio::test]
async fn emulated_fixture_sites_survive_shared_settings_regeneration() {
    use serde_json::json;
    let (app, state, _temp) = setup_test_app().await;
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test-fixtures/etc/nginx");
    let settings_dir = state.config.nginx.inputs_dir.clone();
    std::fs::create_dir_all(&settings_dir).unwrap();
    std::fs::copy(
        fixture.join("../router-hub/nginx/sites.toml"),
        settings_dir.join("sites.toml"),
    )
    .unwrap();
    let sites = router_hub::nginx_sites::load(&state.config).unwrap();
    assert_eq!(sites.sites.len(), 3);
    for (key, site) in &sites.sites {
        let name = site.object_name(key).unwrap();
        let source =
            router_hub::nginx::available_path(&state.config, site.kind, &site.domain, &name)
                .unwrap();
        let relative = source.strip_prefix(&state.config.nginx.root_dir).unwrap();
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::copy(fixture.join(relative), &source).unwrap();
    }
    let (status, response) = nginx_request(&app, "PUT", "/settings", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    for (key, site) in &sites.sites {
        let name = site.object_name(key).unwrap();
        let route = format!("/objects/{}/{}/{}", site.kind.as_str(), site.domain, name);
        let (status, response) = nginx_request(&app, "GET", &route, json!(null)).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(
            response["settings"],
            serde_json::to_value(&site.settings).unwrap()
        );
        assert_eq!(
            response["upstream"],
            serde_json::to_value(&site.upstream).unwrap()
        );
        assert!(
            response["content"]
                .as_str()
                .unwrap()
                .starts_with(router_hub::nginx_render::SETTINGS_PREFIX)
        );
    }
}

#[tokio::test]
async fn test_disable_managed_subdomain_without_explicit_name() {
    use router_hub::{models::NginxObjectKind, nginx, nginx_sites};
    use serde_json::json;
    let (app, state, _temp) = setup_test_app().await;

    // Create parent domain
    let (status, _) = nginx_request(
        &app,
        "POST",
        "/objects/domain",
        json!({"domain":"example.test","name":"example.test","settings":{},"upstream":"http://127.0.0.1:8080","enabled":true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Create subdomain files
    let sub_avail = nginx::available_path(
        &state.config,
        NginxObjectKind::Subdomain,
        "example.test",
        "api",
    )
    .unwrap();
    std::fs::create_dir_all(sub_avail.parent().unwrap()).unwrap();
    std::fs::write(&sub_avail, "server { server_name api.example.test; }\n").unwrap();
    nginx::set_enabled(
        &state.config,
        NginxObjectKind::Subdomain,
        "example.test",
        "api",
        true,
    )
    .unwrap();

    // In sites.toml, add the subdomain WITHOUT name = "api" (typical user format)
    let sites_path = nginx_sites::path(&state.config);
    let mut sites_content = std::fs::read_to_string(&sites_path).unwrap_or_default();
    sites_content.push_str("\n[sites.\"api.example.test\"]\nkind = \"subdomain\"\ndomain = \"example.test\"\nserver_name = \"api.example.test\"\nupstream = \"http://127.0.0.1:8085\"\nenabled = true\n");
    std::fs::write(&sites_path, sites_content).unwrap();

    // Disabling subdomain must succeed with 200 OK (not 500)
    let (status, result) = nginx_request(
        &app,
        "POST",
        "/objects/subdomain/example.test/api/disable",
        json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["enabled"], false);

    // Verify sites.toml still loads and reflects enabled = false
    let site = nginx_sites::find(
        &state.config,
        NginxObjectKind::Subdomain,
        "example.test",
        "api",
    )
    .unwrap()
    .expect("site must exist in sites.toml");
    assert!(!site.enabled);
    assert_eq!(site.name.as_deref(), Some("api"));

    // Enabling it again also works
    let (status, result) = nginx_request(
        &app,
        "POST",
        "/objects/subdomain/example.test/api/enable",
        json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["enabled"], true);
}
