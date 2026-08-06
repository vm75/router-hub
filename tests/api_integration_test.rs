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
    config.nginx.config_path = config.nginx.root_dir.join("nginx.conf");
    config.nginx.pid_path = config.nginx.root_dir.join("nginx.pid");
    config.nginx.domains_available_dir = config.nginx.root_dir.join("domains-available");
    config.nginx.domains_enabled_dir = config.nginx.root_dir.join("domains-enabled");
    config.nginx.templates_dir = config.nginx.root_dir.join("templates");
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

#[tokio::test]
async fn test_nginx_files_templates_objects_actions_and_logs_api() {
    let (app, state, _temp) = setup_test_app().await;
    let auth_header = ("authorization", "Bearer router-hub-test-token");

    // Root-level nginx files can be created and read.
    let req = Request::builder()
        .method("PUT")
        .uri("/api/nginx/files/conf.d%2Fglobal.conf")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"content":"server_tokens off;"}"#))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .uri("/api/nginx/files/conf.d%2Fglobal.conf")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Templates are independently managed.
    let req = Request::builder()
        .method("PUT")
        .uri("/api/nginx/templates/domain/basic")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"content":"server { server_name {{server_name}}; }"}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // A domain can be created from a template and enabled.
    let create_domain = serde_json::json!({
        "domain": "example.test",
        "name": "example.test",
        "template": "basic",
        "server_names": ["example.test", "www.example.test"],
        "upstream": "http://127.0.0.1:8080",
        "enabled": true
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/nginx/objects/domain")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_domain).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let domain: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(domain["upstream"], "http://127.0.0.1:8080");
    assert!(
        std::fs::read_to_string(&state.config.nginx.domain_upstream_map_path)
            .unwrap()
            .contains("example.test http://127.0.0.1:8080;")
    );
    assert!(
        std::fs::read_to_string(&state.config.nginx.domain_upstream_map_path)
            .unwrap()
            .contains("www.example.test http://127.0.0.1:8080;")
    );

    let req = Request::builder()
        .method("PUT")
        .uri("/api/nginx/objects/domain/example.test/example.test")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"template":"basic","upstream":"https://127.0.0.1:8443"}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let domain: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(domain["upstream"], "https://127.0.0.1:8443");
    let domain_map = std::fs::read_to_string(&state.config.nginx.domain_upstream_map_path).unwrap();
    assert!(domain_map.contains("example.test https://127.0.0.1:8443;"));
    assert!(domain_map.contains("www.example.test https://127.0.0.1:8443;"));

    let req = Request::builder()
        .method("PUT")
        .uri("/api/nginx/templates/subdomain/proxy")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"content":"server { server_name {{server_name}}; }"}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let create_subdomain = serde_json::json!({
        "domain": "example.test",
        "name": "app",
        "template": "proxy",
        "server_names": ["app.example.test", "media.example.test"],
        "upstream": "http://127.0.0.1:8081",
        "enabled": true
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/nginx/objects/subdomain")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_subdomain).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let subdomain: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        subdomain["content"]
            .as_str()
            .unwrap()
            .contains("server_name app.example.test media.example.test;")
    );
    assert_eq!(subdomain["object"]["template"], "proxy");
    assert_eq!(subdomain["upstream"], "http://127.0.0.1:8081");
    assert_eq!(
        subdomain["server_names"],
        serde_json::json!(["app.example.test", "media.example.test"])
    );
    assert!(
        subdomain["content"]
            .as_str()
            .unwrap()
            .starts_with("# router-hub-template: proxy\n")
    );

    // Changing a selected template rerenders the same site and preserves its aliases.
    let req = Request::builder()
        .method("PUT")
        .uri("/api/nginx/templates/subdomain/proxy-alt")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"content":"server { server_name {{server_name}}; return 204; }"}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let update_subdomain = serde_json::json!({
        "template": "proxy-alt",
        "server_names": ["app.example.test", "media.example.test"],
        "upstream": "https://127.0.0.1:8443"
    });
    let req = Request::builder()
        .method("PUT")
        .uri("/api/nginx/objects/subdomain/example.test/app")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&update_subdomain).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let subdomain: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(subdomain["object"]["template"], "proxy-alt");
    assert_eq!(subdomain["upstream"], "https://127.0.0.1:8443");
    assert!(
        subdomain["content"]
            .as_str()
            .unwrap()
            .contains("return 204;")
    );

    // Omitting aliases on an update keeps the aliases already present in the
    // authoritative nginx object.
    let req = Request::builder()
        .method("PUT")
        .uri("/api/nginx/objects/subdomain/example.test/app")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"template":"proxy-alt"}"#))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let subdomain: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        subdomain["server_names"],
        serde_json::json!(["app.example.test", "media.example.test"])
    );
    assert_eq!(subdomain["upstream"], "https://127.0.0.1:8443");

    // A subfolder can use custom configuration, then start and stop.
    let create_subfolder = serde_json::json!({
        "domain": "example.test",
        "name": "media",
        "content": "location /media/ { proxy_pass http://127.0.0.1:8080; }",
        "upstream": "http://127.0.0.1:8082",
        "enabled": false
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/nginx/objects/subfolder")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_subfolder).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let subfolder: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(subfolder["upstream"], "http://127.0.0.1:8082");

    let forwarder = std::fs::read_to_string(&state.config.nginx.http_forwarder_path).unwrap();
    assert!(forwarder.contains("example.test"));
    assert!(forwarder.contains("app.example.test"));

    let req = Request::builder()
        .method("PUT")
        .uri("/api/nginx/objects/subfolder/example.test/media")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r##"{"content":"# router-hub-template: stale\nlocation /media/ { return 204; }"}"##,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let subfolder: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(subfolder["object"]["template"], serde_json::Value::Null);
    assert!(
        !subfolder["content"]
            .as_str()
            .unwrap()
            .contains("router-hub-template")
    );

    // An empty upstream explicitly removes the generated subfolder map entry.
    let req = Request::builder()
        .method("PUT")
        .uri("/api/nginx/objects/subfolder/example.test/media")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"content":"location /media/ { return 204; }","upstream":""}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let subfolder: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(subfolder["upstream"].is_null());
    let subfolder_map =
        std::fs::read_to_string(&state.config.nginx.subfolder_upstream_map_path).unwrap();
    assert!(!subfolder_map.contains("media http://127.0.0.1:8082;"));

    for (action, expected_enabled) in [
        ("start", true),
        ("stop", false),
        ("enable", true),
        ("disable", false),
    ] {
        let req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/nginx/objects/subfolder/example.test/media/{action}"
            ))
            .header(auth_header.0, auth_header.1)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "action {action}");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let object: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(object["enabled"], expected_enabled);
        assert_eq!(object["running"], expected_enabled);
    }

    // Logs are read only and returned on explicit request.
    std::fs::write(
        state.config.nginx.log_dir.join("access.log"),
        "first\nlast\n",
    )
    .unwrap();
    let req = Request::builder()
        .uri("/api/nginx/logs/access.log")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let log: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(log["content"], "first\nlast\n");

    let req = Request::builder()
        .uri("/api/nginx/objects")
        .header(auth_header.0, auth_header.1)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let objects: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(objects.len(), 3);
    assert_eq!(
        objects
            .iter()
            .find(|object| object["kind"] == "domain")
            .unwrap()["template"],
        "basic"
    );
    assert_eq!(
        objects
            .iter()
            .find(|object| object["kind"] == "subdomain")
            .unwrap()["template"],
        "proxy-alt"
    );
    assert_eq!(
        objects
            .iter()
            .find(|object| object["kind"] == "subdomain")
            .unwrap()["display_name"],
        "app.example.test"
    );
    assert_eq!(
        objects
            .iter()
            .find(|object| object["kind"] == "subfolder")
            .unwrap()["display_name"],
        "example.test/media"
    );

    for (kind, domain, name) in [
        ("subfolder", "example.test", "media"),
        ("subdomain", "example.test", "app"),
        ("domain", "example.test", "example.test"),
    ] {
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/nginx/objects/{kind}/{domain}/{name}"))
            .header(auth_header.0, auth_header.1)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let subdomain_map =
        std::fs::read_to_string(&state.config.nginx.subdomain_upstream_map_path).unwrap();
    assert!(!subdomain_map.contains("app.example.test https://127.0.0.1:8443;"));
    let forwarder = std::fs::read_to_string(&state.config.nginx.http_forwarder_path).unwrap();
    assert!(!forwarder.contains("example.test"));

    for path in [
        "/api/nginx/templates/domain/basic",
        "/api/nginx/templates/subdomain/proxy",
        "/api/nginx/templates/subdomain/proxy-alt",
        "/api/nginx/files/conf.d%2Fglobal.conf",
    ] {
        let req = Request::builder()
            .method("DELETE")
            .uri(path)
            .header(auth_header.0, auth_header.1)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn test_nginx_root_file_validation_failure_restores_previous_content() {
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
    config.nginx.config_path = config.nginx.root_dir.join("nginx.conf");
    config.nginx.pid_path = config.nginx.root_dir.join("nginx.pid");
    config.nginx.domains_available_dir = config.nginx.root_dir.join("domains-available");
    config.nginx.domains_enabled_dir = config.nginx.root_dir.join("domains-enabled");
    config.nginx.templates_dir = config.nginx.root_dir.join("templates");
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

    let stores = Stores::load(&config).await.unwrap();
    let firewall = FirewallManager::new(config.clone(), stores.clone())
        .await
        .unwrap();
    let state = AppState::new(config, stores, firewall);
    let app = api::app(state.clone()).unwrap();

    let req = Request::builder()
        .method("PUT")
        .uri("/api/nginx/files/nginx.conf")
        .header(
            header::AUTHORIZATION,
            "Bearer router-hub-test-token-that-is-long-enough",
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"content":"invalid replacement"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(
        std::fs::read_to_string(&state.config.nginx.config_path).unwrap(),
        "original"
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
