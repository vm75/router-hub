use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use maestro::{
    api, certificate_http,
    config::AppConfig,
    firewall::FirewallManager,
    models::{CertificateMethod, CertificateSpec, NginxObjectKind},
    nginx,
    nginx_ingress::{HttpAccess, HttpMode},
    nginx_render::{self, GlobalSettings},
    nginx_sites::{self, Site},
    state::AppState,
    storage::Stores,
};
use serde_json::{Value, json};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

async fn setup() -> (tempfile::TempDir, AppState) {
    let temp = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    config
        .apply_test_mode(
            &temp
                .path()
                .join("test-fixtures/etc/router-hub/router-hub.toml"),
        )
        .unwrap();
    config.ensure_directories().unwrap();
    fs::write(&config.nginx.config_path, "events {} http {}\n").unwrap();
    let stores = Stores::load(&config).await.unwrap();
    let firewall = FirewallManager::new(config.clone(), stores.clone())
        .await
        .unwrap();
    (temp, AppState::new(config, stores, firewall))
}

async fn request(
    app: &axum::Router,
    method: &str,
    route: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(format!("/api{route}"))
                .header("Authorization", "Bearer router-hub-test-token")
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let code = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (code, serde_json::from_slice(&bytes).unwrap())
}

fn globals() -> GlobalSettings {
    serde_json::from_value(json!({
        "listener_profiles":{"internal":{"https":[{"address":"127.0.0.1","port":19443}]}},
        "access_policies":{"trusted":{"allow":["192.0.2.0/24","2001:db8::/32"]},"narrow":{"allow":["192.0.2.16/28"]}},
        "http_access":{"mode":"renewal_only","externally_managed_wan":true}
    })).unwrap()
}

#[tokio::test]
async fn api_round_trip_preview_references_and_legacy_payload_protection() {
    let (_temp, state) = setup().await;
    let app = api::app(state.clone()).unwrap();
    let (code, global) = request(&app, "GET", "/nginx/settings", json!(null)).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(
        global["http_access"]["mode"], "renewal_only",
        "a genuinely new installation starts closed"
    );
    let (code, reply) = request(
        &app,
        "PUT",
        "/nginx/settings",
        serde_json::to_value(globals()).unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{reply}");
    let (code,reply)=request(&app,"POST","/nginx/objects/domain",json!({"domain":"example.test","name":"example.test","settings":{"listener_profile":"internal","access_policy":"trusted"}})).await;
    assert_eq!(code, StatusCode::OK, "{reply}");
    let before = fs::read(nginx_sites::path(&state.config)).unwrap();
    let (code,preview)=request(&app,"POST","/nginx/access-preview",json!({"kind":"subfolder","domain":"example.test","settings":{"access_policy":"narrow","routes":[{"path":"/admin","match":"exact","access_policy":"deny"}]}})).await;
    assert_eq!(code, StatusCode::OK, "{preview}");
    assert_eq!(preview["listener_profile"], "internal");
    assert_eq!(preview["allowed_sources"], json!(["192.0.2.16/28"]));
    assert_eq!(preview["routes"][0]["allowed_sources"], json!([]));
    assert_eq!(
        fs::read(nginx_sites::path(&state.config)).unwrap(),
        before,
        "preview is read-only"
    );
    let (code, usage) = request(&app, "GET", "/nginx/ingress-usage", json!(null)).await;
    assert_eq!(code, StatusCode::OK);
    assert!(
        usage["access:trusted"][0]
            .as_str()
            .unwrap()
            .contains("example.test")
    );
    let mut changed = globals();
    changed.access_policies.remove("trusted");
    let (code, reply) = request(
        &app,
        "PUT",
        "/nginx/settings",
        serde_json::to_value(changed).unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST, "{reply}");
    assert!(reply.to_string().contains("trusted"));
    let (code, _) = request(&app, "PUT", "/nginx/settings", json!({})).await;
    assert_eq!(
        code,
        StatusCode::CONFLICT,
        "old clients must not erase the HTTP lifecycle policy"
    );
    let (code,reply)=request(&app,"POST","/nginx/objects/subdomain",json!({"domain":"example.test","name":"other","server_names":["example.test"],"settings":{"listener_profile":"internal","access_policy":"public"}})).await;
    assert_eq!(
        code,
        StatusCode::BAD_REQUEST,
        "duplicate identity must fail: {reply}"
    );
    assert_eq!(fs::read(nginx_sites::path(&state.config)).unwrap(), before);
}

#[test]
fn rejects_rewrite_and_spa_targets_that_bypass_access() {
    for key in ["rewrite_to", "spa_fallback"] {
        for (mut settings, target) in [
            (
                json!({"access_policy":"public","routes":[{"path":"/admin","access_policy":"deny"}]}),
                "/admin",
            ),
            (
                json!({"access_policy":"public","enable_restricted_sessions":true}),
                "/Sessions",
            ),
            (
                json!({"enable_lanonly":false,"enable_restricted_sessions":true}),
                "/Sessions",
            ),
        ] {
            settings[key] = json!(target);
            assert!(
                nginx_render::render_site(
                    &globals(),
                    settings.as_object().unwrap(),
                    NginxObjectKind::Subdomain,
                    "example.test",
                    "app",
                    &[]
                )
                .unwrap_err()
                .to_string()
                .contains("bypasses")
            );
        }
    }
}

#[tokio::test]
async fn old_hostname_collisions_can_be_repaired_through_the_api() {
    let (_temp, state) = setup().await;
    let app = api::app(state.clone()).unwrap();
    let (code, reply) = request(
        &app,
        "POST",
        "/nginx/objects/domain",
        json!({"domain":"example.test", "name":"example.test"}),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{reply}");
    let (code, reply) = request(
        &app,
        "POST",
        "/nginx/objects/subdomain",
        json!({"domain":"example.test","name":"old"}),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{reply}");
    let mut sites = nginx_sites::load(&state.config).unwrap();
    sites
        .sites
        .values_mut()
        .find(|site| site.kind == NginxObjectKind::Subdomain)
        .unwrap()
        .server_name = "example.test".into();
    fs::write(
        nginx_sites::path(&state.config),
        toml::to_string_pretty(&sites).unwrap(),
    )
    .unwrap();
    let (code, reply) = request(&app, "GET", "/nginx/settings", json!(null)).await;
    assert_eq!(code, StatusCode::OK, "{reply}");
    certificate_http::recover_startup(&state).await.unwrap();
    let (code, reply) = request(
        &app,
        "PUT",
        "/nginx/objects/subdomain/example.test/old",
        json!({"server_names":["old.example.test"]}),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{reply}");
    let sites = nginx_sites::load(&state.config).unwrap();
    maestro::nginx_ingress::validate_tree(
        &nginx_render::load_global(&state.config).unwrap(),
        &sites,
    )
    .unwrap();
}

#[tokio::test]
async fn removing_the_public_vhost_preserves_shared_split_dns() {
    let (_temp, mut state) = setup().await;
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let lan_ip = "192.0.2.10";
    let shared = json!({"domain":"app.example.test", "answer":lan_ip});
    let unshared = json!({"domain":"unshared.example.test", "answer":lan_ip});
    let rewrites = Arc::new(tokio::sync::Mutex::new(vec![shared.clone(), unshared]));
    let list = {
        let rewrites = rewrites.clone();
        move || async move { axum::Json(rewrites.lock().await.clone()) }
    };
    let delete = {
        let rewrites = rewrites.clone();
        move |axum::Json(entry): axum::Json<Value>| async move {
            rewrites.lock().await.retain(|rewrite| *rewrite != entry);
            StatusCode::OK
        }
    };
    let mock = axum::Router::new()
        .route("/control/rewrite/list", axum::routing::get(list))
        .route("/control/rewrite/delete", axum::routing::post(delete));
    let endpoint = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let adguard = &mut Arc::make_mut(&mut state.config).adguard;
    adguard.enabled = true;
    adguard.api_endpoint = format!("http://{endpoint}");
    adguard.lan_ip = lan_ip.into();

    let global = nginx_render::with_path_defaults(globals(), &state.config);
    nginx_render::FileTransaction::apply(
        &state.config,
        nginx_render::shared_files(&state.config, &global).unwrap(),
    )
    .unwrap()
    .commit();
    let upstream = "http://127.0.0.1:8080";
    install_site(
        &state.config,
        &global,
        NginxObjectKind::Domain,
        "example.test",
        json!({}),
        upstream,
    );
    for name in ["app", "unshared"] {
        install_site(
            &state.config,
            &global,
            NginxObjectKind::Subdomain,
            name,
            json!({}),
            upstream,
        );
    }
    install_site_with_names(
        &state.config,
        &global,
        NginxObjectKind::Subdomain,
        "private",
        &["app.example.test".into()],
        json!({"listener_profile":"internal"}),
        upstream,
    );

    let app = api::app(state).unwrap();
    for name in ["app", "unshared"] {
        let (code, reply) = request(
            &app,
            "DELETE",
            &format!("/nginx/objects/subdomain/example.test/{name}"),
            json!(null),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{reply}");
    }
    assert_eq!(*rewrites.lock().await, vec![shared]);
    task.abort();
}

#[tokio::test]
async fn session_is_challenge_only_and_startup_recovers_stale_window() {
    let (_temp, state) = setup().await;
    let global = nginx_render::with_path_defaults(globals(), &state.config);
    nginx_render::FileTransaction::apply(
        &state.config,
        nginx_render::shared_files(&state.config, &global).unwrap(),
    )
    .unwrap()
    .commit();
    let spec:CertificateSpec=serde_json::from_value(json!({"name":"example_test","domains":["example.test","app.example.test"],"method":"http","auto_renew":true})).unwrap();
    let session = certificate_http::begin(&state, &[spec])
        .await
        .unwrap()
        .unwrap();
    assert!(session.expires_at > chrono::Utc::now());
    let http = fs::read_to_string(&state.config.nginx.http_forwarder_path).unwrap();
    assert!(http.contains("example.test"));
    assert!(http.contains("location / { return 404; }"));
    assert!(!http.contains("proxy_pass") && !http.contains("301"));
    assert_eq!(
        certificate_http::status(&state.config).unwrap().state,
        "active"
    );
    let stale_lock = state.config.certificates.certs_dir.join("lock");
    fs::write(&stale_lock, "stale").unwrap();
    let restarted = AppState::new(
        (*state.config).clone(),
        state.stores.clone(),
        state.firewall.clone(),
    );
    certificate_http::close(&restarted).await.unwrap();
    assert!(
        stale_lock.exists(),
        "the dehydrated lock is managed separately"
    );
    assert!(
        !fs::read_to_string(&state.config.nginx.http_forwarder_path)
            .unwrap()
            .contains("listen")
    );
    assert!(
        !fs::read_to_string(
            state
                .config
                .nginx
                .root_dir
                .join("ban-shield/default-drop.conf")
        )
        .unwrap()
        .contains(":80 ")
    );
    assert_eq!(
        certificate_http::status(&state.config).unwrap().state,
        "closed"
    );
    assert!(certificate_http::active(&state.config).unwrap().is_none());
}

fn certificate(name: &str, method: CertificateMethod) -> CertificateSpec {
    serde_json::from_value(json!({"name":name,"domains":[format!("{}.example.test",name.replace('_',"-"))],"method":method,"auto_renew":true})).unwrap()
}

async fn processor(state: &AppState, delay: f32) -> (AppState, ProbeServer) {
    let mut config = (*state.config).clone();
    config.test_mode = false;
    let root = &config.paths.data_dir;
    let nginx = root.join("nginx-mock");
    let dehydrated = root.join("certificate-processor");
    fs::write(&nginx,format!("#!/usr/bin/python3\nimport sys,pathlib\nif 'reload' in sys.argv and pathlib.Path({}).exists(): sys.exit(1)\n",serde_json::to_string(&root.join("fail-reload")).unwrap())).unwrap();
    fs::write(&dehydrated,format!("#!/usr/bin/python3\nimport json,sys,time,pathlib\ncfg=pathlib.Path(sys.argv[sys.argv.index('--config')+1])\nwith pathlib.Path({}).open('a') as f: f.write(json.dumps({{'name':cfg.stem,'http':pathlib.Path({}).read_text()}})+'\\n')\ntime.sleep({delay})\nif cfg.stem.startswith('fail'): sys.exit(1)\nprint('issued')\n",serde_json::to_string(&root.join("issued.jsonl")).unwrap(),serde_json::to_string(&config.nginx.http_forwarder_path).unwrap())).unwrap();
    for file in [&nginx, &dehydrated] {
        fs::set_permissions(file, fs::Permissions::from_mode(0o700)).unwrap();
    }
    config.commands.nginx = nginx;
    config.commands.dehydrated = dehydrated;
    fs::write(&config.nginx.pid_path, std::process::id().to_string()).unwrap();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let http_file = config.nginx.http_forwarder_path.clone();
    let token_dir = config.certificates.certs_dir.join("acme-challenge");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let http_file = http_file.clone();
            let token_dir = token_dir.clone();
            tokio::spawn(async move {
                let mut bytes = [0u8; 4096];
                let count = stream.read(&mut bytes).await.unwrap();
                let request = String::from_utf8_lossy(&bytes[..count]);
                let token = request
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .rsplit('/')
                    .next()
                    .unwrap_or("");
                let ready =
                    fs::read_to_string(http_file).is_ok_and(|content| content.contains("listen"));
                let body = if ready && token.starts_with("router-hub-probe-") {
                    fs::read(token_dir.join(token)).unwrap_or_default()
                } else {
                    vec![]
                };
                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    if body.is_empty() {
                        "404 Not Found"
                    } else {
                        "200 OK"
                    },
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });
    (
        AppState::new(config, state.stores.clone(), state.firewall.clone()),
        ProbeServer { port, task },
    )
}

struct ProbeServer {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for ProbeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(condition(), "condition did not complete within two seconds");
}

#[tokio::test]
async fn automatic_http_batch_survives_one_failure_and_preserves_concurrent_settings() {
    let (_temp, base) = setup().await;
    let (state, probe) = processor(&base, 0.5).await;
    let mut global = nginx_render::with_path_defaults(globals(), &state.config);
    global.shared.insert("http_port".into(), json!(probe.port));
    nginx_render::FileTransaction::apply(
        &state.config,
        nginx_render::shared_files(&state.config, &global).unwrap(),
    )
    .unwrap()
    .commit();
    let mut first_certificate = certificate("fail_first", CertificateMethod::Http);
    first_certificate
        .domains
        .push("san-first.example.test".into());
    state.stores.certificates.write().await.extend([
        first_certificate,
        certificate("second", CertificateMethod::Http),
    ]);
    state.start_certificate_renewal_loop();
    let log = state.config.paths.data_dir.join("issued.jsonl");
    let mut first = None;
    wait_until(|| {
        first = fs::read_to_string(&log).ok().and_then(|content| {
            content
                .lines()
                .next()
                .and_then(|line| serde_json::from_str::<Value>(line).ok())
        });
        first.is_some()
    })
    .await;
    let first = first.unwrap();
    assert!(
        first["http"]
            .as_str()
            .unwrap()
            .contains("fail-first.example.test")
    );
    assert!(
        first["http"]
            .as_str()
            .unwrap()
            .contains("second.example.test")
    );
    assert!(
        first["http"]
            .as_str()
            .unwrap()
            .contains("san-first.example.test"),
        "the session must include every SAN before starting the first job"
    );
    let app = api::app(state.clone()).unwrap();
    let mut update = serde_json::to_value(&global).unwrap();
    update["access_policies"]["extra"] = json!({"allow":["127.0.0.1"]});
    let (code, reply) = request(&app, "PUT", "/nginx/settings", update.clone()).await;
    assert_eq!(
        code,
        StatusCode::OK,
        "unrelated edits must be retained: {reply}"
    );
    let (code, reply) = request(&app, "POST", "/certificates", json!({
        "name":"late-reconcile", "domains":["late.example.test"], "method":"http", "auto_renew":false
    })).await;
    assert_eq!(
        code,
        StatusCode::OK,
        "certificate-route regeneration: {reply}"
    );
    let active_routes = fs::read_to_string(&state.config.nginx.http_forwarder_path).unwrap();
    assert!(active_routes.contains("san-first.example.test"));
    assert!(
        !active_routes.contains("late.example.test"),
        "definition saves cannot widen the active batch"
    );
    update["shared"]["http_port"] = json!(18082);
    let (code, reply) = request(&app, "PUT", "/nginx/settings", update).await;
    assert_eq!(
        code,
        StatusCode::CONFLICT,
        "HTTP bindings cannot change during the window: {reply}"
    );
    wait_until(|| !state.certificate_busy()).await;
    assert_eq!(
        fs::read_to_string(&log).unwrap().lines().count(),
        2,
        "failure must not skip remaining certificates"
    );
    assert_eq!(
        certificate_http::status(&state.config).unwrap().state,
        "closed"
    );
    assert!(
        !fs::read_to_string(&state.config.nginx.http_forwarder_path)
            .unwrap()
            .contains("listen")
    );
    assert!(
        fs::read_to_string(
            state
                .config
                .nginx
                .root_dir
                .join("conf.d/00-ingress-access.conf")
        )
        .unwrap()
        .contains("rh_policy_extra")
    );
}

#[tokio::test]
async fn disconnected_manual_request_still_closes_its_window() {
    let (_temp, base) = setup().await;
    let (state, probe) = processor(&base, 0.2).await;
    let mut global = nginx_render::with_path_defaults(globals(), &state.config);
    global.shared.insert("http_port".into(), json!(probe.port));
    nginx_render::FileTransaction::apply(
        &state.config,
        nginx_render::shared_files(&state.config, &global).unwrap(),
    )
    .unwrap()
    .commit();
    let cert = certificate("manual", CertificateMethod::Http);
    let id = cert.id;
    state.stores.certificates.write().await.push(cert);
    let worker = state.clone();
    let request = tokio::spawn(async move { worker.issue_certificate(id, false).await });
    wait_until(|| state.config.paths.data_dir.join("issued.jsonl").exists()).await;
    request.abort();
    wait_until(|| !state.certificate_busy()).await;
    assert_eq!(
        certificate_http::status(&state.config).unwrap().state,
        "closed"
    );
    assert!(certificate_http::active(&state.config).unwrap().is_none());
}

#[tokio::test]
async fn shutdown_cancels_process_group_and_closes_http_without_waiting_for_command_timeout() {
    let (_temp, base) = setup().await;
    let (state, probe) = processor(&base, 30.0).await;
    let mut global = nginx_render::with_path_defaults(globals(), &state.config);
    global.shared.insert("http_port".into(), json!(probe.port));
    nginx_render::FileTransaction::apply(
        &state.config,
        nginx_render::shared_files(&state.config, &global).unwrap(),
    )
    .unwrap()
    .commit();
    let cert = certificate("shutdown", CertificateMethod::Http);
    let id = cert.id;
    state.stores.certificates.write().await.push(cert);
    let worker = state.clone();
    let request = tokio::spawn(async move { worker.issue_certificate(id, false).await });
    wait_until(|| state.config.paths.data_dir.join("issued.jsonl").exists()).await;
    tokio::time::timeout(Duration::from_secs(2), state.stop_certificates())
        .await
        .unwrap()
        .unwrap();
    assert!(request.await.unwrap().is_err());
    assert_eq!(
        certificate_http::status(&state.config).unwrap().state,
        "closed"
    );
}

#[tokio::test]
async fn dns_and_disabled_http_never_open_a_validation_window() {
    let (_temp, state) = setup().await;
    let mut global = globals();
    global.http_access = Some(HttpAccess {
        mode: HttpMode::Off,
        ..Default::default()
    });
    nginx_render::FileTransaction::apply(
        &state.config,
        nginx_render::shared_files(&state.config, &global).unwrap(),
    )
    .unwrap()
    .commit();
    assert!(
        certificate_http::begin(&state, &[certificate("dns", CertificateMethod::Dns)])
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        certificate_http::begin(&state, &[certificate("http", CertificateMethod::Http)])
            .await
            .is_err()
    );
    assert!(certificate_http::active(&state.config).unwrap().is_none());
}

fn available_ports(count: usize) -> Vec<u16> {
    let listeners = (0..count)
        .map(|_| std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
        .collect::<Vec<_>>();
    listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect()
}

async fn served_certificate(port: u16) -> String {
    let output = tokio::process::Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-servername",
            "app.example.test",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let start = text.find("-----BEGIN CERTIFICATE-----").unwrap();
    let end = text.find("-----END CERTIFICATE-----").unwrap() + "-----END CERTIFICATE-----".len();
    text[start..end].to_owned()
}

async fn tcp_forwarder(target: u16) -> ProbeServer {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut incoming, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut upstream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, target))
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut incoming, &mut upstream).await;
            });
        }
    });
    ProbeServer { port, task }
}

struct Process(std::process::Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn install_site(
    config: &AppConfig,
    global: &GlobalSettings,
    kind: NginxObjectKind,
    name: &str,
    settings: Value,
    upstream: &str,
) {
    install_site_with_names(config, global, kind, name, &[], settings, upstream);
}

fn install_site_with_names(
    config: &AppConfig,
    global: &GlobalSettings,
    kind: NginxObjectKind,
    name: &str,
    names: &[String],
    settings: Value,
    upstream: &str,
) {
    let names = nginx::normalize_server_names(kind, "example.test", name, names).unwrap();
    let settings = settings.as_object().unwrap().clone();
    let site = Site {
        kind,
        domain: "example.test".into(),
        name: Some(name.into()),
        server_name: names.join(" "),
        subfolder: (kind == NginxObjectKind::Subfolder).then(|| name.into()),
        upstream: Some(upstream.into()),
        enabled: true,
        settings: settings.clone(),
    };
    nginx_sites::save(config, kind, "example.test", name, Some(site))
        .unwrap()
        .commit();
    let content =
        nginx_render::render_site(global, &settings, kind, "example.test", name, &names).unwrap();
    nginx::write_object(config, kind, "example.test", name, &content, true).unwrap();
    nginx::set_enabled(config, kind, "example.test", name, true).unwrap();
}

#[tokio::test]
async fn live_nginx_separates_ingress_and_blocks_paths_before_upstream() {
    let paths = std::env::var_os("PATH").unwrap_or_default();
    let program = |name: &str| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|path| path.is_file())
    };
    let Some(nginx_bin) = program("nginx") else {
        eprintln!("nginx missing: live ingress test skipped");
        return;
    };
    let openssl = program("openssl").expect("live ingress test requires openssl");
    let (_temp, state) = setup().await;
    let config = &state.config;
    let ports = available_ports(4);
    let backend = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let upstream = format!("http://{}", backend.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let backend_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = backend.accept().await else {
                break;
            };
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut bytes = [0u8; 4096];
                let count = stream.read(&mut bytes).await.unwrap();
                let request = String::from_utf8_lossy(&bytes[..count]);
                let path = request.split_whitespace().nth(1).unwrap_or("");
                counter.fetch_add(1, Ordering::SeqCst);
                let body = if path == "/identity" {
                    request.to_string()
                } else {
                    "OK".into()
                };
                let response = if path.contains("/missing") {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .into()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                };
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    let mut global:GlobalSettings=serde_json::from_value(json!({
        "shared":{"router_ip":"127.0.0.1","http_port":ports[0],"https_port":ports[1],"nginx_daemon":false,"nginx_user":"root","temp_dir":config.nginx.root_dir.join("tmp")},
        "listener_profiles":{"internal":{"https":[{"address":"127.0.0.1","port":ports[2]},{"address":"127.0.0.3","port":ports[2]}]},"management":{"https":[{"address":"127.0.0.1","port":ports[3]}]}},
        "access_policies":{"local":{"allow":["127.0.0.1"]}},
        "limit_policies":{"forwarder_budget":{"rate":"1r/m","burst":0,"nodelay":true,"connections":10}},
        "http_access":{"mode":"always"}
    })).unwrap();
    global = nginx_render::with_path_defaults(global, config);
    nginx_render::FileTransaction::apply(
        config,
        nginx_render::shared_files(config, &global).unwrap(),
    )
    .unwrap()
    .commit();
    install_site(
        config,
        &global,
        NginxObjectKind::Domain,
        "example.test",
        json!({"access_policy":"local","disable_root":false}),
        &upstream,
    );
    install_site(
        config,
        &global,
        NginxObjectKind::Subdomain,
        "app",
        json!({"listener_profile":"internal","access_policy":"local","routes":[{"path":"/admin","match":"exact","access_policy":"deny"},{"path":"/admin/","access_policy":"deny"},{"path":"/child","access_policy":"public"},{"path":"/budget","limit_policy":"forwarder_budget"}]}),
        &upstream,
    );
    install_site_with_names(
        config,
        &global,
        NginxObjectKind::Subdomain,
        "wildcard",
        &["*.example.test".into()],
        json!({"enable_lanonly":false}),
        &upstream,
    );
    install_site(
        config,
        &global,
        NginxObjectKind::Subfolder,
        "mount",
        json!({"access_policy":"public","enable_restricted_sessions":true,"spa_fallback":"/index.html", "routes":[
            {"path":"/private", "access_policy":"deny"},
            {"path":"/nested", "access_policy":"local", "children":[
                {"path":"/nested/open", "access_policy":"public"}
            ]}
        ]}),
        &upstream,
    );
    install_site(
        config,
        &global,
        NginxObjectKind::Subdomain,
        "manage",
        json!({"listener_profile":"management","access_policy":"public","enable_restricted_sessions":true,"routes":[{"path":"/budget","limit_policy":"forwarder_budget"},{"path":"/restricted", "access_policy":"local", "spa_fallback":"/index.html", "children":[{"path":"/restricted/open","access_policy":"public"}]}]}),
        &upstream,
    );
    // Reserve a port without listening so parallel fixtures cannot claim it.
    let offline_socket = tokio::net::TcpSocket::new_v4().unwrap();
    offline_socket
        .bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .unwrap();
    let offline_port = offline_socket.local_addr().unwrap().port();
    install_site(
        config,
        &global,
        NginxObjectKind::Subdomain,
        "offline",
        json!({"listener_profile":"management","access_policy":"public"}),
        &format!("http://127.0.0.1:{offline_port}"),
    );
    state
        .stores
        .certificates
        .write()
        .await
        .push(certificate("app", CertificateMethod::Http));
    state.stores.save_certificates().await.unwrap();
    nginx_render::FileTransaction::apply(
        config,
        nginx_render::shared_files(config, &global).unwrap(),
    )
    .unwrap()
    .commit();
    for dir in ["certs/default", "certs/example_test", "module.d", "logs"] {
        fs::create_dir_all(config.nginx.root_dir.join(dir)).unwrap();
    }
    let output = std::process::Command::new("openssl")
        .args([
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
        ])
        .arg(config.nginx.root_dir.join("certs/default/privkey.pem"))
        .arg("-out")
        .arg(config.nginx.root_dir.join("certs/default/fullchain.pem"))
        .output()
        .unwrap();
    assert!(output.status.success());
    for file in ["privkey.pem", "fullchain.pem"] {
        fs::copy(
            config.nginx.root_dir.join("certs/default").join(file),
            config.nginx.root_dir.join("certs/example_test").join(file),
        )
        .unwrap();
    }
    let bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/nginx");
    for file in ["mime.types", "dhparams.pem"] {
        fs::copy(bundle.join(file), config.nginx.root_dir.join(file)).unwrap();
    }
    let test = std::process::Command::new(&nginx_bin)
        .arg("-t")
        .arg("-p")
        .arg(&config.nginx.root_dir)
        .arg("-c")
        .arg(&config.nginx.config_path)
        .output()
        .unwrap();
    assert!(
        test.status.success(),
        "{}",
        String::from_utf8_lossy(&test.stderr)
    );
    let process = std::process::Command::new(&nginx_bin)
        .arg("-p")
        .arg(&config.nginx.root_dir)
        .arg("-c")
        .arg(&config.nginx.config_path)
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut process = Process(process);
    for _ in 0..50 {
        if tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, ports[2]))
            .await
            .is_ok()
        {
            break;
        }
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "nginx exited early"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let client = |source| {
        reqwest::Client::builder()
            .no_proxy()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .local_address(source)
            .resolve(
                "app.example.test",
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ports[2]),
            )
            .resolve(
                "manage.example.test",
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ports[3]),
            )
            .resolve(
                "offline.example.test",
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ports[3]),
            )
            .resolve(
                "example.test",
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ports[1]),
            )
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap()
    };
    let local = client(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let response = local
        .get(format!("https://app.example.test:{}/", ports[2]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let second_binding = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .resolve("app.example.test", ([127, 0, 0, 3], ports[2]).into())
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    assert_eq!(
        second_binding
            .get(format!("https://app.example.test:{}/", ports[2]))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(response.text().await.unwrap(), "OK");
    assert_eq!(
        local
            .get(format!("https://offline.example.test:{}/", ports[3]))
            .send()
            .await
            .unwrap()
            .status(),
        502,
        "an unavailable backend does not stop nginx startup"
    );
    assert_eq!(
        local
            .get(format!("https://app.example.test:{}/", ports[2]))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "the independent application stays available"
    );
    let identity = local
        .get(format!("https://app.example.test:{}/identity", ports[2]))
        .header("X-Forwarded-For", "192.0.2.123")
        .header("X-Forwarded-Host", "attacker.example.test")
        .header("X-Forwarded-Port", "1")
        .header("X-Forwarded-Proto", "http")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
        .to_ascii_lowercase();
    for expected in [
        "x-forwarded-for: 127.0.0.1".to_owned(),
        "x-forwarded-host: app.example.test".to_owned(),
        format!("x-forwarded-port: {}", ports[2]),
        "x-forwarded-proto: https".to_owned(),
    ] {
        assert!(
            identity.contains(&expected),
            "missing trusted identity {expected}: {identity}"
        );
    }
    assert!(!identity.contains("attacker.example.test"));
    assert!(!identity.contains("192.0.2.123"));
    let allowed_hits = hits.load(Ordering::SeqCst);
    for path in [
        "/admin",
        "/admin/",
        "/admin/settings",
        "/ad%6din?query=1",
        "/x/../admin",
    ] {
        assert_eq!(
            local
                .get(format!("https://app.example.test:{}{path}", ports[2]))
                .send()
                .await
                .unwrap()
                .status(),
            403,
            "{path}"
        );
    }
    assert!(
        local
            .get(format!("https://app.example.test:{}/", ports[1]))
            .send()
            .await
            .is_err(),
        "private app must not exist on public TLS ingress"
    );
    assert!(
        local
            .get(format!("https://manage.example.test:{}/", ports[2]))
            .send()
            .await
            .is_err(),
        "management must not exist on application ingress"
    );
    assert!(
        local
            .get(format!("https://app.example.test:{}/", ports[2]))
            .header("Host", "manage.example.test")
            .send()
            .await
            .is_err(),
        "known SNI must not bypass Host validation"
    );
    assert!(
        local
            .get(format!("https://app.example.test:{}/", ports[2]))
            .header("Host", "unknown.example.test")
            .send()
            .await
            .is_err(),
        "a reused TLS connection must not route an unknown Host"
    );
    let other = client(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
    assert_eq!(
        other
            .get(format!("https://app.example.test:{}/child", ports[2]))
            .header("X-Forwarded-For", "127.0.0.1")
            .header("X-Real-IP", "127.0.0.1")
            .header("Forwarded", "for=127.0.0.1")
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "a public child cannot widen a restricted site"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        allowed_hits,
        "denials must not reach the backend"
    );
    assert_eq!(
        local
            .get(format!(
                "https://app.example.test:{}/administrator",
                ports[2]
            ))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let before_mount = hits.load(Ordering::SeqCst);
    assert_eq!(
        local
            .get(format!("https://example.test:{}/mount/", ports[1]))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(hits.load(Ordering::SeqCst), before_mount + 1);
    assert_eq!(
        local
            .get(format!(
                "https://example.test:{}/mount/missing-page",
                ports[1]
            ))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "named SPA fallback must reach the shell"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        before_mount + 3,
        "a SPA miss must reach the backend once and retry the shell once"
    );
    let allowed_mount_hits = hits.load(Ordering::SeqCst);
    for path in [
        "/mount/",
        "/mount/missing-page",
        "/mount/nested/open",
        "/mount/Sessions",
    ] {
        assert_eq!(
            other
                .get(format!("https://example.test:{}{path}", ports[1]))
                .send()
                .await
                .unwrap()
                .status(),
            403,
            "domain restriction must protect {path}"
        );
    }
    assert_eq!(
        local
            .get(format!(
                "https://example.test:{}/mount/private/secret",
                ports[1]
            ))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        allowed_mount_hits,
        "denied mount and fallback requests must never reach an upstream"
    );
    assert_eq!(
        local
            .get(format!("https://example.test:{}/mount/Sessions", ports[1]))
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "generated Sessions keeps its explicit legacy restriction"
    );
    assert_eq!(
        local
            .get(format!(
                "https://manage.example.test:{}/restricted/missing",
                ports[3]
            ))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let route_hits = hits.load(Ordering::SeqCst);
    for path in ["/restricted/open", "/restricted/missing", "/Sessions"] {
        assert_eq!(
            other
                .get(format!("https://manage.example.test:{}{path}", ports[3]))
                .send()
                .await
                .unwrap()
                .status(),
            403,
            "route ancestors must protect {path}"
        );
    }
    assert_eq!(
        local
            .get(format!("https://manage.example.test:{}/Sessions", ports[3]))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        route_hits,
        "restricted nested routes, generated Sessions and SPA fallbacks cannot proxy denied clients"
    );
    let redirect = local
        .get(format!("http://example.test:{}/", ports[0]))
        .send()
        .await
        .unwrap();
    assert_eq!(redirect.status(), 301);
    assert_eq!(
        redirect.headers()["location"],
        format!("https://example.test:{}/", ports[1])
    );
    let wrong = local
        .get(format!("http://app.example.test:{}/", ports[0]))
        .send()
        .await;
    assert_eq!(
        wrong.unwrap().status(),
        404,
        "private certificate host is challenge-only"
    );
    assert!(
        local
            .get(format!("http://127.0.0.1:{}/", ports[0]))
            .header("Host", "unknown.invalid")
            .send()
            .await
            .is_err()
    );
    let unknown_log = config.nginx.log_dir.join("unknown-host.log");
    wait_until(|| {
        fs::read_to_string(&unknown_log)
            .is_ok_and(|content| content.contains("host=\"unknown.invalid\""))
    })
    .await;
    let app_forwarder = tcp_forwarder(ports[2]).await;
    let management_forwarder = tcp_forwarder(ports[3]).await;
    let forwarded_client = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .local_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
        .resolve(
            "app.example.test",
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), app_forwarder.port),
        )
        .resolve(
            "manage.example.test",
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), management_forwarder.port),
        )
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    assert_eq!(
        forwarded_client
            .get(format!("https://app.example.test:{}/", app_forwarder.port))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "TCP forwarding collapses the source to the allowed loopback peer; it does not identify the original client"
    );
    assert_eq!(
        forwarded_client
            .get(format!(
                "https://app.example.test:{}/budget",
                app_forwarder.port
            ))
            .header("X-Forwarded-For", "192.0.2.1")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let after_first_budget = hits.load(Ordering::SeqCst);
    assert_eq!(
        forwarded_client
            .get(format!(
                "https://manage.example.test:{}/budget",
                management_forwarder.port
            ))
            .header("X-Forwarded-For", "198.51.100.1")
            .send()
            .await
            .unwrap()
            .status(),
        429,
        "different forwarded users/sites share the named budget of their actual socket peer"
    );
    assert_eq!(hits.load(Ordering::SeqCst), after_first_budget);
    // A custom vhost can legally share port 80 with the redirect/challenge
    // vhost. nginx -t alone cannot establish challenge-only isolation.
    let custom_path = config.nginx.root_dir.join("conf.d/99-authored-http.conf");
    let custom_content = format!(
        "server {{ listen 127.0.0.1:{}; server_name authored.example.test; location / {{ return 200 'authored'; }} }}\n",
        ports[0]
    );
    fs::write(&custom_path, &custom_content).unwrap();
    let mut real_config = (**config).clone();
    real_config.test_mode = false;
    real_config.commands.nginx = nginx_bin.clone();
    real_config.commands.openssl = openssl;
    real_config.nginx.prefix_path = Some(config.nginx.root_dir.clone());
    let deployed = config
        .nginx
        .root_dir
        .join("certs/example_test/fullchain.pem");
    let renewed = deployed.with_file_name("renewed.pem");
    let output = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-days",
            "1",
            "-subj",
            "/CN=app.example.test",
            "-addext",
            "subjectAltName=DNS:app.example.test",
            "-key",
        ])
        .arg(deployed.with_file_name("privkey.pem"))
        .arg("-out")
        .arg(&renewed)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let renewal_dir = config.certificates.certs_dir.join("certs/example_test");
    fs::create_dir_all(&renewal_dir).unwrap();
    fs::copy(
        deployed.with_file_name("privkey.pem"),
        renewal_dir.join("privkey.pem"),
    )
    .unwrap();
    let dns_processor = config.paths.data_dir.join("dns-processor");
    fs::write(
        &dns_processor,
        format!(
            "#!/usr/bin/python3\nimport os\nos.replace({}, {})\n",
            serde_json::to_string(&renewed).unwrap(),
            serde_json::to_string(
                &config
                    .certificates
                    .certs_dir
                    .join("certs/example_test/fullchain.pem")
            )
            .unwrap()
        ),
    )
    .unwrap();
    fs::set_permissions(&dns_processor, fs::Permissions::from_mode(0o700)).unwrap();
    real_config.commands.dehydrated = dns_processor;
    let real_state = AppState::new(real_config, state.stores.clone(), state.firewall.clone());
    let app = api::app(real_state.clone()).unwrap();
    let (code, reply) = request(
        &app,
        "POST",
        "/nginx/objects/subdomain",
        json!({
            "domain":"example.test", "name":"old-public", "server_names":["app.example.test"],
            "upstream":upstream, "enabled":true, "settings":{"access_policy":"public"}
        }),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{reply}");
    let public_url = format!("https://app.example.test:{}/", ports[1]);
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if client(Ipv4Addr::LOCALHOST.into())
                .get(&public_url)
                .send()
                .await
                .is_ok_and(|response| response.status() == 200)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the staged public vhost must serve the app before removal");
    let (code, reply) = request(
        &app,
        "DELETE",
        "/nginx/objects/subdomain/example.test/old-public",
        json!(null),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{reply}");
    let private = client(Ipv4Addr::LOCALHOST.into());
    assert_eq!(
        private
            .get(format!("https://app.example.test:{}/", ports[2]))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if client(Ipv4Addr::LOCALHOST.into())
                .get(&public_url)
                .send()
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the public endpoint must stop serving the app after removal");
    let mut renewal_only = global.clone();
    renewal_only.http_access = Some(HttpAccess {
        mode: HttpMode::RenewalOnly,
        externally_managed_wan: true,
        ..Default::default()
    });
    let (code, reply) = request(
        &app,
        "PUT",
        "/nginx/settings",
        serde_json::to_value(&renewal_only).unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::CONFLICT, "{reply}");
    assert!(
        reply.to_string().contains("unmanaged HTTP listeners"),
        "{reply}"
    );
    assert_eq!(fs::read_to_string(custom_path).unwrap(), custom_content);
    assert_eq!(
        maestro::nginx_ingress::mode(&nginx_render::load_global(config).unwrap()),
        HttpMode::Always,
        "failed adoption must restore the legacy HTTP policy"
    );
    fs::remove_file(config.nginx.root_dir.join("conf.d/99-authored-http.conf")).unwrap();
    let (code, reply) = request(
        &app,
        "PUT",
        "/nginx/settings",
        serde_json::to_value(&renewal_only).unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{reply}");
    wait_until(|| std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0])).is_err()).await;
    certificate_http::begin(
        &real_state,
        &[certificate("challenge_only", CertificateMethod::Http)],
    )
    .await
    .unwrap()
    .unwrap();
    let token = config
        .certificates
        .certs_dir
        .join("acme-challenge/lab-token");
    fs::write(token, "challenge-response").unwrap();
    let http_client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let challenge = http_client
        .get(format!(
            "http://127.0.0.1:{}/.well-known/acme-challenge/lab-token",
            ports[0]
        ))
        .header("Host", "challenge-only.example.test")
        .send()
        .await
        .unwrap();
    assert_eq!(challenge.status(), 200);
    assert_eq!(challenge.text().await.unwrap(), "challenge-response");
    let during_challenge = hits.load(Ordering::SeqCst);
    assert_eq!(
        http_client
            .get(format!("http://127.0.0.1:{}/admin", ports[0]))
            .header("Host", "challenge-only.example.test")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert!(
        http_client
            .get(format!("http://127.0.0.1:{}/", ports[0]))
            .header("Host", "app.example.test")
            .send()
            .await
            .is_err(),
        "validation cannot expose a private application"
    );
    assert_eq!(hits.load(Ordering::SeqCst), during_challenge);
    // An out-of-band authored edit must not stop removal of our server or
    // permit a false closed-state report while the custom socket remains.
    let custom_path = config.nginx.root_dir.join("conf.d/99-authored-http.conf");
    fs::write(&custom_path, &custom_content).unwrap();
    let error = certificate_http::close(&real_state).await.unwrap_err();
    assert!(format!("{error:#}").contains("unmanaged HTTP listeners"));
    assert!(
        certificate_http::active(&real_state.config)
            .unwrap()
            .is_none()
    );
    assert!(
        !fs::read_to_string(&config.nginx.http_forwarder_path)
            .unwrap()
            .contains("listen")
    );
    assert_eq!(
        certificate_http::status(&real_state.config).unwrap().state,
        "cleanup_failed"
    );
    assert_eq!(fs::read_to_string(&custom_path).unwrap(), custom_content);
    fs::remove_file(custom_path).unwrap();
    certificate_http::close(&real_state).await.unwrap();
    wait_until(|| std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0])).is_err()).await;
    assert_eq!(
        local
            .get(format!("https://app.example.test:{}/", ports[2]))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "HTTP window cleanup must retain HTTPS application service"
    );
    let before = served_certificate(ports[2]).await;
    let renewed_pem = fs::read_to_string(&renewed).unwrap();
    let (code, spec) = request(
        &app,
        "POST",
        "/certificates",
        json!({
            "name":"example_test", "method":"dns", "domains":["app.example.test"]
        }),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{spec}");
    // A successful ACME command with invalid output must not replace the live certificate.
    let valid_processor = fs::read_to_string(&real_state.config.commands.dehydrated).unwrap();
    fs::write(&real_state.config.commands.dehydrated, format!(
        "#!/usr/bin/python3\nfrom pathlib import Path\nPath({}).write_text('invalid certificate')\n",
        serde_json::to_string(&renewal_dir.join("fullchain.pem")).unwrap()
    )).unwrap();
    let (code, _) = request(
        &app,
        "POST",
        &format!("/certificates/{}/renew", spec["id"].as_str().unwrap()),
        json!(null),
    )
    .await;
    assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(served_certificate(ports[2]).await, before);
    fs::write(&real_state.config.commands.dehydrated, valid_processor).unwrap();
    let (code, result) = request(
        &app,
        "POST",
        &format!("/certificates/{}/renew", spec["id"].as_str().unwrap()),
        json!(null),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{result}");
    assert_eq!(result["success"], true);
    let after = served_certificate(ports[2]).await;
    assert_ne!(after, before);
    assert_eq!(after, renewed_pem.trim());
    assert!(std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0])).is_err());
    assert!(
        client(Ipv4Addr::LOCALHOST.into())
            .get(format!("https://app.example.test:{}/", ports[1]))
            .send()
            .await
            .is_err()
    );
    backend_task.abort();
}

#[tokio::test]
async fn documented_ingress_inputs_validate_and_render() {
    let (_temp, state) = setup().await;
    fs::write(
        state.config.nginx.inputs_dir.join("nginx.toml"),
        include_str!("../config/nginx/examples/ingress.toml"),
    )
    .unwrap();
    fs::write(
        nginx_sites::path(&state.config),
        include_str!("../config/nginx/examples/ingress-sites.toml"),
    )
    .unwrap();
    let global = nginx_render::load_global(&state.config).unwrap();
    let mut sites = nginx_sites::load(&state.config).unwrap();
    maestro::nginx_ingress::validate_tree(&global, &sites).unwrap();
    let site = sites.sites.values().next().unwrap();
    let output = nginx_render::render_site(
        &global,
        &site.settings,
        site.kind,
        &site.domain,
        &site.object_name("app.example.test").unwrap(),
        &[],
    )
    .unwrap();
    assert!(output.contains("listen 127.0.0.2:19443 ssl"));
    assert!(output.contains("location = /admin"));
    assert!(output.contains("return 403"));
    let mut without_profile = global.clone();
    without_profile.listener_profiles.remove("private");
    assert!(
        maestro::nginx_ingress::runtime_files(&state.config, &without_profile).is_err(),
        "disabled sites still protect their profile references"
    );
    let legacy_settings = json!({"access_policy":"public", "disable_root":false})
        .as_object()
        .unwrap()
        .clone();
    let legacy_render = |settings: &GlobalSettings| {
        nginx_render::render_site(
            settings,
            &legacy_settings,
            NginxObjectKind::Domain,
            "legacy.example.test",
            "legacy.example.test",
            &[],
        )
        .unwrap()
    };
    assert_eq!(
        legacy_render(&global),
        legacy_render(&without_profile),
        "adding an unused profile must not change a legacy site's output"
    );
    let defaults_path = state
        .config
        .nginx
        .root_dir
        .join("ban-shield/default-drop.conf");
    assert!(
        maestro::nginx_ingress::runtime_files(&state.config, &global).unwrap()[&defaults_path]
            .contains("127.0.0.2:19443")
    );
    let mut duplicate = site.clone();
    duplicate.server_name = "APP.EXAMPLE.TEST".into();
    duplicate.domain = "alias.example.test".into();
    sites.sites.insert("alias.example.test".into(), duplicate);
    assert!(
        maestro::nginx_ingress::validate_tree(&global, &sites)
            .unwrap_err()
            .to_string()
            .contains("belongs to both")
    );
    fs::write(nginx_sites::path(&state.config), "[sites]\n").unwrap();
    let files = maestro::nginx_ingress::runtime_files(&state.config, &without_profile).unwrap();
    assert!(
        !files[&defaults_path].contains("127.0.0.2:19443"),
        "removing the last reference and profile removes its rejecting listener too"
    );
}

#[tokio::test]
async fn failed_challenge_readiness_cleans_up_before_running_acme() {
    let (_temp, base) = setup().await;
    let (state, probe) = processor(&base, 0.01).await;
    let mut global = nginx_render::with_path_defaults(globals(), &state.config);
    global.shared.insert("http_port".into(), json!(probe.port));
    // The port is no longer served: a successful nginx command alone must not
    // permit issuance through an unavailable challenge listener.
    drop(probe);
    nginx_render::FileTransaction::apply(
        &state.config,
        nginx_render::shared_files(&state.config, &global).unwrap(),
    )
    .unwrap()
    .commit();
    let error = certificate_http::begin(&state, &[certificate("unready", CertificateMethod::Http)])
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("readiness"), "{error:#}");
    assert!(certificate_http::active(&state.config).unwrap().is_none());
    assert!(
        !fs::read_to_string(&state.config.nginx.http_forwarder_path)
            .unwrap()
            .contains("listen")
    );
    assert!(!state.config.paths.data_dir.join("issued.jsonl").exists());
    let tokens = state.config.certificates.certs_dir.join("acme-challenge");
    assert!(fs::read_dir(tokens).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("router-hub-probe-")
    }));
}

#[tokio::test]
async fn batch_deadline_stops_work_and_does_not_restart_for_the_next_certificate() {
    let (_temp, base) = setup().await;
    let (mut state, probe) = processor(&base, 90.0).await;
    Arc::make_mut(&mut state.config)
        .certificates
        .command_timeout_seconds = 120;
    let mut global = nginx_render::with_path_defaults(globals(), &state.config);
    global.shared.insert("http_port".into(), json!(probe.port));
    global.http_access.as_mut().unwrap().window_seconds = 60;
    nginx_render::FileTransaction::apply(
        &state.config,
        nginx_render::shared_files(&state.config, &global).unwrap(),
    )
    .unwrap()
    .commit();
    state.stores.certificates.write().await.extend([
        certificate("first", CertificateMethod::Http),
        certificate("second", CertificateMethod::Http),
    ]);
    let started = std::time::Instant::now();
    state.start_certificate_renewal_loop();
    let log = state.config.paths.data_dir.join("issued.jsonl");
    wait_until(|| log.exists()).await;
    tokio::time::timeout(Duration::from_secs(75), async {
        while state.certificate_busy() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(58));
    assert!(started.elapsed() < Duration::from_secs(75));
    assert_eq!(
        fs::read_to_string(&log).unwrap().lines().count(),
        1,
        "the second job must not get a fresh command/window timeout"
    );
    assert!(certificate_http::active(&state.config).unwrap().is_none());
    assert_eq!(
        certificate_http::status(&state.config).unwrap().state,
        "closed"
    );
    assert!(
        !fs::read_to_string(&state.config.nginx.http_forwarder_path)
            .unwrap()
            .contains("listen")
    );
}
