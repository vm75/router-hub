//! CLI backups. Archive paths are relative to /; symlinks are preserved, not followed.
use std::{
    ffi::OsString,
    fs::{self, DirBuilder, OpenOptions},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use chrono::Local;
use uuid::Uuid;

use crate::{
    command::CommandRunner,
    config::{AppConfig, Platform},
};

fn output_directory(config: &AppConfig, config_path: &Path) -> PathBuf {
    if config.platform == Platform::Linux || config.test_mode {
        config_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        PathBuf::from("/tmp")
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    // Resolve the parent so relative configuration paths and /opt mount aliases
    // yield stable archive names, while leaving the final symlink intact.
    let parent = joined
        .parent()
        .context("cannot back up the filesystem root")?;
    Ok(parent
        .canonicalize()?
        .join(joined.file_name().context("missing backup input name")?))
}

fn inputs(config: &AppConfig, config_path: &Path) -> Result<Vec<PathBuf>> {
    ensure!(
        config_path.is_file(),
        "backup requires an existing configuration file: {}",
        config_path.display()
    );
    let config_path = absolute(config_path)?;
    let mut candidates = vec![
        config_path.parent().unwrap().to_path_buf(),
        config_path.clone(),
        std::env::current_exe()?,
        config.paths.data_dir.clone(),
        config.nginx.root_dir.clone(),
        config.nginx.inputs_dir.clone(),
        config.nginx.config_path.clone(),
        config.nginx.domains_available_dir.clone(),
        config.nginx.domains_enabled_dir.clone(),
        config.nginx.subdomain_upstream_map_path.clone(),
        config.nginx.domain_upstream_map_path.clone(),
        config.nginx.subfolder_upstream_map_path.clone(),
        config.nginx.http_forwarder_path.clone(),
        config.certificates.certs_dir.clone(),
        config.commands.dehydrated.clone(),
        config.certificates.dns01_hook.clone(),
        config.services.init_dir.join("S99maestro"),
    ];
    if config.platform == Platform::Asuswrt {
        candidates.extend([
            config.paths.jffs_scripts_dir.clone(),
            config.paths.hosts_add.clone(),
            config.paths.dnsmasq_conf_add.clone(),
        ]);
    }
    let mut paths = Vec::new();
    for candidate in candidates {
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                paths.push(absolute(&candidate)?);
                // Include targets of explicitly configured roots (for example a
                // symlinked certificate store), but never follow nested links.
                if metadata.file_type().is_symlink() {
                    match candidate.canonicalize() {
                        Ok(target) => paths.push(target),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(error).context("cannot resolve backup input symlink");
                        }
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot inspect {}", candidate.display()));
            }
        }
    }
    paths.sort();
    paths.dedup();
    // Do not archive a subtree twice when configuration and state share a directory.
    let mut roots = Vec::<PathBuf>::new();
    for path in paths {
        if !roots
            .iter()
            .any(|root| path.starts_with(root) && root.is_dir() && !root.is_symlink())
        {
            roots.push(path);
        }
    }
    Ok(roots)
}

struct Staging(PathBuf);

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub async fn run(config: &AppConfig, config_path: &Path, output_dir: Option<&Path>) -> Result<()> {
    let directory = output_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| output_directory(config, config_path));
    let filename = format!(
        "maestro-backup-{}.tar.gz",
        Local::now().format("%Y%m%d-%H%M%S")
    );
    let target = directory.join(filename);
    if config.test_mode {
        println!("SIMULATED: would create backup {}", target.display());
        return Ok(());
    }
    let sources = inputs(config, config_path)?;
    let directory = directory
        .canonicalize()
        .context("backup output directory must exist")?;
    let target = directory.join(target.file_name().unwrap());
    let staging = directory.join(format!(".maestro-backup-{}", Uuid::new_v4()));
    DirBuilder::new().mode(0o700).create(&staging)?;
    let staging = Staging(staging);
    let archive = staging.0.join("archive.tar.gz");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&archive)?;
    let mut args: Vec<OsString> = vec![
        "-czf".into(),
        archive.as_os_str().into(),
        "--exclude=maestro-backup-*.tar.gz".into(),
        "--exclude=.maestro-backup-*".into(),
        "-C".into(),
        "/".into(),
        "--".into(),
    ];
    for path in sources {
        args.push(path.strip_prefix("/")?.as_os_str().into());
    }
    let result = CommandRunner::new(false)
        .run_process_group(&config.commands.tar, args, Duration::from_secs(300))
        .await
        .context("unable to create backup archive")?;
    ensure!(result.success, "backup archive failed: {}", result.stderr);
    ensure!(file.metadata()?.len() > 0, "backup archive is empty");
    file.sync_all()?;
    // hard_link publishes atomically without replacing a same-second backup or symlink.
    publish(&archive, &target)?;
    println!("Backup created: {}", target.display());
    Ok(())
}

fn publish(archive: &Path, target: &Path) -> Result<()> {
    fs::hard_link(archive, target).with_context(|| {
        format!(
            "cannot publish backup {}; existing backups are never overwritten",
            target.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };

    fn fixture(base: &Path) -> (AppConfig, PathBuf) {
        let config_dir = base.join("config with spaces");
        fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("router-hub.toml");
        fs::write(&config_path, "secret-token").unwrap();
        let mut config = AppConfig {
            platform: Platform::Linux,
            ..AppConfig::default()
        };
        config.paths.data_dir = config_dir.join("state");
        config.nginx.root_dir = base.join("nginx");
        config.nginx.inputs_dir = config_dir.join("nginx");
        config.nginx.config_path = config.nginx.root_dir.join("nginx.conf");
        config.nginx.domains_available_dir = config.nginx.root_dir.join("available");
        config.nginx.domains_enabled_dir = config.nginx.root_dir.join("enabled");
        config.nginx.subdomain_upstream_map_path = base.join("missing-map1");
        config.nginx.domain_upstream_map_path = base.join("missing-map2");
        config.nginx.subfolder_upstream_map_path = base.join("missing-map3");
        config.nginx.http_forwarder_path = base.join("missing-forwarder");
        config.certificates.certs_dir = base.join("certificates");
        config.commands.dehydrated = base.join("missing-dehydrated");
        config.services.init_dir = base.join("init.d");
        for directory in [
            &config.paths.data_dir,
            &config.nginx.root_dir,
            &config.certificates.certs_dir,
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(config.paths.data_dir.join("state.json"), "persistent-state").unwrap();
        fs::write(&config.nginx.config_path, "nginx-config").unwrap();
        fs::write(config.certificates.certs_dir.join("key.pem"), "private-key").unwrap();
        (config, config_path)
    }

    #[test]
    fn platform_destinations_and_test_override() {
        let mut config = AppConfig::default();
        let path = Path::new("/lab/config/router-hub.toml");
        assert_eq!(output_directory(&config, path), Path::new("/tmp"));
        config.platform = Platform::Linux;
        assert_eq!(output_directory(&config, path), Path::new("/lab/config"));
        assert_eq!(
            output_directory(&config, Path::new("router-hub.toml")),
            Path::new(".")
        );
        config.platform = Platform::Asuswrt;
        config.test_mode = true;
        assert_eq!(output_directory(&config, path), Path::new("/lab/config"));
    }

    #[test]
    fn publication_never_overwrites_an_existing_backup_or_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("archive");
        let target = temp.path().join("backup.tar.gz");
        let secret = temp.path().join("secret");
        fs::write(&archive, "new backup").unwrap();
        fs::write(&target, "old backup").unwrap();
        assert!(publish(&archive, &target).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "old backup");
        fs::remove_file(&target).unwrap();
        fs::write(&secret, "secret").unwrap();
        symlink(&secret, &target).unwrap();
        assert!(publish(&archive, &target).is_err());
        assert_eq!(fs::read_to_string(&secret).unwrap(), "secret");
        assert!(target.is_symlink());
    }

    #[test]
    fn configured_router_hooks_and_symlinked_certificate_store_are_included() {
        let temp = tempfile::tempdir().unwrap();
        let (mut config, path) = fixture(temp.path());
        config.paths.jffs_scripts_dir = temp.path().join("jffs-scripts");
        config.paths.hosts_add = temp.path().join("hosts.add");
        config.paths.dnsmasq_conf_add = temp.path().join("dnsmasq.conf.add");
        fs::create_dir(&config.paths.jffs_scripts_dir).unwrap();
        fs::write(&config.paths.hosts_add, "hosts").unwrap();
        fs::write(&config.paths.dnsmasq_conf_add, "dnsmasq").unwrap();
        let cert_target = temp.path().join("certificate-target");
        fs::rename(&config.certificates.certs_dir, &cert_target).unwrap();
        symlink(&cert_target, &config.certificates.certs_dir).unwrap();
        let linux_inputs = inputs(&config, &path).unwrap();
        assert!(linux_inputs.contains(&cert_target));
        assert!(linux_inputs.contains(&config.certificates.certs_dir));
        assert!(!linux_inputs.contains(&config.paths.jffs_scripts_dir));
        config.platform = Platform::Asuswrt;
        let router_inputs = inputs(&config, &path).unwrap();
        for expected in [
            &config.paths.jffs_scripts_dir,
            &config.paths.hosts_add,
            &config.paths.dnsmasq_conf_add,
        ] {
            assert!(router_inputs.contains(expected));
        }
    }

    #[tokio::test]
    async fn real_archive_preserves_data_and_links_excludes_backups_and_is_private() {
        let temp = tempfile::tempdir().unwrap();
        let (config, path) = fixture(temp.path());
        let parent = path.parent().unwrap();
        fs::write(
            parent.join("maestro-backup-20000101-000000.tar.gz"),
            "old backup",
        )
        .unwrap();
        symlink("nginx.conf", config.nginx.root_dir.join("enabled.conf")).unwrap();
        run(&config, &path, None).await.unwrap();
        let backup = fs::read_dir(parent)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("maestro-backup-")
                    && !p
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .contains("20000101")
            })
            .unwrap();
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let extract = temp.path().join("extract");
        fs::create_dir(&extract).unwrap();
        assert!(
            Command::new("/bin/tar")
                .arg("-xzf")
                .arg(&backup)
                .arg("-C")
                .arg(&extract)
                .status()
                .unwrap()
                .success()
        );
        let restored = |p: &Path| extract.join(p.strip_prefix("/").unwrap());
        assert_eq!(fs::read_to_string(restored(&path)).unwrap(), "secret-token");
        assert_eq!(
            fs::read_to_string(restored(&config.paths.data_dir.join("state.json"))).unwrap(),
            "persistent-state"
        );
        assert_eq!(
            fs::read_to_string(restored(&config.certificates.certs_dir.join("key.pem"))).unwrap(),
            "private-key"
        );
        assert_eq!(
            fs::read_link(restored(&config.nginx.root_dir.join("enabled.conf"))).unwrap(),
            Path::new("nginx.conf")
        );
        assert!(!restored(&parent.join("maestro-backup-20000101-000000.tar.gz")).exists());
        assert!(
            fs::metadata(restored(&std::env::current_exe().unwrap()))
                .unwrap()
                .len()
                > 0
        );
        assert!(!fs::read_dir(parent).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".maestro-backup-")
        }));
    }

    #[tokio::test]
    async fn failures_and_simulation_do_not_publish_an_archive() {
        let temp = tempfile::tempdir().unwrap();
        let (mut config, path) = fixture(temp.path());
        config.commands.tar = PathBuf::from("/bin/false");
        assert!(run(&config, &path, None).await.is_err());
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
        config.test_mode = true;
        run(&config, &path, None).await.unwrap();
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
    }
}
