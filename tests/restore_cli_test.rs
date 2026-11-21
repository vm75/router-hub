use std::{fs, process::Command};

#[test]
fn restore_works_with_corrupt_configuration_and_test_mode_leaves_destination_untouched() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("broken.toml");
    fs::write(&config, "not valid TOML [[[\n").unwrap();
    let root = temp.path().join("restore");
    fs::create_dir(&root).unwrap();
    let backup = temp.path().join("backup.tar.gz");
    let gzip = flate2::write::GzEncoder::new(
        fs::File::create(&backup).unwrap(),
        flate2::Compression::fast(),
    );
    let mut tar = tar::Builder::new(gzip);
    let contents = b"recovered settings";
    let mut header = tar::Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    tar.append_data(&mut header, "etc/router-hub/router-hub.toml", &contents[..])
        .unwrap();
    tar.into_inner().unwrap().finish().unwrap();

    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_maestro"));
        command
            .arg("--config")
            .arg(&config)
            .arg("restore")
            .arg(&backup)
            .arg("--root")
            .arg(&root);
        command
    };
    let simulated = command().arg("--test-mode").output().unwrap();
    assert!(
        simulated.status.success(),
        "{}",
        String::from_utf8_lossy(&simulated.stderr)
    );
    assert!(String::from_utf8_lossy(&simulated.stdout).contains("SIMULATED"));
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);

    let restored = command().output().unwrap();
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_eq!(
        fs::read(root.join("etc/router-hub/router-hub.toml")).unwrap(),
        contents
    );
}

#[test]
fn update_dehydrated_cli_simulates_in_test_mode() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("router-hub.toml");
    fs::write(
        &config,
        "[commands]\ndehydrated = \"/opt/var/lib/router-hub/dehydrated/dehydrated\"\n",
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_maestro"));
    command
        .arg("--config")
        .arg(&config)
        .arg("--test-mode")
        .arg("update-dehydrated");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("simulated download of dehydrated"));
}
