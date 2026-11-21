//! Validate and stage archives before restoring with descriptor-relative writes.
use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read},
    os::{
        fd::OwnedFd,
        unix::fs::{DirBuilderExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use flate2::read::MultiGzDecoder;
use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use uuid::Uuid;

const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone)]
enum Contents {
    Directory,
    File(PathBuf),
    Symlink(PathBuf),
    Hardlink(PathBuf),
}

#[derive(Clone)]
struct Item {
    mode: u32,
    contents: Contents,
}

struct Staging(PathBuf);

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn relative(path: &Path) -> Result<PathBuf> {
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(name) => result.push(name),
            Component::CurDir => {}
            _ => bail!("unsafe archive path: {}", path.display()),
        }
    }
    ensure!(!result.as_os_str().is_empty(), "empty archive path");
    Ok(result)
}

fn stage(archive: &Path, directory: &Path) -> Result<BTreeMap<PathBuf, Item>> {
    let compressed = File::open(archive).context("cannot open backup archive")?;
    let mut archive = tar::Archive::new(MultiGzDecoder::new(compressed).take(MAX_BYTES + 1));
    let mut items = BTreeMap::new();
    let mut bytes = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        ensure!(
            items.len() < MAX_ENTRIES,
            "backup exceeds {MAX_ENTRIES} entries"
        );
        let path = relative(&entry.path()?)?;
        ensure!(
            !items.contains_key(&path),
            "duplicate archive path: {}",
            path.display()
        );
        let kind = entry.header().entry_type();
        let mode = entry.header().mode()? & if kind.is_dir() { 0o1777 } else { 0o777 };
        let contents = if kind.is_dir() {
            ensure!(entry.size() == 0, "directory contains unexpected data");
            Contents::Directory
        } else if kind.is_file() {
            bytes = bytes
                .checked_add(entry.size())
                .context("archive size overflow")?;
            ensure!(bytes <= MAX_BYTES, "backup exceeds 2 GiB uncompressed");
            let source = directory.join(items.len().to_string());
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&source)?;
            let copied = io::copy(&mut entry, &mut file)?;
            ensure!(
                copied == entry.size(),
                "truncated backup file: {}",
                path.display()
            );
            Contents::File(source)
        } else if kind.is_symlink() || kind.is_hard_link() {
            ensure!(entry.size() == 0, "link contains unexpected data");
            let link = entry
                .link_name()?
                .context("archive link has no target")?
                .into_owned();
            if kind.is_symlink() {
                ensure!(!link.as_os_str().is_empty(), "empty symlink target");
                Contents::Symlink(link)
            } else {
                Contents::Hardlink(relative(&link)?)
            }
        } else {
            bail!("unsupported archive entry type at {}", path.display());
        };
        items.insert(path, Item { mode, contents });
    }
    // Consume the gzip trailer as well, so CRC/truncation errors cannot be hidden
    // behind tar's end marker. Bound headers, padding and trailing bytes too.
    let mut reader = archive.into_inner();
    io::copy(&mut reader, &mut io::sink())?;
    ensure!(reader.limit() > 0, "backup exceeds 2 GiB uncompressed");
    ensure!(!items.is_empty(), "backup archive is empty");
    for (path, item) in &items {
        for ancestor in path.ancestors().skip(1) {
            if let Some(parent) = items.get(ancestor) {
                ensure!(
                    matches!(parent.contents, Contents::Directory),
                    "archive writes through a non-directory: {}",
                    ancestor.display()
                );
            }
        }
        if let Contents::Hardlink(target) = &item.contents {
            ensure!(
                matches!(
                    items.get(target).map(|i| &i.contents),
                    Some(Contents::File(_))
                ),
                "hard link must reference an archived regular file: {}",
                target.display()
            );
        }
    }
    // Hard links are restored as independent files; never link to live filesystem data.
    for path in items.keys().cloned().collect::<Vec<_>>() {
        if let Contents::Hardlink(target) = &items[&path].contents {
            let source = items[target].clone();
            items.insert(path, source);
        }
    }
    Ok(items)
}

struct Destination(OwnedFd);

impl Destination {
    fn parent(&self, path: &Path, create: bool) -> Result<Option<OwnedFd>> {
        let mut directory = rfs::openat(&self.0, ".", DIR_FLAGS, Mode::empty())?;
        for name in path.parent().unwrap().components() {
            let name = name.as_os_str();
            directory = match rfs::openat(&directory, name, DIR_FLAGS, Mode::empty()) {
                Ok(fd) => fd,
                Err(Errno::NOENT) if !create => return Ok(None),
                Err(Errno::NOENT) => {
                    match rfs::mkdirat(&directory, name, Mode::from_raw_mode(0o700)) {
                        Ok(()) | Err(Errno::EXIST) => {}
                        Err(error) => return Err(error.into()),
                    }
                    rfs::openat(&directory, name, DIR_FLAGS, Mode::empty())?
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("restore parent is not a real directory: {}", path.display())
                    });
                }
            };
        }
        Ok(Some(directory))
    }

    fn check(&self, path: &Path, item: &Item) -> Result<()> {
        let Some(parent) = self.parent(path, false)? else {
            return Ok(());
        };
        match rfs::statat(
            &parent,
            path.file_name().unwrap(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => {
                let kind = FileType::from_raw_mode(stat.st_mode);
                let compatible = if matches!(item.contents, Contents::Directory) {
                    kind == FileType::Directory
                } else {
                    kind == FileType::RegularFile || kind == FileType::Symlink
                };
                ensure!(
                    compatible,
                    "restore destination type conflict: {}",
                    path.display()
                );
                Ok(())
            }
            Err(Errno::NOENT) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn write(&self, path: &Path, item: &Item) -> Result<()> {
        let parent = self.parent(path, true)?.unwrap();
        let name = path.file_name().unwrap();
        if matches!(item.contents, Contents::Directory) {
            match rfs::mkdirat(&parent, name, Mode::from_raw_mode(0o700)) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            // Verify even an existing entry without following a symlink.
            rfs::openat(&parent, name, DIR_FLAGS, Mode::empty())?;
            return Ok(());
        }
        let temporary = format!(".maestro-restore-{}", Uuid::new_v4());
        let result = (|| -> Result<()> {
            match &item.contents {
                Contents::File(source) => {
                    let fd = rfs::openat(
                        &parent,
                        &temporary,
                        OFlags::WRONLY
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC,
                        Mode::from_raw_mode(0o600),
                    )?;
                    let mut file = File::from(fd);
                    io::copy(&mut File::open(source)?, &mut file)?;
                    rfs::fchmod(&file, Mode::from_raw_mode(item.mode))?;
                    file.sync_all()?;
                }
                Contents::Symlink(target) => rfs::symlinkat(target, &parent, &temporary)?,
                _ => unreachable!("directories and hard links handled earlier"),
            }
            rfs::renameat(&parent, &temporary, &parent, name)?;
            rfs::fsync(&parent)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = rfs::unlinkat(&parent, &temporary, AtFlags::empty());
        }
        result
    }
}

pub fn run(archive: &Path, root: &Path, test_mode: bool) -> Result<()> {
    let root = root
        .canonicalize()
        .context("restore root must be an existing directory")?;
    let destination = Destination(rfs::open(&root, DIR_FLAGS, Mode::empty())?);
    let staging = std::env::temp_dir().join(format!(".maestro-restore-{}", Uuid::new_v4()));
    DirBuilder::new().mode(0o700).create(&staging)?;
    let staging = Staging(staging);
    let items =
        stage(archive, &staging.0).context("backup validation failed; nothing was restored")?;
    for (path, item) in &items {
        destination
            .check(path, item)
            .with_context(|| format!("cannot restore {}; nothing was restored", path.display()))?;
    }
    if test_mode {
        println!(
            "SIMULATED: validated {} entries for restore beneath {}",
            items.len(),
            root.display()
        );
        return Ok(());
    }
    for (path, item) in &items {
        destination.write(path, item).with_context(|| {
            format!(
                "restore failed at {}; earlier entries may have been restored",
                path.display()
            )
        })?;
    }
    // Apply restrictive directory modes only after their children are restored.
    for (path, item) in items.iter().rev() {
        if matches!(item.contents, Contents::Directory) {
            let parent = destination
                .parent(path, false)?
                .context("restored directory disappeared")?;
            let directory =
                rfs::openat(&parent, path.file_name().unwrap(), DIR_FLAGS, Mode::empty())?;
            rfs::fchmod(&directory, Mode::from_raw_mode(item.mode))?;
        }
    }
    println!(
        "Restored {} entries beneath {}. Review configuration before starting services.",
        items.len(),
        root.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::{
        io::Write,
        os::unix::fs::{PermissionsExt, symlink},
    };

    fn archive(path: &Path, entries: &[(&str, u8, &str)]) {
        let gzip = GzEncoder::new(File::create(path).unwrap(), Compression::fast());
        let mut tar = tar::Builder::new(gzip);
        for (name, kind, value) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::new(*kind));
            header.set_mode(if *kind == b'5' { 0o1750 } else { 0o6640 });
            let data = if *kind == b'0' { value.as_bytes() } else { &[] };
            header.set_size(data.len() as u64);
            if *kind == b'1' || *kind == b'2' {
                header.set_link_name(value).unwrap();
            }
            // Raw names deliberately let adversarial fixtures contain paths the
            // normal tar builder refuses to generate.
            header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            tar.append(&header, data).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn restore_replaces_files_and_symlinks_preserves_modes_and_materializes_hardlinks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("restored");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("config")).unwrap();
        fs::write(root.join("config/settings"), "old").unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, "untouched").unwrap();
        symlink(&outside, root.join("config/key")).unwrap();
        let backup = temp.path().join("backup.tar.gz");
        archive(
            &backup,
            &[
                ("config", b'5', ""),
                ("config/settings", b'0', "restored"),
                ("config/key", b'0', "private-key"),
                ("config/enabled", b'2', "settings"),
                ("config/duplicate", b'1', "config/settings"),
            ],
        );
        run(&backup, &root, false).unwrap();
        assert_eq!(
            fs::read_to_string(root.join("config/settings")).unwrap(),
            "restored"
        );
        assert_eq!(
            fs::read_to_string(root.join("config/key")).unwrap(),
            "private-key"
        );
        assert_eq!(
            fs::read_to_string(root.join("config/duplicate")).unwrap(),
            "restored"
        );
        assert_eq!(fs::read_to_string(&outside).unwrap(), "untouched");
        assert_eq!(
            fs::read_link(root.join("config/enabled")).unwrap(),
            Path::new("settings")
        );
        assert_eq!(
            fs::metadata(root.join("config"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o1750
        );
        assert_eq!(
            fs::metadata(root.join("config/settings"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        assert!(!root.join("config/key").is_symlink());
    }

    #[test]
    fn invalid_archives_and_symlink_parents_leave_destinations_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("sentinel"), "original").unwrap();
        let backup = temp.path().join("backup.tar.gz");
        let invalid = [
            vec![("sentinel", b'0', "changed"), ("../escape", b'0', "bad")],
            vec![("sentinel", b'0', "changed"), ("/absolute", b'0', "bad")],
            vec![
                ("sentinel", b'0', "changed"),
                ("sentinel", b'0', "duplicate"),
            ],
            vec![("sentinel", b'0', "changed"), ("device", b'3', "")],
            vec![
                ("sentinel", b'0', "changed"),
                ("link", b'2', "../outside"),
                ("link/file", b'0', "bad"),
            ],
            vec![
                ("sentinel", b'0', "changed"),
                ("hardlink", b'1', "../outside"),
            ],
            vec![("sentinel", b'0', "changed"), ("hardlink", b'1', "missing")],
            vec![
                ("sentinel", b'0', "changed"),
                ("sentinel/child", b'0', "bad"),
            ],
        ];
        for entries in invalid {
            archive(&backup, &entries);
            assert!(run(&backup, &root, false).is_err());
            assert_eq!(
                fs::read_to_string(root.join("sentinel")).unwrap(),
                "original"
            );
            assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        }
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, root.join("link")).unwrap();
        archive(
            &backup,
            &[("sentinel", b'0', "changed"), ("link/file", b'0', "bad")],
        );
        assert!(run(&backup, &root, false).is_err());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        assert_eq!(
            fs::read_to_string(root.join("sentinel")).unwrap(),
            "original"
        );
    }

    #[test]
    fn corrupt_gzip_and_simulated_restore_never_write_destination_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let backup = temp.path().join("backup.tar.gz");
        archive(&backup, &[("file", b'0', "contents")]);
        run(&backup, &root, true).unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        let mut bytes = fs::read(&backup).unwrap();
        let trailer = bytes.len() - 8;
        bytes[trailer] ^= 1;
        fs::write(&backup, &bytes).unwrap();
        assert!(run(&backup, &root, false).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        File::create(&backup)
            .unwrap()
            .write_all(&bytes[..bytes.len() - 12])
            .unwrap();
        assert!(run(&backup, &root, false).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn real_backup_restores_into_an_isolated_tree() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join("config");
        fs::create_dir(&config_dir).unwrap();
        let config_path = config_dir.join("router-hub.toml");
        fs::write(&config_path, "original config").unwrap();
        let mut config = crate::config::AppConfig::default();
        config.apply_test_mode(&config_path).unwrap();
        config.test_mode = false;
        config.platform = crate::config::Platform::Linux;
        crate::backup::run(&config, &config_path, None)
            .await
            .unwrap();
        let backup = fs::read_dir(&config_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "gz"))
            .unwrap();
        fs::write(&config_path, "changed config").unwrap();
        let root = temp.path().join("restored");
        fs::create_dir(&root).unwrap();
        run(&backup, &root, false).unwrap();
        assert_eq!(
            fs::read_to_string(root.join(config_path.strip_prefix("/").unwrap())).unwrap(),
            "original config"
        );
        assert_eq!(fs::read_to_string(&config_path).unwrap(), "changed config");
    }
}
