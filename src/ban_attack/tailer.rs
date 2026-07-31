use std::{
    collections::{HashMap, HashSet},
    fs::{File, Metadata},
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::ban_attack::{StartAt, compiled::CompiledFile};

const ANCHOR_BYTES: usize = 64;
const RETIRED_IDLE_POLLS: u8 = 2;
#[cfg(test)]
const DEFAULT_MAX_READ_BYTES_PER_FILE_POLL: usize = 256 * 1024;
#[cfg(test)]
const DEFAULT_MAX_LINES_PER_FILE_POLL: usize = 1_000;
#[cfg(test)]
const DEFAULT_MAX_LINE_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileId {
    device: u64,
    inode: u64,
}

impl FileId {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct OpenFile {
    file: File,
    id: FileId,
    offset: u64,
    pending: Vec<u8>,
    anchor: Vec<u8>,
    last_len: u64,
    last_modified: Option<SystemTime>,
    idle_polls: u8,
    discarding_long_line: bool,
    dropped_line_count: u64,
}

#[derive(Default)]
struct PathState {
    active: Option<OpenFile>,
    retired: Vec<OpenFile>,
    initialized: bool,
}

#[derive(Default)]
pub(crate) struct Tailer {
    paths: HashMap<PathBuf, PathState>,
}

impl Tailer {
    pub fn dropped_line_count(&self) -> u64 {
        self.paths
            .values()
            .map(|state| {
                state
                    .active
                    .as_ref()
                    .map_or(0, |file| file.dropped_line_count)
                    + state
                        .retired
                        .iter()
                        .map(|file| file.dropped_line_count)
                        .sum::<u64>()
            })
            .sum()
    }
    pub fn sync(&mut self, files: &[CompiledFile]) {
        let configured: HashSet<PathBuf> = files.iter().map(|file| file.path.clone()).collect();
        self.paths.retain(|path, _| configured.contains(path));

        for file in files {
            let state = self.paths.entry(file.path.clone()).or_default();
            if state.active.is_none() {
                if let Ok(open) = OpenFile::open(&file.path, file.start_at) {
                    state.active = Some(open);
                }
                state.initialized = true;
            }
        }
    }

    #[cfg(test)]
    pub fn read_lines(&mut self, path: &Path, initial_start: StartAt) -> io::Result<Vec<Vec<u8>>> {
        self.read_lines_bounded(
            path,
            initial_start,
            DEFAULT_MAX_READ_BYTES_PER_FILE_POLL,
            DEFAULT_MAX_LINES_PER_FILE_POLL,
            DEFAULT_MAX_LINE_BYTES,
        )
    }

    pub fn read_lines_bounded(
        &mut self,
        path: &Path,
        initial_start: StartAt,
        max_bytes: usize,
        max_lines: usize,
        max_line_bytes: usize,
    ) -> io::Result<Vec<Vec<u8>>> {
        let state = self.paths.entry(path.to_path_buf()).or_default();
        let path_metadata = match std::fs::metadata(path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };

        if path_metadata.is_none() {
            if let Some(old) = state.active.take() {
                state.retired.push(old);
            }
        }

        if let Some(metadata) = path_metadata.as_ref() {
            if state.active.is_none() {
                let start_at = if state.initialized {
                    StartAt::Beginning
                } else {
                    initial_start
                };
                state.active = Some(OpenFile::open(path, start_at)?);
                state.initialized = true;
            } else {
                let current_id = FileId::from_metadata(metadata);
                let rotated = state
                    .active
                    .as_ref()
                    .is_some_and(|active| active.id != current_id);
                if rotated {
                    let old = state.active.take().expect("active file exists");
                    state.retired.push(old);
                    state.active = Some(OpenFile::open(path, StartAt::Beginning)?);
                } else if let Some(active) = &mut state.active {
                    if active.was_rewritten(metadata)? {
                        active.reset(metadata);
                    }
                }
            }
        }

        let mut lines = Vec::new();
        let mut remaining_bytes = max_bytes;

        let mut retained = Vec::with_capacity(state.retired.len());
        for mut retired in state.retired.drain(..) {
            if remaining_bytes == 0 || lines.len() >= max_lines {
                retained.push(retired);
                continue;
            }
            let (read_any, consumed) = retired.read_complete_lines(
                &mut lines,
                remaining_bytes,
                max_lines,
                max_line_bytes,
            )?;
            remaining_bytes = remaining_bytes.saturating_sub(consumed);
            if read_any {
                retired.idle_polls = 0;
            } else {
                retired.idle_polls = retired.idle_polls.saturating_add(1);
            }

            if retired.idle_polls >= RETIRED_IDLE_POLLS {
                if !retired.pending.is_empty() {
                    lines.push(trim_line_ending(std::mem::take(&mut retired.pending)));
                }
            } else {
                retained.push(retired);
            }
        }
        state.retired = retained;

        if let Some(active) = &mut state.active {
            if remaining_bytes > 0 && lines.len() < max_lines {
                active.read_complete_lines(
                    &mut lines,
                    remaining_bytes,
                    max_lines,
                    max_line_bytes,
                )?;
            }
        }

        Ok(lines)
    }
}

impl OpenFile {
    fn open(path: &Path, start_at: StartAt) -> io::Result<Self> {
        let before = std::fs::symlink_metadata(path)?;
        if before.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("symlink log path: {}", path.display()),
            ));
        }
        if !before.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", path.display()),
            ));
        }
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || FileId::from_metadata(&before) != FileId::from_metadata(&metadata)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} changed while it was opened", path.display()),
            ));
        }
        let offset = match start_at {
            StartAt::Beginning => 0,
            StartAt::End => metadata.len(),
        };
        let anchor = read_anchor(&mut file, offset)?;

        Ok(Self {
            file,
            id: FileId::from_metadata(&metadata),
            offset,
            pending: Vec::new(),
            anchor,
            last_len: metadata.len(),
            last_modified: metadata.modified().ok(),
            idle_polls: 0,
            discarding_long_line: false,
            dropped_line_count: 0,
        })
    }

    fn reset(&mut self, metadata: &Metadata) {
        self.offset = 0;
        self.pending.clear();
        self.anchor.clear();
        self.last_len = metadata.len();
        self.last_modified = metadata.modified().ok();
        self.idle_polls = 0;
        self.discarding_long_line = false;
    }

    fn was_rewritten(&mut self, metadata: &Metadata) -> io::Result<bool> {
        if metadata.len() < self.offset {
            return Ok(true);
        }

        let modified = metadata.modified().ok();
        if metadata.len() == self.last_len && modified == self.last_modified {
            return Ok(false);
        }
        if self.anchor.is_empty() {
            return Ok(false);
        }

        let start = self.offset.saturating_sub(self.anchor.len() as u64);
        self.file.seek(SeekFrom::Start(start))?;
        let mut actual = vec![0; self.anchor.len()];
        if self.file.read_exact(&mut actual).is_err() {
            return Ok(true);
        }
        Ok(actual != self.anchor)
    }

    fn read_complete_lines(
        &mut self,
        output: &mut Vec<Vec<u8>>,
        max_bytes: usize,
        max_lines: usize,
        max_line_bytes: usize,
    ) -> io::Result<(bool, usize)> {
        self.file.seek(SeekFrom::Start(self.offset))?;
        let mut bytes = vec![0; max_bytes];
        let count = self.file.read(&mut bytes)?;
        bytes.truncate(count);
        let read_any = !bytes.is_empty();
        let mut consumed = 0usize;
        for byte in bytes {
            if output.len() >= max_lines {
                break;
            }
            consumed += 1;
            self.offset = self.offset.saturating_add(1);
            if self.discarding_long_line {
                if byte == b'\n' {
                    self.discarding_long_line = false;
                }
                continue;
            }
            if byte == b'\n' {
                output.push(trim_line_ending(std::mem::take(&mut self.pending)));
            } else if self.pending.len() < max_line_bytes {
                self.pending.push(byte);
            } else {
                self.pending.clear();
                self.discarding_long_line = true;
                self.dropped_line_count = self.dropped_line_count.saturating_add(1);
            }
        }

        let metadata = self.file.metadata()?;
        self.last_len = metadata.len();
        self.last_modified = metadata.modified().ok();
        if read_any {
            self.anchor = read_anchor(&mut self.file, self.offset)?;
        }
        Ok((read_any, consumed))
    }
}

fn read_anchor(file: &mut File, offset: u64) -> io::Result<Vec<u8>> {
    let length = usize::try_from(offset.min(ANCHOR_BYTES as u64)).unwrap_or(ANCHOR_BYTES);
    if length == 0 {
        return Ok(Vec::new());
    }
    file.seek(SeekFrom::Start(offset - length as u64))?;
    let mut anchor = vec![0; length];
    file.read_exact(&mut anchor)?;
    Ok(anchor)
}

fn trim_line_ending(mut line: Vec<u8>) -> Vec<u8> {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    line
}

#[cfg(test)]
mod tests {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::symlink};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn detects_truncate_and_rewrite_without_replaying_old_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("app.log");
        std::fs::write(&path, b"old\n").unwrap();

        let mut tailer = Tailer::default();
        assert_eq!(
            tailer.read_lines(&path, StartAt::Beginning).unwrap(),
            vec![b"old".to_vec()]
        );

        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(0).unwrap();
        drop(file);
        std::fs::write(&path, b"new\n").unwrap();

        assert_eq!(
            tailer.read_lines(&path, StartAt::Beginning).unwrap(),
            vec![b"new".to_vec()]
        );
    }

    #[test]
    fn follows_rotation_and_drains_old_inode() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("app.log");
        let rotated = dir.path().join("app.log.1");
        std::fs::write(&path, b"before\n").unwrap();

        let mut tailer = Tailer::default();
        tailer.read_lines(&path, StartAt::Beginning).unwrap();

        std::fs::rename(&path, &rotated).unwrap();
        std::fs::write(&path, b"new-file\n").unwrap();
        OpenOptions::new()
            .append(true)
            .open(&rotated)
            .unwrap()
            .write_all(b"late-old\n")
            .unwrap();

        let lines = tailer.read_lines(&path, StartAt::Beginning).unwrap();
        assert!(lines.contains(&b"late-old".to_vec()));
        assert!(lines.contains(&b"new-file".to_vec()));
        assert!(!lines.contains(&b"before".to_vec()));
    }

    #[test]
    fn line_limit_preserves_backlog_instead_of_dropping_it() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("app.log");
        std::fs::write(&path, b"one\ntwo\nthree\n").unwrap();
        let mut tailer = Tailer::default();

        assert_eq!(
            tailer
                .read_lines_bounded(&path, StartAt::Beginning, 1024, 1, 64)
                .unwrap(),
            vec![b"one".to_vec()]
        );
        assert_eq!(
            tailer
                .read_lines_bounded(&path, StartAt::Beginning, 1024, 1, 64)
                .unwrap(),
            vec![b"two".to_vec()]
        );
        assert_eq!(
            tailer
                .read_lines_bounded(&path, StartAt::Beginning, 1024, 1, 64)
                .unwrap(),
            vec![b"three".to_vec()]
        );
    }

    #[test]
    fn rejects_symlink_log_files() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.log");
        let link = dir.path().join("linked.log");
        std::fs::write(&real, b"line\n").unwrap();
        symlink(&real, &link).unwrap();

        let mut tailer = Tailer::default();
        assert!(
            tailer
                .read_lines(&link, StartAt::Beginning)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
    }

    #[test]
    fn allows_symlink_parent_directories() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real_opt");
        let sym_dir = dir.path().join("opt");
        std::fs::create_dir_all(&real_dir).unwrap();
        symlink(&real_dir, &sym_dir).unwrap();

        let log_file = sym_dir.join("access.log");
        std::fs::write(real_dir.join("access.log"), b"line1\nline2\n").unwrap();

        let mut tailer = Tailer::default();
        let lines = tailer.read_lines(&log_file, StartAt::Beginning).unwrap();
        assert_eq!(lines, vec![b"line1".to_vec(), b"line2".to_vec()]);
    }
}
