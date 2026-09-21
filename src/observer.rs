use crate::detector::Event;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, Metadata};
use std::io::{Read, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const MAX_IMAGE_BYTES: u64 = 32 << 20;
const METADATA_GRACE: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct FileState {
    size: u64,
    modified: SystemTime,
    first_seen: SystemTime,
    emitted: bool,
}

pub struct ScreenshotScanner<C: Fn(&Path) -> bool> {
    directory: PathBuf,
    classify: C,
    seen: HashMap<PathBuf, FileState>,
    bootstrapped: bool,
    sequence: u64,
}

impl<C: Fn(&Path) -> bool> ScreenshotScanner<C> {
    pub fn new(directory: PathBuf, classify: C) -> Result<Self> {
        if !directory.is_absolute() || !directory.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "watch directory must be an existing absolute directory",
            ));
        }
        Ok(Self {
            directory,
            classify,
            seen: HashMap::new(),
            bootstrapped: false,
            sequence: 0,
        })
    }

    pub fn scan(&mut self) -> Result<Vec<Event>> {
        let now = SystemTime::now();
        let mut events = Vec::new();
        let mut observed = HashSet::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let path = entry.path();
            if !is_image(&path) {
                continue;
            }
            let file_type = entry.file_type()?;
            if !file_type.is_file() || file_type.is_symlink() {
                continue;
            }
            observed.insert(path.clone());
            let metadata = entry.metadata()?;
            if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_IMAGE_BYTES {
                continue;
            }
            let modified = metadata.modified()?;
            let state = self.seen.entry(path.clone()).or_insert_with(|| FileState {
                size: metadata.len(),
                modified,
                first_seen: now,
                emitted: !self.bootstrapped,
            });
            if state.size != metadata.len() || state.modified != modified {
                *state = FileState {
                    size: metadata.len(),
                    modified,
                    first_seen: now,
                    emitted: !self.bootstrapped,
                };
            }
            if !state.emitted
                && now.duration_since(state.first_seen).unwrap_or_default() <= METADATA_GRACE
                && (self.classify)(&path)
            {
                if let Ok(digest) = hash_stable_file(&path, &metadata) {
                    self.sequence += 1;
                    let mut event =
                        Event::new(format!("macos-capture-{}", self.sequence), "screen_capture");
                    event.digest = digest;
                    event.application = "macos".into();
                    events.push(event);
                    state.emitted = true;
                }
            }
        }
        self.seen.retain(|path, _| observed.contains(path));
        self.bootstrapped = true;
        Ok(events)
    }
}

fn is_image(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "png" | "jpg" | "jpeg" | "heic" | "webp"
            )
        })
}

fn hash_stable_file(path: &Path, before: &Metadata) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut limited = (&mut file).take(MAX_IMAGE_BYTES + 1);
    let mut buffer = [0u8; 8192];
    let mut read = 0;
    loop {
        let count = limited.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read += count as u64;
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if read > MAX_IMAGE_BYTES
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err(std::io::Error::other("image changed while hashing"));
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(target_os = "macos")]
pub fn apple_screenshot(path: &Path) -> bool {
    // xattr only sees the selected file; the marker itself is not proof of a trusted producer.
    std::process::Command::new("/usr/bin/xattr")
        .arg("-p")
        .arg("com.apple.metadata:kMDItemIsScreenCapture")
        .arg(path)
        .output()
        .is_ok_and(|output| output.status.success())
}

#[cfg(not(target_os = "macos"))]
pub fn apple_screenshot(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_directory() {
        assert!(ScreenshotScanner::new(PathBuf::from("relative"), |_| true).is_err());
    }
}
