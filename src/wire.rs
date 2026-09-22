use crate::detector::Event;
use crate::parse_exact;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_MESSAGE_BYTES: u64 = 4096;

pub fn socket_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(".runeward-guard/monitor.sock"))
}

pub struct PrivateListener {
    pub listener: UnixListener,
    path: PathBuf,
}

impl Drop for PrivateListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn listen(path: &Path) -> Result<PrivateListener, String> {
    if !path.is_absolute() {
        return Err("socket path must be absolute".into());
    }
    let directory = path.parent().ok_or("socket has no parent directory")?;
    if !directory.exists() {
        fs::create_dir(directory).map_err(|error| error.to_string())?;
    }
    let metadata = fs::symlink_metadata(directory).map_err(|error| error.to_string())?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err("socket directory must be private and owned by the current user".into());
    }
    if let Ok(existing) = fs::symlink_metadata(path) {
        if !existing.file_type().is_socket()
            || existing.permissions().mode() & 0o077 != 0
            || existing.uid() != unsafe { libc::geteuid() }
        {
            return Err("socket path exists but is not a private owner-owned socket".into());
        }
        match UnixStream::connect(path) {
            Ok(_) => return Err("monitor socket is already active".into()),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                let current = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
                if current.dev() != existing.dev() || current.ino() != existing.ino() {
                    return Err("socket changed while checking stale state".into());
                }
                fs::remove_file(path).map_err(|error| error.to_string())?;
            }
            Err(error) => return Err(format!("could not verify monitor socket: {error}")),
        }
    }
    let listener = UnixListener::bind(path).map_err(|error| error.to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    Ok(PrivateListener {
        listener,
        path: path.into(),
    })
}

pub fn read_event(stream: &mut UnixStream) -> Result<Event, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    let mut data = Vec::new();
    stream
        .take(MAX_MESSAGE_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() as u64 > MAX_MESSAGE_BYTES {
        return Err("browser event too large".into());
    }
    let event: Event = parse_exact(&data)?;
    if !matches!(
        event.kind.as_str(),
        "file_attach" | "image_paste" | "image_request_completed"
    ) || !event.text.is_empty()
        || !event.path.is_empty()
    {
        return Err("only metadata-only browser image events are accepted".into());
    }
    Ok(event)
}

pub fn send_event(path: &Path, event: &Event) -> Result<(), String> {
    let mut stream = UnixStream::connect(path).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    serde_json::to_writer(&mut stream, event).map_err(|error| error.to_string())?;
    stream.write_all(b"\n").map_err(|error| error.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut ack = [0];
    stream
        .read_exact(&mut ack)
        .map_err(|error| error.to_string())?;
    if ack[0] != 1 {
        return Err("monitor rejected browser event".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn recovers_only_a_private_stale_socket() {
        let directory = Path::new("/tmp").join(format!(
            "rgw-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_micros()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("monitor.sock");
        let old = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        drop(old);
        let replacement = listen(&path).unwrap();
        drop(replacement);
        assert!(!path.exists());
        fs::remove_dir(directory).unwrap();
    }
}
