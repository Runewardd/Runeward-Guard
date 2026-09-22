use crate::detector::{Event, valid_digest};
use crate::parse_exact;
use crate::wire;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const MAX_NATIVE_MESSAGE: u32 = 4096;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub allowed_origin: String,
    pub socket: PathBuf,
}

#[derive(Serialize)]
struct NativeManifest<'a> {
    name: &'a str,
    description: &'a str,
    path: &'a Path,
    #[serde(rename = "type")]
    kind: &'a str,
    allowed_origins: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachMessage {
    kind: String,
    digest: String,
    destination: String,
}

#[derive(Serialize)]
struct HostResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

fn valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
}

fn user_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".into())
}

pub fn setup_chrome(extension_id: &str, binary: &Path) -> Result<PathBuf, String> {
    if !valid_extension_id(extension_id) || !binary.is_absolute() {
        return Err(
            "setup requires a 32-letter Chrome extension ID and absolute host binary path".into(),
        );
    }
    let binary_metadata = fs::metadata(binary).map_err(|error| error.to_string())?;
    if !binary_metadata.is_file() || binary_metadata.permissions().mode() & 0o111 == 0 {
        return Err("host binary must be an existing executable file".into());
    }
    let home = user_home()?;
    let guard_dir = home.join(".runeward-guard");
    if !guard_dir.exists() {
        fs::create_dir(&guard_dir).map_err(|error| error.to_string())?;
    }
    let dir_metadata = fs::symlink_metadata(&guard_dir).map_err(|error| error.to_string())?;
    if !dir_metadata.is_dir() || dir_metadata.permissions().mode() & 0o077 != 0 {
        return Err("Guard configuration directory must be private".into());
    }
    let origin = format!("chrome-extension://{extension_id}/");
    let config = HostConfig {
        allowed_origin: origin.clone(),
        socket: guard_dir.join("monitor.sock"),
    };
    let manifest = NativeManifest {
        name: "com.runeward.guard",
        description: "Runeward Guard browser bridge",
        path: binary,
        kind: "stdio",
        allowed_origins: vec![origin],
    };
    let config_path = guard_dir.join("browser-host.json");
    let manifest_path = home.join(
        "Library/Application Support/Google/Chrome/NativeMessagingHosts/com.runeward.guard.json",
    );
    if config_path.exists() || manifest_path.exists() {
        return Err("browser host configuration already exists; refusing to overwrite".into());
    }
    let parent = manifest_path.parent().ok_or("invalid manifest path")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    write_private_json(&config_path, &config)?;
    if let Err(error) = write_private_json(&manifest_path, &manifest) {
        let _ = fs::remove_file(config_path);
        return Err(error);
    }
    Ok(manifest_path)
}

fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut data = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    data.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())?;
    if let Err(error) = file.write_all(&data).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(error.to_string());
    }
    Ok(())
}

use std::os::unix::fs::OpenOptionsExt;

pub fn load_config() -> Result<HostConfig, String> {
    let path = user_home()?.join(".runeward-guard/browser-host.json");
    let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("browser-host.json must be an owner-only regular file".into());
    }
    let data = fs::read(path).map_err(|error| error.to_string())?;
    let config: HostConfig = parse_exact(&data)?;
    let id = config
        .allowed_origin
        .strip_prefix("chrome-extension://")
        .and_then(|value| value.strip_suffix('/'));
    if !id.is_some_and(valid_extension_id) || !config.socket.is_absolute() {
        return Err("invalid browser host configuration".into());
    }
    Ok(config)
}

pub fn serve_native<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    socket: &Path,
) -> Result<(), String> {
    loop {
        let mut length_bytes = [0u8; 4];
        match input.read(&mut length_bytes[..1]) {
            Ok(0) => return Ok(()),
            Ok(_) => (),
            Err(error) => return Err(error.to_string()),
        }
        input
            .read_exact(&mut length_bytes[1..])
            .map_err(|error| error.to_string())?;
        let length = u32::from_le_bytes(length_bytes);
        if length == 0 || length > MAX_NATIVE_MESSAGE {
            return Err("invalid native message length".into());
        }
        let mut data = vec![0u8; length as usize];
        input
            .read_exact(&mut data)
            .map_err(|error| error.to_string())?;
        let response = handle_message(&data, socket);
        let encoded = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
        output
            .write_all(&(encoded.len() as u32).to_le_bytes())
            .map_err(|error| error.to_string())?;
        output
            .write_all(&encoded)
            .map_err(|error| error.to_string())?;
        output.flush().map_err(|error| error.to_string())?;
    }
}

fn handle_message(data: &[u8], socket: &Path) -> HostResponse {
    let Ok(message): Result<AttachMessage, _> = parse_exact(data) else {
        return HostResponse {
            ok: false,
            error: Some("invalid attachment metadata"),
        };
    };
    if !matches!(
        message.kind.as_str(),
        "file_attach" | "image_paste" | "image_request_completed"
    ) || !valid_digest(&message.digest)
    {
        return HostResponse {
            ok: false,
            error: Some("invalid attachment metadata"),
        };
    }
    if !matches!(
        message.destination.as_str(),
        "https://chatgpt.com" | "https://claude.ai"
    ) {
        return HostResponse {
            ok: false,
            error: Some("unsupported AI destination"),
        };
    }
    let mut event = Event::new(
        format!("browser-{}", chrono::Utc::now().timestamp_micros()),
        &message.kind,
    );
    event.harness = "browser".into();
    event.digest = message.digest;
    event.destination = message.destination;
    if wire::send_event(socket, &event).is_err() {
        return HostResponse {
            ok: false,
            error: Some("Guard monitor unavailable"),
        };
    }
    HostResponse {
        ok: true,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_extension_id() {
        assert!(!valid_extension_id("not-an-id"));
        assert!(valid_extension_id(&"a".repeat(32)));
    }

    #[test]
    fn rejects_unexpected_native_metadata() {
        let response = handle_message(
            br#"{"kind":"file_attach","digest":"bad","destination":"https://chatgpt.com"}"#,
            Path::new("/nonexistent"),
        );
        assert!(!response.ok);
    }

    #[test]
    fn image_paste_passes_metadata_validation() {
        let message = format!(
            "{{\"kind\":\"image_paste\",\"digest\":\"{}\",\"destination\":\"https://chatgpt.com\"}}",
            "a".repeat(64)
        );
        let response = handle_message(message.as_bytes(), Path::new("/nonexistent"));
        assert!(!response.ok);
        assert_eq!(response.error, Some("Guard monitor unavailable"));
    }
}
