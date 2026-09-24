use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const IDENTITY_FILE: &str = "device.json";
const MAX_IDENTITY_BYTES: u64 = 16 << 10;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceIdentity {
    pub schema_version: u32,
    pub device_id: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub os: String,
    pub architecture: String,
}

pub fn initialize(state_dir: &Path, display_name: Option<&str>) -> Result<DeviceIdentity, String> {
    validate_state_dir_path(state_dir)?;
    ensure_private_directory(state_dir)?;
    let path = identity_path(state_dir);
    if path.exists() {
        return load(state_dir);
    }

    let display_name = match display_name {
        Some(name) => validate_display_name(name)?,
        None => validate_display_name(&hostname()?)?,
    };
    let identity = DeviceIdentity {
        schema_version: 1,
        device_id: random_device_id()?,
        display_name,
        created_at: Utc::now(),
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
    };
    write_identity(&path, &identity)?;
    Ok(identity)
}

pub fn load(state_dir: &Path) -> Result<DeviceIdentity, String> {
    validate_state_dir_path(state_dir)?;
    validate_private_directory(state_dir)?;
    let path = identity_path(state_dir);
    let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != effective_uid()
        || metadata.len() > MAX_IDENTITY_BYTES
    {
        return Err("device identity must be an owner-only regular file of at most 16 KiB".into());
    }
    let data = fs::read(&path).map_err(|error| error.to_string())?;
    let identity: DeviceIdentity = crate::parse_exact(&data)?;
    validate_identity(&identity)?;
    Ok(identity)
}

fn identity_path(state_dir: &Path) -> PathBuf {
    state_dir.join(IDENTITY_FILE)
}

fn validate_state_dir_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("device state directory must be absolute".into());
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    if !path.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|error| error.to_string())?;
    }
    validate_private_directory(path)
}

fn validate_private_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != effective_uid()
    {
        return Err("device state directory must be private and owned by the current user".into());
    }
    Ok(())
}

fn write_identity(path: &Path, identity: &DeviceIdentity) -> Result<(), String> {
    let mut encoded = serde_json::to_vec_pretty(identity).map_err(|error| error.to_string())?;
    encoded.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| error.to_string())?;
    if let Err(error) = file.write_all(&encoded).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(error.to_string());
    }
    Ok(())
}

fn validate_identity(identity: &DeviceIdentity) -> Result<(), String> {
    if identity.schema_version != 1
        || identity.device_id.len() != 64
        || !identity
            .device_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || identity.os.is_empty()
        || identity.architecture.is_empty()
    {
        return Err("invalid device identity".into());
    }
    validate_display_name(&identity.display_name)?;
    Ok(())
}

fn validate_display_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 128 || name.chars().any(char::is_control) {
        return Err("device display name must contain 1-128 printable characters".into());
    }
    Ok(name.into())
}

fn random_device_id() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| error.to_string())?;
    Ok(hex::encode(bytes))
}

fn hostname() -> Result<String, String> {
    let mut bytes = [0u8; 256];
    let status = unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) };
    if status != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec()).map_err(|_| "hostname is not UTF-8".into())
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "runeward-guard-{label}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_micros()
        ))
    }

    #[test]
    fn initialization_is_private_and_idempotent() {
        let directory = temporary_directory("identity");
        let first = initialize(&directory, Some("Test Mac")).unwrap();
        let second = initialize(&directory, Some("Ignored replacement")).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.display_name, "Test Mac");
        assert_eq!(first.device_id.len(), 64);
        assert_eq!(
            fs::metadata(identity_path(&directory))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn refuses_identity_exposed_to_other_users() {
        let directory = temporary_directory("permissions");
        initialize(&directory, Some("Test Mac")).unwrap();
        let path = identity_path(&directory);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&directory).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
