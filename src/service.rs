use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const LABEL: &str = "com.runeward.guard.monitor";

fn xml(value: &str) -> Result<String, String> {
    if value.chars().any(|character| character.is_control()) {
        return Err("launch agent paths cannot contain control characters".into());
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

pub fn monitor_plist(
    binary: &Path,
    watch: &Path,
    audit: &Path,
    retain_days: u32,
) -> Result<String, String> {
    if !binary.is_absolute()
        || !watch.is_absolute()
        || !audit.is_absolute()
        || !(1..=365).contains(&retain_days)
    {
        return Err("launch agent requires absolute paths and 1-365 retention days".into());
    }
    let binary = xml(binary.to_str().ok_or("binary path is not UTF-8")?)?;
    let watch = xml(watch.to_str().ok_or("watch path is not UTF-8")?)?;
    let audit_raw = audit.to_str().ok_or("audit path is not UTF-8")?;
    let audit = xml(audit_raw)?;
    let errors = xml(&format!("{audit_raw}/guard-service.err"))?;
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{LABEL}</string>\n<key>ProgramArguments</key><array>\n<string>{binary}</string><string>monitor</string><string>--dir</string><string>{watch}</string><string>--audit-dir</string><string>{audit}</string><string>--retain-days</string><string>{retain_days}</string>\n</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>ThrottleInterval</key><integer>30</integer>\n<key>Umask</key><integer>63</integer>\n<key>StandardErrorPath</key><string>{errors}</string>\n</dict></plist>\n"
    ))
}

pub fn setup_monitor_agent(
    binary: &Path,
    watch: &Path,
    audit: &Path,
    retain_days: u32,
) -> Result<PathBuf, String> {
    if !cfg!(target_os = "macos") {
        return Err("launch agents are supported only on macOS".into());
    }
    let binary_metadata = fs::metadata(binary).map_err(|error| error.to_string())?;
    if !binary_metadata.is_file() || binary_metadata.permissions().mode() & 0o111 == 0 {
        return Err("monitor binary must be an executable regular file".into());
    }
    if !watch.is_dir() {
        return Err("watch path must be an existing directory".into());
    }
    let audit_metadata = fs::symlink_metadata(audit).map_err(|error| error.to_string())?;
    if !audit_metadata.is_dir()
        || audit_metadata.permissions().mode() & 0o077 != 0
        || audit_metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err("audit directory must be private and owned by the current user".into());
    }
    let plist = monitor_plist(binary, watch, audit, retain_days)?;
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let destination = PathBuf::from(home)
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"));
    if destination.exists() {
        return Err("launch agent already exists; refusing to overwrite".into());
    }
    let parent = destination.parent().ok_or("invalid LaunchAgents path")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let stderr_path = audit.join("guard-service.err");
    let stderr_file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(stderr_path)
        .map_err(|error| error.to_string())?;
    let stderr_metadata = stderr_file.metadata().map_err(|error| error.to_string())?;
    if !stderr_metadata.is_file()
        || stderr_metadata.permissions().mode() & 0o077 != 0
        || stderr_metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err("launch agent error log must be an owner-only regular file".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&destination)
        .map_err(|error| error.to_string())?;
    if let Err(error) = file
        .write_all(plist.as_bytes())
        .and_then(|_| file.sync_all())
    {
        let _ = fs::remove_file(&destination);
        return Err(error.to_string());
    }
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_paths_in_launch_agent_plist() {
        let xml = monitor_plist(
            Path::new("/opt/guard & test"),
            Path::new("/Users/a/<screens>"),
            Path::new("/private/audit & logs"),
            30,
        )
        .unwrap();
        assert!(xml.contains("/opt/guard &amp; test"));
        assert!(xml.contains("/Users/a/&lt;screens&gt;"));
        assert!(xml.contains("/private/audit &amp; logs/guard-service.err"));
        assert!(xml.contains("<key>Umask</key><integer>63</integer>"));
    }
}
