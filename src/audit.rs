use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const MAX_AUDIT_FILE_BYTES: u64 = 64 << 20;
const MAX_AUDIT_LINE_BYTES: usize = 1 << 20;

pub struct DailyAuditLog {
    directory: PathBuf,
    day: chrono::NaiveDate,
    file: File,
    retain_days: u32,
}

impl DailyAuditLog {
    pub fn new(directory: PathBuf, retain_days: u32) -> Result<Self, String> {
        if !directory.is_absolute() || !(1..=365).contains(&retain_days) {
            return Err("audit directory must be absolute and retention must be 1-365 days".into());
        }
        if !directory.exists() {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|error| error.to_string())?;
        }
        let metadata = fs::symlink_metadata(&directory).map_err(|error| error.to_string())?;
        if !metadata.is_dir()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err("audit directory must be a private, owner-owned directory".into());
        }
        let day = Utc::now().date_naive();
        let file = open_day(&directory, day)?;
        prune(&directory, day, retain_days)?;
        Ok(Self {
            directory,
            day,
            file,
            retain_days,
        })
    }

    fn refresh(&mut self) -> io::Result<()> {
        let today = Utc::now().date_naive();
        if today != self.day {
            self.file = open_day(&self.directory, today).map_err(io::Error::other)?;
            self.day = today;
            prune(&self.directory, today, self.retain_days).map_err(io::Error::other)?;
        }
        Ok(())
    }
}

impl Write for DailyAuditLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.refresh()?;
        let size = self.file.metadata()?.len();
        if size.saturating_add(bytes.len() as u64) > MAX_AUDIT_FILE_BYTES {
            return Err(io::Error::other(
                "daily audit file is full; coverage is incomplete",
            ));
        }
        self.file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.refresh()?;
        let size = self.file.metadata()?.len();
        if size.saturating_add(bytes.len() as u64) > MAX_AUDIT_FILE_BYTES {
            return Err(io::Error::other(
                "daily audit file is full; coverage is incomplete",
            ));
        }
        self.file.write_all(bytes)
    }
}

fn day_path(directory: &Path, day: chrono::NaiveDate) -> PathBuf {
    directory.join(format!("guard-{}.jsonl", day.format("%Y-%m-%d")))
}

fn open_day(directory: &Path, day: chrono::NaiveDate) -> Result<File, String> {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(day_path(directory, day))
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.len() > MAX_AUDIT_FILE_BYTES
    {
        return Err("daily audit file must be an owner-only regular file of at most 64 MiB".into());
    }
    Ok(file)
}

fn prune(directory: &Path, today: chrono::NaiveDate, retain_days: u32) -> Result<(), String> {
    let cutoff = today - chrono::Duration::days(retain_days as i64);
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let Some(date) = name
            .to_str()
            .and_then(|name| name.strip_prefix("guard-"))
            .and_then(|name| name.strip_suffix(".jsonl"))
            .filter(|date| date.len() == 10)
            .and_then(|date| chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok())
        else {
            continue;
        };
        if date > cutoff {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0
        {
            fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct AuditFinding {
    rule: String,
}

#[derive(Deserialize)]
struct AuditRecord {
    event_id: String,
    time: DateTime<Utc>,
    kind: String,
    decision: String,
    #[serde(default)]
    findings: Vec<AuditFinding>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct AuditSummary {
    pub scanned_records: u64,
    pub matched_records: u64,
    pub first: Option<DateTime<Utc>>,
    pub last: Option<DateTime<Utc>>,
    pub rules: BTreeMap<String, u64>,
}

pub fn summarize<R: BufRead>(
    input: &mut R,
    since: Option<DateTime<Utc>>,
) -> Result<AuditSummary, String> {
    let mut summary = AuditSummary {
        scanned_records: 0,
        matched_records: 0,
        first: None,
        last: None,
        rules: BTreeMap::new(),
    };
    let mut line = Vec::new();
    let mut total = 0u64;
    loop {
        line.clear();
        let read = Read::take(&mut *input, (MAX_AUDIT_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > MAX_AUDIT_FILE_BYTES || read > MAX_AUDIT_LINE_BYTES {
            return Err("audit input exceeds its size limit".into());
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        summary.scanned_records += 1;
        let record: AuditRecord = serde_json::from_slice(&line)
            .map_err(|error| format!("audit line {}: {error}", summary.scanned_records))?;
        if record.event_id.is_empty() || record.kind.is_empty() || record.decision.is_empty() {
            return Err(format!(
                "audit line {}: missing monitor metadata",
                summary.scanned_records
            ));
        }
        if since.is_some_and(|boundary| record.time < boundary) {
            continue;
        }
        summary.matched_records += 1;
        summary.first = Some(
            summary
                .first
                .map_or(record.time, |time| time.min(record.time)),
        );
        summary.last = Some(
            summary
                .last
                .map_or(record.time, |time| time.max(record.time)),
        );
        for finding in record.findings {
            *summary.rules.entry(finding.rule).or_default() += 1;
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_only_selected_window_without_raw_content() {
        let data = br#"{"event_id":"one","time":"2026-09-01T00:00:00Z","kind":"image_paste","decision":"warn","findings":[{"rule":"image_pasted_into_ai","severity":"medium","message":"example"}]}
{"event_id":"two","time":"2026-09-22T00:00:00Z","kind":"image_request_completed","decision":"warn","findings":[{"rule":"screenshot_http_request_completed","severity":"high","message":"example"}]}
"#;
        let since = "2026-09-20T00:00:00Z".parse().unwrap();
        let summary = summarize(&mut data.as_slice(), Some(since)).unwrap();
        assert_eq!(summary.scanned_records, 2);
        assert_eq!(summary.matched_records, 1);
        assert_eq!(summary.rules["screenshot_http_request_completed"], 1);
        assert!(!serde_json::to_string(&summary).unwrap().contains("example"));
    }

    #[test]
    fn daily_log_is_private_and_prunes_only_expired_guard_files() {
        let directory = std::env::temp_dir().join(format!(
            "runeward-guard-audit-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_micros()
        ));
        let today = Utc::now().date_naive();
        let expired = day_path(&directory, today - chrono::Duration::days(31));
        let unrelated = directory.join("notes.txt");
        let mut log = DailyAuditLog::new(directory.clone(), 30).unwrap();
        log.write_all(b"synthetic metadata\n").unwrap();
        fs::write(&expired, b"old metadata\n").unwrap();
        fs::set_permissions(&expired, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&unrelated, b"keep me\n").unwrap();
        prune(&directory, today, 30).unwrap();
        assert!(!expired.exists());
        assert!(unrelated.exists());
        let current = day_path(&directory, today);
        assert_eq!(fs::read(current).unwrap(), b"synthetic metadata\n");
        drop(log);
        fs::remove_dir_all(directory).unwrap();
    }
}
