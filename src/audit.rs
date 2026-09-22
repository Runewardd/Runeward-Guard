use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, Read};

pub const MAX_AUDIT_FILE_BYTES: u64 = 64 << 20;
const MAX_AUDIT_LINE_BYTES: usize = 1 << 20;

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
}
