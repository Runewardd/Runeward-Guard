use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use url::Url;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub id: String,
    pub time: DateTime<Utc>,
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub harness: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub application: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub destination: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub digest: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
}

impl Event {
    pub fn new(id: String, kind: &str) -> Self {
        Self {
            id,
            time: Utc::now(),
            kind: kind.into(),
            harness: String::new(),
            application: String::new(),
            destination: String::new(),
            path: String::new(),
            digest: String::new(),
            text: String::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub rule: String,
    pub severity: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Result {
    pub event_id: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub findings: Vec<Finding>,
}

#[derive(Default)]
pub struct Detector {
    captures: HashMap<String, DateTime<Utc>>,
    attachments: HashMap<String, DateTime<Utc>>,
    last_time: Option<DateTime<Utc>>,
}

fn pattern(source: &'static str, cell: &'static OnceLock<Regex>) -> &'static Regex {
    cell.get_or_init(|| Regex::new(source).expect("constant regex"))
}

fn matches(source: &'static str, cell: &'static OnceLock<Regex>, value: &str) -> bool {
    pattern(source, cell).is_match(value)
}

fn finding(rule: &str, severity: &str, message: &str) -> Finding {
    Finding {
        rule: rule.into(),
        severity: severity.into(),
        message: message.into(),
    }
}

pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn path_key(path: &str) -> String {
    // Inputs are adapter-supplied absolute paths; retain only a one-way key.
    hex::encode(Sha256::digest(path.as_bytes()))
}

pub fn is_ai_destination(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    if !matches!(url.scheme(), "https" | "wss")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    [
        "chatgpt.com",
        "openai.com",
        "claude.ai",
        "anthropic.com",
        "githubcopilot.com",
    ]
    .iter()
    .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
}

impl Detector {
    pub fn inspect(&mut self, event: &Event) -> std::result::Result<Result, String> {
        static ID: OnceLock<Regex> = OnceLock::new();
        static KEY: OnceLock<Regex> = OnceLock::new();
        static TOKEN: OnceLock<Regex> = OnceLock::new();
        static PASSWORD: OnceLock<Regex> = OnceLock::new();
        if !matches(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", &ID, &event.id) {
            return Err("event id must be 1-128 safe characters".into());
        }
        if self.last_time.is_some_and(|time| event.time < time) {
            return Err("events must be in timestamp order".into());
        }
        self.captures
            .retain(|_, time| event.time.signed_duration_since(*time) <= Duration::minutes(15));
        self.attachments
            .retain(|_, time| event.time.signed_duration_since(*time) <= Duration::minutes(15));
        let mut result = Result {
            event_id: event.id.clone(),
            decision: "allow".into(),
            findings: vec![],
        };
        match event.kind.as_str() {
            "prompt_submit" => {
                if event.harness.is_empty() || event.text.is_empty() {
                    return Err("prompt_submit requires harness and text".into());
                }
                if matches(
                    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
                    &KEY,
                    &event.text,
                ) {
                    result.findings.push(finding(
                        "private_key_in_prompt",
                        "critical",
                        "Private key material appears in an AI prompt.",
                    ));
                }
                if matches(
                    r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b",
                    &TOKEN,
                    &event.text,
                ) {
                    result.findings.push(finding(
                        "provider_token_in_prompt",
                        "high",
                        "A provider token appears in an AI prompt.",
                    ));
                }
                if matches(
                    r#"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'";,]{8,})"#,
                    &PASSWORD,
                    &event.text,
                ) {
                    result.findings.push(finding(
                        "possible_password_in_prompt",
                        "high",
                        "A password-like assignment appears in an AI prompt.",
                    ));
                }
                if !result.findings.is_empty() {
                    result.decision = "block".into()
                }
            }
            "keychain_access" => {
                if event.harness.is_empty() || !event.text.is_empty() {
                    return Err("keychain_access requires harness and no text".into());
                }
                result.decision = "warn".into();
                result.findings.push(finding(
                    "agent_keychain_access",
                    "high",
                    "An AI harness accessed Keychain; this does not establish disclosure.",
                ));
            }
            "screen_capture" => {
                if (event.path.is_empty() && event.digest.is_empty())
                    || (!event.path.is_empty() && !Path::new(&event.path).is_absolute())
                    || !event.text.is_empty()
                    || (!event.digest.is_empty() && !valid_digest(&event.digest))
                {
                    return Err(
                        "screen_capture requires an absolute path or SHA-256 digest, and no text"
                            .into(),
                    );
                }
                if !event.path.is_empty() {
                    self.captures.insert(path_key(&event.path), event.time);
                }
                if !event.digest.is_empty() {
                    self.captures
                        .insert(format!("sha256:{}", event.digest), event.time);
                    if let Some(attached) = self.attachments.get(&event.digest)
                        && event.time >= *attached
                        && event.time.signed_duration_since(*attached) <= Duration::minutes(15)
                    {
                        result.decision = "warn".into();
                        result.findings.push(finding("screenshot_selected_for_ai", "high", "A recently observed screenshot was selected for an AI page; upload is not confirmed."));
                        self.attachments.remove(&event.digest);
                    }
                }
            }
            "file_upload" => {
                if !Path::new(&event.path).is_absolute()
                    || event.destination.is_empty()
                    || !event.text.is_empty()
                {
                    return Err(
                        "file_upload requires an absolute path, destination, and no text".into(),
                    );
                }
                if is_ai_destination(&event.destination)
                    && self
                        .captures
                        .get(&path_key(&event.path))
                        .is_some_and(|time| {
                            event.time >= *time
                                && event.time.signed_duration_since(*time) <= Duration::minutes(15)
                        })
                {
                    result.decision = "warn".into();
                    result.findings.push(finding(
                        "screenshot_uploaded_to_ai",
                        "high",
                        "A recently captured screenshot was uploaded to an AI destination.",
                    ));
                }
            }
            "file_attach" => {
                if !valid_digest(&event.digest)
                    || event.destination.is_empty()
                    || !event.text.is_empty()
                {
                    return Err(
                        "file_attach requires a SHA-256 digest, destination, and no text".into(),
                    );
                }
                if is_ai_destination(&event.destination) {
                    if self
                        .captures
                        .get(&format!("sha256:{}", event.digest))
                        .is_some_and(|time| {
                            event.time >= *time
                                && event.time.signed_duration_since(*time) <= Duration::minutes(15)
                        })
                    {
                        result.decision = "warn".into();
                        result.findings.push(finding("screenshot_selected_for_ai", "high", "A recently captured screenshot was selected for an AI page; upload is not confirmed."));
                    } else {
                        self.attachments.insert(event.digest.clone(), event.time);
                    }
                }
            }
            _ => return Err(format!("unsupported event kind {:?}", event.kind)),
        }
        self.last_time = Some(event.time);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_prompt_without_echoing_secret() {
        let mut event = Event::new("one".into(), "prompt_submit");
        event.harness = "claude".into();
        event.text = "password=example-only-credential".into();
        let result = Detector::default().inspect(&event).unwrap();
        assert_eq!(result.decision, "block");
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("example-only-credential")
        );
    }

    #[test]
    fn correlates_capture_then_attachment() {
        let digest = "a".repeat(64);
        let mut capture = Event::new("one".into(), "screen_capture");
        capture.digest = digest.clone();
        let mut attach = Event::new("two".into(), "file_attach");
        attach.time = capture.time + Duration::seconds(1);
        attach.digest = digest;
        attach.destination = "https://chatgpt.com".into();
        let mut detector = Detector::default();
        assert_eq!(detector.inspect(&capture).unwrap().decision, "allow");
        assert_eq!(detector.inspect(&attach).unwrap().decision, "warn");
    }

    #[test]
    fn exact_ai_domain_only() {
        assert!(is_ai_destination("https://chatgpt.com/"));
        assert!(!is_ai_destination("https://chatgpt.com.evil.invalid/"));
        assert!(!is_ai_destination("https://evil.invalid@chatgpt.com/"));
    }
}
