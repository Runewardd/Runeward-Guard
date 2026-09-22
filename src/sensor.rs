//! Metadata-only Endpoint Security observations and conservative attribution.
//! This module is platform-neutral so it can be replayed and tested without an
//! entitlement. Only the macOS adapter collects live observations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

const MAX_PROCESSES: usize = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessId {
    pub pid: i32,
    pub pid_version: i32,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation {
    Exec {
        time: DateTime<Utc>,
        process: ProcessId,
        parent: Option<ProcessId>,
        executable: String,
        signing_id: String,
    },
    Fork {
        time: DateTime<Utc>,
        process: ProcessId,
        parent: ProcessId,
        executable: String,
    },
    Open {
        time: DateTime<Utc>,
        process: ProcessId,
        executable: String,
        path: String,
    },
    Exit {
        time: DateTime<Utc>,
        process: ProcessId,
    },
}

#[derive(Debug, Serialize)]
pub struct SensorFinding {
    pub time: DateTime<Utc>,
    pub rule: &'static str,
    pub confidence: &'static str,
    pub actor_pid: i32,
    pub harness_candidate: String,
    pub message: &'static str,
}

struct ProcessInfo {
    parent: Option<ProcessId>,
    harness_candidate: Option<&'static str>,
    sequence: u64,
}

#[derive(Default)]
pub struct SensorEngine {
    processes: HashMap<ProcessId, ProcessInfo>,
    sequence: u64,
}

impl SensorEngine {
    /// No raw path, arguments, environment variables, or Keychain item values
    /// are retained. A process name is only a *candidate*, never proof of identity.
    pub fn inspect(&mut self, observation: Observation) -> Option<SensorFinding> {
        match observation {
            Observation::Exec {
                process,
                parent,
                executable,
                ..
            } => {
                self.remember(process, parent, harness_candidate(&executable));
                None
            }
            Observation::Fork {
                process,
                parent,
                executable,
                ..
            } => {
                self.remember(process, Some(parent), harness_candidate(&executable));
                None
            }
            Observation::Exit { process, .. } => {
                self.processes.remove(&process);
                None
            }
            Observation::Open {
                time,
                process,
                executable,
                path,
            } => {
                if !is_keychain_path(&path) || is_securityd(&executable) {
                    return None;
                }
                let candidate =
                    harness_candidate(&executable).or_else(|| self.ancestor_candidate(process));
                candidate.map(|harness| SensorFinding {
                    time,
                    rule: "direct_keychain_file_open_by_ai_harness_candidate",
                    confidence: "low",
                    actor_pid: process.pid,
                    harness_candidate: harness.into(),
                    message: "A process named like an AI harness, or its descendant, directly opened a Keychain file. This does not establish item access or disclosure.",
                })
            }
        }
    }

    fn remember(
        &mut self,
        process: ProcessId,
        parent: Option<ProcessId>,
        candidate: Option<&'static str>,
    ) {
        self.sequence += 1;
        self.processes.insert(
            process,
            ProcessInfo {
                parent,
                harness_candidate: candidate,
                sequence: self.sequence,
            },
        );
        if self.processes.len() > MAX_PROCESSES
            && let Some(oldest) = self
                .processes
                .iter()
                .min_by_key(|(_, info)| info.sequence)
                .map(|(id, _)| *id)
        {
            self.processes.remove(&oldest);
        }
    }

    fn ancestor_candidate(&self, process: ProcessId) -> Option<&'static str> {
        let mut current = Some(process);
        for _ in 0..32 {
            let info = self.processes.get(&current?)?;
            if let Some(candidate) = info.harness_candidate {
                return Some(candidate);
            }
            current = info.parent;
        }
        None
    }
}

fn harness_candidate(executable: &str) -> Option<&'static str> {
    let name = Path::new(executable)
        .file_name()?
        .to_string_lossy()
        .to_ascii_lowercase();
    match name.as_str() {
        "codex" => Some("codex"),
        "claude" | "claude-code" => Some("claude"),
        "copilot" | "github-copilot" | "github copilot" => Some("copilot"),
        _ => None,
    }
}

fn is_securityd(executable: &str) -> bool {
    Path::new(executable)
        .file_name()
        .is_some_and(|name| name == "securityd")
}

fn is_keychain_path(path: &str) -> bool {
    let components: Vec<_> = Path::new(path).components().collect();
    if !Path::new(path).is_absolute() {
        return false;
    }
    if components
        .iter()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return false;
    }
    let parts: Vec<_> = components
        .iter()
        .filter_map(|part| match part {
            std::path::Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect();
    match parts.as_slice() {
        ["Library", "Keychains", ..] | ["System", "Library", "Keychains", ..] => parts.len() > 2,
        ["Users", _, "Library", "Keychains", ..] => parts.len() > 4,
        ["var", "root", "Library", "Keychains", ..] => parts.len() > 4,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(pid: i32, pid_version: i32) -> ProcessId {
        ProcessId { pid, pid_version }
    }

    fn exec(process: ProcessId, parent: Option<ProcessId>, executable: &str) -> Observation {
        Observation::Exec {
            time: Utc::now(),
            process,
            parent,
            executable: executable.into(),
            signing_id: String::new(),
        }
    }

    fn open(process: ProcessId, executable: &str, path: &str) -> Observation {
        Observation::Open {
            time: Utc::now(),
            process,
            executable: executable.into(),
            path: path.into(),
        }
    }

    #[test]
    fn direct_open_is_a_low_confidence_finding_without_path() {
        let finding = SensorEngine::default()
            .inspect(open(
                id(4, 1),
                "/usr/local/bin/codex",
                "/Users/alice/Library/Keychains/login.keychain-db",
            ))
            .unwrap();
        let output = serde_json::to_string(&finding).unwrap();
        assert_eq!(finding.harness_candidate, "codex");
        assert_eq!(finding.confidence, "low");
        assert!(!output.contains("alice"));
        assert!(!output.contains("login.keychain"));
    }

    #[test]
    fn child_is_correlated_by_pid_version() {
        let mut engine = SensorEngine::default();
        engine.inspect(exec(id(10, 1), None, "/usr/bin/claude"));
        engine.inspect(exec(id(11, 1), Some(id(10, 1)), "/bin/sh"));
        assert!(
            engine
                .inspect(open(
                    id(11, 1),
                    "/bin/sh",
                    "/Library/Keychains/System.keychain"
                ))
                .is_some()
        );
        assert!(
            engine
                .inspect(open(
                    id(11, 2),
                    "/bin/sh",
                    "/Library/Keychains/System.keychain"
                ))
                .is_none()
        );
    }

    #[test]
    fn securityd_activity_is_not_attributed_to_harness() {
        let mut engine = SensorEngine::default();
        engine.inspect(exec(id(10, 1), None, "/usr/bin/codex"));
        engine.inspect(exec(id(11, 1), Some(id(10, 1)), "/usr/libexec/securityd"));
        assert!(
            engine
                .inspect(open(
                    id(11, 1),
                    "/usr/libexec/securityd",
                    "/Users/alice/Library/Keychains/login.keychain-db"
                ))
                .is_none()
        );
    }

    #[test]
    fn unrelated_paths_and_processes_do_not_alert() {
        let mut engine = SensorEngine::default();
        assert!(
            engine
                .inspect(open(
                    id(1, 1),
                    "/usr/bin/codex",
                    "/tmp/Library/Keychains/fake.keychain"
                ))
                .is_none()
        );
        assert!(
            engine
                .inspect(open(
                    id(1, 1),
                    "/usr/bin/codex",
                    "/Users/alice/Library/Keychains"
                ))
                .is_none()
        );
        assert!(
            engine
                .inspect(open(
                    id(1, 1),
                    "/bin/sh",
                    "/Library/Keychains/System.keychain"
                ))
                .is_none()
        );
        assert!(
            engine
                .inspect(open(
                    id(1, 1),
                    "/usr/bin/codex",
                    "/Users/alice/Library/Keychains/../not-a-keychain"
                ))
                .is_none()
        );
    }
}
