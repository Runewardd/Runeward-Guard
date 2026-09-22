use runeward_guard::MAX_EVENT_BYTES;
use runeward_guard::parse_exact;
use runeward_guard::sensor::{Observation, SensorEngine};
use std::io::{self, BufRead, Write};

fn replay<R: BufRead, W: Write>(input: &mut R, output: &mut W) -> Result<(), String> {
    let mut engine = SensorEngine::default();
    let mut line = Vec::new();
    let mut number = 0;
    loop {
        line.clear();
        let count = (&mut *input)
            .take((MAX_EVENT_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Ok(());
        }
        number += 1;
        if count > MAX_EVENT_BYTES {
            return Err(format!("line {number}: observation exceeds 1 MiB"));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let observation: Observation =
            parse_exact(&line).map_err(|error| format!("line {number}: {error}"))?;
        if let Some(finding) = engine.inspect(observation) {
            serde_json::to_writer(&mut *output, &finding).map_err(|error| error.to_string())?;
            writeln!(output).map_err(|error| error.to_string())?;
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use endpoint_sec::{Client, Event, Message, sys::es_event_type_t, version};
    use runeward_guard::sensor::ProcessId;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::Duration;

    fn os_version() -> Result<(u64, u64, u64), String> {
        let output = Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err("could not read macOS version".into());
        }
        let raw = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
        let mut parts = raw.trim().split('.');
        let major = parts
            .next()
            .ok_or("invalid macOS version")?
            .parse()
            .map_err(|_| "invalid macOS major version")?;
        let minor = parts
            .next()
            .unwrap_or("0")
            .parse()
            .map_err(|_| "invalid macOS minor version")?;
        let patch = parts
            .next()
            .unwrap_or("0")
            .parse()
            .map_err(|_| "invalid macOS patch version")?;
        Ok((major, minor, patch))
    }

    fn id(token: endpoint_sec::AuditToken) -> ProcessId {
        ProcessId {
            pid: token.pid(),
            pid_version: token.pidversion(),
        }
    }

    fn observation(message: &Message) -> Option<Observation> {
        let time = chrono::DateTime::<chrono::Utc>::from(message.time());
        match message.event()? {
            Event::NotifyExec(exec) => {
                let target = exec.target();
                let file = target.executable();
                if file.path_truncated() {
                    return None;
                }
                Some(Observation::Exec {
                    time,
                    process: id(target.audit_token()),
                    parent: target.parent_audit_token().map(id),
                    executable: file.path().to_string_lossy().into_owned(),
                    signing_id: target.signing_id().to_string_lossy().into_owned(),
                })
            }
            Event::NotifyFork(fork) => {
                let child = fork.child();
                let file = child.executable();
                if file.path_truncated() {
                    return None;
                }
                Some(Observation::Fork {
                    time,
                    process: id(child.audit_token()),
                    parent: id(message.process().audit_token()),
                    executable: file.path().to_string_lossy().into_owned(),
                })
            }
            Event::NotifyOpen(open) => {
                let file = open.file();
                if file.path_truncated() {
                    return None;
                }
                let actor = message.process();
                let executable = actor.executable();
                if executable.path_truncated() {
                    return None;
                }
                Some(Observation::Open {
                    time,
                    process: id(actor.audit_token()),
                    executable: executable.path().to_string_lossy().into_owned(),
                    path: file.path().to_string_lossy().into_owned(),
                })
            }
            Event::NotifyExit(_) => Some(Observation::Exit {
                time,
                process: id(message.process().audit_token()),
            }),
            _ => None,
        }
    }

    pub fn live() -> Result<(), String> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("live Endpoint Security collection requires a root-owned, signed and entitled installation".into());
        }
        let (major, minor, patch) = os_version()?;
        if major < 11 {
            return Err("Guard's sensor requires macOS 11 or later".into());
        }
        version::set_runtime_version(major, minor, patch);

        let (sender, receiver) = mpsc::sync_channel::<Observation>(1024);
        let dropped = Arc::new(AtomicU64::new(0));
        let callback_dropped = dropped.clone();
        let mut client = Client::new(move |_, message| {
            if let Some(observation) = observation(&message)
                && sender.try_send(observation).is_err()
            {
                callback_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }).map_err(|error| format!("Endpoint Security client unavailable: {error:?}. Verify signing, entitlement and Full Disk Access"))?;
        client
            .subscribe(&[
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_FORK,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_OPEN,
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
            ])
            .map_err(|error| format!("could not subscribe to Endpoint Security: {error:?}"))?;

        let running = Arc::new(AtomicBool::new(true));
        let stop = running.clone();
        ctrlc::set_handler(move || stop.store(false, Ordering::SeqCst))
            .map_err(|error| error.to_string())?;
        let mut engine = SensorEngine::default();
        let stdout = io::stdout();
        let mut output = stdout.lock();
        let mut last_dropped = 0;
        while running.load(Ordering::SeqCst) {
            match receiver.recv_timeout(Duration::from_millis(500)) {
                Ok(observation) => {
                    if let Some(finding) = engine.inspect(observation) {
                        serde_json::to_writer(&mut output, &finding)
                            .map_err(|error| error.to_string())?;
                        writeln!(output).map_err(|error| error.to_string())?;
                        output.flush().map_err(|error| error.to_string())?;
                    }
                }
                Err(RecvTimeoutError::Timeout) => (),
                Err(RecvTimeoutError::Disconnected) => {
                    return Err("Endpoint Security callback stopped".into());
                }
            }
            let total = dropped.load(Ordering::Relaxed);
            if total != last_dropped {
                eprintln!(
                    "guard-sensor: dropped {total} observations due to full queue; coverage is incomplete"
                );
                last_dropped = total;
            }
        }
        client
            .delete()
            .map_err(|error| format!("could not close Endpoint Security client: {error:?}"))?;
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
mod macos {
    pub fn live() -> Result<(), String> {
        Err("live Endpoint Security collection requires macOS".into())
    }
}

fn run() -> Result<(), String> {
    match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [command] if command == "replay" => {
            replay(&mut io::stdin().lock(), &mut io::stdout().lock())
        }
        [command] if command == "live" => macos::live(),
        _ => Err("usage: guard-sensor <replay|live>".into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("guard-sensor: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_emits_only_findings() {
        let input = br#"{"kind":"exec","time":"2026-09-22T00:00:00Z","process":{"pid":10,"pid_version":1},"parent":null,"executable":"/usr/bin/codex","signing_id":""}
{"kind":"open","time":"2026-09-22T00:00:01Z","process":{"pid":10,"pid_version":1},"executable":"/usr/bin/codex","path":"/Users/alice/Library/Keychains/login.keychain-db"}
"#;
        let mut output = Vec::new();
        replay(&mut input.as_slice(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("direct_keychain_file_open"));
        assert!(!text.contains("alice"));
    }
}
