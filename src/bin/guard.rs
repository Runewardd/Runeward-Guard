use chrono::Utc;
use regex::Regex;
use runeward_guard::MAX_EVENT_BYTES;
use runeward_guard::detector::{Detector, Event};
use runeward_guard::{host, observer, parse_exact, wire};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaudeInput {
    hook_event_name: String,
    prompt: String,
}

#[derive(Deserialize)]
struct ToolInput {
    hook_event_name: String,
    tool_name: String,
    tool_input: Option<ToolCommand>,
}

#[derive(Deserialize)]
struct ToolCommand {
    command: Option<String>,
}

#[derive(Serialize)]
struct MonitorOutput<'a> {
    event_id: &'a str,
    time: chrono::DateTime<Utc>,
    kind: &'a str,
    decision: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    findings: &'a Vec<runeward_guard::detector::Finding>,
}

fn read_limited<R: Read>(input: &mut R) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    input
        .take((MAX_EVENT_BYTES + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() > MAX_EVENT_BYTES {
        return Err("event exceeds 1048576 bytes".into());
    }
    Ok(data)
}

fn check<R: Read, W: Write>(input: &mut R, output: &mut W) -> Result<bool, String> {
    let event: Event = parse_exact(&read_limited(input)?)?;
    let result = Detector::default().inspect(&event)?;
    serde_json::to_writer(&mut *output, &result).map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())?;
    Ok(result.decision == "block")
}

fn inspect<R: BufRead, W: Write>(input: &mut R, output: &mut W) -> Result<(), String> {
    let mut detector = Detector::default();
    let mut line = Vec::new();
    let mut number = 0;
    loop {
        line.clear();
        let bytes = input
            .take((MAX_EVENT_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|error| error.to_string())?;
        if bytes == 0 {
            return Ok(());
        }
        number += 1;
        if bytes > MAX_EVENT_BYTES {
            return Err(format!("line {number}: event too large"));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let event: Event = parse_exact(&line).map_err(|error| format!("line {number}: {error}"))?;
        let result = detector
            .inspect(&event)
            .map_err(|error| format!("line {number}: {error}"))?;
        serde_json::to_writer(&mut *output, &result).map_err(|error| error.to_string())?;
        writeln!(output).map_err(|error| error.to_string())?;
    }
}

fn claude_block<W: Write>(output: &mut W, reason: &str) -> Result<(), String> {
    serde_json::to_writer(
        &mut *output,
        &serde_json::json!({"decision":"block","reason":reason,"suppressOriginalPrompt":true}),
    )
    .map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())
}

fn claude_hook<R: Read, W: Write>(input: &mut R, output: &mut W) -> Result<(), String> {
    let data = match read_limited(input) {
        Ok(data) => data,
        Err(_) => return claude_block(output, "Runeward Guard could not inspect this prompt."),
    };
    let Ok(hook): Result<ClaudeInput, _> = parse_exact(&data) else {
        return claude_block(output, "Runeward Guard could not inspect this prompt.");
    };
    if hook.hook_event_name != "UserPromptSubmit" || hook.prompt.is_empty() {
        return claude_block(output, "Runeward Guard could not inspect this prompt.");
    }
    let mut event = Event::new("claude-prompt".into(), "prompt_submit");
    event.harness = "claude".into();
    event.text = hook.prompt;
    match Detector::default().inspect(&event) {
        Ok(result) if result.decision == "block" => claude_block(
            output,
            "Runeward Guard detected a possible secret in this prompt.",
        ),
        Ok(_) => Ok(()),
        Err(_) => claude_block(output, "Runeward Guard could not inspect this prompt."),
    }
}

fn tool_deny<W: Write>(output: &mut W, reason: &str) -> Result<(), String> {
    serde_json::to_writer(&mut *output, &serde_json::json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":reason}})).map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())
}

fn claude_tool_hook<R: Read, W: Write>(input: &mut R, output: &mut W) -> Result<(), String> {
    let data = match read_limited(input) {
        Ok(data) => data,
        Err(_) => return tool_deny(output, "Runeward Guard could not inspect this tool call."),
    };
    let Ok(hook): Result<ToolInput, _> = parse_exact(&data) else {
        return tool_deny(output, "Runeward Guard could not inspect this tool call.");
    };
    if hook.hook_event_name != "PreToolUse" || hook.tool_name.is_empty() {
        return tool_deny(output, "Runeward Guard could not inspect this tool call.");
    }
    if !matches!(hook.tool_name.as_str(), "Bash" | "PowerShell") {
        return Ok(());
    }
    let Some(command) = hook
        .tool_input
        .and_then(|tool| tool.command)
        .filter(|command| !command.is_empty())
    else {
        return tool_deny(output, "Runeward Guard could not inspect this tool call.");
    };
    let keychain_cli = Regex::new(r"(?i)(?:^|[^a-z0-9_])(?:/usr/bin/)?security\s+(?:find-generic-password|find-internet-password|dump-keychain|export|unlock-keychain)\b").expect("constant regex");
    if keychain_cli.is_match(&command)
        || command.to_ascii_lowercase().contains("library/keychains/")
    {
        return tool_deny(
            output,
            "Runeward Guard blocked a Keychain-related tool command.",
        );
    }
    Ok(())
}

fn setup_command(args: &[String], output: &mut impl Write) -> Result<(), String> {
    let mut id = None;
    let mut binary = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--extension-id" => id = rest.next().map(String::as_str),
            "--host-binary" => binary = rest.next().map(String::as_str),
            _ => return Err(format!("unexpected setup-chrome argument: {arg}")),
        }
    }
    let manifest = host::setup_chrome(
        id.ok_or("missing --extension-id")?,
        Path::new(binary.ok_or("missing --host-binary")?),
    )?;
    writeln!(
        output,
        "Chrome native host configured: {}",
        manifest.display()
    )
    .map_err(|error| error.to_string())
}

fn monitor_command(args: &[String], output: &mut impl Write) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("monitor currently requires macOS".into());
    }
    let mut directory = None;
    let mut socket = None;
    let mut interval = Duration::from_secs(2);
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--dir" => directory = rest.next().map(PathBuf::from),
            "--socket" => socket = rest.next().map(PathBuf::from),
            "--interval" => {
                interval = parse_duration(rest.next().ok_or("missing --interval value")?)?
            }
            _ => return Err(format!("unexpected monitor argument: {arg}")),
        }
    }
    if interval < Duration::from_millis(250) {
        return Err("monitor requires --interval >= 250ms".into());
    }
    let directory = directory.ok_or("monitor requires --dir")?;
    let socket = match socket {
        Some(socket) => socket,
        None => wire::socket_path()?,
    };
    eprintln!(
        "Guard monitoring {}; browser socket {}",
        directory.display(),
        socket.display()
    );
    run_monitor(directory, socket, interval, output)
}

fn parse_duration(raw: &str) -> Result<Duration, String> {
    if let Some(milliseconds) = raw.strip_suffix("ms") {
        return milliseconds
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|error| error.to_string());
    }
    if let Some(seconds) = raw.strip_suffix('s') {
        return seconds
            .parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|error| error.to_string());
    }
    Err("interval must use ms or s".into())
}

fn process_event<W: Write>(
    event: &mut Event,
    detector: &mut Detector,
    output: &mut W,
) -> Result<(), String> {
    event.time = Utc::now();
    let result = detector.inspect(event)?;
    let record = MonitorOutput {
        event_id: &result.event_id,
        time: event.time,
        kind: &event.kind,
        decision: &result.decision,
        findings: &result.findings,
    };
    serde_json::to_writer(&mut *output, &record).map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())
}

fn scan<W: Write, C: Fn(&Path) -> bool>(
    scanner: &mut observer::ScreenshotScanner<C>,
    detector: &mut Detector,
    output: &mut W,
) -> Result<(), String> {
    for mut event in scanner.scan().map_err(|error| error.to_string())? {
        process_event(&mut event, detector, output)?
    }
    Ok(())
}

fn receive(stream: &mut UnixStream, sequence: u64) -> Result<Event, String> {
    let mut event = wire::read_event(stream)?;
    event.id = format!("browser-{sequence}");
    event.time = Utc::now();
    Detector::default().inspect(&event)?;
    Ok(event)
}

fn run_monitor<W: Write>(
    directory: PathBuf,
    socket: PathBuf,
    interval: Duration,
    output: &mut W,
) -> Result<(), String> {
    let mut scanner = observer::ScreenshotScanner::new(directory, observer::apple_screenshot)
        .map_err(|error| error.to_string())?;
    scanner.scan().map_err(|error| error.to_string())?; // baseline existing images
    let listener = wire::listen(&socket)?;
    let running = Arc::new(AtomicBool::new(true));
    let flag = running.clone();
    ctrlc::set_handler(move || flag.store(false, Ordering::SeqCst))
        .map_err(|error| error.to_string())?;
    let mut detector = Detector::default();
    let mut sequence = 0;
    let mut next_scan = Instant::now() + interval;
    while running.load(Ordering::SeqCst) {
        match listener.listener.accept() {
            Ok((mut stream, _)) => {
                sequence += 1;
                let event = receive(&mut stream, sequence);
                let mut accepted = false;
                if let Ok(mut event) = event {
                    scan(&mut scanner, &mut detector, output)?;
                    accepted = process_event(&mut event, &mut detector, output).is_ok();
                }
                let _ = stream.write_all(&[u8::from(accepted)]);
                if !accepted {
                    eprintln!("Guard rejected a browser event");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
            Err(error) => return Err(error.to_string()),
        }
        if Instant::now() >= next_scan {
            scan(&mut scanner, &mut detector, output)?;
            next_scan = Instant::now() + interval;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        return Err(
            "usage: guard <inspect|check|claude-hook|claude-tool-hook|monitor|setup-chrome>".into(),
        );
    };
    let mut stdout = io::stdout().lock();
    match command.as_str() {
        "inspect" if args.len() == 1 => inspect(&mut io::stdin().lock(), &mut stdout).map(|_| 0),
        "check" if args.len() == 1 => {
            check(&mut io::stdin().lock(), &mut stdout).map(|blocked| if blocked { 2 } else { 0 })
        }
        "claude-hook" if args.len() == 1 => {
            claude_hook(&mut io::stdin().lock(), &mut stdout).map(|_| 0)
        }
        "claude-tool-hook" if args.len() == 1 => {
            claude_tool_hook(&mut io::stdin().lock(), &mut stdout).map(|_| 0)
        }
        "monitor" => monitor_command(&args[1..], &mut stdout).map(|_| 0),
        "setup-chrome" => setup_command(&args[1..], &mut stdout).map(|_| 0),
        _ => Err("unknown command or unexpected arguments".into()),
    }
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("guard: {error}");
            std::process::exit(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_prompt_is_blocked_without_echo() {
        let mut output = Vec::new();
        claude_hook(&mut br#"{"hook_event_name":"UserPromptSubmit","prompt":"password=example-only-credential"}"#.as_slice(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("\"decision\":\"block\""));
        assert!(!text.contains("example-only-credential"));
    }

    #[test]
    fn keychain_command_is_denied() {
        let mut output = Vec::new();
        claude_tool_hook(&mut br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"security find-generic-password"}}"#.as_slice(), &mut output).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("\"permissionDecision\":\"deny\"")
        );
    }
}
