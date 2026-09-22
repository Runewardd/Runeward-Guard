# Local operations (experimental)

Guard runs as a foreground command by default and can write an opt-in user-level `launchd` agent for the unprivileged folder monitor. It does not automatically install or activate that agent, deploy a signed macOS system extension, manage updates, or enforce a central retention policy. These gaps matter before calling it an EDR product.

## Check local setup

```sh
./target/release/guard doctor --dir /absolute/path/to/screenshot-folder
```

`doctor` checks whether the chosen folder is readable, the native-messaging config is valid, and the monitor socket exists as an owner-only Unix socket. Socket presence does **not** prove the monitor is running; `endpoint_security_live: "not_verified"` is intentional. A signed, entitled deployment needs separate live-sensor health and coverage-loss reporting.

## Keep a bounded, private record

The monitor can write metadata-only JSONL to a private daily file and delete its own expired daily files. Choose an absolute directory under your control:

```sh
./target/release/guard monitor --dir /absolute/path/to/screenshot-folder --audit-dir /absolute/private/audit-directory --retain-days 30
```

The audit directory and files must be owned by the current user and accessible only to that user. Guard creates new daily files with mode `0600`, caps each at 64 MiB, and at startup or the next write after a day rollover prunes only owner-owned files named `guard-YYYY-MM-DD.jsonl` older than the selected 1–365-day retention window. If the daily file fills or cannot be written, monitoring stops with an error rather than silently losing findings. The log contains times, event kinds, decisions, and finding messages—not raw prompt text, screenshot bytes, or screenshot paths. Without `--audit-dir`, the monitor still writes to standard output and does not manage retention.

To summarize a private Guard log without returning its individual events:

```sh
./target/release/guard audit-summary --file /absolute/private/audit-directory/guard-2026-09-22.jsonl --since 2026-09-01T00:00:00Z
```

The command refuses symlinks, non-owner-only files, and files over 64 MiB. It scans only the selected Guard log and returns counts by finding rule with the first and last matching timestamps. It cannot reconstruct disclosures from before Guard was running, infer upload from browser history, or recover unseen prompt content.

## Run the folder monitor at login

On macOS, first create a private audit directory. Then configure a user-level LaunchAgent with absolute paths to the built binary and the screenshot folder:

```sh
install -d -m 700 /absolute/private/audit-directory
./target/release/guard setup-launch-agent --binary /absolute/path/to/guard --dir /absolute/path/to/screenshot-folder --audit-dir /absolute/private/audit-directory --retain-days 30
```

The setup command validates the executable and directories, writes an owner-only plist at `~/Library/LaunchAgents/com.runeward.guard.monitor.plist`, and refuses to overwrite an existing one. It does **not** load or start it. Review that file, then bootstrap it for the logged-in user with `launchctl bootstrap gui/UID /absolute/path/to/com.runeward.guard.monitor.plist`, replacing `UID` and the path. Check status with `launchctl print gui/UID/com.runeward.guard.monitor`. To stop it, use `launchctl bootout gui/UID/com.runeward.guard.monitor`. The LaunchAgent uses `KeepAlive`, a 30-second throttle, a private stderr log, and the daily audit directory. Guard handles SIGTERM and can recover its own stale, private monitor socket after an abnormal exit. This agent monitors only the selected folder and browser bridge; it does not run the privileged Endpoint Security sensor. See [Apple's launchd agent guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) for the user-agent model.

Before a managed rollout, add a signed and notarized app/system-extension bundle, user approval and Full Disk Access guidance, durable coverage-loss alerts, signed updates, and managed recovery/uninstall procedures. The live Endpoint Security sensor remains gated by Apple's entitlement and signing requirements.
