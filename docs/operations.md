# Local operations (experimental)

Guard currently runs as a foreground command. It does not install or supervise a signed macOS system extension, start automatically at login, manage updates, or enforce a central retention policy. These gaps matter before calling it an EDR product.

## Check local setup

```sh
./target/release/guard doctor --dir /absolute/path/to/screenshot-folder
```

`doctor` checks whether the chosen folder is readable, the native-messaging config is valid, and the monitor socket exists as an owner-only Unix socket. Socket presence does **not** prove the monitor is running; `endpoint_security_live: "not_verified"` is intentional. A signed, entitled deployment needs separate live-sensor health and coverage-loss reporting.

## Keep a bounded, private record

The monitor writes metadata-only JSONL to standard output. Choose a private log location and run with an owner-only file creation mask:

```sh
umask 077
./target/release/guard monitor --dir /absolute/path/to/screenshot-folder > /absolute/private/path/guard-monitor.jsonl
```

Guard does not rotate or delete this log. The operator must set a retention period and protect the file. Do not redirect it into a shared directory. The log contains times, event kinds, decisions, and finding messages—not raw prompt text, screenshot bytes, or screenshot paths.

To summarize a private Guard log without returning its individual events:

```sh
./target/release/guard audit-summary --file /absolute/private/path/guard-monitor.jsonl --since 2026-09-01T00:00:00Z
```

The command refuses symlinks, non-owner-only files, and files over 64 MiB. It scans only the selected Guard log and returns counts by finding rule with the first and last matching timestamps. It cannot reconstruct disclosures from before Guard was running, infer upload from browser history, or recover unseen prompt content.

Before a managed rollout, add a signed and notarized app/system-extension bundle, user approval and Full Disk Access guidance, a service supervisor, durable coverage-loss alerts, bounded log rotation and deletion, signed updates, and recovery/uninstall procedures. The live Endpoint Security sensor remains gated by Apple's entitlement and signing requirements.
