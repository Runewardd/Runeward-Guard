# Security model and responsible use

Guard's current executable is a detector over **adapter-supplied events**, not a privileged endpoint sensor. An untrusted process can forge, omit, or reorder those events. The opt-in Claude Code hook enforces detected prompt-text findings only when the hook executes successfully. Decisions cannot establish that a disclosure did or did not happen across other channels without a trustworthy collection and enforcement path.

## Privacy boundaries

- Prompt content is accepted only when an operator explicitly pipes it into `guard check` or `guard inspect`, or installs the `guard claude-hook` integration. The detector does not persist or return the content; findings contain rule identifiers and fixed messages.
- Screenshot correlation keeps only a SHA-256 digest of the normalized file path in process memory. It does not read image pixels. Path hashing is an accidental-disclosure safeguard, **not anonymization** against an observer who can guess local paths.
- Keychain events must represent access metadata only. Do not supply Keychain item values or passwords as event fields.
- There is no telemetry endpoint, remote control service, background daemon, automatic history scan, or network proxy in this version.
- The 1 MiB per-event input limit reduces accidental ingestion of very large prompts; it is not a complete resource budget or production hardening limit.

## Detection limits

Pattern detection is incomplete and can produce false positives. A `possible_password_in_prompt` finding is a heuristic, not confirmation of a real password. A Keychain access is not proof of exfiltration. A screenshot-upload finding requires two correctly sourced events with the same path; copies, renames, unobserved uploads, and uploads to destinations not in the allowlist can be missed. The CLI's `block` decision has no effect unless a separate hook adapter enforces it before submission.

The default approach for future endpoint collection is metadata-first and opt-in. Private prompt text, screenshots, browser content, and historical data must not be collected silently. A macOS Endpoint Security extension will require Apple's entitlement and system approval; it must be designed and tested separately from this prototype. Claude Code command-hook timeouts and launch failures can allow a prompt to continue, so this hook is not a tamper-resistant policy boundary.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository if enabled, or contact the maintainers privately. Do not put live secrets, screenshots, or exploit details in a public issue.
