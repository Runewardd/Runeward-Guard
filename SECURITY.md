# Security model and responsible use

Guard's current executable combines a detector, an unprivileged macOS screenshot-folder monitor, an opt-in Chrome extension, and a Claude Code hook. It is not a privileged endpoint sensor. A local user can forge, omit, or reorder browser events or screenshot metadata. The Claude Code hook enforces detected prompt-text findings only when the hook executes successfully. Decisions cannot establish that a disclosure did or did not happen across other channels without a trustworthy collection and enforcement path.

## Privacy boundaries

- Prompt content is accepted only when an operator explicitly pipes it into `guard check` or `guard inspect`, or installs the `guard claude-hook` integration. The detector does not persist or return the content; findings contain rule identifiers and fixed messages.
- The macOS monitor reads screenshot file bytes to compute SHA-256, then discards them. The Chrome extension similarly hashes selected image bytes in browser memory. Raw image bytes are not sent over the native-message socket or to a remote service, but a digest can still identify a known image and is **not anonymization**. The experimental path-only event feed separately hashes supplied paths in memory.
- Keychain events must represent access metadata only. Do not supply Keychain item values or passwords as event fields.
- There is no telemetry endpoint, remote control service, automatic history scan, or network proxy in this version. `guard monitor` is a foreground local process with a user-private Unix socket; it stops when the process exits.
- The 1 MiB per-event input limit reduces accidental ingestion of very large prompts; it is not a complete resource budget or production hardening limit.

## Detection limits

Pattern detection is incomplete and can produce false positives. A `possible_password_in_prompt` finding is a heuristic, not confirmation of a real password. A Keychain access is not proof of exfiltration. The macOS monitor sees only new files in explicitly selected directories, with Apple's screenshot extended attribute. That marker can be copied or forged, and clipboard-only captures leave no watched file. The Chrome extension observes image selection/drop/paste on two sites, not completed network delivery. A digest match supports a **selection attempt**, not proof of sharing. The CLI's generic `block` decision has no effect unless a separate hook adapter enforces it before submission.

The default approach for future endpoint collection is metadata-first and opt-in. Private prompt text, screenshots, browser content, and historical data must not be collected silently. A macOS Endpoint Security extension will require Apple's entitlement and system approval; it must be designed and tested separately from this prototype. Even Endpoint Security file events alone cannot necessarily attribute Security.framework-mediated Keychain access by `securityd` to a particular AI client. Claude Code command-hook timeouts and launch failures can allow a prompt to continue, so this hook is not a tamper-resistant policy boundary.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository if enabled, or contact the maintainers privately. Do not put live secrets, screenshots, or exploit details in a public issue.
