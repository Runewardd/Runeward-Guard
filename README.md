# Runeward Guard

Runeward Guard is a separate endpoint-side project intended to complement [Runeward](https://github.com/Runewardd/runeward). Runeward governs agents inside its sandbox; Guard is being built to detect risky activity by AI harnesses on a person's own machine.

**Current status: experimental endpoint monitoring, not a complete EDR.** Guard can watch a selected macOS folder for files bearing Apple's screenshot marker and correlate their local SHA-256 digests with image-selection events from an opt-in Chrome extension on ChatGPT and Claude. The extension can also confirm a narrow class of matching completed HTTP requests. It provides opt-in Claude Code and Codex prompt hooks. It does not observe all Keychain access, cover most browser upload methods, inspect other browsers or desktop AI apps, or install a system extension. Do not rely on it as complete disclosure prevention.

## Try the first slice

The native Guard CLI, detector, screenshot monitor, and browser bridge are written in Rust. The Chrome extension is JavaScript because it runs inside Chrome. Build with Rust 1.95 or newer; dependencies are locked in `Cargo.lock`.

```sh
cargo test --locked
cargo build --locked
./target/debug/guard inspect < examples/events.ndjson
```

`inspect` consumes newline-delimited JSON events and returns one decision per event. The example demonstrates a captured screenshot followed by a matching upload to an AI destination, a password-like prompt, and a Keychain-access signal. These are **synthetic events**, not observations made by Guard on your computer.

For a synchronous, single-event hook, use `check`:

```sh
printf '%s\n' '{"id":"example","time":"2026-09-21T12:00:00Z","kind":"prompt_submit","harness":"codex","text":"password=example-only-credential"}' | ./target/debug/guard check
```

`check` exits 0 for `allow` or `warn`, 2 for `block`, and 1 when inspection fails. A hook adapter must interpret these exit codes and enforce the block.

For the first actual harness integration, see [the opt-in Claude Code hook](docs/claude-code.md). It blocks a detected password-like string, token, or private-key header before Claude processes a submitted text prompt. It does not cover every way Claude can receive sensitive information.

For live screenshot-to-browser correlation, see [macOS monitoring setup](docs/macos-monitor.md). The browser extension observes file selection, drag/drop, and paste on supported AI pages. It only reports a completed HTTP request when the request body contains an exact digest match; this does not prove what the server retained. Opt-in prompt and Keychain-command hooks are available for [Claude Code](docs/claude-code.md) and [Codex](docs/codex.md).

For read-only setup checks and bounded retrospective summaries of Guard's own logs, see [local operations](docs/operations.md).

For the experimental macOS Endpoint Security sensor and an entitlement-free replay, see [the sensor notes](docs/endpoint-security.md). The live sensor is not usable as an unsigned Cargo binary and does not identify Keychain item retrieval through `securityd`.

## Event contract

Every event needs `id`, RFC 3339 `time`, and `kind`. The supported kinds are:

Events in a feed must be ordered by timestamp. IDs are 1–128 ASCII letters, digits, `.`, `_`, `:`, or `-`, starting with a letter or digit. Supplied file paths must be absolute. Metadata events must not contain `text`.

| Kind | Additional required fields | Result |
| --- | --- | --- |
| `prompt_submit` | `harness`, `text` | Flags private-key headers, provider-token shapes, and possible password assignments. |
| `keychain_access` | `harness` | Warns that a harness accessed Keychain. This is **not** proof that a secret was sent to an AI service. |
| `screen_capture` | Absolute `path` or SHA-256 `digest` | Remembers a one-way path key or image digest in memory for 15 minutes. The macOS observer sends only a digest. |
| `file_upload` | `path`, `destination` | Warns when that same captured path was uploaded to a recognized AI destination within 15 minutes. |
| `file_attach` | SHA-256 `digest`, `destination` | Warns when a recently observed screenshot is selected on a supported AI page. It does not confirm delivery. |
| `image_paste` | SHA-256 `digest`, `destination` | Warns on an image pasted into a supported AI page, including clipboard-only images. Without a matching saved screenshot, Guard cannot establish screenshot provenance; it does not confirm delivery. |
| `image_request_completed` | SHA-256 `digest`, `destination` | Warns when a trusted browser adapter observes exact selected-image bytes in a same-origin HTTP request body and a 2xx completion. This does not establish server retention. |

`harness` names the adapter-supplied source, such as `codex`, `claude`, or `copilot`. `application` is optional context. `destination` must be an HTTPS or WSS URL; hostnames are matched on exact domain boundaries, not substrings. A `file_upload` event must mean an actual upload observed by a trusted adapter, not merely that a file was opened or selected. Path-only correlation cannot prove the same file bytes were uploaded if a path was reused.

Prompt text is inspected in memory and is never included in a finding. The monitor reads local image bytes only to compute a digest, then discards them; the extension hashes selected image bytes locally and sends only the digest to the native host. Guard makes no outbound network connection and does not write an event database. Input and output still pass through your shell and whatever adapter you choose; do not record real secrets in terminal history or demo fixtures.

See [SECURITY.md](SECURITY.md) for the data-handling and trust model, [docs/roadmap.md](docs/roadmap.md) for the build plan, and [the macOS entitlement note](docs/endpoint-security.md) for the system-wide sensor requirement.
