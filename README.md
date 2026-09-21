# Runeward Guard

Runeward Guard is a separate endpoint-side project intended to complement [Runeward](https://github.com/Runewardd/runeward). Runeward governs agents inside its sandbox; Guard is being built to detect risky activity by AI harnesses on a person's own machine.

**Current status: foundation, not an installed EDR.** The executable provides an opt-in, local event inspector and a Claude Code prompt hook. It does not watch processes, intercept network traffic, read Keychain, collect screenshots, inspect browser history, or install a system extension. Its findings are only as trustworthy as the adapter supplying each event. Do not rely on it as complete disclosure prevention.

## Try the first slice

Requires Go 1.22 or newer. No third-party Go modules are required.

```sh
go test ./...
go run ./cmd/guard inspect < examples/events.ndjson
```

`inspect` consumes newline-delimited JSON events and returns one decision per event. The example demonstrates a captured screenshot followed by a matching upload to an AI destination, a password-like prompt, and a Keychain-access signal. These are **synthetic events**, not observations made by Guard on your computer.

For a synchronous, single-event hook, use `check`:

```sh
printf '%s\n' '{"id":"example","time":"2026-09-21T12:00:00Z","kind":"prompt_submit","harness":"codex","text":"password=example-only-credential"}' | go run ./cmd/guard check
```

`check` exits 0 for `allow` or `warn`, 2 for `block`, and 1 when inspection fails. A hook adapter must interpret these exit codes and enforce the block. `go run` itself may wrap the child's exit status, so build a binary before using it in a hook.

For the first actual harness integration, see [the opt-in Claude Code hook](docs/claude-code.md). It blocks a detected password-like string, token, or private-key header before Claude processes a submitted text prompt. It does not cover every way Claude can receive sensitive information.

## Event contract

Every event needs `id`, RFC 3339 `time`, and `kind`. The supported kinds are:

Events in a feed must be ordered by timestamp. IDs are 1–128 ASCII letters, digits, `.`, `_`, `:`, or `-`, starting with a letter or digit. File paths must be absolute. Metadata events must not contain `text`.

| Kind | Additional required fields | Result |
| --- | --- | --- |
| `prompt_submit` | `harness`, `text` | Flags private-key headers, provider-token shapes, and possible password assignments. |
| `keychain_access` | `harness` | Warns that a harness accessed Keychain. This is **not** proof that a secret was sent to an AI service. |
| `screen_capture` | `path` | Remembers a one-way path key in memory for 15 minutes. |
| `file_upload` | `path`, `destination` | Warns when that same captured path was uploaded to a recognized AI destination within 15 minutes. |

`harness` names the adapter-supplied source, such as `codex`, `claude`, or `copilot`. `application` is optional context. `destination` must be an HTTPS or WSS URL; hostnames are matched on exact domain boundaries, not substrings. A `file_upload` event must mean an actual upload observed by a trusted adapter, not merely that a file was opened or selected. Path-only correlation cannot prove the same file bytes were uploaded if a path was reused.

Prompt text is inspected in memory and is never included in a finding. The CLI makes no outbound network connection and does not write an event database. Input and output still pass through your shell and whatever adapter you choose; do not record real secrets in terminal history or demo fixtures.

See [SECURITY.md](SECURITY.md) for the data-handling and trust model and [docs/roadmap.md](docs/roadmap.md) for the endpoint collection plan.
