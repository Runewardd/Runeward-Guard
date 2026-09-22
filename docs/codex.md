# Codex hooks (opt-in)

Codex supports [lifecycle hooks](https://learn.chatgpt.com/docs/hooks). Guard provides two local Rust commands for a narrow, testable integration:

- `guard codex-prompt-hook` checks a submitted text prompt for private-key blocks, token patterns, and password-like assignments. It returns Codex's documented `decision: "block"` response without echoing the matched text.
- `guard codex-tool-hook` checks a `Bash` tool command for selected macOS `security` Keychain subcommands or a `Library/Keychains/` path. It does not see direct Security.framework calls or every way to construct a shell command.

Both commands consume one JSON hook input on standard input. A benign input produces no output; an invalid or oversized input is blocked. Test only with synthetic strings:

```sh
printf '%s\n' '{"hook_event_name":"UserPromptSubmit","prompt":"password=example-only-credential"}' | ./target/release/guard codex-prompt-hook
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"security find-generic-password"}}' | ./target/release/guard codex-tool-hook
```

After building the binary, opt in by adding the following to your **user-level** `~/.codex/hooks.json`. Replace the placeholder with the absolute path to the `guard` binary and merge these entries with any hooks you already have:

```json
{
  "hooks": {
    "UserPromptSubmit": [{
      "hooks": [{
        "type": "command",
        "command": "/absolute/path/to/guard codex-prompt-hook",
        "timeout": 5
      }]
    }],
    "PreToolUse": [{
      "matcher": "^Bash$",
      "hooks": [{
        "type": "command",
        "command": "/absolute/path/to/guard codex-tool-hook",
        "timeout": 5
      }]
    }]
  }
}
```

Use Codex's `/hooks` command to inspect and trust the exact hook definitions. This is not installed automatically. Hooks are voluntary controls, not an endpoint boundary: untrusted or disabled hooks will not run, a hook launch failure may allow the operation to proceed, and tool coverage has documented exceptions. The prompt hook does not inspect attachments, tool results, other AI apps, or prompts entered outside the Codex client. Do not use a real credential to test it.
