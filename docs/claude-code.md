# Opt-in Claude Code prompt check

[Claude Code's `UserPromptSubmit` command hook](https://code.claude.com/docs/en/hooks#userpromptsubmit) receives the submitted prompt before the model processes it. Guard can inspect that text locally and emit Claude's documented JSON `decision: "block"` response with `suppressOriginalPrompt: true`. A benign prompt produces no hook output.

Guard also supports a [Claude Code `PreToolUse` hook](https://code.claude.com/docs/en/hooks#pretooluse) for Bash/PowerShell tool calls. It denies commands that directly invoke selected macOS `security` Keychain subcommands or name a `Library/Keychains/` path. This is a narrow, best-effort command check, not observation of every Keychain API call.

Build a binary:

```sh
cargo build --release --locked
```

Test the adapter without installing a hook:

```sh
./target/release/guard claude-hook < examples/claude-hook.json
```

To opt in for one project, add this entry to that project's `.claude/settings.json`, replacing the example path with the **absolute path** to your built `guard` binary. Merge the `UserPromptSubmit` entry with any existing hooks instead of replacing them:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/guard",
            "args": ["claude-hook"],
            "timeout": 5
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/guard",
            "args": ["claude-tool-hook"],
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

These are voluntary prompt and command checks, not endpoint-wide enforcement. They do not inspect attachments, tool results, browser chats, Codex, Copilot, or other applications. A shell command can be constructed in ways the simple Keychain pattern misses, and a native Security.framework call need not invoke `/usr/bin/security`. An operator who controls hook settings can remove them; if Claude cannot launch a hook or it times out, Claude's command-hook behavior may allow the action to proceed. For sensitive deployments, verify the effective hook configuration and test synthetic blocks in the exact Claude version in use. Do not test with real credentials.
