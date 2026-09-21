# Opt-in Claude Code prompt check

[Claude Code's `UserPromptSubmit` command hook](https://code.claude.com/docs/en/hooks#userpromptsubmit) receives the submitted prompt before the model processes it. Guard can inspect that text locally and emit Claude's documented JSON `decision: "block"` response with `suppressOriginalPrompt: true`. A benign prompt produces no hook output.

Build a binary:

```sh
go build -o ./bin/guard ./cmd/guard
```

Test the adapter without installing a hook:

```sh
./bin/guard claude-hook < examples/claude-hook.json
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
    ]
  }
}
```

This is a voluntary text-prompt check, not endpoint-wide enforcement. It does not inspect attachments, tool results, browser chats, Codex, Copilot, or other applications. An operator who controls hook settings can remove it; if Claude cannot launch the hook or the hook times out, Claude's command-hook behavior may allow the prompt to proceed. For sensitive deployments, verify the effective hook configuration and test a synthetic block in the exact Claude version in use. Do not test with real credentials.
