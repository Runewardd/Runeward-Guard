# GitHub Copilot CLI hooks (opt-in)

[Copilot CLI hooks](https://docs.github.com/en/copilot/reference/hooks-reference) run local commands during a session. Guard provides two Rust adapters for Copilot CLI:

- `guard copilot-prompt-hook` reads the `userPromptTransformed` payload. If its model-facing text matches Guard's secret heuristics, it returns a fixed `modifiedTransformedPrompt` that asks for a clean resubmission. This is a rewrite, **not** a rejected prompt: the original user text may still appear in Copilot's local timeline, and this does not inspect attachments.
- `guard copilot-tool-hook` reads `preToolUse` payloads for `bash` or `powershell`. It denies selected Keychain-related commands with Copilot's documented `permissionDecision: "deny"` response. It cannot see direct Security.framework calls or every shell construction.

Test the adapters with synthetic inputs before configuring Copilot:

```sh
printf '%s\n' '{"transformedPrompt":"password=example-only-credential"}' | ./target/release/guard copilot-prompt-hook
printf '%s\n' '{"toolName":"bash","toolArgs":"{\"command\":\"security find-generic-password\"}"}' | ./target/release/guard copilot-tool-hook
```

For an opt-in local setup, add a file at `~/.copilot/hooks/runeward-guard.json`. Replace the placeholder with the absolute path to your `guard` binary:

```json
{
  "version": 1,
  "hooks": {
    "userPromptTransformed": [{
      "type": "command",
      "exec": "/absolute/path/to/guard",
      "args": ["copilot-prompt-hook"],
      "timeoutSec": 5
    }],
    "preToolUse": [{
      "type": "command",
      "matcher": "bash|powershell",
      "exec": "/absolute/path/to/guard",
      "args": ["copilot-tool-hook"],
      "timeoutSec": 5
    }]
  }
}
```

This configuration is for **Copilot CLI on the local machine**, not Copilot cloud agent, an IDE extension, or Copilot Chat in a browser. We have unit-tested the payload parser and output but have not validated it in a live Copilot CLI session. Hook settings can be changed or disabled by the local user; command-hook timeouts may proceed normally. In particular, Copilot's `userPromptSubmitted` command hook discards output, so Guard does not claim it can block submission there. Do not test with a real credential.
