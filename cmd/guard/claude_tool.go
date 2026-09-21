package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

type claudeToolInput struct {
	HookEventName string `json:"hook_event_name"`
	ToolName      string `json:"tool_name"`
	ToolInput     struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

type preToolDecision struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

var keychainCLI = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])(?:/usr/bin/)?security\s+(?:find-generic-password|find-internet-password|dump-keychain|export|unlock-keychain)\b`)

func claudeToolHook(input io.Reader, output io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(input, maxEventBytes+1))
	if err != nil || len(data) > maxEventBytes {
		return writeToolDeny(output, "Runeward Guard could not inspect this tool call.")
	}
	var hook claudeToolInput
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&hook); err != nil {
		return writeToolDeny(output, "Runeward Guard could not inspect this tool call.")
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) || hook.HookEventName != "PreToolUse" {
		return writeToolDeny(output, "Runeward Guard could not inspect this tool call.")
	}
	if hook.ToolName == "" {
		return writeToolDeny(output, "Runeward Guard could not inspect this tool call.")
	}
	if hook.ToolName != "Bash" && hook.ToolName != "PowerShell" {
		return nil
	}
	if hook.ToolInput.Command == "" {
		return writeToolDeny(output, "Runeward Guard could not inspect this tool call.")
	}
	command := hook.ToolInput.Command
	if keychainCLI.MatchString(command) || strings.Contains(strings.ToLower(command), "library/keychains/") {
		return writeToolDeny(output, "Runeward Guard blocked a Keychain-related tool command.")
	}
	return nil
}

func writeToolDeny(output io.Writer, reason string) error {
	decision := preToolDecision{}
	decision.HookSpecificOutput.HookEventName = "PreToolUse"
	decision.HookSpecificOutput.PermissionDecision = "deny"
	decision.HookSpecificOutput.PermissionDecisionReason = reason
	return json.NewEncoder(output).Encode(decision)
}
