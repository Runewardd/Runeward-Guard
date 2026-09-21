package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestClaudeToolHookDeniesKeychainCommandWithoutEcho(t *testing.T) {
	input := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"/usr/bin/security find-generic-password -s sensitive-service -w"}}`
	var output bytes.Buffer
	if err := claudeToolHook(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"permissionDecision":"deny"`) || strings.Contains(output.String(), "sensitive-service") {
		t.Fatalf("unexpected response: %s", output.String())
	}
}

func TestClaudeToolHookAllowsUnrelatedCommandSilently(t *testing.T) {
	input := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"go test ./..."}}`
	var output bytes.Buffer
	if err := claudeToolHook(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("expected no output, got %q", output.String())
	}
}

func TestClaudeToolHookDeniesMalformedInput(t *testing.T) {
	var output bytes.Buffer
	if err := claudeToolHook(strings.NewReader(`{"hook_event_name":"PreToolUse"}`), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"permissionDecision":"deny"`) {
		t.Fatal("missing tool name should be denied")
	}
}
