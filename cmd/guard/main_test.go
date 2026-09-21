package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestInspectDoesNotEchoPrompt(t *testing.T) {
	secret := "correct-horse-battery-staple"
	input := `{"id":"1","time":"2026-09-21T12:00:00Z","kind":"prompt_submit","harness":"codex","text":"password=` + secret + `"}` + "\n"
	var output bytes.Buffer
	if err := inspect(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("result leaked prompt content")
	}
	if !strings.Contains(output.String(), `"decision":"block"`) {
		t.Fatalf("unexpected result: %s", output.String())
	}
}

func TestInspectRejectsUnknownFields(t *testing.T) {
	input := `{"id":"1","time":"2026-09-21T12:00:00Z","kind":"screen_capture","path":"/tmp/a.png","surprise":1}` + "\n"
	if err := inspect(strings.NewReader(input), &bytes.Buffer{}); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestCheckReturnsBlockDecision(t *testing.T) {
	input := `{"id":"1","time":"2026-09-21T12:00:00Z","kind":"prompt_submit","harness":"codex","text":"password=example-only-credential"}`
	var output bytes.Buffer
	blocked, err := check(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if !blocked || !strings.Contains(output.String(), `"decision":"block"`) {
		t.Fatalf("unexpected outcome: blocked=%v output=%s", blocked, output.String())
	}
}

func TestCheckRejectsMultipleEvents(t *testing.T) {
	input := `{"id":"1","time":"2026-09-21T12:00:00Z","kind":"keychain_access","harness":"codex"}` + "\n" + `{"id":"2"}`
	if _, err := check(strings.NewReader(input), &bytes.Buffer{}); err == nil {
		t.Fatal("expected multiple events error")
	}
}

func TestClaudeHookBlocksWithoutEchoingPrompt(t *testing.T) {
	secret := "example-only-credential"
	input := `{"hook_event_name":"UserPromptSubmit","prompt":"password=` + secret + `","session_id":"test"}`
	var output bytes.Buffer
	if err := claudeHook(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"decision":"block"`) || !strings.Contains(output.String(), `"suppressOriginalPrompt":true`) {
		t.Fatalf("unexpected response: %s", output.String())
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("hook leaked prompt content")
	}
}

func TestClaudeHookAllowsBenignPromptSilently(t *testing.T) {
	input := `{"hook_event_name":"UserPromptSubmit","prompt":"Explain this function"}`
	var output bytes.Buffer
	if err := claudeHook(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("expected no output, got %q", output.String())
	}
}

func TestClaudeHookBlocksMalformedInput(t *testing.T) {
	var output bytes.Buffer
	if err := claudeHook(strings.NewReader(`{"hook_event_name":"UserPromptSubmit"}`), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"decision":"block"`) {
		t.Fatalf("unexpected response: %s", output.String())
	}
}
