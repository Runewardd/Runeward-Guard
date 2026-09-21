package detector

import (
	"strings"
	"testing"
	"time"
)

var baseTime = time.Date(2026, time.September, 21, 12, 0, 0, 0, time.UTC)

func TestPromptSecretIsBlockedWithoutEchoingSecret(t *testing.T) {
	d := New()
	secret := "ultra-secret-credential"
	result, err := d.Inspect(Event{ID: "e1", Time: baseTime, Kind: "prompt_submit", Harness: "claude", Text: "password=" + secret})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "block" || len(result.Findings) != 1 || result.Findings[0].Rule != "possible_password_in_prompt" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if strings.Contains(result.Findings[0].Message, secret) {
		t.Fatal("finding leaked inspected content")
	}
}

func TestScreenshotRequiresCorrelatedCaptureAndAIDestination(t *testing.T) {
	d := New()
	path := "/tmp/Screen Shot 2026-09-21.png"
	_, err := d.Inspect(Event{ID: "capture", Time: baseTime, Kind: "screen_capture", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, destination, path, want string
		at                            time.Time
	}{
		{"known AI host", "https://claude.ai/new", path, "warn", baseTime.Add(time.Minute)},
		{"lookalike host", "https://claude.ai.evil.example/upload", path, "allow", baseTime.Add(time.Minute)},
		{"unrelated file", "https://chatgpt.com/", "/tmp/other.png", "allow", baseTime.Add(time.Minute)},
		{"expired capture", "https://chatgpt.com/", path, "allow", baseTime.Add(16 * time.Minute)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := d.Inspect(Event{ID: strings.ReplaceAll(tc.name, " ", "-"), Time: tc.at, Kind: "file_upload", Path: tc.path, Destination: tc.destination})
			if err != nil {
				t.Fatal(err)
			}
			if result.Decision != tc.want {
				t.Fatalf("decision = %q, want %q", result.Decision, tc.want)
			}
		})
	}
}

func TestKeychainAccessIsWarningNotProofOfDisclosure(t *testing.T) {
	result, err := New().Inspect(Event{ID: "e1", Time: baseTime, Kind: "keychain_access", Harness: "codex"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "warn" || result.Findings[0].Rule != "agent_keychain_access" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestDestinationRequiresExactDomainBoundary(t *testing.T) {
	for _, raw := range []string{"http://chatgpt.com/", "https://chatgpt.com.evil.test/", "https://chatgpt.com@evil.test/", "file://chatgpt.com/"} {
		if isAIDestination(raw) {
			t.Fatalf("accepted destination %q", raw)
		}
	}
	if !isAIDestination("https://api.openai.com/v1/responses") {
		t.Fatal("expected OpenAI API destination")
	}
}

func TestInvalidEventFailsClosed(t *testing.T) {
	_, err := New().Inspect(Event{ID: "e1", Time: baseTime, Kind: "prompt_submit", Harness: "codex"})
	if err == nil {
		t.Fatal("expected missing text error")
	}
}

func TestMetadataEventRejectsRawText(t *testing.T) {
	_, err := New().Inspect(Event{ID: "e1", Time: baseTime, Kind: "keychain_access", Harness: "codex", Text: "should-not-be-collected"})
	if err == nil {
		t.Fatal("expected keychain text rejection")
	}
}

func TestOutOfOrderEventsFail(t *testing.T) {
	d := New()
	_, err := d.Inspect(Event{ID: "e1", Time: baseTime, Kind: "screen_capture", Path: "/tmp/a.png"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Inspect(Event{ID: "e2", Time: baseTime.Add(-time.Second), Kind: "file_upload", Path: "/tmp/a.png", Destination: "https://chatgpt.com/"})
	if err == nil {
		t.Fatal("expected ordering error")
	}
}

func TestBrowserFileSelectionMatchesScreenshotDigest(t *testing.T) {
	d := New()
	digest := strings.Repeat("a", 64)
	_, err := d.Inspect(Event{ID: "capture", Time: baseTime, Kind: "screen_capture", Path: "/tmp/screenshot.png", Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	result, err := d.Inspect(Event{ID: "selection", Time: baseTime.Add(time.Minute), Kind: "file_attach", Digest: digest, Destination: "https://chatgpt.com/"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "warn" || result.Findings[0].Rule != "screenshot_selected_for_ai" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestLateScreenshotMetadataStillCorrelatesSelection(t *testing.T) {
	d := New()
	digest := strings.Repeat("b", 64)
	first, err := d.Inspect(Event{ID: "selection", Time: baseTime, Kind: "file_attach", Digest: digest, Destination: "https://claude.ai/"})
	if err != nil || first.Decision != "allow" {
		t.Fatalf("unexpected first result: %#v err=%v", first, err)
	}
	second, err := d.Inspect(Event{ID: "capture", Time: baseTime.Add(time.Second), Kind: "screen_capture", Digest: digest})
	if err != nil || second.Decision != "warn" || second.Findings[0].Rule != "screenshot_selected_for_ai" {
		t.Fatalf("unexpected correlated result: %#v err=%v", second, err)
	}
}
