package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const captureWindow = 15 * time.Minute

type Event struct {
	ID          string    `json:"id"`
	Time        time.Time `json:"time"`
	Kind        string    `json:"kind"`
	Harness     string    `json:"harness,omitempty"`
	Application string    `json:"application,omitempty"`
	Destination string    `json:"destination,omitempty"`
	Path        string    `json:"path,omitempty"`
	Text        string    `json:"text,omitempty"`
}

type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type Result struct {
	EventID  string    `json:"event_id"`
	Decision string    `json:"decision"`
	Findings []Finding `json:"findings,omitempty"`
}

type capture struct {
	at time.Time
}

type Detector struct {
	captures map[string]capture
	lastTime time.Time
}

func New() *Detector {
	return &Detector{captures: make(map[string]capture)}
}

var (
	privateKey         = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`)
	providerToken      = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b`)
	passwordAssignment = regexp.MustCompile(`(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'";,]{8,})`)
	eventID            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// Inspect processes one event without retaining prompt content. Events should come
// from an explicitly enabled, trusted local adapter; they are not OS observations.
func (d *Detector) Inspect(event Event) (Result, error) {
	result := Result{EventID: event.ID, Decision: "allow"}
	if !eventID.MatchString(event.ID) {
		return Result{}, fmt.Errorf("event id must be 1-128 safe characters")
	}
	if event.Time.IsZero() {
		return Result{}, fmt.Errorf("event time is required")
	}
	if !d.lastTime.IsZero() && event.Time.Before(d.lastTime) {
		return Result{}, fmt.Errorf("events must be in timestamp order")
	}
	d.expire(event.Time)

	switch event.Kind {
	case "prompt_submit":
		if event.Harness == "" {
			return Result{}, fmt.Errorf("prompt_submit requires harness")
		}
		if event.Text == "" {
			return Result{}, fmt.Errorf("prompt_submit requires text")
		}
		if privateKey.MatchString(event.Text) {
			result.Findings = append(result.Findings, Finding{"private_key_in_prompt", "critical", "Private key material appears in an AI prompt."})
		}
		if providerToken.MatchString(event.Text) {
			result.Findings = append(result.Findings, Finding{"provider_token_in_prompt", "high", "A provider token appears in an AI prompt."})
		}
		if passwordAssignment.MatchString(event.Text) {
			result.Findings = append(result.Findings, Finding{"possible_password_in_prompt", "high", "A password-like assignment appears in an AI prompt."})
		}
		if len(result.Findings) > 0 {
			result.Decision = "block"
		}
	case "keychain_access":
		if event.Harness == "" {
			return Result{}, fmt.Errorf("keychain_access requires harness")
		}
		if event.Text != "" {
			return Result{}, fmt.Errorf("keychain_access must not include text")
		}
		result.Decision = "warn"
		result.Findings = append(result.Findings, Finding{"agent_keychain_access", "high", "An AI harness accessed Keychain; this does not establish disclosure."})
	case "screen_capture":
		if !filepath.IsAbs(event.Path) || event.Text != "" {
			return Result{}, fmt.Errorf("screen_capture requires an absolute path and no text")
		}
		d.captures[pathKey(event.Path)] = capture{at: event.Time}
	case "file_upload":
		if !filepath.IsAbs(event.Path) || event.Destination == "" || event.Text != "" {
			return Result{}, fmt.Errorf("file_upload requires an absolute path, destination, and no text")
		}
		if !isAIDestination(event.Destination) {
			break
		}
		if previous, ok := d.captures[pathKey(event.Path)]; ok && !event.Time.Before(previous.at) && event.Time.Sub(previous.at) <= captureWindow {
			result.Decision = "warn"
			result.Findings = append(result.Findings, Finding{"screenshot_uploaded_to_ai", "high", "A recently captured screenshot was uploaded to an AI destination."})
		}
	default:
		return Result{}, fmt.Errorf("unsupported event kind %q", event.Kind)
	}
	d.lastTime = event.Time
	return result, nil
}

func (d *Detector) expire(now time.Time) {
	for key, value := range d.captures {
		if now.Sub(value.at) > captureWindow {
			delete(d.captures, key)
		}
	}
}

// Keep a one-way key in state so a finding cannot expose a local filename.
func pathKey(path string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(path)))
	return hex.EncodeToString(sum[:])
}

func isAIDestination(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "wss") || u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, domain := range []string{"chatgpt.com", "openai.com", "claude.ai", "anthropic.com", "githubcopilot.com"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
