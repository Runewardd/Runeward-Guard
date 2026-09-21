package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Runewardd/Runeward-Guard/internal/detector"
)

const maxEventBytes = 1 << 20

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: guard <inspect|check|claude-hook|claude-tool-hook|monitor|setup-chrome>")
		os.Exit(1)
	}
	if os.Args[1] != "monitor" && os.Args[1] != "setup-chrome" && len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "guard: unexpected arguments")
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "inspect":
		err = inspect(os.Stdin, os.Stdout)
	case "check":
		var blocked bool
		blocked, err = check(os.Stdin, os.Stdout)
		if err == nil && blocked {
			os.Exit(2)
		}
	case "claude-hook":
		err = claudeHook(os.Stdin, os.Stdout)
	case "claude-tool-hook":
		err = claudeToolHook(os.Stdin, os.Stdout)
	case "monitor":
		err = monitorCommand(os.Args[2:], os.Stdout, os.Stderr)
	case "setup-chrome":
		err = setupChromeCommand(os.Args[2:], os.Stdout)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "guard:", err)
		os.Exit(1)
	}
}

type claudeInput struct {
	HookEventName string `json:"hook_event_name"`
	Prompt        string `json:"prompt"`
}

type claudeDecision struct {
	Decision               string `json:"decision"`
	Reason                 string `json:"reason"`
	SuppressOriginalPrompt bool   `json:"suppressOriginalPrompt"`
}

// claudeHook consumes Claude Code's native UserPromptSubmit JSON. It emits
// nothing on allow, and a fixed, non-echoing block response on detection or
// inspection failure. This only protects the enabled Claude Code hook path.
func claudeHook(input io.Reader, output io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(input, maxEventBytes+1))
	if err != nil || len(data) > maxEventBytes {
		return writeClaudeBlock(output, "Runeward Guard could not inspect this prompt.")
	}
	var hook claudeInput
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&hook); err != nil {
		return writeClaudeBlock(output, "Runeward Guard could not inspect this prompt.")
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) || hook.HookEventName != "UserPromptSubmit" || hook.Prompt == "" {
		return writeClaudeBlock(output, "Runeward Guard could not inspect this prompt.")
	}
	result, err := detector.New().Inspect(detector.Event{ID: "claude-prompt", Time: time.Now().UTC(), Kind: "prompt_submit", Harness: "claude", Text: hook.Prompt})
	if err != nil {
		return writeClaudeBlock(output, "Runeward Guard could not inspect this prompt.")
	}
	if result.Decision == "block" {
		return writeClaudeBlock(output, "Runeward Guard detected a possible secret in this prompt.")
	}
	return nil
}

func writeClaudeBlock(output io.Writer, reason string) error {
	return json.NewEncoder(output).Encode(claudeDecision{Decision: "block", Reason: reason, SuppressOriginalPrompt: true})
}

// check is the fail-closed single-event path for a synchronous, opt-in hook.
// Exit code 2 means the event should be blocked; 1 means inspection failed.
func check(input io.Reader, output io.Writer) (bool, error) {
	data, err := io.ReadAll(io.LimitReader(input, maxEventBytes+1))
	if err != nil {
		return false, fmt.Errorf("read event: %w", err)
	}
	if len(data) > maxEventBytes {
		return false, fmt.Errorf("event exceeds %d bytes", maxEventBytes)
	}
	event, err := decodeEvent(data)
	if err != nil {
		return false, err
	}
	result, err := detector.New().Inspect(event)
	if err != nil {
		return false, err
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		return false, fmt.Errorf("write result: %w", err)
	}
	return result.Decision == "block", nil
}

func inspect(input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxEventBytes)
	enc := json.NewEncoder(output)
	d := detector.New()
	line := 0
	for scanner.Scan() {
		line++
		data := scanner.Bytes()
		if len(bytes.TrimSpace(data)) == 0 {
			continue
		}
		event, err := decodeEvent(data)
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		result, err := d.Inspect(event)
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if err := enc.Encode(result); err != nil {
			return fmt.Errorf("write result: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read events: %w", err)
	}
	return nil
}

func decodeEvent(data []byte) (detector.Event, error) {
	var event detector.Event
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&event); err != nil {
		return detector.Event{}, fmt.Errorf("invalid event: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return detector.Event{}, fmt.Errorf("expected one JSON object")
	}
	return event, nil
}
