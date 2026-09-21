package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Runewardd/Runeward-Guard/internal/detector"
	"github.com/Runewardd/Runeward-Guard/internal/localwire"
)

func TestMonitorCorrelatesObservedScreenshotWithBrowserSelection(t *testing.T) {
	root, err := os.MkdirTemp("", "rg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "screenshots")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "monitor.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	done := make(chan error, 1)
	go func() {
		done <- runMonitor(ctx, directory, socket, time.Hour, func(context.Context, string) bool { return true }, writer)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("monitor exited before socket started: %v", err)
		default:
		}
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("monitor socket did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	image := []byte("synthetic screenshot bytes")
	if err := os.WriteFile(filepath.Join(directory, "capture.png"), image, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(image)
	digest := hex.EncodeToString(sum[:])
	event := detector.Event{Kind: "file_attach", Digest: digest, Destination: "https://chatgpt.com"}
	if err := localwire.SendEvent(socket, event); err != nil {
		t.Fatal(err)
	}
	lines := bufio.NewScanner(reader)
	for i := 0; i < 2; i++ {
		if !lines.Scan() {
			t.Fatal("missing monitor output")
		}
		var result monitorOutput
		if err := json.Unmarshal(lines.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if i == 1 && (result.Kind != "file_attach" || result.Decision != "warn" || result.Findings[0].Rule != "screenshot_selected_for_ai") {
			t.Fatalf("unexpected correlated result: %#v", result)
		}
		if strings.Contains(string(lines.Bytes()), directory) || strings.Contains(string(lines.Bytes()), string(image)) {
			t.Fatal("monitor leaked path or image content")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("monitor did not stop")
	}
}
