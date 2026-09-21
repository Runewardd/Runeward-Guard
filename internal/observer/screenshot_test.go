package observer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Runewardd/Runeward-Guard/internal/detector"
)

func TestScannerBaselinesThenEmitsDigestOnly(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "old.png")
	if err := os.WriteFile(existing, []byte("old image"), 0600); err != nil {
		t.Fatal(err)
	}
	scanner, err := NewScreenshotScanner([]string{dir}, func(context.Context, string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	events, err := scanner.Scan(context.Background())
	if err != nil || len(events) != 0 {
		t.Fatalf("initial scan: events=%#v err=%v", events, err)
	}
	path := filepath.Join(dir, "new.png")
	if err := os.WriteFile(path, []byte("new image"), 0600); err != nil {
		t.Fatal(err)
	}
	events, err = scanner.Scan(context.Background())
	if err != nil || len(events) != 1 {
		t.Fatalf("second scan: events=%#v err=%v", events, err)
	}
	if events[0].Path != "" || len(events[0].Digest) != 64 || events[0].Kind != "screen_capture" {
		t.Fatalf("unexpected privacy shape: %#v", events[0])
	}
	if _, err := detector.New().Inspect(events[0]); err != nil {
		t.Fatalf("detector rejected observed event: %v", err)
	}
	events, err = scanner.Scan(context.Background())
	if err != nil || len(events) != 0 {
		t.Fatalf("duplicate event: events=%#v err=%v", events, err)
	}
}

func TestScannerRetriesDelayedMetadata(t *testing.T) {
	dir := t.TempDir()
	marked := false
	scanner, err := NewScreenshotScanner([]string{dir}, func(context.Context, string) bool { return marked })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "later.png"), []byte("image"), 0600); err != nil {
		t.Fatal(err)
	}
	if events, err := scanner.Scan(context.Background()); err != nil || len(events) != 0 {
		t.Fatalf("unexpected first scan: events=%#v err=%v", events, err)
	}
	marked = true
	if events, err := scanner.Scan(context.Background()); err != nil || len(events) != 1 {
		t.Fatalf("expected delayed marker: events=%#v err=%v", events, err)
	}
}

func TestScannerRejectsRelativeDirectory(t *testing.T) {
	_, err := NewScreenshotScanner([]string{"relative"}, func(context.Context, string) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("unexpected error: %v", err)
	}
}
