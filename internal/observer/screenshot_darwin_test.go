//go:build darwin

package observer

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAppleScreenshotChecksMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.png")
	if err := os.WriteFile(path, []byte("test image"), 0600); err != nil {
		t.Fatal(err)
	}
	if AppleScreenshot(context.Background(), path) {
		t.Fatal("untagged image reported as screenshot")
	}
	if err := exec.Command("/usr/bin/xattr", "-w", screenshotAttribute, "1", path).Run(); err != nil {
		t.Fatalf("set screenshot marker: %v", err)
	}
	if !AppleScreenshot(context.Background(), path) {
		t.Fatal("tagged image not reported as screenshot")
	}
}
