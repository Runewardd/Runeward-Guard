package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupChromeCreatesPrivateManifestWithoutOverwrite(t *testing.T) {
	home := t.TempDir()
	host := filepath.Join(home, "guard-browser-host")
	if err := os.WriteFile(host, []byte("test executable"), 0700); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	path, err := setupChrome(home, id, host)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest nativeManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Path != host || manifest.AllowedOrigins[0] != "chrome-extension://"+id+"/" {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	configPath := filepath.Join(home, ".runeward-guard", "browser-host.json")
	info, err := os.Stat(configPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("config is not private: info=%v err=%v", info, err)
	}
	if _, err := setupChrome(home, id, host); err == nil {
		t.Fatal("setup overwrote existing configuration")
	}
}

func TestSetupChromeRejectsBadExtensionID(t *testing.T) {
	if _, err := setupChrome(t.TempDir(), "not-an-id", "/bin/echo"); err == nil {
		t.Fatal("accepted invalid Chrome extension ID")
	}
}
