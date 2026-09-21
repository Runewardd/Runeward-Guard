package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var chromeExtensionID = regexp.MustCompile(`^[a-p]{32}$`)

type browserHostConfig struct {
	AllowedOrigin string `json:"allowed_origin"`
	Socket        string `json:"socket"`
}

type nativeManifest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Path           string   `json:"path"`
	Type           string   `json:"type"`
	AllowedOrigins []string `json:"allowed_origins"`
}

func setupChromeCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("setup-chrome", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("extension-id", "", "Chrome extension ID")
	binary := flags.String("host-binary", "", "absolute path to guard-browser-host")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected setup-chrome arguments")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	manifest, err := setupChrome(home, *id, *binary)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Chrome native host configured: %s\n", manifest)
	return err
}

func setupChrome(home, extensionID, hostBinary string) (string, error) {
	if !chromeExtensionID.MatchString(extensionID) || !filepath.IsAbs(hostBinary) {
		return "", fmt.Errorf("setup requires a 32-letter Chrome extension ID and absolute host binary path")
	}
	info, err := os.Stat(hostBinary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("host binary must be an existing executable file")
	}
	guardDir := filepath.Join(home, ".runeward-guard")
	if err := os.Mkdir(guardDir, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	dirInfo, err := os.Lstat(guardDir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("Guard configuration directory must be private")
	}
	socket := filepath.Join(guardDir, "monitor.sock")
	origin := "chrome-extension://" + extensionID + "/"
	config := browserHostConfig{AllowedOrigin: origin, Socket: socket}
	manifest := nativeManifest{Name: "com.runeward.guard", Description: "Runeward Guard browser bridge", Path: hostBinary, Type: "stdio", AllowedOrigins: []string{origin}}
	configPath := filepath.Join(guardDir, "browser-host.json")
	manifestPath := filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts", "com.runeward.guard.json")
	if _, err := os.Lstat(configPath); err == nil {
		return "", fmt.Errorf("browser-host.json already exists; refusing to overwrite")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if _, err := os.Lstat(manifestPath); err == nil {
		return "", fmt.Errorf("Chrome native manifest already exists; refusing to overwrite")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0700); err != nil {
		return "", err
	}
	if err := createJSON(configPath, config); err != nil {
		return "", err
	}
	if err := createJSON(manifestPath, manifest); err != nil {
		_ = os.Remove(configPath)
		return "", err
	}
	return manifestPath, nil
}

func createJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}
