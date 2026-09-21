package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Runewardd/Runeward-Guard/internal/detector"
	"github.com/Runewardd/Runeward-Guard/internal/localwire"
)

const maxNativeMessage = 4096

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type hostConfig struct {
	AllowedOrigin string `json:"allowed_origin"`
	Socket        string `json:"socket"`
}

type attachMessage struct {
	Kind        string `json:"kind"`
	Digest      string `json:"digest"`
	Destination string `json:"destination"`
}

type hostResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "guard-browser-host: expected Chrome extension origin")
		os.Exit(1)
	}
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "guard-browser-host:", err)
		os.Exit(1)
	}
	if strings.TrimSuffix(os.Args[1], "/") != strings.TrimSuffix(config.AllowedOrigin, "/") {
		fmt.Fprintln(os.Stderr, "guard-browser-host: unexpected extension origin")
		os.Exit(1)
	}
	if err := serveNative(os.Stdin, os.Stdout, config.Socket); err != nil {
		fmt.Fprintln(os.Stderr, "guard-browser-host:", err)
		os.Exit(1)
	}
}

func loadConfig() (hostConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return hostConfig{}, err
	}
	path := filepath.Join(home, ".runeward-guard", "browser-host.json")
	info, err := os.Stat(path)
	if err != nil {
		return hostConfig{}, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return hostConfig{}, fmt.Errorf("browser-host.json must be readable only by its owner")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return hostConfig{}, err
	}
	var config hostConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return hostConfig{}, err
	}
	if !regexp.MustCompile(`^chrome-extension://[a-p]{32}/$`).MatchString(config.AllowedOrigin) || !filepath.IsAbs(config.Socket) {
		return hostConfig{}, fmt.Errorf("invalid browser host configuration")
	}
	return config, nil
}

func serveNative(input io.Reader, output io.Writer, socket string) error {
	reader := bufio.NewReader(input)
	for {
		var length uint32
		if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if length == 0 || length > maxNativeMessage {
			return fmt.Errorf("invalid native message length")
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(reader, data); err != nil {
			return err
		}
		response := handleMessage(data, socket)
		encoded, err := json.Marshal(response)
		if err != nil {
			return err
		}
		if err := binary.Write(output, binary.LittleEndian, uint32(len(encoded))); err != nil {
			return err
		}
		if _, err := output.Write(encoded); err != nil {
			return err
		}
	}
}

func handleMessage(data []byte, socket string) hostResponse {
	var message attachMessage
	if err := json.Unmarshal(data, &message); err != nil || message.Kind != "file_attach" || !digestPattern.MatchString(message.Digest) {
		return hostResponse{Error: "invalid attachment metadata"}
	}
	if message.Destination != "https://chatgpt.com" && message.Destination != "https://claude.ai" {
		return hostResponse{Error: "unsupported AI destination"}
	}
	event := detector.Event{ID: fmt.Sprintf("browser-%d", time.Now().UnixNano()), Time: time.Now().UTC(), Kind: "file_attach", Harness: "browser", Digest: message.Digest, Destination: message.Destination}
	if err := localwire.SendEvent(socket, event); err != nil {
		return hostResponse{Error: "Guard monitor unavailable"}
	}
	return hostResponse{OK: true}
}
