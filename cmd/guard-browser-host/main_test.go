package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Runewardd/Runeward-Guard/internal/detector"
	"github.com/Runewardd/Runeward-Guard/internal/localwire"
)

func TestNativeProtocolRejectsInvalidDigest(t *testing.T) {
	payload := []byte(`{"kind":"file_attach","digest":"bad","destination":"https://chatgpt.com"}`)
	var input, output bytes.Buffer
	if err := binary.Write(&input, binary.LittleEndian, uint32(len(payload))); err != nil {
		t.Fatal(err)
	}
	input.Write(payload)
	if err := serveNative(&input, &output, "/tmp/no-socket"); err != nil {
		t.Fatal(err)
	}
	var length uint32
	if err := binary.Read(&output, binary.LittleEndian, &length); err != nil {
		t.Fatal(err)
	}
	if length != uint32(output.Len()) {
		t.Fatal("invalid response framing")
	}
	var response hostResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.OK || !strings.Contains(response.Error, "invalid") {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestHostRejectsUnsupportedDestination(t *testing.T) {
	response := handleMessage([]byte(`{"kind":"file_attach","digest":"`+strings.Repeat("a", 64)+`","destination":"https://chatgpt.com.evil.test"}`), "/tmp/no-socket")
	if response.OK || response.Error != "unsupported AI destination" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestHostForwardsValidMetadataToMonitor(t *testing.T) {
	directory, err := os.MkdirTemp("", "rg-host-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "monitor.sock")
	listener, err := localwire.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan detector.Event, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		event, err := localwire.ReadEvent(conn)
		if err == nil {
			received <- event
			_, _ = conn.Write([]byte{1})
		}
	}()
	digest := strings.Repeat("c", 64)
	response := handleMessage([]byte(`{"kind":"file_attach","digest":"`+digest+`","destination":"https://claude.ai"}`), socket)
	if !response.OK {
		t.Fatalf("valid message failed: %#v", response)
	}
	select {
	case event := <-received:
		if event.Digest != digest || event.Kind != "file_attach" {
			t.Fatalf("unexpected forwarded event: %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("host did not forward event")
	}
}
