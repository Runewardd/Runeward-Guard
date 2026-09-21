package localwire

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Runewardd/Runeward-Guard/internal/detector"
)

func TestSendAndReadEvent(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "monitor.sock")
	listener, err := Listen(path)
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
		event, err := ReadEvent(conn)
		if err == nil {
			received <- event
			_, _ = conn.Write([]byte{1})
		}
	}()
	original := detector.Event{ID: "browser-1", Time: time.Now().UTC(), Kind: "file_attach", Digest: strings.Repeat("a", 64), Destination: "https://chatgpt.com"}
	if err := SendEvent(path, original); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-received:
		if event.Digest != original.Digest {
			t.Fatalf("unexpected event: %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

func TestReadEventRejectsRawText(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		_, _ = client.Write([]byte(`{"kind":"file_attach","text":"secret"}`))
		client.Close()
	}()
	if _, err := ReadEvent(server); err == nil {
		t.Fatal("expected metadata-only rejection")
	}
}
