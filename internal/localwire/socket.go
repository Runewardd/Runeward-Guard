package localwire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Runewardd/Runeward-Guard/internal/detector"
)

const maxMessageBytes = 4096

func SocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".runeward-guard", "monitor.sock"), nil
}

// Listen creates a user-private Unix socket. It refuses to replace an existing
// socket or use a directory that other local users can access.
func Listen(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("socket path must be absolute")
	}
	directory := filepath.Dir(path)
	if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("socket directory must be a private directory (mode %v)", info.Mode().Perm())
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("socket directory must belong to the current user")
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, fmt.Errorf("socket path already exists; refusing to replace it")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func ReadEvent(conn net.Conn) (detector.Event, error) {
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return detector.Event{}, err
	}
	data, err := io.ReadAll(io.LimitReader(conn, maxMessageBytes+1))
	if err != nil {
		return detector.Event{}, err
	}
	if len(data) > maxMessageBytes {
		return detector.Event{}, fmt.Errorf("browser event too large")
	}
	var event detector.Event
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&event); err != nil {
		return detector.Event{}, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return detector.Event{}, fmt.Errorf("expected one browser event")
	}
	if event.Kind != "file_attach" || event.Text != "" || event.Path != "" {
		return detector.Event{}, fmt.Errorf("only metadata-only file_attach is accepted")
	}
	return event, nil
}

func SendEvent(path string, event detector.Event) error {
	conn, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	if err := json.NewEncoder(conn).Encode(event); err != nil {
		return err
	}
	if unixConn, ok := conn.(*net.UnixConn); ok {
		if err := unixConn.CloseWrite(); err != nil {
			return err
		}
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		return err
	}
	if ack[0] != 1 {
		return fmt.Errorf("monitor rejected browser event")
	}
	return nil
}
