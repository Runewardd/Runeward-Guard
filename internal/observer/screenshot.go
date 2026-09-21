package observer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Runewardd/Runeward-Guard/internal/detector"
)

const (
	maxImageBytes = 32 << 20
	metadataGrace = 30 * time.Second
)

type Classifier func(context.Context, string) bool

type fileState struct {
	size      int64
	modified  time.Time
	firstSeen time.Time
	emitted   bool
}

// ScreenshotScanner watches only operator-selected, non-recursive directories.
// It never emits the file path or image bytes, only a SHA-256 digest.
type ScreenshotScanner struct {
	directories  []string
	classify     Classifier
	seen         map[string]fileState
	bootstrapped bool
	sequence     uint64
	now          func() time.Time
}

func NewScreenshotScanner(directories []string, classify Classifier) (*ScreenshotScanner, error) {
	if len(directories) == 0 || classify == nil {
		return nil, fmt.Errorf("at least one directory and a classifier are required")
	}
	clean := make([]string, 0, len(directories))
	for _, directory := range directories {
		if !filepath.IsAbs(directory) {
			return nil, fmt.Errorf("watch directories must be absolute")
		}
		info, err := os.Stat(directory)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("watch directory is unavailable: %s", directory)
		}
		clean = append(clean, filepath.Clean(directory))
	}
	return &ScreenshotScanner{directories: clean, classify: classify, seen: make(map[string]fileState), now: time.Now}, nil
}

// Scan baselines existing files on its first call; subsequent calls report only
// newly observed or changed screenshot files. Call from one goroutine.
func (s *ScreenshotScanner) Scan(ctx context.Context) ([]detector.Event, error) {
	initial := !s.bootstrapped
	now := s.now().UTC()
	var events []detector.Event
	observed := make(map[string]bool)
	for _, directory := range s.directories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, fmt.Errorf("read watch directory %s: %w", directory, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !isImage(entry.Name()) {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			observed[path] = true
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxImageBytes {
				continue
			}
			state, known := s.seen[path]
			if !known || state.size != info.Size() || !state.modified.Equal(info.ModTime()) {
				state = fileState{size: info.Size(), modified: info.ModTime(), firstSeen: now, emitted: initial}
			}
			if !state.emitted && now.Sub(state.firstSeen) <= metadataGrace && s.classify(ctx, path) {
				digest, err := hashStableFile(path, info)
				if err == nil {
					s.sequence++
					events = append(events, detector.Event{ID: fmt.Sprintf("macos-capture-%d", s.sequence), Time: now, Kind: "screen_capture", Digest: digest, Application: "macos"})
					state.emitted = true
				}
			}
			s.seen[path] = state
		}
	}
	for path := range s.seen {
		if !observed[path] {
			delete(s.seen, path)
		}
	}
	s.bootstrapped = true
	return events, nil
}

func isImage(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png", ".jpg", ".jpeg", ".heic", ".webp":
		return true
	default:
		return false
	}
}

func hashStableFile(path string, before os.FileInfo) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maxImageBytes+1)); err != nil {
		return "", err
	}
	after, err := file.Stat()
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", fmt.Errorf("image changed while hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
