package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/Runewardd/Runeward-Guard/internal/detector"
	"github.com/Runewardd/Runeward-Guard/internal/localwire"
	"github.com/Runewardd/Runeward-Guard/internal/observer"
)

type monitorOutput struct {
	EventID  string             `json:"event_id"`
	Time     time.Time          `json:"time"`
	Kind     string             `json:"kind"`
	Decision string             `json:"decision"`
	Findings []detector.Finding `json:"findings,omitempty"`
}

func monitorCommand(args []string, output, status io.Writer) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("monitor currently requires macOS")
	}
	flags := flag.NewFlagSet("monitor", flag.ContinueOnError)
	flags.SetOutput(status)
	directory := flags.String("dir", "", "absolute screenshot directory to watch (non-recursive)")
	socket := flags.String("socket", "", "private Unix socket path (optional)")
	interval := flags.Duration("interval", 2*time.Second, "scan interval")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *directory == "" || *interval < 250*time.Millisecond {
		return fmt.Errorf("monitor requires --dir, with --interval >= 250ms")
	}
	if *socket == "" {
		var err error
		*socket, err = localwire.SocketPath()
		if err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(status, "Guard monitoring %s; browser socket %s\n", *directory, *socket)
	return runMonitor(ctx, *directory, *socket, *interval, observer.AppleScreenshot, output)
}

func runMonitor(ctx context.Context, directory, socket string, interval time.Duration, classify observer.Classifier, output io.Writer) error {
	scanner, err := observer.NewScreenshotScanner([]string{directory}, classify)
	if err != nil {
		return err
	}
	if _, err := scanner.Scan(ctx); err != nil {
		return err
	}
	listener, err := localwire.Listen(socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	incoming := make(chan detector.Event, 64)
	serverErrors := make(chan error, 1)
	go serveBrowserSocket(ctx, listener, incoming, serverErrors)
	engine := detector.New()
	enc := json.NewEncoder(output)
	process := func(event detector.Event) error {
		event.Time = time.Now().UTC()
		result, err := engine.Inspect(event)
		if err != nil {
			return err
		}
		return enc.Encode(monitorOutput{EventID: result.EventID, Time: event.Time, Kind: event.Kind, Decision: result.Decision, Findings: result.Findings})
	}
	scan := func() error {
		events, err := scanner.Scan(ctx)
		if err != nil {
			return err
		}
		for _, event := range events {
			if err := process(event); err != nil {
				return err
			}
		}
		return nil
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-serverErrors:
			return err
		case event := <-incoming:
			// Catch a screenshot created just before a browser selection.
			if err := scan(); err != nil {
				return err
			}
			if err := process(event); err != nil {
				return err
			}
		case <-ticker.C:
			if err := scan(); err != nil {
				return err
			}
		}
	}
}

func serveBrowserSocket(ctx context.Context, listener net.Listener, events chan<- detector.Event, failures chan<- error) {
	var sequence uint64
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				failures <- err
			}
			return
		}
		event, err := localwire.ReadEvent(conn)
		if err == nil {
			sequence++
			event.ID = fmt.Sprintf("browser-%d", sequence)
			event.Time = time.Now().UTC()
			_, err = detector.New().Inspect(event)
		}
		if err == nil {
			select {
			case events <- event:
				_, _ = conn.Write([]byte{1})
			default:
				_, _ = conn.Write([]byte{0})
			}
		} else {
			_, _ = conn.Write([]byte{0})
		}
		conn.Close()
	}
}
