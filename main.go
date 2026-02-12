package main

import (
	"NDPeekr/lib"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	var (
		listenAddr = flag.String("listen", "::", "IPv6 address to bind (typically ::)")
		ifaceName  = flag.String("iface", "", "Optional interface name to restrict reads (best-effort)")
		logLevel   = flag.String("log-level", "info", "debug|info|warn|error")
		window     = flag.Duration("window", 15*time.Minute, "Sliding window duration for stats (e.g. 15m, 1h)")
		refresh    = flag.Duration("refresh", 2*time.Second, "Table refresh interval (e.g. 2s, 500ms)")
	)
	flag.Parse()

	level := parseLogLevel(*logLevel)

	// Log to a file instead of stderr so output doesn't corrupt the TUI alt screen.
	logFile, err := os.OpenFile("ndpeekr.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	handler := slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: level})
	logger := slog.New(handler).With("component", "ndpmon")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create stats tracker
	stats := lib.NewNDPStats(*window)

	l := lib.NewNDPListener(lib.NDPListenerConfig{
		ListenAddr: *listenAddr,
		Interface:  *ifaceName,
		Logger:     logger.With("component", "ndp_listener"),
		Stats:      stats,
	})

	// Start listener in background goroutine.
	listenerErrCh := make(chan error, 1)
	go func() {
		listenerErrCh <- l.Run(ctx)
	}()

	logger.Info("starting NDP listener", "listen", *listenAddr, "iface", *ifaceName, "window", *window, "refresh", *refresh)

	// Create and run Bubble Tea program.
	m := lib.NewModel(stats, *window, *refresh)
	p := tea.NewProgram(m, tea.WithAltScreen())

	// Run blocks until the user quits (Ctrl+C or 'q').
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
		cancel()
		os.Exit(1)
	}

	// TUI exited normally; shut down the listener.
	cancel()
	if err := <-listenerErrCh; err != nil && ctx.Err() == nil {
		logger.Error("listener error", "err", err)
		os.Exit(1)
	}
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
