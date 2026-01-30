package main

import (
	"NDPeekr/lib"
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
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
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	logger := slog.New(handler).With("component", "ndpmon")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		logger.Info("signal received, shutting down", "signal", s.String())
		cancel()
	}()

	// Create stats tracker
	stats := lib.NewNDPStats(*window)

	l := lib.NewNDPListener(lib.NDPListenerConfig{
		ListenAddr: *listenAddr,
		Interface:  *ifaceName,
		Logger:     logger.With("component", "ndp_listener"),
		Stats:      stats,
	})

	// Enter alternate screen buffer (like top/vim)
	lib.EnterAltScreen(os.Stdout)
	defer lib.ExitAltScreen(os.Stdout)

	// Start display goroutine
	displayDone := make(chan struct{})
	go func() {
		defer close(displayDone)
		ticker := time.NewTicker(*refresh)
		defer ticker.Stop()

		// Initial render
		lib.RenderTable(os.Stdout, stats.GetStats(), *window)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				lib.RenderTable(os.Stdout, stats.GetStats(), *window)
				// Periodically prune old data (every refresh)
				stats.Prune()
			}
		}
	}()

	logger.Info("starting NDP listener", "listen", *listenAddr, "iface", *ifaceName, "window", *window, "refresh", *refresh)

	if err := l.Run(ctx); err != nil {
		// Wait for display goroutine to finish
		<-displayDone

		// If ctx canceled, treat as normal shutdown.
		if ctx.Err() != nil {
			return
		}
		lib.ExitAltScreen(os.Stdout) // Restore terminal before printing error
		logger.Error("listener error", "err", err)
		os.Exit(1)
	}

	// Wait for display goroutine to finish
	<-displayDone
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
