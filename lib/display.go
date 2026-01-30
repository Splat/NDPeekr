package lib

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// NDP message type short names for table columns
var ndpShortNames = map[string]string{
	"router_solicitation":           "RS",
	"router_advertisement":          "RA",
	"neighbor_solicitation":         "NS",
	"neighbor_advertisement":        "NA",
	"redirect":                      "Redir",
	"duplicate_address_request":     "DAR",
	"duplicate_address_confirmation": "DAC",
}

// Column order for display
var ndpColumnOrder = []string{
	"router_solicitation",
	"router_advertisement",
	"neighbor_solicitation",
	"neighbor_advertisement",
	"redirect",
	"duplicate_address_request",
	"duplicate_address_confirmation",
}

// RenderTable renders the stats table to the given writer.
// It clears the screen and positions the cursor at the top.
func RenderTable(w io.Writer, stats []PeerSummary, window time.Duration) {
	// ANSI escape codes
	clearScreen := "\033[2J"
	moveCursor := "\033[H"

	fmt.Fprint(w, clearScreen, moveCursor)

	// Header
	fmt.Fprintf(w, "NDP Statistics (window: %s, updated: %s)\n",
		formatDuration(window),
		time.Now().Format("15:04:05"))
	fmt.Fprintln(w, strings.Repeat("─", 120))

	if len(stats) == 0 {
		fmt.Fprintln(w, "No NDP traffic observed yet...")
		return
	}

	// Table header
	fmt.Fprintf(w, "%-40s %5s %5s %5s %5s %5s %5s %5s %6s  %-10s  %-10s\n",
		"IPv6 Address", "RS", "RA", "NS", "NA", "Redir", "DAR", "DAC", "Total", "First Seen", "Last Seen")
	fmt.Fprintln(w, strings.Repeat("─", 120))

	// Table rows
	for _, peer := range stats {
		counts := make([]int, len(ndpColumnOrder))
		for i, kind := range ndpColumnOrder {
			counts[i] = peer.Counts[kind]
		}

		fmt.Fprintf(w, "%-40s %5d %5d %5d %5d %5d %5d %5d %6d  %-10s  %-10s\n",
			truncate(peer.Address, 40),
			counts[0], counts[1], counts[2], counts[3],
			counts[4], counts[5], counts[6],
			peer.Total,
			formatTimestamp(peer.FirstSeen),
			formatTimestamp(peer.LastSeen),
		)
	}

	fmt.Fprintln(w, strings.Repeat("─", 120))
	fmt.Fprintf(w, "Total peers: %d\n", len(stats))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatTimestamp(t time.Time) string {
	return t.Format("15:04:05")
}

func formatDuration(d time.Duration) string {
	if d >= time.Hour {
		hours := d / time.Hour
		mins := (d % time.Hour) / time.Minute
		if mins > 0 {
			return fmt.Sprintf("%dh%dm", hours, mins)
		}
		return fmt.Sprintf("%dh", hours)
	}
	if d >= time.Minute {
		mins := d / time.Minute
		secs := (d % time.Minute) / time.Second
		if secs > 0 {
			return fmt.Sprintf("%dm%ds", mins, secs)
		}
		return fmt.Sprintf("%dm", mins)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}
