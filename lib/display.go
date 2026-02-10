package lib

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// ANSI escape sequences for terminal control
const (
	enterAltScreen = "\033[?1049h" // Switch to alternate screen buffer
	exitAltScreen  = "\033[?1049l" // Return to main screen buffer
	cursorHome     = "\033[H"      // Move cursor to top-left
	clearToEnd     = "\033[J"      // Clear from cursor to end of screen
	hideCursor     = "\033[?25l"   // Hide cursor
	showCursor     = "\033[?25h"   // Show cursor
)

const tableWidth = 140

// Message type short names for table columns
var msgShortNames = map[string]string{
	"router_solicitation":            "RS",
	"router_advertisement":           "RA",
	"neighbor_solicitation":          "NS",
	"neighbor_advertisement":         "NA",
	"redirect":                       "Rdr",
	"duplicate_address_request":      "DAR",
	"duplicate_address_confirmation": "DAC",
	"mld_query":                      "MQ",
	"mld_report":                     "MR",
	"mld_done":                       "MD",
}

// Column order for display (NDP types followed by MLD types)
var msgColumnOrder = []string{
	"router_solicitation",
	"router_advertisement",
	"neighbor_solicitation",
	"neighbor_advertisement",
	"redirect",
	"duplicate_address_request",
	"duplicate_address_confirmation",
	"mld_query",
	"mld_report",
	"mld_done",
}

// Well-known IPv6 multicast groups and what they indicate
var knownMulticastGroups = map[string]string{
	"ff02::1":     "All Nodes",
	"ff02::2":     "All Routers",
	"ff02::5":     "OSPFv3",
	"ff02::6":     "OSPFv3 DR",
	"ff02::9":     "RIPng",
	"ff02::a":     "EIGRP",
	"ff02::c":     "SSDP/UPnP",
	"ff02::d":     "PIM",
	"ff02::16":    "MLDv2",
	"ff02::fb":    "mDNS",
	"ff02::1:2":   "DHCPv6",
	"ff02::1:3":   "LLMNR",
	"ff05::1:3":   "DHCP Site",
	"ff02::6a":    "VRRP",
	"ff02::12":    "VRRP",
	"ff02::102":   "HSRPv6",
	"ff02::1:ff00:0/104": "Solicited-Node", // prefix, handled specially
}

// EnterAltScreen switches to the alternate screen buffer (like top/vim).
// Call ExitAltScreen when done to restore the original terminal.
func EnterAltScreen(w io.Writer) {
	fmt.Fprint(w, enterAltScreen, hideCursor)
}

// ExitAltScreen returns to the main screen buffer and restores cursor.
func ExitAltScreen(w io.Writer) {
	fmt.Fprint(w, showCursor, exitAltScreen)
}

// RenderTable renders the stats table to the given writer.
// It moves the cursor home and redraws in place.
func RenderTable(w io.Writer, stats []PeerSummary, window time.Duration) {
	// Move cursor to top-left, then draw content
	fmt.Fprint(w, cursorHome)

	// Header
	fmt.Fprintf(w, "NDP/MLD Statistics (window: %s, updated: %s)\n",
		formatDuration(window),
		time.Now().Format("15:04:05"))
	fmt.Fprintln(w, strings.Repeat("─", tableWidth))

	if len(stats) == 0 {
		fmt.Fprintln(w, "No NDP/MLD traffic observed yet...")
		fmt.Fprint(w, clearToEnd)
		return
	}

	// Table header: Address | MAC | NDP columns | MLD columns | Total | Timestamps
	fmt.Fprintf(w, "%-40s %-17s %4s %4s %4s %4s %4s %4s %4s %4s %4s %4s %5s  %-8s  %-8s\n",
		"IPv6 Address", "MAC",
		"RS", "RA", "NS", "NA", "Rdr", "DAR", "DAC",
		"MQ", "MR", "MD",
		"Total", "First", "Last")
	fmt.Fprintln(w, strings.Repeat("─", tableWidth))

	// Table rows
	for _, peer := range stats {
		counts := make([]int, len(msgColumnOrder))
		for i, kind := range msgColumnOrder {
			counts[i] = peer.Counts[kind]
		}

		mac := peer.MAC
		if mac == "" {
			mac = "-"
		}

		fmt.Fprintf(w, "%-40s %-17s %4d %4d %4d %4d %4d %4d %4d %4d %4d %4d %5d  %-8s  %-8s\n",
			truncate(peer.Address, 40),
			mac,
			counts[0], counts[1], counts[2], counts[3],
			counts[4], counts[5], counts[6],
			counts[7], counts[8], counts[9],
			peer.Total,
			formatTimestamp(peer.FirstSeen),
			formatTimestamp(peer.LastSeen),
		)
	}

	fmt.Fprintln(w, strings.Repeat("─", tableWidth))
	fmt.Fprintf(w, "Total peers: %d\n", len(stats))

	// Multicast group summary
	groupMembers := aggregateMulticastGroups(stats)
	if len(groupMembers) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Multicast Groups:")
		for _, gm := range groupMembers {
			label := multicastLabel(gm.Group)
			noun := "hosts"
			if gm.Members == 1 {
				noun = "host"
			}
			if label != "" {
				fmt.Fprintf(w, "  %-40s %-16s %d %s\n",
					truncate(gm.Group, 40), label, gm.Members, noun)
			} else {
				fmt.Fprintf(w, "  %-40s %-16s %d %s\n",
					truncate(gm.Group, 40), "", gm.Members, noun)
			}
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Press Ctrl+C to exit")

	// Clear any leftover content from previous renders (e.g., if peer count decreased)
	fmt.Fprint(w, clearToEnd)
}

type multicastGroupEntry struct {
	Group   string
	Members int
}

// aggregateMulticastGroups collects all multicast groups across peers,
// counts unique members, and returns them sorted by member count descending.
func aggregateMulticastGroups(stats []PeerSummary) []multicastGroupEntry {
	counts := make(map[string]int)
	for _, peer := range stats {
		for _, group := range peer.Groups {
			counts[group]++
		}
	}
	if len(counts) == 0 {
		return nil
	}

	entries := make([]multicastGroupEntry, 0, len(counts))
	for group, members := range counts {
		entries = append(entries, multicastGroupEntry{Group: group, Members: members})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Members != entries[j].Members {
			return entries[i].Members > entries[j].Members
		}
		return entries[i].Group < entries[j].Group
	})
	return entries
}

// multicastLabel returns a human-readable label for well-known multicast groups.
func multicastLabel(group string) string {
	if label, ok := knownMulticastGroups[group]; ok {
		return label
	}
	// Solicited-node multicast: ff02::1:ffXX:XXXX
	if strings.HasPrefix(group, "ff02::1:ff") {
		return "Solicited-Node"
	}
	return ""
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
