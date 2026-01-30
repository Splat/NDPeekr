package lib

import (
	"sort"
	"sync"
	"time"
)

// NDPStats tracks all observed NDP peers with thread-safe access.
type NDPStats struct {
	mu     sync.RWMutex
	peers  map[string]*PeerStats // key: IPv6 address string
	window time.Duration         // sliding window size
}

// PeerStats holds per-peer statistics.
type PeerStats struct {
	FirstSeen time.Time
	LastSeen  time.Time
	// Messages stores timestamps for each message type for windowed counting.
	Messages map[string][]time.Time // key: ndpKind, value: timestamps
}

// PeerSummary is a snapshot of peer stats for display.
type PeerSummary struct {
	Address   string
	FirstSeen time.Time
	LastSeen  time.Time
	Counts    map[string]int // message type -> count within window
	Total     int
}

// NewNDPStats creates a new NDPStats tracker with the given sliding window duration.
func NewNDPStats(window time.Duration) *NDPStats {
	return &NDPStats{
		peers:  make(map[string]*PeerStats),
		window: window,
	}
}

// RecordMessage records an NDP message from the given IP address.
func (s *NDPStats) RecordMessage(ip string, ndpKind string) {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	peer, ok := s.peers[ip]
	if !ok {
		peer = &PeerStats{
			FirstSeen: now,
			Messages:  make(map[string][]time.Time),
		}
		s.peers[ip] = peer
	}

	peer.LastSeen = now
	peer.Messages[ndpKind] = append(peer.Messages[ndpKind], now)
}

// GetStats returns a sorted list of peer summaries for display.
// Only messages within the sliding window are counted.
// Results are sorted by total message count (descending).
func (s *NDPStats) GetStats() []PeerSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().Add(-s.window)
	summaries := make([]PeerSummary, 0, len(s.peers))

	for addr, peer := range s.peers {
		summary := PeerSummary{
			Address:   addr,
			FirstSeen: peer.FirstSeen,
			LastSeen:  peer.LastSeen,
			Counts:    make(map[string]int),
		}

		for kind, timestamps := range peer.Messages {
			count := 0
			for _, ts := range timestamps {
				if ts.After(cutoff) {
					count++
				}
			}
			summary.Counts[kind] = count
			summary.Total += count
		}

		summaries = append(summaries, summary)
	}

	// Sort by total count descending (chattiest first)
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Total > summaries[j].Total
	})

	return summaries
}

// Prune removes timestamps older than the window from all peers.
// Peers with no messages in the window are removed entirely.
func (s *NDPStats) Prune() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-s.window)

	for addr, peer := range s.peers {
		totalKept := 0

		for kind, timestamps := range peer.Messages {
			kept := make([]time.Time, 0, len(timestamps))
			for _, ts := range timestamps {
				if ts.After(cutoff) {
					kept = append(kept, ts)
				}
			}
			if len(kept) > 0 {
				peer.Messages[kind] = kept
				totalKept += len(kept)
			} else {
				delete(peer.Messages, kind)
			}
		}

		// Remove peer if no messages remain in window
		if totalKept == 0 {
			delete(s.peers, addr)
		}
	}
}

// Window returns the configured sliding window duration.
func (s *NDPStats) Window() time.Duration {
	return s.window
}
