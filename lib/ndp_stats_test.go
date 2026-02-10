package lib

import (
	"testing"
	"time"
)

func TestNewNDPStats(t *testing.T) {
	window := 5 * time.Minute
	stats := NewNDPStats(window)

	if stats == nil {
		t.Fatal("NewNDPStats returned nil")
	}
	if stats.Window() != window {
		t.Errorf("Window() = %v, want %v", stats.Window(), window)
	}
}

func TestRecordMessage_NewPeer(t *testing.T) {
	stats := NewNDPStats(5 * time.Minute)

	stats.RecordMessage("fe80::1", "router_solicitation")

	summaries := stats.GetStats()
	if len(summaries) != 1 {
		t.Fatalf("GetStats() returned %d peers, want 1", len(summaries))
	}
	if summaries[0].Address != "fe80::1" {
		t.Errorf("Address = %q, want %q", summaries[0].Address, "fe80::1")
	}
	if summaries[0].Counts["router_solicitation"] != 1 {
		t.Errorf("router_solicitation count = %d, want 1", summaries[0].Counts["router_solicitation"])
	}
	if summaries[0].Total != 1 {
		t.Errorf("Total = %d, want 1", summaries[0].Total)
	}
}

func TestRecordMessage_MultiplePeers(t *testing.T) {
	stats := NewNDPStats(5 * time.Minute)

	stats.RecordMessage("fe80::1", "router_solicitation")
	stats.RecordMessage("fe80::2", "neighbor_solicitation")
	stats.RecordMessage("fe80::1", "router_solicitation")

	summaries := stats.GetStats()
	if len(summaries) != 2 {
		t.Fatalf("GetStats() returned %d peers, want 2", len(summaries))
	}

	// First should be fe80::1 with 2 messages (sorted by total desc)
	if summaries[0].Address != "fe80::1" {
		t.Errorf("First peer = %q, want fe80::1", summaries[0].Address)
	}
	if summaries[0].Total != 2 {
		t.Errorf("First peer total = %d, want 2", summaries[0].Total)
	}

	// Second should be fe80::2 with 1 message
	if summaries[1].Address != "fe80::2" {
		t.Errorf("Second peer = %q, want fe80::2", summaries[1].Address)
	}
	if summaries[1].Total != 1 {
		t.Errorf("Second peer total = %d, want 1", summaries[1].Total)
	}
}

func TestRecordMessage_MultipleTypes(t *testing.T) {
	stats := NewNDPStats(5 * time.Minute)

	stats.RecordMessage("fe80::1", "router_solicitation")
	stats.RecordMessage("fe80::1", "router_advertisement")
	stats.RecordMessage("fe80::1", "neighbor_solicitation")

	summaries := stats.GetStats()
	if len(summaries) != 1 {
		t.Fatalf("GetStats() returned %d peers, want 1", len(summaries))
	}

	peer := summaries[0]
	if peer.Counts["router_solicitation"] != 1 {
		t.Errorf("RS count = %d, want 1", peer.Counts["router_solicitation"])
	}
	if peer.Counts["router_advertisement"] != 1 {
		t.Errorf("RA count = %d, want 1", peer.Counts["router_advertisement"])
	}
	if peer.Counts["neighbor_solicitation"] != 1 {
		t.Errorf("NS count = %d, want 1", peer.Counts["neighbor_solicitation"])
	}
	if peer.Total != 3 {
		t.Errorf("Total = %d, want 3", peer.Total)
	}
}

func TestGetStats_SortedByTotal(t *testing.T) {
	stats := NewNDPStats(5 * time.Minute)

	// Record different amounts for different peers
	for i := 0; i < 5; i++ {
		stats.RecordMessage("fe80::1", "router_solicitation")
	}
	for i := 0; i < 3; i++ {
		stats.RecordMessage("fe80::2", "router_solicitation")
	}
	for i := 0; i < 7; i++ {
		stats.RecordMessage("fe80::3", "router_solicitation")
	}

	summaries := stats.GetStats()
	if len(summaries) != 3 {
		t.Fatalf("GetStats() returned %d peers, want 3", len(summaries))
	}

	// Should be sorted: fe80::3 (7), fe80::1 (5), fe80::2 (3)
	expected := []struct {
		addr  string
		total int
	}{
		{"fe80::3", 7},
		{"fe80::1", 5},
		{"fe80::2", 3},
	}

	for i, exp := range expected {
		if summaries[i].Address != exp.addr {
			t.Errorf("summaries[%d].Address = %q, want %q", i, summaries[i].Address, exp.addr)
		}
		if summaries[i].Total != exp.total {
			t.Errorf("summaries[%d].Total = %d, want %d", i, summaries[i].Total, exp.total)
		}
	}
}

func TestPrune_RemovesOldTimestamps(t *testing.T) {
	// Use a very short window for testing
	stats := NewNDPStats(100 * time.Millisecond)

	stats.RecordMessage("fe80::1", "router_solicitation")

	// Verify message is counted
	summaries := stats.GetStats()
	if summaries[0].Total != 1 {
		t.Fatalf("Initial total = %d, want 1", summaries[0].Total)
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Prune should remove old data
	stats.Prune()

	summaries = stats.GetStats()
	if len(summaries) != 0 {
		t.Errorf("After prune, got %d peers, want 0", len(summaries))
	}
}

func TestPrune_KeepsRecentMessages(t *testing.T) {
	stats := NewNDPStats(1 * time.Second)

	stats.RecordMessage("fe80::1", "router_solicitation")

	// Prune immediately (message should still be within window)
	stats.Prune()

	summaries := stats.GetStats()
	if len(summaries) != 1 {
		t.Fatalf("After immediate prune, got %d peers, want 1", len(summaries))
	}
	if summaries[0].Total != 1 {
		t.Errorf("Total after prune = %d, want 1", summaries[0].Total)
	}
}

func TestRecordMLDMembership(t *testing.T) {
	stats := NewNDPStats(5 * time.Minute)

	stats.RecordMessage("fe80::1", "mld_report")
	stats.RecordMLDMembership("fe80::1", "ff02::fb")
	stats.RecordMLDMembership("fe80::1", "ff02::1:3")

	summaries := stats.GetStats()
	if len(summaries) != 1 {
		t.Fatalf("GetStats() returned %d peers, want 1", len(summaries))
	}
	if len(summaries[0].Groups) != 2 {
		t.Fatalf("Groups = %v, want 2 groups", summaries[0].Groups)
	}
	// Groups should be sorted
	if summaries[0].Groups[0] != "ff02::1:3" || summaries[0].Groups[1] != "ff02::fb" {
		t.Errorf("Groups = %v, want [ff02::1:3, ff02::fb]", summaries[0].Groups)
	}
}

func TestRecordMLDMembership_MultipleHosts(t *testing.T) {
	stats := NewNDPStats(5 * time.Minute)

	stats.RecordMessage("fe80::1", "mld_report")
	stats.RecordMLDMembership("fe80::1", "ff02::fb")
	stats.RecordMessage("fe80::2", "mld_report")
	stats.RecordMLDMembership("fe80::2", "ff02::fb")
	stats.RecordMLDMembership("fe80::2", "ff02::c")

	summaries := stats.GetStats()
	if len(summaries) != 2 {
		t.Fatalf("GetStats() returned %d peers, want 2", len(summaries))
	}
	// Both should have ff02::fb
	for _, s := range summaries {
		found := false
		for _, g := range s.Groups {
			if g == "ff02::fb" {
				found = true
			}
		}
		if !found {
			t.Errorf("peer %s missing ff02::fb group", s.Address)
		}
	}
}

func TestPruneMLDMemberships(t *testing.T) {
	stats := NewNDPStats(100 * time.Millisecond)

	stats.RecordMessage("fe80::1", "mld_report")
	stats.RecordMLDMembership("fe80::1", "ff02::fb")

	summaries := stats.GetStats()
	if len(summaries[0].Groups) != 1 {
		t.Fatalf("Initial groups = %d, want 1", len(summaries[0].Groups))
	}

	time.Sleep(150 * time.Millisecond)
	stats.Prune()

	// Peer should be removed entirely (no messages in window)
	summaries = stats.GetStats()
	if len(summaries) != 0 {
		t.Errorf("After prune, got %d peers, want 0", len(summaries))
	}
}

func TestRecordMAC(t *testing.T) {
	stats := NewNDPStats(5 * time.Minute)

	stats.RecordMessage("fe80::1", "neighbor_solicitation")
	stats.RecordMAC("fe80::1", "aa:bb:cc:dd:ee:01")

	summaries := stats.GetStats()
	if len(summaries) != 1 {
		t.Fatalf("GetStats() returned %d peers, want 1", len(summaries))
	}
	if summaries[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("MAC = %q, want %q", summaries[0].MAC, "aa:bb:cc:dd:ee:01")
	}
}

func TestRecordMAC_UpdatesOnNewMessage(t *testing.T) {
	stats := NewNDPStats(5 * time.Minute)

	stats.RecordMessage("fe80::1", "neighbor_solicitation")
	stats.RecordMAC("fe80::1", "aa:bb:cc:dd:ee:01")
	stats.RecordMAC("fe80::1", "aa:bb:cc:dd:ee:02")

	summaries := stats.GetStats()
	if summaries[0].MAC != "aa:bb:cc:dd:ee:02" {
		t.Errorf("MAC = %q, want %q (should be updated)", summaries[0].MAC, "aa:bb:cc:dd:ee:02")
	}
}

func TestRecordMAC_NoMessageYet(t *testing.T) {
	stats := NewNDPStats(5 * time.Minute)

	// RecordMAC on a peer that hasn't sent any messages yet
	stats.RecordMAC("fe80::99", "11:22:33:44:55:66")

	summaries := stats.GetStats()
	if len(summaries) != 1 {
		t.Fatalf("GetStats() returned %d peers, want 1", len(summaries))
	}
	if summaries[0].MAC != "11:22:33:44:55:66" {
		t.Errorf("MAC = %q, want %q", summaries[0].MAC, "11:22:33:44:55:66")
	}
}

func TestFirstSeenLastSeen(t *testing.T) {
	stats := NewNDPStats(5 * time.Minute)

	before := time.Now()
	stats.RecordMessage("fe80::1", "router_solicitation")
	time.Sleep(10 * time.Millisecond)
	stats.RecordMessage("fe80::1", "router_solicitation")
	after := time.Now()

	summaries := stats.GetStats()
	if len(summaries) != 1 {
		t.Fatalf("GetStats() returned %d peers, want 1", len(summaries))
	}

	peer := summaries[0]
	if peer.FirstSeen.Before(before) || peer.FirstSeen.After(after) {
		t.Errorf("FirstSeen %v not in expected range", peer.FirstSeen)
	}
	if peer.LastSeen.Before(before) || peer.LastSeen.After(after) {
		t.Errorf("LastSeen %v not in expected range", peer.LastSeen)
	}
	if !peer.LastSeen.After(peer.FirstSeen) && peer.LastSeen != peer.FirstSeen {
		t.Errorf("LastSeen %v should be >= FirstSeen %v", peer.LastSeen, peer.FirstSeen)
	}
}
