# NDPeekr — Short-Term Feature Queue

Features to implement next, ordered by priority.

---

## 1. OS Fingerprinting from MLD Groups

**Effort:** Low — data already collected, no new capture needed
**Files:** `lib/ndp_stats.go`, `lib/display.go`

MLD membership data in `PeerStats.Groups` already fingerprints OS:

| Groups Present         | Likely OS / Device        |
|------------------------|---------------------------|
| `ff02::fb` only        | macOS or Linux (Avahi)    |
| `ff02::1:3` present    | Windows                   |
| `ff02::fb` + `ff02::1:3` | Windows with mDNS       |
| `ff02::c` (SSDP)       | IoT / smart home device   |
| `ff02::2` (All Routers)| Acting as router          |

**Implementation:**
- Add `GuessedOS string` to `PeerSummary`
- Add `GuessOS(groups []string) string` function in `ndp_stats.go` that scores group memberships
- Show as a `Type` column (truncated) in the peers table
- Show full value in peer detail view

---

## 2. OUI/MAC Vendor Lookup

**Effort:** Low — MACs already extracted, just need a lookup table
**Files:** `lib/oui.go` (new), `lib/ndp_stats.go`, `lib/display.go`

Map the first 3 bytes of a MAC to a manufacturer name.

**Implementation:**
- Create `lib/oui.go` with a `LookupVendor(mac string) string` function
- Hardcode a map of the top ~150 vendors by network market share (Apple, Raspberry Pi Foundation, Intel, Cisco, TP-Link, Netgear, Ubiquiti, Amazon, Google, Samsung, etc.) — keeps the binary small
- Add `Vendor string` to `PeerSummary`, populate in `GetStats()`
- Show in peer detail view; optionally add a narrow truncated column to the peers table

---

## 3. mDNS Hostname Resolution

**Effort:** Medium — requires a new listener goroutine
**Files:** `lib/mdns_listener.go` (new), `lib/ndp_stats.go`, `lib/display.go`, `main.go`

Listen on `ff02::fb` UDP port 5353, parse DNS responses, attach hostnames to peers.

**Implementation:**
- New `MDNSListener` struct with a `Run(ctx context.Context)` method, same pattern as `NDPListener`
- Join multicast group `ff02::fb` on the target interface
- Parse AAAA and PTR records using `golang.org/x/net/dns/dnsmessage` (already in module graph via `x/net`)
- Add `Hostname string` to `PeerStats` and `PeerSummary`; populate via new `RecordHostname(ip, hostname string)` on `NDPStats`
- Show hostname column in peers table (truncated); full value in detail view
- Start listener in `main.go` alongside `NDPListener`

---

## 4. JSON Snapshot Export

**Effort:** Low — existing data structures, just marshal and write
**Files:** `lib/export.go` (new), `main.go`

Periodic JSON snapshots for integration with other tools.

**Implementation:**
- Add `--output <path>` and `--output-interval <duration>` (default: `30s`) flags to `main.go`
- New `lib/export.go` with `WriteSnapshot(stats *NDPStats, path string) error`
- Output structure mirrors existing `PeerSummary` and `RouterInfo` types — add `json` tags
- Run a ticker goroutine in `main.go` that calls `WriteSnapshot` when `--output` is set
- Write atomically: write to `<path>.tmp` then `os.Rename` to avoid partial reads

---

## 5. Security Event Logging

**Effort:** Medium — requires state comparison on each update
**Files:** `lib/security.go` (new), `lib/ndp_stats.go`, `main.go`

Detect and log anomalous NDP behavior to the log file.

**Alerts to implement (v1):**
- New router seen for the first time
- Known router's MAC address changed
- Known peer's MAC address changed (possible spoofing)
- Router advertising a prefix not seen before

**Implementation:**
- `SecurityMonitor` struct wraps `*NDPStats` and holds a `*slog.Logger`
- Expose `CheckRouter(new RouterInfo)` and `CheckPeer(ip, mac string)` methods
- Call these from `NDPListener.Run()` after `RecordRouter` / `RecordMAC`
- Log at `WARN` level with structured fields for easy grep/SIEM ingestion
- No TUI changes needed for v1 — log file output is sufficient

---

## Implementation Order

1. OS fingerprinting (zero infra, immediate TUI improvement)
2. OUI vendor lookup (same — quick win on top of existing MAC data)
3. JSON export (enables tool to integrate into larger workflows)
4. mDNS listener (biggest UX win — human names for addresses)
5. Security event logging (foundational for monitoring use cases)
