# NDPeekr Consolidated Implementation Plan

Single source of truth for roadmap and next work. This file replaces the old split between `FEATURES.md` and the previous short-term `NEXT.md`.

---

## Status Review (Compared to Current Code)

Assessed against `main.go`, `lib/ndp_listener.go`, `lib/ndp_stats.go`, and `lib/display.go`.

### Implemented

1. Passive NDP capture (RS/RA/NS/NA/Redirect/DAR/DAC)
2. MLD capture (Query/Report v1+v2/Done)
3. Sliding-window per-peer counting and pruning
4. MAC extraction from NDP options (SLLA/TLLA)
5. Router tracking from RA (lifetime, M/O flags, prefixes, MTU, RDNSS, routes)
6. Two-tab TUI (Peers + Routers) with detail views
7. Hop-limit and interface tracking per peer
8. OS/type inference from MLD group membership heuristic

### Partially Implemented

1. Prefix/subnet tracking: RA prefix data is collected per router, but no dedicated global prefix inventory view exists.
2. Passive OS fingerprinting: currently limited to simple MLD-group heuristics; no broader behavior fingerprinting.

### Not Implemented

1. mDNS hostname resolution
2. LLMNR traffic monitoring listener
3. DHCPv6 traffic monitoring listener
4. SLAAC vs DHCPv6 classification logic
5. JSON snapshot export
6. OUI/MAC vendor lookup
7. Security event logging/alerting
8. Multi-interface capture in one run
9. Network topology inference
10. Historical data storage

---

## Prioritized Backlog

### Phase 1 - Immediate Product Value

#### 1) JSON Snapshot Export

**Priority:** High  
**Effort:** Low  
**Files:** `lib/export.go` (new), `main.go`, `lib/ndp_stats.go`

**Implementation:**
- Add `--output` and `--output-interval` flags in `main.go`.
- Add periodic exporter goroutine using atomic write (`.tmp` + rename).
- Export peers and routers using stable JSON schema with timestamps.

**Acceptance Criteria:**
- When `--output` is set, snapshot file updates at configured interval.
- Output is valid JSON and never partially written.

#### 2) mDNS Hostname Resolution

**Priority:** High  
**Effort:** Medium  
**Files:** `lib/mdns_listener.go` (new), `lib/ndp_stats.go`, `lib/display.go`, `main.go`

**Implementation:**
- Add UDP listener for `ff02::fb:5353` on selected interface.
- Parse AAAA and PTR response records.
- Add hostname field to peer stats and render in TUI.

**Acceptance Criteria:**
- Hostnames appear for peers when mDNS data is observed.
- Listener starts/stops with app lifecycle and does not block TUI.

#### 3) Security Event Logging (v1)

**Priority:** High  
**Effort:** Medium  
**Files:** `lib/security.go` (new), `lib/ndp_stats.go`, `lib/ndp_listener.go`, `main.go`

**Implementation:**
- Add stateful detector for router/peer MAC changes and new routers.
- Detect new prefixes advertised by known routers.
- Emit structured `WARN` logs for SIEM ingestion.

**Acceptance Criteria:**
- Alert events are logged once per event transition (not on every packet).
- Existing log format remains parse-friendly.

#### 4) OUI/MAC Vendor Lookup

**Priority:** Medium  
**Effort:** Low  
**Files:** `lib/oui.go` (new), `lib/ndp_stats.go`, `lib/display.go`

**Implementation:**
- Add local OUI prefix map and lookup helper.
- Add vendor to peer summary and detail display.

**Acceptance Criteria:**
- Known OUIs resolve to vendor names.
- Unknown OUIs remain blank/`Unknown` without errors.

---

### Phase 2 - Protocol and Classification Expansion

#### 5) DHCPv6 Listener + Address Method Inference

**Priority:** Medium  
**Effort:** Medium  
**Files:** `lib/dhcpv6_listener.go` (new), `lib/ndp_stats.go`, `main.go`, `lib/display.go`

**Implementation:**
- Capture DHCPv6 (`546/547`, `ff02::1:2`) and parse core message types.
- Correlate leases/DUID with peers and router flags.
- Add config-method field: `SLAAC`, `SLAAC-Privacy`, `DHCPv6`, `Unknown`.

**Acceptance Criteria:**
- DHCPv6 server/client activity is visible in stats.
- Peer config method reflects correlation logic with clear fallback behavior.

#### 6) Dedicated Prefix/Subnet View

**Priority:** Medium  
**Effort:** Low-Medium  
**Files:** `lib/ndp_stats.go`, `lib/display.go`

**Implementation:**
- Build global prefix index from RA prefixes + observed addresses.
- Add prefix table view with host count and advertising routers.

**Acceptance Criteria:**
- Prefix view shows unique prefixes with counts and timestamps.
- Prefix data remains pruned with window rules.

#### 7) Multi-Interface Support

**Priority:** Medium  
**Effort:** Medium  
**Files:** `main.go`, `lib/ndp_listener.go`, `lib/display.go`

**Implementation:**
- Support comma-separated interface list.
- Run listener per interface and merge into shared stats.

**Acceptance Criteria:**
- Multiple interfaces can be monitored in one process.
- Interface attribution remains accurate in peer/router views.

---

### Phase 3 - Advanced Intelligence

#### 8) LLMNR Listener

**Priority:** Low  
**Effort:** Medium  
**Files:** `lib/llmnr_listener.go` (new), `lib/ndp_stats.go`, `main.go`

#### 9) Historical Storage

**Priority:** Low  
**Effort:** High  
**Files:** `lib/store.go` (new), `main.go`, data-model updates

#### 10) Topology Inference

**Priority:** Low  
**Effort:** High  
**Files:** `lib/topology.go` (new), export surfaces

---

## Recommended Implementation Order

1. JSON export
2. mDNS hostname resolution
3. Security event logging
4. OUI vendor lookup
5. DHCPv6 + config-method inference
6. Prefix view
7. Multi-interface support

---

## Notes

- Keep listener goroutines decoupled and share only through `NDPStats` (thread-safe).
- Preserve file-based logging to avoid TUI corruption.
- Add tests for each parser and each new state transition rule before wiring to UI.
