# NDPeekr Feature Roadmap

This document outlines planned features to evolve NDPeekr from a simple NDP monitor into a comprehensive IPv6 asset discovery and tracking suite.

NDPeeker was a quick illustration of what is possible. However, as enumerated in some my articles on IPv6 there is a plethora of ways we can built something more comprehensive with what already exists in the noise.

---

## Current Capabilities

- Passive NDP message capture (RS, RA, NS, NA, Redirect, DAD)
- Per-address message counting with sliding time window
- Real-time terminal display with automatic pruning
- Interface filtering

---

## Proposed Features

### 1. MAC Address Extraction from NDP

**Priority:** High
**Complexity:** Low
**Status:** Ready to implement

NDP Neighbor Solicitation and Neighbor Advertisement messages contain a Source/Target Link-Layer Address option that carries the MAC address. This is the IPv6 equivalent of ARP. This is interesting for a few reasons. We can track hosts leaving and re-entering a network via the MAC address and also build a list of more concrete host to IP assigment for more permanent appliances. These are usually the more interesting things to look at for researchers anyways. 

**Implementation:**
- Parse ICMPv6 options in NS/NA messages
- Extract link-layer address (MAC) from option type 1 (source) or 2 (target)
- Add MAC column to peer stats table
- Track MAC-to-IPv6 mappings (one MAC can have multiple IPv6 addresses)

**Value:**
- Direct IPv6-to-MAC correlation without additional protocols
- Identify devices by hardware address across address changes
- Detect MAC spoofing or address conflicts

---

### 2. Router Tracking Table

**Priority:** High
**Complexity:** Medium
**Status:** Ready to implement

Router Advertisement messages contain rich information that deserves dedicated tracking.

**Data to extract from RA messages:**
- Router link-local address
- Router MAC address (from link-layer option)
- Router Lifetime (how long to use as default gateway)
- Managed (M) flag - indicates DHCPv6 for addresses
- Other (O) flag - indicates DHCPv6 for other config (DNS, etc.)
- Prefix Information options (advertised /64s, valid/preferred lifetimes)
- MTU option
- RDNSS (Recursive DNS Server) addresses
- Route Information options

**Display:**
- Separate "Routers" table showing:
  - Router Address | MAC | Lifetime | M | O | Prefixes | Last Seen
- Could toggle between peer view and router view with a keypress

**Value:**
- Identify all routers on segment
- Detect rogue router advertisements (security)
- Understand network configuration (SLAAC vs DHCPv6)
- Track advertised prefixes for subnet enumeration

---

### 3. SLAAC vs DHCPv6 Detection

**Priority:** Medium
**Complexity:** Medium
**Status:** Requires research & implementation

Determining how an address was configured requires inference:

**Approach A: Heuristic detection**
- EUI-64 addresses: If interface ID matches `xx:xx:xx:FF:FE:xx:xx:xx` pattern derived from MAC, likely SLAAC
- Privacy extensions: Random-looking interface IDs that change periodically
- DHCPv6: Addresses that don't match EUI-64 and aren't in privacy extension ranges

**Approach B: RA flag correlation**
- If router sets M=1, network supports DHCPv6 for addresses
- If router sets M=0, O=1, SLAAC for addresses but DHCPv6 for other config
- If router sets M=0, O=0, pure SLAAC

**Approach C: DHCPv6 traffic monitoring** (see Feature #4)

**Display:**
- Add "Type" column: SLAAC-EUI64, SLAAC-Privacy, DHCPv6, Unknown

**Value:**
- Understand address assignment mechanisms in use
- Identify devices that may not be getting proper network config
- Security: Detect addresses that shouldn't exist based on RA flags

---

### 4. DHCPv6 Traffic Monitoring

**Priority:** Medium
**Complexity:** Medium
**Status:** Requires new listener

Monitor DHCPv6 (UDP ports 546/547) to correlate with NDP data.

**Implementation:**
- New UDP listener for DHCPv6 multicast (ff02::1:2)
- Parse DHCPv6 messages: Solicit, Advertise, Request, Reply, Renew, Rebind
- Extract: Client DUID, Server DUID, IA_NA (assigned addresses), lease times
- Correlate with NDP-observed addresses

**Data to track:**
- DHCPv6 servers on segment
- Client DUIDs (device identifiers, often contain MAC)
- Assigned addresses and lease durations
- DNS servers provided via DHCPv6

**Value:**
- Definitive DHCPv6 vs SLAAC determination
- Track lease lifecycle
- Identify DHCPv6 servers (and rogues)

---

### 5. mDNS Monitoring

**Priority:** High
**Complexity:** Medium
**Status:** Requires new listener

mDNS (Multicast DNS, UDP 5353) provides hostname and service discovery.

**Implementation:**
- UDP listener on port 5353, join multicast group ff02::fb
- Parse DNS response records (A, AAAA, PTR, SRV, TXT)
- Extract: Hostname, IPv6 addresses, IPv4 addresses, services, MAC (sometimes in TXT records)

**Data to correlate:**
- Hostname to IPv6 address mappings
- Service announcements (e.g., _http._tcp, _ssh._tcp, _airplay._tcp)
- Device type hints from service names

**Display:**
- Add "Hostname" column to peer stats
- Optional services view

**Value:**
- Human-readable device identification
- Discover device types and capabilities
- Correlate across protocols

---

### 6. LLMNR Monitoring (Windows Networks)

**Priority:** Low (Windows-specific)
**Complexity:** Medium
**Status:** Future consideration

Link-Local Multicast Name Resolution is the Windows equivalent of mDNS.

**Implementation:**
- UDP listener on port 5355, join multicast group ff02::1:3
- Parse LLMNR queries and responses
- Extract hostname-to-address mappings

**Value:**
- Better coverage on Windows-heavy networks
- Often reveals Windows machine names

---

### 7. JSON Export

**Priority:** High
**Complexity:** Low
**Status:** Ready to implement

Periodic JSON snapshots enable integration with other tools.

**Implementation:**
- New `--output` flag for file path
- New `--output-interval` flag (default: 30s or match refresh)
- Write JSON representation of current state

**JSON Structure:**
```json
{
  "timestamp": "2024-01-15T14:30:00Z",
  "window_seconds": 900,
  "peers": [
    {
      "ipv6": "fe80::1",
      "mac": "aa:bb:cc:dd:ee:ff",
      "hostname": "router.local",
      "first_seen": "2024-01-15T14:15:00Z",
      "last_seen": "2024-01-15T14:29:58Z",
      "is_router": false,
      "address_type": "link-local",
      "config_method": "slaac-eui64",
      "messages": {
        "router_solicitation": 3,
        "neighbor_solicitation": 12,
        "neighbor_advertisement": 10
      }
    }
  ],
  "routers": [
    {
      "ipv6": "fe80::1",
      "mac": "aa:bb:cc:dd:ee:ff",
      "lifetime": 1800,
      "managed_flag": false,
      "other_flag": true,
      "prefixes": [
        {
          "prefix": "2001:db8::/64",
          "valid_lifetime": 86400,
          "preferred_lifetime": 14400
        }
      ],
      "dns_servers": ["2001:db8::53"],
      "last_seen": "2024-01-15T14:29:45Z"
    }
  ],
  "prefixes": [
    {
      "prefix": "2001:db8::/64",
      "advertising_routers": ["fe80::1"],
      "observed_hosts": 15
    }
  ]
}
```

**Value:**
- Feed into SIEM/SOAR platforms
- Input for topology visualization tools
- Historical analysis and trending
- Integration with asset management systems

---

### 8. Network Topology Inference

**Priority:** Medium
**Complexity:** High
**Status:** Future / separate tool

Use collected data to infer network topology.

**Data points for inference:**
- Router advertisements define L3 segments
- Prefix information shows subnet boundaries
- Multiple routers on same prefix = redundancy
- Hosts grouped by prefix = same broadcast domain
- Interface-based grouping = local segments

**Output:**
- Prefix hierarchy
- Router relationships
- Host-to-router associations
- Potential network diagram data (nodes/edges for visualization)

**Value:**
- Automated network documentation
- Change detection
- Security: Identify unexpected topology changes

---

### 9. Prefix/Subnet Tracking

**Priority:** Medium
**Complexity:** Low
**Status:** Ready to implement

Aggregate view of IPv6 prefixes in use.

**Implementation:**
- Extract prefix from each observed global address
- Group addresses by /64 (or configured prefix length)
- Track: Prefix, advertising router(s), host count, address types

**Display:**
- Prefix view table:
  - Prefix | Router(s) | Host Count | First Seen | Last Seen

**Value:**
- Subnet enumeration
- Identify unexpected prefixes
- Capacity planning

---

### 10. Multi-Interface Support

**Priority:** Medium
**Complexity:** Medium
**Status:** Enhancement to existing

Monitor multiple interfaces simultaneously with per-interface stats.

**Implementation:**
- Accept comma-separated interface list: `--iface en0,en1,eth0`
- Spawn listener per interface or use BPF/raw socket with interface tagging
- Add interface column to stats

**Value:**
- Monitor multiple network segments from one host
- Compare traffic patterns across interfaces
- Gateway/firewall deployment scenarios

---

### 11. Security Alerting

**Priority:** Medium
**Complexity:** Medium
**Status:** Future consideration

Real-time detection of suspicious NDP behavior.

**Alerts to implement:**
- **Rogue RA**: Router advertisement from unknown source
- **RA flood**: Excessive RAs (potential DoS)
- **DAD attack**: Repeated DAD failures for same address
- **New router**: First RA from previously unknown router
- **Prefix change**: Router advertising different prefix
- **MAC change**: Known IPv6 address with different MAC (spoofing)
- **Rapid address churn**: Device cycling through many addresses

**Output:**
- Log alerts to stderr/file
- Optional webhook/syslog integration
- Add alert indicator to display

**Value:**
- Real-time security monitoring
- Detect IPv6-specific attacks
- Incident response support

---

### 12. Historical Data Storage

**Priority:** Low
**Complexity:** High
**Status:** Future / v2.0

Persist data beyond the sliding window for trend analysis.

**Options:**
- SQLite database for local storage
- Time-series DB integration (InfluxDB, Prometheus)
- Simple append-only log file

**Queries to support:**
- When was this address first/last seen?
- What addresses has this MAC used?
- Historical router changes
- Address churn rate over time

**Value:**
- Long-term asset tracking
- Forensic investigation support
- Trend analysis and capacity planning

---

### 13. Passive OS Fingerprinting

**Priority:** Low
**Complexity:** High
**Status:** Research needed

Infer operating system from NDP behavior patterns.

**Signals:**
- RS/RA timing patterns
- DAD behavior (number of probes, timing)
- Privacy extension usage patterns
- mDNS service announcements
- DHCPv6 client behavior

**Value:**
- Asset inventory enrichment
- Identify device types without active scanning

---

### 14. MLD Support (IMPLEMENTED IN PR #10)
```
**Priority:** High
**Complexity:** Low
**Status:** Future / v2.0

MLD (Multicast Listener Discovery) is IPv6's mechanism for hosts to tell routers "I want to receive traffic for this multicast group." It's the IPv6 equivalent of IGMP in v4.

How it works on the wire:

- A router periodically sends a Multicast Listener Query (ICMPv6 type 130) asking "who's listening to what?"
- Hosts respond with a Multicast Listener Report (type 131 for MLDv1, type 143 for MLDv2) declaring which multicast groups they've joined
- When a host leaves a group, it sends a Multicast Listener Done (type 132)

All of this is ICMPv6 with the same protocol family the listener already has a raw socket open for. You're currently seeing these packets and throwing them away in classifyICMPv6().

Why it's valuable for NDPeekr:

The multicast groups a host joins are a fingerprint of what services it's running. These are well-known group addresses with direct meaning:

| Multicast Group   | What It Means                                                                           |
|-------------------|-----------------------------------------------------------------------------------------|
| ff02::fb          | mDNS — the host runs Bonjour/Avahi (macOS, Linux with avahi, Chromecasts, printers)     |
| ff02::1:3         | LLMNR — almost always Windows                                                           |
| ff02::c           | SSDP/UPnP — device discovery (smart home devices, media servers)                        |
| ff02::2           | All-Routers — the host is acting as a router                                            |
| ff02::16          | MLDv2-capable nodes                                                                     |
| ff02::1:ffXX:XXXX | Solicited-node multicast — tied to a specific unicast address (used for NDP resolution) |

So passively listening to MLD tells you not just that a host exists (which you already know from NDP), but what it's doing. A host joining `ff02::fb` and `ff02::1:3` is likely a Windows machine with mDNS enabled. One joining only `ff02::fb` is likely macOS or Linux. This feeds directly into the OS fingerprinting goal without any active probing.

It also reveals devices that might be quiet on NDP but chatty on multicast such as IoT devices that primarily communicate via mDNS.
```

## Implementation Priority

### Phase 1: Core Enhancements
1. MAC Address Extraction from NDP
2. Router Tracking Table
3. JSON Export
4. MLD

### Phase 2: Protocol Expansion
4. mDNS Monitoring
5. SLAAC vs DHCPv6 Detection
6. Prefix/Subnet Tracking

### Phase 3: Integration & Analysis
7. DHCPv6 Traffic Monitoring
8. Multi-Interface Support
9. Security Alerting

### Phase 4: Advanced Features
10. Network Topology Inference
11. Historical Data Storage
12. LLMNR Monitoring
13. Passive OS Fingerprinting

---

## Architecture Considerations

### Current: Single Binary
- Simple deployment
- All features in one process
- Suitable for Phase 1-2

### Future: Modular Suite
As features grow, consider splitting into:
- **ndp-collector**: Core NDP/DHCPv6/mDNS capture daemon
- **ndp-store**: Data aggregation and storage service
- **ndp-view**: Terminal UI / web dashboard
- **ndp-export**: JSON/Prometheus/SIEM integrations
- **ndp-alert**: Security monitoring and alerting

Communication via:
- Unix sockets for local
- gRPC for distributed deployment
- Shared SQLite/Redis for state

---

## Contributing

Each feature above should become a GitHub issue/epic with:
- Clear acceptance criteria
- Test cases
- Documentation requirements

PRs welcome for any Phase 1-2 features. Phase 3+ features should be discussed in issues first to align on architecture.
