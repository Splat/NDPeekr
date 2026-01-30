# NDPeekr

A lightweight Go tool for passive IPv6 network discovery through NDP (Neighbor Discovery Protocol) traffic monitoring. NDPeekr captures and aggregates NDP messages to build a real-time inventory of active IPv6 hosts on your network segment.

## What It Does

NDPeekr listens for ICMPv6 NDP messages and displays a rolling summary table showing:

- All unique IPv6 addresses observed
- Message counts by type (Router Solicitation, Router Advertisement, Neighbor Solicitation, Neighbor Advertisement, Redirect, DAD)
- First and last seen timestamps
- Automatic timeout of stale entries via configurable sliding window

Instead of flooding your terminal with individual packet logs, NDPeekr maintains aggregate statistics and refreshes a clean summary table at regular intervals.

## Why Monitor NDP Traffic?

### Network Inventory & Asset Discovery

IPv6 networks often have hosts that don't appear in traditional asset inventories. NDP traffic reveals:

- **SLAAC-configured hosts** that self-assign addresses without DHCP
- **Link-local addresses** (fe80::) that exist on every IPv6-enabled interface
- **Temporary/privacy addresses** that rotate but still generate NDP traffic
- **IoT and embedded devices** that may be invisible to other discovery methods

### Security Monitoring

Passive NDP monitoring provides valuable security insights:

- **Rogue device detection**: New IPv6 addresses appearing unexpectedly may indicate unauthorized devices
- **Router advertisement spoofing**: Unexpected RA messages could indicate a rogue router or MITM attack
- **DAD attacks**: Duplicate Address Detection abuse can be used for DoS attacks
- **Network reconnaissance**: Unusual NS/NA patterns may indicate active scanning
- **Baseline establishment**: Understanding normal NDP patterns helps identify anomalies

### Incident Response

During an incident, NDP data helps answer:

- What IPv6 hosts were active during a specific time window?
- Which hosts are generating unusual amounts of NDP traffic?
- Are there unexpected router advertisements on the segment?

## Building

```bash
# Install dependencies
go mod tidy

# Build the binary
go build -o NDPeekr
```

## Running Tests

```bash
go test ./... -v
```

## Running NDPeekr

NDPeekr requires root/sudo privileges to open raw ICMPv6 sockets.

### Using go run

```bash
# Basic usage with defaults (15m window, 2s refresh)
sudo go run .

# With custom window and refresh interval
sudo go run . --window 5m --refresh 1s

# Restrict to a specific interface
sudo go run . --iface en0

# Debug logging (goes to stderr, won't interfere with table)
sudo go run . --log-level debug
```

### Using the compiled binary

```bash
# Basic usage
sudo ./NDPeekr

# Custom sliding window (stats older than this are pruned)
sudo ./NDPeekr --window 2m

# Faster refresh rate
sudo ./NDPeekr --refresh 500ms

# Full example with all options
sudo ./NDPeekr --iface en0 --window 10m --refresh 1s --log-level info
```

## Command Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `::` | IPv6 address to bind |
| `--iface` | (all) | Interface name to restrict capture (best-effort) |
| `--window` | `15m` | Sliding window duration for statistics |
| `--refresh` | `2s` | Table refresh interval |
| `--log-level` | `info` | Log verbosity: debug, info, warn, error |

## Output

NDPeekr displays a table like:

```
NDP Statistics (window: 15m, updated: 14:32:15)
──────────────────────────────────────────────────────────────────────────────────────────────────────
IPv6 Address                 RS    RA    NS    NA Redir   DAR   DAC  Total  First Seen  Last Seen
──────────────────────────────────────────────────────────────────────────────────────────────────────
fe80::1                      0    12     0     8     0     0     0     20  14:17:03    14:32:14
fe80::a1b2:c3d4:e5f6:7890    3     0     5     5     0     0     0     13  14:20:45    14:31:58
2001:db8::1234               0     0     2     2     0     0     0      4  14:28:12    14:30:22
──────────────────────────────────────────────────────────────────────────────────────────────────────
Total peers: 3
```

## Message Types

| Abbreviation | Full Name | Description |
|--------------|-----------|-------------|
| RS | Router Solicitation | Host requesting router information |
| RA | Router Advertisement | Router announcing its presence and network config |
| NS | Neighbor Solicitation | Address resolution (like ARP for IPv6) |
| NA | Neighbor Advertisement | Response to NS with link-layer address |
| Redir | Redirect | Router informing host of better first-hop |
| DAR | Duplicate Address Request | DAD probe (RFC 6775) |
| DAC | Duplicate Address Confirmation | DAD response (RFC 6775) |
