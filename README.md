# NDPeekr
![NDPPeekr](ndpeekr_logo.png)

A lightweight Go tool for passive IPv6 network discovery through NDP (Neighbor Discovery Protocol) traffic monitoring. NDPeekr captures and aggregates NDP messages to build a real-time inventory of active IPv6 hosts on your network segment. This probably isn't as interesting running at home as it is in a corporate environment, campus, or public wifi. It can be a useful tool for network administrators, security analysts, and incident responders to gain visibility into IPv6 host activity without relying on active scanning.

## What It Does

NDPeekr listens for ICMPv6 NDP and MLD messages and displays a rolling two-tab TUI showing:

- All unique IPv6 addresses observed, with per-type message counts (RS, RA, NS, NA, Redirect, DAR, DAC, MLD Query/Report/Done)
- MAC address and hop limit extracted from NDP options
- Inferred OS/device type based on MLD multicast group memberships (macOS/Linux, Windows, IoT/UPnP, Router)
- Active multicast group memberships per peer, with a cross-peer group summary
- Router Advertisement details: lifetime, DHCPv6 flags, advertised prefixes (with SLAAC/on-link flags and lifetimes), RDNSS DNS servers, and RFC 4191 route information
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
You will likely need to run `go run` with elevated privileges.
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

| Flag          | Default | Description                                      |
|---------------|---------|--------------------------------------------------|
| `--listen`    | `::`    | IPv6 address to bind                             |
| `--iface`     | (all)   | Interface name to restrict capture (best-effort) |
| `--window`    | `15m`   | Sliding window duration for statistics           |
| `--refresh`   | `2s`    | Table refresh interval                           |
| `--log-level` | `info`  | Log verbosity: debug, info, warn, error          |

## Output

NDPeekr runs as a full-screen TUI with two tabs. Use `Tab` to switch between them. Press `q` to quit. Press `Enter` to view details for a specific row. Up/down arrow keys navigate the table.

### NDP/MLD Peers tab

```
NDP/MLD Statistics (window: 15m, updated: 14:32:15)

[ NDP/MLD Peers ]    Routers

 IPv6 Address                              MAC               RS  RA  NS  NA  Rdr DAR DAC  MQ  MR  MD  Total First    Last    HL  Iface      Type
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 fe80::1                                   aa:bb:cc:dd:ee:ff   0  12   0   8    0   0   0   3   1   0     24  14:17:03 14:32:14  64  en0        Router
▶fe80::a1b2:c3d4:e5f6:7890                 11:22:33:44:55:66   3   0   5   5    0   0   0   0   2   0     15  14:20:45 14:31:58  64  en0        macOS/Linux
 2001:db8:cafe::1                          -                    0   0   2   2    0   0   0   1   0   0      5  14:28:12 14:30:22   -  en0        -
 ff02::1:ff1a:2b3c                         -                    0   0   0   0    0   0   0   8   0   0      8  14:22:00 14:32:10   -  en0        -
 ff02::16                                  -                    0   0   0   0    0   0   0   0   4   0      4  14:17:05 14:30:55   -  en0        -

Total peers: 5

Multicast Groups:
  ff02::1                                    All Nodes        5 hosts
  ff02::1:ff1a:2b3c                          Solicited-Node   3 hosts
  ff02::16                                   MLDv2            2 hosts
  ff02::2                                    All Routers      1 host

↑/↓: navigate  Enter: details  Tab: switch view  q: quit
```

### Routers tab

```
NDP/MLD Statistics (window: 15m, updated: 14:32:15)

  NDP/MLD Peers    [ Routers ]

 Router Address                             MAC               Life   Hop M O Pfx MTU   DNS Iface      Last
──────────────────────────────────────────────────────────────────────────────────────────────────────────
▶fe80::1                                    aa:bb:cc:dd:ee:ff  30m     64 N N   2  1500   1 en0        14:32:14

Total routers: 1

↑/↓: navigate  Enter: details  Tab: switch view  q: quit
```

### Peer detail view (press Enter on a row)

```
NDP/MLD Statistics (window: 15m, updated: 14:32:15)

  NDP/MLD Peers    Routers

Peer Detail: fe80::a1b2:c3d4:e5f6:7890

  MAC:        11:22:33:44:55:66
  Hop Limit:  64
  Interface:  en0
  OS/Type:    macOS/Linux
  First Seen: 14:20:45
  Last Seen:  14:31:58

  Message Counts:
    RS       3    RA       0    NS       5    NA       5    Rdr      0    DAR      0    DAC      0
    MQ       0    MR       2    MD       0

  Total:  15

  Multicast Groups:
    ff02::1:ffc3:d4e5                         Solicited-Node
    ff02::1                                   All Nodes

Esc: back  q: quit
```

### Router detail view (press Enter on a router row)

```
NDP/MLD Statistics (window: 15m, updated: 14:32:15)

  NDP/MLD Peers    [ Routers ]

Router Detail: fe80::1

  MAC:        aa:bb:cc:dd:ee:ff
  Interface:  en0
  Hop Limit:  64
  First Seen: 14:17:03
  Last Seen:  14:32:14

  Router Advertisement:
    Lifetime:      30m
    Managed (M):   No
    Other (O):     No
    MTU:           1500

  Prefixes:
    Prefix                                    Valid     Pref      L  A
    2001:db8:cafe::/64                        24h       4h        Y  Y

  DNS Servers (RDNSS):
    2001:db8::53

  Routes:
    Prefix                                    Lifetime  Pref
    ::/0                                      30m       med

Esc: back  q: quit
```

## Column Reference

### Peers Tab Columns

| Column | Description |
|--------|-------------|
| IPv6 Address | Source IPv6 address of the observed peer |
| MAC | Link-layer address extracted from NDP Source/Target Link-Layer Address options (`-` if not yet observed) |
| RS | Router Solicitation count within the sliding window |
| RA | Router Advertisement count within the sliding window |
| NS | Neighbor Solicitation count within the sliding window |
| NA | Neighbor Advertisement count within the sliding window |
| Rdr | ICMPv6 Redirect count within the sliding window |
| DAR | Duplicate Address Request count within the sliding window (RFC 6775) |
| DAC | Duplicate Address Confirmation count within the sliding window (RFC 6775) |
| MQ | MLD Query count within the sliding window |
| MR | MLD Report count within the sliding window (v1 and v2 combined) |
| MD | MLD Done count within the sliding window |
| Total | Sum of all message type counts within the sliding window |
| First | Time the address was first observed (HH:MM:SS) |
| Last | Time the most recent message was observed (HH:MM:SS) |
| HL | IPv6 hop limit observed in the packet header (`-` if unknown) |
| Iface | Network interface the traffic was seen on |
| Type | Inferred OS or device type based on MLD group memberships (see [OS/Type Inference](#ostype-inference)) |

### Routers Tab Columns

| Column | Description |
|--------|-------------|
| Router Address | Link-local IPv6 address of the advertising router |
| MAC | Link-layer address from the Source Link-Layer Address option in RA |
| Life | Router lifetime from the Router Advertisement (how long this router is valid as a default gateway) |
| Hop | Current hop limit advertised in the RA (recommended TTL for outgoing packets) |
| M | Managed address configuration flag — `Y` means hosts should use DHCPv6 for address assignment |
| O | Other configuration flag — `Y` means hosts should use DHCPv6 for other config (DNS, NTP, etc.) even if addresses are SLAAC |
| Pfx | Number of Prefix Information options in the RA (advertised on-link / SLAAC prefixes) |
| MTU | Link MTU from the MTU option (`-` if not advertised) |
| DNS | Number of RDNSS (Recursive DNS Server) addresses advertised in the RA |
| Iface | Network interface the RA was received on |
| Last Seen | Time the most recent RA from this router was observed |

## OS/Type Inference

NDPeekr infers the likely OS or device type from the MLD multicast groups a peer has reported joining. This is a heuristic based on well-known protocol group memberships:

| Inferred Type | Signal |
|---------------|--------|
| Router | Peer has joined `ff02::2` (All Routers) |
| Windows | Peer has joined `ff02::1:3` (LLMNR) |
| macOS/Linux | Peer has joined `ff02::fb` (mDNS/Bonjour) without LLMNR |
| IoT/UPnP | Peer has joined `ff02::c` (SSDP/UPnP) without mDNS |
| (blank) | Insufficient MLD data to make an inference |

A peer is only shown in the Peers tab after it generates NDP/MLD traffic; the OS/Type field remains blank until MLD Report messages reveal group memberships. Peers that join both `ff02::fb` (mDNS) and `ff02::1:3` (LLMNR) are classified as Windows (Windows 10+ supports both protocols).

## Message Types

### NDP (Neighbor Discovery Protocol)

| Abbreviation | Full Name                      | Description                                       |
|--------------|--------------------------------|---------------------------------------------------|
| RS           | Router Solicitation            | Host requesting router information                |
| RA           | Router Advertisement           | Router announcing its presence and network config |
| NS           | Neighbor Solicitation          | Address resolution (like ARP for IPv6)            |
| NA           | Neighbor Advertisement         | Response to NS with link-layer address            |
| Rdr          | Redirect                       | Router informing host of better first-hop         |
| DAR          | Duplicate Address Request      | DAD probe (RFC 6775)                              |
| DAC          | Duplicate Address Confirmation | DAD response (RFC 6775)                           |

### MLD (Multicast Listener Discovery)

| Abbreviation | Full Name         | Description                                          |
|--------------|-------------------|------------------------------------------------------|
| MQ           | MLD Query         | Router querying for multicast group membership       |
| MR           | MLD Report        | Host reporting multicast group membership (v1 or v2) |
| MD           | MLD Done          | Host leaving a multicast group                       |
