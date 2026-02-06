package lib

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

type NDPListenerConfig struct {
	ListenAddr string       // e.g. "::"
	Interface  string       // optional; best-effort restriction by ifindex (requires control msgs)
	Logger     *slog.Logger // required
	Stats      *NDPStats    // optional; if set, records messages instead of logging
}

type NDPListener struct {
	cfg NDPListenerConfig
}

func NewNDPListener(cfg NDPListenerConfig) *NDPListener {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "::"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &NDPListener{cfg: cfg}
}

// Run opens an ICMPv6 socket and logs common NDP message types.
//
// Notes:
// - Requires elevated privileges (root/CAP_NET_RAW) for "ip6:ipv6-icmp".
// - Interface restriction is best-effort; we filter using the received IfIndex control message.
// - If you later want strict NDP validity, enforce HopLimit == 255 before accepting events.
// - -- TODO: Add hop limit as a cli parameter
func (l *NDPListener) Run(ctx context.Context) error {
	// ICMPv6 socket (datagram-style, not net.Conn).
	pc, err := icmp.ListenPacket("ip6:ipv6-icmp", l.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen icmpv6: %w", err)
	}
	defer pc.Close()

	// FIX: Derives the IPv6 PacketConn wrapper from the ICMP PacketConn.
	p := pc.IPv6PacketConn()
	if p == nil {
		return fmt.Errorf("pc.IPv6PacketConn() returned nil (unexpected for ip6:ipv6-icmp)")
	}

	// Request control messages: hop limit + interface index + destination address.
	if err := p.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagInterface|ipv6.FlagDst, true); err != nil {
		l.cfg.Logger.Warn("failed to enable ipv6 control messages; continuing", "err", err)
	}

	// Resolve the requested interface if any
	var wantIfIndex int
	if l.cfg.Interface != "" {
		ifi, e := net.InterfaceByName(l.cfg.Interface)
		if e != nil {
			l.cfg.Logger.Warn("interface not found; continuing without restriction", "iface", l.cfg.Interface, "err", e)
		} else {
			wantIfIndex = ifi.Index
			l.cfg.Logger.Info("interface restriction requested", "iface", ifi.Name, "ifindex", ifi.Index)
		}
	}

	buf := make([]byte, 64*1024)

	// Use deadlines so ctx cancellation is honored promptly
	const readTimeout = 800 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_ = pc.SetReadDeadline(time.Now().Add(readTimeout))

		// Read via ipv6.PacketConn so we get control messages (cm).
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read: %w", err)
		}

		srcIP := ipFromAddr(src)

		// Best-effort interface restriction (requires cm.IfIndex)
		if wantIfIndex != 0 {
			if cm == nil || cm.IfIndex != wantIfIndex {
				continue
			}
		}

		// Parse ICMPv6 message bytes
		msg, perr := icmp.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), buf[:n])
		if perr != nil {
			l.cfg.Logger.Warn("failed to parse icmpv6", "src", srcIP, "len", n, "err", perr)
			continue
		}

		ndpKind := classifyICMPv6(msg.Type)
		if ndpKind == "" {
			// Not an NDP ICMPv6 type; ignore by default
			continue
		}

		// this is the args sent to log info further down
		fields := []any{
			"type", msg.Type,
			"code", msg.Code,
			"ndp", ndpKind,
			"src", srcIP,
			"len", n,
		}

		if cm != nil {
			if cm.HopLimit != 0 {
				fields = append(fields, "hoplimit", cm.HopLimit)
			}
			if cm.IfIndex != 0 {
				if ifi, e := net.InterfaceByIndex(cm.IfIndex); e == nil {
					fields = append(fields, "iface", ifi.Name, "ifindex", ifi.Index)
				} else {
					fields = append(fields, "ifindex", cm.IfIndex)
				}
			}
			if cm.Dst != nil {
				fields = append(fields, "dst", cm.Dst.String())
			}
		}

		// Record to stats if configured, otherwise log
		if l.cfg.Stats != nil {
			l.cfg.Stats.RecordMessage(srcIP, ndpKind)

			// Extract multicast group addresses from MLD reports/done
			if ndpKind == "mld_report" || ndpKind == "mld_done" {
				for _, group := range parseMLDGroups(buf[:n]) {
					l.cfg.Stats.RecordMLDMembership(srcIP, group)
				}
			}
		} else {
			l.cfg.Logger.Info("ndp event", fields...)
		}
	}
}

func ipFromAddr(a net.Addr) string {
	switch v := a.(type) {
	case *net.IPAddr:
		return v.IP.String()
	case *net.UDPAddr:
		return v.IP.String()
	default:
		if a == nil {
			return ""
		}
		return a.String()
	}
}

// classifyICMPv6 maps ICMPv6 message types to internal kind strings.
//
// NDP (Neighbor Discovery Protocol):
//   133 Router Solicitation (RS)
//   134 Router Advertisement (RA)
//   135 Neighbor Solicitation (NS)
//   136 Neighbor Advertisement (NA)
//   137 Redirect
//   157 Duplicate Address Request (DAR)
//   158 Duplicate Address Confirmation (DAC)
//
// MLD (Multicast Listener Discovery):
//   130 Multicast Listener Query
//   131 Multicast Listener Report (MLDv1)
//   132 Multicast Listener Done
//   143 Multicast Listener Report (MLDv2)
func classifyICMPv6(t icmp.Type) string {
	switch t {
	// NDP
	case ipv6.ICMPTypeRouterSolicitation:
		return "router_solicitation"
	case ipv6.ICMPTypeRouterAdvertisement:
		return "router_advertisement"
	case ipv6.ICMPTypeNeighborSolicitation:
		return "neighbor_solicitation"
	case ipv6.ICMPTypeNeighborAdvertisement:
		return "neighbor_advertisement"
	case ipv6.ICMPTypeDuplicateAddressRequest:
		return "duplicate_address_request"
	case ipv6.ICMPTypeDuplicateAddressConfirmation:
		return "duplicate_address_confirmation"
	case ipv6.ICMPTypeRedirect:
		return "redirect"
	// MLD
	case ipv6.ICMPTypeMulticastListenerQuery:
		return "mld_query"
	case ipv6.ICMPTypeMulticastListenerReport:
		return "mld_report"
	case ipv6.ICMPTypeMulticastListenerDone:
		return "mld_done"
	case ipv6.ICMPTypeVersion2MulticastListenerReport:
		return "mld_report"
	default:
		return ""
	}
}

// parseMLDGroups extracts multicast group addresses from a raw ICMPv6 packet.
// buf must include the full ICMPv6 message (type, code, checksum, body).
// Returns nil for non-MLD types or malformed packets.
func parseMLDGroups(buf []byte) []string {
	if len(buf) < 4 {
		return nil
	}
	icmpType := buf[0]

	switch icmpType {
	case 131, 132: // MLDv1 Report or Done
		return parseMLDv1Groups(buf)
	case 143: // MLDv2 Report
		return parseMLDv2Groups(buf)
	default:
		return nil
	}
}

// parseMLDv1Groups parses an MLDv1 Report (131) or Done (132) message.
// Layout after ICMPv6 header (4 bytes):
//
//	Bytes 0-1: Maximum Response Delay
//	Bytes 2-3: Reserved
//	Bytes 4-19: Multicast Address (16 bytes)
func parseMLDv1Groups(buf []byte) []string {
	// 4 (ICMPv6 header) + 4 (delay + reserved) + 16 (address) = 24
	if len(buf) < 24 {
		return nil
	}
	group := net.IP(buf[8:24])
	if group.IsUnspecified() {
		return nil
	}
	return []string{group.String()}
}

// parseMLDv2Groups parses an MLDv2 Report (143) message.
// Layout after ICMPv6 header (4 bytes):
//
//	Bytes 0-1: Reserved
//	Bytes 2-3: Number of Multicast Address Records
//	Bytes 4+:  Multicast Address Records
//
// Each record:
//
//	Byte 0:    Record Type
//	Byte 1:    Aux Data Len (in 32-bit words)
//	Bytes 2-3: Number of Sources
//	Bytes 4-19: Multicast Address (16 bytes)
//	Bytes 20+: Source Addresses (16 bytes each)
//	Then:      Auxiliary Data (AuxDataLen * 4 bytes)
func parseMLDv2Groups(buf []byte) []string {
	// Need at least: 4 (ICMPv6 header) + 4 (reserved + count) = 8
	if len(buf) < 8 {
		return nil
	}
	numRecords := int(binary.BigEndian.Uint16(buf[6:8]))
	if numRecords == 0 {
		return nil
	}

	var groups []string
	offset := 8 // start of first record
	for i := 0; i < numRecords; i++ {
		// Each record needs at least 20 bytes (4 header + 16 group addr)
		if offset+20 > len(buf) {
			break
		}
		auxDataLen := int(buf[offset+1])
		numSources := int(binary.BigEndian.Uint16(buf[offset+2 : offset+4]))
		group := net.IP(buf[offset+4 : offset+20])
		if !group.IsUnspecified() {
			groups = append(groups, group.String())
		}
		// Advance: 20 (fixed) + sources*16 + auxData*4
		offset += 20 + numSources*16 + auxDataLen*4
	}
	return groups
}
