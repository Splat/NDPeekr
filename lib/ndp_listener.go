package lib

import (
	"context"
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

	// Resolve requested interface (if any).
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

	// Use deadlines so ctx cancellation is honored promptly.
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

		// Best-effort interface restriction (requires cm.IfIndex).
		if wantIfIndex != 0 {
			if cm == nil || cm.IfIndex != wantIfIndex {
				continue
			}
		}

		// Parse ICMPv6 message bytes.
		msg, perr := icmp.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), buf[:n])
		if perr != nil {
			l.cfg.Logger.Warn("failed to parse icmpv6", "src", srcIP, "len", n, "err", perr)
			continue
		}

		ndpKind := classifyICMPv6(msg.Type)
		if ndpKind == "" {
			// Not an NDP ICMPv6 type; ignore by default.
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

		// log the fields for the NDP message
		l.cfg.Logger.Info("ndp event", fields...)
		// TODO: create a running tally of sr ips, ts, intervals per msg type.
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

// NDP over ICMPv6 uses these primary message types:
// 133 Router Solicitation (RS)
// 134 Router Advertisement (RA)
// 135 Neighbor Solicitation (NS)
// 136 Neighbor Advertisement (NA)
// 137 Redirect
func classifyICMPv6(t icmp.Type) string {
	switch t {
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
	default:
		return ""
	}
}
