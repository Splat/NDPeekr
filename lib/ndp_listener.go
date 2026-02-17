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
			if cm != nil {
				if cm.HopLimit != 0 {
					l.cfg.Stats.RecordHopLimit(srcIP, cm.HopLimit)
				}
				if cm.IfIndex != 0 {
					if ifi, e := net.InterfaceByIndex(cm.IfIndex); e == nil {
						l.cfg.Stats.RecordInterface(srcIP, ifi.Name)
					}
				}
			}

			// Extract link-layer (MAC) address from NDP options
			var mac string
			switch ndpKind {
			case "router_solicitation", "router_advertisement", "neighbor_solicitation":
				mac = parseLinkLayerAddr(buf[:n], 1) // Source Link-Layer Address
			case "neighbor_advertisement":
				mac = parseLinkLayerAddr(buf[:n], 2) // Target Link-Layer Address
			}
			if mac != "" {
				l.cfg.Stats.RecordMAC(srcIP, mac)
			}

			// Parse Router Advertisement details
			if ndpKind == "router_advertisement" {
				ifName := ""
				if cm != nil && cm.IfIndex != 0 {
					if ifi, e := net.InterfaceByIndex(cm.IfIndex); e == nil {
						ifName = ifi.Name
					}
				}
				hopLim := 0
				if cm != nil {
					hopLim = cm.HopLimit
				}
				if ri := parseRA(buf[:n], srcIP, mac, hopLim, ifName); ri != nil {
					l.cfg.Stats.RecordRouter(*ri)
				}
			}

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

// ndpOptionsOffset returns the byte offset where NDP options begin for a given
// ICMPv6 message type, or -1 if the type doesn't carry NDP options.
//
//	RS  (133): 4 (header) + 4 (reserved) = 8
//	RA  (134): 4 (header) + 12 (fields)  = 16
//	NS  (135): 4 (header) + 4 (reserved) + 16 (target) = 24
//	NA  (136): 4 (header) + 4 (flags)    + 16 (target) = 24
//	Rdr (137): 4 (header) + 4 (reserved) + 16 (target) + 16 (dest) = 40
func ndpOptionsOffset(icmpType byte) int {
	switch icmpType {
	case 133: // RS
		return 8
	case 134: // RA
		return 16
	case 135, 136: // NS, NA
		return 24
	case 137: // Redirect
		return 40
	default:
		return -1
	}
}

// parseLinkLayerAddr extracts a link-layer (MAC) address from NDP options.
// buf is the full raw ICMPv6 message (type byte at buf[0]).
// optionType: 1 = Source Link-Layer Address, 2 = Target Link-Layer Address.
// Returns "" if the option is not found or the packet is malformed.
func parseLinkLayerAddr(buf []byte, optionType byte) string {
	if len(buf) < 1 {
		return ""
	}
	offset := ndpOptionsOffset(buf[0])
	if offset < 0 || len(buf) < offset {
		return ""
	}

	// Walk the TLV option chain
	for offset+2 <= len(buf) {
		oType := buf[offset]
		oLen := int(buf[offset+1]) * 8 // Length field is in 8-byte units

		if oLen == 0 {
			break // malformed option; avoid infinite loop
		}
		if offset+oLen > len(buf) {
			break // truncated
		}

		if oType == optionType && oLen >= 8 {
			// Bytes 2-7 of the option are the 6-byte Ethernet MAC address
			mac := net.HardwareAddr(buf[offset+2 : offset+8])
			return mac.String()
		}

		offset += oLen
	}
	return ""
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
// parseRA extracts Router Advertisement fields and options from a raw ICMPv6 packet.
// buf must be the full ICMPv6 message. Returns nil if the packet is too short.
//
// RA header layout (after 4-byte ICMPv6 header):
//
//	Byte 4:   Cur Hop Limit
//	Byte 5:   Flags — bit 7 = M (managed), bit 6 = O (other config)
//	Bytes 6-7: Router Lifetime (seconds, big-endian)
//
// RA options start at byte 16 (TLV chain).
func parseRA(buf []byte, srcIP, mac string, hopLimit int, ifName string) *RouterInfo {
	// Minimum RA: 4 (ICMPv6 header) + 12 (RA fields) = 16 bytes
	if len(buf) < 16 {
		return nil
	}

	ri := &RouterInfo{
		Address:   srcIP,
		MAC:       mac,
		Interface: ifName,
		LastSeen:  time.Now(),
	}

	// RA header fields
	ri.HopLimit = int(buf[4])
	ri.Managed = buf[5]&0x80 != 0
	ri.Other = buf[5]&0x40 != 0
	ri.Lifetime = time.Duration(binary.BigEndian.Uint16(buf[6:8])) * time.Second

	// If the IPv6 hop limit from the control message is available and the RA
	// cur-hop-limit field is zero, use the control message value.
	if ri.HopLimit == 0 && hopLimit != 0 {
		ri.HopLimit = hopLimit
	}

	// Walk RA options (TLV chain starting at byte 16)
	offset := 16
	for offset+2 <= len(buf) {
		oType := buf[offset]
		oLen := int(buf[offset+1]) * 8 // length in 8-byte units
		if oLen == 0 {
			break
		}
		if offset+oLen > len(buf) {
			break
		}

		switch oType {
		case 3: // Prefix Information (32 bytes)
			if oLen >= 32 {
				parseRAPrefixInfo(buf[offset:offset+oLen], ri)
			}
		case 5: // MTU
			if oLen >= 8 {
				ri.MTU = binary.BigEndian.Uint32(buf[offset+4 : offset+8])
			}
		case 24: // Route Information (RFC 4191)
			if oLen >= 8 {
				parseRARouteInfo(buf[offset:offset+oLen], oLen, ri)
			}
		case 25: // RDNSS (RFC 6106)
			if oLen >= 24 {
				parseRARDNSS(buf[offset:offset+oLen], oLen, ri)
			}
		}

		offset += oLen
	}

	return ri
}

// parseRAPrefixInfo parses an RA Prefix Information option (type 3, 32 bytes).
//
//	Byte 2:     Prefix Length
//	Byte 3:     Flags — bit 7 = L (on-link), bit 6 = A (autonomous/SLAAC)
//	Bytes 4-7:  Valid Lifetime (seconds)
//	Bytes 8-11: Preferred Lifetime (seconds)
//	Bytes 16-31: Prefix (16 bytes)
func parseRAPrefixInfo(opt []byte, ri *RouterInfo) {
	prefixLen := int(opt[2])
	onLink := opt[3]&0x80 != 0
	autonomous := opt[3]&0x40 != 0
	validLife := time.Duration(binary.BigEndian.Uint32(opt[4:8])) * time.Second
	prefLife := time.Duration(binary.BigEndian.Uint32(opt[8:12])) * time.Second
	prefix := net.IP(opt[16:32])

	ri.Prefixes = append(ri.Prefixes, PrefixInfo{
		Prefix:        fmt.Sprintf("%s/%d", prefix, prefixLen),
		ValidLifetime: validLife,
		PreferredLife: prefLife,
		OnLink:        onLink,
		Autonomous:    autonomous,
	})
}

// parseRARouteInfo parses an RA Route Information option (type 24, RFC 4191).
//
//	Byte 2:    Prefix Length
//	Byte 3:    Preference (bits 4-3): 00=medium, 01=high, 11=low
//	Bytes 4-7: Route Lifetime (seconds)
//	Bytes 8+:  Prefix (variable, padded to option boundary)
func parseRARouteInfo(opt []byte, oLen int, ri *RouterInfo) {
	prefixLen := int(opt[2])
	pref := int((opt[3] >> 3) & 0x03)
	lifetime := time.Duration(binary.BigEndian.Uint32(opt[4:8])) * time.Second

	// Prefix bytes: remaining option bytes after the 8-byte header, up to 16 bytes
	prefixBytes := make(net.IP, 16)
	copyLen := oLen - 8
	if copyLen > 16 {
		copyLen = 16
	}
	if copyLen > 0 && 8+copyLen <= len(opt) {
		copy(prefixBytes, opt[8:8+copyLen])
	}

	ri.Routes = append(ri.Routes, RouteInfo{
		Prefix:     fmt.Sprintf("%s/%d", prefixBytes, prefixLen),
		PrefixLen:  prefixLen,
		Preference: pref,
		Lifetime:   lifetime,
	})
}

// parseRARDNSS parses an RA RDNSS option (type 25, RFC 6106).
//
//	Bytes 4-7: Lifetime (seconds)
//	Bytes 8+:  DNS server addresses (16 bytes each)
func parseRARDNSS(opt []byte, oLen int, ri *RouterInfo) {
	// Each address is 16 bytes, starting at offset 8
	for off := 8; off+16 <= oLen && off+16 <= len(opt); off += 16 {
		addr := net.IP(opt[off : off+16])
		ri.RDNSS = append(ri.RDNSS, addr.String())
	}
}

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
