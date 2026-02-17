package lib

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
)

func TestClassifyICMPv6_NDPTypes(t *testing.T) {
	cases := []struct {
		name string
		typ  ipv6.ICMPType
		want string
	}{
		{"RS", ipv6.ICMPTypeRouterSolicitation, "router_solicitation"},
		{"RA", ipv6.ICMPTypeRouterAdvertisement, "router_advertisement"},
		{"NS", ipv6.ICMPTypeNeighborSolicitation, "neighbor_solicitation"},
		{"NA", ipv6.ICMPTypeNeighborAdvertisement, "neighbor_advertisement"},
		{"Redirect", ipv6.ICMPTypeRedirect, "redirect"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyICMPv6(tc.typ)
			if got != tc.want {
				t.Fatalf("classifyICMPv6(%v) = %q, want %q", tc.typ, got, tc.want)
			}
		})
	}
}

 func TestClassifyICMPv6_MLDTypes(t *testing.T) {
	cases := []struct {
		name string
		typ  ipv6.ICMPType
		want string
	}{
		{"MLDQuery", ipv6.ICMPTypeMulticastListenerQuery, "mld_query"},
		{"MLDv1Report", ipv6.ICMPTypeMulticastListenerReport, "mld_report"},
		{"MLDDone", ipv6.ICMPTypeMulticastListenerDone, "mld_done"},
		{"MLDv2Report", ipv6.ICMPTypeVersion2MulticastListenerReport, "mld_report"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyICMPv6(tc.typ)
			if got != tc.want {
				t.Fatalf("classifyICMPv6(%v) = %q, want %q", tc.typ, got, tc.want)
			}
		})
	}
}

func TestClassifyICMPv6_NonNDPTypesReturnEmpty(t *testing.T) {
	non := []ipv6.ICMPType{
		ipv6.ICMPTypeEchoRequest,
		ipv6.ICMPTypeEchoReply,
		ipv6.ICMPTypePacketTooBig,
		ipv6.ICMPTypeTimeExceeded,
		ipv6.ICMPTypeDestinationUnreachable,
	}

	for _, typ := range non {
		t.Run(typ.String(), func(t *testing.T) {
			if got := classifyICMPv6(typ); got != "" {
				t.Fatalf("classifyICMPv6(%v) = %q, want empty string", typ, got)
			}
		})
	}
}

func TestIPFromAddr_IPAddr(t *testing.T) {
	a := &net.IPAddr{IP: net.ParseIP("fe80::1")}
	got := ipFromAddr(a)
	if got != "fe80::1" {
		t.Fatalf("ipFromAddr(IPAddr) = %q, want %q", got, "fe80::1")
	}
}

func TestIPFromAddr_UDPAddr(t *testing.T) {
	a := &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 1234}
	got := ipFromAddr(a)
	if got != "2001:db8::2" {
		t.Fatalf("ipFromAddr(UDPAddr) = %q, want %q", got, "2001:db8::2")
	}
}

type dummyAddr string

func (d dummyAddr) Network() string { return "dummy" }
func (d dummyAddr) String() string  { return string(d) }

func TestIPFromAddr_UnknownAddrUsesString(t *testing.T) {
	a := dummyAddr("weird://addr")
	got := ipFromAddr(a)
	if got != "weird://addr" {
		t.Fatalf("ipFromAddr(dummy) = %q, want %q", got, "weird://addr")
	}
}

func TestIPFromAddr_Nil(t *testing.T) {
	got := ipFromAddr(nil)
	if got != "" {
		t.Fatalf("ipFromAddr(nil) = %q, want empty string", got)
	}
}

// --- Link-Layer Address (MAC) extraction tests ---

// buildNS constructs a raw NS (type 135) packet with a Source Link-Layer Address option.
// Layout: type(1) + code(1) + checksum(2) + reserved(4) + target(16) + option(8) = 32 bytes
func buildNS(targetIP net.IP, srcMAC net.HardwareAddr) []byte {
	buf := make([]byte, 32)
	buf[0] = 135 // NS
	copy(buf[8:24], targetIP.To16())
	// Source Link-Layer Address option (type=1, len=1 → 8 bytes)
	buf[24] = 1 // option type
	buf[25] = 1 // length in 8-byte units
	copy(buf[26:32], srcMAC)
	return buf
}

// buildNA constructs a raw NA (type 136) packet with a Target Link-Layer Address option.
func buildNA(targetIP net.IP, targetMAC net.HardwareAddr) []byte {
	buf := make([]byte, 32)
	buf[0] = 136 // NA
	buf[4] = 0xe0 // R+S+O flags
	copy(buf[8:24], targetIP.To16())
	// Target Link-Layer Address option (type=2, len=1 → 8 bytes)
	buf[24] = 2
	buf[25] = 1
	copy(buf[26:32], targetMAC)
	return buf
}

// buildRS constructs a raw RS (type 133) packet with a Source Link-Layer Address option.
// Layout: type(1) + code(1) + checksum(2) + reserved(4) + option(8) = 16 bytes
func buildRS(srcMAC net.HardwareAddr) []byte {
	buf := make([]byte, 16)
	buf[0] = 133 // RS
	buf[8] = 1   // option type (Source LLA)
	buf[9] = 1   // length
	copy(buf[10:16], srcMAC)
	return buf
}

// buildRA constructs a raw RA (type 134) packet with a Source Link-Layer Address option.
// Layout: type(1) + code(1) + checksum(2) + hop(1) + flags(1) + lifetime(2) +
//
//	reachable(4) + retrans(4) + option(8) = 24 bytes
func buildRA(srcMAC net.HardwareAddr) []byte {
	buf := make([]byte, 24)
	buf[0] = 134 // RA
	buf[4] = 64  // cur hop limit
	// Source Link-Layer Address option starts at offset 16
	buf[16] = 1
	buf[17] = 1
	copy(buf[18:24], srcMAC)
	return buf
}

func TestParseLinkLayerAddr_NS(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	buf := buildNS(net.ParseIP("fe80::1"), mac)

	got := parseLinkLayerAddr(buf, 1)
	if got != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("parseLinkLayerAddr(NS, source) = %q, want %q", got, "aa:bb:cc:dd:ee:01")
	}
}

func TestParseLinkLayerAddr_NA(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	buf := buildNA(net.ParseIP("fe80::2"), mac)

	got := parseLinkLayerAddr(buf, 2)
	if got != "00:11:22:33:44:55" {
		t.Fatalf("parseLinkLayerAddr(NA, target) = %q, want %q", got, "00:11:22:33:44:55")
	}
}

func TestParseLinkLayerAddr_RS(t *testing.T) {
	mac := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	buf := buildRS(mac)

	got := parseLinkLayerAddr(buf, 1)
	if got != "de:ad:be:ef:00:01" {
		t.Fatalf("parseLinkLayerAddr(RS, source) = %q, want %q", got, "de:ad:be:ef:00:01")
	}
}

func TestParseLinkLayerAddr_RA(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}
	buf := buildRA(mac)

	got := parseLinkLayerAddr(buf, 1)
	if got != "02:42:ac:11:00:02" {
		t.Fatalf("parseLinkLayerAddr(RA, source) = %q, want %q", got, "02:42:ac:11:00:02")
	}
}

func TestParseLinkLayerAddr_NoOption(t *testing.T) {
	// NS with no options (DAD sends NS from :: without Source LLA)
	buf := make([]byte, 24)
	buf[0] = 135
	copy(buf[8:24], net.ParseIP("fe80::1").To16())

	got := parseLinkLayerAddr(buf, 1)
	if got != "" {
		t.Fatalf("parseLinkLayerAddr(NS without option) = %q, want empty", got)
	}
}

func TestParseLinkLayerAddr_WrongOptionType(t *testing.T) {
	// NA carries Target LLA (type 2), asking for Source (type 1) should find nothing
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	buf := buildNA(net.ParseIP("fe80::1"), mac)

	got := parseLinkLayerAddr(buf, 1) // asking for Source, but only Target present
	if got != "" {
		t.Fatalf("parseLinkLayerAddr(NA, wrong option type) = %q, want empty", got)
	}
}

func TestParseLinkLayerAddr_TruncatedPacket(t *testing.T) {
	got := parseLinkLayerAddr([]byte{135, 0, 0}, 1)
	if got != "" {
		t.Fatalf("parseLinkLayerAddr(truncated) = %q, want empty", got)
	}
}

func TestParseLinkLayerAddr_NonNDPType(t *testing.T) {
	buf := []byte{128, 0, 0, 0, 0, 0, 0, 0} // Echo Request
	got := parseLinkLayerAddr(buf, 1)
	if got != "" {
		t.Fatalf("parseLinkLayerAddr(echo) = %q, want empty", got)
	}
}

func TestParseLinkLayerAddr_MultipleOptions(t *testing.T) {
	// NA with a prefix info option (type 3) followed by Target LLA (type 2)
	buf := make([]byte, 24+8+8) // NS body + 8-byte dummy option + 8-byte LLA option
	buf[0] = 136                // NA
	buf[4] = 0xe0
	copy(buf[8:24], net.ParseIP("fe80::1").To16())
	// First option: type=3 (Prefix Info, normally 32 bytes, but we use 8 for simplicity)
	buf[24] = 3
	buf[25] = 1 // 8 bytes
	// Second option: Target Link-Layer Address
	buf[32] = 2
	buf[33] = 1
	mac := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	copy(buf[34:40], mac)

	got := parseLinkLayerAddr(buf, 2)
	if got != "11:22:33:44:55:66" {
		t.Fatalf("parseLinkLayerAddr(multiple options) = %q, want %q", got, "11:22:33:44:55:66")
	}
}

func TestNdpOptionsOffset(t *testing.T) {
	cases := []struct {
		icmpType byte
		want     int
	}{
		{133, 8},   // RS
		{134, 16},  // RA
		{135, 24},  // NS
		{136, 24},  // NA
		{137, 40},  // Redirect
		{128, -1},  // Echo Request (not NDP)
		{131, -1},  // MLD (not NDP options)
	}
	for _, tc := range cases {
		got := ndpOptionsOffset(tc.icmpType)
		if got != tc.want {
			t.Errorf("ndpOptionsOffset(%d) = %d, want %d", tc.icmpType, got, tc.want)
		}
	}
}

// buildMLDv1Report constructs a raw MLDv1 Report (type 131) packet.
// Layout: type(1) + code(1) + checksum(2) + maxResponseDelay(2) + reserved(2) + multicastAddr(16) = 24 bytes
func buildMLDv1Report(group net.IP) []byte {
	buf := make([]byte, 24)
	buf[0] = 131 // MLDv1 Report
	copy(buf[8:24], group.To16())
	return buf
}

// buildMLDv1Done constructs a raw MLDv1 Done (type 132) packet.
func buildMLDv1Done(group net.IP) []byte {
	buf := make([]byte, 24)
	buf[0] = 132 // MLDv1 Done
	copy(buf[8:24], group.To16())
	return buf
}

// buildMLDv2Report constructs a raw MLDv2 Report (type 143) with the given groups.
// Each record: recordType(1) + auxDataLen(1) + numSources(2) + multicastAddr(16) = 20 bytes
func buildMLDv2Report(groups []net.IP) []byte {
	numRecords := len(groups)
	buf := make([]byte, 8+numRecords*20) // header(8) + records
	buf[0] = 143                         // MLDv2 Report
	buf[6] = byte(numRecords >> 8)
	buf[7] = byte(numRecords)
	for i, group := range groups {
		offset := 8 + i*20
		buf[offset] = 4 // Record Type: CHANGE_TO_EXCLUDE (join)
		copy(buf[offset+4:offset+20], group.To16())
	}
	return buf
}

func TestParseMLDGroups_MLDv1Report(t *testing.T) {
	group := net.ParseIP("ff02::fb")
	buf := buildMLDv1Report(group)

	got := parseMLDGroups(buf)
	if len(got) != 1 {
		t.Fatalf("parseMLDGroups(MLDv1 report) returned %d groups, want 1", len(got))
	}
	if got[0] != "ff02::fb" {
		t.Errorf("group = %q, want %q", got[0], "ff02::fb")
	}
}

func TestParseMLDGroups_MLDv1Done(t *testing.T) {
	group := net.ParseIP("ff02::1:3")
	buf := buildMLDv1Done(group)

	got := parseMLDGroups(buf)
	if len(got) != 1 {
		t.Fatalf("parseMLDGroups(MLDv1 done) returned %d groups, want 1", len(got))
	}
	if got[0] != "ff02::1:3" {
		t.Errorf("group = %q, want %q", got[0], "ff02::1:3")
	}
}

func TestParseMLDGroups_MLDv1UnspecifiedGroupIgnored(t *testing.T) {
	buf := buildMLDv1Report(net.IPv6zero)
	got := parseMLDGroups(buf)
	if len(got) != 0 {
		t.Fatalf("parseMLDGroups with :: group returned %d groups, want 0", len(got))
	}
}

func TestParseMLDGroups_MLDv2Report(t *testing.T) {
	groups := []net.IP{
		net.ParseIP("ff02::fb"),
		net.ParseIP("ff02::1:3"),
		net.ParseIP("ff02::c"),
	}
	buf := buildMLDv2Report(groups)

	got := parseMLDGroups(buf)
	if len(got) != 3 {
		t.Fatalf("parseMLDGroups(MLDv2 report) returned %d groups, want 3", len(got))
	}

	want := []string{"ff02::fb", "ff02::1:3", "ff02::c"}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("group[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestParseMLDGroups_MLDv2EmptyReport(t *testing.T) {
	buf := buildMLDv2Report(nil)
	got := parseMLDGroups(buf)
	if len(got) != 0 {
		t.Fatalf("parseMLDGroups(empty MLDv2) returned %d groups, want 0", len(got))
	}
}

func TestParseMLDGroups_NonMLDType(t *testing.T) {
	buf := []byte{133, 0, 0, 0, 0, 0, 0, 0} // RS type
	got := parseMLDGroups(buf)
	if got != nil {
		t.Fatalf("parseMLDGroups(RS) = %v, want nil", got)
	}
}

func TestParseMLDGroups_TruncatedPacket(t *testing.T) {
	// Too short for MLDv1
	buf := []byte{131, 0, 0, 0, 0, 0}
	got := parseMLDGroups(buf)
	if got != nil {
		t.Fatalf("parseMLDGroups(truncated) = %v, want nil", got)
	}
}

func TestParseMLDGroups_TruncatedMLDv2(t *testing.T) {
	// MLDv2 header claims 1 record but buffer is too short
	buf := []byte{143, 0, 0, 0, 0, 0, 0, 1}
	got := parseMLDGroups(buf)
	if len(got) != 0 {
		t.Fatalf("parseMLDGroups(truncated v2) returned %d groups, want 0", len(got))
	}
}

// --- Router Advertisement parsing tests ---

// buildRAFull constructs an RA packet with header fields and optional NDP options.
// Returns the raw ICMPv6 bytes.
func buildRAFull(hopLimit byte, managed, other bool, lifetime uint16, srcMAC net.HardwareAddr, options ...[]byte) []byte {
	// RA header: type(1) + code(1) + checksum(2) + hopLimit(1) + flags(1) + lifetime(2) + reachable(4) + retrans(4) = 16 bytes
	buf := make([]byte, 16)
	buf[0] = 134 // RA type
	buf[4] = hopLimit
	if managed {
		buf[5] |= 0x80
	}
	if other {
		buf[5] |= 0x40
	}
	binary.BigEndian.PutUint16(buf[6:8], lifetime)

	// Add Source Link-Layer Address option if MAC provided
	if len(srcMAC) == 6 {
		opt := make([]byte, 8)
		opt[0] = 1 // Source LLA
		opt[1] = 1 // 8 bytes
		copy(opt[2:8], srcMAC)
		buf = append(buf, opt...)
	}

	// Append additional options
	for _, opt := range options {
		buf = append(buf, opt...)
	}

	return buf
}

// buildPrefixInfoOption constructs a Prefix Information option (type 3, 32 bytes).
func buildPrefixInfoOption(prefix net.IP, prefixLen byte, onLink, autonomous bool, validLife, prefLife uint32) []byte {
	opt := make([]byte, 32)
	opt[0] = 3  // type
	opt[1] = 4  // length: 32/8 = 4
	opt[2] = prefixLen
	if onLink {
		opt[3] |= 0x80
	}
	if autonomous {
		opt[3] |= 0x40
	}
	binary.BigEndian.PutUint32(opt[4:8], validLife)
	binary.BigEndian.PutUint32(opt[8:12], prefLife)
	copy(opt[16:32], prefix.To16())
	return opt
}

// buildMTUOption constructs an MTU option (type 5, 8 bytes).
func buildMTUOption(mtu uint32) []byte {
	opt := make([]byte, 8)
	opt[0] = 5 // type
	opt[1] = 1 // length: 8/8 = 1
	binary.BigEndian.PutUint32(opt[4:8], mtu)
	return opt
}

// buildRDNSSOption constructs an RDNSS option (type 25) with DNS server addresses.
func buildRDNSSOption(lifetime uint32, servers ...net.IP) []byte {
	// Header: type(1) + len(1) + reserved(2) + lifetime(4) + addresses(16 each)
	optLen := 8 + len(servers)*16
	// Length field is in 8-byte units; round up
	lenField := optLen / 8
	opt := make([]byte, lenField*8)
	opt[0] = 25 // type
	opt[1] = byte(lenField)
	binary.BigEndian.PutUint32(opt[4:8], lifetime)
	for i, srv := range servers {
		copy(opt[8+i*16:8+(i+1)*16], srv.To16())
	}
	return opt
}

// buildRouteInfoOption constructs a Route Information option (type 24).
func buildRouteInfoOption(prefix net.IP, prefixLen byte, pref byte, lifetime uint32) []byte {
	// Determine option length based on prefix length
	// 0: 8 bytes, 1-64: 16 bytes, 65-128: 24 bytes
	var optSize int
	if prefixLen == 0 {
		optSize = 8
	} else if prefixLen <= 64 {
		optSize = 16
	} else {
		optSize = 24
	}
	opt := make([]byte, optSize)
	opt[0] = 24 // type
	opt[1] = byte(optSize / 8)
	opt[2] = prefixLen
	opt[3] = (pref & 0x03) << 3 // preference in bits 4-3
	binary.BigEndian.PutUint32(opt[4:8], lifetime)
	if optSize > 8 && prefix != nil {
		p := prefix.To16()
		copyLen := optSize - 8
		if copyLen > 16 {
			copyLen = 16
		}
		copy(opt[8:8+copyLen], p[:copyLen])
	}
	return opt
}

func TestParseRA_BasicFields(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	buf := buildRAFull(64, true, true, 1800, mac)

	ri := parseRA(buf, "fe80::1", "aa:bb:cc:dd:ee:01", 255, "en0")
	if ri == nil {
		t.Fatal("parseRA returned nil")
	}
	if ri.Address != "fe80::1" {
		t.Errorf("Address = %q, want %q", ri.Address, "fe80::1")
	}
	if ri.MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("MAC = %q", ri.MAC)
	}
	if ri.HopLimit != 64 {
		t.Errorf("HopLimit = %d, want 64", ri.HopLimit)
	}
	if !ri.Managed {
		t.Error("Managed should be true")
	}
	if !ri.Other {
		t.Error("Other should be true")
	}
	if ri.Lifetime != 1800*time.Second {
		t.Errorf("Lifetime = %v, want 1800s", ri.Lifetime)
	}
	if ri.Interface != "en0" {
		t.Errorf("Interface = %q, want %q", ri.Interface, "en0")
	}
}

func TestParseRA_PrefixInfo(t *testing.T) {
	prefix := net.ParseIP("2001:db8::")
	prefixOpt := buildPrefixInfoOption(prefix, 64, true, true, 86400, 14400)
	buf := buildRAFull(64, false, false, 1800, nil, prefixOpt)

	ri := parseRA(buf, "fe80::1", "", 0, "")
	if ri == nil {
		t.Fatal("parseRA returned nil")
	}
	if len(ri.Prefixes) != 1 {
		t.Fatalf("Prefixes = %d, want 1", len(ri.Prefixes))
	}
	p := ri.Prefixes[0]
	if p.Prefix != "2001:db8::/64" {
		t.Errorf("Prefix = %q, want %q", p.Prefix, "2001:db8::/64")
	}
	if !p.OnLink {
		t.Error("OnLink should be true")
	}
	if !p.Autonomous {
		t.Error("Autonomous should be true")
	}
	if p.ValidLifetime != 86400*time.Second {
		t.Errorf("ValidLifetime = %v, want 86400s", p.ValidLifetime)
	}
	if p.PreferredLife != 14400*time.Second {
		t.Errorf("PreferredLife = %v, want 14400s", p.PreferredLife)
	}
}

func TestParseRA_MTU(t *testing.T) {
	mtuOpt := buildMTUOption(9000)
	buf := buildRAFull(64, false, false, 1800, nil, mtuOpt)

	ri := parseRA(buf, "fe80::1", "", 0, "")
	if ri == nil {
		t.Fatal("parseRA returned nil")
	}
	if ri.MTU != 9000 {
		t.Errorf("MTU = %d, want 9000", ri.MTU)
	}
}

func TestParseRA_RDNSS(t *testing.T) {
	dns1 := net.ParseIP("2001:db8::53")
	dns2 := net.ParseIP("2001:db8::54")
	rdnssOpt := buildRDNSSOption(3600, dns1, dns2)
	buf := buildRAFull(64, false, false, 1800, nil, rdnssOpt)

	ri := parseRA(buf, "fe80::1", "", 0, "")
	if ri == nil {
		t.Fatal("parseRA returned nil")
	}
	if len(ri.RDNSS) != 2 {
		t.Fatalf("RDNSS = %d servers, want 2", len(ri.RDNSS))
	}
	if ri.RDNSS[0] != "2001:db8::53" {
		t.Errorf("RDNSS[0] = %q, want %q", ri.RDNSS[0], "2001:db8::53")
	}
	if ri.RDNSS[1] != "2001:db8::54" {
		t.Errorf("RDNSS[1] = %q, want %q", ri.RDNSS[1], "2001:db8::54")
	}
}

func TestParseRA_RouteInfo(t *testing.T) {
	prefix := net.ParseIP("2001:db8:1::")
	routeOpt := buildRouteInfoOption(prefix, 48, 1, 7200) // high preference
	buf := buildRAFull(64, false, false, 1800, nil, routeOpt)

	ri := parseRA(buf, "fe80::1", "", 0, "")
	if ri == nil {
		t.Fatal("parseRA returned nil")
	}
	if len(ri.Routes) != 1 {
		t.Fatalf("Routes = %d, want 1", len(ri.Routes))
	}
	rt := ri.Routes[0]
	if rt.PrefixLen != 48 {
		t.Errorf("PrefixLen = %d, want 48", rt.PrefixLen)
	}
	if rt.Preference != 1 {
		t.Errorf("Preference = %d, want 1 (high)", rt.Preference)
	}
	if rt.Lifetime != 7200*time.Second {
		t.Errorf("Lifetime = %v, want 7200s", rt.Lifetime)
	}
}

func TestParseRA_AllOptions(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x01}
	prefixOpt := buildPrefixInfoOption(net.ParseIP("2001:db8::"), 64, true, true, 86400, 14400)
	mtuOpt := buildMTUOption(1500)
	rdnssOpt := buildRDNSSOption(3600, net.ParseIP("2001:db8::53"))
	routeOpt := buildRouteInfoOption(net.ParseIP("2001:db8:1::"), 48, 0, 3600)

	buf := buildRAFull(64, true, true, 1800, mac, prefixOpt, mtuOpt, rdnssOpt, routeOpt)

	ri := parseRA(buf, "fe80::1", "02:42:ac:11:00:01", 255, "en0")
	if ri == nil {
		t.Fatal("parseRA returned nil")
	}

	if ri.HopLimit != 64 {
		t.Errorf("HopLimit = %d", ri.HopLimit)
	}
	if !ri.Managed || !ri.Other {
		t.Error("M and O flags should be set")
	}
	if ri.Lifetime != 1800*time.Second {
		t.Errorf("Lifetime = %v", ri.Lifetime)
	}
	if len(ri.Prefixes) != 1 {
		t.Errorf("Prefixes = %d", len(ri.Prefixes))
	}
	if ri.MTU != 1500 {
		t.Errorf("MTU = %d", ri.MTU)
	}
	if len(ri.RDNSS) != 1 {
		t.Errorf("RDNSS = %d", len(ri.RDNSS))
	}
	if len(ri.Routes) != 1 {
		t.Errorf("Routes = %d", len(ri.Routes))
	}
}

func TestParseRA_TooShort(t *testing.T) {
	buf := []byte{134, 0, 0, 0} // Only 4 bytes, need 16
	ri := parseRA(buf, "fe80::1", "", 0, "")
	if ri != nil {
		t.Fatal("parseRA should return nil for too-short packet")
	}
}

func TestParseRA_NoOptions(t *testing.T) {
	// Minimal RA: 16 bytes, no options
	buf := make([]byte, 16)
	buf[0] = 134
	buf[4] = 128 // hop limit
	buf[5] = 0xC0 // M + O
	binary.BigEndian.PutUint16(buf[6:8], 600)

	ri := parseRA(buf, "fe80::1", "", 0, "")
	if ri == nil {
		t.Fatal("parseRA returned nil")
	}
	if ri.HopLimit != 128 {
		t.Errorf("HopLimit = %d, want 128", ri.HopLimit)
	}
	if !ri.Managed || !ri.Other {
		t.Error("M and O should be set")
	}
	if ri.Lifetime != 600*time.Second {
		t.Errorf("Lifetime = %v, want 600s", ri.Lifetime)
	}
	if len(ri.Prefixes) != 0 {
		t.Errorf("Prefixes = %d, want 0", len(ri.Prefixes))
	}
}
