package lib

import (
	"net"
	"testing"

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
