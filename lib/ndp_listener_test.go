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
