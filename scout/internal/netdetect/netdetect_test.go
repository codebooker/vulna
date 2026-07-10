package netdetect

import (
	"net"
	"reflect"
	"testing"
)

func cidr(t *testing.T, s string) *net.IPNet {
	t.Helper()
	// ParseCIDR returns the host IP plus the network; interface addresses carry
	// the host IP with the network mask, which is what we simulate here.
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return &net.IPNet{IP: ip, Mask: ipnet.Mask}
}

func TestCandidatesFromAddrs(t *testing.T) {
	addrs := []net.Addr{
		cidr(t, "192.168.1.50/24"), // private -> 192.168.1.0/24
		cidr(t, "10.20.0.5/16"),    // private -> 10.20.0.0/16
		cidr(t, "192.168.1.51/24"), // duplicate network
		cidr(t, "8.8.8.8/24"),      // public -> excluded
		cidr(t, "169.254.1.1/16"),  // link-local -> excluded (not IsPrivate)
	}
	got := candidatesFromAddrs(addrs)
	want := []string{"10.20.0.0/16", "192.168.1.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCandidatesFromAddrsEmpty(t *testing.T) {
	if got := candidatesFromAddrs(nil); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestPrivateCandidatesDoesNotPanic(t *testing.T) {
	// Runs against the host's real interfaces; must never panic and must only
	// return private networks.
	for _, c := range PrivateCandidates() {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("invalid CIDR %q: %v", c, err)
		}
		if !n.IP.IsPrivate() {
			t.Fatalf("non-private candidate reported: %s", c)
		}
	}
}
