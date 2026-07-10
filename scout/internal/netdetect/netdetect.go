// Package netdetect derives advisory private network candidates from the host's
// own interfaces. These are only *suggestions* for the first-run wizard — the
// orchestrator never approves or scans a range without explicit operator action.
// Only RFC1918 private IPv4 networks are reported; loopback, link-local, and
// public addresses are excluded so the wizard can never suggest scanning the
// internet.
package netdetect

import (
	"net"
	"sort"
)

// PrivateCandidates returns the deduplicated private IPv4 networks the host is
// attached to, in CIDR form (e.g. "192.168.1.0/24").
func PrivateCandidates() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var addrs []net.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		a, err := iface.Addrs()
		if err != nil {
			continue
		}
		addrs = append(addrs, a...)
	}
	return candidatesFromAddrs(addrs)
}

// candidatesFromAddrs is the pure core: it maps interface addresses to private
// IPv4 network CIDRs, deduplicated and sorted. Split out so it is testable
// without depending on the host's real interfaces.
func candidatesFromAddrs(addrs []net.Addr) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil || !ip4.IsPrivate() {
			continue
		}
		network := &net.IPNet{IP: ip4.Mask(ipnet.Mask), Mask: ipnet.Mask}
		cidr := network.String()
		if _, dup := seen[cidr]; dup {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	sort.Strings(out)
	return out
}
