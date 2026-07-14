// Package discovery turns the discovery stage's Nmap XML into the concrete
// service endpoints later stages should target, so the vulnerability and TLS
// scanners hit the services that were actually found instead of re-scanning the
// original address range.
package discovery

import (
	"encoding/xml"
	"net/netip"
	"strconv"
	"strings"
)

// Endpoint is one open service discovered on a host: a literal IP, a port, and
// enough classification for a scanner to decide how to probe it.
type Endpoint struct {
	IP        string // literal IPv4/IPv6 address
	Port      int
	Transport string // "tcp" or "udp"
	Service   string // Nmap's service name, e.g. "http", "https", "ftp"
	TLS       bool   // service is TLS-wrapped (worth a testssl scan)
	HTTP      bool   // service speaks HTTP (worth a nuclei URL)
}

// Addr renders the endpoint as host:port (IPv6 bracketed), suitable for a
// testssl-style target.
func (e Endpoint) Addr() string {
	return netip.AddrPortFrom(mustAddr(e.IP), uint16(e.Port)).String()
}

// URL renders the endpoint as an http(s):// URL for an HTTP service, choosing
// the scheme from whether the service is TLS-wrapped.
func (e Endpoint) URL() string {
	scheme := "http"
	if e.TLS {
		scheme = "https"
	}
	return scheme + "://" + e.Addr()
}

func mustAddr(ip string) netip.Addr {
	a, _ := netip.ParseAddr(ip)
	return a
}

// nmap XML (only the fields we need).
type xmlRun struct {
	Hosts []xmlHost `xml:"host"`
}

type xmlHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr string `xml:"addr,attr"`
		Type string `xml:"addrtype,attr"`
	} `xml:"address"`
	Ports struct {
		Ports []xmlPort `xml:"port"`
	} `xml:"ports"`
}

type xmlPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name   string `xml:"name,attr"`
		Tunnel string `xml:"tunnel,attr"`
	} `xml:"service"`
}

// liveStates mirrors the backend parser: ports Nmap reports open (or
// open|filtered) are the ones worth handing to a scanner.
var liveStates = map[string]bool{"open": true, "open|filtered": true}

// ParseEndpoints extracts the open service endpoints from one Nmap XML document
// (an <nmaprun> with <host> children — the shape the Scout streams per host).
// Malformed input yields no endpoints rather than an error: a discovery batch we
// can't read must not take down the stages that follow.
func ParseEndpoints(nmapXML []byte) []Endpoint {
	var run xmlRun
	if err := xml.Unmarshal(nmapXML, &run); err != nil {
		return nil
	}
	var out []Endpoint
	for _, h := range run.Hosts {
		if h.Status.State != "" && h.Status.State != "up" {
			continue
		}
		ip := hostIP(h)
		if ip == "" {
			continue
		}
		for _, p := range h.Ports.Ports {
			if !liveStates[p.State.State] && p.State.State != "" {
				continue
			}
			port, err := strconv.Atoi(p.PortID)
			if err != nil || port <= 0 || port > 65535 {
				continue
			}
			transport := strings.ToLower(p.Protocol)
			if transport == "" {
				transport = "tcp"
			}
			name := strings.ToLower(p.Service.Name)
			out = append(out, Endpoint{
				IP:        ip,
				Port:      port,
				Transport: transport,
				Service:   name,
				TLS:       isTLS(name, p.Service.Tunnel, port),
				HTTP:      isHTTP(name, port),
			})
		}
	}
	return out
}

// hostIP returns the first literal IPv4/IPv6 address of a host.
func hostIP(h xmlHost) string {
	for _, a := range h.Addresses {
		if a.Type == "ipv4" || a.Type == "ipv6" {
			if _, err := netip.ParseAddr(a.Addr); err == nil {
				return a.Addr
			}
		}
	}
	return ""
}

// tlsPorts / httpPorts are well-known fallbacks for when -sV didn't classify the
// service — better to probe a likely TLS/HTTP port than to skip it.
var tlsPorts = map[int]bool{
	443: true, 465: true, 563: true, 585: true, 636: true, 853: true, 989: true,
	990: true, 993: true, 995: true, 4433: true, 4443: true, 5061: true, 8443: true,
	9443: true, 10443: true,
}

var httpPorts = map[int]bool{
	80: true, 280: true, 591: true, 593: true, 981: true, 1311: true, 3000: true,
	5000: true, 8000: true, 8008: true, 8080: true, 8081: true, 8088: true, 8888: true,
}

func isTLS(name, tunnel string, port int) bool {
	if strings.EqualFold(tunnel, "ssl") {
		return true
	}
	if strings.Contains(name, "https") || strings.Contains(name, "ssl") || strings.Contains(name, "tls") {
		return true
	}
	return tlsPorts[port]
}

func isHTTP(name string, port int) bool {
	if strings.Contains(name, "http") { // http, https, http-proxy, http-alt, ...
		return true
	}
	return httpPorts[port]
}
