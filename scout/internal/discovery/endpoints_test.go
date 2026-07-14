package discovery

import "testing"

// A minimal but realistic per-host Nmap batch, the shape the Scout streams:
// an <nmaprun> wrapping one <host>. Covers a plain HTTP port, a tunnel=ssl HTTPS
// port on a non-standard port, an FTP port, a closed port (ignored), and a
// down host (ignored).
const sampleXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="8443"><state state="open"/><service name="http" tunnel="ssl"/></port>
      <port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/></port>
      <port protocol="tcp" portid="9"><state state="closed"/><service name="discard"/></port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.6" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/></port></ports>
  </host>
</nmaprun>`

func find(eps []Endpoint, port int) (Endpoint, bool) {
	for _, e := range eps {
		if e.Port == port {
			return e, true
		}
	}
	return Endpoint{}, false
}

func TestParseEndpoints(t *testing.T) {
	eps := ParseEndpoints([]byte(sampleXML))
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints (closed port + down host dropped), got %d: %+v", len(eps), eps)
	}

	http80, ok := find(eps, 80)
	if !ok || !http80.HTTP || http80.TLS || http80.IP != "10.0.0.5" {
		t.Errorf("port 80 should be plain HTTP on 10.0.0.5: %+v", http80)
	}
	if http80.URL() != "http://10.0.0.5:80" {
		t.Errorf("port 80 URL = %q", http80.URL())
	}

	https, ok := find(eps, 8443)
	if !ok || !https.HTTP || !https.TLS {
		t.Errorf("port 8443 (tunnel=ssl) should be HTTP+TLS: %+v", https)
	}
	if https.URL() != "https://10.0.0.5:8443" {
		t.Errorf("tunnel=ssl endpoint should be an https URL, got %q", https.URL())
	}
	if https.Addr() != "10.0.0.5:8443" {
		t.Errorf("Addr = %q", https.Addr())
	}

	ftp, ok := find(eps, 21)
	if !ok || ftp.HTTP || ftp.TLS {
		t.Errorf("port 21 ftp should be neither HTTP nor TLS: %+v", ftp)
	}
}

func TestParseEndpointsWellKnownPortFallback(t *testing.T) {
	// -sV left the service unnamed; classification falls back to the port number.
	xml := `<nmaprun><host><status state="up"/><address addr="10.1.1.9" addrtype="ipv4"/>` +
		`<ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>`
	eps := ParseEndpoints([]byte(xml))
	if len(eps) != 1 || !eps[0].TLS {
		t.Fatalf("bare 443 should be classified TLS by port fallback: %+v", eps)
	}
}

func TestParseEndpointsBadInput(t *testing.T) {
	for _, in := range []string{"", "not xml", "<nmaprun><host></host></nmaprun>"} {
		if eps := ParseEndpoints([]byte(in)); len(eps) != 0 {
			t.Errorf("ParseEndpoints(%q) = %+v, want none", in, eps)
		}
	}
}
