package relayagent

import "testing"

func TestParseRouteInterface(t *testing.T) {
	got, err := ParseRouteInterface("192.168.50.2 dev vulna-lan src 192.168.50.1 uid 0\n")
	if err != nil || got != "vulna-lan" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestValidateConfigRejectsIPv6AndMalformedScope(t *testing.T) {
	base := relayConfig{
		Active: true, Endpoint: "example.com:51820", ServerPublicKey: "key",
		ServerAddress: "10.254.0.1/24", TunnelAddress: "10.254.0.2/32",
	}
	base.ApprovedCIDRs = []string{"10.0.0.0/8"}
	if err := validateConfig(base); err != nil {
		t.Fatal(err)
	}
	base.ApprovedCIDRs = []string{"2001:db8::/64"}
	if err := validateConfig(base); err == nil {
		t.Fatal("IPv6 relay scope must be rejected until IPv6 forwarding/NAT is implemented")
	}
}
