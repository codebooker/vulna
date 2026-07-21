package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Vector produced by the orchestrator's Python signer (see test_signing.py /
// dash/backend/app/services/signing.py). Verifying it here proves the Go and
// Python canonicalizations are byte-identical.
const (
	vectorPubKeyB64 = "qeuFHUglCrQqa3muPqvIxaFBa42B8ml3sOFuRAwU06g="
	vectorDoc       = `{"policy_version": 7, "probe_id": "11111111-1111-1111-1111-111111111111", "site_id": "22222222-2222-2222-2222-222222222222", "approved_cidrs": ["10.20.0.0/24", "192.168.5.0/24"], "denied_cidrs": ["10.20.0.128/25"], "allow_public_addresses": false, "allowed_modes": ["vulnerability_assessment"], "allowed_plugins": ["nmap"], "limits": {"max_hosts": 256, "max_parallel_hosts": 8, "max_packets_per_second": 1000, "max_duration_seconds": 10800}, "signature": "G2aRixi5QVnCS8RSmxhdJLjknWQH3LrfI66TLI2bb3Ov6e2BmKVL7zpUsli50PS+4td2qnaMzKrkoK4UWbu6DA=="}`
)

func vectorKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, err := ParsePublicKey(vectorPubKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestParseCrossLanguageVector(t *testing.T) {
	p, err := Parse([]byte(vectorDoc), vectorKey(t))
	if err != nil {
		t.Fatalf("cross-language verification failed: %v", err)
	}
	if p.PolicyVersion != 7 {
		t.Errorf("PolicyVersion = %d", p.PolicyVersion)
	}
	if len(p.ApprovedCIDRs) != 2 {
		t.Errorf("ApprovedCIDRs = %v", p.ApprovedCIDRs)
	}
	if p.Limits.MaxPacketsPerSecond != 1000 {
		t.Errorf("MaxPacketsPerSecond = %d", p.Limits.MaxPacketsPerSecond)
	}
}

func TestTamperedDocumentFailsVerification(t *testing.T) {
	tampered := strings.Replace(vectorDoc, "10.20.0.0/24", "10.99.0.0/24", 1)
	if _, err := Parse([]byte(tampered), vectorKey(t)); err == nil {
		t.Fatal("expected verification to fail on a tampered document")
	}
}

func TestAllowsTarget(t *testing.T) {
	p, err := Parse([]byte(vectorDoc), vectorKey(t))
	if err != nil {
		t.Fatal(err)
	}
	// In approved 10.20.0.0/24, below the denied /25 boundary.
	if err := p.AllowsTarget("10.20.0.5"); err != nil {
		t.Errorf("10.20.0.5 should be allowed: %v", err)
	}
	if err := p.AllowsTarget("192.168.5.0/24"); err != nil {
		t.Errorf("192.168.5.0/24 should be allowed: %v", err)
	}
	// In approved range but within the denied 10.20.0.128/25.
	if err := p.AllowsTarget("10.20.0.200"); err == nil {
		t.Error("10.20.0.200 should be denied (denied range)")
	}
	// Outside approved scope.
	if err := p.AllowsTarget("10.99.0.1"); err == nil {
		t.Error("10.99.0.1 should be rejected (out of scope)")
	}
	// Public address, public scanning disabled.
	if err := p.AllowsTarget("8.8.8.8"); err == nil {
		t.Error("8.8.8.8 should be rejected (public)")
	}
	// A CIDR target wider than any approved prefix is rejected.
	if err := p.AllowsTarget("10.20.0.0/16"); err == nil {
		t.Error("10.20.0.0/16 should be rejected (wider than approved /24)")
	}
}

func TestAllowsMode(t *testing.T) {
	p, err := Parse([]byte(vectorDoc), vectorKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AllowsMode("vulnerability_assessment"); err != nil {
		t.Errorf("mode should be allowed: %v", err)
	}
	if err := p.AllowsMode("full_spectrum"); err == nil {
		t.Error("full_spectrum should not be allowed")
	}
}

func TestAllowsWorkflowGatesActiveZAPSeparatelyFromPassive(t *testing.T) {
	passive := []map[string]any{{
		"stage": "web", "plugin": "zap",
		"config": map[string]any{"profile": "passive_baseline"},
	}}
	active := []map[string]any{{
		"stage": "web", "plugin": "zap",
		"config": map[string]any{"profile": "limited_active"},
	}}
	p := &Policy{AllowedPlugins: []string{"zap"}}
	if err := p.AllowsWorkflow(passive); err != nil {
		t.Fatalf("passive ZAP should be allowed by the standard plugin policy: %v", err)
	}
	if err := p.AllowsWorkflow(active); err == nil {
		t.Fatal("active ZAP must fail closed without the signed active-web opt-in")
	}
	p.ActiveWebScansAllowed = true
	if err := p.AllowsWorkflow(active); err != nil {
		t.Fatalf("active ZAP should be allowed after signed opt-in: %v", err)
	}
}

func TestGoNativeSignRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"policy_version":         json.Number("1"),
		"approved_cidrs":         []any{"10.0.0.0/8"},
		"denied_cidrs":           []any{},
		"allow_public_addresses": false,
		"allowed_modes":          []any{"vulnerability_assessment"},
		"allowed_plugins":        []any{"nmap"},
		"limits": map[string]any{
			"max_hosts": json.Number("10"), "max_parallel_hosts": json.Number("2"),
			"max_packets_per_second": json.Number("100"), "max_duration_seconds": json.Number("60"),
		},
	}
	msg, err := canonicalBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	payload["signature"] = sig
	doc, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(doc, pub)
	if err != nil {
		t.Fatalf("round-trip verification failed: %v", err)
	}
	if err := p.AllowsTarget("10.1.2.3"); err != nil {
		t.Errorf("10.1.2.3 should be allowed: %v", err)
	}
}

func TestUnsignedDocumentRejected(t *testing.T) {
	if _, err := Parse([]byte(`{"policy_version":1}`), vectorKey(t)); err == nil {
		t.Error("expected error for unsigned document")
	}
}
