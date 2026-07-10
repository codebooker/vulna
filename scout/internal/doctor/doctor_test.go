package doctor

import (
	"errors"
	"testing"
)

func healthyDeps() Deps {
	return Deps{
		Host:          "vulna.example.com",
		MaxClockSkew:  5,
		ResolveDNS:    func(string) error { return nil },
		DialTLS:       func() error { return nil },
		ServerSkew:    func() (float64, bool, error) { return 1, true, nil },
		Enrolled:      func() (bool, string) { return true, "enrolled" },
		Heartbeat:     func() error { return nil },
		PolicyPresent: func() bool { return true },
		MissingScan:   func() []string { return nil },
		UploadReach:   func() error { return nil },
	}
}

func find(rs []Result, name string) Result {
	for _, r := range rs {
		if r.Name == name {
			return r
		}
	}
	return Result{Name: "MISSING"}
}

func TestAllHealthy(t *testing.T) {
	rs := Run(healthyDeps())
	if Blocking(rs) {
		t.Fatalf("healthy deps should not block: %+v", rs)
	}
}

func TestDNSFailureBlocksWithRemediation(t *testing.T) {
	d := healthyDeps()
	d.ResolveDNS = func(string) error { return errors.New("nxdomain") }
	r := find(Run(d), "dns")
	if r.Status != Fail || r.Remediation == "" {
		t.Fatalf("dns failure must fail with remediation: %+v", r)
	}
}

func TestTLSFailureMentionsCAAndFirewall(t *testing.T) {
	d := healthyDeps()
	d.DialTLS = func() error { return errors.New("x509") }
	r := find(Run(d), "tls")
	if r.Status != Fail {
		t.Fatal("tls should fail")
	}
	if !contains(r.Remediation, "CA") || !contains(r.Remediation, "MTU") {
		t.Fatalf("tls remediation should mention private CA and MTU: %q", r.Remediation)
	}
}

func TestClockSkewFails(t *testing.T) {
	d := healthyDeps()
	d.ServerSkew = func() (float64, bool, error) { return 120, true, nil }
	if find(Run(d), "time").Status != Fail {
		t.Fatal("large skew should fail")
	}
}

func TestNotEnrolledSkipsHeartbeat(t *testing.T) {
	d := healthyDeps()
	d.Enrolled = func() (bool, string) { return false, "not enrolled" }
	rs := Run(d)
	if find(rs, "enrollment").Status != Fail {
		t.Fatal("enrollment should fail")
	}
	if find(rs, "heartbeat").Status != Warn {
		t.Fatal("heartbeat should be skipped (warn) when not enrolled")
	}
}

func TestMissingScannersWarnsNotBlocks(t *testing.T) {
	d := healthyDeps()
	d.MissingScan = func() []string { return []string{"nuclei"} }
	rs := Run(d)
	if Blocking(rs) {
		t.Fatal("missing scanners should warn, not block")
	}
	if find(rs, "scanners").Status != Warn {
		t.Fatal("scanners should warn")
	}
}

func TestNilProbesDoNotPanic(t *testing.T) {
	rs := Run(Deps{Host: "h", MaxClockSkew: 5})
	if len(rs) == 0 {
		t.Fatal("expected results")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
