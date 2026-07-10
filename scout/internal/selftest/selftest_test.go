package selftest

import "testing"

func TestRunIncludesRequiredChecks(t *testing.T) {
	checks := Run()
	if len(checks) == 0 {
		t.Fatal("expected at least one check")
	}

	var haveRuntime, haveTemp bool
	for _, c := range checks {
		switch c.Name {
		case "runtime":
			haveRuntime = true
		case "temp-writable":
			haveTemp = true
		}
	}
	if !haveRuntime {
		t.Error("missing runtime check")
	}
	if !haveTemp {
		t.Error("missing temp-writable check")
	}
}

func TestRequiredChecksPass(t *testing.T) {
	checks := Run()
	if !Passed(checks) {
		t.Errorf("expected required checks to pass: %+v", checks)
	}
}

func TestPassedFailsWhenRequiredCheckFails(t *testing.T) {
	checks := []Check{
		{Name: "runtime", OK: true, Required: true},
		{Name: "broken", OK: false, Required: true},
	}
	if Passed(checks) {
		t.Error("expected Passed to be false when a required check fails")
	}
}

func TestPassedIgnoresOptionalChecks(t *testing.T) {
	checks := []Check{
		{Name: "runtime", OK: true, Required: true},
		{Name: "scanner:nmap", OK: false, Required: false},
	}
	if !Passed(checks) {
		t.Error("expected Passed to be true when only optional checks fail")
	}
}
