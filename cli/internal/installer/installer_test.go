package installer

import (
	"bytes"
	"strings"
	"testing"

	"github.com/codebooker/vulna/cli/internal/config"
	"github.com/codebooker/vulna/cli/internal/deploy"
	"github.com/codebooker/vulna/cli/internal/preflight"
)

func TestInteractiveParsesChoices(t *testing.T) {
	o := config.Defaults("/opt/vulna")
	// answers: install dir (accept default), data dir (accept), mode=public,
	// url, acme email, admin email, update checks = no
	input := "\n\npublic\nvulna.example.com\nops@example.com\nadmin@example.com\nno\n"
	var out bytes.Buffer
	got, err := Interactive(strings.NewReader(input), &out, o)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessMode != config.AccessPublic {
		t.Fatalf("access mode = %q", got.AccessMode)
	}
	if got.URL != "vulna.example.com" || got.ACMEEmail != "ops@example.com" {
		t.Fatalf("url/acme not captured: %+v", got)
	}
	if got.AdminEmail != "admin@example.com" {
		t.Fatalf("admin email = %q", got.AdminEmail)
	}
	if got.UpdateChecks {
		t.Fatal("update checks should be off")
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("interactive result should validate: %v", err)
	}
}

func TestPrintPlanListsServicesPortsCapabilities(t *testing.T) {
	o := config.Defaults("/opt/vulna")
	o.AdminEmail = "admin@example.com"
	_ = o.Normalize()
	plan, err := deploy.PlanInstall(o)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	PrintPlan(&b, plan, o)
	s := b.String()
	for _, want := range []string{"local-scout", "postgres", "443", "capabilit", "0600"} {
		if !strings.Contains(s, want) {
			t.Fatalf("plan output missing %q:\n%s", want, s)
		}
	}
	// A dry-run plan must never print a secret value; only the "[secret, 0600]" tag.
	if strings.Contains(s, "POSTGRES_PASSWORD=") {
		t.Fatal("plan output must not contain secret values")
	}
}

func TestPrintPreflightShowsGuidance(t *testing.T) {
	results := []preflight.Result{
		{Name: "container-runtime", Status: preflight.Fail,
			Problem: "Docker is not installed", Impact: "cannot start", NextStep: "install Docker"},
	}
	var b bytes.Buffer
	PrintPreflight(&b, results)
	s := b.String()
	for _, want := range []string{"problem:", "impact:", "next step:", "1 failure"} {
		if !strings.Contains(s, want) {
			t.Fatalf("preflight output missing %q:\n%s", want, s)
		}
	}
}
