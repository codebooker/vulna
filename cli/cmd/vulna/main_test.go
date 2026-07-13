package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"

	"github.com/codebooker/vulna/cli/internal/config"
)

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut); code != 0 {
		t.Fatalf("version exit = %d", code)
	}
	if !strings.HasPrefix(out.String(), "vulna ") {
		t.Fatalf("unexpected version output: %q", out.String())
	}
}

func TestHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"help"}, &out, &errOut); code != 0 {
		t.Fatalf("help exit = %d", code)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Fatalf("help missing usage: %q", out.String())
	}
}

func TestNoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, &out, &errOut); code != 2 {
		t.Fatalf("no-args exit = %d, want 2", code)
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"frobnicate"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("unknown exit = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "unknown command") {
		t.Fatalf("expected unknown-command message, got %q", errOut.String())
	}
}

func TestPreflightDoesNotPanic(t *testing.T) {
	// preflight runs real probes; it must return a valid exit code (0 or 1),
	// never panic, regardless of the host.
	var out, errOut bytes.Buffer
	code := cmdPreflight([]string{"--dir", t.TempDir()}, &out, &errOut)
	if code != 0 && code != 1 {
		t.Fatalf("preflight exit = %d, want 0 or 1", code)
	}
	if !strings.Contains(out.String(), "Preflight checks:") {
		t.Fatalf("preflight missing header: %q", out.String())
	}
}

func TestDeploymentProfileFlagOverridesDefault(t *testing.T) {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	f := bindInstallFlags(fs)
	if err := fs.Parse([]string{
		"--deployment-profile", "enterprise",
		"--admin-email", "admin@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	o, err := resolveOptions(f, fs, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if o.DeploymentProfile != config.DeploymentEnterprise {
		t.Fatalf("deployment profile = %q", o.DeploymentProfile)
	}
}
