package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestExecuteVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute([]string{"version"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(out.String(), "vulnascout") {
		t.Errorf("version output missing program name: %q", out.String())
	}
}

func TestExecuteSelfTest(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute([]string{"self-test"}, &out, &errOut)
	// Required checks (runtime, temp-writable) should pass in CI.
	if code != 0 {
		t.Fatalf("expected self-test to pass with exit 0, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "self-test: PASS") {
		t.Errorf("self-test output missing PASS: %q", out.String())
	}
}

func TestExecuteNoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute(nil, &out, &errOut)
	if code != 2 {
		t.Errorf("expected exit code 2 for no args, got %d", code)
	}
	if !strings.Contains(errOut.String(), "Usage:") {
		t.Errorf("expected usage on stderr, got %q", errOut.String())
	}
}

func TestExecuteUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute([]string{"frobnicate"}, &out, &errOut)
	if code != 2 {
		t.Errorf("expected exit code 2 for unknown command, got %d", code)
	}
	if !strings.Contains(errOut.String(), "unknown command") {
		t.Errorf("expected unknown-command message, got %q", errOut.String())
	}
}

func TestExecuteHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute([]string{"help"}, &out, &errOut)
	if code != 0 {
		t.Errorf("expected exit code 0 for help, got %d", code)
	}
	if !strings.Contains(out.String(), "Commands:") {
		t.Errorf("expected help text, got %q", out.String())
	}
}
