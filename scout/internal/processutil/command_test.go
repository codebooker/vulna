package processutil

import (
	"context"
	"strings"
	"testing"
)

func TestScannerCommandContextUsesConfiguredSandbox(t *testing.T) {
	t.Setenv(scannerSandboxHelperEnv, "/test/vulnascout")
	cmd := ScannerCommandContext(context.Background(), "/tmp/job-1", "nmap", "-sT")
	if cmd.Path != "/test/vulnascout" {
		t.Fatalf("path = %q", cmd.Path)
	}
	want := []string{"/test/vulnascout", "scanner-sandbox", "--", "nmap", "-sT"}
	if strings.Join(cmd.Args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v", cmd.Args)
	}
	found := 0
	for _, entry := range cmd.Env {
		if entry == "VULNA_SCANNER_WORKSPACE=/tmp/job-1" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("workspace entries = %d", found)
	}
}
