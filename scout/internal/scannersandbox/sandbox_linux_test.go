//go:build linux

package scannersandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const sandboxTestHelperEnv = "VULNA_SANDBOX_TEST_HELPER"

func TestSandboxHelperProcess(t *testing.T) {
	if os.Getenv(sandboxTestHelperEnv) != "1" {
		return
	}
	separator := -1
	for index, arg := range os.Args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator < 0 {
		os.Exit(2)
	}
	os.Exit(Execute(os.Args[separator:], os.Stdout, os.Stderr))
}

func TestLandlockAllowsWorkspaceAndDeniesScoutState(t *testing.T) {
	workspace := t.TempDir()
	stateDir := t.TempDir()
	secret := filepath.Join(stateDir, "identity.key")
	if err := os.WriteFile(secret, []byte("do-not-read"), 0o600); err != nil {
		t.Fatal(err)
	}

	result := filepath.Join(workspace, "result")
	allowed := sandboxTestCommand(
		t, workspace, "sh", "-c", `printf 'isolated' > "$1"`, "sandbox", result,
	)
	if output, err := allowed.CombinedOutput(); err != nil {
		t.Fatalf("workspace write failed: %v\n%s", err, output)
	}
	data, err := os.ReadFile(result)
	if err != nil || string(data) != "isolated" {
		t.Fatalf("workspace result = %q, %v", data, err)
	}

	denied := sandboxTestCommand(t, workspace, "sh", "-c", `cat "$1"`, "sandbox", secret)
	output, err := denied.CombinedOutput()
	if err == nil {
		t.Fatalf("sandbox read protected state: %s", output)
	}
	if strings.Contains(string(output), "do-not-read") {
		t.Fatalf("sandbox disclosed protected state: %s", output)
	}
}

func sandboxTestCommand(t *testing.T, workspace string, command ...string) *exec.Cmd {
	t.Helper()
	args := []string{"-test.run=^TestSandboxHelperProcess$", "--"}
	args = append(args, command...)
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(),
		sandboxTestHelperEnv+"=1",
		workspaceEnv+"="+workspace,
	)
	return cmd
}
