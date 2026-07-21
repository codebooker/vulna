// Package processutil starts scanner commands with cancellation semantics that
// apply to the complete subprocess tree, not only the immediate executable.
package processutil

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

const scannerSandboxHelperEnv = "VULNA_SCANNER_SANDBOX_HELPER"

// CommandContext is exec.CommandContext with platform-specific process-tree
// cleanup. Scanner adapters must use it for every external tool they launch.
func CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	return commandContext(ctx, name, args...)
}

// ScannerCommandContext starts an external scanner inside the configured
// filesystem sandbox. Development builds may leave the helper unset; supported
// deployment images and systemd units set it to the vulnascout binary itself.
func ScannerCommandContext(
	ctx context.Context, workspace, name string, args ...string,
) *exec.Cmd {
	helper := strings.TrimSpace(os.Getenv(scannerSandboxHelperEnv))
	if helper == "" {
		return commandContext(ctx, name, args...)
	}
	helperArgs := make([]string, 0, len(args)+3)
	helperArgs = append(helperArgs, "scanner-sandbox", "--", name)
	helperArgs = append(helperArgs, args...)
	cmd := commandContext(ctx, helper, helperArgs...)
	cmd.Env = replaceEnvironment(os.Environ(), "VULNA_SCANNER_WORKSPACE", workspace)
	return cmd
}

func replaceEnvironment(environment []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+value)
}
