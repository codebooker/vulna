// Package processutil starts scanner commands with cancellation semantics that
// apply to the complete subprocess tree, not only the immediate executable.
package processutil

import (
	"context"
	"os/exec"
)

// CommandContext is exec.CommandContext with platform-specific process-tree
// cleanup. Scanner adapters must use it for every external tool they launch.
func CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	return commandContext(ctx, name, args...)
}
