//go:build unix

package processutil

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"
)

func commandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	// Shell-based scanners such as testssl.sh spawn their own OpenSSL children.
	// Killing only the shell leaves those children probing after the job has
	// ended. Give every scanner its own process group and kill the complete group
	// when the context expires or an operator cancels the job.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	// Do not let inherited descriptors from an unexpected descendant make Wait
	// block forever after cancellation.
	cmd.WaitDelay = 5 * time.Second
	return cmd
}
