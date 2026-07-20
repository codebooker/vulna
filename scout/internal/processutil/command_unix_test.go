//go:build unix

package processutil

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCommandContextKillsDescendantProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	cmd := CommandContext(
		ctx,
		"sh",
		"-c",
		`sleep 30 & echo $! > "$1"; wait`,
		"vulna-process-test",
		pidFile,
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	var childPID int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidFile)
		if err == nil {
			childPID, _ = strconv.Atoi(strings.TrimSpace(string(data)))
			if childPID > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID == 0 {
		_ = cmd.Process.Kill()
		t.Fatal("scanner descendant did not start")
	}

	cancel()
	if err := cmd.Wait(); err == nil {
		t.Fatal("cancelled command unexpectedly succeeded")
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(childPID, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("descendant process %d survived context cancellation", childPID)
}
