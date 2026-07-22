//go:build !linux

package scannersandbox

import "os/exec"

func applyPlatformSandbox(string) error {
	return unsupportedPlatformError()
}

func protectCurrentProcess() error { return nil }

func normalizedExitCode(exitErr *exec.ExitError) (int, string) {
	code := exitErr.ExitCode()
	if code < 0 {
		return 1, "unknown"
	}
	return code, ""
}
