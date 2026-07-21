//go:build !linux

package scannersandbox

func applyPlatformSandbox(string) error {
	return unsupportedPlatformError()
}

func protectCurrentProcess() error { return nil }
