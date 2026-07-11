// Package buildinfo exposes version metadata for the vulna installer CLI.
//
// The values are overridable at build time via -ldflags, e.g.:
//
//	go build -ldflags "-X github.com/codebooker/vulna/cli/internal/buildinfo.Commit=$(git rev-parse --short HEAD)"
package buildinfo

// These values are set at build time via -ldflags. The defaults keep local
// builds working without a build system.
var (
	// Version is the semantic version of the installer CLI. The default is "dev"
	// (NOT a real-looking release like "0.1.0"): an un-injected build must pin the
	// deployment to the build-from-source path (VULNA_VERSION=dev) rather than
	// request a published image tag that was never built. Release builds inject the
	// real version via -ldflags (see .github/workflows).
	Version = "dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// Date is the build timestamp (RFC3339).
	Date = "unknown"
)
