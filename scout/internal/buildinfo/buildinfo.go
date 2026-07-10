// Package buildinfo exposes version metadata for the VulnaScout binary.
//
// The values are overridable at build time via -ldflags, e.g.:
//
//	go build -ldflags "-X github.com/codebooker/vulna/scout/internal/buildinfo.Commit=$(git rev-parse --short HEAD)"
package buildinfo

// These values are set at build time via -ldflags. The defaults keep local
// builds working without a build system.
var (
	// Version is the semantic version of the agent.
	Version = "0.1.0"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// Date is the build timestamp (RFC3339).
	Date = "unknown"
)
