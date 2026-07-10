// Package selftest implements the VulnaScout `self-test` diagnostics.
//
// Phase 0 self-tests are intentionally read-only and non-destructive: they
// verify the runtime environment and report which scanner tools are available
// on PATH. They never contact the network or execute a scan.
package selftest

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// Check is the result of a single diagnostic.
type Check struct {
	Name     string
	OK       bool
	Required bool
	Detail   string
}

// scannerTools are the scanner executables VulnaScout can drive. In Phase 0
// their presence is informational only — none are required to pass self-test.
var scannerTools = []struct {
	name string
	bins []string
}{
	{"nmap", []string{"nmap"}},
	{"nuclei", []string{"nuclei"}},
	{"zap", []string{"zap.sh", "zaproxy"}},
	{"testssl", []string{"testssl.sh", "testssl"}},
}

// Run executes all self-test checks and returns their results.
func Run() []Check {
	checks := []Check{runtimeCheck(), tempWritableCheck()}
	for _, tool := range scannerTools {
		checks = append(checks, scannerCheck(tool.name, tool.bins))
	}
	return checks
}

// Passed reports whether all required checks succeeded.
func Passed(checks []Check) bool {
	for _, c := range checks {
		if c.Required && !c.OK {
			return false
		}
	}
	return true
}

func runtimeCheck() Check {
	return Check{
		Name:     "runtime",
		OK:       true,
		Required: true,
		Detail:   fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH),
	}
}

func tempWritableCheck() Check {
	f, err := os.CreateTemp("", "vulnascout-selftest-*")
	if err != nil {
		return Check{Name: "temp-writable", OK: false, Required: true, Detail: err.Error()}
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return Check{Name: "temp-writable", OK: true, Required: true, Detail: os.TempDir()}
}

func scannerCheck(name string, bins []string) Check {
	for _, bin := range bins {
		if path, err := exec.LookPath(bin); err == nil {
			return Check{Name: "scanner:" + name, OK: true, Required: false, Detail: path}
		}
	}
	return Check{Name: "scanner:" + name, OK: false, Required: false, Detail: "not found on PATH"}
}
