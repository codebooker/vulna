// Command vulnascout is the Vulna remote assessment appliance (VulnaScout).
//
// Authorized use only: VulnaScout must only assess networks it is explicitly
// permitted to test, as enforced by its signed local policy in later phases.
package main

import (
	"fmt"
	"os"

	"github.com/codebooker/vulna/scout/internal/cli"
	"github.com/codebooker/vulna/scout/internal/scannersandbox"
)

func main() {
	if err := scannersandbox.ProtectCurrentProcess(); err != nil {
		fmt.Fprintln(os.Stderr, "vulnascout: process hardening:", err)
		os.Exit(1)
	}
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
