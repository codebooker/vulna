// Command vulnascout is the Vulna remote assessment appliance (VulnaScout).
//
// Authorized use only: VulnaScout must only assess networks it is explicitly
// permitted to test, as enforced by its signed local policy in later phases.
package main

import (
	"os"

	"github.com/codebooker/vulna/scout/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
