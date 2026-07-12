// Command vulnarelay is the scanner-free VulnaRelay WireGuard endpoint agent.
package main

import (
	"os"

	"github.com/codebooker/vulna/scout/internal/relayagent"
)

func main() {
	os.Exit(relayagent.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
