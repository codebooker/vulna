package main

import (
	"encoding/json"
	"flag"
	"io"
	"path/filepath"

	"github.com/codebooker/vulna/cli/internal/installer"
	"github.com/codebooker/vulna/cli/internal/preflight"
)

// cmdDoctor diagnoses the host environment (a superset of preflight) and emits a
// human-readable report or, with --json, machine-readable output for automation.
// The web System Health page provides the full multi-component view; this covers
// the host the operator is standing on.
func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "deployment directory (default: detected)")
	dataDir := fs.String("data-dir", "", "data directory to check")
	asJSON := fs.Bool("json", false, "emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	base := *dir
	if base == "" {
		if src := detectSource("."); src != "" {
			base = src
		} else {
			base, _ = filepath.Abs(".")
		}
	}
	dd := *dataDir
	if dd == "" {
		dd = filepath.Join(base, "data")
	}

	results := preflight.Run(preflight.RealEnv(), preflight.DefaultParams(base, dd))

	if *asJSON {
		okN, warnN, failN := preflight.Counts(results)
		payload := map[string]any{
			"summary": map[string]int{"ok": okN, "warn": warnN, "fail": failN},
			"checks":  results,
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(payload)
	} else {
		installer.PrintPreflight(stdout, results)
	}
	if preflight.Blocking(results) {
		return 1
	}
	return 0
}
