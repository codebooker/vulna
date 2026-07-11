// Command vulna is the host-side installation and administration CLI for the
// Vulna single-host deployment. It runs environment preflight, generates strong
// secrets and a restrictive configuration, materializes the deployment
// idempotently, and can start, dry-run, or cleanly uninstall the stack.
//
// Authorized use only. See SECURITY.md and docs/authorized-use.md.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/codebooker/vulna/cli/internal/buildinfo"
	"github.com/codebooker/vulna/cli/internal/config"
	"github.com/codebooker/vulna/cli/internal/deploy"
	"github.com/codebooker/vulna/cli/internal/installer"
	"github.com/codebooker/vulna/cli/internal/preflight"
)

const usage = `vulna — Vulna single-host installer and administration CLI

Usage:
  vulna <command> [flags]

Commands:
  install        Preflight, generate config/secrets, and materialize the deployment
  preflight      Run environment checks only (no changes)
  uninstall      Stop the stack and remove generated files (data is preserved)
  update check   Check for a newer signed release on a channel (no changes)
  update         Pre-update checks + backup, then print the apply steps
  update status  Show current version and the recorded rollback point
  rollback       Roll back to the prior known-good version (restore from backup)
  backup ...     create | list | verify | restore | prune | recovery-sheet
  version        Print version and build information
  help           Show this help message

Run "vulna <command> -h" for command-specific flags.
Authorized use only. See SECURITY.md and docs/authorized-use.md.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "vulna %s (commit %s, built %s)\n",
			buildinfo.Version, buildinfo.Commit, buildinfo.Date)
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	case "preflight":
		return cmdPreflight(args[1:], stdout, stderr)
	case "install":
		return cmdInstall(args[1:], stdout, stderr)
	case "uninstall":
		return cmdUninstall(args[1:], stdout, stderr)
	case "update":
		return cmdUpdate(args[1:], stdout, stderr)
	case "rollback":
		return cmdRollback(args[1:], stdout, stderr)
	case "backup":
		return cmdBackup(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %q\n\n%s", args[0], usage)
		return 2
	}
}

// detectSource returns the nearest ancestor of start that contains the Compose
// files, or "" if none is found.
func detectSource(start string) string {
	dir, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	for {
		if deploy.SourceHasCompose(dir) == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

type installFlags struct {
	dir, dataDir, configDir       string
	accessMode, url, adminEmail   string
	acmeEmail, answers            string
	updateChecks                  bool
	nonInteractive, dryRun, start bool
	force                         bool
	saveAnswers                   string
}

func bindInstallFlags(fs *flag.FlagSet) *installFlags {
	f := &installFlags{}
	fs.StringVar(&f.dir, "dir", "", "deployment directory (default: detected Vulna directory)")
	fs.StringVar(&f.dataDir, "data-dir", "", "data directory (default: <dir>/data)")
	fs.StringVar(&f.configDir, "config-dir", "", "config directory (default: <dir>/config)")
	fs.StringVar(&f.accessMode, "access-mode", "", "access mode: localhost | lan | public")
	fs.StringVar(&f.url, "url", "", "hostname or URL (for lan/public)")
	fs.StringVar(&f.adminEmail, "admin-email", "", "initial administrator email")
	fs.StringVar(&f.acmeEmail, "acme-email", "", "email for automatic TLS (public mode)")
	fs.StringVar(&f.answers, "answers", "", "versioned answer file for non-interactive install")
	fs.BoolVar(&f.updateChecks, "update-checks", true, "enable update checks")
	fs.BoolVar(&f.nonInteractive, "non-interactive", false, "do not prompt (requires --answers or full flags)")
	fs.BoolVar(&f.dryRun, "dry-run", false, "report intended changes without making them")
	fs.BoolVar(&f.start, "start", false, "start the stack after install (docker compose up -d)")
	fs.BoolVar(&f.force, "force", false, "proceed despite preflight warnings (failures still block)")
	fs.StringVar(&f.saveAnswers, "save-answers", "", "write the effective answer file to this path")
	return f
}

// resolveOptions builds the effective Options from defaults, an optional answer
// file, and explicit flag overrides.
func resolveOptions(f *installFlags, fs *flag.FlagSet, source string) (config.Options, error) {
	o := config.Defaults(source)
	if f.answers != "" {
		loaded, err := config.Load(f.answers)
		if err != nil {
			return o, err
		}
		o = loaded
	}
	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	if set["dir"] {
		o.InstallDir = f.dir
	}
	if set["data-dir"] {
		o.DataDir = f.dataDir
	}
	if set["config-dir"] {
		o.ConfigDir = f.configDir
	}
	if set["access-mode"] {
		o.AccessMode = config.AccessMode(f.accessMode)
	}
	if set["url"] {
		o.URL = f.url
	}
	if set["admin-email"] {
		o.AdminEmail = f.adminEmail
	}
	if set["acme-email"] {
		o.ACMEEmail = f.acmeEmail
	}
	if set["update-checks"] {
		o.UpdateChecks = f.updateChecks
	}
	if o.DataDir == "" {
		o.DataDir = filepath.Join(o.InstallDir, "data")
	}
	if o.ConfigDir == "" {
		o.ConfigDir = filepath.Join(o.InstallDir, "config")
	}
	return o, nil
}

func cmdPreflight(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "deployment directory (default: current)")
	dataDir := fs.String("data-dir", "", "data directory to check")
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
	installer.PrintPreflight(stdout, results)
	if preflight.Blocking(results) {
		return 1
	}
	return 0
}

func cmdInstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := bindInstallFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	source := f.dir
	if source == "" {
		source = detectSource(".")
	}
	if source == "" {
		fmt.Fprintln(stderr, "install: could not find the Vulna deployment files "+
			"(docker-compose.yml + docker-compose.single-host.yml).")
		fmt.Fprintln(stderr, "         Run from a Vulna directory or pass --dir. See docs/installation/.")
		return 2
	}
	if err := deploy.SourceHasCompose(source); err != nil {
		fmt.Fprintf(stderr, "install: %v\n", err)
		return 2
	}

	o, err := resolveOptions(f, fs, source)
	if err != nil {
		fmt.Fprintf(stderr, "install: %v\n", err)
		return 2
	}

	// Interactive unless an answer file or --non-interactive was supplied.
	if f.answers == "" && !f.nonInteractive {
		o, err = installer.Interactive(os.Stdin, stdout, o)
		if err != nil {
			fmt.Fprintf(stderr, "install: %v\n", err)
			return 2
		}
	}
	if err := o.Normalize(); err != nil {
		fmt.Fprintf(stderr, "install: %v\n", err)
		return 2
	}
	if err := o.Validate(); err != nil {
		fmt.Fprintf(stderr, "install: %v\n", err)
		return 2
	}

	// Preflight before any change. A dry run still reports and previews the plan
	// (it changes nothing), so only a real install is blocked by problems.
	results := preflight.Run(preflight.RealEnv(), preflight.DefaultParams(o.InstallDir, o.DataDir))
	installer.PrintPreflight(stdout, results)
	if !f.dryRun {
		if preflight.Blocking(results) {
			fmt.Fprintln(stderr, "install: preflight found blocking problems; resolve them and re-run.")
			return 1
		}
		if _, warnN, _ := preflight.Counts(results); warnN > 0 && !f.force {
			fmt.Fprintln(stderr, "install: preflight raised warnings; re-run with --force to proceed anyway.")
			return 1
		}
	}

	plan, err := deploy.PlanInstall(o)
	if err != nil {
		fmt.Fprintf(stderr, "install: %v\n", err)
		return 1
	}
	installer.PrintPlan(stdout, plan, o)

	if f.dryRun {
		fmt.Fprintln(stdout, "\nDry run: no changes were made.")
		return 0
	}

	if err := deploy.Apply(o); err != nil {
		fmt.Fprintf(stderr, "install: %v\n", err)
		return 1
	}
	if f.saveAnswers != "" {
		if err := config.Save(f.saveAnswers, o); err != nil {
			fmt.Fprintf(stderr, "install: write answers: %v\n", err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "\nInstalled. Config: %s (0600). Admin email: %s\n", o.InstallDir, o.AdminEmail)
	fmt.Fprintln(stdout, "The initial admin password was generated into the 0600 .env file and not printed.")

	if f.start {
		fmt.Fprintln(stdout, "Starting the stack ...")
		if err := deploy.Up(o.InstallDir, stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "install: docker compose up failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "Started. Open the dashboard once containers report healthy.")
	} else {
		fmt.Fprintf(stdout, "To start: docker compose %s --env-file %s up -d\n",
			composeFlags(o.InstallDir), filepath.Join(o.InstallDir, deploy.EnvFile))
	}
	return 0
}

func composeFlags(dir string) string {
	return fmt.Sprintf("-f %s -f %s",
		filepath.Join(dir, "docker-compose.yml"),
		filepath.Join(dir, "docker-compose.single-host.yml"))
}

func cmdUninstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "deployment directory (default: detected)")
	purge := fs.String("purge", "", "ALSO delete persistent data volumes; must equal the data directory to confirm")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	source := *dir
	if source == "" {
		source = detectSource(".")
	}
	if source == "" {
		fmt.Fprintln(stderr, "uninstall: could not find the deployment; pass --dir.")
		return 2
	}

	// Load the recorded data dir to validate a purge confirmation.
	rec, _ := config.Load(filepath.Join(source, deploy.RecordFile))

	if *purge != "" {
		if rec.DataDir == "" {
			fmt.Fprintln(stderr, "uninstall: no install record found; cannot confirm the data path for purge.")
			return 2
		}
		absPurge, _ := filepath.Abs(*purge)
		if absPurge != rec.DataDir {
			fmt.Fprintf(stderr, "uninstall: --purge must exactly name the data directory to confirm.\n"+
				"           expected: %s\n", rec.DataDir)
			return 2
		}
	}

	fmt.Fprintln(stdout, "Stopping the stack (data volumes preserved) ...")
	if err := deploy.Down(source, *purge != "", stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "uninstall: docker compose down failed: %v\n", err)
		// continue to remove generated files regardless
	}
	removed, err := deploy.RemoveGeneratedFiles(source)
	if err != nil {
		fmt.Fprintf(stderr, "uninstall: %v\n", err)
		return 1
	}
	for _, p := range removed {
		fmt.Fprintf(stdout, "removed %s\n", p)
	}

	if *purge != "" {
		if err := os.RemoveAll(rec.DataDir); err != nil {
			fmt.Fprintf(stderr, "uninstall: purge data dir: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "PURGED data volumes and %s\n", rec.DataDir)
	} else {
		fmt.Fprintln(stdout, "Uninstalled. Persistent data volumes were preserved.")
		fmt.Fprintln(stdout, "To also delete data, re-run with --purge <data-dir>.")
	}
	return 0
}
