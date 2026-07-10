// Package cli implements command dispatch for the vulnascout binary.
//
// Commands: version, self-test, enroll, status, run, help. Later phases add
// diagnostics, policy, scan stop, update, logs, and reset.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/codebooker/vulna/scout/internal/api"
	"github.com/codebooker/vulna/scout/internal/buildinfo"
	"github.com/codebooker/vulna/scout/internal/config"
	"github.com/codebooker/vulna/scout/internal/enrollment"
	"github.com/codebooker/vulna/scout/internal/selftest"
	"github.com/codebooker/vulna/scout/internal/storage"
)

const usage = `vulnascout — Vulna remote assessment appliance (VulnaScout)

Usage:
  vulnascout <command> [flags]

Commands:
  version      Print version and build information
  self-test    Run local, non-destructive diagnostics
  enroll       Enroll with the orchestrator using a one-time token
  status       Show local enrollment status
  run          Heartbeat to the orchestrator until stopped
  help         Show this help message

Authorized use only. See SECURITY.md and docs/authorized-use.md.
`

// Execute runs the CLI with the given arguments (excluding the program name)
// and returns a process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}

	switch args[0] {
	case "version", "--version", "-v":
		return runVersion(stdout)
	case "self-test", "selftest":
		return runSelfTest(stdout)
	case "enroll":
		return runEnroll(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "run":
		return runRun(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %q\n\n", args[0])
		fmt.Fprint(stderr, usage)
		return 2
	}
}

func runVersion(w io.Writer) int {
	fmt.Fprintf(w, "vulnascout %s\n", buildinfo.Version)
	fmt.Fprintf(w, "  commit: %s\n", buildinfo.Commit)
	fmt.Fprintf(w, "  built:  %s\n", buildinfo.Date)
	return 0
}

func runSelfTest(w io.Writer) int {
	checks := selftest.Run()
	for _, c := range checks {
		status := "ok"
		if !c.OK {
			if c.Required {
				status = "FAIL"
			} else {
				status = "absent"
			}
		}
		fmt.Fprintf(w, "[%-6s] %-18s %s\n", status, c.Name, c.Detail)
	}
	if selftest.Passed(checks) {
		fmt.Fprintln(w, "\nself-test: PASS")
		return 0
	}
	fmt.Fprintln(w, "\nself-test: FAIL")
	return 1
}

// loadConfig loads config from a path and applies shared flag overrides.
func loadConfig(cfgPath, server, stateDir, serverCA string, insecure bool) (config.Config, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return cfg, err
	}
	if server != "" {
		cfg.ServerURL = server
	}
	if stateDir != "" {
		cfg.StateDir = stateDir
	}
	if serverCA != "" {
		cfg.ServerCAPath = serverCA
	}
	if insecure {
		cfg.InsecureSkipVerify = true
	}
	return cfg, nil
}

func runEnroll(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultConfigPath, "config file path")
	server := fs.String("server", "", "orchestrator base URL (overrides config)")
	token := fs.String("token", "", "one-time enrollment token (or VULNASCOUT_ENROLL_TOKEN)")
	stateDir := fs.String("state-dir", "", "state directory (overrides config)")
	serverCA := fs.String("server-ca", "", "orchestrator TLS CA path (overrides config)")
	insecure := fs.Bool("insecure", false, "skip orchestrator TLS verification (DEV/LAB ONLY)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*cfgPath, *server, *stateDir, *serverCA, *insecure)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return 1
	}
	tok := *token
	if tok == "" {
		tok = os.Getenv("VULNASCOUT_ENROLL_TOKEN")
	}
	if tok == "" {
		fmt.Fprintln(stderr, "enroll: --token (or VULNASCOUT_ENROLL_TOKEN) is required")
		return 2
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(stderr, "enroll:", err)
		return 2
	}

	store, err := storage.New(cfg.StateDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if store.IsEnrolled() {
		fmt.Fprintln(stderr, "already enrolled; remove the state directory to re-enroll")
		return 1
	}

	hc, err := api.NewEnrollHTTPClient(cfg.ServerCAPath, cfg.InsecureSkipVerify)
	if err != nil {
		fmt.Fprintln(stderr, "enroll:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	state, err := enrollment.Enroll(ctx, hc, cfg.ServerURL, tok, store)
	if err != nil {
		fmt.Fprintln(stderr, "enroll failed:", err)
		return 1
	}
	fmt.Fprintf(stdout, "enrolled: probe %s at site %s\n", state.ProbeID, state.SiteID)
	fmt.Fprintf(stdout, "  fingerprint: %s\n", state.Fingerprint)
	fmt.Fprintf(stdout, "  state dir:   %s\n", cfg.StateDir)
	return 0
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultConfigPath, "config file path")
	stateDir := fs.String("state-dir", "", "state directory (overrides config)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath, "", *stateDir, "", false)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return 1
	}
	store, err := storage.New(cfg.StateDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !store.IsEnrolled() {
		fmt.Fprintln(stdout, "status: not enrolled")
		return 0
	}
	state, err := store.LoadState()
	if err != nil {
		fmt.Fprintln(stderr, "load state:", err)
		return 1
	}
	fmt.Fprintln(stdout, "status: enrolled")
	fmt.Fprintf(stdout, "  probe id:    %s\n", state.ProbeID)
	fmt.Fprintf(stdout, "  site id:     %s\n", state.SiteID)
	fmt.Fprintf(stdout, "  fingerprint: %s\n", state.Fingerprint)
	fmt.Fprintf(stdout, "  server:      %s\n", state.ServerURL)
	fmt.Fprintf(stdout, "  enrolled at: %s\n", state.EnrolledAt)
	return 0
}

func runRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultConfigPath, "config file path")
	server := fs.String("server", "", "orchestrator base URL (overrides config)")
	stateDir := fs.String("state-dir", "", "state directory (overrides config)")
	serverCA := fs.String("server-ca", "", "orchestrator TLS CA path (overrides config)")
	insecure := fs.Bool("insecure", false, "skip orchestrator TLS verification (DEV/LAB ONLY)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*cfgPath, *server, *stateDir, *serverCA, *insecure)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return 1
	}
	store, err := storage.New(cfg.StateDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !store.IsEnrolled() {
		fmt.Fprintln(stderr, "not enrolled: run `vulnascout enroll` first")
		return 1
	}
	state, err := store.LoadState()
	if err != nil {
		fmt.Fprintln(stderr, "load state:", err)
		return 1
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = state.ServerURL
	}

	client, err := api.NewMTLSClient(
		cfg.ServerURL, state.ProbeID, store.CertPath(), store.KeyPath(),
		cfg.ServerCAPath, cfg.InsecureSkipVerify,
	)
	if err != nil {
		fmt.Fprintln(stderr, "client:", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	interval := time.Duration(cfg.HeartbeatIntervalSeconds) * time.Second
	fmt.Fprintf(
		stdout, "vulnascout: heartbeating %s as probe %s every %s\n",
		cfg.ServerURL, state.ProbeID, interval,
	)

	hb := buildHeartbeat()
	for {
		resp, hbErr := client.Heartbeat(ctx, hb)
		switch {
		case hbErr == nil:
			if resp.HeartbeatIntervalSeconds > 0 {
				interval = time.Duration(resp.HeartbeatIntervalSeconds) * time.Second
			}
			fmt.Fprintf(
				stdout, "vulnascout: heartbeat ok (status=%s, pending_jobs=%d)\n",
				resp.ProbeStatus, resp.PendingJobCount,
			)
		default:
			var rejected api.ErrRejected
			if errors.As(hbErr, &rejected) {
				fmt.Fprintln(stderr, "vulnascout: rejected by orchestrator (revoked/disabled); stopping")
				return 1
			}
			if ctx.Err() != nil {
				fmt.Fprintln(stdout, "vulnascout: shutting down")
				return 0
			}
			fmt.Fprintln(stderr, "vulnascout: heartbeat error:", hbErr)
		}

		select {
		case <-ctx.Done():
			fmt.Fprintln(stdout, "vulnascout: shutting down")
			return 0
		case <-time.After(interval):
		}
	}
}

func buildHeartbeat() api.HeartbeatRequest {
	host, _ := os.Hostname()
	return api.HeartbeatRequest{
		AgentVersion:    buildinfo.Version,
		Hostname:        host,
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
		Capabilities:    []string{},
		Health:          map[string]any{},
	}
}
