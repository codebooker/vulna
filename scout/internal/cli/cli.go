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
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/codebooker/vulna/scout/internal/agent"
	"github.com/codebooker/vulna/scout/internal/api"
	"github.com/codebooker/vulna/scout/internal/buildinfo"
	"github.com/codebooker/vulna/scout/internal/config"
	"github.com/codebooker/vulna/scout/internal/enrollment"
	"github.com/codebooker/vulna/scout/internal/executor"
	"github.com/codebooker/vulna/scout/internal/netdetect"
	"github.com/codebooker/vulna/scout/internal/policy"
	"github.com/codebooker/vulna/scout/internal/queue"
	"github.com/codebooker/vulna/scout/internal/scanners"
	"github.com/codebooker/vulna/scout/internal/scanners/metasploit"
	"github.com/codebooker/vulna/scout/internal/scanners/nmap"
	"github.com/codebooker/vulna/scout/internal/scanners/nuclei"
	"github.com/codebooker/vulna/scout/internal/scanners/ssh_inventory"
	"github.com/codebooker/vulna/scout/internal/scanners/testssl"
	"github.com/codebooker/vulna/scout/internal/scanners/winrm_inventory"
	"github.com/codebooker/vulna/scout/internal/scanners/zap"
	"github.com/codebooker/vulna/scout/internal/selftest"
	"github.com/codebooker/vulna/scout/internal/storage"
	"github.com/codebooker/vulna/scout/internal/telemetry"
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
  doctor       Run a connection test (DNS, TLS, time, enrollment, heartbeat, …)
  stop         Local emergency stop (halts work; works offline)
  resume       Clear the local emergency stop
  reset        Revoke this identity and wipe local state for clean re-enrollment
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
	case "doctor", "connection-test":
		return runDoctor(args[1:], stdout, stderr)
	case "stop":
		return runStop(args[1:], stdout, stderr)
	case "resume":
		return runResume(args[1:], stdout, stderr)
	case "reset":
		return runReset(args[1:], stdout, stderr)
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
	if stopped, reason := store.IsStopped(); stopped {
		fmt.Fprintf(stderr, "vulnascout: local emergency stop is set (%s). "+
			"Run `vulnascout resume` to clear it before running.\n", reason)
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

	pubkey, err := policy.ParsePublicKey(state.SigningPublicKey)
	if err != nil {
		fmt.Fprintln(stderr, "signing key (re-enroll to obtain it):", err)
		return 1
	}
	capabilities := scannerCapabilities()
	workers := standardScannerWorkers(capabilities)
	// Controlled-pentest execution is opt-in and requires Metasploit. Only a scout
	// with VULNA_MSF_CONSOLE set registers the exploit worker; without it, a
	// controlled-pentest job's exploit stage is simply not run here. (The scout's
	// signed policy must also permit controlled_pentest — see pentest_enabled.)
	if msf := os.Getenv("VULNA_MSF_CONSOLE"); msf != "" {
		workers = append(workers, metasploit.NewWorker(&metasploit.ConsoleRunner{Binary: msf}))
		fmt.Fprintln(stdout, "vulnascout: controlled-pentest execution enabled (metasploit)")
	}
	workflow := scanners.NewWorkflow(workers...)
	scout := agent.New(client, store, pubkey, workflow)
	if credentialKey, keyErr := store.LoadCredentialKey(); keyErr == nil {
		scout.SetCredentialPrivateKey(credentialKey)
	} else if !os.IsNotExist(keyErr) {
		fmt.Fprintln(stderr, "vulnascout: credential encryption key unavailable:", keyErr)
	}

	// Durable result queue: finished work survives an intermittent WAN link and
	// resumes upload without duplicating observations.
	if q, qerr := queue.Open(filepath.Join(cfg.StateDir, "queue"), cfg.ResultQueueMaxBytes); qerr != nil {
		fmt.Fprintln(stderr, "vulnascout: durable queue unavailable:", qerr)
	} else {
		scout.SetQueue(q)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := scout.SyncPolicy(ctx); err != nil {
		fmt.Fprintln(stderr, "vulnascout: initial policy sync failed:", err)
		// Fall back to a previously-synced policy so a restart during an outage
		// keeps enforcing scope and can keep running jobs. With no cached policy
		// the Scout stays fail-closed (jobs are refused) until a sync succeeds.
		if loaded, lerr := scout.LoadCachedPolicy(); lerr != nil {
			fmt.Fprintln(stderr, "vulnascout: cached policy unusable:", lerr)
		} else if loaded {
			fmt.Fprintln(stdout, "vulnascout: using last-synced local policy (offline)")
		} else {
			fmt.Fprintln(stderr, "vulnascout: no local policy yet; jobs are refused until sync succeeds")
		}
	} else {
		fmt.Fprintln(stdout, "vulnascout: local policy synced")
	}

	interval := time.Duration(cfg.HeartbeatIntervalSeconds) * time.Second
	fmt.Fprintf(stdout, "vulnascout: running as probe %s against %s\n", state.ProbeID, cfg.ServerURL)

	hb := buildHeartbeat(cfg.StateDir)
	var running *agent.RunningJob
	var pendingResult *executor.Result
	finalizeRetryDelay := time.Second
	var nextFinalizeAttempt time.Time
	for {
		// Local emergency stop is authoritative even if the orchestrator is
		// unreachable or compromised: honor it before doing any work.
		if stopped, reason := store.IsStopped(); stopped {
			fmt.Fprintf(stdout, "vulnascout: local emergency stop set (%s); halting\n", reason)
			if running != nil {
				running.Cancel()
			}
			break
		}
		// Lease renewal is independent of heartbeat success. During a network
		// partition the Agent uses repeated renewal failures to stop the worker
		// before the server can fence and reassign the attempt.
		if running != nil {
			if err := scout.RenewLease(ctx, running); err != nil {
				fmt.Fprintln(stderr, "vulnascout: job lease renewal failed:", err)
			}
		}
		hb.PolicyHash = scout.PolicyHash()
		// Surface the durable upload backlog so the operator can see accumulated
		// work and its storage footprint during a WAN outage.
		if n, b := scout.QueueBacklog(); n > 0 {
			hb.Health["queue_backlog"] = n
			hb.Health["queue_backlog_bytes"] = b
		} else {
			delete(hb.Health, "queue_backlog")
			delete(hb.Health, "queue_backlog_bytes")
		}
		resp, hbErr := client.Heartbeat(ctx, hb)
		if hbErr != nil {
			var rejected api.ErrRejected
			if errors.As(hbErr, &rejected) {
				fmt.Fprintln(stderr, "vulnascout: rejected by orchestrator (revoked/disabled); stopping")
				if running != nil {
					running.Cancel()
				}
				return 1
			}
			if ctx.Err() != nil {
				break
			}
			fmt.Fprintln(stderr, "vulnascout: heartbeat error:", hbErr)
		} else {
			if resp.HeartbeatIntervalSeconds > 0 {
				interval = time.Duration(resp.HeartbeatIntervalSeconds) * time.Second
			}
			// The link is up: flush any results queued during an outage. Uploads
			// are idempotent, so a retried batch never duplicates observations.
			if drained, derr := scout.DrainQueue(ctx); derr != nil {
				if ctx.Err() == nil {
					fmt.Fprintln(stderr, "vulnascout: result upload backlog draining:", derr)
				}
			} else if drained > 0 {
				fmt.Fprintf(stdout, "vulnascout: uploaded %d queued result batch(es)\n", drained)
			}
			if resp.Policy.UpdateAvailable {
				if err := scout.SyncPolicy(ctx); err != nil {
					fmt.Fprintln(stderr, "vulnascout: policy sync failed:", err)
				} else {
					fmt.Fprintln(stdout, "vulnascout: local policy updated")
				}
			}
			if running != nil {
				if pendingResult == nil {
					for _, id := range resp.Cancellations {
						if id == running.JobID {
							fmt.Fprintf(stdout, "vulnascout: cancelling job %s\n", id)
							running.Cancel()
						}
					}
				}
			} else if started, perr := scout.PollAndStart(ctx); perr != nil {
				var rejected api.ErrRejected
				if errors.As(perr, &rejected) {
					fmt.Fprintln(stderr, "vulnascout: rejected by orchestrator; stopping")
					return 1
				}
				fmt.Fprintln(stderr, "vulnascout: poll error:", perr)
			} else if started != nil {
				running = started
				fmt.Fprintf(stdout, "vulnascout: started job %s\n", started.JobID)
			}
		}

		// Poll faster while a job runs so cancellation is responsive; finalize
		// the job as soon as the worker finishes.
		tick := interval
		if running != nil {
			tick = time.Second
			if pendingResult == nil {
				select {
				case res := <-running.Done():
					pendingResult = &res
				default:
				}
			}
			if pendingResult != nil && !time.Now().Before(nextFinalizeAttempt) {
				if err := scout.Finalize(ctx, running, *pendingResult); err != nil {
					fmt.Fprintf(
						stderr, "vulnascout: finalize error (retrying in %s): %v\n",
						finalizeRetryDelay, err,
					)
					nextFinalizeAttempt = time.Now().Add(finalizeRetryDelay)
					finalizeRetryDelay *= 2
					if finalizeRetryDelay > 30*time.Second {
						finalizeRetryDelay = 30 * time.Second
					}
				} else {
					outcome := "completed"
					if pendingResult.Cancelled {
						outcome = "cancelled"
					}
					fmt.Fprintf(
						stdout, "vulnascout: job %s %s (%d/%d stages)\n",
						running.JobID, outcome,
						pendingResult.StagesRun, pendingResult.StagesTotal,
					)
					running = nil
					pendingResult = nil
					finalizeRetryDelay = time.Second
					nextFinalizeAttempt = time.Time{}
				}
			}
		}

		select {
		case <-ctx.Done():
			if running != nil {
				running.Cancel()
			}
		case <-time.After(tick):
		}
		if ctx.Err() != nil {
			break
		}
	}
	fmt.Fprintln(stdout, "vulnascout: shutting down")
	return 0
}

// standardScannerWorkers registers only adapters whose executable was detected
// on PATH. Capability reporting and execution must use the same set; otherwise a
// partial Scout advertises (for example) Nmap-only operation but later fails a
// job by trying to launch an absent Nuclei or testssl binary.
func standardScannerWorkers(capabilities []string) []scanners.Scanner {
	present := make(map[string]bool, len(capabilities))
	for _, capability := range capabilities {
		present[capability] = true
	}
	workers := make([]scanners.Scanner, 0, len(capabilities))
	if present["nmap"] {
		workers = append(workers, nmap.NewWorker())
	}
	if present["nuclei"] {
		workers = append(workers, nuclei.NewWorker())
	}
	if present["testssl"] {
		workers = append(workers, testssl.NewWorker())
	}
	if present["zap"] {
		workers = append(workers, zap.NewWorker())
	}
	if present["ssh_inventory"] {
		workers = append(workers, ssh_inventory.NewWorker())
	}
	if present["winrm_inventory"] {
		workers = append(workers, winrm_inventory.NewWorker())
	}
	return workers
}

func buildHeartbeat(dataDir string) api.HeartbeatRequest {
	host, _ := os.Hostname()
	// Measured host resources let VulnaDash pick a Lite/Standard/Full profile and
	// warn when a preset exceeds this Scout's capability (Phase 27).
	health := telemetry.Probe(dataDir).AsHealth()
	// Advisory only: suggest private ranges the operator may choose to approve in
	// the first-run wizard. Never an approved scope (see docs/adr/0019).
	if candidates := netdetect.PrivateCandidates(); len(candidates) > 0 {
		health["network_candidates"] = candidates
	}
	return api.HeartbeatRequest{
		AgentVersion:    buildinfo.Version,
		Hostname:        host,
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
		Capabilities:    scannerCapabilities(),
		Health:          health,
	}
}
