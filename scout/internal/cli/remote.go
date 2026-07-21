package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/codebooker/vulna/scout/internal/api"
	"github.com/codebooker/vulna/scout/internal/config"
	"github.com/codebooker/vulna/scout/internal/doctor"
	"github.com/codebooker/vulna/scout/internal/selftest"
	"github.com/codebooker/vulna/scout/internal/storage"
)

// runStop sets the local emergency stop. It needs no network and is authoritative
// even when the orchestrator is unreachable.
func runStop(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultConfigPath, "config file path")
	stateDir := fs.String("state-dir", "", "state directory (overrides config)")
	reason := fs.String("reason", "operator emergency stop", "reason recorded with the stop")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	store, code := openStore(*cfgPath, *stateDir, stderr)
	if store == nil {
		return code
	}
	if err := store.SetStop(*reason, time.Now().UTC().Format(time.RFC3339)); err != nil {
		fmt.Fprintln(stderr, "stop:", err)
		return 1
	}
	fmt.Fprintf(stdout, "vulnascout: emergency stop SET (%s). The Scout will not run until `resume`.\n", *reason)
	return 0
}

// runResume clears the local emergency stop.
func runResume(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("resume", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultConfigPath, "config file path")
	stateDir := fs.String("state-dir", "", "state directory (overrides config)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	store, code := openStore(*cfgPath, *stateDir, stderr)
	if store == nil {
		return code
	}
	if err := store.ClearStop(); err != nil {
		fmt.Fprintln(stderr, "resume:", err)
		return 1
	}
	fmt.Fprintln(stdout, "vulnascout: emergency stop cleared.")
	return 0
}

// runReset revokes this Scout's identity (best-effort, server-side) and wipes the
// local enrollment material so the host can re-enroll cleanly. A non-secret
// diagnostics snapshot is preserved. The private key is removed, never exported.
func runReset(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reset", flag.ContinueOnError)
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
		fmt.Fprintln(stdout, "vulnascout: not enrolled; nothing to reset.")
		return 0
	}
	state, err := store.LoadState()
	if err != nil {
		fmt.Fprintln(stderr, "load state:", err)
		return 1
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = state.ServerURL
	}

	// Best-effort central revocation so the old identity cannot poll or upload.
	client, cerr := api.NewMTLSClient(
		cfg.ServerURL, state.ProbeID, store.CertPath(), store.KeyPath(),
		cfg.ServerCAPath, cfg.InsecureSkipVerify,
	)
	if cerr == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		if rerr := client.SelfRevoke(ctx); rerr != nil {
			fmt.Fprintln(stderr, "vulnascout: warning: could not revoke centrally "+
				"(wiping locally anyway; revoke this Scout in VulnaDash to be safe):", rerr)
		} else {
			fmt.Fprintln(stdout, "vulnascout: identity revoked centrally.")
		}
		cancel()
	}

	diag := resetDiagnostics(state)
	if err := store.Reset(diag); err != nil {
		fmt.Fprintln(stderr, "reset:", err)
		return 1
	}
	fmt.Fprintln(stdout, "vulnascout: local identity wiped (diagnostics preserved). "+
		"Re-enroll with `vulnascout enroll --server <url> --token <token>`.")
	return 0
}

func resetDiagnostics(state storage.State) []byte {
	snapshot := map[string]string{
		"prior_probe_id":    state.ProbeID,
		"prior_site_id":     state.SiteID,
		"prior_fingerprint": state.Fingerprint,
		"prior_server_url":  state.ServerURL,
		"enrolled_at":       state.EnrolledAt,
		"reset_at":          time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.MarshalIndent(snapshot, "", "  ")
	return data
}

// runDoctor runs the staged connection test and prints results with remediation.
func runDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
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

	serverURL := cfg.ServerURL
	if serverURL == "" && store.IsEnrolled() {
		if st, lerr := store.LoadState(); lerr == nil {
			serverURL = st.ServerURL
		}
	}

	deps := doctor.Deps{Host: hostFromURL(serverURL), MaxClockSkew: 60}
	deps.ResolveDNS = func(h string) error {
		if h == "" {
			return fmt.Errorf("no orchestrator host configured")
		}
		_, e := net.LookupHost(h)
		return e
	}
	deps.DialTLS = func() error { return dialTLS(serverURL, cfg.ServerCAPath, cfg.InsecureSkipVerify) }
	deps.ServerSkew = func() (float64, bool, error) { return serverTimeSkew(serverURL, cfg) }
	deps.Enrolled = func() (bool, string) {
		if store.IsEnrolled() {
			return true, "enrolled"
		}
		return false, "not enrolled"
	}
	deps.PolicyPresent = func() bool { _, e := store.LoadPolicy(); return e == nil }
	deps.MissingScan = missingScanners

	if store.IsEnrolled() {
		if st, lerr := store.LoadState(); lerr == nil {
			if serverURL == "" {
				serverURL = st.ServerURL
			}
			client, cerr := api.NewMTLSClient(
				serverURL, st.ProbeID, store.CertPath(), store.KeyPath(),
				cfg.ServerCAPath, cfg.InsecureSkipVerify,
			)
			if cerr == nil {
				deps.Heartbeat = func() error {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					_, e := client.Heartbeat(ctx, buildHeartbeat(cfg.StateDir))
					return e
				}
				deps.UploadReach = func() error {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					return client.CheckReachable(ctx)
				}
			}
		}
	}

	results := doctor.Run(deps)
	fmt.Fprintf(stdout, "vulnascout connection test (%s)\n", serverURL)
	for _, r := range results {
		mark := map[doctor.Status]string{doctor.OK: "ok  ", doctor.Warn: "WARN", doctor.Fail: "FAIL"}[r.Status]
		fmt.Fprintf(stdout, "  [%s] %-12s %s\n", mark, r.Name, r.Detail)
		if r.Status != doctor.OK && r.Remediation != "" {
			fmt.Fprintf(stdout, "         -> %s\n", r.Remediation)
		}
	}
	if doctor.Blocking(results) {
		fmt.Fprintln(stdout, "\nconnection test: FAIL")
		return 1
	}
	fmt.Fprintln(stdout, "\nconnection test: OK")
	return 0
}

// --- helpers ---

func openStore(cfgPath, stateDir string, stderr io.Writer) (*storage.Store, int) {
	cfg, err := loadConfig(cfgPath, "", stateDir, "", false)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return nil, 1
	}
	store, err := storage.New(cfg.StateDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, 1
	}
	return store, 0
}

func hostFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func dialTLS(serverURL, caPath string, insecure bool) error {
	u, err := url.Parse(serverURL)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("invalid server URL")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	tlsCfg := &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: insecure} //nolint:gosec // opt-in dev/lab
	if caPath != "" && !insecure {
		pem, rerr := os.ReadFile(caPath) //nolint:gosec // operator-provided CA path
		if rerr != nil {
			return fmt.Errorf("read server CA: %w", rerr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("server CA is not valid PEM")
		}
		tlsCfg.RootCAs = pool
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(u.Hostname(), port), tlsCfg)
	if err != nil {
		return err
	}
	return conn.Close()
}

func serverTimeSkew(serverURL string, cfg config.Config) (float64, bool, error) {
	if serverURL == "" {
		return 0, false, nil
	}
	hc, err := api.NewEnrollHTTPClient(cfg.ServerCAPath, cfg.InsecureSkipVerify)
	if err != nil {
		return 0, false, err
	}
	hc.Timeout = 8 * time.Second
	resp, err := hc.Get(strings.TrimRight(serverURL, "/") + "/health")
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	dateHeader := resp.Header.Get("Date")
	if dateHeader == "" {
		return 0, false, nil
	}
	serverTime, err := http.ParseTime(dateHeader)
	if err != nil {
		return 0, false, nil
	}
	return time.Since(serverTime).Seconds(), true, nil
}

// missingScanners returns the standard-pack scanners that are not on PATH.
func missingScanners() []string {
	standard := map[string]bool{"nmap": true, "nuclei": true, "testssl": true, "zap": true}
	var missing []string
	for _, c := range selftest.Run() {
		name := strings.TrimPrefix(c.Name, "scanner:")
		if name == c.Name {
			continue // not a scanner check
		}
		if standard[name] && !c.OK {
			missing = append(missing, name)
		}
	}
	return missing
}

// scannerCapabilities returns the scanner tools present on PATH, reported to the
// orchestrator so the capability manager and preset previews know what can run.
func scannerCapabilities() []string {
	// Authenticated collectors are built into the Scout binary. Their execution
	// remains disabled by signed policy until an administrator opts the Scout in.
	present := []string{"ssh_inventory", "winrm_inventory"}
	for _, c := range selftest.Run() {
		name := strings.TrimPrefix(c.Name, "scanner:")
		if name == c.Name {
			continue // not a scanner check
		}
		if c.OK {
			present = append(present, name)
		}
	}
	return present
}
