package zap

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/codebooker/vulna/scout/internal/discovery"
	"github.com/codebooker/vulna/scout/internal/policy"
	"github.com/codebooker/vulna/scout/internal/processutil"
)

const (
	defaultBinary  = "zap.sh"
	reportBaseName = "zap-report"
	// Conservative defaults applied when the job config omits a limit.
	defaultMaxDepth       = 5
	defaultMaxChildren    = 10
	defaultMaxDuration    = 10
	defaultRequestsPerS   = 10
	diagnosticOutputRunes = 1800
)

// safeExcludeURLs are always excluded from crawling/attack to avoid disrupting
// the target (logging out the scan session, triggering destructive endpoints).
var safeExcludeURLs = []string{
	"(?i).*/logout.*",
	"(?i).*/signout.*",
	"(?i).*/sign-out.*",
	"(?i).*(delete|destroy|shutdown|reboot).*",
}

// Worker runs OWASP ZAP web assessments. It satisfies scanners.Scanner.
type Worker struct {
	Binary string
	// Timeout is an optional per-invocation override. Zero inherits the signed,
	// whole-job deadline installed by the agent.
	Timeout time.Duration
}

// NewWorker returns a Worker with defaults.
func NewWorker() *Worker {
	return &Worker{Binary: defaultBinary}
}

func (w *Worker) Stage() string { return "web" }
func (w *Worker) Name() string  { return "zap" }

// TargetsFor turns Nmap-discovered HTTP services into exact start URLs. The
// workflow runner retains the job's original signed address scope separately, so
// these runtime-derived URLs can be validated against it before ZAP launches.
func (w *Worker) TargetsFor(endpoints []discovery.Endpoint) []string {
	seen := map[string]bool{}
	var out []string
	for _, endpoint := range endpoints {
		if !endpoint.HTTP || endpoint.Transport != "tcp" {
			continue
		}
		target := endpoint.URL()
		if !seen[target] {
			seen[target] = true
			out = append(out, target)
		}
	}
	return out
}

func (w *Worker) binary() string {
	if w.Binary != "" {
		return w.Binary
	}
	return defaultBinary
}

func (w *Worker) runContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if w.Timeout > 0 {
		return context.WithTimeout(ctx, w.Timeout)
	}
	return context.WithCancel(ctx)
}

// BuildArgs returns the allowlisted ZAP arguments to run an automation plan.
func BuildArgs(planPath, homeDir string) []string {
	return []string{"-dir", homeDir, "-cmd", "-autorun", planPath}
}

// Run executes the web-assessment stage. It resolves the ZAP stage config from
// the job workflow, builds a scoped automation plan, runs ZAP, and returns the
// raw JSON report. If the job has no ZAP stage, it is a no-op.
func (w *Worker) Run(ctx context.Context, job *policy.Job) ([]byte, error) {
	cfg := findStageConfig(job.Workflow, w.Name())
	if cfg == nil {
		return nil, nil
	}
	if autoDiscover, _ := cfg["auto_discover"].(bool); autoDiscover {
		startURLs := httpURLs(job.Targets)
		if len(startURLs) == 0 {
			// Discovery found no HTTP(S) service in this target chunk. That is a
			// valid empty passive-web result, not a scanner failure and not a reason
			// to hand ZAP a raw CIDR it cannot crawl.
			return nil, nil
		}
		cfg = cloneConfig(cfg)
		cfg["start_urls"] = startURLs
	}
	scopeTargets := job.ScopeTargets
	if len(scopeTargets) == 0 {
		scopeTargets = job.Targets
	}
	scope, err := scopeFromConfig(cfg, scopeTargets)
	if err != nil {
		return nil, err
	}

	dir, err := os.MkdirTemp("", "vulnascout-zap-*")
	if err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	zapHome := filepath.Join(dir, "home")
	if err := os.Mkdir(zapHome, 0o700); err != nil {
		return nil, fmt.Errorf("create ZAP home: %w", err)
	}

	plan, err := BuildAutomationPlan(scope, dir, reportBaseName)
	if err != nil {
		return nil, err
	}
	planPath := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(planPath, plan, 0o600); err != nil {
		return nil, fmt.Errorf("write plan: %w", err)
	}

	// The agent's parent context carries the signed authorization expiry and the
	// whole-job max duration. Do not impose a hidden per-invocation deadline.
	runCtx, cancel := w.runContext(ctx)
	defer cancel()
	cmd := processutil.ScannerCommandContext(
		runCtx, dir, w.binary(), BuildArgs(planPath, zapHome)...,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	data, _ := os.ReadFile(filepath.Join(dir, reportBaseName+".json"))
	if runCtx.Err() != nil {
		return data, runCtx.Err()
	}
	if runErr != nil {
		return data, fmt.Errorf(
			"zap failed: %v: %s",
			runErr,
			processutil.BoundedDiagnostic(stderr.String(), diagnosticOutputRunes),
		)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf(
			"zap produced no report: %v: %s",
			runErr,
			processutil.BoundedDiagnostic(stderr.String(), diagnosticOutputRunes),
		)
	}
	return data, nil
}

func cloneConfig(cfg map[string]any) map[string]any {
	cloned := make(map[string]any, len(cfg)+1)
	for key, value := range cfg {
		cloned[key] = value
	}
	return cloned
}

// httpURLs keeps only the exact runtime-derived URL form accepted by the ZAP
// adapter. A raw IP/CIDR fallback therefore produces an intentional no-op.
func httpURLs(targets []string) []string {
	var out []string
	for _, target := range targets {
		u, err := url.Parse(target)
		if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			out = append(out, target)
		}
	}
	return out
}

// findStageConfig returns the config map of the first workflow stage whose plugin
// matches name, or nil if there is none.
func findStageConfig(workflow []map[string]any, name string) map[string]any {
	for _, stage := range workflow {
		if plugin, _ := stage["plugin"].(string); plugin == name {
			if cfg, ok := stage["config"].(map[string]any); ok {
				return cfg
			}
			return map[string]any{}
		}
	}
	return nil
}

// scopeFromConfig resolves a ScopeConfig from the stage config and the job's
// approved targets. In-scope hosts are derived from the start URLs and every
// IP-literal host must fall within an approved target (scope enforcement).
func scopeFromConfig(cfg map[string]any, targets []string) (ScopeConfig, error) {
	profile, _ := cfg["profile"].(string)
	if profile == "" {
		profile = ProfilePassiveBaseline
	}
	startURLs := asStringSlice(cfg["start_urls"])
	if len(startURLs) == 0 {
		return ScopeConfig{}, fmt.Errorf("zap stage has no start_urls")
	}

	hosts, err := inScopeHosts(startURLs, targets)
	if err != nil {
		return ScopeConfig{}, err
	}

	excludes := append([]string{}, safeExcludeURLs...)
	excludes = append(excludes, asStringSlice(cfg["exclude_urls"])...)

	return ScopeConfig{
		Profile:            profile,
		StartURLs:          startURLs,
		InScopeHosts:       hosts,
		ExcludeURLs:        excludes,
		MaxDepth:           asIntOr(cfg["max_depth"], defaultMaxDepth),
		MaxChildren:        asIntOr(cfg["max_children"], defaultMaxChildren),
		MaxDurationMinutes: asIntOr(cfg["max_duration_minutes"], defaultMaxDuration),
		RequestsPerSecond:  asIntOr(cfg["requests_per_second"], defaultRequestsPerS),
	}, nil
}

// inScopeHosts returns the unique hosts of the start URLs, rejecting any
// IP-literal host that is not covered by an approved target.
func inScopeHosts(startURLs, targets []string) ([]string, error) {
	seen := map[string]bool{}
	var hosts []string
	for _, raw := range startURLs {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("invalid start URL %q", raw)
		}
		host := u.Hostname()
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf(
				"start URL host %q is a DNS name; only IP-literal hosts are permitted", host,
			)
		}
		if !addrInTargets(addr, targets) {
			return nil, fmt.Errorf("start URL host %q is outside the approved scope", host)
		}
		if !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	return hosts, nil
}

func addrInTargets(addr netip.Addr, targets []string) bool {
	for _, t := range targets {
		if a, err := netip.ParseAddr(t); err == nil {
			if a == addr {
				return true
			}
			continue
		}
		if p, err := netip.ParsePrefix(t); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}

func asStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// asIntOr coerces a JSON-decoded numeric value (float64/int/json.Number) to an
// int, falling back to def when absent or non-positive.
func asIntOr(v any, def int) int {
	var n int
	switch t := v.(type) {
	case float64:
		n = int(t)
	case int:
		n = t
	default:
		return def
	}
	if n <= 0 {
		return def
	}
	return n
}
