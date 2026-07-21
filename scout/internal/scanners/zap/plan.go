// Package zap adapts OWASP ZAP (via its Automation Framework) for VulnaScout's
// web-assessment stage. It generates a scoped automation plan and runs ZAP with
// only allowlisted arguments; the passive profile performs no active attacks and
// the limited-active profile enables only an allowlisted set of active rules.
package zap

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Web-assessment profiles (build plan Section 12.5).
const (
	ProfilePassiveBaseline = "passive_baseline"
	ProfileLimitedActive   = "limited_active"
)

// contextName is the single ZAP context all jobs run within; its include/exclude
// paths are what bound the assessment to the authorized scope.
const contextName = "vulna-web"

// safeActiveRules is the allowlist of ZAP active-scan rule IDs enabled by the
// limited-active profile. Everything else is left off (defaultThreshold: off).
// These are conservative, non-destructive injection/traversal checks; DoS and
// other intrusive rules are deliberately excluded.
var safeActiveRules = []int{
	40012, // Cross Site Scripting (Reflected)
	40014, // Cross Site Scripting (Persistent)
	40018, // SQL Injection
	6,     // Path Traversal
	40008, // Parameter Tampering
}

// ScopeConfig is the fully-resolved input to the automation-plan generator.
type ScopeConfig struct {
	Profile            string
	StartURLs          []string
	InScopeHosts       []string // hosts (IPs) the context is bounded to
	ExcludeURLs        []string // regex exclude paths (e.g. logout)
	MaxDepth           int
	MaxChildren        int
	MaxDurationMinutes int
	RequestsPerSecond  int
}

// hostRegex returns a ZAP include-path regex that matches only the given host
// (any scheme/port/path), with the host's special characters escaped so an IP's
// dots are literal.
func hostRegex(host string) string {
	return "^https?://" + regexp.QuoteMeta(host) + "(:[0-9]+)?/.*$"
}

// ValidateStartURLs ensures every start URL's host is in the in-scope set, so the
// assessment cannot be pointed outside the authorized scope.
func ValidateStartURLs(startURLs, inScopeHosts []string) error {
	inScope := make(map[string]bool, len(inScopeHosts))
	for _, h := range inScopeHosts {
		inScope[h] = true
	}
	for _, raw := range startURLs {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid start URL %q", raw)
		}
		if !inScope[u.Hostname()] {
			return fmt.Errorf("start URL host %q is out of scope", u.Hostname())
		}
	}
	return nil
}

func rpsToDelayMs(rps int) int {
	if rps <= 0 {
		return 0
	}
	return 1000 / rps
}

// BuildAutomationPlan generates a ZAP Automation Framework plan for the given
// scope, writing its JSON report to reportFile (a basename, no extension) inside
// the plan's report directory reportDir. The plan is emitted as JSON, which is
// valid YAML and accepted by the Automation Framework.
//
// The passive profile runs spider + passive scan only (no active attacks). The
// limited-active profile additionally runs an active scan whose policy enables
// only the allowlisted rules (every other rule threshold is "off").
func BuildAutomationPlan(scope ScopeConfig, reportDir, reportFile string) ([]byte, error) {
	if scope.Profile != ProfilePassiveBaseline && scope.Profile != ProfileLimitedActive {
		return nil, fmt.Errorf("unknown web profile %q", scope.Profile)
	}
	if len(scope.StartURLs) == 0 {
		return nil, fmt.Errorf("at least one start URL is required")
	}
	if len(scope.InScopeHosts) == 0 {
		return nil, fmt.Errorf("no in-scope hosts resolved")
	}
	if err := ValidateStartURLs(scope.StartURLs, scope.InScopeHosts); err != nil {
		return nil, err
	}

	includePaths := make([]any, 0, len(scope.InScopeHosts))
	for _, h := range scope.InScopeHosts {
		includePaths = append(includePaths, hostRegex(h))
	}
	excludePaths := make([]any, 0, len(scope.ExcludeURLs))
	for _, e := range scope.ExcludeURLs {
		excludePaths = append(excludePaths, e)
	}
	startURLs := make([]any, 0, len(scope.StartURLs))
	for _, u := range scope.StartURLs {
		startURLs = append(startURLs, u)
	}

	ctx := map[string]any{
		"name":         contextName,
		"urls":         startURLs,
		"includePaths": includePaths,
		"excludePaths": excludePaths,
	}
	env := map[string]any{
		"contexts": []any{ctx},
		"parameters": map[string]any{
			"failOnError":      false,
			"failOnWarning":    false,
			"progressToStdout": true,
		},
	}

	jobs := []any{
		map[string]any{
			"type": "spider",
			"parameters": map[string]any{
				"context":     contextName,
				"maxDuration": scope.MaxDurationMinutes,
				"maxDepth":    scope.MaxDepth,
				"maxChildren": scope.MaxChildren,
			},
		},
		map[string]any{
			"type":       "passiveScan-wait",
			"parameters": map[string]any{"maxDuration": scope.MaxDurationMinutes},
		},
	}

	if scope.Profile == ProfileLimitedActive {
		rules := make([]any, 0, len(safeActiveRules))
		for _, id := range safeActiveRules {
			rules = append(rules, map[string]any{
				"id": id, "strength": "low", "threshold": "medium",
			})
		}
		jobs = append(jobs, map[string]any{
			"type": "activeScan",
			"parameters": map[string]any{
				"context":               contextName,
				"maxRuleDurationInMins": 1,
				"maxScanDurationInMins": scope.MaxDurationMinutes,
				"threadPerHost":         2,
				"delayInMs":             rpsToDelayMs(scope.RequestsPerSecond),
			},
			"policyDefinition": map[string]any{
				"defaultStrength":  "low",
				"defaultThreshold": "off", // allowlist: only the rules below run
				"rules":            rules,
			},
		})
	}

	jobs = append(jobs, map[string]any{
		"type": "report",
		"parameters": map[string]any{
			"template":    "traditional-json",
			"reportDir":   reportDir,
			"reportFile":  reportFile,
			"reportTitle": "Vulna Web Assessment",
		},
		"risks": []any{"info", "low", "medium", "high"},
	})
	// Automation Framework warnings normally produce process exit code 2 even
	// when failOnWarning is false. Findings and non-fatal spider warnings must not
	// turn an otherwise completed assessment into a failed Vulna scan; genuine
	// framework errors retain exit code 1.
	jobs = append(jobs, map[string]any{
		"type": "exitStatus",
		"parameters": map[string]any{
			"okExitValue": 0, "warnExitValue": 0, "errorExitValue": 1,
		},
		"alwaysRun": true,
	})

	plan := map[string]any{"env": env, "jobs": jobs}
	return json.MarshalIndent(plan, "", "  ")
}

// planHasActiveScan reports whether a marshaled plan contains an activeScan job.
// Used by tests to assert the passive profile performs no active attacks.
func planHasActiveScan(planJSON []byte) bool {
	return strings.Contains(string(planJSON), `"type": "activeScan"`)
}
