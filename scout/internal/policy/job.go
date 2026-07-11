package policy

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrExpired indicates a job's expiry time has passed.
var ErrExpired = errors.New("job has expired")

// ErrNotYetValid indicates a job's not_before time is in the future.
var ErrNotYetValid = errors.New("job is not yet valid")

// ErrNoPolicy indicates no local policy is loaded. The Scout is an independent
// safety boundary: without a policy it cannot enforce scope, mode, or limits, so
// it refuses to run any job rather than trusting the orchestrator's word.
var ErrNoPolicy = errors.New("no local policy is loaded; refusing to run jobs (fail closed)")

// hostSaturation caps host-count arithmetic so a huge (e.g. IPv6) target range
// can't overflow. Any realistic max_hosts limit is far below this.
const hostSaturation = 1 << 30

// Job is a verified job envelope (build plan Section 11.3).
type Job struct {
	JobID         string           `json:"job_id"`
	ProbeID       string           `json:"probe_id"`
	SiteID        string           `json:"site_id"`
	Mode          string           `json:"mode"`
	PolicyVersion int              `json:"policy_version"`
	NotBefore     string           `json:"not_before"`
	ExpiresAt     string           `json:"expires_at"`
	Targets       []string         `json:"targets"`
	Workflow      []map[string]any `json:"workflow"`
	Limits        Limits           `json:"limits"`
}

// VerifyJob verifies a signed job envelope and enforces it against the local
// policy: the signature must be valid (rejecting altered jobs), the current
// time must be within [not_before, expires_at] (rejecting expired jobs), the
// mode must be permitted, and every target must be within the approved scope
// (rejecting out-of-scope targets). Pass the current time for deterministic
// tests.
func VerifyJob(raw []byte, pub ed25519.PublicKey, p *Policy, now time.Time) (*Job, error) {
	doc, err := VerifyDocument(raw, pub)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var job Job
	if err := json.Unmarshal(b, &job); err != nil {
		return nil, fmt.Errorf("parse job fields: %w", err)
	}

	notBefore, err := time.Parse(time.RFC3339, job.NotBefore)
	if err != nil {
		return nil, fmt.Errorf("invalid not_before %q: %w", job.NotBefore, err)
	}
	expiresAt, err := time.Parse(time.RFC3339, job.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invalid expires_at %q: %w", job.ExpiresAt, err)
	}
	if now.After(expiresAt) {
		return nil, ErrExpired
	}
	if now.Before(notBefore) {
		return nil, ErrNotYetValid
	}

	// Fail closed: with no local policy the Scout cannot enforce its own scope,
	// mode, or resource limits, so it refuses the job outright rather than
	// trusting a correctly-signed-but-unbounded orchestrator response.
	if p == nil {
		return nil, ErrNoPolicy
	}

	// The job must be for this probe/site and match the policy the Scout holds;
	// a version skew means the two disagree on scope and the job is refused.
	if job.PolicyVersion != p.PolicyVersion {
		return nil, fmt.Errorf(
			"job policy_version %d does not match local policy version %d",
			job.PolicyVersion, p.PolicyVersion,
		)
	}
	if p.ProbeID != "" && job.ProbeID != p.ProbeID {
		return nil, fmt.Errorf(
			"job probe_id %q is not this probe (%q)", job.ProbeID, p.ProbeID,
		)
	}
	if p.SiteID != "" && job.SiteID != p.SiteID {
		return nil, fmt.Errorf(
			"job site_id %q does not match local policy site %q", job.SiteID, p.SiteID,
		)
	}

	if err := p.AllowsMode(job.Mode); err != nil {
		return nil, err
	}
	if len(job.Targets) == 0 {
		return nil, errors.New("job has no targets")
	}

	total := 0
	for _, t := range job.Targets {
		if err := p.AllowsTarget(t); err != nil {
			return nil, err
		}
		n, err := hostCount(t)
		if err != nil {
			return nil, err
		}
		total += n
		if total > hostSaturation {
			total = hostSaturation
		}
	}
	if p.Limits.MaxHosts > 0 && total > p.Limits.MaxHosts {
		return nil, fmt.Errorf(
			"job spans %d hosts, exceeding the local policy limit of %d",
			total, p.Limits.MaxHosts,
		)
	}

	// The job's own declared limits may not exceed the policy's ceilings.
	if err := enforceLimits(job.Limits, p.Limits); err != nil {
		return nil, err
	}
	// Every workflow stage's plugin must be permitted by the local policy.
	if err := p.AllowsPlugins(job.Workflow); err != nil {
		return nil, err
	}
	return &job, nil
}

// hostCount returns the number of addresses a target IP or CIDR spans, saturated
// at hostSaturation so an oversized range can't overflow the running total.
func hostCount(target string) (int, error) {
	t, err := parseTargetPrefix(target)
	if err != nil {
		return 0, err
	}
	hostBits := t.Addr().BitLen() - t.Bits()
	if hostBits >= 30 {
		return hostSaturation, nil
	}
	return 1 << hostBits, nil
}

// enforceLimits rejects a job whose declared limits exceed the policy ceilings.
// A zero policy ceiling means "unset" and is not enforced.
func enforceLimits(job, pol Limits) error {
	checks := []struct {
		name       string
		job, limit int
	}{
		{"max_hosts", job.MaxHosts, pol.MaxHosts},
		{"max_parallel_hosts", job.MaxParallelHosts, pol.MaxParallelHosts},
		{"max_packets_per_second", job.MaxPacketsPerSecond, pol.MaxPacketsPerSecond},
		{"max_duration_seconds", job.MaxDurationSeconds, pol.MaxDurationSeconds},
	}
	for _, c := range checks {
		if c.limit > 0 && c.job > c.limit {
			return fmt.Errorf(
				"job %s (%d) exceeds the local policy limit (%d)", c.name, c.job, c.limit,
			)
		}
	}
	return nil
}
